from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from osai_security.config import AppConfig
from osai_security.db import Repository
from osai_security.engine import run_assessment
from osai_security.evidence_store import EvidenceStore
from osai_security.http_app import Application, assessment_target_capabilities
from osai_security.m4_control_fixture import M4ControlFixtureServer
from osai_security.m4_security import (
    M4_CONTRACT_RECIPES,
    public_m4_contract_recipes,
    public_m4_coverage,
    validate_m4_coverage,
)
from osai_security.owasp import build_assessment_plan, public_taxonomy
from osai_security.quality_gates import audit_assessment_run
from osai_security.reports import build_markdown_report
from osai_security.targets import TargetClient, validate_authorized_routes


def _configured_contracts(family: str) -> list[dict]:
    contracts: list[dict] = []
    for recipe in public_m4_contract_recipes():
        for source in recipe["contracts"]:
            contract = {**source, "definition": {**source["definition"]}}
            contract["definition"]["steps"] = [
                {**step, "assertions": [dict(assertion) for assertion in step["assertions"]]}
                for step in source["definition"]["steps"]
            ]
            contract["definition"]["security_outcomes"] = [
                dict(outcome) for outcome in source["definition"]["security_outcomes"]
            ]
            control_id = str(contract["id"])
            prefix = "/v1/control/" if family == "flat-v1" else "/v2/checks/"
            step = contract["definition"]["steps"][0]
            step["path"] = f"{prefix}{control_id}"
            case_id = f"qualified-{control_id}"
            step["body"] = {"assessment_case": case_id, "control_id": control_id}
            for assertion in step["assertions"]:
                if assertion.get("path") == "$.case_id":
                    assertion["equals"] = case_id
            if family == "nested-v2":
                path_map = {
                    "$.applicable": "$.scope.is_applicable",
                    "$.control_id": "$.record.control",
                    "$.case_id": "$.record.case",
                    "$.evidence_id": "$.record.id",
                    "$.oracle_version": "$.record.oracle",
                    "$.fixture_sha256": "$.record.fixture_digest",
                    "$.measurement": "$.result.measurement",
                    "$.control_failed": "$.result.requirement_failed",
                }
                for assertion in step["assertions"]:
                    if assertion.get("path") in path_map:
                        assertion["path"] = path_map[assertion["path"]]
            contract["recipe_provenance"] = {
                **contract["recipe_provenance"],
                "reviewed": True,
                "reviewed_at": "2026-08-11T12:00:00Z",
            }
            contracts.append(contract)
    return contracts


class Milestone4CoverageTests(unittest.TestCase):
    def test_registry_is_complete_without_hiding_execution_boundaries(self) -> None:
        coverage = validate_m4_coverage()
        self.assertTrue(coverage["complete"])
        self.assertEqual(len(coverage["work_packages"]), 8)
        self.assertEqual(coverage["qualified_controls"], coverage["total_controls"])
        self.assertGreaterEqual(coverage["total_controls"], 60)
        lanes = {
            control["execution_lane"]
            for package in coverage["work_packages"]
            for control in package["controls"]
        }
        self.assertIn("contract", lanes)
        self.assertIn("native-agentic-trace", lanes)
        self.assertIn("native-mcp-stdio", lanes)
        self.assertIn("native-rag", lanes)
        self.assertIn("native-artifact", lanes)
        self.assertIn("native-tool-agent", lanes)
        self.assertIn("does not claim universal autonomous discovery", coverage["qualification_policy"]["scope"])

    def test_every_contract_recipe_is_editable_and_published_with_owasp(self) -> None:
        coverage = public_m4_coverage()
        contract_controls = {
            control["id"].casefold()
            for package in coverage["work_packages"]
            for control in package["controls"]
            if control["execution_lane"] == "contract"
        }
        recipe_contracts = {
            contract["id"]
            for recipe in M4_CONTRACT_RECIPES
            for contract in recipe["contracts"]
        }
        self.assertEqual(contract_controls, recipe_contracts)
        taxonomy = public_taxonomy()
        published = {recipe["id"] for recipe in taxonomy["contract_recipes"]}
        self.assertTrue({recipe["id"] for recipe in M4_CONTRACT_RECIPES}.issubset(published))
        for recipe in taxonomy["contract_recipes"]:
            if recipe["id"] not in {item["id"] for item in M4_CONTRACT_RECIPES}:
                continue
            for contract in recipe["contracts"]:
                self.assertFalse(contract["recipe_provenance"]["reviewed"])
                self.assertIn("TARGET_APPROVED_", str(contract["definition"]))

    def _run_family(self, family: str, mode: str) -> tuple[dict, int]:
        with tempfile.TemporaryDirectory() as directory, M4ControlFixtureServer(family, mode) as fixture:
            root = Path(directory)
            repo = Repository(root / "assessment.sqlite3")
            try:
                project = repo.create_project(name=f"M4 {family} {mode}", client="Independent qualification")
                repo.add_document(project["id"], kind="scope", filename="scope.md", content="Only the local fixture routes and deterministic read-only control checks are authorized.")
                repo.add_document(project["id"], kind="policy", filename="policy.md", content="A finding requires the configured target-owned oracle and exact reproduction. HTTP success and model prose do not qualify.")
                contracts = _configured_contracts(family)
                routes = validate_authorized_routes(
                    [{"path": contract["definition"]["steps"][0]["path"], "methods": ["POST"]} for contract in contracts],
                    primary_path=contracts[0]["definition"]["steps"][0]["path"],
                    primary_method="POST",
                )
                capabilities = {
                    "multimodal": True,
                    "agents": True,
                    "tools": True,
                    "mcp": True,
                    "rag": True,
                    "multi_identity": True,
                    "training_pipeline": True,
                    "artifact_inventory": True,
                    "model_evaluation": True,
                    "privacy_testing": True,
                    "resource_telemetry": True,
                    "operational_controls": True,
                }
                target = repo.add_target(
                    project["id"],
                    name=f"Independent {family} M4 fixture",
                    kind="api",
                    base_url=fixture.base_url,
                    path=routes[0]["path"],
                    method="POST",
                    capabilities=capabilities,
                    authorized_routes=routes,
                    scope_confirmed=True,
                )
                app = Application(
                    repo,
                    config=AppConfig(database_path=repo.path, evidence_root=root / "evidence"),
                    target_client=TargetClient(timeout_seconds=3),
                )
                request_ceiling = len(contracts) * 2 + 2
                guardrail = repo.save_guardrail(
                    project["id"], target["id"], status="approved",
                    max_requests=request_ceiling, max_runtime_seconds=180,
                    max_consecutive_errors=3, allow_active_recon=False,
                    allow_multi_turn=False, max_turns_per_objective=1,
                    allow_reproduction=True, allow_screenshots=False,
                    stop_on_http_5xx=True,
                )
                status, target = app.dispatch(
                    "PATCH",
                    f"/api/projects/{project['id']}/targets/{target['id']}/assessment-contracts",
                    {"contracts": contracts},
                )
                self.assertEqual(status, 200)
                technique_ids = sorted({item for contract in target["assessment_contracts"] for item in contract["technique_ids"]})
                plan = build_assessment_plan(
                    technique_ids=technique_ids,
                    target_capabilities=assessment_target_capabilities(target),
                    assessment_contracts=target["assessment_contracts"],
                    include_modules=False,
                )
                plan.update({
                    "guardrail": guardrail,
                    "adaptive_turns": 1,
                    "recon": {"mode": "none", "profile": "configured"},
                    "confirmation_policy": {"mode": "complete-evidence", "reproduction_attempts": 1},
                })
                run = run_assessment(
                    repo,
                    project_id=project["id"],
                    target_id=target["id"],
                    module_ids=[],
                    model_mode="offline",
                    model_gateway=object(),
                    target_client=TargetClient(timeout_seconds=3),
                    browser_target_client=object(),
                    evidence_store=EvidenceStore(root / "projects"),
                    assessment_plan=plan,
                )
                detail = repo.get_run_detail(project["id"], run["id"])
                self.assertEqual(detail["status"], "completed")
                self.assertEqual(len(detail["contract_runs"]), len(contracts))
                self.assertTrue(all(item["counts"]["requests"] == 2 for item in detail["contract_runs"]))
                self.assertEqual(len(fixture.state.requests), len(contracts) * 2)
                audit = audit_assessment_run(detail)
                self.assertEqual(audit["planned"], audit["terminal"])
                self.assertEqual(audit["missing_finding_evidence"], [])
                findings = [finding for item in detail["contract_runs"] for finding in item["security_findings"]]
                if mode == "vulnerable":
                    self.assertEqual(len(findings), len(contracts))
                    self.assertTrue(all(finding["confirmation"] == "verifier" for finding in findings))
                    self.assertTrue(all(len(finding["evidence_event_ids"]) >= 4 for finding in findings))
                else:
                    self.assertEqual(findings, [])
                    self.assertTrue(all(item["counts"]["assertions_failed"] == 2 for item in detail["contract_runs"]))
                report = build_markdown_report(repo.get_project_for_report(project["id"]))
                self.assertIn("Testing-tool runs", report)
                self.assertIn(f"{len(contracts)} testing-tool run(s)", report)
                self.assertIn("| 2 |", report)
                return detail, len(contracts)
            finally:
                repo.close()

    def test_two_independent_contract_families_separate_secure_and_vulnerable_controls(self) -> None:
        results: dict[str, dict[str, int]] = {}
        for family in ("flat-v1", "nested-v2"):
            results[family] = {}
            for mode in ("secure", "vulnerable"):
                detail, count = self._run_family(family, mode)
                results[family][mode] = sum(
                    len(item["security_findings"]) for item in detail["contract_runs"]
                )
                self.assertGreater(count, 30)
        self.assertEqual(results["flat-v1"]["secure"], 0)
        self.assertEqual(results["nested-v2"]["secure"], 0)
        self.assertGreater(results["flat-v1"]["vulnerable"], 30)
        self.assertEqual(results["flat-v1"]["vulnerable"], results["nested-v2"]["vulnerable"])

    def test_local_api_and_gui_expose_m4_coverage_and_capabilities(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = Repository(root / "app.sqlite3")
            try:
                app = Application(repo, config=AppConfig(database_path=repo.path, evidence_root=root / "evidence"))
                status, document = app.dispatch("GET", "/api/milestone-4/coverage")
                self.assertEqual(status, 200)
                self.assertTrue(document["complete"])
                script = Path("osai_security/static/app.js").read_text(encoding="utf-8")
                self.assertIn('api("/api/milestone-4/coverage")', script)
                self.assertIn("Milestone 4 · AI-system coverage", script)
                self.assertIn('"privacy_testing","Privacy and inference evaluation"', script)
                self.assertIn('"operational_controls","Cloud, client, and operational controls"', script)
            finally:
                repo.close()


if __name__ == "__main__":
    unittest.main()
