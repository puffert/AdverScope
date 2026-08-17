from __future__ import annotations

import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from osai_security.assessment_contracts import normalize_assessment_contracts
from osai_security.config import AppConfig
from osai_security.db import NotFoundError, Repository
from osai_security.engine import run_assessment
from osai_security.evidence_store import EvidenceStore
from osai_security.http_app import Application, assessment_target_capabilities
from osai_security.owasp import build_assessment_plan, public_taxonomy
from osai_security.quality_gates import audit_assessment_run
from osai_security.targets import TargetClient, validate_authorized_routes


class ContractTargetHandler(BaseHTTPRequestHandler):
    requests: list[str] = []

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _write(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        self.__class__.requests.append(self.path)
        if self.path == "/prove":
            return self._write({
                "confirmed": True,
                "count": 2,
                "source": "target-verifier",
                "controls": {
                    "multimodal_failed": True,
                    "model_provenance_failed": True,
                    "dependency_integrity_failed": True,
                    "training_integrity_failed": True,
                    "backdoor_triggered": True,
                    "input_limit_failed": True,
                    "quota_limit_failed": True,
                },
            })
        if self.path == "/safe":
            return self._write({"confirmed": False, "source": "target-verifier"})
        if self.path == "/wrong-schema":
            return self._write({"unexpected": False, "source": "target-verifier"})
        if self.path == "/methodology":
            return self._write({"complete": True, "source": "target-verifier"})
        if self.path == "/observation":
            return self._write({"visible": True, "source": "authorized-inventory"})
        if self.path == "/unavailable":
            return self._write({"error": "backend model unavailable"}, status=502)
        if self.path == "/model-provenance":
            return self._write({"provenance_verified": False})
        if self.path == "/dependency-integrity":
            return self._write({"integrity_verified": False})
        if self.path == "/training-integrity":
            return self._write({"integrity_verified": False})
        if self.path == "/resource-telemetry":
            return self._write({"quota_enforced": False})
        return self._write({"error": "not found"}, status=404)

    def do_POST(self) -> None:
        self.__class__.requests.append(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        payload = json.loads(self.rfile.read(length) or b"{}")
        if self.path == "/multimodal":
            return self._write({"instruction_boundary_violated": payload.get("fixture_id") == "adversarial-fixture"})
        if self.path == "/model-evaluation":
            return self._write({"trigger_activated": payload.get("evaluation_case") == "trigger-case"})
        if self.path == "/input-resource":
            return self._write({"input_limit_enforced": False})
        if self.path == "/bounded-cost-probe":
            return self._write({"accepted": True})
        return self._write({"error": "not found"}, status=404)


def security_contract(
    path: str,
    *,
    contract_id: str = "security-proof",
    objective_ids: list[str] | None = None,
) -> dict:
    return {
        "id": contract_id,
        "title": "Reproducible target-owned security proof",
        "description": "The customer-supplied verifier is evaluated twice.",
        "enabled": True,
        "reproduce": True,
        "definition": {
            "steps": [{
                "id": "verify",
                "name": "Read the documented verifier",
                "type": "http",
                "method": "GET",
                "path": path,
                "assertions": [
                    {"type": "status", "equals": 200, "label": "Verifier responded"},
                    {"type": "json_equals", "path": "$.confirmed", "equals": True, "label": "Security condition confirmed"},
                    {"type": "json_gte", "path": "$.count", "equals": 1, "label": "At least one target event exists", "required": False},
                    {"type": "json_not_equals", "path": "$.source", "equals": "", "label": "Evidence source is identified", "required": False},
                ],
            }],
            "security_outcomes": [{
                "id": "supply-chain-boundary-failed",
                "kind": "security",
                "title": "Configured trust boundary failed",
                "summary": "The documented target verifier reproduced the configured security condition.",
                "severity": "high",
                "confidence": 0.98,
                "risk_ids": ["LLM03"],
                "technique_ids": ["LLM03-DEPS"],
                "objective_ids": list(objective_ids or []),
                "required_step_ids": ["verify"],
                "confirmation": "verifier",
            }],
        },
    }


def methodology_contract() -> dict:
    return {
        "id": "methodology-check",
        "title": "Architecture methodology check",
        "enabled": True,
        "reproduce": False,
        "definition": {
            "steps": [{
                "id": "methodology",
                "name": "Submit the documented methodology record",
                "type": "http",
                "method": "GET",
                "path": "/methodology",
                "assertions": [
                    {"type": "status", "equals": 200},
                    {"type": "json_equals", "path": "$.complete", "equals": True},
                ],
            }],
            "security_outcomes": [{
                "id": "methodology-completed",
                "kind": "methodology",
                "title": "Methodology requirement completed",
                "summary": "The documented methodology record satisfied its deterministic assertions.",
                "severity": "info",
                "confidence": 1.0,
                "required_step_ids": ["methodology"],
                "confirmation": "exact-http",
            }],
        },
    }


def observation_contract() -> dict:
    return {
        "id": "security-observation",
        "title": "Security-relevant inventory observation",
        "enabled": True,
        "reproduce": True,
        "definition": {
            "steps": [{
                "id": "inventory",
                "name": "Read the authorized inventory",
                "type": "http",
                "method": "GET",
                "path": "/observation",
                "assertions": [
                    {"type": "status", "equals": 200},
                    {"type": "json_equals", "path": "$.visible", "equals": True},
                ],
            }],
            "security_outcomes": [{
                "id": "authorized-capability-visible",
                "kind": "observation",
                "title": "Capability metadata is visible",
                "summary": "Visibility is retained for policy review and does not prove a failed security requirement.",
                "severity": "info",
                "confidence": 1.0,
                "risk_ids": ["LLM06"],
                "technique_ids": ["LLM06-TOOLS"],
                "required_step_ids": ["inventory"],
                "confirmation": "exact-http",
            }],
        },
    }


class AssessmentContractTests(unittest.TestCase):
    def setUp(self) -> None:
        ContractTargetHandler.requests = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), ContractTargetHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.repo = Repository(self.root / "assessment.sqlite3")
        self.project = self.repo.create_project(name="Contract assessment")
        self.repo.add_document(self.project["id"], kind="scope", filename="scope.md", content="Authorized read-only API validation. Maximum 12 requests. Reproduction is allowed.")
        self.repo.add_document(self.project["id"], kind="policy", filename="policy.md", content="Only deterministic target evidence may confirm a finding.")
        routes = validate_authorized_routes(
            [
                {"path": "/prove", "methods": ["GET"]},
                {"path": "/safe", "methods": ["GET"]},
                {"path": "/wrong-schema", "methods": ["GET"]},
                {"path": "/missing-verifier", "methods": ["GET"]},
                {"path": "/methodology", "methods": ["GET"]},
                {"path": "/observation", "methods": ["GET"]},
                {"path": "/unavailable", "methods": ["GET"]},
                {"path": "/model-provenance", "methods": ["GET"]},
                {"path": "/dependency-integrity", "methods": ["GET"]},
                {"path": "/training-integrity", "methods": ["GET"]},
                {"path": "/resource-telemetry", "methods": ["GET"]},
                {"path": "/multimodal", "methods": ["POST"]},
                {"path": "/model-evaluation", "methods": ["POST"]},
                {"path": "/input-resource", "methods": ["POST"]},
                {"path": "/bounded-cost-probe", "methods": ["POST"]},
            ],
            primary_path="/prove",
            primary_method="GET",
        )
        self.target = self.repo.add_target(
            self.project["id"],
            name="Documented API",
            kind="api",
            base_url=f"http://127.0.0.1:{self.server.server_address[1]}",
            path="/prove",
            method="GET",
            capabilities={
                "artifact_inventory": True,
                "training_pipeline": True,
                "model_evaluation": True,
                "resource_telemetry": True,
                "multimodal": True,
                "tools": True,
            },
            authorized_routes=routes,
            scope_confirmed=True,
        )
        self.guardrail = self.repo.save_guardrail(
            self.project["id"], self.target["id"], status="approved", max_requests=12,
            max_runtime_seconds=60, max_consecutive_errors=2, allow_active_recon=False,
            allow_multi_turn=False, max_turns_per_objective=1, allow_reproduction=True,
            allow_screenshots=False, stop_on_http_5xx=True,
        )
        self.app = Application(
            self.repo,
            config=AppConfig(database_path=self.repo.path, evidence_root=self.root / "evidence"),
            target_client=TargetClient(timeout_seconds=2),
        )

    def tearDown(self) -> None:
        self.repo.close()
        self.temp.cleanup()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def _configure(self, contracts: list[dict]) -> dict:
        status, target = self.app.dispatch(
            "PATCH",
            f"/api/projects/{self.project['id']}/targets/{self.target['id']}/assessment-contracts",
            {"contracts": contracts},
        )
        self.assertEqual(status, 200)
        self.target = target
        return target

    def _run(self, *, technique_ids: list[str], objective_ids: list[str] | None = None) -> dict:
        objectives = self.repo.get_objectives(self.project["id"], objective_ids or [])
        plan = build_assessment_plan(
            technique_ids=technique_ids,
            objectives=objectives,
            target_capabilities=assessment_target_capabilities(self.target),
            assessment_contracts=self.target.get("assessment_contracts") or [],
        )
        plan.update({
            "guardrail": self.guardrail,
            "adaptive_turns": 1,
            "recon": {"mode": "none", "profile": "configured"},
            "confirmation_policy": {"mode": "minimum-proof", "reproduction_attempts": 1, "stop_after_confirmed_technique": True},
        })
        run = run_assessment(
            self.repo,
            project_id=self.project["id"],
            target_id=self.target["id"],
            module_ids=plan["module_ids"],
            model_mode="offline",
            model_gateway=object(),
            target_client=TargetClient(timeout_seconds=2),
            browser_target_client=object(),
            evidence_store=EvidenceStore(self.root / "projects"),
            assessment_plan=plan,
        )
        return self.repo.get_run_detail(self.project["id"], run["id"])

    def test_contract_only_api_run_reproduces_and_links_complete_evidence(self) -> None:
        target = self._configure([security_contract("/prove")])
        contract = target["assessment_contracts"][0]
        self.assertEqual(contract["maximum_requests"], 2)
        self.assertEqual(contract["definition"]["reproduction"]["attempts"], 1)
        self.assertEqual(contract["definition"]["security_outcomes"][0]["reproduction_step_ids"], ["r_verify"])

        detail = self._run(technique_ids=["LLM03-DEPS"])
        self.assertEqual(detail["status"], "completed")
        self.assertEqual(detail["test_cases"], [])
        self.assertEqual(ContractTargetHandler.requests, ["/prove", "/prove"])
        self.assertEqual(len(detail["contract_runs"]), 1)
        contract_run = detail["contract_runs"][0]
        self.assertEqual(contract_run["assessment_run_id"], detail["id"])
        self.assertEqual(contract_run["counts"]["requests"], 2)
        self.assertEqual(contract_run["counts"]["assertions_failed"], 0)
        self.assertEqual(contract_run["context"]["security_outcomes"][0]["status"], "confirmed")
        self.assertEqual(len(contract_run["security_findings"]), 1)
        finding_event_ids = contract_run["security_findings"][0]["evidence_event_ids"]
        self.assertGreaterEqual(len(finding_event_ids), 4)
        self.assertTrue(set(finding_event_ids).issubset({event["id"] for event in contract_run["events"]}))
        requests = [event for event in contract_run["events"] if event["event_type"] == "request.sent"]
        responses = [event for event in contract_run["events"] if event["event_type"] == "response.received"]
        self.assertEqual(len(requests), 2)
        self.assertEqual(len(responses), 2)
        self.assertTrue(all("curl --silent" in event["details"]["curl_command"] for event in requests))
        self.assertTrue(all(event["details"]["raw_http_response"].startswith("HTTP/") for event in responses))
        terminal = [event for event in detail["events"] if event["event_type"].startswith("contract.") and event["details"].get("terminal")]
        self.assertEqual([(event["details"]["contract_id"], event["details"]["status"]) for event in terminal], [("security-proof", "completed")])
        quality = audit_assessment_run(detail)
        self.assertEqual(quality["planned"], quality["terminal"])
        self.assertEqual(quality["finding_count"], quality["confirmed_reproductions"])
        self.assertEqual([], quality["missing_finding_evidence"])
        technique = next(item for risk in detail["owasp_coverage"]["risks"] for item in risk["techniques"] if item["id"] == "LLM03-DEPS")
        self.assertEqual(technique["status"], "confirmed")
        self.assertEqual(technique["attempts"], 1)

    def test_reproduced_contract_outcome_explicitly_satisfies_selected_objective(self) -> None:
        objective = self.repo.add_objective(
            self.project["id"],
            title="Confirm dependency trust-boundary failure",
            description="Exercise the documented verifier without broadening scope.",
            success_criteria="The target-owned dependency verifier reproduces the failed requirement.",
            expected_safe_behavior="The verifier reports that the dependency boundary held.",
            false_positive_exclusions="HTTP success, schema errors, and unreproduced responses do not count.",
            proof_mode="model-review",
            require_reproduction=True,
            risk_ids=["LLM03"],
            technique_ids=["LLM03-DEPS"],
        )
        target = self._configure([
            security_contract("/prove", objective_ids=[objective["id"]])
        ])
        compiled_outcome = target["assessment_contracts"][0]["definition"]["security_outcomes"][0]
        self.assertEqual(compiled_outcome["objective_ids"], [objective["id"]])

        detail = self._run(
            technique_ids=["LLM03-DEPS"],
            objective_ids=[objective["id"]],
        )

        self.assertEqual([item["id"] for item in detail["assessment_plan"]["objectives"]], [objective["id"]])
        outcome = detail["contract_runs"][0]["context"]["security_outcomes"][0]
        self.assertTrue(outcome["reproduction_confirmed"])
        self.assertEqual(len(outcome["objective_results"]), 1)
        result = outcome["objective_results"][0]
        self.assertEqual(result["objective_id"], objective["id"])
        self.assertTrue(result["achieved"])
        self.assertTrue(result["reproduction_confirmed"])
        self.assertEqual(result["proof_source"], "deterministic-target-contract")
        self.assertEqual(result["contract_id"], "security-proof")
        self.assertTrue(result["contract_sha256"])

    def test_contract_objective_link_is_ignored_when_objective_is_not_selected(self) -> None:
        objective = self.repo.add_objective(
            self.project["id"],
            title="Unselected contract objective",
            description="A valid reusable objective that is not selected for this run.",
            success_criteria="The documented verifier reproduces the failed requirement.",
            risk_ids=["LLM03"],
            technique_ids=["LLM03-DEPS"],
        )
        self._configure([security_contract("/prove", objective_ids=[objective["id"]])])

        detail = self._run(technique_ids=["LLM03-DEPS"])

        outcome = detail["contract_runs"][0]["context"]["security_outcomes"][0]
        self.assertEqual(outcome["objective_ids"], [])
        self.assertEqual(outcome["objective_results"], [])

    def test_contract_configuration_rejects_unknown_or_incompatible_objective_links(self) -> None:
        with self.assertRaisesRegex(ValueError, "outside this project"):
            self._configure([security_contract("/prove", objective_ids=["obj_missing"])])

        incompatible = self.repo.add_objective(
            self.project["id"],
            title="Sensitive disclosure objective",
            description="A differently mapped objective.",
            success_criteria="Protected response data is disclosed.",
            risk_ids=["LLM02"],
            technique_ids=["LLM02-SECRETS"],
        )
        with self.assertRaisesRegex(ValueError, "does not share an OWASP technique"):
            self._configure([security_contract("/prove", objective_ids=[incompatible["id"]])])

    def test_contract_only_lane_executes_every_remaining_conditionally_automatable_owasp_control(self) -> None:
        mappings = {
            "LLM01-MULTIMODAL": ("LLM01", "multimodal_failed"),
            "LLM03-MODEL": ("LLM03", "model_provenance_failed"),
            "LLM03-DEPS": ("LLM03", "dependency_integrity_failed"),
            "LLM04-DATA": ("LLM04", "training_integrity_failed"),
            "LLM04-BACKDOOR": ("LLM04", "backdoor_triggered"),
            "LLM10-TOKEN": ("LLM10", "input_limit_failed"),
            "LLM10-COST": ("LLM10", "quota_limit_failed"),
        }
        contract = {
            "id": "remaining-owasp-controls",
            "title": "Target-owned OWASP control matrix",
            "description": "Read the documented deterministic control verifier inside the approved request budget.",
            "enabled": True,
            "reproduce": True,
            "definition": {
                "steps": [{
                    "id": "verify_controls",
                    "name": "Read documented control outcomes",
                    "type": "http",
                    "method": "GET",
                    "path": "/prove",
                    "assertions": [
                        {"type": "status", "equals": 200, "label": "Verifier responded"},
                        *[
                            {
                                "type": "json_equals",
                                "path": f"$.controls.{field}",
                                "equals": True,
                                "label": f"Target verifier confirmed {technique_id}",
                            }
                            for technique_id, (_risk_id, field) in mappings.items()
                        ],
                    ],
                }],
                "security_outcomes": [
                    {
                        "id": f"control-{index}",
                        "kind": "security",
                        "title": f"Documented {technique_id} boundary failed",
                        "summary": "The target-owned verifier reproduced the configured failed security requirement.",
                        "severity": "high",
                        "confidence": 0.98,
                        "risk_ids": [risk_id],
                        "technique_ids": [technique_id],
                        "required_step_ids": ["verify_controls"],
                        "confirmation": "verifier",
                    }
                    for index, (technique_id, (risk_id, _field)) in enumerate(mappings.items(), start=1)
                ],
            },
        }
        self._configure([contract])

        plan = build_assessment_plan(
            technique_ids=list(mappings),
            target_capabilities=assessment_target_capabilities(self.target),
            assessment_contracts=self.target.get("assessment_contracts") or [],
            include_modules=False,
        )
        self.assertEqual(plan["module_ids"], [])
        self.assertEqual(plan["executable_technique_ids"], sorted(mappings))
        plan.update({
            "guardrail": self.guardrail,
            "adaptive_turns": 1,
            "recon": {"mode": "none", "profile": "configured"},
            "confirmation_policy": {"mode": "minimum-proof", "reproduction_attempts": 1},
        })
        run = run_assessment(
            self.repo,
            project_id=self.project["id"],
            target_id=self.target["id"],
            module_ids=[],
            model_mode="offline",
            model_gateway=object(),
            target_client=TargetClient(timeout_seconds=2),
            browser_target_client=object(),
            evidence_store=EvidenceStore(self.root / "projects"),
            assessment_plan=plan,
        )
        detail = self.repo.get_run_detail(self.project["id"], run["id"])

        self.assertEqual(detail["status"], "completed")
        self.assertEqual(ContractTargetHandler.requests, ["/prove", "/prove"])
        self.assertEqual(len(detail["contract_runs"][0]["security_findings"]), len(mappings))
        statuses = {
            item["id"]: item["status"]
            for risk in detail["owasp_coverage"]["risks"]
            for item in risk["techniques"]
            if item["id"] in mappings
        }
        self.assertEqual(statuses, {technique_id: "confirmed" for technique_id in mappings})

    def test_published_phase4_recipes_execute_as_bounded_reproduced_contracts(self) -> None:
        taxonomy = public_taxonomy()
        replacements = {
            "/TARGET_APPROVED_MULTIMODAL_ROUTE": "/multimodal",
            "TARGET_APPROVED_BENIGN_FIXTURE": "benign-fixture",
            "TARGET_APPROVED_ADVERSARIAL_FIXTURE": "adversarial-fixture",
            "TARGET_APPROVED_BENIGN_REQUEST": "Summarize the approved fixture.",
            "/TARGET_APPROVED_MODEL_PROVENANCE_ROUTE": "/model-provenance",
            "/TARGET_APPROVED_DEPENDENCY_INTEGRITY_ROUTE": "/dependency-integrity",
            "/TARGET_APPROVED_TRAINING_INTEGRITY_ROUTE": "/training-integrity",
            "/TARGET_APPROVED_MODEL_EVALUATION_ROUTE": "/model-evaluation",
            "TARGET_APPROVED_BASELINE": "baseline-case",
            "TARGET_APPROVED_TRIGGER": "trigger-case",
            "/TARGET_APPROVED_INPUT_RESOURCE_ROUTE": "/input-resource",
            "TARGET_APPROVED_MAXIMUM_INPUT": "maximum-safe-profile",
            "/TARGET_APPROVED_RESOURCE_TELEMETRY_ROUTE": "/resource-telemetry",
            "/TARGET_APPROVED_BOUNDED_COST_PROBE_ROUTE": "/bounded-cost-probe",
            "TARGET_APPROVED_BOUNDED_COST_PROFILE": "single-safe-probe",
        }
        contracts = []
        phase4_recipe_ids = {
            "multimodal-instruction-boundary",
            "supply-chain-integrity",
            "poisoning-and-backdoor-differential",
            "bounded-resource-controls",
        }
        for recipe in taxonomy["contract_recipes"]:
            if recipe["id"] not in phase4_recipe_ids:
                continue
            for draft in recipe["contracts"]:
                encoded = json.dumps(draft)
                for source, target in replacements.items():
                    encoded = encoded.replace(source, target)
                configured = json.loads(encoded)
                configured["recipe_provenance"]["reviewed"] = True
                configured["recipe_provenance"]["reviewed_at"] = "2026-08-05T12:00:00Z"
                self.assertNotIn("TARGET_APPROVED_", json.dumps(configured))
                contracts.append(configured)

        self.guardrail = self.repo.save_guardrail(
            self.project["id"], self.target["id"], status="approved", max_requests=30,
            max_runtime_seconds=60, max_consecutive_errors=2, allow_active_recon=False,
            allow_multi_turn=False, max_turns_per_objective=1, allow_reproduction=True,
            allow_screenshots=False, stop_on_http_5xx=True,
        )
        target = self._configure(contracts)
        self.assertEqual(len(target["assessment_contracts"]), 7)
        self.assertTrue(all(contract["contract_sha256"] for contract in target["assessment_contracts"]))

        technique_ids = [
            "LLM01-MULTIMODAL", "LLM03-MODEL", "LLM03-DEPS", "LLM04-DATA",
            "LLM04-BACKDOOR", "LLM10-TOKEN", "LLM10-COST",
        ]
        detail = self._run(technique_ids=technique_ids)

        self.assertEqual(detail["status"], "completed")
        self.assertEqual(len(detail["contract_runs"]), 7)
        self.assertEqual(sum(run["counts"]["requests"] for run in detail["contract_runs"]), 22)
        self.assertEqual(sum(len(run["security_findings"]) for run in detail["contract_runs"]), 7)
        self.assertTrue(all(
            outcome["status"] == "confirmed"
            for run in detail["contract_runs"]
            for outcome in run["context"]["security_outcomes"]
        ))
        statuses = {
            item["id"]: item["status"]
            for risk in detail["owasp_coverage"]["risks"]
            for item in risk["techniques"]
            if item["id"] in technique_ids
        }
        self.assertEqual(statuses, {technique_id: "confirmed" for technique_id in technique_ids})

    def test_any_of_proof_variants_are_reproduced_as_a_separate_group(self) -> None:
        contract = security_contract("/prove", contract_id="alternative-proof")
        contract["definition"]["steps"].append({
            "id": "alternate",
            "name": "Try the alternate bounded proof",
            "type": "http",
            "method": "GET",
            "path": "/safe",
            "assertions": [
                {"type": "status", "equals": 200},
                {"type": "json_equals", "path": "$.confirmed", "equals": True},
            ],
        })
        outcome = contract["definition"]["security_outcomes"][0]
        outcome["required_step_ids"] = []
        outcome["required_any_step_groups"] = [["verify", "alternate"]]

        target = self._configure([contract])
        compiled = target["assessment_contracts"][0]["definition"]
        compiled_outcome = compiled["security_outcomes"][0]
        self.assertEqual(
            compiled_outcome["required_any_step_groups"],
            [["verify", "alternate"], ["r_verify", "r_alternate"]],
        )
        self.assertEqual(compiled_outcome["reproduction_step_ids"], ["r_verify", "r_alternate"])

        detail = self._run(technique_ids=["LLM03-DEPS"])
        result = detail["contract_runs"][0]["context"]["security_outcomes"][0]
        self.assertEqual("confirmed", result["status"])
        self.assertEqual(
            [["verify"], ["r_verify"]],
            [group["matched_step_ids"] for group in result["group_results"]],
        )
        self.assertEqual(["r_verify"], result["reproduction_step_ids"])

    def test_blocked_contract_propagates_to_the_parent_assessment(self) -> None:
        self._configure([security_contract("/unavailable")])

        detail = self._run(technique_ids=["LLM03-DEPS"])

        self.assertEqual("blocked", detail["status"])
        self.assertEqual("blocked", detail["contract_runs"][0]["status"])
        terminal = [event for event in detail["events"] if event["event_type"] == "assessment.blocked"]
        self.assertEqual(1, len(terminal))
        self.assertTrue(terminal[0]["details"]["terminal"])

    def test_failed_proof_is_a_control_held_not_a_false_positive(self) -> None:
        self._configure([security_contract("/safe", contract_id="secure-control")])
        detail = self._run(technique_ids=["LLM03-DEPS"])
        contract_run = detail["contract_runs"][0]
        self.assertEqual(detail["status"], "completed")
        self.assertEqual(contract_run["context"]["security_outcomes"][0]["status"], "not_demonstrated")
        self.assertEqual(contract_run["security_findings"], [])
        technique = next(item for risk in detail["owasp_coverage"]["risks"] for item in risk["techniques"] if item["id"] == "LLM03-DEPS")
        self.assertEqual(technique["status"], "control_held")
        self.assertEqual(technique["attempts"], 1)

    def test_missing_route_response_is_inconclusive_not_a_false_pass(self) -> None:
        self._configure([security_contract("/missing-verifier", contract_id="missing-verifier")])

        detail = self._run(technique_ids=["LLM03-DEPS"])

        outcome = detail["contract_runs"][0]["context"]["security_outcomes"][0]
        self.assertEqual(outcome["status"], "inconclusive")
        self.assertFalse(outcome["determinate"])
        self.assertEqual(outcome["evidence_assurance"]["level"], "contract-inconclusive")
        self.assertTrue(any("precondition failed" in reason for state in outcome["step_determinacy"].values() for reason in state["reasons"]))
        self.assertEqual(detail["contract_runs"][0]["security_findings"], [])
        technique = next(item for risk in detail["owasp_coverage"]["risks"] for item in risk["techniques"] if item["id"] == "LLM03-DEPS")
        self.assertEqual(technique["status"], "inconclusive")

    def test_missing_evidence_selector_is_inconclusive_not_a_false_pass(self) -> None:
        self._configure([security_contract("/wrong-schema", contract_id="wrong-schema")])

        detail = self._run(technique_ids=["LLM03-DEPS"])

        contract_run = detail["contract_runs"][0]
        outcome = contract_run["context"]["security_outcomes"][0]
        self.assertEqual(outcome["status"], "inconclusive")
        self.assertFalse(outcome["determinate"])
        assertion_results = contract_run["context"]["assertion_results"]["verify"]["assertions"]
        missing_selector = next(item for item in assertion_results if item["type"] == "json_equals")
        self.assertFalse(missing_selector["evaluated"])
        technique = next(item for risk in detail["owasp_coverage"]["risks"] for item in risk["techniques"] if item["id"] == "LLM03-DEPS")
        self.assertEqual(technique["status"], "inconclusive")

    def test_methodology_outcome_is_recorded_without_claiming_a_vulnerability(self) -> None:
        self._configure([methodology_contract()])
        detail = self._run(technique_ids=[])
        contract_run = detail["contract_runs"][0]
        self.assertEqual(detail["status"], "completed")
        self.assertEqual(contract_run["context"]["security_outcomes"][0]["kind"], "methodology")
        self.assertEqual(contract_run["context"]["security_outcomes"][0]["status"], "confirmed")
        self.assertEqual(contract_run["security_findings"], [])
        self.assertEqual(self.repo.list_tool_findings(self.project["id"]), [])

    def test_security_observation_is_reviewable_without_becoming_a_finding_or_pass(self) -> None:
        self._configure([observation_contract()])
        detail = self._run(technique_ids=["LLM06-TOOLS"])
        contract_run = detail["contract_runs"][0]
        outcome = contract_run["context"]["security_outcomes"][0]
        self.assertEqual(outcome["kind"], "observation")
        self.assertEqual(outcome["status"], "confirmed")
        self.assertEqual(contract_run["security_findings"], [])
        self.assertEqual(self.repo.list_tool_findings(self.project["id"]), [])
        self.assertTrue(any(event["event_type"] == "security_observation.recorded" for event in contract_run["events"]))
        technique = next(
            item for risk in detail["owasp_coverage"]["risks"]
            for item in risk["techniques"] if item["id"] == "LLM06-TOOLS"
        )
        self.assertEqual(technique["status"], "inconclusive")
        self.assertEqual(technique["attempts"], 1)

    def test_unapproved_routes_budget_and_reproduction_permission_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "not in the target allowlist"):
            normalize_assessment_contracts([security_contract("/not-authorized")], self.target)

        self.repo.save_guardrail(
            self.project["id"], self.target["id"], status="approved", max_requests=1,
            max_runtime_seconds=60, max_consecutive_errors=2, allow_active_recon=False,
            allow_multi_turn=False, max_turns_per_objective=1, allow_reproduction=True,
            allow_screenshots=False, stop_on_http_5xx=True,
        )
        with self.assertRaisesRegex(ValueError, "exceeding the approved target limit"):
            self._configure([security_contract("/prove")])

        self.repo.save_guardrail(
            self.project["id"], self.target["id"], status="approved", max_requests=12,
            max_runtime_seconds=60, max_consecutive_errors=2, allow_active_recon=False,
            allow_multi_turn=False, max_turns_per_objective=1, allow_reproduction=False,
            allow_screenshots=False, stop_on_http_5xx=True,
        )
        with self.assertRaisesRegex(ValueError, "require reproduction permission"):
            self._configure([security_contract("/prove")])

    def test_one_shot_security_contract_is_rejected_but_explicit_reproduction_is_allowed(self) -> None:
        one_shot = security_contract("/prove")
        one_shot["reproduce"] = False
        with self.assertRaisesRegex(ValueError, "explicit reproduction_step_ids"):
            normalize_assessment_contracts([one_shot], self.target)

        explicit = security_contract("/prove")
        explicit["reproduce"] = False
        explicit["definition"]["steps"].append({
            "id": "verify_again", "name": "Repeat the verifier", "type": "http", "method": "GET", "path": "/prove",
            "assertions": [{"type": "json_equals", "path": "$.confirmed", "equals": True}],
        })
        outcome = explicit["definition"]["security_outcomes"][0]
        outcome["required_step_ids"] = ["verify", "verify_again"]
        outcome["reproduction_step_ids"] = ["verify_again"]
        normalized = normalize_assessment_contracts([explicit], self.target)
        self.assertEqual(normalized[0]["definition"]["security_outcomes"][0]["reproduction_step_ids"], ["verify_again"])

    def test_compiled_contract_round_trips_without_duplicate_reproduction_steps(self) -> None:
        first = normalize_assessment_contracts([security_contract("/prove")], self.target)
        second = normalize_assessment_contracts(first, self.target)

        self.assertEqual(first[0]["definition"], second[0]["definition"])
        self.assertEqual(first[0]["source_definition"], second[0]["source_definition"])
        self.assertEqual(["verify", "r_verify"], [step["id"] for step in second[0]["definition"]["steps"]])
        self.assertEqual(["verify"], [step["id"] for step in second[0]["source_definition"]["steps"]])

    def test_recipe_contract_requires_resolved_values_and_explicit_review(self) -> None:
        unresolved = security_contract("/prove", contract_id="recipe-proof")
        unresolved["definition"]["steps"][0]["body"] = {"fixture": "TARGET_APPROVED_FIXTURE"}
        with self.assertRaisesRegex(ValueError, "unresolved recipe values"):
            normalize_assessment_contracts([unresolved], self.target)

        recipe = security_contract("/prove", contract_id="recipe-proof")
        recipe["recipe_provenance"] = {
            "recipe_id": "supply-chain-integrity",
            "recipe_version": "2026.08.2",
            "reviewed": False,
        }
        with self.assertRaisesRegex(ValueError, "unreviewed recipe"):
            normalize_assessment_contracts([recipe], self.target)

        recipe["recipe_provenance"]["reviewed"] = True
        recipe["recipe_provenance"]["reviewed_at"] = "2026-08-05T12:00:00Z"
        target = self._configure([recipe])
        stored = target["assessment_contracts"][0]
        self.assertRegex(stored["contract_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(stored["recipe_provenance"]["recipe_id"], "supply-chain-integrity")
        self.assertTrue(stored["recipe_provenance"]["reviewed"])

        round_tripped = normalize_assessment_contracts([stored], self.target)[0]
        self.assertEqual(round_tripped["contract_sha256"], stored["contract_sha256"])
        changed_metadata = {**stored, "description": "A materially revised customer contract."}
        revised = normalize_assessment_contracts([changed_metadata], self.target)[0]
        self.assertNotEqual(revised["contract_sha256"], stored["contract_sha256"])

        detail = self._run(technique_ids=["LLM03-DEPS"])
        contract_run = detail["contract_runs"][0]
        self.assertEqual(contract_run["definition"]["assessment_contract"]["contract_sha256"], stored["contract_sha256"])
        started = next(event for event in detail["events"] if event["event_type"] == "contract.started")
        self.assertEqual(started["details"]["contract_sha256"], stored["contract_sha256"])
        self.assertEqual(started["details"]["recipe_provenance"]["recipe_version"], "2026.08.2")

    def test_contract_run_and_findings_cannot_cross_project_boundaries(self) -> None:
        self._configure([security_contract("/prove")])
        detail = self._run(technique_ids=["LLM03-DEPS"])
        other = self.repo.create_project(name="Other project")
        with self.assertRaises(NotFoundError):
            self.repo.get_tool_run(other["id"], detail["contract_runs"][0]["id"])
        self.assertEqual(self.repo.list_tool_findings(other["id"]), [])
        with self.assertRaises(NotFoundError):
            self.repo.get_run_detail(other["id"], detail["id"])

    def test_api_contract_does_not_schedule_an_unrelated_chatbot_module(self) -> None:
        contract = security_contract("/prove")
        outcome = contract["definition"]["security_outcomes"][0]
        outcome["risk_ids"] = ["LLM02"]
        outcome["technique_ids"] = ["LLM02-CONTEXT"]
        contract["risk_ids"] = ["LLM02"]
        contract["technique_ids"] = ["LLM02-CONTEXT"]

        plan = build_assessment_plan(
            technique_ids=["LLM02-CONTEXT"],
            target_capabilities={"chat_prompt_adapter": False},
            assessment_contracts=[contract],
        )

        self.assertEqual(plan["module_ids"], [])
        self.assertEqual([item["id"] for item in plan["assessment_contracts"]], [contract["id"]])
        self.assertIn("LLM02-CONTEXT", plan["executable_technique_ids"])

    def test_explicit_chat_adapter_opt_out_survives_capability_resolution(self) -> None:
        retrieval_only = assessment_target_capabilities({
            "kind": "chatbot",
            "capabilities": {"rag": True, "retrieval_only": True},
            "assessment_contracts": [],
        })
        normal_chat = assessment_target_capabilities({
            "kind": "chatbot",
            "capabilities": {"rag": True},
            "assessment_contracts": [],
        })

        self.assertFalse(retrieval_only["chat_prompt_adapter"])
        self.assertTrue(normal_chat["chat_prompt_adapter"])

        stored = self.repo.update_target_capabilities(
            self.project["id"], self.target["id"], {"retrieval_only": True, "chat_prompt_adapter": False}
        )
        self.assertTrue(stored["capabilities"]["retrieval_only"])
        self.assertFalse(stored["capabilities"]["chat_prompt_adapter"])

    def test_chatbot_contract_keeps_the_reviewed_chatbot_module_when_supported(self) -> None:
        contract = security_contract("/prove")
        outcome = contract["definition"]["security_outcomes"][0]
        outcome["risk_ids"] = ["LLM02"]
        outcome["technique_ids"] = ["LLM02-CONTEXT"]
        contract["risk_ids"] = ["LLM02"]
        contract["technique_ids"] = ["LLM02-CONTEXT"]

        plan = build_assessment_plan(
            technique_ids=["LLM02-CONTEXT"],
            target_capabilities={"chat_prompt_adapter": True},
            assessment_contracts=[contract],
        )

        self.assertEqual(plan["module_ids"], ["sensitive-disclosure"])

    def test_contract_only_lane_omits_the_generic_chatbot_module(self) -> None:
        contract = security_contract("/prove")
        outcome = contract["definition"]["security_outcomes"][0]
        outcome["risk_ids"] = ["LLM02"]
        outcome["technique_ids"] = ["LLM02-CONTEXT"]
        contract["risk_ids"] = ["LLM02"]
        contract["technique_ids"] = ["LLM02-CONTEXT"]

        plan = build_assessment_plan(
            technique_ids=["LLM02-CONTEXT"],
            target_capabilities={"chat_prompt_adapter": True},
            assessment_contracts=[contract],
            include_modules=False,
        )

        self.assertEqual(plan["execution_mode"], "contracts-only")
        self.assertEqual(plan["module_ids"], [])
        self.assertEqual([item["id"] for item in plan["assessment_contracts"]], [contract["id"]])
        self.assertIn("LLM02-CONTEXT", plan["executable_technique_ids"])

    def test_contract_backed_agency_technique_does_not_require_legacy_cases(self) -> None:
        contract = security_contract("/prove")
        outcome = contract["definition"]["security_outcomes"][0]
        outcome["risk_ids"] = ["LLM06"]
        outcome["technique_ids"] = ["LLM06-TOOLS"]
        contract["risk_ids"] = ["LLM06"]
        contract["technique_ids"] = ["LLM06-TOOLS"]

        plan = build_assessment_plan(
            technique_ids=["LLM06-TOOLS"],
            target_capabilities={"chat_prompt_adapter": True, "tools": True},
            evaluation_config={},
            assessment_contracts=[contract],
        )

        self.assertEqual(plan["module_ids"], [])
        self.assertEqual([item["id"] for item in plan["assessment_contracts"]], [contract["id"]])


if __name__ == "__main__":
    unittest.main()
