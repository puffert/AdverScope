from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from osai_security.config import AppConfig
from osai_security.db import Repository
from osai_security.http_app import Application
from osai_security.run_insights import build_run_result_summary, compare_runs
from osai_security.target_profiles import (
    TARGET_PROFILE_SCHEMA_VERSION,
    export_target_profile,
    public_target_profiles,
    target_profile_readiness,
    validate_target_profile_document,
)


def synthetic_run(run_id: str, *, vulnerable: bool, selected: list[str] | None = None) -> dict:
    selected = selected or ["LLM01-DIRECT"]
    finding = {
        "id": f"find_{run_id}",
        "fingerprint": "stable-prompt-injection",
        "title": "Direct instruction override",
        "severity": "high",
        "status": "open",
        "module_id": "prompt-injection",
        "occurrences": [{
            "run_id": run_id,
            "evaluation": {"owasp_technique_ids": ["LLM01-DIRECT"]},
        }] if vulnerable else [],
        "validations": [{"id": f"val_{run_id}", "run_id": run_id, "status": "confirmed"}] if vulnerable else [],
    }
    return {
        "id": run_id,
        "project_id": "proj_test",
        "target_id": "tgt_test",
        "status": "completed",
        "model_mode": "offline",
        "attack_profile": "focused",
        "attack_budget": 4,
        "module_ids": ["prompt-injection"],
        "target": {"id": "tgt_test", "kind": "chatbot", "base_url": "http://127.0.0.1:1", "path": "/chat", "method": "POST"},
        "assessment_plan": {
            "taxonomy_version": "2025",
            "selected_technique_ids": selected,
            "executable_technique_ids": selected,
            "unsupported_technique_ids": [],
            "target_adapter_snapshot": {"kind": "chatbot", "authorized_routes": [{"method": "POST", "path": "/chat"}]},
            "guardrail": {"status": "approved", "max_requests": 20},
            "attack_catalog": {"id": "reviewed", "version": "1"},
            "objectives": [],
        },
        "manifest": {},
        "events": [],
        "test_cases": [{
            "id": f"case_{run_id}",
            "status": "vulnerable" if vulnerable else "safe",
            "generation_source": "offline-baseline",
            "evaluation": {
                "execution_source": "native-reviewed",
                "owasp_technique_ids": ["LLM01-DIRECT"],
            },
        }],
        "findings": [finding] if vulnerable else [],
        "contract_runs": [],
    }


class TargetProfileTests(unittest.TestCase):
    def test_catalog_covers_every_milestone_profile_without_target_assumptions(self) -> None:
        catalog = public_target_profiles()
        ids = {item["id"] for item in catalog["profiles"]}
        self.assertEqual(
            ids,
            {
                "generic-json-chatbot", "openai-compatible-api", "ollama-compatible-api",
                "browser-chatbot", "tool-calling-agent", "mcp-server", "rag-application",
                "artifact-assessment",
            },
        )
        self.assertFalse(catalog["safety"]["creates_target"])
        for profile in catalog["profiles"]:
            self.assertNotIn("defaults", profile)
            self.assertIn("operator_note", profile)

    def test_profile_import_is_versioned_review_only_and_rejects_literal_secret_headers(self) -> None:
        document = {
            "schema_version": TARGET_PROFILE_SCHEMA_VERSION,
            "profile_id": "generic-json-chatbot",
            "target": {
                "name": "Imported draft",
                "kind": "chatbot",
                "base_url": "https://authorized.example",
                "path": "/documented",
                "method": "POST",
                "headers": {"Authorization": "env:CUSTOMER_TOKEN"},
                "request_template": {"question": "{{prompt}}"},
            },
        }
        result = validate_target_profile_document(document)
        self.assertFalse(result["creates_target"])
        self.assertFalse(result["target_draft"]["scope_confirmed"])
        self.assertEqual(result["target_draft"]["headers"]["Authorization"], "env:CUSTOMER_TOKEN")
        document["target"]["headers"]["Authorization"] = "literal-secret"
        with self.assertRaisesRegex(ValueError, "literal sensitive"):
            validate_target_profile_document(document)

    def test_export_omits_sensitive_sections_and_literal_sensitive_headers(self) -> None:
        exported = export_target_profile({
            "name": "Target",
            "kind": "chatbot",
            "base_url": "https://authorized.example",
            "path": "/chat",
            "method": "POST",
            "headers": {"Authorization": "literal", "Content-Type": "application/json"},
            "request_template": {"message": "{{prompt}}"},
            "evaluation_config": {"canaries": [{"expected_sha256": "secret-digest"}]},
            "scope_confirmed": True,
        })
        self.assertNotIn("evaluation_config", exported["target"])
        self.assertNotIn("scope_confirmed", exported["target"])
        self.assertEqual(exported["target"]["headers"], {"Content-Type": "application/json"})
        self.assertIn("Authorization", exported["review"]["omitted_sensitive_headers"])

    def test_profile_readiness_is_capability_specific_and_not_a_security_verdict(self) -> None:
        target = {
            "id": "tgt_1", "kind": "api", "base_url": "https://authorized.example",
            "path": "/mcp", "method": "POST", "request_template": {"message": "{{prompt}}"},
            "capabilities": {"mcp": True, "tools": True},
            "evaluation_config": {"mcp": {"enabled": True}},
        }
        result = target_profile_readiness(
            "mcp-server", target, has_scope=True, has_policy=True,
            guardrail={"status": "approved"},
        )
        self.assertTrue(result["ready"])
        self.assertIn("not a security verdict", result["statement"])


class RunInsightTests(unittest.TestCase):
    def test_result_summary_separates_selected_executed_reproduced_and_not_tested(self) -> None:
        run = synthetic_run("run_one", vulnerable=True, selected=["LLM01-DIRECT", "LLM01-SUFFIX", "LLM02-SECRETS"])
        run["assessment_plan"]["unsupported_technique_ids"] = ["LLM02-SECRETS"]
        run["events"] = [{"id": "ev_skip", "event_type": "variant.skipped", "title": "Minimum proof", "details": {"planned_technique_ids": ["LLM01-SUFFIX"], "reason": "Already reproduced."}}]
        summary = build_run_result_summary(run)
        self.assertEqual(summary["counts"]["selected_techniques"], 3)
        self.assertEqual(summary["counts"]["reviewed_executed_cases"], 1)
        self.assertEqual(summary["counts"]["reproduced_techniques"], 1)
        self.assertIn("LLM01-SUFFIX", summary["technique_ids"]["not_tested"])
        self.assertIn("LLM02-SECRETS", summary["technique_ids"]["unsupported"])
        self.assertEqual(summary["skipped"][0]["reason"], "Already reproduced.")

    def test_comparison_is_run_scoped_and_conservative_about_fixed_findings(self) -> None:
        baseline = synthetic_run("run_before", vulnerable=True)
        current = synthetic_run("run_after", vulnerable=False)
        comparison = compare_runs(baseline, current)
        self.assertTrue(comparison["configuration_equivalent"])
        self.assertEqual(comparison["security_outcomes"][0]["status"], "non-reproduced")
        baseline["findings"][0]["status"] = "fixed"
        fixed = compare_runs(baseline, current)
        self.assertEqual(fixed["security_outcomes"][0]["status"], "fixed")
        current["model_mode"] = "asus"
        changed = compare_runs(baseline, current)
        self.assertFalse(changed["configuration_equivalent"])
        self.assertIn("model", changed["changed_sections"])


class RetestApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        root = Path(self.directory.name)
        self.config = AppConfig(database_path=root / "assessment.sqlite3", evidence_root=root / "projects")
        self.repo = Repository(self.config.database_path)
        self.app = Application(self.repo, config=self.config, model_gateway=object())  # type: ignore[arg-type]
        self.project = self.repo.create_project(name="Retest project")
        project_id = self.project["id"]
        self.repo.add_document(project_id, kind="scope", filename="scope.md", content="Authorized target and non-destructive security testing.")
        self.repo.add_document(project_id, kind="policy", filename="policy.md", content="The assistant must not follow untrusted instructions.")
        self.target = self.repo.add_target(
            project_id,
            name="Synthetic chatbot", kind="chatbot", base_url="http://127.0.0.1:19999",
            path="/chat", method="POST", request_template={"message": "{{prompt}}"},
            scope_confirmed=True,
        )
        self.repo.save_guardrail(
            project_id, self.target["id"], status="approved", max_requests=20,
            max_runtime_seconds=120, max_consecutive_errors=2,
            allow_reproduction=True, allow_multi_turn=False,
        )
        self.source = self.repo.create_run(
            project_id, self.target["id"], ["prompt-injection"], "offline",
            attack_profile="focused", attack_budget=4,
            assessment_plan={
                "taxonomy_version": "2025",
                "selected_risk_ids": [],
                "selected_technique_ids": ["LLM01-DIRECT"],
                "executable_technique_ids": ["LLM01-DIRECT"],
                "unsupported_technique_ids": [],
                "objectives": [],
                "adaptive_turns": 1,
                "recon": {"mode": "none", "profile": "configured"},
                "target_adapter_snapshot": {"kind": "chatbot"},
            },
        )
        self.repo.complete_run(project_id, self.source["id"], status="completed")

    def tearDown(self) -> None:
        self.app.close()
        self.repo.close()
        self.directory.cleanup()

    def test_retest_requires_explicit_approval_and_creates_a_new_immutable_run(self) -> None:
        path = f"/api/projects/{self.project['id']}/runs/{self.source['id']}/retest"
        with self.assertRaisesRegex(ValueError, "explicit approval"):
            self.app.dispatch("POST", path, {"change_note": "Exact retest of the accepted baseline."})
        self.repo.pin_methodology_card(self.project["id"], "boundary-first-reasoning")
        with mock.patch("osai_security.http_app.threading.Thread") as thread:
            status, created = self.app.dispatch("POST", path, {
                "approved": True,
                "change_note": "Exact retest of the accepted baseline after remediation.",
                "target_id": self.target["id"],
                "model_mode": "offline",
                "attack_profile": "focused",
            })
        self.assertEqual(status, 202)
        self.assertNotEqual(created["id"], self.source["id"])
        self.assertEqual(created["retest"]["source_run_id"], self.source["id"])
        self.assertTrue(created["retest"]["immutable_source"])
        methodology_change = next(
            item for item in created["retest"]["approved_changes"]
            if item["field"] == "assessment_methodology"
        )
        self.assertEqual(methodology_change["before"], [])
        self.assertEqual(methodology_change["after"][0]["id"], "boundary-first-reasoning")
        thread.return_value.start.assert_called_once()


if __name__ == "__main__":
    unittest.main()
