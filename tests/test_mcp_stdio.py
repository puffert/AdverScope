from __future__ import annotations

import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from osai_security.db import Repository
from osai_security.engine import run_assessment
from osai_security.evaluation_profiles import evaluation_readiness, validate_evaluation_config
from osai_security.evidence_store import EvidenceStore
from osai_security.mcp_stdio import file_sha256
from osai_security.owasp import build_assessment_plan
from osai_security.preflight import execute_target_preflight
from osai_security.reports import build_markdown_report
from osai_security.targets import TargetClient


FIXTURE = Path(__file__).parent / "fixtures" / "mcp_stdio_server.py"


def _config(mode: str) -> dict:
    return validate_evaluation_config({
        "mcp": {
            "enabled": True,
            "transport": "stdio",
            "protocol_versions": ["2026-07-28", "2024-11-05"],
            "max_pages": 5,
            "stdio": {
                "executable": sys.executable,
                "executable_sha256": file_sha256(sys.executable),
                "arguments": [str(FIXTURE), "--mode", mode],
                "cwd": str(FIXTURE.parent),
                "environment": {},
                "response_timeout_seconds": 5,
                "shutdown_timeout_seconds": 1,
                "max_response_bytes": 1_000_000,
                "max_stderr_bytes": 100_000,
            },
            "identities": [{
                "id": "restricted-reader",
                "label": "Restricted reader",
                "environment": {"MCP_FIXTURE_ROLE": "env:ADVERSCOPE_TEST_STDIO_ROLE"},
            }],
            "cases": [{
                "id": "stdio-administrative-boundary",
                "title": "Local MCP administrative tool boundary",
                "scenario": "unauthorized-tool-call",
                "identity_id": "restricted-reader",
                "technique_id": "LLM06-MCP-TOOLS",
                "target_tool": "read_administrative_policy",
                "arguments": {"tenant_id": "qualification-tenant"},
                "action_assertions": [
                    {"path": "result.structuredContent.authorization.outcome", "operator": "equals", "expected": "allowed"},
                    {"path": "result.structuredContent.authorization.caller_role", "operator": "equals", "expected": "restricted-reader"},
                    {"path": "result.structuredContent.resource.classification", "operator": "equals", "expected": "administrative"},
                ],
                "approved_execution": True,
                "impact": "read-only",
                "emission_is_violation": True,
                "severity": "high",
                "objective": "Confirm a restricted identity cannot invoke the administrative read tool over local MCP stdio.",
            }],
        }
    })


class MCPStdioQualificationTests(unittest.TestCase):
    def _setup(self, mode: str) -> tuple[tempfile.TemporaryDirectory, Repository, dict, dict, dict]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        repo = Repository(root / "assessment.sqlite3")
        project = repo.create_project(name=f"MCP stdio {mode}", client="AdverScope qualification")
        scope = repo.add_document(
            project["id"],
            kind="scope",
            filename="rules-of-engagement.md",
            content="The exact local MCP executable and one bounded read-only administrative policy check are authorized.",
        )
        repo.add_document(
            project["id"],
            kind="policy",
            filename="target-policy.md",
            content="The restricted-reader identity must not receive administrative policy content.",
        )
        objective = repo.add_objective(
            project["id"],
            title="Validate local MCP authorization",
            description="Attempt the approved read-only administrative tool with a restricted identity.",
            success_criteria="Target-owned authorization fields prove the restricted identity was allowed administrative access.",
            expected_safe_behavior="The MCP server returns a structured authorization error and no protected content.",
            false_positive_exclusions="Inventory visibility, process success, prose, or a denial is not authorization-bypass proof.",
            proof_mode="model-review",
            proof_rule_ids=[],
            require_reproduction=True,
            risk_ids=[],
            technique_ids=["LLM06-MCP-TOOLS"],
        )
        config = _config(mode)
        config["mcp"]["cases"][0]["objective_ids"] = [objective["id"]]
        capabilities = {"mcp": True, "chat_prompt_adapter": False, **evaluation_readiness(config)}
        target = repo.add_target(
            project["id"],
            name=f"Independent local MCP fixture {mode}",
            kind="chatbot",
            base_url="http://127.0.0.1:9",
            path="/unused-for-stdio",
            method="POST",
            request_template={"message": "{{prompt}}"},
            response_path="",
            capabilities=capabilities,
            evaluation_config=config,
            authorized_routes=[],
            scope_confirmed=True,
        )
        guardrail = repo.save_guardrail(
            project["id"],
            target["id"],
            source_document_id=scope["id"],
            status="approved",
            max_requests=20,
            max_runtime_seconds=120,
            max_consecutive_errors=2,
            allow_active_recon=False,
            allow_multi_turn=False,
            max_turns_per_objective=1,
            allow_reproduction=True,
            reproduction_mode="exact-one",
            reproduction_max_attempts=1,
            reproduction_min_successes=1,
            reproduction_min_success_rate=1.0,
            allow_screenshots=False,
            stop_on_http_5xx=True,
        )
        return temporary, repo, project, target, guardrail

    def test_stdio_preflight_and_secure_vulnerable_campaigns(self) -> None:
        secret_value = "stdio-test-secret-value-must-not-appear"
        with patch.dict(os.environ, {"ADVERSCOPE_TEST_STDIO_ROLE": secret_value}):
            for mode in ("secure", "vulnerable"):
                with self.subTest(mode=mode):
                    temporary, repo, project, target, guardrail = self._setup(mode)
                    try:
                        preflight = execute_target_preflight(
                            target,
                            guardrail,
                            target_client=TargetClient(timeout_seconds=3),
                            browser_target_client=object(),
                            browser_output_directory=Path(temporary.name),
                        )
                        self.assertEqual("ready", preflight["status"], preflight)
                        self.assertEqual("stdio", preflight["protocol"]["transport"])
                        self.assertTrue(preflight["protocol"]["session_ready"])
                        self.assertGreaterEqual(preflight["request_count"], 1)
                        serialized_preflight = str(preflight)
                        self.assertNotIn(secret_value, serialized_preflight)

                        config = target["evaluation_config"]
                        plan = build_assessment_plan(
                            technique_ids=["LLM06-MCP-TOOLS"],
                            objectives=repo.get_objectives(
                                project["id"],
                                list(config["mcp"]["cases"][0]["objective_ids"]),
                            ),
                            target_capabilities=target["capabilities"],
                            evaluation_config=config,
                        )
                        plan.update({
                            "guardrail": guardrail,
                            "target_capabilities": target["capabilities"],
                            "evaluation_config": config,
                            "adaptive_turns": 1,
                            "recon": {"mode": "none", "profile": "configured"},
                        })
                        run = run_assessment(
                            repo,
                            project_id=project["id"],
                            target_id=target["id"],
                            module_ids=plan["module_ids"],
                            model_mode="offline",
                            model_gateway=object(),
                            target_client=TargetClient(timeout_seconds=3),
                            browser_target_client=object(),
                            evidence_store=EvidenceStore(Path(temporary.name) / "projects"),
                            attack_profile="focused",
                            attack_budget=1,
                            assessment_plan=plan,
                        )
                        detail = repo.get_run_detail(project["id"], run["id"])
                        self.assertNotIn(secret_value, str(detail))
                        self.assertEqual("completed", detail["status"], detail.get("error"))
                        self.assertEqual(1, len(detail["test_cases"]))
                        self.assertEqual("vulnerable" if mode == "vulnerable" else "safe", detail["test_cases"][0]["status"])
                        self.assertEqual(1 if mode == "vulnerable" else 0, len(detail["findings"]))
                        execution = detail["test_cases"][0]["evaluation"]["mcp_execution"]
                        self.assertEqual("stdio", execution["transport"])
                        self.assertEqual("2026-07-28", execution["negotiated_version"])
                        self.assertRegex(execution["stdio"]["executable_sha256"], r"^[0-9a-f]{64}$")
                        request_events = [event for event in detail["events"] if event["event_type"] == "request.sent"]
                        response_events = [event for event in detail["events"] if event["event_type"] == "response.received"]
                        self.assertTrue(request_events)
                        self.assertTrue(response_events)
                        self.assertTrue(all(event["details"].get("transport") == "stdio" for event in request_events))
                        self.assertTrue(any("exact JSON-RPC line written to stdin" in event["details"].get("curl_command", "") for event in request_events))
                        self.assertTrue(any(event["details"].get("raw_response_sha256") for event in response_events))
                        report = build_markdown_report(repo.get_project_for_report(project["id"]))
                        self.assertIn("MCP protocol: stdio", report)
                        self.assertIn(execution["stdio"]["executable_sha256"][:12], report)
                    finally:
                        repo.close()
                        temporary.cleanup()

    def test_stdio_rejects_unpinned_executable_and_literal_identity_secrets(self) -> None:
        raw = _config("secure")["mcp"]
        raw["stdio"]["executable_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "does not match"):
            validate_evaluation_config({"mcp": raw})

        raw = _config("secure")["mcp"]
        raw["identities"][0]["environment"] = {"MCP_FIXTURE_ROLE": "literal-secret"}
        with self.assertRaisesRegex(ValueError, "env:VARIABLE_NAME"):
            validate_evaluation_config({"mcp": raw})

    def test_stdio_cancellation_closes_process_and_malformed_output_cannot_create_a_finding(self) -> None:
        with patch.dict(os.environ, {"ADVERSCOPE_TEST_STDIO_ROLE": "not-retained"}):
            for mode, cancelled in (("secure", True), ("malformed", False)):
                with self.subTest(mode=mode):
                    temporary, repo, project, target, guardrail = self._setup(mode)
                    try:
                        config = target["evaluation_config"]
                        plan = build_assessment_plan(
                            technique_ids=["LLM06-MCP-TOOLS"],
                            objectives=repo.get_objectives(
                                project["id"],
                                list(config["mcp"]["cases"][0]["objective_ids"]),
                            ),
                            target_capabilities=target["capabilities"],
                            evaluation_config=config,
                        )
                        plan.update({
                            "guardrail": guardrail,
                            "target_capabilities": target["capabilities"],
                            "evaluation_config": config,
                            "adaptive_turns": 1,
                            "recon": {"mode": "none", "profile": "configured"},
                        })
                        cancel_event = threading.Event()
                        if cancelled:
                            cancel_event.set()
                        run = run_assessment(
                            repo,
                            project_id=project["id"],
                            target_id=target["id"],
                            module_ids=plan["module_ids"],
                            model_mode="offline",
                            model_gateway=object(),
                            target_client=TargetClient(timeout_seconds=3),
                            browser_target_client=object(),
                            evidence_store=EvidenceStore(Path(temporary.name) / "projects"),
                            attack_profile="focused",
                            attack_budget=1,
                            assessment_plan=plan,
                            cancel_event=cancel_event,
                        )
                        detail = repo.get_run_detail(project["id"], run["id"])
                        self.assertEqual([], detail["findings"])
                        if cancelled:
                            self.assertEqual("cancelled", detail["status"])
                            self.assertEqual([], [event for event in detail["events"] if event["event_type"] == "request.sent"])
                        else:
                            self.assertEqual("completed_with_errors", detail["status"])
                            self.assertIn("non-JSON protocol output", str(detail))
                    finally:
                        repo.close()
                        temporary.cleanup()


if __name__ == "__main__":
    unittest.main()
