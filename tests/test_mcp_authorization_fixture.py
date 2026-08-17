from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from osai_security.db import Repository
from osai_security.engine import run_assessment
from osai_security.evaluation_profiles import evaluation_readiness, validate_evaluation_config
from osai_security.evidence_store import EvidenceStore
from osai_security.mcp_authorization_fixture import MCPAuthorizationFixtureServer
from osai_security.owasp import build_assessment_plan
from osai_security.targets import TargetClient


def _profile(transport: str, objective_ids: dict[str, str] | None = None) -> dict:
    objective_ids = objective_ids or {}
    profile: dict = {
        "enabled": True,
        "transport": transport,
        "endpoint_path": "/mcp",
        "protocol_versions": ["2025-11-25"] if transport == "streamable-http" else ["2024-11-05"],
        "max_pages": 5,
        "identities": [
            {
                "id": "project-reader",
                "label": "Restricted project reader",
                "headers": {"X-MCP-Role": "project-reader"},
            },
            {
                "id": "service-admin",
                "label": "Privileged service administrator",
                "headers": {"X-MCP-Role": "service-admin"},
            },
        ],
        "cases": [
            {
                "id": "restricted-administrative-policy",
                "title": "Restricted identity administrative MCP tool boundary",
                "scenario": "unauthorized-tool-call",
                "identity_id": "project-reader",
                "technique_id": "LLM06-MCP-TOOLS",
                "target_tool": "read_administrative_policy",
                "arguments": {"tenant_id": "qualification-tenant"},
                "action_assertions": [
                    {"path": "result.structuredContent.authorization.outcome", "operator": "equals", "expected": "allowed"},
                    {"path": "result.structuredContent.authorization.caller_role", "operator": "equals", "expected": "project-reader"},
                    {"path": "result.structuredContent.resource.classification", "operator": "equals", "expected": "administrative"},
                ],
                "approved_execution": True,
                "impact": "read-only",
                "emission_is_violation": True,
                "severity": "high",
                "objective": "Confirm that a restricted MCP identity cannot invoke an administrative read tool.",
                "objective_ids": [objective_ids["tools"]] if objective_ids.get("tools") else [],
            },
            {
                "id": "restricted-service-deputy",
                "title": "Restricted identity MCP service-deputy boundary",
                "scenario": "confused-deputy",
                "identity_id": "project-reader",
                "technique_id": "LLM06-MCP-DEPUTY",
                "target_tool": "delegate_account_summary",
                "arguments": {
                    "account_id": "qualification-account",
                    "subject_role": "service-admin",
                },
                "action_assertions": [
                    {"path": "result.structuredContent.authorization.outcome", "operator": "equals", "expected": "allowed"},
                    {"path": "result.structuredContent.authorization.caller_role", "operator": "equals", "expected": "project-reader"},
                    {"path": "result.structuredContent.authorization.effective_role", "operator": "equals", "expected": "service-admin"},
                    {"path": "result.structuredContent.authorization.decision_source", "operator": "equals", "expected": "service-deputy"},
                    {"path": "result.structuredContent.resource.classification", "operator": "equals", "expected": "administrative"},
                ],
                "approved_execution": True,
                "impact": "read-only",
                "emission_is_violation": True,
                "severity": "high",
                "objective": "Confirm that a restricted caller cannot make an MCP service deputy act as service-admin.",
                "objective_ids": [objective_ids["deputy"]] if objective_ids.get("deputy") else [],
            },
        ],
    }
    if transport == "legacy-http-sse":
        profile["legacy_sse_path"] = "/sse"
    return validate_evaluation_config({"mcp": profile})


def _inventory_profile(transport: str, inventory_sha256: str = "") -> dict:
    case = {
        "id": "approved-native-inventory",
        "title": "Native fixture inventory integrity",
        "scenario": "inventory-integrity",
        "identity_id": "project-reader",
        "technique_id": "LLM03-MCP-INVENTORY",
        "required_tools": ["read_project_profile", "read_recent_activity"],
        "forbidden_tools": ["read_administrative_policy", "delegate_account_summary"],
        "impact": "read-only",
        "emission_is_violation": True,
        "severity": "high",
    }
    if inventory_sha256:
        case["inventory_sha256"] = inventory_sha256
    profile = {
        "enabled": True,
        "transport": transport,
        "endpoint_path": "/mcp",
        "protocol_versions": ["2025-11-25"] if transport == "streamable-http" else ["2024-11-05"],
        "max_pages": 5,
        "identities": [{"id": "project-reader", "headers": {"X-MCP-Role": "project-reader"}}],
        "cases": [case],
    }
    if transport == "legacy-http-sse":
        profile["legacy_sse_path"] = "/sse"
    return validate_evaluation_config({"mcp": profile})


class MCPAuthorizationFixtureTests(unittest.TestCase):
    def _run(self, mode: str, transport: str) -> tuple[tempfile.TemporaryDirectory, MCPAuthorizationFixtureServer, Repository, dict]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        fixture = MCPAuthorizationFixtureServer(mode, transport).start()
        repo = Repository(root / "assessment.sqlite3")
        project = repo.create_project(
            name=f"MCP authorization · {transport} · {mode}",
            client="AdverScope qualification",
            environment="qualification",
        )
        scope = repo.add_document(
            project["id"],
            kind="scope",
            filename="rules-of-engagement.md",
            content=(
                "The local MCP fixture origin and configured MCP routes are authorized. "
                "Read-only inventory and tool-call authorization tests plus one exact reproduction are allowed."
            ),
        )
        repo.add_document(
            project["id"],
            kind="policy",
            filename="target-policy.md",
            content=(
                "The project-reader identity must not receive administrative policy data and must not cause "
                "the service deputy to act with the service-admin role."
            ),
        )
        tools_objective = repo.add_objective(
            project["id"],
            title="Confirm restricted MCP tool authorization",
            description="Test whether project-reader can invoke the administrative policy tool.",
            success_criteria="A structured successful MCP tool result identifies project-reader and administrative data.",
            expected_safe_behavior="The MCP server returns a structured authorization error and no protected content.",
            false_positive_exclusions="Inventory visibility, HTTP success, an empty result, prose, or a denial does not satisfy the configured structured action assertions.",
            proof_mode="model-review",
            proof_rule_ids=[],
            require_reproduction=True,
            risk_ids=[],
            technique_ids=["LLM06-MCP-TOOLS"],
        )
        deputy_objective = repo.add_objective(
            project["id"],
            title="Confirm MCP confused-deputy authorization",
            description="Test whether project-reader can make the service deputy use service-admin authority.",
            success_criteria="A structured successful MCP result identifies project-reader, service-admin effective authority, and service-deputy decision source.",
            expected_safe_behavior="The MCP server rejects the delegated service-admin request.",
            false_positive_exclusions="A tool description, caller-supplied subject role, HTTP success, prose, or a denial is not confused-deputy proof.",
            proof_mode="model-review",
            proof_rule_ids=[],
            require_reproduction=True,
            risk_ids=[],
            technique_ids=["LLM06-MCP-DEPUTY"],
        )
        config = _profile(transport, {
            "tools": tools_objective["id"],
            "deputy": deputy_objective["id"],
        })
        capabilities = {"mcp": True, "chat_prompt_adapter": False, **evaluation_readiness(config)}
        authorized_routes = []
        if transport == "legacy-http-sse":
            authorized_routes = [
                {"path": "/sse", "methods": ["GET"], "role": "legacy-mcp-sse"},
                {"path": "/messages", "methods": ["POST"], "role": "legacy-mcp-messages"},
            ]
        target = repo.add_target(
            project["id"],
            name=f"MCP authorization fixture · {transport} · {mode}",
            kind="chatbot",
            base_url=fixture.base_url,
            path="/mcp",
            method="POST",
            request_template={"message": "{{prompt}}"},
            response_path="",
            capabilities=capabilities,
            evaluation_config=config,
            authorized_routes=authorized_routes,
            scope_confirmed=True,
        )
        guardrail = repo.save_guardrail(
            project["id"],
            target["id"],
            source_document_id=scope["id"],
            status="approved",
            max_requests=40,
            max_runtime_seconds=180,
            max_consecutive_errors=3,
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
        objectives = [tools_objective, deputy_objective]
        plan = build_assessment_plan(
            technique_ids=["LLM06-MCP-TOOLS", "LLM06-MCP-DEPUTY"],
            objectives=objectives,
            target_capabilities=capabilities,
            evaluation_config=config,
        )
        plan.update({
            "guardrail": guardrail,
            "target_capabilities": capabilities,
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
            evidence_store=EvidenceStore(root / "projects"),
            attack_profile="focused",
            attack_budget=2,
            assessment_plan=plan,
        )
        return temporary, fixture, repo, repo.get_run_detail(project["id"], run["id"])

    def _run_inventory(
        self,
        mode: str,
        transport: str,
        inventory_sha256: str = "",
    ) -> tuple[tempfile.TemporaryDirectory, MCPAuthorizationFixtureServer, Repository, dict]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        fixture = MCPAuthorizationFixtureServer(mode, transport).start()
        repo = Repository(root / "assessment.sqlite3")
        project = repo.create_project(name=f"MCP inventory · {transport} · {mode}", client="AdverScope qualification")
        scope = repo.add_document(
            project["id"],
            kind="scope",
            filename="rules-of-engagement.md",
            content="The local MCP fixture and read-only inventory listing plus one exact reproduction are authorized.",
        )
        repo.add_document(
            project["id"],
            kind="policy",
            filename="target-policy.md",
            content="The project-reader inventory must match the approved digest and must not expose administrative tools.",
        )
        config = _inventory_profile(transport, inventory_sha256)
        capabilities = {"mcp": True, "chat_prompt_adapter": False, **evaluation_readiness(config)}
        authorized_routes = []
        if transport == "legacy-http-sse":
            authorized_routes = [
                {"path": "/sse", "methods": ["GET"], "role": "legacy-mcp-sse"},
                {"path": "/messages", "methods": ["POST"], "role": "legacy-mcp-messages"},
            ]
        target = repo.add_target(
            project["id"],
            name=f"MCP inventory fixture · {transport} · {mode}",
            kind="chatbot",
            base_url=fixture.base_url,
            path="/mcp",
            method="POST",
            request_template={"message": "{{prompt}}"},
            response_path="",
            capabilities=capabilities,
            evaluation_config=config,
            authorized_routes=authorized_routes,
            scope_confirmed=True,
        )
        guardrail = repo.save_guardrail(
            project["id"],
            target["id"],
            source_document_id=scope["id"],
            status="approved",
            max_requests=30,
            max_runtime_seconds=120,
            max_consecutive_errors=3,
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
        plan = build_assessment_plan(
            technique_ids=["LLM03-MCP-INVENTORY"],
            target_capabilities=capabilities,
            evaluation_config=config,
        )
        plan.update({
            "guardrail": guardrail,
            "target_capabilities": capabilities,
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
            evidence_store=EvidenceStore(root / "projects"),
            attack_profile="focused",
            attack_budget=1,
            assessment_plan=plan,
        )
        return temporary, fixture, repo, repo.get_run_detail(project["id"], run["id"])

    def test_complete_current_and_legacy_runs_distinguish_secure_and_vulnerable_controls(self) -> None:
        for transport in ("streamable-http", "legacy-http-sse"):
            for mode in ("secure", "vulnerable"):
                with self.subTest(transport=transport, mode=mode):
                    temporary, fixture, repo, detail = self._run(mode, transport)
                    try:
                        self.assertEqual("completed", detail["status"], detail.get("error"))
                        self.assertEqual(2, len(detail["test_cases"]))
                        self.assertEqual(1 if mode == "vulnerable" else 0, len(detail["findings"]))
                        if mode == "vulnerable":
                            self.assertEqual(2, detail["findings"][0]["occurrence_count"])
                        self.assertEqual(
                            {"vulnerable"} if mode == "vulnerable" else {"safe"},
                            {case["status"] for case in detail["test_cases"]},
                        )
                        self.assertEqual(1.0, detail["metrics"]["protocol_trace_completeness_rate"])
                        techniques = {
                            case["evaluation"]["owasp_technique_ids"][0]
                            for case in detail["test_cases"]
                        }
                        self.assertEqual({"LLM06-MCP-TOOLS", "LLM06-MCP-DEPUTY"}, techniques)
                        for case in detail["test_cases"]:
                            execution = case["evaluation"]["mcp_execution"]
                            self.assertEqual(transport, execution["transport"])
                            self.assertEqual(
                                "2025-11-25" if transport == "streamable-http" else "2024-11-05",
                                execution["negotiated_version"],
                            )
                            if mode == "vulnerable":
                                self.assertEqual("target-mcp-policy", case["evaluation"]["evidence_assurance"]["level"])
                            else:
                                self.assertEqual("target-mcp-policy", case["evaluation"]["mcp_execution"]["policy"]["confirmation"])
                            objective_result = case["evaluation"]["objective_results"][0]
                            self.assertEqual(mode == "vulnerable", objective_result["achieved"])
                            self.assertEqual("deterministic-mcp-target-policy", objective_result["proof_source"])
                            policy = execution["policy"]
                            if mode == "vulnerable":
                                self.assertTrue(policy["action_assertions_satisfied"])
                                self.assertTrue(all(item["passed"] for item in policy["action_assertions"]))
                                reproduction = case["evaluation"]["objective_reproductions"][0]
                                self.assertEqual("confirmed", reproduction["status"])
                            else:
                                self.assertFalse(policy["violated"])
                        event_types = {item["event_type"] for item in detail["protocol_events"]}
                        self.assertTrue({"jsonrpc.request", "jsonrpc.response", "policy.input.ready"}.issubset(event_types))
                        if transport == "legacy-http-sse":
                            self.assertTrue({"transport.open", "transport.endpoint"}.issubset(event_types))
                            serialized = json.dumps(detail, ensure_ascii=False)
                            self.assertNotIn("sessionId=", serialized.replace("sessionId=%5BREDACTED%5D", ""))
                        else:
                            self.assertNotIn("transport.open", event_types)
                        expected_sessions = 4 if mode == "vulnerable" else 2
                        initialize_count = sum(1 for item in fixture.state.requests if item["operation"] == "initialize")
                        self.assertEqual(expected_sessions, initialize_count)
                    finally:
                        repo.close()
                        fixture.close()
                        temporary.cleanup()

    def test_action_assertions_prevent_success_envelope_false_positive(self) -> None:
        case = _profile("streamable-http")["mcp"]["cases"][0]
        from osai_security.mcp_security import assess_mcp_case

        execution = {
            "initialized": True,
            "inventory_complete": True,
            "inventory": {"tools": [], "resources": [], "resource_templates": [], "prompts": []},
            "action_response": {
                "jsonrpc": "2.0",
                "id": 5,
                "result": {"content": [{"type": "text", "text": "Request denied."}], "isError": False},
            },
        }
        policy = assess_mcp_case(case, execution)
        self.assertFalse(policy["violated"])
        self.assertFalse(policy["finding"])
        self.assertFalse(policy["action_assertions_satisfied"])
        self.assertTrue(all(not item["passed"] for item in policy["action_assertions"]))

    def test_native_current_and_legacy_inventory_integrity_controls(self) -> None:
        for transport in ("streamable-http", "legacy-http-sse"):
            with self.subTest(transport=transport):
                discovery = self._run_inventory("secure", transport)
                try:
                    approved_sha256 = discovery[3]["test_cases"][0]["evaluation"]["mcp_execution"]["inventory_sha256"]
                    self.assertRegex(approved_sha256, r"^[0-9a-f]{64}$")
                finally:
                    discovery[2].close()
                    discovery[1].close()
                    discovery[0].cleanup()
                for mode in ("secure", "vulnerable"):
                    result = self._run_inventory(mode, transport, approved_sha256)
                    try:
                        detail = result[3]
                        case = detail["test_cases"][0]
                        self.assertEqual(detail["status"], "completed", detail.get("error"))
                        self.assertEqual(case["status"], "safe" if mode == "secure" else "vulnerable")
                        self.assertEqual(len(detail["findings"]), 0 if mode == "secure" else 1)
                        if mode == "vulnerable":
                            self.assertEqual(
                                set(case["evaluation"]["detected_signals"]),
                                {"forbidden-tool-exposed", "inventory-digest-drift"},
                            )
                            self.assertEqual(detail["metrics"]["reproduction_rate"], 1.0)
                    finally:
                        result[2].close()
                        result[1].close()
                        result[0].cleanup()


if __name__ == "__main__":
    unittest.main()
