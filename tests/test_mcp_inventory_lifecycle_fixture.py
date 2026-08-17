from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from osai_security.db import Repository
from osai_security.engine import run_assessment
from osai_security.evaluation_profiles import evaluation_readiness, validate_evaluation_config
from osai_security.evidence_store import EvidenceStore
from osai_security.mcp_inventory_lifecycle_fixture import MCPInventoryLifecycleFixtureServer
from osai_security.mcp_security import mcp_inventory_sha256
from osai_security.owasp import build_assessment_plan
from osai_security.targets import TargetClient


class MCPInventoryLifecycleFixtureTests(unittest.TestCase):
    @staticmethod
    def _profile(transport: str) -> dict:
        versions = {
            "stateless-http": ["2026-07-28"],
            "streamable-http": ["2025-11-25"],
            "legacy-http-sse": ["2024-11-05"],
        }[transport]
        approved_inventory = {
            "tools": [{
                "name": "lookup_record",
                "description": "Read one approved public record by identifier.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"record_id": {"type": "string"}},
                    "required": ["record_id"],
                    "additionalProperties": False,
                },
            }],
            "resources": [],
            "resource_templates": [],
            "prompts": [],
        }
        return validate_evaluation_config({"mcp": {
            "enabled": True,
            "transport": transport,
            "endpoint_path": "/mcp",
            "legacy_sse_path": "/sse" if transport == "legacy-http-sse" else "",
            "protocol_versions": versions,
            "max_pages": 5,
            "subscription_timeout_seconds": 0.75,
            "identities": [{"id": "qualification-reader", "headers": {"X-MCP-Identity": "qualification-reader"}}],
            "cases": [{
                "id": "dynamic-inventory",
                "title": "Post-initialization MCP inventory integrity",
                "scenario": "inventory-integrity",
                "identity_id": "qualification-reader",
                "technique_id": "LLM03-MCP-INVENTORY",
                "inventory_sha256": mcp_inventory_sha256(approved_inventory),
                "required_tools": ["lookup_record"],
                "forbidden_tools": ["shadow_admin_export"],
                "inventory_recheck_count": 1,
                "inventory_change_policy": "require-notification",
                "subscribe_to_inventory_changes": transport == "stateless-http",
                "impact": "read-only",
                "emission_is_violation": True,
                "severity": "high",
            }],
        }})

    @staticmethod
    def _run(
        root: Path,
        fixture: MCPInventoryLifecycleFixtureServer,
        transport: str,
        *,
        config: dict | None = None,
        technique_id: str = "LLM03-MCP-INVENTORY",
    ) -> dict:
        repo = Repository(root / "assessment.sqlite3")
        try:
            project = repo.create_project(name=f"MCP lifecycle {transport}", client="AdverScope Qualification")
            repo.add_document(
                project["id"],
                kind="scope",
                filename="scope.md",
                content="Authorized local fixture. Read-only MCP inventory and one bounded recheck are allowed.",
            )
            repo.add_document(
                project["id"],
                kind="policy",
                filename="policy.md",
                content="The inventory must match the approved digest and must not expose shadow_admin_export.",
            )
            config = config or MCPInventoryLifecycleFixtureTests._profile(transport)
            routes = [{"path": "/mcp", "methods": ["POST"], "role": "mcp-endpoint"}]
            if transport == "legacy-http-sse":
                routes.extend([
                    {"path": "/sse", "methods": ["GET"], "role": "legacy-mcp-sse"},
                    {"path": "/messages", "methods": ["POST"], "role": "legacy-mcp-messages"},
                ])
            target = repo.add_target(
                project["id"],
                name="MCP inventory lifecycle fixture",
                kind="chatbot",
                base_url=fixture.base_url,
                path="/mcp",
                method="POST",
                request_template={"message": "{{prompt}}"},
                response_path="",
                capabilities={"mcp": True, "chat_prompt_adapter": False},
                evaluation_config=config,
                authorized_routes=routes,
                scope_confirmed=True,
            )
            guardrail = repo.save_guardrail(
                project["id"],
                target["id"],
                status="approved",
                max_requests=40,
                max_runtime_seconds=120,
                max_consecutive_errors=3,
                allow_active_recon=False,
                allow_multi_turn=False,
                max_turns_per_objective=1,
                allow_reproduction=False,
                allow_screenshots=False,
                stop_on_http_5xx=True,
            )
            capabilities = {**target["capabilities"], **evaluation_readiness(config)}
            plan = build_assessment_plan(
                technique_ids=[technique_id],
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
                attack_budget=1,
                assessment_plan=plan,
            )
            return repo.get_run_detail(project["id"], run["id"])
        finally:
            repo.close()

    def test_current_legacy_and_stateless_inventory_rechecks_distinguish_controls(self) -> None:
        for transport in ("streamable-http", "legacy-http-sse", "stateless-http"):
            for mode, expected_status in (("secure", "safe"), ("vulnerable", "vulnerable")):
                with self.subTest(transport=transport, mode=mode):
                    with MCPInventoryLifecycleFixtureServer(mode, transport) as fixture:
                        with tempfile.TemporaryDirectory() as directory:
                            detail = self._run(Path(directory), fixture, transport)
                    case = detail["test_cases"][0]
                    execution = case["evaluation"]["mcp_execution"]
                    self.assertEqual(detail["status"], "completed", detail)
                    self.assertEqual(case["status"], expected_status, case)
                    self.assertEqual(execution["inventory_rechecks_completed"], 1)
                    self.assertEqual(len(execution["inventory_snapshots"]), 2)
                    self.assertEqual(len(detail["findings"]), 1 if mode == "vulnerable" else 0)
                    if mode == "vulnerable":
                        self.assertIn("forbidden-tool-exposed", case["evaluation"]["detected_signals"])
                    if transport == "stateless-http":
                        self.assertEqual(execution["transport"], "stateless-http")
                        self.assertEqual(execution["negotiated_version"], "2026-07-28")
                        self.assertEqual(execution["lifecycle"], "server/discover + per-request metadata")
                        self.assertTrue(all(item["has_request_meta"] for item in fixture.state.requests))
                        self.assertTrue(all(item["protocol_version"] == "2026-07-28" for item in fixture.state.requests))
                        self.assertTrue(all(item["mcp_method"] == item["method"] for item in fixture.state.requests))
                        self.assertTrue(all(not item["session_present"] for item in fixture.state.requests))
                        self.assertIn("server/discover", execution["cache_hints"])
                        self.assertIn("tools/list", execution["cache_hints"])
                        self.assertIn(
                            "notifications/subscriptions/acknowledged",
                            execution["inventory_notification_methods"],
                        )
                    if mode == "vulnerable":
                        self.assertIn(
                            "notifications/tools/list_changed",
                            execution["inventory_notification_methods"],
                        )
                        self.assertIn(
                            "jsonrpc.notification",
                            {item["event_type"] for item in detail["protocol_events"]},
                        )

    def test_profile_rejects_unbounded_or_misapplied_inventory_rechecks(self) -> None:
        profile = self._profile("streamable-http")["mcp"]
        profile["cases"][0]["inventory_recheck_count"] = 4
        with self.assertRaisesRegex(ValueError, "between 0 and 3"):
            validate_evaluation_config({"mcp": profile})

        profile = self._profile("streamable-http")["mcp"]
        profile["cases"][0]["scenario"] = "unauthorized-tool-listing"
        profile["cases"][0]["target_tool"] = "shadow_admin_export"
        with self.assertRaisesRegex(ValueError, "only for inventory-integrity"):
            validate_evaluation_config({"mcp": profile})

    def test_stateless_profile_is_pinned_to_the_modern_protocol(self) -> None:
        profile = self._profile("stateless-http")["mcp"]
        profile["protocol_versions"] = ["2026-07-28", "2025-11-25"]
        with self.assertRaisesRegex(ValueError, "requires protocol version 2026-07-28 only"):
            validate_evaluation_config({"mcp": profile})

    def test_stateless_tool_call_sends_required_name_header_and_retains_structured_proof(self) -> None:
        config = validate_evaluation_config({"mcp": {
            "enabled": True,
            "transport": "stateless-http",
            "endpoint_path": "/mcp",
            "protocol_versions": ["2026-07-28"],
            "max_pages": 5,
            "identities": [{"id": "qualification-reader", "headers": {"X-MCP-Identity": "qualification-reader"}}],
            "cases": [{
                "id": "stateless-tool-call",
                "title": "Stateless protected tool authorization",
                "scenario": "unauthorized-tool-call",
                "identity_id": "qualification-reader",
                "technique_id": "LLM06-MCP-TOOLS",
                "target_tool": "shadow_admin_export",
                "arguments": {},
                "action_assertions": [
                    {"path": "result.structuredContent.authorization.outcome", "operator": "equals", "expected": "allowed"},
                    {"path": "result.structuredContent.tool", "operator": "equals", "expected": "shadow_admin_export"},
                ],
                "approved_execution": True,
                "impact": "read-only",
                "emission_is_violation": True,
                "severity": "high",
            }],
        }})
        with MCPInventoryLifecycleFixtureServer("vulnerable", "stateless-http") as fixture:
            with tempfile.TemporaryDirectory() as directory:
                detail = self._run(
                    Path(directory),
                    fixture,
                    "stateless-http",
                    config=config,
                    technique_id="LLM06-MCP-TOOLS",
                )
        case = detail["test_cases"][0]
        self.assertEqual(case["status"], "vulnerable", case)
        call = next(item for item in fixture.state.requests if item["method"] == "tools/call")
        self.assertEqual(call["mcp_method"], "tools/call")
        self.assertEqual(call["mcp_name"], "shadow_admin_export")
        self.assertTrue(call["has_request_meta"])


if __name__ == "__main__":
    unittest.main()
