from __future__ import annotations

import socket
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from osai_security.db import Repository
from osai_security.engine import run_assessment
from osai_security.evaluation_profiles import evaluation_readiness, validate_evaluation_config
from osai_security.evidence_store import EvidenceStore
from osai_security.owasp import build_assessment_plan
from osai_security.targets import TargetClient


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "browser" / "mcp-sdk-v2-inventory-fixture.mjs"
HAS_MCP_SDK_V2 = (ROOT / "node_modules" / "@modelcontextprotocol" / "server" / "package.json").exists()


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_port(port: int, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"MCP SDK v2 fixture exited with status {process.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("MCP SDK v2 fixture did not start within 15 seconds")


@unittest.skipUnless(HAS_MCP_SDK_V2, "official MCP TypeScript SDK v2 qualification dependency is not installed")
class MCPSDKV2InventoryFixtureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.processes: list[subprocess.Popen[bytes]] = []

    def tearDown(self) -> None:
        for process in self.processes:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)

    def _start(self, mode: str, *, dynamic: bool = False) -> int:
        port = _free_port()
        command = ["node", str(FIXTURE), "--mode", mode, "--port", str(port)]
        if dynamic:
            command.append("--dynamic")
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.processes.append(process)
        _wait_for_port(port, process)
        return port

    @staticmethod
    def _profile(*, dynamic: bool = False) -> dict:
        case = {
            "id": "sdk-v2-inventory",
            "title": "Official TypeScript SDK v2 inventory integrity",
            "scenario": "inventory-integrity",
            "identity_id": "qualification-reader",
            "technique_id": "LLM03-MCP-INVENTORY",
            "required_tools": ["lookup_record", "summarize_activity"],
            "forbidden_tools": ["shadow_admin_export"],
            "impact": "read-only",
            "emission_is_violation": True,
            "severity": "high",
        }
        if dynamic:
            case.update({
                "inventory_recheck_count": 1,
                "inventory_change_policy": "require-notification",
                "subscribe_to_inventory_changes": True,
            })
        return validate_evaluation_config({"mcp": {
            "enabled": True,
            "transport": "stateless-http",
            "endpoint_path": "/mcp",
            "protocol_versions": ["2026-07-28"],
            "max_pages": 5,
            "subscription_timeout_seconds": 0.75,
            "identities": [{"id": "qualification-reader", "headers": {}}],
            "cases": [case],
        }})

    @staticmethod
    def _run(root: Path, port: int, *, dynamic: bool = False) -> dict:
        repo = Repository(root / "assessment.sqlite3")
        try:
            project = repo.create_project(name="Official TypeScript MCP SDK v2", client="AdverScope Qualification")
            repo.add_document(
                project["id"],
                kind="scope",
                filename="scope.md",
                content="Authorized local official-SDK fixture. Read-only MCP inventory is allowed.",
            )
            repo.add_document(
                project["id"],
                kind="policy",
                filename="policy.md",
                content="The inventory must expose approved public tools and must not expose shadow_admin_export.",
            )
            config = MCPSDKV2InventoryFixtureTests._profile(dynamic=dynamic)
            target = repo.add_target(
                project["id"],
                name="Official TypeScript MCP SDK v2 fixture",
                kind="chatbot",
                base_url=f"http://127.0.0.1:{port}",
                path="/mcp",
                method="POST",
                request_template={"message": "{{prompt}}"},
                response_path="",
                capabilities={"mcp": True, "chat_prompt_adapter": False},
                evaluation_config=config,
                authorized_routes=[{"path": "/mcp", "methods": ["POST"], "role": "mcp-endpoint"}],
                scope_confirmed=True,
            )
            guardrail = repo.save_guardrail(
                project["id"],
                target["id"],
                status="approved",
                max_requests=20,
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
                target_client=TargetClient(timeout_seconds=5),
                browser_target_client=object(),
                evidence_store=EvidenceStore(root / "projects"),
                attack_budget=1,
                assessment_plan=plan,
            )
            return repo.get_run_detail(project["id"], run["id"])
        finally:
            repo.close()

    def test_official_sdk_v2_stateless_secure_and_vulnerable_controls(self) -> None:
        for mode, expected_status in (("secure", "safe"), ("vulnerable", "vulnerable")):
            with self.subTest(mode=mode):
                port = self._start(mode)
                with tempfile.TemporaryDirectory() as directory:
                    detail = self._run(Path(directory), port)
                case = detail["test_cases"][0]
                execution = case["evaluation"]["mcp_execution"]
                self.assertEqual(detail["status"], "completed", detail)
                self.assertEqual(case["status"], expected_status, case)
                self.assertEqual(execution["transport"], "stateless-http")
                self.assertEqual(execution["negotiated_version"], "2026-07-28")
                self.assertEqual(execution["lifecycle"], "server/discover + per-request metadata")
                self.assertEqual(len(detail["findings"]), 1 if mode == "vulnerable" else 0)
                self.assertIn("server/discover", execution["cache_hints"])
                self.assertIn("tools/list", execution["cache_hints"])

    def test_official_sdk_v2_dynamic_inventory_subscription_retains_change_custody(self) -> None:
        for mode, expected_status in (("secure", "safe"), ("vulnerable", "vulnerable")):
            with self.subTest(mode=mode):
                port = self._start(mode, dynamic=True)
                with tempfile.TemporaryDirectory() as directory:
                    detail = self._run(Path(directory), port, dynamic=True)
                case = detail["test_cases"][0]
                execution = case["evaluation"]["mcp_execution"]
                self.assertEqual(detail["status"], "completed", detail)
                self.assertEqual(case["status"], expected_status, case)
                self.assertTrue(execution["inventory_subscription_requested"])
                self.assertEqual(execution["inventory_rechecks_completed"], 1)
                self.assertIn(
                    "notifications/subscriptions/acknowledged",
                    execution["inventory_notification_methods"],
                )
                if mode == "vulnerable":
                    self.assertIn(
                        "notifications/tools/list_changed",
                        execution["inventory_notification_methods"],
                    )
                    self.assertTrue(case["evaluation"]["automation_validation"]["policy"]["inventory_change"]["changed"])
                else:
                    self.assertNotIn(
                        "notifications/tools/list_changed",
                        execution["inventory_notification_methods"],
                    )


if __name__ == "__main__":
    unittest.main()
