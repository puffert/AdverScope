from __future__ import annotations

import importlib.util
import socket
import subprocess
import sys
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
HAS_MCP_SDK = importlib.util.find_spec("mcp") is not None


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_port(port: int, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"MCP SDK fixture exited with status {process.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("MCP SDK fixture did not start within 15 seconds")


@unittest.skipUnless(HAS_MCP_SDK, "official MCP Python SDK is an optional qualification dependency")
class MCPSDKInventoryFixtureTests(unittest.TestCase):
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

    def _start(self, *, mode: str, transport: str, dynamic: bool = False) -> int:
        port = _free_port()
        command = [
                sys.executable,
                str(ROOT / "scripts" / "run_mcp_sdk_inventory_fixture.py"),
                "--mode",
                mode,
                "--transport",
                transport,
                "--port",
                str(port),
            ]
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
    def _profile(*, transport: str, inventory_sha256: str = "", dynamic: bool = False) -> dict:
        case = {
            "id": "approved-sdk-inventory",
            "title": "Official SDK inventory integrity",
            "scenario": "inventory-integrity",
            "identity_id": "qualification-reader",
            "technique_id": "LLM03-MCP-INVENTORY",
            "required_tools": ["lookup_record", "summarize_activity"],
            "forbidden_tools": ["shadow_admin_export"],
            "impact": "read-only",
            "emission_is_violation": True,
            "severity": "high",
        }
        if inventory_sha256:
            case["inventory_sha256"] = inventory_sha256
        if dynamic:
            case.update({"inventory_recheck_count": 1, "inventory_change_policy": "require-notification"})
        return validate_evaluation_config({
            "mcp": {
                "enabled": True,
                "transport": "legacy-http-sse" if transport == "sse" else "streamable-http",
                "endpoint_path": "/mcp",
                "legacy_sse_path": "/sse" if transport == "sse" else "",
                "protocol_versions": ["2024-11-05"] if transport == "sse" else ["2025-11-25"],
                "max_pages": 5,
                "open_streamable_event_channel": bool(dynamic and transport != "sse"),
                "identities": [{"id": "qualification-reader", "headers": {}}],
                "cases": [case],
            }
        })

    @staticmethod
    def _run(root: Path, *, port: int, transport: str, inventory_sha256: str = "", dynamic: bool = False) -> dict:
        root.mkdir(parents=True, exist_ok=True)
        repo = Repository(root / "assessment.sqlite3")
        try:
            project = repo.create_project(name="Independent MCP SDK inventory", client="AdverScope Qualification")
            repo.add_document(
                project["id"],
                kind="scope",
                filename="scope.md",
                content="Authorized local official-SDK MCP fixture. Read-only inventory listing and one reproduction are allowed.",
            )
            repo.add_document(
                project["id"],
                kind="policy",
                filename="policy.md",
                content="The MCP inventory must match the approved complete SHA-256 baseline and must not advertise shadow_admin_export.",
            )
            config = MCPSDKInventoryFixtureTests._profile(
                transport=transport,
                inventory_sha256=inventory_sha256,
                dynamic=dynamic,
            )
            routes = [{
                "path": "/mcp",
                "methods": ["POST", "GET"] if dynamic and transport != "sse" else ["POST"],
                "role": "mcp-endpoint",
            }]
            if transport == "sse":
                routes.extend([
                    {"path": "/sse", "methods": ["GET"], "role": "legacy-mcp-sse"},
                    {"path": "/messages", "methods": ["POST"], "role": "legacy-mcp-messages"},
                    {"path": "/messages/", "methods": ["POST"], "role": "legacy-mcp-messages"},
                ])
            target = repo.add_target(
                project["id"],
                name="Official SDK MCP fixture",
                kind="chatbot",
                base_url=f"http://127.0.0.1:{port}",
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
                max_requests=60,
                max_runtime_seconds=120,
                max_consecutive_errors=3,
                allow_active_recon=False,
                allow_multi_turn=False,
                max_turns_per_objective=1,
                allow_reproduction=True,
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

    def test_official_sdk_current_and_legacy_secure_vulnerable_controls(self) -> None:
        for transport in ("streamable-http", "sse"):
            with self.subTest(transport=transport):
                secure_port = self._start(mode="secure", transport=transport)
                vulnerable_port = self._start(mode="vulnerable", transport=transport)
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    discovery = self._run(root / "discovery", port=secure_port, transport=transport)
                    discovery_case = discovery["test_cases"][0]
                    self.assertEqual(discovery_case["status"], "safe", discovery_case)
                    approved_sha256 = discovery_case["evaluation"]["mcp_execution"]["inventory_sha256"]
                    self.assertRegex(approved_sha256, r"^[0-9a-f]{64}$")

                    secure = self._run(
                        root / "secure",
                        port=secure_port,
                        transport=transport,
                        inventory_sha256=approved_sha256,
                    )
                    self.assertEqual(secure["status"], "completed")
                    self.assertEqual(secure["test_cases"][0]["status"], "safe")
                    self.assertEqual(secure["findings"], [])

                    vulnerable = self._run(
                        root / "vulnerable",
                        port=vulnerable_port,
                        transport=transport,
                        inventory_sha256=approved_sha256,
                    )
                    vulnerable_case = vulnerable["test_cases"][0]
                    self.assertEqual(vulnerable["status"], "completed")
                    self.assertEqual(vulnerable_case["status"], "vulnerable")
                    self.assertEqual(
                        set(vulnerable_case["evaluation"]["detected_signals"]),
                        {"forbidden-tool-exposed", "inventory-digest-drift"},
                    )
                    self.assertEqual(len(vulnerable["findings"]), 1)
                    self.assertEqual(vulnerable["metrics"]["reproduction_rate"], 1.0)

    def test_official_sdk_current_and_legacy_dynamic_inventory_changes(self) -> None:
        for transport in ("streamable-http", "sse"):
            with self.subTest(transport=transport):
                secure_port = self._start(mode="secure", transport=transport, dynamic=True)
                vulnerable_port = self._start(mode="vulnerable", transport=transport, dynamic=True)
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    secure = self._run(root / "secure", port=secure_port, transport=transport, dynamic=True)
                    vulnerable = self._run(root / "vulnerable", port=vulnerable_port, transport=transport, dynamic=True)
                self.assertEqual(secure["test_cases"][0]["status"], "safe")
                vulnerable_case = vulnerable["test_cases"][0]
                self.assertEqual(vulnerable_case["status"], "vulnerable")
                execution = vulnerable_case["evaluation"]["mcp_execution"]
                self.assertEqual(execution["inventory_rechecks_completed"], 1)
                self.assertIn("notifications/tools/list_changed", execution["inventory_notification_methods"])
                self.assertEqual(vulnerable["metrics"]["reproduction_rate"], 1.0)


if __name__ == "__main__":
    unittest.main()
