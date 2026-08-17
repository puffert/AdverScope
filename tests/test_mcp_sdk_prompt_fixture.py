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
from osai_security.mcp_sdk_prompt_fixture import PROTECTED_PROMPT, PUBLIC_PROMPT, SYNTHETIC_PROMPT_MARKER
from osai_security.owasp import build_assessment_plan
from osai_security.targets import TargetClient


ROOT = Path(__file__).resolve().parents[1]
HAS_MCP_SDK = importlib.util.find_spec("mcp") is not None
TECHNIQUES = ["LLM03-MCP-INVENTORY", "LLM02-MCP-PROMPT"]


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_port(port: int, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"MCP SDK prompt fixture exited with status {process.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("MCP SDK prompt fixture did not start")


@unittest.skipUnless(HAS_MCP_SDK, "official MCP Python SDK is an optional qualification dependency")
class MCPSDKPromptFixtureTests(unittest.TestCase):
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

    def _start(self, mode: str, transport: str) -> int:
        port = _free_port()
        process = subprocess.Popen(
            [sys.executable, str(ROOT / "scripts" / "run_mcp_sdk_prompt_fixture.py"), "--mode", mode, "--transport", transport, "--port", str(port)],
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.processes.append(process)
        _wait_for_port(port, process)
        return port

    @staticmethod
    def _profile(transport: str) -> dict:
        return validate_evaluation_config({
            "mcp": {
                "enabled": True,
                "transport": "legacy-http-sse" if transport == "sse" else "streamable-http",
                "endpoint_path": "/mcp",
                "legacy_sse_path": "/sse" if transport == "sse" else "",
                "protocol_versions": ["2024-11-05"] if transport == "sse" else ["2025-11-25"],
                "max_pages": 5,
                "identities": [{"id": "restricted-reader", "headers": {"X-MCP-Identity": "restricted-reader"}}],
                "cases": [
                    {
                        "id": "prompt-inventory",
                        "title": "Official SDK prompt inventory",
                        "scenario": "inventory-integrity",
                        "identity_id": "restricted-reader",
                        "technique_id": "LLM03-MCP-INVENTORY",
                        "required_prompts": [PUBLIC_PROMPT],
                        "forbidden_prompts": [PROTECTED_PROMPT],
                        "impact": "read-only",
                        "emission_is_violation": True,
                        "severity": "high",
                    },
                    {
                        "id": "protected-prompt",
                        "title": "Official SDK protected prompt",
                        "scenario": "unauthorized-prompt-get",
                        "identity_id": "restricted-reader",
                        "technique_id": "LLM02-MCP-PROMPT",
                        "prompt_name": PROTECTED_PROMPT,
                        "prompt_arguments": {"case_id": "synthetic-qualification-case"},
                        "action_assertions": [
                            {"path": "result.description", "operator": "equals", "expected": "Synthetic restricted incident-response prompt."},
                            {"path": "result.messages.0.content.text", "operator": "contains", "expected": SYNTHETIC_PROMPT_MARKER},
                        ],
                        "approved_execution": True,
                        "impact": "read-only",
                        "emission_is_violation": True,
                        "severity": "high",
                    },
                ],
            }
        })

    @staticmethod
    def _run(root: Path, port: int, transport: str) -> dict:
        repo = Repository(root / "assessment.sqlite3")
        try:
            project = repo.create_project(name="Official SDK MCP prompt", client="AdverScope Qualification")
            repo.add_document(project["id"], kind="scope", filename="scope.md", content="Authorized local official-SDK prompt fixture; read-only listing, get, and one reproduction are allowed.")
            repo.add_document(project["id"], kind="policy", filename="policy.md", content="The restricted identity must not discover or retrieve the protected prompt.")
            config = MCPSDKPromptFixtureTests._profile(transport)
            routes = [{"path": "/mcp", "methods": ["POST"], "role": "mcp-endpoint"}]
            if transport == "sse":
                routes.extend([
                    {"path": "/sse", "methods": ["GET"], "role": "legacy-mcp-sse"},
                    {"path": "/messages", "methods": ["POST"], "role": "legacy-mcp-messages"},
                    {"path": "/messages/", "methods": ["POST"], "role": "legacy-mcp-messages"},
                ])
            target = repo.add_target(
                project["id"], name="Official SDK prompt fixture", kind="chatbot", base_url=f"http://127.0.0.1:{port}",
                path="/mcp", method="POST", request_template={"message": "{{prompt}}"}, response_path="",
                capabilities={"mcp": True, "chat_prompt_adapter": False}, evaluation_config=config,
                authorized_routes=routes, scope_confirmed=True,
            )
            guardrail = repo.save_guardrail(
                project["id"], target["id"], status="approved", max_requests=120, max_runtime_seconds=120,
                max_consecutive_errors=3, allow_active_recon=False, allow_multi_turn=False,
                max_turns_per_objective=1, allow_reproduction=True, allow_screenshots=False, stop_on_http_5xx=True,
            )
            capabilities = {**target["capabilities"], **evaluation_readiness(config)}
            plan = build_assessment_plan(technique_ids=TECHNIQUES, target_capabilities=capabilities, evaluation_config=config)
            plan.update({"guardrail": guardrail, "target_capabilities": capabilities, "adaptive_turns": 1, "recon": {"mode": "none", "profile": "configured"}})
            run = run_assessment(
                repo, project_id=project["id"], target_id=target["id"], module_ids=plan["module_ids"],
                model_mode="offline", model_gateway=object(), target_client=TargetClient(timeout_seconds=5),
                browser_target_client=object(), evidence_store=EvidenceStore(root / "projects"), attack_budget=2,
                assessment_plan=plan,
            )
            return repo.get_run_detail(project["id"], run["id"])
        finally:
            repo.close()

    def test_official_sdk_current_and_legacy_prompt_controls(self) -> None:
        for transport in ("streamable-http", "sse"):
            for mode in ("secure", "vulnerable"):
                with self.subTest(transport=transport, mode=mode):
                    port = self._start(mode, transport)
                    with tempfile.TemporaryDirectory() as directory:
                        detail = self._run(Path(directory), port, transport)
                    expected = "safe" if mode == "secure" else "vulnerable"
                    self.assertEqual({case["status"] for case in detail["test_cases"]}, {expected})
                    self.assertEqual(len(detail["findings"]), 0 if mode == "secure" else 1)
                    if mode == "vulnerable":
                        self.assertEqual(detail["metrics"]["reproduction_rate"], 1.0)


if __name__ == "__main__":
    unittest.main()
