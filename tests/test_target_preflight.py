from __future__ import annotations

import json
import os
import shutil
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from osai_security.browser_targets import BrowserTargetClient
from osai_security.config import AppConfig
from osai_security.db import NotFoundError, Repository
from osai_security.http_app import Application
from osai_security.preflight import PREFLIGHT_PROMPT, build_target_preflight_readiness
from osai_security.targets import TargetClient, target_runtime_readiness


class PreflightChatHandler(BaseHTTPRequestHandler):
    response_path_present = True

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length).decode("utf-8"))
        self.server.requests.append({"path": self.path, "body": body})  # type: ignore[attr-defined]
        payload = (
            {"choices": [{"message": {"content": "Connection acknowledged."}}]}
            if self.response_path_present
            else {"unexpected": "shape"}
        )
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, *_args: object) -> None:
        pass


class PreflightMCPHandler(BaseHTTPRequestHandler):
    requests: list[dict] = []

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length) or b"{}")
        self.__class__.requests.append({
            "body": body,
            "session": str(self.headers.get("MCP-Session-Id") or ""),
            "version": str(self.headers.get("MCP-Protocol-Version") or ""),
        })
        if body.get("method") == "initialize":
            payload = json.dumps({
                "jsonrpc": "2.0", "id": body["id"],
                "result": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "serverInfo": {"name": "preflight-fixture", "version": "1"},
                },
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("MCP-Session-Id", "private-session-value")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        self.send_response(202)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *_args: object) -> None:
        pass


class PreflightBrowserHandler(BaseHTTPRequestHandler):
    submitted = 0

    def do_GET(self) -> None:
        payload = b"<!doctype html><html><head><title>Preflight browser fixture</title></head><body><textarea id='input'></textarea><button id='submit'>Send</button><div id='response'>Ready</div></body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self) -> None:
        self.__class__.submitted += 1
        self.send_response(500)
        self.end_headers()

    def log_message(self, *_args: object) -> None:
        pass


class NoTrafficClient:
    timeout_seconds = 1

    def send(self, *_args: object, **_kwargs: object) -> dict:
        raise AssertionError("blocked preflight must not send target traffic")


class BrowserPreflightStub:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def send(self, target: dict, prompt: str, **kwargs: object) -> dict:
        self.calls.append({"target": target, "prompt": prompt, **kwargs})
        return {
            "status_code": "200",
            "status_line": "BROWSER DOM PREFLIGHT",
            "response": "",
            "raw": json.dumps({"input_selector_matches": 1, "submit_selector_matches": 1}),
            "raw_http_response": "",
            "raw_response_sha256": "a" * 64,
            "response_headers": [],
            "request": {"runner": "playwright-browser", "method": "GET", "url": "https://browser.invalid/chat"},
            "captures": [],
            "completion": {"state": "complete", "signals": ["required-selectors-ready"]},
            "preflight": {
                "selectors_ready": True,
                "input_selector_matches": 1,
                "submit_selector_matches": 1,
                "response_selector_matches": 1,
            },
            "scope_enforcement": {"authorized_origin": "https://browser.invalid", "final_origin": "https://browser.invalid"},
        }

    def open_session(self, _target: dict) -> dict:
        return {"status": "opened", "target_id": "unused", "process_id": 1}


class TargetPreflightTests(unittest.TestCase):
    def make_app(self, root: Path, **kwargs: object) -> tuple[Repository, Application]:
        config = AppConfig(database_path=root / "assessment.sqlite3", evidence_root=root / "projects", target_timeout_seconds=3)
        repo = Repository(config.database_path)
        app = Application(repo, config=config, **kwargs)
        return repo, app

    @staticmethod
    def approve(repo: Repository, project_id: str, target_id: str, **values: object) -> None:
        repo.save_guardrail(project_id, target_id, status="approved", **values)

    def test_successful_chat_preflight_is_retained_separately(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), PreflightChatHandler)
        server.requests = []  # type: ignore[attr-defined]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                repo, app = self.make_app(root, target_client=TargetClient(timeout_seconds=3))
                project = repo.create_project(name="Preflight project")
                target = repo.add_target(
                    project["id"],
                    name="Chat API",
                    kind="chatbot",
                    base_url=f"http://127.0.0.1:{server.server_port}",
                    path="/chat",
                    method="POST",
                    request_template={"message": "{{prompt}}"},
                    response_path="choices.0.message.content",
                    scope_confirmed=True,
                )
                self.approve(repo, project["id"], target["id"])

                status, item = app.dispatch(
                    "POST",
                    f"/api/projects/{project['id']}/targets/{target['id']}/preflights",
                    {},
                )
                self.assertEqual(status, 201)
                self.assertEqual(item["status"], "ready")
                self.assertEqual(item["request_count"], 1)
                self.assertEqual(item["result"]["resolved"]["route"], "/chat")
                self.assertEqual(item["result"]["resolved"]["method"], "POST")
                self.assertEqual(item["result"]["traffic"][0]["status_code"], "200")
                self.assertIn("curl --silent", item["result"]["traffic"][0]["request"]["curl_command"])
                self.assertEqual(server.requests[0]["path"], "/chat")  # type: ignore[attr-defined]
                self.assertEqual(server.requests[0]["body"]["message"], PREFLIGHT_PROMPT)  # type: ignore[attr-defined]

                detail = app.dispatch("GET", f"/api/projects/{project['id']}", {})[1]
                saved_target = next(entry for entry in detail["targets"] if entry["id"] == target["id"])
                self.assertTrue(saved_target["latest_preflight"]["current"])
                self.assertEqual(detail["counts"]["preflights"], 1)
                self.assertEqual(detail["runs"], [])
                self.assertEqual(detail["findings"], [])
                repo.close()
        finally:
            server.shutdown()
            server.server_close()

    def test_missing_adapter_identity_environment_blocks_without_traffic(self) -> None:
        environment_name = "ADV_PREFLIGHT_MISSING_IDENTITY_TOKEN"
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {}, clear=False):
            os.environ.pop(environment_name, None)
            root = Path(directory)
            repo, app = self.make_app(root, target_client=NoTrafficClient())  # type: ignore[arg-type]
            project = repo.create_project(name="Blocked preflight")
            target = repo.add_target(
                project["id"], name="Chat", kind="chatbot", base_url="https://target.invalid",
                path="/chat", method="POST", request_template={"message": "{{prompt}}"},
                response_path="response", scope_confirmed=True,
                evaluation_config={
                    "tool_agent": {
                        "enabled": True,
                        "identities": [{"id": "restricted", "headers": {"Authorization": f"env:{environment_name}"}}],
                    }
                },
            )
            self.approve(repo, project["id"], target["id"])
            _status, item = app.dispatch("POST", f"/api/projects/{project['id']}/targets/{target['id']}/preflights", {})
            self.assertEqual(item["status"], "blocked")
            self.assertEqual(item["request_count"], 0)
            serialized = json.dumps(item)
            self.assertIn(environment_name, serialized)
            self.assertNotIn("Bearer", serialized)
            repo.close()

    def test_schema_failure_retains_http_response_and_does_not_create_a_run(self) -> None:
        handler = type("MissingResponsePathHandler", (PreflightChatHandler,), {"response_path_present": False})
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        server.requests = []  # type: ignore[attr-defined]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                repo, app = self.make_app(root, target_client=TargetClient(timeout_seconds=3))
                project = repo.create_project(name="Schema preflight")
                target = repo.add_target(
                    project["id"], name="Chat", kind="chatbot", base_url=f"http://127.0.0.1:{server.server_port}",
                    path="/chat", method="POST", request_template={"message": "{{prompt}}"},
                    response_path="response", scope_confirmed=True,
                )
                self.approve(repo, project["id"], target["id"])
                _status, item = app.dispatch("POST", f"/api/projects/{project['id']}/targets/{target['id']}/preflights", {})
                self.assertEqual(item["status"], "failed")
                self.assertEqual(item["request_count"], 1)
                self.assertIn("configured response JSON path", item["error"])
                self.assertIn("unexpected", item["result"]["traffic"][0]["raw"])
                self.assertEqual(repo.get_project(project["id"])["runs"], [])
                repo.close()
        finally:
            server.shutdown()
            server.server_close()

    def test_browser_preflight_validates_selectors_without_submitting(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            browser = BrowserPreflightStub()
            repo, app = self.make_app(root, browser_target_client=browser)  # type: ignore[arg-type]
            project = repo.create_project(name="Browser preflight")
            target = repo.add_target(
                project["id"], name="Browser", kind="browser-chatbot", base_url="https://browser.invalid",
                path="/chat", method="GET", scope_confirmed=True,
                browser_profile={
                    "input_selector": "#input", "submit_selector": "#submit", "response_selector": "#response",
                    "response_stability_ms": 1000, "persistent_session": True,
                },
            )
            self.approve(repo, project["id"], target["id"], allow_screenshots=False)
            _status, item = app.dispatch("POST", f"/api/projects/{project['id']}/targets/{target['id']}/preflights", {})
            self.assertEqual(item["status"], "needs-attention")
            self.assertEqual(item["request_count"], 1)
            self.assertTrue(browser.calls[0]["preflight"])
            self.assertEqual(browser.calls[0]["prompt"], "")
            self.assertEqual(item["result"]["traffic"][0]["captures"], [])
            repo.close()

    @unittest.skipUnless(shutil.which("node") and (Path(__file__).resolve().parents[1] / "node_modules" / "playwright-core").exists(), "browser runtime is not installed")
    def test_real_browser_preflight_navigates_and_never_submits(self) -> None:
        PreflightBrowserHandler.submitted = 0
        server = ThreadingHTTPServer(("127.0.0.1", 0), PreflightBrowserHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                config = AppConfig(database_path=root / "assessment.sqlite3", evidence_root=root / "projects", browser_timeout_seconds=10)
                repo = Repository(config.database_path)
                app = Application(repo, config=config, browser_target_client=BrowserTargetClient(config))
                project = repo.create_project(name="Real browser preflight")
                target = repo.add_target(
                    project["id"], name="Browser", kind="browser-chatbot",
                    base_url=f"http://127.0.0.1:{server.server_port}", path="/", method="GET", scope_confirmed=True,
                    browser_profile={
                        "input_selector": "#input", "submit_selector": "#submit", "response_selector": "#response",
                        "response_stability_ms": 500, "persistent_session": False,
                    },
                )
                self.approve(repo, project["id"], target["id"], allow_screenshots=False)
                _status, item = app.dispatch("POST", f"/api/projects/{project['id']}/targets/{target['id']}/preflights", {})
                self.assertEqual(item["status"], "needs-attention")
                self.assertTrue(item["result"]["browser"]["selectors_ready"])
                self.assertEqual(item["result"]["browser"]["response_selector_matches"], 1)
                self.assertEqual(PreflightBrowserHandler.submitted, 0)
                self.assertEqual(item["result"]["traffic"][0]["captures"], [])
                repo.close()
        finally:
            server.shutdown()
            server.server_close()

    def test_preflight_records_are_project_and_target_isolated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo, app = self.make_app(root, target_client=NoTrafficClient())  # type: ignore[arg-type]
            first = repo.create_project(name="First")
            second = repo.create_project(name="Second")
            target = repo.add_target(
                first["id"], name="Blocked", kind="chatbot", base_url="https://target.invalid",
                path="/chat", method="POST", request_template={"message": "{{prompt}}"},
                response_path="response", scope_confirmed=True,
            )
            _status, item = app.dispatch("POST", f"/api/projects/{first['id']}/targets/{target['id']}/preflights", {})
            with self.assertRaises(NotFoundError):
                app.dispatch("GET", f"/api/projects/{second['id']}/targets/{target['id']}/preflights/{item['id']}", {})
            repo.close()

    def test_mcp_budget_and_legacy_route_are_checked_before_traffic(self) -> None:
        target = {
            "id": "tgt_mcp", "kind": "api", "base_url": "https://mcp.invalid", "path": "/mcp", "method": "POST",
            "headers": {}, "request_template": {}, "response_path": "", "scope_confirmed": True,
            "authorized_routes": [{"path": "/mcp", "methods": ["POST"], "role": "primary"}],
            "analysis_config": {},
            "evaluation_config": {"mcp": {
                "enabled": True, "transport": "legacy-http-sse", "endpoint_path": "/mcp", "legacy_sse_path": "/sse",
                "protocol_versions": ["2024-11-05"], "identities": [{"id": "user", "headers": {}}], "cases": [{}],
            }},
        }
        readiness = build_target_preflight_readiness(target, {"status": "approved", "max_requests": 2, "allow_screenshots": False})
        failures = {item["id"] for item in readiness["checks"] if item["status"] == "fail"}
        self.assertIn("mcp-legacy-route", failures)
        self.assertIn("setup-budget", failures)

    def test_rag_budget_includes_cleanup_verification_control_and_one_reproduction(self) -> None:
        rag_case = {
            "scenario": "external-content-injection",
            "control_query": "Return the benign retrieval marker only.",
        }
        target = {
            "id": "tgt_rag",
            "kind": "api",
            "base_url": "https://rag.invalid",
            "path": "/query",
            "method": "POST",
            "headers": {},
            "request_template": {"query": "{{prompt}}"},
            "response_path": "response",
            "scope_confirmed": True,
            "authorized_routes": [
                {"path": "/query", "methods": ["POST"], "role": "primary"},
                {"path": "/ingest", "methods": ["POST"], "role": "workflow"},
                {"path": "/cleanup", "methods": ["POST"], "role": "workflow"},
            ],
            "analysis_config": {},
            "evaluation_config": {
                "rag": {
                    "enabled": True,
                    "identities": [{"id": "user", "headers": {}}],
                    "operations": {
                        "ingest": {"path": "/ingest", "method": "POST"},
                        "query": {"path": "/query", "method": "POST"},
                        "cleanup": {"path": "/cleanup", "method": "POST"},
                    },
                    "query_attempts": 1,
                    "cleanup_verify_attempts": 1,
                    "cases": [dict(rag_case), dict(rag_case)],
                }
            },
        }
        readiness = build_target_preflight_readiness(
            target,
            {
                "status": "approved",
                "max_requests": 17,
                "allow_reproduction": True,
                "allow_screenshots": False,
            },
        )
        budget = next(item for item in readiness["checks"] if item["id"] == "rag-request-budget")
        self.assertEqual("warning", budget["status"])
        self.assertIn("estimated at 18 requests", budget["message"])

        readiness = build_target_preflight_readiness(
            target,
            {
                "status": "approved",
                "max_requests": 12,
                "allow_reproduction": False,
                "allow_screenshots": False,
            },
        )
        budget = next(item for item in readiness["checks"] if item["id"] == "rag-request-budget")
        self.assertEqual("pass", budget["status"])
        self.assertIn("estimated at 12 requests", budget["message"])

        target["transport_config"] = {"enabled": True, "max_retries": 1}
        target["evaluation_config"]["rag"]["operations"]["query"]["replay_safe"] = True
        readiness = build_target_preflight_readiness(
            target,
            {
                "status": "approved",
                "max_requests": 29,
                "allow_reproduction": True,
                "allow_screenshots": False,
            },
        )
        budget = next(item for item in readiness["checks"] if item["id"] == "rag-request-budget")
        self.assertEqual("warning", budget["status"])
        self.assertIn("estimated at 30 requests", budget["message"])

    def test_mcp_preflight_negotiates_lifecycle_without_calling_a_tool(self) -> None:
        PreflightMCPHandler.requests = []
        server = ThreadingHTTPServer(("127.0.0.1", 0), PreflightMCPHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                repo, app = self.make_app(root, target_client=TargetClient(timeout_seconds=3))
                project = repo.create_project(name="MCP preflight")
                target = repo.add_target(
                    project["id"], name="MCP", kind="api", base_url=f"http://127.0.0.1:{server.server_port}",
                    path="/mcp", method="POST", request_template={}, response_path="", scope_confirmed=True,
                    authorized_routes=[{"path": "/mcp", "methods": ["POST"], "role": "primary"}],
                    evaluation_config={"mcp": {
                        "enabled": True,
                        "transport": "streamable-http",
                        "endpoint_path": "/mcp",
                        "protocol_versions": ["2025-11-25"],
                        "max_pages": 2,
                        "identities": [{"id": "restricted", "headers": {"X-Identity": "restricted"}}],
                        "cases": [{}],
                    }},
                )
                self.approve(repo, project["id"], target["id"], max_requests=5)
                _status, item = app.dispatch("POST", f"/api/projects/{project['id']}/targets/{target['id']}/preflights", {})
                self.assertEqual(item["status"], "ready")
                self.assertEqual(item["request_count"], 2)
                self.assertEqual(item["result"]["protocol"]["negotiated_version"], "2025-11-25")
                self.assertEqual([entry["body"]["method"] for entry in PreflightMCPHandler.requests], ["initialize", "notifications/initialized"])
                self.assertEqual(PreflightMCPHandler.requests[0]["session"], "")
                self.assertEqual(PreflightMCPHandler.requests[1]["session"], "private-session-value")
                self.assertNotIn("private-session-value", json.dumps(item))
                repo.close()
        finally:
            server.shutdown()
            server.server_close()

    def test_runtime_readiness_includes_native_adapter_identity_headers(self) -> None:
        environment_name = "ADV_PREFLIGHT_ADAPTER_TOKEN"
        target = {
            "headers": {}, "request_template": {"message": "{{prompt}}"},
            "evaluation_config": {"mcp": {"identities": [{"headers": {"Authorization": f"env:{environment_name}"}}]}},
        }
        with patch.dict(os.environ, {environment_name: "Bearer adapter-secret"}, clear=False):
            readiness = target_runtime_readiness(target)
        self.assertTrue(readiness["ready"])
        self.assertIn(environment_name, {item["environment"] for item in readiness["checks"]})
        self.assertNotIn("adapter-secret", json.dumps(readiness))


if __name__ == "__main__":
    unittest.main()
