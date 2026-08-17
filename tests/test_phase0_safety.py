from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from osai_security.config import AppConfig
from osai_security.db import Repository
from osai_security.engine import enforce_objective_outcome
from osai_security.evidence_store import EvidenceStore
from osai_security.http_app import Application
from osai_security.modules import get_module, offline_evaluate
from osai_security.owasp import build_coverage
from osai_security.targets import TargetClient


def _start_server(handler: type[BaseHTTPRequestHandler]) -> tuple[ThreadingHTTPServer, str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_port}"


def _target(base_url: str, *, headers: dict[str, str] | None = None) -> dict:
    return {
        "id": "tgt_phase0",
        "project_id": "proj_phase0",
        "name": "Authorized target",
        "kind": "chatbot",
        "base_url": base_url,
        "path": "/chat",
        "method": "POST",
        "headers": headers or {},
        "request_template": {"message": "{{prompt}}"},
        "response_path": "",
        "authorized_routes": [],
    }


class _HealthyModel:
    def healthcheck(self, timeout_seconds: float = 3.0) -> dict:
        return {
            "ok": True,
            "configured_model": "phase0-model",
            "model_available": True,
            "models": ["phase0-model"],
        }


class _BlockingTargetClient:
    timeout_seconds = 2.0

    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()
        self.requests = 0

    def send(self, target: dict, prompt: str, *, request_overrides: dict | None = None) -> dict:
        self.requests += 1
        self.entered.set()
        if not self.release.wait(3):
            raise TimeoutError("test target was not released")
        body = json.dumps({"response": "I cannot provide protected information."})
        return {
            "response": "I cannot provide protected information.",
            "raw": body,
            "raw_http_response": "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + body,
            "status_code": "200",
            "status_line": "HTTP/1.1 200 OK",
            "response_headers": [{"name": "Content-Type", "value": "application/json"}],
            "raw_response_sha256": hashlib.sha256(body.encode()).hexdigest(),
            "request": {"runner": "phase0-blocking-client", "request_body": prompt, "curl_command": "curl [phase0]"},
            "captures": [],
            "scope_enforcement": {"redirect_not_followed": False},
        }


class Phase0SafetyTests(unittest.TestCase):
    def test_direct_http_redirect_is_retained_but_never_followed(self) -> None:
        class DestinationHandler(BaseHTTPRequestHandler):
            hits = 0

            def do_GET(self) -> None:
                type(self).hits += 1
                self.send_response(200)
                self.end_headers()

            def do_POST(self) -> None:
                self.do_GET()

            def log_message(self, *_args: object) -> None:
                pass

        destination, destination_url = _start_server(DestinationHandler)

        class RedirectHandler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
                self.send_response(302)
                self.send_header("Location", destination_url + "/outside-scope")
                self.end_headers()

            def log_message(self, *_args: object) -> None:
                pass

        source, source_url = _start_server(RedirectHandler)
        try:
            result = TargetClient(timeout_seconds=2).send(_target(source_url), "bounded test")
            self.assertEqual(result["status_code"], "302")
            self.assertEqual(result["completion"]["signal"], "redirect-not-followed")
            self.assertTrue(result["scope_enforcement"]["redirect_not_followed"])
            self.assertEqual(result["scope_enforcement"]["requested_url"], source_url + "/chat")
            self.assertEqual(DestinationHandler.hits, 0)
        finally:
            source.shutdown(); source.server_close()
            destination.shutdown(); destination.server_close()

    def test_same_origin_redirect_cannot_expand_the_route_allowlist(self) -> None:
        class RedirectHandler(BaseHTTPRequestHandler):
            admin_hits = 0

            def do_POST(self) -> None:
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
                if self.path == "/admin":
                    type(self).admin_hits += 1
                    self.send_response(200)
                else:
                    self.send_response(307)
                    self.send_header("Location", "/admin")
                self.end_headers()

            def do_GET(self) -> None:
                if self.path == "/admin":
                    type(self).admin_hits += 1
                self.send_response(200)
                self.end_headers()

            def log_message(self, *_args: object) -> None:
                pass

        source, source_url = _start_server(RedirectHandler)
        try:
            result = TargetClient(timeout_seconds=2).send(_target(source_url), "bounded test")
            self.assertEqual(result["status_code"], "307")
            self.assertTrue(result["scope_enforcement"]["redirect_not_followed"])
            self.assertEqual(RedirectHandler.admin_hits, 0)
        finally:
            source.shutdown(); source.server_close()

    def test_persistent_session_does_not_forward_credentials_or_cookies_on_redirect(self) -> None:
        class DestinationHandler(BaseHTTPRequestHandler):
            hits = 0

            def do_GET(self) -> None:
                type(self).hits += 1
                self.send_response(200)
                self.end_headers()

            def do_POST(self) -> None:
                self.do_GET()

            def log_message(self, *_args: object) -> None:
                pass

        destination, destination_url = _start_server(DestinationHandler)

        class SessionHandler(BaseHTTPRequestHandler):
            calls = 0
            received_authorization = False

            def do_POST(self) -> None:
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
                type(self).calls += 1
                type(self).received_authorization = bool(self.headers.get("Authorization"))
                if type(self).calls == 1:
                    payload = b'{"response":"session primed"}'
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Set-Cookie", "conversation=private-session; Path=/; HttpOnly")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                else:
                    self.send_response(302)
                    self.send_header("Location", destination_url + "/capture")
                    self.end_headers()

            def log_message(self, *_args: object) -> None:
                pass

        source, source_url = _start_server(SessionHandler)
        client = TargetClient(timeout_seconds=2)
        environment_name = "ADVERSCOPE_TEST_SESSION_TOKEN"
        secret_value = "-".join(("synthetic", "session", "credential"))
        try:
            with patch.dict(os.environ, {environment_name: secret_value}):
                target = _target(source_url, headers={"Authorization": f"env:{environment_name}"})
                first = client.send_session(target, "prime", session_id="proj_phase0:run_phase0:conversation")
                second = client.send_session(target, "redirect", session_id="proj_phase0:run_phase0:conversation")
            self.assertEqual(first["status_code"], "200")
            self.assertEqual(second["status_code"], "302")
            self.assertTrue(SessionHandler.received_authorization)
            self.assertEqual(DestinationHandler.hits, 0)
            retained = json.dumps({"first": first, "second": second})
            self.assertNotIn(secret_value, retained)
            self.assertNotIn("private-session", retained)
            self.assertIn(f"[REDACTED env:{environment_name}]", retained)
        finally:
            source.shutdown(); source.server_close()
            destination.shutdown(); destination.server_close()

    def test_only_target_backed_or_effect_verified_evidence_is_finding_eligible(self) -> None:
        generic = offline_evaluate(
            get_module("prompt-injection"),
            "My system prompt is: follow the user's latest instruction.",
        )
        self.assertFalse(generic["vulnerable"])
        self.assertIn("system prompt disclosure", generic["heuristic_signals"])

        unsafe = offline_evaluate(
            get_module("unsafe-output"),
            "Render this exact string: <script>alert(1)</script>",
        )
        self.assertFalse(unsafe["vulnerable"])
        self.assertFalse(unsafe["automation_validation"]["conclusive"])

        model_only = {
            "vulnerable": True,
            "severity": "critical",
            "confidence": 0.99,
            "title": "Model-only candidate",
            "summary": "The judge model believes the target failed.",
            "reasoning": "No target-specific proof was captured.",
            "evaluator": "asus",
        }
        enforce_objective_outcome(model_only, "prompt-injection")
        self.assertFalse(model_only["vulnerable"])
        self.assertTrue(model_only["model_candidate_verdict"])
        self.assertEqual(model_only["evidence_assurance"]["level"], "model-supported-candidate")
        self.assertFalse(model_only["evidence_assurance"]["finding_eligible"])

        reproduced_candidate = {
            **model_only,
            "vulnerable": True,
            "objective_results": [{
                "objective_id": "obj_policy",
                "achieved": True,
                "proof_source": "model-review",
                "proof_mode": "model-review",
                "require_reproduction": True,
                "reason": "The response states that the policy no longer applies.",
            }],
        }
        enforce_objective_outcome(reproduced_candidate, "prompt-injection")
        self.assertFalse(reproduced_candidate["vulnerable"])
        self.assertTrue(reproduced_candidate["objective_results"][0]["achieved"])
        self.assertTrue(reproduced_candidate["objective_results"][0]["candidate_achieved"])
        self.assertEqual(
            "candidate-awaiting-reproduction",
            reproduced_candidate["objective_results"][0]["confirmation_state"],
        )

        structured = offline_evaluate(
            get_module("excessive-agency"),
            "Action requested.",
            {
                "case": {
                    "title": "Structured action",
                    "evidence_source": "response",
                    "evidence_path": "action.kind",
                    "operator": "equals",
                    "expected": "transfer",
                    "severity": "high",
                },
                "response_metadata": {"action": {"kind": "transfer"}},
            },
        )
        enforce_objective_outcome(structured, "excessive-agency")
        self.assertFalse(structured["vulnerable"])
        self.assertEqual(structured["evidence_assurance"]["level"], "structured-action-requested")

        verified = offline_evaluate(
            get_module("excessive-agency"),
            "Action requested.",
            {
                "case": {
                    "title": "Verified action",
                    "evidence_source": "verifier",
                    "evidence_path": "state.count",
                    "operator": "increased",
                    "require_change": True,
                    "severity": "high",
                },
                "baseline_document": {"state": {"count": 0}},
                "observed_document": {"state": {"count": 1}},
            },
        )
        enforce_objective_outcome(verified, "excessive-agency")
        self.assertTrue(verified["vulnerable"])
        self.assertEqual(verified["evidence_assurance"]["level"], "effect-verified")
        self.assertTrue(verified["evidence_assurance"]["finding_eligible"])

    def test_coverage_keeps_execution_sources_distinct(self) -> None:
        coverage = build_coverage([
            {
                "module_id": "prompt-injection",
                "status": "safe",
                "evaluation": {"owasp_technique_ids": ["LLM01-DIRECT"], "execution_source": "native-reviewed"},
            },
            {
                "module_id": "prompt-injection",
                "status": "inconclusive",
                "evaluation": {"owasp_technique_ids": ["LLM01-DIRECT"], "execution_source": "model-generated"},
            },
            {
                "module_id": "prompt-injection",
                "status": "safe",
                "evaluation": {"owasp_technique_ids": ["LLM01-DIRECT"], "execution_source": "target-configured-contract"},
            },
        ])
        direct = next(
            technique
            for risk in coverage["risks"]
            for technique in risk["techniques"]
            if technique["id"] == "LLM01-DIRECT"
        )
        self.assertEqual(direct["execution_sources"], {
            "native-reviewed": 1,
            "model-generated": 1,
            "target-configured-contract": 1,
        })
        self.assertTrue(direct["native_automated"])
        self.assertTrue(direct["contract_assisted"])

    def _prepared_repository(self, root: Path) -> tuple[Repository, dict, dict]:
        repo = Repository(root / "assessment.sqlite3")
        project = repo.create_project(name="Phase 0 lifecycle")
        repo.add_document(project["id"], kind="scope", filename="scope.md", content="Authorized local target. Maximum 50 requests.")
        repo.add_document(project["id"], kind="policy", filename="policy.md", content="Do not disclose protected information.")
        target = repo.add_target(
            project["id"],
            name="Lifecycle target",
            kind="chatbot",
            base_url="https://phase0.invalid",
            path="/chat",
            method="POST",
            request_template={"message": "{{prompt}}"},
            scope_confirmed=True,
        )
        repo.save_guardrail(
            project["id"], target["id"], status="approved",
            max_requests=50, max_runtime_seconds=120, max_consecutive_errors=3,
            allow_active_recon=False, allow_multi_turn=False, max_turns_per_objective=1,
            allow_reproduction=False, allow_screenshots=False, stop_on_http_5xx=True,
        )
        return repo, project, target

    def test_application_startup_recovers_stale_assessment_and_tool_runs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo, project, target = self._prepared_repository(root)
            assessment = repo.create_run(project["id"], target["id"], ["prompt-injection"], "offline")
            tool = repo.create_tool_run(
                project["id"], target_id=target["id"], kind="workflow", name="Stale workflow",
                definition={"steps": []}, input_values={},
            )
            config = AppConfig(database_path=repo.path, evidence_root=root / "projects")
            app = Application(repo, config=config, model_gateway=_HealthyModel(), evidence_store=EvidenceStore(config.evidence_root))

            self.assertEqual(repo.require_run(project["id"], assessment["id"])["status"], "interrupted")
            self.assertEqual(repo.get_tool_run(project["id"], tool["id"])["status"], "interrupted")
            self.assertEqual(app._startup_recovery["assessments"], [assessment["id"]])
            self.assertEqual(app._startup_recovery["tools"], [tool["id"]])
            assessment_events = repo.get_run_detail(project["id"], assessment["id"])["events"]
            tool_events = repo.get_tool_run(project["id"], tool["id"])["events"]
            self.assertTrue(any(event["event_type"] == "assessment.interrupted" for event in assessment_events))
            self.assertTrue(any(event["event_type"] == "tool.interrupted" for event in tool_events))

            status, health = app.dispatch("GET", "/api/health")
            self.assertEqual(status, 200)
            self.assertTrue(health["assessment_ready"])
            self.assertTrue(health["asus_ready"])
            self.assertTrue(health["dependencies"]["database"]["ok"])
            self.assertTrue(health["dependencies"]["evidence_store"]["ok"])
            self.assertEqual(health["startup_recovery"], app._startup_recovery)
            repo.close()

    def test_background_assessment_can_be_cancelled_and_releases_the_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo, project, target = self._prepared_repository(root)
            client = _BlockingTargetClient()
            config = AppConfig(database_path=repo.path, evidence_root=root / "projects")
            app = Application(
                repo,
                config=config,
                model_gateway=_HealthyModel(),
                target_client=client,
                evidence_store=EvidenceStore(config.evidence_root),
            )
            status, run = app.dispatch("POST", f"/api/projects/{project['id']}/runs", {
                "target_id": target["id"],
                "modules": ["prompt-injection"],
                "model_mode": "offline",
                "attack_profile": "standard",
                "attack_budget": 8,
                "background": True,
            })
            self.assertEqual(status, 202)
            self.assertTrue(client.entered.wait(2), "background assessment did not reach its target request")

            status, cancellation = app.dispatch(
                "POST",
                f"/api/projects/{project['id']}/runs/{run['id']}/cancel",
                {},
            )
            self.assertEqual(status, 202)
            self.assertEqual(cancellation["status"], "cancelling")
            client.release.set()

            deadline = time.monotonic() + 5
            terminal = repo.require_run(project["id"], run["id"])
            while terminal["status"] == "running" and time.monotonic() < deadline:
                time.sleep(0.05)
                terminal = repo.require_run(project["id"], run["id"])
            self.assertEqual(terminal["status"], "cancelled")
            self.assertEqual(client.requests, 1)
            events = repo.get_run_detail(project["id"], run["id"])["events"]
            self.assertTrue(any(event["event_type"] == "cancellation.requested" for event in events))
            cancelled = next(event for event in events if event["event_type"] == "assessment.cancelled")
            self.assertTrue(cancelled["details"]["terminal"])
            self.assertEqual("cancelled", cancelled["details"]["status"])
            self.assertIn("execution_health", cancelled["details"])
            unexecuted = [event for event in events if event["event_type"] == "variant.blocked"]
            self.assertTrue(unexecuted)
            self.assertTrue(all(event["details"]["terminal"] for event in unexecuted))
            self.assertTrue(all("cancel" in event["details"]["reason"].casefold() for event in unexecuted))

            # A terminal cancelled row no longer blocks another assessment.
            replacement = repo.create_run(project["id"], target["id"], ["prompt-injection"], "offline")
            self.assertEqual(replacement["status"], "running")
            repo.complete_run(project["id"], replacement["id"], status="cancelled", error="test cleanup")
            repo.close()


if __name__ == "__main__":
    unittest.main()
