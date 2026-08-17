from __future__ import annotations

import json
import tempfile
import threading
import unittest
import urllib.request
from pathlib import Path
from unittest.mock import patch

from osai_security.config import AppConfig
from osai_security.db import NotFoundError, Repository
from osai_security.guardrails import ExecutionGuard
from osai_security.http_app import Application, create_server
from osai_security.quality_gates import audit_tool_run
from osai_security.targets import TargetError, request_log_preview, validate_authorized_routes
from osai_security.tool_engine import execute_tool_run, normalize_tool_definition
from osai_security.tool_packs import instantiate_tool_pack


class FakeToolTargetClient:
    timeout_seconds = 5.0

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, object]] = []
        self.delayed_status = False
        self.status_attempts = 0

    def send_authorized(self, target, *, path, method, payload=None, response_path="", body_encoding="json"):
        from osai_security.targets import route_is_authorized
        if not route_is_authorized(target, path, method):
            raise TargetError(f"{method} {path} is not in the target's authorized route allowlist")
        self.calls.append((method, path, payload))
        if path == "/start":
            document = {"job": {"id": "job-42"}}
        elif path.startswith("/status"):
            self.status_attempts += 1
            document = {"done": not self.delayed_status or self.status_attempts >= 2, "flag": "2501{workflow_complete}"}
        else:
            message = payload.get("message", "") if isinstance(payload, dict) else ""
            if message == "metadata-only-spaced-proof":
                document = {
                    "response": "safe refusal",
                    "debug": {"request_echo": "2 5 0 1 { w h i t e s p a c e _ p r o o f }"},
                }
            else:
                document = {
                    "response": (
                        "2 5 0 1 { w h i t e s p a c e _ p r o o f }"
                        if message == "spaced-proof"
                        else f"echo:{message}"
                    ),
                }
        raw = json.dumps(document)
        return {
            "status_code": "200", "status_line": "HTTP/1.1 200 OK", "response": document.get(response_path, raw) if response_path else raw,
            "raw": raw, "raw_http_response": f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{raw}",
            "raw_response_sha256": "a" * 64, "response_headers": [{"name": "Content-Type", "value": "application/json"}],
            "request": request_log_preview(target, "", timeout_seconds=self.timeout_seconds, path_override=path, method_override=method, payload_override=payload, body_encoding=body_encoding),
            "captures": [], "completion": {"streaming": False, "signal": "response-closed"},
        }


class StochasticCampaignClient(FakeToolTargetClient):
    def __init__(self, reproduction_results: list[bool]) -> None:
        super().__init__()
        self.reproduction_results = list(reproduction_results)

    def send_authorized(self, target, *, path, method, payload=None, response_path="", body_encoding="json"):
        result = super().send_authorized(
            target,
            path=path,
            method=method,
            payload=payload,
            response_path=response_path,
            body_encoding=body_encoding,
        )
        message = payload.get("message", "") if isinstance(payload, dict) else ""
        if message == "initial-proof":
            response = "target-proof"
        elif message == "reproduction-proof":
            response = "target-proof" if self.reproduction_results and self.reproduction_results.pop(0) else "safe refusal"
        else:
            return result
        document = {"response": response}
        raw = json.dumps(document)
        result.update({
            "response": document.get(response_path, raw) if response_path else raw,
            "raw": raw,
            "raw_http_response": f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{raw}",
        })
        return result


class TestingToolsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.repo = Repository(self.root / "adverscope.sqlite3")
        self.project = self.repo.create_project(name="Tool project", client="Lab")
        self.repo.add_document(self.project["id"], kind="scope", filename="scope.md", content="Authorized same-origin API testing. Maximum 50 requests.")
        self.repo.add_document(self.project["id"], kind="policy", filename="policy.md", content="Synthetic lab flags may be collected as evidence.")
        routes = validate_authorized_routes(
            [
                {"path": "/start", "methods": ["POST"]},
                {"path": "/status", "methods": ["GET"]},
                {"path": "/chat/{level}", "methods": ["POST"]},
                {"path": "/custom-mcp", "methods": ["POST"]},
            ],
            primary_path="/start", primary_method="POST",
        )
        self.target = self.repo.add_target(
            self.project["id"], name="Workflow API", kind="api", base_url="http://target.invalid",
            path="/start", method="POST", authorized_routes=routes, scope_confirmed=True,
        )
        self.repo.save_guardrail(
            self.project["id"], self.target["id"], status="approved",
            max_requests=50, max_runtime_seconds=900, max_consecutive_errors=3,
            allow_active_recon=False, allow_multi_turn=False, max_turns_per_objective=1,
            allow_reproduction=True, allow_screenshots=False, stop_on_http_5xx=True,
            notes="Approved deterministic testing-tool fixture boundary.",
        )
        self.client = FakeToolTargetClient()

    def tearDown(self) -> None:
        self.repo.close()
        self.temp.cleanup()

    def test_workflow_captures_values_polls_and_preserves_exact_events(self) -> None:
        definition = normalize_tool_definition("workflow", {
            "security_outcomes": [{
                "id": "protected-metadata",
                "title": "Protected workflow metadata disclosed",
                "summary": "The verifier response returned the configured synthetic proof marker.",
                "severity": "high",
                "confidence": 0.97,
                "risk_ids": ["LLM03"],
                "technique_ids": ["LLM03-DEPS"],
                "required_step_ids": ["status"],
                "confirmation": "key-pattern",
            }],
            "steps": [
                {"id": "start", "type": "http", "method": "POST", "path": "/start", "body": {"action": "begin"}, "captures": {"job_id": "$.job.id"}, "assertions": [{"type": "status", "equals": 200}]},
                {"id": "status", "type": "poll", "method": "GET", "path": "/status?job={{captures.job_id}}", "max_attempts": 2, "interval_ms": 0, "assertions": [{"type": "json_equals", "path": "$.done", "equals": True}, {"type": "body_regex", "pattern": "2501\\{"}]},
            ]
        })
        saved = self.repo.create_tool_definition(self.project["id"], target_id=self.target["id"], kind="workflow", name="State chain", description="Capture and poll", definition=definition)
        run = self.repo.create_tool_run(self.project["id"], target_id=self.target["id"], kind="workflow", name=saved["name"], definition=saved["definition"], definition_id=saved["id"])
        completed = execute_tool_run(self.repo, project_id=self.project["id"], tool_run_id=run["id"], target_client=self.client)
        self.assertEqual(completed["status"], "completed")
        self.assertEqual(completed["context"]["captures"]["job_id"], "job-42")
        self.assertTrue(completed["context"]["all_required_assertions_passed"])
        self.assertEqual(self.client.calls[1][1], "/status?job=job-42")
        request_events = [event for event in completed["events"] if event["event_type"] == "request.sent"]
        self.assertEqual(len(request_events), 2)
        self.assertIn("curl --silent", request_events[0]["details"]["curl_command"])
        self.assertEqual(completed["counts"]["assertions_failed"], 0)
        self.assertEqual(completed["context"]["security_outcomes"][0]["status"], "confirmed")
        self.assertEqual(len(completed["security_findings"]), 1)
        self.assertEqual(completed["security_findings"][0]["technique_ids"], ["LLM03-DEPS"])
        project = self.repo.get_project(self.project["id"])
        self.assertEqual(project["counts"]["tool_findings"], 1)
        self.assertEqual(next(item for item in project["owasp_coverage"]["risks"] if item["id"] == "LLM03")["status"], "confirmed")

        app = Application(self.repo, config=AppConfig(database_path=self.repo.path, evidence_root=self.root / "evidence"), target_client=self.client)
        status, reviewed = app.dispatch("PATCH", f"/api/projects/{self.project['id']}/tool-findings/{completed['security_findings'][0]['id']}", {"status": "accepted"})
        self.assertEqual(status, 200)
        self.assertEqual(reviewed["status"], "accepted")
        adjudications = self.repo.list_adjudications(self.project["id"], execution_kind="tool", execution_id=completed["id"])
        self.assertEqual(adjudications[0]["classification"], "true_positive")

    def test_form_body_encoding_is_explicit_and_replayable(self) -> None:
        definition = normalize_tool_definition("workflow", {
            "steps": [{
                "id": "login", "type": "http", "method": "POST", "path": "/start",
                "body_encoding": "form", "body": {"username": "reviewer", "password": "synthetic"},
                "assertions": [{"type": "status", "equals": 200}],
            }],
        })
        self.assertEqual(definition["steps"][0]["body_encoding"], "form")
        preview = request_log_preview(
            self.target, "", path_override="/start", method_override="POST",
            payload_override={"username": "reviewer", "password": "synthetic"}, body_encoding="form",
        )
        self.assertEqual(preview["headers"]["Content-Type"], "application/x-www-form-urlencoded")
        self.assertEqual(preview["request_body"], "username=reviewer&password=synthetic")
        self.assertIn("username=reviewer&password=synthetic", preview["curl_command"])

    def test_poll_retries_are_pending_until_the_terminal_attempt(self) -> None:
        self.client.delayed_status = True
        definition = normalize_tool_definition("workflow", {
            "steps": [{
                "id": "status", "type": "poll", "method": "GET", "path": "/status",
                "max_attempts": 3, "interval_ms": 0,
                "assertions": [{"type": "json_equals", "path": "$.done", "equals": True, "label": "Job completed"}],
            }],
        })
        run = self.repo.create_tool_run(self.project["id"], target_id=self.target["id"], kind="workflow", name="Delayed poll", definition=definition)
        completed = execute_tool_run(self.repo, project_id=self.project["id"], tool_run_id=run["id"], target_client=self.client)
        self.assertEqual(completed["status"], "completed")
        self.assertEqual(completed["counts"]["assertions_failed"], 0)
        self.assertEqual(completed["counts"]["assertions_passed"], 1)
        self.assertEqual(len([event for event in completed["events"] if event["event_type"] == "assertion.pending"]), 1)
        self.assertTrue(completed["context"]["all_required_assertions_passed"])

    def test_optional_assertion_miss_is_not_counted_as_a_failure(self) -> None:
        definition = normalize_tool_definition("workflow", {
            "steps": [{
                "id": "status", "type": "http", "method": "GET", "path": "/status",
                "assertions": [{"type": "json_equals", "path": "$.done", "equals": False, "required": False}],
            }],
        })
        run = self.repo.create_tool_run(self.project["id"], target_id=self.target["id"], kind="workflow", name="Optional signal", definition=definition)
        completed = execute_tool_run(self.repo, project_id=self.project["id"], tool_run_id=run["id"], target_client=self.client)
        self.assertEqual(completed["counts"]["assertions_failed"], 0)
        self.assertEqual(len([event for event in completed["events"] if event["event_type"] == "assertion.not_observed"]), 1)
        self.assertTrue(completed["context"]["all_required_assertions_passed"])

    def test_invalid_body_encoding_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported body encoding"):
            normalize_tool_definition("workflow", {
                "steps": [{"id": "login", "type": "http", "method": "POST", "path": "/start", "body_encoding": "binary"}],
            })

    def test_invalid_body_regex_normalizer_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported regex normalizer"):
            normalize_tool_definition("workflow", {
                "steps": [{
                    "id": "probe", "type": "http", "method": "GET", "path": "/status",
                    "assertions": [{"type": "body_regex", "pattern": "proof", "normalizer": "decode-anything"}],
                }],
            })

    def test_assertion_roles_default_safely_and_reject_unknown_values(self) -> None:
        definition = normalize_tool_definition("workflow", {
            "steps": [{
                "id": "probe", "type": "http", "method": "GET", "path": "/status",
                "assertions": [
                    {"type": "status", "equals": 200},
                    {"type": "json_equals", "path": "$.confirmed", "equals": True},
                ],
            }],
        })
        assertions = definition["steps"][0]["assertions"]
        self.assertEqual([item["role"] for item in assertions], ["precondition", "evidence"])
        with self.assertRaisesRegex(ValueError, "unsupported assertion role"):
            normalize_tool_definition("workflow", {
                "steps": [{
                    "id": "probe", "type": "http", "method": "GET", "path": "/status",
                    "assertions": [{"type": "status", "equals": 200, "role": "pass-anyway"}],
                }],
            })

    def test_security_outcome_contract_rejects_unknown_steps_and_unmapped_outcomes(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown steps"):
            normalize_tool_definition("workflow", {
                "steps": [{"id": "probe", "type": "http", "method": "GET", "path": "/status"}],
                "security_outcomes": [{
                    "id": "bad-step", "title": "Bad", "summary": "Bad mapping",
                    "technique_ids": ["LLM03-DEPS"], "required_step_ids": ["missing"],
                }],
            })

        with self.assertRaisesRegex(ValueError, "required evidence assertion"):
            normalize_tool_definition("workflow", {
                "steps": [{
                    "id": "reachable", "type": "http", "method": "GET", "path": "/status",
                    "assertions": [{"type": "status", "equals": 200}],
                }],
                "security_outcomes": [{
                    "id": "http-only", "title": "HTTP alone", "summary": "A response alone is not security proof.",
                    "technique_ids": ["LLM03-DEPS"], "required_step_ids": ["reachable"],
                }],
            })
        with self.assertRaisesRegex(ValueError, "OWASP technique"):
            normalize_tool_definition("workflow", {
                "steps": [{"id": "probe", "type": "http", "method": "GET", "path": "/status"}],
                "security_outcomes": [{
                    "id": "unmapped", "title": "Unmapped", "summary": "No taxonomy mapping",
                    "required_step_ids": ["probe"],
                }],
            })

    def test_campaign_route_template_and_replay_denial_are_enforced(self) -> None:
        campaign_definition = normalize_tool_definition("campaign", {
            "request": {"method": "POST", "path": "{{payload_item.path}}", "body": {"message": "{{payload}}"}, "assertions": [{"type": "status", "equals": 200}]},
            "payloads": [
                {"label": "Level A", "path": "/chat/A", "value": "first"},
                {"label": "Level D", "path": "/chat/D", "value": "second"},
            ],
        })
        run = self.repo.create_tool_run(self.project["id"], target_id=self.target["id"], kind="campaign", name="Matrix", definition=campaign_definition)
        completed = execute_tool_run(self.repo, project_id=self.project["id"], tool_run_id=run["id"], target_client=self.client)
        self.assertEqual(completed["status"], "completed")
        self.assertEqual([call[1] for call in self.client.calls], ["/chat/A", "/chat/D"])

        denied_definition = normalize_tool_definition("replay", {"request": {"method": "POST", "path": "/admin/delete", "body": {"confirm": True}}})
        denied = self.repo.create_tool_run(self.project["id"], target_id=self.target["id"], kind="replay", name="Denied route", definition=denied_definition)
        denied = execute_tool_run(self.repo, project_id=self.project["id"], tool_run_id=denied["id"], target_client=self.client)
        self.assertEqual(denied["status"], "completed_with_errors")
        self.assertIn("authorized route allowlist", denied["error"])
        self.assertNotIn("/admin/delete", [call[1] for call in self.client.calls])

    def test_campaign_confirms_and_reproduces_one_match_per_configured_group(self) -> None:
        campaign_definition = normalize_tool_definition("campaign", {
            "request": {
                "method": "POST", "path": "{{payload_item.path}}",
                "body": {"message": "{{payload}}"},
                "assertions": [
                    {"type": "status", "equals": 200},
                    {"type": "body_contains", "value": "echo:success"},
                ],
            },
            "payloads": [
                {"label": "initial miss", "path": "/chat/A", "value": "miss", "match_group": "A:initial"},
                {"label": "initial proof", "path": "/chat/A", "value": "success", "match_group": "A:initial"},
                {"label": "initial skipped", "path": "/chat/A", "value": "success", "match_group": "A:initial"},
                {"label": "reproduction proof", "path": "/chat/A", "value": "success", "match_group": "A:reproduction"},
                {"label": "reproduction skipped", "path": "/chat/A", "value": "success", "match_group": "A:reproduction"},
            ],
            "stop_on_match_by": "match_group",
            "security_outcomes": [{
                "id": "level-a-bypass", "title": "Level A bypassed",
                "summary": "A grouped payload was reproduced.",
                "severity": "high", "confidence": 0.98,
                "risk_ids": ["LLM01"], "technique_ids": ["LLM01-DIRECT"],
                "required_any_step_groups": [
                    ["campaign_1", "campaign_2", "campaign_3"],
                    ["campaign_4", "campaign_5"],
                ],
                "reproduction_step_ids": ["campaign_4", "campaign_5"],
                "confirmation": "reproduction",
            }],
        })
        run = self.repo.create_tool_run(
            self.project["id"], target_id=self.target["id"], kind="campaign",
            name="Grouped matrix", definition=campaign_definition,
        )

        completed = execute_tool_run(
            self.repo, project_id=self.project["id"], tool_run_id=run["id"], target_client=self.client,
        )

        self.assertEqual("completed", completed["status"])
        self.assertEqual(3, len(self.client.calls))
        self.assertEqual("confirmed", completed["context"]["security_outcomes"][0]["status"])
        self.assertEqual(["campaign_2", "campaign_4"], completed["context"]["security_outcomes"][0]["required_step_ids"])
        self.assertEqual(["campaign_4"], completed["context"]["security_outcomes"][0]["reproduction_step_ids"])
        self.assertEqual(2, sum(event["event_type"] == "campaign.skipped" for event in completed["events"]))
        audit = audit_tool_run(completed)
        self.assertEqual(1, audit["finding_count"])
        self.assertEqual(1, audit["confirmed_reproductions"])
        self.assertEqual([], audit["missing_finding_evidence"])

    @staticmethod
    def _stochastic_campaign_definition() -> dict:
        return normalize_tool_definition("campaign", {
            "request": {
                "method": "POST", "path": "/chat/A", "body": {"message": "{{payload}}"},
                "assertions": [
                    {"type": "status", "equals": 200},
                    {"type": "json_contains", "path": "$.response", "value": "target-proof"},
                ],
            },
            "payloads": [
                {
                    "label": "initial proof", "value": "initial-proof",
                    "match_group": "A:initial", "replay_key": "A:strategy-one",
                },
                {
                    "label": "reproduction proof", "value": "reproduction-proof",
                    "match_group": "A:reproduction", "replay_key": "A:strategy-one",
                },
            ],
            "stop_on_match_by": "match_group",
            "bounded_reproduction": True,
            "security_outcomes": [{
                "id": "stochastic-boundary", "title": "Stochastic boundary failure reproduced",
                "summary": "The target-configured proof crossed the boundary in a bounded replay.",
                "severity": "high", "confidence": 0.9,
                "risk_ids": ["LLM01"], "technique_ids": ["LLM01-OBFUSCATED"],
                "required_any_step_groups": [["campaign_1"], ["campaign_2"]],
                "reproduction_step_ids": ["campaign_2"], "confirmation": "reproduction",
            }],
        })

    def _save_statistical_guardrail(
        self,
        *,
        allow_reproduction: bool = True,
        max_requests: int = 50,
        maximum_attempts: int = 3,
        minimum_successes: int = 1,
        minimum_success_rate: float = 0.33,
    ) -> None:
        self.repo.save_guardrail(
            self.project["id"], self.target["id"], status="approved",
            max_requests=max_requests, max_runtime_seconds=900, max_consecutive_errors=3,
            allow_active_recon=False, allow_multi_turn=False, max_turns_per_objective=1,
            allow_reproduction=allow_reproduction, reproduction_mode="bounded-statistical",
            reproduction_max_attempts=maximum_attempts,
            reproduction_min_successes=minimum_successes,
            reproduction_min_success_rate=minimum_success_rate,
            allow_screenshots=False, stop_on_http_5xx=True,
            notes="Approved bounded statistical campaign reproduction.",
        )

    def test_campaign_bounded_reproduction_retries_the_explicitly_paired_payload(self) -> None:
        self._save_statistical_guardrail()
        client = StochasticCampaignClient([False, False, True])
        run = self.repo.create_tool_run(
            self.project["id"], target_id=self.target["id"], kind="campaign",
            name="Stochastic campaign", definition=self._stochastic_campaign_definition(),
        )

        completed = execute_tool_run(
            self.repo, project_id=self.project["id"], tool_run_id=run["id"], target_client=client,
        )

        self.assertEqual("completed", completed["status"])
        self.assertEqual(4, len(client.calls))
        self.assertEqual(
            "confirmed", completed["context"]["security_outcomes"][0]["status"],
            completed["context"]["security_outcomes"][0],
        )
        summary = completed["context"]["security_outcomes"][0]["reproduction_assessment"]
        self.assertEqual("stochastic-confirmed", summary["classification"])
        self.assertEqual(3, summary["attempts"])
        self.assertEqual(1, summary["successful_attempts"])
        self.assertEqual(1, len(completed["security_findings"]))
        reproduction_requests = [
            event for event in completed["events"]
            if event["event_type"] == "request.sent" and event["step_id"] == "campaign_2"
        ]
        self.assertEqual([1, 2, 3], [event["details"]["attempt"] for event in reproduction_requests])

    def test_statistical_guardrail_supports_fifty_samples_for_low_frequency_failures(self) -> None:
        self._save_statistical_guardrail(
            max_requests=100,
            maximum_attempts=50,
            minimum_successes=1,
            minimum_success_rate=0.02,
        )

        guardrail = self.repo.get_guardrail(self.project["id"], self.target["id"])

        self.assertEqual("bounded-statistical", guardrail["reproduction_mode"])
        self.assertEqual(50, guardrail["reproduction_max_attempts"])
        self.assertEqual(1, guardrail["reproduction_min_successes"])
        self.assertEqual(0.02, guardrail["reproduction_min_success_rate"])

    def test_testing_tool_runs_inherit_saved_target_request_pacing(self) -> None:
        self.repo.update_target_transport_config(
            self.project["id"],
            self.target["id"],
            {"enabled": False, "min_request_interval_ms": 2100},
        )
        run = self.repo.create_tool_run(
            self.project["id"],
            target_id=self.target["id"],
            kind="campaign",
            name="Paced campaign",
            definition=normalize_tool_definition("campaign", {
                "request": {
                    "method": "POST",
                    "path": "/chat/A",
                    "body": {"message": "{{payload}}"},
                    "assertions": [{"type": "status", "equals": 200}],
                },
                "payloads": [{"label": "single probe", "value": "test"}],
            }),
        )
        captured: dict[str, int] = {}

        def guard_factory(snapshot, *, cancel_event=None, min_request_interval_ms=0):
            captured["min_request_interval_ms"] = min_request_interval_ms
            return ExecutionGuard(snapshot, cancel_event=cancel_event, min_request_interval_ms=0)

        with patch("osai_security.tool_engine.ExecutionGuard", side_effect=guard_factory):
            completed = execute_tool_run(
                self.repo,
                project_id=self.project["id"],
                tool_run_id=run["id"],
                target_client=FakeToolTargetClient(),
            )

        self.assertEqual("completed", completed["status"])
        self.assertEqual(2100, captured["min_request_interval_ms"])

    def test_campaign_bounded_reproduction_does_not_confirm_below_threshold(self) -> None:
        self._save_statistical_guardrail(minimum_successes=2, minimum_success_rate=0.66)
        client = StochasticCampaignClient([False, True, False])
        run = self.repo.create_tool_run(
            self.project["id"], target_id=self.target["id"], kind="campaign",
            name="Stochastic negative control", definition=self._stochastic_campaign_definition(),
        )

        completed = execute_tool_run(
            self.repo, project_id=self.project["id"], tool_run_id=run["id"], target_client=client,
        )

        self.assertEqual("completed", completed["status"])
        self.assertEqual("not_demonstrated", completed["context"]["security_outcomes"][0]["status"])
        self.assertFalse(completed["context"]["security_outcomes"][0]["reproduction_assessment"]["threshold_met"])
        self.assertEqual([], completed["security_findings"])

    def test_campaign_bounded_reproduction_rejects_a_different_strategy_success(self) -> None:
        self._save_statistical_guardrail(maximum_attempts=3, minimum_success_rate=0.33)

        class StrategySpecificClient(FakeToolTargetClient):
            def __init__(self) -> None:
                super().__init__()
                self.messages: list[str] = []

            def send_authorized(self, target, *, path, method, payload=None, response_path="", body_encoding="json"):
                result = super().send_authorized(
                    target, path=path, method=method, payload=payload,
                    response_path=response_path, body_encoding=body_encoding,
                )
                message = payload.get("message", "") if isinstance(payload, dict) else ""
                self.messages.append(message)
                response = "target-proof" if message in {"initial-a", "reproduction-b"} else "safe refusal"
                document = {"response": response}
                raw = json.dumps(document)
                result.update({
                    "response": document.get(response_path, raw) if response_path else raw,
                    "raw": raw,
                    "raw_http_response": f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{raw}",
                })
                return result

        definition = normalize_tool_definition("campaign", {
            "request": {
                "method": "POST", "path": "/chat/A", "body": {"message": "{{payload}}"},
                "assertions": [
                    {"type": "status", "equals": 200},
                    {"type": "json_contains", "path": "$.response", "value": "target-proof"},
                ],
            },
            "payloads": [
                {"label": "initial A", "value": "initial-a", "match_group": "A:initial", "replay_key": "A:strategy-a"},
                {"label": "initial B", "value": "initial-b", "match_group": "A:initial", "replay_key": "A:strategy-b"},
                {"label": "reproduction A", "value": "reproduction-a", "match_group": "A:reproduction", "replay_key": "A:strategy-a"},
                {"label": "reproduction B", "value": "reproduction-b", "match_group": "A:reproduction", "replay_key": "A:strategy-b"},
            ],
            "stop_on_match_by": "match_group",
            "bounded_reproduction": True,
            "security_outcomes": [{
                "id": "paired-only", "title": "Exact strategy reproduced",
                "summary": "Only the exact successful strategy may confirm the outcome.",
                "severity": "high", "confidence": 0.9,
                "risk_ids": ["LLM01"], "technique_ids": ["LLM01-OBFUSCATED"],
                "required_any_step_groups": [["campaign_1", "campaign_2"], ["campaign_3", "campaign_4"]],
                "reproduction_step_ids": ["campaign_3", "campaign_4"], "confirmation": "reproduction",
            }],
        })
        client = StrategySpecificClient()
        run = self.repo.create_tool_run(
            self.project["id"], target_id=self.target["id"], kind="campaign",
            name="Exact replay campaign", definition=definition,
        )

        completed = execute_tool_run(
            self.repo, project_id=self.project["id"], tool_run_id=run["id"], target_client=client,
        )

        self.assertEqual("completed", completed["status"])
        self.assertEqual(
            "not_demonstrated", completed["context"]["security_outcomes"][0]["status"],
            completed["context"]["security_outcomes"][0],
        )
        self.assertEqual([], completed["security_findings"])
        self.assertNotIn("reproduction-b", client.messages)
        self.assertEqual(["initial-a", "reproduction-a", "reproduction-a", "reproduction-a"], client.messages)

    def test_campaign_reproduction_is_skipped_when_guardrail_disallows_it(self) -> None:
        self._save_statistical_guardrail(allow_reproduction=False)
        client = StochasticCampaignClient([True, True, True])
        run = self.repo.create_tool_run(
            self.project["id"], target_id=self.target["id"], kind="campaign",
            name="Reproduction denied", definition=self._stochastic_campaign_definition(),
        )

        completed = execute_tool_run(
            self.repo, project_id=self.project["id"], tool_run_id=run["id"], target_client=client,
        )

        self.assertEqual("completed", completed["status"])
        self.assertEqual(1, len(client.calls))
        self.assertEqual([], completed["security_findings"])
        skipped = [event for event in completed["events"] if event["event_type"] == "campaign.skipped"]
        self.assertTrue(any("not allowed" in event["details"]["reason"] for event in skipped))

    def test_campaign_bounded_reproduction_cannot_exceed_request_guardrail(self) -> None:
        self._save_statistical_guardrail(max_requests=2)
        client = StochasticCampaignClient([False, True, True])
        run = self.repo.create_tool_run(
            self.project["id"], target_id=self.target["id"], kind="campaign",
            name="Request-bounded reproduction", definition=self._stochastic_campaign_definition(),
        )

        completed = execute_tool_run(
            self.repo, project_id=self.project["id"], tool_run_id=run["id"], target_client=client,
        )

        self.assertEqual("blocked", completed["status"])
        self.assertEqual(2, len(client.calls))
        self.assertIn("request limit", completed["error"])
        self.assertEqual([], completed["security_findings"])

    def test_bounded_campaign_requires_explicit_reproduction_pair_keys(self) -> None:
        definition = self._stochastic_campaign_definition()
        definition["payloads"][1].pop("replay_key")
        with self.assertRaisesRegex(ValueError, "replay_key"):
            normalize_tool_definition("campaign", definition)

    def test_campaign_can_verify_whitespace_obfuscated_proof_without_replacing_raw_evidence(self) -> None:
        campaign_definition = normalize_tool_definition("campaign", {
            "request": {
                "method": "POST", "path": "/chat/A", "body": {"message": "{{payload}}"},
                "assertions": [
                    {"type": "status", "equals": 200},
                    {
                        "type": "json_regex", "path": "$.response", "pattern": r"2501\{whitespace_proof\}",
                        "normalizer": "remove-whitespace", "label": "Canonical proof observed",
                    },
                ],
            },
            "payloads": [
                {"label": "initial", "value": "spaced-proof", "match_group": "A:initial"},
                {"label": "reproduction", "value": "spaced-proof", "match_group": "A:reproduction"},
            ],
            "stop_on_match_by": "match_group",
            "security_outcomes": [{
                "id": "spaced-proof", "title": "Transformed proof disclosed",
                "summary": "A target-approved canonicalizer verified the exact retained response.",
                "severity": "high", "confidence": 0.98,
                "risk_ids": ["LLM02"], "technique_ids": ["LLM02-SECRETS"],
                "required_any_step_groups": [["campaign_1"], ["campaign_2"]],
                "reproduction_step_ids": ["campaign_2"], "confirmation": "key-pattern",
            }],
        })
        run = self.repo.create_tool_run(
            self.project["id"], target_id=self.target["id"], kind="campaign",
            name="Whitespace proof", definition=campaign_definition,
        )

        completed = execute_tool_run(
            self.repo, project_id=self.project["id"], tool_run_id=run["id"], target_client=self.client,
        )

        self.assertEqual("completed", completed["status"])
        self.assertEqual("confirmed", completed["context"]["security_outcomes"][0]["status"])
        response_event = next(event for event in completed["events"] if event["event_type"] == "response.received")
        self.assertIn("2 5 0 1", response_event["details"]["raw_response"])
        assertion_event = next(
            event for event in completed["events"]
            if event["event_type"] == "assertion.passed" and event["details"]["assertion"]["type"] == "json_regex"
        )
        self.assertEqual("remove-whitespace", assertion_event["details"]["actual"]["normalizer"])
        self.assertTrue(assertion_event["details"]["actual"]["matched"])
        self.assertNotIn("whitespace_proof", json.dumps(assertion_event["details"]["actual"]))

    def test_json_regex_does_not_match_proof_text_in_unselected_metadata(self) -> None:
        definition = normalize_tool_definition("campaign", {
            "request": {
                "method": "POST", "path": "/chat/A", "body": {"message": "{{payload}}"},
                "assertions": [{
                    "type": "json_regex", "path": "$.response",
                    "pattern": r"2501\{whitespace_proof\}", "normalizer": "remove-whitespace",
                }],
            },
            "payloads": ["metadata-only-spaced-proof"],
        })
        run = self.repo.create_tool_run(
            self.project["id"], target_id=self.target["id"], kind="campaign",
            name="Selector isolation", definition=definition,
        )

        completed = execute_tool_run(
            self.repo, project_id=self.project["id"], tool_run_id=run["id"], target_client=self.client,
        )

        self.assertFalse(completed["context"]["all_required_assertions_passed"])
        self.assertEqual([], completed["security_findings"])
        failed = next(event for event in completed["events"] if event["event_type"] == "assertion.failed")
        self.assertEqual("$.response", failed["details"]["actual"]["selector"])
        self.assertFalse(failed["details"]["actual"]["matched"])

    def test_layered_guardrail_pack_tracks_every_level_and_reproduces_each_proof(self) -> None:
        target = {
            **self.target,
            "technique_adapters": {
                "layered-guardrail-matrix": {
                    "route_template": "/chat/{level}", "route_method": "POST",
                    "success_status": 200, "levels": ["A", "B", "C", "D"],
                    "prompt_field": "message", "response_selector": "$.response",
                    "success_regex": r"2501\{[^}]+\}",
                    "success_normalizer": "remove-whitespace",
                    "protected_value_locator": "the value after the colon on the second line of the approved policy context",
                },
            },
        }

        pack = instantiate_tool_pack("layered-guardrail-matrix", target)
        definition = normalize_tool_definition(pack["kind"], pack["definition"])

        self.assertEqual(160, len(definition["payloads"]))
        self.assertEqual("match_group", definition["stop_on_match_by"])
        self.assertEqual(8, len(definition["security_outcomes"]))
        self.assertEqual("json_regex", definition["request"]["assertions"][1]["type"])
        self.assertEqual("$.response", definition["request"]["assertions"][1]["path"])
        self.assertEqual("remove-whitespace", definition["request"]["assertions"][1]["normalizer"])
        for outcome in definition["security_outcomes"]:
            self.assertEqual(2, len(outcome["required_any_step_groups"]))
            self.assertEqual(20, len(outcome["required_any_step_groups"][0]))
            self.assertEqual(20, len(outcome["reproduction_step_ids"]))
        self.assertTrue(all("second line" in payload["prompt"] for payload in definition["payloads"]))

    def test_tool_records_and_interactions_are_project_isolated(self) -> None:
        other = self.repo.create_project(name="Other")
        definition = normalize_tool_definition("workflow", {"steps": [{"id": "one", "type": "http", "method": "POST", "path": "/start"}]})
        saved = self.repo.create_tool_definition(self.project["id"], target_id=self.target["id"], kind="workflow", name="Private", description="", definition=definition)
        with self.assertRaises(NotFoundError):
            self.repo.get_tool_definition(other["id"], saved["id"])
        token = self.repo.create_interaction_token(self.project["id"], name="Callback", target_id=self.target["id"])
        event = self.repo.record_interaction(token["token"], method="POST", path=f"/interactions/{token['token']}", source="127.0.0.1", headers={"Authorization": "Bearer secret"}, body='{"token":"secret-value"}')
        self.assertIsNotNone(event)
        stored = self.repo.get_interaction_token(self.project["id"], token["id"])
        self.assertEqual(len(stored["events"]), 1)
        self.assertNotIn("Bearer secret", json.dumps(stored))
        with self.assertRaises(NotFoundError):
            self.repo.get_interaction_token(other["id"], token["id"])

    def test_http_callback_and_pack_catalog_are_connected(self) -> None:
        config = AppConfig(database_path=self.root / "unused.sqlite3", evidence_root=self.root / "evidence")
        app = Application(self.repo, config=config, target_client=self.client)
        status, catalog = app.dispatch("GET", "/api/testing-tool-packs")
        self.assertEqual(status, 200)
        self.assertIn("mcp-read-only-cartography", {pack["id"] for pack in catalog["packs"]})
        self.assertEqual(catalog["configuration_location"], "attack_surface")
        serialized_catalog = json.dumps(catalog)
        for lab_assumption in ("/api/score", "/api/datasets", "/chat/{level}", "/model/{model_id}/chat", "2501\\\\{"):
            self.assertNotIn(lab_assumption, serialized_catalog)
        token = self.repo.create_interaction_token(self.project["id"], name="HTTP callback")
        server = create_server(app, host="127.0.0.1", port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_address[1]}/interactions/{token['token']}?case=7"
            request = urllib.request.Request(url, data=b"callback evidence", method="POST", headers={"Content-Type": "text/plain"})
            with urllib.request.urlopen(request, timeout=3) as response:
                self.assertEqual(response.status, 200)
            stored = self.repo.get_interaction_token(self.project["id"], token["id"])
            self.assertEqual(stored["events"][0]["body"], "callback evidence")
            self.assertIn("case=7", stored["events"][0]["path"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

    def test_pack_is_blocked_until_attack_surface_mapping_is_ready(self) -> None:
        app = Application(self.repo, config=AppConfig(database_path=self.root / "unused.sqlite3", evidence_root=self.root / "evidence"), target_client=self.client)
        with self.assertRaisesRegex(ValueError, "needs Attack Surface configuration"):
            app.dispatch("POST", f"/api/projects/{self.project['id']}/testing-tools", {"pack_id": "mcp-read-only-cartography", "target_id": self.target["id"]})

        status, draft = app.dispatch(
            "PATCH",
            f"/api/projects/{self.project['id']}/targets/{self.target['id']}/technique-adapters/mcp-read-only-cartography",
            {"configuration": {"rpc_path": "/not-authorized", "rpc_method": "POST", "success_status": 200, "result_selector": "$.payload"}},
        )
        self.assertEqual(status, 200)
        self.assertFalse(draft["readiness"]["ready"])
        self.assertIn("not present in the target allowlist", draft["readiness"]["errors"][0])

        status, configured = app.dispatch(
            "PATCH",
            f"/api/projects/{self.project['id']}/targets/{self.target['id']}/technique-adapters/mcp-read-only-cartography",
            {"configuration": {"rpc_path": "/custom-mcp", "rpc_method": "POST", "success_status": 200, "result_selector": "$.payload"}},
        )
        self.assertEqual(status, 200)
        self.assertTrue(configured["readiness"]["ready"])
        status, saved = app.dispatch("POST", f"/api/projects/{self.project['id']}/testing-tools", {"pack_id": "mcp-read-only-cartography", "target_id": self.target["id"]})
        self.assertEqual(status, 201)
        self.assertEqual({step["path"] for step in saved["definition"]["steps"]}, {"/custom-mcp"})
        self.assertEqual(saved["definition"]["pack_snapshot"]["adapter"]["result_selector"], "$.payload")
        self.assertNotIn("/api/score", json.dumps(saved["definition"]))

    def test_adapter_mapping_is_target_and_project_scoped(self) -> None:
        other_project = self.repo.create_project(name="Other adapter project")
        other_target = self.repo.add_target(other_project["id"], name="Other target", kind="api", base_url="http://other.invalid", path="/", method="GET", scope_confirmed=True)
        self.repo.update_target_technique_adapter(self.project["id"], self.target["id"], "mcp-read-only-cartography", {"rpc_path": "/custom-mcp", "rpc_method": "POST", "success_status": 200, "result_selector": "$.payload"})
        self.assertIn("mcp-read-only-cartography", self.repo.get_target(self.project["id"], self.target["id"])["technique_adapters"])
        self.assertEqual(self.repo.get_target(other_project["id"], other_target["id"])["technique_adapters"], {})


if __name__ == "__main__":
    unittest.main()
