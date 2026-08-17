from __future__ import annotations

import json
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from osai_security.config import AppConfig
from osai_security.db import Repository
from osai_security.faults import public_fault_taxonomy
from osai_security.http_app import Application
from osai_security.model_gateway import ModelGateway, ModelGatewayError, SshTunnel
from osai_security.runtime_lifecycle import RuntimeAlreadyActiveError, RuntimeLock
from osai_security.targets import TargetError, _read_sse


class _Response:
    status = 200

    def __init__(self, document: dict):
        self.document = document

    def __enter__(self):
        return self

    def __exit__(self, *_args: object) -> None:
        pass

    def read(self, *_args: object) -> bytes:
        return json.dumps(self.document).encode("utf-8")


class _StalledStream:
    def __iter__(self):
        yield b'data: {"choices":[{"delta":{"content":"partial"}}]}\n\n'
        raise TimeoutError("read timed out")


class RuntimeAndProviderTests(unittest.TestCase):
    def config(self, root: Path, **overrides: object) -> AppConfig:
        values = {
            "database_path": root / "assessment.sqlite3",
            "evidence_root": root / "projects",
            "model_profiles_path": root / "model-providers.json",
            "llm_base_url": "http://127.0.0.1:18001/v1",
            "llm_model": "qwen3.8-27b",
        }
        values.update(overrides)
        return AppConfig(**values)

    def test_provider_defaults_use_current_local_qwen_and_offer_requested_remote_models(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            gateway = ModelGateway(self.config(Path(directory)))
            profiles = gateway.public_provider_profiles()
            by_id = {item["id"]: item for item in profiles["providers"]}
            self.assertEqual("local", profiles["selected_provider"])
            self.assertEqual("qwen3.8-27b", by_id["local"]["model"])
            self.assertEqual("gpt-5.5", by_id["openai"]["model"])
            self.assertEqual("glm-5.2", by_id["zai"]["model"])
            self.assertFalse(by_id["local"]["requires_api_key"])
            self.assertIn(by_id["openai"]["credential_source"], {"missing", "environment"})
            self.assertNotEqual("session", by_id["openai"]["credential_source"])

    def test_remote_key_is_memory_only_redacted_from_public_and_persisted_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gateway = ModelGateway(self.config(root))
            gateway.configure_provider("openai", model="gpt-5.5", api_key_env="OPENAI_API_KEY")
            synthetic_key = "sk-test-memory-only-value"
            public = gateway.set_session_api_key("openai", synthetic_key)
            self.assertNotIn(synthetic_key, json.dumps(public))
            self.assertEqual("session", next(item for item in public["providers"] if item["id"] == "openai")["credential_source"])
            self.assertNotIn(synthetic_key, (root / "model-providers.json").read_text(encoding="utf-8"))
            gateway.close()

    def test_named_profiles_and_role_assignments_persist_without_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gateway = ModelGateway(self.config(root))
            try:
                gateway.upsert_provider_profile(
                    "planning-local",
                    label="Planning model",
                    kind="local-openai-compatible",
                    base_url="http://127.0.0.1:19001/v1",
                    model="planner-model",
                )
                gateway.upsert_provider_profile(
                    "evaluation-remote",
                    label="Approved evaluator",
                    kind="remote-openai-compatible",
                    base_url="https://models.example.test/v1",
                    model="evaluator-model",
                    api_key_env="APPROVED_EVALUATOR_KEY",
                )
                profiles = gateway.configure_model_roles({
                    "planner": "planning-local",
                    "generator": "local",
                    "evaluator": "evaluation-remote",
                    "adjudicator": None,
                })
                self.assertEqual("planning-local", profiles["role_profiles"]["planner"])
                self.assertEqual("evaluation-remote", profiles["role_profiles"]["evaluator"])
                self.assertIsNone(profiles["role_profiles"]["adjudicator"])
            finally:
                gateway.close()

            stored = json.loads((root / "model-providers.json").read_text(encoding="utf-8"))
            self.assertEqual("2.0", stored["schema_version"])
            self.assertEqual("planning-local", stored["role_profiles"]["planner"])
            self.assertNotIn('"api_key":', json.dumps(stored))
            reopened = ModelGateway(self.config(root))
            try:
                public = reopened.public_provider_profiles()
                self.assertEqual("evaluation-remote", public["role_profiles"]["evaluator"])
                self.assertEqual("not-tested", next(item for item in public["providers"] if item["id"] == "evaluation-remote")["qualification"]["status"])
            finally:
                reopened.close()

    def test_legacy_provider_selection_loads_and_migrates_on_explicit_update(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "model-providers.json"
            path.write_text(json.dumps({
                "schema_version": "1.0",
                "selected_provider": "openai",
                "profiles": {"openai": {"model": "legacy-openai-model", "api_key_env": "LEGACY_OPENAI_KEY"}},
            }), encoding="utf-8")
            gateway = ModelGateway(self.config(root))
            try:
                public = gateway.public_provider_profiles()
                self.assertTrue(public["migration_pending"])
                self.assertEqual("openai", public["role_profiles"]["planner"])
                self.assertEqual("legacy-openai-model", next(item for item in public["providers"] if item["id"] == "openai")["model"])
                gateway.configure_model_roles({"adjudicator": None})
            finally:
                gateway.close()
            migrated = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual("2.0", migrated["schema_version"])
            self.assertEqual("openai", migrated["role_profiles"]["generator"])

    def test_model_requests_route_through_the_explicit_role_profiles(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gateway = ModelGateway(self.config(root))
            try:
                for profile_id, port, model in (
                    ("planning-local", 19011, "planner-model"),
                    ("generation-local", 19012, "generator-model"),
                    ("evaluation-local", 19013, "evaluator-model"),
                ):
                    gateway.upsert_provider_profile(
                        profile_id,
                        label=profile_id,
                        kind="local-openai-compatible",
                        base_url=f"http://127.0.0.1:{port}/v1",
                        model=model,
                    )
                gateway.configure_model_roles({
                    "planner": "planning-local",
                    "generator": "generation-local",
                    "evaluator": "evaluation-local",
                })
                captured = []

                def fake_urlopen(request, **_kwargs):
                    captured.append((request.full_url, json.loads(request.data.decode("utf-8"))["model"]))
                    return _Response({"choices": [{"message": {"content": "ready"}}]})

                with patch("urllib.request.urlopen", side_effect=fake_urlopen):
                    traces = [
                        gateway._request_with_trace([{"role": "user", "content": "plan"}], max_tokens=16, role="planner")[1],
                        gateway._request_with_trace([{"role": "user", "content": "generate"}], max_tokens=16, role="generator")[1],
                        gateway._request_with_trace([{"role": "user", "content": "evaluate"}], max_tokens=16, role="evaluator")[1],
                    ]
                self.assertEqual(["planner-model", "generator-model", "evaluator-model"], [item[1] for item in captured])
                self.assertEqual(["planner", "generator", "evaluator"], [item["model_role"] for item in traces])
                self.assertEqual(["planning-local", "generation-local", "evaluation-local"], [item["provider"] for item in traces])
            finally:
                gateway.close()

    def test_connection_verification_is_not_reported_as_professional_qualification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            gateway = ModelGateway(self.config(Path(directory)))
            try:
                with patch("urllib.request.urlopen", return_value=_Response({"data": [{"id": "qwen3.8-27b"}]})):
                    result = gateway.qualify_provider_profile("local")
                self.assertEqual("connection-verified", result["status"])
                self.assertEqual("not-established", result["professional_qualification"])
                self.assertTrue(result["warnings"])
                profile = next(item for item in gateway.public_provider_profiles()["providers"] if item["id"] == "local")
                self.assertEqual("connection-verified", profile["qualification"]["status"])
            finally:
                gateway.close()

    def test_remote_profile_rejects_http_and_credentialed_urls(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            gateway = ModelGateway(self.config(Path(directory)))
            try:
                for base_url in ("http://models.example.test/v1", "https://user:password@models.example.test/v1"):
                    with self.assertRaises(ValueError):
                        gateway.upsert_provider_profile(
                            "unsafe-remote",
                            label="Unsafe remote",
                            kind="remote-openai-compatible",
                            base_url=base_url,
                            model="remote-model",
                            api_key_env="REMOTE_MODEL_KEY",
                        )
            finally:
                gateway.close()

    def test_openai_compatible_remote_request_uses_bearer_auth_without_persisting_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gateway = ModelGateway(self.config(root))
            gateway.configure_provider("openai", model="gpt-5.5", api_key_env="OPENAI_API_KEY")
            gateway.set_session_api_key("openai", "sk-test-request-header")
            captured = {}

            def fake_urlopen(request, **_kwargs):
                captured["url"] = request.full_url
                captured["headers"] = dict(request.header_items())
                captured["body"] = json.loads(request.data.decode("utf-8"))
                return _Response({"choices": [{"message": {"content": "ready"}}]})

            with patch("urllib.request.urlopen", side_effect=fake_urlopen):
                content, trace = gateway._request_with_trace(
                    [{"role": "user", "content": "connection test"}],
                    max_tokens=32,
                    temperature=0.0,
                )
            self.assertEqual("ready", content)
            self.assertEqual("https://api.openai.com/v1/chat/completions", captured["url"])
            self.assertEqual("Bearer sk-test-request-header", captured["headers"]["Authorization"])
            self.assertEqual(32, captured["body"]["max_completion_tokens"])
            self.assertNotIn("max_tokens", captured["body"])
            self.assertNotIn("chat_template_kwargs", captured["body"])
            self.assertEqual("openai", trace["provider"])
            self.assertNotIn("sk-test-request-header", json.dumps(trace))

    def test_runtime_lock_rejects_a_second_process_owner_and_releases_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".runtime.lock"
            first = RuntimeLock(path, port=8091)
            second = RuntimeLock(path, port=8091)
            first.acquire()
            try:
                with self.assertRaises(RuntimeAlreadyActiveError):
                    second.acquire()
            finally:
                first.release()
            second.acquire()
            second.release()

    def test_ssh_tunnel_refuses_to_spawn_when_its_local_port_is_already_owned(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port = listener.getsockname()[1]
            tunnel = SshTunnel(self.config(
                Path(directory),
                ssh_tunnel=True,
                gx10_user="configured-user",
                gx10_host="authorized-model-host",
                ssh_local_port=port,
            ))
            try:
                with patch("subprocess.Popen") as popen:
                    with self.assertRaisesRegex(ModelGatewayError, "will not create a duplicate"):
                        tunnel.start()
                    popen.assert_not_called()
            finally:
                listener.close()

    def test_model_request_reuses_verified_operator_managed_tunnel(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            gateway = ModelGateway(self.config(
                Path(directory),
                ssh_tunnel=True,
                gx10_user="configured-user",
                gx10_host="authorized-model-host",
                ssh_local_port=18001,
            ))
            responses = [
                _Response({"data": [{"id": "qwen3.8-27b"}]}),
                _Response({"choices": [{"message": {"content": "ready"}}]}),
            ]
            try:
                with patch.object(gateway.tunnel, "_port_is_open", return_value=True), \
                        patch("urllib.request.urlopen", side_effect=responses), \
                        patch("subprocess.Popen") as popen:
                    content = gateway._request(
                        [{"role": "user", "content": "connection test"}],
                        max_tokens=16,
                    )
                self.assertEqual("ready", content)
                popen.assert_not_called()
            finally:
                gateway.close()

    def test_model_request_rejects_incompatible_operator_managed_tunnel(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            gateway = ModelGateway(self.config(
                Path(directory),
                ssh_tunnel=True,
                gx10_user="configured-user",
                gx10_host="authorized-model-host",
                ssh_local_port=18001,
            ))
            try:
                with patch.object(gateway.tunnel, "_port_is_open", return_value=True), \
                        patch("urllib.request.urlopen", return_value=_Response({"data": [{"id": "other-model"}]})), \
                        patch("subprocess.Popen") as popen:
                    with self.assertRaisesRegex(ModelGatewayError, "did not expose the configured model"):
                        gateway._request(
                            [{"role": "user", "content": "connection test"}],
                            max_tokens=16,
                        )
                popen.assert_not_called()
            finally:
                gateway.close()

    def test_partial_sse_timeout_is_classified_as_a_streaming_stall(self) -> None:
        with self.assertRaisesRegex(TargetError, "stalled after partial output"):
            _read_sse(_StalledStream(), "choices.0.delta.content")

    def test_fault_taxonomy_exports_every_professional_failure_component(self) -> None:
        taxonomy = public_fault_taxonomy()
        components = {item["component"] for item in taxonomy["faults"]}
        self.assertTrue({"target", "browser", "model", "evaluator", "reproduction", "cleanup", "guardrail", "cancellation", "framework"}.issubset(components))

    def test_runtime_and_provider_apis_never_return_a_submitted_session_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = self.config(root)
            repo = Repository(config.database_path)
            app = Application(repo, config=config)
            try:
                status, runtime = app.dispatch("GET", "/api/runtime")
                self.assertEqual(200, status)
                self.assertTrue(runtime["api_contract_version"])
                status, configured = app.dispatch("PATCH", "/api/model-providers/selection", {
                    "provider_id": "zai", "model": "glm-5.2", "api_key_env": "ZAI_API_KEY",
                })
                self.assertEqual(200, status)
                synthetic_key = "zai-test-session-only"
                status, public = app.dispatch("POST", "/api/model-providers/zai/session-key", {"api_key": synthetic_key})
                self.assertEqual(200, status)
                self.assertNotIn(synthetic_key, json.dumps(public))
                self.assertNotIn(synthetic_key, (root / "model-providers.json").read_text(encoding="utf-8"))

                status, profiles = app.dispatch("PUT", "/api/model-providers/profiles/secondary-local", {
                    "label": "Secondary local",
                    "kind": "local-openai-compatible",
                    "base_url": "http://127.0.0.1:19021/v1",
                    "model": "secondary-model",
                })
                self.assertEqual(200, status)
                self.assertIn("secondary-local", {item["id"] for item in profiles["providers"]})
                with self.assertRaisesRegex(ValueError, "JSON boolean"):
                    app.dispatch("PUT", "/api/model-providers/profiles/ambiguous-flags", {
                        "label": "Ambiguous flags",
                        "kind": "local-openai-compatible",
                        "base_url": "http://127.0.0.1:19022/v1",
                        "model": "flag-model",
                        "use_ssh_tunnel": "false",
                    })
                status, profiles = app.dispatch("PATCH", "/api/model-providers/roles", {
                    "role_profiles": {"planner": "secondary-local", "generator": "secondary-local", "evaluator": "zai"},
                })
                self.assertEqual(200, status)
                self.assertEqual("secondary-local", profiles["role_profiles"]["planner"])
                with self.assertRaisesRegex(ValueError, "assigned"):
                    app.dispatch("DELETE", "/api/model-providers/profiles/secondary-local")
                status, profiles = app.dispatch("PATCH", "/api/model-providers/roles", {
                    "role_profiles": {"planner": "local", "generator": "local", "evaluator": "local"},
                })
                self.assertEqual(200, status)
                status, profiles = app.dispatch("DELETE", "/api/model-providers/profiles/secondary-local")
                self.assertEqual(200, status)
                self.assertNotIn("secondary-local", {item["id"] for item in profiles["providers"]})
            finally:
                app.close()
                repo.close()

    def test_restart_eligibility_never_replays_unattested_post_traffic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = self.config(root)
            repo = Repository(config.database_path)
            app = Application(repo, config=config)
            try:
                project = repo.create_project(name="Restart safety")
                target = repo.add_target(
                    project["id"], name="Target", kind="chatbot", base_url="http://127.0.0.1:18090",
                    path="/chat", method="POST", request_template={"message": "{{prompt}}"},
                    response_path="response", transport_config={"enabled": False, "replay_safe": False},
                    scope_confirmed=True,
                )
                run = repo.create_run(project["id"], target["id"], ["prompt-injection"], "offline", assessment_plan={})
                repo.complete_run(project["id"], run["id"], status="interrupted", error="test interruption")
                detail = repo.get_run_detail(project["id"], run["id"])
                self.assertTrue(app._safe_restart_eligibility(project["id"], detail)["eligible"])
                repo.add_run_event(project["id"], run["id"], event_type="request.sent", title="Prior POST", details={"method": "POST"})
                detail = repo.get_run_detail(project["id"], run["id"])
                eligibility = app._safe_restart_eligibility(project["id"], detail)
                self.assertFalse(eligibility["eligible"])
                self.assertIn("not explicitly attested replay-safe", eligibility["reason"])
            finally:
                app.close()
                repo.close()


if __name__ == "__main__":
    unittest.main()
