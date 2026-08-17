from __future__ import annotations

import io
import json
import socket
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from osai_security import DATABASE_SCHEMA_VERSION, __version__, build_identity
from osai_security.cli import main
from osai_security.config import AppConfig
from osai_security.db import Repository
from osai_security.deployment_security import permission_status, validate_serve_security
from osai_security.http_app import Application, create_server
from osai_security.local_setup import SetupError, doctor_report, initialize_local_state, load_local_document
from osai_security.model_gateway import ModelGateway
from osai_security.release import API_CONTRACT_VERSION, MODEL_PROVIDER_SCHEMA_VERSION, PRODUCT_VERSION, SCHEMA_VERSIONS
from osai_security.tutorial import create_tutorial_project


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class _ModelInventoryHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - standard library callback name
        if self.path != "/v1/models":
            self.send_error(404)
            return
        body = json.dumps({"data": [{"id": "existing-tunnel-model"}]}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


class ReleaseIdentityTests(unittest.TestCase):
    def test_build_identity_uses_authoritative_release_and_schemas(self) -> None:
        identity = build_identity()
        self.assertEqual(__version__, PRODUCT_VERSION)
        self.assertEqual(identity["version"], PRODUCT_VERSION)
        self.assertEqual(identity["release_channel"], "beta")
        self.assertEqual(identity["schemas"], dict(SCHEMA_VERSIONS))
        self.assertEqual(int(identity["database_schema"]), DATABASE_SCHEMA_VERSION)

    def test_cli_version_uses_authoritative_release(self) -> None:
        output = io.StringIO()
        with self.assertRaises(SystemExit) as raised, redirect_stdout(output):
            main(["--version"])
        self.assertEqual(raised.exception.code, 0)
        self.assertIn(PRODUCT_VERSION, output.getvalue())


class LocalInitializationTests(unittest.TestCase):
    def test_init_creates_non_secret_state_and_doctor_passes_without_model_probe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = root / "configuration" / "config.json"
            result = initialize_local_state(
                config_path=config_path,
                data_directory=root / "state",
                evidence_directory=root / "evidence",
                port=_free_port(),
                provider="openai",
                model="approved-test-model",
                api_key_env="ADVERSCOPE_TEST_OPENAI_KEY",
            )
            self.assertTrue(config_path.is_file())
            self.assertTrue(Path(result["database_path"]).is_file())
            self.assertTrue(Path(result["evidence_directory"]).is_dir())
            self.assertTrue(Path(result["training_directory"]).is_dir())
            configuration = load_local_document(config_path)
            self.assertEqual(Path(result["training_directory"]), Path(configuration["training_root"]))
            self.assertNotIn("api_key", configuration)
            self.assertNotIn("ADVERSCOPE_TEST_OPENAI_KEY", json.dumps(configuration))

            providers = json.loads(Path(result["model_profiles_path"]).read_text(encoding="utf-8"))
            self.assertEqual(providers["schema_version"], MODEL_PROVIDER_SCHEMA_VERSION)
            self.assertEqual(providers["selected_provider"], "openai")
            self.assertEqual(providers["profiles"]["openai"]["api_key_env"], "ADVERSCOPE_TEST_OPENAI_KEY")
            self.assertNotIn("api_key", providers["profiles"]["openai"])

            report = doctor_report(config_path, probe_model=False)
            self.assertTrue(report["ok"], report)
            self.assertEqual(report["summary"]["failures"], 0)
            database = next(item for item in report["checks"] if item["id"] == "database")
            self.assertEqual(database["details"]["schema_version"], DATABASE_SCHEMA_VERSION)

    def test_init_refuses_overwrite_and_force_preserves_projects_and_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = root / "config.json"
            first = initialize_local_state(config_path=config_path, port=_free_port())
            evidence_marker = Path(first["evidence_directory"]) / "preserve.txt"
            evidence_marker.write_text("preserve", encoding="utf-8")
            repository = Repository(first["database_path"])
            try:
                project = repository.create_project(name="Preserved project", client="Test")
            finally:
                repository.close()

            with self.assertRaises(SetupError):
                initialize_local_state(config_path=config_path, port=_free_port())
            initialize_local_state(config_path=config_path, port=_free_port(), force=True)
            self.assertEqual(evidence_marker.read_text(encoding="utf-8"), "preserve")
            repository = Repository(first["database_path"])
            try:
                self.assertEqual(repository.get_project(project["id"])["name"], "Preserved project")
            finally:
                repository.close()

    def test_configuration_rejects_persisted_secret_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps({"api_key": "must-not-be-persisted"}), encoding="utf-8")
            with self.assertRaisesRegex(SetupError, "environment variable"):
                load_local_document(path)

    def test_cli_init_json_contains_no_secret_value(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.json"
            output = io.StringIO()
            with redirect_stdout(output):
                code = main([
                    "init", "--config", str(config), "--port", str(_free_port()),
                    "--provider", "zai", "--api-key-env", "ADVERSCOPE_ZAI_TEST_KEY", "--json",
                ])
            self.assertEqual(code, 0)
            result = json.loads(output.getvalue())
            self.assertEqual(result["secret_storage"], "environment-reference-only")
            self.assertNotIn("api_key", result)

    def test_diagnostic_probe_reuses_an_existing_local_model_tunnel(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), _ModelInventoryHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        config = AppConfig(
            llm_base_url=f"http://127.0.0.1:{server.server_port}/v1",
            llm_model="existing-tunnel-model",
            ssh_tunnel=True,
            gx10_user="diagnostic-user",
            gx10_host="diagnostic-host",
            ssh_local_port=server.server_port,
        )
        gateway = ModelGateway(config)
        try:
            health = gateway.healthcheck(timeout_seconds=2, allow_existing_tunnel=True)
            self.assertTrue(health["ok"], health)
            self.assertTrue(health["model_available"], health)
            self.assertIsNone(gateway.tunnel.process if gateway.tunnel else None)
        finally:
            gateway.close()
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_cli_manages_named_profiles_and_model_roles(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "config.json"
            initialize_local_state(config_path=config, data_directory=root / "data", port=_free_port())
            output = io.StringIO()
            with redirect_stdout(output):
                code = main([
                    "profiles", "--config", str(config), "add", "planner-local",
                    "--label", "Planner local", "--kind", "local-openai-compatible",
                    "--base-url", "http://127.0.0.1:19031/v1", "--model", "planner-model",
                ])
            self.assertEqual(0, code)
            with redirect_stdout(io.StringIO()):
                code = main([
                    "profiles", "--config", str(config), "roles",
                    "--planner", "planner-local", "--generator", "local", "--evaluator", "local",
                    "--adjudicator", "none",
                ])
            self.assertEqual(0, code)
            output = io.StringIO()
            with redirect_stdout(output):
                code = main(["profiles", "--config", str(config), "list", "--json"])
            self.assertEqual(0, code)
            document = json.loads(output.getvalue())
            self.assertEqual("planner-local", document["role_profiles"]["planner"])
            self.assertIn("planner-local", {item["id"] for item in document["providers"]})
            with redirect_stdout(io.StringIO()):
                code = main([
                    "profiles", "--config", str(config), "add", "openai-evaluator",
                    "--label", "OpenAI evaluator", "--kind", "openai",
                    "--model", "approved-model", "--api-key-env", "OPENAI_API_KEY",
                ])
            self.assertEqual(0, code)
            stored = json.loads((root / "data" / "model-providers.json").read_text(encoding="utf-8"))
            self.assertEqual("https://api.openai.com/v1", stored["profiles"]["openai-evaluator"]["base_url"])

    def test_remote_binding_requires_acknowledgement_authentication_and_tls(self) -> None:
        with self.assertRaisesRegex(ValueError, "acknowledge"):
            validate_serve_security(AppConfig(host="192.0.2.10"))
        with self.assertRaisesRegex(ValueError, "environment variable"):
            validate_serve_security(AppConfig(host="192.0.2.10", remote_exposure_acknowledged=True))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            certificate = root / "server.crt"
            private_key = root / "server.key"
            certificate.write_text("test certificate path", encoding="utf-8")
            private_key.write_text("test private key path", encoding="utf-8")
            configured = AppConfig(
                host="192.0.2.10",
                remote_exposure_acknowledged=True,
                remote_access_token_env="ADVERSCOPE_REMOTE_TEST_TOKEN",
                tls_cert_path=str(certificate),
                tls_key_path=str(private_key),
            )
            with patch.dict("os.environ", {"ADVERSCOPE_REMOTE_TEST_TOKEN": "short"}):
                with self.assertRaisesRegex(ValueError, "at least 32"):
                    validate_serve_security(configured)
            with patch.dict("os.environ", {"ADVERSCOPE_REMOTE_TEST_TOKEN": "A" * 48}):
                result = validate_serve_security(configured)
            self.assertEqual(result["mode"], "remote-api")
            self.assertTrue(result["authentication"])
            self.assertTrue(result["tls"])

    def test_container_api_mode_is_explicit_and_host_loopback_only(self) -> None:
        config = AppConfig(host="0.0.0.0", container_api_only=True)
        with self.assertRaisesRegex(ValueError, "AISEC_CONTAINER_API_ONLY"):
            validate_serve_security(config)
        with patch.dict("os.environ", {"AISEC_CONTAINER_API_ONLY": "1"}):
            result = validate_serve_security(config)
        self.assertEqual(result["mode"], "container-host-loopback")
        self.assertFalse(result["authentication"])

    def test_initialized_state_permissions_are_private_where_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialized = initialize_local_state(config_path=root / "config.json", port=_free_port())
            for path, is_directory in (
                (root / "config.json", False),
                (initialized["data_directory"], True),
                (initialized["evidence_directory"], True),
                (initialized["database_path"], False),
                (initialized["model_profiles_path"], False),
            ):
                status = permission_status(path, directory=is_directory)
                self.assertTrue(status["ok"], status)

    def test_local_config_boolean_strings_are_parsed_strictly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(
                json.dumps(
                    {
                        "ssh_tunnel": "false",
                        "remote_exposure_acknowledged": "yes",
                        "container_api_only": 0,
                    }
                ),
                encoding="utf-8",
            )
            config = AppConfig.from_sources(path)
            self.assertFalse(config.ssh_tunnel)
            self.assertTrue(config.remote_exposure_acknowledged)
            self.assertFalse(config.container_api_only)

    def test_invalid_local_config_boolean_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps({"container_api_only": "maybe"}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "container_api_only must be a boolean"):
                AppConfig.from_sources(path)

    def test_tutorial_project_is_complete_isolated_and_runnable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialized = initialize_local_state(config_path=root / "config.json", port=_free_port())
            config = AppConfig.from_sources(root / "config.json")
            result = create_tutorial_project(config, target_port=_free_port())
            repository = Repository(initialized["database_path"])
            try:
                detail = repository.get_project(result["project"]["id"])
                self.assertEqual(len(detail["documents"]), 2)
                self.assertEqual(len(detail["targets"]), 1)
                self.assertEqual(len(detail["objectives"]), 1)
                self.assertEqual(detail["guardrails"][0]["status"], "approved")
                self.assertEqual(detail["objectives"][0]["proof_rule_ids"], ["tutorial-proof"])
                self.assertTrue(detail["targets"][0]["scope_confirmed"])
                self.assertEqual(len(repository.list_projects()), 1)
            finally:
                repository.close()


class ReleaseHeaderTests(unittest.TestCase):
    def test_runtime_response_propagates_product_and_contract_versions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = AppConfig(
                database_path=root / "assessment.sqlite3",
                evidence_root=root / "projects",
                model_profiles_path=root / "model-providers.json",
            )
            application = Application(Repository(config.database_path), config=config)
            server = create_server(application, "127.0.0.1", 0)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{server.server_port}/api/runtime", timeout=5) as response:
                    document = json.loads(response.read().decode("utf-8"))
                    self.assertEqual(response.headers["X-AdverScope-Version"], PRODUCT_VERSION)
                    self.assertEqual(response.headers["X-AdverScope-API-Contract"], API_CONTRACT_VERSION)
                self.assertEqual(document["build"]["version"], PRODUCT_VERSION)
                self.assertEqual(document["build"]["schemas"], dict(SCHEMA_VERSIONS))
            finally:
                server.shutdown()
                server.server_close()
                application.close()
                application.repo.close()
                thread.join(timeout=5)

    def test_bearer_authentication_protects_http_routes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            token = "remote-test-token-" + "x" * 32
            config = AppConfig(database_path=root / "assessment.sqlite3", evidence_root=root / "projects")
            application = Application(Repository(config.database_path), config=config)
            server = create_server(application, "127.0.0.1", 0, access_token=token)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            url = f"http://127.0.0.1:{server.server_port}/api/runtime"
            try:
                with self.assertRaises(urllib.error.HTTPError) as denied:
                    urllib.request.urlopen(url, timeout=5)
                self.assertEqual(denied.exception.code, 401)
                self.assertEqual(denied.exception.headers["WWW-Authenticate"], 'Bearer realm="AdverScope"')
                request = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
                with urllib.request.urlopen(request, timeout=5) as response:
                    self.assertEqual(response.status, 200)
                    self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
            finally:
                server.shutdown()
                server.server_close()
                application.close()
                application.repo.close()
                thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
