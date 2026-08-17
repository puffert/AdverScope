from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from osai_security.config import AppConfig
from osai_security.db import Repository
from osai_security.http_app import Application
from osai_security.targets import assert_target_runtime_ready, target_runtime_readiness
from osai_security.telemetry import diagnose_case


class RuntimeReadinessTests(unittest.TestCase):
    environment_name = "ADV_TEST_RUNTIME_AUTHORIZATION"

    def target(self) -> dict:
        return {
            "kind": "chatbot",
            "base_url": "https://target.invalid",
            "path": "/chat",
            "method": "POST",
            "headers": {"Authorization": f"env:{self.environment_name}"},
            "request_template": {"message": "{{prompt}}"},
            "response_path": "response",
        }

    def test_authorization_environment_requires_complete_header_value(self) -> None:
        with patch.dict(os.environ, {self.environment_name: "raw-token-without-scheme"}, clear=False):
            readiness = target_runtime_readiness(self.target())
            self.assertFalse(readiness["ready"])
            self.assertEqual(readiness["issues"][0]["code"], "authorization_scheme_missing")
            self.assertNotIn("raw-token", str(readiness))
            with self.assertRaisesRegex(ValueError, "including its scheme"):
                assert_target_runtime_ready(self.target())

    def test_runtime_readiness_never_returns_resolved_secret(self) -> None:
        secret = "Bearer private-test-token"
        target = self.target()
        target["request_template"]["session_token"] = "env:ADV_TEST_REQUEST_TOKEN"
        with patch.dict(
            os.environ,
            {self.environment_name: secret, "ADV_TEST_REQUEST_TOKEN": "private-request-token"},
            clear=False,
        ):
            readiness = target_runtime_readiness(target)
        self.assertTrue(readiness["ready"])
        serialized = str(readiness)
        self.assertNotIn(secret, serialized)
        self.assertNotIn("private-request-token", serialized)
        self.assertEqual({item["environment"] for item in readiness["checks"]}, {self.environment_name, "ADV_TEST_REQUEST_TOKEN"})

    def test_missing_environment_blocks_before_a_run_is_created(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = Repository(root / "assessment.sqlite3")
            app = Application(
                repo,
                config=AppConfig(database_path=root / "assessment.sqlite3", evidence_root=root / "projects"),
            )
            project = repo.create_project(name="Runtime preflight")
            target = repo.add_target(
                project["id"],
                name="Authenticated target",
                kind="chatbot",
                base_url="https://target.invalid",
                path="/chat",
                method="POST",
                headers={"Authorization": f"env:{self.environment_name}"},
                request_template={"message": "{{prompt}}"},
                response_path="response",
                scope_confirmed=True,
            )
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop(self.environment_name, None)
                with self.assertRaisesRegex(ValueError, "target runtime preflight blocked"):
                    app.dispatch(
                        "POST",
                        f"/api/projects/{project['id']}/runs",
                        {"target_id": target["id"], "technique_ids": ["LLM01-DIRECT"], "background": True},
                    )
            self.assertEqual(repo.get_project(project["id"])["runs"], [])
            repo.close()

    def test_http_authentication_error_precedes_schema_diagnosis(self) -> None:
        case = {
            "id": "case-auth",
            "status": "error",
            "evaluation": {"evaluator": "error"},
            "trace": {
                "transport": {
                    "request_sent": True,
                    "response_received": True,
                    "status_code": "401",
                    "schema_error": "configured response JSON path was not present: response",
                },
                "extraction": {"completed": False},
            },
        }
        diagnostic = diagnose_case(case, [])
        self.assertEqual(diagnostic["stage"], "transport")
        self.assertEqual(diagnostic["root_cause"], "target_adapter")
        self.assertIn("authentication or authorization", diagnostic["explanation"])

    def test_success_status_schema_failure_remains_a_parser_diagnostic(self) -> None:
        case = {
            "id": "case-schema",
            "status": "error",
            "evaluation": {"evaluator": "error"},
            "trace": {
                "transport": {
                    "request_sent": True,
                    "response_received": True,
                    "status_code": "200",
                    "schema_error": "configured response JSON path was not present: response",
                },
                "extraction": {"completed": False},
            },
        }
        diagnostic = diagnose_case(case, [])
        self.assertEqual(diagnostic["stage"], "extraction")
        self.assertEqual(diagnostic["root_cause"], "response_parser")


if __name__ == "__main__":
    unittest.main()
