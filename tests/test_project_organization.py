from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from osai_security import DATABASE_SCHEMA_VERSION
from osai_security.config import AppConfig
from osai_security.db import NotFoundError, Repository
from osai_security.http_app import Application


class ProjectOrganizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.config = AppConfig(database_path=self.root / "assessment.sqlite3", evidence_root=self.root / "projects")
        self.repo = Repository(self.config.database_path)
        self.app = Application(self.repo, config=self.config, model_gateway=object())  # type: ignore[arg-type]

    def tearDown(self) -> None:
        self.repo.close()
        self.directory.cleanup()

    def test_organization_is_isolated_and_does_not_change_assessment_revision(self) -> None:
        first = self.repo.create_project(name="Acme assistant", client="Acme", environment="test")
        second = self.repo.create_project(name="Beta assistant", client="Beta", environment="production")
        first_revision = self.repo.require_project(first["id"])["updated_at"]

        status, organized = self.app.dispatch(
            "PATCH",
            f"/api/projects/{first['id']}/organization",
            {"folder": "Acme / 2026", "tags": ["Chatbot", "Retest", "chatbot"], "pinned": True},
        )

        self.assertEqual(status, 200)
        self.assertEqual(organized["folder"], "Acme / 2026")
        self.assertEqual(organized["tags"], ["Chatbot", "Retest"])
        self.assertTrue(organized["pinned"])
        self.assertEqual(self.repo.require_project(first["id"])["updated_at"], first_revision)
        untouched = self.repo.get_project(second["id"])
        self.assertEqual(untouched["folder"], "")
        self.assertEqual(untouched["tags"], [])
        self.assertFalse(untouched["pinned"])
        with self.assertRaises(NotFoundError):
            self.repo.update_project_organization("proj_missing", folder="Wrong project")

    def test_archived_projects_are_excluded_by_default_read_only_and_recoverable(self) -> None:
        project = self.repo.create_project(name="Recoverable assessment", client="Example")
        project_id = project["id"]
        self.repo.add_document(project_id, kind="scope", filename="scope.md", content="Authorized example target only.")
        revision_before_archive = self.repo.require_project(project_id)["updated_at"]

        status, archived = self.app.dispatch("POST", f"/api/projects/{project_id}/archive", {})

        self.assertEqual(status, 200)
        self.assertEqual(archived["status"], "archived")
        self.assertIsNotNone(archived["archived_at"])
        self.assertNotEqual(self.repo.require_project(project_id)["updated_at"], revision_before_archive)
        self.assertEqual(self.app.dispatch("GET", "/api/projects", {})[1]["projects"], [])
        all_projects = self.app.dispatch("GET", "/api/projects?include_archived=true", {})[1]["projects"]
        self.assertEqual([item["id"] for item in all_projects], [project_id])
        self.assertEqual(all_projects[0]["counts"]["documents"], 1)
        with self.assertRaisesRegex(ValueError, "read-only"):
            self.app.dispatch(
                "POST",
                f"/api/projects/{project_id}/documents",
                {"kind": "policy", "filename": "policy.md", "content": "Should be blocked."},
            )

        self.app.dispatch(
            "PATCH",
            f"/api/projects/{project_id}/organization",
            {"folder": "Archive / 2026", "tags": ["retained"]},
        )
        status, restored = self.app.dispatch("POST", f"/api/projects/{project_id}/restore", {})
        self.assertEqual(status, 200)
        self.assertEqual(restored["status"], "active")
        self.assertIsNone(restored["archived_at"])
        detail = self.app.dispatch("GET", f"/api/projects/{project_id}", {})[1]
        self.assertEqual(detail["folder"], "Archive / 2026")
        self.assertEqual(detail["tags"], ["retained"])
        self.assertEqual(len(detail["documents"]), 1)
        self.assertEqual(self.app.dispatch("GET", "/api/projects", {})[1]["projects"][0]["id"], project_id)

    def test_archive_is_blocked_while_an_assessment_is_running(self) -> None:
        project = self.repo.create_project(name="Active assessment")
        target = self.repo.add_target(
            project["id"],
            name="Local target",
            base_url="http://127.0.0.1:18080",
            path="/chat",
            method="POST",
            request_template={"message": "{{prompt}}"},
            scope_confirmed=True,
        )
        run = self.repo.create_run(project["id"], target["id"], ["prompt-injection"], "offline")

        with self.assertRaisesRegex(ValueError, "active work"):
            self.repo.archive_project(project["id"])

        self.repo.complete_run(project["id"], run["id"], status="completed")
        self.assertEqual(self.repo.archive_project(project["id"])["status"], "archived")

    def test_opening_a_project_updates_recent_activity_without_changing_revision(self) -> None:
        project = self.repo.create_project(name="Recently opened")
        project_id = project["id"]
        revision = self.repo.require_project(project_id)["updated_at"]

        status, opened = self.app.dispatch("POST", f"/api/projects/{project_id}/opened", {})

        self.assertEqual(status, 200)
        self.assertIsNotNone(opened["last_opened_at"])
        self.assertEqual(self.repo.require_project(project_id)["updated_at"], revision)
        listed = self.repo.list_projects()[0]
        self.assertEqual(listed["last_opened_at"], opened["last_opened_at"])

    def test_hundreds_of_project_summaries_use_a_fixed_query_budget(self) -> None:
        projects = [self.repo.create_project(name=f"Assessment {index:03d}", client=f"Client {index % 8}") for index in range(250)]
        self.repo.update_project_organization(projects[117]["id"], pinned=True, tags=["priority"])

        with mock.patch.object(self.repo, "_all", wraps=self.repo._all) as all_queries:
            listed = self.repo.list_projects()

        self.assertEqual(len(listed), 250)
        self.assertEqual(listed[0]["id"], projects[117]["id"])
        self.assertLessEqual(all_queries.call_count, 16)


class ProjectOrganizationMigrationTests(unittest.TestCase):
    def test_schema_one_project_rows_migrate_without_data_loss(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "legacy.sqlite3"
            connection = sqlite3.connect(path)
            connection.executescript(
                """
                CREATE TABLE projects (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    client TEXT NOT NULL DEFAULT '',
                    environment TEXT NOT NULL DEFAULT 'test',
                    status TEXT NOT NULL DEFAULT 'active',
                    data_classification TEXT NOT NULL DEFAULT 'confidential',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                INSERT INTO projects VALUES ('proj_legacy','Legacy project','Legacy client','test','active','confidential','2026-08-01T00:00:00+00:00','2026-08-01T00:00:00+00:00');
                PRAGMA user_version = 1;
                """
            )
            connection.close()

            repo = Repository(path)
            try:
                self.assertEqual(repo.healthcheck()["schema_version"], DATABASE_SCHEMA_VERSION)
                migrated = repo.get_project("proj_legacy")
                self.assertEqual(migrated["name"], "Legacy project")
                self.assertEqual(migrated["folder"], "")
                self.assertEqual(migrated["tags"], [])
                self.assertFalse(migrated["pinned"])
                self.assertIsNone(migrated["archived_at"])
                self.assertIsNone(migrated["last_opened_at"])
            finally:
                repo.close()


if __name__ == "__main__":
    unittest.main()
