from __future__ import annotations

import json
import socket
import sqlite3
import tempfile
import threading
import unittest
import urllib.request
import zipfile
import io
from contextlib import redirect_stdout
from pathlib import Path

from osai_security.config import AppConfig
from osai_security.cli import main
from osai_security.db import Repository
from osai_security.http_app import Application, create_server
from osai_security.local_setup import initialize_local_state
from osai_security.recovery import (
    RecoveryError,
    create_local_backup,
    export_project,
    import_project,
    recover_interrupted_restore,
    restore_local_backup,
    verify_archive,
)
from osai_security.release import DATABASE_SCHEMA_VERSION


class _InterruptedRepository(Repository):
    def _before_migration_commit(self, source_schema: int, target_schema: int) -> None:
        raise RuntimeError("simulated upgrade interruption")


class MigrationRecoveryTests(unittest.TestCase):
    def test_schema_three_upgrade_adds_assessment_reasoning_without_losing_projects(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "adverscope.sqlite3"
            original = Repository(database)
            project = original.create_project(name="Schema three reasoning migration")
            original.close()
            connection = sqlite3.connect(database)
            try:
                for table in (
                    "reasoning_checkpoints",
                    "reasoning_hypotheses",
                    "reasoning_edges",
                    "reasoning_nodes",
                    "project_methodology_cards",
                ):
                    connection.execute(f'DROP TABLE "{table}"')
                connection.execute("DELETE FROM schema_migrations WHERE version = 4")
                connection.execute("PRAGMA user_version = 3")
                connection.commit()
            finally:
                connection.close()

            upgraded = Repository(database)
            try:
                self.assertEqual(upgraded.get_project(project["id"])["name"], "Schema three reasoning migration")
                self.assertEqual(upgraded.reasoning_workspace(project["id"])["summary"]["nodes"], 0)
                ledger = upgraded.connection.execute(
                    "SELECT name FROM schema_migrations WHERE version = 4"
                ).fetchone()
                self.assertEqual(str(ledger["name"]), "assessment-reasoning")
            finally:
                upgraded.close()

    def test_schema_upgrade_creates_verified_backup_and_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "adverscope.sqlite3"
            original = Repository(database)
            project = original.create_project(name="Preserved migration project")
            original.close()
            connection = sqlite3.connect(database)
            try:
                connection.execute("DELETE FROM schema_migrations")
                connection.execute("PRAGMA user_version = 2")
                connection.commit()
            finally:
                connection.close()

            upgraded = Repository(database)
            try:
                self.assertEqual(upgraded.get_project(project["id"])["name"], "Preserved migration project")
                self.assertEqual(upgraded.healthcheck()["schema_version"], DATABASE_SCHEMA_VERSION)
                backup = upgraded.last_migration_backup
                self.assertIsNotNone(backup)
                self.assertTrue(Path(str(backup["path"])).is_file())
                self.assertTrue(Path(str(backup["manifest_path"])).is_file())
                ledger = upgraded.connection.execute(
                    "SELECT version,backup_sha256 FROM schema_migrations WHERE version = ?",
                    (DATABASE_SCHEMA_VERSION,),
                ).fetchone()
                self.assertEqual(int(ledger["version"]), DATABASE_SCHEMA_VERSION)
                self.assertEqual(str(ledger["backup_sha256"]), backup["sha256"])
            finally:
                upgraded.close()

    def test_interrupted_upgrade_restores_the_exact_pre_upgrade_database(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "adverscope.sqlite3"
            original = Repository(database)
            project = original.create_project(name="Rollback project")
            original.close()
            connection = sqlite3.connect(database)
            try:
                connection.execute("DELETE FROM schema_migrations")
                connection.execute("PRAGMA user_version = 2")
                connection.commit()
            finally:
                connection.close()
            with self.assertRaisesRegex(RuntimeError, "simulated upgrade interruption"):
                _InterruptedRepository(database)

            connection = sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True)
            try:
                self.assertEqual(int(connection.execute("PRAGMA user_version").fetchone()[0]), 2)
                self.assertEqual(connection.execute("SELECT name FROM projects WHERE id = ?", (project["id"],)).fetchone()[0], "Rollback project")
                self.assertEqual(str(connection.execute("PRAGMA integrity_check").fetchone()[0]), "ok")
            finally:
                connection.close()
            backups = list((database.parent / "backups" / "migrations").glob("*.sqlite3"))
            self.assertEqual(len(backups), 1)


class ProjectTransferTests(unittest.TestCase):
    def test_project_transfer_preserves_only_the_selected_project_and_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_evidence = root / "source-evidence"
            source = Repository(root / "source.sqlite3")
            selected = source.create_project(name="Selected", data_classification="restricted")
            other = source.create_project(name="Other")
            source.add_document(selected["id"], kind="scope", filename="scope.md", content="Authorized target")
            source.pin_methodology_card(selected["id"], "boundary-first-reasoning")
            source.create_reasoning_node(selected["id"], kind="component", label="SELECTED_REASONING_MARKER")
            source.create_reasoning_hypothesis(
                selected["id"],
                classification="hypothesis",
                decision="hold",
                claim="SELECTED_HYPOTHESIS_MARKER",
            )
            source.create_reasoning_checkpoint(selected["id"], title="SELECTED_CHECKPOINT_MARKER")
            source.create_reasoning_node(other["id"], kind="component", label="OTHER_REASONING_MARKER")
            selected_directory = source_evidence / selected["id"] / "run_1" / "capture_1"
            selected_directory.mkdir(parents=True)
            (selected_directory / "response.txt").write_text("retained evidence", encoding="utf-8")
            browser_directory = source_evidence / selected["id"] / "_browser_sessions" / "target_1"
            browser_directory.mkdir(parents=True)
            (browser_directory / "cookies.json").write_text("session material", encoding="utf-8")
            other_directory = source_evidence / other["id"]
            other_directory.mkdir(parents=True)
            (other_directory / "other.txt").write_text("must not transfer", encoding="utf-8")
            archive = root / "selected.advscope-project.zip"
            exported = export_project(source, source_evidence, selected["id"], archive, acknowledge_sensitive=True)
            self.assertTrue(exported["verified"])
            with zipfile.ZipFile(archive) as bundle:
                names = set(bundle.namelist())
            self.assertIn(f"evidence/{selected['id']}/run_1/capture_1/response.txt", names)
            self.assertNotIn(f"evidence/{selected['id']}/_browser_sessions/target_1/cookies.json", names)
            self.assertFalse(any(other["id"] in name for name in names))

            destination_evidence = root / "destination-evidence"
            destination = Repository(root / "destination.sqlite3")
            try:
                imported = import_project(destination, destination_evidence, archive, acknowledge_sensitive=True)
                self.assertEqual(imported["project"]["id"], selected["id"])
                documents = destination.list_documents(selected["id"])
                self.assertEqual(documents[0]["content"], "Authorized target")
                reasoning = destination.reasoning_workspace(selected["id"])
                self.assertEqual([item["card_id"] for item in reasoning["methodology_cards"]], ["boundary-first-reasoning"])
                serialized_reasoning = json.dumps(reasoning, sort_keys=True)
                self.assertIn("SELECTED_REASONING_MARKER", serialized_reasoning)
                self.assertIn("SELECTED_HYPOTHESIS_MARKER", serialized_reasoning)
                self.assertIn("SELECTED_CHECKPOINT_MARKER", serialized_reasoning)
                self.assertNotIn("OTHER_REASONING_MARKER", serialized_reasoning)
                self.assertEqual(
                    (destination_evidence / selected["id"] / "run_1" / "capture_1" / "response.txt").read_text(encoding="utf-8"),
                    "retained evidence",
                )
                with self.assertRaisesRegex(ValueError, "already contains|already exists"):
                    import_project(destination, destination_evidence, archive, acknowledge_sensitive=True)
            finally:
                destination.close()
                source.close()

    def test_project_transfer_rejects_tampering_and_requires_acknowledgement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = Repository(root / "source.sqlite3")
            project = repository.create_project(name="Sensitive")
            archive = root / "project.zip"
            with self.assertRaisesRegex(RecoveryError, "acknowledgement"):
                export_project(repository, root / "evidence", project["id"], archive, acknowledge_sensitive=False)
            export_project(repository, root / "evidence", project["id"], archive, acknowledge_sensitive=True)
            with zipfile.ZipFile(archive, "a") as bundle:
                bundle.writestr("undeclared.txt", "tampered")
            with self.assertRaisesRegex(RecoveryError, "undeclared"):
                verify_archive(archive, expected_kind="adverscope-project-transfer")
            repository.close()


class LocalBackupRestoreTests(unittest.TestCase):
    def _config(self, root: Path) -> AppConfig:
        return AppConfig(
            database_path=root / "data" / "adverscope.sqlite3",
            evidence_root=root / "data" / "projects",
            model_profiles_path=root / "data" / "model-providers.json",
            port=18991,
        )

    def test_full_assessment_backup_restores_projects_evidence_and_provider_profiles(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = self._config(root)
            repository = Repository(config.database_path)
            first = repository.create_project(name="First")
            repository.create_project(name="Second")
            repository.create_reasoning_hypothesis(
                first["id"],
                classification="fact",
                decision="hold",
                claim="LOCAL_BACKUP_REASONING_MARKER",
            )
            evidence_file = config.evidence_root / first["id"] / "run" / "capture" / "response.txt"
            evidence_file.parent.mkdir(parents=True)
            evidence_file.write_text("original evidence", encoding="utf-8")
            browser_file = config.evidence_root / first["id"] / "_browser_sessions" / "target" / "cookies.json"
            browser_file.parent.mkdir(parents=True)
            browser_file.write_text("ephemeral session", encoding="utf-8")
            config.model_profiles_path.parent.mkdir(parents=True, exist_ok=True)
            config.model_profiles_path.write_text(json.dumps({"schema_version": "2.0", "profiles": {}, "roles": {}}), encoding="utf-8")
            archive = root / "backup.zip"
            result = create_local_backup(repository, config, archive, acknowledge_sensitive=True)
            self.assertEqual(result["project_count"], 2)
            repository.create_project(name="Added after backup")
            evidence_file.write_text("changed", encoding="utf-8")
            config.model_profiles_path.write_text(json.dumps({"schema_version": "broken"}), encoding="utf-8")
            repository.close()

            restored = restore_local_backup(config, archive, acknowledge_sensitive=True)
            self.assertEqual(restored["project_count"], 2)
            opened = Repository(config.database_path)
            try:
                self.assertEqual(len(opened.project_ids()), 2)
                restored_reasoning = json.dumps(opened.reasoning_workspace(first["id"]), sort_keys=True)
                self.assertIn("LOCAL_BACKUP_REASONING_MARKER", restored_reasoning)
            finally:
                opened.close()
            self.assertEqual(evidence_file.read_text(encoding="utf-8"), "original evidence")
            self.assertFalse(browser_file.exists())
            self.assertEqual(json.loads(config.model_profiles_path.read_text(encoding="utf-8"))["schema_version"], "2.0")

    def test_recovery_journal_rolls_back_an_interrupted_restore(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = self._config(root)
            repository = Repository(config.database_path)
            project = repository.create_project(name="Before interruption")
            repository.close()
            rollback_root = config.database_path.parent / "backups" / "restore-rollback" / "test"
            rollback_root.mkdir(parents=True)
            rollback_database = rollback_root / "database.sqlite3"
            rollback_database.write_bytes(config.database_path.read_bytes())
            rollback_evidence = rollback_root / "evidence"
            config.evidence_root.mkdir(parents=True)
            (config.evidence_root / "marker.txt").write_text("before", encoding="utf-8")
            config.evidence_root.replace(rollback_evidence)
            config.database_path.write_bytes(b"interrupted")
            journal = config.database_path.parent / "backups" / "restore-in-progress.json"
            journal.write_text(json.dumps({
                "database": str(config.database_path.resolve()),
                "evidence": str(config.evidence_root.resolve()),
                "provider": str(config.model_profiles_path.resolve()),
                "rollback_database": str(rollback_database.resolve()),
                "rollback_evidence": str(rollback_evidence.resolve()),
                "rollback_provider": str((rollback_root / "model-providers.json").resolve()),
                "database_existed": True,
                "evidence_existed": True,
                "provider_existed": False,
                "phase": "previous-state-retained",
            }), encoding="utf-8")

            recovered = recover_interrupted_restore(config)
            self.assertTrue(recovered["recovered"])
            reopened = Repository(config.database_path)
            try:
                self.assertEqual(reopened.get_project(project["id"])["name"], "Before interruption")
            finally:
                reopened.close()
            self.assertEqual((config.evidence_root / "marker.txt").read_text(encoding="utf-8"), "before")
            self.assertFalse(journal.exists())

    def test_recovery_journal_rejects_paths_outside_the_rollback_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = self._config(root)
            repository = Repository(config.database_path)
            repository.close()
            journal = config.database_path.parent / "backups" / "restore-in-progress.json"
            journal.parent.mkdir(parents=True)
            journal.write_text(json.dumps({
                "database": str(config.database_path.resolve()),
                "evidence": str(config.evidence_root.resolve()),
                "provider": str(config.model_profiles_path.resolve()),
                "rollback_database": str((root / "outside.sqlite3").resolve()),
                "rollback_evidence": str((root / "outside-evidence").resolve()),
                "rollback_provider": str((root / "outside-providers.json").resolve()),
            }), encoding="utf-8")
            with self.assertRaisesRegex(RecoveryError, "unsafe rollback path"):
                recover_interrupted_restore(config)
            self.assertTrue(journal.is_file())


class RecoveryApiTests(unittest.TestCase):
    @staticmethod
    def _port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            return int(sock.getsockname()[1])

    def test_gui_transport_endpoints_download_verify_and_import_a_project(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_config = AppConfig(
                database_path=root / "source" / "adverscope.sqlite3",
                evidence_root=root / "source" / "projects",
                model_profiles_path=root / "source" / "providers.json",
                port=self._port(),
            )
            source_repo = Repository(source_config.database_path)
            project = source_repo.create_project(name="GUI transfer")
            marker = source_config.evidence_root / project["id"] / "run" / "capture" / "response.txt"
            marker.parent.mkdir(parents=True)
            marker.write_text("GUI-retained evidence", encoding="utf-8")
            source_app = Application(source_repo, config=source_config, model_gateway=object())
            source_server = create_server(source_app, "127.0.0.1", source_config.port)
            source_thread = threading.Thread(target=source_server.serve_forever, daemon=True)
            source_thread.start()
            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{source_config.port}/api/projects/{project['id']}/transfer?acknowledge_sensitive=1",
                    timeout=10,
                ) as response:
                    transfer = response.read()
                    self.assertEqual(response.status, 200)
                    self.assertIn("attachment", response.headers.get("Content-Disposition", ""))
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{source_config.port}/api/local-backup?acknowledge_sensitive=1",
                    timeout=10,
                ) as response:
                    self.assertEqual(response.status, 200)
                    self.assertGreater(len(response.read()), 100)
            finally:
                source_server.shutdown()
                source_server.server_close()
                source_thread.join(timeout=5)
                source_app.close()
                source_repo.close()

            destination_config = AppConfig(
                database_path=root / "destination" / "adverscope.sqlite3",
                evidence_root=root / "destination" / "projects",
                model_profiles_path=root / "destination" / "providers.json",
                port=self._port(),
            )
            destination_repo = Repository(destination_config.database_path)
            destination_app = Application(destination_repo, config=destination_config, model_gateway=object())
            destination_server = create_server(destination_app, "127.0.0.1", destination_config.port)
            destination_thread = threading.Thread(target=destination_server.serve_forever, daemon=True)
            destination_thread.start()
            try:
                request = urllib.request.Request(
                    f"http://127.0.0.1:{destination_config.port}/api/project-transfers?acknowledge_sensitive=1",
                    data=transfer,
                    method="POST",
                    headers={"Content-Type": "application/zip"},
                )
                with urllib.request.urlopen(request, timeout=10) as response:
                    result = json.loads(response.read().decode("utf-8"))
                    self.assertEqual(response.status, 201)
                self.assertEqual(result["project"]["id"], project["id"])
                self.assertEqual(destination_repo.get_project(project["id"])["name"], "GUI transfer")
                self.assertEqual(
                    (destination_config.evidence_root / project["id"] / "run" / "capture" / "response.txt").read_text(encoding="utf-8"),
                    "GUI-retained evidence",
                )
            finally:
                destination_server.shutdown()
                destination_server.server_close()
                destination_thread.join(timeout=5)
                destination_app.close()
                destination_repo.close()


class RecoveryCliTests(unittest.TestCase):
    def test_cli_creates_verifies_exports_and_imports_without_source_edits(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_config_path = root / "source-config.json"
            initialized = initialize_local_state(
                config_path=source_config_path,
                data_directory=root / "source-data",
                evidence_directory=root / "source-evidence",
                port=RecoveryApiTests._port(),
            )
            repository = Repository(initialized["database_path"])
            project = repository.create_project(name="CLI project")
            repository.close()
            project_archive = root / "project.zip"
            output = io.StringIO()
            with redirect_stdout(output):
                code = main([
                    "projects", "--config", str(source_config_path), "export", project["id"], str(project_archive),
                    "--acknowledge-sensitive-data", "--json",
                ])
            self.assertEqual(code, 0, output.getvalue())
            self.assertTrue(json.loads(output.getvalue())["verified"])
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(["projects", "verify", str(project_archive), "--json"]), 0)

            backup_archive = root / "local-backup.zip"
            output = io.StringIO()
            with redirect_stdout(output):
                code = main([
                    "backup", "--config", str(source_config_path), "create", str(backup_archive),
                    "--acknowledge-sensitive-data", "--json",
                ])
            self.assertEqual(code, 0, output.getvalue())
            self.assertEqual(json.loads(output.getvalue())["project_count"], 1)
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(["backup", "verify", str(backup_archive), "--json"]), 0)

            destination_config_path = root / "destination-config.json"
            destination = initialize_local_state(
                config_path=destination_config_path,
                data_directory=root / "destination-data",
                evidence_directory=root / "destination-evidence",
                port=RecoveryApiTests._port(),
            )
            output = io.StringIO()
            with redirect_stdout(output):
                code = main([
                    "projects", "--config", str(destination_config_path), "import", str(project_archive),
                    "--acknowledge-sensitive-data", "--json",
                ])
            self.assertEqual(code, 0, output.getvalue())
            imported = Repository(destination["database_path"])
            try:
                self.assertEqual(imported.get_project(project["id"])["name"], "CLI project")
            finally:
                imported.close()


if __name__ == "__main__":
    unittest.main()
