from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from . import DATABASE_SCHEMA_VERSION
from .deployment_security import secure_directory, secure_file
from .faults import fault_for_event
from .methodology import methodology_card, methodology_card_is_trusted
from .owasp import build_coverage, validate_mapping
from .release import ASSESSMENT_REASONING_SCHEMA_VERSION, PRODUCT_VERSION
from .security import redact_text
from .transport_reliability import normalize_transport_profile
from .recovery import create_pre_migration_backup, restore_database_file


class NotFoundError(LookupError):
    pass


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def now_iso_precise() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def finding_fingerprint(target_id: str, module_id: str, title: str) -> str:
    """Aggregate one root weakness per target and module; attacks remain occurrences."""
    source = f"{target_id}\n{module_id.casefold()}"
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def aggregate_validation_status(validations: list[dict[str, Any]]) -> str:
    """Summarize reproduction evidence without letting a later miss erase proof."""
    statuses = {str(item.get("status") or "") for item in validations}
    if "confirmed" in statuses:
        return "confirmed"
    if "not-reproduced" in statuses:
        return "not-reproduced"
    if "error" in statuses:
        return "error"
    return "pending"


def preview_payload(value: Any, prompt: str) -> Any:
    """Render a request for logs without resolving environment-backed secrets."""
    if isinstance(value, str):
        if value.startswith("env:"):
            return "[REDACTED ENVIRONMENT VALUE]"
        return value.replace("{{prompt}}", prompt)
    if isinstance(value, list):
        return [preview_payload(item, prompt) for item in value]
    if isinstance(value, dict):
        return {str(key): preview_payload(item, prompt) for key, item in value.items()}
    return value


class Repository:
    """SQLite persistence with project_id required on every project-owned lookup."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        secure_directory(self.path.parent)
        self.connection = sqlite3.connect(self.path, check_same_thread=False)
        secure_file(self.path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA journal_mode = WAL")
        secure_file(self.path.with_name(f"{self.path.name}-wal"))
        secure_file(self.path.with_name(f"{self.path.name}-shm"))
        self._lock = threading.RLock()
        self.last_migration_backup: dict[str, Any] | None = None
        current_schema = int(self.connection.execute("PRAGMA user_version").fetchone()[0])
        table_count = int(self.connection.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        ).fetchone()[0])
        if table_count and current_schema < DATABASE_SCHEMA_VERSION:
            try:
                self.last_migration_backup = create_pre_migration_backup(
                    self.connection,
                    self.path,
                    source_schema=current_schema,
                    target_schema=DATABASE_SCHEMA_VERSION,
                )
            except Exception:
                self.connection.close()
                raise
        try:
            self._init_schema()
        except Exception:
            try:
                self.connection.rollback()
            finally:
                self.connection.close()
            if self.last_migration_backup:
                restore_database_file(self.path, self.last_migration_backup["path"])
            raise

    def close(self) -> None:
        with self._lock:
            self.connection.close()

    def healthcheck(self) -> dict[str, Any]:
        with self._lock:
            value = int(self.connection.execute("SELECT 1").fetchone()[0])
            schema_version = int(self.connection.execute("PRAGMA user_version").fetchone()[0])
            self.connection.execute("BEGIN IMMEDIATE")
            self.connection.rollback()
        return {
            "ok": value == 1 and schema_version == DATABASE_SCHEMA_VERSION,
            "path": str(self.path),
            "schema_version": schema_version,
            "migration_backup": self.last_migration_backup,
        }

    def database_snapshot(self, destination: str | Path) -> Path:
        target = Path(destination).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            raise ValueError("database snapshot destination already exists")
        with self._lock:
            output = sqlite3.connect(target)
            try:
                self.connection.backup(output)
                if str(output.execute("PRAGMA integrity_check").fetchone()[0]) != "ok":
                    raise RuntimeError("database snapshot failed integrity verification")
                if list(output.execute("PRAGMA foreign_key_check")):
                    raise RuntimeError("database snapshot failed foreign-key verification")
            finally:
                output.close()
        return target

    def project_ids(self) -> list[str]:
        with self._lock:
            return [str(row[0]) for row in self.connection.execute("SELECT id FROM projects ORDER BY id")]

    def retained_file_records(self, project_ids: list[str] | None = None) -> list[dict[str, Any]]:
        project_filter = ""
        parameters: tuple[Any, ...] = ()
        if project_ids is not None:
            if not project_ids:
                return []
            placeholders = ",".join("?" for _ in project_ids)
            project_filter = f" WHERE project_id IN ({placeholders})"
            parameters = tuple(project_ids)
        query = (
            "SELECT project_id,relative_path,size_bytes,sha256,'evidence-asset' AS record_kind FROM evidence_assets"
            f"{project_filter} UNION ALL "
            "SELECT project_id,relative_path,size_bytes,sha256,'project-artifact' AS record_kind FROM project_artifacts"
            f"{project_filter} ORDER BY project_id,relative_path,record_kind"
        )
        with self._lock:
            return [dict(row) for row in self.connection.execute(query, parameters + parameters).fetchall()]

    def export_project_snapshot(self, project_id: str, destination: str | Path) -> Path:
        self.get_project(project_id)
        target = self.database_snapshot(destination)
        connection = sqlite3.connect(target)
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM projects WHERE id <> ?", (project_id,))
            connection.commit()
            if int(connection.execute("SELECT COUNT(*) FROM projects").fetchone()[0]) != 1:
                raise RuntimeError("project snapshot did not retain exactly one project")
            if list(connection.execute("PRAGMA foreign_key_check")):
                raise RuntimeError("project snapshot failed foreign-key verification")
            connection.execute("VACUUM")
        finally:
            connection.close()
        return target

    def import_project_snapshot(
        self,
        source: str | Path,
        project_id: str,
        *,
        before_commit: Any | None = None,
    ) -> dict[str, Any]:
        snapshot = Path(source).resolve()
        if not snapshot.is_file():
            raise ValueError("project database snapshot is missing")
        source_connection = sqlite3.connect(f"file:{snapshot.as_posix()}?mode=ro", uri=True)
        try:
            source_schema = int(source_connection.execute("PRAGMA user_version").fetchone()[0])
            projects = [str(row[0]) for row in source_connection.execute("SELECT id FROM projects")]
            if source_schema != DATABASE_SCHEMA_VERSION:
                raise ValueError("project database schema is not supported")
            if projects != [project_id]:
                raise ValueError("project database does not match the transfer manifest")
            if str(source_connection.execute("PRAGMA integrity_check").fetchone()[0]) != "ok" or list(source_connection.execute("PRAGMA foreign_key_check")):
                raise ValueError("project database failed integrity verification")
            source_tables = {
                str(row[0])
                for row in source_connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                )
            }
        finally:
            source_connection.close()
        with self._lock:
            if self.connection.execute("SELECT 1 FROM projects WHERE id = ?", (project_id,)).fetchone():
                raise ValueError("project already exists in this installation")
            destination_tables = {
                str(row[0])
                for row in self.connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                )
            }
            project_tables: list[str] = []
            source_schema_connection = sqlite3.connect(f"file:{snapshot.as_posix()}?mode=ro", uri=True)
            try:
                for table in sorted(source_tables & destination_tables):
                    source_columns = [str(row[1]) for row in source_schema_connection.execute(f'PRAGMA table_info("{table}")')]
                    destination_columns = [str(row[1]) for row in self.connection.execute(f'PRAGMA table_info("{table}")')]
                    if source_columns != destination_columns:
                        raise ValueError(f"project database table is incompatible: {table}")
                    if table == "projects" or "project_id" in source_columns:
                        project_tables.append(table)
            finally:
                source_schema_connection.close()
            if "projects" not in project_tables:
                raise ValueError("project database has no projects table")
            alias = f"transfer_{uuid.uuid4().hex[:8]}"
            self.connection.execute(f'ATTACH DATABASE ? AS "{alias}"', (str(snapshot),))
            try:
                self.connection.execute("BEGIN IMMEDIATE")
                self.connection.execute("PRAGMA defer_foreign_keys = ON")
                ordered = ["projects", *[table for table in project_tables if table != "projects"]]
                for table in ordered:
                    columns = [str(row[1]) for row in self.connection.execute(f'PRAGMA table_info("{table}")')]
                    quoted = ",".join(f'"{column}"' for column in columns)
                    predicate = '"id" = ?' if table == "projects" else '"project_id" = ?'
                    self.connection.execute(
                        f'INSERT INTO main."{table}" ({quoted}) SELECT {quoted} FROM "{alias}"."{table}" WHERE {predicate}',
                        (project_id,),
                    )
                foreign_errors = list(self.connection.execute("PRAGMA foreign_key_check"))
                if foreign_errors:
                    raise ValueError("project import failed foreign-key verification")
                if before_commit:
                    before_commit()
                self.connection.commit()
            except Exception:
                self.connection.rollback()
                raise
            finally:
                self.connection.execute(f'DETACH DATABASE "{alias}"')
        return self.get_project(project_id)

    def _init_schema(self) -> None:
        current_schema_version = int(self.connection.execute("PRAGMA user_version").fetchone()[0])
        if current_schema_version > DATABASE_SCHEMA_VERSION:
            raise RuntimeError(
                f"database schema {current_schema_version} is newer than supported schema {DATABASE_SCHEMA_VERSION}"
            )
        schema = """
        CREATE TABLE IF NOT EXISTS projects (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            client TEXT NOT NULL DEFAULT '',
            environment TEXT NOT NULL DEFAULT 'test',
            status TEXT NOT NULL DEFAULT 'active',
            data_classification TEXT NOT NULL DEFAULT 'confidential',
            folder TEXT NOT NULL DEFAULT '',
            tags_json TEXT NOT NULL DEFAULT '[]',
            pinned INTEGER NOT NULL DEFAULT 0 CHECK(pinned IN (0,1)),
            archived_at TEXT,
            last_opened_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS project_documents (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            kind TEXT NOT NULL CHECK(kind IN ('scope', 'policy')),
            filename TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS assessment_objectives (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            title TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            success_criteria TEXT NOT NULL,
            expected_safe_behavior TEXT NOT NULL DEFAULT '',
            false_positive_exclusions TEXT NOT NULL DEFAULT '',
            proof_mode TEXT NOT NULL DEFAULT 'model-review',
            proof_rule_ids_json TEXT NOT NULL DEFAULT '[]',
            require_reproduction INTEGER NOT NULL DEFAULT 0,
            risk_ids_json TEXT NOT NULL DEFAULT '[]',
            technique_ids_json TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS targets (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            kind TEXT NOT NULL,
            base_url TEXT NOT NULL DEFAULT '',
            path TEXT NOT NULL DEFAULT '',
            method TEXT NOT NULL DEFAULT '',
            headers_json TEXT NOT NULL DEFAULT '{}',
            request_template_json TEXT NOT NULL DEFAULT '{}',
            response_path TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            browser_profile_json TEXT NOT NULL DEFAULT '{}',
            capabilities_json TEXT NOT NULL DEFAULT '{}',
            analysis_config_json TEXT NOT NULL DEFAULT '{}',
            conversation_config_json TEXT NOT NULL DEFAULT '{}',
            transport_config_json TEXT NOT NULL DEFAULT '{}',
            evaluation_config_json TEXT NOT NULL DEFAULT '{}',
            technique_adapters_json TEXT NOT NULL DEFAULT '{}',
            assessment_contracts_json TEXT NOT NULL DEFAULT '[]',
            authorized_routes_json TEXT NOT NULL DEFAULT '[]',
            scope_confirmed INTEGER NOT NULL DEFAULT 0 CHECK(scope_confirmed IN (0,1)),
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS execution_guardrails (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            target_id TEXT NOT NULL UNIQUE REFERENCES targets(id) ON DELETE CASCADE,
            source_document_id TEXT REFERENCES project_documents(id) ON DELETE SET NULL,
            status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','approved')),
            max_requests INTEGER NOT NULL DEFAULT 50,
            max_runtime_seconds INTEGER NOT NULL DEFAULT 900,
            max_consecutive_errors INTEGER NOT NULL DEFAULT 3,
            allow_active_recon INTEGER NOT NULL DEFAULT 0 CHECK(allow_active_recon IN (0,1)),
            allow_multi_turn INTEGER NOT NULL DEFAULT 0 CHECK(allow_multi_turn IN (0,1)),
            max_turns_per_objective INTEGER NOT NULL DEFAULT 3,
            allow_reproduction INTEGER NOT NULL DEFAULT 1 CHECK(allow_reproduction IN (0,1)),
            reproduction_mode TEXT NOT NULL DEFAULT 'exact-one' CHECK(reproduction_mode IN ('exact-one','bounded-statistical')),
            reproduction_max_attempts INTEGER NOT NULL DEFAULT 1,
            reproduction_min_successes INTEGER NOT NULL DEFAULT 1,
            reproduction_min_success_rate REAL NOT NULL DEFAULT 1.0,
            reproduction_delay_ms INTEGER NOT NULL DEFAULT 0,
            allow_screenshots INTEGER NOT NULL DEFAULT 1 CHECK(allow_screenshots IN (0,1)),
            stop_on_http_5xx INTEGER NOT NULL DEFAULT 1 CHECK(stop_on_http_5xx IN (0,1)),
            blocked_prompt_patterns_json TEXT NOT NULL DEFAULT '[]',
            notes TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            approved_at TEXT
        );
        CREATE TABLE IF NOT EXISTS target_preflight_runs (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
            status TEXT NOT NULL CHECK(status IN ('running','ready','needs-attention','failed','blocked')),
            request_count INTEGER NOT NULL DEFAULT 0,
            configuration_sha256 TEXT NOT NULL DEFAULT '',
            target_snapshot_json TEXT NOT NULL DEFAULT '{}',
            guardrail_snapshot_json TEXT NOT NULL DEFAULT '{}',
            result_json TEXT NOT NULL DEFAULT '{}',
            error TEXT NOT NULL DEFAULT '',
            started_at TEXT NOT NULL,
            completed_at TEXT
        );
        CREATE TABLE IF NOT EXISTS project_imports (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            run_id TEXT REFERENCES test_runs(id) ON DELETE CASCADE,
            kind TEXT NOT NULL,
            filename TEXT NOT NULL,
            content TEXT NOT NULL,
            summary_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS project_artifacts (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
            filename TEXT NOT NULL,
            kind TEXT NOT NULL CHECK(kind IN ('model','adapter','dependency-manifest','sbom','container-manifest','dataset-manifest','other')),
            relative_path TEXT NOT NULL,
            mime_type TEXT NOT NULL DEFAULT 'application/octet-stream',
            size_bytes INTEGER NOT NULL,
            sha256 TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','archived')),
            created_at TEXT NOT NULL,
            archived_at TEXT,
            UNIQUE(project_id, relative_path)
        );
        CREATE TABLE IF NOT EXISTS test_runs (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE RESTRICT,
            status TEXT NOT NULL,
            model_mode TEXT NOT NULL,
            module_ids_json TEXT NOT NULL,
            assessment_plan_json TEXT NOT NULL DEFAULT '{}',
            attack_profile TEXT NOT NULL DEFAULT 'standard',
            attack_budget INTEGER NOT NULL DEFAULT 8,
            manifest_json TEXT NOT NULL DEFAULT '{}',
            metrics_json TEXT NOT NULL DEFAULT '{}',
            error TEXT NOT NULL DEFAULT '',
            started_at TEXT NOT NULL,
            completed_at TEXT
        );
        CREATE TABLE IF NOT EXISTS test_cases (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            run_id TEXT NOT NULL REFERENCES test_runs(id) ON DELETE CASCADE,
            target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE RESTRICT,
            module_id TEXT NOT NULL,
            title TEXT NOT NULL,
            prompt TEXT NOT NULL,
            rationale TEXT NOT NULL DEFAULT '',
            response TEXT NOT NULL DEFAULT '',
            evaluation_json TEXT NOT NULL DEFAULT '{}',
            trace_json TEXT NOT NULL DEFAULT '{}',
            generation_source TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS run_events (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            run_id TEXT NOT NULL REFERENCES test_runs(id) ON DELETE CASCADE,
            test_case_id TEXT REFERENCES test_cases(id) ON DELETE SET NULL,
            sequence INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            title TEXT NOT NULL,
            details_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            UNIQUE(run_id, sequence)
        );
        CREATE TABLE IF NOT EXISTS ai_protocol_events (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            run_id TEXT NOT NULL REFERENCES test_runs(id) ON DELETE CASCADE,
            test_case_id TEXT REFERENCES test_cases(id) ON DELETE SET NULL,
            sequence INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            phase TEXT NOT NULL,
            direction TEXT NOT NULL,
            event_type TEXT NOT NULL,
            correlation_id TEXT NOT NULL,
            round_number INTEGER NOT NULL DEFAULT 0,
            payload_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            UNIQUE(run_id, sequence)
        );
        CREATE TABLE IF NOT EXISTS evidence (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            run_id TEXT NOT NULL REFERENCES test_runs(id) ON DELETE CASCADE,
            test_case_id TEXT NOT NULL REFERENCES test_cases(id) ON DELETE CASCADE,
            kind TEXT NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS evidence_assets (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            run_id TEXT NOT NULL REFERENCES test_runs(id) ON DELETE CASCADE,
            test_case_id TEXT NOT NULL REFERENCES test_cases(id) ON DELETE CASCADE,
            evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
            kind TEXT NOT NULL,
            attempt TEXT NOT NULL DEFAULT 'initial',
            relative_path TEXT NOT NULL,
            mime_type TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            sha256 TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(project_id, relative_path)
        );
        CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            run_id TEXT NOT NULL REFERENCES test_runs(id) ON DELETE CASCADE,
            test_case_id TEXT NOT NULL REFERENCES test_cases(id) ON DELETE CASCADE,
            evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE RESTRICT,
            module_id TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence REAL NOT NULL DEFAULT 0,
            summary TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open', 'accepted', 'rejected', 'fixed')),
            fingerprint TEXT NOT NULL DEFAULT '',
            occurrence_count INTEGER NOT NULL DEFAULT 1,
            last_seen_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS finding_occurrences (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
            run_id TEXT NOT NULL REFERENCES test_runs(id) ON DELETE CASCADE,
            test_case_id TEXT NOT NULL REFERENCES test_cases(id) ON DELETE CASCADE,
            evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE RESTRICT,
            created_at TEXT NOT NULL,
            UNIQUE(finding_id, run_id, test_case_id)
        );
        CREATE TABLE IF NOT EXISTS finding_validations (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
            run_id TEXT NOT NULL REFERENCES test_runs(id) ON DELETE CASCADE,
            test_case_id TEXT NOT NULL REFERENCES test_cases(id) ON DELETE CASCADE,
            evidence_id TEXT REFERENCES evidence(id) ON DELETE SET NULL,
            status TEXT NOT NULL CHECK(status IN ('confirmed', 'not-reproduced', 'error')),
            response TEXT NOT NULL DEFAULT '',
            evaluation_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_events (
            id TEXT PRIMARY KEY,
            project_id TEXT REFERENCES projects(id) ON DELETE CASCADE,
            action TEXT NOT NULL,
            object_type TEXT NOT NULL,
            object_id TEXT NOT NULL,
            outcome TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS project_report_reviews (
            project_id TEXT PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
            status TEXT NOT NULL CHECK(status IN ('draft','accepted')),
            reviewer TEXT NOT NULL DEFAULT '',
            notes TEXT NOT NULL DEFAULT '',
            accepted_project_updated_at TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS project_methodology_cards (
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            card_id TEXT NOT NULL,
            card_snapshot_json TEXT NOT NULL,
            notes TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(project_id, card_id)
        );
        CREATE TABLE IF NOT EXISTS reasoning_nodes (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            target_id TEXT REFERENCES targets(id) ON DELETE CASCADE,
            kind TEXT NOT NULL CHECK(kind IN ('component','identity','credential-reference','data','artifact','consumer','sink','route')),
            label TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            confidence TEXT NOT NULL DEFAULT 'unknown' CHECK(confidence IN ('confirmed','likely','unknown')),
            source_ref TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(project_id, id)
        );
        CREATE TABLE IF NOT EXISTS reasoning_edges (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            source_node_id TEXT NOT NULL,
            target_node_id TEXT NOT NULL,
            kind TEXT NOT NULL CHECK(kind IN ('data-flow','trust','authority','uses-credential','triggers','produces','reaches','consumes')),
            status TEXT NOT NULL DEFAULT 'unknown' CHECK(status IN ('confirmed','likely','unknown','blocked')),
            label TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            evidence_refs_json TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(project_id, source_node_id) REFERENCES reasoning_nodes(project_id, id) ON DELETE CASCADE,
            FOREIGN KEY(project_id, target_node_id) REFERENCES reasoning_nodes(project_id, id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS reasoning_hypotheses (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            target_id TEXT REFERENCES targets(id) ON DELETE CASCADE,
            classification TEXT NOT NULL CHECK(classification IN ('fact','inference','hypothesis','failure')),
            decision TEXT NOT NULL DEFAULT 'hold' CHECK(decision IN ('go','hold','no-go')),
            claim TEXT NOT NULL,
            rationale TEXT NOT NULL DEFAULT '',
            missing_prerequisite TEXT NOT NULL DEFAULT '',
            cheapest_test TEXT NOT NULL DEFAULT '',
            evidence_refs_json TEXT NOT NULL DEFAULT '[]',
            methodology_card_ids_json TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS reasoning_checkpoints (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            target_id TEXT REFERENCES targets(id) ON DELETE CASCADE,
            run_id TEXT REFERENCES test_runs(id) ON DELETE CASCADE,
            test_case_id TEXT REFERENCES test_cases(id) ON DELETE CASCADE,
            evidence_id TEXT REFERENCES evidence(id) ON DELETE SET NULL,
            correction_of_id TEXT REFERENCES reasoning_checkpoints(id) ON DELETE RESTRICT,
            title TEXT NOT NULL,
            starting_identity TEXT NOT NULL DEFAULT '',
            prerequisite TEXT NOT NULL DEFAULT '',
            action TEXT NOT NULL DEFAULT '',
            result TEXT NOT NULL DEFAULT '',
            impact TEXT NOT NULL DEFAULT '',
            cleanup_status TEXT NOT NULL DEFAULT 'not-required' CHECK(cleanup_status IN ('not-required','pending','completed','failed')),
            stages_json TEXT NOT NULL DEFAULT '{}',
            notes TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS testing_tool_definitions (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE RESTRICT,
            kind TEXT NOT NULL CHECK(kind IN ('workflow','campaign')),
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            definition_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS testing_tool_runs (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE RESTRICT,
            definition_id TEXT REFERENCES testing_tool_definitions(id) ON DELETE SET NULL,
            assessment_run_id TEXT REFERENCES test_runs(id) ON DELETE CASCADE,
            contract_id TEXT NOT NULL DEFAULT '',
            kind TEXT NOT NULL CHECK(kind IN ('workflow','campaign','replay')),
            name TEXT NOT NULL,
            status TEXT NOT NULL,
            definition_json TEXT NOT NULL,
            input_json TEXT NOT NULL DEFAULT '{}',
            manifest_json TEXT NOT NULL DEFAULT '{}',
            context_json TEXT NOT NULL DEFAULT '{}',
            error TEXT NOT NULL DEFAULT '',
            started_at TEXT NOT NULL,
            completed_at TEXT
        );
        CREATE TABLE IF NOT EXISTS testing_tool_events (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            tool_run_id TEXT NOT NULL REFERENCES testing_tool_runs(id) ON DELETE CASCADE,
            sequence INTEGER NOT NULL,
            step_id TEXT NOT NULL DEFAULT '',
            event_type TEXT NOT NULL,
            title TEXT NOT NULL,
            details_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            UNIQUE(tool_run_id, sequence)
        );
        CREATE TABLE IF NOT EXISTS testing_tool_findings (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            tool_run_id TEXT NOT NULL REFERENCES testing_tool_runs(id) ON DELETE CASCADE,
            target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE RESTRICT,
            outcome_id TEXT NOT NULL,
            title TEXT NOT NULL,
            summary TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence REAL NOT NULL DEFAULT 0,
            risk_ids_json TEXT NOT NULL DEFAULT '[]',
            technique_ids_json TEXT NOT NULL DEFAULT '[]',
            required_step_ids_json TEXT NOT NULL DEFAULT '[]',
            evidence_event_ids_json TEXT NOT NULL DEFAULT '[]',
            confirmation TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open', 'accepted', 'rejected', 'fixed')),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(tool_run_id, outcome_id)
        );
        CREATE TABLE IF NOT EXISTS interaction_tokens (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            target_id TEXT REFERENCES targets(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            token TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled')),
            created_at TEXT NOT NULL,
            last_seen_at TEXT
        );
        CREATE TABLE IF NOT EXISTS interaction_events (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            interaction_token_id TEXT NOT NULL REFERENCES interaction_tokens(id) ON DELETE CASCADE,
            method TEXT NOT NULL,
            path TEXT NOT NULL,
            source TEXT NOT NULL DEFAULT '',
            headers_json TEXT NOT NULL DEFAULT '{}',
            body TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS validation_adjudications (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            execution_kind TEXT NOT NULL CHECK(execution_kind IN ('assessment','tool')),
            execution_id TEXT NOT NULL,
            test_case_id TEXT NOT NULL DEFAULT '',
            source TEXT NOT NULL CHECK(source IN ('human','oracle','automated')),
            expectation_id TEXT NOT NULL,
            expected_outcome TEXT NOT NULL,
            observed_outcome TEXT NOT NULL,
            classification TEXT NOT NULL,
            root_cause TEXT NOT NULL DEFAULT 'unclassified',
            notes TEXT NOT NULL DEFAULT '',
            metadata_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(project_id,execution_kind,execution_id,source,expectation_id,test_case_id)
        );
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at TEXT NOT NULL,
            app_version TEXT NOT NULL,
            backup_path TEXT NOT NULL DEFAULT '',
            backup_sha256 TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_documents_project ON project_documents(project_id);
        CREATE INDEX IF NOT EXISTS idx_objectives_project ON assessment_objectives(project_id);
        CREATE INDEX IF NOT EXISTS idx_targets_project ON targets(project_id);
        CREATE INDEX IF NOT EXISTS idx_guardrails_project ON execution_guardrails(project_id);
        CREATE INDEX IF NOT EXISTS idx_target_preflights_project ON target_preflight_runs(project_id, started_at);
        CREATE INDEX IF NOT EXISTS idx_target_preflights_target ON target_preflight_runs(target_id, started_at);
        CREATE INDEX IF NOT EXISTS idx_imports_project ON project_imports(project_id);
        CREATE INDEX IF NOT EXISTS idx_artifacts_project ON project_artifacts(project_id, status, created_at);
        CREATE INDEX IF NOT EXISTS idx_artifacts_target ON project_artifacts(target_id, status, created_at);
        CREATE INDEX IF NOT EXISTS idx_runs_project ON test_runs(project_id);
        CREATE INDEX IF NOT EXISTS idx_cases_run ON test_cases(run_id);
        CREATE INDEX IF NOT EXISTS idx_run_events_run ON run_events(run_id, sequence);
        CREATE INDEX IF NOT EXISTS idx_ai_protocol_events_run ON ai_protocol_events(run_id, sequence);
        CREATE INDEX IF NOT EXISTS idx_ai_protocol_events_case ON ai_protocol_events(test_case_id, sequence);
        CREATE INDEX IF NOT EXISTS idx_evidence_project ON evidence(project_id);
        CREATE INDEX IF NOT EXISTS idx_assets_evidence ON evidence_assets(evidence_id);
        CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id);
        CREATE INDEX IF NOT EXISTS idx_occurrences_finding ON finding_occurrences(finding_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_validations_finding ON finding_validations(finding_id);
        CREATE INDEX IF NOT EXISTS idx_audit_project ON audit_events(project_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_methodology_cards_project ON project_methodology_cards(project_id, updated_at);
        CREATE INDEX IF NOT EXISTS idx_reasoning_nodes_project ON reasoning_nodes(project_id, target_id, updated_at);
        CREATE INDEX IF NOT EXISTS idx_reasoning_edges_project ON reasoning_edges(project_id, updated_at);
        CREATE INDEX IF NOT EXISTS idx_reasoning_hypotheses_project ON reasoning_hypotheses(project_id, target_id, updated_at);
        CREATE INDEX IF NOT EXISTS idx_reasoning_checkpoints_project ON reasoning_checkpoints(project_id, target_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_tool_definitions_project ON testing_tool_definitions(project_id, kind);
        CREATE INDEX IF NOT EXISTS idx_tool_runs_project ON testing_tool_runs(project_id, started_at);
        CREATE INDEX IF NOT EXISTS idx_tool_events_run ON testing_tool_events(tool_run_id, sequence);
        CREATE INDEX IF NOT EXISTS idx_tool_findings_project ON testing_tool_findings(project_id, status, created_at);
        CREATE INDEX IF NOT EXISTS idx_tool_findings_run ON testing_tool_findings(tool_run_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_interaction_tokens_project ON interaction_tokens(project_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_interaction_events_token ON interaction_events(interaction_token_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_adjudications_execution ON validation_adjudications(project_id, execution_kind, execution_id, updated_at);
        """
        with self._lock:
            self.connection.executescript(schema)
            self.connection.execute("BEGIN IMMEDIATE")
            project_columns = {row["name"] for row in self.connection.execute("PRAGMA table_info(projects)")}
            if "folder" not in project_columns:
                self.connection.execute("ALTER TABLE projects ADD COLUMN folder TEXT NOT NULL DEFAULT ''")
            if "tags_json" not in project_columns:
                self.connection.execute("ALTER TABLE projects ADD COLUMN tags_json TEXT NOT NULL DEFAULT '[]'")
            if "pinned" not in project_columns:
                self.connection.execute("ALTER TABLE projects ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0")
            if "archived_at" not in project_columns:
                self.connection.execute("ALTER TABLE projects ADD COLUMN archived_at TEXT")
            if "last_opened_at" not in project_columns:
                self.connection.execute("ALTER TABLE projects ADD COLUMN last_opened_at TEXT")
            self.connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_projects_organization "
                "ON projects(status, pinned, last_opened_at, updated_at)"
            )
            columns = {row["name"] for row in self.connection.execute("PRAGMA table_info(targets)")}
            if "browser_profile_json" not in columns:
                self.connection.execute("ALTER TABLE targets ADD COLUMN browser_profile_json TEXT NOT NULL DEFAULT '{}'")
            if "scope_confirmed" not in columns:
                self.connection.execute("ALTER TABLE targets ADD COLUMN scope_confirmed INTEGER NOT NULL DEFAULT 0")
            if "capabilities_json" not in columns:
                self.connection.execute("ALTER TABLE targets ADD COLUMN capabilities_json TEXT NOT NULL DEFAULT '{}'")
            if "analysis_config_json" not in columns:
                self.connection.execute("ALTER TABLE targets ADD COLUMN analysis_config_json TEXT NOT NULL DEFAULT '{}'")
            if "conversation_config_json" not in columns:
                self.connection.execute("ALTER TABLE targets ADD COLUMN conversation_config_json TEXT NOT NULL DEFAULT '{}'")
            if "transport_config_json" not in columns:
                self.connection.execute("ALTER TABLE targets ADD COLUMN transport_config_json TEXT NOT NULL DEFAULT '{}'")
            if "evaluation_config_json" not in columns:
                self.connection.execute("ALTER TABLE targets ADD COLUMN evaluation_config_json TEXT NOT NULL DEFAULT '{}'")
            if "technique_adapters_json" not in columns:
                self.connection.execute("ALTER TABLE targets ADD COLUMN technique_adapters_json TEXT NOT NULL DEFAULT '{}'")
            if "assessment_contracts_json" not in columns:
                self.connection.execute("ALTER TABLE targets ADD COLUMN assessment_contracts_json TEXT NOT NULL DEFAULT '[]'")
            if "authorized_routes_json" not in columns:
                self.connection.execute("ALTER TABLE targets ADD COLUMN authorized_routes_json TEXT NOT NULL DEFAULT '[]'")
            guardrail_columns = {row["name"] for row in self.connection.execute("PRAGMA table_info(execution_guardrails)")}
            if "blocked_prompt_patterns_json" not in guardrail_columns:
                self.connection.execute("ALTER TABLE execution_guardrails ADD COLUMN blocked_prompt_patterns_json TEXT NOT NULL DEFAULT '[]'")
            if "reproduction_mode" not in guardrail_columns:
                self.connection.execute("ALTER TABLE execution_guardrails ADD COLUMN reproduction_mode TEXT NOT NULL DEFAULT 'exact-one'")
            if "reproduction_max_attempts" not in guardrail_columns:
                self.connection.execute("ALTER TABLE execution_guardrails ADD COLUMN reproduction_max_attempts INTEGER NOT NULL DEFAULT 1")
            if "reproduction_min_successes" not in guardrail_columns:
                self.connection.execute("ALTER TABLE execution_guardrails ADD COLUMN reproduction_min_successes INTEGER NOT NULL DEFAULT 1")
            if "reproduction_min_success_rate" not in guardrail_columns:
                self.connection.execute("ALTER TABLE execution_guardrails ADD COLUMN reproduction_min_success_rate REAL NOT NULL DEFAULT 1.0")
            if "reproduction_delay_ms" not in guardrail_columns:
                self.connection.execute("ALTER TABLE execution_guardrails ADD COLUMN reproduction_delay_ms INTEGER NOT NULL DEFAULT 0")
            objective_columns = {row["name"] for row in self.connection.execute("PRAGMA table_info(assessment_objectives)")}
            if "expected_safe_behavior" not in objective_columns:
                self.connection.execute("ALTER TABLE assessment_objectives ADD COLUMN expected_safe_behavior TEXT NOT NULL DEFAULT ''")
            if "false_positive_exclusions" not in objective_columns:
                self.connection.execute("ALTER TABLE assessment_objectives ADD COLUMN false_positive_exclusions TEXT NOT NULL DEFAULT ''")
            if "proof_mode" not in objective_columns:
                self.connection.execute("ALTER TABLE assessment_objectives ADD COLUMN proof_mode TEXT NOT NULL DEFAULT 'model-review'")
            if "proof_rule_ids_json" not in objective_columns:
                self.connection.execute("ALTER TABLE assessment_objectives ADD COLUMN proof_rule_ids_json TEXT NOT NULL DEFAULT '[]'")
            if "require_reproduction" not in objective_columns:
                self.connection.execute("ALTER TABLE assessment_objectives ADD COLUMN require_reproduction INTEGER NOT NULL DEFAULT 0")
            run_columns = {row["name"] for row in self.connection.execute("PRAGMA table_info(test_runs)")}
            if "attack_profile" not in run_columns:
                self.connection.execute("ALTER TABLE test_runs ADD COLUMN attack_profile TEXT NOT NULL DEFAULT 'legacy'")
            if "attack_budget" not in run_columns:
                self.connection.execute("ALTER TABLE test_runs ADD COLUMN attack_budget INTEGER NOT NULL DEFAULT 3")
            if "assessment_plan_json" not in run_columns:
                self.connection.execute("ALTER TABLE test_runs ADD COLUMN assessment_plan_json TEXT NOT NULL DEFAULT '{}'")
            if "manifest_json" not in run_columns:
                self.connection.execute("ALTER TABLE test_runs ADD COLUMN manifest_json TEXT NOT NULL DEFAULT '{}'")
            if "metrics_json" not in run_columns:
                self.connection.execute("ALTER TABLE test_runs ADD COLUMN metrics_json TEXT NOT NULL DEFAULT '{}'")
            tool_run_columns = {row["name"] for row in self.connection.execute("PRAGMA table_info(testing_tool_runs)")}
            if "assessment_run_id" not in tool_run_columns:
                self.connection.execute("ALTER TABLE testing_tool_runs ADD COLUMN assessment_run_id TEXT REFERENCES test_runs(id) ON DELETE CASCADE")
            if "contract_id" not in tool_run_columns:
                self.connection.execute("ALTER TABLE testing_tool_runs ADD COLUMN contract_id TEXT NOT NULL DEFAULT ''")
            if "manifest_json" not in tool_run_columns:
                self.connection.execute("ALTER TABLE testing_tool_runs ADD COLUMN manifest_json TEXT NOT NULL DEFAULT '{}'")
            case_columns = {row["name"] for row in self.connection.execute("PRAGMA table_info(test_cases)")}
            if "trace_json" not in case_columns:
                self.connection.execute("ALTER TABLE test_cases ADD COLUMN trace_json TEXT NOT NULL DEFAULT '{}'")
            import_table = self.connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'project_imports'"
            ).fetchone()
            if import_table and "CHECK(kind IN ('api', 'burp'))" in str(import_table["sql"]):
                self.connection.execute(
                    """CREATE TABLE project_imports_migrated (
                        id TEXT PRIMARY KEY,
                        project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                        run_id TEXT,
                        kind TEXT NOT NULL,
                        filename TEXT NOT NULL,
                        content TEXT NOT NULL,
                        summary_json TEXT NOT NULL DEFAULT '{}',
                        created_at TEXT NOT NULL
                    )"""
                )
                self.connection.execute(
                    """INSERT INTO project_imports_migrated(id,project_id,run_id,kind,filename,content,summary_json,created_at)
                    SELECT id,project_id,NULL,kind,filename,content,summary_json,created_at FROM project_imports;
                    """
                )
                self.connection.execute("DROP TABLE project_imports")
                self.connection.execute("ALTER TABLE project_imports_migrated RENAME TO project_imports")
                self.connection.execute("CREATE INDEX IF NOT EXISTS idx_imports_project ON project_imports(project_id)")
            import_columns = {row["name"] for row in self.connection.execute("PRAGMA table_info(project_imports)")}
            if "run_id" not in import_columns:
                self.connection.execute("ALTER TABLE project_imports ADD COLUMN run_id TEXT")
            self.connection.execute("CREATE INDEX IF NOT EXISTS idx_imports_run ON project_imports(run_id, created_at)")
            finding_columns = {row["name"] for row in self.connection.execute("PRAGMA table_info(findings)")}
            if "fingerprint" not in finding_columns:
                self.connection.execute("ALTER TABLE findings ADD COLUMN fingerprint TEXT NOT NULL DEFAULT ''")
            if "occurrence_count" not in finding_columns:
                self.connection.execute("ALTER TABLE findings ADD COLUMN occurrence_count INTEGER NOT NULL DEFAULT 1")
            if "last_seen_at" not in finding_columns:
                self.connection.execute("ALTER TABLE findings ADD COLUMN last_seen_at TEXT")
            timestamp = now_iso()
            self.connection.execute(
                "INSERT OR IGNORE INTO execution_guardrails"
                "(id,project_id,target_id,status,max_requests,max_runtime_seconds,max_consecutive_errors,"
                "allow_active_recon,allow_multi_turn,max_turns_per_objective,allow_reproduction,allow_screenshots,"
                "stop_on_http_5xx,notes,created_at,updated_at,approved_at) "
                "SELECT 'grd_' || substr(hex(randomblob(12)),1,12), project_id, id, "
                "CASE WHEN scope_confirmed = 1 THEN 'approved' ELSE 'draft' END, 50, 900, 3, 0, 0, 3, 1, 1, 1, "
                "'Conservative migration default; review against the rules of engagement.', ?, ?, "
                "CASE WHEN scope_confirmed = 1 THEN ? ELSE NULL END FROM targets",
                (timestamp, timestamp, timestamp),
            )
            self._merge_existing_finding_duplicates()
            self.connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_project_fingerprint "
                "ON findings(project_id, fingerprint) WHERE fingerprint <> ''"
            )
            backup_path = str((self.last_migration_backup or {}).get("path") or "")
            backup_sha256 = str((self.last_migration_backup or {}).get("sha256") or "")
            for version in range(max(1, current_schema_version + 1), DATABASE_SCHEMA_VERSION + 1):
                name = {2: "project-organization", 3: "transactional-recovery", 4: "assessment-reasoning"}.get(version, f"schema-{version}")
                self.connection.execute(
                    "INSERT OR IGNORE INTO schema_migrations(version,name,applied_at,app_version,backup_path,backup_sha256) VALUES(?,?,?,?,?,?)",
                    (version, name, now_iso(), PRODUCT_VERSION, backup_path, backup_sha256),
                )
            self.connection.execute(f"PRAGMA user_version = {DATABASE_SCHEMA_VERSION}")
            if current_schema_version < DATABASE_SCHEMA_VERSION:
                self._before_migration_commit(current_schema_version, DATABASE_SCHEMA_VERSION)
            if list(self.connection.execute("PRAGMA foreign_key_check")):
                raise RuntimeError("database migration failed foreign-key verification")
            self.connection.commit()

    def _before_migration_commit(self, source_schema: int, target_schema: int) -> None:
        """Test seam for simulating an interrupted upgrade before commit."""
        return None

    def _merge_existing_finding_duplicates(self) -> None:
        """Backfill occurrences and merge historical duplicates without losing evidence."""
        rows = list(self.connection.execute(
            "SELECT f.*, tc.target_id FROM findings f "
            "JOIN test_cases tc ON tc.id = f.test_case_id AND tc.project_id = f.project_id "
            "ORDER BY f.created_at, f.id"
        ))
        groups: dict[tuple[str, str], list[sqlite3.Row]] = {}
        for row in rows:
            fingerprint = finding_fingerprint(row["target_id"], row["module_id"], row["title"])
            groups.setdefault((row["project_id"], fingerprint), []).append(row)

        status_priority = {"accepted": 0, "fixed": 1, "open": 2, "rejected": 3}
        severity_priority = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        for (project_id, fingerprint), members in groups.items():
            canonical = sorted(
                members,
                key=lambda row: (status_priority.get(row["status"], 9), row["created_at"], row["id"]),
            )[0]
            canonical_id = canonical["id"]
            for member in members:
                self.connection.execute(
                    "INSERT OR IGNORE INTO finding_occurrences"
                    "(id,project_id,finding_id,run_id,test_case_id,evidence_id,created_at) VALUES(?,?,?,?,?,?,?)",
                    (new_id("occ"), project_id, canonical_id, member["run_id"], member["test_case_id"], member["evidence_id"], member["created_at"]),
                )
                if member["id"] != canonical_id:
                    self.connection.execute(
                        "UPDATE finding_validations SET finding_id = ? WHERE finding_id = ? AND project_id = ?",
                        (canonical_id, member["id"], project_id),
                    )
                    self.connection.execute("DELETE FROM findings WHERE id = ? AND project_id = ?", (member["id"], project_id))
                    self.connection.execute(
                        "INSERT INTO audit_events(id,project_id,action,object_type,object_id,outcome,metadata_json,created_at) "
                        "VALUES(?,?,?,?,?,?,?,?)",
                        (new_id("audit"), project_id, "finding.deduplicated", "finding", canonical_id, "merged", json_dumps({"merged_finding_id": member["id"]}), now_iso()),
                    )

            occurrence = self.connection.execute(
                "SELECT COUNT(*) AS count, MIN(created_at) AS first_seen, MAX(created_at) AS last_seen "
                "FROM finding_occurrences WHERE finding_id = ?",
                (canonical_id,),
            ).fetchone()
            highest_severity = max(
                (member["severity"] for member in members),
                key=lambda value: severity_priority.get(value, 0),
            )
            self.connection.execute(
                "UPDATE findings SET fingerprint = ?, occurrence_count = ?, last_seen_at = ?, created_at = ?, "
                "severity = ?, confidence = ?, updated_at = ? WHERE id = ? AND project_id = ?",
                (
                    fingerprint,
                    int(occurrence["count"]),
                    occurrence["last_seen"],
                    occurrence["first_seen"],
                    highest_severity,
                    max(float(member["confidence"]) for member in members),
                    max(member["updated_at"] for member in members),
                    canonical_id,
                    project_id,
                ),
            )

    def _one(self, query: str, params: tuple[Any, ...] = ()) -> sqlite3.Row | None:
        with self._lock:
            return self.connection.execute(query, params).fetchone()

    def _all(self, query: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return list(self.connection.execute(query, params).fetchall())

    def _write(self, query: str, params: tuple[Any, ...] = ()) -> None:
        with self._lock:
            self.connection.execute(query, params)
            self.connection.commit()

    def record_audit(self, project_id: str | None, *, action: str, object_type: str, object_id: str, outcome: str = "success", metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        if project_id is not None:
            self.require_project(project_id)
        safe_metadata: dict[str, Any] = {}
        for key, value in (metadata or {}).items():
            safe_metadata[str(key)[:80]] = redact_text(str(value), 1000)
        item = {
            "id": new_id("audit"),
            "project_id": project_id,
            "action": action[:120],
            "object_type": object_type[:80],
            "object_id": object_id[:160],
            "outcome": outcome[:40],
            "metadata_json": json_dumps(safe_metadata),
            "created_at": now_iso(),
        }
        self._write("INSERT INTO audit_events(id,project_id,action,object_type,object_id,outcome,metadata_json,created_at) VALUES(?,?,?,?,?,?,?,?)", tuple(item.values()))
        return {**item, "metadata": safe_metadata}

    @staticmethod
    def _decode(row: sqlite3.Row | None) -> dict[str, Any] | None:
        return dict(row) if row else None

    def create_project(self, *, name: str, client: str = "", environment: str = "test", data_classification: str = "confidential") -> dict[str, Any]:
        name = name.strip()
        if not name:
            raise ValueError("project name is required")
        timestamp = now_iso()
        item = {
            "id": new_id("proj"),
            "name": name[:160],
            "client": client.strip()[:160],
            "environment": environment.strip()[:80] or "test",
            "status": "active",
            "data_classification": data_classification.strip()[:80] or "confidential",
            "folder": "",
            "tags_json": "[]",
            "pinned": 0,
            "archived_at": None,
            "last_opened_at": None,
            "created_at": timestamp,
            "updated_at": timestamp,
        }
        self._write(
            "INSERT INTO projects(id,name,client,environment,status,data_classification,folder,tags_json,pinned,archived_at,last_opened_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            tuple(item.values()),
        )
        self.record_audit(item["id"], action="project.created", object_type="project", object_id=item["id"], metadata={"name": item["name"], "client": item["client"]})
        return self._project_record(item)

    @staticmethod
    def _project_record(item: dict[str, Any]) -> dict[str, Any]:
        result = dict(item)
        try:
            decoded_tags = json.loads(str(result.pop("tags_json", "[]") or "[]"))
        except (TypeError, ValueError, json.JSONDecodeError):
            decoded_tags = []
        result["tags"] = [str(tag) for tag in decoded_tags] if isinstance(decoded_tags, list) else []
        result["pinned"] = bool(result.get("pinned"))
        return result

    @staticmethod
    def _empty_project_counts() -> dict[str, int]:
        return {
            "documents": 0,
            "objectives": 0,
            "targets": 0,
            "preflights": 0,
            "imports": 0,
            "artifacts": 0,
            "runs": 0,
            "evidence_assets": 0,
            "evidence_records": 0,
            "assessment_findings": 0,
            "tool_findings": 0,
            "open_findings": 0,
            "findings": 0,
            "testing_tools": 0,
            "tool_runs": 0,
            "interactions": 0,
        }

    def _bulk_project_counts(self, project_ids: set[str]) -> dict[str, dict[str, int]]:
        """Load sidebar counts in a fixed number of queries, independent of project count."""
        counts = {project_id: self._empty_project_counts() for project_id in project_ids}
        if not project_ids:
            return counts
        for key, table, qualifier in (
            ("documents", "project_documents", ""),
            ("objectives", "assessment_objectives", ""),
            ("targets", "targets", ""),
            ("preflights", "target_preflight_runs", ""),
            ("imports", "project_imports", "WHERE run_id IS NULL"),
            ("artifacts", "project_artifacts", "WHERE status = 'active'"),
            ("runs", "test_runs", ""),
            ("evidence_assets", "evidence_assets", ""),
            ("evidence_records", "evidence", ""),
            ("testing_tools", "testing_tool_definitions", ""),
            ("tool_runs", "testing_tool_runs", ""),
            ("interactions", "interaction_events", ""),
        ):
            rows = self._all(f"SELECT project_id, COUNT(*) AS count FROM {table} {qualifier} GROUP BY project_id")
            for row in rows:
                project_id = str(row["project_id"])
                if project_id in counts:
                    counts[project_id][key] = int(row["count"])
        for prefix, table in (("assessment", "findings"), ("tool", "testing_tool_findings")):
            rows = self._all(
                f"SELECT project_id, COUNT(*) AS count, "
                f"SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) AS open_count "
                f"FROM {table} GROUP BY project_id"
            )
            for row in rows:
                project_id = str(row["project_id"])
                if project_id not in counts:
                    continue
                counts[project_id][f"{prefix}_findings"] = int(row["count"])
                counts[project_id]["open_findings"] += int(row["open_count"] or 0)
                counts[project_id]["findings"] += int(row["count"])
        return counts

    def list_projects(self, *, include_archived: bool = False) -> list[dict[str, Any]]:
        where = "" if include_archived else "WHERE status <> 'archived'"
        rows = self._all(
            f"SELECT * FROM projects {where} "
            "ORDER BY pinned DESC, COALESCE(last_opened_at, updated_at) DESC, updated_at DESC, id"
        )
        items = [dict(row) for row in rows]
        counts = self._bulk_project_counts({str(item["id"]) for item in items})
        return [{**self._project_record(item), "counts": counts[str(item["id"])]} for item in items]

    def get_project(self, project_id: str) -> dict[str, Any]:
        row = self._one("SELECT * FROM projects WHERE id = ?", (project_id,))
        if not row:
            raise NotFoundError("project not found")
        return self.project_summary(dict(row), detailed=True)

    def get_project_for_report(self, project_id: str) -> dict[str, Any]:
        """Return an untruncated project snapshot for professional reports."""
        result = self.get_project(project_id)
        result["runs"] = [
            self._run_dict(row)
            for row in self._all(
                "SELECT * FROM test_runs WHERE project_id = ? ORDER BY started_at DESC, id",
                (project_id,),
            )
        ]
        tool_run_ids = [
            str(row["id"])
            for row in self._all(
                "SELECT id FROM testing_tool_runs WHERE project_id = ? ORDER BY started_at DESC, id",
                (project_id,),
            )
        ]
        result["tool_runs"] = [
            self.get_tool_run(project_id, tool_run_id, include_events=False)
            for tool_run_id in tool_run_ids
        ]
        return result

    def project_summary(self, item: dict[str, Any], detailed: bool = False) -> dict[str, Any]:
        project_id = item["id"]
        counts = {}
        for key, table in (("documents", "project_documents"), ("objectives", "assessment_objectives"), ("targets", "targets"), ("preflights", "target_preflight_runs"), ("imports", "project_imports"), ("artifacts", "project_artifacts"), ("runs", "test_runs"), ("evidence_assets", "evidence_assets"), ("evidence_records", "evidence")):
            qualifier = " AND run_id IS NULL" if table == "project_imports" else " AND status = 'active'" if table == "project_artifacts" else ""
            row = self._one(f"SELECT COUNT(*) AS count FROM {table} WHERE project_id = ?{qualifier}", (project_id,))
            counts[key] = int(row["count"] if row else 0)
        row = self._one("SELECT COUNT(*) AS count FROM findings WHERE project_id = ? AND status = 'open'", (project_id,))
        assessment_open_findings = int(row["count"] if row else 0)
        row = self._one("SELECT COUNT(*) AS count FROM findings WHERE project_id = ?", (project_id,))
        assessment_findings = int(row["count"] if row else 0)
        row = self._one("SELECT COUNT(*) AS count FROM testing_tool_findings WHERE project_id = ? AND status = 'open'", (project_id,))
        tool_open_findings = int(row["count"] if row else 0)
        row = self._one("SELECT COUNT(*) AS count FROM testing_tool_findings WHERE project_id = ?", (project_id,))
        tool_findings = int(row["count"] if row else 0)
        counts["assessment_findings"] = assessment_findings
        counts["tool_findings"] = tool_findings
        counts["open_findings"] = assessment_open_findings + tool_open_findings
        counts["findings"] = assessment_findings + tool_findings
        row = self._one("SELECT COUNT(*) AS count FROM testing_tool_definitions WHERE project_id = ?", (project_id,))
        counts["testing_tools"] = int(row["count"] if row else 0)
        row = self._one("SELECT COUNT(*) AS count FROM testing_tool_runs WHERE project_id = ?", (project_id,))
        counts["tool_runs"] = int(row["count"] if row else 0)
        row = self._one("SELECT COUNT(*) AS count FROM interaction_events WHERE project_id = ?", (project_id,))
        counts["interactions"] = int(row["count"] if row else 0)
        result = {**self._project_record(item), "counts": counts}
        if detailed:
            result["documents"] = [dict(row) for row in self._all("SELECT id,kind,filename,created_at FROM project_documents WHERE project_id = ? ORDER BY created_at DESC", (project_id,))]
            result["objectives"] = [self._objective_dict(row) for row in self._all("SELECT * FROM assessment_objectives WHERE project_id = ? ORDER BY created_at", (project_id,))]
            result["targets"] = [self._target_dict(row) for row in self._all("SELECT * FROM targets WHERE project_id = ? ORDER BY created_at DESC", (project_id,))]
            result["target_preflights"] = self.list_target_preflights(project_id, limit=100)
            result["guardrails"] = [self._guardrail_dict(row) for row in self._all("SELECT * FROM execution_guardrails WHERE project_id = ? ORDER BY created_at", (project_id,))]
            result["imports"] = [self._import_dict(row) for row in self._all("SELECT * FROM project_imports WHERE project_id = ? AND run_id IS NULL ORDER BY created_at DESC", (project_id,))]
            result["artifacts"] = [self._artifact_dict(row) for row in self._all("SELECT * FROM project_artifacts WHERE project_id = ? AND status = 'active' ORDER BY created_at DESC", (project_id,))]
            result["runs"] = [self._run_dict(row) for row in self._all("SELECT * FROM test_runs WHERE project_id = ? ORDER BY started_at DESC LIMIT 20", (project_id,))]
            result["findings"] = [self._finding_dict(row) for row in self._all("SELECT * FROM findings WHERE project_id = ? ORDER BY CASE status WHEN 'open' THEN 0 ELSE 1 END, updated_at DESC", (project_id,))]
            result["tool_findings"] = self.list_tool_findings(project_id)
            result["owasp_coverage"] = self.owasp_coverage(project_id)
            result["audit_events"] = [self._audit_dict(row) for row in self._all("SELECT * FROM audit_events WHERE project_id = ? ORDER BY created_at DESC LIMIT 40", (project_id,))]
            result["testing_tools"] = self.list_tool_definitions(project_id)
            result["tool_runs"] = self.list_tool_runs(project_id, limit=40)
            result["interaction_tokens"] = self.list_interaction_tokens(project_id)
            result["report_review"] = self.get_report_review(project_id)
            result["assessment_reasoning"] = self.reasoning_workspace(project_id)
            result["counts"]["reasoning_records"] = sum(
                int(result["assessment_reasoning"]["summary"].get(key) or 0)
                for key in ("methodology_cards", "nodes", "edges", "hypotheses", "checkpoints")
            )
            from .telemetry import aggregate_project_analysis
            adjudications = [
                self._adjudication_dict(row)
                for row in self._all(
                    "SELECT * FROM validation_adjudications WHERE project_id = ? ORDER BY updated_at, id",
                    (project_id,),
                )
            ]
            result["validation_analysis"] = aggregate_project_analysis(result["runs"], result["tool_runs"], adjudications)
        return result

    @staticmethod
    def _normalize_project_tags(tags: list[Any]) -> list[str]:
        if not isinstance(tags, list):
            raise ValueError("project tags must be a list")
        normalized: list[str] = []
        seen: set[str] = set()
        for raw_tag in tags:
            tag = str(raw_tag).strip()
            if not tag:
                continue
            if len(tag) > 40:
                raise ValueError("project tags must be 40 characters or fewer")
            key = tag.casefold()
            if key not in seen:
                seen.add(key)
                normalized.append(tag)
            if len(normalized) > 12:
                raise ValueError("a project can have at most 12 tags")
        return normalized

    def update_project_organization(
        self,
        project_id: str,
        *,
        folder: str | None = None,
        tags: list[Any] | None = None,
        pinned: bool | None = None,
    ) -> dict[str, Any]:
        project = self.require_project(project_id)
        updates: list[str] = []
        values: list[Any] = []
        metadata: dict[str, Any] = {}
        if folder is not None:
            normalized_folder = str(folder).strip()
            if len(normalized_folder) > 80:
                raise ValueError("project folder must be 80 characters or fewer")
            updates.append("folder = ?")
            values.append(normalized_folder)
            metadata["folder"] = normalized_folder
        if tags is not None:
            normalized_tags = self._normalize_project_tags(tags)
            updates.append("tags_json = ?")
            values.append(json_dumps(normalized_tags))
            metadata["tags"] = ", ".join(normalized_tags)
        if pinned is not None:
            if not isinstance(pinned, bool):
                raise ValueError("pinned must be true or false")
            if pinned and project.get("status") == "archived":
                raise ValueError("restore the project before pinning it")
            updates.append("pinned = ?")
            values.append(int(pinned))
            metadata["pinned"] = pinned
        if updates:
            values.append(project_id)
            self._write(f"UPDATE projects SET {', '.join(updates)} WHERE id = ?", tuple(values))
            self.record_audit(
                project_id,
                action="project.organized",
                object_type="project",
                object_id=project_id,
                metadata=metadata,
            )
        refreshed = self.require_project(project_id)
        return self._project_record(refreshed)

    def mark_project_opened(self, project_id: str) -> dict[str, Any]:
        self.require_project(project_id)
        self._write("UPDATE projects SET last_opened_at = ? WHERE id = ?", (now_iso_precise(), project_id))
        return self._project_record(self.require_project(project_id))

    def archive_project(self, project_id: str) -> dict[str, Any]:
        project = self.require_project(project_id)
        if project.get("status") == "archived":
            return self._project_record(project)
        active: list[str] = []
        for table, label in (
            ("test_runs", "assessment"),
            ("testing_tool_runs", "testing-tool run"),
            ("target_preflight_runs", "connection check"),
        ):
            row = self._one(
                f"SELECT id FROM {table} WHERE project_id = ? AND status = 'running' LIMIT 1",
                (project_id,),
            )
            if row:
                active.append(f"{label} {row['id']}")
        if active:
            raise ValueError("cannot archive while active work is running: " + ", ".join(active))
        timestamp = now_iso_precise()
        self._write(
            "UPDATE projects SET status = 'archived', archived_at = ?, updated_at = ? WHERE id = ?",
            (timestamp, timestamp, project_id),
        )
        self.record_audit(project_id, action="project.archived", object_type="project", object_id=project_id)
        return self._project_record(self.require_project(project_id))

    def restore_project(self, project_id: str) -> dict[str, Any]:
        project = self.require_project(project_id)
        if project.get("status") != "archived":
            return self._project_record(project)
        timestamp = now_iso_precise()
        self._write(
            "UPDATE projects SET status = 'active', archived_at = NULL, updated_at = ? WHERE id = ?",
            (timestamp, project_id),
        )
        self.record_audit(project_id, action="project.restored", object_type="project", object_id=project_id)
        return self._project_record(self.require_project(project_id))

    def get_report_review(self, project_id: str) -> dict[str, Any]:
        project = self._one("SELECT updated_at FROM projects WHERE id = ?", (project_id,))
        if not project:
            raise NotFoundError("project not found")
        row = self._one("SELECT * FROM project_report_reviews WHERE project_id = ?", (project_id,))
        if not row:
            return {
                "project_id": project_id,
                "status": "draft",
                "effective_status": "draft",
                "reviewer": "",
                "notes": "",
                "accepted_project_updated_at": "",
                "current_project_updated_at": str(project["updated_at"]),
                "is_current": False,
                "updated_at": "",
            }
        item = dict(row)
        current = bool(
            item["status"] == "accepted"
            and item["accepted_project_updated_at"]
            and item["accepted_project_updated_at"] == project["updated_at"]
        )
        item.update({
            "effective_status": "accepted" if current else "draft",
            "current_project_updated_at": str(project["updated_at"]),
            "is_current": current,
        })
        return item

    def set_report_review(
        self,
        project_id: str,
        *,
        status: str,
        reviewer: str = "",
        notes: str = "",
    ) -> dict[str, Any]:
        if status not in {"draft", "accepted"}:
            raise ValueError("report review status must be draft or accepted")
        project = self._one("SELECT updated_at FROM projects WHERE id = ?", (project_id,))
        if not project:
            raise NotFoundError("project not found")
        clean_reviewer = redact_text(reviewer, 160).strip()
        if status == "accepted" and not clean_reviewer:
            raise ValueError("reviewer is required before accepting a professional report")
        item = {
            "project_id": project_id,
            "status": status,
            "reviewer": clean_reviewer,
            "notes": redact_text(notes, 4000).strip(),
            "accepted_project_updated_at": str(project["updated_at"]) if status == "accepted" else "",
            "updated_at": now_iso(),
        }
        self._write(
            "INSERT INTO project_report_reviews(project_id,status,reviewer,notes,accepted_project_updated_at,updated_at) "
            "VALUES(?,?,?,?,?,?) ON CONFLICT(project_id) DO UPDATE SET status=excluded.status,reviewer=excluded.reviewer,"
            "notes=excluded.notes,accepted_project_updated_at=excluded.accepted_project_updated_at,updated_at=excluded.updated_at",
            tuple(item.values()),
        )
        self.record_audit(
            project_id,
            action="report.reviewed" if status == "accepted" else "report.review_reset",
            object_type="project_report",
            object_id=project_id,
            outcome=status,
            metadata={"reviewer": clean_reviewer, "accepted_project_updated_at": item["accepted_project_updated_at"]},
        )
        return self.get_report_review(project_id)

    @staticmethod
    def _reasoning_reference_ids(values: list[Any] | None, *, label: str, maximum: int = 50) -> list[str]:
        if values is None:
            return []
        if not isinstance(values, list):
            raise ValueError(f"{label} must be a list")
        result: list[str] = []
        for raw in values:
            value = str(raw or "").strip()
            if not value:
                continue
            if len(value) > 160:
                raise ValueError(f"{label} entries must be 160 characters or fewer")
            if value not in result:
                result.append(value)
        if len(result) > maximum:
            raise ValueError(f"{label} may contain at most {maximum} entries")
        return result

    def _reasoning_target_id(self, project_id: str, target_id: str | None) -> str | None:
        normalized = str(target_id or "").strip() or None
        if normalized:
            self.get_target(project_id, normalized)
        return normalized

    def _reasoning_evidence_refs(self, project_id: str, values: list[Any] | None) -> list[str]:
        references = self._reasoning_reference_ids(values, label="evidence_refs")
        for evidence_id in references:
            if not self._one("SELECT id FROM evidence WHERE id = ? AND project_id = ?", (evidence_id, project_id)):
                raise NotFoundError("evidence record not found in project")
        return references

    @staticmethod
    def _methodology_pin_dict(row: sqlite3.Row | None) -> dict[str, Any]:
        if not row:
            raise NotFoundError("methodology card is not pinned in project")
        item = dict(row)
        try:
            snapshot = json.loads(item.pop("card_snapshot_json") or "{}")
        except json.JSONDecodeError:
            snapshot = {}
        if not isinstance(snapshot, dict):
            snapshot = {}
        trusted = bool(
            str(snapshot.get("id") or "") == str(item["card_id"])
            and methodology_card_is_trusted(snapshot)
        )
        return {
            **snapshot,
            "project_id": item["project_id"],
            "card_id": item["card_id"],
            "notes": item["notes"],
            "pinned_at": item["created_at"],
            "updated_at": item["updated_at"],
            "integrity_status": "verified" if trusted else "untrusted",
            "trusted_for_model": trusted,
        }

    def list_methodology_pins(self, project_id: str) -> list[dict[str, Any]]:
        self.require_project(project_id)
        return [
            self._methodology_pin_dict(row)
            for row in self._all(
                "SELECT * FROM project_methodology_cards WHERE project_id = ? ORDER BY created_at, card_id",
                (project_id,),
            )
        ]

    def get_methodology_pin(self, project_id: str, card_id: str) -> dict[str, Any]:
        return self._methodology_pin_dict(self._one(
            "SELECT * FROM project_methodology_cards WHERE project_id = ? AND card_id = ?",
            (project_id, card_id),
        ))

    def pin_methodology_card(
        self,
        project_id: str,
        card_id: str,
        *,
        notes: str = "",
        refresh: bool = False,
    ) -> dict[str, Any]:
        self.require_project(project_id)
        normalized_id = str(card_id or "").strip()
        try:
            current_card = methodology_card(normalized_id)
        except KeyError as exc:
            raise ValueError("unknown methodology card") from exc
        timestamp = now_iso()
        safe_notes = redact_text(notes, 4000).strip()
        existing = self._one(
            "SELECT * FROM project_methodology_cards WHERE project_id = ? AND card_id = ?",
            (project_id, normalized_id),
        )
        if existing:
            snapshot_json = json_dumps(current_card) if refresh else str(existing["card_snapshot_json"])
            if snapshot_json == str(existing["card_snapshot_json"]) and safe_notes == str(existing["notes"]):
                return self._methodology_pin_dict(existing)
            self._write(
                "UPDATE project_methodology_cards SET card_snapshot_json = ?, notes = ?, updated_at = ? "
                "WHERE project_id = ? AND card_id = ?",
                (snapshot_json, safe_notes, timestamp, project_id, normalized_id),
            )
            action = "methodology_card.refreshed" if refresh else "methodology_card.annotated"
        else:
            self._write(
                "INSERT INTO project_methodology_cards(project_id,card_id,card_snapshot_json,notes,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?)",
                (project_id, normalized_id, json_dumps(current_card), safe_notes, timestamp, timestamp),
            )
            action = "methodology_card.pinned"
        self.record_audit(
            project_id,
            action=action,
            object_type="methodology_card",
            object_id=normalized_id,
            metadata={"version": current_card.get("version", ""), "sha256": current_card.get("sha256", "")},
        )
        self.touch_project(project_id)
        return self.get_methodology_pin(project_id, normalized_id)

    def unpin_methodology_card(self, project_id: str, card_id: str) -> dict[str, Any]:
        item = self.get_methodology_pin(project_id, card_id)
        self._write(
            "DELETE FROM project_methodology_cards WHERE project_id = ? AND card_id = ?",
            (project_id, card_id),
        )
        self.record_audit(
            project_id,
            action="methodology_card.unpinned",
            object_type="methodology_card",
            object_id=card_id,
            outcome="deleted",
            metadata={"version": item.get("version", "")},
        )
        self.touch_project(project_id)
        return {"card_id": card_id, "deleted": True}

    @staticmethod
    def _reasoning_node_dict(row: sqlite3.Row | None) -> dict[str, Any]:
        if not row:
            raise NotFoundError("reasoning node not found in project")
        return dict(row)

    def list_reasoning_nodes(self, project_id: str, *, target_id: str | None = None) -> list[dict[str, Any]]:
        self.require_project(project_id)
        if target_id:
            self.get_target(project_id, target_id)
            rows = self._all(
                "SELECT * FROM reasoning_nodes WHERE project_id = ? AND (target_id IS NULL OR target_id = ?) ORDER BY created_at, id",
                (project_id, target_id),
            )
        else:
            rows = self._all("SELECT * FROM reasoning_nodes WHERE project_id = ? ORDER BY created_at, id", (project_id,))
        return [self._reasoning_node_dict(row) for row in rows]

    def get_reasoning_node(self, project_id: str, node_id: str) -> dict[str, Any]:
        return self._reasoning_node_dict(self._one(
            "SELECT * FROM reasoning_nodes WHERE id = ? AND project_id = ?",
            (node_id, project_id),
        ))

    def create_reasoning_node(
        self,
        project_id: str,
        *,
        kind: str,
        label: str,
        description: str = "",
        confidence: str = "unknown",
        source_ref: str = "",
        target_id: str | None = None,
    ) -> dict[str, Any]:
        self.require_project(project_id)
        normalized_kind = str(kind or "").strip().casefold()
        normalized_confidence = str(confidence or "unknown").strip().casefold()
        if normalized_kind not in {"component", "identity", "credential-reference", "data", "artifact", "consumer", "sink", "route"}:
            raise ValueError("reasoning node kind is not supported")
        if normalized_confidence not in {"confirmed", "likely", "unknown"}:
            raise ValueError("reasoning node confidence must be confirmed, likely, or unknown")
        clean_label = redact_text(label, 180).strip()
        if not clean_label:
            raise ValueError("reasoning node label is required")
        timestamp = now_iso()
        item = {
            "id": new_id("rnode"),
            "project_id": project_id,
            "target_id": self._reasoning_target_id(project_id, target_id),
            "kind": normalized_kind,
            "label": clean_label,
            "description": redact_text(description, 4000).strip(),
            "confidence": normalized_confidence,
            "source_ref": redact_text(source_ref, 1000).strip(),
            "created_at": timestamp,
            "updated_at": timestamp,
        }
        self._write(
            "INSERT INTO reasoning_nodes(id,project_id,target_id,kind,label,description,confidence,source_ref,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            tuple(item.values()),
        )
        self.record_audit(project_id, action="reasoning_node.created", object_type="reasoning_node", object_id=item["id"], metadata={"kind": normalized_kind, "label": clean_label})
        self.touch_project(project_id)
        return self.get_reasoning_node(project_id, item["id"])

    def update_reasoning_node(
        self,
        project_id: str,
        node_id: str,
        *,
        kind: str,
        label: str,
        description: str = "",
        confidence: str = "unknown",
        source_ref: str = "",
        target_id: str | None = None,
    ) -> dict[str, Any]:
        self.get_reasoning_node(project_id, node_id)
        normalized_kind = str(kind or "").strip().casefold()
        normalized_confidence = str(confidence or "unknown").strip().casefold()
        if normalized_kind not in {"component", "identity", "credential-reference", "data", "artifact", "consumer", "sink", "route"}:
            raise ValueError("reasoning node kind is not supported")
        if normalized_confidence not in {"confirmed", "likely", "unknown"}:
            raise ValueError("reasoning node confidence must be confirmed, likely, or unknown")
        clean_label = redact_text(label, 180).strip()
        if not clean_label:
            raise ValueError("reasoning node label is required")
        self._write(
            "UPDATE reasoning_nodes SET target_id=?,kind=?,label=?,description=?,confidence=?,source_ref=?,updated_at=? "
            "WHERE id=? AND project_id=?",
            (
                self._reasoning_target_id(project_id, target_id), normalized_kind, clean_label,
                redact_text(description, 4000).strip(), normalized_confidence,
                redact_text(source_ref, 1000).strip(), now_iso(), node_id, project_id,
            ),
        )
        self.record_audit(project_id, action="reasoning_node.updated", object_type="reasoning_node", object_id=node_id, metadata={"kind": normalized_kind, "label": clean_label})
        self.touch_project(project_id)
        return self.get_reasoning_node(project_id, node_id)

    def delete_reasoning_node(self, project_id: str, node_id: str) -> dict[str, Any]:
        item = self.get_reasoning_node(project_id, node_id)
        edge_count = self._one(
            "SELECT COUNT(*) AS count FROM reasoning_edges WHERE project_id = ? AND (source_node_id = ? OR target_node_id = ?)",
            (project_id, node_id, node_id),
        )
        deleted_edges = int(edge_count["count"] if edge_count else 0)
        self._write("DELETE FROM reasoning_nodes WHERE id = ? AND project_id = ?", (node_id, project_id))
        self.record_audit(project_id, action="reasoning_node.deleted", object_type="reasoning_node", object_id=node_id, outcome="deleted", metadata={"label": item["label"], "cascaded_edges": deleted_edges})
        self.touch_project(project_id)
        return {"id": node_id, "deleted": True, "cascaded_edges": deleted_edges}

    @staticmethod
    def _reasoning_edge_dict(row: sqlite3.Row | None) -> dict[str, Any]:
        if not row:
            raise NotFoundError("reasoning edge not found in project")
        item = dict(row)
        item["evidence_refs"] = json.loads(item.pop("evidence_refs_json") or "[]")
        return item

    def list_reasoning_edges(self, project_id: str) -> list[dict[str, Any]]:
        self.require_project(project_id)
        return [self._reasoning_edge_dict(row) for row in self._all(
            "SELECT * FROM reasoning_edges WHERE project_id = ? ORDER BY created_at, id", (project_id,)
        )]

    def get_reasoning_edge(self, project_id: str, edge_id: str) -> dict[str, Any]:
        return self._reasoning_edge_dict(self._one(
            "SELECT * FROM reasoning_edges WHERE id = ? AND project_id = ?", (edge_id, project_id)
        ))

    def create_reasoning_edge(
        self,
        project_id: str,
        *,
        source_node_id: str,
        target_node_id: str,
        kind: str,
        status: str = "unknown",
        label: str = "",
        description: str = "",
        evidence_refs: list[Any] | None = None,
    ) -> dict[str, Any]:
        self.get_reasoning_node(project_id, source_node_id)
        self.get_reasoning_node(project_id, target_node_id)
        normalized_kind = str(kind or "").strip().casefold()
        normalized_status = str(status or "unknown").strip().casefold()
        if normalized_kind not in {"data-flow", "trust", "authority", "uses-credential", "triggers", "produces", "reaches", "consumes"}:
            raise ValueError("reasoning edge kind is not supported")
        if normalized_status not in {"confirmed", "likely", "unknown", "blocked"}:
            raise ValueError("reasoning edge status must be confirmed, likely, unknown, or blocked")
        timestamp = now_iso()
        item = {
            "id": new_id("redge"), "project_id": project_id,
            "source_node_id": source_node_id, "target_node_id": target_node_id,
            "kind": normalized_kind, "status": normalized_status,
            "label": redact_text(label, 180).strip(),
            "description": redact_text(description, 4000).strip(),
            "evidence_refs_json": json_dumps(self._reasoning_evidence_refs(project_id, evidence_refs)),
            "created_at": timestamp, "updated_at": timestamp,
        }
        self._write(
            "INSERT INTO reasoning_edges(id,project_id,source_node_id,target_node_id,kind,status,label,description,evidence_refs_json,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)", tuple(item.values())
        )
        self.record_audit(project_id, action="reasoning_edge.created", object_type="reasoning_edge", object_id=item["id"], metadata={"kind": normalized_kind, "source": source_node_id, "target": target_node_id})
        self.touch_project(project_id)
        return self.get_reasoning_edge(project_id, item["id"])

    def update_reasoning_edge(
        self,
        project_id: str,
        edge_id: str,
        *,
        source_node_id: str,
        target_node_id: str,
        kind: str,
        status: str = "unknown",
        label: str = "",
        description: str = "",
        evidence_refs: list[Any] | None = None,
    ) -> dict[str, Any]:
        self.get_reasoning_edge(project_id, edge_id)
        self.get_reasoning_node(project_id, source_node_id)
        self.get_reasoning_node(project_id, target_node_id)
        normalized_kind = str(kind or "").strip().casefold()
        normalized_status = str(status or "unknown").strip().casefold()
        if normalized_kind not in {"data-flow", "trust", "authority", "uses-credential", "triggers", "produces", "reaches", "consumes"}:
            raise ValueError("reasoning edge kind is not supported")
        if normalized_status not in {"confirmed", "likely", "unknown", "blocked"}:
            raise ValueError("reasoning edge status must be confirmed, likely, unknown, or blocked")
        self._write(
            "UPDATE reasoning_edges SET source_node_id=?,target_node_id=?,kind=?,status=?,label=?,description=?,evidence_refs_json=?,updated_at=? "
            "WHERE id=? AND project_id=?",
            (
                source_node_id, target_node_id, normalized_kind, normalized_status,
                redact_text(label, 180).strip(), redact_text(description, 4000).strip(),
                json_dumps(self._reasoning_evidence_refs(project_id, evidence_refs)), now_iso(), edge_id, project_id,
            ),
        )
        self.record_audit(project_id, action="reasoning_edge.updated", object_type="reasoning_edge", object_id=edge_id, metadata={"kind": normalized_kind, "source": source_node_id, "target": target_node_id})
        self.touch_project(project_id)
        return self.get_reasoning_edge(project_id, edge_id)

    def delete_reasoning_edge(self, project_id: str, edge_id: str) -> dict[str, Any]:
        item = self.get_reasoning_edge(project_id, edge_id)
        self._write("DELETE FROM reasoning_edges WHERE id = ? AND project_id = ?", (edge_id, project_id))
        self.record_audit(project_id, action="reasoning_edge.deleted", object_type="reasoning_edge", object_id=edge_id, outcome="deleted", metadata={"kind": item["kind"]})
        self.touch_project(project_id)
        return {"id": edge_id, "deleted": True}

    @staticmethod
    def _reasoning_hypothesis_dict(row: sqlite3.Row | None) -> dict[str, Any]:
        if not row:
            raise NotFoundError("reasoning hypothesis not found in project")
        item = dict(row)
        item["evidence_refs"] = json.loads(item.pop("evidence_refs_json") or "[]")
        item["methodology_card_ids"] = json.loads(item.pop("methodology_card_ids_json") or "[]")
        item["advisory_only"] = True
        return item

    def _reasoning_methodology_refs(self, project_id: str, values: list[Any] | None) -> list[str]:
        references = self._reasoning_reference_ids(values, label="methodology_card_ids", maximum=20)
        for card_id in references:
            self.get_methodology_pin(project_id, card_id)
        return references

    def list_reasoning_hypotheses(self, project_id: str, *, target_id: str | None = None) -> list[dict[str, Any]]:
        self.require_project(project_id)
        if target_id:
            self.get_target(project_id, target_id)
            rows = self._all(
                "SELECT * FROM reasoning_hypotheses WHERE project_id = ? AND (target_id IS NULL OR target_id = ?) ORDER BY created_at, id",
                (project_id, target_id),
            )
        else:
            rows = self._all("SELECT * FROM reasoning_hypotheses WHERE project_id = ? ORDER BY created_at, id", (project_id,))
        return [self._reasoning_hypothesis_dict(row) for row in rows]

    def get_reasoning_hypothesis(self, project_id: str, hypothesis_id: str) -> dict[str, Any]:
        return self._reasoning_hypothesis_dict(self._one(
            "SELECT * FROM reasoning_hypotheses WHERE id = ? AND project_id = ?", (hypothesis_id, project_id)
        ))

    def create_reasoning_hypothesis(
        self,
        project_id: str,
        *,
        classification: str,
        decision: str,
        claim: str,
        rationale: str = "",
        missing_prerequisite: str = "",
        cheapest_test: str = "",
        evidence_refs: list[Any] | None = None,
        methodology_card_ids: list[Any] | None = None,
        target_id: str | None = None,
    ) -> dict[str, Any]:
        self.require_project(project_id)
        normalized_classification = str(classification or "").strip().casefold()
        normalized_decision = str(decision or "hold").strip().casefold()
        if normalized_classification not in {"fact", "inference", "hypothesis", "failure"}:
            raise ValueError("classification must be fact, inference, hypothesis, or failure")
        if normalized_decision not in {"go", "hold", "no-go"}:
            raise ValueError("decision must be go, hold, or no-go")
        clean_claim = redact_text(claim, 4000).strip()
        if not clean_claim:
            raise ValueError("hypothesis claim is required")
        timestamp = now_iso()
        item = {
            "id": new_id("rhyp"), "project_id": project_id,
            "target_id": self._reasoning_target_id(project_id, target_id),
            "classification": normalized_classification, "decision": normalized_decision,
            "claim": clean_claim, "rationale": redact_text(rationale, 6000).strip(),
            "missing_prerequisite": redact_text(missing_prerequisite, 3000).strip(),
            "cheapest_test": redact_text(cheapest_test, 3000).strip(),
            "evidence_refs_json": json_dumps(self._reasoning_evidence_refs(project_id, evidence_refs)),
            "methodology_card_ids_json": json_dumps(self._reasoning_methodology_refs(project_id, methodology_card_ids)),
            "created_at": timestamp, "updated_at": timestamp,
        }
        self._write(
            "INSERT INTO reasoning_hypotheses(id,project_id,target_id,classification,decision,claim,rationale,missing_prerequisite,cheapest_test,evidence_refs_json,methodology_card_ids_json,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", tuple(item.values())
        )
        self.record_audit(project_id, action="reasoning_hypothesis.created", object_type="reasoning_hypothesis", object_id=item["id"], metadata={"classification": normalized_classification, "decision": normalized_decision})
        self.touch_project(project_id)
        return self.get_reasoning_hypothesis(project_id, item["id"])

    def update_reasoning_hypothesis(self, project_id: str, hypothesis_id: str, **values: Any) -> dict[str, Any]:
        existing = self.get_reasoning_hypothesis(project_id, hypothesis_id)
        classification = str(values.get("classification", existing["classification"]) or "").strip().casefold()
        decision = str(values.get("decision", existing["decision"]) or "").strip().casefold()
        if classification not in {"fact", "inference", "hypothesis", "failure"}:
            raise ValueError("classification must be fact, inference, hypothesis, or failure")
        if decision not in {"go", "hold", "no-go"}:
            raise ValueError("decision must be go, hold, or no-go")
        claim = redact_text(str(values.get("claim", existing["claim"])), 4000).strip()
        if not claim:
            raise ValueError("hypothesis claim is required")
        target_id = self._reasoning_target_id(project_id, values.get("target_id", existing.get("target_id")))
        evidence_refs = self._reasoning_evidence_refs(project_id, values.get("evidence_refs", existing.get("evidence_refs")))
        methodology_refs = self._reasoning_methodology_refs(project_id, values.get("methodology_card_ids", existing.get("methodology_card_ids")))
        self._write(
            "UPDATE reasoning_hypotheses SET target_id=?,classification=?,decision=?,claim=?,rationale=?,missing_prerequisite=?,cheapest_test=?,evidence_refs_json=?,methodology_card_ids_json=?,updated_at=? WHERE id=? AND project_id=?",
            (
                target_id, classification, decision, claim,
                redact_text(str(values.get("rationale", existing["rationale"])), 6000).strip(),
                redact_text(str(values.get("missing_prerequisite", existing["missing_prerequisite"])), 3000).strip(),
                redact_text(str(values.get("cheapest_test", existing["cheapest_test"])), 3000).strip(),
                json_dumps(evidence_refs), json_dumps(methodology_refs), now_iso(), hypothesis_id, project_id,
            ),
        )
        self.record_audit(project_id, action="reasoning_hypothesis.updated", object_type="reasoning_hypothesis", object_id=hypothesis_id, metadata={"classification": classification, "decision": decision})
        self.touch_project(project_id)
        return self.get_reasoning_hypothesis(project_id, hypothesis_id)

    def delete_reasoning_hypothesis(self, project_id: str, hypothesis_id: str) -> dict[str, Any]:
        item = self.get_reasoning_hypothesis(project_id, hypothesis_id)
        self._write("DELETE FROM reasoning_hypotheses WHERE id = ? AND project_id = ?", (hypothesis_id, project_id))
        self.record_audit(project_id, action="reasoning_hypothesis.deleted", object_type="reasoning_hypothesis", object_id=hypothesis_id, outcome="deleted", metadata={"classification": item["classification"]})
        self.touch_project(project_id)
        return {"id": hypothesis_id, "deleted": True}

    @staticmethod
    def _reasoning_checkpoint_stages(stages: dict[str, Any] | None) -> dict[str, dict[str, str]]:
        if stages is not None and not isinstance(stages, dict):
            raise ValueError("checkpoint stages must be an object")
        allowed_statuses = {"not-observed", "claimed", "observed", "verified", "failed", "not-applicable"}
        result: dict[str, dict[str, str]] = {}
        for key in ("model_proposed", "application_returned", "tool_executed", "backend_changed", "impact_verified"):
            raw = (stages or {}).get(key, "not-observed")
            if isinstance(raw, bool):
                raw = "verified" if raw else "not-observed"
            if isinstance(raw, str):
                status, source_ref, note = raw.strip().casefold(), "", ""
            elif isinstance(raw, dict):
                status = str(raw.get("status") or "not-observed").strip().casefold()
                source_ref = redact_text(str(raw.get("source_ref") or ""), 1000).strip()
                note = redact_text(str(raw.get("note") or ""), 2000).strip()
            else:
                raise ValueError(f"checkpoint stage {key} must be a status string or object")
            if status not in allowed_statuses:
                raise ValueError(f"checkpoint stage {key} has an unsupported status")
            result[key] = {"status": status, "source_ref": source_ref, "note": note}
        return result

    @staticmethod
    def _reasoning_checkpoint_dict(row: sqlite3.Row | None) -> dict[str, Any]:
        if not row:
            raise NotFoundError("evidence checkpoint not found in project")
        item = dict(row)
        item["stages"] = json.loads(item.pop("stages_json") or "{}")
        item.update({"advisory_only": True, "append_only": True, "finding_grade": False})
        return item

    def list_reasoning_checkpoints(self, project_id: str, *, target_id: str | None = None) -> list[dict[str, Any]]:
        self.require_project(project_id)
        if target_id:
            self.get_target(project_id, target_id)
            rows = self._all(
                "SELECT * FROM reasoning_checkpoints WHERE project_id = ? AND (target_id IS NULL OR target_id = ?) ORDER BY created_at, id",
                (project_id, target_id),
            )
        else:
            rows = self._all("SELECT * FROM reasoning_checkpoints WHERE project_id = ? ORDER BY created_at, id", (project_id,))
        return [self._reasoning_checkpoint_dict(row) for row in rows]

    def get_reasoning_checkpoint(self, project_id: str, checkpoint_id: str) -> dict[str, Any]:
        return self._reasoning_checkpoint_dict(self._one(
            "SELECT * FROM reasoning_checkpoints WHERE id = ? AND project_id = ?", (checkpoint_id, project_id)
        ))

    def create_reasoning_checkpoint(
        self,
        project_id: str,
        *,
        title: str,
        starting_identity: str = "",
        prerequisite: str = "",
        action: str = "",
        result: str = "",
        impact: str = "",
        cleanup_status: str = "not-required",
        stages: dict[str, Any] | None = None,
        notes: str = "",
        target_id: str | None = None,
        run_id: str | None = None,
        test_case_id: str | None = None,
        evidence_id: str | None = None,
        correction_of_id: str | None = None,
    ) -> dict[str, Any]:
        self.require_project(project_id)
        clean_title = redact_text(title, 180).strip()
        if not clean_title:
            raise ValueError("evidence checkpoint title is required")
        cleanup = str(cleanup_status or "not-required").strip().casefold()
        if cleanup not in {"not-required", "pending", "completed", "failed"}:
            raise ValueError("cleanup status must be not-required, pending, completed, or failed")
        resolved_target_id = self._reasoning_target_id(project_id, target_id)
        resolved_run_id = str(run_id or "").strip() or None
        resolved_case_id = str(test_case_id or "").strip() or None
        resolved_evidence_id = str(evidence_id or "").strip() or None
        resolved_correction_id = str(correction_of_id or "").strip() or None
        if resolved_run_id:
            run = self.require_run(project_id, resolved_run_id)
            if resolved_target_id and run["target_id"] != resolved_target_id:
                raise ValueError("checkpoint run does not belong to the selected target")
            resolved_target_id = resolved_target_id or str(run["target_id"])
        if resolved_case_id:
            case = self._one("SELECT id,run_id,target_id FROM test_cases WHERE id = ? AND project_id = ?", (resolved_case_id, project_id))
            if not case:
                raise NotFoundError("test case not found in project")
            if resolved_run_id and str(case["run_id"]) != resolved_run_id:
                raise ValueError("checkpoint test case does not belong to the selected run")
            if resolved_target_id and str(case["target_id"]) != resolved_target_id:
                raise ValueError("checkpoint test case does not belong to the selected target")
            resolved_run_id = resolved_run_id or str(case["run_id"])
            resolved_target_id = resolved_target_id or str(case["target_id"])
        if resolved_evidence_id:
            evidence = self._one("SELECT id,run_id,test_case_id FROM evidence WHERE id = ? AND project_id = ?", (resolved_evidence_id, project_id))
            if not evidence:
                raise NotFoundError("evidence record not found in project")
            if resolved_run_id and str(evidence["run_id"]) != resolved_run_id:
                raise ValueError("checkpoint evidence does not belong to the selected run")
            if resolved_case_id and str(evidence["test_case_id"]) != resolved_case_id:
                raise ValueError("checkpoint evidence does not belong to the selected test case")
            resolved_run_id = resolved_run_id or str(evidence["run_id"])
            resolved_case_id = resolved_case_id or str(evidence["test_case_id"])
            case = self._one("SELECT target_id FROM test_cases WHERE id = ? AND project_id = ?", (resolved_case_id, project_id))
            evidence_target_id = str(case["target_id"]) if case else None
            if resolved_target_id and evidence_target_id != resolved_target_id:
                raise ValueError("checkpoint evidence does not belong to the selected target")
            resolved_target_id = resolved_target_id or evidence_target_id
        if resolved_correction_id:
            self.get_reasoning_checkpoint(project_id, resolved_correction_id)
        item = {
            "id": new_id("rcheck"), "project_id": project_id, "target_id": resolved_target_id,
            "run_id": resolved_run_id, "test_case_id": resolved_case_id, "evidence_id": resolved_evidence_id,
            "correction_of_id": resolved_correction_id, "title": clean_title,
            "starting_identity": redact_text(starting_identity, 1000).strip(),
            "prerequisite": redact_text(prerequisite, 3000).strip(),
            "action": redact_text(action, 5000).strip(), "result": redact_text(result, 5000).strip(),
            "impact": redact_text(impact, 5000).strip(), "cleanup_status": cleanup,
            "stages_json": json_dumps(self._reasoning_checkpoint_stages(stages)),
            "notes": redact_text(notes, 4000).strip(), "created_at": now_iso(),
        }
        self._write(
            "INSERT INTO reasoning_checkpoints(id,project_id,target_id,run_id,test_case_id,evidence_id,correction_of_id,title,starting_identity,prerequisite,action,result,impact,cleanup_status,stages_json,notes,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", tuple(item.values())
        )
        self.record_audit(project_id, action="reasoning_checkpoint.recorded", object_type="reasoning_checkpoint", object_id=item["id"], metadata={"title": clean_title, "run_id": resolved_run_id or "", "correction_of": resolved_correction_id or ""})
        self.touch_project(project_id)
        return self.get_reasoning_checkpoint(project_id, item["id"])

    def reasoning_workspace(self, project_id: str, *, target_id: str | None = None) -> dict[str, Any]:
        self.require_project(project_id)
        cards = self.list_methodology_pins(project_id)
        nodes = self.list_reasoning_nodes(project_id, target_id=target_id)
        node_ids = {item["id"] for item in nodes}
        edges = [
            item for item in self.list_reasoning_edges(project_id)
            if item["source_node_id"] in node_ids and item["target_node_id"] in node_ids
        ]
        hypotheses = self.list_reasoning_hypotheses(project_id, target_id=target_id)
        checkpoints = self.list_reasoning_checkpoints(project_id, target_id=target_id)
        summary = {
            "methodology_cards": len(cards), "nodes": len(nodes), "edges": len(edges),
            "hypotheses": len(hypotheses), "checkpoints": len(checkpoints),
            "facts": sum(item["classification"] == "fact" for item in hypotheses),
            "inferences": sum(item["classification"] == "inference" for item in hypotheses),
            "failures": sum(item["classification"] == "failure" for item in hypotheses),
            "holds": sum(item["decision"] == "hold" for item in hypotheses),
            "no_go": sum(item["decision"] == "no-go" for item in hypotheses),
        }
        return {
            "schema_version": ASSESSMENT_REASONING_SCHEMA_VERSION,
            "advisory_only": True,
            "authority_notice": "Assessment reasoning cannot add scope, routes, identities, permissions, evidence, findings, or verdicts.",
            "target_id": target_id,
            "summary": summary,
            "methodology_cards": cards,
            "nodes": nodes,
            "edges": edges,
            "hypotheses": hypotheses,
            "checkpoints": checkpoints,
        }

    def reasoning_snapshot(self, project_id: str, *, target_id: str | None = None) -> dict[str, Any]:
        snapshot = self.reasoning_workspace(project_id, target_id=target_id)
        canonical = json.dumps(snapshot, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        snapshot["snapshot_sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        snapshot["captured_at"] = now_iso()
        return snapshot

    def list_run_ids(self, project_id: str) -> list[str]:
        self.require_project(project_id)
        return [str(row["id"]) for row in self._all(
            "SELECT id FROM test_runs WHERE project_id = ? ORDER BY started_at, id",
            (project_id,),
        )]

    def list_tool_run_ids(self, project_id: str, *, assessment_run_id: str | None = None) -> list[str]:
        self.require_project(project_id)
        if assessment_run_id:
            self.require_run(project_id, assessment_run_id)
            rows = self._all(
                "SELECT id FROM testing_tool_runs WHERE project_id = ? AND assessment_run_id = ? ORDER BY started_at, id",
                (project_id, assessment_run_id),
            )
        else:
            rows = self._all(
                "SELECT id FROM testing_tool_runs WHERE project_id = ? ORDER BY started_at, id",
                (project_id,),
            )
        return [str(row["id"]) for row in rows]

    def list_evidence_assets(self, project_id: str, *, run_id: str | None = None) -> list[dict[str, Any]]:
        self.require_project(project_id)
        if run_id:
            self.require_run(project_id, run_id)
            rows = self._all(
                "SELECT * FROM evidence_assets WHERE project_id = ? AND run_id = ? ORDER BY created_at, id",
                (project_id, run_id),
            )
        else:
            rows = self._all(
                "SELECT * FROM evidence_assets WHERE project_id = ? ORDER BY created_at, id",
                (project_id,),
            )
        return [dict(row) for row in rows]

    def add_document(self, project_id: str, *, kind: str, filename: str, content: str) -> dict[str, Any]:
        self.require_project(project_id)
        if kind not in {"scope", "policy"}:
            raise ValueError("document kind must be scope or policy")
        if not content.strip():
            raise ValueError("document content is required")
        item = {"id": new_id("doc"), "project_id": project_id, "kind": kind, "filename": filename.strip()[:180] or f"{kind}.txt", "content": redact_text(content, 500000), "created_at": now_iso()}
        self._write("INSERT INTO project_documents(id,project_id,kind,filename,content,created_at) VALUES(?,?,?,?,?,?)", tuple(item.values()))
        self.record_audit(project_id, action="document.imported", object_type=kind, object_id=item["id"], metadata={"filename": item["filename"]})
        self.touch_project(project_id)
        return {k: item[k] for k in ("id", "project_id", "kind", "filename", "created_at")}

    def list_documents(self, project_id: str) -> list[dict[str, Any]]:
        self.require_project(project_id)
        return [dict(row) for row in self._all("SELECT * FROM project_documents WHERE project_id = ? ORDER BY created_at DESC", (project_id,))]

    def get_document(self, project_id: str, document_id: str) -> dict[str, Any]:
        row = self._one("SELECT * FROM project_documents WHERE id = ? AND project_id = ?", (document_id, project_id))
        if not row:
            raise NotFoundError("document not found in project")
        return dict(row)

    def update_document(self, project_id: str, document_id: str, *, kind: str, filename: str, content: str) -> dict[str, Any]:
        current = self.get_document(project_id, document_id)
        if kind not in {"scope", "policy"}:
            raise ValueError("document kind must be scope or policy")
        if not content.strip():
            raise ValueError("document content is required")
        safe_filename = filename.strip()[:180] or f"{kind}.txt"
        self._write(
            "UPDATE project_documents SET kind = ?, filename = ?, content = ? WHERE id = ? AND project_id = ?",
            (kind, safe_filename, redact_text(content, 500000), document_id, project_id),
        )
        self.record_audit(
            project_id,
            action="document.updated",
            object_type=kind,
            object_id=document_id,
            metadata={"filename": safe_filename, "previous_kind": current["kind"]},
        )
        self.touch_project(project_id)
        return self.get_document(project_id, document_id)

    def delete_document(self, project_id: str, document_id: str) -> dict[str, Any]:
        document = self.get_document(project_id, document_id)
        self._write("DELETE FROM project_documents WHERE id = ? AND project_id = ?", (document_id, project_id))
        self.record_audit(
            project_id,
            action="document.deleted",
            object_type=document["kind"],
            object_id=document_id,
            outcome="deleted",
            metadata={"filename": document["filename"]},
        )
        self.touch_project(project_id)
        return {"id": document_id, "deleted": True}

    @staticmethod
    def _objective_dict(row: sqlite3.Row | None) -> dict[str, Any]:
        if not row:
            raise NotFoundError("assessment objective not found in project")
        item = dict(row)
        item["risk_ids"] = json.loads(item.pop("risk_ids_json") or "[]")
        item["technique_ids"] = json.loads(item.pop("technique_ids_json") or "[]")
        item["proof_rule_ids"] = json.loads(item.pop("proof_rule_ids_json", "[]") or "[]")
        item["require_reproduction"] = bool(item.get("require_reproduction"))
        return item

    @staticmethod
    def _objective_proof_contract(proof_mode: str, proof_rule_ids: list[str] | None, require_reproduction: bool) -> tuple[str, list[str], int]:
        mode = str(proof_mode or "model-review").strip().casefold()
        if mode not in {"model-review", "any", "all"}:
            raise ValueError("objective proof mode must be model-review, any, or all")
        if proof_rule_ids in (None, []):
            rule_ids: list[str] = []
        elif not isinstance(proof_rule_ids, list):
            raise ValueError("objective proof rule ids must be a list")
        else:
            rule_ids = []
            for value in proof_rule_ids:
                rule_id = str(value or "").strip()
                if not rule_id:
                    continue
                if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", rule_id):
                    raise ValueError("objective proof rule ids may contain only letters, numbers, underscores, and hyphens")
                if rule_id not in rule_ids:
                    rule_ids.append(rule_id)
            if len(rule_ids) > 50:
                raise ValueError("an objective may reference at most 50 proof rules")
        if mode in {"any", "all"} and not rule_ids:
            raise ValueError("deterministic objective proof needs at least one target proof rule")
        if mode == "model-review" and rule_ids:
            raise ValueError("model-review objectives cannot reference deterministic proof rules")
        return mode, rule_ids, 1 if require_reproduction else 0

    def add_objective(self, project_id: str, *, title: str, description: str, success_criteria: str, risk_ids: list[str], technique_ids: list[str], expected_safe_behavior: str = "", false_positive_exclusions: str = "", proof_mode: str = "model-review", proof_rule_ids: list[str] | None = None, require_reproduction: bool = False) -> dict[str, Any]:
        self.require_project(project_id)
        title = title.strip()
        success_criteria = success_criteria.strip()
        if not title:
            raise ValueError("objective title is required")
        if not success_criteria:
            raise ValueError("objective success criteria are required")
        risks, techniques = validate_mapping(risk_ids, technique_ids)
        normalized_proof_mode, normalized_proof_rules, reproduction_required = self._objective_proof_contract(proof_mode, proof_rule_ids, require_reproduction)
        timestamp = now_iso()
        item = {
            "id": new_id("obj"), "project_id": project_id, "title": title[:180],
            "description": redact_text(description, 4000), "success_criteria": redact_text(success_criteria, 4000),
            "expected_safe_behavior": redact_text(expected_safe_behavior, 4000),
            "false_positive_exclusions": redact_text(false_positive_exclusions, 4000),
            "proof_mode": normalized_proof_mode,
            "proof_rule_ids_json": json_dumps(normalized_proof_rules),
            "require_reproduction": reproduction_required,
            "risk_ids_json": json_dumps(risks), "technique_ids_json": json_dumps(techniques),
            "created_at": timestamp, "updated_at": timestamp,
        }
        self._write("INSERT INTO assessment_objectives(id,project_id,title,description,success_criteria,expected_safe_behavior,false_positive_exclusions,proof_mode,proof_rule_ids_json,require_reproduction,risk_ids_json,technique_ids_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", tuple(item.values()))
        self.record_audit(project_id, action="objective.created", object_type="assessment_objective", object_id=item["id"], metadata={"title": item["title"], "risks": ",".join(risks)})
        self.touch_project(project_id)
        return self.get_objective(project_id, item["id"])

    def update_objective(self, project_id: str, objective_id: str, *, title: str, description: str, success_criteria: str, risk_ids: list[str], technique_ids: list[str], expected_safe_behavior: str = "", false_positive_exclusions: str = "", proof_mode: str = "model-review", proof_rule_ids: list[str] | None = None, require_reproduction: bool = False) -> dict[str, Any]:
        self.get_objective(project_id, objective_id)
        title = title.strip()
        success_criteria = success_criteria.strip()
        if not title or not success_criteria:
            raise ValueError("objective title and success criteria are required")
        risks, techniques = validate_mapping(risk_ids, technique_ids)
        normalized_proof_mode, normalized_proof_rules, reproduction_required = self._objective_proof_contract(proof_mode, proof_rule_ids, require_reproduction)
        self._write("UPDATE assessment_objectives SET title = ?, description = ?, success_criteria = ?, expected_safe_behavior = ?, false_positive_exclusions = ?, proof_mode = ?, proof_rule_ids_json = ?, require_reproduction = ?, risk_ids_json = ?, technique_ids_json = ?, updated_at = ? WHERE id = ? AND project_id = ?", (title[:180], redact_text(description, 4000), redact_text(success_criteria, 4000), redact_text(expected_safe_behavior, 4000), redact_text(false_positive_exclusions, 4000), normalized_proof_mode, json_dumps(normalized_proof_rules), reproduction_required, json_dumps(risks), json_dumps(techniques), now_iso(), objective_id, project_id))
        self.record_audit(project_id, action="objective.updated", object_type="assessment_objective", object_id=objective_id, metadata={"title": title[:180], "risks": ",".join(risks)})
        self.touch_project(project_id)
        return self.get_objective(project_id, objective_id)

    def get_objective(self, project_id: str, objective_id: str) -> dict[str, Any]:
        return self._objective_dict(self._one("SELECT * FROM assessment_objectives WHERE id = ? AND project_id = ?", (objective_id, project_id)))

    def get_objectives(self, project_id: str, objective_ids: list[str]) -> list[dict[str, Any]]:
        return [self.get_objective(project_id, objective_id) for objective_id in dict.fromkeys(objective_ids)]

    def delete_objective(self, project_id: str, objective_id: str) -> dict[str, Any]:
        item = self.get_objective(project_id, objective_id)
        self._write("DELETE FROM assessment_objectives WHERE id = ? AND project_id = ?", (objective_id, project_id))
        self.record_audit(project_id, action="objective.deleted", object_type="assessment_objective", object_id=objective_id, outcome="deleted", metadata={"title": item["title"]})
        self.touch_project(project_id)
        return {"id": objective_id, "deleted": True}

    def add_target(self, project_id: str, *, name: str, kind: str = "chatbot", base_url: str = "", path: str = "", method: str = "", headers: dict[str, Any] | None = None, request_template: dict[str, Any] | None = None, response_path: str = "", description: str = "", browser_profile: dict[str, Any] | None = None, capabilities: dict[str, Any] | None = None, analysis_config: dict[str, Any] | None = None, conversation_config: dict[str, Any] | None = None, transport_config: dict[str, Any] | None = None, evaluation_config: dict[str, Any] | None = None, technique_adapters: dict[str, Any] | None = None, assessment_contracts: list[dict[str, Any]] | None = None, authorized_routes: list[dict[str, Any]] | None = None, scope_confirmed: bool = False) -> dict[str, Any]:
        self.require_project(project_id)
        if not name.strip():
            raise ValueError("target name is required")
        if kind not in {"chatbot", "browser-chatbot", "api"}:
            raise ValueError("target kind must be chatbot, browser-chatbot, or api")
        if kind in {"chatbot", "browser-chatbot"} and not base_url.strip():
            raise ValueError("chatbot base URL is required")
        if base_url.strip():
            parsed_base = urlsplit(base_url.strip())
            if parsed_base.scheme not in {"http", "https"} or not parsed_base.hostname:
                raise ValueError("target base URL must be an absolute HTTP or HTTPS origin")
            if parsed_base.username or parsed_base.password:
                raise ValueError("target base URL must not contain credentials")
            if parsed_base.path not in {"", "/"} or parsed_base.query or parsed_base.fragment:
                raise ValueError("target base URL must contain only the origin; put the complete route in Primary path")
        if scope_confirmed and not path.strip():
            raise ValueError("authorized targets require an explicit path; use / for the origin root")
        if scope_confirmed and not method.strip():
            raise ValueError("authorized targets require an explicit HTTP method")
        if kind == "browser-chatbot" and not browser_profile:
            raise ValueError("browser target selectors are required")
        headers = headers or {}
        request_template = request_template or {}
        if scope_confirmed and kind == "chatbot" and "{{prompt}}" not in json_dumps(request_template):
            raise ValueError("authorized chatbot targets require an explicit request template containing {{prompt}}")
        normalized_capabilities = {str(k): bool(v) for k, v in (capabilities or {}).items()}
        if (conversation_config or {}).get("enabled"):
            normalized_capabilities.update({"multi_turn": True, "structured_history": True})
        normalized_transport = normalize_transport_profile(transport_config)
        item = {"id": new_id("tgt"), "project_id": project_id, "name": name.strip()[:160], "kind": kind.strip()[:60] or "chatbot", "base_url": base_url.strip().rstrip("/"), "path": path.strip(), "method": method.upper()[:10], "headers_json": json_dumps(headers), "request_template_json": json_dumps(request_template), "response_path": response_path.strip()[:180], "description": description.strip()[:500], "browser_profile_json": json_dumps(browser_profile or {}), "capabilities_json": json_dumps(normalized_capabilities), "analysis_config_json": json_dumps(analysis_config or {}), "conversation_config_json": json_dumps(conversation_config or {}), "transport_config_json": json_dumps(normalized_transport), "evaluation_config_json": json_dumps(evaluation_config or {}), "technique_adapters_json": json_dumps(technique_adapters or {}), "assessment_contracts_json": json_dumps(assessment_contracts or []), "authorized_routes_json": json_dumps(authorized_routes or []), "scope_confirmed": 1 if scope_confirmed else 0, "created_at": now_iso()}
        self._write("INSERT INTO targets(id,project_id,name,kind,base_url,path,method,headers_json,request_template_json,response_path,description,browser_profile_json,capabilities_json,analysis_config_json,conversation_config_json,transport_config_json,evaluation_config_json,technique_adapters_json,assessment_contracts_json,authorized_routes_json,scope_confirmed,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", tuple(item.values()))
        self.save_guardrail(project_id, item["id"], status="draft", notes="Conservative draft created with the target. Explicit operator review and approval are required before execution.")
        self.record_audit(project_id, action="target.created", object_type="target", object_id=item["id"], metadata={"name": item["name"], "kind": item["kind"], "scope_confirmed": bool(item["scope_confirmed"])})
        self.touch_project(project_id)
        return self._target_dict(self._one("SELECT * FROM targets WHERE id = ? AND project_id = ?", (item["id"], project_id)))

    def delete_target(self, project_id: str, target_id: str) -> dict[str, Any]:
        """Remove an unused target while preserving every historical execution."""
        target = self.get_target(project_id, target_id)
        references = {
            "assessment runs": "test_runs",
            "testing-tool definitions": "testing_tool_definitions",
            "testing-tool runs": "testing_tool_runs",
            "stored artifacts": "project_artifacts",
            "assessment-reasoning nodes": "reasoning_nodes",
            "assessment-reasoning hypotheses": "reasoning_hypotheses",
            "assessment-reasoning checkpoints": "reasoning_checkpoints",
        }
        used_by = []
        for label, table in references.items():
            row = self._one(f"SELECT COUNT(*) AS count FROM {table} WHERE project_id = ? AND target_id = ?", (project_id, target_id))
            if row and int(row["count"]):
                used_by.append(label)
        if used_by:
            raise ValueError("target cannot be deleted because it is referenced by " + ", ".join(used_by) + "; historical evidence must remain reproducible")
        self._write("DELETE FROM targets WHERE id = ? AND project_id = ?", (target_id, project_id))
        self.record_audit(project_id, action="target.deleted", object_type="target", object_id=target_id, outcome="deleted", metadata={"name": target["name"], "kind": target["kind"]})
        self.touch_project(project_id)
        return {"id": target_id, "deleted": True}

    def get_target(self, project_id: str, target_id: str) -> dict[str, Any]:
        self.require_project(project_id)
        row = self._one("SELECT * FROM targets WHERE id = ? AND project_id = ?", (target_id, project_id))
        if not row:
            raise NotFoundError("target not found in project")
        return self._target_dict(row)

    def create_target_preflight(
        self,
        project_id: str,
        target_id: str,
        *,
        target_snapshot: dict[str, Any],
        guardrail_snapshot: dict[str, Any],
        configuration_sha256: str,
    ) -> dict[str, Any]:
        self.get_target(project_id, target_id)
        item = {
            "id": new_id("pfl"),
            "project_id": project_id,
            "target_id": target_id,
            "status": "running",
            "request_count": 0,
            "configuration_sha256": str(configuration_sha256 or "")[:128],
            "target_snapshot_json": json_dumps(target_snapshot),
            "guardrail_snapshot_json": json_dumps(guardrail_snapshot),
            "result_json": "{}",
            "error": "",
            "started_at": now_iso_precise(),
            "completed_at": None,
        }
        self._write(
            "INSERT INTO target_preflight_runs(id,project_id,target_id,status,request_count,configuration_sha256,target_snapshot_json,guardrail_snapshot_json,result_json,error,started_at,completed_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            tuple(item.values()),
        )
        self.record_audit(
            project_id,
            action="target.preflight.started",
            object_type="target_preflight",
            object_id=item["id"],
            metadata={"target_id": target_id, "configuration_sha256": item["configuration_sha256"]},
        )
        return self.get_target_preflight(project_id, item["id"])

    def complete_target_preflight(self, project_id: str, preflight_id: str, result: dict[str, Any]) -> dict[str, Any]:
        item = self.get_target_preflight(project_id, preflight_id)
        status = str(result.get("status") or "failed")
        if status not in {"ready", "needs-attention", "failed", "blocked"}:
            raise ValueError("target preflight returned an unsupported status")
        request_count = max(0, int(result.get("request_count") or 0))
        error = str(result.get("error") or "")[:1000]
        self._write(
            "UPDATE target_preflight_runs SET status = ?, request_count = ?, configuration_sha256 = ?, result_json = ?, error = ?, completed_at = ? WHERE id = ? AND project_id = ?",
            (
                status,
                request_count,
                str(result.get("configuration_sha256") or item.get("configuration_sha256") or "")[:128],
                json_dumps(result),
                error,
                now_iso_precise(),
                preflight_id,
                project_id,
            ),
        )
        self.record_audit(
            project_id,
            action="target.preflight.completed",
            object_type="target_preflight",
            object_id=preflight_id,
            outcome=status,
            metadata={"target_id": item["target_id"], "request_count": request_count},
        )
        self.touch_project(project_id)
        return self.get_target_preflight(project_id, preflight_id)

    def get_target_preflight(self, project_id: str, preflight_id: str) -> dict[str, Any]:
        self.require_project(project_id)
        row = self._one(
            "SELECT * FROM target_preflight_runs WHERE id = ? AND project_id = ?",
            (preflight_id, project_id),
        )
        if not row:
            raise NotFoundError("target preflight not found in project")
        return self._target_preflight_dict(row)

    def list_target_preflights(
        self,
        project_id: str,
        *,
        target_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        self.require_project(project_id)
        bounded_limit = max(1, min(500, int(limit)))
        if target_id:
            self.get_target(project_id, target_id)
            rows = self._all(
                "SELECT * FROM target_preflight_runs WHERE project_id = ? AND target_id = ? ORDER BY started_at DESC LIMIT ?",
                (project_id, target_id, bounded_limit),
            )
        else:
            rows = self._all(
                "SELECT * FROM target_preflight_runs WHERE project_id = ? ORDER BY started_at DESC LIMIT ?",
                (project_id, bounded_limit),
            )
        return [self._target_preflight_dict(row) for row in rows]

    @staticmethod
    def _target_preflight_dict(row: sqlite3.Row | None) -> dict[str, Any]:
        if not row:
            raise NotFoundError("target preflight not found")
        item = dict(row)
        item["target_snapshot"] = json.loads(item.pop("target_snapshot_json") or "{}")
        item["guardrail_snapshot"] = json.loads(item.pop("guardrail_snapshot_json") or "{}")
        item["result"] = json.loads(item.pop("result_json") or "{}")
        return item

    def update_target_browser_profile(self, project_id: str, target_id: str, browser_profile: dict[str, Any]) -> dict[str, Any]:
        target = self.get_target(project_id, target_id)
        if target["kind"] != "browser-chatbot":
            raise ValueError("browser profile updates require a browser chatbot target")
        self._write(
            "UPDATE targets SET browser_profile_json = ? WHERE id = ? AND project_id = ?",
            (json_dumps(browser_profile), target_id, project_id),
        )
        self.record_audit(
            project_id,
            action="target.browser_profile.updated",
            object_type="target",
            object_id=target_id,
            metadata={
                "navigation_transport": str(browser_profile.get("navigation_transport") or "auto"),
                "persistent_session": bool(browser_profile.get("persistent_session", True)),
            },
        )
        self.touch_project(project_id)
        return self.get_target(project_id, target_id)

    def update_target_origin(self, project_id: str, target_id: str, base_url: str) -> dict[str, Any]:
        target = self.get_target(project_id, target_id)
        normalized = str(base_url or "").strip().rstrip("/")
        parsed = urlsplit(normalized)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("target base URL must be an absolute HTTP or HTTPS origin")
        if parsed.username or parsed.password:
            raise ValueError("target base URL must not contain credentials")
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise ValueError("target base URL must contain only the origin; the saved Primary path remains unchanged")
        previous_origin = str(target.get("base_url") or "")
        self._write(
            "UPDATE targets SET base_url = ? WHERE id = ? AND project_id = ?",
            (normalized, target_id, project_id),
        )
        self.record_audit(
            project_id,
            action="target.origin.updated",
            object_type="target",
            object_id=target_id,
            metadata={
                "previous_origin": previous_origin,
                "new_origin": normalized,
                "historical_run_snapshots_unchanged": True,
            },
        )
        self.touch_project(project_id)
        return self.get_target(project_id, target_id)

    def _target_dict(self, row: sqlite3.Row | None) -> dict[str, Any]:
        if not row:
            raise NotFoundError("target not found")
        item = dict(row)
        item["headers"] = json.loads(item.pop("headers_json") or "{}")
        item["request_template"] = json.loads(item.pop("request_template_json") or "{}")
        item["browser_profile"] = json.loads(item.pop("browser_profile_json", "{}") or "{}")
        item["capabilities"] = json.loads(item.pop("capabilities_json", "{}") or "{}")
        item["analysis_config"] = json.loads(item.pop("analysis_config_json", "{}") or "{}")
        item["conversation_config"] = json.loads(item.pop("conversation_config_json", "{}") or "{}")
        item["transport_config"] = normalize_transport_profile(json.loads(item.pop("transport_config_json", "{}") or "{}"))
        required_analysis_fields = {"tokenizer_path", "tokenizer_method", "context_info_path", "context_info_method", "context_padding_field", "history_field", "tokenizer_text_field", "max_context_padding_chars"}
        if item["analysis_config"].get("enabled") and not required_analysis_fields.issubset(item["analysis_config"]):
            # Older targets did not record HTTP methods. Never guess them: retain the
            # historical values, disable execution, and require an explicit remap.
            item["analysis_config"]["enabled"] = False
            item["analysis_config"]["needs_reconfiguration"] = True
        item["evaluation_config"] = json.loads(item.pop("evaluation_config_json", "{}") or "{}")
        agency_profile = item["evaluation_config"].get("agency") or {}
        if agency_profile.get("enabled"):
            agency_needs_reconfiguration = False
            for case in agency_profile.get("cases") or []:
                if case.get("impact") not in {"read-only", "reversible-change"}:
                    agency_needs_reconfiguration = True
                if case.get("evidence_source") == "verifier" and not {
                    "verification_path", "verification_method", "verification_status", "verification_body"
                }.issubset(case):
                    agency_needs_reconfiguration = True
                if case.get("impact") == "reversible-change" and not {
                    "cleanup_path", "cleanup_method", "cleanup_status", "cleanup_body"
                }.issubset(case):
                    agency_needs_reconfiguration = True
            if agency_needs_reconfiguration:
                # Historical evaluator profiles omitted methods, expected statuses,
                # impact class, and cleanup. Retain them for operator editing but
                # never execute them by guessing the missing target behavior.
                agency_profile["enabled"] = False
                agency_profile["needs_reconfiguration"] = True
                item["evaluation_config"]["agency"] = agency_profile
        item["technique_adapters"] = json.loads(item.pop("technique_adapters_json", "{}") or "{}")
        item["assessment_contracts"] = json.loads(item.pop("assessment_contracts_json", "[]") or "[]")
        item["authorized_routes"] = json.loads(item.pop("authorized_routes_json", "[]") or "[]")
        item["scope_confirmed"] = bool(item.get("scope_confirmed"))
        return item

    def update_target_authorized_routes(self, project_id: str, target_id: str, authorized_routes: list[dict[str, Any]]) -> dict[str, Any]:
        self.get_target(project_id, target_id)
        self._write("UPDATE targets SET authorized_routes_json = ? WHERE id = ? AND project_id = ?", (json_dumps(authorized_routes), target_id, project_id))
        self.record_audit(project_id, action="target.authorized_routes.updated", object_type="target", object_id=target_id, metadata={"route_count": len(authorized_routes)})
        self.touch_project(project_id)
        return self.get_target(project_id, target_id)

    def update_target_capabilities(self, project_id: str, target_id: str, capabilities: dict[str, Any]) -> dict[str, Any]:
        target = self.get_target(project_id, target_id)
        allowed = {
            "external_content", "rag", "retrieval_only", "chat_prompt_adapter", "file_uploads",
            "tools", "mcp", "agents", "memory", "transcript_replay", "multimodal",
            "multi_turn", "multi_identity", "high_impact_domain", "artifact_inventory",
            "training_pipeline", "model_evaluation", "resource_telemetry",
        }
        normalized = {key: bool(value) for key, value in capabilities.items() if key in allowed}
        if (target.get("conversation_config") or {}).get("enabled"):
            normalized.update({"multi_turn": True, "structured_history": True})
        self._write("UPDATE targets SET capabilities_json = ? WHERE id = ? AND project_id = ?", (json_dumps(normalized), target_id, project_id))
        self.record_audit(project_id, action="target.capabilities.updated", object_type="target", object_id=target_id, metadata={"enabled": ",".join(key for key, value in normalized.items() if value)})
        self.touch_project(project_id)
        return self.get_target(project_id, target_id)

    def update_target_analysis_config(self, project_id: str, target_id: str, analysis_config: dict[str, Any]) -> dict[str, Any]:
        self.get_target(project_id, target_id)
        self._write("UPDATE targets SET analysis_config_json = ? WHERE id = ? AND project_id = ?", (json_dumps(analysis_config), target_id, project_id))
        self.record_audit(project_id, action="target.token_context_adapter.updated", object_type="target", object_id=target_id, metadata={"enabled": bool(analysis_config.get("enabled")), "tokenizer_path": analysis_config.get("tokenizer_path", ""), "context_info_path": analysis_config.get("context_info_path", "")})
        self.touch_project(project_id)
        return self.get_target(project_id, target_id)

    def update_target_transport_config(self, project_id: str, target_id: str, transport_config: dict[str, Any]) -> dict[str, Any]:
        self.get_target(project_id, target_id)
        normalized = normalize_transport_profile(transport_config)
        self._write("UPDATE targets SET transport_config_json = ? WHERE id = ? AND project_id = ?", (json_dumps(normalized), target_id, project_id))
        self.record_audit(
            project_id,
            action="target.transport_reliability.updated",
            object_type="target",
            object_id=target_id,
            metadata={
                "enabled": normalized["enabled"],
                "max_retries": normalized["max_retries"],
                "min_request_interval_ms": normalized["min_request_interval_ms"],
                "require_sse_done": normalized["require_sse_done"],
            },
        )
        self.touch_project(project_id)
        return self.get_target(project_id, target_id)

    def update_target_conversation_config(self, project_id: str, target_id: str, conversation_config: dict[str, Any]) -> dict[str, Any]:
        target = self.get_target(project_id, target_id)
        capabilities = dict(target.get("capabilities") or {})
        if conversation_config.get("enabled"):
            capabilities.update({"multi_turn": True, "structured_history": True})
        else:
            capabilities.pop("structured_history", None)
        self._write(
            "UPDATE targets SET conversation_config_json = ?, capabilities_json = ? WHERE id = ? AND project_id = ?",
            (json_dumps(conversation_config), json_dumps(capabilities), target_id, project_id),
        )
        self.record_audit(
            project_id,
            action="target.conversation_adapter.updated",
            object_type="target",
            object_id=target_id,
            metadata={
                "enabled": bool(conversation_config.get("enabled")),
                "transport": conversation_config.get("transport", ""),
                "history_field": conversation_config.get("history_field", ""),
                "max_history_turns": conversation_config.get("max_history_turns", 0),
            },
        )
        self.touch_project(project_id)
        return self.get_target(project_id, target_id)

    def update_target_evaluation_config(self, project_id: str, target_id: str, evaluation_config: dict[str, Any]) -> dict[str, Any]:
        self.get_target(project_id, target_id)
        self._write("UPDATE targets SET evaluation_config_json = ? WHERE id = ? AND project_id = ?", (json_dumps(evaluation_config), target_id, project_id))
        self.record_audit(project_id, action="target.behavioral_evaluators.updated", object_type="target", object_id=target_id, metadata={"canary_rules": len(evaluation_config.get("canaries") or []), "agency_cases": len((evaluation_config.get("agency") or {}).get("cases") or []), "autonomous_interface_rules": len((evaluation_config.get("autonomous_interface") or {}).get("interfaces") or []), "autonomous_effect_constraints": len((evaluation_config.get("autonomous_interface") or {}).get("effect_constraints") or []), "tool_agent_cases": len((evaluation_config.get("tool_agent") or {}).get("cases") or []), "mcp_cases": len((evaluation_config.get("mcp") or {}).get("cases") or []), "rag_cases": len((evaluation_config.get("rag") or {}).get("cases") or []), "stored_web_cases": len((evaluation_config.get("stored_web") or {}).get("cases") or []), "artifact_cases": len((evaluation_config.get("artifact") or {}).get("cases") or []), "misinformation_cases": len((evaluation_config.get("misinformation") or {}).get("cases") or [])})
        self.touch_project(project_id)
        return self.get_target(project_id, target_id)

    def update_target_technique_adapter(self, project_id: str, target_id: str, pack_id: str, configuration: dict[str, Any] | None) -> dict[str, Any]:
        target = self.get_target(project_id, target_id)
        adapters = dict(target.get("technique_adapters") or {})
        if configuration:
            adapters[str(pack_id)] = configuration
            outcome = "saved"
        else:
            adapters.pop(str(pack_id), None)
            outcome = "removed"
        self._write("UPDATE targets SET technique_adapters_json = ? WHERE id = ? AND project_id = ?", (json_dumps(adapters), target_id, project_id))
        self.record_audit(project_id, action="target.technique_adapter.updated", object_type="target", object_id=target_id, outcome=outcome, metadata={"pack_id": str(pack_id), "configured_fields": sorted((configuration or {}).keys())})
        self.touch_project(project_id)
        return self.get_target(project_id, target_id)

    def update_target_assessment_contracts(self, project_id: str, target_id: str, contracts: list[dict[str, Any]]) -> dict[str, Any]:
        self.get_target(project_id, target_id)
        self._write("UPDATE targets SET assessment_contracts_json = ? WHERE id = ? AND project_id = ?", (json_dumps(contracts), target_id, project_id))
        self.record_audit(
            project_id,
            action="target.assessment_contracts.updated",
            object_type="target",
            object_id=target_id,
            metadata={
                "contract_count": len(contracts),
                "enabled_count": sum(1 for item in contracts if item.get("enabled")),
                "techniques": sorted({technique for item in contracts for technique in item.get("technique_ids") or []}),
            },
        )
        self.touch_project(project_id)
        return self.get_target(project_id, target_id)

    @staticmethod
    def _guardrail_dict(row: sqlite3.Row | None) -> dict[str, Any]:
        if not row:
            raise NotFoundError("execution guardrail not found in project")
        item = dict(row)
        for key in ("allow_active_recon", "allow_multi_turn", "allow_reproduction", "allow_screenshots", "stop_on_http_5xx"):
            item[key] = bool(item.get(key))
        item["blocked_prompt_patterns"] = json.loads(item.pop("blocked_prompt_patterns_json", "[]") or "[]")
        return item

    def get_guardrail(self, project_id: str, target_id: str) -> dict[str, Any]:
        self.get_target(project_id, target_id)
        return self._guardrail_dict(self._one("SELECT * FROM execution_guardrails WHERE project_id = ? AND target_id = ?", (project_id, target_id)))

    def save_guardrail(self, project_id: str, target_id: str, *, source_document_id: str | None = None, status: str = "draft", max_requests: int = 50, max_runtime_seconds: int = 900, max_consecutive_errors: int = 3, allow_active_recon: bool = False, allow_multi_turn: bool = False, max_turns_per_objective: int = 3, allow_reproduction: bool = True, reproduction_mode: str = "exact-one", reproduction_max_attempts: int = 1, reproduction_min_successes: int = 1, reproduction_min_success_rate: float = 1.0, reproduction_delay_ms: int = 0, allow_screenshots: bool = True, stop_on_http_5xx: bool = True, blocked_prompt_patterns: list[str] | str | None = None, notes: str = "") -> dict[str, Any]:
        self.get_target(project_id, target_id)
        existing = self._one("SELECT id,created_at,source_document_id,blocked_prompt_patterns_json FROM execution_guardrails WHERE project_id = ? AND target_id = ?", (project_id, target_id))
        if source_document_id is None and existing:
            source_document_id = existing["source_document_id"]
        if source_document_id:
            document = self.get_document(project_id, source_document_id)
            if document["kind"] != "scope":
                raise ValueError("guardrail source must be a scope document")
        if status not in {"draft", "approved"}:
            raise ValueError("guardrail status must be draft or approved")
        max_requests = max(1, min(10000, int(max_requests)))
        max_runtime_seconds = max(10, min(86400, int(max_runtime_seconds)))
        max_consecutive_errors = max(1, min(20, int(max_consecutive_errors)))
        max_turns_per_objective = max(1, min(10, int(max_turns_per_objective)))
        reproduction_mode = str(reproduction_mode or "exact-one").strip().casefold()
        if reproduction_mode not in {"exact-one", "bounded-statistical"}:
            raise ValueError("reproduction mode must be exact-one or bounded-statistical")
        # Low-frequency stochastic model failures can require a larger sample
        # than the original five-attempt ceiling. The operator must still opt
        # into bounded statistical reproduction, and every sample remains
        # constrained by the independent request and runtime guardrails.
        reproduction_max_attempts = max(1, min(50, int(reproduction_max_attempts)))
        if reproduction_mode == "exact-one":
            reproduction_max_attempts = 1
        reproduction_min_successes = max(1, min(reproduction_max_attempts, int(reproduction_min_successes)))
        reproduction_min_success_rate = max(0.01, min(1.0, float(reproduction_min_success_rate)))
        reproduction_delay_ms = max(0, min(30_000, int(reproduction_delay_ms)))
        if blocked_prompt_patterns is None:
            blocked_prompt_patterns = json.loads(existing["blocked_prompt_patterns_json"] or "[]") if existing else []
        elif isinstance(blocked_prompt_patterns, str):
            blocked_prompt_patterns = blocked_prompt_patterns.splitlines()
        elif not isinstance(blocked_prompt_patterns, list):
            raise ValueError("blocked_prompt_patterns must be a list or newline-separated string")
        normalized_patterns: list[str] = []
        for raw_pattern in blocked_prompt_patterns[:20]:
            pattern = str(raw_pattern).strip()
            if not pattern or pattern in normalized_patterns:
                continue
            if len(pattern) > 500:
                raise ValueError("blocked prompt patterns must be 500 characters or fewer")
            try:
                re.compile(pattern, re.IGNORECASE)
            except re.error as exc:
                raise ValueError(f"invalid blocked prompt pattern {pattern!r}: {exc}") from exc
            normalized_patterns.append(pattern)
        timestamp = now_iso()
        values = (
            source_document_id, status, max_requests, max_runtime_seconds, max_consecutive_errors,
            1 if allow_active_recon else 0, 1 if allow_multi_turn else 0, max_turns_per_objective,
            1 if allow_reproduction else 0, reproduction_mode, reproduction_max_attempts,
            reproduction_min_successes, reproduction_min_success_rate, reproduction_delay_ms,
            1 if allow_screenshots else 0, 1 if stop_on_http_5xx else 0,
            json_dumps(normalized_patterns), redact_text(notes, 4000), timestamp,
            timestamp if status == "approved" else None,
        )
        if existing:
            self._write("UPDATE execution_guardrails SET source_document_id=?,status=?,max_requests=?,max_runtime_seconds=?,max_consecutive_errors=?,allow_active_recon=?,allow_multi_turn=?,max_turns_per_objective=?,allow_reproduction=?,reproduction_mode=?,reproduction_max_attempts=?,reproduction_min_successes=?,reproduction_min_success_rate=?,reproduction_delay_ms=?,allow_screenshots=?,stop_on_http_5xx=?,blocked_prompt_patterns_json=?,notes=?,updated_at=?,approved_at=? WHERE id=? AND project_id=?", (*values, existing["id"], project_id))
            guardrail_id = existing["id"]
        else:
            guardrail_id = new_id("grd")
            self._write("INSERT INTO execution_guardrails(id,project_id,target_id,source_document_id,status,max_requests,max_runtime_seconds,max_consecutive_errors,allow_active_recon,allow_multi_turn,max_turns_per_objective,allow_reproduction,reproduction_mode,reproduction_max_attempts,reproduction_min_successes,reproduction_min_success_rate,reproduction_delay_ms,allow_screenshots,stop_on_http_5xx,blocked_prompt_patterns_json,notes,created_at,updated_at,approved_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (guardrail_id, project_id, target_id, *values[:-2], timestamp, values[-2], values[-1]))
        self.record_audit(project_id, action="guardrail.approved" if status == "approved" else "guardrail.saved", object_type="execution_guardrail", object_id=guardrail_id, metadata={"target_id": target_id, "max_requests": max_requests, "blocked_prompt_pattern_count": len(normalized_patterns), "status": status, "reproduction_mode": reproduction_mode, "reproduction_max_attempts": reproduction_max_attempts})
        self.touch_project(project_id)
        return self.get_guardrail(project_id, target_id)

    def add_import(self, project_id: str, *, kind: str, filename: str, content: str, summary: dict[str, Any], run_id: str | None = None) -> dict[str, Any]:
        self.require_project(project_id)
        if run_id is not None:
            self.require_run(project_id, run_id)
        item = {"id": new_id("imp"), "project_id": project_id, "run_id": run_id, "kind": kind, "filename": filename.strip()[:180] or f"import.{kind}", "content": redact_text(content, 300000), "summary_json": json_dumps(summary), "created_at": now_iso()}
        self._write("INSERT INTO project_imports(id,project_id,run_id,kind,filename,content,summary_json,created_at) VALUES(?,?,?,?,?,?,?,?)", tuple(item.values()))
        action = "run.reconnaissance.captured" if run_id else "technical_input.imported"
        self.record_audit(project_id, action=action, object_type=kind, object_id=item["id"], metadata={"filename": item["filename"], "run_id": run_id or ""})
        self.touch_project(project_id)
        return self._import_dict(self._one("SELECT * FROM project_imports WHERE id = ? AND project_id = ?", (item["id"], project_id)))

    def get_import(self, project_id: str, import_id: str) -> dict[str, Any]:
        row = self._one("SELECT * FROM project_imports WHERE id = ? AND project_id = ?", (import_id, project_id))
        if not row:
            raise NotFoundError("reconnaissance record not found in project")
        item = dict(row)
        item["summary"] = json.loads(item.pop("summary_json") or "{}")
        return item

    def delete_import(self, project_id: str, import_id: str) -> dict[str, Any]:
        item = self.get_import(project_id, import_id)
        if item.get("run_id"):
            raise ValueError("run-scoped reconnaissance is immutable and cannot be deleted separately from its run")
        self._write("DELETE FROM project_imports WHERE id = ? AND project_id = ?", (import_id, project_id))
        self.record_audit(project_id, action="recon.deleted", object_type=item["kind"], object_id=import_id, outcome="deleted", metadata={"filename": item["filename"]})
        self.touch_project(project_id)
        return {"id": import_id, "deleted": True}

    def _import_dict(self, row: sqlite3.Row | None) -> dict[str, Any]:
        if not row:
            raise NotFoundError("import not found")
        item = dict(row)
        item.pop("content", None)
        item["summary"] = json.loads(item.pop("summary_json") or "{}")
        return item

    def add_artifact(
        self,
        project_id: str,
        *,
        artifact_id: str,
        target_id: str,
        filename: str,
        kind: str,
        relative_path: str,
        mime_type: str,
        size_bytes: int,
        sha256: str,
    ) -> dict[str, Any]:
        self.get_target(project_id, target_id)
        allowed_kinds = {"model", "adapter", "dependency-manifest", "sbom", "container-manifest", "dataset-manifest", "other"}
        if kind not in allowed_kinds:
            raise ValueError("artifact kind is not supported")
        if not re.fullmatch(r"art_[A-Za-z0-9]{12}", artifact_id):
            raise ValueError("invalid artifact identifier")
        relative = Path(relative_path)
        if relative.is_absolute() or ".." in relative.parts or not relative.parts or relative.parts[0] != project_id:
            raise ValueError("artifact path must stay inside its project")
        if int(size_bytes) <= 0:
            raise ValueError("artifact size must be positive")
        if not re.fullmatch(r"[0-9a-f]{64}", str(sha256).lower()):
            raise ValueError("artifact SHA-256 is invalid")
        item = {
            "id": artifact_id,
            "project_id": project_id,
            "target_id": target_id,
            "filename": filename.strip()[:240] or "artifact.bin",
            "kind": kind,
            "relative_path": relative.as_posix(),
            "mime_type": str(mime_type or "application/octet-stream")[:160],
            "size_bytes": int(size_bytes),
            "sha256": str(sha256).lower(),
            "status": "active",
            "created_at": now_iso(),
            "archived_at": None,
        }
        self._write(
            "INSERT INTO project_artifacts(id,project_id,target_id,filename,kind,relative_path,mime_type,size_bytes,sha256,status,created_at,archived_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            tuple(item.values()),
        )
        self.record_audit(
            project_id,
            action="artifact.uploaded",
            object_type="artifact",
            object_id=artifact_id,
            metadata={"target_id": target_id, "filename": item["filename"], "kind": kind, "size_bytes": size_bytes, "sha256": item["sha256"]},
        )
        self.touch_project(project_id)
        return self.get_artifact(project_id, artifact_id, include_path=False)

    def get_artifact(self, project_id: str, artifact_id: str, *, include_path: bool = True) -> dict[str, Any]:
        self.require_project(project_id)
        row = self._one("SELECT * FROM project_artifacts WHERE id = ? AND project_id = ?", (artifact_id, project_id))
        if not row:
            raise NotFoundError("artifact not found in project")
        return self._artifact_dict(row, include_path=include_path)

    def list_artifacts(self, project_id: str, *, target_id: str | None = None, include_archived: bool = False) -> list[dict[str, Any]]:
        self.require_project(project_id)
        query = "SELECT * FROM project_artifacts WHERE project_id = ?"
        params: list[Any] = [project_id]
        if target_id:
            self.get_target(project_id, target_id)
            query += " AND target_id = ?"
            params.append(target_id)
        if not include_archived:
            query += " AND status = 'active'"
        query += " ORDER BY created_at DESC, id"
        return [self._artifact_dict(row, include_path=False) for row in self._all(query, tuple(params))]

    def archive_artifact(self, project_id: str, artifact_id: str) -> dict[str, Any]:
        artifact = self.get_artifact(project_id, artifact_id)
        if artifact["status"] == "archived":
            return {"id": artifact_id, "archived": True}
        running = self._all(
            "SELECT id,assessment_plan_json FROM test_runs WHERE project_id = ? AND target_id = ? AND status = 'running'",
            (project_id, artifact["target_id"]),
        )
        for row in running:
            plan = json.loads(row["assessment_plan_json"] or "{}")
            referenced = {str(item.get("id") or "") for item in plan.get("artifact_inventory") or [] if isinstance(item, dict)}
            if artifact_id in referenced:
                raise ValueError(f"artifact is in use by running assessment {row['id']}")
        timestamp = now_iso()
        self._write(
            "UPDATE project_artifacts SET status = 'archived', archived_at = ? WHERE id = ? AND project_id = ?",
            (timestamp, artifact_id, project_id),
        )
        self.record_audit(project_id, action="artifact.archived", object_type="artifact", object_id=artifact_id, outcome="archived", metadata={"filename": artifact["filename"], "sha256": artifact["sha256"]})
        self.touch_project(project_id)
        return {"id": artifact_id, "archived": True, "retained_for_evidence": True}

    @staticmethod
    def _artifact_dict(row: sqlite3.Row | None, *, include_path: bool = False) -> dict[str, Any]:
        if not row:
            raise NotFoundError("artifact not found")
        item = dict(row)
        if not include_path:
            item.pop("relative_path", None)
        return item

    def create_run(self, project_id: str, target_id: str, module_ids: list[str], model_mode: str, *, attack_profile: str = "standard", attack_budget: int = 8, assessment_plan: dict[str, Any] | None = None, manifest: dict[str, Any] | None = None) -> dict[str, Any]:
        self.get_target(project_id, target_id)
        active = self._one(
            "SELECT id FROM test_runs WHERE project_id = ? AND target_id = ? AND status = 'running' ORDER BY started_at DESC LIMIT 1",
            (project_id, target_id),
        )
        if active:
            raise ValueError(f"assessment {active['id']} is already running against this target")
        item = {"id": new_id("run"), "project_id": project_id, "target_id": target_id, "status": "running", "model_mode": model_mode, "module_ids_json": json_dumps(module_ids), "assessment_plan_json": json_dumps(assessment_plan or {}), "attack_profile": attack_profile, "attack_budget": int(attack_budget), "manifest_json": json_dumps(manifest or {}), "metrics_json": "{}", "error": "", "started_at": now_iso(), "completed_at": None}
        self._write("INSERT INTO test_runs(id,project_id,target_id,status,model_mode,module_ids_json,assessment_plan_json,attack_profile,attack_budget,manifest_json,metrics_json,error,started_at,completed_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", tuple(item.values()))
        self.record_audit(project_id, action="assessment.started", object_type="run", object_id=item["id"], metadata={"target_id": target_id, "modules": ",".join(module_ids), "model_mode": model_mode, "attack_profile": attack_profile, "attack_budget": attack_budget, "owasp_version": (assessment_plan or {}).get("taxonomy_version", "")})
        self.touch_project(project_id)
        return self._run_dict(self._one("SELECT * FROM test_runs WHERE id = ? AND project_id = ?", (item["id"], project_id)))

    def complete_run(self, project_id: str, run_id: str, *, status: str, error: str = "") -> dict[str, Any]:
        self.require_run(project_id, run_id)
        self._write("UPDATE test_runs SET status = ?, error = ?, completed_at = ? WHERE id = ? AND project_id = ?", (status, redact_text(error, 1000), now_iso(), run_id, project_id))
        self.refresh_run_metrics(project_id, run_id)
        self.record_audit(project_id, action="assessment.completed", object_type="run", object_id=run_id, outcome=status, metadata={"error_count": len([line for line in error.splitlines() if line])})
        return self._run_dict(self._one("SELECT * FROM test_runs WHERE id = ? AND project_id = ?", (run_id, project_id)))

    def reconcile_stale_executions(self) -> dict[str, list[str]]:
        """Close executions left running by a previous application process.

        Background workers are intentionally process-local.  On startup no
        worker from the previous process can still own a persisted ``running``
        row, so leaving it active would block the target indefinitely and make
        the audit trail misleading.
        """
        reason = "application restarted before the background worker recorded a terminal state"
        assessment_ids: list[str] = []
        tool_ids: list[str] = []
        for row in self._all("SELECT id,project_id FROM test_runs WHERE status = 'running' ORDER BY started_at"):
            project_id, run_id = str(row["project_id"]), str(row["id"])
            self.add_run_event(project_id, run_id, event_type="assessment.interrupted", title="Assessment interrupted by application restart", details={"reason": reason, "terminal": True})
            self.complete_run(project_id, run_id, status="interrupted", error=reason)
            assessment_ids.append(run_id)
        for row in self._all("SELECT id,project_id FROM testing_tool_runs WHERE status = 'running' ORDER BY started_at"):
            project_id, run_id = str(row["project_id"]), str(row["id"])
            self.add_tool_event(project_id, run_id, step_id="", event_type="tool.interrupted", title="Testing-tool run interrupted by application restart", details={"reason": reason, "terminal": True})
            self.complete_tool_run(project_id, run_id, status="interrupted", error=reason)
            tool_ids.append(run_id)
        return {"assessments": assessment_ids, "tools": tool_ids}

    def update_run_manifest(self, project_id: str, run_id: str, manifest: dict[str, Any]) -> dict[str, Any]:
        self.require_run(project_id, run_id)
        self._write("UPDATE test_runs SET manifest_json = ? WHERE id = ? AND project_id = ?", (json_dumps(manifest), run_id, project_id))
        self.record_audit(project_id, action="assessment.manifest.recorded", object_type="run", object_id=run_id, metadata={"schema_version": manifest.get("schema_version", ""), "manifest_sha256": manifest.get("manifest_sha256", "")})
        return self.require_run(project_id, run_id)

    def update_run_assessment_plan(self, project_id: str, run_id: str, assessment_plan: dict[str, Any]) -> dict[str, Any]:
        """Finalize immutable execution context before a pre-created run sends traffic."""
        run = self.require_run(project_id, run_id)
        if run.get("status") != "running":
            raise ValueError("only a running assessment plan can be finalized")
        encoded = json_dumps(assessment_plan)
        self._write(
            "UPDATE test_runs SET assessment_plan_json = ? WHERE id = ? AND project_id = ?",
            (encoded, run_id, project_id),
        )
        self.record_audit(
            project_id,
            action="assessment.plan_context_recorded",
            object_type="run",
            object_id=run_id,
            metadata={
                "reasoning_snapshot_sha256": str((assessment_plan.get("reasoning_snapshot") or {}).get("snapshot_sha256") or ""),
                "project_context_sha256": hashlib.sha256(str(assessment_plan.get("project_context_snapshot") or "").encode("utf-8")).hexdigest(),
                "methodology_context_sha256": hashlib.sha256(str(assessment_plan.get("methodology_context_snapshot") or "").encode("utf-8")).hexdigest(),
            },
        )
        return self.require_run(project_id, run_id)

    def refresh_run_metrics(self, project_id: str, run_id: str) -> dict[str, Any]:
        detail = self.get_run_detail(project_id, run_id)
        metrics = detail.get("metrics") or {}
        self._write("UPDATE test_runs SET metrics_json = ? WHERE id = ? AND project_id = ?", (json_dumps(metrics), run_id, project_id))
        return metrics

    def require_run(self, project_id: str, run_id: str) -> dict[str, Any]:
        row = self._one("SELECT * FROM test_runs WHERE id = ? AND project_id = ?", (run_id, project_id))
        if not row:
            raise NotFoundError("run not found in project")
        return self._run_dict(row)

    def _run_dict(self, row: sqlite3.Row | None) -> dict[str, Any]:
        if not row:
            raise NotFoundError("run not found")
        item = dict(row)
        item["module_ids"] = json.loads(item.pop("module_ids_json") or "[]")
        item["assessment_plan"] = json.loads(item.pop("assessment_plan_json") or "{}")
        item["manifest"] = json.loads(item.pop("manifest_json") or "{}")
        item["metrics"] = json.loads(item.pop("metrics_json") or "{}")
        run_id = item["id"]
        for key, query in {
            "test_cases": "SELECT COUNT(*) AS count FROM test_cases WHERE run_id = ?",
            "vulnerable_cases": "SELECT COUNT(*) AS count FROM test_cases WHERE run_id = ? AND status = 'vulnerable'",
            "evidence_records": "SELECT COUNT(*) AS count FROM evidence WHERE run_id = ?",
            "screenshots": "SELECT COUNT(*) AS count FROM evidence_assets WHERE run_id = ?",
            "protocol_events": "SELECT COUNT(*) AS count FROM ai_protocol_events WHERE run_id = ?",
        }.items():
            count = self._one(query, (run_id,))
            item.setdefault("counts", {})[key] = int(count["count"] if count else 0)
        return item

    def add_run_event(self, project_id: str, run_id: str, *, event_type: str, title: str, details: dict[str, Any] | None = None, test_case_id: str | None = None) -> dict[str, Any]:
        self.require_run(project_id, run_id)
        if test_case_id:
            case = self._one("SELECT id FROM test_cases WHERE id = ? AND project_id = ? AND run_id = ?", (test_case_id, project_id, run_id))
            if not case:
                raise NotFoundError("test case not found in project run")
        serialized = redact_text(json_dumps(details or {}), 4_500_000)
        try:
            safe_details = json.loads(serialized)
        except json.JSONDecodeError:
            safe_details = {"message": redact_text(str(details or {}), 4_500_000)}
        fault = fault_for_event(event_type, safe_details)
        if fault:
            safe_details.setdefault("fault", fault)
        with self._lock:
            sequence_row = self.connection.execute(
                "SELECT COALESCE(MAX(sequence), 0) + 1 AS next_sequence FROM run_events WHERE run_id = ? AND project_id = ?",
                (run_id, project_id),
            ).fetchone()
            item = {
                "id": new_id("event"), "project_id": project_id, "run_id": run_id,
                "test_case_id": test_case_id, "sequence": int(sequence_row["next_sequence"]),
                "event_type": event_type.strip()[:80] or "status",
                "title": title.strip()[:200] or "Assessment event",
                "details_json": json_dumps(safe_details), "created_at": now_iso_precise(),
            }
            self.connection.execute(
                "INSERT INTO run_events(id,project_id,run_id,test_case_id,sequence,event_type,title,details_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                tuple(item.values()),
            )
            self.connection.commit()
        return {**item, "details": safe_details}

    def add_ai_protocol_event(
        self,
        project_id: str,
        run_id: str,
        *,
        protocol: str,
        phase: str,
        direction: str,
        event_type: str,
        correlation_id: str,
        round_number: int,
        payload: dict[str, Any] | None = None,
        test_case_id: str | None = None,
    ) -> dict[str, Any]:
        """Retain a normalized AI protocol message inside one project run."""
        self.require_run(project_id, run_id)
        if test_case_id and not self._one(
            "SELECT id FROM test_cases WHERE id = ? AND project_id = ? AND run_id = ?",
            (test_case_id, project_id, run_id),
        ):
            raise NotFoundError("AI protocol event test case is not part of the project run")
        if direction not in {"client-to-target", "target-to-client", "local"}:
            raise ValueError("AI protocol event direction is invalid")
        if phase not in {"initial", "reproduction", "analysis"}:
            raise ValueError("AI protocol event phase is invalid")
        serialized = redact_text(json_dumps(payload or {}), 4_500_000)
        try:
            safe_payload = json.loads(serialized)
        except json.JSONDecodeError:
            safe_payload = {"message": redact_text(str(payload or {}), 4_500_000)}
        with self._lock:
            row = self.connection.execute(
                "SELECT COALESCE(MAX(sequence),0) + 1 AS next_sequence FROM ai_protocol_events WHERE project_id = ? AND run_id = ?",
                (project_id, run_id),
            ).fetchone()
            item = {
                "id": new_id("protocol"), "project_id": project_id, "run_id": run_id,
                "test_case_id": test_case_id, "sequence": int(row["next_sequence"]),
                "protocol": str(protocol)[:120], "phase": phase,
                "direction": direction, "event_type": str(event_type)[:120],
                "correlation_id": str(correlation_id)[:160],
                "round_number": max(0, min(1000, int(round_number))),
                "payload_json": json_dumps(safe_payload), "created_at": now_iso_precise(),
            }
            self.connection.execute(
                "INSERT INTO ai_protocol_events(id,project_id,run_id,test_case_id,sequence,protocol,phase,direction,event_type,correlation_id,round_number,payload_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                tuple(item.values()),
            )
            self.connection.commit()
        return {**item, "payload": safe_payload}

    @staticmethod
    def _ai_protocol_event_dict(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["payload"] = json.loads(item.pop("payload_json") or "{}")
        return item

    def list_ai_protocol_events(self, project_id: str, run_id: str, *, test_case_id: str | None = None) -> list[dict[str, Any]]:
        self.require_run(project_id, run_id)
        query = "SELECT * FROM ai_protocol_events WHERE project_id = ? AND run_id = ?"
        params: tuple[Any, ...] = (project_id, run_id)
        if test_case_id:
            query += " AND test_case_id = ?"
            params = (project_id, run_id, test_case_id)
        query += " ORDER BY sequence"
        return [self._ai_protocol_event_dict(row) for row in self._all(query, params)]

    def link_ai_protocol_events(self, project_id: str, run_id: str, correlation_id: str, test_case_id: str) -> int:
        if not self._one(
            "SELECT id FROM test_cases WHERE id = ? AND project_id = ? AND run_id = ?",
            (test_case_id, project_id, run_id),
        ):
            raise NotFoundError("AI protocol event test case is not part of the project run")
        with self._lock:
            cursor = self.connection.execute(
                "UPDATE ai_protocol_events SET test_case_id = ? WHERE project_id = ? AND run_id = ? AND correlation_id = ? AND test_case_id IS NULL",
                (test_case_id, project_id, run_id, correlation_id),
            )
            self.connection.commit()
        return int(cursor.rowcount)

    @staticmethod
    def _run_event_dict(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["details"] = json.loads(item.pop("details_json") or "{}")
        return item

    def _test_case_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["evaluation"] = json.loads(item.pop("evaluation_json") or "{}")
        item["trace"] = json.loads(item.pop("trace_json") or "{}")
        evidence_items = []
        for evidence_row in self._all("SELECT * FROM evidence WHERE project_id = ? AND run_id = ? AND test_case_id = ? ORDER BY created_at", (item["project_id"], item["run_id"], item["id"])):
            evidence = dict(evidence_row)
            evidence["metadata"] = json.loads(evidence.pop("metadata_json") or "{}")
            evidence["assets"] = [dict(asset) for asset in self._all(
                "SELECT id,kind,attempt,mime_type,size_bytes,sha256,created_at FROM evidence_assets WHERE evidence_id = ? AND project_id = ? ORDER BY created_at",
                (evidence["id"], item["project_id"]),
            )]
            evidence_items.append(evidence)
        item["evidence"] = evidence_items
        item["protocol_events"] = [
            self._ai_protocol_event_dict(event)
            for event in self._all(
                "SELECT * FROM ai_protocol_events WHERE project_id = ? AND run_id = ? AND test_case_id = ? ORDER BY sequence",
                (item["project_id"], item["run_id"], item["id"]),
            )
        ]
        return item

    def _historical_run_events(self, run: dict[str, Any], target: dict[str, Any], cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = [{
            "id": f"historical-{run['id']}-start", "project_id": run["project_id"], "run_id": run["id"],
            "test_case_id": None, "sequence": 1, "event_type": "assessment.started", "title": "Assessment started",
            "details": {"modules": run["module_ids"], "model_mode": run["model_mode"]}, "created_at": run["started_at"],
        }]
        sequence = 2
        url = target["base_url"].rstrip("/") + "/" + target["path"].lstrip("/")
        for case in cases:
            events.append({
                "id": f"historical-{case['id']}-request", "project_id": run["project_id"], "run_id": run["id"],
                "test_case_id": case["id"], "sequence": sequence, "event_type": "request.sent", "title": f"Payload sent: {case['title']}",
                "details": {"attempt": "initial", "module_id": case["module_id"], "method": target["method"], "url": url, "payload": preview_payload(target["request_template"], case["prompt"])},
                "created_at": case["created_at"],
            })
            sequence += 1
            events.append({
                "id": f"historical-{case['id']}-response", "project_id": run["project_id"], "run_id": run["id"],
                "test_case_id": case["id"], "sequence": sequence, "event_type": "response.received", "title": f"Response received: {case['title']}",
                "details": {"attempt": "initial", "module_id": case["module_id"], "response": case["response"]},
                "created_at": case["created_at"],
            })
            sequence += 1
            events.append({
                "id": f"historical-{case['id']}-evaluation", "project_id": run["project_id"], "run_id": run["id"],
                "test_case_id": case["id"], "sequence": sequence, "event_type": "evaluation.completed", "title": f"Evaluation completed: {case['title']}",
                "details": case["evaluation"], "created_at": case["created_at"],
            })
            sequence += 1
        if run["completed_at"]:
            events.append({
                "id": f"historical-{run['id']}-complete", "project_id": run["project_id"], "run_id": run["id"],
                "test_case_id": None, "sequence": sequence, "event_type": "assessment.completed", "title": "Assessment completed",
                "details": {"status": run["status"], "error": run["error"]}, "created_at": run["completed_at"],
            })
        return events

    def get_run_detail(self, project_id: str, run_id: str) -> dict[str, Any]:
        run = self.require_run(project_id, run_id)
        target = self.get_target(project_id, run["target_id"])
        cases = [self._test_case_dict(row) for row in self._all(
            "SELECT * FROM test_cases WHERE project_id = ? AND run_id = ? ORDER BY created_at, rowid",
            (project_id, run_id),
        )]
        event_rows = self._all(
            "SELECT * FROM run_events WHERE project_id = ? AND run_id = ? ORDER BY sequence",
            (project_id, run_id),
        )
        findings = [self._finding_dict(row) for row in self._all(
            "SELECT DISTINCT f.* FROM findings f LEFT JOIN finding_occurrences o ON o.finding_id = f.id "
            "WHERE f.project_id = ? AND (f.run_id = ? OR o.run_id = ?) ORDER BY f.created_at",
            (project_id, run_id, run_id),
        )]
        result = {
            **run,
            "target": {key: target[key] for key in ("id", "name", "kind", "base_url", "path", "method")},
            "events": [self._run_event_dict(row) for row in event_rows] if event_rows else self._historical_run_events(run, target, cases),
            "protocol_events": self.list_ai_protocol_events(project_id, run_id),
            "test_cases": cases,
            "findings": findings,
            "reconnaissance": [self.get_import(project_id, row["id"]) for row in self._all(
                "SELECT id FROM project_imports WHERE project_id = ? AND run_id = ? ORDER BY created_at",
                (project_id, run_id),
            )],
            "owasp_coverage": self.owasp_coverage(project_id, run_id=run_id),
            "adjudications": self.list_adjudications(project_id, execution_kind="assessment", execution_id=run_id),
            "contract_runs": [self.get_tool_run(project_id, row["id"]) for row in self._all(
                "SELECT id FROM testing_tool_runs WHERE project_id = ? AND assessment_run_id = ? ORDER BY started_at, id",
                (project_id, run_id),
            )],
        }
        from .telemetry import analyze_assessment_run
        analysis = analyze_assessment_run(result)
        result["metrics"] = {key: value for key, value in analysis.items() if key != "diagnostics"}
        for case in result["test_cases"]:
            case["diagnostic"] = analysis["diagnostics"].get(case["id"], {})
        return result

    def add_test_case(self, project_id: str, *, run_id: str, target_id: str, module_id: str, title: str, prompt: str, rationale: str, response: str, evaluation: dict[str, Any], generation_source: str, status: str, trace: dict[str, Any] | None = None) -> dict[str, Any]:
        self.require_run(project_id, run_id)
        self.get_target(project_id, target_id)
        item = {"id": new_id("case"), "project_id": project_id, "run_id": run_id, "target_id": target_id, "module_id": module_id, "title": title[:200], "prompt": redact_text(prompt, 12000), "rationale": redact_text(rationale, 2000), "response": redact_text(response, 2_000_000), "evaluation_json": json_dumps(evaluation), "trace_json": json_dumps(trace or {}), "generation_source": generation_source[:40], "status": status, "created_at": now_iso_precise()}
        self._write("INSERT INTO test_cases(id,project_id,run_id,target_id,module_id,title,prompt,rationale,response,evaluation_json,trace_json,generation_source,status,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", tuple(item.values()))
        return {**item, "evaluation": evaluation, "trace": trace or {}}

    def update_test_case_trace(self, project_id: str, run_id: str, test_case_id: str, trace: dict[str, Any]) -> dict[str, Any]:
        row = self._one("SELECT id FROM test_cases WHERE id = ? AND project_id = ? AND run_id = ?", (test_case_id, project_id, run_id))
        if not row:
            raise NotFoundError("test case not found in project run")
        self._write("UPDATE test_cases SET trace_json = ? WHERE id = ? AND project_id = ? AND run_id = ?", (json_dumps(trace), test_case_id, project_id, run_id))
        return self._test_case_dict(self._one("SELECT * FROM test_cases WHERE id = ? AND project_id = ? AND run_id = ?", (test_case_id, project_id, run_id)))

    def update_test_case_evaluation(self, project_id: str, run_id: str, test_case_id: str, *, evaluation: dict[str, Any], status: str) -> dict[str, Any]:
        if status not in {"safe", "vulnerable", "inconclusive", "error"}:
            raise ValueError("invalid test-case status")
        row = self._one(
            "SELECT * FROM test_cases WHERE id = ? AND project_id = ? AND run_id = ?",
            (test_case_id, project_id, run_id),
        )
        if not row:
            raise NotFoundError("test case not found in project run")
        self._write(
            "UPDATE test_cases SET evaluation_json = ?, status = ? WHERE id = ? AND project_id = ? AND run_id = ?",
            (json_dumps(evaluation), status, test_case_id, project_id, run_id),
        )
        return self._test_case_dict(self._one(
            "SELECT * FROM test_cases WHERE id = ? AND project_id = ? AND run_id = ?",
            (test_case_id, project_id, run_id),
        ))

    def unlink_case_from_findings(self, project_id: str, run_id: str, test_case_id: str) -> int:
        """Remove a disproven case from finding aggregation while retaining its evidence and audit history."""
        case = self._one(
            "SELECT id FROM test_cases WHERE id = ? AND project_id = ? AND run_id = ?",
            (test_case_id, project_id, run_id),
        )
        if not case:
            raise NotFoundError("test case not found in project run")
        actions: list[tuple[str, str, dict[str, Any]]] = []
        severity_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        with self._lock:
            linked = self.connection.execute(
                "SELECT DISTINCT finding_id FROM finding_occurrences WHERE project_id = ? AND run_id = ? AND test_case_id = ?",
                (project_id, run_id, test_case_id),
            ).fetchall()
            for linked_row in linked:
                finding_id = str(linked_row["finding_id"])
                self.connection.execute(
                    "DELETE FROM finding_validations WHERE project_id = ? AND finding_id = ? AND run_id = ? AND test_case_id = ?",
                    (project_id, finding_id, run_id, test_case_id),
                )
                self.connection.execute(
                    "DELETE FROM finding_occurrences WHERE project_id = ? AND finding_id = ? AND run_id = ? AND test_case_id = ?",
                    (project_id, finding_id, run_id, test_case_id),
                )
                remaining = self.connection.execute(
                    "SELECT o.run_id,o.test_case_id,o.evidence_id,o.created_at,tc.evaluation_json "
                    "FROM finding_occurrences o JOIN test_cases tc ON tc.id = o.test_case_id AND tc.project_id = o.project_id "
                    "WHERE o.project_id = ? AND o.finding_id = ? ORDER BY o.created_at, o.id",
                    (project_id, finding_id),
                ).fetchall()
                if not remaining:
                    self.connection.execute("DELETE FROM findings WHERE id = ? AND project_id = ?", (finding_id, project_id))
                    actions.append(("finding.removed_after_reevaluation", finding_id, {"run_id": run_id, "test_case_id": test_case_id, "remaining_occurrences": 0}))
                    continue
                evaluated = []
                for occurrence in remaining:
                    evaluation = json.loads(occurrence["evaluation_json"] or "{}")
                    severity = str(evaluation.get("severity") or "info").lower()
                    confidence = max(0.0, min(1.0, float(evaluation.get("confidence") or 0.0)))
                    evaluated.append((severity_rank.get(severity, 0), confidence, severity))
                _, confidence, severity = max(evaluated)
                first = remaining[0]
                self.connection.execute(
                    "UPDATE findings SET run_id = ?, test_case_id = ?, evidence_id = ?, severity = ?, confidence = ?, "
                    "occurrence_count = ?, last_seen_at = ?, updated_at = ? WHERE id = ? AND project_id = ?",
                    (first["run_id"], first["test_case_id"], first["evidence_id"], severity, confidence, len(remaining), remaining[-1]["created_at"], now_iso(), finding_id, project_id),
                )
                actions.append(("finding.occurrence_unlinked", finding_id, {"run_id": run_id, "test_case_id": test_case_id, "remaining_occurrences": len(remaining)}))
            self.connection.commit()
        for action, finding_id, metadata in actions:
            self.record_audit(project_id, action=action, object_type="finding", object_id=finding_id, outcome="safe", metadata=metadata)
        if linked:
            self.touch_project(project_id)
        return len(linked)

    def add_evidence(self, project_id: str, *, run_id: str, test_case_id: str, kind: str, title: str, content: str, metadata: dict[str, Any]) -> dict[str, Any]:
        self.require_run(project_id, run_id)
        item = {"id": new_id("ev"), "project_id": project_id, "run_id": run_id, "test_case_id": test_case_id, "kind": kind, "title": title[:200], "content": redact_text(content, 4_500_000), "metadata_json": json_dumps(metadata), "created_at": now_iso()}
        self._write("INSERT INTO evidence(id,project_id,run_id,test_case_id,kind,title,content,metadata_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)", tuple(item.values()))
        return {**item, "metadata": metadata}

    def add_evidence_asset(self, project_id: str, *, run_id: str, test_case_id: str, evidence_id: str, kind: str, attempt: str, relative_path: str, mime_type: str, size_bytes: int, sha256: str) -> dict[str, Any]:
        self.require_run(project_id, run_id)
        evidence = self._one("SELECT id FROM evidence WHERE id = ? AND project_id = ? AND run_id = ? AND test_case_id = ?", (evidence_id, project_id, run_id, test_case_id))
        if not evidence:
            raise NotFoundError("evidence not found in project run")
        relative = Path(relative_path)
        if relative.is_absolute() or ".." in relative.parts or not relative.parts or relative.parts[0] != project_id:
            raise ValueError("evidence asset path must stay inside its project")
        item = {
            "id": new_id("asset"), "project_id": project_id, "run_id": run_id,
            "test_case_id": test_case_id, "evidence_id": evidence_id, "kind": kind[:80],
            "attempt": attempt[:40], "relative_path": relative.as_posix(), "mime_type": mime_type[:100],
            "size_bytes": int(size_bytes), "sha256": sha256[:128], "created_at": now_iso(),
        }
        self._write("INSERT INTO evidence_assets(id,project_id,run_id,test_case_id,evidence_id,kind,attempt,relative_path,mime_type,size_bytes,sha256,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", tuple(item.values()))
        self.record_audit(project_id, action="evidence.screenshot.stored", object_type="evidence_asset", object_id=item["id"], metadata={"kind": item["kind"], "attempt": item["attempt"], "sha256": item["sha256"]})
        return item

    def get_evidence_asset(self, project_id: str, asset_id: str) -> dict[str, Any]:
        row = self._one("SELECT * FROM evidence_assets WHERE id = ? AND project_id = ?", (asset_id, project_id))
        if not row:
            raise NotFoundError("evidence asset not found in project")
        return dict(row)

    def add_finding(self, project_id: str, *, run_id: str, test_case_id: str, evidence_id: str, module_id: str, title: str, severity: str, confidence: float, summary: str) -> dict[str, Any]:
        self.require_run(project_id, run_id)
        test_case = self._one(
            "SELECT target_id FROM test_cases WHERE id = ? AND project_id = ? AND run_id = ?",
            (test_case_id, project_id, run_id),
        )
        evidence = self._one(
            "SELECT id FROM evidence WHERE id = ? AND project_id = ? AND run_id = ? AND test_case_id = ?",
            (evidence_id, project_id, run_id, test_case_id),
        )
        if not test_case or not evidence:
            raise NotFoundError("finding evidence is not part of the project run")
        confidence = max(0.0, min(1.0, float(confidence)))
        timestamp = now_iso()
        safe_title = title[:240]
        safe_severity = severity.lower() if severity.lower() in {"critical", "high", "medium", "low", "info"} else "medium"
        fingerprint = finding_fingerprint(test_case["target_id"], module_id, safe_title)
        deduplicated = False
        with self._lock:
            existing = self.connection.execute(
                "SELECT * FROM findings WHERE project_id = ? AND fingerprint = ?",
                (project_id, fingerprint),
            ).fetchone()
            if existing:
                cursor = self.connection.execute(
                    "INSERT OR IGNORE INTO finding_occurrences"
                    "(id,project_id,finding_id,run_id,test_case_id,evidence_id,created_at) VALUES(?,?,?,?,?,?,?)",
                    (new_id("occ"), project_id, existing["id"], run_id, test_case_id, evidence_id, timestamp),
                )
                if cursor.rowcount:
                    severity_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
                    updated_severity = safe_severity if severity_rank[safe_severity] > severity_rank.get(existing["severity"], 0) else existing["severity"]
                    count_row = self.connection.execute(
                        "SELECT COUNT(*) AS count FROM finding_occurrences WHERE finding_id = ?",
                        (existing["id"],),
                    ).fetchone()
                    self.connection.execute(
                        "UPDATE findings SET severity = ?, confidence = ?, occurrence_count = ?, last_seen_at = ?, updated_at = ? "
                        "WHERE id = ? AND project_id = ?",
                        (updated_severity, max(confidence, float(existing["confidence"])), int(count_row["count"]), timestamp, timestamp, existing["id"], project_id),
                    )
                self.connection.commit()
                finding_id = existing["id"]
                deduplicated = True
            else:
                item = {
                    "id": new_id("find"), "project_id": project_id, "run_id": run_id,
                    "test_case_id": test_case_id, "evidence_id": evidence_id, "module_id": module_id,
                    "title": safe_title, "severity": safe_severity, "confidence": confidence,
                    "summary": redact_text(summary, 5000), "status": "open", "fingerprint": fingerprint,
                    "occurrence_count": 1, "last_seen_at": timestamp, "created_at": timestamp, "updated_at": timestamp,
                }
                self.connection.execute(
                    "INSERT INTO findings(id,project_id,run_id,test_case_id,evidence_id,module_id,title,severity,confidence,summary,status,fingerprint,occurrence_count,last_seen_at,created_at,updated_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    tuple(item.values()),
                )
                self.connection.execute(
                    "INSERT INTO finding_occurrences(id,project_id,finding_id,run_id,test_case_id,evidence_id,created_at) VALUES(?,?,?,?,?,?,?)",
                    (new_id("occ"), project_id, item["id"], run_id, test_case_id, evidence_id, timestamp),
                )
                self.connection.commit()
                finding_id = item["id"]
        action = "finding.observed_again" if deduplicated else "finding.created"
        self.record_audit(project_id, action=action, object_type="finding", object_id=finding_id, metadata={"severity": safe_severity, "module_id": module_id, "run_id": run_id})
        self.touch_project(project_id)
        result = self._finding_dict(self._one("SELECT * FROM findings WHERE id = ? AND project_id = ?", (finding_id, project_id)))
        result["deduplicated"] = deduplicated
        return result

    def add_finding_validation(self, project_id: str, *, finding_id: str, run_id: str, test_case_id: str, evidence_id: str | None, status: str, response: str, evaluation: dict[str, Any]) -> dict[str, Any]:
        if status not in {"confirmed", "not-reproduced", "error"}:
            raise ValueError("invalid validation status")
        finding = self._one("SELECT id FROM findings WHERE id = ? AND project_id = ?", (finding_id, project_id))
        if not finding:
            raise NotFoundError("finding not found in project")
        item = {
            "id": new_id("validation"), "project_id": project_id, "finding_id": finding_id,
            "run_id": run_id, "test_case_id": test_case_id, "evidence_id": evidence_id,
            "status": status, "response": redact_text(response, 2_000_000),
            "evaluation_json": json_dumps(evaluation), "created_at": now_iso(),
        }
        self._write("INSERT INTO finding_validations(id,project_id,finding_id,run_id,test_case_id,evidence_id,status,response,evaluation_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)", tuple(item.values()))
        self.record_audit(project_id, action="finding.reproduced", object_type="finding", object_id=finding_id, outcome=status, metadata={"validation_id": item["id"]})
        return {**item, "evaluation": evaluation}

    @staticmethod
    def _adjudication_dict(row: sqlite3.Row | None) -> dict[str, Any]:
        if not row:
            raise NotFoundError("validation adjudication not found")
        item = dict(row)
        item["metadata"] = json.loads(item.pop("metadata_json") or "{}")
        return item

    def list_adjudications(self, project_id: str, *, execution_kind: str, execution_id: str) -> list[dict[str, Any]]:
        self.require_project(project_id)
        return [self._adjudication_dict(row) for row in self._all(
            "SELECT * FROM validation_adjudications WHERE project_id = ? AND execution_kind = ? AND execution_id = ? ORDER BY updated_at, id",
            (project_id, execution_kind, execution_id),
        )]

    def upsert_adjudication(
        self,
        project_id: str,
        *,
        execution_kind: str,
        execution_id: str,
        source: str,
        expectation_id: str,
        expected_outcome: str,
        observed_outcome: str,
        classification: str,
        root_cause: str,
        notes: str = "",
        metadata: dict[str, Any] | None = None,
        test_case_id: str = "",
    ) -> dict[str, Any]:
        from .telemetry import ADJUDICATION_CLASSIFICATIONS, ADJUDICATION_OUTCOMES, ROOT_CAUSES
        if execution_kind not in {"assessment", "tool"}:
            raise ValueError("execution kind must be assessment or tool")
        if source not in {"human", "oracle", "automated"}:
            raise ValueError("adjudication source must be human, oracle, or automated")
        if expected_outcome not in ADJUDICATION_OUTCOMES or observed_outcome not in ADJUDICATION_OUTCOMES:
            raise ValueError("invalid adjudication outcome")
        if classification not in ADJUDICATION_CLASSIFICATIONS:
            raise ValueError("invalid adjudication classification")
        if root_cause not in ROOT_CAUSES:
            raise ValueError("invalid adjudication root cause")
        expectation_id = expectation_id.strip()[:160]
        if not expectation_id:
            raise ValueError("adjudication expectation id is required")
        if execution_kind == "assessment":
            self.require_run(project_id, execution_id)
            if test_case_id and not self._one("SELECT id FROM test_cases WHERE id = ? AND project_id = ? AND run_id = ?", (test_case_id, project_id, execution_id)):
                raise NotFoundError("adjudicated test case is not part of the assessment run")
        else:
            self.get_tool_run(project_id, execution_id, include_events=False)
            if test_case_id:
                raise ValueError("tool-run adjudications cannot reference assessment test cases")
        timestamp = now_iso()
        existing = self._one(
            "SELECT id,created_at FROM validation_adjudications WHERE project_id = ? AND execution_kind = ? AND execution_id = ? AND source = ? AND expectation_id = ? AND test_case_id = ?",
            (project_id, execution_kind, execution_id, source, expectation_id, test_case_id),
        )
        item = {
            "id": existing["id"] if existing else new_id("adj"), "project_id": project_id,
            "execution_kind": execution_kind, "execution_id": execution_id, "test_case_id": test_case_id,
            "source": source, "expectation_id": expectation_id, "expected_outcome": expected_outcome,
            "observed_outcome": observed_outcome, "classification": classification, "root_cause": root_cause,
            "notes": redact_text(notes, 4000), "metadata_json": json_dumps(metadata or {}),
            "created_at": existing["created_at"] if existing else timestamp, "updated_at": timestamp,
        }
        if existing:
            self._write(
                "UPDATE validation_adjudications SET expected_outcome=?,observed_outcome=?,classification=?,root_cause=?,notes=?,metadata_json=?,updated_at=? WHERE id=? AND project_id=?",
                (item["expected_outcome"], item["observed_outcome"], item["classification"], item["root_cause"], item["notes"], item["metadata_json"], item["updated_at"], item["id"], project_id),
            )
        else:
            self._write(
                "INSERT INTO validation_adjudications(id,project_id,execution_kind,execution_id,test_case_id,source,expectation_id,expected_outcome,observed_outcome,classification,root_cause,notes,metadata_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                tuple(item.values()),
            )
        self.record_audit(project_id, action="validation.adjudicated", object_type=execution_kind, object_id=execution_id, outcome=classification, metadata={"adjudication_id": item["id"], "source": source, "expectation_id": expectation_id, "root_cause": root_cause, "test_case_id": test_case_id})
        if execution_kind == "assessment":
            self.refresh_run_metrics(project_id, execution_id)
        else:
            self.refresh_tool_run_metrics(project_id, execution_id)
        self.touch_project(project_id)
        return self._adjudication_dict(self._one("SELECT * FROM validation_adjudications WHERE id = ? AND project_id = ?", (item["id"], project_id)))

    def update_finding_status(self, project_id: str, finding_id: str, status: str) -> dict[str, Any]:
        if status not in {"open", "accepted", "rejected", "fixed"}:
            raise ValueError("invalid finding status")
        row = self._one("SELECT * FROM findings WHERE id = ? AND project_id = ?", (finding_id, project_id))
        if not row:
            raise NotFoundError("finding not found in project")
        self._write("UPDATE findings SET status = ?, updated_at = ? WHERE id = ? AND project_id = ?", (status, now_iso(), finding_id, project_id))
        self.record_audit(project_id, action="finding.reviewed", object_type="finding", object_id=finding_id, outcome=status)
        self.touch_project(project_id)
        return self._finding_dict(self._one("SELECT * FROM findings WHERE id = ? AND project_id = ?", (finding_id, project_id)))

    def _finding_dict(self, row: sqlite3.Row | None) -> dict[str, Any]:
        if not row:
            raise NotFoundError("finding not found")
        item = dict(row)
        evidence = self._one(
            "SELECT id,title,content,metadata_json,created_at FROM evidence WHERE id = ? AND project_id = ?",
            (item["evidence_id"], item["project_id"]),
        )
        if evidence:
            item["evidence"] = dict(evidence)
            item["evidence"]["metadata"] = json.loads(item["evidence"].pop("metadata_json") or "{}")
            item["evidence"]["assets"] = [dict(asset) for asset in self._all("SELECT id,kind,attempt,mime_type,size_bytes,sha256,created_at FROM evidence_assets WHERE evidence_id = ? AND project_id = ? ORDER BY created_at", (item["evidence_id"], item["project_id"]))]
        validations = []
        for row in self._all("SELECT * FROM finding_validations WHERE finding_id = ? AND project_id = ? ORDER BY created_at", (item["id"], item["project_id"])):
            validation = dict(row)
            validation["evaluation"] = json.loads(validation.pop("evaluation_json") or "{}")
            validation["assets"] = [dict(asset) for asset in self._all("SELECT id,kind,attempt,mime_type,size_bytes,sha256,created_at FROM evidence_assets WHERE evidence_id = ? AND project_id = ? ORDER BY created_at", (validation.get("evidence_id"), item["project_id"]))] if validation.get("evidence_id") else []
            validations.append(validation)
        item["validations"] = validations
        item["validation_status"] = aggregate_validation_status(validations)
        occurrences = []
        for occurrence_row in self._all(
            "SELECT o.id,o.run_id,o.test_case_id,o.evidence_id,o.created_at,"
            "tc.title AS case_title,tc.prompt,tc.response,tc.status AS case_status,tc.evaluation_json,"
            "e.title AS evidence_title,e.content AS evidence_content "
            "FROM finding_occurrences o "
            "JOIN test_cases tc ON tc.id = o.test_case_id AND tc.project_id = o.project_id "
            "JOIN evidence e ON e.id = o.evidence_id AND e.project_id = o.project_id "
            "WHERE o.finding_id = ? AND o.project_id = ? ORDER BY o.created_at",
            (item["id"], item["project_id"]),
        ):
            occurrence = dict(occurrence_row)
            occurrence["evaluation"] = json.loads(occurrence.pop("evaluation_json") or "{}")
            occurrence["protocol_events"] = [
                self._ai_protocol_event_dict(event)
                for event in self._all(
                    "SELECT * FROM ai_protocol_events WHERE project_id = ? AND run_id = ? AND test_case_id = ? ORDER BY sequence",
                    (item["project_id"], occurrence["run_id"], occurrence["test_case_id"]),
                )
            ]
            occurrences.append(occurrence)
        item["occurrences"] = occurrences
        item["occurrence_count"] = len(occurrences)
        return item

    @staticmethod
    def _audit_dict(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["metadata"] = json.loads(item.pop("metadata_json") or "{}")
        return item

    def owasp_coverage(self, project_id: str, *, run_id: str | None = None) -> dict[str, Any]:
        self.require_project(project_id)
        query = (
            "SELECT tc.run_id,tc.module_id,tc.status,tc.generation_source,tc.evaluation_json,"
            "(SELECT fv.status FROM finding_validations fv WHERE fv.project_id = tc.project_id AND fv.run_id = tc.run_id AND fv.test_case_id = tc.id ORDER BY fv.created_at DESC LIMIT 1) AS validation_status "
            "FROM test_cases tc WHERE tc.project_id = ?"
        )
        params: tuple[Any, ...] = (project_id,)
        if run_id is not None:
            self.require_run(project_id, run_id)
            query += " AND tc.run_id = ?"
            params = (project_id, run_id)
        rows = []
        for row in self._all(query, params):
            item = dict(row)
            item["evaluation"] = json.loads(item.pop("evaluation_json") or "{}")
            generation_source = str(item.get("generation_source") or "legacy")
            item["evaluation"].setdefault(
                "execution_source",
                "model-generated" if generation_source.startswith("asus") else "native-reviewed",
            )
            rows.append(item)
        if run_id is not None:
            run = self.require_run(project_id, run_id)
            tool_run_rows = self._all(
                "SELECT id FROM testing_tool_runs WHERE project_id = ? AND assessment_run_id = ? ORDER BY started_at, id",
                (project_id, run_id),
            )
            targets = [self.get_target(project_id, run["target_id"])]
        else:
            tool_run_rows = self._all(
                "SELECT id FROM testing_tool_runs WHERE project_id = ? ORDER BY started_at, id",
                (project_id,),
            )
            targets = [self._target_dict(row) for row in self._all("SELECT * FROM targets WHERE project_id = ?", (project_id,))]
        findings_by_run: dict[str, set[str]] = {}
        for finding in self.list_tool_findings(project_id):
            findings_by_run.setdefault(str(finding["tool_run_id"]), set()).add(str(finding["outcome_id"]))
        for tool_row in tool_run_rows:
            tool_run = self.get_tool_run(project_id, tool_row["id"], include_events=False)
            for outcome in (tool_run.get("context") or {}).get("security_outcomes") or []:
                outcome_kind = str(outcome.get("kind") or "security")
                if outcome_kind not in {"security", "observation"} or not outcome.get("technique_ids"):
                    continue
                confirmed = (
                    outcome_kind == "security"
                    and outcome.get("status") == "confirmed"
                    and outcome.get("id") in findings_by_run.get(tool_run["id"], set())
                )
                outcome_status = str(outcome.get("status") or "inconclusive")
                determinate_negative = (
                    outcome_kind == "security"
                    and outcome_status == "not_demonstrated"
                    and outcome.get("determinate", True) is True
                    and tool_run.get("status") == "completed"
                )
                rows.append({
                    "run_id": run_id or tool_run["id"],
                    "module_id": "assessment-contract" if tool_run.get("assessment_run_id") else "testing-tool",
                    "status": (
                        "vulnerable" if confirmed
                        else "inconclusive" if outcome_kind == "observation"
                        else "safe" if determinate_negative
                        else "inconclusive"
                    ),
                    "validation_status": "confirmed" if confirmed else "",
                    "evaluation": {
                        "vulnerable": confirmed,
                        "owasp_risk_ids": outcome.get("risk_ids") or [],
                        "owasp_technique_ids": outcome.get("technique_ids") or [],
                        "evaluator": "deterministic-assessment-contract" if tool_run.get("assessment_run_id") else "deterministic-tool-evidence-contract",
                        "execution_source": "target-configured-contract" if tool_run.get("assessment_run_id") else "target-configured-testing-tool",
                        "outcome_id": outcome.get("id"),
                        "contract_outcome_kind": outcome_kind,
                    },
                })
        from .evaluation_profiles import evaluation_readiness
        capabilities = [{
            **(target.get("capabilities") or {}),
            **evaluation_readiness(target.get("evaluation_config") or {}),
            "assessment_contract_technique_ids": sorted({
                technique
                for contract in target.get("assessment_contracts") or []
                if contract.get("enabled")
                for technique in contract.get("technique_ids") or []
            }),
        } for target in targets]
        return build_coverage(rows, target_capabilities=capabilities)

    @staticmethod
    def _tool_definition_dict(row: sqlite3.Row | None) -> dict[str, Any]:
        if not row:
            raise NotFoundError("testing tool definition not found in project")
        item = dict(row)
        item["definition"] = json.loads(item.pop("definition_json") or "{}")
        return item

    def create_tool_definition(self, project_id: str, *, target_id: str, kind: str, name: str, description: str, definition: dict[str, Any]) -> dict[str, Any]:
        self.get_target(project_id, target_id)
        if kind not in {"workflow", "campaign"}:
            raise ValueError("testing tool kind must be workflow or campaign")
        if not name.strip():
            raise ValueError("testing tool name is required")
        timestamp = now_iso()
        item = {
            "id": new_id("tool"), "project_id": project_id, "target_id": target_id,
            "kind": kind, "name": name.strip()[:180], "description": redact_text(description, 2000),
            "definition_json": json_dumps(definition), "created_at": timestamp, "updated_at": timestamp,
        }
        self._write("INSERT INTO testing_tool_definitions(id,project_id,target_id,kind,name,description,definition_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)", tuple(item.values()))
        self.record_audit(project_id, action="testing_tool.created", object_type=kind, object_id=item["id"], metadata={"name": item["name"], "target_id": target_id})
        self.touch_project(project_id)
        return self.get_tool_definition(project_id, item["id"])

    def update_tool_definition(self, project_id: str, tool_id: str, *, target_id: str, name: str, description: str, definition: dict[str, Any]) -> dict[str, Any]:
        existing = self.get_tool_definition(project_id, tool_id)
        self.get_target(project_id, target_id)
        if not name.strip():
            raise ValueError("testing tool name is required")
        self._write(
            "UPDATE testing_tool_definitions SET target_id = ?, name = ?, description = ?, definition_json = ?, updated_at = ? WHERE id = ? AND project_id = ?",
            (target_id, name.strip()[:180], redact_text(description, 2000), json_dumps(definition), now_iso(), tool_id, project_id),
        )
        self.record_audit(project_id, action="testing_tool.updated", object_type=existing["kind"], object_id=tool_id, metadata={"name": name.strip()[:180], "target_id": target_id})
        self.touch_project(project_id)
        return self.get_tool_definition(project_id, tool_id)

    def get_tool_definition(self, project_id: str, tool_id: str) -> dict[str, Any]:
        return self._tool_definition_dict(self._one("SELECT * FROM testing_tool_definitions WHERE id = ? AND project_id = ?", (tool_id, project_id)))

    def list_tool_definitions(self, project_id: str) -> list[dict[str, Any]]:
        self.require_project(project_id)
        return [self._tool_definition_dict(row) for row in self._all("SELECT * FROM testing_tool_definitions WHERE project_id = ? ORDER BY updated_at DESC", (project_id,))]

    def delete_tool_definition(self, project_id: str, tool_id: str) -> dict[str, Any]:
        item = self.get_tool_definition(project_id, tool_id)
        self._write("DELETE FROM testing_tool_definitions WHERE id = ? AND project_id = ?", (tool_id, project_id))
        self.record_audit(project_id, action="testing_tool.deleted", object_type=item["kind"], object_id=tool_id, outcome="deleted", metadata={"name": item["name"]})
        self.touch_project(project_id)
        return {"id": tool_id, "deleted": True}

    @staticmethod
    def _tool_run_dict(row: sqlite3.Row | None) -> dict[str, Any]:
        if not row:
            raise NotFoundError("testing tool run not found in project")
        item = dict(row)
        item["definition"] = json.loads(item.pop("definition_json") or "{}")
        item["input"] = json.loads(item.pop("input_json") or "{}")
        item["manifest"] = json.loads(item.pop("manifest_json") or "{}")
        item["context"] = json.loads(item.pop("context_json") or "{}")
        return item

    def create_tool_run(self, project_id: str, *, target_id: str, kind: str, name: str, definition: dict[str, Any], input_values: dict[str, Any] | None = None, definition_id: str | None = None, assessment_run_id: str | None = None, contract_id: str = "") -> dict[str, Any]:
        target = self.assert_tool_ready(project_id, target_id)
        if kind not in {"workflow", "campaign", "replay"}:
            raise ValueError("testing tool run kind must be workflow, campaign, or replay")
        if definition_id:
            saved = self.get_tool_definition(project_id, definition_id)
            if saved["target_id"] != target_id or saved["kind"] != kind:
                raise ValueError("saved testing tool does not match the requested target and kind")
        if assessment_run_id:
            linked = self.require_run(project_id, assessment_run_id)
            if linked["target_id"] != target_id:
                raise ValueError("assessment contract tool run must use the parent assessment target")
        normalized_name = name.strip()[:180] or kind.title()
        normalized_inputs = input_values or {}
        from .telemetry import build_tool_run_manifest
        manifest = build_tool_run_manifest(
            project_id=project_id,
            target=target,
            kind=kind,
            name=normalized_name,
            definition=definition,
            input_values=normalized_inputs,
            definition_id=definition_id,
            assessment_run_id=assessment_run_id,
            contract_id=contract_id[:80],
        )
        item = {
            "id": new_id("toolrun"), "project_id": project_id, "target_id": target_id,
            "definition_id": definition_id, "assessment_run_id": assessment_run_id, "contract_id": contract_id[:80],
            "kind": kind, "name": normalized_name,
            "status": "running", "definition_json": json_dumps(definition), "input_json": json_dumps(normalized_inputs),
            "manifest_json": json_dumps(manifest),
            "context_json": "{}", "error": "", "started_at": now_iso(), "completed_at": None,
        }
        self._write("INSERT INTO testing_tool_runs(id,project_id,target_id,definition_id,assessment_run_id,contract_id,kind,name,status,definition_json,input_json,manifest_json,context_json,error,started_at,completed_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", tuple(item.values()))
        self.record_audit(project_id, action="testing_tool.run.started", object_type=kind, object_id=item["id"], metadata={"name": item["name"], "target_id": target_id, "assessment_run_id": assessment_run_id or "", "contract_id": contract_id, "manifest_sha256": manifest["manifest_sha256"]})
        self.touch_project(project_id)
        return self.get_tool_run(project_id, item["id"])

    def add_tool_event(self, project_id: str, tool_run_id: str, *, step_id: str, event_type: str, title: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
        self.get_tool_run(project_id, tool_run_id, include_events=False)
        safe_details = json.loads(redact_text(json_dumps(details or {}), 2_000_000))
        fault = fault_for_event(event_type, safe_details)
        if fault:
            safe_details.setdefault("fault", fault)
        with self._lock:
            row = self.connection.execute("SELECT COALESCE(MAX(sequence),0) AS sequence FROM testing_tool_events WHERE tool_run_id = ?", (tool_run_id,)).fetchone()
            sequence = int(row["sequence"] if row else 0) + 1
            item = {
                "id": new_id("toolevent"), "project_id": project_id, "tool_run_id": tool_run_id,
                "sequence": sequence, "step_id": step_id[:120], "event_type": event_type[:120],
                "title": title.strip()[:240] or event_type, "details_json": json_dumps(safe_details), "created_at": now_iso_precise(),
            }
            self.connection.execute("INSERT INTO testing_tool_events(id,project_id,tool_run_id,sequence,step_id,event_type,title,details_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)", tuple(item.values()))
            self.connection.commit()
        return {**item, "details": safe_details}

    @staticmethod
    def _tool_event_dict(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["details"] = json.loads(item.pop("details_json") or "{}")
        return item

    def get_tool_run(self, project_id: str, tool_run_id: str, *, include_events: bool = True) -> dict[str, Any]:
        item = self._tool_run_dict(self._one("SELECT * FROM testing_tool_runs WHERE id = ? AND project_id = ?", (tool_run_id, project_id)))
        item["security_findings"] = self.list_tool_findings(project_id, tool_run_id=tool_run_id)
        item["adjudications"] = self.list_adjudications(project_id, execution_kind="tool", execution_id=tool_run_id) if include_events else []
        if include_events:
            item["events"] = [self._tool_event_dict(row) for row in self._all("SELECT * FROM testing_tool_events WHERE tool_run_id = ? AND project_id = ? ORDER BY sequence", (tool_run_id, project_id))]
            item["counts"] = {
                "requests": len([event for event in item["events"] if event["event_type"] == "request.sent"]),
                "responses": len([event for event in item["events"] if event["event_type"] == "response.received"]),
                "assertions_passed": len([event for event in item["events"] if event["event_type"] == "assertion.passed"]),
                "assertions_failed": len([event for event in item["events"] if event["event_type"] == "assertion.failed"]),
            }
            from .telemetry import analyze_tool_run
            item["metrics"] = analyze_tool_run(item)
        else:
            item["metrics"] = (item.get("context") or {}).get("telemetry_metrics") or {}
        return item

    @staticmethod
    def _tool_finding_dict(row: sqlite3.Row | None) -> dict[str, Any]:
        if not row:
            raise NotFoundError("testing tool finding not found in project")
        item = dict(row)
        item["risk_ids"] = json.loads(item.pop("risk_ids_json") or "[]")
        item["technique_ids"] = json.loads(item.pop("technique_ids_json") or "[]")
        item["required_step_ids"] = json.loads(item.pop("required_step_ids_json") or "[]")
        item["evidence_event_ids"] = json.loads(item.pop("evidence_event_ids_json") or "[]")
        return item

    def add_tool_finding(
        self,
        project_id: str,
        *,
        tool_run_id: str,
        target_id: str,
        outcome_id: str,
        title: str,
        summary: str,
        severity: str,
        confidence: float,
        risk_ids: list[str],
        technique_ids: list[str],
        required_step_ids: list[str],
        confirmation: str,
    ) -> dict[str, Any]:
        self.get_tool_run(project_id, tool_run_id, include_events=False)
        self.get_target(project_id, target_id)
        evidence_rows = self._all(
            "SELECT id FROM testing_tool_events WHERE project_id = ? AND tool_run_id = ? "
            f"AND step_id IN ({','.join('?' for _ in required_step_ids)}) "
            "AND event_type IN ('request.sent','response.received','assertion.passed') ORDER BY sequence",
            (project_id, tool_run_id, *required_step_ids),
        )
        if not evidence_rows:
            raise ValueError("tool finding requires retained request, response, and assertion evidence")
        timestamp = now_iso()
        existing = self._one(
            "SELECT * FROM testing_tool_findings WHERE project_id = ? AND tool_run_id = ? AND outcome_id = ?",
            (project_id, tool_run_id, outcome_id),
        )
        if existing:
            return self._tool_finding_dict(existing)
        item = {
            "id": new_id("toolfinding"), "project_id": project_id, "tool_run_id": tool_run_id,
            "target_id": target_id, "outcome_id": outcome_id, "title": title[:240],
            "summary": redact_text(summary, 5000), "severity": severity,
            "confidence": max(0.0, min(1.0, float(confidence))),
            "risk_ids_json": json_dumps(risk_ids), "technique_ids_json": json_dumps(technique_ids),
            "required_step_ids_json": json_dumps(required_step_ids),
            "evidence_event_ids_json": json_dumps([row["id"] for row in evidence_rows]),
            "confirmation": confirmation[:80], "status": "open",
            "created_at": timestamp, "updated_at": timestamp,
        }
        self._write(
            "INSERT INTO testing_tool_findings(id,project_id,tool_run_id,target_id,outcome_id,title,summary,severity,confidence,risk_ids_json,technique_ids_json,required_step_ids_json,evidence_event_ids_json,confirmation,status,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            tuple(item.values()),
        )
        self.record_audit(project_id, action="testing_tool.finding.created", object_type="tool_finding", object_id=item["id"], metadata={"tool_run_id": tool_run_id, "outcome_id": outcome_id, "risk_ids": risk_ids, "technique_ids": technique_ids})
        self.touch_project(project_id)
        return self._tool_finding_dict(self._one("SELECT * FROM testing_tool_findings WHERE id = ?", (item["id"],)))

    def list_tool_findings(self, project_id: str, *, tool_run_id: str | None = None) -> list[dict[str, Any]]:
        self.require_project(project_id)
        query = "SELECT * FROM testing_tool_findings WHERE project_id = ?"
        params: tuple[Any, ...] = (project_id,)
        if tool_run_id:
            query += " AND tool_run_id = ?"
            params = (project_id, tool_run_id)
        query += " ORDER BY CASE status WHEN 'open' THEN 0 ELSE 1 END, updated_at DESC"
        return [self._tool_finding_dict(row) for row in self._all(query, params)]

    def update_tool_finding_status(self, project_id: str, finding_id: str, status: str) -> dict[str, Any]:
        if status not in {"open", "accepted", "rejected", "fixed"}:
            raise ValueError("invalid finding status")
        finding = self._tool_finding_dict(self._one("SELECT * FROM testing_tool_findings WHERE id = ? AND project_id = ?", (finding_id, project_id)))
        self._write("UPDATE testing_tool_findings SET status = ?, updated_at = ? WHERE id = ? AND project_id = ?", (status, now_iso(), finding_id, project_id))
        classification = "true_positive" if status == "accepted" else "false_positive" if status == "rejected" else "inconclusive"
        self.upsert_adjudication(
            project_id, execution_kind="tool", execution_id=finding["tool_run_id"], source="human",
            expectation_id=finding["outcome_id"], expected_outcome="vulnerable",
            observed_outcome="vulnerable" if status in {"accepted", "fixed"} else "secure" if status == "rejected" else "unknown",
            classification=classification, root_cause="none" if status in {"accepted", "fixed"} else "evaluator" if status == "rejected" else "unclassified",
            notes=f"Tool finding review status changed to {status}.", metadata={"tool_finding_id": finding_id},
        )
        self.record_audit(project_id, action="testing_tool.finding.reviewed", object_type="tool_finding", object_id=finding_id, outcome=status, metadata={"tool_run_id": finding["tool_run_id"]})
        self.touch_project(project_id)
        return self._tool_finding_dict(self._one("SELECT * FROM testing_tool_findings WHERE id = ? AND project_id = ?", (finding_id, project_id)))

    def list_tool_runs(self, project_id: str, *, limit: int = 40) -> list[dict[str, Any]]:
        self.require_project(project_id)
        rows = self._all("SELECT * FROM testing_tool_runs WHERE project_id = ? ORDER BY started_at DESC LIMIT ?", (project_id, max(1, min(200, int(limit)))))
        return [self.get_tool_run(project_id, row["id"], include_events=False) for row in rows]

    def complete_tool_run(self, project_id: str, tool_run_id: str, *, status: str, context: dict[str, Any] | None = None, error: str = "") -> dict[str, Any]:
        if status not in {"completed", "completed_with_errors", "blocked", "cancelled", "interrupted"}:
            raise ValueError("invalid testing tool run status")
        item = self.get_tool_run(project_id, tool_run_id, include_events=False)
        final_context = dict(context or {})
        self._write("UPDATE testing_tool_runs SET status = ?, context_json = ?, error = ?, completed_at = ? WHERE id = ? AND project_id = ?", (status, json_dumps(final_context), redact_text(error, 10000), now_iso(), tool_run_id, project_id))
        self.refresh_tool_run_metrics(project_id, tool_run_id)
        self.record_audit(project_id, action="testing_tool.run.completed", object_type=item["kind"], object_id=tool_run_id, outcome=status, metadata={"error": error[:500]})
        self.touch_project(project_id)
        return self.get_tool_run(project_id, tool_run_id)

    def refresh_tool_run_metrics(self, project_id: str, tool_run_id: str) -> dict[str, Any]:
        detail = self.get_tool_run(project_id, tool_run_id)
        metrics = detail.get("metrics") or {}
        context = dict(detail.get("context") or {})
        context["telemetry_metrics"] = metrics
        self._write("UPDATE testing_tool_runs SET context_json = ? WHERE id = ? AND project_id = ?", (json_dumps(context), tool_run_id, project_id))
        return metrics

    @staticmethod
    def _interaction_token_dict(row: sqlite3.Row | None) -> dict[str, Any]:
        if not row:
            raise NotFoundError("interaction token not found in project")
        return dict(row)

    def create_interaction_token(self, project_id: str, *, name: str, target_id: str | None = None) -> dict[str, Any]:
        self.require_project(project_id)
        if target_id:
            self.get_target(project_id, target_id)
        item = {
            "id": new_id("interaction"), "project_id": project_id, "target_id": target_id,
            "name": name.strip()[:180] or "Interaction token", "token": uuid.uuid4().hex + uuid.uuid4().hex[:8],
            "status": "active", "created_at": now_iso(), "last_seen_at": None,
        }
        self._write("INSERT INTO interaction_tokens(id,project_id,target_id,name,token,status,created_at,last_seen_at) VALUES(?,?,?,?,?,?,?,?)", tuple(item.values()))
        self.record_audit(project_id, action="interaction_token.created", object_type="interaction_token", object_id=item["id"], metadata={"name": item["name"], "target_id": target_id or ""})
        self.touch_project(project_id)
        return {**item, "events": []}

    def get_interaction_token(self, project_id: str, token_id: str) -> dict[str, Any]:
        item = self._interaction_token_dict(self._one("SELECT * FROM interaction_tokens WHERE id = ? AND project_id = ?", (token_id, project_id)))
        item["events"] = [self._interaction_event_dict(row) for row in self._all("SELECT * FROM interaction_events WHERE interaction_token_id = ? AND project_id = ? ORDER BY created_at DESC", (token_id, project_id))]
        return item

    def list_interaction_tokens(self, project_id: str) -> list[dict[str, Any]]:
        self.require_project(project_id)
        return [self.get_interaction_token(project_id, row["id"]) for row in self._all("SELECT id FROM interaction_tokens WHERE project_id = ? ORDER BY created_at DESC", (project_id,))]

    def disable_interaction_token(self, project_id: str, token_id: str) -> dict[str, Any]:
        item = self.get_interaction_token(project_id, token_id)
        self._write("UPDATE interaction_tokens SET status = 'disabled' WHERE id = ? AND project_id = ?", (token_id, project_id))
        self.record_audit(project_id, action="interaction_token.disabled", object_type="interaction_token", object_id=token_id, outcome="disabled")
        return {**item, "status": "disabled"}

    @staticmethod
    def _interaction_event_dict(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["headers"] = json.loads(item.pop("headers_json") or "{}")
        return item

    def record_interaction(self, token: str, *, method: str, path: str, source: str, headers: dict[str, Any], body: str) -> dict[str, Any] | None:
        row = self._one("SELECT * FROM interaction_tokens WHERE token = ?", (token,))
        if not row or row["status"] != "active":
            return None
        secret_header_names = {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "api-key", "x-auth-token"}
        safe_headers = {
            str(key)[:200]: "[REDACTED]" if str(key).casefold() in secret_header_names else redact_text(str(value), 10000)
            for key, value in headers.items()
        }
        item = {
            "id": new_id("callback"), "project_id": row["project_id"], "interaction_token_id": row["id"],
            "method": str(method).upper()[:12], "path": redact_text(path, 2000), "source": redact_text(source, 300),
            "headers_json": json_dumps(safe_headers), "body": redact_text(body, 200000), "created_at": now_iso_precise(),
        }
        with self._lock:
            self.connection.execute("INSERT INTO interaction_events(id,project_id,interaction_token_id,method,path,source,headers_json,body,created_at) VALUES(?,?,?,?,?,?,?,?,?)", tuple(item.values()))
            self.connection.execute("UPDATE interaction_tokens SET last_seen_at = ? WHERE id = ?", (item["created_at"], row["id"]))
            self.connection.commit()
        self.record_audit(row["project_id"], action="interaction.observed", object_type="interaction_token", object_id=row["id"], metadata={"method": item["method"], "source": item["source"]})
        return {**item, "headers": safe_headers}

    def interaction_seen(self, project_id: str, token: str) -> bool:
        row = self._one("SELECT id FROM interaction_tokens WHERE project_id = ? AND token = ?", (project_id, token))
        if not row:
            raise NotFoundError("interaction token not found in project")
        event = self._one("SELECT id FROM interaction_events WHERE project_id = ? AND interaction_token_id = ? LIMIT 1", (project_id, row["id"]))
        return bool(event)

    def assert_tool_ready(self, project_id: str, target_id: str) -> dict[str, Any]:
        target = self.get_target(project_id, target_id)
        kinds = {row["kind"] for row in self._all("SELECT kind FROM project_documents WHERE project_id = ?", (project_id,))}
        missing = []
        if "scope" not in kinds:
            missing.append("scope document")
        if "policy" not in kinds:
            missing.append("policy document")
        if not target.get("scope_confirmed"):
            missing.append("target authorization confirmation")
        if not target.get("base_url"):
            missing.append("absolute target base URL")
        try:
            guardrail = self.get_guardrail(project_id, target_id)
            if guardrail.get("status") != "approved":
                missing.append("approved execution guardrail")
        except NotFoundError:
            missing.append("approved execution guardrail")
        if missing:
            self.record_audit(project_id, action="testing_tool.blocked", object_type="target", object_id=target_id, outcome="blocked", metadata={"missing": ", ".join(missing)})
            raise ValueError("scope gate blocked the testing tool; missing " + ", ".join(missing))
        return target

    def assert_run_ready(self, project_id: str, target_id: str) -> dict[str, Any]:
        target = self.get_target(project_id, target_id)
        kinds = {row["kind"] for row in self._all("SELECT kind FROM project_documents WHERE project_id = ?", (project_id,))}
        missing = []
        if "scope" not in kinds:
            missing.append("scope document")
        if "policy" not in kinds:
            missing.append("policy document")
        if not target.get("scope_confirmed"):
            missing.append("target authorization confirmation")
        evaluation_config = target.get("evaluation_config") or {}
        has_native_protocol_adapter = any(
            bool((evaluation_config.get(profile_name) or {}).get("enabled"))
            for profile_name in ("mcp", "rag", "artifact")
        )
        if (
            target.get("kind") not in {"chatbot", "browser-chatbot"}
            and not has_native_protocol_adapter
            and not any(item.get("enabled") for item in target.get("assessment_contracts") or [])
        ):
            missing.append("executable chatbot adapter, native protocol/artifact adapter, or autonomous assessment contract")
        if not str(target.get("path") or "").strip():
            missing.append("explicit target path")
        if not str(target.get("method") or "").strip():
            missing.append("explicit target HTTP method")
        if target.get("kind") == "chatbot" and "{{prompt}}" not in json_dumps(target.get("request_template") or {}):
            missing.append("explicit chatbot request template")
        if target.get("kind") == "browser-chatbot" and not target.get("browser_profile"):
            missing.append("browser selectors")
        try:
            guardrail = self.get_guardrail(project_id, target_id)
            if guardrail.get("status") != "approved":
                missing.append("approved execution guardrail")
        except NotFoundError:
            missing.append("approved execution guardrail")
        if missing:
            self.record_audit(project_id, action="assessment.blocked", object_type="target", object_id=target_id, outcome="blocked", metadata={"missing": ", ".join(missing)})
            raise ValueError("scope gate blocked the run; missing " + ", ".join(missing))
        return target

    def assert_recon_ready(self, project_id: str, target_id: str) -> dict[str, Any]:
        target = self.get_target(project_id, target_id)
        kinds = {row["kind"] for row in self._all("SELECT kind FROM project_documents WHERE project_id = ?", (project_id,))}
        missing = []
        if "scope" not in kinds:
            missing.append("scope document")
        if "policy" not in kinds:
            missing.append("policy document")
        if not target.get("scope_confirmed"):
            missing.append("target authorization confirmation")
        if not target.get("base_url"):
            missing.append("absolute target base URL")
        try:
            guardrail = self.get_guardrail(project_id, target_id)
            if guardrail.get("status") != "approved":
                missing.append("approved execution guardrail")
            elif not guardrail.get("allow_active_recon"):
                missing.append("active reconnaissance permission")
        except NotFoundError:
            missing.append("approved execution guardrail")
        if missing:
            self.record_audit(project_id, action="recon.blocked", object_type="target", object_id=target_id, outcome="blocked", metadata={"missing": ", ".join(missing)})
            raise ValueError("scope gate blocked reconnaissance; missing " + ", ".join(missing))
        return target

    def require_project(self, project_id: str) -> dict[str, Any]:
        row = self._one("SELECT * FROM projects WHERE id = ?", (project_id,))
        if not row:
            raise NotFoundError("project not found")
        return dict(row)

    def touch_project(self, project_id: str) -> None:
        # Report acceptance is tied to the exact project revision. Millisecond
        # precision prevents two legitimate changes in the same second from
        # leaving a previously accepted report looking current.
        self._write(
            "UPDATE projects SET updated_at = ? WHERE id = ?",
            (datetime.now(timezone.utc).isoformat(timespec="microseconds"), project_id),
        )

    def project_context(self, project_id: str, *, target_id: str | None = None) -> str:
        """Build model context without mixing target-specific authority records.

        Projects may retain historical targets and their immutable scope documents.
        A live run must receive only scope records that apply to its active target,
        plus project-wide policies and generic scope records.  Callers that do not
        identify a target retain the legacy project-wide view for administrative
        summaries and compatibility.
        """
        self.require_project(project_id)
        documents = self.list_documents(project_id)
        all_targets = [
            self.get_target(project_id, row["id"])
            for row in self._all("SELECT id FROM targets WHERE project_id = ?", (project_id,))
        ]
        targets = all_targets
        heading = "PROJECT CONTEXT (use only this project's material):"
        if target_id:
            active_target = self.get_target(project_id, target_id)
            targets = [active_target]
            heading = "PROJECT CONTEXT (active target authority and project policy only):"
            known_target_urls = {
                str(item.get("base_url") or "").rstrip("/")
                for item in all_targets
                if str(item.get("base_url") or "").strip()
            }
            active_url = str(active_target.get("base_url") or "").rstrip("/")
            try:
                source_document_id = str(self.get_guardrail(project_id, target_id).get("source_document_id") or "")
            except NotFoundError:
                source_document_id = ""

            scoped_documents = []
            for document in documents:
                if document.get("kind") != "scope":
                    scoped_documents.append(document)
                    continue
                content = str(document.get("content") or "")
                mentioned_urls = {url for url in known_target_urls if url and url in content}
                is_explicit_source = bool(source_document_id and document.get("id") == source_document_id)
                is_active_scope = bool(active_url and active_url in content)
                is_generic_scope = not mentioned_urls
                if is_explicit_source or is_active_scope or is_generic_scope:
                    scoped_documents.append(document)
            documents = scoped_documents

        parts = [heading]
        for doc in documents:
            parts.append(f"[{doc['kind'].upper()} {doc['filename']}]\n{doc['content'][:6000]}")
        for target in targets:
            label = "ACTIVE TARGET" if target_id else "TARGET"
            parts.append(f"[{label} {target['name']}] kind={target['kind']} description={target['description'][:500]}")
        return "\n\n".join(parts)[:24000]
