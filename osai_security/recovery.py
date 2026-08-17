from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, TYPE_CHECKING

from .release import (
    DATABASE_SCHEMA_VERSION,
    LOCAL_BACKUP_SCHEMA_VERSION,
    PRODUCT_VERSION,
    PROJECT_TRANSFER_SCHEMA_VERSION,
)

if TYPE_CHECKING:
    from .config import AppConfig
    from .db import Repository


MAX_ARCHIVE_FILES = 100_000
MAX_ARCHIVE_BYTES = 20 * 1024 * 1024 * 1024
_COPY_CHUNK = 1024 * 1024
_SECRET_KEYS = {
    "api_key", "apikey", "access_token", "auth_token", "bearer_token",
    "client_secret", "password", "private_key", "secret", "session_token",
}


class RecoveryError(ValueError):
    pass


def _now_compact() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_COPY_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_json_write(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(document, handle, indent=2, sort_keys=True)
            handle.write("\n")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _database_inventory(connection: sqlite3.Connection) -> dict[str, Any]:
    tables = [
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )
    ]
    counts: dict[str, int] = {}
    for table in ("projects", "test_runs", "evidence", "evidence_assets", "findings", "project_artifacts"):
        if table in tables:
            counts[table] = int(connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])
    return {
        "schema_version": int(connection.execute("PRAGMA user_version").fetchone()[0]),
        "tables": tables,
        "counts": counts,
    }


def create_pre_migration_backup(
    connection: sqlite3.Connection,
    database_path: str | Path,
    *,
    source_schema: int,
    target_schema: int,
) -> dict[str, Any]:
    """Create and verify an online SQLite backup before any schema mutation."""
    source = Path(database_path).resolve()
    root = source.parent / "backups" / "migrations"
    root.mkdir(parents=True, exist_ok=True)
    stem = f"{source.stem}-schema-{source_schema}-to-{target_schema}-{_now_compact()}"
    destination = root / f"{stem}.sqlite3"
    temporary = root / f".{stem}.{uuid.uuid4().hex}.tmp"
    backup_connection = sqlite3.connect(temporary)
    try:
        connection.backup(backup_connection)
        integrity = str(backup_connection.execute("PRAGMA integrity_check").fetchone()[0])
        foreign_key_errors = list(backup_connection.execute("PRAGMA foreign_key_check"))
        inventory = _database_inventory(backup_connection)
    finally:
        backup_connection.close()
    if integrity != "ok" or foreign_key_errors:
        temporary.unlink(missing_ok=True)
        raise RecoveryError("pre-migration database backup failed integrity verification")
    temporary.replace(destination)
    digest = _sha256_file(destination)
    manifest = {
        "kind": "adverscope-pre-migration-backup",
        "schema_version": LOCAL_BACKUP_SCHEMA_VERSION,
        "created_at": _now_iso(),
        "product_version": PRODUCT_VERSION,
        "source_database": source.name,
        "source_schema": source_schema,
        "target_schema": target_schema,
        "database_file": destination.name,
        "database_sha256": digest,
        "inventory": inventory,
        "recovery": "Stop AdverScope and use the adjacent verified SQLite file if automatic rollback cannot complete.",
    }
    manifest_path = destination.with_suffix(".manifest.json")
    _safe_json_write(manifest_path, manifest)
    return {
        "path": str(destination),
        "manifest_path": str(manifest_path),
        "sha256": digest,
        "inventory": inventory,
    }


def restore_database_file(database_path: str | Path, backup_path: str | Path) -> None:
    destination = Path(database_path).resolve()
    source = Path(backup_path).resolve()
    if not source.is_file():
        raise RecoveryError("database rollback file is missing")
    check = sqlite3.connect(f"file:{source.as_posix()}?mode=ro", uri=True)
    try:
        if str(check.execute("PRAGMA integrity_check").fetchone()[0]) != "ok":
            raise RecoveryError("database rollback file failed integrity verification")
    finally:
        check.close()
    temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.restore")
    shutil.copy2(source, temporary)
    for suffix in ("-wal", "-shm"):
        Path(f"{destination}{suffix}").unlink(missing_ok=True)
    temporary.replace(destination)


def _safe_member_name(name: str) -> str:
    normalized = str(name).replace("\\", "/")
    path = PurePosixPath(normalized)
    if not normalized or normalized.startswith("/") or path.is_absolute() or ".." in path.parts:
        raise RecoveryError("archive contains an unsafe path")
    if any(part in {"", "."} for part in path.parts):
        raise RecoveryError("archive contains a malformed path")
    return path.as_posix()


def _zip_is_symlink(info: zipfile.ZipInfo) -> bool:
    return ((info.external_attr >> 16) & 0o170000) == 0o120000


def _read_manifest(archive: zipfile.ZipFile) -> dict[str, Any]:
    try:
        raw = archive.read("manifest.json")
        document = json.loads(raw.decode("utf-8"))
    except (KeyError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RecoveryError("archive manifest is missing or invalid") from exc
    if not isinstance(document, dict):
        raise RecoveryError("archive manifest must be a JSON object")
    return document


def verify_archive(path: str | Path, *, expected_kind: str | None = None) -> dict[str, Any]:
    source = Path(path).expanduser().resolve()
    if not source.is_file():
        raise RecoveryError(f"archive does not exist: {source}")
    try:
        archive = zipfile.ZipFile(source, "r")
    except (OSError, zipfile.BadZipFile) as exc:
        raise RecoveryError("archive is not a readable ZIP file") from exc
    with archive:
        infos = archive.infolist()
        if len(infos) > MAX_ARCHIVE_FILES:
            raise RecoveryError("archive contains too many files")
        names: set[str] = set()
        total = 0
        for info in infos:
            name = _safe_member_name(info.filename)
            if name in names:
                raise RecoveryError("archive contains duplicate paths")
            if _zip_is_symlink(info):
                raise RecoveryError("archive contains a symbolic link")
            names.add(name)
            total += int(info.file_size)
            if total > MAX_ARCHIVE_BYTES:
                raise RecoveryError("archive exceeds the supported expanded size")
        manifest = _read_manifest(archive)
        if expected_kind and manifest.get("kind") != expected_kind:
            raise RecoveryError(f"archive kind must be {expected_kind}")
        declared = manifest.get("files")
        if not isinstance(declared, list):
            raise RecoveryError("archive manifest has no file inventory")
        declared_names: set[str] = set()
        for item in declared:
            if not isinstance(item, dict):
                raise RecoveryError("archive file inventory is malformed")
            name = _safe_member_name(str(item.get("path") or ""))
            if name in declared_names:
                raise RecoveryError("archive manifest contains duplicate paths")
            declared_names.add(name)
            if name not in names:
                raise RecoveryError(f"archive is missing declared file: {name}")
            digest = hashlib.sha256()
            size = 0
            with archive.open(name, "r") as handle:
                for chunk in iter(lambda: handle.read(_COPY_CHUNK), b""):
                    size += len(chunk)
                    digest.update(chunk)
            if size != int(item.get("size_bytes", -1)) or digest.hexdigest() != str(item.get("sha256") or ""):
                raise RecoveryError(f"archive integrity verification failed for {name}")
        if names != declared_names | {"manifest.json"}:
            raise RecoveryError("archive contains undeclared files")
        result = dict(manifest)
        result["archive_path"] = str(source)
        result["archive_sha256"] = _sha256_file(source)
        result["verified"] = True
        return result


def _write_archive(
    destination: Path,
    *,
    kind: str,
    schema_version: str,
    metadata: dict[str, Any],
    files: list[tuple[str, Path]],
) -> dict[str, Any]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
    inventory: list[dict[str, Any]] = []
    seen: set[str] = set()
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
            for archive_name, source in sorted(files, key=lambda item: item[0]):
                name = _safe_member_name(archive_name)
                if name in seen or name == "manifest.json":
                    raise RecoveryError("duplicate archive path")
                seen.add(name)
                if source.is_symlink() or not source.is_file():
                    raise RecoveryError(f"archive source is not a regular file: {source}")
                digest = _sha256_file(source)
                size = int(source.stat().st_size)
                archive.write(source, name)
                inventory.append({"path": name, "size_bytes": size, "sha256": digest})
            manifest = {
                "kind": kind,
                "schema_version": schema_version,
                "created_at": _now_iso(),
                "product_version": PRODUCT_VERSION,
                **metadata,
                "files": inventory,
            }
            archive.writestr("manifest.json", json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)
    return verify_archive(destination, expected_kind=kind)


def _project_files(evidence_root: Path, project_id: str, *, include_browser_sessions: bool) -> list[tuple[str, Path]]:
    directory = (evidence_root / project_id).resolve()
    if evidence_root.resolve() not in directory.parents:
        raise RecoveryError("project evidence directory escaped the configured root")
    if not directory.exists():
        return []
    result: list[tuple[str, Path]] = []
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise RecoveryError("project evidence contains a symbolic link")
        if not path.is_file():
            continue
        relative = path.relative_to(directory).as_posix()
        if not include_browser_sessions and relative.startswith("_browser_sessions/"):
            continue
        result.append((f"evidence/{project_id}/{relative}", path))
    return result


def _database_file_records(connection: sqlite3.Connection, project_ids: list[str] | None = None) -> list[dict[str, Any]]:
    parameters: tuple[Any, ...] = ()
    project_filter = ""
    if project_ids is not None:
        if not project_ids:
            return []
        placeholders = ",".join("?" for _ in project_ids)
        project_filter = f" WHERE project_id IN ({placeholders})"
        parameters = tuple(project_ids)
    rows = connection.execute(
        "SELECT project_id,relative_path,size_bytes,sha256,'evidence-asset' AS record_kind FROM evidence_assets"
        f"{project_filter} UNION ALL "
        "SELECT project_id,relative_path,size_bytes,sha256,'project-artifact' AS record_kind FROM project_artifacts"
        f"{project_filter} ORDER BY project_id,relative_path,record_kind",
        parameters + parameters,
    ).fetchall()
    return [
        {
            "project_id": str(row[0]),
            "relative_path": str(row[1]),
            "size_bytes": int(row[2]),
            "sha256": str(row[3]),
            "record_kind": str(row[4]),
        }
        for row in rows
    ]


def _verify_retained_files(records: list[dict[str, Any]], evidence_root: Path) -> None:
    root = evidence_root.resolve()
    seen: dict[str, tuple[int, str]] = {}
    for record in records:
        project_id = str(record.get("project_id") or "")
        relative = _safe_member_name(str(record.get("relative_path") or ""))
        parts = PurePosixPath(relative).parts
        if not parts or parts[0] != project_id:
            raise RecoveryError(f"retained {record.get('record_kind')} path is outside its project")
        candidate = root / Path(*parts)
        path = candidate.resolve()
        if root not in path.parents or candidate.is_symlink() or not path.is_file():
            raise RecoveryError(f"retained {record.get('record_kind')} file is missing or unsafe: {relative}")
        size = int(record.get("size_bytes", -1))
        digest = str(record.get("sha256") or "")
        previous = seen.get(relative)
        if previous and previous != (size, digest):
            raise RecoveryError(f"retained file metadata conflicts for {relative}")
        seen[relative] = (size, digest)
        if path.stat().st_size != size or _sha256_file(path) != digest:
            raise RecoveryError(f"retained file integrity verification failed: {relative}")


def export_project(
    repository: "Repository",
    evidence_root: str | Path,
    project_id: str,
    destination: str | Path,
    *,
    acknowledge_sensitive: bool,
    include_browser_sessions: bool = False,
) -> dict[str, Any]:
    if not acknowledge_sensitive:
        raise RecoveryError("project transfer requires explicit sensitive-data acknowledgement")
    project = repository.get_project(project_id)
    evidence = Path(evidence_root).resolve()
    _verify_retained_files(repository.retained_file_records([project_id]), evidence)
    target = Path(destination).expanduser().resolve()
    with tempfile.TemporaryDirectory(prefix="adverscope-project-export-") as temporary_directory:
        snapshot = Path(temporary_directory) / "project.sqlite3"
        repository.export_project_snapshot(project_id, snapshot)
        files = [("database/project.sqlite3", snapshot)]
        files.extend(_project_files(evidence, project_id, include_browser_sessions=include_browser_sessions))
        result = _write_archive(
            target,
            kind="adverscope-project-transfer",
            schema_version=PROJECT_TRANSFER_SCHEMA_VERSION,
            metadata={
                "database_schema": DATABASE_SCHEMA_VERSION,
                "project": {"id": project_id, "name": project["name"], "classification": project["data_classification"]},
                "evidence_policy": {
                    "assessment_evidence_included": True,
                    "artifact_bytes_included": True,
                    "browser_sessions_included": bool(include_browser_sessions),
                    "contains_sensitive_data": True,
                },
            },
            files=files,
        )
    return result


def _extract_verified_archive(path: Path, destination: Path, *, expected_kind: str) -> dict[str, Any]:
    manifest = verify_archive(path, expected_kind=expected_kind)
    with zipfile.ZipFile(path, "r") as archive:
        for info in archive.infolist():
            name = _safe_member_name(info.filename)
            target = (destination / Path(*PurePosixPath(name).parts)).resolve()
            if destination.resolve() not in target.parents:
                raise RecoveryError("archive extraction escaped the staging directory")
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info, "r") as source, target.open("xb") as output:
                shutil.copyfileobj(source, output, length=_COPY_CHUNK)
    return manifest


def import_project(
    repository: "Repository",
    evidence_root: str | Path,
    archive_path: str | Path,
    *,
    acknowledge_sensitive: bool,
) -> dict[str, Any]:
    if not acknowledge_sensitive:
        raise RecoveryError("project transfer requires explicit sensitive-data acknowledgement")
    source = Path(archive_path).expanduser().resolve()
    evidence = Path(evidence_root).resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="adverscope-project-import-", dir=evidence.parent) as temporary_directory:
        staging = Path(temporary_directory)
        manifest = _extract_verified_archive(source, staging, expected_kind="adverscope-project-transfer")
        if str(manifest.get("schema_version")) != PROJECT_TRANSFER_SCHEMA_VERSION:
            raise RecoveryError("project transfer schema is not supported")
        project = manifest.get("project") if isinstance(manifest.get("project"), dict) else {}
        project_id = str(project.get("id") or "")
        if not project_id:
            raise RecoveryError("project transfer has no project identifier")
        snapshot = staging / "database" / "project.sqlite3"
        incoming_evidence = staging / "evidence" / project_id
        snapshot_connection = sqlite3.connect(f"file:{snapshot.as_posix()}?mode=ro", uri=True)
        try:
            _verify_retained_files(_database_file_records(snapshot_connection, [project_id]), staging / "evidence")
        finally:
            snapshot_connection.close()
        final_evidence = (evidence / project_id).resolve()
        if evidence not in final_evidence.parents or final_evidence.exists():
            raise RecoveryError("destination already contains this project evidence directory")
        moved = False

        def install_evidence() -> None:
            nonlocal moved
            if incoming_evidence.exists():
                incoming_evidence.replace(final_evidence)
            else:
                final_evidence.mkdir(parents=True, exist_ok=False)
            moved = True

        try:
            imported = repository.import_project_snapshot(snapshot, project_id, before_commit=install_evidence)
        except Exception:
            if moved:
                shutil.rmtree(final_evidence, ignore_errors=True)
            raise
    return {"imported": True, "project": imported, "archive_sha256": manifest["archive_sha256"]}


def _non_secret_configuration(config: "AppConfig") -> dict[str, Any]:
    return {
        "host": config.host,
        "port": int(config.port),
        "llm_provider": config.llm_provider,
        "llm_base_url": config.llm_base_url,
        "llm_model": config.llm_model,
        "llm_timeout_seconds": config.llm_timeout_seconds,
        "target_timeout_seconds": config.target_timeout_seconds,
        "ssh_tunnel": bool(config.ssh_tunnel),
        "gx10_user": config.gx10_user,
        "gx10_host": config.gx10_host,
        "ssh_local_port": int(config.ssh_local_port),
        "ssh_remote_port": int(config.ssh_remote_port),
        "browser_executable": config.browser_executable,
        "browser_timeout_seconds": config.browser_timeout_seconds,
        "restore_note": "Storage paths are intentionally rebound to the destination installation during restore.",
    }


def _contains_secret(value: Any) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).casefold().replace("-", "_")
            if normalized in _SECRET_KEYS and item not in (None, ""):
                return True
            if _contains_secret(item):
                return True
    elif isinstance(value, list):
        return any(_contains_secret(item) for item in value)
    return False


def create_local_backup(
    repository: "Repository",
    config: "AppConfig",
    destination: str | Path,
    *,
    acknowledge_sensitive: bool,
    include_browser_sessions: bool = False,
) -> dict[str, Any]:
    if not acknowledge_sensitive:
        raise RecoveryError("local backup requires explicit sensitive-data acknowledgement")
    target = Path(destination).expanduser().resolve()
    with tempfile.TemporaryDirectory(prefix="adverscope-local-backup-") as temporary_directory:
        root = Path(temporary_directory)
        database = root / "adverscope.sqlite3"
        repository.database_snapshot(database)
        configuration = root / "configuration.json"
        _safe_json_write(configuration, _non_secret_configuration(config))
        files: list[tuple[str, Path]] = [
            ("database/adverscope.sqlite3", database),
            ("configuration/configuration.json", configuration),
        ]
        provider_path = Path(config.model_profiles_path)
        if provider_path.is_file():
            try:
                provider_document = json.loads(provider_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise RecoveryError("model provider configuration could not be backed up") from exc
            if not isinstance(provider_document, dict) or _contains_secret(provider_document):
                raise RecoveryError("model provider configuration contains a persisted secret")
            files.append(("configuration/model-providers.json", provider_path))
        project_ids = repository.project_ids()
        _verify_retained_files(repository.retained_file_records(project_ids), Path(config.evidence_root).resolve())
        for project_id in project_ids:
            files.extend(_project_files(Path(config.evidence_root).resolve(), project_id, include_browser_sessions=include_browser_sessions))
        result = _write_archive(
            target,
            kind="adverscope-local-backup",
            schema_version=LOCAL_BACKUP_SCHEMA_VERSION,
            metadata={
                "database_schema": DATABASE_SCHEMA_VERSION,
                "project_count": len(project_ids),
                "project_ids_sha256": hashlib.sha256("\n".join(sorted(project_ids)).encode("utf-8")).hexdigest(),
                "evidence_policy": {
                    "assessment_evidence_included": True,
                    "artifact_bytes_included": True,
                    "browser_sessions_included": bool(include_browser_sessions),
                    "contains_sensitive_data": True,
                },
            },
            files=files,
        )
    return result


def _remove_database_sidecars(path: Path) -> None:
    for suffix in ("-wal", "-shm"):
        Path(f"{path}{suffix}").unlink(missing_ok=True)


def _snapshot_stopped_database(source: Path, destination: Path) -> None:
    if not source.is_file():
        return
    input_connection = sqlite3.connect(f"file:{source.as_posix()}?mode=ro", uri=True)
    output_connection = sqlite3.connect(destination)
    try:
        input_connection.backup(output_connection)
        if str(output_connection.execute("PRAGMA integrity_check").fetchone()[0]) != "ok":
            raise RecoveryError("pre-restore rollback database failed integrity verification")
    finally:
        output_connection.close()
        input_connection.close()


def restore_local_backup(
    config: "AppConfig",
    archive_path: str | Path,
    *,
    acknowledge_sensitive: bool,
) -> dict[str, Any]:
    """Restore while AdverScope is stopped, retaining rollback state until success."""
    if not acknowledge_sensitive:
        raise RecoveryError("local restore requires explicit sensitive-data acknowledgement")
    source = Path(archive_path).expanduser().resolve()
    database = Path(config.database_path).resolve()
    evidence = Path(config.evidence_root).resolve()
    provider = Path(config.model_profiles_path).resolve()
    state_root = database.parent
    rollback_root = state_root / "backups" / "restore-rollback" / _now_compact()
    rollback_root.mkdir(parents=True, exist_ok=False)
    journal = state_root / "backups" / "restore-in-progress.json"
    with tempfile.TemporaryDirectory(prefix="adverscope-local-restore-", dir=state_root) as temporary_directory:
        staging = Path(temporary_directory)
        manifest = _extract_verified_archive(source, staging, expected_kind="adverscope-local-backup")
        if str(manifest.get("schema_version")) != LOCAL_BACKUP_SCHEMA_VERSION:
            raise RecoveryError("local backup schema is not supported")
        restored_database = staging / "database" / "adverscope.sqlite3"
        check = sqlite3.connect(f"file:{restored_database.as_posix()}?mode=ro", uri=True)
        try:
            schema = int(check.execute("PRAGMA user_version").fetchone()[0])
            integrity = str(check.execute("PRAGMA integrity_check").fetchone()[0])
            foreign_errors = list(check.execute("PRAGMA foreign_key_check"))
        finally:
            check.close()
        if schema != DATABASE_SCHEMA_VERSION or integrity != "ok" or foreign_errors:
            raise RecoveryError("backup database is incompatible or failed integrity verification")
        check = sqlite3.connect(f"file:{restored_database.as_posix()}?mode=ro", uri=True)
        try:
            restored_project_ids = [str(row[0]) for row in check.execute("SELECT id FROM projects ORDER BY id")]
            expected_count = int(manifest.get("project_count", -1))
            expected_digest = str(manifest.get("project_ids_sha256") or "")
            actual_digest = hashlib.sha256("\n".join(restored_project_ids).encode("utf-8")).hexdigest()
            if len(restored_project_ids) != expected_count or actual_digest != expected_digest:
                raise RecoveryError("backup project inventory does not match its manifest")
            _verify_retained_files(_database_file_records(check, restored_project_ids), staging / "evidence")
        finally:
            check.close()
        rollback_database = rollback_root / "database.sqlite3"
        rollback_evidence = rollback_root / "evidence"
        rollback_provider = rollback_root / "model-providers.json"
        journal_document = {
            "schema_version": LOCAL_BACKUP_SCHEMA_VERSION,
            "created_at": _now_iso(),
            "database": str(database),
            "evidence": str(evidence),
            "provider": str(provider),
            "rollback_database": str(rollback_database),
            "rollback_evidence": str(rollback_evidence),
            "rollback_provider": str(rollback_provider),
            "database_existed": database.is_file(),
            "evidence_existed": evidence.exists(),
            "provider_existed": provider.is_file(),
            "phase": "prepared",
        }
        _safe_json_write(journal, journal_document)
        try:
            if database.is_file():
                _snapshot_stopped_database(database, rollback_database)
            if evidence.exists():
                evidence.replace(rollback_evidence)
            if provider.is_file():
                shutil.copy2(provider, rollback_provider)
            journal_document["phase"] = "previous-state-retained"
            _safe_json_write(journal, journal_document)
            database.parent.mkdir(parents=True, exist_ok=True)
            _remove_database_sidecars(database)
            shutil.copy2(restored_database, database)
            restored_evidence = staging / "evidence"
            if restored_evidence.exists():
                restored_evidence.replace(evidence)
            else:
                evidence.mkdir(parents=True, exist_ok=True)
            restored_provider = staging / "configuration" / "model-providers.json"
            if restored_provider.is_file():
                provider.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(restored_provider, provider)
            elif provider.exists():
                provider.unlink()
            journal_document["phase"] = "restored"
            _safe_json_write(journal, journal_document)
            final = sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True)
            try:
                project_count = int(final.execute("SELECT COUNT(*) FROM projects").fetchone()[0])
                if str(final.execute("PRAGMA integrity_check").fetchone()[0]) != "ok" or list(final.execute("PRAGMA foreign_key_check")):
                    raise RecoveryError("restored database failed final verification")
            finally:
                final.close()
            journal.unlink(missing_ok=True)
            shutil.rmtree(rollback_root, ignore_errors=True)
            return {
                "restored": True,
                "project_count": project_count,
                "database_schema": schema,
                "archive_sha256": manifest["archive_sha256"],
                "browser_sessions_restored": bool((manifest.get("evidence_policy") or {}).get("browser_sessions_included")),
            }
        except Exception:
            recover_interrupted_restore(config)
            raise


def recover_interrupted_restore(config: "AppConfig") -> dict[str, Any]:
    database = Path(config.database_path).resolve()
    journal = database.parent / "backups" / "restore-in-progress.json"
    if not journal.is_file():
        return {"recovered": False}
    try:
        document = json.loads(journal.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RecoveryError("restore recovery journal is unreadable; do not start AdverScope until storage is reviewed") from exc
    expected_database = Path(str(document.get("database") or "")).resolve()
    expected_evidence = Path(str(document.get("evidence") or "")).resolve()
    expected_provider = Path(str(document.get("provider") or "")).resolve()
    if expected_database != database or expected_evidence != Path(config.evidence_root).resolve() or expected_provider != Path(config.model_profiles_path).resolve():
        raise RecoveryError("restore recovery journal does not match this installation")
    rollback_database = Path(str(document.get("rollback_database") or "")).resolve()
    rollback_evidence = Path(str(document.get("rollback_evidence") or "")).resolve()
    rollback_provider = Path(str(document.get("rollback_provider") or "")).resolve()
    rollback_base = (database.parent / "backups" / "restore-rollback").resolve()
    rollback_paths = (rollback_database, rollback_evidence, rollback_provider)
    if any(rollback_base not in path.parents for path in rollback_paths):
        raise RecoveryError("restore recovery journal contains an unsafe rollback path")
    if len({path.parent for path in rollback_paths}) != 1:
        raise RecoveryError("restore recovery journal rollback paths do not share one operation directory")
    if rollback_database.is_file():
        restore_database_file(database, rollback_database)
    elif not bool(document.get("database_existed")):
        _remove_database_sidecars(database)
        database.unlink(missing_ok=True)
    if rollback_evidence.exists():
        if expected_evidence.exists():
            shutil.rmtree(expected_evidence)
        rollback_evidence.replace(expected_evidence)
    elif not bool(document.get("evidence_existed")) and expected_evidence.exists():
        shutil.rmtree(expected_evidence)
    if rollback_provider.is_file():
        expected_provider.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(rollback_provider, expected_provider)
    elif not bool(document.get("provider_existed")):
        expected_provider.unlink(missing_ok=True)
    journal.unlink(missing_ok=True)
    shutil.rmtree(rollback_database.parent, ignore_errors=True)
    return {"recovered": True, "restored_previous_state": True}
