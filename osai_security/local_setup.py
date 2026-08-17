from __future__ import annotations

import json
import os
import platform
import shutil
import socket
import sqlite3
import subprocess
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any

from . import DATABASE_SCHEMA_VERSION, build_identity
from .config import AppConfig, ROOT
from .db import Repository
from .deployment_security import LOOPBACK_HOSTS, permission_status, secure_directory, secure_file, validate_serve_security
from .model_gateway import ModelGateway
from .model_providers import ModelProviderRegistry
from .release import LOCAL_CONFIGURATION_SCHEMA_VERSION, MODEL_PROVIDER_SCHEMA_VERSION
from .security import safe_error


SETUP_SCHEMA_VERSION = LOCAL_CONFIGURATION_SCHEMA_VERSION
SUPPORTED_PROVIDERS = {"local", "openai", "zai"}
_SECRET_KEYS = {
    "api_key", "apikey", "access_token", "auth_token", "bearer_token",
    "client_secret", "password", "private_key", "secret", "session_token",
}


class SetupError(ValueError):
    pass


def default_state_root() -> Path:
    configured = os.environ.get("ADVERSCOPE_HOME", "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        return (base / "AdverScope").resolve()
    if sys.platform == "darwin":
        return (Path.home() / "Library" / "Application Support" / "AdverScope").resolve()
    base = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    return (base / "adverscope").resolve()


def default_config_path() -> Path:
    configured = os.environ.get("ADVERSCOPE_CONFIG", "").strip()
    return Path(configured).expanduser().resolve() if configured else default_state_root() / "config.json"


def _absolute(path: str | Path) -> Path:
    return Path(path).expanduser().resolve()


def _safe_write_json(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(document, handle, indent=2, sort_keys=True)
            handle.write("\n")
        secure_file(temporary)
        temporary.replace(path)
        secure_file(path)
    finally:
        temporary.unlink(missing_ok=True)


def _secret_paths(value: Any, prefix: str = "") -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        for raw_key, item in value.items():
            key = str(raw_key).casefold().replace("-", "_")
            path = f"{prefix}.{raw_key}" if prefix else str(raw_key)
            if key in _SECRET_KEYS and item is not None and item != "":
                found.append(path)
            found.extend(_secret_paths(item, path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(_secret_paths(item, f"{prefix}[{index}]"))
    return found


def load_local_document(path: str | Path) -> dict[str, Any]:
    source = _absolute(path)
    try:
        document = json.loads(source.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SetupError(f"configuration does not exist: {source}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise SetupError(f"configuration could not be read: {safe_error(exc)}") from exc
    if not isinstance(document, dict):
        raise SetupError("configuration must be a JSON object")
    secret_paths = _secret_paths(document)
    if secret_paths:
        raise SetupError(
            "configuration contains a secret value; store the value in an environment variable instead "
            f"({', '.join(secret_paths)})"
        )
    return document


def initialize_local_state(
    *,
    config_path: str | Path | None = None,
    data_directory: str | Path | None = None,
    evidence_directory: str | Path | None = None,
    host: str = "127.0.0.1",
    port: int = 8080,
    provider: str = "local",
    model: str = "",
    base_url: str = "",
    api_key_env: str = "",
    browser_executable: str = "",
    force: bool = False,
) -> dict[str, Any]:
    target_config = _absolute(config_path or default_config_path())
    if target_config.exists() and not force:
        raise SetupError(f"configuration already exists: {target_config}; use --force to update it without deleting project data")
    if provider not in SUPPORTED_PROVIDERS:
        raise SetupError(f"provider must be one of: {', '.join(sorted(SUPPORTED_PROVIDERS))}")
    if host not in LOOPBACK_HOSTS:
        raise SetupError("first-run setup binds locally; remote binding requires the separately hardened remote-deployment workflow")
    if not 1 <= int(port) <= 65535:
        raise SetupError("port must be between 1 and 65535")

    state_root = target_config.parent
    data_root = _absolute(data_directory or state_root / "data")
    evidence_root = _absolute(evidence_directory or data_root / "projects")
    training_root = data_root / "training"
    database_path = data_root / "adverscope.sqlite3"
    provider_path = data_root / "model-providers.json"
    selected_model = model.strip() or {
        "local": "qwen3.8-27b",
        "openai": "gpt-5.5",
        "zai": "glm-5.2",
    }[provider]
    local_base_url = base_url.strip().rstrip("/") or "http://127.0.0.1:8001/v1"
    if provider != "local" and base_url.strip():
        raise SetupError("built-in remote provider endpoints are fixed; configure only the model and API-key environment variable")
    selected_env = api_key_env.strip() or {"openai": "OPENAI_API_KEY", "zai": "ZAI_API_KEY"}.get(provider, "")

    document: dict[str, Any] = {
        "schema_version": SETUP_SCHEMA_VERSION,
        "host": host,
        "port": int(port),
        "database_path": str(database_path),
        "evidence_root": str(evidence_root),
        "training_root": str(training_root),
        "model_profiles_path": str(provider_path),
        "llm_provider": provider,
        "llm_base_url": local_base_url,
        "llm_model": selected_model,
        "browser_executable": str(_absolute(browser_executable)) if browser_executable else "",
    }
    if _secret_paths(document):
        raise SetupError("configuration attempted to persist a secret")

    secure_directory(data_root)
    secure_directory(evidence_root)
    secure_directory(training_root)
    _safe_write_json(target_config, document)
    config = AppConfig.from_sources(target_config)
    repository = Repository(config.database_path)
    try:
        database_health = repository.healthcheck()
    finally:
        repository.close()
    registry = ModelProviderRegistry(config)
    registry.select(provider, model=selected_model, api_key_env=selected_env)
    return {
        "schema_version": SETUP_SCHEMA_VERSION,
        "created": True,
        "updated_existing_configuration": bool(force),
        "config_path": str(target_config),
        "data_directory": str(data_root),
        "database_path": str(database_path),
        "evidence_directory": str(evidence_root),
        "training_directory": str(training_root),
        "model_profiles_path": str(provider_path),
        "provider": provider,
        "model": selected_model,
        "api_key_environment": selected_env,
        "database_schema": database_health.get("schema_version"),
        "secret_storage": "environment-reference-only",
    }


def _check(identifier: str, label: str, status: str, summary: str, **details: Any) -> dict[str, Any]:
    return {"id": identifier, "label": label, "status": status, "summary": summary, "details": details}


def _writable_directory(path: Path) -> tuple[bool, str]:
    probe = path / f".adverscope-doctor-{uuid.uuid4().hex}.tmp"
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe.write_bytes(b"adverscope-doctor")
        if probe.read_bytes() != b"adverscope-doctor":
            return False, "write verification did not round-trip"
        return True, "read/write verification passed"
    except OSError as exc:
        return False, safe_error(exc)
    finally:
        probe.unlink(missing_ok=True)


def _command_version(command: str, arguments: list[str]) -> tuple[bool, str]:
    executable = shutil.which(command)
    if not executable:
        return False, "not installed or not available on PATH"
    try:
        result = subprocess.run([executable, *arguments], capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, safe_error(exc)
    value = (result.stdout or result.stderr).strip().splitlines()
    return result.returncode == 0, (value[0][:200] if value else f"exit status {result.returncode}")


def _browser_executable(configured: str) -> Path | None:
    candidates = [configured] if configured else []
    if os.name == "nt":
        candidates.extend([
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        ])
    else:
        if sys.platform == "darwin":
            candidates.extend([
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
                "/Applications/Chromium.app/Contents/MacOS/Chromium",
            ])
        candidates.extend(["/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser"])
    return next((Path(item).resolve() for item in candidates if item and Path(item).is_file()), None)


def _database_check(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return _check("database", "Database", "fail", "database file is missing; run adverscope init", path=str(path))
    try:
        uri = f"file:{path.as_posix()}?mode=ro"
        connection = sqlite3.connect(uri, uri=True)
        try:
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            connection.execute("SELECT 1").fetchone()
        finally:
            connection.close()
    except sqlite3.Error as exc:
        return _check("database", "Database", "fail", f"database could not be read: {safe_error(exc)}", path=str(path))
    if version != DATABASE_SCHEMA_VERSION:
        return _check("database", "Database", "fail", f"database schema {version} does not match supported schema {DATABASE_SCHEMA_VERSION}", path=str(path), schema_version=version)
    return _check("database", "Database", "pass", f"schema {version} is readable", path=str(path), schema_version=version)


def _port_check(host: str, port: int) -> dict[str, Any]:
    probe_host = "127.0.0.1" if host in {"0.0.0.0", "::"} else host
    try:
        with urllib.request.urlopen(f"http://{probe_host}:{port}/api/runtime", timeout=0.5) as response:
            document = json.loads(response.read(200_000).decode("utf-8"))
        running_version = str((document.get("build") or {}).get("version") or "unknown")
        return _check("port", "Application port", "pass", f"AdverScope {running_version} is already running", host=host, port=port, running=True)
    except (OSError, urllib.error.URLError, json.JSONDecodeError, ValueError, AttributeError, TypeError):
        pass
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as server:
            server.bind((host, port))
        return _check("port", "Application port", "pass", "port is available", host=host, port=port, running=False)
    except OSError as exc:
        return _check("port", "Application port", "fail", f"port is unavailable: {safe_error(exc)}", host=host, port=port, running=False)


def doctor_report(config_path: str | Path | None = None, *, probe_model: bool = True) -> dict[str, Any]:
    source = _absolute(config_path or default_config_path())
    checks: list[dict[str, Any]] = []
    python_ok = sys.version_info >= (3, 11)
    checks.append(_check("python", "Python", "pass" if python_ok else "fail", platform.python_version(), minimum="3.11"))
    if not source.is_file():
        checks.append(_check("configuration", "Configuration", "fail", "not initialized; run adverscope init", path=str(source)))
        return _doctor_result(source, checks)
    try:
        document = load_local_document(source)
        config = AppConfig.from_sources(source)
        checks.append(_check("configuration", "Configuration", "pass", "valid non-secret configuration", path=str(source), schema_version=str(document.get("schema_version") or "legacy")))
    except (SetupError, ValueError) as exc:
        checks.append(_check("configuration", "Configuration", "fail", str(exc), path=str(source)))
        return _doctor_result(source, checks)

    for identifier, label, directory in (
        ("data-directory", "Data directory", config.database_path.parent),
        ("evidence-directory", "Evidence directory", config.evidence_root),
    ):
        ok, summary = _writable_directory(Path(directory))
        checks.append(_check(identifier, label, "pass" if ok else "fail", summary, path=str(Path(directory).resolve())))
        permissions = permission_status(directory, directory=True)
        checks.append(_check(
            f"{identifier}-permissions", f"{label} permissions",
            "pass" if permissions["ok"] else "fail", str(permissions["summary"]),
            **{key: value for key, value in permissions.items() if key not in {"ok", "summary"}},
        ))
    recovery_journal = Path(config.database_path).parent / "backups" / "restore-in-progress.json"
    checks.append(_check(
        "restore-recovery", "Restore recovery", "fail" if recovery_journal.is_file() else "pass",
        "an interrupted restore is pending; start AdverScope to recover the retained previous state"
        if recovery_journal.is_file()
        else "no interrupted restore is pending",
        pending=recovery_journal.is_file(),
    ))
    checks.append(_database_check(Path(config.database_path)))
    database_permissions = permission_status(config.database_path, directory=False)
    checks.append(_check(
        "database-permissions", "Database permissions",
        "pass" if database_permissions["ok"] else "fail", str(database_permissions["summary"]),
        **{key: value for key, value in database_permissions.items() if key not in {"ok", "summary"}},
    ))
    try:
        deployment = validate_serve_security(config)
        checks.append(_check(
            "deployment-boundary", "Deployment boundary", "pass",
            "local loopback binding" if deployment["mode"] == "local-loopback" else str(deployment.get("warning") or deployment["mode"]),
            mode=deployment["mode"], tls=deployment["tls"], authentication=deployment["authentication"],
        ))
    except ValueError as exc:
        checks.append(_check("deployment-boundary", "Deployment boundary", "fail", str(exc), host=config.host))
    checks.append(_port_check(config.host, int(config.port)))

    node_ok, node_version = _command_version("node", ["--version"])
    try:
        node_major = int(node_version.strip().lstrip("v").split(".", 1)[0]) if node_ok else 0
    except ValueError:
        node_major = 0
    node_supported = node_ok and node_major >= 20
    checks.append(_check("node", "Node.js browser runtime", "pass" if node_supported else "warning", node_version if node_supported else f"{node_version}; Node.js 20 or newer is required for browser targets", minimum="20", optional_for="API-only targets"))
    browser_runtime = ROOT / "browser" / "capture.mjs"
    playwright_runtime = ROOT / "node_modules" / "playwright-core"
    browser_runtime_ok = browser_runtime.is_file() and playwright_runtime.is_dir()
    checks.append(_check(
        "browser-runtime", "Browser capture dependencies", "pass" if browser_runtime_ok else "warning",
        "Playwright capture runtime is installed" if browser_runtime_ok else "browser capture is unavailable; run the source bootstrap or use API-only targets",
        optional_for="API-only targets",
    ))
    browser = _browser_executable(config.browser_executable)
    checks.append(_check(
        "browser", "Chrome or Edge", "pass" if browser else "warning",
        "supported browser executable found" if browser else "no supported browser executable found",
        configured=bool(config.browser_executable), optional_for="API-only targets",
    ))

    registry_path = Path(config.model_profiles_path)
    if registry_path.is_file():
        try:
            provider_document = json.loads(registry_path.read_text(encoding="utf-8"))
            provider_schema = str(provider_document.get("schema_version") or "") if isinstance(provider_document, dict) else ""
            provider_ok = provider_schema == MODEL_PROVIDER_SCHEMA_VERSION
        except (OSError, json.JSONDecodeError):
            provider_ok, provider_schema = False, ""
        legacy_compatible = provider_schema == "1.0" and MODEL_PROVIDER_SCHEMA_VERSION != "1.0"
        status = "pass" if provider_ok else "warning" if legacy_compatible else "fail"
        summary = (
            "non-secret named provider profiles are readable"
            if provider_ok
            else "legacy provider selection is readable and will migrate on the next explicit profile update"
            if legacy_compatible
            else "provider profile file is malformed or has an unsupported schema"
        )
        checks.append(_check(
            "model-profiles", "Model profiles", status, summary,
            path=str(registry_path), schema_version=provider_schema,
            migration_available=legacy_compatible,
        ))
    else:
        checks.append(_check(
            "model-profiles", "Model profiles", "warning",
            "no saved provider profile; built-in non-secret defaults will be used until a provider is selected",
            path=str(registry_path), legacy_compatible=True,
        ))

    if probe_model:
        gateway = ModelGateway(config)
        try:
            health = gateway.healthcheck(
                timeout_seconds=min(3.0, config.llm_timeout_seconds),
                allow_existing_tunnel=True,
            )
        finally:
            gateway.close()
        checks.append(_check(
            "model", "Selected model", "pass" if health.get("ok") and health.get("model_available") else "fail",
            "configured model is available" if health.get("ok") and health.get("model_available") else str(health.get("error") or "configured model was not returned by the provider"),
            provider=health.get("provider"), model=health.get("configured_model"), credential_ready=bool(health.get("credential_ready")),
        ))
    else:
        checks.append(_check("model", "Selected model", "warning", "model network probe was skipped", skipped=True))
    return _doctor_result(source, checks)


def _doctor_result(config_path: Path, checks: list[dict[str, Any]]) -> dict[str, Any]:
    failures = len([item for item in checks if item["status"] == "fail"])
    warnings = len([item for item in checks if item["status"] == "warning"])
    return {
        "schema_version": SETUP_SCHEMA_VERSION,
        "ok": failures == 0,
        "summary": {"passed": len(checks) - failures - warnings, "warnings": warnings, "failures": failures},
        "config_path": str(config_path),
        "release": build_identity(),
        "checks": checks,
    }


def render_doctor_report(report: dict[str, Any]) -> str:
    marker = {"pass": "PASS", "warning": "WARN", "fail": "FAIL"}
    lines = [
        f"AdverScope doctor · {report['release']['version']} ({report['release']['release_channel']})",
        f"Configuration: {report['config_path']}",
        "",
    ]
    for item in report.get("checks") or []:
        lines.append(f"[{marker.get(item['status'], 'INFO')}] {item['label']}: {item['summary']}")
    summary = report.get("summary") or {}
    lines.extend(["", f"Result: {summary.get('failures', 0)} failure(s), {summary.get('warnings', 0)} warning(s)"])
    return "\n".join(lines)
