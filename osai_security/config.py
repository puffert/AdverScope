from __future__ import annotations

import os
import json
from dataclasses import dataclass
from dataclasses import replace
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def _bool_env(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _strict_bool(value: object, *, field: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
    raise ValueError(f"{field} must be a boolean")


@dataclass(frozen=True)
class AppConfig:
    host: str = "127.0.0.1"
    port: int = 8080
    database_path: Path = ROOT / "data" / "osai-security.sqlite3"
    evidence_root: Path = ROOT / "data" / "projects"
    training_root: Path = ROOT / "data" / "training"
    model_profiles_path: Path = ROOT / "data" / "model-providers.json"
    llm_provider: str = "local"
    llm_base_url: str = "http://127.0.0.1:8001/v1"
    llm_model: str = "qwen3.8-27b"
    llm_timeout_seconds: float = 90.0
    target_timeout_seconds: float = 90.0
    ssh_tunnel: bool = False
    gx10_user: str = ""
    gx10_host: str = ""
    ssh_local_port: int = 18001
    ssh_remote_port: int = 8001
    browser_executable: str = ""
    browser_timeout_seconds: float = 90.0
    remote_access_token_env: str = ""
    tls_cert_path: str = ""
    tls_key_path: str = ""
    remote_exposure_acknowledged: bool = False
    container_api_only: bool = False

    @classmethod
    def from_env(cls) -> "AppConfig":
        database = Path(os.environ.get("AISEC_DATABASE_PATH", str(cls.database_path)))
        evidence_root = Path(os.environ.get("AISEC_EVIDENCE_ROOT", str(cls.evidence_root)))
        training_root = Path(os.environ.get("AISEC_TRAINING_ROOT", str(cls.training_root)))
        model_profiles = Path(os.environ.get("AISEC_MODEL_PROFILES_PATH", str(cls.model_profiles_path)))
        return cls(
            host=os.environ.get("AISEC_HOST", cls.host),
            port=int(os.environ.get("AISEC_PORT", str(cls.port))),
            database_path=database,
            evidence_root=evidence_root,
            training_root=training_root,
            model_profiles_path=model_profiles,
            llm_provider=os.environ.get("AISEC_LLM_PROVIDER", cls.llm_provider),
            llm_base_url=os.environ.get("AISEC_LLM_BASE_URL", cls.llm_base_url),
            llm_model=os.environ.get("AISEC_LLM_MODEL", cls.llm_model),
            llm_timeout_seconds=float(os.environ.get("AISEC_LLM_TIMEOUT", str(cls.llm_timeout_seconds))),
            target_timeout_seconds=float(os.environ.get("AISEC_TARGET_TIMEOUT", str(cls.target_timeout_seconds))),
            ssh_tunnel=_bool_env("AISEC_SSH_TUNNEL", False),
            gx10_user=os.environ.get("AISEC_GX10_USER", cls.gx10_user),
            gx10_host=os.environ.get("AISEC_GX10_HOST", cls.gx10_host),
            ssh_local_port=int(os.environ.get("AISEC_SSH_LOCAL_PORT", str(cls.ssh_local_port))),
            ssh_remote_port=int(os.environ.get("AISEC_SSH_REMOTE_PORT", str(cls.ssh_remote_port))),
            browser_executable=os.environ.get("AISEC_BROWSER_EXECUTABLE", ""),
            browser_timeout_seconds=float(os.environ.get("AISEC_BROWSER_TIMEOUT", str(cls.browser_timeout_seconds))),
            remote_access_token_env=os.environ.get("AISEC_REMOTE_ACCESS_TOKEN_ENV", ""),
            tls_cert_path=os.environ.get("AISEC_TLS_CERT_PATH", ""),
            tls_key_path=os.environ.get("AISEC_TLS_KEY_PATH", ""),
            remote_exposure_acknowledged=_bool_env("AISEC_REMOTE_EXPOSURE_ACKNOWLEDGED", False),
            container_api_only=_bool_env("AISEC_CONTAINER_API_ONLY", False),
        )

    @classmethod
    def from_sources(cls, local_config_path: Path | str | None = None) -> "AppConfig":
        """Load an ignored local config and then apply environment overrides."""
        path = Path(local_config_path) if local_config_path else ROOT / "data" / "local-config.json"
        local: dict[str, object] = {}
        if path.is_file():
            try:
                parsed = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ValueError(f"local config could not be read: {exc}") from exc
            if not isinstance(parsed, dict):
                raise ValueError("local config must be a JSON object")
            local = parsed
        base = cls()
        converters = {
            "host": str,
            "port": int,
            "database_path": Path,
            "database": Path,
            "evidence_root": Path,
            "training_root": Path,
            "model_profiles_path": Path,
            "llm_provider": str,
            "llm_base_url": str,
            "llm_model": str,
            "llm_timeout_seconds": float,
            "target_timeout_seconds": float,
            "ssh_tunnel": bool,
            "gx10_user": str,
            "gx10_host": str,
            "ssh_local_port": int,
            "ssh_remote_port": int,
            "browser_executable": str,
            "browser_timeout_seconds": float,
            "remote_access_token_env": str,
            "tls_cert_path": str,
            "tls_key_path": str,
            "remote_exposure_acknowledged": bool,
            "container_api_only": bool,
        }
        aliases = {"database": "database_path"}
        values: dict[str, object] = {}
        for key, converter in converters.items():
            if key not in local:
                continue
            destination = aliases.get(key, key)
            raw = local[key]
            values[destination] = _strict_bool(raw, field=key) if converter is bool else converter(raw)
        configured = replace(base, **values)
        environment_names = {
            "host": "AISEC_HOST",
            "port": "AISEC_PORT",
            "database_path": "AISEC_DATABASE_PATH",
            "evidence_root": "AISEC_EVIDENCE_ROOT",
            "training_root": "AISEC_TRAINING_ROOT",
            "model_profiles_path": "AISEC_MODEL_PROFILES_PATH",
            "llm_provider": "AISEC_LLM_PROVIDER",
            "llm_base_url": "AISEC_LLM_BASE_URL",
            "llm_model": "AISEC_LLM_MODEL",
            "llm_timeout_seconds": "AISEC_LLM_TIMEOUT",
            "target_timeout_seconds": "AISEC_TARGET_TIMEOUT",
            "ssh_tunnel": "AISEC_SSH_TUNNEL",
            "gx10_user": "AISEC_GX10_USER",
            "gx10_host": "AISEC_GX10_HOST",
            "ssh_local_port": "AISEC_SSH_LOCAL_PORT",
            "ssh_remote_port": "AISEC_SSH_REMOTE_PORT",
            "browser_executable": "AISEC_BROWSER_EXECUTABLE",
            "browser_timeout_seconds": "AISEC_BROWSER_TIMEOUT",
            "remote_access_token_env": "AISEC_REMOTE_ACCESS_TOKEN_ENV",
            "tls_cert_path": "AISEC_TLS_CERT_PATH",
            "tls_key_path": "AISEC_TLS_KEY_PATH",
            "remote_exposure_acknowledged": "AISEC_REMOTE_EXPOSURE_ACKNOWLEDGED",
            "container_api_only": "AISEC_CONTAINER_API_ONLY",
        }
        overrides: dict[str, object] = {}
        for field, environment_name in environment_names.items():
            if environment_name not in os.environ:
                continue
            raw = os.environ[environment_name]
            if field in {"ssh_tunnel", "remote_exposure_acknowledged", "container_api_only"}:
                overrides[field] = _strict_bool(raw, field=environment_name)
            else:
                converter = type(getattr(configured, field))
                overrides[field] = converter(raw)
        return replace(configured, **overrides)
