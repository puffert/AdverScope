from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import Any

from .config import AppConfig


LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_ENVIRONMENT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,159}$")


def is_loopback_host(host: str) -> bool:
    return str(host or "").strip().casefold() in LOOPBACK_HOSTS


def validate_environment_name(value: str, *, label: str = "environment variable") -> str:
    cleaned = str(value or "").strip()
    if not _ENVIRONMENT_NAME.fullmatch(cleaned):
        raise ValueError(f"{label} must be a valid environment variable name")
    return cleaned


def secure_directory(path: str | Path) -> Path:
    """Create a state directory and apply owner-only POSIX permissions.

    Windows access control remains inherited from the user's profile. The
    doctor command reports that boundary instead of pretending chmod provides
    a Windows ACL guarantee.
    """

    directory = Path(path).expanduser().resolve()
    directory.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        os.chmod(directory, 0o700)
    return directory


def secure_file(path: str | Path) -> Path:
    file_path = Path(path).expanduser().resolve()
    if file_path.exists() and os.name != "nt":
        os.chmod(file_path, 0o600)
    return file_path


def permission_status(path: str | Path, *, directory: bool) -> dict[str, Any]:
    target = Path(path).expanduser().resolve()
    if not target.exists():
        return {"ok": False, "platform_enforced": os.name != "nt", "summary": "path does not exist", "path": str(target)}
    if os.name == "nt":
        return {
            "ok": True,
            "platform_enforced": False,
            "summary": "Windows owner ACL is inherited; keep state inside the user profile or a protected volume",
            "path": str(target),
        }
    mode = stat.S_IMODE(target.stat().st_mode)
    unsafe = mode & 0o077
    expected = 0o700 if directory else 0o600
    return {
        "ok": not bool(unsafe),
        "platform_enforced": True,
        "summary": f"owner-only permissions ({mode:04o})" if not unsafe else f"group or other access is enabled ({mode:04o}); expected {expected:04o}",
        "path": str(target),
        "mode": f"{mode:04o}",
        "expected": f"{expected:04o}",
    }


def validate_serve_security(config: AppConfig) -> dict[str, Any]:
    """Validate a deployment boundary without returning credential material."""

    if is_loopback_host(config.host):
        return {"mode": "local-loopback", "tls": False, "authentication": False, "warning": ""}

    if config.container_api_only:
        if config.host != "0.0.0.0" or not os.environ.get("AISEC_CONTAINER_API_ONLY", "").strip().casefold() in {"1", "true", "yes", "on"}:
            raise ValueError("container API mode requires host 0.0.0.0 and AISEC_CONTAINER_API_ONLY=1")
        return {
            "mode": "container-host-loopback",
            "tls": False,
            "authentication": False,
            "warning": "publish the container port only to 127.0.0.1; this mode is not approved for remote exposure",
        }

    if not config.remote_exposure_acknowledged:
        raise ValueError("remote binding requires --acknowledge-remote-exposure")
    token_environment = validate_environment_name(config.remote_access_token_env, label="remote access token environment variable")
    token = os.environ.get(token_environment, "")
    if len(token) < 32:
        raise ValueError(f"{token_environment} must contain an unpredictable access token of at least 32 characters")
    certificate = Path(config.tls_cert_path).expanduser().resolve() if config.tls_cert_path else None
    private_key = Path(config.tls_key_path).expanduser().resolve() if config.tls_key_path else None
    if certificate is None or private_key is None:
        raise ValueError("remote binding requires both --tls-cert and --tls-key")
    if not certificate.is_file() or not private_key.is_file():
        raise ValueError("remote TLS certificate or private key does not exist")
    return {
        "mode": "remote-api",
        "tls": True,
        "authentication": True,
        "token_environment": token_environment,
        "certificate": str(certificate),
        "private_key": str(private_key),
        "warning": "remote API exposure is enabled; use a restricted network and rotate the bearer token after the engagement",
    }
