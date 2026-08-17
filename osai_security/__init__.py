"""AdverScope modular AI security testing framework."""

from __future__ import annotations

import os
import platform
import re
import subprocess
from pathlib import Path
from typing import Any

from .release import DATABASE_SCHEMA_VERSION, PRODUCT_NAME, PRODUCT_VERSION, RELEASE_CHANNEL, SCHEMA_VERSIONS

__version__ = PRODUCT_VERSION
USER_AGENT = f"AdverScope/{__version__}"


def _source_revision() -> str:
    """Resolve a source checkout revision without requiring Git at runtime."""
    repository_root = Path(__file__).resolve().parents[1]
    try:
        revision_result = subprocess.run(
            ["git", "rev-parse", "--short=12", "HEAD"],
            cwd=repository_root,
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
        revision = revision_result.stdout.strip()
        if revision_result.returncode or not re.fullmatch(r"[0-9a-fA-F]{7,40}", revision):
            return "working-tree"
        status_result = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=normal"],
            cwd=repository_root,
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
        return f"{revision}-dirty" if status_result.returncode or status_result.stdout.strip() else revision
    except (OSError, subprocess.SubprocessError):
        return "working-tree"


def build_identity() -> dict[str, Any]:
    """Return the non-secret build identity persisted with executions and exports."""
    configured_revision = " ".join(os.environ.get("ADVERSCOPE_BUILD_REVISION", "").split())[:120]
    revision = configured_revision or _source_revision()
    return {
        "name": PRODUCT_NAME,
        "version": __version__,
        "release_channel": RELEASE_CHANNEL,
        "build_revision": revision,
        "database_schema": str(DATABASE_SCHEMA_VERSION),
        "schemas": dict(SCHEMA_VERSIONS),
        "python": platform.python_version(),
        "platform": platform.platform(),
    }
