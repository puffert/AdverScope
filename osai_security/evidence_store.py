from __future__ import annotations

import hashlib
import re
import uuid
from pathlib import Path
from typing import BinaryIO

from .deployment_security import secure_directory, secure_file


_SAFE_ID = re.compile(r"^[A-Za-z0-9_-]+$")


class EvidenceStore:
    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()
        secure_directory(self.root)

    def attempt_directory(self, project_id: str, run_id: str, capture_id: str) -> Path:
        for value in (project_id, run_id, capture_id):
            if not _SAFE_ID.fullmatch(value):
                raise ValueError("invalid evidence identifier")
        directory = (self.root / project_id / run_id / capture_id).resolve()
        self._assert_inside(directory)
        secure_directory(directory)
        return directory

    def session_directory(self, project_id: str, target_id: str) -> Path:
        for value in (project_id, target_id):
            if not _SAFE_ID.fullmatch(value):
                raise ValueError("invalid browser session identifier")
        directory = (self.root / project_id / "_browser_sessions" / target_id).resolve()
        self._assert_inside(directory)
        secure_directory(directory)
        return directory

    def artifact_directory(self, project_id: str, artifact_id: str) -> Path:
        for value in (project_id, artifact_id):
            if not _SAFE_ID.fullmatch(value):
                raise ValueError("invalid artifact identifier")
        directory = (self.root / project_id / "_artifacts" / artifact_id).resolve()
        self._assert_inside(directory)
        directory.mkdir(parents=True, exist_ok=False)
        secure_directory(directory)
        return directory

    def store_artifact_stream(
        self,
        project_id: str,
        artifact_id: str,
        stream: BinaryIO,
        *,
        content_length: int,
        maximum_bytes: int,
    ) -> dict[str, object]:
        """Store an immutable project artifact while hashing the exact upload.

        Files use a server-owned name so an untrusted client filename can never
        influence the filesystem path. A failed or short upload is removed.
        """

        if content_length <= 0:
            raise ValueError("artifact upload is empty")
        if content_length > maximum_bytes:
            raise ValueError(f"artifact upload exceeds the {maximum_bytes} byte limit")
        directory = self.artifact_directory(project_id, artifact_id)
        destination = directory / "content.bin"
        digest = hashlib.sha256()
        remaining = int(content_length)
        size = 0
        try:
            with destination.open("xb") as handle:
                while remaining:
                    chunk = stream.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise ValueError("artifact upload ended before Content-Length bytes were received")
                    handle.write(chunk)
                    digest.update(chunk)
                    size += len(chunk)
                    remaining -= len(chunk)
            secure_file(destination)
            if size != content_length:
                raise ValueError("artifact upload size did not match Content-Length")
            return {
                "relative_path": self.relative_path(destination),
                "size_bytes": size,
                "sha256": digest.hexdigest(),
            }
        except Exception:
            destination.unlink(missing_ok=True)
            try:
                directory.rmdir()
            except OSError:
                pass
            raise

    def relative_path(self, path: str | Path) -> str:
        resolved = Path(path).resolve()
        self._assert_inside(resolved)
        return resolved.relative_to(self.root).as_posix()

    def resolve(self, relative_path: str) -> Path:
        relative = Path(relative_path)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("invalid evidence asset path")
        resolved = (self.root / relative).resolve()
        self._assert_inside(resolved)
        return resolved

    def _assert_inside(self, path: Path) -> None:
        if path != self.root and self.root not in path.parents:
            raise ValueError("evidence path escaped the configured root")

    def healthcheck(self) -> dict[str, object]:
        probe = (self.root / f".advscope-health-{uuid.uuid4().hex}.tmp").resolve()
        self._assert_inside(probe)
        try:
            probe.write_bytes(b"advscope-evidence-health")
            readable = probe.read_bytes() == b"advscope-evidence-health"
        finally:
            probe.unlink(missing_ok=True)
        return {"ok": readable, "root": str(self.root)}
