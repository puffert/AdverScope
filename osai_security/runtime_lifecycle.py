from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import IO

from .release import API_CONTRACT_VERSION


class RuntimeAlreadyActiveError(RuntimeError):
    pass


class RuntimeLock:
    """Cross-platform, crash-releasing single-instance lock for one database/port."""

    def __init__(self, path: Path, *, port: int):
        self.path = Path(path)
        self.port = int(port)
        self._handle: IO[bytes] | None = None
        self._lock = threading.RLock()

    def acquire(self) -> None:
        with self._lock:
            if self._handle is not None:
                return
            self.path.parent.mkdir(parents=True, exist_ok=True)
            handle = self.path.open("a+b")
            try:
                handle.seek(0)
                if not handle.read(1):
                    handle.seek(0)
                    handle.write(b"\0")
                    handle.flush()
                handle.seek(0)
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except (OSError, BlockingIOError) as exc:
                handle.close()
                raise RuntimeAlreadyActiveError(
                    f"another AdverScope process already owns port {self.port} and this data store"
                ) from exc
            self._handle = handle
            metadata = json.dumps({"pid": os.getpid(), "port": self.port}, sort_keys=True).encode("utf-8")
            handle.seek(0)
            handle.truncate()
            handle.write(metadata)
            handle.flush()

    def release(self) -> None:
        with self._lock:
            handle, self._handle = self._handle, None
            if handle is None:
                return
            try:
                handle.seek(0)
                if os.name == "nt":
                    import msvcrt
                    try:
                        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                    except OSError:
                        # Closing the owning handle below also releases every
                        # Windows byte-range lock held by that handle.
                        pass
                else:
                    import fcntl
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            finally:
                handle.close()

    def __enter__(self) -> "RuntimeLock":
        self.acquire()
        return self

    def __exit__(self, *_args: object) -> None:
        self.release()


def runtime_lock_path(database_path: Path, port: int) -> Path:
    return Path(database_path).parent / f".adverscope-{int(port)}.lock"
