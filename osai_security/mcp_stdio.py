from __future__ import annotations

import hashlib
import json
import os
import queue
import re
import shlex
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from .mcp_security import MCPProtocolError


MCP_STDIO = "stdio"
_ENV_REFERENCE = re.compile(r"env:([A-Za-z_][A-Za-z0-9_]*)\Z")
_RUNTIME_ENVIRONMENT = (
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "PATH",
    "PATHEXT",
    "TEMP",
    "TMP",
    "LANG",
    "LC_ALL",
)


def file_sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate_stdio_config(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError("MCP stdio configuration must be an object")
    executable = Path(str(raw.get("executable") or "").strip())
    if not executable.is_absolute() or not executable.is_file():
        raise ValueError("MCP stdio executable must be an existing absolute file")
    executable_sha256 = str(raw.get("executable_sha256") or "").strip().casefold()
    if not re.fullmatch(r"[0-9a-f]{64}", executable_sha256):
        raise ValueError("MCP stdio executable_sha256 must be a 64-character SHA-256 digest")
    if file_sha256(executable) != executable_sha256:
        raise ValueError("MCP stdio executable does not match executable_sha256")

    arguments = raw.get("arguments") or []
    if not isinstance(arguments, list) or len(arguments) > 50:
        raise ValueError("MCP stdio arguments must be a list with at most 50 entries")
    cleaned_arguments: list[str] = []
    for argument in arguments:
        if not isinstance(argument, str) or "\x00" in argument or len(argument) > 4096:
            raise ValueError("each MCP stdio argument must be a string of at most 4096 characters without NUL bytes")
        cleaned_arguments.append(argument)

    cwd_value = str(raw.get("cwd") or "").strip()
    cwd = Path(cwd_value) if cwd_value else executable.parent
    if not cwd.is_absolute() or not cwd.is_dir():
        raise ValueError("MCP stdio cwd must be an existing absolute directory")

    environment = _validate_environment(raw.get("environment") or {}, "MCP stdio environment")
    try:
        response_timeout_seconds = float(raw.get("response_timeout_seconds") or 10)
        shutdown_timeout_seconds = float(raw.get("shutdown_timeout_seconds") or 2)
        max_response_bytes = int(raw.get("max_response_bytes") or 2_000_000)
        max_stderr_bytes = int(raw.get("max_stderr_bytes") or 200_000)
    except (TypeError, ValueError) as exc:
        raise ValueError("MCP stdio limits must be numeric") from exc
    if not 0.5 <= response_timeout_seconds <= 60:
        raise ValueError("MCP stdio response_timeout_seconds must be between 0.5 and 60")
    if not 0.1 <= shutdown_timeout_seconds <= 10:
        raise ValueError("MCP stdio shutdown_timeout_seconds must be between 0.1 and 10")
    if not 1_024 <= max_response_bytes <= 10_000_000:
        raise ValueError("MCP stdio max_response_bytes must be between 1024 and 10000000")
    if not 1_024 <= max_stderr_bytes <= 1_000_000:
        raise ValueError("MCP stdio max_stderr_bytes must be between 1024 and 1000000")
    return {
        "executable": str(executable.resolve()),
        "executable_sha256": executable_sha256,
        "arguments": cleaned_arguments,
        "cwd": str(cwd.resolve()),
        "environment": environment,
        "response_timeout_seconds": response_timeout_seconds,
        "shutdown_timeout_seconds": shutdown_timeout_seconds,
        "max_response_bytes": max_response_bytes,
        "max_stderr_bytes": max_stderr_bytes,
    }


def _validate_environment(raw: Any, label: str) -> dict[str, str]:
    if not isinstance(raw, dict) or len(raw) > 30:
        raise ValueError(f"{label} must be an object with at most 30 entries")
    cleaned: dict[str, str] = {}
    for key, value in raw.items():
        name = str(key)
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise ValueError(f"{label} contains an invalid environment variable name")
        if not isinstance(value, str) or not _ENV_REFERENCE.fullmatch(value):
            raise ValueError(f"{label} values must use env:VARIABLE_NAME references")
        cleaned[name] = value
    return cleaned


def validate_identity_environment(raw: Any, identity_id: str) -> dict[str, str]:
    return _validate_environment(raw or {}, f"MCP identity {identity_id} environment")


def _materialize_environment(*mappings: dict[str, str]) -> dict[str, str]:
    environment = {name: os.environ[name] for name in _RUNTIME_ENVIRONMENT if name in os.environ}
    for mapping in mappings:
        for target_name, reference in mapping.items():
            match = _ENV_REFERENCE.fullmatch(reference)
            source_name = match.group(1) if match else ""
            if not source_name or source_name not in os.environ:
                raise MCPProtocolError(f"MCP stdio environment source {source_name or '[invalid]'} is not available")
            environment[target_name] = os.environ[source_name]
    return environment


def _command_display(command: list[str]) -> str:
    return subprocess.list2cmdline(command) if os.name == "nt" else shlex.join(command)


class MCPStdioProcess:
    """One bounded MCP stdio child with newline-delimited JSON-RPC evidence."""

    def __init__(self, config: dict[str, Any], *, identity_environment: dict[str, str] | None = None):
        self.config = validate_stdio_config(config)
        self.identity_environment = validate_identity_environment(identity_environment or {}, "selected")
        self.command = [self.config["executable"], *self.config["arguments"]]
        self.command_display = _command_display(self.command)
        self._stdout_queue: queue.Queue[tuple[str, Any]] = queue.Queue()
        self._stderr_parts: list[str] = []
        self._stderr_bytes = 0
        self._response_bytes = 0
        self._transcript: list[dict[str, Any]] = []
        self.last_notifications: list[dict[str, Any]] = []
        self._closed = False
        creationflags = 0
        if os.name == "nt":
            creationflags = int(getattr(subprocess, "CREATE_NO_WINDOW", 0))
        try:
            self.process = subprocess.Popen(
                self.command,
                cwd=self.config["cwd"],
                env=_materialize_environment(self.config["environment"], self.identity_environment),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="strict",
                bufsize=1,
                shell=False,
                creationflags=creationflags,
            )
        except OSError as exc:
            raise MCPProtocolError(f"MCP stdio process could not start: {type(exc).__name__}: {exc}") from exc
        self._stdout_thread = threading.Thread(target=self._read_stdout, name="adverscope-mcp-stdout", daemon=True)
        self._stderr_thread = threading.Thread(target=self._read_stderr, name="adverscope-mcp-stderr", daemon=True)
        self._stdout_thread.start()
        self._stderr_thread.start()

    def _read_stdout(self) -> None:
        assert self.process.stdout is not None
        try:
            for line in self.process.stdout:
                self._stdout_queue.put(("line", line))
        except Exception as exc:  # decoding and pipe faults are protocol evidence
            self._stdout_queue.put(("error", exc))
        finally:
            self._stdout_queue.put(("eof", None))

    def _read_stderr(self) -> None:
        assert self.process.stderr is not None
        try:
            for chunk in iter(lambda: self.process.stderr.read(4096), ""):
                encoded = chunk.encode("utf-8", errors="replace")
                remaining = int(self.config["max_stderr_bytes"]) - self._stderr_bytes
                if remaining > 0:
                    retained = encoded[:remaining].decode("utf-8", errors="replace")
                    self._stderr_parts.append(retained)
                    self._stderr_bytes += len(retained.encode("utf-8"))
        except Exception:
            return

    @property
    def stderr(self) -> str:
        return "".join(self._stderr_parts)

    @property
    def transcript(self) -> list[dict[str, Any]]:
        return [dict(item) for item in self._transcript]

    def _write(self, message: dict[str, Any]) -> str:
        if self._closed or self.process.poll() is not None:
            raise MCPProtocolError(f"MCP stdio process is not running (exit {self.process.poll()})")
        raw = json.dumps(message, ensure_ascii=False, separators=(",", ":"))
        assert self.process.stdin is not None
        try:
            self.process.stdin.write(raw + "\n")
            self.process.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise MCPProtocolError(f"MCP stdio write failed: {type(exc).__name__}") from exc
        self._transcript.append({"direction": "client-to-target", "raw": raw, "message": message, "timestamp_ns": time.time_ns()})
        return raw

    def send_request(self, message: dict[str, Any], *, expected_id: int | str) -> tuple[dict[str, Any], str, list[dict[str, Any]]]:
        self._write(message)
        deadline = time.monotonic() + float(self.config["response_timeout_seconds"])
        notifications: list[dict[str, Any]] = []
        raw_lines: list[str] = []
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise MCPProtocolError(f"MCP stdio response timed out for JSON-RPC id {expected_id}")
            try:
                kind, value = self._stdout_queue.get(timeout=remaining)
            except queue.Empty as exc:
                raise MCPProtocolError(f"MCP stdio response timed out for JSON-RPC id {expected_id}") from exc
            if kind == "error":
                raise MCPProtocolError(f"MCP stdio stdout failed: {type(value).__name__}")
            if kind == "eof":
                raise MCPProtocolError(f"MCP stdio process exited before JSON-RPC id {expected_id} (exit {self.process.poll()})")
            raw = str(value).rstrip("\r\n")
            encoded_size = len(raw.encode("utf-8"))
            self._response_bytes += encoded_size
            if self._response_bytes > int(self.config["max_response_bytes"]):
                raise MCPProtocolError("MCP stdio response exceeded the configured byte boundary")
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise MCPProtocolError("MCP stdio stdout contained non-JSON protocol output") from exc
            if not isinstance(parsed, dict) or parsed.get("jsonrpc") != "2.0":
                raise MCPProtocolError("MCP stdio stdout contained an invalid JSON-RPC message")
            raw_lines.append(raw)
            self._transcript.append({"direction": "target-to-client", "raw": raw, "message": parsed, "timestamp_ns": time.time_ns()})
            if "id" not in parsed and isinstance(parsed.get("method"), str):
                notifications.append(parsed)
                continue
            if str(parsed.get("id")) != str(expected_id):
                raise MCPProtocolError(f"MCP stdio returned unexpected JSON-RPC id {parsed.get('id')}")
            if "result" not in parsed and "error" not in parsed:
                raise MCPProtocolError("MCP stdio response contained neither result nor error")
            self.last_notifications = notifications
            return parsed, "\n".join(raw_lines), notifications

    def send_notification(self, message: dict[str, Any]) -> str:
        return self._write(message)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self.process.stdin is not None:
            try:
                self.process.stdin.close()
            except OSError:
                pass
        try:
            self.process.wait(timeout=float(self.config["shutdown_timeout_seconds"]))
        except subprocess.TimeoutExpired:
            self.process.terminate()
            try:
                self.process.wait(timeout=float(self.config["shutdown_timeout_seconds"]))
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)
        for stream in (self.process.stdout, self.process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass

    def __enter__(self) -> "MCPStdioProcess":
        return self

    def __exit__(self, _type: Any, _value: Any, _traceback: Any) -> None:
        self.close()
