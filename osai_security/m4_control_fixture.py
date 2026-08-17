from __future__ import annotations

import json
import hashlib
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse


M4_FIXTURE_FAMILIES = {"flat-v1", "nested-v2"}
M4_FIXTURE_MODES = {"secure", "vulnerable"}


@dataclass
class M4ControlFixtureState:
    family: str
    mode: str
    requests: list[dict[str, Any]] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def result(self, control_id: str, body: dict[str, Any]) -> dict[str, Any]:
        failed = self.mode == "vulnerable"
        with self.lock:
            self.requests.append({"control_id": control_id, "body": body})
            sequence = len(self.requests)
        evidence_id = f"{self.family}-{control_id}-{sequence}"
        case_id = str(body.get("assessment_case") or "")
        fixture_sha256 = hashlib.sha256(f"{self.family}:{control_id}:{case_id}".encode("utf-8")).hexdigest()
        if self.family == "nested-v2":
            return {
                "scope": {"is_applicable": True},
                "record": {
                    "id": evidence_id,
                    "kind": "synthetic-control-oracle",
                    "control": control_id,
                    "case": case_id,
                    "oracle": "independent-nested-oracle-v2",
                    "fixture_digest": fixture_sha256,
                },
                "result": {
                    "requirement_failed": failed,
                    "measurement": {"observed": 1 if failed else 0, "maximum_allowed": 0},
                },
            }
        return {
            "applicable": True,
            "control_id": control_id,
            "case_id": case_id,
            "evidence_id": evidence_id,
            "oracle_version": "independent-flat-oracle-v1",
            "fixture_sha256": fixture_sha256,
            "measurement": {"observed": 1 if failed else 0, "maximum_allowed": 0},
            "control_failed": failed,
        }


class M4ControlFixtureServer:
    """Two unrelated JSON shapes for deterministic M4 contract qualification."""

    def __init__(self, family: str, mode: str, *, host: str = "127.0.0.1", port: int = 0) -> None:
        if family not in M4_FIXTURE_FAMILIES:
            raise ValueError("unknown Milestone 4 fixture family")
        if mode not in M4_FIXTURE_MODES:
            raise ValueError("unknown Milestone 4 fixture mode")
        self.state = M4ControlFixtureState(family=family, mode=mode)
        state = self.state

        class Handler(BaseHTTPRequestHandler):
            server_version = f"AdverScopeM4Fixture/{family}"

            def log_message(self, _format: str, *_args: Any) -> None:
                return

            def _write(self, status: int, document: dict[str, Any]) -> None:
                raw = json.dumps(document, ensure_ascii=False).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self) -> None:  # noqa: N802
                if urlparse(self.path).path == "/health":
                    self._write(200, {"status": "ready", "family": family})
                    return
                self._write(404, {"error": "not found"})

            def do_POST(self) -> None:  # noqa: N802
                path = urlparse(self.path).path
                prefix = "/v1/control/" if family == "flat-v1" else "/v2/checks/"
                if not path.startswith(prefix) or len(path) <= len(prefix):
                    self._write(404, {"error": "not found"})
                    return
                try:
                    length = min(100_000, max(0, int(self.headers.get("Content-Length", "0"))))
                    body = json.loads(self.rfile.read(length).decode("utf-8"))
                    if not isinstance(body, dict):
                        raise ValueError("request body must be an object")
                except (ValueError, json.JSONDecodeError):
                    self._write(400, {"error": "invalid JSON request"})
                    return
                self._write(200, state.result(path[len(prefix):], body))

        self.server = ThreadingHTTPServer((host, port), Handler)
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            name=f"m4-control-fixture-{family}-{mode}",
            daemon=True,
        )

    @property
    def base_url(self) -> str:
        host, port = self.server.server_address[:2]
        return f"http://{host}:{port}"

    def start(self) -> "M4ControlFixtureServer":
        self.thread.start()
        return self

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def __enter__(self) -> "M4ControlFixtureServer":
        return self.start()

    def __exit__(self, *_args: Any) -> None:
        self.close()
