from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse


AGENTIC_TRACE_FIXTURE_MODES = {"secure", "vulnerable"}


@dataclass
class AgenticTraceFixtureState:
    mode: str
    requests: int = 0
    effect_count: int = 0
    observations: list[dict[str, Any]] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def execute(self, prompt: str, identity: str) -> dict[str, Any]:
        approval_case = "APPROVAL_BOUNDARY" in prompt
        target_action = "export-tenant"
        vulnerable = self.mode == "vulnerable" and identity == "standard-user"
        with self.lock:
            self.requests += 1
            if vulnerable:
                self.effect_count += 1
            self.observations.append({
                "identity": identity,
                "approval_case": approval_case,
                "vulnerable": vulnerable,
            })
            request_number = self.requests
        return {
            "answer": "Agent workflow completed." if vulnerable else "The requested action was blocked by policy.",
            "agent_trace": {
                "trace_id": f"trace-{request_number}",
                "plan": {"action": target_action},
                "approval": {"state": "pending" if approval_case else "not-required"},
                "execution": {
                    "action": target_action,
                    "state": "executed" if vulnerable else "blocked",
                },
            },
        }


class AgenticTraceFixtureServer:
    """Independent safe/vulnerable planner-executor target for qualification."""

    def __init__(self, mode: str, *, host: str = "127.0.0.1", port: int = 0) -> None:
        if mode not in AGENTIC_TRACE_FIXTURE_MODES:
            raise ValueError("unknown agentic trace fixture mode")
        self.state = AgenticTraceFixtureState(mode=mode)
        state = self.state

        class Handler(BaseHTTPRequestHandler):
            server_version = "AdverScopeAgenticTraceFixture/1"

            def log_message(self, _format: str, *_args: Any) -> None:
                return

            def _write_json(self, status: int, document: dict[str, Any]) -> None:
                body = json.dumps(document, ensure_ascii=False).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:  # noqa: N802
                path = urlparse(self.path).path
                if path == "/health":
                    self._write_json(200, {"status": "ready"})
                    return
                if path == "/effects":
                    with state.lock:
                        count = state.effect_count
                    self._write_json(200, {"effect_count": count})
                    return
                self._write_json(404, {"error": "not found"})

            def do_POST(self) -> None:  # noqa: N802
                path = urlparse(self.path).path
                if path == "/effects/reset":
                    with state.lock:
                        state.effect_count = 0
                    self._write_json(200, {"reset": True})
                    return
                if path != "/agent/run":
                    self._write_json(404, {"error": "not found"})
                    return
                try:
                    size = min(1_000_000, max(0, int(self.headers.get("Content-Length", "0"))))
                    document = json.loads(self.rfile.read(size).decode("utf-8"))
                except (ValueError, json.JSONDecodeError):
                    self._write_json(400, {"error": "invalid JSON request"})
                    return
                prompt = str(document.get("message") or "") if isinstance(document, dict) else ""
                identity = str(self.headers.get("X-Agent-Identity") or "")
                self._write_json(200, state.execute(prompt, identity))

        self.server = ThreadingHTTPServer((host, port), Handler)
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            name=f"agentic-trace-fixture-{mode}",
            daemon=True,
        )

    @property
    def base_url(self) -> str:
        host, port = self.server.server_address[:2]
        return f"http://{host}:{port}"

    def start(self) -> "AgenticTraceFixtureServer":
        self.thread.start()
        return self

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def __enter__(self) -> "AgenticTraceFixtureServer":
        return self.start()

    def __exit__(self, *_args: Any) -> None:
        self.close()
