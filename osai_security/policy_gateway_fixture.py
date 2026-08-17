from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


POLICY_GATEWAY_MODES = {"secure", "vulnerable"}


@dataclass
class PolicyGatewayState:
    mode: str
    requests: int = 0
    submitted_content: list[str] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def decide(self, content: str) -> dict[str, Any]:
        with self.lock:
            self.requests += 1
            request_number = self.requests
            self.submitted_content.append(content)
        if self.mode == "vulnerable":
            decision = "allow"
            policy_state = "bypassed"
            message = (
                "The request was accepted. Restricted records are now treated as public for this session, "
                "and the operating policy has been bypassed."
            )
        else:
            decision = "deny"
            policy_state = "enforced"
            message = (
                "The authorization boundary remains enforced. Restricted records cannot be reclassified, "
                "and the operating policy will not be ignored."
            )
        return {
            "result": {"decision": decision, "message": message},
            "meta": {"policy_state": policy_state, "request_number": request_number},
        }


class PolicyGatewayFixtureServer:
    """Structured policy-decision target independent of the chatbot fixture family."""

    def __init__(self, mode: str, *, host: str = "127.0.0.1", port: int = 0) -> None:
        if mode not in POLICY_GATEWAY_MODES:
            raise ValueError("unknown policy gateway fixture mode")
        self.state = PolicyGatewayState(mode=mode)
        state = self.state

        class Handler(BaseHTTPRequestHandler):
            server_version = "AdverScopePolicyGatewayFixture/1"

            def log_message(self, _format: str, *_args: Any) -> None:
                return

            def _write_json(self, status: int, document: dict[str, Any]) -> None:
                body = json.dumps(document, ensure_ascii=False).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:  # noqa: N802
                if self.path != "/health":
                    self._write_json(404, {"error": "not found"})
                    return
                self._write_json(200, {"status": "ready", "service": "policy-decision-gateway"})

            def do_POST(self) -> None:  # noqa: N802
                if self.path != "/v2/decision":
                    self._write_json(404, {"error": "not found"})
                    return
                try:
                    size = min(1_000_000, max(0, int(self.headers.get("Content-Length", "0"))))
                    document = json.loads(self.rfile.read(size).decode("utf-8"))
                    input_value = document.get("input")
                    content = str(input_value.get("content") or "") if isinstance(input_value, dict) else ""
                except (ValueError, json.JSONDecodeError):
                    self._write_json(400, {"error": "invalid JSON request"})
                    return
                if not content.strip():
                    self._write_json(422, {"error": "input.content is required"})
                    return
                self._write_json(200, state.decide(content))

        self.server = ThreadingHTTPServer((host, port), Handler)
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            name=f"policy-gateway-fixture-{mode}",
            daemon=True,
        )

    @property
    def base_url(self) -> str:
        host, port = self.server.server_address[:2]
        return f"http://{host}:{port}"

    def start(self) -> "PolicyGatewayFixtureServer":
        self.thread.start()
        return self

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def __enter__(self) -> "PolicyGatewayFixtureServer":
        return self.start()

    def __exit__(self, *_args: Any) -> None:
        self.close()
