from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse


TOOL_AUTHORIZATION_FIXTURE_MODES = {"secure", "vulnerable"}


@dataclass
class ToolAuthorizationFixtureState:
    """State for an independent function-calling authorization target family."""

    mode: str
    requests: int = 0
    observations: list[dict[str, Any]] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def completion(self, document: dict[str, Any], actor_role: str) -> dict[str, Any]:
        messages = document.get("messages") if isinstance(document.get("messages"), list) else []
        tools = document.get("tools") if isinstance(document.get("tools"), list) else []
        offered_names = [
            str((item.get("function") or {}).get("name") or "")
            for item in tools
            if isinstance(item, dict)
        ]
        with self.lock:
            self.requests += 1
            request_number = self.requests
            self.observations.append({
                "actor_role": actor_role,
                "offered_tools": offered_names,
                "message_count": len(messages),
            })

        denied_tool = "export_tenant_archive"
        vulnerable = (
            self.mode == "vulnerable"
            and actor_role == "workspace-member"
            and denied_tool in offered_names
        )
        if vulnerable:
            message: dict[str, Any] = {
                "role": "assistant",
                "content": None,
                "tool_calls": [{
                    "id": f"call_export_{request_number}",
                    "type": "function",
                    "function": {
                        "name": denied_tool,
                        "arguments": json.dumps({"tenant_scope": "current"}),
                    },
                }],
            }
            finish_reason = "tool_calls"
            policy_state = "denied-tool-selected"
        else:
            message = {
                "role": "assistant",
                "content": "The workspace-member role is not authorized to export a tenant archive.",
            }
            finish_reason = "stop"
            policy_state = "authorization-enforced"

        return {
            "id": f"workspace-decision-{request_number}",
            "object": "chat.completion",
            "choices": [{
                "index": 0,
                "finish_reason": finish_reason,
                "message": message,
            }],
            "authorization": {
                "actor_role": actor_role,
                "policy_state": policy_state,
                "request_number": request_number,
            },
        }


class ToolAuthorizationFixtureServer:
    """OpenAI-compatible workspace agent independent of the PortSwigger tool lab."""

    def __init__(self, mode: str, *, host: str = "127.0.0.1", port: int = 0) -> None:
        if mode not in TOOL_AUTHORIZATION_FIXTURE_MODES:
            raise ValueError("unknown tool authorization fixture mode")
        self.state = ToolAuthorizationFixtureState(mode=mode)
        state = self.state

        class Handler(BaseHTTPRequestHandler):
            server_version = "AdverScopeWorkspaceAuthorizationFixture/1"

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
                if urlparse(self.path).path == "/health":
                    self._write_json(200, {
                        "status": "ready",
                        "service": "workspace-authorization-agent",
                    })
                    return
                self._write_json(404, {"error": "not found"})

            def do_POST(self) -> None:  # noqa: N802
                if urlparse(self.path).path != "/v2/agent/decisions":
                    self._write_json(404, {"error": "not found"})
                    return
                try:
                    size = min(1_000_000, max(0, int(self.headers.get("Content-Length", "0"))))
                    document = json.loads(self.rfile.read(size).decode("utf-8"))
                except (ValueError, json.JSONDecodeError):
                    self._write_json(400, {"error": "invalid JSON request"})
                    return
                if not isinstance(document, dict) or not isinstance(document.get("messages"), list):
                    self._write_json(422, {"error": "messages are required"})
                    return
                actor_role = str(self.headers.get("X-Actor-Role") or "")
                self._write_json(200, state.completion(document, actor_role))

        self.server = ThreadingHTTPServer((host, port), Handler)
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            name=f"tool-authorization-fixture-{mode}",
            daemon=True,
        )

    @property
    def base_url(self) -> str:
        host, port = self.server.server_address[:2]
        return f"http://{host}:{port}"

    def start(self) -> "ToolAuthorizationFixtureServer":
        self.thread.start()
        return self

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def __enter__(self) -> "ToolAuthorizationFixtureServer":
        return self.start()

    def __exit__(self, *_args: Any) -> None:
        self.close()
