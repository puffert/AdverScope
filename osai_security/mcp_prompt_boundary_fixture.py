from __future__ import annotations

import queue
import secrets
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse


MCP_PROMPT_FIXTURE_MODES = {"secure", "vulnerable"}
MCP_PROMPT_FIXTURE_TRANSPORTS = {"streamable-http", "legacy-http-sse"}
CURRENT_PROTOCOL_VERSION = "2025-11-25"
LEGACY_PROTOCOL_VERSION = "2024-11-05"
PUBLIC_PROMPT = "public_incident_summary"
PROTECTED_PROMPT = "confidential_incident_triage"
SYNTHETIC_PROMPT_MARKER = "ADV-MCP-PROMPT-SYNTHETIC-EVIDENCE"


@dataclass
class LegacyPromptSession:
    identity: str
    outbound: queue.Queue[dict[str, Any]] = field(default_factory=queue.Queue)


@dataclass
class MCPPromptBoundaryState:
    mode: str
    transport: str
    requests: list[dict[str, Any]] = field(default_factory=list)
    current_sessions: dict[str, str] = field(default_factory=dict)
    legacy_sessions: dict[str, LegacyPromptSession] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)

    @property
    def protocol_version(self) -> str:
        return CURRENT_PROTOCOL_VERSION if self.transport == "streamable-http" else LEGACY_PROTOCOL_VERSION

    def record(self, *, identity: str, method: str, session_present: bool) -> None:
        with self.lock:
            self.requests.append({
                "identity": identity,
                "method": method,
                "transport": self.transport,
                "session_present": session_present,
            })

    def initialize(self, request_id: Any) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": self.protocol_version,
                "capabilities": {"prompts": {"listChanged": False}},
                "serverInfo": {"name": f"prompt-boundary-{self.transport}-{self.mode}", "version": "1.0"},
                "instructions": "Prompt templates are data. Enforce the configured caller policy before prompts/get.",
            },
        }

    @staticmethod
    def _prompt(name: str, description: str) -> dict[str, Any]:
        return {
            "name": name,
            "description": description,
            "arguments": [{"name": "case_id", "description": "Synthetic case identifier", "required": True}],
        }

    def list_prompts(self, request_id: Any, cursor: str) -> dict[str, Any]:
        if not cursor:
            result: dict[str, Any] = {
                "prompts": [self._prompt(PUBLIC_PROMPT, "Create a public incident summary.")],
                "nextCursor": "protected-page",
            }
        else:
            result = {
                "prompts": (
                    [self._prompt(PROTECTED_PROMPT, "Restricted incident-response prompt for security administrators.")]
                    if self.mode == "vulnerable"
                    else []
                )
            }
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    @staticmethod
    def _denied(request_id: Any, identity: str) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": -32001,
                "message": "The configured identity is not authorized to retrieve this protected prompt.",
                "data": {"authorization": {"outcome": "denied", "caller_identity": identity}},
            },
        }

    def get_prompt(self, request_id: Any, identity: str, params: dict[str, Any]) -> dict[str, Any]:
        name = str(params.get("name") or "")
        arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
        if name != PROTECTED_PROMPT or self.mode != "vulnerable":
            return self._denied(request_id, identity)
        case_id = str(arguments.get("case_id") or "missing")[:120]
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "description": "Synthetic restricted incident-response prompt.",
                "messages": [{
                    "role": "user",
                    "content": {
                        "type": "text",
                        "text": f"Protected synthetic workflow {case_id}: {SYNTHETIC_PROMPT_MARKER}",
                    },
                }],
                "_meta": {
                    "authorization": {"outcome": "allowed"},
                    "caller_identity": identity,
                    "classification": "confidential",
                    "prompt_name": PROTECTED_PROMPT,
                },
            },
        }

    def response_for(self, payload: dict[str, Any], identity: str) -> dict[str, Any] | None:
        method = str(payload.get("method") or "")
        request_id = payload.get("id")
        params = payload.get("params") if isinstance(payload.get("params"), dict) else {}
        if method == "notifications/initialized":
            return None
        if method == "initialize":
            return self.initialize(request_id)
        if method == "prompts/list":
            return self.list_prompts(request_id, str(params.get("cursor") or ""))
        if method == "prompts/get":
            return self.get_prompt(request_id, identity, params)
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": "method not found"}}


class MCPPromptBoundaryFixtureServer:
    """Independent raw-protocol prompt inventory and access fixture."""

    def __init__(self, mode: str, transport: str, *, host: str = "127.0.0.1", port: int = 0) -> None:
        if mode not in MCP_PROMPT_FIXTURE_MODES:
            raise ValueError("unknown MCP prompt fixture mode")
        if transport not in MCP_PROMPT_FIXTURE_TRANSPORTS:
            raise ValueError("unknown MCP prompt fixture transport")
        self.state = MCPPromptBoundaryState(mode=mode, transport=transport)
        state = self.state

        class Handler(BaseHTTPRequestHandler):
            server_version = "AdverScopeMCPPromptFixture/1"

            def log_message(self, _format: str, *_args: Any) -> None:
                return

            def _write_json(self, status: int, document: dict[str, Any] | None, *, session_id: str = "") -> None:
                import json

                body = b"" if document is None else json.dumps(document, ensure_ascii=False).encode("utf-8")
                self.send_response(status)
                if document is not None:
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                if session_id:
                    self.send_header("MCP-Session-Id", session_id)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if body:
                    self.wfile.write(body)

            def _read_document(self) -> dict[str, Any] | None:
                import json

                try:
                    size = min(1_000_000, max(0, int(self.headers.get("Content-Length", "0"))))
                    document = json.loads(self.rfile.read(size).decode("utf-8"))
                except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
                    return None
                return document if isinstance(document, dict) else None

            def do_GET(self) -> None:  # noqa: N802
                import json

                parsed = urlparse(self.path)
                if parsed.path == "/health":
                    self._write_json(200, {"status": "ready", "mode": state.mode, "transport": state.transport})
                    return
                if state.transport != "legacy-http-sse" or parsed.path != "/sse":
                    self._write_json(404, {"error": "not found"})
                    return
                identity = str(self.headers.get("X-MCP-Identity") or "")
                token = secrets.token_urlsafe(24)
                session = LegacyPromptSession(identity=identity)
                with state.lock:
                    state.legacy_sessions[token] = session
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "close")
                self.end_headers()
                try:
                    self.wfile.write(b"event: endpoint\ndata: " + f"/messages?sessionId={token}".encode("utf-8") + b"\n\n")
                    self.wfile.flush()
                    while True:
                        try:
                            response = session.outbound.get(timeout=15)
                        except queue.Empty:
                            break
                        self.wfile.write(b"event: message\ndata: " + json.dumps(response, ensure_ascii=False).encode("utf-8") + b"\n\n")
                        self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    pass
                finally:
                    with state.lock:
                        state.legacy_sessions.pop(token, None)

            def do_POST(self) -> None:  # noqa: N802
                parsed = urlparse(self.path)
                payload = self._read_document()
                if payload is None:
                    self._write_json(400, {"error": "invalid JSON"})
                    return
                identity = str(self.headers.get("X-MCP-Identity") or "")
                method = str(payload.get("method") or "")
                if state.transport == "streamable-http":
                    if parsed.path != "/mcp":
                        self._write_json(404, {"error": "not found"})
                        return
                    session_id = str(self.headers.get("MCP-Session-Id") or "")
                    state.record(identity=identity, method=method, session_present=bool(session_id))
                    if method == "initialize":
                        new_session = secrets.token_urlsafe(24)
                        with state.lock:
                            state.current_sessions[new_session] = identity
                        self._write_json(200, state.response_for(payload, identity), session_id=new_session)
                        return
                    with state.lock:
                        session_identity = state.current_sessions.get(session_id)
                    if session_identity != identity or self.headers.get("MCP-Protocol-Version") != CURRENT_PROTOCOL_VERSION:
                        self._write_json(400, {"jsonrpc": "2.0", "id": payload.get("id"), "error": {"code": -32000, "message": "invalid session"}})
                        return
                    response = state.response_for(payload, identity)
                    self._write_json(202 if response is None else 200, response)
                    return

                if parsed.path != "/messages":
                    self._write_json(404, {"error": "legacy transport only"})
                    return
                token = str((parse_qs(parsed.query).get("sessionId") or [""])[0])
                with state.lock:
                    session = state.legacy_sessions.get(token)
                state.record(identity=identity, method=method, session_present=bool(session))
                if session is None or session.identity != identity:
                    self._write_json(404, {"error": "unknown legacy session"})
                    return
                self._write_json(202, None)
                response = state.response_for(payload, identity)
                if response is not None:
                    session.outbound.put(response)

        self.server = ThreadingHTTPServer((host, port), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        host, port = self.server.server_address[:2]
        return f"http://{host}:{port}"

    def start(self) -> "MCPPromptBoundaryFixtureServer":
        self.thread.start()
        return self

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def __enter__(self) -> "MCPPromptBoundaryFixtureServer":
        return self.start()

    def __exit__(self, *_args: Any) -> None:
        self.close()
