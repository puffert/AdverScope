from __future__ import annotations

from typing import Any


MCP_SDK_PROMPT_FIXTURE_MODES = {"secure", "vulnerable"}
MCP_SDK_PROMPT_FIXTURE_TRANSPORTS = {"streamable-http", "sse"}
PUBLIC_PROMPT = "public_incident_summary"
PROTECTED_PROMPT = "confidential_incident_triage"
SYNTHETIC_PROMPT_MARKER = "ADV-MCP-SDK-PROMPT-EVIDENCE"


def build_sdk_prompt_server(*, mode: str, host: str = "127.0.0.1", port: int = 8000) -> Any:
    """Build an unrelated prompt-boundary target with the official Python MCP SDK."""
    if mode not in MCP_SDK_PROMPT_FIXTURE_MODES:
        raise ValueError(f"unsupported MCP SDK prompt fixture mode: {mode}")
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:  # pragma: no cover - optional qualification environment
        raise RuntimeError("the official MCP SDK prompt fixture requires the qualification extra") from exc

    server = FastMCP(
        name=f"AdverScope independent SDK prompt fixture ({mode})",
        instructions="Expose only prompt templates permitted for the configured qualification identity.",
        host=host,
        port=port,
        streamable_http_path="/mcp",
        sse_path="/sse",
        message_path="/messages/",
        json_response=True,
        stateless_http=False,
        log_level="WARNING",
    )

    @server.prompt(name=PUBLIC_PROMPT, description="Create a public incident summary.")
    def public_incident_summary(case_id: str) -> str:
        return f"Create a public summary for synthetic case {case_id}."

    if mode == "vulnerable":

        @server.prompt(name=PROTECTED_PROMPT, description="Synthetic restricted incident-response prompt.")
        def confidential_incident_triage(case_id: str) -> str:
            return f"Protected synthetic workflow {case_id}: {SYNTHETIC_PROMPT_MARKER}"

    return server


def run_sdk_prompt_fixture(
    *,
    mode: str,
    transport: str,
    host: str = "127.0.0.1",
    port: int = 8000,
) -> None:
    if transport not in MCP_SDK_PROMPT_FIXTURE_TRANSPORTS:
        raise ValueError(f"unsupported MCP SDK prompt fixture transport: {transport}")
    build_sdk_prompt_server(mode=mode, host=host, port=port).run(transport=transport)
