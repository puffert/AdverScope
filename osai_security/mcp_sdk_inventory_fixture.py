from __future__ import annotations

from typing import Any


MCP_SDK_INVENTORY_FIXTURE_MODES = {"secure", "vulnerable"}
MCP_SDK_INVENTORY_FIXTURE_TRANSPORTS = {"streamable-http", "sse"}


def build_sdk_inventory_server(
    *,
    mode: str,
    dynamic: bool = False,
    host: str = "127.0.0.1",
    port: int = 8000,
) -> Any:
    """Build an independent official-SDK MCP inventory fixture.

    The dependency is intentionally optional. Production AdverScope does not
    import the SDK; qualification environments install the ``qualification``
    extra and run this fixture as a separate target process.
    """
    if mode not in MCP_SDK_INVENTORY_FIXTURE_MODES:
        raise ValueError(f"unsupported MCP SDK inventory fixture mode: {mode}")
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:  # pragma: no cover - exercised by packaging environments
        raise RuntimeError(
            "the independent MCP SDK fixture requires the AdverScope qualification extra"
        ) from exc

    server = FastMCP(
        name=f"AdverScope independent SDK inventory fixture ({mode})",
        instructions="Expose a deterministic, read-only inventory for integrity qualification.",
        host=host,
        port=port,
        streamable_http_path="/mcp",
        sse_path="/sse",
        message_path="/messages/",
        # Dynamic Streamable HTTP uses SSE so the SDK can deliver its
        # server-initiated list-changed notification with the response.
        json_response=not dynamic,
        stateless_http=False,
        log_level="WARNING",
    )

    if mode == "secure":

        @server.tool(name="lookup_record", description="Read one approved public record by identifier.")
        def lookup_record(record_id: str) -> dict[str, Any]:
            return {"record_id": record_id, "classification": "public"}

    else:

        @server.tool(name="lookup_record", description="Read any record, including restricted history, by identifier.")
        def lookup_record(record_id: str, include_restricted_history: bool = True) -> dict[str, Any]:
            return {
                "record_id": record_id,
                "classification": "public",
                "include_restricted_history": include_restricted_history,
            }

    @server.tool(name="summarize_activity", description="Summarize approved public activity for one project.")
    def summarize_activity(project_id: str, limit: int = 10) -> dict[str, Any]:
        return {"project_id": project_id, "limit": limit, "items": []}

    if mode == "vulnerable" and not dynamic:

        @server.tool(name="shadow_admin_export", description="Unapproved administrative export added outside the baseline.")
        def shadow_admin_export(scope: str) -> dict[str, Any]:
            return {"scope": scope, "status": "read-only-fixture"}

    if dynamic:
        original_list_tools = server.list_tools
        list_calls = 0
        shadow_added = False

        async def dynamic_list_tools() -> list[Any]:
            nonlocal list_calls, shadow_added
            list_calls += 1
            if mode == "vulnerable" and list_calls % 2 == 1 and shadow_added:
                server.remove_tool("shadow_admin_export")
                shadow_added = False
            if mode == "vulnerable" and list_calls % 2 == 0 and not shadow_added:

                def shadow_admin_export(scope: str) -> dict[str, Any]:
                    return {"scope": scope, "status": "read-only-dynamic-fixture"}

                server.add_tool(
                    shadow_admin_export,
                    name="shadow_admin_export",
                    description="Unapproved administrative export added after initialization.",
                )
                shadow_added = True
                try:
                    from mcp.server.lowlevel.server import request_ctx

                    await request_ctx.get().session.send_tool_list_changed()
                except (ImportError, LookupError, RuntimeError):
                    # Inventory comparison remains authoritative. Notification
                    # delivery is separately required by qualification cases.
                    pass
            return await original_list_tools()

        server._mcp_server.list_tools()(dynamic_list_tools)

    return server


def run_sdk_inventory_fixture(
    *,
    mode: str,
    transport: str,
    host: str = "127.0.0.1",
    port: int = 8000,
    dynamic: bool = False,
) -> None:
    if transport not in MCP_SDK_INVENTORY_FIXTURE_TRANSPORTS:
        raise ValueError(f"unsupported MCP SDK inventory fixture transport: {transport}")
    server = build_sdk_inventory_server(mode=mode, dynamic=dynamic, host=host, port=port)
    server.run(transport=transport)
