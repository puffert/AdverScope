from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from .mcp_security import (
    MCP_CURRENT_VERSION,
    MCP_LEGACY_HTTP_SSE,
    MCP_MODERN_VERSION,
    MCPProtocolError,
    MCPProtocolSession,
    parse_jsonrpc_exchange,
)
from .mcp_stdio import MCP_STDIO, MCPStdioProcess
from .security import redact_text, safe_error
from .targets import (
    TargetClient,
    TargetError,
    route_is_authorized,
    target_runtime_readiness,
    target_url,
)


PREFLIGHT_SCHEMA_VERSION = "adverscope-target-preflight-v1"
PREFLIGHT_PROMPT = (
    "AdverScope connection preflight. Reply with a short acknowledgement only. "
    "Do not use tools, change data, or perform external actions."
)

COMMON_RESPONSE_PATHS = (
    "choices.0.message.content",
    "choices.0.delta.content",
    "choices.0.text",
    "data.response",
    "data.answer",
    "data.message.content",
    "data.message",
    "result.response",
    "result.answer",
    "result.message.content",
    "result.message",
    "message.content",
    "response",
    "answer",
    "output_text",
    "output",
    "message",
    "content",
    "text",
)


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def target_preflight_signature(target: dict[str, Any], guardrail: dict[str, Any]) -> str:
    """Fingerprint only stored configuration, never resolved secret values."""
    return _canonical_sha256({
        "target": {
            key: target.get(key)
            for key in (
                "id", "kind", "base_url", "path", "method", "headers",
                "request_template", "response_path", "browser_profile",
                "analysis_config", "conversation_config", "transport_config",
                "evaluation_config", "technique_adapters",
                "assessment_contracts", "authorized_routes", "scope_confirmed",
            )
        },
        "guardrail": {
            key: guardrail.get(key)
            for key in (
                "id", "status", "max_requests", "max_runtime_seconds",
                "allow_active_recon", "allow_screenshots", "stop_on_http_5xx",
            )
        },
    })


def _extract_path(value: Any, path: str) -> tuple[bool, Any]:
    current = value
    for raw in str(path or "").replace("[", ".").replace("]", "").split("."):
        part = raw.strip()
        if not part:
            continue
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return False, None
    return True, current


def _prompt_paths(value: Any, location: str = "request") -> list[str]:
    paths: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            paths.extend(_prompt_paths(child, f"{location}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            paths.extend(_prompt_paths(child, f"{location}[{index}]"))
    elif isinstance(value, str) and "{{prompt}}" in value:
        paths.append(location)
    return paths


def _request_shape(target: dict[str, Any]) -> dict[str, Any]:
    template = target.get("request_template") or {}
    prompt_paths = _prompt_paths(template)
    if isinstance(template, dict) and isinstance(template.get("messages"), list):
        schema = "OpenAI-compatible messages"
    elif prompt_paths:
        schema = "JSON prompt template"
    elif str(target.get("method") or "").upper() in {"GET", "OPTIONS"}:
        schema = "body-free HTTP request"
    else:
        schema = "explicit API request"
    return {"schema": schema, "prompt_paths": prompt_paths}


def _response_candidate(raw: str) -> dict[str, Any]:
    try:
        parsed = json.loads(raw or "")
    except json.JSONDecodeError:
        return {"format": "text", "candidate_path": "", "candidate_present": bool(raw)}
    for path in COMMON_RESPONSE_PATHS:
        found, value = _extract_path(parsed, path)
        if found and value not in (None, ""):
            return {
                "format": "json",
                "candidate_path": path,
                "candidate_present": True,
                "candidate_type": type(value).__name__,
            }
    return {
        "format": "json",
        "candidate_path": "",
        "candidate_present": bool(parsed),
        "candidate_type": type(parsed).__name__,
    }


def _check(
    checks: list[dict[str, Any]],
    check_id: str,
    category: str,
    label: str,
    status: str,
    message: str,
    section: str,
) -> None:
    checks.append({
        "id": check_id,
        "category": category,
        "label": label,
        "status": status,
        "message": message,
        "section": section,
    })


def _mcp_request_ceiling(profile: dict[str, Any]) -> int:
    transport = str(profile.get("transport") or "auto")
    if transport == MCP_LEGACY_HTTP_SSE:
        return 3
    versions = list(profile.get("protocol_versions") or [MCP_CURRENT_VERSION])
    return 1 if versions and versions[0] == MCP_MODERN_VERSION and len(versions) == 1 else 3


def _concrete_route(path: Any) -> str:
    value = str(path or "")
    for placeholder in ("document_id", "canary", "case_id", "owner_identity_id", "query_identity_id"):
        value = value.replace("{{" + placeholder + "}}", "adverscope-preflight")
    return value


def _route_ready(target: dict[str, Any], path: Any, method: Any) -> bool:
    try:
        return bool(str(path or "") and str(method or "") and route_is_authorized(target, str(path), str(method)))
    except (ValueError, TargetError):
        return False


def build_target_preflight_readiness(target: dict[str, Any], guardrail: dict[str, Any]) -> dict[str, Any]:
    """Build the local, no-traffic part of target readiness."""
    checks: list[dict[str, Any]] = []
    request_shape = _request_shape(target)
    evaluation = target.get("evaluation_config") or {}
    mcp = evaluation.get("mcp") or {}
    rag = evaluation.get("rag") or {}
    tool_agent = evaluation.get("tool_agent") or {}
    agentic_trace = evaluation.get("agentic_trace") or {}
    browser = target.get("browser_profile") or {}

    _check(
        checks, "target-authorized", "Authorization", "Exact target is authorized",
        "pass" if target.get("scope_confirmed") else "fail",
        "The saved target is inside the approved scope." if target.get("scope_confirmed") else "Confirm this exact target under Attack Surface before sending setup traffic.",
        "target-form",
    )
    approved = guardrail.get("status") == "approved"
    _check(
        checks, "guardrail-approved", "Authorization", "Execution guardrail is approved",
        "pass" if approved else "fail",
        "The setup request is covered by an approved execution boundary." if approved else "Review and approve the target guardrail before testing the connection.",
        "guardrail-form",
    )
    resolved_url = ""
    try:
        resolved_url = target_url(target)
        _check(checks, "exact-route", "Connection", "Exact route resolves", "pass", f"Only {str(target.get('method') or '').upper()} {resolved_url} will be used.", "target-form")
    except (ValueError, TargetError) as exc:
        _check(checks, "exact-route", "Connection", "Exact route resolves", "fail", safe_error(exc), "target-form")

    runtime = target_runtime_readiness(target)
    _check(
        checks, "environment-references", "Authentication", "Environment references are ready",
        "pass" if runtime["ready"] else "fail",
        (
            f"{len(runtime['checks'])} environment-backed value(s) are present; their values remain hidden."
            if runtime["ready"]
            else "; ".join(str(item.get("message") or "An environment value is missing.") for item in runtime["issues"])
        ),
        "evaluation-config-form" if any(str(item.get("location") or "").startswith("adapter") for item in runtime["issues"]) else "target-form",
    )

    kind = str(target.get("kind") or "")
    method = str(target.get("method") or "").upper()
    if kind == "chatbot":
        prompt_ready = bool(request_shape["prompt_paths"])
        _check(
            checks, "request-schema", "Request schema", "Prompt field is mapped",
            "pass" if prompt_ready else "fail",
            (
                "Prompt placeholder found at " + ", ".join(request_shape["prompt_paths"])
                if prompt_ready else "Map {{prompt}} to the target-owned request field before testing the connection."
            ),
            "target-form",
        )
    elif kind == "browser-chatbot":
        selector_ready = all(str(browser.get(name) or "").strip() for name in ("input_selector", "submit_selector", "response_selector"))
        _check(
            checks, "browser-selectors", "Browser", "Required selectors are configured",
            "pass" if selector_ready else "fail",
            "Input, submit, and response selectors will be checked without submitting a message." if selector_ready else "Add input, submit, and response selectors for the browser chatbot.",
            "target-form",
        )
        _check(
            checks, "screenshot-permission", "Browser", "Screenshot permission",
            "pass" if guardrail.get("allow_screenshots") else "warning",
            "The approved guardrail allows assessment screenshots." if guardrail.get("allow_screenshots") else "Screenshots are disabled. Selector readiness can still be tested, but assessment screenshots will not be captured.",
            "guardrail-form",
        )

    response_path = str(target.get("response_path") or "")
    if kind == "browser-chatbot":
        _check(
            checks, "response-path", "Response schema", "DOM response extraction rule",
            "pass",
            f"Configured DOM response selector: {browser.get('response_selector')}",
            "target-form",
        )
    elif any(profile.get("enabled") for profile in (mcp, rag, tool_agent, agentic_trace)):
        enabled_names = [name for name, profile in (("MCP", mcp), ("RAG", rag), ("tool-agent", tool_agent), ("agentic trace", agentic_trace)) if profile.get("enabled")]
        _check(
            checks, "response-path", "Response schema", "Native adapter response contract",
            "pass",
            ", ".join(enabled_names) + " response schemas are defined by the saved native adapter.",
            "evaluation-config-form",
        )
    else:
        _check(
            checks, "response-path", "Response schema", "Response extraction rule",
            "pass" if response_path else "warning",
            f"Configured response JSON path: {response_path}" if response_path else "No response path is saved. Preflight will inspect the exact response for a common, non-persisted candidate.",
            "target-form",
        )

    required_requests = 1
    if mcp.get("enabled"):
        required_requests = _mcp_request_ceiling(mcp)
        transport = str(mcp.get("transport") or "auto")
        if transport == MCP_STDIO:
            stdio = mcp.get("stdio") or {}
            executable_ready = bool(stdio.get("executable") and stdio.get("executable_sha256"))
            _check(
                checks, "mcp-stdio-executable", "MCP", "MCP stdio executable is pinned",
                "pass" if executable_ready else "fail",
                (
                    f"The local executable is pinned by SHA-256 {str(stdio.get('executable_sha256') or '')[:12]}…."
                    if executable_ready else "Select an absolute local executable and record its SHA-256 digest."
                ),
                "evaluation-config-form",
            )
        else:
            endpoint = str(mcp.get("endpoint_path") or "")
            endpoint_ready = bool(endpoint and route_is_authorized(target, endpoint, "POST"))
            _check(
                checks, "mcp-endpoint", "MCP", "MCP lifecycle endpoint is authorized",
                "pass" if endpoint_ready else "fail",
                f"POST {endpoint} is authorized for a read-only lifecycle negotiation." if endpoint_ready else "Map the configured MCP POST endpoint under authorized routes.",
                "evaluation-config-form",
            )
        identities = mcp.get("identities") or []
        _check(
            checks, "mcp-identity", "MCP", "MCP identity is configured",
            "pass" if identities else "fail",
            f"{len(identities)} target-owned MCP identity profile(s) are available." if identities else "Add at least one MCP identity profile.",
            "evaluation-config-form",
        )
        versions = list(mcp.get("protocol_versions") or [])
        _check(
            checks, "mcp-protocol", "MCP", "Current and legacy protocol policy",
            "pass" if versions else "fail",
            "Negotiation order: " + ", ".join(versions) if versions else "Configure at least one supported MCP protocol version.",
            "evaluation-config-form",
        )
        if transport == MCP_LEGACY_HTTP_SSE:
            legacy_path = str(mcp.get("legacy_sse_path") or "")
            legacy_ready = bool(legacy_path and route_is_authorized(target, legacy_path, "GET"))
            _check(
                checks, "mcp-legacy-route", "MCP", "Legacy HTTP+SSE route is authorized",
                "pass" if legacy_ready else "fail",
                f"GET {legacy_path} may establish the legacy event channel." if legacy_ready else "Map the legacy MCP SSE GET route before using legacy mode.",
                "evaluation-config-form",
            )

    if rag.get("enabled"):
        operations = rag.get("operations") or {}
        identities = rag.get("identities") or []
        required_names = {"ingest", "query", "cleanup"}
        present_names = set(operations)
        _check(
            checks, "rag-operations", "RAG", "RAG lifecycle routes are complete",
            "pass" if required_names.issubset(present_names) else "fail",
            (
                "Ingestion, query, and cleanup operations are mapped; preflight validates them without creating documents."
                if required_names.issubset(present_names)
                else "Map explicit ingestion, query, and cleanup operations."
            ),
            "evaluation-config-form",
        )
        route_results = []
        for operation in operations.values():
            try:
                route_results.append(_route_ready(
                    target,
                    _concrete_route(operation.get("path")),
                    str(operation.get("method") or ""),
                ))
            except (ValueError, TargetError):
                route_results.append(False)
        _check(
            checks, "rag-route-authorization", "RAG", "RAG routes remain inside the allowlist",
            "pass" if route_results and all(route_results) else "fail",
            "Every configured ingestion, query, and cleanup operation resolves to an authorized same-origin route." if route_results and all(route_results) else "Authorize every configured RAG operation route before assessment execution.",
            "evaluation-config-form",
        )
        _check(
            checks, "rag-identities", "RAG", "RAG identities are configured",
            "pass" if identities else "fail",
            f"{len(identities)} target-owned identity profile(s) are available." if identities else "Add the identities needed for ingestion, query, and cleanup.",
            "evaluation-config-form",
        )
        rag_cases = rag.get("cases") or []
        query_attempts = max(1, int(rag.get("query_attempts") or 1))
        cleanup_verify_attempts = max(1, int(rag.get("cleanup_verify_attempts") or 1))
        transport_profile = target.get("transport_config") or {}
        configured_retries = (
            max(0, int(transport_profile.get("max_retries") or 0))
            if transport_profile.get("enabled")
            else 0
        )

        def rag_operation_cost(name: str, count: int = 1) -> int:
            operation = operations.get(name) or {}
            method = str(operation.get("method") or "").upper()
            replay_safe = method in {"GET", "HEAD", "OPTIONS"} or operation.get("replay_safe") is True
            return count * (1 + (configured_retries if replay_safe else 0))

        rag_case_estimates = [
            (
                rag_operation_cost("ingest")
                + rag_operation_cost("cleanup")
                + rag_operation_cost(
                    "query",
                    1  # clean baseline
                    + query_attempts
                    + cleanup_verify_attempts
                    + (
                        1
                        if case.get("control_query")
                        or case.get("scenario") in {"cross-identity-retrieval", "retrieval-access-bypass"}
                        else 0
                    ),
                )
            )
            for case in rag_cases
        ]
        # The engine stops this technique after the first reproduced proof, so a
        # complete safe campaign needs every initial attempt while the worst case
        # adds exactly one full reproduction (which may occur on the final case).
        rag_estimate = sum(rag_case_estimates)
        if guardrail.get("allow_reproduction") and rag_case_estimates:
            rag_estimate += max(rag_case_estimates)
        rag_budget_ready = rag_estimate <= max(0, int(guardrail.get("max_requests") or 0))
        _check(
            checks, "rag-request-budget", "RAG", "RAG request estimate",
            "pass" if rag_budget_ready else "warning",
            f"The full configured RAG profile is estimated at {rag_estimate} requests against the {int(guardrail.get('max_requests') or 0)}-request execution ceiling.",
            "guardrail-form",
        )

    if tool_agent.get("enabled"):
        tools = tool_agent.get("tools") or []
        identities = tool_agent.get("identities") or []
        cases = tool_agent.get("cases") or []
        _check(
            checks, "tool-schema", "Tool agent", "Tool schemas and policies are complete",
            "pass" if tools and identities and cases else "fail",
            f"{len(tools)} tools, {len(identities)} identities, and {len(cases)} bounded cases are configured." if tools and identities and cases else "Add tool schemas, identity policy, and at least one bounded case.",
            "evaluation-config-form",
        )
        reversible = [item for item in cases if item.get("impact") == "reversible-change"]
        cleanup_ready = all(item.get("cleanup_path") and item.get("cleanup_method") for item in reversible)
        _check(
            checks, "tool-cleanup", "Tool agent", "Reversible cases have cleanup",
            "pass" if cleanup_ready else "fail",
            f"{len(reversible)} reversible case(s) have explicit cleanup contracts." if cleanup_ready else "Every reversible tool case needs an authorized cleanup route and method.",
            "evaluation-config-form",
        )
        verifier_routes = [
            (str(item.get("verification_path") or ""), str(item.get("verification_method") or ""))
            for item in cases if item.get("confirmation") == "verifier"
        ]
        cleanup_routes = [
            (str(item.get("cleanup_path") or ""), str(item.get("cleanup_method") or ""))
            for item in reversible
        ]
        route_contracts = [*verifier_routes, *cleanup_routes]
        route_contracts_ready = all(_route_ready(target, path, method) for path, method in route_contracts)
        _check(
            checks, "tool-verifier-routes", "Tool agent", "Verifier and cleanup routes are authorized",
            "pass" if route_contracts_ready else "fail",
            f"{len(verifier_routes)} verifier and {len(cleanup_routes)} cleanup route contract(s) stay within the target allowlist." if route_contracts_ready else "Authorize every verifier and cleanup route used by the tool-agent profile.",
            "evaluation-config-form",
        )
        tool_estimate = sum(
            max(1, int(item.get("max_rounds") or 1))
            + (1 if item.get("confirmation") == "verifier" else 0)
            + (1 if item.get("impact") == "reversible-change" else 0)
            for item in cases
        )
        tool_budget_ready = tool_estimate <= max(0, int(guardrail.get("max_requests") or 0))
        _check(
            checks, "tool-request-budget", "Tool agent", "Tool-agent request estimate",
            "pass" if tool_budget_ready else "warning",
            f"The full configured tool-agent profile is estimated at {tool_estimate} requests against the {int(guardrail.get('max_requests') or 0)}-request execution ceiling.",
            "guardrail-form",
        )

    if agentic_trace.get("enabled"):
        identities = agentic_trace.get("identities") or []
        cases = agentic_trace.get("cases") or []
        _check(
            checks, "agentic-trace-contract", "Agentic system", "Planner and executor trace contract",
            "pass" if identities and cases else "fail",
            f"{len(identities)} identities and {len(cases)} deterministic boundary cases are configured." if identities and cases else "Add an identity policy and at least one planner/executor or approval case.",
            "evaluation-config-form",
        )
        reversible = [item for item in cases if item.get("impact") == "reversible-change"]
        route_contracts = [
            (str(item.get("verification_path") or ""), str(item.get("verification_method") or ""))
            for item in cases if item.get("confirmation") == "verifier"
        ] + [
            (str(item.get("cleanup_path") or ""), str(item.get("cleanup_method") or ""))
            for item in reversible
        ]
        routes_ready = all(_route_ready(target, path, method) for path, method in route_contracts)
        _check(
            checks, "agentic-trace-routes", "Agentic system", "Verifier and cleanup routes are authorized",
            "pass" if routes_ready else "fail",
            f"{len(route_contracts)} verifier and cleanup route contract(s) stay within the target allowlist." if routes_ready else "Authorize every verifier and cleanup route used by the agentic trace profile.",
            "evaluation-config-form",
        )
        trace_estimate = sum(
            1
            + (2 if item.get("confirmation") == "verifier" else 0)
            + (2 if item.get("impact") == "reversible-change" else 0)
            for item in cases
        )
        _check(
            checks, "agentic-trace-request-budget", "Agentic system", "Agentic request estimate",
            "pass" if trace_estimate <= max(0, int(guardrail.get("max_requests") or 0)) else "warning",
            f"The full agentic trace profile is estimated at {trace_estimate} requests against the {int(guardrail.get('max_requests') or 0)}-request execution ceiling.",
            "guardrail-form",
        )

    approved_budget = max(0, int(guardrail.get("max_requests") or 0))
    _check(
        checks, "setup-budget", "Authorization", "Setup request budget",
        "pass" if approved_budget >= required_requests else "fail",
        f"This preflight may use up to {required_requests} request(s) within the approved {approved_budget}-request ceiling." if approved_budget >= required_requests else f"Increase the approved request ceiling to at least {required_requests} for this preflight.",
        "guardrail-form",
    )
    return {
        "checks": checks,
        "resolved": {
            "origin": str(target.get("base_url") or ""),
            "route": str(target.get("path") or ""),
            "method": method,
            "url": resolved_url,
            "kind": kind,
        },
        "authentication": runtime,
        "request_schema": request_shape,
        "budget": {
            "approved_request_ceiling": approved_budget,
            "preflight_request_ceiling": required_requests,
        },
        "blocking": any(item["status"] == "fail" for item in checks),
    }


def _public_result(result: dict[str, Any]) -> dict[str, Any]:
    return {str(key): value for key, value in result.items() if not str(key).startswith("_")}


def _identity_headers(profile: dict[str, Any]) -> dict[str, str]:
    identities = profile.get("identities") or []
    return dict((identities[0] if identities else {}).get("headers") or {})


def _probe_mcp(target: dict[str, Any], client: TargetClient, profile: dict[str, Any]) -> dict[str, Any]:
    if str(profile.get("transport") or "auto") == MCP_STDIO:
        traffic: list[dict[str, Any]] = []
        request_count = 0
        identities = profile.get("identities") or []
        selected_identity = identities[0] if identities else {}
        stdio_config = dict(profile.get("stdio") or {})
        with MCPStdioProcess(
            stdio_config,
            identity_environment=dict(selected_identity.get("environment") or {}),
        ) as transport:
            def exchange(message: dict[str, Any], operation: str, request_id: int) -> dict[str, Any]:
                nonlocal request_count
                request_count += 1
                request_raw = json.dumps(message, ensure_ascii=False, separators=(",", ":"))
                response, response_raw, _notifications = transport.send_request(message, expected_id=request_id)
                traffic.append({
                    "status_code": 200,
                    "status_line": "MCP stdio JSON-RPC",
                    "raw": response_raw,
                    "raw_http_response": response_raw,
                    "response": json.dumps(response, ensure_ascii=False),
                    "request": {
                        "runner": "adverscope-mcp-stdio-client",
                        "method": "MCP stdio",
                        "url": "stdio://authorized-local-process",
                        "headers": {},
                        "request_body": request_raw,
                        "curl_command": (
                            f"{transport.command_display}\n"
                            f"# exact JSON-RPC line written to stdin\n{request_raw}"
                        ),
                    },
                    "scope_enforcement": {
                        "mode": "local-stdio-executable",
                        "executable_sha256": stdio_config.get("executable_sha256"),
                    },
                    "completion": {"streaming": True, "state": "complete", "signal": "stdio-jsonrpc-line"},
                    "operation": operation,
                })
                return response

            def notify(message: dict[str, Any], operation: str, _request_id: int) -> None:
                nonlocal request_count
                request_count += 1
                request_raw = transport.send_notification(message)
                traffic.append({
                    "status_code": 200,
                    "status_line": "MCP stdio notification written",
                    "raw": "",
                    "raw_http_response": "",
                    "response": "",
                    "request": {
                        "runner": "adverscope-mcp-stdio-client",
                        "method": "MCP stdio",
                        "url": "stdio://authorized-local-process",
                        "headers": {},
                        "request_body": request_raw,
                        "curl_command": (
                            f"{transport.command_display}\n"
                            f"# exact JSON-RPC line written to stdin\n{request_raw}"
                        ),
                    },
                    "scope_enforcement": {
                        "mode": "local-stdio-executable",
                        "executable_sha256": stdio_config.get("executable_sha256"),
                    },
                    "completion": {"streaming": True, "state": "complete", "signal": "stdio-notification-written"},
                    "operation": operation,
                })

            session = MCPProtocolSession(
                send_request=exchange,
                send_notification=notify,
                preferred_versions=tuple(profile.get("protocol_versions") or [MCP_CURRENT_VERSION]),
                max_pages=int(profile.get("max_pages") or 10),
            )
            session.initialize()
            return {
                "request_count": request_count,
                "traffic": traffic,
                "protocol": {
                    "transport": MCP_STDIO,
                    "lifecycle": "newline-delimited JSON-RPC over local stdio",
                    "negotiated_version": session.negotiated_version,
                    "session_ready": bool(session.negotiated_version),
                    "server_capabilities": sorted((session.server_capabilities or {}).keys()),
                    "executable_sha256": stdio_config.get("executable_sha256"),
                    "stderr": transport.stderr,
                },
            }

    traffic: list[dict[str, Any]] = []
    request_count = 0
    identity_headers = _identity_headers(profile)
    transport = str(profile.get("transport") or "auto")
    endpoint_path = str(profile.get("endpoint_path") or "")
    versions = tuple(profile.get("protocol_versions") or [MCP_CURRENT_VERSION])

    if transport == MCP_LEGACY_HTTP_SSE:
        handshake = client.open_legacy_mcp_channel(
            target,
            path=str(profile.get("legacy_sse_path") or ""),
            request_headers=identity_headers,
        )
        request_count += 1
        traffic.append(_public_result(handshake))
        channel = handshake.get("_legacy_mcp_channel")
        try:
            initialize = {
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "AdverScope", "version": "preflight"},
                },
            }
            accepted = client.send_authorized(
                target, path=channel.endpoint_path, method="POST", payload=initialize,
                request_headers=identity_headers,
            )
            request_count += 1
            traffic.append(_public_result(accepted))
            rpc, async_raw = channel.read_jsonrpc(1)
            if rpc.get("error") or not isinstance(rpc.get("result"), dict):
                raise MCPProtocolError("legacy MCP initialize did not return a successful result")
            negotiated = str(rpc["result"].get("protocolVersion") or "")
            notification = {"jsonrpc": "2.0", "method": "notifications/initialized"}
            notified = client.send_authorized(
                target, path=channel.endpoint_path, method="POST", payload=notification,
                request_headers={**identity_headers, "MCP-Protocol-Version": negotiated},
            )
            request_count += 1
            traffic.append(_public_result(notified))
            return {
                "request_count": request_count,
                "traffic": traffic,
                "protocol": {
                    "transport": MCP_LEGACY_HTTP_SSE,
                    "lifecycle": "SSE endpoint + initialize + initialized",
                    "negotiated_version": negotiated,
                    "session_ready": True,
                    "async_initialize_response": redact_text(async_raw, 2_000_000),
                },
            }
        finally:
            if channel is not None:
                channel.close()

    session_id = ""
    negotiated_version = ""

    def headers(operation: str, initialized: bool) -> dict[str, str]:
        modern = operation == "server/discover" or negotiated_version == MCP_MODERN_VERSION
        result = {**identity_headers, "Accept": "application/json, text/event-stream"}
        if modern:
            result.update({"MCP-Protocol-Version": MCP_MODERN_VERSION, "Mcp-Method": operation})
        elif initialized and negotiated_version:
            result["MCP-Protocol-Version"] = negotiated_version
        if session_id and not modern:
            result["MCP-Session-Id"] = session_id
        return result

    def exchange(message: dict[str, Any], operation: str, request_id: int) -> dict[str, Any]:
        nonlocal request_count, session_id, negotiated_version
        result = client.send_authorized(
            target,
            path=endpoint_path,
            method="POST",
            payload=message,
            request_headers=headers(operation, operation != "initialize"),
            capture_response_headers=("MCP-Session-Id",),
        )
        request_count += 1
        traffic.append(_public_result(result))
        if operation == "initialize":
            session_id = str((result.get("_private_response_headers") or {}).get("mcp-session-id") or "")
        try:
            rpc, _notifications = parse_jsonrpc_exchange(str(result.get("raw") or ""), expected_id=request_id)
        except MCPProtocolError:
            if operation != "server/discover" or int(result.get("status_code") or 0) not in {400, 404, 405}:
                raise
            rpc = {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": "server/discover not supported"}}
        if operation == "initialize" and isinstance(rpc.get("result"), dict):
            negotiated_version = str(rpc["result"].get("protocolVersion") or "")
        if operation == "server/discover":
            rpc = {**rpc, "_adverscope_http_status": int(result.get("status_code") or 0)}
        return rpc

    def notify(message: dict[str, Any], operation: str, _request_id: int) -> None:
        nonlocal request_count
        result = client.send_authorized(
            target,
            path=endpoint_path,
            method="POST",
            payload=message,
            request_headers=headers(operation, True),
        )
        request_count += 1
        traffic.append(_public_result(result))
        if not 200 <= int(result.get("status_code") or 0) < 300:
            raise MCPProtocolError(f"MCP notification returned HTTP {result.get('status_code')}")

    session = MCPProtocolSession(
        send_request=exchange,
        send_notification=notify,
        preferred_versions=versions,
        max_pages=int(profile.get("max_pages") or 10),
    )
    session.initialize()
    negotiated_version = session.negotiated_version
    return {
        "request_count": request_count,
        "traffic": traffic,
        "protocol": {
            "transport": "stateless-http" if session.modern_mode else "streamable-http",
            "lifecycle": "server/discover" if session.modern_mode else "initialize + initialized",
            "negotiated_version": session.negotiated_version,
            "session_ready": bool(session.modern_mode or session_id or session.negotiated_version),
            "server_capabilities": sorted((session.server_capabilities or {}).keys()),
        },
    }


def execute_target_preflight(
    target: dict[str, Any],
    guardrail: dict[str, Any],
    *,
    target_client: TargetClient,
    browser_target_client: Any,
    browser_output_directory: Any,
) -> dict[str, Any]:
    """Execute one bounded setup preflight without attacks or findings."""
    started = time.monotonic()
    static = build_target_preflight_readiness(target, guardrail)
    result: dict[str, Any] = {
        "schema_version": PREFLIGHT_SCHEMA_VERSION,
        "configuration_sha256": target_preflight_signature(target, guardrail),
        **static,
        "request_count": 0,
        "traffic": [],
        "completion": {},
        "response_detection": {},
    }
    if static["blocking"]:
        result.update({
            "status": "blocked",
            "summary": "Connection test was blocked before target traffic because required setup is incomplete.",
            "duration_ms": max(0, int((time.monotonic() - started) * 1000)),
        })
        return result

    try:
        evaluation = target.get("evaluation_config") or {}
        mcp = evaluation.get("mcp") or {}
        kind = str(target.get("kind") or "")
        if mcp.get("enabled"):
            protocol_result = _probe_mcp(target, target_client, mcp)
            result.update(protocol_result)
            result["completion"] = {
                "streaming": protocol_result["protocol"]["transport"] == MCP_LEGACY_HTTP_SSE,
                "state": "complete",
                "signal": protocol_result["protocol"]["lifecycle"],
            }
        elif kind == "browser-chatbot":
            traffic = browser_target_client.send(
                target,
                "",
                output_directory=browser_output_directory,
                attempt="preflight",
                preflight=True,
            )
            result["request_count"] = 1
            result["traffic"] = [_public_result(traffic)]
            result["completion"] = traffic.get("completion") or {}
            diagnostics = traffic.get("preflight") or {}
            result["browser"] = diagnostics
            if not diagnostics.get("selectors_ready"):
                raise TargetError("browser navigation succeeded, but the configured selectors are not ready")
        elif kind == "chatbot":
            traffic = target_client.send(target, PREFLIGHT_PROMPT)
            result["request_count"] = 1
            result["traffic"] = [_public_result(traffic)]
            result["completion"] = traffic.get("completion") or {}
            result["response_detection"] = _response_candidate(str(traffic.get("raw") or ""))
            status = int(traffic.get("status_code") or 0)
            if not 200 <= status < 300:
                raise TargetError(f"target returned HTTP {status} during the connection test")
            if traffic.get("schema_error"):
                raise TargetError(str(traffic["schema_error"]))
            if not str(traffic.get("response") or "").strip():
                raise TargetError("the configured response rule did not extract chatbot output")
            completion = traffic.get("completion") or {}
            if completion.get("streaming"):
                require_done = bool((target.get("transport_config") or {}).get("require_sse_done"))
                explicit_done = completion.get("signal") == "sse-done"
                complete = completion.get("state") != "incomplete" and (explicit_done or not require_done)
                _check(
                    result["checks"], "streaming-completion", "Streaming", "Streaming completion signal",
                    "pass" if complete else "fail",
                    (
                        f"Streaming completed with signal {completion.get('signal') or 'unavailable'} and state {completion.get('state') or 'unavailable'}."
                        if complete else "The stream ended without the explicitly required completion signal."
                    ),
                    "target-form",
                )
                if not complete:
                    raise TargetError("the streaming response did not satisfy the configured completion rule")
        elif str(target.get("method") or "").upper() in {"GET", "OPTIONS"}:
            traffic = target_client.send_authorized(
                target,
                path=str(target.get("path") or ""),
                method=str(target.get("method") or ""),
                payload={},
                response_path=str(target.get("response_path") or ""),
            )
            result["request_count"] = 1
            result["traffic"] = [_public_result(traffic)]
            result["completion"] = traffic.get("completion") or {}
            result["response_detection"] = _response_candidate(str(traffic.get("raw") or ""))
            status = int(traffic.get("status_code") or 0)
            if not 200 <= status < 300:
                raise TargetError(f"target returned HTTP {status} during the connection test")
        else:
            _check(
                result["checks"], "read-only-live-probe", "Connection", "Read-only live request",
                "warning",
                "Configuration is structurally ready, but AdverScope did not send this action-shaped API request. Add a chatbot, MCP, browser, GET, or OPTIONS adapter for a live read-only connection check.",
                "target-form",
            )

        warnings = [item for item in result["checks"] if item["status"] == "warning"]
        result["status"] = "needs-attention" if warnings else "ready"
        result["summary"] = (
            "Connection and adapter checks passed with configuration notes."
            if warnings else "Connection and adapter checks passed."
        )
    except Exception as exc:
        result["status"] = "failed"
        result["error"] = safe_error(exc)
        result["summary"] = "The target was reached only as recorded below, but the configured connection or adapter check failed."
        _check(
            result["checks"], "live-connection", "Connection", "Live connection result",
            "fail", safe_error(exc), "target-form",
        )
    result["duration_ms"] = max(0, int((time.monotonic() - started) * 1000))
    result["budget"]["requests_used"] = int(result.get("request_count") or 0)
    return result
