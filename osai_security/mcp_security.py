from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Callable

from . import __version__


MCP_PROTOCOL = "mcp-jsonrpc"
MCP_STREAMABLE_HTTP = "streamable-http"
MCP_LEGACY_HTTP_SSE = "legacy-http-sse"
MCP_STATELESS_HTTP = "stateless-http"
MCP_MODERN_VERSION = "2026-07-28"
MCP_CURRENT_VERSION = MCP_MODERN_VERSION
MCP_SUPPORTED_VERSIONS = (
    MCP_MODERN_VERSION,
    "2025-11-25",
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
)


class MCPProtocolError(RuntimeError):
    """Raised when a target does not complete a valid, bounded MCP exchange."""


def canonical_sha256(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


MCP_INVENTORY_CATEGORIES = ("tools", "resources", "resource_templates", "prompts")


def normalized_mcp_inventory(inventory: dict[str, Any] | None) -> dict[str, list[dict[str, Any]]]:
    """Return an order-independent exact inventory suitable for target baselines."""
    source = inventory if isinstance(inventory, dict) else {}
    normalized: dict[str, list[dict[str, Any]]] = {}
    for category in MCP_INVENTORY_CATEGORIES:
        items = [item for item in (source.get(category) or []) if isinstance(item, dict)]
        normalized[category] = sorted(
            items,
            key=lambda item: json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        )
    return normalized


def mcp_inventory_sha256(inventory: dict[str, Any] | None) -> str:
    """Hash the complete normalized inventory without depending on pagination order."""
    return canonical_sha256(normalized_mcp_inventory(inventory))


def parse_sse_events(raw: str) -> list[dict[str, str]]:
    """Parse complete SSE events while retaining only protocol-relevant fields."""
    events: list[dict[str, str]] = []
    current: dict[str, Any] = {"data": []}
    for line in (raw or "").replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if not line:
            if current.get("data") or current.get("event") or current.get("id"):
                events.append({
                    "event": str(current.get("event") or "message"),
                    "id": str(current.get("id") or ""),
                    "data": "\n".join(current.get("data") or []),
                })
            current = {"data": []}
            continue
        if line.startswith(":"):
            continue
        field, separator, value = line.partition(":")
        if separator and value.startswith(" "):
            value = value[1:]
        if field == "data":
            current.setdefault("data", []).append(value)
        elif field in {"event", "id"}:
            current[field] = value
    if current.get("data") or current.get("event") or current.get("id"):
        events.append({
            "event": str(current.get("event") or "message"),
            "id": str(current.get("id") or ""),
            "data": "\n".join(current.get("data") or []),
        })
    return events


def parse_jsonrpc_exchange(raw: str, *, expected_id: int | str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Extract one response and every preceding notification from JSON or SSE."""
    candidates: list[Any] = []
    try:
        candidates.append(json.loads(raw or ""))
    except json.JSONDecodeError:
        for event in parse_sse_events(raw):
            if not event.get("data"):
                continue
            try:
                candidates.append(json.loads(event["data"]))
            except json.JSONDecodeError:
                continue
    flattened: list[Any] = []
    for candidate in candidates:
        flattened.extend(candidate if isinstance(candidate, list) else [candidate])
    notifications: list[dict[str, Any]] = []
    response: dict[str, Any] | None = None
    for candidate in flattened:
        if not isinstance(candidate, dict):
            continue
        if candidate.get("jsonrpc") != "2.0":
            continue
        if "id" not in candidate and isinstance(candidate.get("method"), str):
            notifications.append(candidate)
            continue
        if str(candidate.get("id")) == str(expected_id):
            if "result" not in candidate and "error" not in candidate:
                raise MCPProtocolError("MCP JSON-RPC response contained neither result nor error")
            response = candidate
            break
    if response is not None:
        return response, notifications
    raise MCPProtocolError(f"MCP response did not contain JSON-RPC id {expected_id}")


def parse_jsonrpc_response(raw: str, *, expected_id: int | str) -> dict[str, Any]:
    """Backward-compatible response-only wrapper."""
    response, _notifications = parse_jsonrpc_exchange(raw, expected_id=expected_id)
    return response


@dataclass
class MCPProtocolSession:
    """Bounded MCP lifecycle and inventory client independent of HTTP transport."""

    send_request: Callable[[dict[str, Any], str, int], dict[str, Any]]
    send_notification: Callable[[dict[str, Any], str, int], None]
    preferred_versions: tuple[str, ...]
    max_pages: int

    def __post_init__(self) -> None:
        self._next_id = 1
        self.negotiated_version = ""
        self.server_info: dict[str, Any] = {}
        self.server_capabilities: dict[str, Any] = {}
        self.server_instructions = ""
        self.modern_mode = False
        self.cache_hints: dict[str, list[dict[str, Any]]] = {}

    def _request_meta(self) -> dict[str, Any]:
        return {
            "io.modelcontextprotocol/protocolVersion": MCP_MODERN_VERSION,
            "io.modelcontextprotocol/clientInfo": {
                "name": "AdverScope",
                "title": "AdverScope AI Security Workbench",
                "version": __version__,
                "description": "Bounded AI security assessment client",
            },
            "io.modelcontextprotocol/clientCapabilities": {},
        }

    def _request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        request_id = self._next_id
        self._next_id += 1
        message: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
        request_params = dict(params or {})
        if self.modern_mode:
            request_params["_meta"] = self._request_meta()
        if request_params:
            message["params"] = request_params
        response = self.send_request(message, method, request_id)
        if not isinstance(response, dict):
            raise MCPProtocolError(f"MCP method {method} returned no structured JSON-RPC response")
        return response

    def _initialize_legacy(self, requested: str) -> dict[str, Any]:
        response = self._request("initialize", {
            "protocolVersion": requested,
            "capabilities": {},
            "clientInfo": {
                "name": "AdverScope",
                "title": "AdverScope AI Security Workbench",
                "version": __version__,
                "description": "Bounded AI security assessment client",
            },
        })
        if response.get("error"):
            raise MCPProtocolError(f"MCP initialize failed: {json.dumps(response['error'], ensure_ascii=False)}")
        result = response.get("result")
        if not isinstance(result, dict):
            raise MCPProtocolError("MCP initialize result must be an object")
        negotiated = str(result.get("protocolVersion") or "")
        if negotiated not in self.preferred_versions:
            raise MCPProtocolError(f"MCP server selected unsupported protocol version {negotiated or '[missing]'}")
        self.negotiated_version = negotiated
        self.server_info = result.get("serverInfo") if isinstance(result.get("serverInfo"), dict) else {}
        self.server_capabilities = result.get("capabilities") if isinstance(result.get("capabilities"), dict) else {}
        self.server_instructions = str(result.get("instructions") or "")[:200000]
        self.send_notification({"jsonrpc": "2.0", "method": "notifications/initialized"}, "notifications/initialized", 0)
        return result

    @staticmethod
    def _validate_modern_result(method: str, result: dict[str, Any]) -> None:
        if str(result.get("resultType") or "") != "complete":
            raise MCPProtocolError(f"MCP {method} did not return resultType complete")
        ttl = result.get("ttlMs")
        if not isinstance(ttl, (int, float)) or isinstance(ttl, bool) or ttl < 0:
            raise MCPProtocolError(f"MCP {method} did not return a non-negative ttlMs")
        if result.get("cacheScope") not in {"public", "private"}:
            raise MCPProtocolError(f"MCP {method} did not return cacheScope public or private")

    def initialize(self) -> dict[str, Any]:
        requested = self.preferred_versions[0] if self.preferred_versions else MCP_CURRENT_VERSION
        if requested != MCP_MODERN_VERSION:
            return self._initialize_legacy(requested)

        self.modern_mode = True
        response = self._request("server/discover")
        if response.get("error"):
            error = response.get("error") or {}
            fallback = next((version for version in self.preferred_versions if version != MCP_MODERN_VERSION), "")
            fallback_status = int(response.get("_adverscope_http_status") or 0)
            if (int(error.get("code") or 0) == -32601 or fallback_status in {400, 404, 405}) and fallback:
                self.modern_mode = False
                return self._initialize_legacy(fallback)
            raise MCPProtocolError(f"MCP server/discover failed: {json.dumps(error, ensure_ascii=False)}")
        result = response.get("result")
        if not isinstance(result, dict):
            raise MCPProtocolError("MCP server/discover result must be an object")
        self._validate_modern_result("server/discover", result)
        supported = [str(item) for item in result.get("supportedVersions") or []]
        negotiated = next((version for version in self.preferred_versions if version in supported), "")
        if not negotiated:
            raise MCPProtocolError("MCP server/discover returned no mutually supported protocol version")
        if negotiated != MCP_MODERN_VERSION:
            self.modern_mode = False
            return self._initialize_legacy(negotiated)
        capabilities = result.get("capabilities")
        if not isinstance(capabilities, dict):
            raise MCPProtocolError("MCP server/discover capabilities must be an object")
        result_meta = result.get("_meta") if isinstance(result.get("_meta"), dict) else {}
        server_info = result_meta.get("io.modelcontextprotocol/serverInfo")
        self.negotiated_version = negotiated
        self.server_capabilities = capabilities
        self.server_info = server_info if isinstance(server_info, dict) else {}
        self.server_instructions = str(result.get("instructions") or "")[:200000]
        self.cache_hints["server/discover"] = [{
            "ttlMs": result.get("ttlMs"),
            "cacheScope": result.get("cacheScope"),
        }]
        return result

    def _list_paginated(self, method: str, result_key: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        cursor = ""
        seen_cursors: set[str] = set()
        for _page in range(1, self.max_pages + 1):
            params = {"cursor": cursor} if cursor else None
            response = self._request(method, params)
            if response.get("error"):
                raise MCPProtocolError(f"MCP {method} failed: {json.dumps(response['error'], ensure_ascii=False)}")
            result = response.get("result")
            if not isinstance(result, dict) or not isinstance(result.get(result_key, []), list):
                raise MCPProtocolError(f"MCP {method} result did not contain a {result_key} list")
            if self.modern_mode:
                self._validate_modern_result(method, result)
                self.cache_hints.setdefault(method, []).append({
                    "ttlMs": result.get("ttlMs"),
                    "cacheScope": result.get("cacheScope"),
                })
            page_items = result.get(result_key) or []
            if any(not isinstance(item, dict) for item in page_items):
                raise MCPProtocolError(f"MCP {method} returned a non-object inventory item")
            items.extend(page_items)
            if len(items) > 5000:
                raise MCPProtocolError(f"MCP {method} exceeded the 5000-item inventory boundary")
            next_cursor = str(result.get("nextCursor") or "")
            if not next_cursor:
                return items
            if next_cursor in seen_cursors:
                raise MCPProtocolError(f"MCP {method} repeated a pagination cursor")
            seen_cursors.add(next_cursor)
            cursor = next_cursor
        raise MCPProtocolError(f"MCP {method} exceeded the configured {self.max_pages}-page boundary")

    def inventory(self) -> dict[str, list[dict[str, Any]]]:
        capabilities = self.server_capabilities
        return {
            "tools": self._list_paginated("tools/list", "tools") if isinstance(capabilities.get("tools"), dict) else [],
            "resources": self._list_paginated("resources/list", "resources") if isinstance(capabilities.get("resources"), dict) else [],
            "resource_templates": self._list_paginated("resources/templates/list", "resourceTemplates") if isinstance(capabilities.get("resources"), dict) else [],
            "prompts": self._list_paginated("prompts/list", "prompts") if isinstance(capabilities.get("prompts"), dict) else [],
        }

    def inventory_subscription_request(self, request_id: int | str) -> dict[str, Any]:
        if not self.modern_mode or self.negotiated_version != MCP_MODERN_VERSION:
            raise MCPProtocolError("inventory subscriptions require the 2026-07-28 MCP protocol")
        notifications: dict[str, bool] = {}
        for capability, field in (
            ("tools", "toolsListChanged"),
            ("resources", "resourcesListChanged"),
            ("prompts", "promptsListChanged"),
        ):
            settings = self.server_capabilities.get(capability)
            if isinstance(settings, dict) and settings.get("listChanged") is True:
                notifications[field] = True
        if not notifications:
            raise MCPProtocolError("MCP server advertised no inventory change subscription capability")
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "subscriptions/listen",
            "params": {
                "notifications": notifications,
                "_meta": self._request_meta(),
            },
        }

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return self._request("tools/call", {"name": name, "arguments": arguments})

    def read_resource(self, uri: str) -> dict[str, Any]:
        return self._request("resources/read", {"uri": uri})

    def get_prompt(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return self._request("prompts/get", {"name": name, "arguments": arguments})


def _rpc_success(response: dict[str, Any] | None) -> bool:
    if not isinstance(response, dict) or response.get("error"):
        return False
    result = response.get("result")
    return isinstance(result, dict) and result.get("isError") is not True


def _extract_path(value: Any, path: str) -> tuple[bool, Any]:
    current = value
    for raw_part in str(path).replace("[", ".").replace("]", "").split("."):
        part = raw_part.strip()
        if not part:
            continue
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return False, None
    return True, current


def _action_assertion_results(case: dict[str, Any], response: dict[str, Any] | None) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for assertion in case.get("action_assertions") or []:
        path = str(assertion.get("path") or "")
        operator = str(assertion.get("operator") or "equals")
        exists, observed = _extract_path(response, path)
        expected = assertion.get("expected")
        if operator == "exists":
            passed = exists
        elif operator == "truthy":
            passed = exists and bool(observed)
        elif operator == "equals":
            passed = exists and observed == expected
        elif operator == "not-equals":
            passed = exists and observed != expected
        elif operator == "contains":
            passed = exists and str(expected).casefold() in json.dumps(observed, ensure_ascii=False).casefold()
        elif operator == "regex":
            passed = exists and bool(re.search(str(assertion.get("pattern") or ""), json.dumps(observed, ensure_ascii=False), re.IGNORECASE))
        else:
            passed = False
        result = {
            "path": path,
            "operator": operator,
            "exists": exists,
            "observed": observed,
            "passed": bool(passed),
        }
        if operator == "regex":
            result["pattern"] = str(assertion.get("pattern") or "")
        elif operator not in {"exists", "truthy"}:
            result["expected"] = expected
        results.append(result)
    return results


def _mcp_content_sources(execution: dict[str, Any]) -> list[dict[str, Any]]:
    """Retain where untrusted MCP text originated instead of flattening inventory."""
    inventory = execution.get("inventory") or {}
    sources: list[dict[str, Any]] = []
    instructions = execution.get("server_instructions") or ""
    if instructions:
        sources.append({"source_kind": "server-instructions", "source_id": "initialize.instructions", "value": instructions})
    identifiers = {
        "tools": "name",
        "resources": "uri",
        "resource_templates": "uriTemplate",
        "prompts": "name",
    }
    for key, identifier in identifiers.items():
        for index, item in enumerate(inventory.get(key) or []):
            source_id = str(item.get(identifier) or f"{key}[{index}]") if isinstance(item, dict) else f"{key}[{index}]"
            sources.append({"source_kind": key, "source_id": source_id, "value": item})
    return sources


def assess_mcp_case(case: dict[str, Any], execution: dict[str, Any]) -> dict[str, Any]:
    """Apply only the target-owned MCP policy snapshotted into the run."""
    scenario = str(case.get("scenario") or "")
    inventory = execution.get("inventory") or {}
    tools = {str(item.get("name") or ""): item for item in inventory.get("tools") or [] if item.get("name")}
    resources = {str(item.get("uri") or ""): item for item in inventory.get("resources") or [] if item.get("uri")}
    prompts = {str(item.get("name") or ""): item for item in inventory.get("prompts") or [] if item.get("name")}
    reasons: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    action_assertions: list[dict[str, Any]] = []
    expected_rechecks = int(case.get("inventory_recheck_count") or 0)
    completed_rechecks = int(execution.get("inventory_rechecks_completed") or 0)
    conclusive = bool(
        execution.get("initialized")
        and execution.get("inventory_complete")
        and completed_rechecks >= expected_rechecks
    )
    observed_inventory_sha256 = mcp_inventory_sha256(inventory) if conclusive else ""

    if scenario in {"inventory-integrity", "cross-identity-inventory"}:
        expected_inventory_sha256 = str(case.get("inventory_sha256") or "")
        if expected_inventory_sha256 and observed_inventory_sha256 != expected_inventory_sha256:
            reasons.append({
                "kind": "inventory-digest-drift",
                "expected_sha256": expected_inventory_sha256,
                "observed_sha256": observed_inventory_sha256,
                "reason": "The complete normalized MCP inventory did not match the target-approved SHA-256 baseline.",
            })
        for name in case.get("required_tools") or []:
            if name not in tools:
                reasons.append({"kind": "required-tool-missing", "tool": name, "reason": f"Required MCP tool {name} was not advertised."})
        for name in case.get("forbidden_tools") or []:
            if name in tools:
                reasons.append({"kind": "forbidden-tool-exposed", "tool": name, "reason": f"MCP tool {name} was advertised to this identity contrary to target policy."})
        for expected in case.get("expected_tools") or []:
            name = str(expected.get("name") or "")
            observed = tools.get(name)
            if not observed:
                reasons.append({"kind": "expected-tool-missing", "tool": name, "reason": f"Expected MCP tool {name} was not advertised, so its approved metadata and schema could not be verified."})
                continue
            if expected.get("description_sha256") and hashlib.sha256(str(observed.get("description") or "").encode("utf-8")).hexdigest() != expected["description_sha256"]:
                reasons.append({"kind": "tool-description-drift", "tool": name, "reason": f"MCP tool {name} description did not match the approved digest."})
            if expected.get("input_schema_sha256") and canonical_sha256(observed.get("inputSchema") or {}) != expected["input_schema_sha256"]:
                reasons.append({"kind": "tool-schema-drift", "tool": name, "reason": f"MCP tool {name} input schema did not match the approved digest."})
        for name in case.get("required_prompts") or []:
            if name not in prompts:
                reasons.append({"kind": "required-prompt-missing", "prompt": name, "reason": f"Required MCP prompt {name} was not advertised."})
        for name in case.get("forbidden_prompts") or []:
            if name in prompts:
                reasons.append({"kind": "forbidden-prompt-exposed", "prompt": name, "reason": f"MCP prompt {name} was advertised to this identity contrary to target policy."})
        for expected in case.get("expected_prompts") or []:
            name = str(expected.get("name") or "")
            observed = prompts.get(name)
            if not observed:
                reasons.append({"kind": "expected-prompt-missing", "prompt": name, "reason": f"Expected MCP prompt {name} was not advertised, so its approved metadata could not be verified."})
                continue
            if expected.get("description_sha256") and hashlib.sha256(str(observed.get("description") or "").encode("utf-8")).hexdigest() != expected["description_sha256"]:
                reasons.append({"kind": "prompt-description-drift", "prompt": name, "reason": f"MCP prompt {name} description did not match the approved digest."})
            if expected.get("arguments_sha256") and canonical_sha256(observed.get("arguments") or []) != expected["arguments_sha256"]:
                reasons.append({"kind": "prompt-arguments-drift", "prompt": name, "reason": f"MCP prompt {name} arguments did not match the approved digest."})
        snapshots = execution.get("inventory_snapshots") or []
        snapshot_digests = [
            str(item.get("inventory_sha256") or "")
            for item in snapshots
            if isinstance(item, dict) and item.get("inventory_sha256")
        ]
        inventory_changed = len(set(snapshot_digests)) > 1
        relevant_notifications = [
            item for item in execution.get("inventory_notifications") or []
            if isinstance(item, dict) and str(item.get("method") or "") in {
                "notifications/tools/list_changed",
                "notifications/resources/list_changed",
                "notifications/prompts/list_changed",
            }
        ]
        if (
            inventory_changed
            and case.get("inventory_change_policy") == "require-notification"
            and not relevant_notifications
        ):
            reasons.append({
                "kind": "inventory-change-unannounced",
                "reason": "The MCP inventory changed during the bounded reassessment without a retained list-changed notification required by target policy.",
            })
        if scenario == "cross-identity-inventory":
            comparison = execution.get("comparison_inventory") or {}
            comparison_tools = {str(item.get("name") or "") for item in comparison.get("tools") or []}
            for name in case.get("forbidden_tools") or []:
                if name in tools and name not in comparison_tools:
                    reasons.append({"kind": "cross-identity-tool-exposure", "tool": name, "reason": f"MCP tool {name} was exposed only to the restricted identity."})
            conclusive = conclusive and bool(execution.get("comparison_inventory_complete"))
    elif scenario == "unauthorized-tool-listing":
        target_tool = str(case.get("target_tool") or "")
        if target_tool in tools:
            reasons.append({"kind": "forbidden-tool-exposed", "tool": target_tool, "reason": f"Denied MCP tool {target_tool} was advertised to the configured restricted identity."})
    elif scenario in {"unauthorized-tool-call", "invalid-tool-arguments", "confused-deputy"}:
        action = execution.get("action_response")
        conclusive = conclusive and isinstance(action, dict)
        action_assertions = _action_assertion_results(case, action)
        assertions_satisfied = not action_assertions or all(item.get("passed") for item in action_assertions)
        if _rpc_success(action) and assertions_satisfied:
            reason = "The MCP server returned a successful tool result where the target-owned policy required rejection."
            if action_assertions:
                reason += " Every configured target-owned structured result assertion was satisfied."
            reasons.append({"kind": scenario, "tool": str(case.get("target_tool") or ""), "reason": reason})
    elif scenario == "unauthorized-resource-read":
        action = execution.get("action_response")
        conclusive = conclusive and isinstance(action, dict)
        action_assertions = _action_assertion_results(case, action)
        assertions_satisfied = not action_assertions or all(item.get("passed") for item in action_assertions)
        if _rpc_success(action) and ((action.get("result") or {}).get("contents") or []) and assertions_satisfied:
            reason = "The MCP server returned protected resource contents to an identity configured to be denied."
            if action_assertions:
                reason += " Every configured target-owned resource, identity, and classification assertion was satisfied."
            reasons.append({"kind": scenario, "resource_uri": str(case.get("resource_uri") or ""), "reason": reason})
    elif scenario == "unauthorized-prompt-get":
        action = execution.get("action_response")
        conclusive = conclusive and isinstance(action, dict)
        action_assertions = _action_assertion_results(case, action)
        assertions_satisfied = bool(action_assertions) and all(item.get("passed") for item in action_assertions)
        messages = ((action or {}).get("result") or {}).get("messages") or []
        if _rpc_success(action) and messages and assertions_satisfied:
            reasons.append({
                "kind": scenario,
                "prompt": str(case.get("prompt_name") or ""),
                "reason": (
                    "The MCP server returned a protected prompt to an identity configured to be denied, and every "
                    "target-owned prompt, content, and authorization assertion was satisfied."
                ),
            })
    elif scenario == "content-injection":
        matched_sources: list[dict[str, Any]] = []
        configured_source = str(case.get("resource_uri") or "")
        for source in _mcp_content_sources(execution):
            if configured_source and source["source_id"] != configured_source:
                continue
            content = json.dumps(source["value"], ensure_ascii=False, sort_keys=True)
            for pattern in case.get("forbidden_content_patterns") or []:
                if not re.search(pattern, content, re.IGNORECASE):
                    continue
                match = {
                    "kind": "untrusted-mcp-content-observed",
                    "pattern": pattern,
                    "source_kind": source["source_kind"],
                    "source_id": source["source_id"],
                    "reason": "MCP-provided instructions, metadata, or content matched a target-configured prohibited instruction pattern; visibility alone is not finding-grade evidence.",
                }
                matched_sources.append(match)
                observations.append(match)
        action = execution.get("action_response")
        target_tool = str(case.get("target_tool") or "")
        if target_tool:
            conclusive = conclusive and bool(matched_sources) and isinstance(action, dict)
            action_assertions = _action_assertion_results(case, action)
            assertions_satisfied = bool(action_assertions) and all(item.get("passed") for item in action_assertions)
            if matched_sources and _rpc_success(action) and assertions_satisfied:
                reasons.append({
                    "kind": "mcp-content-policy",
                    "pattern": matched_sources[0]["pattern"],
                    "source_kind": matched_sources[0]["source_kind"],
                    "source_id": matched_sources[0]["source_id"],
                    "tool": target_tool,
                    "reason": "Target-owned structured evidence proved that prohibited MCP content reached the configured read-only sink and altered its instruction-boundary outcome.",
                })
        else:
            conclusive = conclusive and bool(matched_sources)
    else:
        conclusive = False

    violated = bool(reasons)
    finding = bool(violated and case.get("emission_is_violation") is True and conclusive)
    return {
        "violated": violated,
        "finding": finding,
        "conclusive": conclusive,
        "reasons": reasons,
        "observations": observations,
        "scenario": scenario,
        "case_id": str(case.get("id") or ""),
        "confirmation": "target-mcp-policy",
        "emission_is_violation": bool(case.get("emission_is_violation")),
        "action_assertions": action_assertions,
        "action_assertions_satisfied": bool(action_assertions) and all(item.get("passed") for item in action_assertions),
        "inventory_integrity": {
            "expected_sha256": str(case.get("inventory_sha256") or ""),
            "observed_sha256": observed_inventory_sha256,
            "matched": bool(case.get("inventory_sha256")) and str(case.get("inventory_sha256")) == observed_inventory_sha256,
        },
        "inventory_change": {
            "rechecks_expected": expected_rechecks,
            "rechecks_completed": completed_rechecks,
            "snapshot_sha256": [
                str(item.get("inventory_sha256") or "")
                for item in execution.get("inventory_snapshots") or []
                if isinstance(item, dict)
            ],
            "changed": len({
                str(item.get("inventory_sha256") or "")
                for item in execution.get("inventory_snapshots") or []
                if isinstance(item, dict) and item.get("inventory_sha256")
            }) > 1,
            "notification_methods": [
                str(item.get("method") or "")
                for item in execution.get("inventory_notifications") or []
                if isinstance(item, dict)
            ],
        },
    }


def public_mcp_summary(execution: dict[str, Any]) -> dict[str, Any]:
    """Return useful protocol evidence without duplicating resource/tool content."""
    inventory = execution.get("inventory") or {}
    comparison = execution.get("comparison_inventory") or {}
    stdio = execution.get("stdio") if isinstance(execution.get("stdio"), dict) else {}
    return {
        "protocol": MCP_PROTOCOL,
        "transport": execution.get("transport") or "",
        "negotiated_version": execution.get("negotiated_version") or "",
        "compatibility_downgrade": bool(execution.get("compatibility_downgrade")),
        "server_info": execution.get("server_info") or {},
        "server_capabilities": execution.get("server_capabilities") or {},
        "lifecycle": execution.get("lifecycle") or "initialize",
        "inventory_counts": {key: len(inventory.get(key) or []) for key in MCP_INVENTORY_CATEGORIES},
        "inventory_sha256": mcp_inventory_sha256(inventory) if execution.get("inventory_complete") else "",
        "inventory_snapshots": [
            {
                "sequence": int(item.get("sequence") or index),
                "inventory_counts": dict(item.get("inventory_counts") or {}),
                "inventory_sha256": str(item.get("inventory_sha256") or ""),
            }
            for index, item in enumerate(execution.get("inventory_snapshots") or [], start=1)
            if isinstance(item, dict)
        ],
        "inventory_rechecks_completed": int(execution.get("inventory_rechecks_completed") or 0),
        "inventory_subscription_requested": bool(execution.get("inventory_subscription_requested")),
        "inventory_event_stream_requested": bool(execution.get("inventory_event_stream_requested")),
        "inventory_notification_methods": [
            str(item.get("method") or "")
            for item in execution.get("inventory_notifications") or []
            if isinstance(item, dict)
        ],
        "cache_hints": execution.get("cache_hints") or {},
        "comparison_inventory_counts": {key: len(comparison.get(key) or []) for key in MCP_INVENTORY_CATEGORIES},
        "comparison_inventory_sha256": mcp_inventory_sha256(comparison) if execution.get("comparison_inventory_complete") else "",
        "action_method": execution.get("action_method") or "",
        "action_succeeded": _rpc_success(execution.get("action_response")),
        "protocol_event_ids": list(execution.get("protocol_event_ids") or []),
        "stdio": {
            "executable_sha256": str(stdio.get("executable_sha256") or ""),
            "command": str(stdio.get("command") or ""),
            "cwd": str(stdio.get("cwd") or ""),
            "environment_names": list(stdio.get("environment_names") or []),
            "stderr": str(stdio.get("stderr") or ""),
            "transcript_count": int(stdio.get("transcript_count") or 0),
        } if stdio else {},
    }
