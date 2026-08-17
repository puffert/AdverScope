from __future__ import annotations

import copy
import json
from typing import Any

from .release import TARGET_PROFILE_SCHEMA_VERSION


_COMMON_CONNECTION_REQUIREMENTS = [
    {"id": "authorization", "title": "Authorization boundary", "section": "authorization", "description": "A scope / rules-of-engagement document must authorize the exact system and actions."},
    {"id": "target", "title": "Exact target", "section": "target", "description": "Name, origin, route, method, and target-owned request adapter must be reviewed before saving."},
    {"id": "guardrail", "title": "Execution guardrail", "section": "authorization", "description": "Request, runtime, error, reproduction, and optional reconnaissance limits must reference the saved target."},
]


TARGET_SETUP_PROFILES: tuple[dict[str, Any], ...] = (
    {
        "id": "generic-json-chatbot",
        "title": "Generic JSON chatbot",
        "summary": "One documented JSON request and response adapter at an exact HTTP endpoint.",
        "target_kind": "chatbot",
        "capabilities": [],
        "relevant_sections": ["authorization", "target", "capabilities", "adapters", "proof", "readiness"],
        "requirements": _COMMON_CONNECTION_REQUIREMENTS + [
            {"id": "request-adapter", "title": "Request and response adapter", "section": "adapters", "description": "Enter the documented JSON template containing {{prompt}} and the response path when one is required."},
        ],
        "operator_note": "No route, prompt field, response field, authentication value, or model name is supplied by this profile.",
    },
    {
        "id": "openai-compatible-api",
        "title": "OpenAI-compatible API",
        "summary": "A customer-documented OpenAI-compatible chat or response endpoint.",
        "target_kind": "chatbot",
        "capabilities": [],
        "relevant_sections": ["authorization", "target", "capabilities", "adapters", "proof", "readiness"],
        "requirements": _COMMON_CONNECTION_REQUIREMENTS + [
            {"id": "openai-adapter", "title": "Compatible request contract", "section": "adapters", "description": "Confirm the customer's actual route, model field, message schema, streaming behavior, and response path. Compatibility is not inferred from the profile name."},
            {"id": "credential-reference", "title": "Credential reference", "section": "target", "description": "If authentication is required, use an environment-backed header reference; never paste a key into the target profile."},
        ],
        "operator_note": "The commonly used /v1/chat/completions route and messages field are intentionally not inserted automatically.",
    },
    {
        "id": "ollama-compatible-api",
        "title": "Ollama-compatible API",
        "summary": "A locally or remotely hosted Ollama-compatible generation endpoint.",
        "target_kind": "chatbot",
        "capabilities": [],
        "relevant_sections": ["authorization", "target", "capabilities", "adapters", "proof", "readiness"],
        "requirements": _COMMON_CONNECTION_REQUIREMENTS + [
            {"id": "ollama-adapter", "title": "Compatible request contract", "section": "adapters", "description": "Confirm the exact documented route, model value, prompt or messages schema, streaming setting, and response path."},
        ],
        "operator_note": "No /api/chat or /api/generate route, model name, field, or streaming mode is assumed.",
    },
    {
        "id": "browser-chatbot",
        "title": "Browser chatbot",
        "summary": "An authenticated or unauthenticated web chat with completion detection and screenshot evidence.",
        "target_kind": "browser-chatbot",
        "capabilities": ["external_content"],
        "relevant_sections": ["authorization", "target", "capabilities", "adapters", "proof", "readiness"],
        "requirements": _COMMON_CONNECTION_REQUIREMENTS + [
            {"id": "browser-selectors", "title": "Browser selectors", "section": "adapters", "description": "Map the input, submit, response, and optional streaming/completion selectors from the authorized interface."},
            {"id": "browser-session", "title": "Session and screenshot policy", "section": "authorization", "description": "Decide whether a project-isolated login session and screenshots are permitted."},
        ],
        "operator_note": "Selectors, login steps, visible proof text, and screenshot permission remain customer- and engagement-specific.",
    },
    {
        "id": "tool-calling-agent",
        "title": "Tool-calling agent",
        "summary": "An agent or assistant that can propose or invoke documented tools and functions.",
        "target_kind": "api",
        "capabilities": ["tools", "agents"],
        "relevant_sections": ["authorization", "target", "capabilities", "adapters", "proof", "readiness"],
        "requirements": _COMMON_CONNECTION_REQUIREMENTS + [
            {"id": "tool-schema", "title": "Tool and identity schemas", "section": "adapters", "description": "Configure only customer-documented tools, identities, arguments, simulated outputs, and decision boundaries."},
            {"id": "tool-proof", "title": "Effect verification and cleanup", "section": "proof", "description": "A consequential finding needs target-owned verification and, for reversible changes, an authorized cleanup route."},
        ],
        "operator_note": "This profile declares applicability only. It never invents a tool, argument, identity, verifier, or permission.",
    },
    {
        "id": "mcp-server",
        "title": "MCP server",
        "summary": "A current Streamable HTTP, stateless HTTP, or legacy HTTP+SSE MCP deployment.",
        "target_kind": "api",
        "capabilities": ["mcp", "tools"],
        "relevant_sections": ["authorization", "target", "capabilities", "adapters", "proof", "readiness"],
        "requirements": _COMMON_CONNECTION_REQUIREMENTS + [
            {"id": "mcp-transport", "title": "MCP lifecycle and transport", "section": "adapters", "description": "Map the exact POST endpoint, protocol versions, session behavior, notification channel, and any authorized legacy SSE route."},
            {"id": "mcp-identities", "title": "Identity and inventory controls", "section": "proof", "description": "Define customer-owned identities, expected inventory, protected prompts/resources, and read-only or state-changing permissions."},
        ],
        "operator_note": "No MCP endpoint, protocol version, tool inventory, prompt, resource, identity, or session behavior is assumed.",
    },
    {
        "id": "rag-application",
        "title": "RAG application",
        "summary": "A retrieval-augmented application with documented ingestion, query, identity, and cleanup operations.",
        "target_kind": "api",
        "capabilities": ["rag", "external_content", "multi_identity"],
        "relevant_sections": ["authorization", "target", "capabilities", "adapters", "proof", "readiness"],
        "requirements": _COMMON_CONNECTION_REQUIREMENTS + [
            {"id": "rag-operations", "title": "RAG operation map", "section": "adapters", "description": "Authorize and map the exact baseline, ingestion, query, cleanup, and cleanup-verification routes and fields."},
            {"id": "rag-proof", "title": "Retrieval controls and cleanup proof", "section": "proof", "description": "Define owner/restricted identities, deterministic canaries, positive/negative controls, retention, and mandatory cleanup verification."},
        ],
        "operator_note": "No collection, document, canary, identity, route, field, or cleanup permission is generated by this profile.",
    },
    {
        "id": "artifact-assessment",
        "title": "Artifact assessment",
        "summary": "Static assessment of customer-supplied model, adapter, dependency, SBOM, or dataset artifacts.",
        "target_kind": "api",
        "capabilities": ["artifact_inventory"],
        "relevant_sections": ["authorization", "target", "capabilities", "proof", "readiness"],
        "requirements": _COMMON_CONNECTION_REQUIREMENTS + [
            {"id": "artifact", "title": "Authorized artifact", "section": "adapters", "description": "Upload the exact customer-supplied bytes and select the artifact type without loading or executing them."},
            {"id": "artifact-policy", "title": "Artifact policy", "section": "proof", "description": "Define approved digests, structure, serialization, dependency, provenance, and signature-metadata requirements."},
        ],
        "operator_note": "No approved digest, package rule, provenance value, signature claim, or customer artifact is supplied by this profile.",
    },
)


_PROFILE_INDEX = {item["id"]: item for item in TARGET_SETUP_PROFILES}
_SENSITIVE_HEADER_NAMES = {"authorization", "cookie", "proxy-authorization", "x-api-key", "api-key"}
_ALLOWED_TARGET_FIELDS = {
    "name", "kind", "base_url", "path", "method", "headers", "request_template",
    "response_path", "description", "browser_profile", "capabilities", "analysis_config",
    "conversation_config", "transport_config", "authorized_routes",
}


def public_target_profiles() -> dict[str, Any]:
    return {
        "schema_version": TARGET_PROFILE_SCHEMA_VERSION,
        "profiles": copy.deepcopy(list(TARGET_SETUP_PROFILES)),
        "safety": {
            "creates_target": False,
            "secrets_allowed": False,
            "operator_review_required": True,
            "statement": "Profiles reveal relevant controls and can populate a reviewable draft. They never authorize a route, identity, effect, secret, proof value, or permission.",
        },
    }


def get_target_setup_profile(profile_id: str) -> dict[str, Any]:
    profile = _PROFILE_INDEX.get(str(profile_id or "").strip())
    if not profile:
        raise ValueError("unknown target setup profile")
    return copy.deepcopy(profile)


def _safe_headers(headers: Any) -> tuple[dict[str, str], list[str]]:
    if not isinstance(headers, dict):
        return {}, []
    retained: dict[str, str] = {}
    omitted: list[str] = []
    for raw_name, raw_value in headers.items():
        name, value = str(raw_name).strip(), str(raw_value).strip()
        if not name:
            continue
        if name.casefold() in _SENSITIVE_HEADER_NAMES and not value.startswith("env:"):
            omitted.append(name)
            continue
        retained[name] = value
    return retained, sorted(omitted, key=str.casefold)


def export_target_profile(target: dict[str, Any], *, profile_id: str = "generic-json-chatbot") -> dict[str, Any]:
    profile = get_target_setup_profile(profile_id)
    headers, omitted_headers = _safe_headers(target.get("headers"))
    exported = {
        key: copy.deepcopy(target.get(key))
        for key in _ALLOWED_TARGET_FIELDS
        if key in target and key != "headers"
    }
    exported["headers"] = headers
    exported.pop("scope_confirmed", None)
    return {
        "schema_version": TARGET_PROFILE_SCHEMA_VERSION,
        "profile_id": profile["id"],
        "profile_title": profile["title"],
        "target": exported,
        "review": {
            "authorization_included": False,
            "scope_confirmation_included": False,
            "secrets_included": False,
            "omitted_sensitive_headers": omitted_headers,
            "omitted_sections": ["guardrail", "evaluation_config", "technique_adapters", "assessment_contracts", "artifact bytes", "evidence", "credentials"],
            "statement": "Import creates a draft only. Review every address, route, field, capability, selector, and environment reference before saving it in another project.",
        },
    }


def validate_target_profile_document(document: Any) -> dict[str, Any]:
    if isinstance(document, str):
        try:
            document = json.loads(document)
        except json.JSONDecodeError as exc:
            raise ValueError("target profile must be valid JSON") from exc
    if not isinstance(document, dict):
        raise ValueError("target profile must be a JSON object")
    if str(document.get("schema_version") or "") != TARGET_PROFILE_SCHEMA_VERSION:
        raise ValueError(f"target profile schema must be {TARGET_PROFILE_SCHEMA_VERSION}")
    profile = get_target_setup_profile(str(document.get("profile_id") or ""))
    target = document.get("target")
    if not isinstance(target, dict):
        raise ValueError("target profile must contain a target object")
    unknown = sorted(set(target) - _ALLOWED_TARGET_FIELDS)
    if unknown:
        raise ValueError("target profile contains unsupported fields: " + ", ".join(unknown))
    headers, omitted_headers = _safe_headers(target.get("headers"))
    if omitted_headers:
        raise ValueError("target profile contains literal sensitive header values; replace them with env: references: " + ", ".join(omitted_headers))
    normalized = {key: copy.deepcopy(value) for key, value in target.items() if key in _ALLOWED_TARGET_FIELDS}
    normalized["headers"] = headers
    normalized["kind"] = str(normalized.get("kind") or profile["target_kind"])
    if normalized["kind"] not in {"chatbot", "api", "browser-chatbot"}:
        raise ValueError("target profile kind is unsupported")
    capabilities = normalized.get("capabilities") or {}
    if not isinstance(capabilities, dict):
        raise ValueError("target profile capabilities must be an object")
    normalized["capabilities"] = {str(key): bool(value) for key, value in capabilities.items()}
    normalized["scope_confirmed"] = False
    return {
        "schema_version": TARGET_PROFILE_SCHEMA_VERSION,
        "profile": profile,
        "target_draft": normalized,
        "operator_review_required": True,
        "creates_target": False,
        "warnings": [
            "Authorization and guardrails are intentionally not imported.",
            "The target draft is not executable until the operator reviews and saves it under this project's Attack Surface.",
        ],
    }


def target_profile_readiness(
    profile_id: str,
    target: dict[str, Any] | None,
    *,
    has_scope: bool = False,
    has_policy: bool = False,
    guardrail: dict[str, Any] | None = None,
    artifact_count: int = 0,
) -> dict[str, Any]:
    profile = get_target_setup_profile(profile_id)
    target = target or {}
    guardrail = guardrail or {}
    kind_ok = bool(target) and target.get("kind") == profile["target_kind"]
    endpoint_ok = bool(target.get("base_url") and target.get("path") and target.get("method"))
    if target.get("kind") == "browser-chatbot":
        browser = target.get("browser_profile") or {}
        adapter_ok = all(browser.get(key) for key in ("input_selector", "submit_selector", "response_selector"))
    else:
        adapter_ok = isinstance(target.get("request_template"), dict) and bool(target.get("request_template"))
    capabilities = target.get("capabilities") or {}
    capability_ok = all(capabilities.get(key) for key in profile["capabilities"])
    evaluation = target.get("evaluation_config") or {}
    specialized = True
    specialized_detail = "No additional capability-specific adapter is required."
    if profile_id == "tool-calling-agent":
        specialized = bool((evaluation.get("tool_agent") or {}).get("enabled"))
        specialized_detail = "Tool schemas, identities, cases, verifier, and cleanup policy are configured." if specialized else "Configure the tool-agent adapter with target-owned tools, identities, cases, proof, and cleanup."
    elif profile_id == "mcp-server":
        specialized = bool((evaluation.get("mcp") or {}).get("enabled"))
        specialized_detail = "MCP transport, lifecycle, identities, and cases are configured." if specialized else "Configure current or legacy MCP transport, lifecycle, identities, and cases."
    elif profile_id == "rag-application":
        specialized = bool((evaluation.get("rag") or {}).get("enabled"))
        specialized_detail = "RAG operations, identities, controls, and cleanup are configured." if specialized else "Configure documented RAG operations, identities, controls, and cleanup verification."
    elif profile_id == "artifact-assessment":
        specialized = artifact_count > 0 and bool((evaluation.get("artifact") or {}).get("enabled"))
        specialized_detail = "An authorized artifact and artifact policy case are configured." if specialized else "Upload an authorized artifact and configure its deterministic artifact policy."
    checks = [
        {"id": "authorization", "title": "Authorization documents", "ready": bool(has_scope and has_policy), "detail": "Scope/ROE and target policy are present." if has_scope and has_policy else "Add both scope/ROE and target policy documents."},
        {"id": "target", "title": "Exact target", "ready": bool(kind_ok and endpoint_ok), "detail": "Target kind, origin, route, and method match this profile." if kind_ok and endpoint_ok else "Create or select a target whose exact kind, origin, route, and method match this profile."},
        {"id": "adapter", "title": "Primary adapter", "ready": adapter_ok, "detail": "The target-owned request/browser adapter is configured." if adapter_ok else "Configure the documented request and response fields or browser selectors."},
        {"id": "capabilities", "title": "Declared capabilities", "ready": capability_ok, "detail": "Every capability required by this profile is explicitly declared." if capability_ok else "Declare only the profile capabilities that the customer documentation confirms."},
        {"id": "specialized", "title": "Capability-specific proof", "ready": specialized, "detail": specialized_detail},
        {"id": "guardrail", "title": "Approved execution guardrail", "ready": guardrail.get("status") == "approved", "detail": "An approved guardrail references this target." if guardrail.get("status") == "approved" else "Create and approve a target-referenced execution guardrail."},
    ]
    return {
        "schema_version": TARGET_PROFILE_SCHEMA_VERSION,
        "profile": profile,
        "target_id": target.get("id"),
        "ready": all(item["ready"] for item in checks),
        "checks": checks,
        "statement": "Readiness confirms configuration completeness only. It is not a security verdict and sends no target traffic.",
    }
