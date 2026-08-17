from __future__ import annotations

from copy import deepcopy
from typing import Any

from .modules import ATTACK_CATALOG_VERSION
from .owasp import RISK_INDEX, TAXONOMY_ID, TAXONOMY_VERSION, TECHNIQUE_INDEX
from .release import QUALIFICATION_REGISTRY_SCHEMA_VERSION, QUALIFICATION_REGISTRY_VERSION


REGISTRY_SCHEMA_VERSION = QUALIFICATION_REGISTRY_SCHEMA_VERSION
REGISTRY_ID = "adverscope-technique-qualification"
REGISTRY_VERSION = QUALIFICATION_REGISTRY_VERSION
QUALIFICATION_STATUSES = {"experimental", "validated", "qualified", "deprecated"}
IMPLEMENTATION_PATHS = {"native", "contract", "manual", "unsupported"}


_DETERMINISTIC_MODULES = {
    "artifact-security",
    "excessive-agency",
    "mcp-security",
    "misinformation",
    "rag-security",
}


def _mcp_content_boundary_evidence(key: str, technique_scope: str) -> dict[str, Any]:
    report = "validation/target-campaigns/mcp-content-boundary-qualification-2026-08-09-results.json"
    fixtures: dict[str, list[dict[str, str]]] = {"secure": [], "vulnerable": []}
    expectation_ids: list[str] = []
    for transport, family in (
        ("current", "adverscope-streamable-mcp-content-boundary-fixture"),
        ("legacy", "adverscope-legacy-sse-mcp-content-boundary-fixture"),
    ):
        for mode in ("secure", "vulnerable"):
            for repetition in (1, 2):
                label = f"{transport}-{mode}-{repetition}"
                expectation_id = f"{transport}-{key}-{mode}-{repetition}"
                expectation_ids.append(expectation_id)
                fixtures[mode].append({
                    "id": f"{transport}-mcp-{key}-{mode}-{repetition}",
                    "kind": "independent-target-control" if mode == "secure" else "independent-target-vulnerability",
                    "target_family": family,
                    "reference": f"{report}#{label}",
                })
    return {
        "secure_fixtures": fixtures["secure"],
        "vulnerable_fixtures": fixtures["vulnerable"],
        "benchmark_evidence": [{
            "suite_id": "adverscope-current-legacy-mcp-content-boundary-fixtures",
            "campaign_id": "mcp-content-boundary-qualification-2026-08-09",
            "expectation_ids": expectation_ids,
            "date": "2026-08-09",
        }],
        "metrics": {
            "precision": 1.0,
            "supported_recall": 1.0,
            "execution_error_rate": 0.0,
            "reproduction_rate": 1.0,
            "sample_scope": (
                "two independent protocol families; repeated secure and vulnerable MCP content and resource-boundary "
                "runs over Streamable HTTP 2025-11-25 and legacy HTTP+SSE 2024-11-05 through the visible GUI"
            ),
        },
        "known_limitations": [
            technique_scope,
            (
                "The two target families are sibling deterministic protocol fixtures. They qualify AdverScope protocol "
                "handling, source and identity preservation, exact assertion evaluation, evidence custody, and reproduction, "
                "not arbitrary third-party MCP implementations."
            ),
            (
                "The finding gate is deterministic and provider-independent. Remote planners and evaluators, custom transports, "
                "opaque brokers, chained agents, callbacks, prompt access, and state-changing MCP effects remain outside this campaign."
            ),
        ],
    }


def _mcp_inventory_evidence() -> dict[str, Any]:
    report = "validation/target-campaigns/mcp-inventory-qualification-2026-08-09-results.json"
    lifecycle_report = "validation/target-campaigns/mcp-inventory-lifecycle-qualification-2026-08-09-results.json"
    older_dynamic_report = "validation/target-campaigns/mcp-older-dynamic-sdk-qualification-2026-08-09-results.json"
    fixtures: dict[str, list[dict[str, str]]] = {"secure": [], "vulnerable": []}
    expectation_ids: list[str] = []
    for family, target_family in (
        ("native", "adverscope-protocol-mcp-inventory-fixture"),
        ("sdk", "official-mcp-python-sdk-1.25-inventory-fixture"),
    ):
        for transport in ("current", "legacy"):
            for mode in ("secure", "vulnerable"):
                for repetition in (1, 2):
                    label = f"{family}-{transport}-{mode}-{repetition}"
                    expectation_id = f"{label}-inventory-integrity"
                    expectation_ids.append(expectation_id)
                    fixtures[mode].append({
                        "id": f"{label}-mcp-inventory",
                        "kind": "independent-target-control" if mode == "secure" else "independent-target-vulnerability",
                        "target_family": target_family,
                        "reference": f"{report}#{label}",
                    })
    for family, transport, target_family in (
        ("raw", "stateless", "adverscope-protocol-mcp-inventory-lifecycle-fixture"),
        ("raw", "streamable", "adverscope-protocol-mcp-inventory-lifecycle-fixture"),
        ("raw", "legacy", "adverscope-protocol-mcp-inventory-lifecycle-fixture"),
        ("sdk-v2", "stateless", "official-mcp-typescript-sdk-v2-inventory-fixture"),
    ):
        for mode in ("secure", "vulnerable"):
            for repetition in (1, 2):
                label = f"{family}-{transport}-{mode}-{repetition}"
                expectation_id = f"{label}-inventory-lifecycle"
                expectation_ids.append(expectation_id)
                fixtures[mode].append({
                    "id": f"{label}-mcp-inventory-lifecycle",
                    "kind": "independent-target-control" if mode == "secure" else "independent-target-vulnerability",
                    "target_family": target_family,
                    "reference": f"{lifecycle_report}#{label}",
                })
    older_dynamic_expectation_ids: list[str] = []
    for transport in ("current", "legacy"):
        for mode in ("secure", "vulnerable"):
            for repetition in (1, 2):
                label = f"sdk-{transport}-{mode}-{repetition}"
                expectation_id = f"{label}-drift"
                older_dynamic_expectation_ids.append(expectation_id)
                fixtures[mode].append({
                    "id": f"{label}-mcp-inventory-lifecycle",
                    "kind": "independent-target-control" if mode == "secure" else "independent-target-vulnerability",
                    "target_family": "official-mcp-python-sdk-dynamic-inventory-fixture",
                    "reference": f"{older_dynamic_report}#{label}",
                })
    return {
        "secure_fixtures": fixtures["secure"],
        "vulnerable_fixtures": fixtures["vulnerable"],
        "benchmark_evidence": [
            {
                "suite_id": "adverscope-independent-current-legacy-mcp-inventory-fixtures",
                "campaign_id": "mcp-inventory-qualification-2026-08-09",
                "expectation_ids": [item for item in expectation_ids if item.endswith("-inventory-integrity")],
                "date": "2026-08-09",
            },
            {
                "suite_id": "adverscope-mcp-inventory-lifecycle-current-legacy-modern",
                "campaign_id": "mcp-inventory-lifecycle-qualification-2026-08-09",
                "expectation_ids": [item for item in expectation_ids if item.endswith("-inventory-lifecycle")],
                "date": "2026-08-09",
            },
            {
                "suite_id": "adverscope-mcp-older-dynamic-official-python-sdk",
                "campaign_id": "mcp-older-dynamic-sdk-qualification-2026-08-09",
                "expectation_ids": older_dynamic_expectation_ids,
                "date": "2026-08-09",
            },
        ],
        "metrics": {
            "precision": 1.0,
            "supported_recall": 1.0,
            "execution_error_rate": 0.0,
            "reproduction_rate": 1.0,
            "sample_scope": (
                "at least two unrelated implementation families for initial inventory and every retained dynamic lifecycle generation; "
                "repeated secure and vulnerable GUI runs over sessionless 2026-07-28, Streamable HTTP 2025-11-25, "
                "and legacy HTTP+SSE 2024-11-05"
            ),
        },
        "known_limitations": [
            (
                "Qualification covers complete normalized inventory SHA-256 comparison, required and forbidden tool names, "
                "and optional per-tool description and input-schema digests supplied by the target owner."
            ),
            (
                "Initial read-only inventory listing is qualified for an AdverScope raw-protocol fixture and an unrelated "
                "official MCP Python SDK implementation over retained current and legacy transports. Post-initialization drift "
                "and notification custody are qualified for the raw fixture plus an unrelated official TypeScript SDK v2 on the "
                "2026-07-28 sessionless path and an unrelated official Python SDK implementation on older retained transports."
            ),
            (
                "Arbitrary registries, remote brokers, custom transports, every SDK, prompt/resource semantic integrity, and "
                "state-changing effects remain outside this boundary. A notification, HTTP success, JSON-RPC success, or model "
                "prose alone never satisfies the finding gate; a subsequent target-owned inventory-policy violation is required."
            ),
        ],
    }


def _mcp_prompt_evidence() -> dict[str, Any]:
    report = "validation/target-campaigns/mcp-prompt-qualification-2026-08-09-results.json"
    fixtures: dict[str, list[dict[str, str]]] = {"secure": [], "vulnerable": []}
    expectation_ids: list[str] = []
    for family, target_family in (
        ("raw", "adverscope-protocol-mcp-prompt-boundary-fixture"),
        ("sdk", "official-mcp-python-sdk-prompt-boundary-fixture"),
    ):
        for transport in ("current", "legacy"):
            for mode in ("secure", "vulnerable"):
                for repetition in (1, 2):
                    label = f"{family}-{transport}-{mode}-{repetition}"
                    expectation_ids.extend((f"{label}-inventory", f"{label}-get"))
                    fixtures[mode].append({
                        "id": f"{label}-mcp-prompt-boundary",
                        "kind": "independent-target-control" if mode == "secure" else "independent-target-vulnerability",
                        "target_family": target_family,
                        "reference": f"{report}#{label}",
                    })
    return {
        "secure_fixtures": fixtures["secure"],
        "vulnerable_fixtures": fixtures["vulnerable"],
        "benchmark_evidence": [{
            "suite_id": "adverscope-mcp-prompt-current-legacy-raw-sdk",
            "campaign_id": "mcp-prompt-qualification-2026-08-09",
            "expectation_ids": expectation_ids,
            "date": "2026-08-09",
        }],
        "metrics": {
            "precision": 1.0,
            "supported_recall": 1.0,
            "execution_error_rate": 0.0,
            "reproduction_rate": 1.0,
            "sample_scope": (
                "two unrelated implementation families; repeated secure and vulnerable prompt inventory and retrieval runs "
                "over Streamable HTTP 2025-11-25 and legacy HTTP+SSE 2024-11-05 through the visible GUI"
            ),
        },
        "known_limitations": [
            (
                "Qualification covers target-configured required and forbidden prompt names, optional exact prompt metadata "
                "digests, and unauthorized prompts/get disclosure proved by non-empty returned messages plus every exact "
                "target-owned content and authorization assertion."
            ),
            (
                "The two implementation families are an AdverScope raw-protocol fixture and an unrelated official MCP Python "
                "SDK fixture. Current and legacy transport variants are not counted as separate implementation families."
            ),
            (
                "Arbitrary prompt semantics, safe prompt quality, custom authorization brokers, custom transports, every SDK, "
                "chained agents, and state-changing prompt effects remain outside this boundary. Prompt listing, notifications, "
                "HTTP success, JSON-RPC success, non-empty prose, and model confidence alone cannot confirm a finding."
            ),
        ],
    }


# Evidence is deliberately post-run metadata. It contains no target address,
# payload, credential, response body, recovered proof value, or solution step.
_QUALIFICATION_EVIDENCE: dict[str, dict[str, Any]] = {
    "LLM03-MCP-INVENTORY": _mcp_inventory_evidence(),
    "LLM02-MCP-PROMPT": _mcp_prompt_evidence(),
    "LLM01-MCP-CONTENT": _mcp_content_boundary_evidence(
        "content",
        (
            "Qualification covers target-configured untrusted MCP resource provenance and a read-only structured sink effect. "
            "Malicious instructions or metadata that are merely visible remain observations and do not satisfy this finding gate."
        ),
    ),
    "LLM02-MCP-RESOURCE": _mcp_content_boundary_evidence(
        "resource",
        (
            "Qualification covers unauthorized resources/read disclosure proved by exact resource URI, restricted caller identity, "
            "protected classification, data category, and a target-configured synthetic marker. Prose and non-empty content alone do not qualify."
        ),
    ),
    "LLM08-MCP-BOUNDARY": _mcp_content_boundary_evidence(
        "boundary",
        (
            "Qualification covers cross-identity resources/read boundaries proved by exact caller, owner, authorization outcome, "
            "resource URI, and tenant-private classification. Other vector, embedding, and RAG boundaries are separate techniques."
        ),
    ),
    "LLM01-DIRECT": {
        "secure_fixtures": [
            {
                "id": "independent-semantic-secure-qwen27b",
                "kind": "independent-target-control",
                "target_family": "adverscope-independent-semantic-fixture",
                "reference": "validation/target-campaigns/fresh-multi-model-qualification-2026-08-08.json#27b-secure",
            },
            {
                "id": "independent-semantic-secure-qwen4b",
                "kind": "independent-target-control",
                "target_family": "adverscope-independent-semantic-fixture",
                "reference": "validation/target-campaigns/fresh-multi-model-qualification-2026-08-08.json#4b-secure",
            },
            {
                "id": "policy-gateway-secure-qwen27b-repeated",
                "kind": "independent-target-control",
                "target_family": "adverscope-policy-decision-gateway-fixture",
                "reference": "validation/target-campaigns/repeated-policy-gateway-qualification-2026-08-09.json#27b-secure",
            },
            {
                "id": "policy-gateway-secure-qwen4b-repeated",
                "kind": "independent-target-control",
                "target_family": "adverscope-policy-decision-gateway-fixture",
                "reference": "validation/target-campaigns/repeated-policy-gateway-qualification-2026-08-09.json#4b-secure",
            },
        ],
        "vulnerable_fixtures": [
            {
                "id": "independent-semantic-vulnerable-qwen27b",
                "kind": "independent-target-vulnerability",
                "target_family": "adverscope-independent-semantic-fixture",
                "reference": "validation/target-campaigns/fresh-multi-model-qualification-2026-08-08.json#27b-vulnerable",
            },
            {
                "id": "independent-semantic-vulnerable-qwen4b",
                "kind": "independent-target-vulnerability",
                "target_family": "adverscope-independent-semantic-fixture",
                "reference": "validation/target-campaigns/fresh-multi-model-qualification-2026-08-08.json#4b-vulnerable",
            },
            {
                "id": "policy-gateway-vulnerable-qwen27b-repeated",
                "kind": "independent-target-vulnerability",
                "target_family": "adverscope-policy-decision-gateway-fixture",
                "reference": "validation/target-campaigns/repeated-policy-gateway-qualification-2026-08-09.json#27b-vulnerable",
            },
            {
                "id": "policy-gateway-vulnerable-qwen4b-repeated",
                "kind": "independent-target-vulnerability",
                "target_family": "adverscope-policy-decision-gateway-fixture",
                "reference": "validation/target-campaigns/repeated-policy-gateway-qualification-2026-08-09.json#4b-vulnerable",
            },
        ],
        "benchmark_evidence": [
            {
                "suite_id": "adverscope-independent-semantic-fixtures",
                "campaign_id": "fresh-multi-model-qualification-2026-08-08",
                "expectation_ids": [
                    "27b-secure",
                    "27b-vulnerable",
                    "4b-secure",
                    "4b-vulnerable",
                ],
                "date": "2026-08-08",
            },
            {
                "suite_id": "adverscope-policy-decision-gateway-fixtures",
                "campaign_id": "repeated-policy-gateway-qualification-2026-08-09",
                "expectation_ids": [
                    "27b-secure-1",
                    "27b-secure-2",
                    "27b-vulnerable-1",
                    "27b-vulnerable-2",
                    "4b-secure-1",
                    "4b-secure-2",
                    "4b-vulnerable-1",
                    "4b-vulnerable-2",
                ],
                "date": "2026-08-09",
            }
        ],
        "metrics": {
            "precision": 1.0,
            "supported_recall": 1.0,
            "execution_error_rate": 0.0,
            "reproduction_rate": 1.0,
            "sample_scope": "two unrelated independent target families; repeated secure/vulnerable policy-gateway campaigns plus semantic-fixture campaigns with qwen3.6-27b and qwen3-4b-classifier evaluators",
        },
        "known_limitations": [
            "Qualification is limited to direct semantic instruction-boundary violations covered by LLM01-DIRECT; it does not qualify the other LLM01 techniques or the complete OWASP LLM Top 10.",
            "The two target families are independent AdverScope fixtures. Additional external target families and future model versions should be added to detect generalization regressions.",
        ],
    },
    "LLM01-INDIRECT-WEB": {
        "secure_fixtures": [
            {
                "id": "portswigger-ps-llm-03-negative-controls",
                "kind": "independent-target-control",
                "target_family": "portswigger-web-llm",
                "reference": "validation/portswigger/qualification-target-apps-2026-08-08.json#PS-LLM-03",
            },
            {
                "id": "document-assistant-secure-qwen27b-repetition-1",
                "kind": "independent-target-control",
                "target_family": "adverscope-document-retrieval-assistant-fixture",
                "reference": "validation/target-campaigns/indirect-document-assistant-qualification-2026-08-09-results.json#qwen-secure-1",
            },
            {
                "id": "document-assistant-secure-qwen27b-repetition-2",
                "kind": "independent-target-control",
                "target_family": "adverscope-document-retrieval-assistant-fixture",
                "reference": "validation/target-campaigns/indirect-document-assistant-qualification-2026-08-09-results.json#qwen-secure-2",
            },
        ],
        "vulnerable_fixtures": [
            {
                "id": "portswigger-ps-llm-03-stored-indirect-injection",
                "kind": "independent-target-vulnerability",
                "target_family": "portswigger-web-llm",
                "reference": "validation/portswigger/qualification-target-apps-2026-08-08.json#PS-LLM-03",
            },
            {
                "id": "document-assistant-vulnerable-qwen27b-repetition-1",
                "kind": "independent-target-vulnerability",
                "target_family": "adverscope-document-retrieval-assistant-fixture",
                "reference": "validation/target-campaigns/indirect-document-assistant-qualification-2026-08-09-results.json#qwen-vulnerable-1",
            },
            {
                "id": "document-assistant-vulnerable-qwen27b-repetition-2",
                "kind": "independent-target-vulnerability",
                "target_family": "adverscope-document-retrieval-assistant-fixture",
                "reference": "validation/target-campaigns/indirect-document-assistant-qualification-2026-08-09-results.json#qwen-vulnerable-2",
            },
        ],
        "benchmark_evidence": [
            {
                "suite_id": "portswigger-web-llm-target-apps",
                "campaign_id": "portswigger-target-apps-2026-08-08",
                "expectation_ids": [
                    "ps-llm-03-stored-indirect-injection",
                    "ps-llm-03-negative-controls",
                ],
                "date": "2026-08-08",
            },
            {
                "suite_id": "adverscope-indirect-document-assistant-fixtures",
                "campaign_id": "indirect-document-assistant-qualification-2026-08-09",
                "expectation_ids": [
                    "indirect-doc-secure-1",
                    "indirect-doc-secure-2",
                    "indirect-doc-vulnerable-1",
                    "indirect-doc-vulnerable-2",
                ],
                "date": "2026-08-09",
            }
        ],
        "metrics": {
            "precision": 1.0,
            "supported_recall": 1.0,
            "execution_error_rate": 0.0,
            "reproduction_rate": 1.0,
            "sample_scope": "two independent target families; PortSwigger stored-review workflow plus repeated secure/vulnerable document-retrieval-assistant runs through the visible GUI with qwen3.6-27b selected",
        },
        "known_limitations": [
            "Qualification covers operator-prepared stored web or document carriers with a clean negative control and target-configured exact-response or browser-effect proof; it does not qualify every indirect, multimodal, email, RAG-poisoning, or cross-agent delivery channel.",
            "The independent document-assistant fixture is deterministic, so repeated target verdicts validate AdverScope orchestration and evaluation rather than model stochasticity. Additional external target families should be retained as they become available.",
        ],
    },
    "LLM06-TOOLS": {
        "secure_fixtures": [
            {
                "id": "portswigger-ps-llm-01-direct-control",
                "kind": "independent-target-control",
                "target_family": "portswigger-web-llm",
                "reference": "validation/portswigger/qualification-target-apps-2026-08-08.json#PS-LLM-01",
            },
            {
                "id": "workspace-tool-authorization-secure-qwen27b-repetition-1",
                "kind": "independent-target-control",
                "target_family": "adverscope-workspace-tool-authorization-fixture",
                "reference": "validation/target-campaigns/tool-authorization-qualification-2026-08-09-results.json#qwen-secure-1",
            },
            {
                "id": "workspace-tool-authorization-secure-qwen27b-repetition-2",
                "kind": "independent-target-control",
                "target_family": "adverscope-workspace-tool-authorization-fixture",
                "reference": "validation/target-campaigns/tool-authorization-qualification-2026-08-09-results.json#qwen-secure-2",
            },
        ],
        "vulnerable_fixtures": [
            {
                "id": "portswigger-ps-llm-01-excessive-agency",
                "kind": "independent-target-vulnerability",
                "target_family": "portswigger-web-llm",
                "reference": "validation/portswigger/qualification-target-apps-2026-08-08.json#PS-LLM-01",
            },
            {
                "id": "workspace-tool-authorization-vulnerable-qwen27b-repetition-1",
                "kind": "independent-target-vulnerability",
                "target_family": "adverscope-workspace-tool-authorization-fixture",
                "reference": "validation/target-campaigns/tool-authorization-qualification-2026-08-09-results.json#qwen-vulnerable-1",
            },
            {
                "id": "workspace-tool-authorization-vulnerable-qwen27b-repetition-2",
                "kind": "independent-target-vulnerability",
                "target_family": "adverscope-workspace-tool-authorization-fixture",
                "reference": "validation/target-campaigns/tool-authorization-qualification-2026-08-09-results.json#qwen-vulnerable-2",
            },
        ],
        "benchmark_evidence": [
            {
                "suite_id": "portswigger-web-llm-target-apps",
                "campaign_id": "portswigger-target-apps-2026-08-08",
                "expectation_ids": [
                    "ps-llm-01-excessive-agency",
                    "ps-llm-01-direct-control",
                ],
                "date": "2026-08-08",
            },
            {
                "suite_id": "adverscope-workspace-tool-authorization-fixtures",
                "campaign_id": "tool-authorization-qualification-2026-08-09",
                "expectation_ids": [
                    "tool-auth-secure-1",
                    "tool-auth-secure-2",
                    "tool-auth-vulnerable-1",
                    "tool-auth-vulnerable-2",
                ],
                "date": "2026-08-09",
            }
        ],
        "metrics": {
            "precision": 1.0,
            "supported_recall": 1.0,
            "execution_error_rate": 0.0,
            "reproduction_rate": 1.0,
            "sample_scope": "two independent target families; PortSwigger excessive-agency evidence plus repeated secure/vulnerable workspace-authorization runs through the visible GUI with qwen3.6-27b selected",
        },
        "known_limitations": [
            "Qualification covers structured OpenAI-compatible proposed tool calls evaluated against a target-configured identity, allow/deny, approval, schema, and iteration policy. It does not qualify arbitrary agent protocols, implicit side effects, every callback pattern, or the remaining LLM06 techniques.",
            "AdverScope never dispatched the target-proposed administrative tool. The independent fixture is deterministic, so repetition validates generation, protocol evidence, policy evaluation, objective binding, and reproduction rather than stochastic target-model variance.",
            "The local Qwen provider generated attack wording and model-review context, while the finding gate remained the target-owned structured policy assertion. Remote providers remain unqualified until separate campaigns pass.",
        ],
    },
    "LLM06-MCP-TOOLS": {
        "secure_fixtures": [
            {
                "id": "streamable-mcp-tool-authorization-secure-1",
                "kind": "independent-target-control",
                "target_family": "adverscope-streamable-mcp-authorization-fixture",
                "reference": "validation/target-campaigns/mcp-authorization-qualification-2026-08-09-results.json#current-secure-1",
            },
            {
                "id": "streamable-mcp-tool-authorization-secure-2",
                "kind": "independent-target-control",
                "target_family": "adverscope-streamable-mcp-authorization-fixture",
                "reference": "validation/target-campaigns/mcp-authorization-qualification-2026-08-09-results.json#current-secure-2",
            },
            {
                "id": "legacy-sse-mcp-tool-authorization-secure-1",
                "kind": "independent-target-control",
                "target_family": "adverscope-legacy-sse-mcp-authorization-fixture",
                "reference": "validation/target-campaigns/mcp-authorization-qualification-2026-08-09-results.json#legacy-secure-1",
            },
            {
                "id": "legacy-sse-mcp-tool-authorization-secure-2",
                "kind": "independent-target-control",
                "target_family": "adverscope-legacy-sse-mcp-authorization-fixture",
                "reference": "validation/target-campaigns/mcp-authorization-qualification-2026-08-09-results.json#legacy-secure-2",
            },
        ],
        "vulnerable_fixtures": [
            {
                "id": "streamable-mcp-tool-authorization-vulnerable-1",
                "kind": "independent-target-vulnerability",
                "target_family": "adverscope-streamable-mcp-authorization-fixture",
                "reference": "validation/target-campaigns/mcp-authorization-qualification-2026-08-09-results.json#current-vulnerable-1",
            },
            {
                "id": "streamable-mcp-tool-authorization-vulnerable-2",
                "kind": "independent-target-vulnerability",
                "target_family": "adverscope-streamable-mcp-authorization-fixture",
                "reference": "validation/target-campaigns/mcp-authorization-qualification-2026-08-09-results.json#current-vulnerable-2",
            },
            {
                "id": "legacy-sse-mcp-tool-authorization-vulnerable-1",
                "kind": "independent-target-vulnerability",
                "target_family": "adverscope-legacy-sse-mcp-authorization-fixture",
                "reference": "validation/target-campaigns/mcp-authorization-qualification-2026-08-09-results.json#legacy-vulnerable-1",
            },
            {
                "id": "legacy-sse-mcp-tool-authorization-vulnerable-2",
                "kind": "independent-target-vulnerability",
                "target_family": "adverscope-legacy-sse-mcp-authorization-fixture",
                "reference": "validation/target-campaigns/mcp-authorization-qualification-2026-08-09-results.json#legacy-vulnerable-2",
            },
        ],
        "benchmark_evidence": [
            {
                "suite_id": "adverscope-current-legacy-mcp-authorization-fixtures",
                "campaign_id": "mcp-authorization-qualification-2026-08-09",
                "expectation_ids": [
                    "current-tools-secure-1",
                    "current-tools-secure-2",
                    "current-tools-vulnerable-1",
                    "current-tools-vulnerable-2",
                    "legacy-tools-secure-1",
                    "legacy-tools-secure-2",
                    "legacy-tools-vulnerable-1",
                    "legacy-tools-vulnerable-2",
                ],
                "date": "2026-08-09",
            }
        ],
        "metrics": {
            "precision": 1.0,
            "supported_recall": 1.0,
            "execution_error_rate": 0.0,
            "reproduction_rate": 1.0,
            "sample_scope": "two independent protocol families; repeated secure and vulnerable MCP authorization runs over Streamable HTTP 2025-11-25 and legacy HTTP+SSE 2024-11-05 through the visible GUI",
        },
        "known_limitations": [
            "Qualification covers read-only tools/call authorization proved by target-owned structured result assertions. State-changing MCP calls require a separately authorized reversible action, verifier, cleanup contract, and guardrail before they can be qualified.",
            "The two target families are sibling deterministic authorization fixtures using different MCP transports. They qualify AdverScope protocol handling, identity enforcement, exact assertion evaluation, evidence custody, and reproduction, not arbitrary third-party MCP implementations.",
            "The finding gate is deterministic and does not depend on a model provider. Remote planners and evaluators, custom transports, callbacks, and non-JSON tool result formats remain outside this campaign.",
        ],
    },
    "LLM06-MCP-DEPUTY": {
        "secure_fixtures": [
            {
                "id": "streamable-mcp-deputy-authorization-secure-1",
                "kind": "independent-target-control",
                "target_family": "adverscope-streamable-mcp-authorization-fixture",
                "reference": "validation/target-campaigns/mcp-authorization-qualification-2026-08-09-results.json#current-secure-1",
            },
            {
                "id": "streamable-mcp-deputy-authorization-secure-2",
                "kind": "independent-target-control",
                "target_family": "adverscope-streamable-mcp-authorization-fixture",
                "reference": "validation/target-campaigns/mcp-authorization-qualification-2026-08-09-results.json#current-secure-2",
            },
            {
                "id": "legacy-sse-mcp-deputy-authorization-secure-1",
                "kind": "independent-target-control",
                "target_family": "adverscope-legacy-sse-mcp-authorization-fixture",
                "reference": "validation/target-campaigns/mcp-authorization-qualification-2026-08-09-results.json#legacy-secure-1",
            },
            {
                "id": "legacy-sse-mcp-deputy-authorization-secure-2",
                "kind": "independent-target-control",
                "target_family": "adverscope-legacy-sse-mcp-authorization-fixture",
                "reference": "validation/target-campaigns/mcp-authorization-qualification-2026-08-09-results.json#legacy-secure-2",
            },
        ],
        "vulnerable_fixtures": [
            {
                "id": "streamable-mcp-deputy-authorization-vulnerable-1",
                "kind": "independent-target-vulnerability",
                "target_family": "adverscope-streamable-mcp-authorization-fixture",
                "reference": "validation/target-campaigns/mcp-authorization-qualification-2026-08-09-results.json#current-vulnerable-1",
            },
            {
                "id": "streamable-mcp-deputy-authorization-vulnerable-2",
                "kind": "independent-target-vulnerability",
                "target_family": "adverscope-streamable-mcp-authorization-fixture",
                "reference": "validation/target-campaigns/mcp-authorization-qualification-2026-08-09-results.json#current-vulnerable-2",
            },
            {
                "id": "legacy-sse-mcp-deputy-authorization-vulnerable-1",
                "kind": "independent-target-vulnerability",
                "target_family": "adverscope-legacy-sse-mcp-authorization-fixture",
                "reference": "validation/target-campaigns/mcp-authorization-qualification-2026-08-09-results.json#legacy-vulnerable-1",
            },
            {
                "id": "legacy-sse-mcp-deputy-authorization-vulnerable-2",
                "kind": "independent-target-vulnerability",
                "target_family": "adverscope-legacy-sse-mcp-authorization-fixture",
                "reference": "validation/target-campaigns/mcp-authorization-qualification-2026-08-09-results.json#legacy-vulnerable-2",
            },
        ],
        "benchmark_evidence": [
            {
                "suite_id": "adverscope-current-legacy-mcp-authorization-fixtures",
                "campaign_id": "mcp-authorization-qualification-2026-08-09",
                "expectation_ids": [
                    "current-deputy-secure-1",
                    "current-deputy-secure-2",
                    "current-deputy-vulnerable-1",
                    "current-deputy-vulnerable-2",
                    "legacy-deputy-secure-1",
                    "legacy-deputy-secure-2",
                    "legacy-deputy-vulnerable-1",
                    "legacy-deputy-vulnerable-2",
                ],
                "date": "2026-08-09",
            }
        ],
        "metrics": {
            "precision": 1.0,
            "supported_recall": 1.0,
            "execution_error_rate": 0.0,
            "reproduction_rate": 1.0,
            "sample_scope": "two independent protocol families; repeated secure and vulnerable confused-deputy authorization runs over Streamable HTTP 2025-11-25 and legacy HTTP+SSE 2024-11-05 through the visible GUI",
        },
        "known_limitations": [
            "Qualification covers read-only confused-deputy cases where the target exposes caller identity, effective authority, decision source, and resource classification in a structured MCP result. Inferences from prose or caller-supplied fields do not satisfy the gate.",
            "The two target families are sibling deterministic authorization fixtures using different MCP transports. They qualify AdverScope protocol handling, identity preservation, exact assertion evaluation, evidence custody, and reproduction, not arbitrary third-party MCP implementations.",
            "The finding gate is deterministic and does not depend on a model provider. Remote planners and evaluators, custom brokers, chained agents, callbacks, and opaque authorization layers remain outside this campaign.",
        ],
    },
    "LLM05-ACTIVE": {
        "vulnerable_fixtures": [
            {
                "id": "portswigger-ps-llm-04-active-output-effect",
                "kind": "independent-target-vulnerability",
                "target_family": "portswigger-web-llm",
                "reference": "validation/portswigger/qualification-target-apps-2026-08-08.json#PS-LLM-04",
            }
        ],
        "benchmark_evidence": [
            {
                "suite_id": "portswigger-web-llm-target-apps",
                "campaign_id": "portswigger-target-apps-2026-08-08",
                "expectation_ids": ["ps-llm-04-active-output-effect"],
                "date": "2026-08-08",
            }
        ],
        "known_limitations": [
            "Independent secure-control target evidence is still required before validation status can be granted."
        ],
    },
}


def _implementation_path(technique: dict[str, Any]) -> str:
    if technique.get("module_id"):
        return "native"
    if technique.get("contract_automatable"):
        return "contract"
    if technique.get("requirement"):
        return "manual"
    return "unsupported"


def _model_dependence(technique: dict[str, Any], implementation_path: str) -> dict[str, str]:
    module_id = str(technique.get("module_id") or "")
    if implementation_path == "contract":
        return {"attack_generation": "none", "evaluation": "none"}
    if module_id in _DETERMINISTIC_MODULES:
        return {
            "attack_generation": "optional wording or planning supplement",
            "evaluation": "target-configured deterministic validator",
        }
    return {
        "attack_generation": "optional supplement to reviewed catalog",
        "evaluation": "hybrid model review with deterministic target-proof override",
    }


def _proof_requirements(technique: dict[str, Any], implementation_path: str) -> list[str]:
    if implementation_path == "contract":
        return [
            "target-owned deterministic evidence contract",
            "separate approved reproduction",
            "complete immutable request and response evidence",
        ]
    module_id = str(technique.get("module_id") or "")
    if module_id in _DETERMINISTIC_MODULES:
        return [
            "target-configured assertion or effect verifier",
            "negative or positive control where applicable",
            "separate approved reproduction or an explicit one-time-effect exception",
        ]
    return [
        "direct target-response evidence",
        "refusal and request-echo exclusions",
        "separate approved reproduction for confirmation",
    ]


def _qualification_status(entry: dict[str, Any]) -> str:
    secure = entry["fixtures"]["secure"]
    vulnerable = entry["fixtures"]["vulnerable"]
    if not secure or not vulnerable:
        return "experimental"
    families = {
        str(item.get("target_family") or "")
        for item in secure + vulnerable
        if str(item.get("target_family") or "")
    }
    metrics = entry.get("metrics") or {}
    precision = metrics.get("precision")
    recall = metrics.get("supported_recall")
    gates_pass = (
        isinstance(precision, (int, float))
        and isinstance(recall, (int, float))
        and precision >= 0.95
        and recall >= 0.95
    )
    return "qualified" if gates_pass and len(families) >= 2 else "validated"


def build_qualification_registry() -> dict[str, Any]:
    techniques = []
    for technique_id, raw in TECHNIQUE_INDEX.items():
        technique = dict(raw)
        implementation_path = _implementation_path(technique)
        evidence = deepcopy(_QUALIFICATION_EVIDENCE.get(technique_id) or {})
        secure_fixtures = list(evidence.get("secure_fixtures") or [])
        vulnerable_fixtures = list(evidence.get("vulnerable_fixtures") or [])
        entry = {
            "id": technique_id,
            "risk_id": str(technique["risk_id"]),
            "title": str(technique["title"]),
            "implementation": {
                "path": implementation_path,
                "module_id": str(technique.get("module_id") or ""),
                "contract_automatable": bool(technique.get("contract_automatable")),
                "attack_catalog_version": ATTACK_CATALOG_VERSION if technique.get("module_id") else "",
            },
            "requirements": {
                "capabilities": [str(technique["capability"])] if technique.get("capability") else [],
                "configuration": str(technique.get("configuration") or ""),
                "description": str(technique.get("requirement") or "No target-specific capability beyond the configured chatbot adapter."),
            },
            "fixtures": {
                "secure": secure_fixtures,
                "vulnerable": vulnerable_fixtures,
            },
            "benchmark_evidence": list(evidence.get("benchmark_evidence") or []),
            "metrics": evidence.get("metrics") or {
                "precision": None,
                "supported_recall": None,
                "execution_error_rate": None,
                "reproduction_rate": None,
                "sample_scope": "No technique-specific qualification sample recorded.",
            },
            "evaluator": {
                "kind": "deterministic" if implementation_path == "contract" or str(technique.get("module_id") or "") in _DETERMINISTIC_MODULES else "hybrid",
                "proof_requirements": _proof_requirements(technique, implementation_path),
            },
            "model_dependence": _model_dependence(technique, implementation_path),
            "known_limitations": list(evidence.get("known_limitations") or [
                "No professional qualification claim is made until both secure and vulnerable fixtures and repeated model-role evidence are linked."
            ]),
            "qualification_status": "experimental",
        }
        entry["qualification_status"] = _qualification_status(entry)
        techniques.append(entry)
    registry = {
        "schema_version": REGISTRY_SCHEMA_VERSION,
        "registry_id": REGISTRY_ID,
        "registry_version": REGISTRY_VERSION,
        "taxonomy_id": TAXONOMY_ID,
        "taxonomy_version": TAXONOMY_VERSION,
        "qualification_policy": {
            "experimental": "Implemented or mapped, but missing a complete secure/vulnerable validation pair.",
            "validated": "At least one target family supplies both secure and vulnerable evidence.",
            "qualified": "Precision and supported recall gates pass with secure and vulnerable evidence from at least two independent target families.",
            "deprecated": "Retained for historical runs but no longer recommended for new qualification.",
        },
        "techniques": techniques,
    }
    validate_qualification_registry(registry)
    return registry


def validate_qualification_registry(registry: dict[str, Any]) -> dict[str, Any]:
    if registry.get("schema_version") != REGISTRY_SCHEMA_VERSION:
        raise ValueError("unsupported technique qualification registry schema")
    rows = registry.get("techniques")
    if not isinstance(rows, list):
        raise ValueError("technique qualification registry must contain a techniques list")
    ids = [str(item.get("id") or "") for item in rows if isinstance(item, dict)]
    if len(ids) != len(set(ids)):
        raise ValueError("technique qualification registry contains duplicate technique IDs")
    missing = sorted(set(TECHNIQUE_INDEX) - set(ids))
    unknown = sorted(set(ids) - set(TECHNIQUE_INDEX))
    if missing or unknown:
        raise ValueError(
            "technique qualification registry taxonomy mismatch; "
            f"missing={','.join(missing) or 'none'}; unknown={','.join(unknown) or 'none'}"
        )
    for entry in rows:
        technique_id = str(entry["id"])
        status = str(entry.get("qualification_status") or "")
        path = str((entry.get("implementation") or {}).get("path") or "")
        if status not in QUALIFICATION_STATUSES:
            raise ValueError(f"{technique_id} has an invalid qualification status")
        if path not in IMPLEMENTATION_PATHS:
            raise ValueError(f"{technique_id} has an invalid implementation path")
        fixtures = entry.get("fixtures") or {}
        secure = fixtures.get("secure") or []
        vulnerable = fixtures.get("vulnerable") or []
        if status in {"validated", "qualified"} and (not secure or not vulnerable):
            raise ValueError(f"{technique_id} cannot be {status} without secure and vulnerable evidence")
        if status == "qualified":
            families = {
                str(item.get("target_family") or "")
                for item in secure + vulnerable
                if str(item.get("target_family") or "")
            }
            if len(families) < 2:
                raise ValueError(f"{technique_id} cannot be qualified without two independent target families")
            metrics = entry.get("metrics") or {}
            if float(metrics.get("precision") or 0.0) < 0.95 or float(metrics.get("supported_recall") or 0.0) < 0.95:
                raise ValueError(f"{technique_id} cannot be qualified without passing precision and recall gates")
    return registry


def public_qualification_registry() -> dict[str, Any]:
    return build_qualification_registry()


def render_automation_matrix(registry: dict[str, Any] | None = None) -> str:
    """Render public documentation from the same registry exposed by the API."""
    resolved = validate_qualification_registry(registry or build_qualification_registry())
    rows = list(resolved["techniques"])
    lines = [
        "# OWASP LLM 2025 automation and qualification matrix",
        "",
        "<!-- Generated by scripts/export_technique_registry.py; edit the taxonomy or qualification registry, not this file. -->",
        "",
        f"Registry `{resolved['registry_id']}` version `{resolved['registry_version']}` maps {len(rows)} techniques to OWASP LLM Top 10 `{resolved['taxonomy_version']}`.",
        "",
        "AdverScope distinguishes implementation from qualification. `native` and `contract` describe how a test can execute; `experimental`, `validated`, and `qualified` describe the retained evidence supporting reliability. Execution is never shown as a pass merely because a technique is implemented.",
        "",
        "## Risk-level overview",
        "",
        "| Risk | Native | Contract | Manual / unsupported | Validated or qualified |",
        "|---|---:|---:|---:|---:|",
    ]
    for risk_id, risk in RISK_INDEX.items():
        risk_rows = [item for item in rows if item["risk_id"] == risk_id]
        paths = [str(item["implementation"]["path"]) for item in risk_rows]
        promoted = len([item for item in risk_rows if item["qualification_status"] in {"validated", "qualified"}])
        lines.append(
            f"| {risk_id} {risk['title']} | {paths.count('native')} | {paths.count('contract')} | "
            f"{paths.count('manual') + paths.count('unsupported')} | {promoted}/{len(risk_rows)} |"
        )
    lines.extend([
        "",
        "## Technique registry",
        "",
        "| Technique | Risk | Execution path | Qualification | Target requirement | Model role |",
        "|---|---|---|---|---|---|",
    ])
    for item in rows:
        requirement = str(item["requirements"]["description"]).replace("|", "\\|").replace("\n", " ")
        generation = str(item["model_dependence"]["attack_generation"]).replace("|", "\\|")
        evaluation = str(item["model_dependence"]["evaluation"]).replace("|", "\\|")
        title = str(item["title"]).replace("|", "\\|")
        lines.append(
            f"| {item['id']} · {title} | {item['risk_id']} | {item['implementation']['path']} | "
            f"{item['qualification_status']} | {requirement} | Generation: {generation}; evaluation: {evaluation} |"
        )
    lines.extend([
        "",
        "## Evidence threshold",
        "",
        "A general-purpose LLM is not the final oracle for authorization, supply-chain integrity, poisoning, factual correctness, resource limits, or downstream effects. A reportable vulnerability requires the proof listed in the registry entry, complete immutable evidence, and reproduction unless an approved one-time-effect exception applies. HTTP success, generated prose, model confidence, inventory visibility, and implementation alone do not establish a vulnerability or a held control.",
        "",
        "## Status policy",
        "",
    ])
    for status, description in resolved["qualification_policy"].items():
        lines.append(f"- **{status}:** {description}")
    lines.extend([
        "",
        "## Operator boundary",
        "",
        "Contract techniques remain inert templates until a tester supplies and reviews the customer-owned routes, fields, identities, allowed effects, limits, and deterministic assertions in Attack Surface. Native conditional techniques likewise remain `needs configuration` or `not applicable` when their required target capability or validator is absent.",
        "",
    ])
    return "\n".join(lines)
