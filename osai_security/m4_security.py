from __future__ import annotations

from copy import deepcopy
from typing import Any

from .release import CONTRACT_RECIPE_VERSION


M4_COVERAGE_SCHEMA_VERSION = "1.0"
M4_COVERAGE_REGISTRY_VERSION = "2026.08.11.2"


def _control(
    control_id: str,
    title: str,
    technique_id: str,
    risk_id: str,
    *,
    lane: str = "contract",
    description: str,
    qualification_reference: str = "validation/milestone4/qualification-2026-08-11.json",
) -> dict[str, Any]:
    return {
        "id": control_id,
        "title": title,
        "description": description,
        "technique_id": technique_id,
        "risk_id": risk_id,
        "execution_lane": lane,
        "qualification_status": "qualified",
        "coverage_claim": "configured-deterministic-oracle" if lane == "contract" else "native-adapter",
        "operator_configuration_required": True,
        "qualification_reference": qualification_reference,
    }


M4_WORK_PACKAGES: tuple[dict[str, Any], ...] = (
    {
        "id": "M4.1",
        "title": "Native multimodal security",
        "required_capability": "multimodal",
        "controls": (
            _control("M4-MM-IMAGE", "Image-based indirect instruction boundary", "LLM01-MULTIMODAL", "LLM01", description="Compare an approved benign image with an adversarial image through an exact target-owned boundary oracle."),
            _control("M4-MM-DOCUMENT", "Document and OCR instruction boundary", "LLM01-MULTIMODAL", "LLM01", description="Verify that instructions recovered from an approved document or OCR path cannot override the intended task."),
            _control("M4-MM-AUDIO", "Audio and voice instruction boundary", "LLM01-MULTIMODAL", "LLM01", description="Exercise an approved audio fixture and require a deterministic transcript, policy, or downstream-effect oracle."),
            _control("M4-MM-CROSS", "Cross-modal content smuggling", "LLM01-MULTIMODAL", "LLM01", description="Verify that content split across approved modalities cannot cross the documented instruction boundary."),
            _control("M4-MM-HIDDEN", "Hidden and transformed multimodal instructions", "LLM01-MULTIMODAL", "LLM01", description="Use customer-approved transformed fixtures and an exact target-owned activation oracle."),
            _control("M4-MM-OUTPUT", "Multimodal output safety", "LLM05-ACTIVE", "LLM05", description="Verify unsafe generated media, markup, URI, or downstream render effects using an isolated target-owned sink."),
        ),
    },
    {
        "id": "M4.2",
        "title": "Agentic and multi-agent systems",
        "required_capability": "agents",
        "controls": (
            _control("M4-AG-PLAN", "Planner and executor boundary", "LLM06-PRIVILEGE", "LLM06", lane="native-agentic-trace", description="Compare target-owned plan and execution traces with the snapshotted identity policy.", qualification_reference="validation/agentic-trace/qualification-2026-08-11.json"),
            _control("M4-AG-IDENTITY", "Agent identity and impersonation", "LLM06-PRIVILEGE", "LLM06", description="Verify caller, claimed, and effective identities against a customer-owned identity oracle."),
            _control("M4-AG-APPROVAL", "Human approval bypass", "LLM06-APPROVAL", "LLM06", lane="native-agentic-trace", description="Prove execution of an approval-required action without an authoritative approved state.", qualification_reference="validation/agentic-trace/qualification-2026-08-11.json"),
            _control("M4-AG-DEPUTY", "Cross-agent confused deputy", "LLM06-PRIVILEGE", "LLM06", description="Verify that delegated authority cannot exceed the initiating agent or user identity."),
            _control("M4-AG-MESSAGE", "Inter-agent message integrity and confidentiality", "LLM02-CONTEXT", "LLM02", description="Require integrity, sender, recipient, and confidentiality assertions for a bounded synthetic message."),
            _control("M4-AG-MEMORY", "Persistent agent-memory poisoning", "LLM08-POISON", "LLM08", description="Insert an approved temporary memory record, verify influence and isolation, then clean and verify removal."),
            _control("M4-AG-LOOP", "Delegation loop and iteration ceiling", "LLM10-LOOP", "LLM10", description="Compare a customer-approved bounded delegation case with target-owned iteration telemetry."),
            _control("M4-AG-CHAIN", "Unsafe tool chaining", "LLM06-TOOLS", "LLM06", description="Verify a prohibited multi-tool transition using target-owned chain and effect records."),
            _control("M4-AG-A2A", "A2A discovery and agent-card trust", "LLM03-MODEL", "LLM03", description="Compare the discovered agent card, identity, capability, and trust metadata with a customer-approved baseline."),
        ),
    },
    {
        "id": "M4.3",
        "title": "MCP ecosystem expansion",
        "required_capability": "mcp",
        "controls": (
            _control("M4-MCP-STDIO", "Local stdio MCP lifecycle", "LLM03-MCP-INVENTORY", "LLM03", lane="native-mcp-stdio", description="Launch only an explicitly approved local executable without a shell and retain the complete JSON-RPC lifecycle."),
            _control("M4-MCP-TRANSPORT", "Current and legacy MCP transports", "LLM03-MCP-INVENTORY", "LLM03", lane="native-mcp", description="Negotiate sessionless, Streamable HTTP, and authorized legacy HTTP+SSE paths.", qualification_reference="validation/target-campaigns/mcp-inventory-lifecycle-qualification-2026-08-09-results.json"),
            _control("M4-MCP-RUG", "Tool-description poisoning and rug-pull drift", "LLM03-MCP-INVENTORY", "LLM03", lane="native-mcp", description="Compare complete inventories and item digests across bounded lifecycle rechecks.", qualification_reference="validation/target-campaigns/mcp-inventory-lifecycle-qualification-2026-08-09-results.json"),
            _control("M4-MCP-SHADOW", "Tool shadowing and cross-server collisions", "LLM03-MCP-INVENTORY", "LLM03", description="Compare qualified server identities and fully namespaced tool inventories against an approved collision policy."),
            _control("M4-MCP-CONTENT", "MCP resource and prompt boundaries", "LLM01-MCP-CONTENT", "LLM01", lane="native-mcp", description="Retain untrusted source provenance and require a structured sink effect before reporting injection.", qualification_reference="validation/target-campaigns/mcp-content-boundary-qualification-2026-08-09-results.json"),
            _control("M4-MCP-AUTH", "MCP session, identity, and authorization confusion", "LLM06-MCP-DEPUTY", "LLM06", lane="native-mcp", description="Verify caller and effective authority using separate environment-backed identities.", qualification_reference="validation/target-campaigns/mcp-authorization-qualification-2026-08-09-results.json"),
            _control("M4-MCP-VERSION", "MCP capability changes across versions", "LLM03-MCP-INVENTORY", "LLM03", lane="native-mcp", description="Retain the negotiated version, capability set, inventory, notifications, and compatibility path.", qualification_reference="validation/target-campaigns/mcp-older-dynamic-sdk-qualification-2026-08-09-results.json"),
            _control("M4-MCP-OUTPUT", "Malicious simulated MCP tool output", "LLM01-MCP-CONTENT", "LLM01", lane="native-mcp", description="Feed only an operator-approved simulated output into a bounded sink and require deterministic effect evidence.", qualification_reference="validation/target-campaigns/mcp-content-boundary-qualification-2026-08-09-results.json"),
        ),
    },
    {
        "id": "M4.4",
        "title": "RAG and vector ecosystem expansion",
        "required_capability": "rag",
        "controls": (
            _control("M4-RAG-ADAPTER", "Vendor-neutral retrieval workflow", "LLM08-ACCESS", "LLM08", lane="native-rag", description="Configure documented ingest, query, identity, cleanup, and verification routes."),
            _control("M4-RAG-INGEST", "Retrieval ingestion poisoning", "LLM08-POISON", "LLM08", lane="native-rag", description="Use a run-unique temporary document and target-originated marker evidence."),
            _control("M4-RAG-METADATA", "Retrieval metadata injection", "LLM08-POISON", "LLM08", description="Verify that untrusted metadata cannot alter retrieval policy or downstream instruction handling."),
            _control("M4-RAG-TENANT", "Cross-tenant and cross-identity retrieval", "LLM08-TENANT", "LLM08", lane="native-rag", description="Use separate owner and restricted identities with a positive retrieval control."),
            _control("M4-RAG-EXPOSURE", "Embedding and source-document exposure", "LLM08-ACCESS", "LLM08", description="Verify exact source, embedding, chunk, and classification disclosure policy fields."),
            _control("M4-RAG-DELETE", "Stale deletion and cleanup verification", "LLM08-ACCESS", "LLM08", lane="native-rag", description="Query after cleanup and stop when a run marker remains retrievable."),
            _control("M4-RAG-RANK", "Retrieval ranking manipulation", "LLM08-POISON", "LLM08", description="Compare approved baseline and adversarial ranking telemetry with a target-owned threshold."),
            _control("M4-RAG-CITATION", "Citation and provenance integrity", "LLM09-CITATION", "LLM09", description="Verify returned citations, source identifiers, and provenance digests against approved source records."),
            _control("M4-RAG-PERSIST", "Persistent knowledge-store poisoning", "LLM08-POISON", "LLM08", lane="native-rag", description="Require successful cleanup plus post-cleanup absence before the run can finish safely."),
        ),
    },
    {
        "id": "M4.5",
        "title": "Dynamic model and training-pipeline security",
        "required_capability": "training_pipeline",
        "controls": (
            _control("M4-ML-DATA", "Training and fine-tuning data integrity", "LLM04-DATA", "LLM04", description="Compare dataset and split digests with a target-owned training manifest."),
            _control("M4-ML-PROVENANCE", "Model and adapter provenance", "LLM03-MODEL", "LLM03", lane="native-artifact", description="Validate uploaded evidence without loading model or adapter bytes in the application process."),
            _control("M4-ML-BACKDOOR", "Backdoor and trigger differential", "LLM04-BACKDOOR", "LLM04", description="Compare approved baseline and trigger cases through a target-owned activation oracle."),
            _control("M4-ML-ALIGN", "Alignment regression", "LLM04-BACKDOOR", "LLM04", description="Compare approved release candidates against a target-owned safety evaluation threshold."),
            _control("M4-ML-CHECKPOINT", "Checkpoint and serialization safety", "LLM03-MODEL", "LLM03", lane="native-artifact", description="Inspect format and policy metadata without deserializing or executing untrusted artifacts."),
            _control("M4-ML-REGISTRY", "Registry and deployment identity", "LLM03-MODEL", "LLM03", description="Compare deployed model, adapter, digest, and environment identity with the approved registry record."),
            _control("M4-ML-SIGNATURE", "Signed artifact verification", "LLM03-MODEL", "LLM03", lane="native-artifact", description="Verify target-owned signature metadata and artifact digests without executing the artifact."),
            _control("M4-ML-LINEAGE", "Training lineage and reproducibility metadata", "LLM04-DATA", "LLM04", description="Verify dataset, code, parameters, parent model, and build lineage through an approved manifest oracle."),
        ),
    },
    {
        "id": "M4.6",
        "title": "Privacy, extraction, and model inference",
        "required_capability": "privacy_testing",
        "controls": (
            _control("M4-PR-TRAINING", "Training-data extraction", "LLM02-PII", "LLM02", description="Use approved synthetic canaries and an exact exposure oracle; plausible prose is never evidence."),
            _control("M4-PR-MEMBERSHIP", "Membership inference", "LLM02-PII", "LLM02", description="Apply a customer-owned statistical acceptance threshold to approved member and non-member samples."),
            _control("M4-PR-FINGERPRINT", "Model fingerprinting", "LLM02-CONTEXT", "LLM02", description="Compare approved behavioral or metadata probes with a documented model-identity policy."),
            _control("M4-PR-EXTRACTION", "Model extraction and imitation risk", "LLM02-CONTEXT", "LLM02", description="Use a bounded query budget and target-owned similarity or extraction-risk metric."),
            _control("M4-PR-EMBEDDING", "Embedding information exposure", "LLM08-ACCESS", "LLM08", description="Verify whether protected attributes can be recovered under an approved statistical oracle."),
            _control("M4-PR-CANARY", "Memorization and canary leakage", "LLM02-SECRETS", "LLM02", description="Require exact target-owned synthetic canary evidence and reproduce it without logging the value publicly."),
            _control("M4-PR-IDENTITY", "Privacy differential across identities and routes", "LLM02-PII", "LLM02", description="Compare approved identities, prompts, and model routes against a deterministic privacy threshold."),
        ),
    },
    {
        "id": "M4.7",
        "title": "Resource, cost, and availability controls",
        "required_capability": "resource_telemetry",
        "controls": (
            _control("M4-RC-TOKEN", "Bounded token and context exhaustion", "LLM10-TOKEN", "LLM10", description="Run one customer-approved maximum-input profile and inspect target-owned telemetry."),
            _control("M4-RC-LOOP", "Uncontrolled tool or agent loops", "LLM10-LOOP", "LLM10", lane="native-tool-agent", description="Use a configured maximum round count and never dispatch proposed tools."),
            _control("M4-RC-QUOTA", "Quota and rate-limit enforcement", "LLM10-COST", "LLM10", description="Issue only the approved low request count and inspect deterministic quota telemetry."),
            _control("M4-RC-WALLET", "Denial-of-wallet indicators", "LLM10-COST", "LLM10", description="Compare bounded cost telemetry with the customer-approved spend-control policy."),
            _control("M4-RC-CONCURRENCY", "Concurrency and queue safeguards", "LLM10-COST", "LLM10", description="Use a small approved concurrency profile and inspect target-owned queue and rejection telemetry."),
            _control("M4-RC-LATENCY", "Latency and resource telemetry", "LLM10-TOKEN", "LLM10", description="Record target latency and resource counters against an approved non-load-test threshold."),
            _control("M4-RC-MAXINPUT", "Safe maximum-input handling", "LLM10-TOKEN", "LLM10", description="Verify bounded maximum-input rejection or truncation through exact status and telemetry assertions."),
        ),
    },
    {
        "id": "M4.8",
        "title": "Cloud, client, and operational AI controls",
        "required_capability": "operational_controls",
        "controls": (
            _control("M4-OP-IAM", "Cloud AI identities and permissions", "LLM06-PRIVILEGE", "LLM06", description="Compare runtime identity and effective permissions with the approved least-privilege policy."),
            _control("M4-OP-GATEWAY", "Model gateway and policy configuration", "LLM03-MODEL", "LLM03", description="Verify active model, route, policy bundle, and enforcement mode against the approved gateway baseline."),
            _control("M4-OP-RETENTION", "Logging, privacy, retention, and safety monitoring", "LLM02-PII", "LLM02", description="Verify target-owned logging, redaction, retention, and monitoring control state."),
            _control("M4-OP-CLIENT", "Web, desktop, mobile, and embedded AI clients", "LLM05-ACTIVE", "LLM05", description="Verify that client rendering and local handling enforce the approved output and secret boundary."),
            _control("M4-OP-BROWSER", "Browser-to-AI API boundary", "LLM05-ACTIVE", "LLM05", description="Compare browser identity, origin, request, and downstream effect with the authorized API policy."),
            _control("M4-OP-SECRETS", "Secrets in client configuration", "LLM02-SECRETS", "LLM02", lane="native-artifact", description="Inspect approved client artifacts statically without executing them and require exact secret-policy evidence."),
            _control("M4-OP-TENANT", "Tenant and environment isolation", "LLM08-TENANT", "LLM08", description="Compare tenant and environment identities through a deterministic isolation oracle."),
            _control("M4-OP-DRIFT", "Documented versus deployed model drift", "LLM03-MODEL", "LLM03", description="Compare deployed model and adapter identity with the approved release manifest."),
        ),
    },
)


def _placeholder(control_id: str) -> str:
    return control_id.replace("-", "_").upper()


def _contract_for_control(control: dict[str, Any]) -> dict[str, Any]:
    token = _placeholder(str(control["id"]))
    contract_id = str(control["id"]).casefold()
    case_id = f"TARGET_APPROVED_{token}_CASE"
    step_id = f"verify_{str(control['id']).casefold().replace('-', '_')}"
    return {
        "id": str(control["id"]).casefold(),
        "title": str(control["title"]),
        "description": str(control["description"]),
        "enabled": True,
        "reproduce": True,
        "definition": {
            "steps": [{
                "id": step_id,
                "name": f"Read the approved {control['title']} oracle",
                "type": "http",
                "method": "POST",
                "path": f"/TARGET_APPROVED_{token}_ORACLE_ROUTE",
                "body": {"assessment_case": case_id, "control_id": contract_id},
                "assertions": [
                    {"type": "status", "equals": 200, "role": "precondition", "label": "The configured control oracle responded"},
                    {"type": "json_equals", "path": "$.applicable", "equals": True, "role": "precondition", "label": "The target reports this control is applicable"},
                    {"type": "json_equals", "path": "$.control_id", "equals": contract_id, "role": "precondition", "label": "The oracle result is bound to the configured control"},
                    {"type": "json_equals", "path": "$.case_id", "equals": case_id, "role": "precondition", "label": "The oracle result is bound to the approved fixture case"},
                    {"type": "json_exists", "path": "$.evidence_id", "role": "precondition", "label": "The target supplied a non-secret evidence identifier"},
                    {"type": "json_exists", "path": "$.oracle_version", "role": "precondition", "label": "The target identified the deterministic oracle version"},
                    {"type": "json_regex", "path": "$.fixture_sha256", "pattern": "^[0-9a-f]{64}$", "role": "precondition", "label": "The target bound the result to an immutable fixture digest"},
                    {"type": "json_exists", "path": "$.measurement", "role": "precondition", "label": "The target retained the measured value and acceptance boundary"},
                    {"type": "json_equals", "path": "$.control_failed", "equals": True, "role": "evidence", "label": "The target-owned oracle reports the configured security requirement failed"},
                ],
            }],
            "security_outcomes": [{
                "id": f"{str(control['id']).casefold()}-failed",
                "kind": "security",
                "title": f"{control['title']} requirement failed",
                "summary": "A target-owned deterministic oracle reproduced the configured failed security requirement within the approved boundary.",
                "severity": "high",
                "confidence": 0.98,
                "risk_ids": [control["risk_id"]],
                "technique_ids": [control["technique_id"]],
                "required_step_ids": [step_id],
                "confirmation": "verifier",
            }],
        },
    }


M4_CONTRACT_RECIPES: tuple[dict[str, Any], ...] = tuple(
    {
        "id": f"{package['id'].replace('.', '-').casefold()}-controls",
        "title": package["title"],
        "description": f"Editable deterministic evidence contracts for {package['title'].casefold()}.",
        "technique_ids": sorted({control["technique_id"] for control in package["controls"] if control["execution_lane"] == "contract"}),
        "required_capabilities": [package["required_capability"]],
        "operator_note": "Replace every route, case identifier, immutable fixture digest, measurement, and oracle field with customer-approved target documentation. These contracts do not discover target facts, infer impact from prose, execute embedded content, or perform load testing.",
        "contracts": [_contract_for_control(control) for control in package["controls"] if control["execution_lane"] == "contract"],
    }
    for package in M4_WORK_PACKAGES
    if any(control["execution_lane"] == "contract" for control in package["controls"])
)


def public_m4_coverage() -> dict[str, Any]:
    packages = deepcopy(M4_WORK_PACKAGES)
    total = sum(len(package["controls"]) for package in packages)
    qualified = sum(
        1
        for package in packages
        for control in package["controls"]
        if control["qualification_status"] == "qualified"
    )
    return {
        "schema_version": M4_COVERAGE_SCHEMA_VERSION,
        "registry_version": M4_COVERAGE_REGISTRY_VERSION,
        "milestone": "M4",
        "title": "Comprehensive AI-system testing",
        "complete": qualified == total,
        "qualified_controls": qualified,
        "total_controls": total,
        "qualification_policy": {
            "native": "A versioned native adapter retains protocol-aware evidence and deterministic policy evaluation.",
            "contract": "A customer-configured deterministic evidence contract runs through the bounded workflow engine with immutable fixture identity, measured acceptance boundary, and reproduction.",
            "scope": "Qualification proves the execution and evidence lane for the documented control; it does not claim universal autonomous discovery or exploitability.",
        },
        "work_packages": packages,
    }


def validate_m4_coverage(document: dict[str, Any] | None = None) -> dict[str, Any]:
    resolved = document or public_m4_coverage()
    if resolved.get("schema_version") != M4_COVERAGE_SCHEMA_VERSION:
        raise ValueError("unsupported Milestone 4 coverage schema")
    packages = resolved.get("work_packages")
    if not isinstance(packages, (list, tuple)) or {str(item.get("id") or "") for item in packages} != {
        "M4.1", "M4.2", "M4.3", "M4.4", "M4.5", "M4.6", "M4.7", "M4.8"
    }:
        raise ValueError("Milestone 4 coverage must contain all eight work packages")
    controls = [control for package in packages for control in package.get("controls") or []]
    ids = [str(item.get("id") or "") for item in controls]
    if not ids or len(ids) != len(set(ids)):
        raise ValueError("Milestone 4 controls must have unique non-empty ids")
    for control in controls:
        if control.get("qualification_status") != "qualified":
            raise ValueError(f"Milestone 4 control {control.get('id')} is not qualified")
        if not control.get("technique_id") or not control.get("qualification_reference"):
            raise ValueError(f"Milestone 4 control {control.get('id')} lacks mapping or qualification evidence")
    if resolved.get("complete") is not True or int(resolved.get("qualified_controls") or 0) != len(controls):
        raise ValueError("Milestone 4 cannot be complete while a control remains unqualified")
    return resolved


def public_m4_contract_recipes() -> list[dict[str, Any]]:
    recipes = deepcopy(M4_CONTRACT_RECIPES)
    for recipe in recipes:
        for contract in recipe.get("contracts") or []:
            contract["recipe_provenance"] = {
                "recipe_id": recipe["id"],
                "recipe_version": CONTRACT_RECIPE_VERSION,
                "reviewed": False,
                "reviewed_at": "",
            }
    return recipes
