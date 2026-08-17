from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from typing import Any

from . import build_identity
from .release import TELEMETRY_SCHEMA_VERSION
ADJUDICATION_CLASSIFICATIONS = {
    "true_positive",
    "false_positive",
    "false_negative",
    "true_negative",
    "inconclusive",
    "infrastructure_error",
    "not_applicable",
}
ADJUDICATION_OUTCOMES = {"vulnerable", "secure", "error", "not_tested", "inconclusive", "unknown"}
ROOT_CAUSES = {
    "none",
    "planner_coverage",
    "payload_generation",
    "target_adapter",
    "transport",
    "response_parser",
    "evaluator",
    "finding_pipeline",
    "reproduction",
    "infrastructure",
    "target_control_held",
    "legacy_uninstrumented",
    "unclassified",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _canonical_hash(value: Any) -> str:
    serialized = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def build_run_manifest(
    *,
    project_id: str,
    target: dict[str, Any],
    module_ids: list[str],
    model_mode: str,
    model_config: Any,
    model_profiles: dict[str, Any] | None = None,
    assessment_plan: dict[str, Any],
    attack_profile: str,
    attack_budget: int,
    project_context: str,
) -> dict[str, Any]:
    """Create a secret-minimizing immutable snapshot of an assessment execution."""
    reasoning = dict(assessment_plan.get("reasoning_snapshot") or {})
    request_template = target.get("request_template") or {}
    target_snapshot = {
        "id": target.get("id"),
        "name": target.get("name"),
        "kind": target.get("kind"),
        "base_url": target.get("base_url"),
        "path": target.get("path"),
        "method": target.get("method"),
        "response_path": target.get("response_path"),
        "header_names": sorted(str(key) for key in (target.get("headers") or {})),
        "request_template_sha256": _canonical_hash(request_template),
        "capabilities": target.get("capabilities") or {},
        "analysis_config": target.get("analysis_config") or {},
        "conversation_config": target.get("conversation_config") or {},
        "transport_config": target.get("transport_config") or {},
        "evaluation_config": target.get("evaluation_config") or {},
        "technique_adapters": target.get("technique_adapters") or {},
        "authorized_routes": target.get("authorized_routes") or [],
        "guided_discovery": target.get("guided_discovery") or {},
    }
    model_name = str(getattr(model_config, "llm_model", "offline-deterministic")) if model_mode in {"asus", "asus-evaluator"} else "offline-deterministic"
    model_provider = str(getattr(model_config, "llm_provider", "local")) if model_mode in {"asus", "asus-evaluator"} else "offline"
    profile_document = model_profiles or {}
    profiles_by_id = {str(item.get("id")): item for item in profile_document.get("providers") or [] if isinstance(item, dict)}
    configured_roles = dict(profile_document.get("role_profiles") or {})

    def configured_model_role(role: str, *, activity: str, temperature: float) -> dict[str, Any]:
        profile_id = str(configured_roles.get(role) or "")
        profile = profiles_by_id.get(profile_id) or {}
        return {
            "name": str(profile.get("model") or model_name),
            "provider_profile": profile_id or model_provider,
            "provider_kind": str(profile.get("kind") or model_provider),
            "temperature": temperature,
            "role": activity,
            "professional_qualification": str((profile.get("qualification") or {}).get("professional_qualification") or "not-established"),
        }

    if model_mode == "asus":
        model_roles = {
            "planner": configured_model_role("planner", activity="guided-planning", temperature=0.1),
            "generator": configured_model_role("generator", activity="payload-generation", temperature=0.35),
            "adaptive_generator": configured_model_role("generator", activity="response-informed-generation", temperature=0.25),
            "evaluator": configured_model_role("evaluator", activity="security-evaluation", temperature=0.0),
        }
        if configured_roles.get("adjudicator"):
            model_roles["adjudicator"] = configured_model_role("adjudicator", activity="optional-adjudication", temperature=0.0)
    elif model_mode == "asus-evaluator":
        model_roles = {
            "generator": {"name": "adverscope-reviewed-attacks", "temperature": 0.0, "role": "reviewed-catalog"},
            "adaptive_generator": {"name": "disabled", "temperature": 0.0, "role": "disabled"},
            "evaluator": configured_model_role("evaluator", activity="security-evaluation", temperature=0.0),
        }
    else:
        model_roles = {
            "generator": {"name": "adverscope-reviewed-attacks", "temperature": 0.0, "role": "reviewed-catalog"},
            "adaptive_generator": {"name": "disabled", "temperature": 0.0, "role": "disabled"},
            "evaluator": {"name": "offline-deterministic", "temperature": 0.0, "role": "deterministic-evaluation"},
        }
    manifest: dict[str, Any] = {
        "schema_version": TELEMETRY_SCHEMA_VERSION,
        "created_at": _utc_now(),
        "framework": build_identity(),
        "project": {
            "id": project_id,
            "context_sha256": hashlib.sha256(project_context.encode("utf-8")).hexdigest(),
        },
        "target": target_snapshot,
        "execution": {
            "run_mode": assessment_plan.get("run_mode") or "advanced",
            "model_mode": model_mode,
            "modules": list(module_ids),
            "attack_profile": attack_profile,
            "attack_budget_per_module": int(attack_budget),
            "taxonomy_version": assessment_plan.get("taxonomy_version", ""),
            "selected_risk_ids": assessment_plan.get("selected_risk_ids") or [],
            "selected_technique_ids": assessment_plan.get("selected_technique_ids") or [],
            "executable_technique_ids": assessment_plan.get("executable_technique_ids") or [],
            "objectives": assessment_plan.get("objectives") or [],
            "guardrail": assessment_plan.get("guardrail") or {},
            "confirmation_policy": assessment_plan.get("confirmation_policy") or {},
            "adaptive_turns": int(assessment_plan.get("adaptive_turns") or 1),
            "recon": assessment_plan.get("recon") or {},
            "guided": {
                "enabled": bool((assessment_plan.get("guided") or {}).get("enabled")),
                "schema_version": (assessment_plan.get("guided") or {}).get("schema_version", ""),
                "planner_rationale": (assessment_plan.get("guided") or {}).get("planner_rationale", ""),
                "model_selected_technique_ids": (assessment_plan.get("guided") or {}).get("model_selected_technique_ids") or [],
                "mandatory_baseline_technique_ids": (assessment_plan.get("guided") or {}).get("mandatory_baseline_technique_ids") or [],
                "requires_advanced_configuration": (assessment_plan.get("guided") or {}).get("requires_advanced_configuration") or [],
            },
            "attack_catalog": assessment_plan.get("attack_catalog") or {},
            "assessment_reasoning": {
                "schema_version": reasoning.get("schema_version", ""),
                "snapshot_sha256": reasoning.get("snapshot_sha256", ""),
                "advisory_only": bool(reasoning.get("advisory_only", True)),
                "methodology_cards": [
                    {
                        "id": item.get("id") or item.get("card_id"),
                        "version": item.get("version", ""),
                        "library_version": item.get("library_version", ""),
                        "sha256": item.get("sha256", ""),
                    }
                    for item in reasoning.get("methodology_cards") or []
                ],
                "record_counts": dict(reasoning.get("summary") or {}),
            },
            "artifact_inventory": [
                {
                    "id": item.get("id"),
                    "target_id": item.get("target_id"),
                    "filename": item.get("filename"),
                    "kind": item.get("kind"),
                    "size_bytes": item.get("size_bytes"),
                    "sha256": item.get("sha256"),
                    "policy_case_id": item.get("policy_case_id"),
                }
                for item in assessment_plan.get("artifact_inventory") or []
            ],
        },
        "models": model_roles,
        "model_provider": {
            "id": configured_roles.get("generator") or model_provider,
            "model": (profiles_by_id.get(str(configured_roles.get("generator") or "")) or {}).get("model") or model_name,
            "role_profiles": configured_roles,
            "provider_schema_version": profile_document.get("schema_version", ""),
        },
    }
    manifest["manifest_sha256"] = _canonical_hash(manifest)
    return manifest


def build_tool_run_manifest(
    *,
    project_id: str,
    target: dict[str, Any],
    kind: str,
    name: str,
    definition: dict[str, Any],
    input_values: dict[str, Any],
    definition_id: str | None,
    assessment_run_id: str | None,
    contract_id: str,
) -> dict[str, Any]:
    """Snapshot tool execution provenance without copying request inputs or secrets."""
    manifest: dict[str, Any] = {
        "schema_version": TELEMETRY_SCHEMA_VERSION,
        "created_at": _utc_now(),
        "framework": build_identity(),
        "project": {"id": project_id},
        "target": {
            "id": target.get("id"),
            "name": target.get("name"),
            "kind": target.get("kind"),
            "base_url": target.get("base_url"),
            "path": target.get("path"),
            "method": target.get("method"),
        },
        "execution": {
            "kind": kind,
            "name": name,
            "definition_id": definition_id or "",
            "definition_version": definition.get("version") or "",
            "definition_sha256": _canonical_hash(definition),
            "input_sha256": _canonical_hash(input_values),
            "linked_assessment_run_id": assessment_run_id or "",
            "contract_id": contract_id,
        },
    }
    manifest["manifest_sha256"] = _canonical_hash(manifest)
    return manifest


def build_case_trace(
    *,
    module_id: str,
    strategy: str,
    variant_id: str,
    catalog_version: str,
    generation_source: str,
    generation_trace_event_id: str,
    expected_signal: str,
    request_event_id: str,
    response_event_id: str,
    result: dict[str, Any] | None,
    response: str,
    evaluation: dict[str, Any],
    status: str,
    target: dict[str, Any],
) -> dict[str, Any]:
    request = (result or {}).get("request") or {}
    schema_error = str((result or {}).get("schema_error") or "")
    return {
        "schema_version": TELEMETRY_SCHEMA_VERSION,
        "planning": {
            "module_id": module_id,
            "risk_ids": evaluation.get("owasp_risk_ids") or [],
            "technique_ids": evaluation.get("owasp_technique_ids") or [],
            "strategy": strategy,
            "variant_id": variant_id,
            "catalog_version": catalog_version,
        },
        "generation": {
            "source": generation_source,
            "trace_event_id": generation_trace_event_id,
            "expected_signal": expected_signal,
        },
        "transport": {
            "request_prepared": True,
            "request_sent": bool(request_event_id),
            "request_event_id": request_event_id,
            "response_received": bool(response_event_id),
            "response_event_id": response_event_id,
            "runner": request.get("runner", ""),
            "status_code": (result or {}).get("status_code", ""),
            "schema_error": schema_error,
            "raw_response_sha256": (result or {}).get("raw_response_sha256", ""),
        },
        "extraction": {
            "response_path": target.get("response_path", ""),
            "completed": bool(response_event_id) and not schema_error,
            "extracted_length": len(response),
            "response_sha256": hashlib.sha256(response.encode("utf-8")).hexdigest() if response else "",
        },
        "evaluation": {
            "completed": status != "error" and str(evaluation.get("evaluator") or "") != "error",
            "evaluator": evaluation.get("evaluator", ""),
            "vulnerable": bool(evaluation.get("vulnerable")),
            "confidence": float(evaluation.get("confidence") or 0.0),
            "model_trace_event_id": "",
        },
        "finding": {"created": False, "finding_id": ""},
        "reproduction": {"attempted": False, "status": "not_attempted", "evidence_id": ""},
        "terminal_status": status,
    }


def diagnose_case(
    case: dict[str, Any],
    findings: list[dict[str, Any]],
    *,
    run_id: str = "",
) -> dict[str, Any]:
    trace = case.get("trace") or {}
    if not trace:
        return {
            "stage": "legacy",
            "root_cause": "legacy_uninstrumented",
            "explanation": "This case predates stage-level telemetry, so its pipeline cannot be diagnosed reliably.",
        }
    transport = trace.get("transport") or {}
    extraction = trace.get("extraction") or {}
    evaluation = case.get("evaluation") or {}
    linked = next(
        (
            finding
            for finding in findings
            if finding.get("test_case_id") == case.get("id")
            or any(item.get("test_case_id") == case.get("id") for item in finding.get("occurrences") or [])
        ),
        None,
    )
    stage = "complete"
    root_cause = "none"
    explanation = "The attempt completed its configured pipeline."
    if transport.get("kind") == "local-static-analysis":
        if case.get("status") == "error" or str(evaluation.get("evaluator") or "") == "error":
            stage, root_cause, explanation = "evaluation", "evaluator", "Local static artifact inspection did not produce a usable verdict."
        else:
            stage, root_cause, explanation = "complete", "none", "The immutable artifact completed local static analysis without contacting the target."
    elif not transport.get("request_sent"):
        stage, root_cause, explanation = "transport", "target_adapter", "The request was prepared but was not sent to the configured target."
    elif not transport.get("response_received"):
        stage, root_cause, explanation = "transport", "transport", "The request was sent but no target response was retained."
    elif (
        str(transport.get("status_code") or "").isdigit()
        and int(str(transport.get("status_code"))) >= 400
        and (transport.get("schema_error") or case.get("status") == "error")
    ):
        status_code = int(str(transport.get("status_code")))
        if status_code in {401, 403}:
            explanation = "The target rejected the configured authentication or authorization before a usable application response was available."
        else:
            explanation = f"The target returned HTTP {status_code} outside the configured success response contract."
        stage, root_cause = "transport", "target_adapter"
    elif transport.get("schema_error") or not extraction.get("completed"):
        stage, root_cause, explanation = "extraction", "response_parser", "A target response was retained, but the configured response extraction did not complete."
    elif str(evaluation.get("evaluator") or "") == "error" or case.get("status") == "error":
        stage, root_cause, explanation = "evaluation", "evaluator", "Traffic completed, but the security evaluator did not produce a usable verdict."
    elif evaluation.get("vulnerable") and not linked:
        stage, root_cause, explanation = "finding", "finding_pipeline", "The evaluator classified vulnerable behavior, but no finding occurrence is linked."
    elif linked:
        validations = [
            item
            for item in linked.get("validations") or []
            if (
                (not run_id or str(item.get("run_id") or "") == run_id)
                and (not item.get("test_case_id") or item.get("test_case_id") == case.get("id"))
            )
        ]
        if validations and validations[-1].get("status") != "confirmed":
            stage, root_cause, explanation = "reproduction", "reproduction", "The initial finding was not confirmed by its bounded reproduction attempt."
    return {"stage": stage, "root_cause": root_cause, "explanation": explanation}


def analyze_assessment_run(detail: dict[str, Any]) -> dict[str, Any]:
    cases = detail.get("test_cases") or []
    findings = detail.get("findings") or []
    protocol_events = detail.get("protocol_events") or []
    run_id = str(detail.get("id") or "")
    case_ids = {str(case.get("id") or "") for case in cases}
    adjudications = [
        item
        for item in detail.get("adjudications") or []
        if not str(item.get("expectation_id") or "").startswith("finding:")
    ]
    diagnostics = {case["id"]: diagnose_case(case, findings, run_id=run_id) for case in cases}
    stage_keys = ("planned", "generated", "local_analysis", "request_sent", "response_received", "extracted", "evaluated", "finding_created", "reproduction_confirmed")
    pipeline = {key: 0 for key in stage_keys}
    evidence_complete = 0
    local_static_case_count = 0
    for case in cases:
        trace = case.get("trace") or {}
        transport = trace.get("transport") or {}
        extraction = trace.get("extraction") or {}
        evaluation = trace.get("evaluation") or {}
        local_static = transport.get("kind") == "local-static-analysis"
        local_static_case_count += int(local_static)
        pipeline["planned"] += int(bool(trace.get("planning")))
        pipeline["generated"] += int(bool(trace.get("generation")))
        pipeline["local_analysis"] += int(local_static and bool(extraction.get("completed")) and bool(extraction.get("report_sha256")))
        pipeline["request_sent"] += int(bool(transport.get("request_sent")))
        pipeline["response_received"] += int(bool(transport.get("response_received")))
        pipeline["extracted"] += int(bool(extraction.get("completed")))
        pipeline["evaluated"] += int(bool(evaluation.get("completed")))
        pipeline["finding_created"] += int(bool((trace.get("finding") or {}).get("created")))
        pipeline["reproduction_confirmed"] += int((trace.get("reproduction") or {}).get("status") == "confirmed")
        if local_static:
            evidence_complete += int(
                bool(case.get("evidence"))
                and bool(extraction.get("artifact_sha256"))
                and bool(extraction.get("report_sha256"))
                and bool(evaluation.get("completed"))
                and transport.get("target_traffic_sent") is False
            )
        else:
            evidence_complete += int(bool(case.get("evidence")) and bool(transport.get("request_sent")) and bool(transport.get("response_received")) and bool(evaluation.get("completed")))
    classifications = {name: 0 for name in sorted(ADJUDICATION_CLASSIFICATIONS)}
    root_causes: dict[str, int] = {}
    for item in adjudications:
        classification = str(item.get("classification") or "inconclusive")
        classifications[classification] = classifications.get(classification, 0) + 1
        cause = str(item.get("root_cause") or "unclassified")
        if cause != "none":
            root_causes[cause] = root_causes.get(cause, 0) + 1
    for diagnostic in diagnostics.values():
        cause = diagnostic["root_cause"]
        if cause != "none":
            root_causes[cause] = root_causes.get(cause, 0) + 1
    true_positive = classifications.get("true_positive", 0)
    false_positive = classifications.get("false_positive", 0)
    false_negative = classifications.get("false_negative", 0)
    precision_denominator = true_positive + false_positive
    recall_denominator = true_positive + false_negative
    validations = [
        validation
        for finding in findings
        for validation in finding.get("validations") or []
        if (
            (str(validation.get("run_id") or "") == run_id)
            or (
                not validation.get("run_id")
                and str(validation.get("test_case_id") or "") in case_ids
            )
        )
    ]
    attempted_reproductions = len(validations)
    confirmed_reproductions = sum(1 for item in validations if item.get("status") == "confirmed")
    run_findings = [
        finding
        for finding in findings
        if finding.get("status") != "rejected"
        and (
            str(finding.get("run_id") or "") == run_id
            or any(str(item.get("run_id") or "") == run_id for item in finding.get("occurrences") or [])
        )
    ]
    confirmed_findings = sum(
        1
        for finding in run_findings
        if any(
            str(item.get("run_id") or "") == run_id and item.get("status") == "confirmed"
            for item in finding.get("validations") or []
        )
    )
    total = len(cases)
    execution_source_counts: dict[str, int] = {}
    assurance_counts: dict[str, int] = {}
    for case in cases:
        evaluation = case.get("evaluation") or {}
        generation_source = str(case.get("generation_source") or "legacy")
        execution_source = str(evaluation.get("execution_source") or ("model-generated" if generation_source.startswith("asus") else "native-reviewed"))
        assurance = str((evaluation.get("evidence_assurance") or {}).get("level") or "legacy-unknown")
        execution_source_counts[execution_source] = execution_source_counts.get(execution_source, 0) + 1
        assurance_counts[assurance] = assurance_counts.get(assurance, 0) + 1
    protocol_event_counts: dict[str, int] = {}
    protocol_counts: dict[str, int] = {}
    for event in protocol_events:
        event_type = str(event.get("event_type") or "unknown")
        protocol = str(event.get("protocol") or "unknown")
        protocol_event_counts[event_type] = protocol_event_counts.get(event_type, 0) + 1
        protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
    protocol_case_ids = {
        str(event.get("test_case_id") or "")
        for event in protocol_events
        if event.get("test_case_id")
    }
    protocol_expected_case_ids = {
        str(case.get("id") or "")
        for case in cases
        if (
            ((case.get("evaluation") or {}).get("tool_agent_execution") or {}).get("protocol")
            or ((case.get("evaluation") or {}).get("mcp_execution") or {}).get("protocol")
            or ((case.get("evaluation") or {}).get("rag_execution") or {}).get("protocol")
            or ((case.get("evaluation") or {}).get("stored_web_execution") or {}).get("protocol")
        )
    }
    complete_protocol_case_ids: set[str] = set()
    for case in cases:
        case_id = str(case.get("id") or "")
        if case_id not in protocol_expected_case_ids:
            continue
        event_types = {
            str(event.get("event_type") or "")
            for event in protocol_events
            if str(event.get("test_case_id") or "") == case_id
        }
        evaluation = case.get("evaluation") or {}
        if (evaluation.get("mcp_execution") or {}).get("protocol"):
            if {"jsonrpc.request", "policy.input.ready"}.issubset(event_types) and event_types.intersection({"jsonrpc.response", "jsonrpc.error"}):
                complete_protocol_case_ids.add(case_id)
        elif (evaluation.get("rag_execution") or {}).get("protocol"):
            rag_execution = evaluation.get("rag_execution") or {}
            required = {"workflow.started", "rag.ingest.request", "rag.ingest.response", "rag.query.request", "rag.query.response", "rag.cleanup.response", "policy.input.ready", "policy.decision"}
            if rag_execution.get("control_query_performed"):
                required.update({"rag.control_query.request", "rag.control_query.response"})
            if rag_execution.get("cleanup_verification_attempted"):
                required.update({"rag.cleanup_verify.request", "rag.cleanup_verify.response"})
            if required.issubset(event_types):
                complete_protocol_case_ids.add(case_id)
        elif (evaluation.get("stored_web_execution") or {}).get("protocol"):
            required = {"carrier.prepared", "request.sent", "response.received", "policy.decision"}
            case_events = [event for event in protocol_events if str(event.get("test_case_id") or "") == case_id]
            if required.issubset(event_types) and sum(1 for event in case_events if event.get("event_type") == "request.sent") >= 2 and sum(1 for event in case_events if event.get("event_type") == "response.received") >= 2:
                complete_protocol_case_ids.add(case_id)
        elif {"completion.request", "assistant.message", "policy.decision"}.issubset(event_types):
            complete_protocol_case_ids.add(case_id)
    return {
        "schema_version": TELEMETRY_SCHEMA_VERSION,
        "execution_kind": "assessment",
        "case_count": total,
        "status_counts": {status: sum(1 for case in cases if case.get("status") == status) for status in ("safe", "vulnerable", "inconclusive", "error")},
        "execution_source_counts": execution_source_counts,
        "evidence_assurance_counts": assurance_counts,
        "protocol_event_count": len(protocol_events),
        "protocol_counts": dict(sorted(protocol_counts.items())),
        "protocol_event_type_counts": dict(sorted(protocol_event_counts.items())),
        "protocol_correlation_count": len({str(event.get("correlation_id") or "") for event in protocol_events if event.get("correlation_id")}),
        "protocol_trace_completeness_rate": round(len(complete_protocol_case_ids) / len(protocol_expected_case_ids), 4) if protocol_expected_case_ids else None,
        "protocol_unlinked_event_count": sum(1 for event in protocol_events if not event.get("test_case_id")),
        "protocol_linked_case_count": len(protocol_case_ids),
        "local_static_case_count": local_static_case_count,
        "target_transport_case_count": total - local_static_case_count,
        "pipeline": pipeline,
        "evidence_completeness_rate": round(evidence_complete / total, 4) if total else None,
        "execution_error_rate": round(sum(1 for case in cases if case.get("status") == "error") / total, 4) if total else None,
        "reproduction_rate": round(confirmed_reproductions / attempted_reproductions, 4) if attempted_reproductions else None,
        "confirmed_finding_reproducibility_rate": round(confirmed_findings / len(run_findings), 4) if run_findings else None,
        "adjudication_counts": classifications,
        "precision": round(true_positive / precision_denominator, 4) if precision_denominator else None,
        "recall": round(true_positive / recall_denominator, 4) if recall_denominator else None,
        "root_causes": dict(sorted(root_causes.items())),
        "diagnostics": diagnostics,
    }


def analyze_tool_run(detail: dict[str, Any]) -> dict[str, Any]:
    events = detail.get("events") or []
    adjudications = detail.get("adjudications") or []
    event_types = [str(item.get("event_type") or "") for item in events]
    assertions_passed = sum(1 for item in event_types if item in {"assertion.passed", "assertion_passed"})
    assertions_failed = sum(1 for item in event_types if item in {"assertion.failed", "assertion_failed"})
    classifications = {name: 0 for name in sorted(ADJUDICATION_CLASSIFICATIONS)}
    root_causes: dict[str, int] = {}
    for item in adjudications:
        classification = str(item.get("classification") or "inconclusive")
        classifications[classification] = classifications.get(classification, 0) + 1
        cause = str(item.get("root_cause") or "unclassified")
        if cause != "none":
            root_causes[cause] = root_causes.get(cause, 0) + 1
    return {
        "schema_version": TELEMETRY_SCHEMA_VERSION,
        "execution_kind": "tool",
        "event_count": len(events),
        "pipeline": {
            "request_sent": event_types.count("request.sent"),
            "response_received": event_types.count("response.received"),
            "assertions_passed": assertions_passed,
            "assertions_failed": assertions_failed,
            "errors": event_types.count("error"),
        },
        "adjudication_counts": classifications,
        "root_causes": dict(sorted(root_causes.items())),
    }


def aggregate_project_analysis(
    assessment_runs: list[dict[str, Any]],
    tool_runs: list[dict[str, Any]],
    adjudications: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    classifications = {name: 0 for name in sorted(ADJUDICATION_CLASSIFICATIONS)}
    root_causes: dict[str, int] = {}
    errors = 0
    cases = 0
    for run in [*assessment_runs, *tool_runs]:
        metrics = run.get("metrics") or {}
        cases += int(metrics.get("case_count") or 0)
        errors += int((metrics.get("status_counts") or {}).get("error") or (metrics.get("pipeline") or {}).get("errors") or 0)
        if adjudications is None:
            for key, value in (metrics.get("adjudication_counts") or {}).items():
                classifications[key] = classifications.get(key, 0) + int(value or 0)
            for key, value in (metrics.get("root_causes") or {}).items():
                root_causes[key] = root_causes.get(key, 0) + int(value or 0)
    if adjudications is not None:
        # Oracle expectations describe the current project-level benchmark verdict.
        # When later evidence changes the selected execution, keep only the latest
        # verdict for that expectation. Human and automated decisions remain
        # execution-specific records.
        current: dict[tuple[str, ...], dict[str, Any]] = {}
        for item in sorted(adjudications, key=lambda row: (str(row.get("updated_at") or ""), str(row.get("id") or ""))):
            if str(item.get("expectation_id") or "").startswith("finding:"):
                # Historical chatbot root-disposition records are preserved for
                # auditability, but accepting a grouped root finding is not an
                # independent oracle decision for every linked occurrence.
                continue
            if item.get("source") == "oracle":
                key = ("oracle", str(item.get("expectation_id") or ""))
            else:
                key = (str(item.get("source") or ""), str(item.get("id") or ""))
            current[key] = item
        for item in current.values():
            classification = str(item.get("classification") or "inconclusive")
            classifications[classification] = classifications.get(classification, 0) + 1
            cause = str(item.get("root_cause") or "unclassified")
            if cause != "none":
                root_causes[cause] = root_causes.get(cause, 0) + 1
    tp, fp, fn = classifications.get("true_positive", 0), classifications.get("false_positive", 0), classifications.get("false_negative", 0)
    return {
        "schema_version": TELEMETRY_SCHEMA_VERSION,
        "assessment_runs": len(assessment_runs),
        "tool_runs": len(tool_runs),
        "test_cases": cases,
        "errors": errors,
        "adjudication_counts": classifications,
        "precision": round(tp / (tp + fp), 4) if tp + fp else None,
        "recall": round(tp / (tp + fn), 4) if tp + fn else None,
        "root_causes": dict(sorted(root_causes.items(), key=lambda item: (-item[1], item[0]))),
    }


def telemetry_export(detail: dict[str, Any], *, execution_kind: str) -> dict[str, Any]:
    base = {
        "schema_version": TELEMETRY_SCHEMA_VERSION,
        "exported_at": _utc_now(),
        "exporter": build_identity(),
        "execution_kind": execution_kind,
        "execution_id": detail.get("id"),
        "project_id": detail.get("project_id"),
        "status": detail.get("status"),
        "manifest": detail.get("manifest") or {},
        "metrics": detail.get("metrics") or {},
        "adjudications": detail.get("adjudications") or [],
        "events": detail.get("events") or [],
    }
    if execution_kind == "assessment":
        base["test_cases"] = detail.get("test_cases") or []
        base["findings"] = detail.get("findings") or []
        base["owasp_coverage"] = detail.get("owasp_coverage") or {}
    else:
        base["definition"] = detail.get("definition") or {}
        base["input"] = detail.get("input") or {}
        base["context"] = detail.get("context") or {}
    base["export_sha256"] = _canonical_hash(base)
    return base
