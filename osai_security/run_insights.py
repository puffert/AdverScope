from __future__ import annotations

import hashlib
import json
from typing import Any


RUN_INSIGHT_SCHEMA_VERSION = "1.0"
RUN_COMPARISON_SCHEMA_VERSION = "1.0"


def _stable_digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()


def _case_techniques(test_case: dict[str, Any]) -> set[str]:
    return {str(item) for item in (test_case.get("evaluation") or {}).get("owasp_technique_ids") or [] if str(item)}


def _case_execution_source(test_case: dict[str, Any]) -> str:
    evaluation = test_case.get("evaluation") or {}
    source = str(evaluation.get("execution_source") or test_case.get("generation_source") or "legacy/unknown")
    return source


def _is_model_generated(test_case: dict[str, Any]) -> bool:
    source = _case_execution_source(test_case).casefold()
    generation = str(test_case.get("generation_source") or "").casefold()
    return source.startswith("model-") or source.startswith("asus") or generation.startswith("asus")


def _run_scoped_native_findings(run: dict[str, Any]) -> list[dict[str, Any]]:
    scoped: list[dict[str, Any]] = []
    for finding in run.get("findings") or []:
        occurrences = [item for item in finding.get("occurrences") or [] if item.get("run_id") == run.get("id")]
        validations = [item for item in finding.get("validations") or [] if item.get("run_id") == run.get("id")]
        if occurrences or finding.get("run_id") == run.get("id"):
            scoped.append({**finding, "occurrences": occurrences, "validations": validations})
    return scoped


def _run_scoped_contract_findings(run: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for contract_run in run.get("contract_runs") or []:
        for finding in contract_run.get("security_findings") or []:
            records.append({**finding, "contract_run_id": contract_run.get("id"), "contract_id": contract_run.get("contract_id")})
    return records


def _finding_key(finding: dict[str, Any], *, contract: bool = False) -> str:
    if finding.get("fingerprint"):
        return str(finding["fingerprint"])
    mappings = sorted(str(item) for item in (finding.get("technique_ids") or finding.get("risk_ids") or []) if str(item))
    seed = {
        "kind": "contract" if contract else "assessment",
        "module": finding.get("module_id") or finding.get("contract_id") or "",
        "title": str(finding.get("title") or "").strip().casefold(),
        "mappings": mappings,
    }
    return _stable_digest(seed)


def _finding_techniques(finding: dict[str, Any]) -> set[str]:
    result = {str(item) for item in finding.get("technique_ids") or [] if str(item)}
    for occurrence in finding.get("occurrences") or []:
        result.update(str(item) for item in (occurrence.get("evaluation") or {}).get("owasp_technique_ids") or [] if str(item))
    return result


def _event_reason(event: dict[str, Any]) -> dict[str, Any]:
    details = event.get("details") or {}
    return {
        "event_id": event.get("id"),
        "event_type": event.get("event_type"),
        "title": event.get("title") or event.get("event_type") or "Recorded execution decision",
        "reason": details.get("reason") or details.get("message") or details.get("blocked_reason") or "See the exact retained event for details.",
        "technique_ids": sorted({
            str(item)
            for key in ("planned_technique_ids", "technique_ids", "owasp_technique_ids")
            for item in details.get(key) or []
            if str(item)
        }),
        "test_case_id": event.get("test_case_id"),
        "created_at": event.get("created_at"),
    }


def build_run_result_summary(run: dict[str, Any]) -> dict[str, Any]:
    plan = run.get("assessment_plan") or {}
    cases = run.get("test_cases") or []
    native_findings = _run_scoped_native_findings(run)
    contract_findings = _run_scoped_contract_findings(run)
    selected = {str(item) for item in plan.get("selected_technique_ids") or [] if str(item)}
    planned = {str(item) for item in plan.get("executable_technique_ids") or [] if str(item)}
    unsupported = {str(item) for item in plan.get("unsupported_technique_ids") or [] if str(item)}
    contract_planned = {
        str(item)
        for contract in plan.get("assessment_contracts") or []
        if contract.get("enabled")
        for item in contract.get("technique_ids") or []
        if str(item)
    }
    selected.update(contract_planned)
    planned.update(contract_planned)
    executed: set[str] = set()
    for test_case in cases:
        executed.update(_case_techniques(test_case))
    for contract_run in run.get("contract_runs") or []:
        for outcome in (contract_run.get("context") or {}).get("security_outcomes") or []:
            executed.update(str(item) for item in outcome.get("technique_ids") or [] if str(item))

    reproduced: set[str] = set()
    for finding in native_findings:
        if any(item.get("status") == "confirmed" for item in finding.get("validations") or []):
            reproduced.update(_finding_techniques(finding))
    for finding in contract_findings:
        if str(finding.get("confirmation") or "").casefold() in {"reproduced", "confirmed", "deterministic-contract"}:
            reproduced.update(_finding_techniques(finding))

    skipped_events = [
        _event_reason(event)
        for event in run.get("events") or []
        if str(event.get("event_type") or "") in {"variant.skipped", "generation.budget_trimmed", "generation.novel_skipped", "generation.objective_skipped", "reproduction.skipped", "recon.skipped"}
    ]
    stopped_events = [
        _event_reason(event)
        for event in run.get("events") or []
        if str(event.get("event_type") or "") in {"variant.blocked", "contract.blocked", "safety.stop", "assessment.blocked", "assessment.cancelled", "assessment.interrupted"}
    ]
    not_tested = planned - executed
    unsupported_records = [
        {"technique_id": item, "reason": "The selected target did not provide the capability or target-owned configuration required by this technique."}
        for item in sorted(unsupported)
    ]
    not_tested_records = [
        {
            "technique_id": item,
            "reason": "The technique was executable in the immutable plan but no retained attempt reached evaluation. Review skip, stop, budget, and error events.",
        }
        for item in sorted(not_tested)
    ]

    relationships = []
    for technique_id in sorted(selected | planned | executed | unsupported):
        related_cases = [item for item in cases if technique_id in _case_techniques(item)]
        related_findings = [item for item in native_findings if technique_id in _finding_techniques(item)] + [item for item in contract_findings if technique_id in _finding_techniques(item)]
        reproduction_ids = [
            validation.get("id")
            for finding in native_findings
            if technique_id in _finding_techniques(finding)
            for validation in finding.get("validations") or []
            if validation.get("status") == "confirmed"
        ]
        relationships.append({
            "technique_id": technique_id,
            "selected": technique_id in selected,
            "planned": technique_id in planned,
            "executed": technique_id in executed,
            "unsupported": technique_id in unsupported,
            "test_case_ids": [item.get("id") for item in related_cases],
            "finding_ids": [item.get("id") for item in related_findings],
            "reproduction_ids": [item for item in reproduction_ids if item],
        })

    model_cases = [item for item in cases if _is_model_generated(item)]
    reviewed_cases = [item for item in cases if not _is_model_generated(item)]
    findings = native_findings + contract_findings
    terminal_incomplete = str(run.get("status") or "") in {"blocked", "cancelled", "interrupted", "completed_with_errors"}
    complete_subset = not terminal_incomplete and not not_tested and not unsupported
    if findings:
        conclusion = f"{len(findings)} finding(s) are linked to this run. Review direct evidence and reproduction before reporting."
    elif complete_subset:
        conclusion = "No vulnerability was demonstrated by the selected and executed subset. This is not a claim about unselected risks or techniques."
    else:
        conclusion = "No reportable finding is linked to the completed evidence subset. Coverage gaps, unsupported techniques, and stopped work prevent a pass conclusion."
    return {
        "schema_version": RUN_INSIGHT_SCHEMA_VERSION,
        "run_id": run.get("id"),
        "status": run.get("status"),
        "counts": {
            "selected_techniques": len(selected),
            "planned_techniques": len(planned),
            "reviewed_executed_cases": len(reviewed_cases),
            "model_generated_executed_cases": len(model_cases),
            "reproduced_techniques": len(reproduced),
            "skipped_decisions": len(skipped_events),
            "stopped_decisions": len(stopped_events),
            "unsupported_techniques": len(unsupported),
            "not_tested_techniques": len(not_tested),
        },
        "technique_ids": {
            "selected": sorted(selected),
            "planned": sorted(planned),
            "executed": sorted(executed),
            "reproduced": sorted(reproduced),
            "unsupported": sorted(unsupported),
            "not_tested": sorted(not_tested),
        },
        "skipped": skipped_events,
        "stopped": stopped_events,
        "unsupported": unsupported_records,
        "not_tested": not_tested_records,
        "relationships": relationships,
        "finding_ids": [item.get("id") for item in findings if item.get("id")],
        "conclusion": conclusion,
        "limitations": [
            "A held control applies only to a mapped technique that actually executed with conclusive evidence.",
            "Selected, planned, executed, reproduced, unsupported, and not-tested are different states and must not be collapsed into pass/fail.",
        ],
    }


def _configuration_snapshot(run: dict[str, Any]) -> dict[str, Any]:
    plan = run.get("assessment_plan") or {}
    reasoning = plan.get("reasoning_snapshot") or {}
    target = run.get("target") or {}
    adapter = plan.get("target_adapter_snapshot") or {}
    return {
        "target": {
            "id": run.get("target_id") or target.get("id"),
            "name": adapter.get("name") or target.get("name"),
            "kind": adapter.get("kind") or target.get("kind"),
            "base_url": adapter.get("base_url") or target.get("base_url"),
            "path": adapter.get("path") or target.get("path"),
            "method": adapter.get("method") or target.get("method"),
            "snapshot_source": "immutable-plan" if adapter.get("base_url") else "current-target-fallback",
        },
        "adapter": adapter,
        "guardrail": plan.get("guardrail") or {},
        "catalog": plan.get("attack_catalog") or {},
        "assessment_reasoning": {
            "schema_version": reasoning.get("schema_version", ""),
            "snapshot_sha256": reasoning.get("snapshot_sha256", ""),
            "summary": reasoning.get("summary") or {},
            "methodology_cards": [
                {
                    "id": item.get("id") or item.get("card_id"),
                    "version": item.get("version", ""),
                    "sha256": item.get("sha256", ""),
                }
                for item in reasoning.get("methodology_cards") or []
            ],
        },
        "taxonomy_version": plan.get("taxonomy_version"),
        "model": {
            "mode": run.get("model_mode"),
            "planner": (plan.get("guided") or {}).get("planner") or {},
            "manifest_model": (run.get("manifest") or {}).get("model") or {},
        },
        "plan": {
            "module_ids": run.get("module_ids") or [],
            "selected_risk_ids": plan.get("selected_risk_ids") or [],
            "selected_technique_ids": plan.get("selected_technique_ids") or [],
            "executable_technique_ids": plan.get("executable_technique_ids") or [],
            "unsupported_technique_ids": plan.get("unsupported_technique_ids") or [],
            "objectives": plan.get("objectives") or [],
            "attack_profile": run.get("attack_profile"),
            "attack_budget": run.get("attack_budget"),
            "confirmation_policy": plan.get("confirmation_policy") or {},
            "recon": plan.get("recon") or {},
        },
    }


def _section_change(name: str, before: Any, after: Any) -> dict[str, Any]:
    before_digest, after_digest = _stable_digest(before), _stable_digest(after)
    return {
        "section": name,
        "changed": before_digest != after_digest,
        "baseline_sha256": before_digest,
        "current_sha256": after_digest,
        "baseline": before,
        "current": after,
    }


def _finding_records(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    for finding in _run_scoped_native_findings(run):
        key = _finding_key(finding)
        records[key] = {**finding, "comparison_key": key, "kind": "assessment", "technique_ids": sorted(_finding_techniques(finding))}
    for finding in _run_scoped_contract_findings(run):
        key = _finding_key(finding, contract=True)
        records[key] = {**finding, "comparison_key": key, "kind": "contract", "technique_ids": sorted(_finding_techniques(finding))}
    return records


def compare_runs(baseline: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    if baseline.get("project_id") != current.get("project_id"):
        raise ValueError("run comparison requires two runs from the same project")
    if baseline.get("id") == current.get("id"):
        raise ValueError("run comparison requires two different runs")
    before_config, after_config = _configuration_snapshot(baseline), _configuration_snapshot(current)
    changes = [
        _section_change("target", before_config["target"], after_config["target"]),
        _section_change("adapter and capabilities", before_config["adapter"], after_config["adapter"]),
        _section_change("guardrail", before_config["guardrail"], after_config["guardrail"]),
        _section_change("catalog and taxonomy", {"catalog": before_config["catalog"], "taxonomy_version": before_config["taxonomy_version"]}, {"catalog": after_config["catalog"], "taxonomy_version": after_config["taxonomy_version"]}),
        _section_change("model", before_config["model"], after_config["model"]),
        _section_change("assessment reasoning", before_config["assessment_reasoning"], after_config["assessment_reasoning"]),
        _section_change("test plan", before_config["plan"], after_config["plan"]),
    ]
    before_findings, after_findings = _finding_records(baseline), _finding_records(current)
    current_summary = build_run_result_summary(current)
    current_executed = set(current_summary["technique_ids"]["executed"])
    current_planned = set(current_summary["technique_ids"]["planned"])
    current_incomplete = str(current.get("status") or "") in {"blocked", "cancelled", "interrupted", "completed_with_errors", "running"}
    outcomes: list[dict[str, Any]] = []
    for key in sorted(set(before_findings) | set(after_findings)):
        before, after = before_findings.get(key), after_findings.get(key)
        if before and after:
            status, reason = "persistent", "Run-scoped evidence matching this finding is present in both runs."
        elif after:
            status, reason = "new", "This finding has run-scoped evidence in the current run only."
        else:
            techniques = set((before or {}).get("technique_ids") or [])
            retested = bool(techniques.intersection(current_executed or current_planned))
            if not retested:
                status, reason = "not-retested", "The current immutable plan did not execute a technique linked to this baseline finding."
            elif current_incomplete:
                status, reason = "inconclusive", "The relevant area was selected, but the current run did not finish cleanly enough to support remediation."
            elif str((before or {}).get("status") or "") == "fixed":
                status, reason = "fixed", "The relevant area was retested without matching evidence and the reviewer marked the root finding fixed."
            else:
                status, reason = "non-reproduced", "The relevant area was retested without matching run-scoped evidence; human review is required before calling it fixed."
        record = after or before or {}
        outcomes.append({
            "comparison_key": key,
            "status": status,
            "title": record.get("title") or "Untitled finding",
            "severity": record.get("severity") or "unknown",
            "technique_ids": record.get("technique_ids") or [],
            "baseline_finding_id": before.get("id") if before else None,
            "current_finding_id": after.get("id") if after else None,
            "reason": reason,
        })
    counts: dict[str, int] = {}
    for outcome in outcomes:
        counts[outcome["status"]] = counts.get(outcome["status"], 0) + 1
    changed_sections = [item["section"] for item in changes if item["changed"]]
    equivalent_plan = not any(item["changed"] for item in changes)
    return {
        "schema_version": RUN_COMPARISON_SCHEMA_VERSION,
        "project_id": baseline.get("project_id"),
        "baseline_run_id": baseline.get("id"),
        "current_run_id": current.get("id"),
        "baseline_status": baseline.get("status"),
        "current_status": current.get("status"),
        "configuration_equivalent": equivalent_plan,
        "changed_sections": changed_sections,
        "configuration_changes": changes,
        "security_outcomes": outcomes,
        "outcome_counts": counts,
        "baseline_summary": build_run_result_summary(baseline),
        "current_summary": current_summary,
        "conclusion": (
            "The target, configuration, catalog, model, and test plan are equivalent; security-outcome differences can be interpreted as a direct retest subject to evidence review."
            if equivalent_plan
            else "The runs differ in " + ", ".join(changed_sections) + ". Treat security-outcome differences as conditional until the changed test conditions are reviewed."
        ),
        "limitations": [
            "Fixed requires relevant retest coverage plus an explicit reviewer disposition; absence of a repeated finding alone is non-reproduced, not fixed.",
            "Only run-scoped occurrences and reproductions are compared. Aggregate root-finding evidence from other runs is excluded.",
        ],
    }
