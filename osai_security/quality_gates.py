from __future__ import annotations

from typing import Any, Iterable


TERMINAL_RUN_STATUSES = {"completed", "completed_with_errors", "blocked", "cancelled", "interrupted"}


def _event_details_complete(event: dict[str, Any], *, request: bool) -> bool:
    details = event.get("details") or {}
    if request:
        return bool(details.get("curl_command")) and bool(details.get("method")) and bool(details.get("url"))
    return bool(details.get("raw_http_response") or details.get("raw_response_body") or details.get("raw_response")) and bool(
        details.get("status_code") or details.get("status_line")
    )


def _case_events(detail: dict[str, Any], test_case_id: str, *, attempt: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    case = next(
        (item for item in detail.get("test_cases") or [] if str(item.get("id") or "") == test_case_id),
        None,
    )
    trace_event_ids: set[str] = set()
    if attempt == "initial" and case:
        transport = (case.get("trace") or {}).get("transport") or {}
        trace_event_ids.update(
            str(value)
            for value in (transport.get("request_event_id"), transport.get("response_event_id"))
            if value
        )
    events = [
        event for event in detail.get("events") or []
        if str(event.get("test_case_id") or "") == test_case_id
        or str(event.get("id") or "") in trace_event_ids
    ]
    requests = [
        event for event in events
        if event.get("event_type") == "request.sent" and str((event.get("details") or {}).get("attempt") or "initial") == attempt
    ]
    responses = [
        event for event in events
        if event.get("event_type") == "response.received" and str((event.get("details") or {}).get("attempt") or "initial") == attempt
    ]
    return requests, responses


def audit_assessment_run(detail: dict[str, Any]) -> dict[str, Any]:
    """Audit one immutable assessment without making any target request."""
    events = detail.get("events") or []
    cases = detail.get("test_cases") or []
    case_by_id = {str(case.get("id")): case for case in cases}
    planned_ids = {
        str((event.get("details") or {}).get("execution_case_id"))
        for event in events
        if event.get("event_type") == "variant.planned" and (event.get("details") or {}).get("execution_case_id")
    }
    terminal_case_ids = {
        str((case.get("evaluation") or {}).get("execution_case_id"))
        for case in cases
        if (case.get("evaluation") or {}).get("execution_case_id") and case.get("status") in {"safe", "vulnerable", "inconclusive", "error"}
    }
    # Re-evaluation may replace a case's evaluator payload while the immutable
    # execution event still proves that the planned case reached a terminal
    # result.  Count that event so an evidence-only re-evaluation cannot make a
    # completed run look unfinished.
    terminal_case_ids.update(
        str((event.get("details") or {}).get("execution_case_id"))
        for event in events
        if event.get("event_type") == "evaluation.completed"
        and (event.get("details") or {}).get("execution_case_id")
    )
    terminal_case_ids.update(
        str((event.get("details") or {}).get("execution_case_id"))
        for event in events
        if event.get("event_type") in {"variant.skipped", "variant.blocked"}
        and (event.get("details") or {}).get("terminal") is True
        and (event.get("details") or {}).get("execution_case_id")
    )
    selected_contract_ids = {
        str(contract.get("id")) for contract in (detail.get("assessment_plan") or {}).get("assessment_contracts") or []
        if contract.get("id")
    }
    terminal_contract_ids = {
        str((event.get("details") or {}).get("contract_id"))
        for event in events
        if str(event.get("event_type") or "").startswith("contract.")
        and (event.get("details") or {}).get("terminal") is True
        and (event.get("details") or {}).get("contract_id")
    }
    missing_terminal = sorted((planned_ids - terminal_case_ids) | (selected_contract_ids - terminal_contract_ids))

    missing_finding_evidence: list[dict[str, str]] = []
    confirmed_reproductions = 0
    finding_count = 0
    current_run_id = str(detail.get("id") or "")
    for finding in detail.get("findings") or []:
        if finding.get("status") == "rejected":
            continue
        finding_count += 1
        current_validations = [
            item for item in finding.get("validations") or []
            if str(item.get("run_id") or current_run_id) == current_run_id
        ]
        confirmed = next(
            (
                item for item in reversed(current_validations)
                if item.get("status") == "confirmed"
            ),
            None,
        )
        current_occurrence_case_ids = [
            str(occurrence.get("test_case_id") or "")
            for occurrence in finding.get("occurrences") or []
            if str(occurrence.get("run_id") or "") == current_run_id
            and str(occurrence.get("test_case_id") or "") in case_by_id
        ]
        base_case_id = str(finding.get("test_case_id") or "")
        case_id = str((confirmed or {}).get("test_case_id") or "")
        if not case_id and current_occurrence_case_ids:
            case_id = current_occurrence_case_ids[0]
        if not case_id and str(finding.get("run_id") or current_run_id) == current_run_id and base_case_id in case_by_id:
            case_id = base_case_id
        case = case_by_id.get(case_id)
        reasons: list[str] = []
        if not case:
            reasons.append("linked test case is missing")
        else:
            initial_requests, initial_responses = _case_events(detail, case_id, attempt="initial")
            if not case.get("evidence"):
                reasons.append("initial evidence record is missing")
            if not any(_event_details_complete(event, request=True) for event in initial_requests):
                reasons.append("exact initial request or curl command is missing")
            if not any(_event_details_complete(event, request=False) for event in initial_responses):
                reasons.append("raw initial response is missing")
        if not confirmed:
            reasons.append("confirmed reproduction is missing")
        else:
            confirmed_reproductions += 1
            reproduction_requests, reproduction_responses = _case_events(detail, case_id, attempt="reproduction")
            if not confirmed.get("evidence_id"):
                reasons.append("reproduction evidence record is missing")
            if not any(_event_details_complete(event, request=True) for event in reproduction_requests):
                reasons.append("exact reproduction request or curl command is missing")
            if not any(_event_details_complete(event, request=False) for event in reproduction_responses):
                reasons.append("raw reproduction response is missing")
        if reasons:
            missing_finding_evidence.append({"finding_id": str(finding.get("id") or "unknown"), "reason": "; ".join(reasons)})

    secure_controls = 0
    secure_control_false_positives = 0
    for case in cases:
        evaluation = case.get("evaluation") or {}
        if evaluation.get("refusal_detected") and not evaluation.get("direct_evidence"):
            secure_controls += 1
            secure_control_false_positives += int(case.get("status") == "vulnerable" or bool(evaluation.get("vulnerable")))

    contract_audits = [audit_tool_run(run) for run in detail.get("contract_runs") or []]
    contract_findings = sum(item["finding_count"] for item in contract_audits)
    contract_reproductions = sum(item["confirmed_reproductions"] for item in contract_audits)
    for item in contract_audits:
        missing_finding_evidence.extend(item["missing_finding_evidence"])
    run_errors = sum(1 for case in cases if case.get("status") == "error")
    run_errors += sum(1 for item in contract_audits if item["status"] != "completed")
    if detail.get("status") not in TERMINAL_RUN_STATUSES:
        run_errors += 1
    planned_total = len(planned_ids) + len(selected_contract_ids)
    if not planned_total:
        planned_total = len(cases) + len(detail.get("contract_runs") or [])
    return {
        "execution_kind": "assessment",
        "execution_id": detail.get("id"),
        "project_id": detail.get("project_id"),
        "status": detail.get("status"),
        "planned": planned_total,
        "terminal": max(0, planned_total - len(missing_terminal)),
        "missing_terminal_ids": missing_terminal,
        "errors": run_errors,
        "finding_count": finding_count + contract_findings,
        "confirmed_reproductions": confirmed_reproductions + contract_reproductions,
        "missing_finding_evidence": missing_finding_evidence,
        "secure_controls": secure_controls,
        "secure_control_false_positives": secure_control_false_positives,
    }


def audit_tool_run(detail: dict[str, Any]) -> dict[str, Any]:
    events = detail.get("events") or []
    outcomes = {str(item.get("id")): item for item in (detail.get("context") or {}).get("security_outcomes") or []}
    definitions = {str(item.get("id")): item for item in (detail.get("definition") or {}).get("security_outcomes") or []}
    missing: list[dict[str, str]] = []
    findings = [finding for finding in detail.get("security_findings") or [] if finding.get("status") != "rejected"]
    reproduced = 0
    for finding in findings:
        outcome_id = str(finding.get("outcome_id") or "")
        definition = definitions.get(outcome_id) or {}
        outcome = outcomes.get(outcome_id) or {}
        reasons: list[str] = []
        grouped = bool(definition.get("required_any_step_groups"))
        required = list(
            (outcome.get("required_step_ids") or []) if grouped
            else definition.get("required_step_ids") or finding.get("required_step_ids") or []
        )
        reproduction = list(
            (outcome.get("reproduction_step_ids") or []) if grouped
            else definition.get("reproduction_step_ids") or []
        )
        if outcome.get("status") != "confirmed":
            reasons.append("deterministic outcome is not confirmed")
        if not reproduction:
            reasons.append("reproduction step set is missing")
        for step_id in required:
            step_events = [event for event in events if str(event.get("step_id") or "") == str(step_id)]
            if not any(_event_details_complete(event, request=True) for event in step_events if event.get("event_type") == "request.sent"):
                reasons.append(f"{step_id}: exact request is missing")
            if not any(_event_details_complete(event, request=False) for event in step_events if event.get("event_type") == "response.received"):
                reasons.append(f"{step_id}: raw response is missing")
            if not any(event.get("event_type") == "assertion.passed" for event in step_events):
                reasons.append(f"{step_id}: passing assertion is missing")
        if reproduction and all((outcome.get("step_results") or {}).get(step_id) is True for step_id in reproduction):
            reproduced += 1
        if reasons:
            missing.append({"finding_id": str(finding.get("id") or outcome_id or "unknown"), "reason": "; ".join(dict.fromkeys(reasons))})
    return {
        "execution_kind": "tool",
        "execution_id": detail.get("id"),
        "project_id": detail.get("project_id"),
        "status": detail.get("status"),
        "planned": 1,
        "terminal": int(detail.get("status") in TERMINAL_RUN_STATUSES),
        "missing_terminal_ids": [] if detail.get("status") in TERMINAL_RUN_STATUSES else [str(detail.get("contract_id") or detail.get("id") or "tool-run")],
        "errors": int(detail.get("status") != "completed") + sum(1 for event in events if event.get("event_type") == "error"),
        "finding_count": len(findings),
        "confirmed_reproductions": reproduced,
        "missing_finding_evidence": missing,
        "secure_controls": 0,
        "secure_control_false_positives": 0,
    }


def evaluate_quality_gates(
    audits: Iterable[dict[str, Any]],
    *,
    true_positives: int,
    false_negatives: int,
    isolation_violations: int = 0,
    minimum_secure_controls: int = 10,
) -> dict[str, Any]:
    rows = list(audits)
    planned = sum(int(item.get("planned") or 0) for item in rows)
    terminal = sum(int(item.get("terminal") or 0) for item in rows)
    errors = sum(int(item.get("errors") or 0) for item in rows)
    findings = sum(int(item.get("finding_count") or 0) for item in rows)
    reproduced = sum(int(item.get("confirmed_reproductions") or 0) for item in rows)
    missing_evidence = [problem for item in rows for problem in item.get("missing_finding_evidence") or []]
    controls = sum(int(item.get("secure_controls") or 0) for item in rows)
    control_fp = sum(int(item.get("secure_control_false_positives") or 0) for item in rows)
    error_free_rate = 1.0 - (errors / planned) if planned else 0.0
    terminal_rate = terminal / planned if planned else 0.0
    evidence_rate = (findings - len(missing_evidence)) / findings if findings else 1.0
    reproduction_rate = reproduced / findings if findings else 1.0
    control_rate = (controls - control_fp) / controls if controls else 0.0
    recall = true_positives / (true_positives + false_negatives) if true_positives + false_negatives else 0.0
    gates = [
        {"id": "error-free-execution", "threshold": 0.98, "value": round(error_free_rate, 4), "passed": error_free_rate >= 0.98},
        {"id": "planned-terminal-status", "threshold": 1.0, "value": round(terminal_rate, 4), "passed": terminal_rate == 1.0},
        {"id": "finding-evidence-completeness", "threshold": 1.0, "value": round(evidence_rate, 4), "passed": evidence_rate == 1.0},
        {"id": "secure-control-precision", "threshold": 0.95, "value": round(control_rate, 4), "sample_size": controls, "minimum_sample_size": minimum_secure_controls, "passed": controls >= minimum_secure_controls and control_rate >= 0.95},
        {"id": "confirmed-finding-reproducibility", "threshold": 0.95, "value": round(reproduction_rate, 4), "passed": reproduction_rate >= 0.95},
        {"id": "supported-outcome-recall", "threshold": 0.95, "value": round(recall, 4), "passed": recall >= 0.95},
        {"id": "project-session-isolation", "threshold": 0, "value": int(isolation_violations), "passed": int(isolation_violations) == 0},
    ]
    return {
        "passed": all(item["passed"] for item in gates),
        "gates": gates,
        "counts": {
            "executions": len(rows),
            "planned": planned,
            "terminal": terminal,
            "errors": errors,
            "findings": findings,
            "confirmed_reproductions": reproduced,
            "secure_controls": controls,
            "secure_control_false_positives": control_fp,
            "true_positives": int(true_positives),
            "false_negatives": int(false_negatives),
            "isolation_violations": int(isolation_violations),
        },
        "missing_terminal_ids": [value for item in rows for value in item.get("missing_terminal_ids") or []],
        "missing_finding_evidence": missing_evidence,
    }
