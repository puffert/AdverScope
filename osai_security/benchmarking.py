from __future__ import annotations

from collections import Counter
from typing import Any, Callable


BENCHMARK_SCHEMA_VERSION = 1
EXPECTED_OUTCOMES = {"vulnerable", "secure"}
OBSERVATION_KINDS = {"objective", "assessment_finding", "tool_finding", "case"}
CLASSIFICATIONS = {
    "true_positive",
    "true_negative",
    "false_positive",
    "false_negative",
    "inconclusive",
    "infrastructure_error",
    "not_applicable",
}


class BenchmarkConfigurationError(ValueError):
    pass


def validate_benchmark_definition(campaign: dict[str, Any], oracle: dict[str, Any]) -> list[str]:
    """Validate strict oracle/campaign separation without examining target evidence."""
    errors: list[str] = []
    if int(campaign.get("schema_version") or 0) != BENCHMARK_SCHEMA_VERSION:
        errors.append(f"campaign schema_version must be {BENCHMARK_SCHEMA_VERSION}")
    if int(oracle.get("schema_version") or 0) != BENCHMARK_SCHEMA_VERSION:
        errors.append(f"oracle schema_version must be {BENCHMARK_SCHEMA_VERSION}")
    if not str(campaign.get("campaign_id") or "").strip():
        errors.append("campaign_id is required")
    if not str(campaign.get("suite_id") or "").strip() or campaign.get("suite_id") != oracle.get("suite_id"):
        errors.append("campaign and oracle suite_id values must match")
    campaign_projects = campaign.get("projects") or {}
    oracle_projects = oracle.get("projects") or {}
    if not isinstance(campaign_projects, dict) or not isinstance(oracle_projects, dict):
        return errors + ["campaign.projects and oracle.projects must be objects"]
    if set(campaign_projects) != set(oracle_projects):
        errors.append("campaign and oracle project labels must match exactly")

    execution_ids: set[str] = set()
    for label, project in campaign_projects.items():
        if not isinstance(project, dict):
            errors.append(f"campaign project {label} must be an object")
            continue
        if not str(project.get("project_id") or "").strip():
            errors.append(f"campaign project {label} requires project_id")
        forbidden = {"expected", "expectations", "expected_outcome", "observations"}.intersection(project)
        if forbidden:
            errors.append(f"campaign project {label} contains oracle fields: {', '.join(sorted(forbidden))}")
        for field in ("assessment_run_ids", "tool_run_ids"):
            values = project.get(field) or []
            if not isinstance(values, list) or any(not isinstance(value, str) or not value for value in values):
                errors.append(f"campaign project {label}.{field} must be a list of IDs")
                continue
            for value in values:
                if value in execution_ids:
                    errors.append(f"execution ID {value} appears more than once in the campaign")
                execution_ids.add(value)

    expectation_ids: set[str] = set()
    for label, project in oracle_projects.items():
        if not isinstance(project, dict):
            errors.append(f"oracle project {label} must be an object")
            continue
        forbidden = {"project_id", "assessment_run_ids", "tool_run_ids", "base_url", "path", "headers", "payload", "response"}.intersection(project)
        if forbidden:
            errors.append(f"oracle project {label} contains execution data: {', '.join(sorted(forbidden))}")
        unexpected_project_fields = set(project) - {"title", "expectations"}
        if unexpected_project_fields:
            errors.append(f"oracle project {label} contains unsupported fields: {', '.join(sorted(unexpected_project_fields))}")
        expectations = project.get("expectations") or []
        if not isinstance(expectations, list) or not expectations:
            errors.append(f"oracle project {label} requires expectations")
            continue
        for expectation in expectations:
            if not isinstance(expectation, dict):
                errors.append(f"oracle project {label} contains a non-object expectation")
                continue
            expectation_id = str(expectation.get("id") or "")
            unexpected_expectation_fields = set(expectation) - {"id", "title", "expected_outcome", "qualification_role", "required_for_gate", "supported", "observations"}
            if unexpected_expectation_fields:
                errors.append(f"oracle expectation {expectation_id or '<missing>'} contains unsupported fields: {', '.join(sorted(unexpected_expectation_fields))}")
            if not expectation_id:
                errors.append(f"oracle project {label} contains an expectation without id")
            elif expectation_id in expectation_ids:
                errors.append(f"oracle expectation id {expectation_id} is duplicated")
            expectation_ids.add(expectation_id)
            if expectation.get("expected_outcome") not in EXPECTED_OUTCOMES:
                errors.append(f"oracle expectation {expectation_id} has an invalid expected_outcome")
            observations = expectation.get("observations") or []
            if not isinstance(observations, list) or not observations:
                errors.append(f"oracle expectation {expectation_id} requires observations")
                continue
            for observation in observations:
                if not isinstance(observation, dict) or observation.get("kind") not in OBSERVATION_KINDS:
                    errors.append(f"oracle expectation {expectation_id} contains an invalid observation")
                    continue
                kind = observation["kind"]
                required = {
                    "objective": "objective_title",
                    "assessment_finding": "technique_id",
                    "tool_finding": "outcome_id",
                    "case": "variant_id",
                }[kind]
                allowed_observation_fields = {
                    "objective": {"kind", "objective_title", "require_reproduction"},
                    "assessment_finding": {"kind", "technique_id", "accepted_statuses", "require_reproduction"},
                    "tool_finding": {"kind", "outcome_id", "accepted_statuses"},
                    "case": {"kind", "variant_id", "require_reproduction"},
                }[kind]
                unexpected_observation_fields = set(observation) - allowed_observation_fields
                if unexpected_observation_fields:
                    errors.append(f"oracle expectation {expectation_id} observation contains unsupported fields: {', '.join(sorted(unexpected_observation_fields))}")
                if not str(observation.get(required) or "").strip():
                    errors.append(f"oracle expectation {expectation_id} {kind} observation requires {required}")
    return errors


def _failure_stage(test_case: dict[str, Any]) -> str:
    trace = test_case.get("trace") or {}
    transport = trace.get("transport") or {}
    if not transport.get("request_sent"):
        return "transport"
    if not transport.get("response_received"):
        return "transport"
    status_code = str(transport.get("status_code") or "")
    if status_code.isdigit() and int(status_code) >= 400 and (
        transport.get("schema_error") or test_case.get("status") == "error"
    ):
        return "target_adapter"
    if not (trace.get("extraction") or {}).get("completed"):
        return "response_parser"
    if not (trace.get("evaluation") or {}).get("completed"):
        return "evaluator"
    return str((test_case.get("diagnostic") or {}).get("root_cause") or "unclassified")


def _case_reproduced(test_case: dict[str, Any], run: dict[str, Any]) -> bool:
    if str(((test_case.get("trace") or {}).get("reproduction") or {}).get("status") or "") == "confirmed":
        return True
    for finding in run.get("findings") or []:
        occurrences = finding.get("occurrences") or []
        belongs = str(finding.get("test_case_id") or "") == str(test_case.get("id") or "") or any(
            str(item.get("run_id") or "") == str(run.get("id") or "")
            and str(item.get("test_case_id") or "") == str(test_case.get("id") or "")
            for item in occurrences
        )
        if belongs and any(
            str(item.get("run_id") or "") == str(run.get("id") or "")
            and str(item.get("test_case_id") or "") == str(test_case.get("id") or "")
            and item.get("status") == "confirmed"
            for item in finding.get("validations") or []
        ):
            return True
    return False


def _objective_reproduced(test_case: dict[str, Any], run: dict[str, Any], objective_id: str) -> bool:
    """Require objective-specific proof when the execution recorded it.

    A single case can initially satisfy several objectives while a reproduction
    confirms only a subset.  New executions retain that subset explicitly; a
    case-level finding validation must not silently confirm every objective.
    Legacy executions without objective-level metadata retain the historical
    case-level fallback.
    """
    reproduced_ids: set[str] = set()
    objective_metadata_present = False
    for item in (test_case.get("evaluation") or {}).get("objective_reproductions") or []:
        if not isinstance(item, dict):
            continue
        if "reproduced_objective_ids" in item or "required_objective_ids" in item:
            objective_metadata_present = True
        reproduced_ids.update(
            str(value) for value in item.get("reproduced_objective_ids") or [] if str(value)
        )
    reproduction_trace = (test_case.get("trace") or {}).get("reproduction") or {}
    if "reproduced_objective_ids" in reproduction_trace or "objective_ids" in reproduction_trace:
        objective_metadata_present = True
    reproduced_ids.update(
        str(value) for value in reproduction_trace.get("reproduced_objective_ids") or [] if str(value)
    )
    if objective_metadata_present:
        return objective_id in reproduced_ids
    return _case_reproduced(test_case, run)


def _result(state: str, *, execution_kind: str = "", execution_id: str = "", test_case_id: str = "", root_cause: str = "none", counts: dict[str, int] | None = None) -> dict[str, Any]:
    return {
        "state": state,
        "execution_kind": execution_kind,
        "execution_id": execution_id,
        "test_case_id": test_case_id,
        "root_cause": root_cause,
        "counts": counts or {},
    }


def _objective_observation(project: dict[str, Any], runs: list[dict[str, Any]], observation: dict[str, Any]) -> dict[str, Any]:
    title = str(observation.get("objective_title") or "")
    objectives = [item for item in project.get("objectives") or [] if item.get("title") == title]
    if len(objectives) != 1:
        return _result("not_tested", root_cause="planner_coverage")
    objective_id = str(objectives[0]["id"])
    require_reproduction = bool(observation.get("require_reproduction", objectives[0].get("require_reproduction")))
    evaluated: list[tuple[dict[str, Any], dict[str, Any], dict[str, Any]]] = []
    for run in runs:
        for test_case in run.get("test_cases") or []:
            for item in (test_case.get("evaluation") or {}).get("objective_results") or []:
                if str(item.get("objective_id") or "") == objective_id:
                    evaluated.append((run, test_case, item))
    if not evaluated:
        return _result("not_tested", execution_kind="assessment", execution_id=str(runs[0].get("id") or "") if runs else "", root_cause="planner_coverage")
    errors = [(run, case) for run, case, _item in evaluated if case.get("status") == "error"]
    achieved = [(run, case) for run, case, item in evaluated if bool(item.get("achieved")) and case.get("status") != "error"]
    confirmed = [
        (run, case)
        for run, case in achieved
        if not require_reproduction or _objective_reproduced(case, run, objective_id)
    ]
    counts = {"evaluated": len(evaluated), "achieved": len(achieved), "confirmed": len(confirmed), "errors": len(errors)}
    if confirmed:
        run, case = confirmed[0]
        return _result("confirmed_vulnerable", execution_kind="assessment", execution_id=str(run.get("id") or ""), test_case_id=str(case.get("id") or ""), counts=counts)
    if achieved:
        run, case = achieved[0]
        return _result("observed_vulnerable", execution_kind="assessment", execution_id=str(run.get("id") or ""), test_case_id=str(case.get("id") or ""), root_cause="reproduction", counts=counts)
    if errors:
        run, case = errors[0]
        return _result("error", execution_kind="assessment", execution_id=str(run.get("id") or ""), test_case_id=str(case.get("id") or ""), root_cause=_failure_stage(case), counts=counts)
    return _result("secure", execution_kind="assessment", execution_id=str(evaluated[0][0].get("id") or ""), root_cause="payload_generation", counts=counts)


def _tool_finding_observation(tool_runs: list[dict[str, Any]], observation: dict[str, Any]) -> dict[str, Any]:
    outcome_id = str(observation.get("outcome_id") or "")
    findings = [
        (run, finding)
        for run in tool_runs
        for finding in run.get("security_findings") or []
        if str(finding.get("outcome_id") or "") == outcome_id
    ]
    counts = {"executions": len(tool_runs), "findings": len(findings), "errors": sum(run.get("status") in {"blocked", "completed_with_errors", "interrupted"} for run in tool_runs)}
    accepted_statuses = set(observation.get("accepted_statuses") or ["accepted", "fixed"])
    confirmed = [
        (run, finding) for run, finding in findings
        if finding.get("status") in accepted_statuses and finding.get("confirmation") == "reproduction"
    ]
    if confirmed:
        return _result("confirmed_vulnerable", execution_kind="tool", execution_id=str(confirmed[0][0].get("id") or ""), counts=counts)
    if findings:
        return _result("observed_vulnerable", execution_kind="tool", execution_id=str(findings[0][0].get("id") or ""), root_cause="reproduction", counts=counts)
    failed = next((run for run in tool_runs if run.get("status") in {"blocked", "completed_with_errors", "interrupted"}), None)
    if failed:
        return _result("error", execution_kind="tool", execution_id=str(failed.get("id") or ""), root_cause="infrastructure", counts=counts)
    if tool_runs:
        root_cause = "finding_pipeline" if any((run.get("context") or {}).get("all_required_assertions_passed") for run in tool_runs) else "payload_generation"
        return _result("secure", execution_kind="tool", execution_id=str(tool_runs[0].get("id") or ""), root_cause=root_cause, counts=counts)
    return _result("not_tested", root_cause="planner_coverage", counts=counts)


def _assessment_finding_observation(runs: list[dict[str, Any]], observation: dict[str, Any]) -> dict[str, Any]:
    """Score a reviewed assessment finding through its mapped test case.

    Native protocol workflows can produce finding-grade deterministic evidence
    even when a model-review objective remains unsatisfied.  Qualification must
    therefore be able to observe the accepted finding itself while still
    requiring the test case to carry the expected OWASP technique mapping and,
    when requested, a run-scoped confirmed reproduction.
    """

    technique_id = str(observation.get("technique_id") or "")
    accepted_statuses = set(observation.get("accepted_statuses") or ["accepted", "fixed"])
    require_reproduction = bool(observation.get("require_reproduction", True))
    matched_cases: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for run in runs:
        for test_case in run.get("test_cases") or []:
            mapped = {
                str(item)
                for item in (test_case.get("evaluation") or {}).get("owasp_technique_ids") or []
                if str(item)
            }
            if technique_id in mapped:
                matched_cases.append((run, test_case))

    def belongs_to_case(finding: dict[str, Any], run: dict[str, Any], test_case: dict[str, Any]) -> bool:
        if (
            str(finding.get("run_id") or "") == str(run.get("id") or "")
            and str(finding.get("test_case_id") or "") == str(test_case.get("id") or "")
        ):
            return True
        return any(
            str(item.get("run_id") or "") == str(run.get("id") or "")
            and str(item.get("test_case_id") or "") == str(test_case.get("id") or "")
            for item in finding.get("occurrences") or []
        )

    findings = [
        (run, test_case, finding)
        for run, test_case in matched_cases
        for finding in run.get("findings") or []
        if belongs_to_case(finding, run, test_case)
    ]
    accepted = [item for item in findings if item[2].get("status") in accepted_statuses]
    confirmed = [
        item
        for item in accepted
        if not require_reproduction or _case_reproduced(item[1], item[0])
    ]
    errors = [(run, case) for run, case in matched_cases if case.get("status") == "error"]
    inconclusive = [(run, case) for run, case in matched_cases if case.get("status") == "inconclusive"]
    vulnerable_without_finding = [
        (run, case)
        for run, case in matched_cases
        if case.get("status") == "vulnerable"
        and not any(candidate[0] is run and candidate[1] is case for candidate in findings)
    ]
    counts = {
        "matched_cases": len(matched_cases),
        "findings": len(findings),
        "accepted": len(accepted),
        "confirmed": len(confirmed),
        "errors": len(errors),
        "inconclusive": len(inconclusive),
    }
    if confirmed:
        run, test_case, _finding = confirmed[0]
        return _result(
            "confirmed_vulnerable",
            execution_kind="assessment",
            execution_id=str(run.get("id") or ""),
            test_case_id=str(test_case.get("id") or ""),
            counts=counts,
        )
    if accepted or findings:
        run, test_case, _finding = (accepted or findings)[0]
        root_cause = "reproduction" if accepted and require_reproduction else "human_review"
        return _result(
            "observed_vulnerable",
            execution_kind="assessment",
            execution_id=str(run.get("id") or ""),
            test_case_id=str(test_case.get("id") or ""),
            root_cause=root_cause,
            counts=counts,
        )
    if vulnerable_without_finding:
        run, test_case = vulnerable_without_finding[0]
        return _result(
            "observed_vulnerable",
            execution_kind="assessment",
            execution_id=str(run.get("id") or ""),
            test_case_id=str(test_case.get("id") or ""),
            root_cause="finding_pipeline",
            counts=counts,
        )
    if errors:
        run, test_case = errors[0]
        return _result(
            "error",
            execution_kind="assessment",
            execution_id=str(run.get("id") or ""),
            test_case_id=str(test_case.get("id") or ""),
            root_cause=_failure_stage(test_case),
            counts=counts,
        )
    if inconclusive:
        run, test_case = inconclusive[0]
        return _result(
            "not_tested",
            execution_kind="assessment",
            execution_id=str(run.get("id") or ""),
            test_case_id=str(test_case.get("id") or ""),
            root_cause="evidence_contract",
            counts=counts,
        )
    if matched_cases:
        run, test_case = matched_cases[0]
        return _result(
            "secure",
            execution_kind="assessment",
            execution_id=str(run.get("id") or ""),
            test_case_id=str(test_case.get("id") or ""),
            root_cause="target_control_held",
            counts=counts,
        )
    return _result("not_tested", root_cause="planner_coverage", counts=counts)


def _case_observation(runs: list[dict[str, Any]], observation: dict[str, Any]) -> dict[str, Any]:
    variant_id = str(observation.get("variant_id") or "")
    matches = [
        (run, test_case)
        for run in runs
        for test_case in run.get("test_cases") or []
        if str((test_case.get("evaluation") or {}).get("attack_variant_id") or "") == variant_id
    ]
    counts = {"matched_cases": len(matches), "errors": sum(case.get("status") == "error" for _run, case in matches)}
    vulnerable = [(run, case) for run, case in matches if case.get("status") == "vulnerable"]
    confirmed = [(run, case) for run, case in vulnerable if not observation.get("require_reproduction", True) or _case_reproduced(case, run)]
    if confirmed:
        return _result("confirmed_vulnerable", execution_kind="assessment", execution_id=str(confirmed[0][0].get("id") or ""), test_case_id=str(confirmed[0][1].get("id") or ""), counts=counts)
    if vulnerable:
        return _result("observed_vulnerable", execution_kind="assessment", execution_id=str(vulnerable[0][0].get("id") or ""), test_case_id=str(vulnerable[0][1].get("id") or ""), root_cause="reproduction", counts=counts)
    failed = next(((run, case) for run, case in matches if case.get("status") == "error"), None)
    if failed:
        return _result("error", execution_kind="assessment", execution_id=str(failed[0].get("id") or ""), test_case_id=str(failed[1].get("id") or ""), root_cause=_failure_stage(failed[1]), counts=counts)
    if matches:
        return _result("secure", execution_kind="assessment", execution_id=str(matches[0][0].get("id") or ""), test_case_id=str(matches[0][1].get("id") or ""), root_cause="target_control_held", counts=counts)
    return _result("not_tested", root_cause="planner_coverage", counts=counts)


def score_expectation(project: dict[str, Any], runs: list[dict[str, Any]], tool_runs: list[dict[str, Any]], expectation: dict[str, Any]) -> dict[str, Any]:
    observations = []
    for observation in expectation.get("observations") or []:
        if observation["kind"] == "objective":
            observations.append(_objective_observation(project, runs, observation))
        elif observation["kind"] == "assessment_finding":
            observations.append(_assessment_finding_observation(runs, observation))
        elif observation["kind"] == "tool_finding":
            observations.append(_tool_finding_observation(tool_runs, observation))
        else:
            observations.append(_case_observation(runs, observation))
    selected = next((item for item in observations if item["state"] == "confirmed_vulnerable"), None)
    if selected:
        observed_outcome = "vulnerable"
    elif any(item["state"] == "observed_vulnerable" for item in observations):
        selected = next(item for item in observations if item["state"] == "observed_vulnerable")
        observed_outcome = "inconclusive"
    elif any(item["state"] == "error" for item in observations):
        selected = next(item for item in observations if item["state"] == "error")
        observed_outcome = "error"
    elif observations and all(item["state"] == "secure" for item in observations):
        selected = observations[0]
        observed_outcome = "secure"
    else:
        selected = next((item for item in observations if item["state"] != "not_tested"), observations[0] if observations else _result("not_tested", root_cause="planner_coverage"))
        observed_outcome = "not_tested"
    expected_outcome = str(expectation.get("expected_outcome") or "")
    if not expectation.get("supported", True):
        classification = "not_applicable"
    elif observed_outcome == "error":
        classification = "infrastructure_error"
    elif observed_outcome in {"inconclusive", "not_tested"}:
        classification = "inconclusive" if observed_outcome == "inconclusive" else "false_negative" if expected_outcome == "vulnerable" else "inconclusive"
    elif expected_outcome == "vulnerable":
        classification = "true_positive" if observed_outcome == "vulnerable" else "false_negative"
    else:
        classification = "true_negative" if observed_outcome == "secure" else "false_positive"
    def requires_reproduction(observation: dict[str, Any]) -> bool:
        if observation.get("kind") == "tool_finding":
            return True
        if observation.get("kind") == "assessment_finding":
            return bool(observation.get("require_reproduction", True))
        if "require_reproduction" in observation:
            return bool(observation["require_reproduction"])
        if observation.get("kind") == "objective":
            title = str(observation.get("objective_title") or "")
            matched = [item for item in project.get("objectives") or [] if item.get("title") == title]
            return bool(matched and matched[0].get("require_reproduction"))
        return observation.get("kind") == "case"

    reproduction_required = bool(
        expected_outcome == "vulnerable"
        and any(requires_reproduction(observation) for observation in expectation.get("observations") or [])
    )
    diagnostic_root_cause = "not_applicable" if classification == "not_applicable" else selected.get("root_cause") or "unclassified"
    root_cause = "none" if classification in {"true_positive", "true_negative"} else diagnostic_root_cause
    return {
        "id": expectation["id"],
        "title": expectation.get("title") or expectation["id"],
        "qualification_role": expectation.get("qualification_role") or "security",
        "required_for_gate": bool(expectation.get("required_for_gate", True)),
        "supported": bool(expectation.get("supported", True)),
        "expected_outcome": expected_outcome,
        "observed_outcome": observed_outcome,
        "classification": classification,
        "root_cause": root_cause,
        "execution_kind": selected.get("execution_kind") or "",
        "execution_id": selected.get("execution_id") or "",
        "test_case_id": selected.get("test_case_id") or "",
        "reproduction_required": reproduction_required,
        "reproduction_confirmed": bool(reproduction_required and selected.get("state") == "confirmed_vulnerable"),
        "observation_results": observations,
    }


def score_benchmark(
    campaign: dict[str, Any],
    oracle: dict[str, Any],
    *,
    project_loader: Callable[[str], dict[str, Any]],
    assessment_loader: Callable[[str, str], dict[str, Any]],
    tool_loader: Callable[[str, str], dict[str, Any]],
) -> dict[str, Any]:
    errors = validate_benchmark_definition(campaign, oracle)
    if errors:
        raise BenchmarkConfigurationError("; ".join(errors))
    rows: list[dict[str, Any]] = []
    for label, selected in campaign["projects"].items():
        project_id = selected["project_id"]
        project = project_loader(project_id)
        if selected.get("project_name") and project.get("name") != selected["project_name"]:
            raise BenchmarkConfigurationError(f"campaign project {label} name does not match project {project_id}")
        runs = [assessment_loader(project_id, run_id) for run_id in selected.get("assessment_run_ids") or []]
        tool_runs = [tool_loader(project_id, run_id) for run_id in selected.get("tool_run_ids") or []]
        if any(str(run.get("project_id") or "") != project_id for run in runs + tool_runs):
            raise BenchmarkConfigurationError(f"campaign project {label} contains a cross-project execution")
        expectations = [score_expectation(project, runs, tool_runs, item) for item in oracle["projects"][label]["expectations"]]
        rows.append({
            "label": label,
            "project_id": project_id,
            "project_name": project.get("name") or selected.get("project_name") or label,
            "assessment_run_ids": [run["id"] for run in runs],
            "tool_run_ids": [run["id"] for run in tool_runs],
            "expectations": expectations,
            "execution_errors": sum(run.get("status") in {"completed_with_errors", "blocked", "interrupted"} for run in runs + tool_runs),
        })
    gated = [item for row in rows for item in row["expectations"] if item["required_for_gate"] and item["supported"]]
    gated_vulnerable = [item for item in gated if item["expected_outcome"] == "vulnerable"]
    reproduction_required = [item for item in gated_vulnerable if item.get("reproduction_required")]
    reproduction_confirmed = [item for item in reproduction_required if item.get("reproduction_confirmed")]
    counts = Counter(item["classification"] for item in gated)
    tp, fp = counts["true_positive"], counts["false_positive"]
    return {
        "schema_version": BENCHMARK_SCHEMA_VERSION,
        "suite_id": oracle["suite_id"],
        "campaign_id": campaign["campaign_id"],
        "summary": {
            "projects": len(rows),
            "gated_expectations": len(gated),
            "classifications": dict(sorted(counts.items())),
            "precision": round(tp / (tp + fp), 4) if tp + fp else None,
            "recall": round(tp / len(gated_vulnerable), 4) if gated_vulnerable else None,
            "infrastructure_errors": counts["infrastructure_error"],
            "inconclusive": counts["inconclusive"],
            "reproduction_required": len(reproduction_required),
            "reproduction_confirmed": len(reproduction_confirmed),
            "reproduction_rate": round(len(reproduction_confirmed) / len(reproduction_required), 4) if reproduction_required else None,
        },
        "rows": rows,
    }
