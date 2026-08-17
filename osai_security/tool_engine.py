from __future__ import annotations

import json
import re
import threading
import time
from typing import Any

from .db import Repository
from .guardrails import ExecutionCancelled, ExecutionGuard, GuardrailViolation
from .owasp import TECHNIQUE_INDEX, validate_mapping
from .security import safe_error
from .targets import HTTP_METHODS, TargetClient, TargetError, request_log_preview, target_request_timeout
from .transport_reliability import cooperative_delay, reproduction_assessment


TOOL_DEFINITION_VERSION = "2026.08.6"
STEP_TYPES = {"http", "poll", "interaction"}
BODY_ENCODINGS = {"json", "form", "text"}
BODY_REGEX_NORMALIZERS = {"none", "remove-whitespace"}
ASSERTION_ROLES = {"precondition", "evidence"}
ASSERTION_TYPES = {
    "status", "body_contains", "body_regex", "response_contains",
    "json_exists", "json_equals", "json_not_equals", "json_contains", "json_regex",
    "json_gt", "json_gte", "json_lt", "json_lte",
    "header_exists", "header_equals",
}
_TEMPLATE = re.compile(r"\{\{\s*([a-zA-Z0-9_.-]+)\s*\}\}")
_STEP_ID = re.compile(r"^[a-zA-Z][a-zA-Z0-9_-]{0,79}$")
_OUTCOME_ID = re.compile(r"^[a-zA-Z][a-zA-Z0-9_-]{0,79}$")
_OBJECTIVE_ID = re.compile(r"^[a-zA-Z][a-zA-Z0-9_-]{0,79}$")
_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_CONFIRMATION_TYPES = {"exact-http", "key-pattern", "verifier", "callback", "differential", "reproduction"}


class ToolExecutionError(RuntimeError):
    pass


def _as_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _normalize_assertions(value: Any) -> list[dict[str, Any]]:
    if value in (None, []):
        return []
    if not isinstance(value, list) or len(value) > 30:
        raise ValueError("assertions must be a list containing at most 30 entries")
    normalized = []
    for assertion in value:
        assertion = _as_object(assertion, "assertion")
        assertion_type = str(assertion.get("type") or "").strip()
        if assertion_type not in ASSERTION_TYPES:
            raise ValueError(f"unsupported assertion type: {assertion_type or 'missing'}")
        role = str(assertion.get("role") or ("precondition" if assertion_type == "status" else "evidence")).strip().casefold()
        if role not in ASSERTION_ROLES:
            raise ValueError(f"unsupported assertion role: {role or 'missing'}")
        normalized_assertion = {
            **assertion,
            "type": assertion_type,
            "label": str(assertion.get("label") or assertion_type.replace("_", " "))[:180],
            "required": assertion.get("required", True) not in {False, "false", "0", 0},
            "role": role,
        }
        if assertion_type in {"body_regex", "json_regex"}:
            normalizer = str(assertion.get("normalizer") or "none").strip().casefold()
            if normalizer not in BODY_REGEX_NORMALIZERS:
                raise ValueError(f"unsupported regex normalizer: {normalizer or 'missing'}")
            normalized_assertion["normalizer"] = normalizer
        normalized.append(normalized_assertion)
    return normalized


def _normalize_step(value: Any, index: int) -> dict[str, Any]:
    step = _as_object(value, f"step {index + 1}")
    step_id = str(step.get("id") or f"step_{index + 1}")
    if not _STEP_ID.fullmatch(step_id):
        raise ValueError(f"invalid workflow step id: {step_id}")
    step_type = str(step.get("type") or "")
    if step_type not in STEP_TYPES:
        raise ValueError(f"unsupported or missing workflow step type: {step_type or 'missing'}")
    normalized = {
        **step,
        "id": step_id,
        "type": step_type,
        "name": str(step.get("name") or step_id.replace("_", " ").title())[:180],
        "assertions": _normalize_assertions(step.get("assertions")),
        "stop_on_failure": step.get("stop_on_failure") in {True, "true", "1", 1},
    }
    if step_type in {"http", "poll"}:
        normalized["method"] = str(step.get("method") or "").upper()
        if normalized["method"] not in HTTP_METHODS:
            raise ValueError(f"workflow step {step_id} requires an explicit supported HTTP method")
        normalized["path"] = str(step.get("path") or "")[:1000]
        if not normalized["path"]:
            raise ValueError(f"workflow step {step_id} requires a relative path")
        normalized["response_path"] = str(step.get("response_path") or "")[:300]
        normalized["body_encoding"] = str(step.get("body_encoding") or "json").casefold()
        if normalized["body_encoding"] not in BODY_ENCODINGS:
            raise ValueError(f"workflow step {step_id} has an unsupported body encoding")
        captures = step.get("captures") or {}
        if not isinstance(captures, dict) or len(captures) > 30:
            raise ValueError(f"workflow step {step_id} captures must be an object with at most 30 fields")
        normalized["captures"] = {str(key)[:80]: str(selector)[:500] for key, selector in captures.items()}
    if step_type == "poll":
        try:
            normalized["max_attempts"] = int(step["max_attempts"])
            normalized["interval_ms"] = int(step["interval_ms"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"poll step {step_id} requires explicit max_attempts and interval_ms limits") from exc
        if not 1 <= normalized["max_attempts"] <= 20 or not 0 <= normalized["interval_ms"] <= 5000:
            raise ValueError(f"poll step {step_id} limits must use 1-20 attempts and a 0-5000 ms interval")
    if step_type == "interaction":
        normalized["token"] = str(step.get("token") or "")[:500]
        if not normalized["token"]:
            raise ValueError(f"workflow interaction step {step_id} requires a token or token template")
        try:
            normalized["wait_seconds"] = int(step["wait_seconds"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"interaction step {step_id} requires an explicit wait_seconds limit") from exc
        if not 0 <= normalized["wait_seconds"] <= 30:
            raise ValueError(f"interaction step {step_id} wait_seconds must be between 0 and 30")
    return normalized


def _normalize_security_outcomes(value: Any, *, known_step_ids: set[str]) -> list[dict[str, Any]]:
    """Validate explicit evidence contracts that may create tool findings.

    Tool traffic never becomes a finding merely because requests succeeded. The
    operator must map a named security outcome to concrete workflow steps and
    OWASP techniques. All referenced steps must satisfy their required
    assertions in the same immutable run.
    """
    if value in (None, []):
        return []
    if not isinstance(value, list) or len(value) > 30:
        raise ValueError("security_outcomes must be a list containing at most 30 entries")
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(value):
        outcome = _as_object(raw, f"security outcome {index + 1}")
        outcome_id = str(outcome.get("id") or f"outcome_{index + 1}")
        if not _OUTCOME_ID.fullmatch(outcome_id) or outcome_id in seen:
            raise ValueError(f"invalid or duplicate security outcome id: {outcome_id}")
        seen.add(outcome_id)
        title = str(outcome.get("title") or "").strip()
        summary = str(outcome.get("summary") or "").strip()
        if not title or not summary:
            raise ValueError(f"security outcome {outcome_id} requires title and summary")
        required_step_ids = list(dict.fromkeys(str(item) for item in (outcome.get("required_step_ids") or []) if str(item)))
        raw_any_groups = outcome.get("required_any_step_groups") or []
        if not isinstance(raw_any_groups, list) or len(raw_any_groups) > 20:
            raise ValueError(f"security outcome {outcome_id} required_any_step_groups must contain at most 20 groups")
        required_any_step_groups: list[list[str]] = []
        for group_index, raw_group in enumerate(raw_any_groups, start=1):
            if not isinstance(raw_group, list):
                raise ValueError(f"security outcome {outcome_id} any-step group {group_index} must be a list")
            group = list(dict.fromkeys(str(item) for item in raw_group if str(item)))
            if not group or len(group) > 100:
                raise ValueError(f"security outcome {outcome_id} any-step group {group_index} must contain 1-100 step ids")
            required_any_step_groups.append(group)
        if not required_step_ids and not required_any_step_groups:
            raise ValueError(f"security outcome {outcome_id} requires required_step_ids or required_any_step_groups")
        referenced_step_ids = set(required_step_ids).union(*(set(group) for group in required_any_step_groups))
        unknown_steps = sorted(referenced_step_ids - known_step_ids)
        if unknown_steps:
            raise ValueError(f"security outcome {outcome_id} references unknown steps: {', '.join(unknown_steps)}")
        reproduction_step_ids = list(dict.fromkeys(str(item) for item in (outcome.get("reproduction_step_ids") or []) if str(item)))
        unknown_reproduction_steps = sorted(set(reproduction_step_ids) - known_step_ids)
        if unknown_reproduction_steps:
            raise ValueError(f"security outcome {outcome_id} references unknown reproduction steps: {', '.join(unknown_reproduction_steps)}")
        if not set(reproduction_step_ids).issubset(referenced_step_ids):
            raise ValueError(f"security outcome {outcome_id} reproduction steps must also be required steps")
        outcome_kind = str(outcome.get("kind") or "security").casefold()
        if outcome_kind not in {"security", "observation", "methodology"}:
            raise ValueError(
                f"security outcome {outcome_id} kind must be security, observation, or methodology"
            )
        raw_objective_ids = outcome.get("objective_ids") or []
        if not isinstance(raw_objective_ids, list) or len(raw_objective_ids) > 50:
            raise ValueError(f"security outcome {outcome_id} objective_ids must contain at most 50 ids")
        objective_ids: list[str] = []
        for raw_objective_id in raw_objective_ids:
            objective_id = str(raw_objective_id or "").strip()
            if not _OBJECTIVE_ID.fullmatch(objective_id):
                raise ValueError(f"security outcome {outcome_id} has an invalid objective id: {objective_id or 'missing'}")
            if objective_id not in objective_ids:
                objective_ids.append(objective_id)
        if objective_ids and outcome_kind != "security":
            raise ValueError(
                f"security outcome {outcome_id} may link objectives only when kind is security"
            )
        risk_ids, technique_ids = validate_mapping(outcome.get("risk_ids") or [], outcome.get("technique_ids") or [])
        if outcome_kind == "security" and not technique_ids:
            raise ValueError(f"security outcome {outcome_id} requires at least one OWASP technique id")
        if outcome_kind == "methodology" and (risk_ids or technique_ids):
            raise ValueError(f"methodology outcome {outcome_id} must not claim OWASP vulnerability coverage")
        mapped_risks = sorted({TECHNIQUE_INDEX[item]["risk_id"] for item in technique_ids})
        if risk_ids and not set(mapped_risks).issubset(set(risk_ids)):
            raise ValueError(f"security outcome {outcome_id} risk ids do not cover its technique mappings")
        severity = str(outcome.get("severity") or "medium").casefold()
        if severity not in _SEVERITIES:
            raise ValueError(f"security outcome {outcome_id} has an invalid severity")
        try:
            confidence = float(outcome.get("confidence", 0.9))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"security outcome {outcome_id} confidence must be numeric") from exc
        if not 0 <= confidence <= 1:
            raise ValueError(f"security outcome {outcome_id} confidence must be between 0 and 1")
        confirmation = str(outcome.get("confirmation") or "verifier")
        if confirmation not in _CONFIRMATION_TYPES:
            raise ValueError(f"security outcome {outcome_id} has an invalid confirmation type")
        normalized.append({
            "id": outcome_id,
            "kind": outcome_kind,
            "title": title[:240],
            "summary": summary[:5000],
            "severity": severity,
            "confidence": confidence,
            "risk_ids": risk_ids or mapped_risks,
            "technique_ids": technique_ids,
            "objective_ids": objective_ids,
            "required_step_ids": required_step_ids,
            "required_any_step_groups": required_any_step_groups,
            "reproduction_step_ids": reproduction_step_ids,
            "confirmation": confirmation,
        })
    return normalized


def _step_has_required_evidence(step: dict[str, Any]) -> bool:
    return step.get("type") == "interaction" or any(
        assertion.get("required", True) and assertion.get("role") == "evidence"
        for assertion in step.get("assertions") or []
    )


def _validate_security_outcome_evidence(outcomes: list[dict[str, Any]], evidence_step_ids: set[str]) -> None:
    """Guarantee that every possible security proof includes target evidence."""
    for outcome in outcomes:
        if outcome.get("kind") != "security":
            continue
        fixed = set(outcome.get("required_step_ids") or [])
        groups = [set(group) for group in outcome.get("required_any_step_groups") or []]
        fixed_guarantees_evidence = bool(fixed.intersection(evidence_step_ids))
        grouped_guarantees_evidence = any(group and group.issubset(evidence_step_ids) for group in groups)
        if not fixed_guarantees_evidence and not grouped_guarantees_evidence:
            raise ValueError(
                f"security outcome {outcome['id']} requires at least one required evidence assertion on every successful proof path"
            )


def normalize_tool_definition(kind: str, value: Any) -> dict[str, Any]:
    definition = _as_object(value, "testing tool definition")
    kind = str(kind)
    normalized: dict[str, Any] = {**definition, "version": str(definition.get("version") or TOOL_DEFINITION_VERSION)}
    if kind == "workflow":
        steps = definition.get("steps")
        if not isinstance(steps, list) or not steps or len(steps) > 100:
            raise ValueError("workflow steps must contain between 1 and 100 entries")
        normalized["steps"] = [_normalize_step(step, index) for index, step in enumerate(steps)]
        ids = [step["id"] for step in normalized["steps"]]
        if len(ids) != len(set(ids)):
            raise ValueError("workflow step ids must be unique")
        normalized["security_outcomes"] = _normalize_security_outcomes(definition.get("security_outcomes"), known_step_ids=set(ids))
        _validate_security_outcome_evidence(
            normalized["security_outcomes"],
            {step["id"] for step in normalized["steps"] if _step_has_required_evidence(step)},
        )
    elif kind == "campaign":
        request = _normalize_step({**_as_object(definition.get("request"), "campaign request"), "id": "campaign_request", "type": "http"}, 0)
        payloads = definition.get("payloads")
        if not isinstance(payloads, list) or not payloads or len(payloads) > 1000:
            raise ValueError("campaign payloads must contain between 1 and 1000 entries")
        normalized["request"] = request
        normalized["payloads"] = []
        for index, raw_item in enumerate(payloads):
            item = dict(raw_item) if isinstance(raw_item, dict) else {"label": f"Payload {index + 1}", "value": raw_item}
            if item.get("replay_key") not in (None, ""):
                replay_key = str(item["replay_key"]).strip()
                if not replay_key or len(replay_key) > 160:
                    raise ValueError("campaign replay_key must contain 1-160 characters")
                item["replay_key"] = replay_key
            normalized["payloads"].append(item)
        normalized["stop_on_match"] = definition.get("stop_on_match") in {True, "true", "1", 1}
        normalized["bounded_reproduction"] = definition.get("bounded_reproduction") in {True, "true", "1", 1}
        stop_on_match_by = str(definition.get("stop_on_match_by") or "").strip()
        if stop_on_match_by and (len(stop_on_match_by) > 80 or not _STEP_ID.fullmatch(stop_on_match_by)):
            raise ValueError("campaign stop_on_match_by must be a safe payload field name")
        if stop_on_match_by and any(item.get(stop_on_match_by) in (None, "") for item in normalized["payloads"]):
            raise ValueError(f"every campaign payload must define {stop_on_match_by}")
        normalized["stop_on_match_by"] = stop_on_match_by
        campaign_step_ids = {f"campaign_{index}" for index in range(1, len(normalized["payloads"]) + 1)}
        normalized["security_outcomes"] = _normalize_security_outcomes(
            definition.get("security_outcomes"), known_step_ids=campaign_step_ids
        )
        if normalized["bounded_reproduction"]:
            reproduction_step_ids = {
                step_id
                for outcome in normalized["security_outcomes"]
                for step_id in outcome.get("reproduction_step_ids") or []
            }
            if not reproduction_step_ids:
                raise ValueError("bounded campaign reproduction requires explicit reproduction_step_ids")
            keyed_steps = {
                f"campaign_{index}"
                for index, item in enumerate(normalized["payloads"], start=1)
                if item.get("replay_key")
            }
            missing_keys = sorted(reproduction_step_ids - keyed_steps)
            if missing_keys:
                raise ValueError(
                    "bounded campaign reproduction requires replay_key on every reproduction payload: "
                    + ", ".join(missing_keys)
                )
        campaign_evidence_steps: set[str] = set()
        for index, item in enumerate(normalized["payloads"], start=1):
            overrides = {key: item[key] for key in ("path", "method", "body", "response_path", "assertions") if key in item}
            campaign_step = _normalize_step(
                {**request, **overrides, "id": f"campaign_{index}", "name": str(item.get("label") or f"Payload {index}")},
                index - 1,
            )
            if _step_has_required_evidence(campaign_step):
                campaign_evidence_steps.add(campaign_step["id"])
        _validate_security_outcome_evidence(normalized["security_outcomes"], campaign_evidence_steps)
    elif kind == "replay":
        normalized["request"] = _normalize_step({**_as_object(definition.get("request"), "replay request"), "id": "replay_request", "type": "http"}, 0)
        normalized["security_outcomes"] = _normalize_security_outcomes(definition.get("security_outcomes"), known_step_ids={"replay_request"})
        _validate_security_outcome_evidence(
            normalized["security_outcomes"],
            {"replay_request"} if _step_has_required_evidence(normalized["request"]) else set(),
        )
    else:
        raise ValueError("testing tool kind must be workflow, campaign, or replay")
    return normalized


def _step_determinacy(context: dict[str, Any], step_id: str) -> dict[str, Any]:
    """Distinguish a valid negative result from an unusable contract response."""
    outcome = (context.get("outcomes") or {}).get(step_id)
    record = (context.get("assertion_results") or {}).get(step_id)
    if outcome not in {True, False}:
        return {"determinate": False, "reasons": ["step did not produce a terminal assertion result"]}
    if not isinstance(record, dict):
        # Interaction steps and historical tool definitions predate assertion
        # roles. Their explicit boolean observation remains deterministic.
        return {"determinate": True, "reasons": []}
    reasons: list[str] = []
    for assertion in record.get("assertions") or []:
        if not assertion.get("required", True):
            continue
        if not assertion.get("evaluated", True):
            reasons.append(f"{assertion.get('label') or assertion.get('type')}: assertion could not be evaluated")
        elif assertion.get("role") == "precondition" and not assertion.get("passed"):
            reasons.append(f"{assertion.get('label') or assertion.get('type')}: contract precondition failed")
    return {"determinate": not reasons, "reasons": reasons}


def _record_security_outcomes(repo: Repository, *, project_id: str, run: dict[str, Any], context: dict[str, Any]) -> None:
    results = []
    for outcome in run["definition"].get("security_outcomes") or []:
        fixed_step_ids = list(outcome.get("required_step_ids") or [])
        any_groups = list(outcome.get("required_any_step_groups") or [])
        all_step_ids = list(dict.fromkeys([*fixed_step_ids, *(step_id for group in any_groups for step_id in group)]))
        step_results = {step_id: context.get("outcomes", {}).get(step_id) for step_id in all_step_ids}
        step_determinacy = {step_id: _step_determinacy(context, step_id) for step_id in all_step_ids}
        group_results = [
            {
                "step_ids": list(group),
                "matched_step_ids": [step_id for step_id in group if step_results.get(step_id) is True and step_determinacy[step_id]["determinate"]],
                "inconclusive_step_ids": [step_id for step_id in group if not step_determinacy[step_id]["determinate"]],
            }
            for group in any_groups
        ]
        confirmed = bool(all_step_ids) and all(
            step_results.get(step_id) is True and step_determinacy[step_id]["determinate"] for step_id in fixed_step_ids
        ) and all(
            group["matched_step_ids"] for group in group_results
        )
        inconclusive = not confirmed and (
            any(not step_determinacy[step_id]["determinate"] for step_id in fixed_step_ids)
            or any(not group["matched_step_ids"] and group["inconclusive_step_ids"] for group in group_results)
        )
        outcome_status = "confirmed" if confirmed else "inconclusive" if inconclusive else "not_demonstrated"
        matched_step_ids = [
            step_id for step_id in all_step_ids
            if step_id in fixed_step_ids or step_results.get(step_id) is True
        ]
        matched_reproduction_step_ids = [
            step_id for step_id in outcome.get("reproduction_step_ids") or []
            if step_results.get(step_id) is True
        ]
        reproduction_step_ids = set(outcome.get("reproduction_step_ids") or [])
        generated_reproduction_ids = set(
            str(item)
            for item in ((run.get("definition") or {}).get("reproduction") or {}).get("step_id_map", {}).values()
            if str(item)
        )
        if generated_reproduction_ids:
            reproduction_fixed_ids = [
                step_id for step_id in fixed_step_ids if step_id in generated_reproduction_ids
            ]
            reproduction_groups = [
                group for group in any_groups
                if group and set(group).issubset(generated_reproduction_ids)
            ]
            reproduction_confirmed = bool(reproduction_fixed_ids or reproduction_groups) and all(
                step_results.get(step_id) is True and step_determinacy[step_id]["determinate"]
                for step_id in reproduction_fixed_ids
            ) and all(
                any(
                    step_results.get(step_id) is True and step_determinacy[step_id]["determinate"]
                    for step_id in group
                )
                for group in reproduction_groups
            )
        else:
            reproduction_confirmed = bool(reproduction_step_ids) and all(
                step_results.get(step_id) is True and step_determinacy[step_id]["determinate"]
                for step_id in reproduction_step_ids
            )
        contract_metadata = (run.get("definition") or {}).get("assessment_contract") or {}
        objective_reason = (
            f"Deterministic target contract {contract_metadata.get('id') or run.get('contract_id') or 'configured contract'} "
            f"confirmed outcome {outcome['id']} with every required assertion"
            + (" and its configured reproduction." if reproduction_step_ids else ".")
            if confirmed else
            f"Target contract outcome {outcome['id']} was inconclusive because a required transport, schema, or evaluator precondition failed."
            if inconclusive else
            f"Target contract outcome {outcome['id']} completed with valid preconditions but did not demonstrate its configured security proof."
        )
        objective_results = [
            {
                "objective_id": objective_id,
                "achieved": confirmed,
                "confidence": float(outcome.get("confidence") or 0.0) if confirmed else 0.0 if inconclusive else 0.99,
                "reason": objective_reason,
                "proof_source": "deterministic-target-contract",
                "proof_mode": "contract",
                "confirmation_state": "contract-confirmed" if confirmed else "inconclusive" if inconclusive else "not-confirmed",
                "reproduction_confirmed": bool(confirmed and reproduction_confirmed),
                "outcome_id": outcome["id"],
                "contract_id": str(contract_metadata.get("id") or run.get("contract_id") or ""),
                "contract_sha256": str(contract_metadata.get("contract_sha256") or ""),
                "tool_run_id": run["id"],
            }
            for objective_id in outcome.get("objective_ids") or []
        ]
        result = {
            **outcome,
            "status": outcome_status,
            "execution_source": "target-configured-contract" if run.get("assessment_run_id") else "target-configured-testing-tool",
            "evidence_assurance": {
                "level": "deterministic-contract" if confirmed else "contract-inconclusive" if inconclusive else "contract-not-demonstrated",
                "finding_eligible": bool(confirmed and str(outcome.get("kind") or "security") == "security"),
                "confirmation_state": "contract-confirmed" if confirmed else "inconclusive" if inconclusive else "not-confirmed",
                "basis": (
                    "Every target-configured required assertion passed"
                    + (", including the configured reproduction proof." if reproduction_step_ids else ".")
                    if confirmed else
                    "A required transport, schema, or evaluator precondition failed, so this execution cannot support a pass or a finding."
                    if inconclusive else
                    "Every required contract precondition was valid, but the target-configured security proof requirements were not demonstrated."
                ),
            },
            "step_results": step_results,
            "step_determinacy": step_determinacy,
            "determinate": not inconclusive,
            "reproduction_confirmed": bool(confirmed and reproduction_confirmed),
            "objective_results": objective_results,
            "group_results": group_results,
            "required_step_ids": matched_step_ids if any_groups else fixed_step_ids,
            "reproduction_step_ids": matched_reproduction_step_ids if any_groups else list(outcome.get("reproduction_step_ids") or []),
        }
        reproduction_summary = (context.get("campaign_reproduction") or {}).get(outcome["id"])
        if reproduction_summary is None:
            reproduction_summary = next(
                (
                    item
                    for item in (context.get("campaign_reproduction") or {}).values()
                    if item.get("reproduction_step_id") in set(outcome.get("reproduction_step_ids") or [])
                ),
                None,
            )
        if reproduction_summary is not None:
            result["reproduction_assessment"] = reproduction_summary
        results.append(result)
        outcome_kind = str(outcome.get("kind") or "security")
        if outcome_kind == "observation":
            event_type = "security_observation.recorded" if confirmed else "security_observation.inconclusive" if inconclusive else "security_observation.not_demonstrated"
            event_title = f"Security observation {'recorded' if confirmed else 'inconclusive' if inconclusive else 'not demonstrated'}: {outcome['title']}"
        elif outcome_kind == "methodology":
            event_type = "methodology_outcome.completed" if confirmed else "methodology_outcome.inconclusive" if inconclusive else "methodology_outcome.not_completed"
            event_title = f"Methodology outcome {'completed' if confirmed else 'inconclusive' if inconclusive else 'not completed'}: {outcome['title']}"
        else:
            event_type = "security_outcome.confirmed" if confirmed else "security_outcome.inconclusive" if inconclusive else "security_outcome.not_demonstrated"
            event_title = f"Security outcome {'confirmed' if confirmed else 'inconclusive' if inconclusive else 'not demonstrated'}: {outcome['title']}"
        repo.add_tool_event(
            project_id,
            run["id"],
            step_id="",
            event_type=event_type,
            title=event_title,
            details={
                "outcome_id": outcome["id"],
                "kind": outcome_kind,
                "risk_ids": outcome["risk_ids"],
                "technique_ids": outcome["technique_ids"],
                "objective_ids": outcome.get("objective_ids") or [],
                "objective_results": objective_results,
                "required_step_ids": result["required_step_ids"],
                "required_any_step_groups": outcome.get("required_any_step_groups") or [],
                "step_results": step_results,
                "step_determinacy": step_determinacy,
                "confirmation": outcome["confirmation"],
                "execution_source": result["execution_source"],
                "evidence_assurance": result["evidence_assurance"],
            },
        )
        if confirmed and outcome_kind == "security":
            repo.add_tool_finding(
                project_id,
                tool_run_id=run["id"],
                target_id=run["target_id"],
                outcome_id=outcome["id"],
                title=outcome["title"],
                summary=outcome["summary"],
                severity=outcome["severity"],
                confidence=outcome["confidence"],
                risk_ids=outcome["risk_ids"],
                technique_ids=outcome["technique_ids"],
                required_step_ids=result["required_step_ids"],
                confirmation=outcome["confirmation"],
            )
    context["security_outcomes"] = results


def _lookup(context: dict[str, Any], path: str) -> Any:
    current: Any = context
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            raise ToolExecutionError(f"template variable is unavailable: {path}")
    return current


def render_template(value: Any, context: dict[str, Any]) -> Any:
    if isinstance(value, dict):
        return {str(key): render_template(item, context) for key, item in value.items()}
    if isinstance(value, list):
        return [render_template(item, context) for item in value]
    if not isinstance(value, str):
        return value
    exact = _TEMPLATE.fullmatch(value)
    if exact:
        return _lookup(context, exact.group(1))
    return _TEMPLATE.sub(lambda match: str(_lookup(context, match.group(1))), value)


def _json_document(result: dict[str, Any]) -> Any:
    raw = str(result.get("raw") or "")
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def json_path(value: Any, selector: str) -> Any:
    selector = str(selector or "").strip()
    if selector in {"$", "body", "response"}:
        return value
    if selector.startswith("$."):
        selector = selector[2:]
    elif selector.startswith("$"):
        selector = selector[1:].lstrip(".")
    current = value
    for token in re.findall(r"[^.\[\]]+", selector):
        if isinstance(current, list) and token.isdigit():
            current = current[int(token)]
        elif isinstance(current, dict) and token in current:
            current = current[token]
        else:
            raise KeyError(selector)
    return current


def _header_map(result: dict[str, Any]) -> dict[str, str]:
    headers = {}
    for item in result.get("response_headers") or []:
        if isinstance(item, dict):
            headers[str(item.get("name") or "").casefold()] = str(item.get("value") or "")
    return headers


def _evaluate_assertion(assertion: dict[str, Any], result: dict[str, Any], context: dict[str, Any]) -> tuple[bool, str, Any, bool]:
    kind = assertion["type"]
    expected = render_template(assertion.get("equals", assertion.get("value", assertion.get("contains", ""))), context)
    raw = str(result.get("raw") or "")
    response = str(result.get("response") or "")
    document = _json_document(result)
    actual: Any = None
    try:
        if kind == "status":
            actual = int(result.get("status_code") or 0)
            passed = actual == int(expected)
        elif kind == "body_contains":
            actual = raw
            passed = str(expected) in raw
        elif kind == "body_regex":
            pattern = str(assertion.get("pattern") or expected)
            if len(pattern) > 500:
                raise ValueError("body regex is longer than 500 characters")
            normalizer = str(assertion.get("normalizer") or "none")
            candidate = re.sub(r"\s+", "", raw) if normalizer == "remove-whitespace" else raw
            passed = re.search(pattern, candidate, re.IGNORECASE) is not None
            expected = pattern
            actual = raw if normalizer == "none" else {
                "source": "raw_response",
                "normalizer": normalizer,
                "raw_response_sha256": str(result.get("raw_response_sha256") or ""),
                "matched": passed,
            }
        elif kind == "response_contains":
            actual = response
            passed = str(expected) in response
        elif kind == "json_regex":
            selector = str(assertion.get("path") or "$.")
            try:
                selected = json_path(document, selector)
                exists = True
            except (KeyError, IndexError, TypeError):
                selected, exists = None, False
            pattern = str(assertion.get("pattern") or expected)
            if len(pattern) > 500:
                raise ValueError("JSON regex is longer than 500 characters")
            normalizer = str(assertion.get("normalizer") or "none")
            selected_text = selected if isinstance(selected, str) else json.dumps(selected, ensure_ascii=False) if exists else ""
            candidate = re.sub(r"\s+", "", selected_text) if normalizer == "remove-whitespace" else selected_text
            passed = exists and re.search(pattern, candidate, re.IGNORECASE) is not None
            expected = pattern
            actual = selected_text if normalizer == "none" else {
                "source": "json_selector",
                "selector": selector,
                "normalizer": normalizer,
                "raw_response_sha256": str(result.get("raw_response_sha256") or ""),
                "matched": passed,
            }
        elif kind.startswith("json_"):
            selector = str(assertion.get("path") or "$.")
            try:
                actual = json_path(document, selector)
                exists = True
            except (KeyError, IndexError, TypeError):
                actual, exists = None, False
            if kind == "json_exists":
                passed = exists
            elif not exists:
                return False, f"JSON selector {selector!r} was not present in the response", actual, False
            elif kind == "json_equals":
                passed = actual == expected
            elif kind == "json_not_equals":
                passed = actual != expected
            elif kind in {"json_gt", "json_gte", "json_lt", "json_lte"}:
                actual_number = float(actual)
                expected_number = float(expected)
                passed = {
                    "json_gt": actual_number > expected_number,
                    "json_gte": actual_number >= expected_number,
                    "json_lt": actual_number < expected_number,
                    "json_lte": actual_number <= expected_number,
                }[kind]
            else:
                passed = exists and str(expected) in (json.dumps(actual, ensure_ascii=False) if not isinstance(actual, str) else actual)
        elif kind.startswith("header_"):
            header_name = str(assertion.get("name") or "").casefold()
            actual = _header_map(result).get(header_name)
            if kind == "header_exists":
                passed = actual is not None
            elif actual is None:
                return False, f"response header {header_name!r} was not present", actual, False
            else:
                passed = actual == str(expected)
        else:
            raise ValueError(f"unsupported assertion type: {kind}")
    except (TypeError, ValueError, re.error) as exc:
        return False, f"assertion could not be evaluated: {safe_error(exc)}", actual, False
    return passed, f"expected {expected!r}; observed {actual!r}", actual, True


def _capture_value(selector: str, result: dict[str, Any]) -> Any:
    if selector == "body":
        return result.get("raw")
    if selector == "response":
        return result.get("response")
    if selector == "status":
        return int(result.get("status_code") or 0)
    if selector.startswith("header:"):
        return _header_map(result).get(selector.split(":", 1)[1].casefold())
    return json_path(_json_document(result), selector)


def _response_event(result: dict[str, Any], attempt: int) -> dict[str, Any]:
    return {
        "attempt": attempt,
        "status_code": result.get("status_code"),
        "status_line": result.get("status_line"),
        "response_headers": result.get("response_headers") or [],
        "raw_response": result.get("raw"),
        "raw_http_response": result.get("raw_http_response"),
        "raw_response_sha256": result.get("raw_response_sha256"),
        "response": result.get("response"),
        "completion": result.get("completion") or {},
        "scope_enforcement": result.get("scope_enforcement") or {},
    }


def _execute_http_step(
    repo: Repository,
    *,
    project_id: str,
    tool_run_id: str,
    target: dict[str, Any],
    step: dict[str, Any],
    context: dict[str, Any],
    guard: ExecutionGuard,
    target_client: TargetClient,
    attempt: int = 1,
    defer_failures: bool = False,
) -> tuple[dict[str, Any], bool]:
    path = str(render_template(step["path"], context))
    method = str(render_template(step.get("method") or "GET", context)).upper()
    body = render_template(step.get("body", {}), context)
    response_path = str(render_template(step.get("response_path") or "", context))
    guard.before_request(target["id"], operation="testing-tool")
    preview = request_log_preview(
        target,
        "",
        timeout_seconds=target_request_timeout(target_client, target),
        path_override=path,
        method_override=method,
        payload_override=body,
        body_encoding=step.get("body_encoding", "json"),
    )
    repo.add_tool_event(project_id, tool_run_id, step_id=step["id"], event_type="request.sent", title=f"Request sent: {step['name']}", details={**preview, "attempt": attempt})
    try:
        result = target_client.send_authorized(
            target,
            path=path,
            method=method,
            payload=body,
            response_path=response_path,
            body_encoding=step.get("body_encoding", "json"),
        )
    except Exception:
        guard.observe_error()
        raise
    guard.observe_response(result.get("status_code"))
    repo.add_tool_event(project_id, tool_run_id, step_id=step["id"], event_type="response.received", title=f"Response received: {step['name']}", details=_response_event(result, attempt))
    assertions_passed = True
    assertion_results: list[dict[str, Any]] = []
    for assertion in step.get("assertions") or []:
        passed, explanation, actual, evaluated = _evaluate_assertion(assertion, result, context)
        if assertion.get("required", True) and not passed:
            assertions_passed = False
        assertion_results.append({
            "type": assertion["type"],
            "label": assertion["label"],
            "role": assertion.get("role") or "evidence",
            "required": assertion.get("required", True),
            "passed": passed,
            "evaluated": evaluated,
            "explanation": explanation,
        })
        if passed:
            assertion_event = "assertion.passed"
            assertion_state = "passed"
        elif not assertion.get("required", True):
            assertion_event = "assertion.not_observed"
            assertion_state = "not observed"
        elif defer_failures:
            assertion_event = "assertion.pending"
            assertion_state = "pending"
        else:
            assertion_event = "assertion.failed"
            assertion_state = "failed"
        repo.add_tool_event(
            project_id, tool_run_id, step_id=step["id"],
            event_type=assertion_event,
            title=f"Assertion {assertion_state}: {assertion['label']}",
            details={"assertion": assertion, "explanation": explanation, "actual": actual, "required": assertion.get("required", True), "role": assertion.get("role") or "evidence", "evaluated": evaluated},
        )
    context.setdefault("assertion_results", {})[step["id"]] = {
        "attempt": attempt,
        "assertions": assertion_results,
    }
    for name, selector in (step.get("captures") or {}).items():
        try:
            captured = _capture_value(selector, result)
        except (KeyError, IndexError, TypeError) as exc:
            raise ToolExecutionError(f"step {step['id']} could not capture {name} from {selector}") from exc
        context.setdefault("captures", {})[name] = captured
        context[name] = captured
        repo.add_tool_event(project_id, tool_run_id, step_id=step["id"], event_type="value.captured", title=f"Captured workflow value: {name}", details={"name": name, "selector": selector, "value": captured})
    return result, assertions_passed


def _execute_workflow(repo: Repository, *, project_id: str, run: dict[str, Any], target: dict[str, Any], context: dict[str, Any], guard: ExecutionGuard, target_client: TargetClient) -> None:
    for step in run["definition"]["steps"]:
        guard.checkpoint()
        repo.add_tool_event(project_id, run["id"], step_id=step["id"], event_type="step.started", title=f"Step started: {step['name']}", details={"type": step["type"]})
        if step["type"] == "interaction":
            token = str(render_template(step["token"], context))
            deadline = time.monotonic() + int(step.get("wait_seconds") or 0)
            seen = repo.interaction_seen(project_id, token)
            while not seen and time.monotonic() < deadline:
                guard.checkpoint()
                time.sleep(0.25)
                seen = repo.interaction_seen(project_id, token)
            repo.add_tool_event(project_id, run["id"], step_id=step["id"], event_type="assertion.passed" if seen else "assertion.failed", title=f"Interaction {'observed' if seen else 'not observed'}: {step['name']}", details={"token": token, "required": True})
            context.setdefault("assertion_results", {})[step["id"]] = {
                "attempt": 1,
                "assertions": [{
                    "type": "interaction",
                    "label": step["name"],
                    "role": "evidence",
                    "required": True,
                    "passed": seen,
                    "evaluated": True,
                    "explanation": "callback interaction observed" if seen else "callback interaction was not observed",
                }],
            }
            context.setdefault("outcomes", {})[step["id"]] = seen
            if not seen and step.get("stop_on_failure"):
                raise ToolExecutionError(f"required interaction was not observed for step {step['id']}")
            continue
        if step["type"] == "poll":
            passed = False
            maximum_attempts = int(step["max_attempts"])
            for attempt in range(1, maximum_attempts + 1):
                guard.checkpoint()
                _, passed = _execute_http_step(
                    repo,
                    project_id=project_id,
                    tool_run_id=run["id"],
                    target=target,
                    step=step,
                    context=context,
                    guard=guard,
                    target_client=target_client,
                    attempt=attempt,
                    defer_failures=attempt < maximum_attempts,
                )
                if passed:
                    break
                if attempt < int(step["max_attempts"]) and int(step["interval_ms"]):
                    time.sleep(int(step["interval_ms"]) / 1000)
                    guard.checkpoint()
        else:
            _, passed = _execute_http_step(repo, project_id=project_id, tool_run_id=run["id"], target=target, step=step, context=context, guard=guard, target_client=target_client)
        context.setdefault("outcomes", {})[step["id"]] = passed
        if not passed and step.get("stop_on_failure"):
            raise ToolExecutionError(f"required assertions failed for step {step['id']}")


def _execute_campaign(repo: Repository, *, project_id: str, run: dict[str, Any], target: dict[str, Any], context: dict[str, Any], guard: ExecutionGuard, target_client: TargetClient) -> None:
    base = run["definition"]["request"]
    stop_on_match_by = str(run["definition"].get("stop_on_match_by") or "")
    matched_groups: set[str] = set()
    reproduction_step_ids = {
        step_id
        for outcome in run["definition"].get("security_outcomes") or []
        for step_id in outcome.get("reproduction_step_ids") or []
    }
    for index, item in enumerate(run["definition"]["payloads"], start=1):
        guard.checkpoint()
        payload_context = {**context, "payload": item.get("value"), "payload_item": item, "payload_index": index}
        overrides = {key: item[key] for key in ("path", "method", "body", "response_path", "assertions") if key in item}
        step = _normalize_step({**base, **overrides, "id": f"campaign_{index}", "name": str(item.get("label") or f"Payload {index}")}, index - 1)
        match_group = str(item.get(stop_on_match_by) or "") if stop_on_match_by else ""
        if step["id"] in reproduction_step_ids:
            if not guard.snapshot.get("allow_reproduction"):
                reason = "finding reproduction is not allowed by the approved execution guardrail"
            elif run["definition"].get("bounded_reproduction"):
                reason = "payload is reserved for exact replay of its successful initial strategy"
            else:
                reason = ""
            if reason:
                context.setdefault("outcomes", {})[step["id"]] = (
                    False if run["definition"].get("bounded_reproduction") and guard.snapshot.get("allow_reproduction") else None
                )
                repo.add_tool_event(
                    project_id,
                    run["id"],
                    step_id=step["id"],
                    event_type="campaign.skipped",
                    title=f"Reproduction payload skipped: {step['name']}",
                    details={
                        "match_group": match_group,
                        "reason": reason,
                        "terminal": True,
                    },
                )
                continue
        if match_group and match_group in matched_groups:
            context.setdefault("outcomes", {})[step["id"]] = None
            repo.add_tool_event(
                project_id,
                run["id"],
                step_id=step["id"],
                event_type="campaign.skipped",
                title=f"Payload skipped after group proof: {step['name']}",
                details={"match_group": match_group, "reason": "an earlier payload in this group satisfied every required assertion", "terminal": True},
            )
            continue
        _, passed = _execute_http_step(repo, project_id=project_id, tool_run_id=run["id"], target=target, step=step, context=payload_context, guard=guard, target_client=target_client)
        context.setdefault("outcomes", {})[step["id"]] = passed
        if passed and match_group:
            matched_groups.add(match_group)
        if passed and run["definition"].get("stop_on_match"):
            break
    _execute_bounded_campaign_reproduction(
        repo,
        project_id=project_id,
        run=run,
        target=target,
        context=context,
        guard=guard,
        target_client=target_client,
    )


def _execute_bounded_campaign_reproduction(
    repo: Repository,
    *,
    project_id: str,
    run: dict[str, Any],
    target: dict[str, Any],
    context: dict[str, Any],
    guard: ExecutionGuard,
    target_client: TargetClient,
) -> None:
    """Replay an explicitly paired campaign payload within the approved budget.

    This is deliberately opt-in at both layers: the target-configured campaign
    must declare ``bounded_reproduction`` and ``replay_key`` pairs, and the
    operator guardrail must approve bounded statistical reproduction. Every
    sample remains a separate immutable request/response/assertion event.
    """
    definition = run["definition"]
    snapshot = guard.snapshot
    if not (
        definition.get("bounded_reproduction")
        and snapshot.get("allow_reproduction")
        and snapshot.get("reproduction_mode") == "bounded-statistical"
    ):
        return
    maximum_attempts = max(1, int(snapshot.get("reproduction_max_attempts") or 1))
    if maximum_attempts <= 1:
        return

    payloads = definition["payloads"]
    step_items = {f"campaign_{index}": item for index, item in enumerate(payloads, start=1)}
    base = definition["request"]
    summaries = context.setdefault("campaign_reproduction", {})

    for outcome in definition.get("security_outcomes") or []:
        if str(outcome.get("kind") or "security") != "security":
            continue
        reproduction_ids = list(outcome.get("reproduction_step_ids") or [])
        if not reproduction_ids or any(context.get("outcomes", {}).get(step_id) is True for step_id in reproduction_ids):
            continue
        reproduction_set = set(reproduction_ids)
        initial_groups = [
            group
            for group in outcome.get("required_any_step_groups") or []
            if not set(group).intersection(reproduction_set)
        ]
        matched_initial_ids = [
            step_id
            for group in initial_groups
            for step_id in group
            if context.get("outcomes", {}).get(step_id) is True
        ]
        if not matched_initial_ids:
            continue

        selected_initial_id = ""
        selected_reproduction_id = ""
        selected_replay_key = ""
        for initial_id in matched_initial_ids:
            replay_key = str((step_items.get(initial_id) or {}).get("replay_key") or "")
            if not replay_key:
                continue
            paired = next(
                (
                    step_id
                    for step_id in reproduction_ids
                    if str((step_items.get(step_id) or {}).get("replay_key") or "") == replay_key
                ),
                "",
            )
            if paired:
                selected_initial_id = initial_id
                selected_reproduction_id = paired
                selected_replay_key = replay_key
                break
        if not selected_reproduction_id:
            continue

        prior_summary = next(
            (
                item
                for item in summaries.values()
                if item.get("initial_step_id") == selected_initial_id
                and item.get("reproduction_step_id") == selected_reproduction_id
            ),
            None,
        )
        if prior_summary is not None:
            summaries[outcome["id"]] = prior_summary
            context.setdefault("outcomes", {})[selected_reproduction_id] = bool(prior_summary["threshold_met"])
            continue

        item = step_items[selected_reproduction_id]
        index = int(selected_reproduction_id.split("_", 1)[1])
        overrides = {key: item[key] for key in ("path", "method", "body", "response_path", "assertions") if key in item}
        step = _normalize_step(
            {**base, **overrides, "id": selected_reproduction_id, "name": str(item.get("label") or f"Payload {index}")},
            index - 1,
        )
        samples: list[dict[str, Any]] = []
        for attempt in range(1, maximum_attempts + 1):
            if attempt > 1:
                cooperative_delay(int(snapshot.get("reproduction_delay_ms") or 0), guard.checkpoint)
            payload_context = {
                **context,
                "payload": item.get("value"),
                "payload_item": item,
                "payload_index": index,
            }
            try:
                _, passed = _execute_http_step(
                    repo,
                    project_id=project_id,
                    tool_run_id=run["id"],
                    target=target,
                    step=step,
                    context=payload_context,
                    guard=guard,
                    target_client=target_client,
                    attempt=attempt,
                )
                payload_context.setdefault("outcomes", {})[selected_reproduction_id] = passed
                determinacy = _step_determinacy(payload_context, selected_reproduction_id)
                sample_status = "confirmed" if passed and determinacy["determinate"] else "not-reproduced" if determinacy["determinate"] else "error"
            except TargetError as exc:
                sample_status = "error"
                repo.add_tool_event(
                    project_id,
                    run["id"],
                    step_id=selected_reproduction_id,
                    event_type="campaign.reproduction_sample_error",
                    title=f"Reproduction sample failed: {step['name']}",
                    details={"attempt": attempt, "message": safe_error(exc)},
                )
            samples.append({"sample": attempt, "status": sample_status, "step_id": selected_reproduction_id})
            repo.add_tool_event(
                project_id,
                run["id"],
                step_id=selected_reproduction_id,
                event_type="campaign.reproduction_sample",
                title=f"Reproduction sample {attempt}/{maximum_attempts}: {step['name']}",
                details={"attempt": attempt, "maximum_attempts": maximum_attempts, "status": sample_status},
            )

        summary = reproduction_assessment(
            samples,
            minimum_successes=int(snapshot.get("reproduction_min_successes") or 1),
            minimum_success_rate=float(snapshot.get("reproduction_min_success_rate") or 1.0),
        )
        summary.update({
            "samples": samples,
            "initial_step_id": selected_initial_id,
            "reproduction_step_id": selected_reproduction_id,
            "replay_key": selected_replay_key,
        })
        summaries[outcome["id"]] = summary
        context.setdefault("outcomes", {})[selected_reproduction_id] = bool(summary["threshold_met"])
        repo.add_tool_event(
            project_id,
            run["id"],
            step_id=selected_reproduction_id,
            event_type="campaign.reproduction_completed",
            title=f"Bounded reproduction completed: {outcome['title']}",
            details={key: value for key, value in summary.items() if key != "replay_key"},
        )


def execute_tool_run(repo: Repository, *, project_id: str, tool_run_id: str, target_client: TargetClient, guard: ExecutionGuard | None = None, cancel_event: threading.Event | None = None) -> dict[str, Any]:
    run = repo.get_tool_run(project_id, tool_run_id, include_events=False)
    target = repo.assert_tool_ready(project_id, run["target_id"])
    transport_profile = dict(target.get("transport_config") or {})
    guard = guard or ExecutionGuard(
        repo.get_guardrail(project_id, target["id"]),
        cancel_event=cancel_event,
        min_request_interval_ms=int(transport_profile.get("min_request_interval_ms") or 0),
    )
    requests_at_start = guard.requests
    context: dict[str, Any] = {
        "inputs": run.get("input") or {},
        "captures": {},
        "outcomes": {},
        "assertion_results": {},
        "target": {"id": target["id"], "name": target["name"], "base_url": target["base_url"]},
    }
    repo.add_tool_event(project_id, tool_run_id, step_id="", event_type="tool.started", title=f"{run['kind'].title()} execution started", details={"definition_version": run["definition"].get("version"), "target_id": target["id"]})
    try:
        if run["kind"] == "workflow":
            _execute_workflow(repo, project_id=project_id, run=run, target=target, context=context, guard=guard, target_client=target_client)
        elif run["kind"] == "campaign":
            _execute_campaign(repo, project_id=project_id, run=run, target=target, context=context, guard=guard, target_client=target_client)
        else:
            step = run["definition"]["request"]
            _, passed = _execute_http_step(repo, project_id=project_id, tool_run_id=run["id"], target=target, step=step, context=context, guard=guard, target_client=target_client)
            context["outcomes"][step["id"]] = passed
        context["all_required_assertions_passed"] = all(context["outcomes"].values()) if context["outcomes"] else True
        _record_security_outcomes(repo, project_id=project_id, run=run, context=context)
        context["request_count"] = guard.requests - requests_at_start
        repo.add_tool_event(project_id, tool_run_id, step_id="", event_type="tool.completed", title=f"{run['kind'].title()} execution completed", details={"requests": context["request_count"], "shared_guard_requests": guard.requests, "all_required_assertions_passed": context["all_required_assertions_passed"]})
        return repo.complete_tool_run(project_id, tool_run_id, status="completed", context=context)
    except ExecutionCancelled as exc:
        message = safe_error(exc)
        context["request_count"] = guard.requests - requests_at_start
        repo.add_tool_event(project_id, tool_run_id, step_id="", event_type="tool.cancelled", title="Execution cancelled by the operator", details={"message": message, "requests": context["request_count"], "shared_guard_requests": guard.requests})
        return repo.complete_tool_run(project_id, tool_run_id, status="cancelled", context=context, error=message)
    except GuardrailViolation as exc:
        message = safe_error(exc)
        context["request_count"] = guard.requests - requests_at_start
        repo.add_tool_event(project_id, tool_run_id, step_id="", event_type="tool.blocked", title="Execution stopped by the approved guardrail", details={"message": message, "requests": context["request_count"], "shared_guard_requests": guard.requests})
        return repo.complete_tool_run(project_id, tool_run_id, status="blocked", context=context, error=message)
    except Exception as exc:
        message = safe_error(exc)
        context["request_count"] = guard.requests - requests_at_start
        repo.add_tool_event(project_id, tool_run_id, step_id="", event_type="error", title="Testing tool execution failed", details={"message": message, "requests": context["request_count"], "shared_guard_requests": guard.requests})
        return repo.complete_tool_run(project_id, tool_run_id, status="completed_with_errors", context=context, error=message)
