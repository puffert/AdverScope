from __future__ import annotations

from typing import Any, Mapping


FAULT_SCHEMA_VERSION = "1.0"

FAULT_TAXONOMY: tuple[dict[str, Any], ...] = (
    {"id": "target.http", "component": "target", "retryable": False, "title": "Target HTTP response"},
    {"id": "target.rate_limit", "component": "target", "retryable": True, "title": "Target rate limit"},
    {"id": "target.timeout", "component": "target", "retryable": True, "title": "Target timeout"},
    {"id": "target.transport", "component": "target", "retryable": True, "title": "Target transport failure"},
    {"id": "target.schema", "component": "target", "retryable": False, "title": "Target response schema mismatch"},
    {"id": "target.streaming_incomplete", "component": "target", "retryable": True, "title": "Incomplete target stream"},
    {"id": "target.streaming_stall", "component": "target", "retryable": True, "title": "Stalled target stream"},
    {"id": "browser.navigation", "component": "browser", "retryable": True, "title": "Browser navigation failure"},
    {"id": "model.http", "component": "model", "retryable": False, "title": "Model-provider HTTP response"},
    {"id": "model.rate_limit", "component": "model", "retryable": True, "title": "Model-provider rate limit"},
    {"id": "model.timeout", "component": "model", "retryable": True, "title": "Model-provider timeout"},
    {"id": "model.transport", "component": "model", "retryable": True, "title": "Model-provider transport failure"},
    {"id": "model.schema", "component": "model", "retryable": False, "title": "Model-provider response schema mismatch"},
    {"id": "evaluator.invalid", "component": "evaluator", "retryable": False, "title": "Evaluator output invalid"},
    {"id": "reproduction.inconclusive", "component": "reproduction", "retryable": False, "title": "Reproduction inconclusive"},
    {"id": "cleanup.failed", "component": "cleanup", "retryable": False, "title": "Cleanup failed"},
    {"id": "guardrail.blocked", "component": "guardrail", "retryable": False, "title": "Guardrail blocked execution"},
    {"id": "cancellation.requested", "component": "cancellation", "retryable": False, "title": "Operator cancellation"},
    {"id": "framework.interrupted", "component": "framework", "retryable": False, "title": "Framework execution interrupted"},
    {"id": "framework.internal", "component": "framework", "retryable": False, "title": "Framework internal failure"},
)

_INDEX = {item["id"]: item for item in FAULT_TAXONOMY}


def fault_record(
    fault_id: str,
    *,
    reason: str,
    stage: str = "",
    retryable: bool | None = None,
    status_code: int | None = None,
) -> dict[str, Any]:
    definition = _INDEX.get(fault_id) or _INDEX["framework.internal"]
    record: dict[str, Any] = {
        "schema_version": FAULT_SCHEMA_VERSION,
        "id": str(definition["id"]),
        "component": str(definition["component"]),
        "stage": str(stage or definition["component"]),
        "retryable": bool(definition["retryable"] if retryable is None else retryable),
        "reason": str(reason)[:1000],
    }
    if status_code is not None:
        record["status_code"] = int(status_code)
    return record


def public_fault_taxonomy() -> dict[str, Any]:
    return {"schema_version": FAULT_SCHEMA_VERSION, "faults": [dict(item) for item in FAULT_TAXONOMY]}


def classify_exception(error: BaseException, *, component: str = "framework", stage: str = "") -> dict[str, Any]:
    text = str(error).casefold()
    if component == "model":
        if "429" in text or "rate limit" in text:
            fault_id = "model.rate_limit"
        elif "timeout" in text or "timed out" in text:
            fault_id = "model.timeout"
        elif "schema" in text or "chat content" in text or "invalid json" in text:
            fault_id = "model.schema"
        elif "http" in text and any(code in text for code in ("400", "401", "403", "404", "422")):
            fault_id = "model.http"
        else:
            fault_id = "model.transport"
    elif component == "target":
        if "stream" in text and any(token in text for token in ("stall", "timed out", "timeout")):
            fault_id = "target.streaming_stall"
        elif "stream" in text and any(token in text for token in ("closed", "incomplete")):
            fault_id = "target.streaming_incomplete"
        elif "browser capture failed" in text and any(token in text for token in ("navigation", "selector", "page")):
            fault_id = "browser.navigation"
        elif "timeout" in text or "timed out" in text:
            fault_id = "target.timeout"
        elif "schema" in text or "json path" in text:
            fault_id = "target.schema"
        else:
            fault_id = "target.transport"
    elif component == "guardrail":
        fault_id = "guardrail.blocked"
    elif component == "cancellation":
        fault_id = "cancellation.requested"
    elif component == "cleanup":
        fault_id = "cleanup.failed"
    elif component == "reproduction":
        fault_id = "reproduction.inconclusive"
    elif component == "evaluator":
        fault_id = "evaluator.invalid"
    else:
        fault_id = "framework.internal"
    return fault_record(fault_id, stage=stage, reason="The operation failed before a usable result was available.")


def fault_for_event(event_type: str, details: Mapping[str, Any] | None = None) -> dict[str, Any] | None:
    normalized = str(event_type or "").casefold()
    detail = dict(details or {})
    if isinstance(detail.get("fault"), Mapping):
        return dict(detail["fault"])
    reason = str(detail.get("message") or detail.get("reason") or detail.get("error") or "Execution event recorded a fault.")
    if "cancellation" in normalized or "cancelled" in normalized:
        return fault_record("cancellation.requested", reason=reason, stage=normalized)
    if "interrupted" in normalized:
        return fault_record("framework.interrupted", reason=reason, stage=normalized)
    if "guardrail" in normalized or normalized in {"safety.stop", "tool.blocked"}:
        return fault_record("guardrail.blocked", reason=reason, stage=normalized)
    if "cleanup" in normalized and any(token in normalized for token in ("error", "failed")):
        return fault_record("cleanup.failed", reason=reason, stage=normalized)
    if "reproduction" in normalized and any(token in normalized for token in ("error", "failed", "inconclusive")):
        return fault_record("reproduction.inconclusive", reason=reason, stage=normalized)
    if normalized in {"error", "recon.error", "target.application_error"} or normalized.endswith(".error"):
        component = "model" if "model" in reason.casefold() else "target" if "target" in reason.casefold() else "framework"
        return classify_exception(RuntimeError(reason), component=component, stage=normalized)
    return None
