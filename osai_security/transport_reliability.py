from __future__ import annotations

import email.utils
import math
import time
from datetime import datetime, timezone
from typing import Any, Mapping

from .faults import classify_exception, fault_record


TRANSIENT_HTTP_STATUSES = (408, 425, 429, 500, 502, 503, 504)


def normalize_transport_profile(value: Mapping[str, Any] | None) -> dict[str, Any]:
    """Validate target-owned transport behavior without inventing retry policy."""
    raw = dict(value or {})
    enabled = bool(raw.get("enabled", False))
    max_retries = max(0, min(3, int(raw.get("max_retries") or 0)))
    base_delay_ms = max(0, min(30_000, int(raw.get("base_delay_ms") or 250)))
    max_retry_after_ms = max(0, min(30_000, int(raw.get("max_retry_after_ms") or 10_000)))
    min_request_interval_ms = max(0, min(60_000, int(raw.get("min_request_interval_ms") or 0)))
    request_timeout_seconds = max(0, min(1_800, int(raw.get("request_timeout_seconds") or 0)))
    raw_statuses = raw.get("retry_statuses", TRANSIENT_HTTP_STATUSES)
    if not isinstance(raw_statuses, (list, tuple, set)):
        raise ValueError("transport retry statuses must be a list")
    statuses: list[int] = []
    for item in raw_statuses:
        status = int(item)
        if status not in TRANSIENT_HTTP_STATUSES:
            raise ValueError(f"HTTP {status} is not an approved transient retry status")
        if status not in statuses:
            statuses.append(status)
    if enabled and max_retries < 1:
        raise ValueError("enabled transport recovery requires at least one retry")
    return {
        "enabled": enabled,
        "max_retries": max_retries if enabled else 0,
        "replay_safe": bool(raw.get("replay_safe", False)),
        "retry_statuses": sorted(statuses),
        "base_delay_ms": base_delay_ms,
        "honor_retry_after": bool(raw.get("honor_retry_after", True)),
        "max_retry_after_ms": max_retry_after_ms,
        "min_request_interval_ms": min_request_interval_ms,
        "request_timeout_seconds": request_timeout_seconds,
        "require_sse_done": bool(raw.get("require_sse_done", False)),
    }


def _status_code(result: Mapping[str, Any]) -> int | None:
    try:
        return int(result.get("status_code"))
    except (TypeError, ValueError):
        return None


def classify_target_result(result: Mapping[str, Any], profile: Mapping[str, Any]) -> dict[str, Any] | None:
    """Return a stable, non-secret fault record for a retained target response."""
    status = _status_code(result)
    retry_statuses = {int(item) for item in profile.get("retry_statuses") or []}
    if status == 429:
        result_fault = {
            "class": "rate-limit",
            "retryable": bool(profile.get("enabled") and status in retry_statuses),
            "status_code": status,
            "reason": "The target rate-limited the request.",
        }
        result_fault["fault"] = fault_record("target.rate_limit", reason=result_fault["reason"], stage="target.response", retryable=result_fault["retryable"], status_code=status)
        return result_fault
    if status is not None and status >= 400:
        result_fault = {
            "class": "target-http",
            "retryable": bool(profile.get("enabled") and status in retry_statuses),
            "status_code": status,
            "reason": f"The target returned HTTP {status}.",
        }
        result_fault["fault"] = fault_record("target.http", reason=result_fault["reason"], stage="target.response", retryable=result_fault["retryable"], status_code=status)
        return result_fault
    completion = result.get("completion") or {}
    if (
        profile.get("require_sse_done")
        and completion.get("streaming")
        and completion.get("signal") != "sse-done"
    ):
        result_fault = {
            "class": "streaming-incomplete",
            "retryable": bool(profile.get("enabled")),
            "status_code": status,
            "reason": "The SSE stream closed without the configured completion signal.",
        }
        result_fault["fault"] = fault_record("target.streaming_incomplete", reason=result_fault["reason"], stage="target.stream", retryable=result_fault["retryable"], status_code=status)
        return result_fault
    if result.get("schema_error"):
        result_fault = {
            "class": "schema",
            "retryable": False,
            "status_code": status,
            "reason": "The retained response did not match the configured response schema.",
        }
        result_fault["fault"] = fault_record("target.schema", reason=result_fault["reason"], stage="target.response", retryable=False, status_code=status)
        return result_fault
    return None


def classify_target_exception(error: BaseException) -> dict[str, Any]:
    common = classify_exception(error, component="target", stage="target.request")
    category = {
        "browser.navigation": "browser-navigation",
        "target.timeout": "timeout",
        "target.streaming_stall": "streaming-stall",
        "target.streaming_incomplete": "streaming-incomplete",
        "target.schema": "schema",
    }.get(common["id"], "transport")
    return {
        "class": category,
        "retryable": bool(common["retryable"]),
        "status_code": None,
        "reason": "The target exchange failed before a usable response was available.",
        "fault": common,
    }


def retry_after_ms(headers: Mapping[str, Any] | list[Mapping[str, Any]] | None, *, maximum_ms: int, now: datetime | None = None) -> int | None:
    raw = ""
    if isinstance(headers, list):
        pairs = ((item.get("name"), item.get("value")) for item in headers if isinstance(item, Mapping))
    else:
        pairs = (headers or {}).items()
    for key, value in pairs:
        if str(key).casefold() == "retry-after":
            raw = str(value).strip()
            break
    if not raw:
        return None
    try:
        seconds = float(raw)
    except ValueError:
        try:
            parsed = email.utils.parsedate_to_datetime(raw)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            current = now or datetime.now(timezone.utc)
            seconds = max(0.0, (parsed - current).total_seconds())
        except (TypeError, ValueError, OverflowError):
            return None
    if not math.isfinite(seconds):
        return None
    return max(0, min(int(maximum_ms), int(math.ceil(seconds * 1000))))


def retry_delay_ms(profile: Mapping[str, Any], *, retry_number: int, result: Mapping[str, Any] | None = None) -> int:
    if result is not None and profile.get("honor_retry_after"):
        directed = retry_after_ms(
            result.get("response_headers") or {},
            maximum_ms=int(profile.get("max_retry_after_ms") or 0),
        )
        if directed is not None:
            return directed
    base = int(profile.get("base_delay_ms") or 0)
    return min(30_000, base * max(1, 2 ** max(0, retry_number - 1)))


def reproduction_assessment(
    attempts: list[Mapping[str, Any]],
    *,
    minimum_successes: int,
    minimum_success_rate: float,
) -> dict[str, Any]:
    """Classify bounded replay samples without turning uncertainty into a pass."""
    total = len(attempts)
    successes = sum(1 for item in attempts if item.get("status") == "confirmed")
    errors = sum(1 for item in attempts if item.get("status") == "error")
    completed = total - errors
    failures = sum(1 for item in attempts if item.get("status") == "not-reproduced")
    rate = successes / completed if completed else 0.0
    threshold_met = successes >= minimum_successes and rate >= minimum_success_rate
    if threshold_met:
        classification = "deterministic" if failures == 0 and errors == 0 else "stochastic-confirmed"
    elif errors and completed < minimum_successes:
        classification = "infrastructure-inconclusive"
    else:
        classification = "non-reproducible"
    return {
        "classification": classification,
        "attempts": total,
        "completed_attempts": completed,
        "successful_attempts": successes,
        "failed_attempts": failures,
        "error_attempts": errors,
        "success_rate": round(rate, 4),
        "minimum_successes": int(minimum_successes),
        "minimum_success_rate": float(minimum_success_rate),
        "threshold_met": threshold_met,
    }


def cooperative_delay(milliseconds: int, checkpoint: Any, *, quantum_ms: int = 100) -> None:
    """Wait in bounded slices so cancellation and runtime limits remain active."""
    remaining = max(0, int(milliseconds)) / 1000.0
    quantum = max(0.01, int(quantum_ms) / 1000.0)
    while remaining > 0:
        checkpoint()
        interval = min(quantum, remaining)
        time.sleep(interval)
        remaining -= interval
    checkpoint()
