from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass
from typing import Any

from .transport_reliability import cooperative_delay


class GuardrailViolation(RuntimeError):
    """Raised when an autonomous action would exceed the approved boundary."""


class ExecutionCancelled(GuardrailViolation):
    """Raised when an operator requests a cooperative execution stop."""


def _bounded_number(text: str, patterns: tuple[str, ...], default: int, low: int, high: int) -> int:
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return max(low, min(high, int(match.group(1))))
    return default


def derive_guardrail(scope_text: str) -> dict[str, Any]:
    """Conservatively derive a reviewable draft from rules-of-engagement text."""
    text = scope_text or ""
    lowered = text.casefold()
    max_requests = _bounded_number(
        text,
        (r"(?:maximum|max|limit(?:ed)?\s+to)\s+(\d+)\s+(?:requests|attempts|prompts)", r"(\d+)\s+request\s+limit"),
        50,
        1,
        10000,
    )
    minutes = _bounded_number(text, (r"(?:maximum|max|limit(?:ed)?\s+to)\s+(\d+)\s+minutes?",), 15, 1, 1440)
    hours_match = re.search(r"(?:maximum|max|limit(?:ed)?\s+to)\s+(\d+)\s+hours?", text, re.IGNORECASE)
    runtime = min(86400, int(hours_match.group(1)) * 3600) if hours_match else minutes * 60

    def allowed(keywords: tuple[str, ...], prohibited: tuple[str, ...]) -> bool:
        if any(term in lowered for term in prohibited):
            return False
        return any(term in lowered for term in keywords)

    return {
        "max_requests": max_requests,
        "max_runtime_seconds": runtime,
        "max_consecutive_errors": 3,
        "allow_active_recon": allowed(
            ("reconnaissance", "fingerprint", "nmap", "service discovery", "http discovery"),
            ("no reconnaissance", "reconnaissance prohibited", "do not scan", "no scanning"),
        ),
        "allow_multi_turn": allowed(
            ("multi-turn", "multiturn", "conversation testing", "session testing"),
            ("no multi-turn", "single-turn only", "one prompt only"),
        ),
        "max_turns_per_objective": 3,
        "allow_reproduction": not any(term in lowered for term in ("no reproduction", "do not reproduce", "single attempt only")),
        "reproduction_mode": "exact-one",
        "reproduction_max_attempts": 1,
        "reproduction_min_successes": 1,
        "reproduction_min_success_rate": 1.0,
        "reproduction_delay_ms": 0,
        "allow_screenshots": not any(term in lowered for term in ("no screenshots", "screenshots prohibited", "do not capture screenshots")),
        "stop_on_http_5xx": True,
        "blocked_prompt_patterns": [],
        "notes": "Conservative draft derived from the selected scope document. Review every value before approval.",
    }


@dataclass
class ExecutionGuard:
    snapshot: dict[str, Any]
    cancel_event: threading.Event | None = None
    min_request_interval_ms: int = 0

    def __post_init__(self) -> None:
        if self.snapshot.get("status") != "approved":
            raise GuardrailViolation("execution guardrail is not approved")
        self.started = time.monotonic()
        self.requests = 0
        self.consecutive_errors = 0
        self._last_request_started = 0.0
        self.min_request_interval_ms = max(0, min(60_000, int(self.min_request_interval_ms or 0)))
        self._blocked_prompt_patterns: list[tuple[str, re.Pattern[str]]] = []
        for raw_pattern in self.snapshot.get("blocked_prompt_patterns") or []:
            pattern = str(raw_pattern).strip()
            if not pattern:
                continue
            try:
                compiled = re.compile(pattern, re.IGNORECASE)
            except re.error as exc:
                raise GuardrailViolation(f"approved guardrail contains an invalid blocked-prompt pattern: {exc}") from exc
            self._blocked_prompt_patterns.append((pattern, compiled))

    @property
    def remaining_requests(self) -> int:
        """Return unused capacity from the approved request budget."""
        maximum = int(self.snapshot.get("max_requests") or 0)
        return max(0, maximum - self.requests)

    def checkpoint(self) -> None:
        if self.cancel_event is not None and self.cancel_event.is_set():
            raise ExecutionCancelled("execution cancelled by the operator")
        if time.monotonic() - self.started >= int(self.snapshot.get("max_runtime_seconds") or 0):
            raise GuardrailViolation("approved runtime limit reached")

    def blocked_prompt_pattern(self, prompt: str) -> str:
        """Return the approved rule that blocks a candidate, without sending it."""
        for pattern, compiled in self._blocked_prompt_patterns:
            if compiled.search(str(prompt or "")):
                return pattern
        return ""

    def assert_prompt_allowed(self, prompt: str) -> None:
        pattern = self.blocked_prompt_pattern(prompt)
        if pattern:
            raise GuardrailViolation(f"candidate prompt matched approved blocked-prompt pattern: {pattern}")

    def before_request(self, target_id: str, *, operation: str = "assessment", screenshots: bool = False) -> None:
        self.checkpoint()
        if target_id != self.snapshot.get("target_id"):
            raise GuardrailViolation("requested target does not match the approved guardrail target")
        if self.requests >= int(self.snapshot.get("max_requests") or 0):
            raise GuardrailViolation("approved request limit reached")
        if operation == "recon" and not self.snapshot.get("allow_active_recon"):
            raise GuardrailViolation("active reconnaissance is not allowed by the approved guardrail")
        if screenshots and not self.snapshot.get("allow_screenshots"):
            raise GuardrailViolation("screenshots are not allowed by the approved guardrail")
        if self._last_request_started and self.min_request_interval_ms:
            elapsed_ms = (time.monotonic() - self._last_request_started) * 1000
            cooperative_delay(max(0, int(self.min_request_interval_ms - elapsed_ms)), self.checkpoint)
        self.requests += 1
        self._last_request_started = time.monotonic()

    def observe_response(self, status_code: int | None, *, application_error: bool = False) -> None:
        try:
            status_code = int(status_code) if status_code is not None else None
        except (TypeError, ValueError):
            status_code = None
        if application_error:
            self.consecutive_errors += 1
        elif status_code is not None and status_code >= 500:
            self.consecutive_errors += 1
            if self.snapshot.get("stop_on_http_5xx"):
                raise GuardrailViolation(f"stop condition triggered by HTTP {status_code}")
        else:
            self.consecutive_errors = 0
        if self.consecutive_errors >= int(self.snapshot.get("max_consecutive_errors") or 1):
            raise GuardrailViolation("consecutive-error stop condition reached")

    def observe_error(self) -> None:
        self.consecutive_errors += 1
        if self.consecutive_errors >= int(self.snapshot.get("max_consecutive_errors") or 1):
            raise GuardrailViolation("consecutive-error stop condition reached")
