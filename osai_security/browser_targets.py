from __future__ import annotations

import atexit
import hashlib
import json
import shlex
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import AppConfig, ROOT
from .evidence_store import EvidenceStore
from .security import redact_text, safe_error
from .targets import TargetError, request_log_preview, target_url


_PROTECTED_HEADERS = {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "api-key", "x-auth-token"}


def _safe_url(value: Any) -> str:
    """Retain a useful URL while redacting common query-string credentials."""
    from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

    parsed = urlsplit(str(value or ""))
    protected = {"password", "passwd", "secret", "token", "api_key", "apikey", "key", "client_secret"}
    query = [
        (name, "[REDACTED]" if name.casefold().replace("-", "_") in protected else redact_text(item, 2000))
        for name, item in parse_qsl(parsed.query, keep_blank_values=True)
    ]
    host = parsed.hostname or ""
    if parsed.port:
        host = f"{host}:{parsed.port}"
    return urlunsplit((parsed.scheme, host, parsed.path, urlencode(query), ""))[:4000]


def _safe_headers(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {
        str(name)[:200]: "[REDACTED]" if str(name).casefold() in _PROTECTED_HEADERS else redact_text(str(item), 20000)
        for name, item in value.items()
    }


def _safe_failure_diagnostics(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return {
        "requested_url": _safe_url(value.get("requested_url")),
        "final_url": _safe_url(value.get("final_url")),
        "navigation_status": max(0, min(999, int(value.get("navigation_status") or 0))),
        "navigation_status_text": redact_text(str(value.get("navigation_status_text") or ""), 200),
        "content_type": redact_text(str(value.get("content_type") or ""), 200),
        "page_title": redact_text(str(value.get("page_title") or ""), 300),
        "input_selector_matches": max(0, min(1000, int(value.get("input_selector_matches") or 0))),
        "submit_selector_matches": max(0, min(1000, int(value.get("submit_selector_matches") or 0))),
        "selector_wait_ms": max(0, min(300000, int(value.get("selector_wait_ms") or 0))),
    }


def _failure_diagnostics_summary(value: Any) -> str:
    diagnostics = _safe_failure_diagnostics(value)
    if not diagnostics:
        return ""
    return "; ".join([
        f"status={diagnostics['navigation_status'] or 'unavailable'}",
        f"final_url={diagnostics['final_url'] or 'unavailable'}",
        f"title={diagnostics['page_title'] or 'unavailable'}",
        f"content_type={diagnostics['content_type'] or 'unavailable'}",
        f"input_matches={diagnostics['input_selector_matches']}",
        f"submit_matches={diagnostics['submit_selector_matches']}",
        f"selector_wait_ms={diagnostics['selector_wait_ms']}",
    ])


def _browser_curl(request: dict[str, Any], timeout_seconds: float) -> str:
    method = str(request.get("method") or "GET").upper()
    url = _safe_url(request.get("url"))
    pieces = ["curl", "--silent", "--show-error", "--include", "--request", method, "--url", shlex.quote(url), "--max-time", str(max(1, int(timeout_seconds)))]
    for name, value in _safe_headers(request.get("headers")).items():
        pieces.extend(["--header", shlex.quote(f"{name}: {value}")])
    body = redact_text(str(request.get("body") or ""), 2_000_000)
    if method != "GET" and body:
        pieces.extend(["--data-raw", shlex.quote(body)])
    return " ".join(pieces)


def _safe_network_exchanges(value: Any, *, timeout_seconds: float) -> list[dict[str, Any]]:
    exchanges: list[dict[str, Any]] = []
    remaining_body_characters = 3_000_000
    for raw in list(value or [])[:20]:
        if not isinstance(raw, dict):
            continue
        request = raw.get("request") if isinstance(raw.get("request"), dict) else {}
        response = raw.get("response") if isinstance(raw.get("response"), dict) else None
        request_body = redact_text(str(request.get("body") or ""), min(500_000, remaining_body_characters))
        remaining_body_characters = max(0, remaining_body_characters - len(request_body))
        safe_request = {
            "method": str(request.get("method") or "GET")[:20],
            "url": _safe_url(request.get("url")),
            "headers": _safe_headers(request.get("headers")),
            "body": request_body,
            "body_bytes": int(request.get("body_bytes") or 0),
            "body_sha256": str(request.get("body_sha256") or "")[:128],
            "truncated": bool(request.get("truncated")),
        }
        safe_response = None
        if response is not None:
            response_body = redact_text(str(response.get("body") or ""), min(500_000, remaining_body_characters))
            remaining_body_characters = max(0, remaining_body_characters - len(response_body))
            safe_response = {
                "status": int(response.get("status") or 0),
                "status_text": redact_text(str(response.get("status_text") or ""), 500),
                "url": _safe_url(response.get("url")),
                "headers": _safe_headers(response.get("headers")),
                "body": response_body,
                "body_bytes": int(response.get("body_bytes") or 0),
                "body_sha256": str(response.get("body_sha256") or "")[:128],
                "truncated": bool(response.get("truncated")),
                "unavailable": bool(response.get("unavailable")),
            }
        exchanges.append({
            "id": str(raw.get("id") or f"network-{len(exchanges) + 1}")[:120],
            "resource_type": str(raw.get("resource_type") or "unknown")[:80],
            "request": safe_request,
            "response": safe_response,
            "failure": redact_text(str(raw.get("failure") or ""), 1000),
            "curl_command": _browser_curl(safe_request, timeout_seconds),
        })
    return exchanges


def _safe_browser_outcome(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or not value.get("configured"):
        return {}
    rule = value.get("rule") if isinstance(value.get("rule"), dict) else {}

    def observation(raw: Any) -> dict[str, Any]:
        item = raw if isinstance(raw, dict) else {}
        return {
            "selector_matches": max(0, min(1000, int(item.get("selector_matches") or 0))),
            "visible_matches": max(0, min(1000, int(item.get("visible_matches") or 0))),
            "expected_text_present": bool(item.get("expected_text_present")),
            "visible_text_sha256": str(item.get("visible_text_sha256") or "")[:128],
            "checked_url": _safe_url(item.get("checked_url")),
        }

    return {
        "configured": True,
        "rule": {
            "id": str(rule.get("id") or "")[:80],
            "label": redact_text(str(rule.get("label") or ""), 180),
            "path": str(rule.get("path") or "")[:500],
            "selector": str(rule.get("selector") or "")[:500],
            "expected_text": redact_text(str(rule.get("expected_text") or ""), 500),
            "case_sensitive": bool(rule.get("case_sensitive")),
            "finding_evidence": bool(rule.get("finding_evidence")),
            "stop_after_match": bool(rule.get("stop_after_match")),
            "severity": str(rule.get("severity") or "high")[:20],
            "technique_ids": [str(item)[:80] for item in list(rule.get("technique_ids") or [])[:20]],
        },
        "baseline": observation(value.get("baseline")),
        "observed": observation(value.get("observed")),
        "request_contains_expected": bool(value.get("request_contains_expected")),
        "transition_observed": bool(value.get("transition_observed")),
        "conclusive": bool(value.get("conclusive")),
        "verification": {
            "timeout_ms": max(0, min(30000, int((value.get("verification") or {}).get("timeout_ms") or 0))),
            "poll_interval_ms": max(0, min(30000, int((value.get("verification") or {}).get("poll_interval_ms") or 0))),
            "attempts": max(0, min(1000, int((value.get("verification") or {}).get("attempts") or 0))),
            "duration_ms": max(0, min(300000, int((value.get("verification") or {}).get("duration_ms") or 0))),
            "timed_out": bool((value.get("verification") or {}).get("timed_out")),
            "observations": [
                {**observation(item), "elapsed_ms": max(0, min(300000, int((item or {}).get("elapsed_ms") or 0)))}
                for item in list((value.get("verification") or {}).get("observations") or [])[:100]
                if isinstance(item, dict)
            ],
        },
    }


def _safe_page_evidence(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or not value.get("configured"):
        return {}
    return {
        "configured": True,
        "checked_url": _safe_url(value.get("checked_url")),
        "selector": str(value.get("selector") or "")[:500],
        "selector_matches": max(0, min(1000, int(value.get("selector_matches") or 0))),
        "visible_matches": max(0, min(1000, int(value.get("visible_matches") or 0))),
        "expected_text_present": bool(value.get("expected_text_present")),
        "visible_text_sha256": str(value.get("visible_text_sha256") or "")[:128],
    }


@dataclass
class BrowserTargetClient:
    config: AppConfig
    _session_processes: dict[str, subprocess.Popen[str]] = field(default_factory=dict, init=False)
    _target_locks: dict[str, threading.Lock] = field(default_factory=dict, init=False)
    _manager_lock: threading.RLock = field(default_factory=threading.RLock, init=False)

    def __post_init__(self) -> None:
        atexit.register(self.close_sessions)

    @property
    def helper_path(self) -> Path:
        return ROOT / "browser" / "capture.mjs"

    @property
    def session_helper_path(self) -> Path:
        return ROOT / "browser" / "session.mjs"

    def _target_key(self, target: dict[str, Any]) -> str:
        return f"{target['project_id']}:{target['id']}"

    def _target_lock(self, target: dict[str, Any]) -> threading.Lock:
        key = self._target_key(target)
        with self._manager_lock:
            return self._target_locks.setdefault(key, threading.Lock())

    def _session_directory(self, target: dict[str, Any]) -> Path:
        return EvidenceStore(self.config.evidence_root).session_directory(target["project_id"], target["id"])

    def send(
        self,
        target: dict[str, Any],
        prompt: str,
        *,
        output_directory: Path,
        attempt: str,
        page_capture: dict[str, Any] | None = None,
        preflight: bool = False,
    ) -> dict[str, Any]:
        request_started_at = time.monotonic()
        profile = target.get("browser_profile") or {}
        resolved_output_directory = output_directory.resolve()
        result_file = resolved_output_directory / "capture-result.json"
        result_file.unlink(missing_ok=True)
        capture_profile = page_capture if isinstance(page_capture, dict) else {}
        payload = {
            "mode": "preflight" if preflight else "page-evidence" if capture_profile else "chat",
            "url": str(capture_profile.get("url") or target_url(target)),
            "prompt": prompt,
            "capture_selector": str(capture_profile.get("selector") or ""),
            "expected_text": str(capture_profile.get("expected_text") or ""),
            "input_selector": profile.get("input_selector", ""),
            "submit_selector": profile.get("submit_selector", ""),
            "response_selector": profile.get("response_selector", ""),
            "streaming_selector": profile.get("streaming_selector", ""),
            "completion_selector": profile.get("completion_selector", ""),
            "transient_response_patterns": list(profile.get("transient_response_patterns") or []),
            "response_stability_ms": int(profile.get("response_stability_ms", 1200)),
            "full_page": bool(profile.get("full_page", False)),
            "navigation_transport": str(profile.get("navigation_transport") or "auto"),
            "viewport_width": int(profile.get("viewport_width", 1440)),
            "viewport_height": int(profile.get("viewport_height", 1000)),
            "timeout_ms": int(self.config.browser_timeout_seconds * 1000),
            "browser_executable": self.config.browser_executable,
            "output_directory": str(resolved_output_directory),
            "attempt": attempt,
            "user_data_directory": str(self._session_directory(target)) if profile.get("persistent_session", True) else "",
            "outcome_rule": profile.get("outcome_rule") or {},
        }
        with self._target_lock(target):
            try:
                completed = subprocess.run(
                    ["node", str(self.helper_path)],
                    input=json.dumps(payload),
                    capture_output=True,
                    text=True,
                    timeout=self.config.browser_timeout_seconds + 10,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                raise TargetError(f"browser capture failed: {safe_error(exc)}") from exc
        result: dict[str, Any] | None = None
        result_source = "stdout"
        parse_error: json.JSONDecodeError | None = None
        stdout = str(completed.stdout or "").strip()
        if stdout:
            try:
                parsed = json.loads(stdout)
                if isinstance(parsed, dict):
                    result = parsed
            except json.JSONDecodeError as exc:
                parse_error = exc
        if result is None and result_file.is_file() and not result_file.is_symlink():
            if result_file.stat().st_size > 16_000_000:
                raise TargetError("browser capture result exceeded the configured evidence limit")
            try:
                parsed = json.loads(result_file.read_text(encoding="utf-8"))
                if isinstance(parsed, dict):
                    result = parsed
                    result_source = "result-file"
            except json.JSONDecodeError as exc:
                parse_error = exc
        if result is None:
            if parse_error is not None:
                raise TargetError("browser capture returned invalid output") from parse_error
            result = {}
        if not result.get("ok"):
            failure = result.get("error") or completed.stderr
            if not str(failure or "").strip():
                phase = str(result.get("phase") or "unknown phase")
                failure = f"browser helper exited with code {completed.returncode} during {phase} without structured error details"
            diagnostics = _failure_diagnostics_summary(result.get("diagnostics"))
            if diagnostics:
                failure = f"{failure}; navigation diagnostics: {diagnostics}"
            raise TargetError(f"browser capture failed: {safe_error(failure)}")
        if result_source == "result-file":
            result.setdefault("helper_warnings", []).append({
                "kind": "stdout-missing-result-file-used",
                "returncode": completed.returncode,
                "stderr": safe_error(completed.stderr) if completed.stderr else "",
            })
        if completed.returncode != 0:
            result.setdefault("helper_warnings", []).append({
                "kind": "nonzero-exit-after-structured-success",
                "returncode": completed.returncode,
                "stderr": safe_error(completed.stderr) if completed.stderr else "",
            })
        captures = []
        for capture in result.get("captures") or []:
            file_path = Path(str(capture.get("path", ""))).resolve()
            try:
                file_path.relative_to(output_directory.resolve())
            except ValueError as exc:
                raise TargetError("browser capture escaped its evidence directory") from exc
            if not file_path.is_file() or file_path.stat().st_size < 100:
                raise TargetError("browser capture did not create a valid screenshot")
            captures.append({
                "kind": str(capture.get("kind", "screenshot")),
                "path": file_path,
                "mime_type": "image/png",
                "size_bytes": file_path.stat().st_size,
                "sha256": hashlib.sha256(file_path.read_bytes()).hexdigest(),
                "attempt": attempt,
            })
        raw_result = str(result.get("raw", ""))
        network_exchanges = _safe_network_exchanges(
            result.get("network_exchanges"),
            timeout_seconds=self.config.browser_timeout_seconds,
        )
        raw_scope = result.get("scope_enforcement") if isinstance(result.get("scope_enforcement"), dict) else {}
        blocked_requests = []
        for item in list(raw_scope.get("blocked_requests") or [])[:100]:
            if not isinstance(item, dict):
                continue
            blocked_requests.append({
                "url": _safe_url(item.get("url")),
                "method": str(item.get("method") or "")[:20],
                "resource_type": str(item.get("resource_type") or "")[:80],
                "reason": str(item.get("reason") or "")[:200],
                "captured_after_submit": bool(item.get("captured_after_submit")),
            })
        helper_warnings = []
        for item in list(result.get("helper_warnings") or [])[:10]:
            if not isinstance(item, dict):
                continue
            helper_warnings.append({
                "kind": str(item.get("kind") or "browser-helper-warning")[:120],
                "returncode": int(item.get("returncode") or 0),
                "stderr": safe_error(str(item.get("stderr") or "")),
            })
        request_record = request_log_preview(target, prompt)
        if preflight:
            request_record = {
                "runner": "playwright-browser",
                "method": "GET",
                "url": target_url(target),
                "header_names": [],
                "headers": {},
                "payload": {},
                "request_body": "",
                "automation_steps": [
                    f"Open {target_url(target)} without submitting a message",
                    f"Validate input selector {profile.get('input_selector', '')}",
                    f"Validate submit selector {profile.get('submit_selector', '')}",
                    f"Validate response selector {profile.get('response_selector', '')}",
                ],
            }
        return {
            "status_code": str(result.get("status_code", "browser")),
            "status_line": "BROWSER DOM CAPTURE",
            "response": redact_text(str(result.get("response", "")), 2_000_000),
            "raw": redact_text(raw_result, 2_000_000),
            "raw_http_response": "",
            "raw_response_sha256": hashlib.sha256(raw_result.encode("utf-8")).hexdigest(),
            "response_headers": [],
            "request": request_record,
            "network_exchanges": network_exchanges,
            "captures": captures,
            "completion": result.get("completion") or {},
            "duration_ms": max(0, int((time.monotonic() - request_started_at) * 1000)),
            "preflight": result.get("preflight") or {},
            "browser_outcome": _safe_browser_outcome(result.get("browser_outcome")),
            "page_evidence": _safe_page_evidence(result.get("page_evidence")),
            "helper_warnings": helper_warnings,
            "cleanup_warnings": [safe_error(str(item)) for item in list(result.get("cleanup_warnings") or [])[:10]],
            "scope_enforcement": {
                "authorized_origin": _safe_url(raw_scope.get("authorized_origin")),
                "final_origin": _safe_url(raw_scope.get("final_origin")),
                "blocked_requests": blocked_requests,
            },
        }

    def open_session(self, target: dict[str, Any]) -> dict[str, Any]:
        profile = target.get("browser_profile") or {}
        if target.get("kind") != "browser-chatbot":
            raise ValueError("browser sessions are available only for browser chatbot targets")
        if not target.get("scope_confirmed"):
            raise ValueError("target authorization must be confirmed before opening a browser session")
        if not profile.get("persistent_session", True):
            raise ValueError("persistent session is disabled for this target")
        key = self._target_key(target)
        with self._manager_lock:
            existing = self._session_processes.get(key)
            if existing and existing.poll() is None:
                return {"status": "already-open", "target_id": target["id"], "process_id": existing.pid}
            payload = {
                "url": target_url(target),
                "user_data_directory": str(self._session_directory(target)),
                "browser_executable": self.config.browser_executable,
                "timeout_ms": int(self.config.browser_timeout_seconds * 1000),
                "navigation_transport": str(profile.get("navigation_transport") or "auto"),
            }
            try:
                process = subprocess.Popen(
                    ["node", str(self.session_helper_path)],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                if process.stdin is None:
                    raise OSError("browser session input pipe is unavailable")
                process.stdin.write(json.dumps(payload))
                process.stdin.close()
            except OSError as exc:
                raise TargetError(f"browser session could not be opened: {safe_error(exc)}") from exc
            time.sleep(0.2)
            if process.poll() is not None:
                raise TargetError("browser session process exited before the login window opened")
            self._session_processes[key] = process
            return {"status": "opened", "target_id": target["id"], "process_id": process.pid}

    def close_sessions(self) -> None:
        with self._manager_lock:
            for process in self._session_processes.values():
                if process.poll() is None:
                    process.terminate()
            self._session_processes.clear()
