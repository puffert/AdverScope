from __future__ import annotations

import hashlib
import http.cookiejar
import json
import os
import re
import shlex
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any
from urllib.parse import urlparse

from .db import Repository, preview_payload
from .security import redact_text, safe_error


class TargetError(RuntimeError):
    pass


class LegacyMCPChannel:
    """One explicitly authorized MCP 2024-11-05 HTTP+SSE channel.

    The long-lived GET is kept open while JSON-RPC requests are POSTed to the
    endpoint announced by the server. Only same-origin POST routes already in
    the saved target allowlist may be used.
    """

    def __init__(self, *, target: dict[str, Any], response: Any, requested_url: str, response_url: str, endpoint_path: str, initial_raw: str, timeout_seconds: float):
        self.target = target
        self.response = response
        self.requested_url = requested_url
        self.response_url = response_url
        self.endpoint_path = endpoint_path
        self.initial_raw = initial_raw
        self.timeout_seconds = timeout_seconds
        self._consumed = len(initial_raw.encode("utf-8"))

    @staticmethod
    def _read_event_from(response: Any, *, consumed: int, limit: int = 2_000_000) -> tuple[dict[str, str], str, int]:
        event_type = "message"
        event_id = ""
        data_lines: list[str] = []
        raw_lines: list[str] = []
        while True:
            raw_line = response.readline()
            if not raw_line:
                if raw_lines:
                    break
                raise TargetError("legacy MCP SSE stream closed before the expected event")
            consumed += len(raw_line)
            if consumed > limit:
                raise TargetError("legacy MCP SSE evidence exceeded the 2 MB boundary")
            line = raw_line.decode("utf-8", errors="replace")
            raw_lines.append(line)
            normalized = line.rstrip("\r\n")
            if not normalized:
                break
            if normalized.startswith(":"):
                continue
            field, separator, value = normalized.partition(":")
            if separator and value.startswith(" "):
                value = value[1:]
            if field == "event":
                event_type = value or "message"
            elif field == "id":
                event_id = value
            elif field == "data":
                data_lines.append(value)
        return {"event": event_type, "id": event_id, "data": "\n".join(data_lines)}, "".join(raw_lines), consumed

    def read_jsonrpc_with_notifications(
        self,
        expected_id: int | str,
    ) -> tuple[dict[str, Any], str, list[dict[str, Any]]]:
        notifications: list[dict[str, Any]] = []
        retained_raw: list[str] = []
        for _ in range(100):
            event, raw, self._consumed = self._read_event_from(self.response, consumed=self._consumed)
            retained_raw.append(raw)
            if not event.get("data"):
                continue
            try:
                payload = json.loads(event["data"])
            except json.JSONDecodeError:
                continue
            candidates = payload if isinstance(payload, list) else [payload]
            for candidate in candidates:
                if (
                    isinstance(candidate, dict)
                    and candidate.get("jsonrpc") == "2.0"
                    and "id" not in candidate
                    and isinstance(candidate.get("method"), str)
                ):
                    notifications.append(candidate)
                    continue
                if isinstance(candidate, dict) and candidate.get("jsonrpc") == "2.0" and str(candidate.get("id")) == str(expected_id):
                    if "result" not in candidate and "error" not in candidate:
                        raise TargetError("legacy MCP JSON-RPC response contained neither result nor error")
                    return candidate, "".join(retained_raw), notifications
        raise TargetError(f"legacy MCP SSE stream did not return JSON-RPC id {expected_id} within 100 events")

    def read_jsonrpc(self, expected_id: int | str) -> tuple[dict[str, Any], str]:
        response, raw, _notifications = self.read_jsonrpc_with_notifications(expected_id)
        return response, raw

    def close(self) -> None:
        try:
            self.response.close()
        except Exception:
            pass


class ModernMCPSubscriptionChannel:
    """One bounded 2026-07-28 subscriptions/listen response stream."""

    def __init__(self, *, response: Any, consumed: int = 0):
        self.response = response
        self._consumed = consumed

    def read_notifications(
        self,
        *,
        max_events: int,
        stop_methods: set[str] | None = None,
    ) -> tuple[list[dict[str, Any]], str]:
        notifications: list[dict[str, Any]] = []
        raw_parts: list[str] = []
        for _ in range(max_events):
            try:
                event, raw, self._consumed = LegacyMCPChannel._read_event_from(
                    self.response,
                    consumed=self._consumed,
                )
            except (TimeoutError, socket.timeout, OSError):
                break
            raw_parts.append(raw)
            if not event.get("data"):
                continue
            try:
                payload = json.loads(event["data"])
            except json.JSONDecodeError:
                continue
            candidates = payload if isinstance(payload, list) else [payload]
            for candidate in candidates:
                if not (
                    isinstance(candidate, dict)
                    and candidate.get("jsonrpc") == "2.0"
                    and "id" not in candidate
                    and isinstance(candidate.get("method"), str)
                ):
                    continue
                notifications.append(candidate)
                if stop_methods and str(candidate.get("method")) in stop_methods:
                    return notifications, "".join(raw_parts)
        return notifications, "".join(raw_parts)

    def close(self) -> None:
        try:
            self.response.close()
        except Exception:
            pass


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Return redirect responses as evidence instead of following them.

    Authorization is evaluated for one exact origin, method, and route.  The
    standard urllib handler would otherwise issue a second request that has not
    passed that gate and may forward credentials to another origin.
    """

    def redirect_request(self, request: Any, file_pointer: Any, code: int, message: str, headers: Any, new_url: str) -> None:
        return None


HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
_JSON_FIELD = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,79}$")


def _origin(value: str) -> tuple[str, str, int]:
    parsed = urlparse(str(value or ""))
    scheme = parsed.scheme.casefold()
    host = (parsed.hostname or "").casefold()
    if scheme not in {"http", "https"} or not host:
        raise TargetError("target response URL was not an absolute HTTP or HTTPS URL")
    port = parsed.port or (443 if scheme == "https" else 80)
    return scheme, host, port


def _assert_response_boundary(target: dict[str, Any], requested_url: str, response: Any, method: str) -> str:
    """Verify that a transport handler did not move the request out of scope."""
    response_url = str(getattr(response, "geturl", lambda: requested_url)() or requested_url)
    if _origin(response_url) != _origin(str(target.get("base_url") or "")):
        raise TargetError("target response escaped the authorized origin; redirected traffic was not followed")
    parsed = urlparse(response_url)
    if not route_is_authorized(target, parsed.path or "/", method):
        raise TargetError("target response escaped the authorized route allowlist; redirected traffic was not followed")
    return response_url


def _normalized_route_path(value: str) -> str:
    parsed = urlparse(str(value or "/").strip())
    if parsed.scheme or parsed.netloc or str(value).startswith("//"):
        raise ValueError("authorized routes must be relative to the saved target origin")
    path = "/" + (parsed.path or "/").lstrip("/")
    return path.rstrip("/") or "/"


def validate_authorized_routes(
    routes: list[dict[str, Any]] | None,
    *,
    primary_path: str,
    primary_method: str,
    analysis_config: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Normalize the same-origin route allowlist used by testing tools.

    Route templates may contain ``{segment}`` placeholders or a terminal ``*``.
    The saved primary request and enabled token/context routes are always included,
    so the allowlist can narrow additional tooling without breaking the target.
    """
    candidates = list(routes or [])
    candidates.insert(0, {"path": primary_path, "methods": [primary_method], "role": "primary"})
    analysis = analysis_config or {}
    if analysis.get("enabled"):
        candidates.extend([
            {"path": analysis["tokenizer_path"], "methods": [analysis["tokenizer_method"]], "role": "tokenizer"},
            {"path": analysis["context_info_path"], "methods": [analysis["context_info_method"]], "role": "context-info"},
        ])
    normalized: list[dict[str, Any]] = []
    seen: set[tuple[str, tuple[str, ...]]] = set()
    for candidate in candidates:
        if not isinstance(candidate, dict):
            raise ValueError("each authorized route must be an object")
        path = _normalized_route_path(str(candidate.get("path") or "/"))
        raw_methods = candidate.get("methods") or [candidate.get("method") or "GET"]
        if isinstance(raw_methods, str):
            raw_methods = [raw_methods]
        if not isinstance(raw_methods, list) or not raw_methods:
            raise ValueError("authorized route methods must be a non-empty list")
        methods = tuple(dict.fromkeys(str(method).upper() for method in raw_methods))
        if any(method not in HTTP_METHODS for method in methods):
            raise ValueError("authorized routes contain an unsupported HTTP method")
        key = (path, methods)
        if key in seen:
            continue
        seen.add(key)
        normalized.append({
            "path": path[:500],
            "methods": list(methods),
            "role": str(candidate.get("role") or "workflow")[:80],
        })
    if len(normalized) > 100:
        raise ValueError("a target may define at most 100 authorized routes")
    return normalized


def parse_authorized_routes(value: Any) -> list[dict[str, Any]]:
    """Accept route JSON or a friendly one-route-per-line representation."""
    if value in (None, "", []):
        return []
    if isinstance(value, list):
        return value
    text = str(value).strip()
    if not text:
        return []
    if text.startswith("["):
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError("authorized routes must be valid JSON or METHOD /path lines") from exc
        if not isinstance(parsed, list):
            raise ValueError("authorized route JSON must be a list")
        return parsed
    routes: list[dict[str, Any]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        pieces = line.split(None, 1)
        if len(pieces) != 2:
            raise ValueError(f"authorized route line {number} must use METHOD /path")
        methods = [item.strip().upper() for item in pieces[0].split(",") if item.strip()]
        routes.append({"path": pieces[1].strip(), "methods": methods, "role": "workflow"})
    return routes


def route_is_authorized(target: dict[str, Any], path: str, method: str) -> bool:
    if not str(target.get("path") or "").strip() or not str(target.get("method") or "").strip():
        return False
    requested_path = _normalized_route_path(path)
    requested_method = str(method).upper()
    routes = validate_authorized_routes(
        target.get("authorized_routes") or [],
        primary_path=str(target["path"]),
        primary_method=str(target["method"]),
        analysis_config=target.get("analysis_config") or {},
    )
    for route in routes:
        if requested_method not in route["methods"]:
            continue
        pattern = re.escape(route["path"])
        pattern = re.sub(r"\\\{[^{}]+\\\}", r"[^/]+", pattern)
        pattern = pattern.replace(r"\*", ".*")
        if re.fullmatch(pattern, requested_path):
            return True
    return False


def target_url(target: dict[str, Any], path_override: str | None = None) -> str:
    base_url = str(target.get("base_url", "")).strip().rstrip("/")
    path = str(path_override if path_override is not None else target.get("path", "")).strip()
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("target base URL must be an absolute HTTP or HTTPS URL")
    if parsed.username or parsed.password:
        raise ValueError("target URLs must not contain credentials")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("target base URL must contain only the origin; put the complete route in Attack Surface")
    if not path:
        raise ValueError("target path must be configured explicitly in Attack Surface; use / for the origin root")
    if path.startswith("//") or urlparse(path).scheme:
        raise ValueError("target path must be relative to the authorized base URL")
    return base_url + "/" + path.lstrip("/")


def _redacted_url(value: str) -> str:
    """Redact credential- and session-shaped query parameters in retained evidence."""
    parsed = urllib.parse.urlsplit(str(value or ""))
    protected_markers = ("token", "secret", "key", "session", "auth", "credential", "password")
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    safe_query = [
        (key, "[REDACTED]" if any(marker in key.casefold() for marker in protected_markers) else val)
        for key, val in query
    ]
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(safe_query), parsed.fragment))


BODY_ENCODINGS = {"json", "form", "text"}


def _content_type(body_encoding: str) -> str:
    return {
        "json": "application/json",
        "form": "application/x-www-form-urlencoded",
        "text": "text/plain; charset=utf-8",
    }[body_encoding]


def _serialize_request_body(payload: Any, *, method: str, body_encoding: str) -> bytes:
    if method.upper() == "GET":
        return b""
    if body_encoding not in BODY_ENCODINGS:
        raise TargetError(f"unsupported request body encoding: {body_encoding or 'missing'}")
    if body_encoding == "json":
        return json.dumps(payload).encode("utf-8")
    if body_encoding == "form":
        if not isinstance(payload, dict):
            raise TargetError("form request bodies must be JSON objects of field names and values")
        try:
            return urllib.parse.urlencode(payload, doseq=True).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise TargetError(f"form request body could not be encoded: {safe_error(exc)}") from exc
    if not isinstance(payload, str):
        raise TargetError("text request bodies must be strings")
    return payload.encode("utf-8")


def _replay_headers(target: dict[str, Any], *, body_encoding: str = "json") -> dict[str, str]:
    """Return complete request headers while preserving secret references, never values."""
    headers = {"Content-Type": _content_type(body_encoding)}
    protected = {
        "authorization", "proxy-authorization", "cookie", "set-cookie",
        "x-api-key", "api-key", "x-auth-token", "mcp-session-id",
    }
    for key, value in (target.get("headers") or {}).items():
        if not isinstance(value, str):
            continue
        normalized_key = str(key).casefold()
        if value.startswith("env:"):
            environment_name = value[4:].strip()
            value = f"[REDACTED env:{environment_name or 'UNSET'}]"
        elif normalized_key in protected:
            # Protocol-issued session identifiers and caller-supplied protected
            # headers can be literal values in the in-memory transport target.
            # Keep the header name and exact request semantics, never the value.
            value = "[REDACTED]"
        headers[str(key)] = redact_text(value, 20000)
    return headers


def _curl_command(*, method: str, url: str, headers: dict[str, str], serialized_body: str, timeout_seconds: float | None) -> str:
    """Build a copyable Bash curl replay command for the exact HTTP semantics."""
    segments = ["curl --silent --show-error --include", f"--request {shlex.quote(method)}", f"--url {shlex.quote(url)}"]
    if timeout_seconds is not None:
        segments.append(f"--max-time {timeout_seconds:g}")
    for key, value in headers.items():
        segments.append(f"--header {shlex.quote(f'{key}: {value}')}")
    if method.upper() != "GET":
        segments.append(f"--data-raw {shlex.quote(serialized_body)}")
    separator = " " + "\\" + "\n  "
    return separator.join(segments)


def _merge_request_overrides(template: Any, request_overrides: dict[str, Any] | None, allowed_fields: set[str] | None = None) -> Any:
    if not request_overrides:
        return template
    if not isinstance(template, dict):
        raise TargetError("request overrides require a JSON object request template")
    permitted = set(template) | set(allowed_fields or set())
    unknown = sorted(set(request_overrides) - permitted)
    if unknown:
        raise TargetError("request override field is not authorized by the target adapter: " + ", ".join(unknown))
    return {**template, **request_overrides}


def _request_override_fields(target: dict[str, Any]) -> set[str]:
    analysis = target.get("analysis_config") or {}
    conversation = target.get("conversation_config") or {}
    fields = {
        str(analysis.get("context_padding_field") or ""),
        str(analysis.get("history_field") or ""),
        str(conversation.get("history_field") or ""),
    } - {""}
    if ((target.get("evaluation_config") or {}).get("tool_agent") or {}).get("enabled"):
        fields.update({"messages", "tools", "tool_choice", "parallel_tool_calls"})
    return fields


def request_log_preview(target: dict[str, Any], prompt: str, *, timeout_seconds: float | None = None, request_overrides: dict[str, Any] | None = None, path_override: str | None = None, method_override: str | None = None, payload_override: Any = None, body_encoding: str = "json") -> dict[str, Any]:
    """Complete, reproducible request details with environment-backed values withheld."""
    if target.get("kind") == "browser-chatbot":
        browser_profile = target.get("browser_profile") or {}
        outcome_rule = browser_profile.get("outcome_rule") or {}
        payload: Any = {"prompt": prompt}
        method = "BROWSER"
        automation_steps = [
            f"Open {target_url(target)}",
            f"Fill {str(browser_profile.get('input_selector', 'configured input'))}",
            f"Activate {str(browser_profile.get('submit_selector', 'configured submit control'))}",
            f"Read {str(browser_profile.get('response_selector', 'configured response'))}",
        ]
        if outcome_rule.get("enabled"):
            location = str(outcome_rule.get("path") or target.get("path") or "/")
            automation_steps.append(
                f"Compare before/after visible state at {location} using {str(outcome_rule.get('selector') or 'configured outcome selector')} and proof rule {str(outcome_rule.get('id') or 'configured outcome')}"
            )
        return {
            "runner": "playwright-browser",
            "method": method,
            "url": target_url(target),
            "header_names": [],
            "headers": {},
            "payload": payload,
            "request_body": prompt,
            "automation_steps": automation_steps,
        }
    else:
        if body_encoding not in BODY_ENCODINGS:
            raise TargetError(f"unsupported request body encoding: {body_encoding or 'missing'}")
        request_template = target.get("request_template")
        if payload_override is None and not request_template:
            raise TargetError("target request template is not configured in Attack Surface")
        payload = payload_override if payload_override is not None else preview_payload(request_template, prompt)
        payload = _merge_request_overrides(payload, request_overrides, _request_override_fields(target))
        method = str(method_override or target.get("method") or "").upper()
        if method not in HTTP_METHODS:
            raise TargetError("target HTTP method is not configured in Attack Surface")
    url = target_url(target, path_override)
    evidence_url = _redacted_url(url)
    headers = _replay_headers(target, body_encoding=body_encoding)
    request_body_bytes = _serialize_request_body(payload, method=method, body_encoding=body_encoding)
    request_body = request_body_bytes.decode("utf-8")
    return {
        "runner": "python-urllib",
        "method": method,
        "url": evidence_url,
        "header_names": sorted(headers.keys()),
        "headers": headers,
        "payload": payload,
        "body_encoding": body_encoding,
        "request_body": request_body,
        "curl_command": _curl_command(method=method, url=evidence_url, headers=headers, serialized_body=request_body, timeout_seconds=timeout_seconds),
    }


def validate_browser_profile(profile: dict[str, Any] | None) -> dict[str, Any]:
    profile = profile or {}
    required = ("input_selector", "submit_selector", "response_selector")
    cleaned = {key: str(profile.get(key, "")).strip()[:500] for key in required}
    if any(not cleaned[key] for key in required):
        raise ValueError("browser targets require input, submit, and response selectors")
    cleaned["streaming_selector"] = str(profile.get("streaming_selector", "")).strip()[:500]
    cleaned["completion_selector"] = str(profile.get("completion_selector", "")).strip()[:500]
    raw_transient_patterns = profile.get("transient_response_patterns") or []
    if isinstance(raw_transient_patterns, str):
        raw_transient_patterns = raw_transient_patterns.splitlines()
    if not isinstance(raw_transient_patterns, list):
        raise ValueError("browser transient response patterns must be a list or newline-separated text")
    transient_patterns: list[str] = []
    for raw_pattern in raw_transient_patterns:
        pattern = str(raw_pattern or "").strip()
        if not pattern:
            continue
        if len(pattern) > 200:
            raise ValueError("browser transient response patterns may not exceed 200 characters")
        try:
            re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            raise ValueError("browser transient response patterns must be valid regular expressions") from exc
        if pattern not in transient_patterns:
            transient_patterns.append(pattern)
    if len(transient_patterns) > 20:
        raise ValueError("browser targets may define at most 20 transient response patterns")
    cleaned["transient_response_patterns"] = transient_patterns
    try:
        response_stability_ms = int(profile.get("response_stability_ms"))
    except (TypeError, ValueError) as exc:
        raise ValueError("browser targets require an explicit stable-response window") from exc
    cleaned["response_stability_ms"] = max(300, min(10000, response_stability_ms))
    cleaned["persistent_session"] = bool(profile.get("persistent_session", True))
    cleaned["full_page"] = bool(profile.get("full_page", False))
    navigation_transport = str(profile.get("navigation_transport") or "auto").strip().casefold()
    if navigation_transport not in {"auto", "http1"}:
        raise ValueError("browser navigation transport must be auto or http1")
    cleaned["navigation_transport"] = navigation_transport
    cleaned["viewport_width"] = max(800, min(2560, int(profile.get("viewport_width", 1440))))
    cleaned["viewport_height"] = max(600, min(1600, int(profile.get("viewport_height", 1000))))
    raw_outcome = profile.get("outcome_rule") if isinstance(profile.get("outcome_rule"), dict) else {}
    if raw_outcome.get("enabled"):
        rule_id = str(raw_outcome.get("id") or "").strip()
        label = str(raw_outcome.get("label") or "").strip()
        selector = str(raw_outcome.get("selector") or "").strip()
        expected_text = str(raw_outcome.get("expected_text") or "").strip()
        path = str(raw_outcome.get("path") or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", rule_id):
            raise ValueError("browser outcome rule id may contain only letters, numbers, underscores, and hyphens")
        if not label:
            raise ValueError("browser outcome rule label is required")
        if not selector:
            raise ValueError("browser outcome selector is required")
        if not expected_text:
            raise ValueError("browser outcome expected visible text is required")
        if path:
            parsed_path = urlparse(path)
            if not path.startswith("/") or path.startswith("//") or parsed_path.scheme or parsed_path.netloc or parsed_path.fragment:
                raise ValueError("browser outcome verification path must be a relative path on the authorized target origin")
        raw_techniques = raw_outcome.get("technique_ids") or []
        if not isinstance(raw_techniques, list):
            raise ValueError("browser outcome OWASP technique ids must be a list")
        technique_ids: list[str] = []
        for value in raw_techniques:
            technique_id = str(value or "").strip().upper()
            if not technique_id:
                continue
            if not re.fullmatch(r"[A-Z0-9][A-Z0-9_-]{1,79}", technique_id):
                raise ValueError("browser outcome OWASP technique ids contain an invalid value")
            if technique_id not in technique_ids:
                technique_ids.append(technique_id)
        finding_evidence = bool(raw_outcome.get("finding_evidence"))
        if finding_evidence and not technique_ids:
            raise ValueError("finding-grade browser outcome evidence requires an OWASP technique mapping")
        severity = str(raw_outcome.get("severity") or "high").strip().casefold()
        if severity not in {"low", "medium", "high", "critical"}:
            raise ValueError("browser outcome severity must be low, medium, high, or critical")
        try:
            verification_timeout_ms = int(raw_outcome.get("verification_timeout_ms", 5000))
        except (TypeError, ValueError) as exc:
            raise ValueError("browser outcome proof propagation window must be milliseconds") from exc
        cleaned["outcome_rule"] = {
            "enabled": True,
            "id": rule_id,
            "label": label[:180],
            "path": path[:500],
            "selector": selector[:500],
            "expected_text": expected_text[:500],
            "case_sensitive": bool(raw_outcome.get("case_sensitive")),
            "finding_evidence": finding_evidence,
            "stop_after_match": bool(raw_outcome.get("stop_after_match", True)),
            "severity": severity,
            "technique_ids": technique_ids[:20],
            "verification_timeout_ms": max(0, min(30000, verification_timeout_ms)),
        }
    return cleaned


def validate_analysis_config(config: dict[str, Any] | None) -> dict[str, Any]:
    """Validate optional token/context endpoint roles without granting new origins."""
    config = config or {}
    if not config.get("enabled"):
        return {}
    cleaned: dict[str, Any] = {"enabled": True}
    for key in ("tokenizer_path", "context_info_path"):
        value = str(config.get(key) or "").strip()
        if not value:
            raise ValueError(f"{key.replace('_', ' ')} is required when the token/context adapter is enabled")
        if not value.startswith("/") or value.startswith("//") or urlparse(value).scheme:
            raise ValueError(f"{key.replace('_', ' ')} must be a relative path on the authorized target origin")
        cleaned[key] = value[:300]
    for key in ("tokenizer_method", "context_info_method"):
        method = str(config.get(key) or "").upper().strip()
        if method not in HTTP_METHODS:
            raise ValueError(f"{key.replace('_', ' ')} is required and must be a supported HTTP method")
        cleaned[key] = method
    for key in ("context_padding_field", "history_field", "tokenizer_text_field"):
        value = str(config.get(key) or "").strip()
        if not value:
            raise ValueError(f"{key.replace('_', ' ')} is required when the token/context adapter is enabled")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,79}", value):
            raise ValueError(f"{key.replace('_', ' ')} is not a valid JSON field name")
        cleaned[key] = value
    try:
        ceiling = int(config.get("max_context_padding_chars"))
    except (TypeError, ValueError) as exc:
        raise ValueError("maximum context padding is required and must be a whole number") from exc
    if not 1000 <= ceiling <= 200000:
        raise ValueError("maximum context padding must be between 1,000 and 200,000 characters")
    cleaned["max_context_padding_chars"] = ceiling
    return cleaned


def validate_conversation_config(
    config: dict[str, Any] | None,
    *,
    request_template: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate a target-owned structured request-history adapter."""
    config = config or {}
    if not config.get("enabled"):
        return {}
    cleaned: dict[str, Any] = {"enabled": True, "transport": "structured-request-history"}
    for key in ("history_field", "role_field", "content_field"):
        value = str(config.get(key) or "").strip()
        if not _JSON_FIELD.fullmatch(value):
            raise ValueError(f"{key.replace('_', ' ')} is required and must be a top-level JSON field name")
        cleaned[key] = value
    if cleaned["role_field"] == cleaned["content_field"]:
        raise ValueError("role field and content field must be different")
    for key in ("user_role", "assistant_role"):
        value = str(config.get(key) or "").strip()
        if not value or len(value) > 80:
            raise ValueError(f"{key.replace('_', ' ')} is required and must be at most 80 characters")
        cleaned[key] = value
    try:
        maximum = int(config.get("max_history_turns"))
    except (TypeError, ValueError) as exc:
        raise ValueError("maximum retained history turns is required and must be a whole number") from exc
    if not 1 <= maximum <= 50:
        raise ValueError("maximum retained history turns must be between 1 and 50")
    cleaned["max_history_turns"] = maximum
    template = request_template or {}
    if not isinstance(template, dict):
        raise ValueError("structured request history requires a JSON object request template")
    existing = template.get(cleaned["history_field"])
    if "{{prompt}}" in json.dumps(existing, ensure_ascii=False):
        raise ValueError("history field cannot also be the configured prompt field")
    return cleaned


def _read_limited(response: Any, limit: int = 2_000_000) -> bytes:
    body = response.read(limit + 1)
    if len(body) > limit:
        raise TargetError("target response exceeded the 2 MB evidence limit")
    return body


def _extract_path(body: Any, explicit_path: str) -> tuple[bool, Any]:
    current = body
    for part in explicit_path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return False, None
    return True, current


def _sse_content(event: Any, explicit_path: str) -> str:
    if explicit_path == "$auto":
        return _extract_response(event, "$auto")
    if not explicit_path:
        return json.dumps(event, ensure_ascii=False) if isinstance(event, (dict, list)) else str(event) if event is not None else ""
    found, value = _extract_path(event, explicit_path)
    if not found:
        return ""
    return str(value) if not isinstance(value, (dict, list)) else json.dumps(value, ensure_ascii=False)


def _read_sse(response: Any, response_path: str, limit: int = 2_000_000) -> tuple[str, str, str, str]:
    raw_lines: list[str] = []
    content: list[str] = []
    consumed = 0
    digest = hashlib.sha256()
    completion_signal = "stream-closed"
    try:
        for raw_line in response:
            consumed += len(raw_line)
            if consumed > limit:
                raise TargetError("target response exceeded the 2 MB evidence limit")
            digest.update(raw_line)
            decoded_line = raw_line.decode("utf-8", errors="replace")
            raw_lines.append(decoded_line)
            line = decoded_line.strip()
            if not line or line.startswith(":") or not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if data == "[DONE]":
                completion_signal = "sse-done"
                break
            try:
                content.append(_sse_content(json.loads(data), response_path))
            except json.JSONDecodeError:
                content.append(data)
    except (TimeoutError, OSError) as exc:
        if raw_lines or content:
            raise TargetError("target SSE stream stalled after partial output before completion") from exc
        raise
    return "".join(content), "".join(raw_lines), completion_signal, digest.hexdigest()


def _http_version(response: Any) -> str:
    return {10: "HTTP/1.0", 11: "HTTP/1.1", 20: "HTTP/2"}.get(getattr(response, "version", None), "HTTP")


def _safe_response_headers(response: Any) -> list[dict[str, str]]:
    protected = {
        "authorization", "proxy-authorization", "cookie", "set-cookie",
        "x-api-key", "api-key", "x-auth-token", "mcp-session-id",
    }
    return [
        {"name": str(key), "value": "[REDACTED]" if str(key).lower() in protected else redact_text(str(value), 20000)}
        for key, value in response.headers.items()
    ]


def _raw_http_response(status_line: str, headers: list[dict[str, str]], body: str) -> str:
    header_text = "\r\n".join(f"{header['name']}: {header['value']}" for header in headers)
    return redact_text(f"{status_line}\r\n{header_text}\r\n\r\n{body}", 2_100_000)


def _replace_prompt(value: Any, prompt: str) -> Any:
    if isinstance(value, str):
        if value.startswith("env:"):
            environment_name = value[4:].strip()
            resolved = os.environ.get(environment_name, "")
            if not environment_name or not resolved:
                raise TargetError(f"required request environment variable is not set: {environment_name or '[empty]'}")
            return resolved
        return value.replace("{{prompt}}", prompt)
    if isinstance(value, list):
        return [_replace_prompt(item, prompt) for item in value]
    if isinstance(value, dict):
        return {key: _replace_prompt(item, prompt) for key, item in value.items()}
    return value


def _resolve_headers(headers: dict[str, Any]) -> dict[str, str]:
    resolved: dict[str, str] = {}
    for key, value in headers.items():
        if not isinstance(value, str):
            continue
        if value.startswith("env:"):
            environment_name = value[4:].strip()
            value = os.environ.get(environment_name, "")
            if not environment_name or not value:
                raise TargetError(f"required header environment variable is not set: {environment_name or '[empty]'}")
        resolved[str(key)] = value
    return resolved


def target_runtime_readiness(target: dict[str, Any]) -> dict[str, Any]:
    """Validate environment-backed request values without exposing their contents.

    This is intentionally a local structural check.  It never contacts the
    target and never returns resolved environment values, lengths, hashes, or
    reusable credentials.
    """
    checks: list[dict[str, Any]] = []
    issues: list[dict[str, str]] = []

    protected_authorization_headers = {"authorization", "proxy-authorization"}

    def inspect(value: Any, location: str, *, authorization_header: bool = False) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                inspect(
                    child,
                    f"{location}.{key}" if location else str(key),
                    authorization_header=str(key).casefold() in protected_authorization_headers,
                )
            return
        if isinstance(value, list):
            for index, child in enumerate(value):
                inspect(child, f"{location}[{index}]")
            return
        if not isinstance(value, str) or not value.startswith("env:"):
            return
        environment_name = value[4:].strip()
        resolved = os.environ.get(environment_name, "") if environment_name else ""
        present = bool(environment_name and resolved)
        check = {
            "location": location,
            "environment": environment_name,
            "present": present,
            "requirement": "complete-authorization-value" if authorization_header else "environment-value",
        }
        checks.append(check)
        if not present:
            issues.append({
                "code": "missing_environment_value",
                "location": location,
                "environment": environment_name,
                "message": f"{location} requires environment variable {environment_name or '[empty]'}",
            })
            return
        if authorization_header:
            scheme_and_credentials = resolved.split(None, 1)
            if len(scheme_and_credentials) != 2 or not scheme_and_credentials[0] or not scheme_and_credentials[1].strip():
                issues.append({
                    "code": "authorization_scheme_missing",
                    "location": location,
                    "environment": environment_name,
                    "message": (
                        f"{location} environment variable {environment_name} must contain the complete "
                        "authorization value, including its scheme"
                    ),
                })

    for key, value in (target.get("headers") or {}).items():
        normalized = str(key).casefold()
        inspect(
            value,
            f"header {key}",
            authorization_header=normalized in {"authorization", "proxy-authorization"},
        )
    inspect(target.get("request_template") or {}, "request")
    # Native tool, agentic-trace, MCP, and RAG adapters can define identity-specific
    # environment-backed headers.  Treat those as part of the same preflight
    # boundary so a long assessment never discovers a missing credential only
    # after the primary chatbot adapter has already succeeded.
    inspect(target.get("evaluation_config") or {}, "adapter")
    return {
        "ready": not issues,
        "checks": checks,
        "issues": issues,
    }


def assert_target_runtime_ready(target: dict[str, Any]) -> dict[str, Any]:
    readiness = target_runtime_readiness(target)
    if not readiness["ready"]:
        messages = "; ".join(str(item.get("message") or "runtime value is not ready") for item in readiness["issues"])
        raise ValueError(f"target runtime preflight blocked: {messages}")
    return readiness


def _extract_response(body: Any, explicit_path: str = "") -> str:
    if explicit_path == "$auto":
        common_paths = (
            "choices.0.message.content",
            "choices.0.delta.content",
            "choices.0.text",
            "data.response",
            "data.answer",
            "data.message.content",
            "data.message",
            "result.response",
            "result.answer",
            "result.message.content",
            "result.message",
            "message.content",
            "response",
            "answer",
            "output_text",
            "output",
            "message",
            "content",
            "text",
        )
        for path in common_paths:
            found, current = _extract_path(body, path)
            if found and current is not None and current != "":
                return str(current) if not isinstance(current, (dict, list)) else json.dumps(current, ensure_ascii=False)
        return json.dumps(body, ensure_ascii=False) if isinstance(body, (dict, list)) else str(body)
    if explicit_path:
        found, current = _extract_path(body, explicit_path)
        if not found:
            raise TargetError(f"configured response JSON path was not present: {explicit_path}")
        return str(current) if not isinstance(current, (dict, list)) else json.dumps(current, ensure_ascii=False)
    return json.dumps(body, ensure_ascii=False) if isinstance(body, (dict, list)) else str(body)


def target_request_timeout(target_client: Any, target: dict[str, Any]) -> float | None:
    """Resolve a target timeout without breaking compatible transport adapters.

    Third-party and test transports historically exposed only ``timeout_seconds``.
    Keep that protocol working while allowing the built-in client to apply the
    target-specific timeout retained in its transport profile.
    """
    resolver = getattr(target_client, "timeout_for", None)
    if callable(resolver):
        return resolver(target)
    timeout = getattr(target_client, "timeout_seconds", None)
    return float(timeout) if timeout is not None else None


class TargetClient:
    def __init__(self, timeout_seconds: float = 45.0):
        self.timeout_seconds = timeout_seconds
        self._direct_opener = urllib.request.build_opener(_NoRedirectHandler())
        self._session_openers: dict[str, urllib.request.OpenerDirector] = {}
        self._session_lock = threading.RLock()

    def timeout_for(self, target: dict[str, Any]) -> float:
        """Resolve the retained target-specific timeout or inherit the runtime default."""
        configured = int((target.get("transport_config") or {}).get("request_timeout_seconds") or 0)
        return float(configured) if configured > 0 else float(self.timeout_seconds)

    def send(self, target: dict[str, Any], prompt: str, *, request_overrides: dict[str, Any] | None = None) -> dict[str, Any]:
        return self._send_prompt(target, prompt, request_overrides=request_overrides, opener=None)

    def send_session(self, target: dict[str, Any], prompt: str, *, session_id: str, request_overrides: dict[str, Any] | None = None) -> dict[str, Any]:
        """Send through an isolated cookie-preserving conversation session."""
        key = f"{session_id}:{target.get('project_id', '')}:{target.get('id', '')}"[:500]
        with self._session_lock:
            opener = self._session_openers.get(key)
            if opener is None:
                opener = urllib.request.build_opener(
                    _NoRedirectHandler(),
                    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
                )
                self._session_openers[key] = opener
        return self._send_prompt(target, prompt, request_overrides=request_overrides, opener=opener)

    def send_openai_tools(
        self,
        target: dict[str, Any],
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        tool_choice: Any = "auto",
        parallel_tool_calls: bool = False,
        identity_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Send one OpenAI-compatible tool-calling turn without executing tools."""
        request_target = {
            **target,
            "response_path": "",
            "headers": {**(target.get("headers") or {}), **(identity_headers or {})},
        }
        overrides = {
            "messages": messages,
            "tools": tools,
            "tool_choice": tool_choice,
            "parallel_tool_calls": bool(parallel_tool_calls),
        }
        return self._send_prompt(request_target, "", request_overrides=overrides, opener=None)

    def open_legacy_mcp_channel(
        self,
        target: dict[str, Any],
        *,
        path: str,
        request_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Open an authorized MCP 2024-11-05 HTTP+SSE endpoint stream."""
        if not route_is_authorized(target, path, "GET"):
            raise TargetError(f"GET {_normalized_route_path(path)} is not in the target's authorized route allowlist")
        request_target = {
            **target,
            "response_path": "",
            "headers": {
                **(target.get("headers") or {}),
                **(request_headers or {}),
                "Accept": "text/event-stream",
            },
        }
        url = target_url(target, path)
        headers = _resolve_headers(request_target.get("headers") or {})
        request = urllib.request.Request(url, headers=headers, method="GET")
        timeout_seconds = self.timeout_for(target)
        try:
            response = self._direct_opener.open(request, timeout=timeout_seconds)
        except urllib.error.HTTPError as exc:
            body = _read_limited(exc).decode("utf-8", errors="replace")
            raise TargetError(f"legacy MCP SSE handshake returned HTTP {exc.code}: {redact_text(body, 2000)}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise TargetError(f"legacy MCP SSE handshake failed: {safe_error(exc)}") from exc
        try:
            response_url = _assert_response_boundary(target, url, response, "GET")
            content_type = str(response.headers.get("Content-Type") or "").casefold()
            if "text/event-stream" not in content_type:
                raise TargetError("legacy MCP GET did not return text/event-stream")
            consumed = 0
            initial_parts: list[str] = []
            endpoint_value = ""
            for _ in range(20):
                event, raw, consumed = LegacyMCPChannel._read_event_from(response, consumed=consumed)
                initial_parts.append(raw)
                if event.get("event") == "endpoint" and event.get("data"):
                    endpoint_value = event["data"].strip()
                    break
            if not endpoint_value:
                raise TargetError("legacy MCP SSE handshake did not announce an endpoint event")
            endpoint_url = urllib.parse.urljoin(response_url, endpoint_value)
            parsed_endpoint = urllib.parse.urlparse(endpoint_url)
            if parsed_endpoint.username or parsed_endpoint.password or _origin(endpoint_url) != _origin(str(target.get("base_url") or "")):
                raise TargetError("legacy MCP endpoint event escaped the authorized target origin")
            endpoint_path = (parsed_endpoint.path or "/") + (f"?{parsed_endpoint.query}" if parsed_endpoint.query else "")
            if not route_is_authorized(target, parsed_endpoint.path or "/", "POST"):
                raise TargetError("legacy MCP endpoint event referenced a POST route outside the target allowlist")
            initial_raw = "".join(initial_parts)
            safe_initial_raw = initial_raw.replace(endpoint_value, _redacted_url(endpoint_value))
            response_headers = _safe_response_headers(response)
            status_line = f"{_http_version(response)} {response.status} {str(getattr(response, 'reason', '') or '').strip()}".rstrip()
            request_record = request_log_preview(
                request_target,
                "",
                timeout_seconds=timeout_seconds,
                path_override=path,
                method_override="GET",
                payload_override={},
            )
            channel = LegacyMCPChannel(
                target=target,
                response=response,
                requested_url=url,
                response_url=response_url,
                endpoint_path=endpoint_path,
                initial_raw=initial_raw,
                timeout_seconds=timeout_seconds,
            )
            return {
                "status_code": str(response.status),
                "status_line": status_line,
                "response": _redacted_url(endpoint_value),
                "raw": redact_text(safe_initial_raw, 2_000_000),
                "raw_http_response": _raw_http_response(status_line, response_headers, redact_text(safe_initial_raw, 2_000_000)),
                "raw_response_sha256": hashlib.sha256(initial_raw.encode("utf-8")).hexdigest(),
                "response_headers": response_headers,
                "request": request_record,
                "captures": [],
                "completion": {"streaming": True, "signal": "legacy-mcp-endpoint-established"},
                "scope_enforcement": {"requested_url": _redacted_url(url), "response_url": _redacted_url(response_url), "redirect_not_followed": False, "redirect_location": ""},
                "schema_error": "",
                "legacy_endpoint_path": endpoint_path,
                "_legacy_mcp_channel": channel,
            }
        except Exception:
            response.close()
            raise

    def open_modern_mcp_subscription(
        self,
        target: dict[str, Any],
        *,
        path: str,
        payload: dict[str, Any],
        request_headers: dict[str, str],
        timeout_seconds: float,
    ) -> dict[str, Any]:
        """Open one authorized, bounded MCP 2026 subscriptions/listen stream."""
        if not route_is_authorized(target, path, "POST"):
            raise TargetError(f"POST {_normalized_route_path(path)} is not in the target's authorized route allowlist")
        request_target = {
            **target,
            "response_path": "",
            "headers": {**(target.get("headers") or {}), **request_headers},
        }
        url = target_url(target, path)
        body = _serialize_request_body(payload, method="POST", body_encoding="json")
        headers = {"Content-Type": "application/json", **_resolve_headers(request_target.get("headers") or {})}
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            response = self._direct_opener.open(request, timeout=timeout_seconds)
        except urllib.error.HTTPError as exc:
            body_text = _read_limited(exc).decode("utf-8", errors="replace")
            raise TargetError(f"modern MCP subscription returned HTTP {exc.code}: {redact_text(body_text, 2000)}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise TargetError(f"modern MCP subscription failed: {safe_error(exc)}") from exc
        try:
            response_url = _assert_response_boundary(target, url, response, "POST")
            content_type = str(response.headers.get("Content-Type") or "").casefold()
            if "text/event-stream" not in content_type:
                raise TargetError("modern MCP subscriptions/listen did not return text/event-stream")
            response_headers = _safe_response_headers(response)
            status_line = f"{_http_version(response)} {response.status} {str(getattr(response, 'reason', '') or '').strip()}".rstrip()
            request_record = request_log_preview(
                request_target,
                "",
                timeout_seconds=timeout_seconds,
                path_override=path,
                method_override="POST",
                payload_override=payload,
            )
            request_record.update({
                "request_body_sha256": hashlib.sha256(body).hexdigest(),
                "request_body_bytes": len(body),
            })
            return {
                "status_code": str(response.status),
                "status_line": status_line,
                "response": "MCP subscription stream established",
                "raw": "",
                "raw_http_response": _raw_http_response(status_line, response_headers, ""),
                "raw_response_sha256": hashlib.sha256(b"").hexdigest(),
                "response_headers": response_headers,
                "request": request_record,
                "captures": [],
                "completion": {"streaming": True, "signal": "modern-mcp-subscription-established"},
                "scope_enforcement": {
                    "requested_url": redact_text(_redacted_url(url), 2000),
                    "response_url": redact_text(_redacted_url(response_url), 2000),
                    "redirect_not_followed": False,
                    "redirect_location": "",
                },
                "schema_error": "",
                "_modern_mcp_subscription": ModernMCPSubscriptionChannel(response=response),
            }
        except Exception:
            response.close()
            raise

    def open_streamable_mcp_event_channel(
        self,
        target: dict[str, Any],
        *,
        path: str,
        request_headers: dict[str, str],
        timeout_seconds: float,
    ) -> dict[str, Any]:
        """Open the authorized GET SSE channel used by retained Streamable HTTP MCP."""
        if not route_is_authorized(target, path, "GET"):
            raise TargetError(f"GET {_normalized_route_path(path)} is not in the target's authorized route allowlist")
        request_target = {
            **target,
            "response_path": "",
            "headers": {
                **(target.get("headers") or {}),
                **request_headers,
                "Accept": "text/event-stream",
            },
        }
        url = target_url(target, path)
        headers = _resolve_headers(request_target.get("headers") or {})
        request = urllib.request.Request(url, headers=headers, method="GET")
        try:
            response = self._direct_opener.open(request, timeout=timeout_seconds)
        except urllib.error.HTTPError as exc:
            body_text = _read_limited(exc).decode("utf-8", errors="replace")
            raise TargetError(f"Streamable MCP event channel returned HTTP {exc.code}: {redact_text(body_text, 2000)}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise TargetError(f"Streamable MCP event channel failed: {safe_error(exc)}") from exc
        try:
            response_url = _assert_response_boundary(target, url, response, "GET")
            content_type = str(response.headers.get("Content-Type") or "").casefold()
            if "text/event-stream" not in content_type:
                raise TargetError("Streamable MCP GET did not return text/event-stream")
            response_headers = _safe_response_headers(response)
            status_line = f"{_http_version(response)} {response.status} {str(getattr(response, 'reason', '') or '').strip()}".rstrip()
            request_record = request_log_preview(
                request_target,
                "",
                timeout_seconds=timeout_seconds,
                path_override=path,
                method_override="GET",
                payload_override={},
            )
            return {
                "status_code": str(response.status),
                "status_line": status_line,
                "response": "MCP Streamable HTTP event channel established",
                "raw": "",
                "raw_http_response": _raw_http_response(status_line, response_headers, ""),
                "raw_response_sha256": hashlib.sha256(b"").hexdigest(),
                "response_headers": response_headers,
                "request": request_record,
                "captures": [],
                "completion": {"streaming": True, "signal": "streamable-mcp-event-channel-established"},
                "scope_enforcement": {
                    "requested_url": redact_text(_redacted_url(url), 2000),
                    "response_url": redact_text(_redacted_url(response_url), 2000),
                    "redirect_not_followed": False,
                    "redirect_location": "",
                },
                "schema_error": "",
                "_streamable_mcp_event_channel": ModernMCPSubscriptionChannel(response=response),
            }
        except Exception:
            response.close()
            raise

    def close_sessions_for_run(self, project_id: str, run_id: str) -> None:
        marker = f"{project_id}:{run_id}:"
        with self._session_lock:
            stale = [key for key in self._session_openers if key.startswith(marker)]
            for key in stale:
                self._session_openers.pop(key, None)

    def _send_prompt(self, target: dict[str, Any], prompt: str, *, request_overrides: dict[str, Any] | None, opener: urllib.request.OpenerDirector | None) -> dict[str, Any]:
        url = target_url(target)
        request_template = target.get("request_template")
        if not request_template:
            raise TargetError("target request template is not configured in Attack Surface")
        template = _replace_prompt(request_template, prompt)
        analysis = target.get("analysis_config") or {}
        template = _merge_request_overrides(template, request_overrides, _request_override_fields(target))
        if analysis.get("enabled"):
            max_padding_chars = int(analysis["max_context_padding_chars"])
            padding_field = str(analysis["context_padding_field"])
            if isinstance(template.get(padding_field), str) and len(template[padding_field]) > max_padding_chars:
                raise TargetError(f"context padding exceeded the configured {max_padding_chars} character ceiling")
        method = str(target.get("method") or "").upper()
        if method not in HTTP_METHODS:
            raise TargetError("target HTTP method is not configured in Attack Surface")
        return self._send_request(target, url=url, method=method, payload=template, prompt=prompt, request_overrides=request_overrides, opener=opener)

    def send_authorized(
        self,
        target: dict[str, Any],
        *,
        path: str,
        method: str,
        payload: Any = None,
        response_path: str = "",
        body_encoding: str = "json",
        request_headers: dict[str, str] | None = None,
        capture_response_headers: tuple[str, ...] = (),
    ) -> dict[str, Any]:
        """Execute one explicitly encoded request constrained by the target route allowlist."""
        method = str(method or "").upper()
        if method not in HTTP_METHODS:
            raise TargetError("authorized requests require an explicit supported HTTP method")
        if not route_is_authorized(target, path, method):
            raise TargetError(f"{method} {_normalized_route_path(path)} is not in the target's authorized route allowlist")
        request_target = {
            **target,
            "response_path": str(response_path or ""),
            "headers": {**(target.get("headers") or {}), **(request_headers or {})},
        }
        actual_payload = {} if payload is None else payload
        return self._send_request(
            request_target,
            url=target_url(target, path),
            method=method,
            payload=actual_payload,
            prompt="",
            path_override=path,
            method_override=method,
            payload_override=actual_payload,
            body_encoding=body_encoding,
            captured_response_header_names=capture_response_headers,
        )

    def request_json(self, target: dict[str, Any], *, path: str, method: str, payload: Any = None) -> dict[str, Any]:
        analysis = target.get("analysis_config") or {}
        authorized_paths = {str(analysis.get("tokenizer_path") or ""), str(analysis.get("context_info_path") or "")} - {""}
        if path not in authorized_paths:
            raise TargetError("auxiliary path is not authorized by the target adapter")
        actual_payload = {} if payload is None else payload
        request_target = {**target, "response_path": ""}
        return self._send_request(request_target, url=target_url(target, path), method=method, payload=actual_payload, prompt="", path_override=path, method_override=method, payload_override=actual_payload)

    def _send_request(self, target: dict[str, Any], *, url: str, method: str, payload: Any, prompt: str, request_overrides: dict[str, Any] | None = None, path_override: str | None = None, method_override: str | None = None, payload_override: Any = None, opener: urllib.request.OpenerDirector | None = None, body_encoding: str = "json", captured_response_header_names: tuple[str, ...] = ()) -> dict[str, Any]:
        request_started_at = time.monotonic()
        timeout_seconds = self.timeout_for(target)
        method = str(method or "").upper()
        if method not in HTTP_METHODS:
            raise TargetError("target requests require an explicit supported HTTP method")
        body = _serialize_request_body(payload, method=method, body_encoding=body_encoding)
        headers = {"Content-Type": _content_type(body_encoding), **_resolve_headers(target.get("headers") or {})}
        request = urllib.request.Request(url, data=None if method == "GET" else body, headers=headers, method=method)
        try:
            try:
                request_opener = opener or self._direct_opener
                opened_response = request_opener.open(request, timeout=timeout_seconds)
            except urllib.error.HTTPError as exc:
                # A redirect or 4xx/5xx answer is still target evidence and must
                # retain its body. Redirects are deliberately never followed.
                opened_response = exc
            with opened_response as response:
                response_url = _assert_response_boundary(target, url, response, method)
                content_type = response.headers.get("Content-Type", "").lower()
                status = str(response.status)
                reason = str(getattr(response, "reason", "") or "").strip()
                status_line = f"{_http_version(response)} {status}{f' {reason}' if reason else ''}"
                capture_names = {str(name).casefold() for name in captured_response_header_names}
                private_response_headers = {
                    str(key).casefold(): str(value)
                    for key, value in response.headers.items()
                    if str(key).casefold() in capture_names
                }
                response_headers = _safe_response_headers(response)
                redirect_location = redact_text(str(response.headers.get("Location", "")), 2000)
                if "text/event-stream" in content_type:
                    text, raw, completion_signal, raw_sha256 = _read_sse(response, str(target.get("response_path") or ""))
                    streaming = True
                else:
                    raw_bytes = _read_limited(response)
                    raw_sha256 = hashlib.sha256(raw_bytes).hexdigest()
                    raw = raw_bytes.decode("utf-8", errors="replace")
                    text = ""
                    completion_signal = "response-closed"
                    streaming = False
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise TargetError(f"target request failed: {safe_error(exc)}") from exc
        schema_error = ""
        if not streaming:
            try:
                parsed = json.loads(raw)
                try:
                    text = _extract_response(parsed, target.get("response_path", ""))
                except TargetError as exc:
                    # A valid HTTP response with an unexpected schema is still
                    # exact target evidence. Return it to the engine so the raw
                    # status, headers, and body are retained before the case is
                    # marked as an adapter/schema error.
                    schema_error = safe_error(exc)
                    text = ""
            except json.JSONDecodeError:
                if str(target.get("response_path") or "").strip():
                    text = ""
                    schema_error = "target response was not valid JSON for the configured response path"
                else:
                    text = raw
        safe_raw = redact_text(raw, 2_000_000)
        request_record = request_log_preview(
            target,
            prompt,
            timeout_seconds=timeout_seconds,
            request_overrides=request_overrides,
            path_override=path_override,
            method_override=method_override or method,
            payload_override=payload_override if payload_override is not None else payload,
            body_encoding=body_encoding,
        )
        request_record.update({
            "request_body_sha256": hashlib.sha256(body).hexdigest(),
            "request_body_bytes": len(body),
        })
        redirect_not_followed = 300 <= int(status) < 400
        if not redirect_not_followed:
            redirect_location = ""
        return {
            "status_code": status,
            "status_line": status_line,
            "response": redact_text(text, 2_000_000),
            "raw": safe_raw,
            "raw_http_response": _raw_http_response(status_line, response_headers, safe_raw),
            "raw_response_sha256": raw_sha256,
            "response_headers": response_headers,
            "request": request_record,
            "captures": [],
            "completion": {
                "streaming": streaming,
                "signal": "redirect-not-followed" if redirect_not_followed else completion_signal,
                "state": (
                    "redirect-blocked" if redirect_not_followed
                    else "complete" if completion_signal == "sse-done"
                    else "stable-close" if streaming and text
                    else "incomplete" if streaming
                    else "complete"
                ),
            },
            "scope_enforcement": {
                "requested_url": redact_text(_redacted_url(url), 2000),
                "response_url": redact_text(_redacted_url(response_url), 2000),
                "redirect_not_followed": redirect_not_followed,
                "redirect_location": redirect_location,
            },
            "schema_error": schema_error,
            "duration_ms": max(0, int((time.monotonic() - request_started_at) * 1000)),
            # Captured protocol state is intentionally private and must never be
            # copied into run events, evidence, reports, or serialized traces.
            "_private_response_headers": private_response_headers,
        }


def parse_template(value: str, *, require_prompt: bool = True) -> dict[str, Any]:
    try:
        if not value.strip():
            raise ValueError("request template must be configured explicitly in Attack Surface")
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValueError("request template must be valid JSON") from exc
    if not isinstance(parsed, dict):
        raise ValueError("request template must be a JSON object")
    if require_prompt and "{{prompt}}" not in json.dumps(parsed, ensure_ascii=False):
        raise ValueError("request template must contain {{prompt}} in the target-defined prompt field")

    def validate_secrets(item: Any) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                normalized = str(key).lower().replace("-", "_")
                if any(marker in normalized for marker in ("password", "passwd", "secret", "token", "api_key", "apikey")):
                    if isinstance(child, str) and not child.startswith("env:"):
                        raise ValueError(f"secret request field {key} must reference an environment variable using env:VARIABLE_NAME")
                validate_secrets(child)
        elif isinstance(item, list):
            for child in item:
                validate_secrets(child)

    validate_secrets(parsed)
    return parsed


def parse_headers(value: str) -> dict[str, Any]:
    try:
        parsed = json.loads(value) if value.strip() else {}
    except json.JSONDecodeError as exc:
        raise ValueError("headers must be valid JSON") from exc
    if not isinstance(parsed, dict):
        raise ValueError("headers must be a JSON object")
    protected = {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "api-key", "x-auth-token"}
    for key, header_value in parsed.items():
        if str(key).lower() in protected and (not isinstance(header_value, str) or not header_value.startswith("env:")):
            raise ValueError(f"secret header {key} must reference an environment variable using env:VARIABLE_NAME")
    return parsed
