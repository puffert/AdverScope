from __future__ import annotations

import re


_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----",
    re.IGNORECASE,
)
_HEADER_SECRET = re.compile(
    r"(?im)^((?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|x-auth-token)\s*:\s*)([^\r\n]+)",
)
_JSON_SECRET = re.compile(
    r'(?i)(["\'](?:password|passwd|secret|token|api[_-]?key|client_secret)["\']\s*:\s*["\'])(.*?)(["\'])'
)
_QUERY_SECRET = re.compile(
    r"(?i)([?&](?:access_token|token|api[_-]?key|key|secret|password)=)([^&#\s;,]+)"
)
_INLINE_SECRET = re.compile(
    r"(?i)\b((?:access_token|password|passwd|secret|token|api[_-]?key|client_secret)\s*[=:]\s*)([^\s,;]+)"
)
_BEARER_SECRET = re.compile(r"(?i)\b(Bearer\s+)([A-Za-z0-9._~+/=-]{12,})")
_JWT_SECRET = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_PROVIDER_SECRET = re.compile(
    r"\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{16,})\b"
)


def _redact_keyed_secret(match: re.Match[str]) -> str:
    existing = match.group(2).casefold()
    if existing in {"[redacted]", "%5bredacted%5d"}:
        return match.group(0)
    return match.group(1) + "[REDACTED]"


def redact_text(value: str, limit: int = 20000) -> str:
    """Redact common credentials before anything is persisted or displayed."""
    text = (value or "")[:limit]
    text = _PRIVATE_KEY.sub("[REDACTED PRIVATE KEY]", text)
    text = _HEADER_SECRET.sub(r"\1[REDACTED]", text)
    text = _JSON_SECRET.sub(r"\1[REDACTED]\3", text)
    text = _QUERY_SECRET.sub(_redact_keyed_secret, text)
    text = _INLINE_SECRET.sub(_redact_keyed_secret, text)
    text = _BEARER_SECRET.sub(r"\1[REDACTED]", text)
    text = _JWT_SECRET.sub("[REDACTED JWT]", text)
    text = _PROVIDER_SECRET.sub("[REDACTED TOKEN]", text)
    return text


def safe_error(error: BaseException | str) -> str:
    return redact_text(str(error), 500)
