"""Redaction for logs, events and evidence. Keeps secrets out of stored data."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping

SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-csrf-token",
        "x-xsrf-token",
        "x-session-token",
    }
)

_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b")
_BEARER = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}")
_SECRET_PAIR = re.compile(
    r"""(?ix)
    (["']?(?:password|passwd|pwd|secret|token|access_token|refresh_token|
        api[_-]?key|authorization|cookie|session)["']?\s*[:=]\s*)
    ("[^"]*"|'[^']*'|[^\s,&;}\]]+)
    """
)

SENSITIVE_KEYS = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "api_key",
        "apikey",
        "authorization",
        "cookie",
        "session",
        "sessionid",
        "session_id",
    }
)

_MASK = "***"


def _sensitive_key(key) -> bool:
    normalized = str(key).strip().lower().replace("-", "_")
    return normalized in SENSITIVE_KEYS


def redact_text(value: str, extra_patterns: Iterable[str] = ()) -> str:
    if not value:
        return value
    out = _JWT.sub(_MASK, value)
    out = _BEARER.sub(lambda m: f"{m.group(1)} {_MASK}", out)
    out = _SECRET_PAIR.sub(lambda m: f"{m.group(1)}{_MASK}", out)
    for pattern in extra_patterns:
        if not pattern:
            continue
        try:
            out = re.sub(pattern, _MASK, out)
        except re.error:
            continue
    return out


def redact_headers(headers: Mapping[str, str] | Iterable[tuple[str, str]]) -> dict[str, str]:
    items = headers.items() if isinstance(headers, Mapping) else headers
    result: dict[str, str] = {}
    for name, value in items:
        if str(name).strip().lower() in SENSITIVE_HEADERS:
            result[str(name)] = _MASK
        else:
            result[str(name)] = redact_text(str(value))
    return result


def redact_obj(value, extra_patterns: Iterable[str] = ()):
    if isinstance(value, str):
        return redact_text(value, extra_patterns)
    if isinstance(value, Mapping):
        result = {}
        for key, item in value.items():
            if _sensitive_key(key):
                result[key] = _MASK
            else:
                result[key] = redact_obj(item, extra_patterns)
        return result
    if isinstance(value, (list, tuple)):
        return [redact_obj(item, extra_patterns) for item in value]
    return value
