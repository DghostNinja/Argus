"""HTTP replay engine for controlled security tests.

Scope, method and production gates are enforced here so the agent cannot
reach out-of-scope or destructive targets even if it tries. Auth headers are
supplied by the caller (in-memory only); nothing in this module persists
secrets.
"""

from __future__ import annotations

import ipaddress
import json
import re
import time
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, Field

from .config import Config
from .errors import ReplayError, ValidationError
from .redact import redact_headers, redact_text

ALLOWED_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "OPTIONS"})

AUTH_HEADER_NAMES = frozenset(
    {
        "authorization",
        "cookie",
        "x-api-key",
        "x-auth-token",
        "x-csrf-token",
        "x-xsrf-token",
        "x-session-token",
    }
)

_LOCAL_SUFFIXES = (
    ".local",
    ".localhost",
    ".test",
    ".internal",
    ".lan",
    ".home",
    ".localdomain",
    ".intranet",
    ".corp",
)
_TOKEN_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
_MAX_HEADERS = 30
_MAX_HEADER_VALUE = 8192
_MAX_REQUEST_BODY = 65_536
_MAX_RESPONSE_BODY = 65_536
_DIFF_LIMIT = 40


def is_local_host(host: str) -> bool:
    """True for loopback, private IPs and reserved lab suffixes."""
    value = (host or "").strip().lower().rstrip(".")
    if not value:
        return False
    if value == "localhost" or value.endswith(_LOCAL_SUFFIXES):
        return True
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return bool(ip.is_loopback or ip.is_private or ip.is_link_local)


def host_in_scope(host: str, allowed_hosts: list[str]) -> bool:
    value = (host or "").strip().lower().rstrip(".")
    for entry in allowed_hosts:
        pattern = str(entry).strip().lower().rstrip(".")
        if pattern == "*":
            return True
        if pattern.count(":") == 1 and not pattern.startswith("["):
            pattern = pattern.split(":", 1)[0]
        if pattern.startswith("*."):
            suffix = pattern[1:]
            if value.endswith(suffix) and value != suffix[1:]:
                return True
        elif value == pattern:
            return True
    return False


def check_target(host: str, allowed_hosts: list[str], allow_production: bool) -> None:
    if not allowed_hosts:
        raise ValidationError(
            "no allowed_hosts configured; scope the assessment before replay"
        )
    if not host_in_scope(host, allowed_hosts):
        raise ValidationError(f"host {host} is not in allowed_hosts")
    if not is_local_host(host) and not allow_production:
        raise ValidationError(
            f"host {host} is outside the local lab scope; re-run "
            "assessment_configure with allow_production=true to test it, "
            "or scope allowed_hosts to a lab host"
        )


def check_method(method: str) -> str:
    value = str(method or "").strip().upper()
    if value not in ALLOWED_METHODS:
        raise ValidationError(
            f"method {value or '?'} is refused by the engine; allowed: "
            f"{', '.join(sorted(ALLOWED_METHODS))}. Destructive methods are "
            "never replayed."
        )
    return value


def check_headers(headers) -> dict[str, str]:
    if headers is None:
        return {}
    if not isinstance(headers, dict):
        raise ValidationError("headers must be an object of name/value strings")
    if len(headers) > _MAX_HEADERS:
        raise ValidationError(f"too many headers (max {_MAX_HEADERS})")
    out: dict[str, str] = {}
    for name, value in headers.items():
        key = str(name)
        if not _TOKEN_RE.match(key):
            raise ValidationError(f"invalid header name: {key!r}")
        text = str(value)
        if len(text) > _MAX_HEADER_VALUE:
            raise ValidationError(f"header {key} is too long (max {_MAX_HEADER_VALUE})")
        if "\r" in text or "\n" in text:
            raise ValidationError(f"header {key} contains a line break")
        out[key] = text
    return out


def check_body(body: str | None) -> str | None:
    if body is None:
        return None
    if not isinstance(body, str):
        raise ValidationError("body must be a string")
    if len(body.encode("utf-8", errors="replace")) > _MAX_REQUEST_BODY:
        raise ValidationError(f"request body exceeds {_MAX_REQUEST_BODY} bytes")
    return body


class ReplayResult(BaseModel):
    method: str
    url: str
    status: int | None = None
    content_type: str | None = None
    duration_ms: int = 0
    request_headers: dict[str, str] = Field(default_factory=dict)
    request_body: str | None = None
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_body: str | None = None
    body_omitted: bool = False


class ReplayEngine:
    def __init__(
        self, config: Config, transport: httpx.AsyncBaseTransport | None = None
    ):
        self.config = config
        self._transport = transport

    async def send(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: str | None = None,
    ) -> ReplayResult:
        request_headers = dict(headers or {})
        started = time.monotonic()
        try:
            async with httpx.AsyncClient(
                timeout=self.config.call_timeout_s,
                follow_redirects=False,
                transport=self._transport,
            ) as client:
                response = await client.request(
                    method,
                    url,
                    headers=request_headers,
                    content=None if body is None else body.encode("utf-8"),
                )
        except httpx.HTTPError as exc:
            raise ReplayError(
                f"replay request failed: {type(exc).__name__}"
            ) from None
        duration_ms = int((time.monotonic() - started) * 1000)

        raw = response.content[:_MAX_RESPONSE_BODY]
        text: str | None
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = None

        return ReplayResult(
            method=method,
            url=url,
            status=response.status_code,
            content_type=response.headers.get("content-type"),
            duration_ms=duration_ms,
            request_headers=redact_headers(request_headers),
            request_body=None if body is None else redact_text(body),
            response_headers=redact_headers(dict(response.headers)),
            response_body=None if text is None else redact_text(text),
            body_omitted=text is None,
        )


def _try_json(text: str | None):
    if not text:
        return None
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def _short(value, limit: int = 120) -> str:
    try:
        text = json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError):
        text = str(value)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _json_diff(base, var, path: str = "$", out: list | None = None) -> list:
    if out is None:
        out = []
    if len(out) >= _DIFF_LIMIT:
        return out
    if type(base) is not type(var):
        out.append(
            {
                "path": path,
                "op": "changed",
                "baseline": _short(base),
                "variant": _short(var),
            }
        )
        return out
    if isinstance(base, dict):
        for key in sorted(set(base) | set(var)):
            child = f"{path}.{key}"
            if len(out) >= _DIFF_LIMIT:
                break
            if key not in base:
                out.append({"path": child, "op": "added", "variant": _short(var[key])})
            elif key not in var:
                out.append(
                    {"path": child, "op": "removed", "baseline": _short(base[key])}
                )
            else:
                _json_diff(base[key], var[key], child, out)
        return out
    if isinstance(base, list):
        if base != var:
            out.append(
                {
                    "path": path,
                    "op": "changed",
                    "baseline": f"list(len={len(base)})",
                    "variant": f"list(len={len(var)})",
                }
            )
        return out
    if base != var:
        out.append(
            {
                "path": path,
                "op": "changed",
                "baseline": _short(base),
                "variant": _short(var),
            }
        )
    return out


def compare_replay_payloads(baseline: dict, variant: dict) -> dict:
    """Diff two stored replay evidence payloads into a structured verdict."""
    base_resp = baseline.get("response") or {}
    var_resp = variant.get("response") or {}
    base_body = base_resp.get("body") or ""
    var_body = var_resp.get("body") or ""

    notes: list[str] = []
    status_changed = base_resp.get("status") != var_resp.get("status")
    if status_changed:
        notes.append(f"status {base_resp.get('status')} -> {var_resp.get('status')}")

    base_type = base_resp.get("content_type")
    var_type = var_resp.get("content_type")
    if base_type != var_type:
        notes.append(f"content-type {base_type} -> {var_type}")

    json_diff: list[dict] = []
    base_json = _try_json(base_body)
    var_json = _try_json(var_body)
    if base_json is not None and var_json is not None:
        json_diff = _json_diff(base_json, var_json)
        for item in json_diff[:10]:
            notes.append(f"{item['op']} {item['path']}")
    elif base_body != var_body:
        base_lines = base_body.splitlines()
        var_lines = var_body.splitlines()
        removed = [line for line in base_lines if line not in var_lines][:5]
        added = [line for line in var_lines if line not in base_lines][:5]
        for line in removed:
            notes.append(f"removed: {_short(line, 100)}")
        for line in added:
            notes.append(f"added: {_short(line, 100)}")
        if not removed and not added:
            notes.append("body text differs")

    changed = status_changed or base_body != var_body or bool(json_diff)
    return {
        "changed": changed,
        "verdict": "difference detected" if changed else "no difference",
        "status_changed": status_changed,
        "body_length_delta": len(var_body) - len(base_body),
        "baseline": {
            "status": base_resp.get("status"),
            "content_type": base_type,
            "body_length": len(base_body),
            "duration_ms": base_resp.get("duration_ms"),
        },
        "variant": {
            "status": var_resp.get("status"),
            "content_type": var_type,
            "body_length": len(var_body),
            "duration_ms": var_resp.get("duration_ms"),
        },
        "notes": notes[:20],
        "json_diff": json_diff[:20],
    }
