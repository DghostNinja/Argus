"""Build a deduplicated endpoint inventory from captured requests."""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlsplit

from ..models import Endpoint
from .models import TrafficRecord

_UUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_HEX = re.compile(r"^[0-9a-fA-F]{16,}$")
_TOKEN = re.compile(r"^[A-Za-z0-9._~-]{24,}$")

_AUTH_HEADERS = frozenset(
    {"authorization", "cookie", "x-api-key", "x-auth-token", "x-session-token"}
)

_TAG_KEYWORDS: dict[str, tuple[str, ...]] = {
    "authentication": ("auth", "login", "token", "oauth", "session", "password"),
    "admin": ("admin", "internal", "manage", "console"),
    "account": ("user", "account", "profile", "member", "customer"),
    "transaction": (
        "payment",
        "order",
        "transaction",
        "transfer",
        "wallet",
        "refund",
        "checkout",
        "invoice",
    ),
    "upload": ("upload", "attachment", "file"),
    "export": ("export", "download", "report"),
    "debug": ("debug", "test", "staging"),
    "graphql": ("graphql",),
}


def normalize_path(path: str) -> str:
    parts = [part for part in (path or "/").split("/") if part]
    normalized = []
    for part in parts:
        if part.isdigit():
            normalized.append("{id}")
        elif _UUID.match(part):
            normalized.append("{uuid}")
        elif _HEX.match(part):
            normalized.append("{id}")
        elif _TOKEN.match(part) and any(c.isdigit() for c in part) and any(
            c.isalpha() for c in part
        ):
            normalized.append("{token}")
        else:
            normalized.append(part)
    return "/" + "/".join(normalized) if normalized else "/"


def _tags(path: str, query_keys: list[str], content_type: str | None) -> list[str]:
    haystack = " ".join([path, *query_keys, content_type or ""]).lower()
    found = [
        tag
        for tag, keywords in _TAG_KEYWORDS.items()
        if any(keyword in haystack for keyword in keywords)
    ]
    return sorted(found)


def _is_authenticated(record: TrafficRecord) -> bool:
    for name, value in record.req_headers:
        if name.strip().lower() in _AUTH_HEADERS and value.strip():
            return True
    return False


def build_inventory(records: list[TrafficRecord]) -> list[Endpoint]:
    by_key: dict[str, Endpoint] = {}
    for record in records:
        method = (record.method or "").strip().upper()
        if not method or method == "CONNECT":
            continue
        parsed = urlsplit(record.url)
        scheme = (parsed.scheme or record.scheme or "http").lower()
        host = (parsed.netloc or record.host or "").lower()
        if not host:
            continue
        path = normalize_path(parsed.path or record.path or "/")
        key = f"{method} {scheme}://{host}{path}"
        query_keys = sorted(parse_qs(parsed.query, keep_blank_values=True).keys())

        endpoint = by_key.get(key)
        if endpoint is None:
            endpoint = Endpoint(
                key=key,
                method=method,
                scheme=scheme,
                host=host,
                path=path,
                first_seen=record.started,
                last_seen=record.started,
            )
            by_key[key] = endpoint
        endpoint.first_seen = min(endpoint.first_seen or record.started, record.started)
        endpoint.last_seen = max(endpoint.last_seen, record.started)
        endpoint.query_params = sorted(set(endpoint.query_params) | set(query_keys))
        if record.status is not None:
            endpoint.status_codes = sorted(set(endpoint.status_codes) | {record.status})
        if record.content_type:
            endpoint.content_types = sorted(
                set(endpoint.content_types) | {record.content_type}
            )
        if record.id not in endpoint.sample_ids and len(endpoint.sample_ids) < 10:
            endpoint.sample_ids.append(record.id)
        endpoint.auth = endpoint.auth or _is_authenticated(record)
        endpoint.sensitive_tags = sorted(
            set(endpoint.sensitive_tags)
            | set(_tags(path, query_keys, record.content_type))
        )

    return [by_key[key] for key in sorted(by_key)]
