"""Captured request model, mirroring Barrel's TrafficEntry JSON."""

from __future__ import annotations

import base64

from pydantic import BaseModel, ConfigDict, Field


class TrafficRecord(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: int
    started: int
    method: str
    url: str
    host: str = ""
    path: str = ""
    scheme: str = ""
    status: int | None = None
    state: str = ""
    error: str | None = None
    tls: bool = False
    content_type: str | None = None
    duration_ms: int | None = None
    req_headers: list[tuple[str, str]] = Field(default_factory=list)
    resp_headers: list[tuple[str, str]] = Field(default_factory=list)
    req_body: str | None = None
    resp_body: str | None = None
    req_body_len: int = 0
    resp_body_len: int = 0
    req_body_truncated: bool = False
    resp_body_truncated: bool = False
    req_body_b64: bool = False
    resp_body_b64: bool = False

    def header(self, name: str) -> str | None:
        wanted = name.strip().lower()
        for key, value in self.req_headers:
            if key.strip().lower() == wanted:
                return value
        return None

    def request_body_bytes(self) -> bytes | None:
        return _body_bytes(self.req_body, self.req_body_b64)

    def response_body_bytes(self) -> bytes | None:
        return _body_bytes(self.resp_body, self.resp_body_b64)


def _body_bytes(body: str | None, encoded: bool) -> bytes | None:
    if body is None:
        return None
    if not encoded:
        return body.encode("utf-8", errors="replace")
    try:
        return base64.b64decode(body, validate=False)
    except (ValueError, TypeError):
        return None
