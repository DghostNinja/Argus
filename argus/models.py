"""Assessment data model. Everything persisted here is non-secret by design."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class AssessmentState(str, Enum):
    CREATED = "created"
    CONFIGURED = "configured"
    DEVICE_READY = "device_ready"
    INSTALLED = "installed"
    EXPLORED = "explored"
    TESTING = "testing"
    REPORTED = "reported"
    STOPPED = "stopped"


class Target(BaseModel):
    package: str | None = None
    apk_path: str | None = None
    apk_sha256: str | None = None
    device: str | None = None
    allowed_hosts: list[str] = Field(default_factory=list)
    allow_production: bool = False


class Step(BaseModel):
    ts: str = Field(default_factory=utc_now)
    action: str
    detail: dict = Field(default_factory=dict)


class Endpoint(BaseModel):
    key: str
    method: str
    scheme: str
    host: str
    path: str
    query_params: list[str] = Field(default_factory=list)
    status_codes: list[int] = Field(default_factory=list)
    content_types: list[str] = Field(default_factory=list)
    sample_ids: list[int] = Field(default_factory=list)
    auth: bool = False
    sensitive_tags: list[str] = Field(default_factory=list)
    first_seen: int = 0
    last_seen: int = 0


SEVERITIES = ("critical", "high", "medium", "low", "info")
CONFIDENCES = ("high", "medium", "low")
FINDING_STATUSES = ("potential", "confirmed", "rejected")


class Finding(BaseModel):
    id: str
    title: str
    severity: str
    confidence: str
    status: str = "potential"
    endpoint: str | None = None
    description: str = ""
    evidence: list[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=utc_now)
    updated_at: str = Field(default_factory=utc_now)


class Assessment(BaseModel):
    id: str
    name: str
    state: AssessmentState = AssessmentState.CREATED
    paused: bool = False
    stopped: bool = False
    target: Target = Field(default_factory=Target)
    device: str | None = None
    package: str | None = None
    capture_active: bool = False
    capture_port: int | None = None
    endpoints: list[Endpoint] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    created_at: str = Field(default_factory=utc_now)
    updated_at: str = Field(default_factory=utc_now)
    steps: list[Step] = Field(default_factory=list)

    def add_step(self, action: str, detail: dict | None = None) -> None:
        self.updated_at = utc_now()
        self.steps.append(Step(action=action, detail=detail or {}))
        if len(self.steps) > 200:
            self.steps = self.steps[-200:]
