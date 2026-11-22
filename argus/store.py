"""Assessment storage with strict path handling and least-privilege permissions."""

from __future__ import annotations

import json
import os
import re
import uuid
from pathlib import Path

from .errors import ValidationError
from .models import Assessment, utc_now
from .redact import redact_obj

_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]")
_MAX_NAME = 120


def _valid_id(assessment_id: str) -> str:
    if not isinstance(assessment_id, str) or not _ID_RE.match(assessment_id):
        raise ValidationError("invalid assessment id")
    return assessment_id


def _safe_name(name: str) -> str:
    if not isinstance(name, str) or not name.strip():
        raise ValidationError("evidence name is empty")
    if name.strip() in {".", ".."}:
        raise ValidationError("invalid evidence name")
    cleaned = _SAFE_NAME_RE.sub("_", name.strip())
    cleaned = re.sub(r"\.{2,}", "_", cleaned)
    cleaned = cleaned.lstrip(".")[:_MAX_NAME]
    if not cleaned or cleaned in {".", ".."}:
        raise ValidationError("invalid evidence name")
    return cleaned


def _inside(base: Path, target: Path) -> bool:
    try:
        target.resolve().relative_to(base.resolve())
        return True
    except ValueError:
        return False


class AssessmentStore:
    def __init__(self, root: Path):
        self.root = Path(root).expanduser()
        self.assessments_dir = self.root / "assessments"

    def _dir(self, assessment_id: str) -> Path:
        aid = _valid_id(assessment_id)
        path = self.assessments_dir / aid
        if not _inside(self.assessments_dir, path):
            raise ValidationError("assessment path escaped the data directory")
        return path

    def create(self, name: str) -> Assessment:
        clean = (name or "").strip()
        if not clean:
            raise ValidationError("assessment name is empty")
        if len(clean) > 200:
            raise ValidationError("assessment name is too long")
        assessment = Assessment(id=uuid.uuid4().hex, name=clean)
        directory = self._dir(assessment.id)
        directory.mkdir(parents=True, mode=0o700, exist_ok=False)
        os.chmod(directory, 0o700)
        self.save(assessment)
        return assessment

    def load(self, assessment_id: str) -> Assessment:
        path = self._dir(assessment_id) / "assessment.json"
        if not path.is_file():
            raise ValidationError(f"assessment not found: {assessment_id}")
        raw = path.read_text(encoding="utf-8")
        assessment = Assessment.model_validate_json(raw)
        if assessment.id != assessment_id:
            raise ValidationError("assessment id mismatch on disk")
        return assessment

    def save(self, assessment: Assessment) -> None:
        directory = self._dir(assessment.id)
        directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        payload = assessment.model_dump_json(indent=2)
        tmp = directory / f".assessment.{uuid.uuid4().hex}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, directory / "assessment.json")
        finally:
            if tmp.exists():
                tmp.unlink(missing_ok=True)

    def list(self) -> list[dict]:
        if not self.assessments_dir.is_dir():
            return []
        items: list[dict] = []
        for entry in self.assessments_dir.iterdir():
            if not entry.is_dir() or not _ID_RE.match(entry.name):
                continue
            try:
                assessment = self.load(entry.name)
            except Exception:
                continue
            items.append(
                {
                    "id": assessment.id,
                    "name": assessment.name,
                    "state": assessment.state.value,
                    "paused": assessment.paused,
                    "stopped": assessment.stopped,
                    "package": assessment.package or assessment.target.package,
                    "device": assessment.device,
                    "created_at": assessment.created_at,
                    "updated_at": assessment.updated_at,
                }
            )
        items.sort(key=lambda item: item["created_at"], reverse=True)
        return items

    def evidence_path(self, assessment_id: str, name: str) -> Path:
        directory = self._dir(assessment_id) / "evidence"
        directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        os.chmod(directory, 0o700)
        path = directory / _safe_name(name)
        if not _inside(directory, path):
            raise ValidationError("evidence path escaped the assessment directory")
        return path

    def write_evidence(self, assessment_id: str, name: str, data: bytes) -> Path:
        path = self.evidence_path(assessment_id, name)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        return path

    def read_evidence(self, assessment_id: str, name: str) -> bytes:
        path = self.evidence_path(assessment_id, name)
        if not path.is_file():
            raise ValidationError(f"evidence not found: {name}")
        return path.read_bytes()

    def append_event(
        self,
        assessment_id: str,
        action: str,
        detail: dict | None = None,
        *,
        sensitive: bool = False,
        extra_patterns: tuple[str, ...] = (),
    ) -> None:
        self.load(assessment_id)
        directory = self._dir(assessment_id)
        payload = {
            "ts": utc_now(),
            "action": action,
            "detail": {} if sensitive else redact_obj(detail or {}, extra_patterns),
        }
        line = json.dumps(payload, ensure_ascii=False)
        path = directory / "events.jsonl"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    def events(self, assessment_id: str, limit: int = 50) -> list[dict]:
        path = self._dir(assessment_id) / "events.jsonl"
        if not path.is_file():
            return []
        limit = max(1, min(int(limit), 500))
        lines = path.read_text(encoding="utf-8").splitlines()[-limit:]
        out: list[dict] = []
        for line in lines:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out
