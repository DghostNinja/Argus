"""Assessment lifecycle and device actions. All safety checks live here."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from .barrel_client import BarrelClient
from .config import Config
from .errors import ArgusError, StateError, ValidationError
from .explore.ui import UiNode, best_node, find_nodes, parse_hierarchy
from .models import (
    CONFIDENCES,
    FINDING_STATUSES,
    SEVERITIES,
    Assessment,
    AssessmentState,
    Finding,
    utc_now,
)
from .redact import SENSITIVE_HEADERS, redact_text
from .report import (
    REPORT_FILES,
    render_csv,
    render_json,
    render_markdown,
    severity_counts,
    status_counts,
)
from .replay import (
    AUTH_HEADER_NAMES,
    ReplayEngine,
    check_body,
    check_headers,
    check_method,
    check_target,
    compare_replay_payloads,
)
from .store import AssessmentStore
from .traffic.barrel_backend import BarrelBackend
from .traffic.correlate import correlate, windows_from_events
from .traffic.inventory import build_inventory
from .traffic.models import TrafficRecord

_PACKAGE_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_DEVICE_RE = re.compile(r"^[A-Za-z0-9._:-]+$")
_HOST_RE = re.compile(r"^[A-Za-z0-9.*:_-]+$")
_FINDING_ID_RE = re.compile(r"^[0-9a-f]{16}$")
_ACTIVE_STATES = {
    AssessmentState.DEVICE_READY,
    AssessmentState.INSTALLED,
    AssessmentState.EXPLORED,
    AssessmentState.TESTING,
    AssessmentState.REPORTED,
}
_TESTING_STATES = {
    AssessmentState.DEVICE_READY,
    AssessmentState.INSTALLED,
    AssessmentState.EXPLORED,
    AssessmentState.TESTING,
    AssessmentState.REPORTED,
}
_MAX_TEXT = 4096
_MAX_TITLE = 200
_MAX_DESCRIPTION = 4000
_MAX_FINDINGS = 200
_REPORT_STATES = {
    AssessmentState.TESTING,
    AssessmentState.REPORTED,
}


def parse_device_serials(output: str) -> list[str]:
    serials: list[str] = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 2 or parts[0] == "List" or parts[0].startswith("*"):
            continue
        if parts[1] == "device":
            serials.append(parts[0])
    return serials


def _check_package(package: str) -> str:
    value = (package or "").strip()
    if not value or len(value) > 200 or not _PACKAGE_RE.match(value):
        raise ValidationError(
            "invalid package name (letters, digits, '.', '_', '-' only)"
        )
    return value


def _check_device(serial: str) -> str:
    value = (serial or "").strip()
    if not value or len(value) > 200 or not _DEVICE_RE.match(value):
        raise ValidationError("invalid device serial")
    return value


def _check_hosts(hosts: list[str] | None) -> list[str]:
    if not hosts:
        return []
    cleaned: list[str] = []
    for host in hosts:
        value = str(host).strip().lower()
        if not value or len(value) > 253 or not _HOST_RE.match(value):
            raise ValidationError(f"invalid allowed host: {host!r}")
        cleaned.append(value)
    return sorted(set(cleaned))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


_CA_METHODS = frozenset({"user", "system", "bind", "magisk"})


def _redact_header_pairs(
    pairs: list[tuple[str, str]], extra: tuple[str, ...]
) -> list[list[str]]:
    out: list[list[str]] = []
    for name, value in pairs:
        header = str(name)
        if header.strip().lower() in SENSITIVE_HEADERS:
            out.append([header, "***"])
        else:
            out.append([header, redact_text(str(value), extra)])
    return out


def _redact_record(record: TrafficRecord, extra: tuple[str, ...]) -> dict:
    data = record.model_dump()
    data["url"] = redact_text(record.url, extra)
    data["req_headers"] = _redact_header_pairs(record.req_headers, extra)
    data["resp_headers"] = _redact_header_pairs(record.resp_headers, extra)
    if record.req_body is not None:
        data["req_body"] = (
            None if record.req_body_b64 else redact_text(record.req_body, extra)
        )
    if record.resp_body is not None:
        data["resp_body"] = (
            None if record.resp_body_b64 else redact_text(record.resp_body, extra)
        )
    return data


class Orchestrator:
    def __init__(
        self,
        config: Config,
        store: AssessmentStore,
        barrel: BarrelClient,
        replay: ReplayEngine | None = None,
    ):
        self.config = config
        self.store = store
        self.barrel = barrel
        self.replay = replay or ReplayEngine(config)
        # Live auth headers, keyed by (assessment_id, host). Memory only:
        # never persisted, never written to events beyond header names.
        self._auth: dict[tuple[str, str], dict[str, str]] = {}

    # -- lifecycle ---------------------------------------------------------

    async def create(self, name: str) -> Assessment:
        assessment = self.store.create(name)
        self.store.append_event(
            assessment.id,
            "assessment_created",
            {"name": assessment.name},
            extra_patterns=self.config.redact_extra,
        )
        return assessment

    async def configure(
        self,
        assessment_id: str,
        *,
        package: str | None = None,
        apk_path: str | None = None,
        device: str | None = None,
        allowed_hosts: list[str] | None = None,
        allow_production: bool = False,
    ) -> Assessment:
        assessment = self._load(assessment_id)
        if assessment.stopped:
            raise StateError("assessment is stopped")
        if assessment.state not in {AssessmentState.CREATED, AssessmentState.CONFIGURED}:
            raise StateError("configure before starting the assessment")

        if package is not None:
            assessment.target.package = _check_package(package)
        if apk_path is not None:
            path = Path(apk_path).expanduser().resolve()
            if not path.is_file():
                raise ValidationError(f"APK not found: {path}")
            if path.suffix.lower() != ".apk":
                raise ValidationError("APK path must end in .apk")
            assessment.target.apk_path = str(path)
            assessment.target.apk_sha256 = sha256_file(path)
        if device is not None:
            assessment.target.device = _check_device(device)
        if allowed_hosts is not None:
            assessment.target.allowed_hosts = _check_hosts(allowed_hosts)
        assessment.target.allow_production = bool(allow_production)

        if not assessment.target.package and not assessment.target.apk_path:
            raise ValidationError("configure needs a package name or an APK path")

        assessment.state = AssessmentState.CONFIGURED
        detail = {
            "package": assessment.target.package,
            "apk_path": assessment.target.apk_path,
            "device": assessment.target.device,
            "allowed_hosts": assessment.target.allowed_hosts,
        }
        assessment.add_step("configured", detail)
        self.store.save(assessment)
        self.store.append_event(
            assessment_id,
            "assessment_configured",
            detail,
            extra_patterns=self.config.redact_extra,
        )
        return assessment

    async def start(self, assessment_id: str) -> Assessment:
        assessment = self._load(assessment_id)
        self._ensure_active(assessment)
        if assessment.state not in {
            AssessmentState.CONFIGURED,
            AssessmentState.DEVICE_READY,
        }:
            raise StateError("start needs a configured assessment")

        preferred = assessment.target.device
        serial = await self._pick_device(preferred)
        assessment.device = serial
        if assessment.package is None and assessment.target.package:
            assessment.package = assessment.target.package
        assessment.state = AssessmentState.DEVICE_READY
        assessment.add_step("device_ready", {"device": serial})
        self.store.save(assessment)
        self.store.append_event(
            assessment_id,
            "device_ready",
            {"device": serial},
            extra_patterns=self.config.redact_extra,
        )
        return assessment

    async def pause(self, assessment_id: str) -> Assessment:
        assessment = self._load(assessment_id)
        if assessment.stopped:
            raise StateError("assessment is stopped")
        assessment.paused = True
        assessment.add_step("paused")
        self.store.save(assessment)
        self.store.append_event(assessment_id, "paused")
        return assessment

    async def resume(self, assessment_id: str) -> Assessment:
        assessment = self._load(assessment_id)
        if assessment.stopped:
            raise StateError("assessment is stopped")
        assessment.paused = False
        assessment.add_step("resumed")
        self.store.save(assessment)
        self.store.append_event(assessment_id, "resumed")
        return assessment

    async def stop(self, assessment_id: str) -> Assessment:
        assessment = self._load(assessment_id)
        assessment.stopped = True
        assessment.paused = False
        assessment.state = AssessmentState.STOPPED
        assessment.add_step("stopped")
        self.store.save(assessment)
        self.store.append_event(assessment_id, "stopped")
        return assessment

    def status(self, assessment_id: str) -> dict:
        assessment = self._load(assessment_id)
        return assessment.model_dump(mode="json")

    def list_assessments(self) -> list[dict]:
        return self.store.list()

    def events(self, assessment_id: str, limit: int = 50) -> list[dict]:
        return self.store.events(assessment_id, limit)

    # -- device actions ----------------------------------------------------

    async def install(self, assessment_id: str) -> dict:
        assessment = self._load(assessment_id)
        self._ensure_active(assessment)
        self._ensure_state(
            assessment, AssessmentState.DEVICE_READY, AssessmentState.INSTALLED
        )
        if not assessment.target.apk_path:
            raise ValidationError("assessment has no APK path")
        serial = self._device(assessment)
        output = await self.barrel.install_apk(assessment.target.apk_path, serial)
        assessment.state = AssessmentState.INSTALLED
        assessment.add_step(
            "installed",
            {"apk": Path(assessment.target.apk_path).name},
        )
        self.store.save(assessment)
        self.store.append_event(
            assessment_id,
            "app_installed",
            {"output": output[:500]},
            extra_patterns=self.config.redact_extra,
        )
        return {"ok": True, "output": output}

    async def launch(self, assessment_id: str) -> dict:
        assessment = self._load(assessment_id)
        self._ensure_active(assessment)
        self._ensure_state(
            assessment,
            AssessmentState.INSTALLED,
            AssessmentState.EXPLORED,
            AssessmentState.TESTING,
            AssessmentState.REPORTED,
        )
        package = self._package(assessment)
        output = await self.barrel.launch_package(package, self._device(assessment))
        assessment.add_step("launched", {"package": package})
        self.store.save(assessment)
        self.store.append_event(assessment_id, "app_launched", {"package": package})
        return {"ok": True, "output": output}

    async def ui_dump(self, assessment_id: str, limit: int = 100) -> dict:
        assessment = self._load(assessment_id)
        nodes = await self._dump(assessment)
        limit = max(1, min(int(limit), 500))
        if assessment.state == AssessmentState.INSTALLED:
            assessment.state = AssessmentState.EXPLORED
            assessment.add_step("explored")
            self.store.save(assessment)
        return {
            "count": len(nodes),
            "truncated": len(nodes) > limit,
            "nodes": [node.to_dict() for node in nodes[:limit]],
        }

    async def ui_find(
        self,
        assessment_id: str,
        *,
        text: str | None = None,
        resource_id: str | None = None,
        content_desc: str | None = None,
        clickable: bool | None = None,
        exact: bool = False,
        limit: int = 20,
    ) -> dict:
        assessment = self._load(assessment_id)
        nodes = await self._dump(assessment)
        matches = find_nodes(
            nodes,
            text=text,
            resource_id=resource_id,
            content_desc=content_desc,
            clickable=clickable,
            exact=exact,
            limit=limit,
        )
        return {"count": len(matches), "nodes": [node.to_dict() for node in matches]}

    async def ui_tap(self, assessment_id: str, x: int, y: int) -> dict:
        assessment = self._load(assessment_id)
        self._ensure_active(assessment)
        self._ensure_state(assessment, *_ACTIVE_STATES)
        if not (0 <= int(x) <= 20_000 and 0 <= int(y) <= 20_000):
            raise ValidationError("tap point is out of range")
        await self.barrel.ui_tap(int(x), int(y), self._device(assessment))
        self.store.append_event(assessment_id, "ui_tap", {"x": x, "y": y})
        return {"ok": True, "x": int(x), "y": int(y)}

    async def ui_tap_node(
        self,
        assessment_id: str,
        *,
        text: str | None = None,
        resource_id: str | None = None,
        content_desc: str | None = None,
        exact: bool = False,
    ) -> dict:
        if text is None and resource_id is None and content_desc is None:
            raise ValidationError("ui_tap_node needs a text, resource_id or content_desc")
        assessment = self._load(assessment_id)
        self._ensure_active(assessment)
        self._ensure_state(assessment, *_ACTIVE_STATES)
        nodes = await self._dump(assessment)
        try:
            node = best_node(
                nodes,
                text=text,
                resource_id=resource_id,
                content_desc=content_desc,
                exact=exact,
            )
        except ValidationError:
            raise ValidationError(
                "no node matched. Call ui_dump or ui_find and use a visible label"
            ) from None
        cx, cy = node.center
        await self.barrel.ui_tap(cx, cy, self._device(assessment))
        detail = node.to_dict()
        detail.pop("password", None)
        self.store.append_event(assessment_id, "ui_tap_node", detail)
        return {"ok": True, "node": node.to_dict(), "tapped": [cx, cy]}

    async def ui_text(
        self,
        assessment_id: str,
        text: str,
        *,
        submit: bool = False,
        sensitive: bool = False,
    ) -> dict:
        assessment = self._load(assessment_id)
        self._ensure_active(assessment)
        self._ensure_state(assessment, *_ACTIVE_STATES)
        if not isinstance(text, str) or not text or len(text) > _MAX_TEXT:
            raise ValidationError(f"text must be 1..{_MAX_TEXT} characters")
        await self.barrel.ui_set_text(text, submit, self._device(assessment))
        self.store.append_event(
            assessment_id,
            "ui_text",
            {"chars": len(text), "submit": submit},
            sensitive=sensitive,
        )
        return {"ok": True, "chars": len(text), "submit": submit}

    async def ui_key(self, assessment_id: str, keyevent: str) -> dict:
        assessment = self._load(assessment_id)
        self._ensure_active(assessment)
        self._ensure_state(assessment, *_ACTIVE_STATES)
        await self.barrel.ui_key(keyevent, self._device(assessment))
        self.store.append_event(assessment_id, "ui_key", {"keyevent": keyevent})
        return {"ok": True, "keyevent": keyevent}

    async def ui_swipe(
        self,
        assessment_id: str,
        x1: int,
        y1: int,
        x2: int,
        y2: int,
        duration_ms: int = 300,
    ) -> dict:
        assessment = self._load(assessment_id)
        self._ensure_active(assessment)
        self._ensure_state(assessment, *_ACTIVE_STATES)
        for value in (x1, y1, x2, y2):
            if not 0 <= int(value) <= 20_000:
                raise ValidationError("swipe point is out of range")
        duration = max(1, min(int(duration_ms), 10_000))
        await self.barrel.ui_swipe(
            int(x1), int(y1), int(x2), int(y2), duration, self._device(assessment)
        )
        self.store.append_event(
            assessment_id,
            "ui_swipe",
            {"from": [x1, y1], "to": [x2, y2], "duration_ms": duration},
        )
        return {"ok": True}

    async def screenshot(self, assessment_id: str, label: str = "screen") -> dict:
        assessment = self._load(assessment_id)
        self._ensure_active(assessment)
        self._ensure_state(assessment, *_ACTIVE_STATES)
        stamp = utc_now().replace(":", "").replace("-", "").replace("+", "_")
        safe_label = re.sub(r"[^A-Za-z0-9_-]", "_", label)[:40] or "screen"
        path = self.store.evidence_path(assessment_id, f"{safe_label}-{stamp}.png")
        await self.barrel.screenshot(str(path), self._device(assessment))
        if not path.is_file() or path.stat().st_size == 0:
            raise StateError("screenshot was not written")
        self.store.append_event(
            assessment_id, "screenshot", {"path": path.name, "bytes": path.stat().st_size}
        )
        return {"ok": True, "path": str(path), "bytes": path.stat().st_size}

    async def app_stop(self, assessment_id: str) -> dict:
        assessment = self._load(assessment_id)
        self._ensure_active(assessment)
        self._ensure_state(assessment, *_ACTIVE_STATES)
        package = self._package(assessment)
        await self.barrel.app_stop(package, self._device(assessment))
        self.store.append_event(assessment_id, "app_stopped", {"package": package})
        return {"ok": True, "package": package}

    async def logcat(
        self, assessment_id: str, lines: int = 200, filter: str | None = None
    ) -> dict:
        assessment = self._load(assessment_id)
        self._ensure_active(assessment)
        self._ensure_state(assessment, *_ACTIVE_STATES)
        count = max(1, min(int(lines), 5000))
        text = await self.barrel.logcat_tail(count, filter, self._device(assessment))
        text = redact_text(text, self.config.redact_extra)
        return {"ok": True, "lines": count, "output": text[:20_000]}

    # -- traffic capture ---------------------------------------------------

    async def capture_start(
        self,
        assessment_id: str,
        *,
        install_ca: bool = False,
        ca_method: str = "user",
        route: bool = True,
    ) -> dict:
        assessment = self._load(assessment_id)
        self._ensure_active(assessment)
        self._ensure_state(assessment, *_ACTIVE_STATES)
        method = (ca_method or "user").strip().lower()
        if method not in _CA_METHODS:
            raise ValidationError(
                f"ca_method must be one of: {', '.join(sorted(_CA_METHODS))}"
            )
        device = self._device(assessment)
        backend = BarrelBackend(self.barrel)
        status = await backend.start()
        try:
            ca_output = None
            if install_ca:
                if not status.get("ca_path"):
                    await backend.ensure_ca()
                    status = await backend.status()
                ca_output = await backend.install_ca(device, method)
            route_output = await backend.route(device) if route else None
        except BaseException:
            await backend.stop()
            raise
        assessment.capture_active = True
        assessment.capture_port = status.get("port")
        assessment.add_step(
            "capture_started",
            {"port": assessment.capture_port, "ca": bool(install_ca), "routed": bool(route)},
        )
        self.store.save(assessment)
        self.store.append_event(
            assessment_id,
            "capture_started",
            {
                "port": assessment.capture_port,
                "ca_installed": bool(install_ca),
                "ca_method": method if install_ca else None,
                "routed": bool(route),
            },
        )
        return {
            "ok": True,
            "status": status,
            "ca_installed": bool(install_ca),
            "ca_output": ca_output,
            "routed": bool(route),
            "route_output": route_output,
        }

    async def capture_status(self, assessment_id: str) -> dict:
        assessment = self._load(assessment_id)
        self._ensure_active(assessment)
        return await BarrelBackend(self.barrel).status()

    async def capture_entries(self, assessment_id: str, limit: int = 100) -> dict:
        assessment = self._load(assessment_id)
        self._ensure_active(assessment)
        self._ensure_state(assessment, *_ACTIVE_STATES)
        count = max(1, min(int(limit), 200))
        records = await BarrelBackend(self.barrel).entries(count)
        self._snapshot_auth(assessment_id, records)
        extra = self.config.redact_extra
        entries = [
            {
                "id": record.id,
                "started": record.started,
                "method": record.method,
                "url": redact_text(record.url, extra),
                "status": record.status,
                "state": record.state,
                "content_type": record.content_type,
                "duration_ms": record.duration_ms,
            }
            for record in records
        ]
        return {"count": len(entries), "entries": entries}

    async def capture_stop(self, assessment_id: str) -> dict:
        assessment = self._load(assessment_id)
        self._ensure_active(assessment)
        backend = BarrelBackend(self.barrel)
        warnings: list[str] = []
        if not assessment.capture_active:
            await backend.stop()
            return {"ok": True, "already_stopped": True}
        try:
            await backend.stop()
        except ArgusError as exc:
            warnings.append(f"stop: {exc}")
        records: list[TrafficRecord] = []
        try:
            records = await backend.entries(200)
        except ArgusError as exc:
            warnings.append(f"entries: {exc}")
        self._snapshot_auth(assessment_id, records)

        inventory = build_inventory(records)
        assessment.endpoints = inventory
        assessment.capture_active = False
        assessment.capture_port = None
        stamp = utc_now().replace(":", "").replace("-", "").replace("+", "_")
        extra = self.config.redact_extra
        redacted = [_redact_record(record, extra) for record in records]
        traffic_path = self.store.write_evidence(
            assessment_id,
            f"traffic-{stamp}.json",
            json.dumps(redacted, indent=2).encode("utf-8"),
        )
        inventory_path = self.store.write_evidence(
            assessment_id,
            f"endpoints-{stamp}.json",
            json.dumps(
                [endpoint.model_dump(mode="json") for endpoint in inventory], indent=2
            ).encode("utf-8"),
        )
        assessment.add_step(
            "capture_stopped",
            {"entries": len(records), "endpoints": len(inventory)},
        )
        self.store.save(assessment)
        self.store.append_event(
            assessment_id,
            "capture_stopped",
            {
                "entries": len(records),
                "endpoints": len(inventory),
                "traffic": traffic_path.name,
                "inventory": inventory_path.name,
                "auth_snapshot": self._auth_summary(assessment_id),
            },
        )
        return {
            "ok": True,
            "entries": len(records),
            "endpoints": len(inventory),
            "traffic": traffic_path.name,
            "inventory": inventory_path.name,
            "warnings": warnings,
        }

    async def capture_correlate(self, assessment_id: str, limit: int = 200) -> dict:
        assessment = self._load(assessment_id)
        self._ensure_active(assessment)
        self._ensure_state(assessment, *_ACTIVE_STATES)
        count = max(1, min(int(limit), 200))
        records = await BarrelBackend(self.barrel).entries(count)
        events = self.store.events(assessment_id, 500)
        windows = windows_from_events(events)
        return {
            "count": len(records),
            "confidence": "inferred",
            "note": "proxy timing only; confirm causality before reporting",
            "windows": correlate(records, windows),
        }

    async def endpoint_inventory(self, assessment_id: str) -> dict:
        assessment = self._load(assessment_id)
        return {
            "count": len(assessment.endpoints),
            "endpoints": [
                endpoint.model_dump(mode="json") for endpoint in assessment.endpoints
            ],
        }

    # -- testing, replay and findings --------------------------------------

    async def testing_begin(self, assessment_id: str) -> Assessment:
        assessment = self._load(assessment_id)
        self._ensure_active(assessment)
        if assessment.state in (AssessmentState.TESTING, AssessmentState.REPORTED):
            return assessment
        self._ensure_state(
            assessment,
            AssessmentState.DEVICE_READY,
            AssessmentState.INSTALLED,
            AssessmentState.EXPLORED,
        )
        assessment.state = AssessmentState.TESTING
        assessment.add_step("testing")
        self.store.save(assessment)
        self.store.append_event(assessment_id, "testing_begun")
        return assessment

    async def auth_set(
        self, assessment_id: str, host: str, headers: dict
    ) -> dict:
        assessment = self._load(assessment_id)
        self._ensure_active(assessment)
        self._ensure_state(assessment, *_TESTING_STATES)
        clean_host = _check_hosts([host])[0]
        if clean_host not in assessment.target.allowed_hosts:
            raise ValidationError(f"host {clean_host} is not in allowed_hosts")
        clean = check_headers(headers)
        if not clean:
            raise ValidationError("auth_set needs at least one header")
        unknown = [
            name
            for name in clean
            if name.lower() not in AUTH_HEADER_NAMES
        ]
        if unknown:
            raise ValidationError(
                "auth_set only accepts auth headers: "
                + ", ".join(sorted(AUTH_HEADER_NAMES))
            )
        key = (assessment_id, clean_host)
        stored = self._auth.setdefault(key, {})
        stored.update(clean)
        self.store.append_event(
            assessment_id,
            "auth_set",
            {"host": clean_host, "headers": sorted(name.lower() for name in clean)},
        )
        return {
            "ok": True,
            "host": clean_host,
            "headers": sorted(name.lower() for name in stored),
        }

    async def auth_clear(self, assessment_id: str, host: str | None = None) -> dict:
        self._load(assessment_id)
        removed = 0
        for key in list(self._auth):
            key_assessment, key_host = key
            if key_assessment != assessment_id:
                continue
            if host is not None and key_host != host.strip().lower():
                continue
            del self._auth[key]
            removed += 1
        self.store.append_event(
            assessment_id,
            "auth_cleared",
            {"host": host.strip().lower() if host else None, "slots": removed},
        )
        return {"ok": True, "cleared": removed}

    async def replay_send(
        self,
        assessment_id: str,
        method: str,
        url: str,
        headers: dict | None = None,
        body: str | None = None,
        use_auth: bool = True,
    ) -> dict:
        assessment = self._load(assessment_id)
        self._ensure_active(assessment)
        self._ensure_state(assessment, *_REPORT_STATES)
        clean_method = check_method(method)
        if not isinstance(url, str) or len(url) > 4096:
            raise ValidationError("url must be a string of at most 4096 characters")
        parts = urlsplit(url)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ValidationError("url must be an absolute http(s) URL")
        host = parts.hostname.lower()
        check_target(
            host,
            assessment.target.allowed_hosts,
            assessment.target.allow_production,
        )
        clean_headers = check_headers(headers)
        clean_body = check_body(body)

        merged: dict[str, str] = {}
        if use_auth:
            merged.update(self._auth.get((assessment_id, host), {}))
        merged.update(clean_headers)

        result = await self.replay.send(clean_method, url, merged, clean_body)

        stamp = utc_now().replace(":", "").replace("-", "").replace("+", "_")
        evidence_name = f"replay-{stamp}-{uuid.uuid4().hex[:6]}.json"
        payload = {
            "ts": utc_now(),
            "request": {
                "method": clean_method,
                "url": redact_text(url, self.config.redact_extra),
                "headers": result.request_headers,
                "body": result.request_body,
                "auth_used": bool(use_auth and self._auth.get((assessment_id, host))),
            },
            "response": {
                "status": result.status,
                "content_type": result.content_type,
                "duration_ms": result.duration_ms,
                "headers": result.response_headers,
                "body": result.response_body,
                "body_omitted": result.body_omitted,
            },
        }
        self.store.write_evidence(
            assessment_id,
            evidence_name,
            json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8"),
        )
        detail = {
            "method": clean_method,
            "host": host,
            "path": parts.path or "/",
            "status": result.status,
            "duration_ms": result.duration_ms,
            "evidence": evidence_name,
        }
        self.store.append_event(
            assessment_id, "replay_sent", detail, extra_patterns=self.config.redact_extra
        )
        return {
            "ok": True,
            "evidence": evidence_name,
            "method": clean_method,
            "url": url,
            "status": result.status,
            "content_type": result.content_type,
            "duration_ms": result.duration_ms,
            "request_headers": result.request_headers,
            "request_body": result.request_body,
            "response_headers": result.response_headers,
            "response_body": result.response_body,
            "body_omitted": result.body_omitted,
            "auth_used": bool(use_auth and self._auth.get((assessment_id, host))),
        }

    async def replay_compare(
        self, assessment_id: str, baseline: str, variant: str
    ) -> dict:
        assessment = self._load(assessment_id)
        self._ensure_active(assessment)
        self._ensure_state(assessment, *_REPORT_STATES)
        payloads = []
        for name in (baseline, variant):
            if not isinstance(name, str) or not name.startswith("replay-"):
                raise ValidationError("compare needs two replay evidence names")
            if not name.endswith(".json"):
                raise ValidationError("compare needs two replay evidence names")
            payloads.append(json.loads(self.store.read_evidence(assessment_id, name)))
        diff = compare_replay_payloads(payloads[0], payloads[1])
        diff["baseline_evidence"] = baseline
        diff["variant_evidence"] = variant
        self.store.append_event(
            assessment_id,
            "replay_compared",
            {
                "baseline": baseline,
                "variant": variant,
                "changed": diff["changed"],
            },
        )
        return diff

    async def finding_create(
        self,
        assessment_id: str,
        *,
        title: str,
        severity: str,
        confidence: str,
        status: str = "potential",
        endpoint: str | None = None,
        description: str = "",
        evidence: list[str] | None = None,
    ) -> dict:
        assessment = self._load(assessment_id)
        self._ensure_active(assessment)
        self._ensure_state(assessment, *_REPORT_STATES)
        clean_title = str(title or "").strip()
        if not clean_title or len(clean_title) > _MAX_TITLE:
            raise ValidationError(f"title must be 1..{_MAX_TITLE} characters")
        clean_severity = str(severity or "").strip().lower()
        if clean_severity not in SEVERITIES:
            raise ValidationError(
                f"severity must be one of: {', '.join(SEVERITIES)}"
            )
        clean_confidence = str(confidence or "").strip().lower()
        if clean_confidence not in CONFIDENCES:
            raise ValidationError(
                f"confidence must be one of: {', '.join(CONFIDENCES)}"
            )
        clean_status = str(status or "").strip().lower()
        if clean_status not in FINDING_STATUSES:
            raise ValidationError(
                f"status must be one of: {', '.join(FINDING_STATUSES)}"
            )
        clean_description = str(description or "").strip()[:_MAX_DESCRIPTION]
        clean_endpoint = None if endpoint is None else str(endpoint)[:500]
        clean_evidence: list[str] = []
        for name in evidence or []:
            path = self.store.evidence_path(assessment_id, str(name))
            if not path.is_file():
                raise ValidationError(f"evidence not found: {name}")
            clean_evidence.append(path.name)
        if len(assessment.findings) >= _MAX_FINDINGS:
            raise ValidationError(f"finding limit reached ({_MAX_FINDINGS})")

        finding = Finding(
            id=uuid.uuid4().hex[:16],
            title=clean_title,
            severity=clean_severity,
            confidence=clean_confidence,
            status=clean_status,
            endpoint=clean_endpoint,
            description=clean_description,
            evidence=clean_evidence,
        )
        assessment.findings.append(finding)
        assessment.add_step("finding_created", {"id": finding.id, "severity": clean_severity})
        self.store.save(assessment)
        self.store.append_event(
            assessment_id,
            "finding_created",
            {
                "id": finding.id,
                "title": clean_title,
                "severity": clean_severity,
                "confidence": clean_confidence,
                "status": clean_status,
                "evidence": clean_evidence,
            },
            extra_patterns=self.config.redact_extra,
        )
        return finding.model_dump(mode="json")

    async def finding_update(
        self,
        assessment_id: str,
        finding_id: str,
        status: str,
        note: str | None = None,
    ) -> dict:
        assessment = self._load(assessment_id)
        self._ensure_active(assessment)
        self._ensure_state(assessment, *_REPORT_STATES)
        clean_status = str(status or "").strip().lower()
        if clean_status not in FINDING_STATUSES:
            raise ValidationError(
                f"status must be one of: {', '.join(FINDING_STATUSES)}"
            )
        finding = self._find_finding(assessment, finding_id)
        finding.status = clean_status
        finding.updated_at = utc_now()
        if note:
            addition = str(note).strip()[:1000]
            finding.description = (
                finding.description + "\n" + addition
            ).strip()[:_MAX_DESCRIPTION]
        assessment.add_step("finding_updated", {"id": finding.id, "status": clean_status})
        self.store.save(assessment)
        self.store.append_event(
            assessment_id,
            "finding_updated",
            {"id": finding.id, "status": clean_status},
            extra_patterns=self.config.redact_extra,
        )
        return finding.model_dump(mode="json")

    def finding_list(self, assessment_id: str) -> dict:
        assessment = self._load(assessment_id)
        counts = {status: 0 for status in FINDING_STATUSES}
        for finding in assessment.findings:
            counts[finding.status] = counts.get(finding.status, 0) + 1
        return {
            "count": len(assessment.findings),
            "counts": counts,
            "findings": [
                finding.model_dump(mode="json") for finding in assessment.findings
            ],
        }

    async def report_generate(
        self, assessment_id: str, formats: list[str] | None = None
    ) -> dict:
        """Write report.md / report.json / findings.csv into evidence/.

        The first report moves the assessment from testing to reported;
        regenerating from reported overwrites the files. Testing tools stay
        available afterwards, so findings can still be fixed and the report
        rebuilt.
        """
        assessment = self._load(assessment_id)
        self._ensure_active(assessment)
        self._ensure_state(assessment, *_REPORT_STATES)
        requested = formats if formats is not None else ["md", "json", "csv"]
        if not isinstance(requested, list) or not requested:
            raise ValidationError("formats must be a non-empty list")
        clean: list[str] = []
        for item in requested:
            name = str(item).strip().lower()
            if name not in REPORT_FILES:
                raise ValidationError(f"unknown format: {name}; use md, json or csv")
            if name not in clean:
                clean.append(name)

        generated_at = utc_now()
        excerpts = self._evidence_excerpts(
            assessment_id,
            sorted(
                {
                    name
                    for finding in assessment.findings
                    for name in finding.evidence
                }
            ),
        )
        files: list[dict] = []
        for name in clean:
            if name == "md":
                data = render_markdown(
                    assessment, excerpts, generated_at
                ).encode("utf-8")
            elif name == "json":
                data = json.dumps(
                    render_json(assessment, generated_at),
                    indent=2,
                    ensure_ascii=False,
                ).encode("utf-8")
            else:
                data = render_csv(assessment.findings).encode("utf-8")
            path = self.store.write_evidence(assessment_id, REPORT_FILES[name], data)
            files.append({"name": path.name, "bytes": path.stat().st_size})

        transitioned = assessment.state is AssessmentState.TESTING
        if transitioned:
            assessment.state = AssessmentState.REPORTED
        file_names = [item["name"] for item in files]
        assessment.add_step(
            "report_generated", {"formats": clean, "files": file_names}
        )
        self.store.save(assessment)
        self.store.append_event(
            assessment_id,
            "report_generated",
            {
                "formats": clean,
                "files": file_names,
                "state": assessment.state.value,
            },
            extra_patterns=self.config.redact_extra,
        )
        return {
            "ok": True,
            "state": assessment.state.value,
            "transitioned": transitioned,
            "files": files,
            "summary": {
                "findings": len(assessment.findings),
                "severity_counts": severity_counts(assessment.findings),
                "status_counts": status_counts(assessment.findings),
                "endpoints": len(assessment.endpoints),
            },
        }

    # -- internals ---------------------------------------------------------

    def _evidence_excerpts(
        self, assessment_id: str, names: list[str]
    ) -> dict[str, str]:
        """One-line excerpt per evidence file; JSON replays show the exchange."""
        excerpts: dict[str, str] = {}
        for name in names:
            excerpt = "stored evidence file"
            if name.endswith(".json"):
                try:
                    payload = json.loads(self.store.read_evidence(assessment_id, name))
                except (OSError, ValueError, ValidationError):
                    payload = None
                if isinstance(payload, dict):
                    request = payload.get("request") or {}
                    response = payload.get("response") or {}
                    method = request.get("method", "?")
                    url = request.get("url", "?")
                    status = response.get("status", "?")
                    excerpt = f"{method} {url} -> {status}"
            excerpts[name] = excerpt
        return excerpts


    def _snapshot_auth(self, assessment_id: str, records: list[TrafficRecord]) -> None:
        """Keep live auth headers from captured requests in memory for replay."""
        for record in records:
            host = (record.host or "").strip().lower()
            if not host and record.url:
                host = (urlsplit(record.url).hostname or "").lower()
            if not host:
                continue
            key = (assessment_id, host)
            for name, value in record.req_headers:
                if name.strip().lower() not in AUTH_HEADER_NAMES:
                    continue
                if not value or value.strip() == "***":
                    continue
                self._auth.setdefault(key, {})[name] = value

    def _auth_summary(self, assessment_id: str) -> dict:
        summary: dict[str, list[str]] = {}
        for (aid, host), headers in self._auth.items():
            if aid == assessment_id:
                summary[host] = sorted(name.lower() for name in headers)
        return summary

    def _find_finding(self, assessment: Assessment, finding_id: str) -> Finding:
        if not isinstance(finding_id, str) or not _FINDING_ID_RE.match(finding_id):
            raise ValidationError("invalid finding id")
        for finding in assessment.findings:
            if finding.id == finding_id:
                return finding
        raise ValidationError(f"finding not found: {finding_id}")

    def _load(self, assessment_id: str) -> Assessment:
        return self.store.load(assessment_id)

    def _ensure_active(self, assessment: Assessment) -> None:
        if assessment.stopped:
            raise StateError("assessment is stopped")
        if assessment.paused:
            raise StateError("assessment is paused; resume it first")

    def _ensure_state(self, assessment: Assessment, *states: AssessmentState) -> None:
        if assessment.state not in states:
            allowed = ", ".join(state.value for state in states)
            raise StateError(
                f"assessment state is {assessment.state.value}; expected one of: {allowed}"
            )

    def _device(self, assessment: Assessment) -> str:
        if not assessment.device:
            raise StateError("assessment has no device; call assessment_start")
        return assessment.device

    def _package(self, assessment: Assessment) -> str:
        package = assessment.package or assessment.target.package
        if not package:
            raise StateError("assessment has no package name")
        return package

    async def _pick_device(self, preferred: str | None) -> str:
        output = await self.barrel.list_devices()
        serials = parse_device_serials(output)
        if not serials:
            raise StateError(
                "no ready device connected. Attach a device or start an emulator, then retry"
            )
        if preferred:
            if preferred not in serials:
                raise StateError(
                    f"device {preferred} is not ready. Available: {', '.join(serials)}"
                )
            return preferred
        if len(serials) == 1:
            return serials[0]
        raise StateError(
            f"multiple devices attached, configure a device explicitly: {', '.join(serials)}"
        )

    async def _dump(self, assessment: Assessment) -> list[UiNode]:
        self._ensure_active(assessment)
        self._ensure_state(assessment, *_ACTIVE_STATES)
        xml = await self.barrel.ui_dump(self._device(assessment))
        return parse_hierarchy(xml, self.config.max_xml_bytes)
