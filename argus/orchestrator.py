"""Assessment lifecycle and device actions. All safety checks live here."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from .barrel_client import BarrelClient
from .config import Config
from .errors import ArgusError, StateError, ValidationError
from .explore.ui import UiNode, best_node, find_nodes, parse_hierarchy
from .models import Assessment, AssessmentState, utc_now
from .redact import SENSITIVE_HEADERS, redact_text
from .store import AssessmentStore
from .traffic.barrel_backend import BarrelBackend
from .traffic.correlate import correlate, windows_from_events
from .traffic.inventory import build_inventory
from .traffic.models import TrafficRecord

_PACKAGE_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_DEVICE_RE = re.compile(r"^[A-Za-z0-9._:-]+$")
_HOST_RE = re.compile(r"^[A-Za-z0-9.*:_-]+$")
_ACTIVE_STATES = {
    AssessmentState.DEVICE_READY,
    AssessmentState.INSTALLED,
    AssessmentState.EXPLORED,
    AssessmentState.TESTING,
}
_MAX_TEXT = 4096


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
    def __init__(self, config: Config, store: AssessmentStore, barrel: BarrelClient):
        self.config = config
        self.store = store
        self.barrel = barrel

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

    # -- internals ---------------------------------------------------------

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
