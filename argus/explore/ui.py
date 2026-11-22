"""Parse uiautomator XML into a compact, selectable node list."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass

from ..errors import ValidationError

_BOUNDS_RE = re.compile(r"\[(-?\d+),(-?\d+)\]\[(-?\d+),(-?\d+)\]")
_MAX_NODES = 8000


@dataclass(frozen=True)
class UiNode:
    text: str
    resource_id: str
    content_desc: str
    cls: str
    package: str
    clickable: bool
    enabled: bool
    focusable: bool
    focused: bool
    password: bool
    scrollable: bool
    x1: int
    y1: int
    x2: int
    y2: int

    @property
    def center(self) -> tuple[int, int]:
        return ((self.x1 + self.x2) // 2, (self.y1 + self.y2) // 2)

    @property
    def area(self) -> int:
        return max(0, self.x2 - self.x1) * max(0, self.y2 - self.y1)

    def to_dict(self) -> dict:
        cx, cy = self.center
        short_cls = self.cls.rsplit(".", 1)[-1] if self.cls else ""
        return {
            "text": self.text[:120],
            "id": self.resource_id,
            "desc": self.content_desc[:120],
            "class": short_cls,
            "clickable": self.clickable,
            "enabled": self.enabled,
            "focused": self.focused,
            "password": self.password,
            "scrollable": self.scrollable,
            "bounds": [self.x1, self.y1, self.x2, self.y2],
            "center": [cx, cy],
        }


def _bool(value: str | None) -> bool:
    return (value or "").strip().lower() == "true"


def parse_hierarchy(xml: str, max_bytes: int = 5_000_000) -> list[UiNode]:
    if not isinstance(xml, str) or not xml.strip():
        raise ValidationError("UI dump is empty")
    if len(xml.encode("utf-8", errors="ignore")) > max_bytes:
        raise ValidationError(f"UI dump is larger than {max_bytes} bytes")
    head = xml[:4096].lower()
    if "<!doctype" in head or "<!entity" in head:
        raise ValidationError("UI dump contains a DTD, refusing to parse it")
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        raise ValidationError(f"invalid UI XML: {exc}") from exc

    nodes: list[UiNode] = []
    for element in root.iter("node"):
        if len(nodes) >= _MAX_NODES:
            break
        match = _BOUNDS_RE.search(element.get("bounds", ""))
        if not match:
            continue
        x1, y1, x2, y2 = (int(value) for value in match.groups())
        nodes.append(
            UiNode(
                text=element.get("text", ""),
                resource_id=element.get("resource-id", ""),
                content_desc=element.get("content-desc", ""),
                cls=element.get("class", ""),
                package=element.get("package", ""),
                clickable=_bool(element.get("clickable")),
                enabled=_bool(element.get("enabled")),
                focusable=_bool(element.get("focusable")),
                focused=_bool(element.get("focused")),
                password=_bool(element.get("password")),
                scrollable=_bool(element.get("scrollable")),
                x1=x1,
                y1=y1,
                x2=x2,
                y2=y2,
            )
        )
    return nodes


def find_nodes(
    nodes: list[UiNode],
    *,
    text: str | None = None,
    resource_id: str | None = None,
    content_desc: str | None = None,
    clickable: bool | None = None,
    exact: bool = False,
    limit: int = 20,
) -> list[UiNode]:
    limit = max(1, min(int(limit), 200))

    def matches(value: str, needle: str) -> bool:
        if not value:
            return False
        return value == needle if exact else needle.lower() in value.lower()

    found: list[UiNode] = []
    for node in nodes:
        if text is not None and not (
            matches(node.text, text) or matches(node.content_desc, text)
        ):
            continue
        if resource_id is not None and not matches(node.resource_id, resource_id):
            continue
        if content_desc is not None and not matches(node.content_desc, content_desc):
            continue
        if clickable is not None and node.clickable is not clickable:
            continue
        found.append(node)

    def rank(node: UiNode) -> tuple:
        exact_hit = 0
        if exact and text is not None and (node.text == text or node.content_desc == text):
            exact_hit = -1
        return (exact_hit, 0 if node.clickable else 1, 0 if node.enabled else 1, node.area)

    found.sort(key=rank)
    return found[:limit]


def best_node(nodes: list[UiNode], **selector) -> UiNode:
    matches = find_nodes(nodes, limit=1, **selector)
    if not matches:
        raise ValidationError("no UI node matched the selector")
    return matches[0]
