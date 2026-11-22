"""Approximate mapping from UI actions to captured requests.

The proxy sees time, not intent. Every mapping here is inferred and must be
labelled as such. Exact causality needs instrumentation or a marker header.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from .models import TrafficRecord

ACTION_EVENTS = frozenset(
    {"ui_tap", "ui_tap_node", "ui_text", "ui_key", "ui_swipe", "app_launched"}
)


@dataclass(frozen=True)
class ActionWindow:
    action: str
    started_ms: int
    ended_ms: int


def _parse_ms(ts: str) -> int | None:
    try:
        return int(datetime.fromisoformat(ts).timestamp() * 1000)
    except (ValueError, TypeError):
        return None


def windows_from_events(events: list[dict], max_window_ms: int = 10_000) -> list[ActionWindow]:
    windows: list[ActionWindow] = []
    relevant = [
        (event, _parse_ms(event.get("ts", "")))
        for event in events
        if event.get("action") in ACTION_EVENTS
    ]
    for index, (event, started) in enumerate(relevant):
        if started is None:
            continue
        next_started = None
        for _later_event, later in relevant[index + 1 :]:
            if later is not None and later > started:
                next_started = later
                break
        ended = started + max_window_ms
        if next_started is not None:
            ended = min(ended, next_started)
        if ended <= started:
            ended = started + 1_000
        windows.append(
            ActionWindow(
                action=str(event.get("action")),
                started_ms=started,
                ended_ms=ended,
            )
        )
    return windows


def correlate(
    records: list[TrafficRecord],
    windows: list[ActionWindow],
    slack_ms: int = 1_000,
) -> list[dict]:
    assigned: dict[int, list[int]] = {index: [] for index in range(len(windows))}
    for record in records:
        best_index: int | None = None
        best_distance: int | None = None
        for index, window in enumerate(windows):
            if not (
                window.started_ms - slack_ms
                <= record.started
                <= window.ended_ms + slack_ms
            ):
                continue
            if window.started_ms <= record.started <= window.ended_ms:
                distance = 0
            else:
                distance = min(
                    abs(record.started - window.started_ms),
                    abs(record.started - window.ended_ms),
                )
            if best_distance is None or distance < best_distance:
                best_distance = distance
                best_index = index
        if best_index is not None:
            assigned[best_index].append(record.id)

    result = []
    for index, window in enumerate(windows):
        result.append(
            {
                "action": window.action,
                "started_ms": window.started_ms,
                "ended_ms": window.ended_ms,
                "record_ids": sorted(assigned[index]),
                "confidence": "inferred",
            }
        )
    return result
