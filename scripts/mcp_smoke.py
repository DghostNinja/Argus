#!/usr/bin/env python3
"""Smoke test for the Argus MCP server over stdio.

Starts argus_mcp.py exactly as OpenCode does, checks the tool surface and drives
the assessment lifecycle plus the traffic tools' state gates. It needs Barrel
but no device, so it runs on a workstation: capture_start, capture_entries and
capture_correlate are expected to be refused until the assessment reaches
device_ready.

Usage:
    python3 scripts/mcp_smoke.py            # exits non-zero on failure

Environment:
    ARGUS_BARREL_BIN   Barrel MCP binary (defaults to argus/config.py)
    ARGUS_DATA_DIR     ignored; a temporary store is always used
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from mcp import ClientSession, StdioServerParameters  # noqa: E402
from mcp.client.stdio import stdio_client  # noqa: E402

from argus.config import DEFAULT_BARREL_BIN  # noqa: E402

EXPECTED_TOOLS = 28
TRAFFIC_TOOLS = {
    "capture_start",
    "capture_status",
    "capture_entries",
    "capture_stop",
    "capture_correlate",
    "endpoint_inventory",
}

failures: list[str] = []


def check(ok: bool, label: str) -> None:
    print(("PASS " if ok else "FAIL ") + label)
    if not ok:
        failures.append(label)


async def run() -> None:
    barrel = str(Path(os.environ.get("ARGUS_BARREL_BIN", DEFAULT_BARREL_BIN)).expanduser())
    if not Path(barrel).is_file():
        sys.exit(f"barrel MCP binary not found: {barrel}")

    with tempfile.TemporaryDirectory(prefix="argus-smoke-") as data_dir:
        env = dict(os.environ)
        env["ARGUS_DATA_DIR"] = data_dir
        env["ARGUS_BARREL_BIN"] = barrel
        params = StdioServerParameters(
            command=sys.executable,
            args=[str(ROOT / "argus_mcp.py")],
            env=env,
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                init = await session.initialize()
                print(f"server: {init.serverInfo.name} {init.serverInfo.version}")
                check(
                    bool(init.instructions and "capture_start" in init.instructions),
                    "instructions mention the traffic workflow",
                )

                names = {tool.name for tool in (await session.list_tools()).tools}
                check(len(names) == EXPECTED_TOOLS, f"tool count is {EXPECTED_TOOLS} (got {len(names)})")
                missing = sorted(TRAFFIC_TOOLS - names)
                check(not missing, f"traffic tools exposed{f' (missing: {missing})' if missing else ''}")

                async def call(tool: str, **kwargs):
                    return await session.call_tool(tool, kwargs)

                async def ok(tool: str, **kwargs) -> dict:
                    result = await call(tool, **kwargs)
                    if result.isError:
                        raise RuntimeError(f"{tool}: {result.content[0].text}")
                    return json.loads(result.content[0].text)

                created = await ok("assessment_create", name="smoke")
                assessment_id = created["id"]
                check(created["state"] == "created", "create -> created")

                listed = await ok("assessment_list")
                check(
                    [item["id"] for item in listed["assessments"]] == [assessment_id],
                    "list returns the new assessment",
                )

                configured = await ok(
                    "assessment_configure",
                    assessment_id=assessment_id,
                    package="com.example.app",
                    allowed_hosts=["api.example.com"],
                )
                check(configured["state"] == "configured", "configure -> configured")

                status = await ok("capture_status", assessment_id=assessment_id)
                check(status.get("running") is False, "capture_status reports the proxy idle")
                check(bool(status.get("ca_path")), "capture_status reports the CA path")

                for tool in ("capture_start", "capture_entries", "capture_correlate"):
                    result = await call(tool, assessment_id=assessment_id)
                    text = result.content[0].text
                    check(
                        result.isError and "configured" in text,
                        f"{tool} is refused before device_ready",
                    )

                stopped = await ok("capture_stop", assessment_id=assessment_id)
                check(stopped.get("already_stopped") is True, "capture_stop no-ops when inactive")

                inventory = await ok("endpoint_inventory", assessment_id=assessment_id)
                check(inventory["count"] == 0, "endpoint_inventory starts empty")

                bad = await call("assessment_status", assessment_id="../../../etc/passwd")
                check(
                    bad.isError and "assessment id" in bad.content[0].text.lower(),
                    "malformed assessment id is rejected",
                )
                bad_capture = await call("capture_status", assessment_id="not-an-id")
                check(bad_capture.isError, "capture_status rejects a malformed id")

                alive = await ok("assessment_status", assessment_id=assessment_id)
                check(alive["state"] == "configured", "server is healthy after tool errors")

                events = await ok("assessment_events", assessment_id=assessment_id)
                check(len(events["events"]) > 0, "events are recorded")

                await ok("assessment_stop", assessment_id=assessment_id)


def main() -> None:
    asyncio.run(run())
    print("\nRESULT:", "PASS" if not failures else f"FAIL ({len(failures)})")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
