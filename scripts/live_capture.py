#!/usr/bin/env python3
"""End-to-end capture run against a real device, over the Argus MCP server.

Starts argus_mcp.py the way OpenCode does, walks an assessment to
device_ready, starts proxy capture with CA install and device routing, drives
the browser at a URL, and asserts that an HTTPS request was actually decrypted
(not just CONNECTed). Then stops capture and checks the stored evidence.

Usage:
    python3 scripts/live_capture.py --device 192.168.18.3:5555 \
        --url https://example.com/ --package com.android.chrome

Exit code is non-zero if any check fails. The data directory defaults to a
fresh temporary directory, so pass --data-dir to keep the evidence.

Requirements: adb on PATH, a rooted device for ca_method=bind, a device that
trusts a user CA for ca_method=user, and a working network path from the device
to the URL.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from mcp import ClientSession, StdioServerParameters  # noqa: E402
from mcp.client.stdio import stdio_client  # noqa: E402

from argus.config import DEFAULT_BARREL_BIN  # noqa: E402

failures: list[str] = []


def check(ok: bool, label: str) -> None:
    print(("PASS " if ok else "FAIL ") + label)
    if not ok:
        failures.append(label)


def adb(serial: str, *args: str, timeout: int = 30) -> str:
    proc = subprocess.run(
        ["adb", "-s", serial, *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"adb {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout


def device_proxy(serial: str) -> str:
    return adb(serial, "shell", "settings", "get", "global", "http_proxy").strip()


def drive_browser(serial: str, package: str, url: str) -> None:
    adb(serial, "shell", "input", "keyevent", "KEYCODE_WAKEUP")
    adb(serial, "shell", "wm", "dismiss-keyguard")
    adb(serial, "shell", "am", "force-stop", package)
    time.sleep(1)
    adb(
        serial,
        "shell",
        "am",
        "start",
        "-W",
        "-a",
        "android.intent.action.VIEW",
        "-d",
        url,
    )


def screenshot(serial: str, path: Path) -> None:
    proc = subprocess.run(
        ["adb", "-s", serial, "exec-out", "screencap", "-p"],
        capture_output=True,
        timeout=30,
    )
    if proc.returncode != 0:
        print(f"WARN screenshot failed: {proc.stderr.decode(errors='replace').strip()}")
        return
    path.write_bytes(proc.stdout)
    print(f"     screenshot: {path}")


def is_decrypted(entry: dict, host: str) -> bool:
    return (
        entry["method"] != "CONNECT"
        and entry["url"].startswith("https://")
        and urlparse(entry["url"]).hostname == host
        and entry["status"] is not None
        and entry["state"] == "done"
    )


async def run(args: argparse.Namespace) -> None:
    barrel = str(Path(os.environ.get("ARGUS_BARREL_BIN", DEFAULT_BARREL_BIN)).expanduser())
    if not Path(barrel).is_file():
        sys.exit(f"barrel MCP binary not found: {barrel}")
    if not shutil.which("adb"):
        sys.exit("adb not found on PATH")
    host = urlparse(args.url).hostname
    if not host:
        sys.exit(f"not an absolute URL: {args.url}")

    data_dir = args.data_dir or tempfile.mkdtemp(prefix="argus-live-")
    Path(data_dir).mkdir(parents=True, exist_ok=True)
    print(f"data dir: {data_dir}")

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
            await session.initialize()

            async def call(tool: str, **kwargs):
                return await session.call_tool(tool, kwargs)

            async def ok(tool: str, **kwargs) -> dict:
                result = await call(tool, **kwargs)
                if result.isError:
                    raise RuntimeError(f"{tool}: {result.content[0].text}")
                return json.loads(result.content[0].text)

            created = await ok("assessment_create", name="live-capture")
            assessment_id = created["id"]
            print(f"assessment: {assessment_id}")

            configured = await ok(
                "assessment_configure",
                assessment_id=assessment_id,
                package=args.package,
                device=args.device,
                allowed_hosts=[host],
            )
            check(configured["state"] == "configured", "configure -> configured")

            started = await ok("assessment_start", assessment_id=assessment_id)
            check(started["state"] == "device_ready", "start -> device_ready")
            check(started["device"] == args.device, f"start picked {args.device}")

            capture = await ok(
                "capture_start",
                assessment_id=assessment_id,
                install_ca=True,
                ca_method=args.ca_method,
                route=True,
            )
            port = capture["status"]["port"]
            check(port > 0, f"proxy is listening (port {port})")
            check(capture["routed"], "device routing requested")
            check(device_proxy(args.device) != ":0", "device proxy is set")

            drive_browser(args.device, args.package, args.url)

            decrypted: dict | None = None
            deadline = time.time() + args.timeout
            while time.time() < deadline and decrypted is None:
                listed = await ok("capture_entries", assessment_id=assessment_id, limit=200)
                for entry in listed["entries"]:
                    if is_decrypted(entry, host) and entry["status"] in (200, 304):
                        decrypted = entry
                        break
                if decrypted is None:
                    time.sleep(2)

            check(decrypted is not None, f"decrypted HTTPS request to {host}")
            if decrypted:
                print(
                    f"     {decrypted['method']} {decrypted['url']} "
                    f"-> {decrypted['status']} {decrypted['content_type']}"
                )
                check(
                    decrypted["status"] < 400,
                    f"decrypted response succeeded (got {decrypted['status']})",
                )

            evidence_dir = Path(data_dir) / "assessments" / assessment_id / "evidence"
            evidence_dir.mkdir(parents=True, exist_ok=True)
            screenshot(args.device, evidence_dir / "capture-screen.png")

            correlated = await ok("capture_correlate", assessment_id=assessment_id)
            check(correlated["confidence"] == "inferred", "correlation is marked inferred")
            check(correlated["count"] > 0, "correlate sees captured records")

            stopped = await ok("capture_stop", assessment_id=assessment_id)
            check(stopped["entries"] > 0, f"stop stored {stopped['entries']} entries")
            check(stopped["endpoints"] > 0, f"stop stored {stopped['endpoints']} endpoints")
            check(not stopped["warnings"], f"stop had no warnings {stopped['warnings']}")
            for name in ("traffic", "inventory"):
                path = Path(data_dir) / "assessments" / assessment_id / "evidence" / stopped[name]
                check(path.is_file(), f"evidence written: {stopped[name]}")
            check(device_proxy(args.device) == ":0", "device proxy is restored")

            inventory = await ok("endpoint_inventory", assessment_id=assessment_id)
            hosts = {endpoint["host"] for endpoint in inventory["endpoints"]}
            check(host in hosts, f"inventory contains {host}")

            status = await ok("assessment_status", assessment_id=assessment_id)
            check(status["state"] == "device_ready", "assessment still active after capture")

            events = await ok("assessment_events", assessment_id=assessment_id)
            kinds = [event["action"] for event in events["events"]]
            check("capture_started" in kinds, "capture_started event recorded")
            check("capture_stopped" in kinds, "capture_stopped event recorded")

            await ok("assessment_stop", assessment_id=assessment_id)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device", required=True, help="adb serial, e.g. 192.168.18.3:5555")
    parser.add_argument("--package", default="com.android.chrome", help="app to drive")
    parser.add_argument("--url", default="https://example.com/", help="URL to open")
    parser.add_argument(
        "--ca-method",
        default="user",
        choices=["user", "system", "bind", "magisk"],
        help="Barrel CA install method",
    )
    parser.add_argument("--timeout", type=int, default=40, help="seconds to wait for traffic")
    parser.add_argument("--data-dir", help="keep evidence here (default: temp dir)")
    args = parser.parse_args()

    asyncio.run(run(args))
    print("\nRESULT:", "PASS" if not failures else f"FAIL ({len(failures)})")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
