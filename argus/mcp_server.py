"""Argus MCP server. Exposes assessment tools to OpenCode over stdio."""

from __future__ import annotations

from collections.abc import Awaitable
from contextlib import asynccontextmanager
from dataclasses import dataclass

from mcp.server.fastmcp import Context, FastMCP
from mcp.server.fastmcp.exceptions import ToolError

from .barrel_client import BarrelClient
from .config import Config
from .errors import ArgusError
from .models import Assessment
from .orchestrator import Orchestrator, parse_device_serials
from .store import AssessmentStore

INSTRUCTIONS = """Argus is an autonomous Android application security testing
framework built on Barrel. Workflow: assessment_create, assessment_configure,
assessment_start, app_install, app_launch, then explore with ui_dump, ui_find,
ui_tap_node, ui_text, ui_key and ui_swipe. For traffic discovery call
capture_start, drive the app, then capture_entries; capture_stop stores redacted
traffic plus the endpoint inventory. capture_correlate only infers which
requests followed an action from timing, so verify before reporting. When the
app is explored, call testing_begin; replay in-scope requests with replay_send
(auth is snapshotted from capture or supplied via auth_set), compare two runs
with replay_compare, and record results with finding_create, finding_update and
finding_list. Capture screenshots and logcat as evidence. All device access goes
through Barrel. Never ask for or store credentials: pass a password to ui_text
with sensitive=true so it is not logged. Respect pause and stop. Do not attempt
destructive or financial actions; the engine refuses them. If a device action
fails, read the error and fix the cause (device not attached, app not
installed, UI not idle)."""


@dataclass
class Runtime:
    config: Config
    store: AssessmentStore
    barrel: BarrelClient
    orchestrator: Orchestrator


@asynccontextmanager
async def lifespan(_server: FastMCP):
    config = Config.load()
    store = AssessmentStore(config.data_dir)
    barrel = BarrelClient(config)
    runtime = Runtime(
        config=config,
        store=store,
        barrel=barrel,
        orchestrator=Orchestrator(config, store, barrel),
    )
    # The MCP client session owns an anyio task group. It must be entered and
    # exited in the long-lived lifespan task, never inside a per-request tool
    # task, or anyio raises a cancel-scope error on the next request.
    await barrel.start()
    try:
        yield runtime
    finally:
        await barrel.close()


app = FastMCP("argus", instructions=INSTRUCTIONS, lifespan=lifespan)


def _rt(ctx: Context) -> Runtime:
    runtime = ctx.request_context.lifespan_context
    if not isinstance(runtime, Runtime):
        raise ToolError("argus runtime is not available")
    return runtime


async def _run(awaitable: Awaitable):
    try:
        return await awaitable
    except ArgusError as exc:
        raise ToolError(str(exc)) from exc


def _summary(assessment: Assessment) -> dict:
    return {
        "id": assessment.id,
        "name": assessment.name,
        "state": assessment.state.value,
        "paused": assessment.paused,
        "stopped": assessment.stopped,
        "device": assessment.device,
        "package": assessment.package or assessment.target.package,
        "target": assessment.target.model_dump(mode="json"),
        "created_at": assessment.created_at,
        "updated_at": assessment.updated_at,
    }


@app.tool()
async def assessment_create(ctx: Context, name: str) -> dict:
    """Create a new assessment. This is always the first step. Returns the id
    used by every other tool."""
    runtime = _rt(ctx)
    return _summary(await _run(runtime.orchestrator.create(name)))


@app.tool()
async def assessment_configure(
    ctx: Context,
    assessment_id: str,
    package: str | None = None,
    apk_path: str | None = None,
    device: str | None = None,
    allowed_hosts: list[str] | None = None,
    allow_production: bool = False,
) -> dict:
    """Configure the target before starting. package is the Android package
    name. apk_path is a local APK to install; its SHA-256 is recorded.
    allowed_hosts restricts later network testing; production hosts are refused
    unless allow_production is set for this assessment."""
    runtime = _rt(ctx)
    assessment = await _run(
        runtime.orchestrator.configure(
            assessment_id,
            package=package,
            apk_path=apk_path,
            device=device,
            allowed_hosts=allowed_hosts,
            allow_production=allow_production,
        )
    )
    return _summary(assessment)


@app.tool()
async def assessment_start(ctx: Context, assessment_id: str) -> dict:
    """Verify the device through Barrel and move the assessment to device_ready.
    Fails with the list of serials when several devices are attached."""
    runtime = _rt(ctx)
    return _summary(await _run(runtime.orchestrator.start(assessment_id)))


@app.tool()
async def assessment_pause(ctx: Context, assessment_id: str) -> dict:
    """Pause the assessment. Every device action is refused until resume."""
    runtime = _rt(ctx)
    return _summary(await _run(runtime.orchestrator.pause(assessment_id)))


@app.tool()
async def assessment_resume(ctx: Context, assessment_id: str) -> dict:
    """Resume a paused assessment."""
    runtime = _rt(ctx)
    return _summary(await _run(runtime.orchestrator.resume(assessment_id)))


@app.tool()
async def assessment_stop(ctx: Context, assessment_id: str) -> dict:
    """Stop the assessment. This is terminal for the session and is never
    undone by resume."""
    runtime = _rt(ctx)
    return _summary(await _run(runtime.orchestrator.stop(assessment_id)))


@app.tool()
async def assessment_status(ctx: Context, assessment_id: str) -> dict:
    """Full assessment record: state, target, device, package and recent steps.
    Call this before acting when you are unsure of the current state."""
    runtime = _rt(ctx)
    return await _run(_status(runtime, assessment_id))


async def _status(runtime: Runtime, assessment_id: str) -> dict:
    return runtime.orchestrator.status(assessment_id)


@app.tool()
async def assessment_list(ctx: Context) -> dict:
    """List assessments on disk, newest first."""
    runtime = _rt(ctx)
    return {"assessments": runtime.orchestrator.list_assessments()}


@app.tool()
async def assessment_events(ctx: Context, assessment_id: str, limit: int = 50) -> dict:
    """Recent redacted action events for an assessment, oldest first within the
    returned window. Credentials never appear here."""
    runtime = _rt(ctx)
    return {"events": await _run(_events(runtime, assessment_id, limit))}


async def _events(runtime: Runtime, assessment_id: str, limit: int) -> list[dict]:
    return runtime.orchestrator.events(assessment_id, limit)


@app.tool()
async def device_list(ctx: Context) -> dict:
    """List ready Android devices through Barrel. Use it when assessment_start
    reports that no device is ready or that several are attached."""
    runtime = _rt(ctx)
    output = await _run(runtime.barrel.list_devices())
    return {"serials": parse_device_serials(output), "raw": output}


@app.tool()
async def app_install(ctx: Context, assessment_id: str) -> dict:
    """Install the configured APK with adb install (reinstall and grant runtime
    permissions). Fails unless adb reports Success."""
    runtime = _rt(ctx)
    return await _run(runtime.orchestrator.install(assessment_id))


@app.tool()
async def app_launch(ctx: Context, assessment_id: str) -> dict:
    """Launch the configured package and bring it to the foreground."""
    runtime = _rt(ctx)
    return await _run(runtime.orchestrator.launch(assessment_id))


@app.tool()
async def app_stop(ctx: Context, assessment_id: str) -> dict:
    """Force-stop the configured package. Does not clear app data."""
    runtime = _rt(ctx)
    return await _run(runtime.orchestrator.app_stop(assessment_id))


@app.tool()
async def ui_dump(ctx: Context, assessment_id: str, limit: int = 100) -> dict:
    """Dump the current UI hierarchy. Returns nodes with text, resource id,
    content description, class, clickable/focused flags, bounds and center.
    Tap a center point, or use ui_tap_node with a label."""
    runtime = _rt(ctx)
    return await _run(runtime.orchestrator.ui_dump(assessment_id, limit))


@app.tool()
async def ui_find(
    ctx: Context,
    assessment_id: str,
    text: str | None = None,
    resource_id: str | None = None,
    content_desc: str | None = None,
    clickable: bool | None = None,
    exact: bool = False,
    limit: int = 20,
) -> dict:
    """Find UI nodes by visible text, resource id or content description.
    Matching is case-insensitive substring unless exact=true. Use it before
    tapping to avoid blind coordinates."""
    runtime = _rt(ctx)
    return await _run(
        runtime.orchestrator.ui_find(
            assessment_id,
            text=text,
            resource_id=resource_id,
            content_desc=content_desc,
            clickable=clickable,
            exact=exact,
            limit=limit,
        )
    )


@app.tool()
async def ui_tap(ctx: Context, assessment_id: str, x: int, y: int) -> dict:
    """Tap device pixels. Prefer ui_tap_node with a label; use this only when a
    node has no usable text or id."""
    runtime = _rt(ctx)
    return await _run(runtime.orchestrator.ui_tap(assessment_id, x, y))


@app.tool()
async def ui_tap_node(
    ctx: Context,
    assessment_id: str,
    text: str | None = None,
    resource_id: str | None = None,
    content_desc: str | None = None,
    exact: bool = False,
) -> dict:
    """Dump the hierarchy, pick the best matching enabled node and tap its
    center. Provide at least one selector. Returns the tapped node."""
    runtime = _rt(ctx)
    return await _run(
        runtime.orchestrator.ui_tap_node(
            assessment_id,
            text=text,
            resource_id=resource_id,
            content_desc=content_desc,
            exact=exact,
        )
    )


@app.tool()
async def ui_text(
    ctx: Context,
    assessment_id: str,
    text: str,
    submit: bool = False,
    sensitive: bool = False,
) -> dict:
    """Type into the focused field. Tap the field first. Set sensitive=true for
    passwords and tokens so the value is not written to events; it is still sent
    to the device and is never persisted by Argus."""
    runtime = _rt(ctx)
    return await _run(
        runtime.orchestrator.ui_text(
            assessment_id, text, submit=submit, sensitive=sensitive
        )
    )


@app.tool()
async def ui_key(ctx: Context, assessment_id: str, keyevent: str) -> dict:
    """Send a key event, for example KEYCODE_ENTER, KEYCODE_BACK or 66."""
    runtime = _rt(ctx)
    return await _run(runtime.orchestrator.ui_key(assessment_id, keyevent))


@app.tool()
async def ui_swipe(
    ctx: Context,
    assessment_id: str,
    x1: int,
    y1: int,
    x2: int,
    y2: int,
    duration_ms: int = 300,
) -> dict:
    """Swipe between two device points. Use for scrolling and gesture-only
    flows."""
    runtime = _rt(ctx)
    return await _run(
        runtime.orchestrator.ui_swipe(assessment_id, x1, y1, x2, y2, duration_ms)
    )


@app.tool()
async def screenshot(ctx: Context, assessment_id: str, label: str = "screen") -> dict:
    """Capture the screen into the assessment evidence directory and return its
    local path. Read the file with your normal file tool to see the image."""
    runtime = _rt(ctx)
    return await _run(runtime.orchestrator.screenshot(assessment_id, label))


@app.tool()
async def logcat_tail(
    ctx: Context,
    assessment_id: str,
    lines: int = 200,
    filter: str | None = None,
) -> dict:
    """Return recent logcat lines for crash and exception detection. The output
    is redacted before it is returned."""
    runtime = _rt(ctx)
    return await _run(runtime.orchestrator.logcat(assessment_id, lines, filter))


@app.tool()
async def capture_start(
    ctx: Context,
    assessment_id: str,
    install_ca: bool = False,
    ca_method: str = "user",
    route: bool = True,
) -> dict:
    """Start Barrel's proxy, optionally install its CA on the device (user,
    system, bind or magisk), and route the device through the proxy. HTTPS is
    only decrypted when the CA is installed and trusted by the app."""
    runtime = _rt(ctx)
    return await _run(
        runtime.orchestrator.capture_start(
            assessment_id,
            install_ca=install_ca,
            ca_method=ca_method,
            route=route,
        )
    )


@app.tool()
async def capture_status(ctx: Context, assessment_id: str) -> dict:
    """Report whether the proxy is running, its port and CA path, and how many
    requests are captured."""
    runtime = _rt(ctx)
    return await _run(runtime.orchestrator.capture_status(assessment_id))


@app.tool()
async def capture_entries(ctx: Context, assessment_id: str, limit: int = 100) -> dict:
    """List captured requests as redacted summaries (no headers or bodies).
    Use this to discover endpoints while testing."""
    runtime = _rt(ctx)
    return await _run(runtime.orchestrator.capture_entries(assessment_id, limit))


@app.tool()
async def capture_stop(ctx: Context, assessment_id: str) -> dict:
    """Stop the proxy, restore the device routing, then store redacted traffic
    and the endpoint inventory as evidence. Returns the counts and file names."""
    runtime = _rt(ctx)
    return await _run(runtime.orchestrator.capture_stop(assessment_id))


@app.tool()
async def capture_correlate(ctx: Context, assessment_id: str, limit: int = 200) -> dict:
    """Approximate which captured requests followed which UI action. Every
    mapping is inferred from timing; confirm it before reporting."""
    runtime = _rt(ctx)
    return await _run(runtime.orchestrator.capture_correlate(assessment_id, limit))


@app.tool()
async def endpoint_inventory(ctx: Context, assessment_id: str) -> dict:
    """Return the endpoint inventory built at capture_stop: method, host,
    normalized path, query parameter names, status codes, auth use and
    sensitivity tags."""
    runtime = _rt(ctx)
    return await _run(runtime.orchestrator.endpoint_inventory(assessment_id))


@app.tool()
async def testing_begin(ctx: Context, assessment_id: str) -> dict:
    """Move the assessment into the testing state so replay_send,
    replay_compare and finding tools become available. Requires a proven device
    (device_ready or later). Idempotent when already testing."""
    runtime = _rt(ctx)
    return _summary(await _run(runtime.orchestrator.testing_begin(assessment_id)))


@app.tool()
async def auth_set(
    ctx: Context, assessment_id: str, host: str, headers: dict
) -> dict:
    """Store live auth headers (Authorization, Cookie, X-API-Key and similar)
    for one in-scope host in memory only. Values are never persisted and never
    appear in events; only header names are logged. replay_send merges them
    automatically. Captured traffic also snapshots these headers per host."""
    runtime = _rt(ctx)
    return await _run(runtime.orchestrator.auth_set(assessment_id, host, headers))


@app.tool()
async def auth_clear(ctx: Context, assessment_id: str, host: str | None = None) -> dict:
    """Drop stored auth headers for one host, or for every host of the
    assessment when host is omitted."""
    runtime = _rt(ctx)
    return await _run(runtime.orchestrator.auth_clear(assessment_id, host))


@app.tool()
async def replay_send(
    ctx: Context,
    assessment_id: str,
    method: str,
    url: str,
    headers: dict | None = None,
    body: str | None = None,
    use_auth: bool = True,
) -> dict:
    """Send one HTTP request to an in-scope host and store the redacted
    request/response as evidence. Requires the testing state. The host must be
    in allowed_hosts; public hosts additionally require allow_production.
    Destructive methods (DELETE and friends) are refused by the engine. Set
    use_auth=false to send without the stored auth headers. Returns the
    evidence file name for finding_create and replay_compare."""
    runtime = _rt(ctx)
    return await _run(
        runtime.orchestrator.replay_send(
            assessment_id,
            method,
            url,
            headers=headers,
            body=body,
            use_auth=use_auth,
        )
    )


@app.tool()
async def replay_compare(
    ctx: Context, assessment_id: str, baseline: str, variant: str
) -> dict:
    """Diff two replay evidence file names produced by replay_send. Reports
    status changes, body length delta, JSON key differences and a verdict of
    'difference detected' or 'no difference'. A difference is a lead, not a
    finding: confirm it with a repeat run before reporting."""
    runtime = _rt(ctx)
    return await _run(
        runtime.orchestrator.replay_compare(assessment_id, baseline, variant)
    )


@app.tool()
async def finding_create(
    ctx: Context,
    assessment_id: str,
    title: str,
    severity: str,
    confidence: str,
    status: str = "potential",
    endpoint: str | None = None,
    description: str = "",
    evidence: list[str] | None = None,
) -> dict:
    """Record a finding in the testing state. severity: critical, high,
    medium, low or info. confidence: high, medium or low. status: potential,
    confirmed or rejected. evidence lists replay evidence or other evidence
    file names that prove the claim; each must already exist."""
    runtime = _rt(ctx)
    return await _run(
        runtime.orchestrator.finding_create(
            assessment_id,
            title=title,
            severity=severity,
            confidence=confidence,
            status=status,
            endpoint=endpoint,
            description=description,
            evidence=evidence,
        )
    )


@app.tool()
async def finding_update(
    ctx: Context,
    assessment_id: str,
    finding_id: str,
    status: str,
    note: str | None = None,
) -> dict:
    """Change a finding's status (potential, confirmed or rejected) and
    optionally append a note to its description. Use confirmed only when the
    evidence reproduces the issue."""
    runtime = _rt(ctx)
    return await _run(
        runtime.orchestrator.finding_update(
            assessment_id, finding_id, status, note=note
        )
    )


@app.tool()
async def finding_list(ctx: Context, assessment_id: str) -> dict:
    """List the assessment's findings with counts per status."""
    runtime = _rt(ctx)
    return runtime.orchestrator.finding_list(assessment_id)


def main() -> None:
    app.run("stdio")


if __name__ == "__main__":
    main()
