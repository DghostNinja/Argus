# Argus

Argus is an autonomous Android application security testing framework built
for enterprise-grade DAST, IAST and SAST-style mobile testing. It plans,
executes and evidences full assessments — configure a target, prove the device,
explore the UI, capture traffic, run controlled tests, then report — so testers
can hand off a scoped engagement and focus on other work. Barrel remains the
only component that talks to ADB; Barrel is proprietary and distributed as a
signed binary release.

Autonomy runs inside engine-enforced safety controls, not prompt promises:
authorization, scope, pause and stop are checked in code, every action is
state-gated, every secret is redacted, and every result is stored with
reproducible evidence.

```
MCP-capable agent (OpenCode, Claude Code, Codex, Cursor, ...)
  |  MCP stdio                      |  MCP stdio
  v                                 v
barrel-mcp (device truth)       argus-mcp (state, evidence, tests)
  |                                 |
  +--> adb / frida-server           +--> barrel-mcp child process
                                    +--> assessment store
                                    +--> HTTP replay engine
```

## What works now

| Phase | Capability | Status |
|-------|------------|--------|
| 1 | Assessment, architecture, safety model | Done |
| 2 | Device control, app lifecycle, UI exploration, screenshots, logcat | Done |
| 3 | Proxy capture, CA install, routing, endpoint inventory, action correlation | Done |
| 4 | Controlled security tests and request replay | Done |
| 5 | Reporting, severity, export | Done |
| 6 | Autonomous campaigns: unattended scoped runs, scheduling, device pools, regression diff | Planned |
| 7 | APK static triage: manifest, exported components, secrets, pinning config (SAST) | Planned |
| 8 | Runtime instrumentation via Frida: crypto/SSL checks, tamper and pinning detection (IAST) | Planned |
| 9 | Enterprise integration: headless CI, SARIF export, policy profiles, audit trail | Planned |

The MCP server exposes 37 tools. The Barrel 0.4.0 build exposes 43, including
the structured traffic tools Argus uses. See the
[Barrel docs](https://barrelhq.org/docs) for installation and release notes.
Design details and tradeoffs are in [docs/architecture.md](docs/architecture.md).

## How it works

### Components

- **Barrel** owns the device. It runs `adb`, the proxy, and CA installation, and
  returns structured JSON for traffic.
- **Argus** owns assessment state. It validates targets, gates every action,
  redacts output, writes evidence, and builds the endpoint inventory.
- **The agent harness** is the reasoning layer. OpenCode, Claude Code, Codex,
  Cursor or any other MCP stdio client can drive Argus; the harness chooses the
  next tool call and does not get raw device access outside Barrel.
- **The assessment store** is the durable record: state, steps, events, evidence.

### Assessment state machine

```
created -> configured -> device_ready -> installed -> explored -> testing -> reported
                                                    \-> paused / stopped
```

- `configure` records the package, optional APK (with SHA-256), device serial and
  allowed hosts.
- `start` asks Barrel for attached devices and moves to `device_ready`.
- `install` and `launch` are explicit; Argus never installs implicitly.
- `ui_dump` moves `installed` to `explored`.
- `testing_begin` moves `device_ready` (or later) to `testing` and unlocks
  replay and finding tools. API-only targets may skip install and exploration.
- `report_generate` writes the report and moves `testing` to `reported`.
  Reporting, replay and finding tools stay available afterwards, so findings
  can still be fixed and the report rebuilt.
- `pause` blocks every device action in the engine, not just in the prompt.
- `stop` is terminal for the session.

### Capture pipeline

1. `capture_start` starts Barrel's proxy, optionally installs its CA, and points
   the device at the proxy.
2. The app is driven with the UI tools.
3. `capture_entries` returns redacted request summaries.
4. `capture_correlate` maps requests to UI actions using timing only.
5. `capture_stop` restores routing, snapshots redacted traffic, and builds the
   endpoint inventory.

Inventory normalization turns `/v1/users/42` and `/v1/users/7` into
`GET https://host/v1/users/{id}`. UUIDs, hex ids and long tokens are templated
too. Query parameter names, status codes, content types, auth-header use and
sensitivity tags are aggregated per endpoint.

Correlation is explicitly `inferred`: the proxy sees time, not intent. Treat it
as a lead, not proof.

### Controlled tests

`testing_begin` opens the testing state. `replay_send` then issues one HTTP
request against an in-scope host and stores the redacted request/response as
evidence; `replay_compare` diffs two such runs into a verdict. Auth headers are
snapshotted from captured traffic into memory only (or supplied with
`auth_set`), merged into replay requests, and never persisted. Findings are
recorded with `finding_create`, moved through `potential` / `confirmed` /
`rejected` with `finding_update`, and listed with `finding_list`.

`report_generate` then writes `report.md`, `report.json` and `findings.csv`
into the assessment's evidence directory: severity-sorted findings with
evidence excerpts, endpoint coverage with an honest untested-endpoints note,
and a canonical JSON export. The first report moves the assessment to
`reported`; regenerating overwrites the files.

The engine enforces the safety rules itself: the host must be in
`allowed_hosts`, public hosts additionally require `allow_production`,
destructive methods such as `DELETE` are refused, and every replay writes
redacted evidence.

## Prerequisites

- Linux host with Python 3.11 or newer.
- `adb` on `PATH` and a ready device or emulator.
- A Barrel 0.4.0+ build from the public releases repo:
  [github.com/DghostNinja/barrel-releases/releases](https://github.com/DghostNinja/barrel-releases/releases).
  Earlier releases lack the structured traffic tools Argus needs. Barrel source
  is private; end users install the released `barrel-mcp` binary and point Argus
  at it. They do not clone or build Barrel. Docs:
  [barrelhq.org/docs](https://barrelhq.org/docs).
- Python dependencies (`mcp`, `httpx`, `pydantic`):

```sh
python3 -m venv .venv
.venv/bin/pip install -e .
```

- A rooted device is only needed for `system`, `bind` or `magisk` CA methods and
  for transparent proxy redirection. `user` CA install works without root, but
  Android 7+ apps do not trust user CAs unless their network security config
  allows it. Chrome does trust the user store.

## Quick start

### 1. Check the device

```sh
adb devices
```

If the list is empty, attach a device or start an emulator. For a wireless
device, connect first (`adb connect <ip>:<port>`).

### 2. Start Argus

```sh
python3 argus_mcp.py
```

The server speaks MCP over stdio and starts `barrel-mcp` during startup. It
fails fast if the Barrel binary is missing or the data directory is unusable.

Set `ARGUS_BARREL_BIN` to the installed Barrel binary if it is not on the
default development path:

```sh
export ARGUS_BARREL_BIN="$HOME/.local/bin/barrel-mcp"
python3 argus_mcp.py
```

### 3. Connect a harness

Argus is a standard MCP stdio server, so any MCP-capable harness can use it.
Register `argus`; optionally also register `barrel` for direct device
diagnosis. Point `ARGUS_BARREL_BIN` at the downloaded `barrel-mcp` release
binary.

**OpenCode** (`.opencode/opencode.jsonc`):

```json
{
  "mcp": {
    "argus": {
      "type": "local",
      "command": ["python3", "/path/to/Argus/argus_mcp.py"],
      "enabled": true,
      "environment": {
        "ARGUS_BARREL_BIN": "/path/to/barrel-mcp-linux-amd64",
        "ARGUS_DATA_DIR": "/home/you/.local/share/argus"
      }
    }
  }
}
```

**Claude Code** (`.mcp.json` in the project, or user scope):

```json
{
  "mcpServers": {
    "argus": {
      "command": "python3",
      "args": ["/path/to/Argus/argus_mcp.py"],
      "env": {
        "ARGUS_BARREL_BIN": "/path/to/barrel-mcp-linux-amd64",
        "ARGUS_DATA_DIR": "/home/you/.local/share/argus"
      }
    }
  }
}
```

**Codex CLI** (`~/.codex/config.toml`):

```toml
[mcp_servers.argus]
command = "python3"
args = ["/path/to/Argus/argus_mcp.py"]
env = { ARGUS_BARREL_BIN = "/path/to/barrel-mcp-linux-amd64", ARGUS_DATA_DIR = "/home/you/.local/share/argus" }
```

**Cursor** (`.cursor/mcp.json`) and **Gemini CLI** (`~/.gemini/settings.json`)
use the same `mcpServers` object as Claude Code.

The checked-in `.opencode/opencode.jsonc` uses portable defaults: a relative
path to `argus_mcp.py` in this clone and `~/.local/bin/barrel-mcp` for the
Barrel release binary. Override `ARGUS_BARREL_BIN` if your binary is installed
elsewhere. The harness-neutral operator prompt is in `.opencode/agent/argus.md`;
copy it into the system prompt or project instructions of whichever harness you
use. Root `AGENTS.md` and `CLAUDE.md` make the same rules discoverable to Codex
and Claude Code automatically.

### 4. Smoke test without a device

```sh
python3 scripts/mcp_smoke.py
```

This starts the server exactly as a harness does and checks the tool surface,
state gates, error handling and event log. It expects 37 tools.

### 5. Live capture test with a device

```sh
python3 scripts/live_capture.py \
  --device 192.168.18.3:5555 \
  --package com.android.chrome \
  --url https://example.com/ \
  --ca-method user \
  --data-dir /tmp/argus-live
```

It walks an assessment to `device_ready`, starts capture, drives the browser,
asserts that an HTTPS request was decrypted (not just `CONNECT`), stops capture
and checks the evidence. Use `--ca-method bind` on a rooted device if the app
does not trust the user store.

## Using Argus from a harness

A typical session (the wording works in any harness):

```text
Use the argus agent to assess com.example.app on device emulator-5554.
Create an assessment, configure the package and allowed host api.example.com,
start it, install the APK at ./app-debug.apk, launch it, then log in with the
test account and capture traffic.
```

The agent then calls, in order:

```text
assessment_create            -> id
assessment_configure         -> package, apk_path, device, allowed_hosts
assessment_start             -> device_ready
app_install                  -> installed
app_launch
ui_dump / ui_find / ui_tap_node / ui_text
capture_start(install_ca=true, ca_method="user", route=true)
capture_entries
capture_correlate
capture_stop
endpoint_inventory
testing_begin
replay_send / replay_compare
finding_create / finding_list
report_generate
```

Rules the engine enforces:

- No device action before `device_ready`.
- No capture before an active device state.
- No action while paused or stopped.
- Malformed assessment ids, package names, device serials, hosts, UI text and
  key events are rejected before they reach a shell.
- Production hosts are refused unless `allow_production` is set.
- Replay and finding tools require the `testing` state, an in-scope host and a
  non-destructive method; auth headers are memory-only.

Passwords and tokens must be sent with `ui_text(..., sensitive=true)`. The value
still reaches the device but is never written to events or evidence.

## Tool reference

Harnesses prefix these with the server name, for example
`argus_assessment_create` or `mcp__argus__assessment_create`.

### Lifecycle

| Tool | Arguments | Result |
|------|-----------|--------|
| `assessment_create` | `name` | New assessment id |
| `assessment_configure` | `assessment_id`, `package`, `apk_path`, `device`, `allowed_hosts`, `allow_production` | Configured target |
| `assessment_start` | `assessment_id` | `device_ready`, device serial |
| `assessment_pause` | `assessment_id` | Paused |
| `assessment_resume` | `assessment_id` | Resumed |
| `assessment_stop` | `assessment_id` | Terminal stop |
| `assessment_status` | `assessment_id` | Full record |
| `assessment_list` | none | Assessments, newest first |
| `assessment_events` | `assessment_id`, `limit` | Redacted events |
| `device_list` | none | Ready serials |

### App and UI

| Tool | Arguments | Result |
|------|-----------|--------|
| `app_install` | `assessment_id` | Installs the configured APK |
| `app_launch` | `assessment_id` | Launches the package |
| `app_stop` | `assessment_id` | Force-stops, keeps data |
| `ui_dump` | `assessment_id`, `limit` | Parsed nodes with bounds and centers |
| `ui_find` | `assessment_id`, `text`, `resource_id`, `content_desc`, `clickable`, `exact`, `limit` | Matching nodes |
| `ui_tap` | `assessment_id`, `x`, `y` | Tap by pixel |
| `ui_tap_node` | `assessment_id`, `text`, `resource_id`, `content_desc`, `exact` | Taps best enabled match |
| `ui_text` | `assessment_id`, `text`, `submit`, `sensitive` | Types into the focused field |
| `ui_key` | `assessment_id`, `keyevent` | Sends a key event |
| `ui_swipe` | `assessment_id`, `x1`, `y1`, `x2`, `y2`, `duration_ms` | Swipe |
| `screenshot` | `assessment_id`, `label` | PNG in evidence |
| `logcat_tail` | `assessment_id`, `lines`, `filter` | Redacted logcat |

### Traffic

| Tool | Arguments | Result |
|------|-----------|--------|
| `capture_start` | `assessment_id`, `install_ca`, `ca_method`, `route` | Proxy status, CA and routing result |
| `capture_status` | `assessment_id` | Running, port, CA path, counts |
| `capture_entries` | `assessment_id`, `limit` | Redacted request summaries |
| `capture_correlate` | `assessment_id`, `limit` | Inferred action-to-request mapping |
| `capture_stop` | `assessment_id` | Restores routing, writes evidence and inventory |
| `endpoint_inventory` | `assessment_id` | Stored endpoints and tags |

`ca_method` is one of `user`, `system`, `bind`, `magisk`:

- `user`: no root, Chrome trusts it, not trusted by most apps.
- `system`: needs root, writes the system store, reboot required.
- `bind`: needs root, active immediately, gone after reboot.
- `magisk`: needs root, durable module, reboot required.

### Testing

| Tool | Arguments | Result |
|------|-----------|--------|
| `testing_begin` | `assessment_id` | Enters the `testing` state (idempotent) |
| `auth_set` | `assessment_id`, `host`, `headers` | In-memory auth headers for one host |
| `auth_clear` | `assessment_id`, `host` | Drops stored auth headers |
| `replay_send` | `assessment_id`, `method`, `url`, `headers`, `body`, `use_auth` | One in-scope request plus redacted evidence |
| `replay_compare` | `assessment_id`, `baseline`, `variant` | Structured diff of two replay evidence files |
| `finding_create` | `assessment_id`, `title`, `severity`, `confidence`, `status`, `endpoint`, `description`, `evidence` | New finding |
| `finding_update` | `assessment_id`, `finding_id`, `status`, `note` | Updated finding status |
| `finding_list` | `assessment_id` | Findings with counts per status |

`severity` is `critical`, `high`, `medium`, `low` or `info`; `confidence` and
`status` use `high`/`medium`/`low` and `potential`/`confirmed`/`rejected`.
Replay refuses out-of-scope hosts, public hosts without `allow_production`,
and destructive methods. Auth values live only in process memory: events and
evidence record header names, never values.

### Reporting

| Tool | Arguments | Result |
|------|-----------|--------|
| `report_generate` | `assessment_id`, `formats` | Writes `report.md`, `report.json` and/or `findings.csv` into evidence; moves `testing` to `reported` |

`formats` defaults to `["md", "json", "csv"]`. The Markdown report sorts
confirmed findings first by severity, embeds one-line excerpts from replay
evidence, tables every inventoried endpoint, and states how many endpoints
have no finding recorded — absence of a finding is not proof of safety.

## Traffic workflow in detail

### HTTP and HTTPS

`capture_start(install_ca=false)` captures plain HTTP and HTTPS `CONNECT`
metadata. To see HTTPS headers and bodies, install the CA and make sure the app
trusts it. If the app pins certificates or ignores the system proxy, capture will
show a trust or connection error for that host; that is a finding about the app,
not a tool failure.

### What is stored

At `capture_stop`:

- `traffic-<timestamp>.json`: redacted requests and responses.
- `endpoints-<timestamp>.json`: the normalized endpoint inventory.

Sensitive headers (`Authorization`, `Cookie`, `Set-Cookie`, API keys, CSRF
tokens) are replaced with `***`. URLs and text bodies are redacted for bearer
tokens, JWTs and `token=...`-style pairs. Binary bodies are not written.

### Capture limits

Barrel returns at most the 200 most recent entries per call. For long sessions,
stop and inspect in batches, or call `capture_entries` periodically. Argus stores
what it can see at `capture_stop`; it does not claim a complete packet capture.

### Endpoint tags

The inventory tags endpoints by path and query keywords:

`authentication`, `admin`, `account`, `transaction`, `upload`, `export`,
`debug`, `graphql`.

These are leads for testing, not vulnerabilities.

## Evidence and data layout

```
$ARGUS_DATA_DIR/assessments/<32 hex id>/
  assessment.json      # 0600: state, target, APK hash, endpoints, steps
  events.jsonl         # 0600: redacted action log
  evidence/            # 0700: screenshots, traffic, inventory
```

Directories are `0700`; files are `0600`. Assessment ids are validated against
`^[0-9a-f]{32}$`; every path is checked to stay inside the store. Evidence names
are sanitized and cannot traverse directories.

## Configuration

| Variable | Default | Meaning |
|----------|---------|---------|
| `ARGUS_BARREL_BIN` | `~/.local/bin/barrel-mcp` | Installed Barrel MCP binary |
| `ARGUS_DATA_DIR` | `~/.local/share/argus` | Assessment store |
| `ARGUS_CALL_TIMEOUT` | `60` | Per-tool timeout in seconds |
| `ARGUS_REDACT_EXTRA` | empty | Extra comma-separated regexes to redact |

No credential, token or API key is read from source or written to the store.

## Safety model

- Explicit target, device and scope before any action.
- Engine-level pause and stop, independent of the prompt.
- No destructive or financial actions are exposed.
- Shell arguments are validated and single-quoted before use.
- UI XML is size-capped and DTD/entity declarations are rejected.
- Secrets are redacted in events, logcat, traffic and evidence.
- `sensitive=true` drops the typed value from the event log entirely.
- The standalone `barrel` server stays available for diagnosis, but normal
  workflows must go through Argus so state and evidence stay consistent.

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `no ready device connected` | No adb device | Attach or start one; `adb devices` |
| `multiple devices attached` | Ambiguous target | Set `device` in `assessment_configure` |
| `assessment state is configured` | Capture before `start` | Call `assessment_start` first |
| `capture_start` fails on CA | No root for chosen method | Use `user`, or root the device |
| HTTPS entries show `CONNECT` only | CA not trusted | Install CA; check app trust config |
| `trust` / `pinning` error | App pins certificates | Record as a finding; do not bypass blindly |
| Empty `ui_dump` | Compose, Flutter, game or `FLAG_SECURE` | Use `screenshot` and coordinates |
| Proxy ignored by app | App bypasses system proxy | Root + Barrel `traffic_transparent_set` (separate process; see limits) |
| `barrel MCP binary not found` | Barrel not installed or wrong path | Install a Barrel 0.4.0 release; set `ARGUS_BARREL_BIN` |
| Store permission error | Bad `ARGUS_DATA_DIR` | Use a writable directory; do not loosen permissions |

## Development

```sh
python3 -m unittest discover -s tests -v
python3 -m compileall -q argus argus_mcp.py
python3 scripts/mcp_smoke.py
```

The suite covers UI parsing and ranking, redaction, secure storage, the
assessment state machine, capture flow with a fake Barrel, inventory
normalization, correlation and evidence writing. No device is needed for unit
tests or the smoke test.

## Known limits

- Phase 5 ships Markdown, JSON and CSV reporting. There is no HTML/SARIF
  export, no automatic severity scoring and no retest tracking yet; severity
  and confidence are assigned by the operator. Planned phases 6–9 are listed
  in the phase table above. Phase 4 canned exploit modules are not
  implemented; the agent composes multi-step checks itself.
- The capture window is the 200 most recent Barrel entries.
- Correlation is timing-based and can attribute background traffic to the wrong
  action.
- Transparent proxy mode is not exposed through Argus yet; the standalone Barrel
  server owns a different proxy process, so use it only for diagnosis.
- `uiautomator` cannot see some Compose, Flutter, game and `FLAG_SECURE` screens.
- The capture backend is pluggable, so a Burp or Caido backend can be added
  without changing the assessment engine.

## License and distribution

Argus license: not set yet. Barrel is proprietary and source-private; only its
compiled releases are distributed. A public Argus release must therefore depend
on an official Barrel binary, pin a tested Barrel version, and avoid
redistributing Barrel source or internal build artifacts.

Do not publish a release until the Argus license, Barrel version pin and
third-party notices are decided.
