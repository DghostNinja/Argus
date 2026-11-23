# Argus architecture

This document explains the boundaries, the state model, the traffic pipeline
and the decisions that shape later phases.

## 1. Purpose

Argus is an autonomous Android application security testing framework. It
gives an AI agent a structured way to:

- prove a target and device before touching anything,
- drive an app through its UI,
- capture traffic through a proxy,
- build an endpoint inventory,
- record reproducible evidence,
- and, in later phases, run controlled security tests autonomously.

Autonomy is the goal: a tester scopes an assessment and Argus executes the
workflow unattended, inside engine-enforced authorization, scope and stop
controls. It remains a state machine with a small, auditable tool surface —
enterprise reliability comes from gates in code, not from the prompt.

## 2. Boundaries

```
MCP-capable agent
  |  MCP stdio                      |  MCP stdio
  v                                 v
Barrel (device truth)           Argus (state, evidence, tests)
  |                                 |
  +--> adb / frida-server           +--> Barrel MCP client
                                    +--> assessment store
                                    +--> replay engine (Phase 4)
```

- **Barrel** is the only component that talks to ADB. It owns device state,
  installation, UI interaction, screenshots, logcat, proxy capture and CA
  installation. It is a proprietary binary dependency; its source is private.
- **Argus** owns assessment state, validation, redaction, evidence and the
  security test engine. It never shells out to ADB directly.
- **The agent** is the reasoning layer. It selects the next tool call and
  interprets results. It does not receive unrestricted shell access for normal
  workflows.

The process boundary is deliberate: Barrel stays useful on its own, and Argus
can change its test engine without forking device code.

## 3. Design principles

1. **Engine-enforced safety.** Authorization, scope, pause and stop are checked
   in code, not left to the prompt.
2. **Evidence over assertion.** A finding needs a stored request, response, UI
   state or log that proves the property is broken.
3. **Minimum proof.** Demonstrate impact with one record or one action, then
   stop. No enumeration, persistence or destructive follow-through.
4. **Least privilege.** No raw shell in the normal workflow, no destructive
   actions, no financial actions.
5. **Secrets stay out of storage.** Redaction is applied before events,
   evidence and traffic are written.
6. **Explicit uncertainty.** Timing-based correlation and heuristic tags are
   labelled `inferred` or `candidate`, never `confirmed`.

## 4. Assessment lifecycle

```
created -> configured -> device_ready -> installed -> explored -> testing
                    \-> paused / stopped
```

- `created`: an id and a name exist. No target yet.
- `configured`: package, optional APK (with SHA-256), device and allowed hosts
  are recorded.
- `device_ready`: Barrel confirmed a ready device and the serial was chosen.
- `installed`: the APK was installed successfully.
- `explored`: the UI hierarchy was read at least once.
- `testing`: reserved for the Phase 4 test engine.
- `paused`: every device action is refused until resume.
- `stopped`: terminal for the session; resume cannot undo it.

Every transition is persisted, so a new harness process can resume from the
stored state. The orchestrator, not the model, enforces order.

## 5. Data and evidence

```
$ARGUS_DATA_DIR/assessments/<32 hex id>/
  assessment.json      # state, target, APK hash, endpoints, steps
  events.jsonl         # redacted action log
  evidence/            # screenshots, traffic snapshots, inventory
```

- Directories are `0700`; files are `0600`.
- Assessment ids are validated against `^[0-9a-f]{32}$`.
- Every path is checked to stay inside the assessment directory.
- Evidence names are sanitized and cannot traverse directories.
- Events and evidence are redacted before writing.

The store is the source of truth for an assessment. Tool responses are views;
the durable record is on disk.

## 6. Traffic capture pipeline

1. `capture_start` starts Barrel's proxy, optionally installs its CA, and routes
   the device through it.
2. The agent drives the app with UI tools.
3. `capture_entries` returns redacted request summaries.
4. `capture_correlate` maps requests to UI actions using timing.
5. `capture_stop` restores routing, writes redacted traffic, and builds the
   endpoint inventory.

The proxy backend is an interface. Barrel is the first implementation; a Burp
or Caido backend can be added without changing the assessment engine.

### CA methods

| Method | Root | Trust scope | Persistence |
|--------|------|-------------|-------------|
| `user` | No | Chrome and apps that trust the user store | Until removed |
| `system` | Yes | System store | Survives reboot; reboot required |
| `bind` | Yes | System store overlay | Until reboot |
| `magisk` | Yes | System store via module | Until removed; reboot required |

Android 7+ apps do not trust user CAs by default. A trust failure is a finding
about the app, not a tool failure.

### Capture limits

Barrel returns at most the 200 most recent entries per call. Argus snapshots
what it can see at `capture_stop`; it does not claim a complete packet capture.
Long sessions should be stopped and inspected in batches.

## 7. Endpoint inventory

Requests are normalized into method plus host plus templated path:

```
GET https://api.example.com/v1/users/{id}
POST https://api.example.com/v1/orders
```

- Numeric segments, UUIDs, long hex ids and long token-like segments are
  templated.
- Query parameter names are aggregated, not values.
- Status codes and content types are collected per endpoint.
- Auth use is recorded when a recognized auth header is present.
- Sensitivity tags are heuristic: `authentication`, `admin`, `account`,
  `transaction`, `upload`, `export`, `debug`, `graphql`.

Tags are leads for testing, not vulnerabilities.

## 8. Action correlation

The proxy sees time, not intent. Correlation assigns each request to the
nearest UI action window within a bounded slack. The result is always labelled
`inferred`.

Rules:

- A mapping is a lead, not proof.
- Background traffic can be attributed to the wrong action.
- Confirmation needs a repeat, a unique endpoint, or an instrumented marker.

## 9. Safety controls

- Explicit target and device before any action.
- Scope allowlist for network testing.
- Production hosts refused unless explicitly allowed per assessment.
- Pause and stop enforced in the engine.
- No destructive or financial actions are exposed.
- UI input is validated and escaped before it reaches the device shell.
- UI XML is size-capped and DTD/entity declarations are rejected.
- Credentials are never stored; `sensitive=true` drops the value from events.
- Traffic headers, URLs and text bodies are redacted before storage.

## 10. Key decisions and tradeoffs

| Decision | Why | Cost |
|----------|-----|------|
| Barrel remains the only ADB owner | One device truth, no duplicate implementations | Argus depends on a Barrel build |
| Structured tools instead of raw shell | Auditable, validatable, safer for an LLM | New device capability needs a Barrel tool |
| Barrel proxy as the first capture backend | No extra install; structured entries | Burp-specific features wait |
| Pluggable backend interface | Swap capture engines without touching tests | Slight abstraction overhead |
| Engine-enforced gates | The model cannot be trusted to enforce safety | Some workflows need explicit operator steps |
| Redaction before storage | Evidence is shareable and safe | Replay needs live auth, not stored secrets |
| Timing-based correlation | No app instrumentation required | Inferred, can misattribute |

## 11. Extension points

- **Capture backend:** implement the proxy interface for Burp, Caido or a custom
  proxy.
- **Test engine (Phase 4):** replay with preserved auth context, baseline and
  variant comparison, auth/authz/API/logic modules.
- **Reporting (Phase 5):** JSON canonical output plus Markdown/HTML, with
  confirmed and candidate findings separated.
- **Campaigns (Phase 6):** goal-driven unattended runs, scheduling, checkpoint
  and resume, device pools, regression diffing against a previous run.
- **Static triage (Phase 7):** APK manifest and artifact analysis that feeds
  hypotheses into the dynamic engine.
- **Runtime instrumentation (Phase 8):** Frida-based hooks through Barrel for
  crypto, TLS validation and tamper evidence.
- **Enterprise integration (Phase 9):** headless CI mode, SARIF export, policy
  profiles and audit trails.
- **Runtime checks:** pinning, root and tamper detection through the existing
  instrumentation surface.
- **Harnesses:** any MCP stdio client can drive the same tool surface.

## 12. Non-goals

- Out-of-scope testing: work outside the configured package, device or host
  allowlist, even unattended.
- Lateral movement, persistence, destructive testing, data exfiltration or
  denial of service.
- Financial transactions or real-user data.
- Replacing Barrel's device tooling.
- Guaranteeing full traffic visibility on pinned or non-HTTP transports.
