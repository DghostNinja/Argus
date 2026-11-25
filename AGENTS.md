# Argus operator instructions

Argus is an autonomous Android application security testing framework. It is
driven through MCP tools; Barrel is the only component that talks to ADB. The
full blackbelt operator prompt lives in `.opencode/agent/argus.md`. The rules
below are the non-negotiable subset for any harness (Codex, Claude Code, Cursor,
OpenCode, ...).

## Before any action

1. Confirm authorization, target package, device and allowed hosts. If they are
   not explicit, stop and ask.
2. Call `assessment_status` first. Know the current state, device, package and
   what has already been done.
3. Never test production systems or real user data unless the assessment was
   explicitly configured with `allow_production`.

## Workflow

```text
assessment_create
assessment_configure(package, apk_path, device, allowed_hosts)
assessment_start
app_install
app_launch
ui_dump / ui_find / ui_tap_node / ui_text / ui_key / ui_swipe
capture_start(install_ca, ca_method, route)
capture_entries / capture_correlate
capture_stop
endpoint_inventory
testing_begin
auth_set(host, headers) / auth_clear(host)
replay_send / replay_compare
finding_create / finding_update / finding_list
report_generate
```

- Use `ui_tap_node` with a label before falling back to pixel taps.
- Pass passwords and tokens to `ui_text` with `sensitive=true`.
- Capture screenshots and logcat as evidence.
- `capture_correlate` is timing-inferred. Verify causality before reporting.
- Replay and finding tools need the `testing` state; `replay_send` refuses
  out-of-scope hosts, public hosts without `allow_production` and destructive
  methods. Keep auth headers in memory via `auth_set`, never in evidence.
- `report_generate` writes `report.md` / `report.json` / `findings.csv` into
  evidence and moves `testing` to `reported`; findings and reports can still be
  updated afterwards.
- Respect `assessment_pause` and `assessment_stop`; the engine refuses actions
  anyway, but do not try to work around it.

## Evidence standard

A finding is confirmed only when you reproduced it and stored the exact request,
response, UI state or log that proves the security property is broken. Every
confirmed finding needs preconditions, role, exact steps and evidence. If you
could not test something, mark it untested and say why. Never fabricate.

## Controlled exploitation

Prove impact with the smallest safe action. One record is proof. Do not
enumerate, dump, modify or delete beyond that. No persistence, lateral movement,
financial transactions, real-user data or denial of service. Stop after proof.

## Secrets

Never repeat secrets in reasoning, reports, events or tool arguments. Do not ask
for credentials; use the supplied test account. The engine redacts stored data,
but the agent must not create new copies.

## Repository work

For code changes in this repo:

```sh
python3 -m unittest discover -s tests -v
python3 -m compileall -q argus argus_mcp.py
python3 scripts/mcp_smoke.py
```

Do not commit or push unless the operator explicitly asks. Barrel is a binary
dependency; do not add its source or internal build details to public-facing
files.
