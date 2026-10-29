# hermes-plugin-librenms

LibreNMS change management for [Hermes Agent](https://hermes-agent.nousresearch.com/).
The agent can read devices, ports, alerts, rules and logs, but it can only **write through a plan**:
a field-level diff you review, an apply step that verifies and journals every write, and a rollback
that replays the journal in reverse.

[![CI](https://github.com/andrewvieyra/hermes-plugin-librenms/actions/workflows/ci.yml/badge.svg)](https://github.com/andrewvieyra/hermes-plugin-librenms/actions/workflows/ci.yml)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![License MIT](https://img.shields.io/badge/license-MIT-green)

```
you    > access-sw2 moves to SFO-1 tonight. Update it and hold its alerts for the two-hour upgrade.
hermes > [librenms_query]  devices/access-sw2.example.net -> device #3, location NYC-2
hermes > [librenms_plan]   Plan lnp-20261028T190312Z-7dde (planned) — Move access-sw2 to SFO-1
                           [0] update      device #3 "access-sw2.example.net"
                                 location_id: 2 (NYC-2) -> 1 (SFO-1)
                                 notes: "rack B4" -> "rack A2 after the move (NET-112)"
                                 rollback: exact
                           [1] maintenance device #3 "access-sw2.example.net"
                                 duration 2:00, behavior skip_alerts, title "IOS upgrade NET-112", starts now
                                 rollback: none — LibreNMS API v0 cannot end or delete maintenance; ...
                           Summary: 0 create, 1 update, 0 delete, 1 action, 0 noop
         Step [1] cannot be undone: the window expires on its own after two hours. Apply? (yes/no)
you    > yes
hermes > [approval]        Apply LibreNMS plan lnp-20261028T190312Z-7dde to https://nms.example.com:
                           0 create, 1 update, 0 delete, 1 action; irreversible steps [1]   [once/session/always/deny]
you    > once
hermes > [librenms_apply]  [0] update device #3 -> done   [1] maintenance device #3 -> done
         Applied. access-sw2 is in SFO-1 and its alerts are held until 21:05.
```

## Why a plugin

Reading LibreNMS from an agent is easy: a skill wrapping `curl` works. Writing is different. The
LibreNMS API answers `200` to some writes it silently ignored, turns an unknown hostname in a filter
into "every device", re-assigns a location from SNMP on the next poll, and has no `last_updated`
stamp to detect a concurrent edit. "Precisely every time" needs logic that does not depend on the
model remembering it: resolve targets, diff against live state, refuse to touch an object that
changed since planning, re-read every write to prove it happened, record an inverse, revert in
reverse order on failure. That logic lives in Python here and runs the same way on every call.

## How it works

```
 librenms_plan                    librenms_apply                       librenms_rollback
 ─────────────                    ──────────────                       ─────────────────
 validate operations, gates       preflight: status, age, URL, gates   for each journal entry,
 resolve id / match  ──GET──►     for each step:                       newest first:
 diff desired vs live state         re-read, compare with the plan       re-read object
 record the state it saw            journal "running", then write ──►    compare with after-apply state
 save plan (planned)                re-read and verify the write         run inverse ──►
                                    journal inverse + after-state        journal outcome
                                  failure ► revert done steps          status: rolled_back |
                                  link the LibreNMS eventlog             partially_rolled_back
                                  status: applied | failed
```

A plan is a JSON file under `<HERMES_HOME>/plugin-data/librenms/plans/` (`~/.hermes` is the default
profile's home). Each step is journaled before
its write is sent and again after it, so an interrupted run leaves a journal that
`librenms_rollback` (or the CLI) can finish. See [docs/architecture.md](docs/architecture.md) for
the full model and guarantees.

## Install

Requirements: Hermes Agent 0.22.3 or newer, Python 3.10+, `requests` 2.32.4 or newer (earlier ones
send `.netrc` credentials to other hosts, CVE-2024-47081), a LibreNMS instance with the API enabled,
and an API token for a user with the permissions you intend to grant the agent.

```bash
hermes plugins install andrewvieyra/hermes-plugin-librenms
```

Hermes prompts for `LIBRENMS_URL` and `LIBRENMS_TOKEN` and stores them in the active profile's
`.env`: `~/.hermes/.env` for the default profile, `~/.hermes/profiles/<name>/.env` for a named one.
Then:

```bash
hermes plugins enable librenms
```

Start a new session. The tools show up in the `librenms` toolset and `/librenms status` confirms
connectivity, the LibreNMS version, the write mode, and any setting it could not read.

Manual install works too: clone this repository to `~/.hermes/plugins/librenms`, add the two
variables to `<HERMES_HOME>/.env` (`~/.hermes/.env` for the default profile), and enable the plugin.

### The token

A LibreNMS API token carries **every right of its user**; LibreNMS checks no per-token scopes. Give
the agent a dedicated user, so LibreNMS' own eventlog and alert notes name it, with the least role
that does the job:

| You want the agent to | LibreNMS user |
|---|---|
| Read only (`write_mode: read_only`) | A dedicated user with the `global-read` role |
| Plan and apply | A dedicated user with a custom role holding only the permissions the enabled operations need. Never `admin` |

Even a `global-read` token can schedule a rediscovery and write eventlog entries, and a user allowed
to unmask device credentials receives SNMP communities and passwords in device payloads. The plugin
refuses the rediscovery route in `librenms_query` (and any path that would reach it through an
encoded `/`), never writes the eventlog, and masks credential fields in every result, but a token without those rights is the safeguard LibreNMS enforces itself.
Hermes does not hide a standalone plugin's environment from the agent's terminal tool, so a model
with that tool can read `LIBRENMS_TOKEN`, `LIBRENMS_PROXY` and the `LIBRENMS_SNMP_*` credentials:
scope the token accordingly. Hermes masks a value in a printed environment by the variable's name,
which covers `LIBRENMS_TOKEN` and the SNMP credential names the plugin accepts, but not a password
inside `LIBRENMS_PROXY`. See [SECURITY.md](SECURITY.md).

### Configuration

Settings live under `plugins.entries.librenms.settings` in `~/.hermes/config.yaml`:

```yaml
plugins:
  enabled: [librenms]
  entries:
    librenms:
      settings:
        write_mode: full             # full | operator_only | read_only
        require_approval: true       # Hermes' approval prompt for every apply and rollback the model calls
        allow_delete: false          # delete operations are refused unless true
        allow_device_add: false      # device create, and hostname/overwrite_ip changes, are refused unless true
        allow_services: false        # service operations are refused unless true
        allow_insecure_transport: false  # http://, LIBRENMS_VERIFY_SSL=false, plain or unverified audit sinks
        max_operations: 100          # cap per plan (at most 1000)
        max_query_results: 500       # cap per librenms_query call (at most 5000)
        max_plan_age_hours: 24       # older plans are refused by librenms_apply
        max_maintenance_hours: 72    # longest maintenance window a plan may schedule
        plan_retention_days: 90      # prune plan files older than this; 0 keeps them forever
        audit_log: true              # append events to audit.jsonl
        audit_log_path: ""           # absolute; empty = <HERMES_HOME>/plugin-data/librenms/audit.jsonl
        audit_include_request: true  # record the triggering message (masked, truncated) in the actor
        link_eventlog: true          # attach LibreNMS eventlog ids to the journal after apply/rollback
        audit_sinks: []              # optional syslog / HTTP forwarding, see docs/sinks.md
```

A value that cannot be read as its setting's type fails closed: a flag takes the value that lets the
model do least, a number its default (or its upper limit when it is too large), and an unknown
`write_mode` becomes `read_only`, and a relative `audit_log_path` is the default path.
`/librenms status` lists every such fallback. Settings are re-read on each call, so a change in
`config.yaml` or the Desktop settings form applies without a restart. Retention is applied at most
hourly per profile, when a plan is made or listed, on status and on every `/librenms` or `hermes
librenms` command; for a strict policy, run `hermes librenms prune` from cron.

Environment variables (connection only; nothing that relaxes a safeguard is read from the
environment):

| Variable | Required | Meaning |
|---|---|---|
| `LIBRENMS_URL` | yes | Base URL, e.g. `https://librenms.example.com` or `https://nms.example.com/librenms`. A trailing `/api/v0` is stripped; a URL with a user name or password in it is refused |
| `LIBRENMS_TOKEN` | yes | API token, sent only in the `X-Auth-Token` header |
| `LIBRENMS_VERIFY_SSL` | no | `true` (default), `false` (needs `allow_insecure_transport`), or the path of a CA bundle file or directory |
| `LIBRENMS_TIMEOUT` | no | Seconds to connect and to wait for each read (`30`), or both apart (`5,60`) |
| `LIBRENMS_PROXY` | no | Unset: the usual proxy variables apply. `none`: ignore them. Or an `http(s)://` proxy for LibreNMS alone: scheme, host and port, with any user name and password percent-encoded (`%40` for `@`, `%23` for `#`, `%2F` for `/`, `%3F` for `?`, `%25` for `%`); anything else is refused. An `http://` proxy receives that password in clear (Basic authentication), whatever `allow_insecure_transport` says |
| `LIBRENMS_SNMP_*` | no | SNMP credentials a device-create plan names as `{"env": "LIBRENMS_SNMP_<NAME>"}`, read only at apply time. A community's or password's variable ends in `_SECRET`, `_PASS` or `_PASSWORD` (`LIBRENMS_SNMP_COMMUNITY_SECRET`), which Hermes masks in a printed environment |
| `LIBRENMS_AUDIT_SINK_SECRET` | no | A collector token for an `http` audit sink, written as `${LIBRENMS_AUDIT_SINK_SECRET}` in its headers; the Desktop's `audit_sink_secret` field stores it. Once `audit_sinks` holds the placeholder, edit it in `config.yaml`: the Desktop's form shows and saves it with the token in its place. Any variable works the same way (see [docs/sinks.md](docs/sinks.md)) |

## Tools

| Tool | Writes | Purpose |
|---|---|---|
| `librenms_query` | no | Read any allowed API v0 GET path, or `{"action": "status"}` for connectivity, version and settings |
| `librenms_plan` | no | Validate and diff a list of operations; save a plan |
| `librenms_apply` | yes | Apply a plan with preconditions, verified writes, a journal and auto-rollback; `dry_run` re-checks only |
| `librenms_rollback` | yes | Revert an applied or partially applied plan |
| `librenms_plans` | no | List plans or show one with its diff, journal and rollback result |

The bundled skill `librenms:workflow` (see [SKILL.md](SKILL.md)) tells the model to query first,
show the diff, ask, and apply only on an explicit yes, never in unattended contexts. The tool
descriptions repeat that rule.

`librenms_query` takes a `path` relative to `/api/v0` (`devices`, `devices/core-sw1.example.net/ports`,
`faults`, `rules`, `logs/syslog/edge-rtr1.example.net`), optional `params`, `fields` and `limit`. Only
the GET routes of an allow-list are called; graph images, Oxidized configuration backups, the GET that
schedules a rediscovery and the port-by-ifName route are refused with the reason. Hostnames in a path or
a `hostname` filter are resolved to device ids first, and ids are checked to exist, because several
LibreNMS routes answer an unknown device with every device's rows; `0` is refused for the same reason.
A `hostname` filter on a route that ignores it is refused, naming the path that filters by device
(`logs/eventlog/<hostname>`, `services/<hostname>`) where there is one. A 404 that is not LibreNMS's
JSON, such as a web server's page for a `LIBRENMS_URL` missing its sub-path, is an error, never zero
results. Log routes default to newest first and to `max_query_results` rows at most. Credential fields
are masked and long text is clipped before anything reaches the model.
[docs/api-coverage.md](docs/api-coverage.md) maps every v0 route to a query, a plan operation, or the
reason it is refused.

### Operations

`librenms_plan` takes `description` and an ordered `operations` list:

```json
{"op": "update", "resource": "device", "match": {"hostname": "sw1.example.net"}, "data": {"purpose": "core"}}
{"op": "create", "resource": "location", "match": {"location": "SFO-1"},
 "data": {"location": "SFO-1", "lat": 37.6213, "lng": -122.379}}
{"op": "maintenance", "resource": "device_group", "match": {"name": "edge-routers"}, "data": {"duration": "1:30"}}
{"op": "ack", "resource": "alert", "id": 501, "data": {"note": "carrier ticket 4411", "until_clear": false}}
{"op": "delete", "resource": "service", "id": 7}
```

| Resource | Operations | Match keys | Rollback |
|---|---|---|---|
| `device` | create, update, delete, maintenance, discover | `hostname` | exact; delete and maintenance: none |
| `location` | create, update, delete, maintenance | `location` | exact; delete: lossy; maintenance: none |
| `device_group` | create, update, delete, maintenance | `name` | exact; delete: lossy; maintenance: none |
| `service` | create, update, delete | `device` + `type`/`name`/`ip`/`desc` | exact; delete: lossy |
| `alert_rule` | create, update, delete | `name` | exact; delete: lossy |
| `port` | update (description) | `device` + `ifName` or `ifDescr` | lossy |
| `alert` | ack, unmute | id only | lossy |

- `id` or `match` locates the target; `match` must hit exactly one object. `create` with `match` is
  an upsert: an existing match becomes an `update` (or a `noop`).
- An alert rule muted in the LibreNMS UI (`extra.mute`) is not updated or deleted: every API write
  unmutes it, and its rollback could not mute it again. Unmute it, or edit it, in the UI.
- `data` holds only what should change, in friendly names (`location` by name, devices by
  hostname); the plan shows what each resolved to. Unknown fields fail the plan; nothing is dropped
  silently.
- Fields the poller owns (`sysName`, `os`, `hardware`, ...) and an existing device's SNMP settings
  are refused, because the API cannot change them for good. SNMP credentials for a new device are
  never written into a plan: they are named as environment variables and read at apply time.
- Each step says how rollback undoes it: **exact**, **lossy** (with what is lost, usually the id),
  **none** (a device delete; a maintenance window, which the API can neither end nor delete) or
  **not needed** (a rediscovery).

The per-resource fields are in [SKILL.md](SKILL.md#cheat-sheet). More in [examples/](examples/).

### Slash command and CLI

Inside a session, `/librenms` gives an operator the same actions without going through the model:

```
/librenms status
/librenms plans [status]
/librenms show <plan_id>
/librenms check <plan_id>
/librenms apply <plan_id> [--no-rollback]
/librenms rollback <plan_id> [--force]
/librenms prune [--days N] [--dry-run]
```

The same subcommands exist as `hermes librenms …` in the shell, useful for rolling back after a
session has ended. Both accept an unambiguous fragment of the plan id, so `/librenms apply 7dde`
works from a phone; the full id remains the canonical form in files and tool output. Text that
came from LibreNMS is printed with control and bidirectional characters escaped, so a crafted
`ifAlias` cannot rewrite your terminal.

## Safety model

- **Read-only until a plan exists.** `librenms_query`, `librenms_plan` and `librenms_plans` never
  write, and the query tool calls only allow-listed GET routes.
- **Every write is diffed first.** Updates send only the fields that differ; unchanged operations
  become `noop` steps.
- **Optimistic concurrency without stamps.** LibreNMS has no `last_updated` or ETag, so each step
  records the object's state at planning time and refuses to run if it differs at apply time. Creates
  refuse to run if a matching object appeared. A conflict stops the plan like an error does.
- **Verified writes.** Every write is re-read and compared with what was asked; a write LibreNMS
  accepted but did not perform fails the step and triggers rollback. A write whose answer was lost
  (a timeout, a reset, a gateway's 502, 503 or 504) is journaled as possibly written, because
  LibreNMS may still be carrying it out; for ten minutes, a rollback that finds it not done yet
  leaves it pending and says when to roll back again.
- **Journaled inverses.** A step is on disk as `running` before its write is sent, and its inverse is
  on disk before the next step starts. A run that died mid-step is recovered by `librenms_rollback`,
  which treats the dangling step as unknown and checks before undoing it. A rollback that died is
  resumed from its saved progress, adopting what it had re-created instead of creating it twice.
- **Automatic rollback on failure**, in reverse order, on by default. The outcome of every revert is
  journaled too.
- **Rollback respects later edits.** An object modified after the apply is skipped as a conflict
  unless `force` is set.
- **What cannot be undone is said up front.** Each step in the diff names its rollback kind, and the
  approval prompt lists the irreversible steps.
- **Risky operations are opt-in.** `allow_delete`, `allow_device_add` (which also covers changing a
  device's `hostname` other than in letter case, or its `overwrite_ip`, since that redirects its SNMP
  credentials to another host) and `allow_services` (a service runs a check plugin on the poller with
  model-written arguments) default to false. Rollback is exempt, so a write can always be undone.
- **Plans are bound.** A plan applies at most once, only against the LibreNMS URL it was built for,
  and only within `max_plan_age_hours`. The claim is taken under a cross-process file lock, and only
  one plan runs at a time (a failed apply until its automatic rollback ends), so the gateway and the
  CLI cannot interleave writes.
- **No secrets in plans.** The token appears only in the request header. SNMP credentials are
  environment references in the plan and are resolved only while the step runs. Credential fields
  (communities, SNMP passwords, service parameters) are masked in every tool result and audit event;
  plan files are `0600` in `0700` directories, and the plugin's data directory is kept `0700`.
- **Hardened transport.** `https://` with certificate checks unless `allow_insecure_transport` is
  set; redirects are refused rather than followed with the token; `.netrc` and cookies are ignored;
  responses are size-capped; only GETs are retried.
- **Everything is attributed.** Each plan, apply, rollback and approval records who asked, from which
  surface, platform and chat, and the HTTP calls made. See [docs/audit.md](docs/audit.md).

### Write modes

In the default `full` mode the model asks you in chat and calls `librenms_apply` after you say yes.
With `require_approval` (default on), the plugin also sends every `librenms_apply` and
`librenms_rollback` call to Hermes' approval prompt, the same gate as dangerous shell commands, with
the plan summary and its irreversible steps. The approval is keyed per plan, so "session" or "always"
never carries over to another plan. Unattended runs follow your Hermes approval policy:
`approvals.cron_mode` for cron jobs, `approvals.unattended_mode` for webhook and API-server sessions,
and `approvals.single_query_mode` for `hermes -q`, each `deny` unless you set it to `approve`, which
lets an apply through without asking, as YOLO mode and `approvals.mode: off` do. `write_mode` adds
the lock:

| `write_mode` | Who can write | Use it when |
|---|---|---|
| `full` | The model, after asking (and after the approval prompt); and `/librenms`, `hermes librenms` | One trusted user in a direct message, no automation |
| `operator_only` | Only `/librenms` in a session and `hermes librenms` in your own shell. Model calls to apply and rollback are refused with the exact command to relay | Group chats, messaging gateways, cron jobs, webhooks or the API server present, prompt-injection concerns, "a human must cause every write" |
| `read_only` | Nobody. The apply and rollback tools are hidden from the model and refuse if called; `/librenms apply` refuses too | Drift audits, demos, first deployments |

The model can reach a shell through Hermes' terminal tool, so the plugin also blocks a terminal or
code call that runs `hermes librenms apply` or `rollback`, and the CLI refuses those subcommands when
it was started from an agent session, unless `write_mode` is `full` and `require_approval` is off.
Both are heuristics an obfuscated command can evade; the token's role is the hard limit.

Plans persist across every Hermes surface on the same `HERMES_HOME`, so `operator_only` supports
"plan from Signal, apply from the laptop." Refusals (a blocked terminal call included), approval
requests and approval decisions are written to the audit stream.

### Untrusted content

Much of what LibreNMS stores was written by the network, not by its users: syslog from anything that
can reach the collector, SNMP strings (sysDescr, sysLocation, sysContact, ifAlias), LLDP/CDP
neighbour names, eventlog and alert notes, and hostnames found by autodiscovery. The plugin cannot
stop the model from being influenced by that text; it limits what a misled model can do (plans,
review, gates, write modes, approval) and makes every attempt visible (audit). The skill tells the
model to treat fetched content as data and to report instructions found in it.

## Audit trail

Every plan, apply and rollback is recorded for review and for SIEM ingestion:

- **In the plan file:** who requested the plan (`requested_by`), who applied and who rolled back
  (`apply.actor`, `rollback.actor`), the environment it ran in (`audit`: host, OS user, Hermes and
  plugin versions, LibreNMS version and database schema), and the HTTP calls behind every journal
  entry.
- **Linked to LibreNMS' eventlog.** After each apply and rollback the new eventlog entries of the
  devices the plan touched are attached to the journal (`link_eventlog`), so the two trails reference
  each other. Maintenance windows and alert acknowledgements carry `[hermes:<plan id>]` in LibreNMS
  itself.
- **In an append-only event stream**, `<HERMES_HOME>/plugin-data/librenms/audit.jsonl`, one JSON
  object per line: `plan_created`, `apply_started`, `step_done`, `apply_finished`, `rollback_*`,
  `approval_requested`, `approval_decided`, and the refusals and rejections that never reached
  LibreNMS.

The actor record distinguishes a model tool call from a human using `/librenms` or `hermes
librenms`, and carries the Hermes surface, profile, gateway platform, chat, user, session, cron job,
and the message that triggered the call (`audit_include_request`). All timestamps are UTC. Point
your collector at the file, or set `audit_log_path` to an absolute path it already watches (a
regular file owned by the account Hermes runs as, with no other hard link; the plugin never writes
through a symlink).
Schema and examples: [docs/audit.md](docs/audit.md).

Installs without a log shipper can forward events directly: `audit_sinks` sends each event to a
syslog server (UDP, TCP or TLS, JSON or CEF) and/or an HTTP collector such as Splunk HEC, from a
background thread that never delays a LibreNMS operation. See [docs/sinks.md](docs/sinks.md).

## Compatibility

- LibreNMS API v0, developed against LibreNMS 26.10. Alert acknowledgements work on faults
  (`/faults`) and alert rules on alert operations (`alert_operation_id`), as current releases do.
  On older releases a route that does not exist is reported as such, and where `GET rules/{id}` does
  not return what an exact snapshot needs, alert-rule update and delete are refused rather than
  guessed. Each plan records the LibreNMS version and database schema it was built against.
- Hermes Agent 0.22.3+ (`requires_hermes`). The plugin uses the documented `register(ctx)` surface:
  `register_tool`, `register_hook` (`pre_tool_call`, `pre_llm_call`, `post_approval_response`),
  `register_command`, `register_cli_command`, `register_skill`, `get_config`.

## Development

```bash
make test        # unit tests against the in-memory fake LibreNMS, no network
make coverage    # the same under branch coverage
make lint        # ruff
make validate    # hermes plugins validate . (the catalog's admission checks)
make doctor      # hermes plugins doctor . --ci
HERMES_AGENT_ROOT=~/.hermes/hermes-agent make test-hermes   # load through Hermes' real PluginManager
```

The fake LibreNMS in `tests/fake_librenms.py` reproduces the API's envelopes, status codes and
quirks (404 for empty lists, ids returned only inside messages, `200` for writes that did nothing,
the catch-all route, credentials in device payloads) plus an eventlog and an injectable failure
hook, so apply, conflict, recovery and rollback paths are exercised end to end without a server.

Layout:

```
plugin.yaml   manifest (tools, hooks, env, settings schema)
__init__.py   register(ctx)
schemas.py    tool schemas the model sees
handlers.py   tool handlers, the write_mode gate, the approval and request hooks
commands.py   /librenms slash command and `hermes librenms` CLI
client.py     LibreNMS REST client (transport checks, errors, retries, size caps)
routes.py     the read-route allow-list behind librenms_query
redact.py     credential masking, clipping, terminal-safe text
diff.py       value normalisation and field-level diffs
resources/    one module per resource: validate, resolve, diff, execute, verify, revert
planner.py    operations -> plan
executor.py   apply with journal and verification, rollback, eventlog linking
store.py      plan persistence and locks under plugin-data
audit.py      actor capture and the audit.jsonl event stream
sinks.py      optional syslog / HTTP forwarding of audit events
timefmt.py    UTC-to-local rendering for reports (Hermes' timezone setting)
settings.py   operator settings, fail-closed
SKILL.md      bundled skill: the workflow the model follows
```

## License

MIT. See [LICENSE](LICENSE).
