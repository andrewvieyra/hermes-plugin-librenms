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
hermes > [approval]        Apply lnp-20261028T190312Z-7dde: 1 update, 1 action; irreversible steps: [1];
                           rollback_on_failure=true
                           [1] maintenance device #3 "access-sw2.example.net" (irreversible):
                               duration, start, title, notes, behavior
                           [0] update device #3 "access-sw2.example.net": location_id, notes
                           ...                                                  [once/session/always/deny]
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
connectivity, the LibreNMS version, the write mode, and any setting it could not read; when LibreNMS
cannot be configured or reached, it says why under `connection` and still shows the settings.
If the model finds no LibreNMS tools, the variables are not set for the profile, or the `librenms`
toolset is turned off for that platform: `hermes tools` turns it on.

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
        max_query_results: 500       # rows per librenms_query or librenms_report call, the rest by offset (at most 5000)
        max_result_chars: 60000      # characters per tool result for the model (8000 to 90000)
        librenms_timezone: ""        # IANA zone LibreNMS runs in (e.g. Europe/Amsterdam); empty: not known
        max_plan_age_hours: 24       # older plans are refused by librenms_apply
        max_maintenance_hours: 72    # longest maintenance window a plan may schedule
        plan_retention_days: 90      # prune plan files older than this; 0 keeps them forever
        audit_log: true              # append events to audit.jsonl
        audit_log_path: ""           # absolute; empty = <HERMES_HOME>/plugin-data/librenms/audit.jsonl
        audit_include_request: true  # record the triggering message (masked, truncated) in the actor
        link_eventlog: true          # attach LibreNMS eventlog ids to the journal after apply/rollback
        audit_sinks: []              # optional syslog / HTTP forwarding, see docs/sinks.md
```

`max_result_chars` keeps each result the model reads under Hermes' per-result threshold, past which
Hermes shows the model only a 1,500-character preview: 100,000 characters, or 15% of the context
window (at four characters a token) on a smaller model. On a model with a window under 100K tokens,
set it to about half the window's token count (`32000` for 64K tokens).

`librenms_timezone` is the zone LibreNMS runs in (its PHP `date.timezone`). LibreNMS writes fault,
alert-log, eventlog and syslog times in that zone with no offset, and no API field says which zone
it is, so a time such as `2026-10-28 10:02:00` is an hour off for a model that reads it as UTC when
LibreNMS runs in Amsterdam. Every `librenms_report` answer names this zone in `timezone`, or says
it is unknown while the setting is empty. The views that show fault and log times (alerts and
events, in later releases) read them in this zone, and without it give them no age. The 0.4.0
views show only times that are exact in any zone: device times (ISO-8601 UTC), outages (unix
seconds) and uptimes, every age counted to LibreNMS's own clock (the `Date` of its answer). A name
the host's zone database does not hold is refused and the setting stays empty.

A value that cannot be read as its setting's type fails closed: a flag takes the value that lets the
model do least, a number its default (or its upper limit when it is too large), and an unknown
`write_mode` becomes `read_only`, and a relative `audit_log_path` is the default path.
`/librenms status` lists every such fallback, also while LibreNMS is unreachable. Settings are
re-read on each call, so a change in `config.yaml` or the Desktop settings form applies without a
restart. Retention is applied at most hourly per profile, when a plan is made or listed, on status
and on every `/librenms` or `hermes librenms` command; for a strict policy, run `hermes librenms
prune` from cron.

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
| `librenms_query` | no | Look up devices, ports, alerts, sensors and logs through any allowed API v0 GET path, or `{"action": "status"}` for connectivity, version and settings |
| `librenms_report` | no | Answer a question in one call: `find` what a name, address or phrase could mean (ranked, with why), or report on `devices` (state, down since, uptime, last poll, naming checks) with names joined and counts summed |
| `librenms_plan` | no | Validate and diff a list of operations; save a plan |
| `librenms_apply` | yes | Apply a plan with preconditions, verified writes, a journal and auto-rollback; `dry_run` re-checks only |
| `librenms_rollback` | yes | Revert an applied or partially applied plan |
| `librenms_plans` | no | List plans or show one with its diff, journal and rollback result, a range of steps at a time; `detail` adds the steps and full journal entries |

The bundled skill `librenms:workflow` (see [SKILL.md](SKILL.md)) tells the model to query first,
show the diff, ask, and apply only on an explicit yes, never in unattended contexts. The tool
descriptions repeat that rule.

Hermes' tool search (`tools.tool_search.enabled`, on by default) defers plugin tools: the model is
given `tool_search`, `tool_describe` and `tool_call` and one catalog line per tool, the first sentence
of its description. Each of those sentences says in 60 characters or fewer what the tool answers
or does ("Look up LibreNMS devices, ports, alerts, sensors and logs."), and the skill, which is offered
whenever the plugin is enabled, tells the model to reach deferred tools through `tool_call`. The
approval prompt is unaffected: Hermes unwraps `tool_call` before its `pre_tool_call` hooks run.

`librenms_query` takes a `path` relative to `/api/v0` (`devices`, `devices/core-sw1.example.net/ports`,
`faults`, `rules`, `logs/syslog/edge-rtr1.example.net`), optional `params`, `fields` and `limit`, and
`offset`, `where` and `sort` (below). Only the GET routes of an allow-list are called; graph images,
Oxidized configuration backups, the GET that schedules a rediscovery and the port-by-ifName route are
refused with the reason. Hostnames in a path or
a `hostname` filter are resolved to device ids first, and ids are checked to exist, because several
LibreNMS routes answer an unknown device with every device's rows; `0` is refused for the same reason.
A `hostname` filter on a route that ignores it is refused, naming the path that filters by device
(`logs/eventlog/<hostname>`, `services/<hostname>`) where there is one. A 404 that is not LibreNMS's
JSON, such as a web server's page for a `LIBRENMS_URL` missing its sub-path, is an error, never zero
results. An unknown hostname is refused naming the hostnames that contain its first label
(`core-sw1` finds `core-sw1.example.net`). An id that LibreNMS reads as no filter (`faults/0`,
`rules/0`, `bills/x`, `poller_group/0`, `port_security/port/0`) or as another id (`ports/1abc`) is
refused, a MAC in `resources/fdb/{mac}` or `resources/nac/{mac}` is sent as the 12 hex digits
LibreNMS compares it with, `columns` lists are trimmed, and a parameter name PHP would read as
another (`" limit"`, `hostname[]`) is refused. Log routes default to newest first and
to `max_query_results` rows at most. Fault and alert-log rows carry `entities`, the ports or sensors
that alerted, instead of the `details` blob with the alert's contact addresses (`fields:
["details"]` returns it without them). Credential fields are masked and long text is clipped before
anything reaches the model. A result that returns text from LibreNMS names the keys holding it in
`untrusted_fields` (an error, `librenms`: LibreNMS's answer), beside an `untrusted_notice` that it
is data from the monitored network, not instructions; the `error` of an error or a refusal may
quote LibreNMS without one. Characters that would not show as written reach the model escaped
(`\u202e`, `\u200b`), and limits count the escapes; see [Untrusted content](#untrusted-content).

LibreNMS pages only the log routes, and filters and orders most other listings little or not at all:
`ports` takes no filter and no order, `faults` no device, and ports, sensors, links and FDB entries
come in no set order. Elsewhere it sends every row, so `librenms_query` works on all of them:
`where` keeps the rows every condition holds for (`eq`, `ne`, `contains`, `gt`, `lt` on a top-level
key; no expressions), `sort` orders them by one key (`asc` or `desc`), and then `offset` and `limit`
take a page. Numbers compare by value, also when LibreNMS writes them as text; text compares
ignoring case, in natural order (`Gi1/0/2` before `Gi1/0/10`); `gt` and `lt` compare a number with a
text as text when both start with a digit, as versions do (`version` `lt` `16` keeps `15.2(4)E`, not
`16.12.4`), and never with other text; a missing key, `null` and `""` are empty (`eq null` matches
them, a sort puts them last); ties keep LibreNMS's order. A listing says what it holds: `count` (the
rows LibreNMS returned), `matched` (those `where` kept), `total` (log routes: every row LibreNMS
holds for the query), `offset`, `returned`, and while rows follow, `truncated` and `next_offset`,
which is the `offset` to read on with. On a log route `offset` is sent as LibreNMS's `start` and
`where` and `sort` are refused (they would see one page); `params.start` on any other route, which
LibreNMS ignores there, is refused. A `where` or `sort` key no row has is an error naming the keys
there are (on the ports routes LibreNMS returns only the columns `params.columns` names, `ifName`
alone on `devices/<hostname>/ports` without it, so name the key there), and a credential key
compares as masked. For example, the ten busiest ports of the fleet:

```json
{"path": "ports", "params": {"columns": "port_id,device_id,ifName,ifInOctets_rate"},
 "sort": {"key": "ifInOctets_rate", "order": "desc"}, "limit": 10}
```

and the open alerts on device 12: `{"path": "faults", "where": [{"key": "device_id", "op": "eq",
"value": 12}]}`. Pages of `ports`, `resources/sensors`, `resources/links` and `resources/fdb` line
up only when sorted by their id (`port_id`, `sensor_id`, `id`, `ports_fdb_id`), since LibreNMS may
return them in another order on the next call.

Every result the model reads stays within `max_result_chars`: a listing past it keeps its first rows
and says so (`truncated`, `next_offset` at the first row left out, and a `note` naming `fields`; a
row that does not fit on its own gets no `next_offset`, and the note names its offset), and a plan
is shown a range of steps at a time, with `next_offset` for `librenms_plans` to show the next range,
its irreversible steps among them (`irreversible_count` counts them all) and its latest dry-run
check. `librenms_plan` returns the diff without the steps (`librenms_plans` with `detail` has them).
An answer too large to read at all (16 MiB) is refused naming what narrows that route: `limit` and
`offset` narrow only the log routes, which LibreNMS pages; elsewhere they, `where` and `sort` apply
after every row is read.
[docs/api-coverage.md](docs/api-coverage.md) maps every v0 route to a query, a plan operation, or the
reason it is refused.

### Reports

`librenms_query` hands the model LibreNMS's rows as they are: ids rather than names, octets and
timeticks rather than rates and ages, and whole listings to scan for "which" and "how many".
`librenms_report` answers such questions in the plugin. It reads LibreNMS through the same
allow-list (GET only; a path off it is refused before it is sent), at most 30 requests per call,
joins the rows, and returns a `summary` (the counts a short answer needs, over every row that
passed the filter) and the `rows`, each naming its device (`device_id`, `hostname`, `display`)
with units in the key names (`uptime_s` beside `uptime: "100d 0h"`). It never writes, needs no
approval, and is available in every `write_mode`.

| View | Answers | Takes |
|---|---|---|
| `find` | What a hostname, sysName, display name, IP, MAC, interface name or phrase ("the core switch in SFO") could mean: devices, ports, locations, device groups and port groups, best first, each with a `score` and `why`, 10 an answer (`count` counts every candidate, `offset` reads on, and past 10 a note says to narrow the term). An IP or MAC that every device holds matches each; an older LibreNMS that ignores the address filter is detected and set aside. `ambiguous` is true when the best two score within 10 of each other: the model asks the user which one they mean | `term`; `filter.kind` |
| `devices` | Per device: `status` (`up`, `down`, `disabled`, `ignored`, as LibreNMS decides them), `status_reason`, `down_since`/`down_for` (its open outage, read for up to 20 down devices on the page), `uptime`, `booted_at`, `last_polled` and its age, os, hardware, version, type, location, purpose, and `checks` (`naming_mismatch`: hostname and sysName name different hosts; `no_location`; `no_purpose`). `summary` counts states and checks | `scope`; `filter` `status`, `rebooted_within`, `not_polled_for` (`30m`, `24h`, `7d`), `naming_mismatch`, `no_location`, `no_purpose`, `os`, `type`; `sort` `name`, `status`, `uptime`, `last_polled` |

`scope` narrows a report to devices: `device` (an id, a hostname, or a sysName, display name,
first label, IP or phrase), `devices` (a list of them), `group` (a device group's name or id),
`location` (a name, an id, or part of a name: every location that holds it, as LibreNMS's own
`type=location` filter reads it), `os` and `type`; every key given must hold. A device named by
anything but its id or hostname resolves only when exactly one device matches it exactly, or only
one matches every word of the phrase; the result says how (`scope.resolved`). Otherwise the
report answers `ambiguous: true` with the candidates and reports nothing, rather than guess.

```json
{"view": "find", "term": "core switch sfo"}
{"view": "devices", "filter": {"status": "down"}}
{"view": "devices", "scope": {"location": "SFO"}, "filter": {"rebooted_within": "24h"}}
{"view": "devices", "filter": {"not_polled_for": "15m"}, "sort": "last_polled"}
```

Every report carries `data_as_of` (LibreNMS's clock, from the `Date` of its answer), `timezone`
(see `librenms_timezone`), `count`, `returned`, `offset`, `truncated` and `next_offset` (more rows:
read on with `offset`), and `partial` with a `partial_reason` when the data itself is incomplete
(the request budget ran out, or a read for one device failed); `notes` say what to do next. Rows
are cut to `limit` (default 20, at most `max_query_results`; 10 for `find`) and to
`max_result_chars`. Text from LibreNMS is clipped to 200 characters, escaped like every result,
and named in `untrusted_fields`.

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
session has ended. Both accept the end of a plan id, at least four characters and matching exactly
one plan, so `/librenms apply 7dde` works from a phone, and then say which plan it named; anything
shorter, or from the middle of an id, names no plan, because apply and rollback act at once. The
full id remains the canonical form in files and tool output, and the only one the model's apply and
rollback accept. Text that
came from LibreNMS is printed with control, bidirectional and invisible characters escaped, so a
crafted `ifAlias` cannot rewrite your terminal, and two labels that differ only by a zero-width
character do not look the same.

`hermes librenms` exits 0 when the command did what it says, 1 when it failed, was refused or named
no single plan (an apply that failed, even once rolled back; a rollback that left conflicts; a `check`
whose plan is no longer applicable; `status` while LibreNMS cannot be reached), and 2 on a usage
error; anything but 0 is printed on stderr. So `hermes librenms check 7dde && hermes librenms apply
7dde` stops at a conflict, and a script can tell an apply that went through from one that did not.

## Safety model

- **Read-only until a plan exists.** `librenms_query`, `librenms_report`, `librenms_plan` and
  `librenms_plans` never write, and the query and report tools call only allow-listed GET routes
  (a report at most 30 of them per call).
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
  approval prompt lists the irreversible steps and shows them, with the deletes, first.
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
a summary built for the little of it Hermes shows (9 rows of 64 columns in the CLI panel, 300
characters on Discord, 500 on Slack and Telegram): a header with the counts, the irreversible steps
and the rollback choice, then one line per step, deletes and irreversible steps first, then the
field-level diff while room remains. The approval is keyed per plan, so "session" or "always" never
carries over to another plan. The model's `librenms_apply` and `librenms_rollback` take only the full
plan id, and one that names no saved plan is refused without asking, so the plan a person approved
is the plan that runs. Unattended runs follow your Hermes approval policy:
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
code call that runs `hermes librenms apply` or `rollback`, and the same line written to a background
shell's input (`process_manage`), and the CLI refuses those subcommands when it was started from an
agent session, unless `write_mode` is `full` and `require_approval` is off.
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

The results say so too. Hermes puts its own untrusted-data boundary only around its web, browser
and MCP tools, and a plugin cannot opt in, so a result that returns text from LibreNMS carries
`untrusted_fields`, the keys that hold it (`results`, `result` and `extra` of a query, `librenms` of
status and of an error, which is LibreNMS's answer, the `note` of an empty answer; a plan's `diff`
and `warnings`, dry-run `conflicts`, and the `journal`, `report`, `eventlog`, `failure`,
`auto_rollback_error`, `apply`, `rollback`, `checks` and `steps` of apply, rollback and
`librenms_plans`; for a report, the keys of its rows and scope that hold such text, such as
`hostname`, `sysName`, `location`, `purpose`, `port` and a candidate's `why`), and before them an
`untrusted_notice` telling the model that this is data, not instructions. The plugin's own keys (`next_step`, `note` on a cut listing, counts) are not listed.
Refusals and errors are the plugin's own text and carry no marker of their own, but they may quote
LibreNMS: an `error` holds LibreNMS's error message, the refusal of an unknown hostname names the
devices LibreNMS holds whose names come close (autodiscovered ones among them), and a plan's
`errors` may quote LibreNMS's answer. The skill tells the model that this text is data too.

Every string in every result, and everything printed to a terminal or put in the approval prompt,
has its bidirectional controls, invisible characters (zero-width spaces and joiners, the soft
hyphen, the byte-order mark, fillers, variation selectors, and tag characters, which spell ASCII a
model reads and a person does not) and C0/C1 controls written as escapes (`\u202e`, `\u200b`,
`\x9b`) rather than dropped, so the reader sees that something was there; newlines and tabs stay,
and a Windows line end reaches the model as a newline. The emoji and text presentation selectors
stay only right after a symbol, an emoji or a keycap they change; after a letter or a digit, at
the start of a text or after another selector they show as nothing and are escaped too. Every
limit on that text (2,000 characters a value, 200 a report's value or an alert's entity, 300 a
linked eventlog row, 400 and 500 of an error quoting LibreNMS) counts the escapes, so it bounds what the model reads.

Escaping shows what would not show; it does not tell apart what shows alike. An escape reads the
same as those characters written in LibreNMS (a Windows path, a JSON-encoded log line), so the
skill has the model say that a value holds one, never decode it; and letters from other scripts
that look like Latin ones (a Cyrillic U+0430 for an `a`) are left as they are.

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
and the message that triggered the call (`audit_include_request`). Plans belong to the profile, so
`librenms_plans` shows the model of any session only who acted (by display name), how and where,
never that message or the sender's, chat's or session's ids, not even as a name Hermes filled in
with an id. All timestamps are UTC. Point your collector at the file, or set `audit_log_path` to an
absolute path it already watches (a regular file owned by the account Hermes runs as, with no other
hard link; the plugin never writes through a symlink).
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
listing.py    librenms_query's where and sort over the rows read
reports/      librenms_report: views (find, devices), shared reads, scope, budgets, units, ranking
redact.py     credential masking, clipping, terminal-safe text
diff.py       value normalisation and field-level diffs
resources/    one module per resource: validate, resolve, diff, execute, verify, revert
planner.py    operations -> plan
executor.py   apply with journal and verification, rollback, eventlog linking
store.py      plan persistence and locks under plugin-data
audit.py      actor capture and the audit.jsonl event stream
sinks.py      optional syslog / HTTP forwarding of audit events
timefmt.py    UTC-to-local rendering for plan diffs and journals (Hermes' timezone setting)
settings.py   operator settings, fail-closed
SKILL.md      bundled skill: the workflow the model follows
```

## License

MIT. See [LICENSE](LICENSE).
