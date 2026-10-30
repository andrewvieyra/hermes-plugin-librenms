# hermes-plugin-librenms

LibreNMS change management for [Hermes Agent](https://hermes-agent.nousresearch.com/).
The agent can read devices, ports, alerts, rules and logs, answer questions about them over a
conversation and send a scheduled digest of what needs attention, but it can only **write through a plan**:
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
It then shows the plugin's setup notes ([after-install.md](after-install.md)): a least-privilege
token, `operator_only` where other people or automation reach the agent, the approval prompt on, no
local shell for the model, and `/librenms status`. Only `hermes plugins install` shows them; an
install from the Desktop or the dashboard does not, so read the file there. Then:

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
with that tool can read `LIBRENMS_TOKEN`, `LIBRENMS_PROXY` and the `LIBRENMS_SNMP_*` credentials.
The plugin refuses a terminal or code call that reads one of them by name or calls the LibreNMS API
with a token, and asks you before one reads a Hermes `.env` file or prints an environment holding
them, but that is a heuristic a script or an encoding passes: scope the token accordingly. Hermes
masks a value in a printed environment by the variable's name, not always whole (part of the token
can show) and not a password inside `LIBRENMS_PROXY`. See [SECURITY.md](SECURITY.md).

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
        audit_max_mb: 10             # rotate audit.jsonl before it passes this many MiB; 0: never by size
        audit_keep_files: 100        # rotated audit files kept, newest first; 0: any number
        audit_retention_days: 90     # delete rotated audit files this old (rotated daily); 0: keep forever
        link_eventlog: true          # attach LibreNMS eventlog ids to the journal after apply/rollback
        audit_sinks: []              # optional syslog / HTTP forwarding, see docs/sinks.md
```

`max_result_chars` keeps each result the model reads under Hermes' per-result threshold, past which
Hermes shows the model only a 1,500-character preview: 100,000 characters, or 15% of the context
window (at four characters a token) on a smaller model. On a model with a window under 100K tokens,
set it to about half the window's token count (`32000` for 64K tokens).

`librenms_timezone` is the zone LibreNMS runs in (its PHP `date.timezone`). LibreNMS writes fault,
alert-log, eventlog, syslog, authlog and billing times in that zone with no offset, and no API field
says which zone it is, so a time such as `2026-10-28 10:02:00` is an hour off for a model that reads
it as UTC when LibreNMS runs in Amsterdam. Every `librenms_report` answer names this zone in
`timezone`, or says it is unknown while the setting is empty. The views that show fault, log and
billing times (`alerts`, `alert_history`, the `port` view's open faults, `events`, and a bill's last
calculation in `bills`) read them in this zone, and without it show them as LibreNMS wrote them,
with no age; `alert_history` and `events` then read their window from a bound early enough to hold
it in any zone, and say so, and refuse `today`. A zone west of LibreNMS's shows: a time that reads
more than five minutes after LibreNMS's clock (`librenms_timezone` west of the server's, such as
`America/New_York` on a server that writes UTC) has no age, and a note says the setting is wrong, rather
than calling a 3-hour-old alert new. A zone east of the server's cannot be told from the times: they
read earlier than they are, and every age is too large by the difference between the zones (an hour or
two with `Europe/Berlin` on a server that writes UTC), with no note. Every other time a report shows
is exact in any zone: device times (ISO-8601 UTC), outages and port polls (unix seconds), uptimes and the age of a
port's last change (counted from the device's uptime), a billing period's dates (LibreNMS's
calendar), every age counted to LibreNMS's own clock (the `Date` of its answer). A name the host's
zone database does not hold is refused and the setting stays empty.

A value that cannot be read as its setting's type fails closed: a flag takes the value that lets the
model do least, a number its default (or its upper limit when it is too large), and an unknown
`write_mode` becomes `read_only`, and a relative `audit_log_path` is the default path.
`/librenms status` lists every such fallback, also while LibreNMS is unreachable. Settings are
re-read on each call, so a change in `config.yaml` or the Desktop settings form applies without a
restart. Retention is applied at most hourly per profile, when a plan is made or listed, on status
and on every `/librenms` or `hermes librenms` command; for a strict policy, run `hermes librenms
prune` from cron.

The audit log holds every triggering message, so it has a retention of its own. It is rotated before
an event would take it past `audit_max_mb`, and daily while `audit_retention_days` is on, by renaming
it to `audit.jsonl.<UTC time of its newest event>`; rotated files past the newest `audit_keep_files`,
or whose newest event is older than `audit_retention_days`, are deleted after each rotation, by the
same hourly sweep and by `hermes librenms prune`. Every writer, in every process, holds a lock on
`audit.jsonl.lock` from its open to its write, so no event is lost to a rotation. Keep
`audit_keep_files` above `audit_retention_days` (status warns otherwise), and set all three to `0`
when logrotate manages the file. Where the log can be neither rotated nor pruned (an
`audit_log_path` in a directory the account cannot create files in, say), status warns and `prune`
fails. See [docs/audit.md](docs/audit.md#rotation-and-retention).

Environment variables (connection only; nothing that relaxes a safeguard is read from the
environment):

| Variable | Required | Meaning |
|---|---|---|
| `LIBRENMS_URL` | yes | Base URL, e.g. `https://librenms.example.com` or `https://nms.example.com/librenms`. A trailing `/api/v0` is stripped; a URL with a user name or password in it is refused |
| `LIBRENMS_TOKEN` | yes | API token, sent only in the `X-Auth-Token` header |
| `LIBRENMS_VERIFY_SSL` | no | `true` (default), `false` (needs `allow_insecure_transport`), or the path of a CA bundle file or directory |
| `LIBRENMS_TIMEOUT` | no | Seconds to connect and to wait for each read (`30`), or both apart (`5,60`) |
| `LIBRENMS_PROXY` | no | Unset: the usual proxy variables apply. `none`: ignore them. Or an `http(s)://` proxy for LibreNMS alone: scheme, host and port, with any user name and password percent-encoded (`%40` for `@`, `%23` for `#`, `%2F` for `/`, `%3F` for `?`, `%25` for `%`); anything else is refused. An `http://` proxy receives that password in clear (Basic authentication), whatever `allow_insecure_transport` says. Unset, an `HTTPS_PROXY`, `HTTP_PROXY` or `ALL_PROXY` that no URL parser reads as written (an unencoded `#`, `/`, `?`, `\` or bracket in its password, or a host or port it cannot read, such as a blank or a port that is no number) fails each call with an error that names the variable and what to fix, and never quotes it; `NO_PROXY` exempts LibreNMS as `requests` reads it (a name suffix, a CIDR range such as `10.0.0.0/8`, or a `host:port`) |
| `LIBRENMS_SNMP_*` | no | SNMP credentials a device-create plan names as `{"env": "LIBRENMS_SNMP_<NAME>"}`, read only at apply time. A community's or password's variable ends in `_SECRET`, `_PASS` or `_PASSWORD` (`LIBRENMS_SNMP_COMMUNITY_SECRET`), which Hermes masks in a printed environment |
| `LIBRENMS_AUDIT_SINK_SECRET` | no | A collector token for an `http` audit sink, written as `${LIBRENMS_AUDIT_SINK_SECRET}` in its headers; the Desktop's `audit_sink_secret` field stores it. Once `audit_sinks` holds the placeholder, edit it in `config.yaml`: the Desktop's form shows and saves it with the token in its place. Any variable works the same way (see [docs/sinks.md](docs/sinks.md)) |

## Asking questions

The plugin answers questions as well as it makes changes. The second bundled skill, `librenms:ask`
([skills/ask/SKILL.md](skills/ask/SKILL.md)), gives the model the questions operators ask, 57 of them,
each with the `librenms_report` call that answers it: which ports are down, errors and discards,
utilisation and the busiest ports, link speeds and duplex, descriptions and device names, LLDP/CDP
neighbours and mismatches, where a MAC or IP address is, VLANs, what is alerting and what alerted, sensors
and optics, BGP and OSPF, free ports, bills, the eventlog, syslog and logins. It also gives the units and
states of what comes back, how to carry a conversation, when to say an answer is stale, cut short or
incomplete, and what LibreNMS's API cannot answer. Hermes lists both skills in the system prompt: the model
loads `librenms:ask` when you ask and `librenms:workflow` when you want something changed, and each says
when to load the other. `/librenms:ask <question>` loads it before your question.

```
you    > Which ports on edge-rtr1 are down?
hermes > [librenms_report] ports, scope edge-rtr1, state down
         Both WAN ports of edge-rtr1.example.net: Gi0/0/0 (WAN: transit-a) has been down for 2h 5m,
         and Gi0/0/1 (WAN: transit-b) since the router booted, over 50 days ago. Both are
         administratively up, so LibreNMS counts them as down (as of 12:00 UTC).
you    > Is anything alerting about them?
hermes > [librenms_report] alerts, scope device 2, entity_type port
         Yes: Port down on Gi0/0/0 since 10:02, not acknowledged. The one on transit-b was
         acknowledged by alice at 09:15: "carrier ticket 4411".
you    > What is on the other end of transit-a?
hermes > [librenms_report] neighbours, scope device 2, port_id 5
         transit-a-pe1, port xe-0/0/1, which says it is a Juniper MX204. LibreNMS does not monitor
         it, so I cannot see that side; the name and port are what the neighbour advertises.
you    > When exactly did it go down, and has it before?
hermes > [librenms_report] events, scope device 2, port_id 5, window 30d
         At 09:55 today. Before that, once in the last 30 days: on 20 October at 14:05.
you    > How busy is the switch?
hermes > [librenms_report] find "switch"
         There are two: core-sw1.example.net in SFO-1 and access-sw2.example.net in NYC-2. Which one?
you    > The core one. Was it that busy last week too?
hermes > [librenms_report] ports, scope device 1, sort util
         [librenms_report] bills, scope device 1
         Its busiest port is Gi1/0/1 (uplink to edge-rtr1): 800 Mbit/s out of 1G, 80 %, over the
         last five-minute poll. Last week I cannot tell: LibreNMS's API keeps a port's last poll, not
         its history, and no bill covers core-sw1's ports. Its graphs in LibreNMS show last week.
```

Follow-ups build on the answers before them: the model puts the ids an answer gave in the next call
instead of the names (a `device_id` as `scope.device`, a `port_id` as view `port`'s `scope.port` or as
`filter.port_id` of `neighbours` and `events`, a `rule_id` as `filter.rule`), so "that port", "the other
end" (the far port of the link, when LibreNMS monitors it), "what about yesterday" (the same question
over a longer `window`) and "the rest" (`next_offset`) need no name looked up again. "The same for
edge-rtr1" asks the same question of a new device, whose name is resolved like any other, and "is it
still down?" is asked of LibreNMS again, never answered from the earlier result. A name that could be
several devices gets a question back, never a guess. Every answer says when its data is from, and says so
when a device was not polled lately, when rows were cut, or when the data is incomplete. The skill has
the model say what the API does not hold instead of guessing: a port's traffic history or 95th percentile
outside bills, a sensor's history, which ports are err-disabled (only syslog says, when the device sends
it), which ports could run faster than they do, which hosts talk most (there is no flow data), and IPv6
neighbours. [examples/conversations/](examples/conversations/) holds four whole conversations, which the
tests run against the fake LibreNMS, checking that every value an answer quotes is a value the tools
returned, and that each count, percentage and state is the one under the key that holds it.

## Scheduled digest

The plugin adds a scheduled digest to Hermes' Automation Blueprints: `librenms:network-digest`,
listed beside Hermes' own in `/blueprint`, the dashboard's Blueprints tab and the Desktop's Cron page.
`/blueprint network-digest` asks for each blank in the chat; given the values, it schedules the job at
once:

```
/blueprint network-digest time=07:30 recurrence=weekdays group=core-switches rows=10 all_clear=skip deliver=telegram
```

| Blank | Default | Means |
|---|---|---|
| `time` | `08:00` | When it runs (24h, Hermes' local time) |
| `recurrence` | `everyday` | `everyday`, `weekdays` or `weekends` |
| `group` | `all` | Every device, or only those of the LibreNMS device group named here |
| `rows` | `10` | Rows each section lists: 5, 10 or 20 (its count covers every match) |
| `all_clear` | `send` | On a day with nothing to report, `send` a short all-clear or `skip` the message |
| `deliver` | `origin` | The chat you set it up from, `local` (saved, not sent), or a connected platform |

Each run makes six `librenms_report` calls, with `limit` set to `rows` and, for a group, `scope.group`, and
reports them in this order, each section headed with its count:

| Section | Call |
|---|---|
| Devices down | `{"view": "devices", "filter": {"status": "down"}}` |
| Alerts firing | `{"view": "alerts", "sort": "severity"}` (critical first; within a severity, acknowledged ones last) |
| Busiest ports | `{"view": "ports", "sort": "util"}` |
| Ports over 80 % | `{"view": "ports", "filter": {"util_above_pct": 80}, "sort": "util"}` |
| Sensors out of range | `{"view": "health", "filter": {"status": ["warning", "critical"]}, "sort": "status"}` |
| BGP sessions down | `{"view": "routing", "filter": {"protocol": "bgp", "not_established": true}, "sort": "state"}` |

```
hermes > LibreNMS network digest, data as of 08:00 UTC
         Devices down: none.
         Alerts firing (4, 3 unacknowledged): critical High CPU on core-sw1 for 3h 10m; warning
           Port down on edge-rtr1 Gi0/0/0 (WAN: transit-a) for 2h 5m; ...
         Busiest ports: core-sw1 Gi1/0/1 (uplink to edge-rtr1) 78 %, 780 Mbit/s out of 1G; ...
         Ports over 80 %: none.
         Sensors out of range (2): access-sw2 Chassis Temperature 71 °C (critical, limit 70 °C);
           core-sw1 processor 92 % (warning).
         BGP sessions down (1): edge-rtr1 to 203.0.113.1 (AS64500, transit-a), idle for 2h 5m.
```

The digest opens with when its data is from, says so when a section is partial, stale or could not be
read, and treats text from the network as data. It loads no skill: the prompt holds what a run needs,
including how to reach the tools when Hermes defers them, so a run costs the six calls and a short
prompt.

Scheduling makes an ordinary Hermes cron job, changed like any other: `hermes cron list` shows its id,
and `hermes cron edit <id> --schedule "30 6 * * 1-5"` (or `--deliver`), `/cron` in the CLI, or the
dashboard's or the Desktop's Cron page change it. Disabling the plugin takes the blueprint out of the
catalog but leaves the job, whose runs then say the LibreNMS tools are missing.

**It writes nothing.** Its prompt asks for reads only, and the plugin holds it to that: Hermes tells a
plugin which cron run is executing, and in a run whose prompt holds the digest's first sentence
("LibreNMS network digest (read-only).") `librenms_plan`, `librenms_apply` and `librenms_rollback`
refuse, before any approval prompt, whatever a device's text asks for and whatever the job's prompt was
edited to say while it keeps that sentence; `hermes librenms apply` or `rollback` in the run's terminal
is blocked whatever the settings. Nor does the run hand the work on: `delegate_task`, `cronjob_manage`,
the A2A plugin's `a2a_call` and `a2a_orchestrate` and the kanban toolset (`kanban_*`) refuse in it,
since Hermes gives a subagent no cron identity, a job the run created or started is another run, and an
A2A peer or a kanban worker is another agent, so none of them would be held. Each refusal is audited (`plan_rejected`, `apply_refused`,
`rollback_refused`, `delegation_refused`) with the cron job and run in its actor.

## Tools

| Tool | Writes | Purpose |
|---|---|---|
| `librenms_query` | no | Look up devices, ports, alerts, sensors and logs through any allowed API v0 GET path, or `{"action": "status"}` for connectivity, version and settings |
| `librenms_report` | no | Answer a question in one call: `find` what a name, address or phrase could mean (ranked, with why), or report on `devices` (state, down since, uptime, last poll, naming checks), `ports` (state, speed, utilisation, errors, last change), one `port` in depth, free-port `capacity`, LLDP/CDP `neighbours` (both ends, speed, duplex, MTU and description mismatches), where an IP or MAC is (`locate`: the edge port first), `vlans` (per device, and the ports in one), what is alerting (`alerts`: severity, acknowledged and its note, since when, the port or sensor), what alerted over a window (`alert_history`: per rule, device or event), sensors, optics, CPU, memory and storage against their limits (`health`), BGP and OSPF sessions (`routing`: up or not, for how long), what LibreNMS logged over a window (`events`: the eventlog, syslog or logins to LibreNMS, each entry or per device or port, with port flaps) or bills (`bills`: the 95th percentile against the commit, this period or the last), with names joined, units worked out and counts summed; `help` says what each view takes, without a LibreNMS call |
| `librenms_plan` | no | Validate and diff a list of operations; save a plan |
| `librenms_apply` | yes | Apply a plan with preconditions, verified writes, a journal and auto-rollback; `dry_run` re-checks only |
| `librenms_rollback` | yes | Revert an applied or partially applied plan |
| `librenms_plans` | no | List plans or show one with its diff, journal and rollback result, a range of steps at a time; `detail` adds the steps and full journal entries |

The bundled skill `librenms:workflow` (see [SKILL.md](SKILL.md)) tells the model to query first,
show the diff, ask, and apply only on an explicit yes, never in unattended contexts. The tool
descriptions repeat that rule. The other, `librenms:ask`, is for questions (see
[Asking questions](#asking-questions)).

Hermes' tool search (`tools.tool_search.enabled`, on by default) defers plugin tools: the model is
given `tool_search`, `tool_describe` and `tool_call` and one catalog line per tool, the first sentence
of its description. Each of those sentences says in 60 characters or fewer what the tool answers
or does ("Look up LibreNMS devices, ports, alerts, sensors and logs."), and both skills, which are
offered whenever the plugin is enabled, tell the model to reach deferred tools through `tool_call`. The
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
| `ports` | Per port: `state` (`disabled` when administratively down, else its operational status: `up`, `down`, `lowerLayerDown`, `notPresent`, ...), `speed_bps`/`speed` (what utilisation is measured against: the circuit speed parsed from its description, `egress/ingress` such as `100M/20M`, as LibreNMS's web UI measures it; else `ifSpeed`), `interface_speed_bps`/`interface_speed` (the speed the interface runs at, `ifSpeed`, never a circuit speed), `in_bps`/`in` and `out_bps`/`out` (the octet rates times 8), `in_pct` against the ingress speed and `out_pct` against the egress speed, `util_pct` (the larger), `duplex`, `mtu`, errors per poll and per second, `last_change_age` (the device's uptime less `ifLastChange`; "over" when the port has not changed since boot, unknown past 497 days of uptime), `polled_at` and `stale` (not polled for two poll periods: the figures are not current), `no_description` (none, or only its own name), `ignored` and `polling_disabled`. `summary` counts states, `not_up` (administratively up, not up, not ignored and still polled: LibreNMS's down), ports over 80 %, with errors, stale and without a description, and names the busiest | `scope` (also `port_group`); `filter` `state`, `util_above_pct`, `errors`, `speed_below_mbps` (the interface's speed), `duplex`, `no_description`, `type` (`ethernet` or an ifType), `text` (in its names or description); `sort` `name`, `util`, `util_in`, `util_out`, `errors`, `speed` (the interface's) |
| `port` | One port, everything `ports` says of it and its ifIndex, MAC, VLAN, packets per second, discards (from its statistics), LLDP/CDP neighbours (named when LibreNMS monitors them), transceivers, the dBm sensors of its optics with their limits and state, and the open faults about it (rule, severity, state, first seen, note; never their details) | `scope.port`: a `port_id`, or with `scope.device` an interface name (`Gi1/0/5`, `GigabitEthernet1/0/5`) or description; without a device, a name is searched among every port (one holding `#`, `?`, `%` or `\` needs `scope.device`) |
| `capacity` | Per device with physical ethernet ports: how many are `up`, `down` and `disabled`, `used_pct`, `free` (not up and unchanged for `idle_days`, by the interface's speed), and `free_unknown` (not up, but the device has not been up that long, or its uptime counter wrapped) | `scope`; `filter` `idle_days` (default 30); `sort` `name`, `free`, `used_pct` |
| `neighbours` | Per LLDP/CDP link of the devices in scope: the local port (label, description, state, interface speed, duplex, MTU), what the neighbour advertised (`remote_hostname`, `remote_port`, `remote_platform`), whether LibreNMS monitors it (`remote_monitored`, `remote_device`) and, when LibreNMS matched its port (`remote_port_id`), that port's state, speed, duplex and MTU. Checks: `speed_mismatch` and `duplex_mismatch` (both ends up and different; the speed the interfaces run at, never a circuit speed from a description), `mtu_mismatch` (a note when the two differ by an ethernet header, as Junos counts it), `description_mismatch` (the local description names neither the neighbour nor its port, compared as whole words; null without a description); each null when it cannot be checked. `summary` counts links, protocols, unmonitored neighbours (and names them), links whose far port is not known, each mismatch and ports without a description | `scope`; `filter` `mismatch` (`speed`, `duplex`, `mtu`, `description`, or a list: any of them), `remote_unmonitored`, `port` (the local port: its name, long or short, or port_id; a number is both, as HP and Aruba switches name their ports `5`), `port_id` (that port alone, as a follow-up gives a row's `port_id`), `remote` (part of the neighbour's name), `protocol`; `sort` `name`, `remote` |
| `locate` | Where an IPv4 or MAC address is: the switch ports that learned the MAC (`kind` `port`), with how many MACs each learned (`macs_learned`), the device LibreNMS monitors that its LLDP/CDP neighbour is (`neighbour`), `uplink` (that neighbour learned the MAC too: the MAC is behind it), `likely_edge` (of a MAC's ports that are not uplinks, those that learned the fewest, as LibreNMS guesses; a port to the device at the address looked up is never an uplink), its VLANs, `trunk`, `last_seen` and its age; then the routers' ARP entries (`kind` `arp`: IP, MAC, router interface). `summary` names the likely edge ports, the MACs and IPs found and, for an IP, the device LibreNMS monitors at it. An IPv6 address is refused (the API has no IPv6 neighbour table; `find` matches interface addresses) | `term` (a MAC in any usual form, or an IPv4 address); `sort` `edge` |
| `vlans` | Per device in scope, each VLAN: tag (`vlan`), `name`, `type`. With `filter.vlan` and on at most 10 devices, the `ports` in it, `untagged` (access, or a trunk's native VLAN) or `tagged`, with their state and counts. `summary` counts VLANs and devices and names tags that are called differently on different devices | `scope`; `filter` `vlan` (a tag, or part of a name); `sort` `vlan` (by tag, then device), `name` (by device, then tag) |
| `alerts` | What is alerting now: LibreNMS's open faults, one per rule, device and alerted object, each with the rule and its `severity`, `state` (`active`, `acknowledged`, `worse`, `better`, `changed`; `recovered` only when asked for), `acked`, the acknowledgement `note`, `first_seen` and its age, the rule's runbook link (`procedure`) and what alerted: `entity_type` (`port`, `sensor`, ...), `port_id` or `sensor_id`, and `entity`, its label (a port as `ifName (description)`, a sensor by its description and class, with the reading as `value`). The label comes from the rows the rule matched, through an allow-list of label keys; a port fault that holds none is named from its device's ports. Never the fault's `details` (every column the rule joined) or the alert's contacts. `summary` counts states, severities, the unacknowledged alerts, devices and rules, and the rules with the most alerts | `scope`; `filter` `state`, `severity`, `acked`, `rule` (an id, or part of a name), `entity_type` (`port`, `sensor`, ..., `device` for a device-wide rule), `text` (in the device, rule, what alerted or the note); `sort` `severity` (critical and unacknowledged first, newest first), `newest`, `oldest`, `name` |
| `alert_history` | What alerted over `window` (`1h`, `24h` by default, `7d`, `30d`, any duration up to a year, or `today` with `librenms_timezone`), from LibreNMS's alert log, counted per rule (`filter.by` `rule`, the default; for the whole fleet every rule, also those that logged nothing, with `disabled`, `notifies` and `muted`), per `device` (with the rule that fired most there) or as each `event` (newest first: time, device, rule, `state` `alerted`, `recovered`, `acknowledged`, ..., what alerted). Counts: `fired` (alerts raised), `cleared`, `flaps` (raised again after clearing, within the window), `last_fired` and its age. `summary` gives the window and the bound sent (`from`, server time; `exact` false without `librenms_timezone`), what LibreNMS logged there, the totals, the five rules and devices that fired most and, for the whole fleet, how many rules are disabled or notify no one | `scope`, `window`; `filter` `by`, `rule`, `severity`, `state`, `entity`, `disabled`, `notifies`, `fired`; `sort` `fired`, `flaps`, `last_fired`, `name` |
| `health` | What each sensor reads against its limits (temperature, optic dBm, voltage, fans, power, ...): `value` in the class's `unit` and as a `reading` (`41 °C`, `-3.2 dBm`, `6.53 mA`: current, power and frequency with a prefix, as LibreNMS shows them), the four limits, `status` as LibreNMS decides it (`critical` past `limit` or below `limit_low`, `warning` past a warning limit; a limit not set never trips; `unknown` without a reading and for a `state` sensor, whose meaning the API does not return), `low_margin` and `high_margin` (how far from the first limit below and above, in the reading's unit, negative past it), `margin` and `nearest`, `alerting`, and for the page the port a sensor is on (measured on its ifIndex or on one of its transceivers, or for a dBm sensor named in its description) and an optic's `direction` (`rx`, `tx`). For at most 5 devices also their processors and memory pools (when `filter.class` names none) or storage, in percent against LibreNMS's warning limit, memory and storage with bytes used of their size. `stale` when the device was not polled lately. `summary` counts statuses and classes and names the hottest temperature and the reading nearest a limit it has not crossed | `scope`; `filter` `class` (sensor classes, `processor`, `mempool`, `storage`), `status`, `margin_below` (within this much of a limit, or past it), `direction`, `text`; `sort` `status` (critical first, nearest a limit first), `margin`, `low_margin`, `high_margin`, `value` (highest first), `name` |
| `routing` | Per BGP session and OSPF or OSPFv3 neighbour of the devices in scope: BGP's peer (IPv6 written short), `remote_as`, `as_name`, `description`, `state`, `admin_status` and `enabled`, `established`, `up_for` or `down_for` (from the session's established timer at the last poll, plus the time since), `last_error` (LibreNMS's text, else the BGP error code's name); OSPF's peer, `router_id` (dotted: LibreNMS stores an OSPFv3 neighbour's as a number), `state`, `established` (`full`), the port it is on (named for the page), `events`. `not_established` is what LibreNMS alarms on: an enabled BGP session not established, an OSPF neighbour not full (a note says `twoWay` is normal between two routers that are neither DR nor BDR). `summary` counts per protocol, the sessions LibreNMS counts as down and the states | `scope`; `filter` `protocol` (`bgp`, `ospf`, `ospfv3`), `not_established`, `enabled` (a BGP session whose admin status is neither enabled nor shut down matches neither), `state`, `remote_as` (`65001`, `AS65001`, asdot `1.10`), `text`; `sort` `state` (down first), `name`, `up_for` (shortest first), `remote_as` |
| `events` | What LibreNMS logged over `window` (`1h`, `24h` by default, `7d`, `30d`, any duration up to a year, or `today` with `librenms_timezone`), newest first: its eventlog (`filter.log` `eventlog`, the default: a device or port changing, a reboot, an edit through the API, with `type`, `severity` `unknown` to `error`, `message`, the port it is about, named, and `username`, who made a change), the syslog the devices send it (`syslog`: `severity` `emerg` to `debug`, from the name or number the collector wrote, `facility`, `program`, `tag`, `message`), or the logins to LibreNMS itself (`authlog`: `user`, `address`, `result`; no scope). Each entry (`filter.by` `event`, with its time and age), counted per `device` (entries, by severity, the type or program logged most, the latest), or per `port` from the eventlog's port changes (`ifOperStatus: up -> down`): `status_changes`, `went_down`, `flaps` (back up after going down within the window), `last_status` and `last_change`. `summary` gives the window and the bound sent (`exact` false without `librenms_timezone`), what LibreNMS logged there, counts per severity and device, the types, programs or results logged most; for the eventlog the ports that changed, went down and flapped and those that changed most; for the authlog who logged in (logins, addresses, the last). LibreNMS reads a port's state at each poll, about five minutes apart, so a shorter bounce may not be logged | `scope` (not for the authlog), `window`; `filter` `log`, `by`, `min_severity` (`debug`, `info`, `notice`, `warning`, `error`, `critical`: that or worse, eventlog and syslog on one scale; a port change is `notice`), `type` (eventlog), `program` (syslog), `port` (eventlog: a name, long or short, or a port_id; a number is both, as HP and Aruba switches name their ports `5`, but with one device in scope it is that device's port of that name), `port_id` (eventlog: that port alone, as a follow-up gives a row's `port_id`), `text`; `sort` `newest`, `oldest`, `most`, `name` |
| `bills` | Each bill LibreNMS keeps, in the current billing period (`filter.period` `current`, the default) or the last one that ended (`previous`, within 40 days, against the commit it had then): a CDR bill's 95th percentile (`rate_95th_bps`, inbound, outbound and the `direction` billed) against its commit (`commit_bps`), a quota bill's traffic (`used_bytes`) against its quota (`quota_bytes`), `used_pct`, `over` and `overuse`, the average rate, the bytes `transferred`, the period's dates (`period_from`, `period_to`), when LibreNMS last worked the figures out (`last_calculated` and its age) and the bill's ports and their devices. `summary` counts bills, those over, per type, and names the fullest. The 95th percentile is of the bill's ports together over its billing period: the API keeps no other traffic history | `scope` (a bill with a port on a device in it); `filter` `period`, `over`, `type` (`cdr`, `quota`), `used_above_pct`, `text` (in its name, customer id, reference, notes, ports or their devices); `sort` `used_pct` (fullest first), `name`, `rate_95th` |
| `help` | What each view answers and takes: without `topic` the views and what they share (scope, filter, sort, paging, window, units); with `topic` (a view) its scope keys, each filter with what it takes, each sort, the keys of its rows and summary, and examples. Answered by the plugin, without a LibreNMS call | `topic` |

`scope` narrows a report to devices: `device` (an id, a hostname, or a sysName, display name,
first label, IP or phrase), `devices` (a list of them), `group` (a device group's name or id),
`location` (a name, an id, or part of a name: every location that holds it, as LibreNMS's own
`type=location` filter reads it), `os` and `type`; every key given must hold. `ports` also takes
`port_group` (a port group's name or id), and `port` takes `port`; `find` and `locate` take none.
A device named by anything but its id or hostname resolves only when exactly one device matches it
exactly, or only one matches every word of the phrase; the result says how (`scope.resolved`).
Otherwise the report answers `ambiguous: true` with the candidates and reports nothing, rather
than guess; so does a port name that could be several ports.

```json
{"view": "find", "term": "core switch sfo"}
{"view": "devices", "filter": {"status": "down"}}
{"view": "devices", "scope": {"location": "SFO"}, "filter": {"rebooted_within": "24h"}}
{"view": "devices", "filter": {"not_polled_for": "15m"}, "sort": "last_polled"}
{"view": "ports", "sort": "util", "limit": 10}
{"view": "ports", "scope": {"device": "core-sw1"}, "filter": {"state": "down"}}
{"view": "ports", "filter": {"util_above_pct": 80}}
{"view": "port", "scope": {"device": "core-sw1", "port": "Gi1/0/48"}}
{"view": "capacity", "scope": {"group": "access-switches"}, "sort": "free"}
{"view": "neighbours", "scope": {"device": "core-sw1"}}
{"view": "neighbours", "scope": {"device": "edge-rtr1"}, "filter": {"port_id": 5}}
{"view": "neighbours", "filter": {"mismatch": ["speed", "duplex", "mtu"]}}
{"view": "neighbours", "filter": {"remote_unmonitored": true}}
{"view": "locate", "term": "00:11:22:33:44:55"}
{"view": "vlans", "scope": {"device": "access-sw2"}, "filter": {"vlan": 20}}
{"view": "alerts", "filter": {"severity": "critical", "acked": false}}
{"view": "alerts", "scope": {"device": "edge-rtr1"}, "filter": {"entity_type": "port"}}
{"view": "alert_history", "window": "7d", "sort": "fired", "limit": 10}
{"view": "alert_history", "scope": {"device": "edge-rtr1"}, "window": "7d", "filter": {"by": "event"}}
{"view": "alert_history", "filter": {"notifies": false}}
{"view": "health", "filter": {"status": ["warning", "critical"]}}
{"view": "health", "scope": {"device": "core-sw1"}, "filter": {"class": ["temperature", "processor"]}}
{"view": "health", "filter": {"class": "dbm", "direction": "rx"}, "sort": "low_margin", "limit": 10}
{"view": "routing", "filter": {"protocol": "bgp", "not_established": true}}
{"view": "routing", "filter": {"remote_as": "AS64500"}}
{"view": "events", "scope": {"device": "core-sw1"}, "window": "1h"}
{"view": "events", "scope": {"device": "core-sw1"}, "window": "48h", "filter": {"port_id": 2, "by": "event"}}
{"view": "events", "window": "today", "filter": {"type": "interface", "by": "port"}, "sort": "most"}
{"view": "events", "scope": {"device": "edge-rtr1"}, "window": "today", "filter": {"log": "syslog", "min_severity": "error"}}
{"view": "events", "window": "today", "filter": {"log": "authlog"}}
{"view": "bills", "filter": {"over": true}}
{"view": "bills", "filter": {"period": "previous", "text": "transit"}}
{"view": "help", "topic": "health"}
```

The tool's description names the views and what they share; each view's filters, sorts, row keys and
examples are in view `help`, so the schema sent to the model on every turn stays small. A scope,
filter or sort key a view does not take is refused, naming the view and those it does and pointing
to `help`. View `help` ignores `limit` and `offset` (a model may send their defaults) and an empty
`scope` or `filter`, and refuses a scope or filter that names anything, a sort, a term or a window.

A port view reads the ports of a scope of up to 10 devices one device at a time, and otherwise one
listing of every port, always naming the columns it needs; LibreNMS keeps their counters in mixed
units (octets per second, bit/s, Mbit/s, hundredths of a second of sysUpTime), and the report does
the arithmetic. Rates are LibreNMS's average over its last poll (about five minutes): the API
keeps no history of a port's traffic, only bills do. `neighbours` reads the links of up to 10
devices one device at a time, otherwise every link at once, then the ports of the devices at both
ends of them as a port view does (one device at a time, the local devices first, when they are 10
or fewer or LibreNMS's listing of every port is too large to read). `locate` reads the ports that
learned the MAC, its forwarding entries and the ARP tables, then the VLANs and links of the
devices that learned it (a port whose monitored neighbour learned the MAC too is an uplink, not an
edge port). `vlans` reads the VLANs of up to 10 devices one device at a time, otherwise every
device's at once, and for one VLAN the ports of each device that has it, with their VLAN
memberships. `alerts` reads the faults once (LibreNMS has no device filter for them; one severity
at a time when the answer is too large to read) and, for a port fault whose rows hold no label, the
port names of its device (five columns, at most 10 devices). `alert_history` reads the alert rules
once and the alert log from the window's start, newest first, 250 entries a request (fewer while
LibreNMS's answer is too large to read) and at most 2,000 a report: each device's log for a scope
of up to 10 devices (none for a scope that holds no device, which answers no rows), otherwise every
device's; a window that holds more is answered `partial`.
LibreNMS writes alert-log times in its server's zone: without `librenms_timezone` the window is
read from a bound early enough to hold it in any zone (up to 26 hours more), and the result says
so (`exact: false`). `health` reads every sensor once (`resources/sensors`, LibreNMS's only route
that holds their readings and limits, and which takes no filter) and keeps the scope's; when that
answer is too large to read (16 MiB) it reads the scope's devices one sensor at a time within the
request budget, which fits only a narrow question (a device and a class) and is otherwise
`partial`. Processors, memory pools and storage have no fleet-wide route: a listing and a request
per item, for at most 5 devices and 8 of a kind each. The port of a sensor on the page is named from
its device's port names and, where its ifIndex names none, its transceivers. A temperature, bias or
voltage sensor on an inventory entity is most often the chassis's, but may be an optic's that a
device puts on the transceiver's entity: it is tied on a device whose port names the page reads
anyway and, for a scope of at most 5 devices, on any other (its transceivers are read first, its
port names only when one holds the entity); a wider scope reads nothing for it. A LibreNMS without
the transceivers route (an older release) has none, which a note says, and is not `partial`.
Readings are the last poll's: the API keeps no history of them. `routing` reads
`bgp`, `ospf` and `ospfv3` once each (by device id for a scope of one device; `remote_asn` for
`filter.remote_as`), and for the page the port names of the devices whose OSPF neighbours it lists;
LibreNMS answers `ospfv3` with HTTP 500 when it has no OSPFv3 neighbour, which the report reads as
none (as it reads a LibreNMS too old to have the route, with a note, also when that protocol is the
only one asked for). `events` reads its log as `alert_history` reads the alert log (from the
window's start, newest first, 250 entries a request, at most 2,000 a report, each device's log for a
scope of up to 10 devices), and the port names of the devices whose ports the page and summary name
(and for `filter.port`, of the devices whose ports logged a change); the authlog has no device path
and needs no device listing, so a `ping` read gives LibreNMS's clock before it. `bills` reads
LibreNMS's bill listing once (with `period=previous` for the last period), which carries LibreNMS's
own figures and each bill's ports.

Every report carries `data_as_of` (LibreNMS's clock, from the `Date` of its answer), `timezone` (see
`librenms_timezone`), `count`, `returned`, `offset`, `truncated` and `next_offset` (more rows: read
on with `offset`), and `partial` with a `partial_reason` when the data itself is incomplete (the
request budget ran out, as it can when LibreNMS's listing of every port is too large to read and the
ports are read one device at a time, a read for one device failed, or the rows of more than 10
devices name ports a view could not name, as it reads the port names of 10 devices at most); `notes`
say what to do next. Rows are cut to `limit` (default 20, at most `max_query_results`; 10 for
`find`) and to `max_result_chars`. Text from LibreNMS is clipped to 200 characters, escaped like
every result, and named in `untrusted_fields`, whether it is in the rows, the scope or the summary
(a page past the last row still marks the rule and device names its summary counts).

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
whose plan is no longer applicable; `status` while LibreNMS cannot be reached; a `prune` whose audit
log retention could not run or ran only in part), and 2 on a usage error; anything but 0 is printed
on stderr. So `hermes librenms check 7dde && hermes librenms apply 7dde` stops at a conflict, and a
script can tell an apply that went through from one that did not.

## Safety model

- **Read-only until a plan exists.** `librenms_query`, `librenms_report`, `librenms_plan` and
  `librenms_plans` never write, and the query and report tools call only allow-listed GET routes
  (a report at most 30 of them per call).
- **The scheduled digest stays read-only.** In a cron run of `librenms:network-digest` (its prompt's
  first sentence, in the run Hermes says is executing) the plan, apply and rollback tools refuse in
  every `write_mode`, and so does `hermes librenms apply|rollback` in its terminal, audited; see
  [Scheduled digest](#scheduled-digest). The run starts no subagent, cron run, A2A peer or kanban
  worker, which would not be held: `delegate_task`, `cronjob_manage`, `a2a_call`, `a2a_orchestrate`
  and `kanban_*` refuse in it. A Hermes its terminal starts is a session
  of its own ([SECURITY.md](SECURITY.md#what-the-plugin-does-not-do)).
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
- **Approvals are bound to what was shown.** The approval prompt's key carries a digest of the plan's
  content (what runs and what the prompt shows, a rollback's run records included), so a remembered
  "session" or "always" answer does not cover the plan once its file changes, and the handler of the
  approved call refuses, under the claim, a plan whose content is not what the prompt showed (an edit
  made while the prompt was open, another plan saved under the same id), then runs exactly the plan
  it checked. A model's call that no prompt showed while one was due is refused, and so is a plan
  file whose `id` is not its name. See [Write modes](#write-modes).
- **The shell does not read the secrets.** A `terminal`, `execute_code` or `process_manage` call
  that reads `LIBRENMS_TOKEN`, `LIBRENMS_PROXY`, an SNMP credential (`LIBRENMS_SNMP_*`) or a sink's
  collector token by name (`$LIBRENMS_TOKEN`, `printenv` however it is run, `os.environ[...]`,
  `os.getenv(r"...")`, `process.env?.…`; a presence test such as `[ -n "$LIBRENMS_TOKEN" ] && ...`
  reads nothing, unless the call traces with `set -x` or holds a here-document), or that calls the
  LibreNMS API with a token (`Authorization: Bearer` or `X-Auth-Token`, API v0 or v1), is refused
  and audited as `secret_access_refused`. One that reads a Hermes `.env` file (by name, a dotfile
  glob or a recursive search of the home, also after a `cd` into it), or prints an environment that
  holds them (`env`, also through `sudo --user`, `bash -c` and the like), goes to
  Hermes' approval prompt with the command, audited as `secret_access_requested`. A text heuristic,
  like the CLI block below; the token's role is the limit that holds.
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
field-level diff while room remains. The approval is keyed per plan, choice and content (a digest of
the plan as the prompt read it), so "session" or "always" never carries over to another plan, or to
the same plan once its file has changed: Hermes asks again. The model's `librenms_apply` and
`librenms_rollback` take only the full plan id, and one that names no saved plan is refused without
asking; the call then runs only the plan the prompt showed, since a plan whose file changed while
the prompt was open is refused under the claim (`plan … changed after the approval prompt showed
it`), so the plan a person approved is the plan that runs. A call that reaches the tool with no
prompt bound to it (another plugin or middleware turned a dry run into an apply after the prompt was
skipped) is refused too (`apply refused: no approval prompt showed this call`). Unattended runs follow your Hermes
approval policy: `approvals.cron_mode` for cron jobs, `approvals.unattended_mode` for webhook and
API-server sessions, and `approvals.single_query_mode` for `hermes -q`, each `deny` unless you set
it to `approve`, which lets an apply through without asking, as YOLO mode and `approvals.mode: off`
do. `write_mode` adds the lock:

| `write_mode` | Who can write | Use it when |
|---|---|---|
| `full` | The model, after asking (and after the approval prompt); and `/librenms`, `hermes librenms` | One trusted user in a direct message, no automation |
| `operator_only` | Only `/librenms` in a session and `hermes librenms` in your own shell. Model calls to apply and rollback are refused with the exact command to relay | Group chats, messaging gateways, cron jobs, webhooks or the API server present, prompt-injection concerns, "a human must cause every write" |
| `read_only` | Nobody. The apply and rollback tools are hidden from the model and refuse if called; `/librenms apply` refuses too | Drift audits, demos, first deployments |

The model can reach a shell through Hermes' terminal tool, so the plugin also blocks a terminal or
code call that runs `hermes librenms apply` or `rollback`, and the same line written to a background
shell's input (`process_manage`), and the CLI refuses those subcommands when it was started from an
agent session, unless `write_mode` is `full` and `require_approval` is off (and never in a run of the
scheduled digest). The secret guard
([above](#safety-model)) holds in every `write_mode`.
Both are heuristics an obfuscated command can evade; the token's role is the hard limit.

Plans persist across every Hermes surface on the same `HERMES_HOME`, so `operator_only` supports
"plan from Signal, apply from the laptop." Refusals (a blocked terminal call included), approval
requests and approval decisions are written to the audit stream.

### Untrusted content

Much of what LibreNMS stores was written by the network, not by its users: syslog from anything that
can reach the collector, SNMP strings (sysDescr, sysLocation, sysContact, ifAlias), LLDP/CDP
neighbour names, eventlog and alert notes, and hostnames found by autodiscovery. The plugin cannot
stop the model from being influenced by that text; it limits what a misled model can do (plans,
review, gates, write modes, approval) and makes every attempt visible (audit). Both skills tell the
model to treat fetched content as data and to report instructions found in it.

The results say so too. Hermes puts its own untrusted-data boundary only around its web, browser
and MCP tools, and a plugin cannot opt in, so a result that returns text from LibreNMS carries
`untrusted_fields`, the keys that hold it (`results`, `result` and `extra` of a query, `librenms` of
status and of an error, which is LibreNMS's answer, the `note` of an empty answer; a plan's `diff`
and `warnings`, dry-run `conflicts`, and the `journal`, `report`, `eventlog`, `failure`,
`auto_rollback_error`, `apply`, `rollback`, `checks` and `steps` of apply, rollback and
`librenms_plans`; for a report, the keys of its rows, summary and scope that hold such text (also
when a page has no row while its summary names rules, devices or sensors), such as
`hostname`, `sysName`, `location`, `purpose`, `port`, `description`, a neighbour's
`remote_hostname`, `remote_port` and `remote_platform`, a VLAN's `name`, a sensor's `descr`, a BGP
peer's `description`, `as_name`, `last_error` and VRF `context`, a log entry's `message`, `type`,
`program`, `tag` and `username`, a login's `user` and `address`, a bill's name, customer id,
reference and `note`, and a candidate's `why`), and before them an `untrusted_notice` telling the
model that this is data, not instructions. The plugin's own keys (`next_step`, `note` on a cut
listing, counts) are not listed.
Refusals and errors are the plugin's own text and carry no marker of their own, but they may quote
LibreNMS: an `error` holds LibreNMS's error message, the refusal of an unknown hostname names the
devices LibreNMS holds whose names come close (autodiscovered ones among them), and a plan's
`errors` may quote LibreNMS's answer. Both skills tell the model that this text is data too.

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
  `approval_requested`, `approval_decided`, the refusals and rejections that never reached
  LibreNMS, and the shell calls the secret guard refused or asked about (`secret_access_refused`,
  `secret_access_requested`). It is rotated at 10 MiB and daily, and rotated files are deleted
  after 90 days or past the newest 100 (`audit_max_mb`, `audit_retention_days`,
  `audit_keep_files`), each deletion recorded as `audit_pruned`.

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
  `register_tool`, `register_hook` (`pre_tool_call` twice: the approval prompt, then the `modify`
  directive that hands its handler what the prompt showed; `pre_llm_call`, `post_approval_response`),
  `register_command`, `register_cli_command`, `register_skill`, `register_automation_blueprint` (the
  digest; a Hermes without it loads the plugin without the digest), `current_cron_execution` (the
  actor's cron run, and the digest's), `get_config`.

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
handlers.py   tool handlers, the write_mode gate, the approval and request hooks, the shell guards
commands.py   /librenms slash command and `hermes librenms` CLI
digest.py     the scheduled digest: its Automation Blueprint, and the guard that keeps its runs read-only
client.py     LibreNMS REST client (transport checks, errors, retries, size caps)
routes.py     the read-route allow-list behind librenms_query
listing.py    librenms_query's where and sort over the rows read
reports/      librenms_report: views (find, devices, ports, port, capacity, neighbours, locate, vlans, alerts, alert_history, health, routing, events, bills), help, shared reads, scope, budgets, units, ranking
redact.py     credential masking, clipping, terminal-safe text
diff.py       value normalisation and field-level diffs
resources/    one module per resource: validate, resolve, diff, execute, verify, revert
planner.py    operations -> plan
executor.py   apply with journal and verification, rollback, eventlog linking
store.py      plan persistence and locks under plugin-data
audit.py      actor capture and the audit.jsonl event stream, its rotation and retention
sinks.py      optional syslog / HTTP forwarding of audit events
timefmt.py    UTC-to-local rendering for plan diffs and journals (Hermes' timezone setting)
settings.py   operator settings, fail-closed
SKILL.md      bundled skill librenms:workflow: the change workflow the model follows
skills/ask/   bundled skill librenms:ask: answering questions, the question-to-call table, follow-ups
examples/     plan payloads, and conversations the tests run
after-install.md  the setup notes `hermes plugins install` prints
```

## License

MIT. See [LICENSE](LICENSE).
