# Architecture

## Goals

1. The agent can change LibreNMS, but every write is preceded by a reviewable diff, and a person
   approves the run (Hermes' approval prompt) or runs it (`operator_only`).
2. A plan runs the same way every time: deterministic order, explicit preconditions, a
   write-ahead journal of inverses, reverse-order rollback. None of it depends on the model
   remembering a step.
3. Every write is verified by reading it back. LibreNMS answers 2xx to writes it ignored or
   truncated, so a status code is never taken as proof.
4. Where LibreNMS offers no way back, the plan says so before anything runs.
5. The plugin stays inside Hermes' documented plugin surface so it survives Hermes upgrades.

Unlike NetBox, LibreNMS's v0 API is a hand-written set of routes with their own body shapes and
quirks, not a generic model API. So the plugin knows its resources explicitly (one module per
resource) and reads through an allow-list of routes. [api-coverage.md](api-coverage.md) maps every
v0 route to what the plugin does with it.

## Modules

| Module | Responsibility | Depends on |
|---|---|---|
| `client` | HTTP: `X-Auth-Token`, envelope unwrapping, typed errors, transport hardening (no redirects, no `.netrc`, byte caps, GET-only retries), path encoding (no segment that decodes to `/`), LibreNMS's clock (`last_date`, the `Date` of its last answer) | `requests` (lazy), `redact` |
| `redact` | Credential masking by key, error-text scrubbing, clipping that counts escapes, `printable()` for terminals and approval prompts, `one_line()` for free text in plans and journals, `visible()` and `for_model()` for what the model reads, the untrusted-data marker (`untrusted()`, `mark_untrusted()`) | none |
| `routes` | The read-route table for `librenms_query`, in LibreNMS's registration order; path normalisation; hostname-to-id resolution and id checks (naming candidates for an unknown hostname); refusal of a `hostname` or `start` parameter a route ignores, a parameter name PHP reads as another, and an object id LibreNMS reads as no filter; `offset` sent as `start` on the logs routes, which refuse `where` and `sort`; MAC and column-list normalisation; how to narrow an answer too large to read | `client`, `redact` |
| `listing` | `librenms_query`'s typed `where` filter and stable `sort` over the rows a route returned: numbers by value (also written as text), text in natural order ignoring case (`gt`/`lt` compare a number with a text as text when both start with a digit), empty values last, a credential key as masked; a key no row has is refused. Its natural order also orders reports | `redact` |
| `reports/context` | `librenms_report`'s shared machinery: `ReportContext` (every GET through the route allow-list, the request budget, 404-as-empty, a memo of listings and of the port names a view names ports from, partial reasons), scope resolution with ambiguity, argument checks, the result envelope, and how LibreNMS decides a sensor's status and ties it to a port | `client`, `routes`, `listing`, `redact`, `settings` |
| `reports/fuzzy` | Ranking what a person calls a device, a site, a group or a port against what LibreNMS holds: whole-term and per-word matches, role abbreviations, exact addresses, a score and a why | `routes`, `redact` |
| `reports/units` | Rates, speeds (and circuit speeds as LibreNMS parses them), percentages and durations with their readable forms; sensor units and readings per class, sizes in bytes; zone-safe times, and server-local times read in `librenms_timezone` | none |
| `reports/find`, `reports/devices`, `reports/ports`, `reports/port`, `reports/neighbours`, `reports/locate`, `reports/vlans`, `reports/alerts`, `reports/health`, `reports/routing` | The views; `reports/ports` also reads port rows and derives what they mean (`facts`: state, speed, utilisation, errors, last change, staleness; whether a device's figures are current) for every view about ports; `reports/__init__` holds their registry and `run` | `reports/context`, `redact` (`alert_entities`) |
| `reports/help` | View `help`: what each view answers, its filters (with what they take, read from the view), sorts, row and summary keys and examples, answered without a LibreNMS call | `reports/context` |
| `diff` | Value normalisation per field kind, equality, change computation, rendering (sensitive values as digests) | none |
| `resources/*` | One module per resource: reads, `state()`, validation, planning, the write requests, verification, rollback; `base` holds the shared create/update/delete logic | `client`, `diff`, `redact` |
| `planner` | Validate operations, apply the gates, hand each operation to its resource, refuse duplicate targets, build the plan document | `resources`, `audit` (environment only) |
| `executor` | Preflight, claims and run locks, per-step precondition, execute, journal, automatic and manual rollback, crash recovery, eventlog linking | `resources`, `store`, `audit` |
| `store` | Atomic `0600` JSON persistence of plans in `0700` directories, the cross-process claim lock, per-plan run locks, retention, the active profile's key | Hermes `plugin_storage`, `hermes_constants` (optional) |
| `audit` | Actor capture from Hermes' session context and the plugin context; the request cache; append-only `audit.jsonl` | Hermes `gateway.session_context` (optional) |
| `sinks` | Optional syslog / HTTP forwarding of audit records on a background thread per Hermes profile; the warning about a credential written into `config.yaml` | `settings`, `store`, Hermes `hermes_cli.config` (optional) |
| `timefmt` | UTC stamps rendered in the Hermes-configured zone for reports only (`HERMES_TIMEZONE`, else the profile's `timezone`, as Hermes resolves it) | Hermes `agent.secret_scope`, `hermes_cli.config` (optional) |
| `settings` | Operator settings with fail-closed coercion (a time zone the host's zone database does not hold is refused) | Hermes `ctx.get_config` (optional) |
| `schemas` | Tool schemas | none |
| `handlers` | Tool handlers, the `write_mode` gate, the hook callbacks, the client factory seam; result shaping (alert rows, envelope extras, keyed objects, a listing's `offset` and `next_offset`) and the result budget, with plans shown a range of steps at a time | everything above |
| `commands` | `/librenms` and `hermes librenms` built on the handlers; the CLI's exit status | `handlers` |
| `__init__` | `register(ctx)` | all |

Dependencies point downward only. The engine (`client`, `redact`, `routes`, `listing`, `reports`, `diff`,
`resources`, `planner`, `executor`, `store`) imports nothing from Hermes at module load; Hermes imports are lazy
and guarded, which is why the whole engine is testable with plain `unittest` against
`tests/fake_librenms.py`.

## Reports

`librenms_report` answers a question in one read-only call where `librenms_query` would hand the
model raw listings to scan and join: LibreNMS's list routes take few filters and no order, rows
carry ids rather than names, and a fleet-wide listing passes Hermes' result threshold at a few
hundred rows. A report reads what it needs, joins and counts in the plugin, and returns a
`summary` and the matching rows.

- **Reads.** Every GET goes through `ReportContext.get`: the path is built from fixed words and
  resolved ids (each a percent-encoded segment, none holding `/`), matched with `routes.match` as a
  `librenms_query` path is (so a refused route is refused here too, before anything is sent), and
  counted against a budget of 30 requests. LibreNMS's 404 for an empty list is no rows; any other
  failure of a read the report cannot do without fails it, and a failed read it can do without
  (one device's outages, a listing `find` ranks) is left out and makes the answer `partial`, with
  the reason. The devices, locations and group listings are read once per report; nothing is kept
  between calls.
- **Scope.** `scope` becomes a set of device ids from one `devices` listing: `device`/`devices`
  add devices, `group` (`devicegroups/{id}`, never `full=1`), `location` (an id, a name, or every
  location whose name holds the text), `os` and `type` narrow; `port_group` (`port_groups/{id}`,
  never `full=1`) names the ports a port view keeps, and the `port` view's `port` one port. A device named by an id or its exact
  hostname is that device. Anything else is ranked (`reports/fuzzy`) and resolves only when one
  device matches exactly (sysName, display name, first label, IP) or only one matches every word of
  the phrase; otherwise the answer is `ambiguous: true` with the candidates and no report, so a
  phrase never quietly widens or picks a scope.
- **Envelope.** `success`, `view`, the untrusted marker (the row and scope keys that hold text from
  LibreNMS), `scope`, `data_as_of` (LibreNMS's `Date`, else the plugin's clock), `timezone`,
  `count`, `returned`, `offset`, `truncated`/`next_offset`, `partial`/`partial_reason`, `summary`,
  `rows`, `notes`. Strings from LibreNMS are clipped to 200 characters (counted as escaped). The
  handler then fits the result to `max_result_chars` as it fits a query's, cutting rows and saying
  where to read on.
- **Time.** Device times are ISO-8601 UTC and outages and port polls unix seconds, so ages are
  exact and are counted to LibreNMS's own clock. A port's last change is sysUpTime in hundredths
  of a second, so its age is the device's uptime less that, plus the time since the poll: unknown
  past 497 days of uptime (the 32-bit counter may have wrapped), and only a lower bound when it is
  0 (unchanged since the SNMP agent started). Fault, alert-log, eventlog and syslog times are server-local
  `Y-m-d H:i:s`, and no API field names the server's zone (`system`'s `local_date` is the date of
  the LibreNMS commit), so `reports/units` reads them only in `librenms_timezone` and otherwise
  gives them no age; `timezone` says which zone a report used. A window (`alert_history`) is
  counted back from LibreNMS's clock and sent as server-local text: exact in `librenms_timezone`,
  and without it from 12 hours earlier still, which holds the window whatever the server's zone
  (UTC-12 to UTC+14) and may hold up to 26 hours more, as the result says (`exact: false`).
- **Views.** `find` ranks devices (names, attributes, management and interface addresses, ARP
  entries for a MAC), ports (an interface name, `ports/search`), locations, device groups and port
  groups, 10 an answer (`count` counts them all), `ambiguous` when the best two score within 10.
  `devices` gives each device's state as LibreNMS's own filters decide it, its open outage (read
  for the down devices of the page, at most 20), uptime and boot time, last poll and the naming
  checks, with counts in `summary`. `ports` reads the port rows of the scope (one device at a
  time up to 10 devices, else one listing, with a column list) and derives what LibreNMS keeps as
  raw counters in mixed units: the state, the speed it is measured against (the circuit speed in
  the description first, egress and ingress apart), bit rates and percentages, errors per poll and
  per second, the age of the last change, whether the figures are current, and whether it has a
  description of its own; `summary` counts states and finds the busiest. `port` adds, for one
  port, its discards, neighbours, transceivers, dBm sensors with their limits and open faults
  (never their details). `capacity` counts each device's physical ethernet ports by state and
  those free (not up and unchanged for `idle_days`). `neighbours` reads the LLDP/CDP links of the
  scope (per device up to 10, else every link) and joins both ends to their port rows through the
  same `read_ports` (the scope's devices first, then the neighbours, when it reads one device at a
  time) and `facts`, so a link's ends carry the state, speed, duplex and MTU the `ports` view
  gives them; it compares the speed the interfaces run at (never a circuit speed), duplex and MTU,
  and whether the local description names the neighbour as a whole word, and leaves a check null
  rather than false when it cannot be made (the neighbour is not monitored, LibreNMS did not match
  its port, an end is not up). What the neighbour advertised (`remote_hostname`, `remote_port`,
  `remote_platform`) is marked untrusted: any device on the wire writes it. `locate` takes an IPv4
  or MAC address: the ports that learned the MAC (`ports/mac`, with LibreNMS's count of the MACs
  each learned), its forwarding entries (VLAN and last update, the MAC sent as the 12 hex digits
  the exact-match route compares), the ARP entries, and the links of the devices that learned it,
  so that an uplink (a port whose monitored neighbour learned the MAC too) is never named the edge
  port, while a port to a monitored hypervisor, access point or server that did not learn it, or
  to the device at the IP looked up, can be. `vlans` lists each device's VLANs and, for one VLAN
  on up to 10 devices, the ports in it from `with=vlans`, untagged when LibreNMS's PortVlan says
  so or the VLAN is the port's own `ifVlan`. `alerts` reads the open faults once (in the states
  `filter.state` names, narrowed at LibreNMS by one severity or a rule's id; one severity at a time
  when the answer is too large to read) and keeps the scope's; what alerted is named from the rows
  the rule matched through `redact.alert_entities`, the allow-list of label keys `librenms_query`
  uses for `entities`, and a port fault without a label from its device's ports. `alert_history`
  reads the rules once and the alert log from the window's start, newest first, in pages (halved
  while an answer is too large to read) up to 2,000 entries, per device for a scope of up to 10;
  it counts alerts raised, cleared and raised again (`flaps`, per fault) per rule, device or
  event. Neither view puts any other part of a fault's or entry's `details` (every column of
  every table the rule joins, and the alert's contacts) in a row or a summary. `health` reads
  `resources/sensors` once (it takes no filter) and keeps the scope's sensors that LibreNMS has not
  deleted; their status is LibreNMS's (`Sensor::scopeIsCritical`/`IsWarning`: strictly past a
  limit; a limit not set never trips; a `state` sensor's meaning is in state translations no read
  route returns, so it is unknown), and the margins are how far the reading is from the first limit
  it would cross each way. When that listing is too large to read, the sensors are read one device
  and one sensor at a time (`devices/{id}/health`, `.../device_<class>`, `.../device_<class>/{id}`)
  within the budget, partial otherwise. Processors, memory pools and storage (the same routes, one
  request each) are read for at most 5 devices, 8 of a kind each. For the page, a sensor is tied to
  a port as the `port` view ties an optic (measured on the port's ifIndex, or on one of its
  transceivers' entities) or, for a dBm sensor, by the port name its description starts with.
  `routing` reads `bgp`, `ospf` and `ospfv3` once each (by device id for one device, `remote_asn`
  for a remote AS) and keeps the scope's; `not_established` is LibreNMS's `BgpPeer::inAlarm` (admin
  `start`/`running` and not established) and an OSPF neighbour not `full`; a BGP session's up or
  down time is its established timer at the last poll plus the time since. LibreNMS's `ospfv3`
  route answers HTTP 500 `Error retrieving ospfv3_nbrs` for no neighbour, read as none (as is the
  404 of a LibreNMS without the route, with a note); any other failure of a protocol leaves it out,
  partial, unless it is the one asked for.
- **Help.** The tool's schema names the views and the contract they share; each view's filters,
  sorts, row keys and examples are view `help`'s (`reports/help`), answered in the handler before a
  client is made. A filter's line says what it takes from the view's own definition, and a test
  holds every view's filters and sorts to a line each in `help` and runs every example. A scope,
  filter or sort key a view does not take is refused, naming those it does and pointing to `help`.

## The plan document

Plans live in `<HERMES_HOME>/plugin-data/librenms/plans/<plan_id>.json` (mode `0600`, directories
`0700`). The id is `lnp-<UTC timestamp>-<4 hex>`, so ids sort chronologically.

```jsonc
{
  "id": "lnp-20261028T190000Z-ab12",
  "version": 1,
  "created_at": "2026-10-28T19:00:00Z",
  "updated_at": "2026-10-28T19:02:11Z",  // every save
  "status": "planned",                   // see the state machine below
  "description": "Move core-sw1 to NYC-2 and patch it",
  "librenms_url": "https://nms.example.com",
  "summary": {"create": 0, "update": 1, "delete": 0, "action": 1, "noop": 0},
  "warnings": [],                        // "[i] <note>" for every step note
  "irreversible": [1],                   // indexes of steps whose inverse kind is "none"
  "requested_by": {"kind": "model", "via": "tool", "...": "..."},   // the actor record, see audit.md
  "audit": {"host": "hermes-01", "os_user": "hermes", "pid": 41233, "python": "3.12.7",
            "plugin_version": "0.1.0", "hermes_version": "0.22.3", "hermes_home": "/home/hermes/.hermes",
            "librenms_version": "26.10.0", "librenms_sha": "91b9a40…", "db_schema": "2026_03_25_… (412)"},
  "steps": [
    {
      "index": 0, "action": "update", "resource": "device", "object_id": 1, "label": "core-sw1.example.net",
      "requested_op": "update", "resolved_by": "match", "parent_id": null, "notes": [],
      "changes": {
        "purpose": {"from": "core", "to": "core-l3"},
        "location_id": {"from": 1, "to": 2, "from_label": "SFO-1", "to_label": "NYC-2"}
      },
      "payload": {"field": ["purpose", "location_id"], "data": ["core-l3", 2]},
      "precondition": {"state": {"device_id": 1, "hostname": "core-sw1.example.net",
                                 "inserted": "2026-10-28T12:00:04.000000Z", "purpose": "core", "location_id": 1,
                                 "override_sysLocation": true, "type": "network", "icon": "", "...": "..."}},
      "inverse_kind": "exact", "inverse_note": ""
    },
    {
      "index": 1, "action": "maintenance", "resource": "device", "object_id": 1, "label": "core-sw1.example.net",
      "requested_op": "maintenance", "resolved_by": "id", "parent_id": null, "notes": [],
      "params": {"duration": "2:00", "start": null, "title": null, "notes": "", "behavior": "skip_alerts"},
      "precondition": {"state": {"...": "..."}},
      "inverse_kind": "none",
      "inverse_note": "LibreNMS API v0 cannot end or delete maintenance; it expires after 2:00. To end it early, …"
    }
  ],
  "journal": [ /* see below */ ],
  "checks": [{"at": "…", "conflicts": [], "actor": {…}}],          // one per dry run
  "apply": {"started_at": "…", "finished_at": "…", "rollback_on_failure": true, "actor": {…},
            "outcome": "applied", "eventlog": {"linked": true, "devices": {"1": [ … ]}}},
  "rollback": {"started_at": "…", "finished_at": "…", "force": false, "reason": "requested", "entries": 1,
               "actor": {…}, "reverted": 1, "conflict": 0, "failed": 0, "irreversible": 0, "skipped": 0,
               "eventlog": {…}}
}
```

`summary.action` counts maintenance, discover, ack and unmute steps. `audit` is the planning
process's environment plus what `GET system` reported (all three `null` when it could not be
read; planning does not fail for it).

### Steps

Every step has `index`, `action`, `resource`, `object_id` (null for a create), `label`,
`requested_op`, `resolved_by` (`id`, `match` or null), `parent_id` (the owning device of a service,
port or alert; null otherwise) and `notes`. The rest depends on the action:

| action | extra fields | precondition at apply |
|---|---|---|
| `create` | `data` (resolved and normalised; SNMP credentials as `{"env": "LIBRENMS_SNMP_…"}`), `exists_check` (the natural key: `hostname`, `location` or `name`; for a service, the `match` only) | no object matches `exists_check` |
| `update` | `changes` (`from`/`to`, optional `from_label`/`to_label`), `payload` (the request body), `precondition.state`, `upsert: true` when a create with `match` found its object | the object exists and its compared state equals `precondition.state` |
| `delete` | `snapshot` (what rollback re-creates from), `precondition.state` | as for update |
| `maintenance`, `discover`, `ack`, `unmute` | `params` (what is sent), `precondition.state` | the object exists and its state is unchanged; an alert also re-checks its sibling faults |
| `noop` | `reason` | none; journaled as `skipped` |

Every step that is not a noop carries `inverse_kind` and `inverse_note`:

| `inverse_kind` | Rollback |
|---|---|
| `exact` | restores the previous values or deletes what was created |
| `lossy` | restores what the API can write; `inverse_note` says what it cannot (a new id, history, a note that stays) |
| `none` | reported `irreversible`; the plan lists the step under `irreversible` and the approval prompt names it |
| `not_needed` | reported `skipped` (a rediscovery only schedules a discovery run) |

Some resources keep more on the step: a service create keeps `expected_ip` (the address LibreNMS
fills in when `ip` is empty) and `max_service_id` (to tell its new row from older ones); an
alert-rule update keeps `snapshot_body` (the full body to `PUT` back) and `extra_unknown_keys`; a
location delete's `snapshot` keeps the `device_ids` that used it, and a location maintenance the
devices it covers; a device-group delete or maintenance keeps `member_count`; an ack or unmute
keeps `precondition.siblings`, the other open faults of the same device and rule.

### Journal entries

The executor appends one entry per step, in order. It is the record rollback works from.

```jsonc
{
  "index": 0, "action": "update", "resource": "device", "object_id": 1, "label": "core-sw1.example.net",
  "parent_id": null, "inverse_kind": "exact",
  "status": "done",                       // running | done | skipped | conflict | failed | unknown
  "at": "2026-10-28T19:01:02Z",
  "inverse": {"action": "update", "object_id": 1, "data": {"purpose": "core", "location_id": 1}},
  "after_state": {"device_id": 1, "purpose": "core-l3", "location_id": 2, "...": "..."},
  "notes": [],
  "requests": [{"method": "GET", "path": "/api/v0/devices/1", "status": 200, "duration_ms": 41},
               {"method": "PATCH", "path": "/api/v0/devices/1", "status": 200, "duration_ms": 77},
               {"method": "GET", "path": "/api/v0/devices/1", "status": 200, "duration_ms": 38}],
  "request": {"method": "PATCH", "path": "/api/v0/devices/1", "status": 200, "duration_ms": 77},
  "eventlog_ids": [7],
  // after a rollback:
  "revert_status": "reverted",            // running | reverted | conflict | failed | irreversible | skipped
  "revert_at": "2026-10-28T19:05:40Z",
  "revert": {"restored_fields": ["location_id", "purpose"]},
  "revert_requests": [ … ], "revert_request": {"method": "PATCH", "…": "…"}, "revert_eventlog_ids": [8]
}
```

- `done` adds `inverse`, `after_state` (the state read back after the write) and `notes`.
- `failed` adds `error`, and `librenms` (the client error: message, status, kind, method, path,
  scrubbed body) when LibreNMS answered. A failure after LibreNMS may have changed something also
  carries the `done` fields and `wrote: true` (see [Failures after a write](#failures-after-a-write)),
  and `settles_at` when its answer was lost.
- `unknown` (a run that died during the write, see below) also carries `settles_at`.
- `conflict` adds `error` (what changed since planning).
- `requests` lists every call the step made, method, path, status and duration only, never a
  body or a query. `request` is the last write among them, else the last read.
- `revert` holds the resource's details: `restored_fields`, `new_object_id` for a re-created
  object, `note`, or `error`. `revert_progress` is what a revert saved before a write it must not
  repeat (`recreating`, or a service's `floor`).
- Labels, notes and errors are free text from LibreNMS or the model; every rendering of a plan or
  journal keeps each on its own line (`redact.one_line` escapes newlines and tabs), so none can pass
  for a step, a summary or a journal line.

## State machine

```
planned ──apply──► applying ──all steps ok──► applied ──rollback──► rolling_back ──► rolled_back
                      │                                                         └──► partially_rolled_back ──rollback──┐
                      └──conflict/failure──► failed ──(auto or manual rollback)──► rolling_back ──► …                  │
                                                                                                                      ▼
applying / rolling_back with the run lock free (the process died) ──rollback (recovery)──► rolling_back    (retry until rolled_back)
```

- `planned -> applying` and every rollback claim happen under the store's cross-process lock,
  `<plans>/.lock`, after re-reading the file, so two applies of one plan cannot both proceed, from
  the gateway and the CLI or anywhere else. A lock held longer than 30 seconds refuses with a retry
  hint.
- A plan applies once. `failed` with nothing written has nothing to revert: no automatic
  rollback runs, the status stays `failed` (a manual rollback marks it `rolled_back` with nothing to
  do), and the plan cannot be applied again; re-plan.
- Rollback accepts `applied`, `failed` and `partially_rolled_back`. It reverts the **pending**
  entries, newest first: those that may have written (`done`, `unknown`, or `wrote: true`) whose
  `revert_status` is not yet `reverted`, `skipped` or `irreversible`. `partially_rolled_back` can be
  rolled back again; only the entries still pending are retried, which is how `force` finishes a
  rollback that stopped on conflicts.
- The final status is computed over the whole journal: `rolled_back` when every entry that may
  have written ended `reverted` or `skipped`; otherwise `partially_rolled_back`. A plan with an
  irreversible step that ran therefore stays `partially_rolled_back`, and a second rollback with
  nothing left to try is refused: `plan <id> has nothing left to roll back; irreversible steps:
  [1]`.

### Write-ahead entries and crash recovery

Before a step's first request the executor appends its entry with `status: "running"` and saves
the plan; it then settles that entry in place. Before a revert it sets `revert_status: "running"`
and saves. A process that dies mid-write therefore leaves a file that says which step may have
written. A revert that re-creates a deleted object also saves its progress first, through the
executor's `checkpoint`, into the entry's `revert_progress`: `recreating: true`, or for a service
the newest service id on the device (`floor`) before its `POST`.

Each apply or rollback holds the plan's **run lock**, an exclusive non-blocking `flock` on
`<plans>/<id>.run`, from the claim to its last save. The lock dies with the process, so a plan in
`applying` or `rolling_back` whose run lock is free belongs to a run that died. Rollback recovers
it, inside the store lock:

1. emits `run_recovered` with `previous_status` and `dangling_indexes`, and records the same under
   `rollback.recovered`;
2. turns every `status: running` entry into `status: unknown, wrote: true` with `settles_at` ten
   minutes after its `at` (LibreNMS may still be running the request the dead run sent), and every
   `revert_status: running` back into null (that revert is tried again, keeping its
   `revert_progress`);
3. rolls back as usual, with `unknown` entries pending.

A revert tried again resumes rather than repeats. A re-create that finds `recreating` adopts the
object the dead run made instead of reporting "exists again": a location of that name with the
snapshot's coordinates, a device group or alert rule of that name (verified against the snapshot),
or the one service above `floor` with the snapshot's type and name. An update revert counts a field
already back at its previous value as restored, so a revert whose write landed before the run died
finishes instead of reporting a conflict.

A resource reverts an `unknown` entry by looking before it acts, using the plan step, since a dead
run journaled no inverse:

| step | rollback of an `unknown` entry |
|---|---|
| create | find by `exists_check`: none → `reverted` ("nothing was written") once `settles_at` has passed; one that matches the planned data → deleted; anything else → `conflict` |
| update | re-read: every changed field holds its planned or its plan-time value → the ones at the planned value are restored (none: `reverted`, "nothing was written", once `settles_at` has passed); any other value → `conflict` (`force` restores the previous values) |
| delete, maintenance, ack, unmute | `failed`: "outcome of this step is unknown (the process died during the write); check <resource> <label> in LibreNMS" |
| discover | `skipped`, as always |

While the run lock is held, rollback refuses: `plan <id> is still being applied by another process;
try again when it finishes`. Retention (`prune`) never removes a plan that is in flight or whose
run lock is held.

## Guarantees and how they are enforced

| Guarantee | Enforcement |
|---|---|
| A plan applies at most once | `planned -> applying` is flipped under `<plans>/.lock` after re-reading the file; a second claim finds `applying` or later and is refused (`refusing to apply twice`) |
| Only against the LibreNMS it was built for | The plan records `librenms_url`; apply and rollback refuse when `LIBRENMS_URL` now names another base URL |
| Only while fresh | Apply refuses a plan older than `max_plan_age_hours` (default 24) |
| Only while the operator's gates allow it | `allow_delete`, `allow_device_add` (device creates, and updates that change `hostname` or `overwrite_ip`) and `allow_services` are checked when planning and again for every step when applying |
| One run at a time | Under the store lock, apply and rollback refuse while another plan's run lock is held, whatever its status says (a failed apply holds it through its automatic rollback): two runs writing the same objects would trip over each other's preconditions. A refused claim drops the run lock it took before it lets go of the store lock |
| Nothing runs against an object that changed | Each step's `check()` re-reads the object and compares it with `precondition.state` before the write; a conflict stops the run like an error |
| Every write is verified | After each write the resource re-reads the object and compares the written fields with what was sent; a mismatch is a failure with the inverse journaled |
| Everything that may have been written can be rolled back | Write-ahead entries, `PartialWrite`, `unknown` entries (above) |
| Rollback never clobbers a later edit | Each revert compares the object with the `after_state` journaled at apply; a difference is a `conflict` unless `force` |
| Rollback stays possible after a gate is closed | Rollback (manual, automatic and recovery) never asks `allow_delete`, `allow_device_add` or `allow_services`; only `write_mode` and the approval prompt apply |
| No secret is persisted that need not be | SNMP credentials are env references resolved inside the step; error text is scrubbed of the token and the step's sensitive values; tool results and audit events are masked (see [audit.md](audit.md)) |

## Comparing state without `last_updated`

NetBox gives every object a `last_updated` stamp, and the NetBox plugin compared that. LibreNMS
has no modification stamp, ETag or version on any object the API writes. So every resource
defines `state()`: the owned, writable, non-secret fields plus the identity, normalised so that two
reads of an unchanged object compare equal. The plan stores it as `precondition.state`; the
executor's check and rollback compare fresh `state()` reads with it, field by field.

Normalisation (`diff.normalise`, per `Field.kind`): integers from ints or digit strings; booleans
from `true`/`false`, `0`/`1` and their string forms; text with `null` read as `""`; floats rounded
to 8 decimals; id lists sorted and de-duplicated; JSON values (alert-rule builders, group rules)
parsed and compared canonically. Poller data, such as uptime, status and counters, is never in
`state()`.

Comparison rules:

- Identity is always compared: the id, and for a device its `hostname` and `inserted` stamp, so a
  device renamed or re-created in between is not mistaken for the planned one.
- **Volatile fields** are values LibreNMS itself may rewrite: a device's `type` and `icon`
  (discovery), its `location_id` while `override_sysLocation` is off (the poller re-assigns it from
  SNMP `sysLocation` on every poll), a location's geocoder `timestamp`. They are compared only
  when the step writes them, so routine polling does not make every plan conflict. A device update
  that sets a location requires `override_sysLocation: true` for the same reason.
- A conflict names each field that moved: `device #12 changed since planning (purpose: "edge" ->
  "core")`. Sensitive values (a service's `param`) render as `<redacted sha256:1a2b3c4d>`, enough
  to see that a secret changed and not enough to recover it.
- Some resources check more: a location delete re-reads which devices use it, and an
  acknowledgement or unmute re-reads the other open faults of the same device and rule, when it
  is applied and when it is rolled back (LibreNMS acknowledges or unmutes them together when the
  rule does not notify per entity). Whether it does is decided as LibreNMS's `AlertUtil` decides
  it: open faults not in state 0 against `max(1, max_entities)`. A rule without `max_entities`
  falls back to a server setting the API cannot read (20 by default), so with more than one such
  fault it is planned as not notifying per entity, with a note. A rollback whose rule changed its
  per-entity behaviour, or found a fault opened or changed since the apply, is a conflict.

The check is read-then-write, not atomic: LibreNMS has no conditional write, so a change landing
between the check and the write is not detected for that step. The window is one request.
Rollback's own comparison against `after_state` closes the equivalent window on the way back.

## Failures after a write

A step can fail after LibreNMS changed something: a timeout on the response, a 500 thrown after
the row was saved, a 2xx whose body the client cannot read, a verification that finds the value
LibreNMS stored differs from the one sent (truncation, a silently ignored field). The base
resource counts the write requests a step sends and settles every failure:

- **Before any write was sent**, or the first write was refused with a 4xx: the error propagates
  unchanged and the entry is plain `failed`. Nothing to roll back.
- **After a write may have happened**: the resource re-reads (a create looks the object up by its
  `exists_check`; an update or delete reads the object and compares it with
  `precondition.state`).
  - Something changed, or the re-read itself failed: it raises `PartialWrite(message, entry)`. The
    executor journals the entry as `failed` with `wrote: true`, `inverse`, `after_state` (null when
    unknown) and `notes`, and rollback reverts it like a `done` entry. A create whose new id could
    not be told carries `inverse: {"action": "delete", "object_id": null, "find": <exists_check>}`,
    and rollback looks it up again before deleting.
  - Nothing changed yet, but the answer was lost (a timeout or a reset after the request was sent)
    or came from a gateway (502, 503, 504): LibreNMS may still be running the request, and a
    device add that probes SNMP credentials outlasts a proxy's timeout. The re-read proves nothing,
    so this is a `PartialWrite` too, with `after_state: null`, a note that the outcome is unknown,
    and `settles_at` ten minutes on.
  - Nothing changed and LibreNMS answered (a 5xx of its own), or the request never reached it (the
    connection was refused, the name did not resolve): the original error, as a plain `failed`.

Rollback always looks before it acts on such an entry: a create it cannot find, an update whose
fields hold their previous values, a delete whose object is still there. Before the entry's
`settles_at` that look proves nothing either, so the revert is `failed` ("nothing was created so
far, but LibreNMS may still be carrying out the write (its answer was lost); roll back again after
<time> to look again"), the entry stays pending and the plan `partially_rolled_back`. This is what
the automatic rollback straight after the failure usually reports. A rollback after `settles_at`
that finds the write not carried out settles it (`reverted`, "nothing was created"); one that
finds it landed meanwhile undoes it.

The error text in the journal and the audit stream passes through `redact.scrub_text` with the
token and the step's sensitive values (resolved SNMP credentials, old and new service parameters).
A LibreNMS 5xx whose body carries SQL (`SQLSTATE`, `SQL:`) or is not LibreNMS's error envelope is
reported as `LibreNMS server error (details withheld; see the LibreNMS log)`. An unexpected
exception becomes `unexpected error err-<id> (<class>); see the Hermes log`, with the traceback in
the log under that id.

## The approval hook

With `require_approval: true` (the default) and `write_mode: full`, the plugin's `pre_tool_call`
hook sends every `librenms_apply` that is not a dry run, and every `librenms_rollback`, to Hermes'
human approval gate (`{"action": "approve", "message", "rule_key"}`). Hermes shows the prompt in
the CLI, TUI and desktop, or as a pending `/approve` on the gateway; a denial, a timeout, or no
human to ask blocks the call.

- **Message**: built for the little of it Hermes shows: 9 rows of 64 columns in the CLI panel
  (which offers no way to see more of it), 300 characters on Discord, 500 on Slack and Telegram, at
  most 1,500 from the plugin. First one header line,
  `Apply <id>: <n> create, <n> update, <n> delete, <n> action; irreversible steps: [<idx>] | none;
  rollback_on_failure=<bool>` (zero counts left out), or `Roll back <id>: <n> pending entries`, with
  `, FORCE: overwrites edits made after the apply` for a forced rollback. Then one line per step,
  `[<i>] <action> <resource> #<id> "<label>"` with ` (irreversible)` and the names of the fields it
  sets (an update's changes, a create's data, an action's arguments), deletes and irreversible steps
  first and no-ops left out; for a rollback one line per pending entry in the order it is reverted,
  saying what reverting it does (`restore <fields>`, `delete it`, `re-create it (new id)`, `cannot be
  undone`). Only when every step line fit come, while room remains, the field-level diff (`  [<i>]
  <detail>`, with the rollback note of a lossy or irreversible step), the warnings and last the
  model's description (`Description: <text>`); for a rollback, the journal. The message ends with
  `Full plan: /librenms show <id>`, or `… N more lines; full plan: /librenms show <id>` when lines
  were left out. Every line is escaped and kept to one line with `one_line()` and cut to 120
  characters, a label to 40, so no text from LibreNMS or the model can pass for a step or take the
  room the steps need; a line that does not fit is left out and counted, not the lines after it.
- **Rule key**: `librenms:librenms_apply:<id>:rb|norb` and
  `librenms:librenms_rollback:<id>:force|safe`. An "always" or "session" answer therefore covers that
  plan with that choice only.
- **Exact ids only**: the hook and the `librenms_apply` / `librenms_rollback` handlers take a plan's
  full id, never a fragment. A `plan_id` that names no saved plan, or only the end of one (the
  refusal names the plan), or several, is blocked with the handler's own refusal
  (`{"action": "block", "message"}`) rather than put to a person: the handler would refuse it, and a
  fragment resolved again after the prompt could name a plan created while it was open. The block is
  audited as `apply_refused` or `rollback_refused` with `tool` set to the write tool.
- **Dry runs** skip approval only when `dry_run` is true by the same parser the handler uses
  (`handlers.parse_bool`), so a string like `"false"` cannot slip a real apply past the prompt.
- **Failure**: the hook never raises (Hermes blocks any tool call whose hook raises). On any internal
  error it blocks the call with `<action> refused: the plan could not be loaded for the approval
  prompt (err-<id>)`, audited like an unknown plan.
- **Terminal**: a `terminal` or `execute_code` call, or a `process_manage` `write` or `submit` whose
  `data` goes to the input of a shell `terminal(background=true)` started, is blocked when its text
  holds `librenms apply` or `librenms rollback` with the word `hermes` before it in the same command
  (no newline, `;`, `|` or `&` in between; global options allowed), unless `write_mode` is `full` and
  `require_approval` is off. The match takes linear time, so a long line of `hermes` words (a JSON
  list of `~/.hermes` paths) cannot stall the agent loop. It is never approved. The message says what
  the model may do under the `write_mode` in force: in `full`, call the tool, which asks the user; in
  `operator_only`, ask the user to run `/librenms <action> <id>` or `hermes librenms <action> <id>`
  from their own terminal; in `read_only`, that writes are disabled and queries and plans still work.
  The block is audited as `apply_refused` or `rollback_refused` with `reason: "blocked in the agent's
  terminal/execute_code"`, `tool`, `write_mode` and the plan id it names, never the command text.
- **Other tools**: the hook returns immediately, without I/O, for every other tool.
- Every `approve` the hook returns is audited as `approval_requested` (tool, plan id, rule key), and
  `post_approval_response` records the decision as `approval_decided` (choice, tool, plan id).
  Hermes decides some requests without a person and without `post_approval_response`, so a request
  with no decision after it shows one passed or blocked by policy.

The prompt is Hermes' gate under the user's approval policy: YOLO mode, `approvals.mode: off`, an
earlier "always" for the same key, `approvals.cron_mode: approve` (cron jobs),
`approvals.unattended_mode: approve` (webhook and API-server sessions) and
`approvals.single_query_mode: approve` (`hermes -q`) all pass it without asking. `operator_only` is
the setting the plugin controls, and the one to use on a profile that serves unattended platforms.

## Write modes

| | `full` | `operator_only` | `read_only` |
|---|---|---|---|
| `librenms_query`, `librenms_plans`, `librenms_plan` | yes | yes | yes |
| `librenms_apply` with `dry_run` | yes | yes | tool hidden; `/librenms check <id>` |
| `librenms_apply`, `librenms_rollback` (the model) | yes, through the approval prompt when `require_approval` | refused, with the exact `/librenms apply <id>` and `hermes librenms apply <id>` commands to relay | hidden and refused |
| `/librenms apply`, `/librenms rollback` | yes | yes | refused |
| `hermes librenms apply`, `rollback` | yes; from a shell an agent session started, only when `require_approval` is off | yes, but not from a shell an agent session started | refused |
| `terminal` / `execute_code` / `process_manage` input running `hermes librenms apply\|rollback` | blocked unless `require_approval` is off | blocked | blocked |

"A shell an agent session started" is detected by `HERMES_SESSION_ID` or `HERMES_SESSION_KEY` in
the environment, which Hermes binds into its terminal tool's children. Every refusal is audited
(`apply_refused`, `rollback_refused`), the terminal block included. Settings are read live from `config.yaml` on every call, so
switching to `read_only` takes effect on the next call without a restart.

## LibreNMS eventlog linking

LibreNMS records many changes in its eventlog (a device added, renamed or moved to another
location; a port description cleared ...), as the token's user. With `link_eventlog: true` (the
default) the plugin attaches those rows to the plan, so the journal and LibreNMS's own record point
at each other:

1. **Baseline.** When a run starts, for each device its steps touch (a device step's object, the
   owning device of a service, port or alert step), the newest event id from
   `GET logs/eventlog/{device_id}?sortorder=DESC&limit=50`. LibreNMS orders the log by time alone,
   so the newest id is the largest of the latest rows. A device the plan creates has baseline 0.
2. **Link.** After the steps (or reverts), for each device an entry wrote to,
   `GET logs/eventlog/{device_id}?from=<baseline+1>&sortorder=ASC&limit=200`. A numeric `from`
   compares event ids, so no clock or time zone is involved; rows at or below the baseline are
   dropped even when a LibreNMS ignores `from`.
3. **Record.** `apply.eventlog` (or `rollback.eventlog`) is `{"linked": true, "devices": {"<id>":
   [{"event_id", "datetime", "type", "message"}]}}` with messages clipped to 300 characters as
   escaped (what the model reads of them; the text stays as LibreNMS wrote it), and each
   journal entry of that device gets `eventlog_ids` (rollback: `revert_eventlog_ids`). LibreNMS does
   not say which request wrote a row, so every entry about a device gets all of that device's rows
   for the run, which may include rows the poller or a person wrote in the same minutes.

A failure is recorded as `{"linked": false, "error", "status"}` and audited; it never fails the
run. Rollback takes its own baseline when it starts. The cost is two reads per device per phase.

Writes the plugin makes are also tagged where LibreNMS keeps text: a maintenance schedule's title
starts with `[hermes:<plan id>]`, an acknowledgement note with `[hermes:<plan id>]`, and the unmute a
rollback sends says `[hermes:<plan id>] rollback`. Every request carries
`User-Agent: hermes-plugin-librenms/<version>`, so LibreNMS's web server logs attribute the traffic.

## Steps run in order, one request at a time

Steps run sequentially in the order given. Two create, update or delete operations on the same
object are refused when planning (`operations [i] and [j] both target device #12; combine them into
one operation`): each is checked against the state seen before either ran, so the second would
always conflict. Actions (maintenance, discover, ack, unmute) do not write the object's state and
may follow an update of the same object. Bulk routes are not used: one request per object keeps the
journal exact and the rollback granular.

Only GETs are retried: twice when the connection fails (refused, DNS, connect timeout) or LibreNMS
answers 502, 503 or 504, and once after a 429, honouring `Retry-After` up to 5 s. A TLS failure or
a read timeout is not retried. A write is never retried: a timeout may mean it happened, and that is
for the re-read to settle, not a second request.

## Hermes integration

- `register(ctx)` performs no network I/O and does not touch `ctx.manifest` or `ctx.state`;
  Plugin Doctor blocks sockets during registration and this plugin passes. It logs each
  `Settings.errors` entry once.
- Tools are registered with `requires_env` and a `check_fn`, so they are hidden from the model when
  `LIBRENMS_URL` / `LIBRENMS_TOKEN` are missing; `librenms_apply` and `librenms_rollback` are also
  hidden while `write_mode` is `read_only`.
- Under Hermes' tool search (`tools.tool_search.enabled`, `auto` by default) every plugin tool is
  deferred: the model's tool list holds `tool_search`, `tool_describe` and `tool_call`, and a catalog
  line per deferred tool, the first sentence of its description cut at 60 characters. Each
  description therefore opens with a sentence of at most 60 characters ending in a period that says
  what the tool answers or does, and ends saying to invoke the tools through `tool_call` when they
  are deferred. Hermes unwraps `tool_call` before `pre_tool_call`, so the approval hook sees
  `librenms_apply` either way.
- The `librenms:workflow` skill is registered without `requires_toolsets` or `requires_tools`: Hermes
  checks those against the tools the model sees directly, so under tool search such a gate left the
  skill out of the system prompt. It is offered whenever the plugin is enabled, so also in a session
  where the `librenms` toolset is turned off for the platform (`hermes tools`) or the task, and says
  what to do when the tools are deferred or missing. A catalog listing in groups, or no listing at
  all, does not name each tool, so the skill counts the tools missing only when `tool_describe` and
  `tool_search` do not find them (or there is no `tool_search`). It then names both causes for the
  user, `LIBRENMS_URL` / `LIBRENMS_TOKEN` unset for the profile or the toolset turned off, and tells
  the model not to reach LibreNMS another way.
- Handlers follow the contract `handler(args, **kwargs) -> str` and never raise; an unexpected
  exception becomes an error id, with the detail in the log.
- Hermes wraps the results of its web, browser and MCP tools in an `<untrusted_tool_result>` block
  (`agent/tool_dispatch_helpers.py`, chosen by tool name) and offers a plugin no way into it, so the
  results mark themselves, and stay JSON, which Hermes' error preview and the operator paths parse.
  `redact.mark_untrusted` puts `untrusted_fields` (the keys holding text from LibreNMS) and
  `untrusted_notice` (that it is data, not instructions) before the first of those keys: a query's
  `results`, `result`, `extra` or empty-answer `note`, status's `librenms`, and the `diff`,
  `warnings`, `checks`, `conflicts`, `failure`, `eventlog`, `apply`, `rollback`, `journal`,
  `report`, `auto_rollback_error` and `steps` of the plan tools, and an error's `librenms`
  (LibreNMS's answer). Refusals and the plan listing carry none, and the `error` of a refusal or an
  error, like a plan's `errors`, may quote LibreNMS (its message, candidate hostnames) unmarked: the
  skill tells the model that this is data too. The serialiser escapes every string of every result
  with `redact.visible` (a CR LF read as a newline, then `printable()`), so no bidirectional
  control, invisible character or C0/C1 control reaches the model raw whatever key it is under.
  `redact.clip` and `redact.cut` count a character as long as its escape, so every limit on text
  from LibreNMS (`for_model`'s, an alert entity's, a linked eventlog row's, the text of an error)
  bounds what the model reads, though the text stays raw where it is kept. A report reuses all of
  this: its `untrusted_fields` names the label keys of its rows and scope.
- A result for the model stays within `max_result_chars` (default 60,000 characters). Hermes saves
  a larger one to a file and shows the model a 1,500-character preview of it (past 100,000
  characters, or 15% of the context window on a smaller model), and `register_tool` offers a plugin
  no per-tool threshold. A listing keeps as many leading rows as fit and says so (`returned`,
  `truncated`, `next_offset` at the first row left out, counted in the budget, and a `note` naming
  `fields` and that offset; none when the first row does not fit on its own, whose offset the note
  names); a single object that does not fit is refused with the same advice. A plan, its journal, and the results of
  `librenms_plan`, `librenms_plans`, `librenms_apply` and `librenms_rollback` are cut by steps:
  each shows the steps from `offset` on that fit (at least one), the diff, warnings, irreversible
  step indexes, conflicts, journal and eventlog rows of those steps, and `next_offset` for
  `librenms_plans` to show the rest; the diff's last line says which steps it shows. A page that
  leaves irreversible steps out says how many there are (`irreversible_count`), and
  `librenms_plans` shows the latest of a plan's dry-run checks, one recorded per dry run
  (`check_count`). The operator paths (`/librenms`, `hermes librenms`) are not cut.
- Hooks (`pre_tool_call`, `pre_llm_call`, `post_approval_response`) are registered unconditionally
  and declared in `provides_hooks`. `pre_llm_call` remembers the user's message per session for the
  actor record ([audit.md](audit.md)).
- The plan store and the audit file follow the active Hermes profile: `plugins.plugin_storage.
  plugin_data_dir` when available, with a `$HERMES_HOME/plugin-data/librenms` fallback, resolved on
  every use.
- Secrets are read through Hermes' per-profile secret scope (`agent.secret_scope.get_secret`) when
  it exists, else from the environment. A profile with no scope bound fails the call rather than
  reading another profile's value.
- With `plugins.isolation: host`, Hermes skips CLI command registration inside the host, so
  `hermes librenms` is unavailable there; `/librenms` and the tools still work.
- Hermes exits with the int a CLI handler returns. `hermes librenms` returns 0 when the command did
  what it says, 1 when it failed, was refused, found its plan no longer applicable, could not reach
  LibreNMS (`status`) or named no single plan, and 2 on a usage error, printing anything but 0 on
  stderr. Apply and rollback take the handler's `success`, so an apply that failed and was rolled
  back, or a rollback that left conflicts, is 1.
- Status never fails as a whole: when LibreNMS cannot be configured or reached, `connection` says why
  (`ok: false`, the scrubbed error and its kind), `librenms` is null, and the plugin version, write
  mode, settings, settings errors and warnings are still there (the tool result keeps `success:
  false`).
- Private Hermes imports: `hermes plugins validate` names two, both lazy and guarded, which have no
  public equivalent: `gateway.session_context.get_session_env` (the actor's user and chat fields)
  and `hermes_cli.__version__` (the Hermes version each plan records; the package metadata version
  is stale on a git install). The display zone is resolved from public modules (`agent.secret_scope`,
  `hermes_cli.config`), as `hermes_time` resolves it.

## Audit

Actor records, the event stream and the plan's audit fields are described in
[audit.md](audit.md); forwarding to syslog or HTTP in [sinks.md](sinks.md). The executor saves the
plan before it emits each event, so the stream never claims more than the plan file records; an
audit write failure is logged and never fails the operation.

## Non-goals

- A free-form write tool. Every write is a planned operation of a known resource.
- Changing SNMP settings or credentials of an existing device: API v0 cannot. Adding a device takes
  credentials only as environment references.
- Ending or deleting maintenance: API v0 cannot. Maintenance steps are irreversible by design and
  say so in the plan.
- Alert transports, operations and templates, bills, components, device dependencies, port
  groups, BGP descriptions, eventlog and syslog injection: not in 0.1.0
  ([api-coverage.md](api-coverage.md) has the reason for each).
- Reading stored device configurations (Oxidized). They hold every secret a device has.
- Bulk routes, async apply or parallel steps.
- Scoping reads by device or group. The token's LibreNMS role decides what it can read.
