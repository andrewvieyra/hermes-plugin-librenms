# Audit trail

Every plan, apply and rollback is recorded twice: inside the plan file, and as a stream of events in
`audit.jsonl`. The plan file is state that changes as the plan progresses. The stream is append-only
and is what a SIEM or log shipper should read. Refusals are recorded too: a plan that failed
validation, an apply or rollback that was refused (also when the agent's terminal tried to run the
CLI), a query the route allow-list refused, a shell call refused for reading the plugin's secrets, a
delegation refused in a run of the scheduled digest, and every approval the plugin asked Hermes for.

All timestamps are UTC in ISO 8601 with a `Z` suffix. Neither output contains the LibreNMS token
or an SNMP credential: credentials reach LibreNMS from the environment at apply time and are
never written down, and every audit record passes through the same key-based masking as tool
results before it is written or forwarded.

## Where

| Output | Location | Setting |
|---|---|---|
| Plan files | `<HERMES_HOME>/plugin-data/librenms/plans/<plan_id>.json` | `plan_retention_days` (default 90; `0` keeps them forever), applied at most hourly per profile when the plugin is used; `hermes librenms prune` from cron for a strict policy |
| Event stream | `<HERMES_HOME>/plugin-data/librenms/audit.jsonl` | `audit_log` (on/off), `audit_log_path` (absolute path override; a relative one is a settings error and the default is used), `audit_include_request`; rotation and retention: `audit_max_mb` (default 10), `audit_keep_files` (default 100), `audit_retention_days` (default 90), [below](#rotation-and-retention) |

`<HERMES_HOME>` is the active Hermes profile's home, resolved for every event, so a gateway that
serves several profiles writes each profile's events to its own file.

Set `audit_log_path` to a location your collector already watches, for example
`/var/log/hermes/librenms-audit.jsonl` (`~` is expanded). The writer opens the file with `O_APPEND`
for every event and writes each line with a single `write`, so several Hermes processes (the
gateway and `hermes librenms`) can append to the same file; they rotate it under a shared lock
([below](#rotation-and-retention)). A file the plugin creates is `0600`, and directories it creates are `0700`;
an existing directory keeps its mode, except `plugin-data/librenms` itself, which Hermes creates
under the process umask and the plugin narrows to `0700` (a log shipper should read a file at
`audit_log_path` instead). The file is never opened through a symlink, and an event is written to
it only when it is a regular file owned by the account Hermes runs as whose only name is the log's:
in a directory another account can write to, a symbolic or hard link or a file planted at the
log's name would otherwise receive the users' messages, and any account may hard-link a file it can
reach, a shell's rc file among them. The name is looked up again after the open, so a link removed
in between is caught too, and a rotation that renames the file at that moment has the event written
to the new one. An event the file refuses still reaches the sinks, and Hermes' log says why the
file was skipped.
Lines are UTF-8 JSON; a lone surrogate (which UTF-8 cannot encode) is replaced with U+FFFD rather
than losing the event. A failed write is logged to Hermes' log and never fails the operation it
describes.

`audit_log: false` stops the file and the [sinks](sinks.md) alike: events are forwarded from the
same call that writes them. Plan files are always written; they are how apply and rollback work.

## Rotation and retention

Each event can carry the user's message (`request`), so the stream is kept no longer than you say,
like the plan files:

| Setting | Default | Meaning |
|---|---|---|
| `audit_max_mb` | `10` | Before an event would take the file past this many MiB (1,048,576 bytes each), the file is rotated (at most 10240). `0`: never by size |
| `audit_keep_files` | `100` | Rotated files kept, newest first; older ones are deleted (at most 10000). `0`: any number |
| `audit_retention_days` | `90` | Rotated files whose newest event is older than this are deleted (at most 3650). While it is on, the file is also rotated at the first event or sweep of each new UTC day, so each file holds one day's events, and they are deleted together, 90 to 91 days after they were written (at the first rotation or sweep past that). `0`: kept forever |

A value that cannot be read (`30d`, `-1`, `false`, `0.5`) is the default and a settings error in
`/librenms status`, never "keep forever"; only `0` turns a limit off, and a value above the limit is
lowered to it. The settings are read for every event, like the others.

**Rotating** renames the file to `<name>.<UTC time of its newest event>` in the same directory
(`audit.jsonl.20261029T235959Z`; `-2`, `-3` and so on for more rotations within that second, so
the names sort in the order the files were rotated) and starts a new file at the log's name with
the old file's mode and group, as logrotate's `create` does: `0600` for a file the plugin made, and
a shipper that reads a file you made `0640` for its group keeps reading, as long as the new file can
have that group. Only root can give a file a group its owner is not in, so either make the account
Hermes runs as a member of the group, or give the directory that group (`chgrp splunkfwd
/var/log/hermes`, and on Linux `chmod g+s` so new files take the directory's group, as they always
do on BSD and macOS). Otherwise the new file has the directory's or the account's group, and what
the old file let only its group read is not passed on to that group: a `0640` file is followed by a
`0600` one, the shipper can no longer read it, and Hermes' log says so (once per process). ACLs on
the old file are not copied. The new file is created with `O_EXCL` and never through a symlink. Only
a log that passes the writer's own checks (a regular file this account owns, with no other hard
link) is rotated. Log shippers that follow a file across a rename (Filebeat, Fluent Bit, Vector, the
Splunk forwarder) read every line once.

**Retention** deletes the rotated files past the newest `audit_keep_files` and those whose newest
event is older than `audit_retention_days`. It counts and deletes only names of the form above
that are regular files this account owns with no other hard link; anything else in the directory
(logrotate's `audit.jsonl.1`, a compressed copy, a symbolic or hard link or another account's file
planted at such a name) is neither counted nor touched. It runs after each rotation, at most hourly
per profile when the plugin is used (with the plans' retention: a plan made or listed, status, any
`/librenms` or `hermes librenms` command), and on `hermes librenms prune` (`--days` concerns plans
only). The hourly sweep also rotates a file whose events are of an earlier day, so a log nobody
writes to ages out too; a profile nobody uses at all is swept when someone next does, so for a
strict policy run `hermes librenms prune` from cron. Each deletion is recorded as an
`audit_pruned` event naming the files, in the new file and at the sinks. Retention applies whether
or not `audit_log` is on: turning the log off writes no new event, and what was written still ages
out (with no `audit_pruned` record, since the log is off).

`prune --dry-run` changes nothing and lists what the sweep would delete now: the rotated files, and
the live file itself when it is due and would be deleted as soon as it is rotated (`audit.jsonl
(would be rotated to audit.jsonl.20260702T000542Z and removed)`, a log last written more than
`audit_retention_days` ago); the rotation it would do counts toward `audit_keep_files` as well. When
retention cannot run, or runs only in part (a file it cannot rotate or delete), `prune` says so
(`Audit log: retention could not run: cannot open the lock file (Permission denied); see Hermes'
log.`), never "no rotated file to remove", and exits 1, so a cron job notices.

**Several processes** write the same file. Each writer of the plugin, in every process, takes an
exclusive `flock` on `<name>.lock` (next to the log; it stays empty) before it opens the log, and
keeps it until its line is written; rotation and retention happen only under it. So no rotation
falls between a writer's open and its write, no event is written to a file after it was rotated
(where retention could delete it), and no two processes rotate at once (two renames to the same
name would replace the first rotated file): every event is written whole, once, to the file that
was the log when it was written. A writer waits up to two seconds for the lock; past that the event
is written without it and the file is not rotated until a later event takes the lock (Hermes' log
says so). Where the lock cannot be used, because the platform has no `flock` (Windows), the lock
file cannot be created (a directory this account cannot write to, such as a root-owned
`/var/log/hermes` holding a file made for the account) or is not a regular file this account owns,
events are written as before and nothing is rotated or deleted: Hermes' log says why, once per
process, `hermes librenms prune` says retention could not run and exits 1, and `/librenms status`
warns that the audit log can be neither rotated nor pruned (also when the lock works but the
directory does not let the account rename the log). Give the account a directory it can write to,
or turn the plugin's rotation off and rotate the file another way (below). With every limit at `0`
no lock is taken.

On disk the log takes at most about (`audit_keep_files` + 1) × `audit_max_mb`, 1,010 MiB at the
defaults; a day of ordinary use writes far less than 10 MiB, so it is usually one small file per day
for 90 days. While `audit_retention_days` is on, each active day starts a file, so an
`audit_keep_files` below `audit_retention_days` keeps only about as many days; `/librenms status`
warns about it.

### Rotating with logrotate instead

To let the system's logrotate manage a file at `audit_log_path`, turn the plugin's rotation off
(`audit_max_mb: 0`, `audit_keep_files: 0`, `audit_retention_days: 0`) and rotate by renaming, which
loses no line because the plugin opens the file by name for every event:

```
/var/log/hermes/librenms-audit.jsonl {
    su hermes hermes
    daily
    rotate 90
    maxage 90
    dateext
    missingok
    notifempty
    create 0600 hermes hermes
}
```

With `compress`, add `delaycompress`, so the file just renamed is not compressed while a line may
still be on its way to it. `copytruncate` works too (each line is a single `write` at the end of the
file) but loses the lines written between its copy and its truncate. Do not combine logrotate and the
plugin's own rotation on one file: they do not share a lock.

## The actor record

Attached to every event and stored in the plan under `requested_by`, `apply.actor`,
`rollback.actor` and each dry run's `checks[].actor`. Keys are always present, in this order;
unknown values are `null`, so field mappings stay stable.

| Field | Meaning |
|---|---|
| `kind` | `model` when the model called a tool, `operator` when a human used `/librenms` or `hermes librenms` |
| `via` | `tool`, `slash` or `cli` |
| `surface` | Where the session runs, as Hermes' plugin context reports it (`ctx.session_surface()`): `cli`, `tui`, `desktop` or `acp` locally, the platform name in a chat |
| `platform` | Gateway platform: `signal`, `telegram`, `discord`, `slack`, `cli`, … |
| `source` | Hermes session source (`gateway`, `cli`, `tui`, `desktop`, `api_server`, …) |
| `profile` | Hermes profile, when multiplexing (`ctx.profile_name`, else the session's) |
| `chat_id`, `chat_name`, `chat_type`, `parent_chat_id`, `thread_id`, `scope_id` | Where the conversation happened; `chat_type` is `dm`, `group`, `channel` or `thread` |
| `user_id`, `user_id_alt`, `user_name` | The platform user who sent the message (`user_id_alt` is the platform's stable alternate id, such as a Signal UUID) |
| `message_id` | The triggering message, where the platform exposes one |
| `session_key`, `session_id`, `ui_session_id`, `task_id` | Hermes session identifiers, for joining with Hermes' own logs; `task_id` is set for tool calls |
| `cron` | `true` when the turn ran inside a Hermes cron job |
| `cron_job_id`, `cron_execution_id` | The cron job and run, when `cron` is true and Hermes reports them |
| `os_user` | The OS account the Hermes gateway or CLI runs as. Not the person who asked |
| `sender_id` | The gateway's id for the sender of the turn, remembered with the request (below) |
| `request` | The user's message that led to the call, masked and truncated to 500 characters; `null` when `audit_include_request` is off, for operators, and when no message was remembered |

Identity comes from Hermes' per-session context, which the gateway binds for every turn, and from
the plugin context (`surface`, `profile`, the cron run), which also works when plugins run in a
separate host process. For `/librenms` the gateway's record of who sent the command wins over the
session variables. In a plain CLI session most platform fields are `null` and `os_user` is the
meaningful identity.

Plans belong to the profile, so the model of any of its sessions (another user of a shared gateway)
can read one with `librenms_plans`. There each actor (`apply.actor`, `rollback.actor`,
`checks[].actor`) is shown in a public form: `kind`, `via`, `surface`, `platform`, `source`,
`profile`, `chat_type`, `cron`, `cron_job_id`, and `by`, the phrase the diff's `Created:` line and
the journal's `Applied:` and `Rolled back:` lines show ("model via tool on signal for Andrew in dm
Andrew"). The phrase names the user and the chat by display name only. Hermes fills a name in with
the id when the platform has none (an SMS number, a Signal user without a profile name), so a name
that is one of the actor's ids, holds one or is part of one is left out: such a user is "an
unnamed user" and such a chat goes by its type alone ("model via tool on signal for an unnamed user
in dm"). `request`, `sender_id`, the user, chat and message ids and the session ids are kept in the
plan file and the event stream only.

### The request text

Hermes does not pass the user's message to a tool. The plugin's `pre_llm_call` hook remembers it
for each session and task, and a tool call of that session looks it up (a delegated task, which has
its own task id, gets the latest message of its session). The cache holds the last 256 turns of
the process. What it keeps:

- the text only: a multimodal message's text parts are joined, images are skipped;
- with credential shapes masked as `<redacted>`: private key blocks, `Authorization:` values,
  values after `token`, `password`, `passwd`, `secret`, `community`, `authpass`, `cryptopass` or
  `psk` and `:` or `=`, a URL's user and password, LibreNMS API tokens (`<id>|<secret>` and the
  older 32-hex-digit form, so an MD5 sum in the message is masked too), and the configured token;
- at most 500 characters;
- nothing at all while `audit_include_request` is off.

Masking is pattern-based: a password typed as plain prose ("the community is hunter2") is not
recognised. Turn `audit_include_request` off where users paste credentials into chat.

## The config digest

Every event carries `config_digest`: the first 12 hex digits of the SHA-256 of the settings in
force, as canonical JSON, with `audit_sinks` reduced to their count and types (a sink's URL and
headers can hold a credential). The same settings give the same digest in every process, so a
collector can alert on any digest you have not approved, and two events with different digests ran
under different configurations. A setting added in a later release (`max_result_chars` in 0.1.3,
`librenms_timezone` in 0.4.0, `audit_max_mb`, `audit_keep_files` and `audit_retention_days` in
0.12.0) counts only once it differs from its default, so upgrading does not change the digest of a
configuration. `/librenms status` shows the settings behind the digest.

## The plan file

Besides the actor records, each plan carries an `audit` block written at planning time:

```json
"audit": {
  "host": "hermes-01",
  "os_user": "hermes",
  "pid": 41233,
  "python": "3.12.7",
  "plugin_version": "0.1.0",
  "hermes_version": "0.22.3",
  "hermes_home": "/home/hermes/.hermes",
  "librenms_version": "26.10.0",
  "librenms_sha": "91b9a40b4cc42b27a06f3289a38b053ca6320218",
  "db_schema": "2026_03_25_120000_add_ssl_certificate_permissions (412)"
}
```

and every journal entry records the calls it made, method, path, status and duration, never a
body or a query string:

```json
"requests": [
  {"method": "GET", "path": "/api/v0/devices/12", "status": 200, "duration_ms": 41},
  {"method": "PATCH", "path": "/api/v0/devices/12", "status": 200, "duration_ms": 77},
  {"method": "GET", "path": "/api/v0/devices/12", "status": 200, "duration_ms": 38}
],
"request": {"method": "PATCH", "path": "/api/v0/devices/12", "status": 200, "duration_ms": 77}
```

`request` is the step's last write (else its last read). A reverted entry adds `revert_requests`
and `revert_request` for the inverse. A failed entry carries `error` and, when LibreNMS answered,
`librenms`: the message, HTTP status, error kind, method, path and the response body with the token
scrubbed and 5xx debug details (exception, file, line, trace) removed. See
[architecture.md](architecture.md) for the rest of the plan and journal.

Plan files hold object data as LibreNMS returned it, with SNMP credentials masked. A service's
check parameters (`param`) are kept, because rollback must be able to restore them; they can hold a
password. Treat the `plugin-data` directory with the same care as the token.

## LibreNMS's eventlog

After every apply and rollback the plugin reads LibreNMS's eventlog for each device the run wrote
to, from the newest event id it saw before the run, and attaches the new rows:

```json
"eventlog_ids": [8123, 8124]
```

on each journal entry about that device (`revert_eventlog_ids` for a rollback), and under
`apply.eventlog` / `rollback.eventlog`:

```json
{"linked": true, "devices": {"12": [{"event_id": 8123, "datetime": "2026-10-28 12:00:08", "type": "system",
                                      "message": "Location: SFO-1 -> NYC-2"}]}}
```

or `{"linked": false, "error": …, "status": 403}` when the token cannot read the log. `datetime` is
LibreNMS's own, in the LibreNMS server's time zone. The lookup costs two reads per device per
phase, never fails the operation, and can be turned off with `link_eventlog: false`. How rows are
matched, and why a row can belong to someone else's change in the same minutes, is in
[architecture.md](architecture.md#librenms-eventlog-linking).

Other places the plugin's writes can be found from LibreNMS's side:

- a maintenance schedule's title starts with `[hermes:<plan id>]` (Alerts → Scheduled Maintenance);
- an acknowledgement note starts with `[hermes:<plan id>]`, and the unmute a rollback sends says
  `[hermes:<plan id>] rollback`;
- every request carries `User-Agent: hermes-plugin-librenms/<version>`, so the web server's access
  log attributes the traffic; the journal's `request.path` and time locate each call there;
- LibreNMS attributes eventlog rows and acknowledgements to the user that owns the token, which is
  why a dedicated user is recommended ([SECURITY.md](../SECURITY.md)).

## Events

One JSON object per line. Common fields on every event:

| Field | Meaning |
|---|---|
| `ts` | UTC timestamp |
| `schema` | Event schema version, currently `1` |
| `plugin` | `librenms` |
| `event` | Event name, below |
| `plan_id` | The plan, or `null` for a rejected plan, a query, pruning, or an unknown id |
| `librenms_url` | The LibreNMS instance, or `null` when not known |
| `config_digest` | The settings in force (above) |
| `actor` | The actor record |
| `host`, `pid` | Where the event was produced |

Step and revert events identify their object with `index`, `action`, `resource`, `object_id` and
`label` (the "object fields" below); a create learns its `object_id` when it runs.

| Event | When | Extra fields |
|---|---|---|
| `plan_created` | A plan was built and saved | `description`, `summary`, `steps` and `warnings` (counts), `irreversible` (step indexes) |
| `plan_rejected` | Operations failed validation, a gate or resolution, or the plan was asked for in a run of the scheduled digest, which is read-only; nothing saved | `description` (cut to 200 characters), `operations`, `errors`, `first_error` (cut to 500; in a digest run `plan refused: this run is the LibreNMS network digest, ...`, with `errors` 1) |
| `plan_checked` | A dry run re-verified the preconditions | `conflicts` (count), `applicable` |
| `query_refused` | `librenms_query` refused a path or its parameters before sending anything, or `librenms_report` refused a report: its scope names no device, group, location, port group or port LibreNMS holds, or a read would leave the route allow-list | `path` (its first 200 characters; for a report the path it refused, else `null`), `reason` (cut to 500); a report's also `tool` (`librenms_report`) and `view` |
| `apply_refused` | Apply was refused: unknown id (or not a full one), wrong status, stale plan, another LibreNMS, a gate, a second apply, a run in progress, the lock held, `write_mode`, the CLI started from an agent session, `hermes librenms apply` blocked in the agent's `terminal`, `execute_code` or `process_manage` input, a `plan_id` the approval hook blocked before asking (it named no saved plan, the plan could not be loaded, or its file holds another plan's `id`), a call that is not the one the approval prompt showed (another plan or `rollback_on_failure`), a model's call that no approval prompt showed while `require_approval` is on (a dry run turned into an apply after the hook), a plan that changed after the approval prompt showed it, or any apply (a dry run too) in a run of the scheduled digest, which is read-only | `reason`, `dry_run`, `write_mode` when that was the cause; `approved_digest` (the plan's content digest the prompt showed) and `digest` (the one found under the claim) when the plan changed after the prompt. The terminal block: `reason` `blocked in the agent's terminal/execute_code`, `tool` (`terminal`, `execute_code` or `process_manage`), `write_mode`; `plan_id` is the plan the command named (the canonical id when it resolves, else the id as written, or `null`), never the command text. The approval hook's block: `tool` (`librenms_apply`), `reason`, `plan_id` `null`. In a digest run: `reason` `apply refused: this run is the LibreNMS network digest, ...` (also for the terminal block, in place of its usual reason), `plan_id` the saved plan the call named (else `null`), with `tool` when `pre_tool_call` blocked it and `dry_run` when the handler did; the actor's `cron_job_id` and `cron_execution_id` name the job and the run |
| `approval_requested` | The plugin asked Hermes' approval prompt about `librenms_apply` or `librenms_rollback` (`require_approval` in `full` mode). Hermes may pass or block it by policy (YOLO, `approvals.mode: off`, an earlier "always", `approvals.cron_mode`, `approvals.unattended_mode`, `approvals.single_query_mode`) without asking anyone, and then no `approval_decided` follows | `tool`, `plan_id`, `rule_key`, `digest` (the plan's content digest, also the rule key's last part: the plan as the prompt showed it). A `plan_id` that names no saved plan is never asked about: it is blocked, as `apply_refused` or `rollback_refused` |
| `approval_decided` | Hermes' approval prompt for `librenms_apply` or `librenms_rollback`, or for a shell call the secret guard asked about, was answered | `choice` (`once`, `session`, `always`, `deny`, `timeout`, `cancelled`), `tool`, `plan_id` when it could be read, `rule_key` and `digest`, the plan content the answer covers (`null` for a key of 0.10.x or earlier), or Hermes' `pattern_key` for a command that mentions librenms, `decided_by` and `surface` as Hermes reports them. For a shell call: `tool` (`terminal`, `execute_code` or `process_manage`), `rule`, `rule_key` and `digest` (of the call's text, which the answer covers), `plan_id` `null`. Never the command text |
| `secret_access_refused` | A `terminal` or `execute_code` call, or a `process_manage` write or submit to a background shell, was blocked: it read one of the plugin's secrets by name, or called the LibreNMS API with a token. Every `write_mode` | `tool`; `rule`: `secret_variable` (a read of `LIBRENMS_TOKEN`, `LIBRENMS_PROXY`, an SNMP credential (`LIBRENMS_SNMP_*`), `LIBRENMS_AUDIT_SINK_SECRET`, or another `LIBRENMS_` name holding `TOKEN`, `SECRET`, `PASS` or `KEY`) or `librenms_api` (an `Authorization: Bearer` or `X-Auth-Token` header or `api_token` with `/api/v0`, `LIBRENMS_URL`, the configured LibreNMS host, or `/api/v1` beside the word librenms); `variables`, the names it read (upper-cased, at most ten). `plan_id` and `librenms_url` are `null`. Never the command text |
| `secret_access_requested` | The secret guard put such a call to Hermes' approval prompt: it reads a Hermes `.env` file (`env_file`: named, or reached by a dotfile glob or a recursive search of a Hermes home or profile), or prints the whole environment while this process's environment holds one of the plugin's secrets (`environment`). As for `approval_requested`, Hermes may pass or block it by policy without asking, and then no `approval_decided` follows | `tool`, `rule`, `variables` (for `environment`, the secrets the environment holds), `rule_key` (`librenms:secret:<tool>:<rule>:<digest of the call's text>`, so an "always" covers that exact text only). Never the command text |
| `delegation_refused` | In a run of the scheduled digest, a tool that hands work to another agent was blocked (`delegate_task`, `cronjob_manage`, `a2a_call`, `a2a_orchestrate`, a `kanban_*` tool): the subagent, cron run, A2A peer or kanban worker it would start is not the digest run, so the write tools would not refuse there | `tool` (the tool's name), `reason` (`<tool> refused: this run is the LibreNMS network digest, ...`); `plan_id` and `librenms_url` are `null`; the actor's `cron_job_id` and `cron_execution_id` name the job and the run. Never the goal, prompt, message or task the call carried |
| `apply_started` | Plan claimed and execution begins | `steps`, `summary`, `rollback_on_failure` |
| `step_done` | One step's write succeeded and was verified | object fields, `status`, `http_status`, `request` |
| `step_skipped` | A `noop` step | object fields, `status` |
| `step_conflict` | The object changed since planning; the run stops | object fields, `status`, `error` |
| `step_failed` | LibreNMS rejected the write, verification failed, or the request failed; the run stops | object fields, `status`, `error`, `http_status`, `request`, and `wrote: true` when LibreNMS may have applied part of the step |
| `eventlog_linked` | LibreNMS eventlog lookup after an apply or rollback | `phase`, `linked`, `devices`, `events` (counts); or `linked: false`, `error`, `http_status` |
| `apply_finished` | Outcome of the run | `outcome` (`applied` or `failed`), `status`, `done`, and on failure `failed_step`, `failure_kind` (`conflict` or `error`), `error` |
| `rollback_refused` | Rollback was refused: unknown id (or not a full one), wrong status, another LibreNMS, nothing left to roll back, a run in progress, the lock held, `write_mode`, the CLI started from an agent session, `hermes librenms rollback` blocked in the agent's `terminal`, `execute_code` or `process_manage` input, a `plan_id` the approval hook blocked before asking, a call that is not the one the approval prompt showed (another plan or `force`), a model's call that no approval prompt showed while `require_approval` is on, a plan whose journal, run records or content changed after the approval prompt showed it, or any rollback in a run of the scheduled digest | `reason`, `force`, `write_mode` when that was the cause; `automatic: true` and `pending` when the automatic rollback after a failed apply was the one refused; the terminal block, the approval hook's block, a plan that changed (`approved_digest`, `digest`) and a digest run (`force` in place of `dry_run`) as for `apply_refused` |
| `run_recovered` | A rollback found the plan left `applying` or `rolling_back` by a process that died | `previous_status`, `dangling_indexes` (entries that were in flight) |
| `rollback_started` | Reverting begins, newest entry first | `entries`, `force`, `reason` (`requested`, or `automatic after failure at step N`) |
| `revert_reverted`, `revert_conflict`, `revert_failed`, `revert_irreversible`, `revert_skipped` | Outcome of one inverse. A write whose answer was lost and that LibreNMS shows no trace of yet is `revert_failed` until ten minutes have passed (it may still land), with an `error` that says when to roll back again | object fields, `status`, `error`, `new_object_id` (a re-created object), `http_status`, `request` |
| `rollback_finished` | Outcome of the rollback | `status` (`rolled_back` or `partially_rolled_back`), `reverted`, `conflict`, `failed`, `irreversible`, `skipped`, `force`, `reason` |
| `plans_pruned` | Retention removed plan files (`plan_id` is null) | `max_age_days`, `count`, `plan_ids` |
| `audit_pruned` | Retention removed rotated audit log files (`plan_id` is null); `actor` is whoever's call set it off | `max_age_days`, `keep_files`, `count`, `files` (names in the log's directory) |

`summary` counts `create`, `update`, `delete`, `action` (maintenance, discover, ack, unmute) and
`noop`. `request` is `{"method", "path", "status", "duration_ms"}`.

Every string in an event, at any depth, is cut to 2,000 characters; a longer one ends
`… [truncated N chars]`. Text the model writes is cut shorter where it is recorded (above). A
padded description or path therefore cannot make an event that a collector truncates into broken
JSON, or one too large to send over UDP (see [sinks.md](sinks.md) for how a UDP message is fitted).

A complete successful lifecycle emits `plan_created`, (`approval_requested`, `approval_decided`,)
`apply_started`, one `step_*` per step, `eventlog_linked`, `apply_finished`. A failure adds `step_failed` or
`step_conflict` and an `apply_finished` with `outcome: failed`, then, when automatic rollback is on
and something was written, `rollback_started`, one `revert_*` per entry that wrote,
`eventlog_linked` and `rollback_finished`. A step with no inverse (maintenance, a device delete)
reverts as `revert_irreversible`, which leaves the plan `partially_rolled_back`.

## Examples

A step, from a model in a Signal DM:

```json
{"ts":"2026-10-28T19:01:02Z","schema":1,"plugin":"librenms","event":"step_done","plan_id":"lnp-20261028T190000Z-ab12","librenms_url":"https://nms.example.com","config_digest":"4f590a27174c","actor":{"kind":"model","via":"tool","surface":"signal","platform":"signal","source":"gateway","profile":null,"chat_id":"+15550001111","chat_name":"Andrew","chat_type":"dm","parent_chat_id":null,"thread_id":null,"scope_id":null,"user_id":"+15550001111","user_id_alt":"9b1c…","user_name":"Andrew","message_id":"1793214062","session_key":"signal:dm:+15550001111","session_id":"7c0e…","ui_session_id":null,"task_id":"7c0e…","cron":false,"cron_job_id":null,"cron_execution_id":null,"os_user":"hermes","sender_id":"+15550001111","request":"Move core-sw1 to NYC-2 and put it in maintenance for two hours"},"host":"hermes-01","pid":41233,"index":0,"action":"update","resource":"device","object_id":1,"label":"core-sw1.example.net","status":"done","http_status":200,"request":{"method":"PATCH","path":"/api/v0/devices/1","status":200,"duration_ms":77}}
```

A refusal in `operator_only` mode (actor shortened):

```json
{"ts":"2026-10-28T19:00:40Z","schema":1,"plugin":"librenms","event":"apply_refused","plan_id":"lnp-20261028T190000Z-ab12","librenms_url":"https://nms.example.com","config_digest":"0d9e2c61a7b3","actor":{"kind":"model","via":"tool","…":"…"},"host":"hermes-01","pid":41233,"reason":"write_mode is operator_only: …","dry_run":false,"write_mode":"operator_only"}
```

A revert that could not be undone:

```json
{"ts":"2026-10-28T19:05:41Z","schema":1,"plugin":"librenms","event":"revert_irreversible","plan_id":"lnp-20261028T190000Z-ab12","librenms_url":"https://nms.example.com","config_digest":"4f590a27174c","actor":{"kind":"operator","via":"cli","…":"…"},"host":"hermes-01","pid":51877,"index":1,"action":"maintenance","resource":"device","object_id":1,"label":"core-sw1.example.net","status":"irreversible","error":null,"new_object_id":null,"http_status":null,"request":null}
```

## Ingestion notes

- To push events instead of tailing the file, configure `audit_sinks` (syslog or HTTP). See
  [sinks.md](sinks.md).
- The stream is newline-delimited JSON. Point Filebeat, Fluent Bit, Vector or the Splunk forwarder
  at the file with a JSON codec; every line is a self-contained record.
- Map `ts` to your timestamp field (`@timestamp` in Elastic).
- The file is rotated by renaming it ([above](#rotation-and-retention)): watch the log's own name,
  not a pattern that also matches the rotated files (`audit.jsonl.*`), or a shipper that does not
  follow renames reads them twice.
- Useful searches:
  - `event:apply_started AND actor.kind:model AND actor.chat_type:group`: a model wrote to
    LibreNMS from a group chat;
  - `event:apply_refused OR event:rollback_refused OR event:query_refused`: attempts that were
    stopped;
  - `event:secret_access_refused`: the model tried to read the plugin's secrets from a shell or to
    call LibreNMS's API past the plugin; look for injected text in what it read just before
    (`rule:librenms_api` most of all; in CEF the rule is `flexString2` and the tool
    `flexString1`);
  - `event:secret_access_requested` with no `approval_decided` for the same `rule_key` after it: a
    `.env` read or environment dump Hermes passed or blocked without asking anyone;
  - `event:step_failed OR event:revert_failed OR event:revert_conflict OR event:run_recovered`:
    needs a human;
  - `event:revert_irreversible`: something stayed in LibreNMS after a rollback (a maintenance
    window, a deleted device);
  - `actor.cron:true AND event:apply_*`: unattended writes;
  - `actor.cron:true AND (event:plan_rejected OR event:apply_refused OR event:rollback_refused OR
    event:delegation_refused) AND reason:"*network digest*"` (`first_error` for `plan_rejected`): a run
    of the scheduled digest tried to change something, or to hand the work to another agent, which it
    never does on its own; read what its reports returned just before for injected text
    (`actor.cron_execution_id` is the run, `hermes cron runs` its record);
  - `event:approval_requested` with no `approval_decided` for the same `rule_key` after it: an
    apply or rollback Hermes passed or blocked without asking anyone (cron, a webhook or the API
    server, `hermes -q`, YOLO or approvals off);
  - `event:approval_decided AND (choice:session OR choice:always)`: approvals that will not be
    asked again for that plan while its content stays as it was (`digest`);
  - `event:apply_refused AND approved_digest:*` (or `rollback_refused`): a plan file that changed
    between the approval prompt and the run; find who wrote to `plugin-data`;
  - `config_digest` not in the set you approved: the configuration changed;
  - `event:audit_pruned`: local audit files deleted by retention; the collector's copy is the record.
- Join with LibreNMS's eventlog on `eventlog_ids`, and with its web server's access log on
  `request.path`, the time and the plugin's User-Agent.
