# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.4] - 2026-10-29

### Fixed
- `hermes librenms` exits with a status a script can test: 0 when the command did what it says, 1 when it failed,
  was refused or named no single plan, 2 on a usage error, and anything but 0 is printed on stderr. It exited 0
  every time, so `hermes librenms apply <id> && ...` went on after an apply that failed and was rolled back, an
  unknown plan id, a refusal under `read_only` or from an agent's shell, or `LIBRENMS_*` unset. Apply and rollback
  take the handler's `success` (an apply rolled back after a failure, or a rollback that left conflicts, is 1);
  `check` fails when the plan is no longer applicable, `status` when LibreNMS cannot be reached, and
  `hermes librenms` alone prints the help as a usage error. `hermes librenms --help` lists the statuses.
- Status (`librenms_query {"action": "status"}`, `/librenms status`, `hermes librenms status`) shows the plugin
  version, write mode, settings, settings errors and warnings also when LibreNMS cannot be configured or reached,
  with the reason under `connection` (`ok`, `error`, `kind`) and `librenms` null; the tool result still fails. The
  whole report was that one error, so a mistyped `write_mode: fulll`, read as `read_only`, stayed out of sight
  until the connection was fixed, and then apply was refused.
- One plan file without an `id` or a `status` (hand-edited, or damaged) no longer fails `librenms_plans` and
  `/librenms plans` with a `KeyError`, which hid every plan from the listing used to find one to roll back. Each
  plan is listed under the name of its file, which `show`, `apply` and `rollback` go by; a missing or malformed
  status reads `unknown`, which is also the status the filter finds it by (`hermes librenms plans unknown`,
  `librenms_plans` with `"status": "unknown"`), and a creation stamp that is not text is shown as it is.
- Under Hermes' default tool search (`tools.tool_search.enabled: auto`), which defers every plugin tool behind
  `tool_search`, `tool_describe` and `tool_call`, the `librenms:workflow` skill was left out of the system prompt:
  its `requires_toolsets: [librenms]` gate is checked against the tools the model sees directly. The skill is now
  registered without a gate (and `SKILL.md` without `requires_tools`), so it is offered whenever the plugin is
  enabled; it says how to reach deferred tools through `tool_call`. Since that includes sessions where the
  `librenms` toolset is turned off for the platform or task, it counts the tools missing only when
  `tool_describe` and `tool_search` cannot find them, and then has the model tell the user both causes:
  `LIBRENMS_URL` and `LIBRENMS_TOKEN` unset for the profile, or the toolset turned off (`hermes tools`).

### Changed
- Every tool description opens with a sentence of at most 60 characters that says what the tool answers or does,
  because that sentence, cut at 60 characters, is all Hermes' deferred catalog shows the model: `librenms_query`
  read "Read from LibreNMS through its v0 API (GET only, an…", which names no device, port or alert. It now reads
  "Look up LibreNMS devices, ports, alerts, sensors and logs." Each description ends saying to invoke the tools
  through `tool_call` when Hermes has deferred them.
- Report times find the display zone as Hermes does (`HERMES_TIMEZONE`, except in a process serving several
  profiles, else the profile's `timezone` setting) through Hermes' public `agent.secret_scope` and
  `hermes_cli.config` instead of the private `hermes_time`. The two private imports left,
  `gateway.session_context.get_session_env` and `hermes_cli.__version__`, have no public equivalent;
  CONTRIBUTING.md says why they stay.

### Added
- Tests: the CLI's exit status and output stream for every subcommand; status with LibreNMS unconfigured and
  unreachable; a damaged plan file among good ones, and found by the `unknown` status; the display zone with and
  without Hermes, and against `hermes_time` itself; the skill naming both reasons the tools can be missing; and
  through Hermes' real loader under the default tool search, that the tools are deferred, their catalog lines are
  whole, the skill is offered, and an apply sent through `tool_call` still meets the approval hook.

## [0.1.3] - 2026-10-29

### Security
- A `params` name that PHP reads as another name is refused. PHP drops leading spaces and keeps the last of two
  names it reads alike, so `{"limit": 5, " limit": -1}` on a log route reached LibreNMS as `limit=-1`, no limit at
  all, past the clamp that keeps it positive: the whole syslog table was serialised. Likewise `hostname[]` and
  `hostname[0]` reach LibreNMS as `hostname` (an array), which skipped both the device check and the refusal of a
  `hostname` a route ignores, and returned every device's rows. Names with a space, a dot or a `[`, and `hostname`,
  `limit`, `start`, `sortorder` and `columns` in another letter case, are refused before anything is sent.
- `faults/0`, `faults/-1`, `alerts/0`, `rules/0`, `alert_templates/0`, `bills/<not a number>`,
  `port_security/port/0`, `devices/{hostname}/health/{type}/0` and `poller_group/0` are refused: LibreNMS filters
  by those ids only when they are set and positive (or numeric, for bills; PHP's `empty()` reads `"0"` as absent),
  so each answered with every object, under a path that names one. `poller_group/0` named `core-pollers` for a
  device in the General group (0, the default). MySQL also reads `rules/1abc` as rule 1, so the port, bill,
  network and sensor ids (`ports/{portid}` and its sub-paths, `bills/{bill_id}/...`,
  `resources/ip/networks/{id}/ip`, `.../health/{type}/{sensor_id}`, `.../wireless/{type}/{sensor_id}`) must be
  positive whole numbers too; poller group names stay allowed.
- Fault and alert-log rows no longer carry the alert engine's `details`: every column of every table the rule joins,
  for every matched row, and the alert's contacts (e-mail addresses and names). They carry `entities` instead, the
  labels of what alerted (`ifName`, `ifAlias`, `sensor_descr`, `processor_descr`, `bgpPeerDescr` and the like; at
  most 10, 200 characters each). `fields: ["details"]` returns the blob, without its contacts.

### Fixed
- `resources/fdb/{mac}` and `resources/nac/{mac}` compare the MAC with the 12 hex digits LibreNMS stores, exactly,
  so `00:11:22:33:44:55` was never found and the empty answer read as "not on the network". A MAC in any usual form
  (colons, dashes, Cisco dots, single-digit groups, also when that makes it 12 characters long, as
  `0:0:c:7:ac:1`) is now sent as those digits; anything else is refused (`0` listed the whole table).
- A `columns` list with a blank after a comma (`"port_id, ifName"`) is trimmed. LibreNMS checks trimmed names but
  selects them as sent, which failed in SQL as an opaque HTTP 500. The `{field}` list of
  `ports/search/{field}/{search}` is trimmed alike; names other than letters, digits and `_` are refused.
- Envelope extras are returned under `extra`: `resources/fdb/{mac}/detail` answers with the MAC's vendor
  (`mac_oui`) beside the rows, which was dropped.
- `devices/{hostname}/components` answers an object keyed by component id; it is returned as rows carrying the id,
  so `limit` and `fields` apply (`fields` matched the ids, and gave `{}`).
- An answer too large to read (16 MiB) says what narrows that route. The advice named `limit`, which LibreNMS
  applies only on the log routes; elsewhere the plugin applies it after every row is read, so following it failed
  alike. It now names `params.columns` (ports), `type`/`query` (devices), `params.hostname`, or the per-device path
  (`devices/<hostname>/ports`, `.../fdb`, `.../health`), and says that `limit` does not help there.

### Added
- `max_result_chars` (default 60,000, 8,000 to 90,000): every result for the model stays within it. Hermes replaces
  a result over its threshold (100,000 characters, 15% of the context window on a smaller model) with a
  1,500-character preview of one long line, so 50 devices were already over it on a 64K-token model and a 100-step
  plan's diff could not be shown before approval. A listing keeps the first rows that fit and says so (`returned`,
  `truncated`, a `note` naming `fields`, or the next `start` on a log route); a single object that does not fit is
  refused with the same advice; planning errors, conflicts and the plan listing are cut alike. The operator paths
  (`/librenms`, `hermes librenms`) are never cut.
- Plans are shown a range of steps at a time when a whole one does not fit: `librenms_plan`, `librenms_plans`,
  `librenms_apply` and `librenms_rollback` show the diff, warnings, irreversible steps, checks, journal and eventlog
  rows of the steps from `offset` on that fit, and `next_offset`; the diff's last line says which steps it shows.
  When some irreversible steps fall outside the page, `irreversible_count` says how many there are in all and
  `next_step` gives that count rather than every index. `librenms_plans` takes `offset` and `detail`, and shows the
  model the latest dry-run check (`check_count` says how many were recorded).
- An unknown hostname is refused naming up to five hostnames (or display names) that contain its first label, so
  `core-sw1` finds `core-sw1.example.net`.
- Tests: the fake LibreNMS answers the routes the report views will read (`ports`, `ports/search`, `ports/mac`,
  links, sensors, transceivers, components, BGP, OSPF, syslog, the alert log, FDB and NAC, ARP, VLANs, outages,
  availability, bills, port groups and the legacy `alerts` aliases) as their LibreNMS handlers do. Every read
  route's result key is checked against a table taken from LibreNMS's handlers, and every allow-listed route is
  read end to end: a key that drifted made a result null while the tool reported success.

### Changed
- `librenms_plan` no longer returns `steps`, which repeated the diff's content (`librenms_plans` with `detail`
  has them). `librenms_plans` with a `plan_id` returns the journal in summary, as apply does; `detail: true` adds
  the steps and the full journal entries.
- The configuration digest counts a setting added after 0.1.0 only once it differs from its default, so the digest
  of an unchanged configuration is the same after the upgrade.

## [0.1.2] - 2026-10-29

### Security
- The approval prompt shows the steps where Hermes cuts it. Hermes' CLI panel shows 9 rows of 64 columns of the
  message, Discord 300 characters, Slack and Telegram 500, and the message spent them on a long header and the
  rendered plan's Plan/LibreNMS/Created lines: a person approved a two-step plan seeing one field of the first step
  in the CLI and no step at all on Discord. It now opens with one header line (plan id, counts, irreversible steps,
  `rollback_on_failure` or `FORCE`), then one line per step naming the object and the fields it sets, deletes and
  irreversible steps first and marked; the field-level diff, the warnings and the description follow while room
  remains, and the message ends with `/librenms show <id>`. A rollback prompt lists each pending entry and what
  reverting it does. Every line is cut to 120 characters and a label to 40, and a line that does not fit is left
  out and counted instead of ending the message: a 255-character location name (one the model chose, or one
  LibreNMS took from a device's `sysLocation`) escaped to 1,530 characters had hidden a delete after it.
- A `plan_id` that names no saved plan is blocked by the approval hook, with the handler's refusal, instead of
  being put to a person as an "unknown" change. The handler resolved the text again after the answer, so a plan
  created while the prompt was open (by another session, a subagent, cron or the CLI) ran without anyone seeing it:
  `lnp-2` matches every plan id of the year. `librenms_apply` and `librenms_rollback` now take only a plan's full id;
  a fragment is refused, naming the plan it ends. A failure to load the plan blocks too. Both are audited as
  `apply_refused` / `rollback_refused` with `tool` set to the write tool.
- `librenms_plans` returns each actor of a plan (`apply`, `rollback`, `checks[]`) in a public form: how and where it
  acted and the phrase the diff and the journal show. Plans belong to the profile, so another user's session on a
  shared gateway read the message someone else typed to start an apply (a password in prose included) and their
  sender id. The plan file and the audit stream keep the whole record.
- That phrase (`Created: … by`, `Applied: … by`, `Rolled back: … by`) names the user and the chat by display name
  only. It fell back to the user, sender and chat ids, so a Signal user without a profile name showed as their
  phone number in every session of the profile. Hermes also fills a name in with the id where a platform has none
  (SMS, Signal), so a name that is one of the actor's ids, holds one or is part of one is left out too. Such a
  user is "an unnamed user", and such a chat goes by its type alone.
- The terminal guard also reads what `process_manage` writes or submits to the input of a shell
  `terminal(background=true)` started, which no Hermes guard sees: `hermes librenms apply` sent there ran as an
  operator, past the approval prompt and `operator_only`, without any obfuscation.
- The terminal guard's match takes linear time. It scanned from every `hermes` to the end of the line, so a long
  line repeating it (a JSON list of `~/.hermes` paths) held the agent loop in `pre_tool_call` for seconds before
  every `terminal` and `execute_code` call (7.6 s for 112 KB). Padding between `hermes` and `librenms` does not hide
  the command either.
- `/librenms` and `hermes librenms` resolve a plan fragment only as the end of one id, at least four characters
  long, and say which plan it named. Any fragment matched anywhere in an id, so with one plan saved
  `/librenms apply 2` (every id holds `2026`) or `/librenms apply -` applied it at once.
- Audit events no longer carry unbounded model text: a rejected plan's description is cut to 200 characters, a
  refusal's reason and first error to 500, and every string of an event to 2,000, saying so. A UDP syslog message
  over 8,192 bytes is fitted (strings clipped, else only the common fields and the actor, marked
  `"truncated": true`) instead of failing the send: a padded refused attempt never reached the collector.

### Changed
- Approval rule keys always name a saved plan; `librenms:<tool>:unresolved:<digest>` is no longer issued.
- `librenms_plans` with `plan_id` accepts the end of an id (four or more characters) but no longer a substring from
  its middle.

## [0.1.1] - 2026-10-29

### Security
- Audit sink placeholders are no longer read on the sink thread. Hermes' config loader already replaces `${VAR}` in
  `audit_sinks` (headers and url) with the active profile's secret when the settings are read; the plugin then
  read any placeholder left over again on the background thread, where no profile is bound, and so sent the launch
  profile's value of a variable the routed profile does not set to that profile's collector. A placeholder still
  present now means the variable is unset for the profile: the sink is not built, and the log names only the
  variable.
- `LIBRENMS_PROXY` must be a scheme, host and port with a percent-encoded user name and password. An unencoded `#`,
  `/`, `?` or `@` in the password, or a port that is no number, passed validation and made `requests` log the whole
  proxy URL, password included, past Hermes' log and `hermes debug share` redaction. The proxy's user info and
  password (as written and decoded) are also scrubbed from every log line and error the client writes, and with
  `LIBRENMS_PROXY` unset so are those of the environment's `HTTPS_PROXY`, `HTTP_PROXY` or `ALL_PROXY`, which
  `requests` uses instead and nothing validates.
- A malformed `LIBRENMS_URL` is no longer quoted in the error the model reads: swapped `LIBRENMS_URL` and
  `LIBRENMS_TOKEN`, or a scheme-less URL with `?api_token=`, put the token in the tool result. A value shaped like
  an API token is named as such ("are LIBRENMS_URL and LIBRENMS_TOKEN swapped?").
- `audit.jsonl` is never opened through a symlink, nor written when it is not a regular file owned by the account
  Hermes runs as with no other hard link (any account may hard-link a file it can reach, a shell's rc file among
  them, at the log's name in a shared directory). The name is looked up again after the open, so a link removed in
  between is caught, and a rotation at that moment has the event written to the new file. A FIFO no longer blocks
  the write. A refused event still reaches the sinks, and Hermes' log says why.
- `plugin-data/librenms`, which Hermes' helper creates under the process umask (usually `0755`), is kept `0700`, so
  other accounts cannot list plans or watch the audit log grow.
- Status no longer shows `audit_log_path` (a path that names the OS account) to the model, only whether one is set
  (`custom`). The configuration digest is unchanged.
- SNMP credentials shorter than four characters are scrubbed from step errors too, where they stand alone.

### Fixed
- `plan_retention_days` is applied per profile and not only when a plan is created: listing plans, status and
  every `/librenms` and `hermes librenms` command sweep as well, at most once an hour per profile (the throttle was
  per process, so one profile's sweep held off every other's).
- Messages and docs name the active profile's `.env` (`~/.hermes/profiles/<name>/.env` under a named profile), as
  Hermes' own install prompt does, rather than `~/.hermes/.env`.
- A relative `audit_log_path` resolved against each process's working directory; it is now a settings error and the
  default path is used.
- A gateway serving several profiles keeps one audit sink worker per profile instead of rebuilding a shared one at
  every switch, and registers its exit hook once instead of once per rebuilt worker.

### Added
- Status (and the log at registration) warns about a credential header in `audit_sinks` (`Authorization`, or a name
  with `token`, `key`, `secret`, `auth` or `pass`) written into `config.yaml` as a literal value, reading
  `config.yaml` as written through Hermes, and names where the credential belongs instead.
- `audit_sink_secret`, a `type: secret` setting the Desktop shows as a masked field and stores in the profile's
  `.env` as `LIBRENMS_AUDIT_SINK_SECRET`, for a collector token written as `${LIBRENMS_AUDIT_SINK_SECRET}`. Hermes
  fills the Desktop's form with `audit_sinks` expanded and saves it that way, so the setting descriptions, docs and
  the status warning say to edit `audit_sinks` in `config.yaml` once it holds a placeholder.

### Changed
- A community, `authpass` or `cryptopass` reference must name a variable ending in `_SECRET`, `_PASS` or
  `_PASSWORD` (`LIBRENMS_SNMP_COMMUNITY_SECRET`, `LIBRENMS_SNMP_V3_AUTH_PASS`, `LIBRENMS_SNMP_V3_PRIV_PASS`):
  Hermes masks only such names when the agent's terminal prints the environment. 0.1.0 suggested
  `LIBRENMS_SNMP_COMMUNITY`, and its SNMPv3 example used `LIBRENMS_SNMP_V3_AUTH` and `LIBRENMS_SNMP_V3_PRIV`; plans
  naming them are refused with the rule, so rename those variables. The SNMPv3 user name may keep any
  `LIBRENMS_SNMP_` name.

## [0.1.0] - 2026-10-28

### Added
- `librenms_query`: any GET route of an allow-list built from LibreNMS' own route table, in its registration order,
  with `params`, `fields` and `limit`; hostnames in paths and `hostname` filters resolved to device ids first, ids
  checked to exist and `0` refused; a `hostname` filter refused on routes that ignore it, naming the path form to
  use; log routes newest first and capped, `truncated` counting `start`; a 404 on an empty list returned as zero
  results, and a 404 that is not LibreNMS's JSON reported as a wrong `LIBRENMS_URL`; `{"action": "status"}` for
  connectivity, the LibreNMS version, transport posture, settings, write mode and configuration errors.
- `librenms_plan`: plans over seven resources (`device`, `location`, `device_group`, `service`, `alert_rule`,
  `port`, `alert`) with `create`, `update`, `delete`, `maintenance`, `discover`, `ack` and `unmute`; targets by id
  or `match`, upsert via `create` + `match`, names resolved to ids, field-level diff with LibreNMS-aware value
  normalisation, a recorded state precondition per step (LibreNMS has no change stamps), duplicate-target
  detection, and a rollback kind per step (exact, lossy, none, not needed) shown in the diff. Acknowledgements and
  unmutes follow LibreNMS's own per-entity rule, including its default limit; a device create leaves
  `poller_group: 0` to LibreNMS's default group; a hostname change in letter case only is not a move.
- `librenms_apply`: preflight (status, age, URL, gates), per-step precondition re-check, a write-ahead journal
  entry before each write, re-read verification of every write, journaled inverses, automatic reverse-order
  rollback on failure, `dry_run`, and one run at a time across processes (a failed apply until its automatic
  rollback ends). A write whose answer was lost (a timeout, a reset, a gateway's 502, 503 or 504) is journaled as
  possibly written, and for ten minutes a rollback that finds it not done yet leaves it pending.
- `librenms_rollback`: journal replay newest first, post-apply modification detection (for an acknowledgement or
  unmute, also of the other open faults it reaches), `force`, re-creation of deleted locations, device groups,
  services and alert rules from their snapshots, recovery of a run that died mid-step, and resumption of a rollback
  that died, adopting what it re-created instead of creating it twice.
- `librenms_plans`: list and inspect plans.
- `/librenms` slash command and `hermes librenms` CLI with `status`, `plans`, `show`, `check`, `apply`, `rollback`
  and `prune`; plan id fragments accepted.
- Approval: with `require_approval` (default on), every `librenms_apply` and `librenms_rollback` call in `full`
  mode goes to Hermes' approval prompt with the plan summary and its irreversible steps, keyed per plan;
  requests are audited as `approval_requested` and decisions as `approval_decided`.
- `write_mode` (`full`, `operator_only`, `read_only`), plan retention (`plan_retention_days`), and the audit trail
  of the NetBox plugin: actor records (now with Hermes surface, profile and cron job), the triggering message
  captured by a `pre_llm_call` hook, an append-only `audit.jsonl`, and `audit_sinks` forwarding to syslog and
  HTTP collectors, rebuilt when their settings change.
- Eventlog linking (`link_eventlog`): after apply and rollback, the new LibreNMS eventlog entries of the devices a
  plan touched are attached to its journal. Maintenance titles and alert notes carry `[hermes:<plan id>]`.
- Bundled `librenms:workflow` skill with a per-resource cheat sheet and an untrusted-content section.
- Test suite with an in-memory fake LibreNMS reproducing the API's envelopes and quirks, and a loader test
  through Hermes' `PluginManager`.

### Security
- Deletes (`allow_delete`), device adds and retargeting of a device's `hostname` or `overwrite_ip`
  (`allow_device_add`), and services (`allow_services`) are off by default and checked when planning and again
  when applying.
- SNMP credentials are never written into a plan: a device create names environment variables
  (`{"env": "LIBRENMS_SNMP_<NAME>"}`) that are read only while the step runs. Credential fields (communities, SNMP
  passwords, service parameters) are masked in every tool result and audit event; the token appears only in the
  `X-Auth-Token` header and is scrubbed from every error.
- Transport: `https://` with certificate checks unless `allow_insecure_transport`; redirects refused; `.netrc` and
  cookies ignored; responses size-capped; only GETs retried; transport errors reported by id with the detail kept
  in the log. `requests` 2.32.4 or newer (CVE-2024-47081, CVE-2024-35195).
- `librenms_query` refuses graph images, Oxidized configuration backups, the GET that schedules a rediscovery and
  the port-by-ifName route. No request path may hold a segment that decodes to `/`, which LibreNMS would route
  elsewhere (`devices/1%2Fdiscover` is the rediscovery GET), and a device reference with a `/` is refused.
- The agent's terminal is not a way around review: a `pre_tool_call` hook blocks terminal and code calls that run
  `hermes librenms apply` or `rollback`, and the CLI refuses them when started from an agent session, unless
  `write_mode` is `full` and `require_approval` is off. Both refusals are audited; both checks are heuristics, and
  the token's role is the hard limit.
- Free text from the model or LibreNMS (a plan's description, labels, notes, errors) stays on one line in plans,
  journals and the approval prompt, and the description, at most 200 characters, comes last in the prompt, so none
  of it can pass for a step.
- Alert rules muted in the LibreNMS UI are not updated or deleted: every API write unmutes them.
- A loopback HTTP audit sink is never reached through a proxy.
- Settings fail closed: an unreadable flag takes the value that lets the model do least and an unknown
  `write_mode` becomes `read_only`; each fallback is reported by `status`.
- Plan and audit files are `0600` in `0700` directories; operator output escapes control and bidirectional
  characters from LibreNMS text.
