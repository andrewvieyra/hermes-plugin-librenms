# Security

## Reporting

Report vulnerabilities privately through GitHub's security advisory form for this repository
rather than a public issue. You will get an acknowledgement within a few days.

## Threat model

The plugin runs in-process inside Hermes with a LibreNMS API token, which carries every right of
the LibreNMS user that owns it. The things that can go wrong, and what the plugin does about each:

| Threat | Control |
|---|---|
| The token leaks into chat, logs or files | Read through Hermes' per-profile secret scope (else the environment) when a call is made; sent only as the `X-Auth-Token` header, never in a URL (`api_token` is refused as a query parameter and stripped from bodies); replaced with `<token>` in every error message and every response body an error keeps; never written to plans, journals or the audit stream. A LibreNMS token pasted into chat (`<id>\|<secret>`, or the older 32 hex digits) is masked in the audit record of the user's message. |
| The token is sent to another host | Redirects are never followed: `requests` would re-send `X-Auth-Token` to whatever host a `Location` header names. A 3xx is an error that says where it points (without credentials or query) and asks to set `LIBRENMS_URL` to that address. `~/.netrc` is never read, so no Basic credentials ride along, and cookies are refused. A `LIBRENMS_URL` holding a user name or password is refused without being quoted. Request paths are built from percent-encoded segments, and a path with `?`, `#`, `..`, `//` or a scheme is refused, so no argument can reach another host. A segment that decodes to something holding `/` is refused as well: LibreNMS decodes the path before it picks a route, so `devices/1%2Fdiscover` would reach the GET that schedules a rediscovery. A device reference with a `/` in it is refused before anything is sent. |
| The token or LibreNMS's answers are read or changed on the network | An `http://` `LIBRENMS_URL` or `LIBRENMS_VERIFY_SSL=false` fails every call unless `allow_insecure_transport` is on; that setting lives in `config.yaml`, so a line in `.env` alone cannot turn on clear-text or unverified transport. `/librenms status` reports the transport (scheme, verification, proxy mode) without naming a host or path, and warns while insecure transport is allowed. A private CA is named in `LIBRENMS_VERIFY_SSL`; `LIBRENMS_PROXY` gives LibreNMS a proxy of its own, or `none`. |
| Secrets LibreNMS returns reach the model provider | An admin token gets SNMP communities and v3 passwords in clear in every device object, and services carry their Nagios check arguments (`-a user:password`). Every value under a credential key (`community`, `authname`, `authpass`, `cryptopass`, `password`, `secret`, `token`, `service_param`, `param`, `psk`, `key`, …) is masked at any depth in every tool result and every audit event, and device objects are masked as they are read. A plan that changes a service's parameters shows the new value (what the person approves) and LibreNMS's current value only as a short digest. |
| SNMP credentials end up in plans | Adding a device takes credentials only as `{"env": "LIBRENMS_SNMP_<NAME>"}` references, read inside the step at apply time and never stored; a literal is refused with an explanation. Error text from a step is scrubbed of that step's credentials and service parameters before it is journaled. API v0 cannot change an existing device's SNMP settings, and the plugin refuses to try. |
| Fetched content steers the model (prompt injection) | LibreNMS stores text that people outside the conversation control: syslog lines from any host that can reach its syslog port, SNMP strings (`sysDescr`, `sysName`, `sysLocation`, `sysContact`, `ifAlias`) set on the devices, LLDP and CDP neighbour names advertised by other devices, BGP descriptions, eventlog messages, notes. The plugin cannot stop influence; it bounds consequences: there is no write except a saved plan, a person approves or runs every apply, `write_mode`, the `allow_*` gates, deletes off by default, and an audit event for every attempt. The skill tells the model to treat this text as data. Text from LibreNMS is clipped for the model and escaped for terminals and the approval prompt, so control sequences and bidirectional overrides cannot rewrite what the person reads. |
| The model writes without a person seeing the diff | The only writes are `librenms_apply` and `librenms_rollback` of a saved plan. With `require_approval` (the default), each one that is not a dry run goes to Hermes' approval prompt with a header that is never cut (counts, irreversible steps, `rollback_on_failure` or `FORCE`) and the rendered plan; the model's description (at most 200 characters) comes last, and it and every label and note are kept on one line, so no free text can pass for a step or push the steps out of the prompt. A denial, a timeout or no person to ask blocks it. The approval key names the plan and the choice, so "always" covers that plan with that choice only, and a dry run is recognised with the same parser the handler uses. `operator_only` removes the model from applying altogether. |
| The model applies through a shell instead | A `terminal` or `execute_code` call whose text names `hermes librenms apply` or `rollback` is blocked, and `hermes librenms apply` / `rollback` refuses to run from a shell an agent session started (`HERMES_SESSION_ID` or `HERMES_SESSION_KEY` is set), unless `write_mode` is `full` and `require_approval` is off. Both refusals are audited as `apply_refused` or `rollback_refused`; the block records the tool and the plan id, never the command text. The block tells the model what this `write_mode` lets it do instead. |
| A plan runs somewhere, or some time, it was not reviewed for | A plan is bound to the LibreNMS URL it was built against, expires after `max_plan_age_hours`, applies once (the claim is made under a cross-process lock), and has its gates checked again for every step when it runs. |
| The object changed between review and apply, or LibreNMS ignored the write | LibreNMS has no modification stamps, so the plan records each object's state and every step compares the live object with it before writing; a difference stops the run. Every write is read back and compared: LibreNMS answers 2xx to device fields it ignores, to boolean strings it stores as nothing, and to text it truncates. A failure after LibreNMS may have changed something is journaled with its inverse, so rollback undoes it. That includes a write whose answer was lost (a timeout, a reset, a gateway's 502, 503 or 504): LibreNMS may still be carrying it out, so a re-read that finds nothing yet proves nothing. For ten minutes after such a write, a rollback that finds it not carried out leaves it pending instead of settling it, and a later rollback looks again. |
| Rollback destroys a change someone made after the apply | Each revert compares the object with the state journaled after the write and reports a conflict on any difference; `force` overrides, and the approval prompt says `FORCE`. Rolling back an acknowledgement or an unmute also re-reads the other open faults of the device and rule, which LibreNMS changes together unless the rule notifies per entity: a fault opened or changed since the apply, or a change in per-entity behaviour, is a conflict. |
| A crash leaves LibreNMS in an unknown state | Each step's journal entry is saved before its first request, and each run holds a lock that dies with its process. Rollback recovers a plan whose run died, treats the step in flight as "may have written", and looks at the object before acting on it. A revert saves its progress before it re-creates a deleted object, so a rollback that resumes after a dead one adopts what that run created instead of creating it twice. |
| Two runs interfere | One apply or rollback at a time: a run is refused while another plan's run is alive, including a failed apply whose automatic rollback has not started yet. |
| The model makes LibreNMS reach out from its network, or run commands | Adding a device makes LibreNMS probe a host the model chose over ICMP and SNMP, from the NMS's network position; renaming one or changing its `overwrite_ip` points LibreNMS's polling, with the device's credentials, at another host; a service runs a Nagios plugin with the model's arguments on the poller. `allow_device_add` and `allow_services` gate these, off by default, checked when planning and again when applying. |
| A delete destroys history | `allow_delete` is off by default. A device delete is recorded as irreversible and named in the plan and the approval prompt; every other delete says what its re-creation cannot restore. |
| A read is really a write, a secret oracle or a binary | `librenms_query` reads only through an allow-list of LibreNMS's GET routes, matched in LibreNMS's own order so a shadowing route decides as it would. It refuses Oxidized configuration and configuration search, graph images, the GET that schedules a rediscovery (a plan operation instead) and the ifName route. Device names are resolved to ids, and ids are checked to exist, before the request (`0` is refused), because several LibreNMS filters return every device's rows for a device they do not know. A `hostname` parameter on a route that ignores it is refused, naming the path that filters by device where there is one. A 404 that is not LibreNMS's JSON (a web server's page) is an error that points at `LIBRENMS_URL`, never zero results. `api_token` and `_method` parameters are refused. |
| Large responses exhaust context | Results are capped at `max_query_results` (at most 5,000) and long strings clipped, saying so. Responses are streamed and read to 16 MiB, uncompressed (`Accept-Encoding: identity`). Log routes always send a positive `limit`: LibreNMS reads a negative one as no limit. |
| Error text carries local paths, internal hosts or SQL to the model provider | A failure to reach LibreNMS is `could not reach LibreNMS (timeout\|TLS\|DNS\|refused\|connection) err-<id>`, and an unexpected exception is reported by its class and an error id; the URL, the exception text and the traceback go to Hermes' log under that id. A LibreNMS 5xx with SQL in it, or without LibreNMS's error envelope, is reported as `details withheld`, and debug fields (exception, file, line, trace) are dropped from kept bodies. Configuration errors never quote a CA bundle path, a proxy URL, a user name or password in `LIBRENMS_URL`, or a sink's address. |
| A configuration mistake widens what the agent may do | Every setting fails closed: an unreadable `write_mode` is `read_only`, an unreadable flag takes the value that allows least (`require_approval` true, every `allow_*` false), a number that is not a whole number keeps its default and one above its limit is lowered to it. Each fallback is logged at load and listed by `/librenms status`. |
| Plan files are read or changed by another account | Plans are created `0600` with `O_EXCL` in directories created `0700`, replaced atomically with `fsync`, never through a symlink, in the active profile's own directory. |
| Audit sink credentials end up in `config.yaml`, a log or another host | Sink headers take `${VAR}` placeholders read at send time. Sinks follow no redirect, refuse clear text to another machine and unverified TLS unless `allow_insecure_transport`, reach a loopback collector directly and never through a proxy, and refuse a URL with credentials in it; log lines name a sink by its index and kind, never its address, headers or paths. See [docs/sinks.md](docs/sinks.md). |
| The agent's activity cannot be traced | Every audit event carries the actor (platform, chat, user, session, cron job, the user's message), the `config_digest` of the settings in force, the host and the pid; every journal entry records the requests it made. Eventlog rows LibreNMS wrote during a run are linked into the plan, maintenance titles and acknowledgement notes carry `[hermes:<plan id>]`, and every request carries `User-Agent: hermes-plugin-librenms/<version>`. See [docs/audit.md](docs/audit.md). |
| The plugin's hooks break Hermes | Hook callbacks never raise (Hermes blocks any tool call whose `pre_tool_call` hook raises), and return at once for every tool but their own and the shell tools. When the approval hook cannot load a plan, it still asks for approval rather than waving the call through. |
| Registration performs network I/O | It does not; Hermes' Plugin Doctor verifies this. |

## What the plugin does not do

- It does not make a global-read token read-only. LibreNMS lets a token with the global-read role
  schedule a rediscovery (`GET devices/{hostname}/discover`) and append eventlog rows
  (`POST devices/{hostname}/eventlog`). `write_mode: read_only` is enforced by the plugin: the write
  tools are hidden and refused, `librenms_query` refuses the rediscovery GET, the client refuses
  an encoded `/` that would reach it from another path, and the plugin never sends the eventlog
  POST. The same token used by anything else is not bound by it.
- It does not authenticate what LibreNMS stores. Syslog arrives without authentication from any
  host that can reach the collector; SNMP strings, LLDP/CDP neighbours and hostnames from
  autodiscovery are set by whoever controls the devices. The plugin returns them to the model as
  data and cannot tell a forged line from a real one.
- It cannot end maintenance. API v0 has no route to end or delete a maintenance schedule, so a
  maintenance step is irreversible: it lasts its whole duration, and the plan says so. To end one
  early, delete the schedule whose title starts with `[hermes:<plan id>]` in LibreNMS (Alerts →
  Scheduled Maintenance). Maintenance notes may also be appended to the device's notes, depending
  on a preference of the token's user.
- It does not keep the token from a model that has a shell. Hermes does not remove a standalone
  plugin's secrets from the environment of its `terminal` tool, and in a single-profile process
  `.env` is loaded into the environment, so a model with `terminal` or `execute_code` on the local
  backend can read `LIBRENMS_TOKEN` and call LibreNMS directly, past every control here. Only the
  token's LibreNMS role bounds that. The same model can also read and edit the plan files and the
  audit log.
- It does not see a call made through `ctx.dispatch_tool`. Hermes' plugin API lets another plugin
  call a tool's handler directly, which skips `pre_tool_call` hooks and so the approval prompt. A
  plugin installed beside this one could apply a plan without anyone being asked. `write_mode` is
  checked in the handler and still applies.
- It does not ask when Hermes is set not to. The approval prompt is Hermes' gate under the user's
  approval policy: YOLO mode, `approvals.mode: off`, an earlier "session" or "always" answer for the
  same plan and choice, `approvals.cron_mode: approve` (cron jobs),
  `approvals.unattended_mode: approve` (webhook and API-server sessions) and
  `approvals.single_query_mode: approve` (`hermes -q`) all pass it without asking. Each request is
  audited as `approval_requested`, so one passed or blocked without a person shows in the trail
  without an `approval_decided`. With `require_approval: false` in `full` mode, nothing but the
  skill's instruction stands between the model and an apply.
- It does not show a long plan in full in the approval prompt: the prompt is cut at 1,500
  characters (the header, with the counts and the irreversible steps, is never cut) and says how
  to see the rest.
- It does not catch every way to run the CLI from a shell. The `terminal` rule matches the command
  text, so an obfuscated command (a variable, a script, an encoding) passes it; the CLI's check for
  an agent session reads environment variables a command can unset. `operator_only` holds against
  a model with a shell only where that shell is in a container or on a remote backend.
- It does not check who runs `/librenms apply`. In `operator_only` mode any chat user who may send
  commands to the gateway can apply or roll back a plan; Hermes' own access controls decide who
  that is. The audit trail records who it was.
- It does not replace LibreNMS permissions. LibreNMS checks no token abilities on API v0 routes: a
  token can do everything its user can. A leaked token, or a tool other than this plugin, is
  bounded only by that user's role.
- Its preconditions are read-then-write, not atomic. LibreNMS has no conditional write, so a
  change landing between a step's check and its write (one request) is not detected for that
  step. Fields LibreNMS itself rewrites (a device's `type` and `icon`, its location while
  `override_sysLocation` is off, a location's geocoding stamp) are compared only when a step
  writes them.
- Its rollback restores what the API can write. A re-created location, device group, service or
  alert rule gets a new id, and what pointed at the old id (alert-rule scoping, permissions, graph
  history, template mappings, alert history) does not follow; an acknowledgement's note stays in the
  fault's history; notifications already sent are not recalled; whether a port description was
  pinned against the poller cannot be read. Each step says what its rollback cannot restore before
  it runs.
- It does not detect a plan file edited after review. Apply re-checks the status, URL, age, gates
  and every step's precondition against live LibreNMS, but sends what the file says. Keep
  `plugin-data` out of reach of any file or shell tool the model can use.
- It does not encrypt `plugin-data`. Plan files hold object data as LibreNMS returned it, with SNMP
  credentials masked but services' check parameters kept (rollback needs them), and the audit
  stream holds the users' messages. Protect the directory like the token.
- It does not make the audit file tamper-proof. The file is written by the account Hermes runs as,
  so anything that account runs can change it. Forward events off the machine (`audit_sinks` or a
  log shipper) and treat that copy as the record. `audit_log: false` stops the sinks as well.
- Its redaction is by key name and by pattern. A credential under a key the list does not name, or
  typed into free text (device notes, `sysDescr`, a syslog line, an alert note, a user's message
  in prose), passes through.
- It does not refuse clear-text syslog or HTTP to the same machine: a sink on a loopback address
  is allowed without `allow_insecure_transport`, for a local relay. It is always dialed directly,
  never through `HTTP_PROXY`, `HTTPS_PROXY` or `ALL_PROXY`, whatever `NO_PROXY` says.
- It does not limit how many plans the model builds or how often it applies them; `max_operations`
  caps one plan's size. To stop all writes at once, set `write_mode: read_only` in `config.yaml`:
  settings are read on every call, so it applies to the next one without a restart.
- It does not sandbox itself from Hermes. Plugins run as in-process Python with the same privileges
  as the agent.

## Recommended deployment

1. **A dedicated LibreNMS user** for the agent, never an administrator's own token. LibreNMS
   attributes eventlog rows and acknowledgements to the token's user, so the agent's work stays
   distinguishable from people's.
2. **For `read_only`, a token of a user with only the global-read role.** It reads everything the
   plugin reads, gets SNMP secrets back as `null`, and cannot write, apart from the two exceptions
   above. Device lookups by hostname need it (or `device.viewAll`): LibreNMS answers 403, not 404,
   for an unknown hostname to a token that cannot see every device, and the plugin then asks for the
   device id.
3. **For writes, a least-privilege role**, never `admin`: the global-read role plus a custom role
   holding only the write permissions for the operations you enable (or one custom role with the
   view permissions as well). LibreNMS names them `<model>.<ability>`, for example
   `device.update` (device updates, renames and maintenance), `location.create` and
   `location.update`, `device-group.update`, `alert-rule.update`, `port.update`, `alert.update`
   (acknowledging and unmuting faults); `device.create` only with `allow_device_add`,
   `service.create`, `service.update` and `service.delete` only with `allow_services`, and the
   `.delete` permissions only with `allow_delete`. Grant neither `secret.unmask` (device objects would carry SNMP secrets in
   clear) nor `config-backup.view` or `oxidized.search`. Check the names against your LibreNMS
   version's role editor; on a release without per-model permissions, API writes need the admin
   role, and there `operator_only` matters all the more.
4. **`operator_only` on any gateway shared with other people**, anywhere cron jobs run, and on any
   profile that serves unattended platforms (webhooks, the API server), so the model plans and a
   person applies with `/librenms apply <id>` or `hermes librenms apply <id>`.
   Use Hermes' own controls over who may talk to the gateway to keep `/librenms` to the people who
   should run it.
5. **`require_approval` on** (the default) wherever `write_mode` is `full`, and no YOLO mode,
   `approvals.mode: off`, `approvals.cron_mode: approve`, `approvals.unattended_mode: approve` or
   `approvals.single_query_mode: approve` on that profile.
6. **`allow_delete`, `allow_device_add` and `allow_services` off.** Turn one on for the change that
   needs it and off again after; settings are read live.
7. **No shell or file tools for the model on the gateway's host**: Hermes' terminal tool on a
   container or remote backend, or off. Otherwise the model can read the token and the plan files,
   and run the CLI.
8. **Only plugins you trust** beside this one, since a plugin can call this plugin's tools without
   the approval prompt.
9. **LibreNMS over HTTPS with verification on**: `LIBRENMS_VERIFY_SSL` naming the CA bundle of a
   private CA, `allow_insecure_transport` off, and `LIBRENMS_PROXY` set when LibreNMS should not go
   through the proxy Hermes uses for the model provider (or should go through one of its own).
10. **`audit_log_path` pointed at a directory your log shipper watches, or `audit_sinks` over TLS**
    (`protocol: tls`, or an `https://` collector), with `audit_log` left on beside them; alerts on
    `apply_refused`, `rollback_refused`, `step_failed`, `revert_failed`, `revert_conflict` and
    `run_recovered`, on an `approval_requested` that no `approval_decided` follows, and on any
    `config_digest` you have not approved. `audit_include_request: false` where users paste
    credentials into chat.
11. **Short-lived plans**: `max_plan_age_hours` no longer than a review takes, `max_operations` a
    little above what the agent's changes need, and `plan_retention_days` matching your retention
    policy for the data plans hold.
12. **`/librenms status` after every configuration change**, with no warning or settings error left
    unexplained.
