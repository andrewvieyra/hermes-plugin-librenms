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
| Secrets LibreNMS returns reach the model provider | An admin token gets SNMP communities and v3 passwords in clear in every device object, and services carry their Nagios check arguments (`-a user:password`). Every value under a credential key (`community`, `authname`, `authpass`, `cryptopass`, `password`, `secret`, `token`, `service_param`, `param`, `psk`, `key`, …) is masked at any depth in every tool result and every audit event, and device objects are masked as they are read. The contacts LibreNMS stores in an alert's details (e-mail addresses and names) are never returned. A plan that changes a service's parameters shows the new value (what the person approves) and LibreNMS's current value only as a short digest. |
| SNMP credentials end up in plans | Adding a device takes credentials only as `{"env": "LIBRENMS_SNMP_<NAME>"}` references, read inside the step at apply time and never stored; a literal is refused with an explanation. Error text from a step is scrubbed of that step's credentials and service parameters before it is journaled. API v0 cannot change an existing device's SNMP settings, and the plugin refuses to try. |
| Fetched content steers the model (prompt injection) | LibreNMS stores text that people outside the conversation control: syslog lines from any host that can reach its syslog port, SNMP strings (`sysDescr`, `sysName`, `sysLocation`, `sysContact`, `ifAlias`) set on the devices, LLDP and CDP neighbour names advertised by other devices, BGP descriptions, eventlog messages, notes. The plugin cannot stop influence; it bounds consequences: there is no write except a saved plan, a person approves or runs every apply, `write_mode`, the `allow_*` gates, deletes off by default, and an audit event for every attempt. Both skills (`librenms:workflow` for changes, `librenms:ask` for questions) tell the model to treat this text as data, and a result that returns it says so where the model reads it: `untrusted_fields` names the keys holding text from LibreNMS (a query's rows; `librenms` in status and in an error, which is LibreNMS's answer; a plan's diff and warnings, dry-run conflicts, journals, reports, eventlog rows, steps; the label keys of a `librenms_report`'s rows, summary and scope (also when a page has no row and its summary names rules, devices or sensors), such as `hostname`, `sysName`, `location` and `why`, and what an LLDP/CDP neighbour advertised about itself, `remote_hostname`, `remote_port` and `remote_platform`, which any device on the wire writes; an `events` report's `message`, `program` and `tag`, which any host that can reach the syslog collector writes, and a login's `user` and `address`) and `untrusted_notice` says it is data from the monitored network, not instructions. Refusals and errors are the plugin's own text and carry no marker of their own, though they may quote LibreNMS (its error message, the hostnames of devices it holds, a plan's `errors`); the skills tell the model that this text is data too. Hermes draws its own boundary only around its web, browser and MCP tools and offers a plugin no way into it, so the results mark themselves; the JSON quoting around each value is a boundary no value can close. Every string a tool result holds, the errors quoting LibreNMS included, every line printed to a terminal and the approval prompt have their bidirectional controls, invisible characters (zero-width spaces and joiners, the soft hyphen, the byte-order mark, fillers, variation selectors, the emoji and text presentation ones wherever they follow nothing they change, and tag characters, which spell ASCII a model reads and a person does not) and C0/C1 controls escaped (`\u202e`, `\u200b`, `\x9b`), never dropped, so what would not show is shown: text from LibreNMS cannot reorder, overwrite or hide what a person reads or carry instructions only the model sees, and two names that differ by an invisible character read differently. Newlines and tabs stay, and the model reads a Windows line end as a newline. Every limit on text for the model counts the escapes. |
| The model writes without a person seeing the diff | The only writes are `librenms_apply` and `librenms_rollback` of a saved plan. With `require_approval` (the default), each one that is not a dry run goes to Hermes' approval prompt, which shows little of what it is given: 9 rows of 64 columns in the CLI panel, 300 characters on Discord, 500 on Slack and Telegram. The message therefore opens with one header line (the plan id, the counts, the irreversible steps, `rollback_on_failure` or `FORCE`) and one line per step naming the object and the fields it sets (for a rollback, per entry, saying what reverting it does), deletes and irreversible steps first and marked; the field-level diff, the warnings and, last, the model's description follow only while room remains. Every line is kept to one line and cut to 120 characters, a label to 40, so no text from LibreNMS or the model can pass for a step or push the steps out. A denial, a timeout or no person to ask blocks it. The model's apply and rollback take only a plan's full id: a `plan_id` that names no saved plan, or only the end of one, is refused without asking, since a fragment resolved again after the prompt could name a plan created while it was open, and so is a plan the hook cannot load. The approval key names the plan, the choice and a digest of the plan's content (its steps with their snapshots and inverses, the summary, the irreversible steps, the warnings, the description, the LibreNMS, the stamp, the status, the journal, and the apply and rollback records a rollback prompt shows), so "session" or "always" covers that plan with that choice as it was shown: once the file changes, Hermes asks again. The prompt's digest also goes to the handler of the same call (by Hermes' `modify` directive, through a second `pre_tool_call` callback), which refuses a call whose plan or choice is not the one the prompt showed, and under the claim, after the last load before the run, a plan whose digest is not the one the prompt showed, so an edit made while the prompt was open, or another plan saved under the same id, is never applied or rolled back on that approval. The claim runs the plan it digested, whole (no key is taken from an earlier load), with its gates checked again. A model's call that reaches the handler with no prompt bound to it while one was due (a dry run turned into an apply after the prompt was skipped, by another plugin's `modify` or tool middleware) is refused. Plan ids hold only letters, digits, `_`, `.` and `-`, so the key always reads back as the plan it names, and a plan file whose `id` is not its name (edited or copied by hand) is neither shown nor run. A dry run is recognised with the same parser the handler uses. `operator_only` removes the model from applying altogether. |
| The model applies through a shell instead | A `terminal` or `execute_code` call whose text names `hermes librenms apply` or `rollback`, and a `process_manage` write or submit that sends it to the input of a shell `terminal` started in the background, is blocked, and `hermes librenms apply` / `rollback` refuses to run from a shell an agent session started (`HERMES_SESSION_ID` or `HERMES_SESSION_KEY` is set), unless `write_mode` is `full` and `require_approval` is off. Both refusals are audited as `apply_refused` or `rollback_refused`; the block records the tool and the plan id, never the command text. The block tells the model what this `write_mode` lets it do instead. |
| A plan runs somewhere, or some time, it was not reviewed for | A plan is bound to the LibreNMS URL it was built against, expires after `max_plan_age_hours`, applies once (the claim is made under a cross-process lock), and has its gates checked again for every step when it runs. |
| The object changed between review and apply, or LibreNMS ignored the write | LibreNMS has no modification stamps, so the plan records each object's state and every step compares the live object with it before writing; a difference stops the run. Every write is read back and compared: LibreNMS answers 2xx to device fields it ignores, to boolean strings it stores as nothing, and to text it truncates. A failure after LibreNMS may have changed something is journaled with its inverse, so rollback undoes it. That includes a write whose answer was lost (a timeout, a reset, a gateway's 502, 503 or 504): LibreNMS may still be carrying it out, so a re-read that finds nothing yet proves nothing. For ten minutes after such a write, a rollback that finds it not carried out leaves it pending instead of settling it, and a later rollback looks again. |
| Rollback destroys a change someone made after the apply | Each revert compares the object with the state journaled after the write and reports a conflict on any difference; `force` overrides, and the approval prompt says `FORCE`. Rolling back an acknowledgement or an unmute also re-reads the other open faults of the device and rule, which LibreNMS changes together unless the rule notifies per entity: a fault opened or changed since the apply, or a change in per-entity behaviour, is a conflict. |
| A crash leaves LibreNMS in an unknown state | Each step's journal entry is saved before its first request, and each run holds a lock that dies with its process. Rollback recovers a plan whose run died, treats the step in flight as "may have written", and looks at the object before acting on it. A revert saves its progress before it re-creates a deleted object, so a rollback that resumes after a dead one adopts what that run created instead of creating it twice. |
| Two runs interfere | One apply or rollback at a time: a run is refused while another plan's run is alive, including a failed apply whose automatic rollback has not started yet. |
| The model makes LibreNMS reach out from its network, or run commands | Adding a device makes LibreNMS probe a host the model chose over ICMP and SNMP, from the NMS's network position; renaming one or changing its `overwrite_ip` points LibreNMS's polling, with the device's credentials, at another host; a service runs a Nagios plugin with the model's arguments on the poller. `allow_device_add` and `allow_services` gate these, off by default, checked when planning and again when applying. |
| A delete destroys history | `allow_delete` is off by default. A device delete is recorded as irreversible and named in the plan and the approval prompt; every other delete says what its re-creation cannot restore. |
| A read is really a write, a secret oracle or a binary | `librenms_query` reads only through an allow-list of LibreNMS's GET routes, matched in LibreNMS's own order so a shadowing route decides as it would. It refuses Oxidized configuration and configuration search, graph images, the GET that schedules a rediscovery (a plan operation instead) and the ifName route. Device names are resolved to ids, and ids are checked to exist, before the request (`0` is refused), because several LibreNMS filters return every device's rows for a device they do not know. A `hostname` parameter on a route that ignores it is refused, naming the path that filters by device where there is one, and so is a parameter name PHP reads as another (`hostname[]` reaches LibreNMS as `hostname`, unchecked). An object id LibreNMS reads as no filter (`faults/0`, `rules/0`, `bills/x`, `poller_group/0`, `port_security/port/0`) or as another id (`ports/1abc`) is refused, and a MAC an exact-match route could never find is sent in the form LibreNMS stores, so neither every object nor a false "not found" is presented as an answer about one. A 404 that is not LibreNMS's JSON (a web server's page) is an error that points at `LIBRENMS_URL`, never zero results. `api_token` and `_method` parameters are refused. `where` and `sort` run in the plugin on the rows read and compare a credential key as the result shows it (masked when set), and an object or a list (a fault's `details`, which holds the alert's contacts) matches no condition but `ne` and sorts in the order read, so neither a filter nor an order tells anything about a value the result leaves out. A `start` parameter on a route LibreNMS does not page is refused, since it would answer with the first rows again as if they were the next. `librenms_report` sends no path the model wrote: each read is built from fixed words and the ids it resolved, each segment percent-encoded, and is checked against the same allow-list before it is sent, so a refused route stays out of reach (a test records every request a report makes and matches it). It makes at most 30 requests per call, never asks a device or port group for `full=1` rows, asks for ports by a list of named columns, sends a MAC to the exact-match forwarding route as the 12 hex digits LibreNMS stores (so a MAC it holds is never reported as not found), returns from device objects only named fields (never a credential) and from faults and alert-log entries never their `details` (every column of every table the rule joins, and the alert's contacts): only the labels of what alerted (a port's names, a sensor's description, class and reading, ...), through the same allow-list as `librenms_query`'s `entities`. A scope that names no single device or port answers with candidates rather than broadening to several. A routing report narrows `bgp`, `ospf` and `ospfv3` by a resolved device id only, and reads LibreNMS's HTTP 500 for no OSPFv3 neighbour as none only when its message says exactly that. An events report reads a log only from the window's start, newest first, with the paging parameters it sets itself (250 entries a request, at most 2,000 a report), by a resolved device id or every device's, and the authlog never with a device; it shows a log line clipped to 200 characters and never acts on it. A bills report reads LibreNMS's bill listing as is and returns named fields of it, never a bill history row's `pdf`. View `help` is answered by the plugin and reads nothing. |
| Large responses exhaust context | Results are capped at `max_query_results` rows (at most 5,000) and long strings clipped, saying so (a report's at 200 characters). A report does the fleet-wide scans and joins in the plugin and returns a summary with the rows that matched, so a question about every device does not put every device in front of the model; an alert-history report reads at most 2,000 alert-log entries (250 a request, fewer while LibreNMS's answer is too large to read) and says when the window holds more; a health report reads LibreNMS's one listing of every sensor (it takes no filter) and returns only the scope's that pass the filter, and reads processors, memory pools and storage (a request each) for at most 5 devices and 8 of a kind each. The per-view detail of the report tool (filters, sorts, row keys) is in its view `help` rather than in the schema sent on every turn, which keeps all six schemas under 16 KiB. Every result the model reads is also kept within `max_result_chars` (default 60,000, at most 90,000 characters), under Hermes' threshold for replacing a result with a 1,500-character preview: a listing keeps its first rows and says how to see the rest (`next_offset`, the first row left out; a row that does not fit on its own is named, to narrow with `fields`), a single object that does not fit is refused, and a plan, its journal, its apply and its rollback are shown a range of steps at a time, with only the irreversible steps and the conflicts of the steps shown and the latest dry-run check. Fault and alert-log rows leave out the alert engine's `details` (every column of every table a rule joins, for every matched row) unless `fields` asks for it. Responses are streamed and read to 16 MiB, uncompressed (`Accept-Encoding: identity`). Log routes always send a positive `limit`, under the one parameter name LibreNMS reads: a negative one is no limit to LibreNMS, and a second spelling PHP reads alike (`" limit"`) is refused. |
| Error text carries local paths, internal hosts or SQL to the model provider | A failure to reach LibreNMS is `could not reach LibreNMS (timeout\|TLS\|DNS\|refused\|connection) err-<id>`, and an unexpected exception is reported by its class and an error id; the URL, the exception text and the traceback go to Hermes' log under that id. A LibreNMS 5xx with SQL in it, or without LibreNMS's error envelope, is reported as `details withheld`, and debug fields (exception, file, line, trace) are dropped from kept bodies. Configuration errors never quote `LIBRENMS_URL` (a value in the wrong variable may be the token, and one shaped like a token is named as such), a CA bundle path, a proxy URL, or a sink's address, and status says only whether `audit_log_path` is set. `LIBRENMS_PROXY` must be a host and port with a percent-encoded user name and password: an unencoded `#`, `/`, `?` or `@` would make `requests` quote the whole URL into the log, which Hermes' redaction does not mask. Its user info and password are scrubbed from every log line and error the client writes, and with `LIBRENMS_PROXY` unset so are those of the environment's `HTTPS_PROXY`, `HTTP_PROXY` or `ALL_PROXY`, which `requests` uses instead and nothing validates; for a proxy URL no parser reads as written so is each piece of the password between such characters, and the user info up to each of them, which is what a parser that stops there quotes (urllib3 2.8 quotes `user:pass` of `user:pass#word`); a proxy URL that reads is never split, as no parser stops inside its user info. A request that fails while the proxy in use (as `requests` picks it, `NO_PROXY` read as `requests` reads it) is one no URL parser reads as written (an unencoded `#`, `/`, `?`, `\` or bracket in the user info, which ends the authority early and makes part of the password the host or port, or a host or port that cannot be read) never passes the parser's error to the model: the error and the log line say, in fixed words, which variable holds a proxy URL that could not be parsed and what to fix (percent-encode reserved characters in its user name and password, or give a readable host and port). The log line also carries the parser's error, scrubbed, only when that URL has no user name or password. Messages that say where a secret goes name the active profile's `.env`, never a path outside the user's home directory. |
| A configuration mistake widens what the agent may do | Every setting fails closed: an unreadable `write_mode` is `read_only`, an unreadable flag takes the value that allows least (`require_approval` true, every `allow_*` false), a number that is not a whole number keeps its default and one above its limit is lowered to it. Each fallback is logged at load and listed by `/librenms status`. |
| Plan files are read or changed by another account | Plans are created `0600` with `O_EXCL` in directories created `0700`, replaced atomically with `fsync`, never through a symlink, in the active profile's own directory. `plugin-data/librenms`, which Hermes' helper creates under the process umask, is narrowed to `0700` when this account owns it. The audit log is opened without following a symlink and written only when it is a regular file this account owns with no other hard link (its name is looked up again after the open, so a link planted for the open and removed before the check is caught too), and `audit_log_path` must be absolute, so no process writes users' messages into the directory it happened to start in. Rotation renames the log only when it passes the same checks and creates its successor with `O_EXCL` without following a symlink (with the old file's mode and group: `0600` for one the plugin made; when the account cannot give it the old group, which only root can for a group the account is not in, the group it gets instead has no more access than others, so what the old file let only its group read is never handed to another group); retention deletes only rotated files that are regular files this account owns with one name, so a link or another account's file planted at such a name is neither followed nor deleted. The rotation lock file is opened without following a symlink, used only when it is a regular file this account owns, and never written to. |
| Users' messages pile up on the gateway host | Every audit event can carry the message that triggered the call (`audit_include_request`). The event stream is rotated before it passes `audit_max_mb` (10 MiB) and, while `audit_retention_days` is on, at the first event of each UTC day, and rotated files are deleted once their newest event is `audit_retention_days` old (90) or past the newest `audit_keep_files` (100): after each rotation, at most hourly per profile when the plugin is used, and on `hermes librenms prune`, whether or not `audit_log` is on. Each deletion is audited as `audit_pruned`. A setting that cannot be read is its default, never "keep forever". Where retention cannot run (no `flock`, a lock file the account cannot create or use, a directory it cannot rename the log in), `/librenms status` warns, and `hermes librenms prune` says so and exits 1 rather than reporting nothing to remove. Plan files have `plan_retention_days`. See [docs/audit.md](docs/audit.md#rotation-and-retention). |
| Audit sink credentials end up in `config.yaml`, a log or another host | Hermes' config loader replaces `${VAR}` placeholders in `audit_sinks` with the active profile's secret when the settings are read; a placeholder it leaves (the variable is unset for that profile) refuses the sink, naming only the variable, and no placeholder is read again on the sink thread, where no profile is bound and the environment holds another profile's values. A credential header written into `config.yaml` as a literal is a status warning (read from `config.yaml` as written), and the Desktop's `audit_sink_secret` field stores a collector token in `.env`. Hermes fills the Desktop's settings form from the expanded settings, so a sink that holds a placeholder is edited in `config.yaml`: that form shows the token in clear and saving `audit_sinks` there writes it back as a literal. Each profile has its own sink worker. Sinks follow no redirect, refuse clear text to another machine and unverified TLS unless `allow_insecure_transport`, reach a loopback collector directly and never through a proxy, and refuse a URL with credentials in it; log lines name a sink by its index and kind, never its address, headers or paths. See [docs/sinks.md](docs/sinks.md). |
| The agent's activity cannot be traced | Every audit event carries the actor (platform, chat, user, session, cron job, the user's message), the `config_digest` of the settings in force, the host and the pid; every journal entry records the requests it made. Every string in an event is clipped to 2,000 characters, saying so (a refusal's reason to 500, a rejected plan's description to 200), and a UDP syslog message over 8 KiB is fitted rather than dropped, so text the model pads cannot keep its refused attempts from the collector. Every writer, in every process, holds an exclusive `flock` from its open of the log to its write, and rotation and retention run only under it, so no event is written to a file after it was rotated or deleted with one, and no two processes rotate at once; a writer kept waiting more than two seconds writes without it and does not rotate. Eventlog rows LibreNMS wrote during a run are linked into the plan, maintenance titles and acknowledgement notes carry `[hermes:<plan id>]`, and every request carries `User-Agent: hermes-plugin-librenms/<version>`. See [docs/audit.md](docs/audit.md). |
| One user's words reach another user's session | Plans belong to the profile, and the model of any session of it can read them with `librenms_plans`. Its results show an actor only as how and where it acted (`kind`, `via`, surface, platform, source, profile, chat type, cron job) and the phrase the diff and the journal show, which names the user and the chat by display name only: a name Hermes filled in with an id (an SMS number, a Signal user without a profile name) is left out. The user's message and the sender's, user's, chat's and session's ids stay in the plan file and the audit stream. |
| The plugin's hooks break Hermes | Hook callbacks never raise (Hermes blocks any tool call whose `pre_tool_call` hook raises), and return at once for every tool but their own and the shell tools, whose text they scan in linear time, so a long line cannot stall the agent loop. When the approval hook cannot load a plan, it blocks the call rather than waving it through. |
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
- It does not make the model ignore what it reads. `untrusted_notice` and the skills tell the model
  that text from LibreNMS is data, and escaping shows what a person could not see; a model can
  still be persuaded by text it reads in plain sight. What bounds that is the plan, the approval
  and the gates, not the marker. The plugin's own refusals and errors carry no marker of their
  own, though one may quote LibreNMS: its error message, the hostnames of devices it holds (the
  candidates for an unknown hostname), a plan's `errors`. Those are escaped and clipped like the
  rest, and an error's `librenms` (LibreNMS's answer) is marked.
- It does not tell apart what shows alike. Escaping shows characters that would not show, but
  letters from other scripts that look like Latin ones (a Cyrillic U+0430 for an `a`) are left as
  they are, and an escape (`\u202e`) reads the same as those six characters written in LibreNMS
  (a Windows path, a JSON-encoded log line), so the skills have the model say that a value holds one,
  never decode it.
- It cannot end maintenance. API v0 has no route to end or delete a maintenance schedule, so a
  maintenance step is irreversible: it lasts its whole duration, and the plan says so. To end one
  early, delete the schedule whose title starts with `[hermes:<plan id>]` in LibreNMS (Alerts →
  Scheduled Maintenance). Maintenance notes may also be appended to the device's notes, depending
  on a preference of the token's user.
- It does not keep the token from a model that has a shell. Hermes does not remove a standalone
  plugin's secrets from the environment of its `terminal` tool, and in a single-profile process
  `.env` is loaded into the environment, so a model with `terminal` or `execute_code` on the local
  backend can read `LIBRENMS_TOKEN` and call LibreNMS directly, past every control here. Only the
  token's LibreNMS role bounds that. The same holds for `LIBRENMS_PROXY` and the `LIBRENMS_SNMP_*`
  credentials. Hermes masks a value in a printed environment by the variable's name: the token, and
  the SNMP credential names the plugin accepts (ending in `_SECRET`, `_PASS` or `_PASSWORD`), are
  masked; a password inside `LIBRENMS_PROXY` is not. A model that reads a variable some other way
  (`echo`, a script) sees it whole. The same model can also read and edit the plan files and the
  audit log.
- It does not protect a proxy password on the wire to an `http://` proxy. `requests` sends
  `LIBRENMS_PROXY`'s user name and password as `Proxy-Authorization: Basic` in clear to an
  `http://` proxy, as every client does; `allow_insecure_transport` does not gate it. Use an
  `https://` proxy, or one that needs no password, where the network to the proxy is not trusted.
- It does not see a call made through `ctx.dispatch_tool`. Hermes' plugin API lets another plugin
  call a tool's handler directly, which skips `pre_tool_call` hooks and so the approval prompt. A
  plugin installed beside this one could apply a plan without anyone being asked. `write_mode` is
  checked in the handler and still applies.
- It does not ask when Hermes is set not to. The approval prompt is Hermes' gate under the user's
  approval policy: YOLO mode, `approvals.mode: off`, an earlier "session" or "always" answer for the
  same plan, choice and content, `approvals.cron_mode: approve` (cron jobs),
  `approvals.unattended_mode: approve` (webhook and API-server sessions) and
  `approvals.single_query_mode: approve` (`hermes -q`) all pass it without asking. Each request is
  audited as `approval_requested`, so one passed or blocked without a person shows in the trail
  without an `approval_decided`. With `require_approval: false` in `full` mode, nothing but the
  workflow skill's instruction stands between the model and an apply.
- It does not show the whole plan in the approval prompt. Hermes shows 9 rows of 64 columns of it in
  the CLI panel (it offers no way to see more there), 300 characters on Discord and 500 on Slack and
  Telegram, and the plugin caps it at 1,500. The header and the step lines come first, so every
  surface shows the counts, the irreversible steps and the first steps; a long plan's later steps
  and its field-level diff only `/librenms show <id>` shows. Slack and Discord render the prompt as
  markup and Hermes does not escape it there, so text from LibreNMS in it (a label, an `ifAlias` in
  the diff) can show as emphasis or a link; the CLI, the TUI and Telegram show it as text.
- It does not catch every way to run the CLI from a shell. The rule matches the text of a
  `terminal` command, of `execute_code` code and of what `process_manage` writes to a background
  shell, so an obfuscated command (a variable, a script, an encoding, a command split across several
  writes) passes it; the CLI's check for an agent session reads environment variables a command can
  unset. It cannot read `HERMES_AGENT` or `AI_AGENT` instead: every `hermes` command sets those in
  its own environment, an operator's too. `operator_only` holds against
  a model with a shell only where that shell is in a container or on a remote backend.
- It does not check who runs `/librenms apply`. In `operator_only` mode any chat user who may send
  commands to the gateway can apply or roll back a plan; Hermes' own access controls decide who
  that is. The audit trail records who it was. A plan id there may be shortened to its last four or
  more characters when exactly one plan ends with them; anything shorter, or from the middle of an
  id, names no plan (with one plan saved, `/librenms apply 2` applied it), and the reply says which
  plan a fragment named.
- It does not keep the users of one profile apart. Plans, and Hermes' own session history, belong to
  the profile: `librenms_plans` hides what users wrote and their ids, but Hermes' `session_search`
  tool reaches every session's messages of the profile. Give each person or team that must not read
  another's chats a profile of its own.
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
- It does not detect a plan file edited before the approval prompt is built. The approval is bound
  to the plan as the prompt read it, and a file that changes after that is refused at apply or
  rollback (and asked about again next time), but an edit made between `librenms_plan` and the
  prompt, after the user reviewed the diff in chat, is what the prompt shows and, once approved,
  what runs; the prompt shows each step's fields, not the request body the step will send. Apply
  re-checks the status, URL, age, gates and every step's precondition against live LibreNMS, but
  sends what the file says. An identical plan saved again under the same id has the same digest.
  The handler learns what the prompt showed through Hermes' `modify` directive; on a Hermes without
  it only the approval key binds the answer to the content. Keep `plugin-data` out of reach of any
  file or shell tool the model can use.
- It does not encrypt `plugin-data`. Plan files hold object data as LibreNMS returned it, with SNMP
  credentials masked but services' check parameters kept (rollback needs them), and the audit
  stream holds the users' messages until `audit_retention_days` removes them. Protect the directory
  like the token.
- It does not prune on a clock. `plan_retention_days` and the audit log's retention
  (`audit_keep_files`, `audit_retention_days`) are applied when the plugin is used (a plan made or
  listed, status, any `/librenms` or `hermes librenms` command), at most hourly per profile, and the
  audit log's also after each rotation; a profile nobody uses keeps its plans and rotated audit files
  until then. For a strict retention policy, run `hermes librenms prune` (with `-p <profile>` for a
  named one) from cron; it exits 1 when the audit log's retention could not run or ran only in part.
  A rotated file is deleted once its newest event is past the retention, so a day's events go 90 to
  91 days after they were written at the default.
- It does not delete what a collector, a log shipper or a backup already copied. Retention removes
  the local files only; set the same policy where the events are forwarded.
- It does not make the audit file tamper-proof. The file is written by the account Hermes runs as,
  so anything that account runs can change it. Forward events off the machine (`audit_sinks` or a
  log shipper) and treat that copy as the record. `audit_log: false` stops the sinks as well.
- Its redaction is by key name and by pattern. A credential under a key the list does not name, or
  typed into free text (device notes, `sysDescr`, a syslog line, an alert note, a user's message
  in prose), passes through.
- It does not keep a collector token out of the Desktop's settings form. Hermes fills the form
  from the settings as loaded, with every `${VAR}` in `audit_sinks` replaced by its value, so the
  `audit_sinks` editor shows the token in clear and saving that field writes it into `config.yaml`
  (status then warns about the literal). Once `audit_sinks` holds a placeholder, edit it in
  `config.yaml`; only the masked `audit_sink_secret` field keeps the token hidden.
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
10. **`audit_log_path` pointed at a directory your log shipper watches (an absolute path, the file
    owned by the account Hermes runs as and its only name, in a directory no other account can
    write to), or `audit_sinks` over TLS**
    (`protocol: tls`, or an `https://` collector), with `audit_log` left on beside them; alerts on
    `apply_refused`, `rollback_refused`, `step_failed`, `revert_failed`, `revert_conflict` and
    `run_recovered`, on an `approval_requested` that no `approval_decided` follows, and on any
    `config_digest` you have not approved. `audit_include_request: false` where users paste
    credentials into chat.
11. **Short-lived plans and records**: `max_plan_age_hours` no longer than a review takes,
    `max_operations` a little above what the agent's changes need, `plan_retention_days` matching
    your retention policy for the data plans hold, and `audit_retention_days` matching it for the
    users' messages the audit stream holds (with `audit_keep_files` above it, or `0`; or the
    plugin's rotation off and logrotate's `maxage` in its place), with `hermes librenms prune` in
    cron where that policy is strict.
12. **Collector tokens and SNMP credentials in `.env`**, referenced as `${VAR}` in `audit_sinks` and
    as `{"env": ...}` in plans, never written into `config.yaml` or a chat; `audit_sinks` edited in
    `config.yaml` rather than the Desktop's form once it holds a placeholder; no warning about a
    literal sink credential left in `/librenms status`.
13. **`/librenms status` after every configuration change**, with no warning or settings error left
    unexplained.
