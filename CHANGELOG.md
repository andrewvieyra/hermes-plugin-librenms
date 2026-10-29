# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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
