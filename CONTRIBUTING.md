# Contributing

Thanks for helping. This plugin ships as a standalone repository by design: Hermes does not merge
third-party product integrations into its core tree, so this is the place for LibreNMS work.

## Ground rules

- Keep the engine (`client`, `redact`, `routes`, `diff`, `resources/*`, `planner`, `executor`,
  `store`) free of Hermes imports at module load. Hermes imports are lazy and guarded with
  `try/except Exception`. That is what keeps the engine testable without a Hermes checkout.
- Import only what Hermes documents for plugins (`hermes plugins validate` lists the rest). Two
  private imports remain, because Hermes offers no public way to the same data:
  `gateway.session_context.get_session_env` in `audit.py` (the user and chat fields of the actor
  record; the context already gives the surface, profile and cron execution) and
  `hermes_cli.__version__` in `audit.py` (`importlib.metadata.version("hermes-agent")` reports a
  stale version on a git install). Both stay lazy and guarded, so a Hermes that moves them costs
  those fields, not the call. Rebuild anything else from public modules, as `timefmt` does
  `hermes_time.get_timezone`.
- Every write goes through a plan: `planner.build_plan` to build it, `executor.apply_plan` and
  `executor.rollback_plan` to run it. Do not send a non-GET request from anywhere else, and never
  from `librenms_query`, whose routes are GETs only (a GET that changes state, like
  `devices/{hostname}/discover`, is refused there and planned instead).
- Every write path needs a journaled inverse and a test that runs its rollback. Where LibreNMS
  offers no way back, say so with an explicit inverse kind instead: `lossy` (rollback restores what
  the API can write, and the plan says what it cannot), `none` (rollback reports the step
  `irreversible`, the plan lists it under `irreversible` and the approval prompt names it), or
  `not_needed` (the step changes nothing rollback should undo). Each kind comes with the sentence
  the plan shows.
- Every write is verified by re-reading. LibreNMS answers 2xx for writes it ignored or truncated
  (API requests run with `sql_mode=''`, and unknown device fields are dropped silently), so a
  status code proves nothing. A failure after the first write request was sent is settled by a
  re-read: `PartialWrite` with the inverse when LibreNMS changed something or may still be carrying
  the write out (its answer was lost, or a gateway answered), the original error when it answered
  and changed nothing.
- Nothing secret is written into a plan, a journal, an audit event or a tool result. SNMP
  credentials travel as `{"env": "LIBRENMS_SNMP_<NAME>"}` references resolved inside `execute`;
  error text passes through `redact.scrub_text` with the step's sensitive values; tool results go
  through `redact.mask`. The token appears only in the `X-Auth-Token` header.
- Handlers return JSON strings and never raise. Hook callbacks never raise and accept `**kwargs`.
- Settings fail closed: a value that cannot be read becomes the one that lets the model do least,
  and the fallback is recorded in `Settings.errors`.
- Match the existing style: Python 3.10+, `from __future__ import annotations`, type hints, short
  docstrings explaining *why*, comments only where they carry a reason, 120-column lines, no dead
  code, no third-party dependency beyond `requests` (imported lazily).

## Adding or changing a resource

A resource is one module in `resources/` with `RESOURCE = <Subclass>()` at module level. A new one,
or a new operation on an existing one, needs all of:

1. Its name in `RESOURCE_NAMES` (`resources/__init__.py`).
2. `Field` specs for every key the operation accepts, with `create` / `update` / `required` /
   `sensitive` set, and a `note` where LibreNMS may overwrite the value later. Unknown keys are
   errors, never dropped; a key LibreNMS cannot change gets a message that says why.
3. `get`, `find` and `state`. `state()` holds the owned, non-secret fields and the identity, never
   poller data (uptime, status, counters). Fields the poller or discovery may rewrite go in
   `volatile_fields`: they are compared only when the step writes them.
4. The requests (`_create_call`, `_update_call`, `_delete_call`, `_recreate_call`,
   `_execute_action`, `_revert_action`), sent through the `client` the base class passes, so it
   counts writes. Build paths with `path(...)` from `client.py` (each segment percent-encoded),
   using numeric ids once a name is resolved.
5. An `inverse` entry for every op, with its kind and explanation.
6. A gate in `planner.gate_errors` when the operation reaches beyond LibreNMS's own database
   (probes a host, runs a command on the poller) or deletes; gates are checked when planning and
   again when applying, never when rolling back.
7. Fake LibreNMS routes in `tests/fake_librenms.py` for every request it sends, and tests in
   `tests/test_resource_<name>.py`: plan diff and noop, validation errors, precondition conflict,
   execute and verify, a write LibreNMS ignores (verification fails), a failure after the write
   (`PartialWrite`), rollback for each inverse kind, rollback conflict with and without `force`,
   the unknown outcome after a crash, and the gates.
8. The operation vocabulary in `schemas.py` (within the schema size budget `tests/test_version.py`
   checks), the per-resource cheat-sheet in `SKILL.md`, the README's Operations section, and the
   rows in `docs/api-coverage.md`.

## Adding a read route

`routes.ROUTES` lists LibreNMS's GET routes in the order `routes/api.php` registers them, because
LibreNMS answers a path with the first route that matches and several routes shadow later ones.
Add a route in its upstream position, with its envelope key, which path parameters are device
references (resolved to ids before the request), and whether `?hostname=` is honoured. A route
that returns an image, returns secrets, or changes state gets a `refused` reason instead. Add a
test in `tests/test_routes.py` and the row in `docs/api-coverage.md`.

## Workflow

```bash
git clone https://github.com/andrewvieyra/hermes-plugin-librenms ~/.hermes/plugins/librenms
cd ~/.hermes/plugins/librenms
make test
make coverage                     # pip install 'coverage[toml]'
make lint
make doctor                       # needs the hermes CLI on PATH
make validate                     # hermes plugins validate . --install-deps
HERMES_AGENT_ROOT=~/.hermes/hermes-agent make test-hermes
```

Tests use the standard library's `unittest` only: no pytest, no mock library. `make test` runs
against the fake LibreNMS in `tests/fake_librenms.py`. If you need a behaviour the fake does not
model, extend the fake rather than mocking around it, and keep it faithful to what LibreNMS
actually returns: status codes (200 versus 201), envelope shapes, 404 for an empty list, the
message-only answers of most writes, and the quirks the resources work around. Cite the handler in
`includes/html/api_functions.inc.php` or the model you read when the behaviour is surprising.
Write test doubles by hand; a test that patches a module function is testing the patch.

To test against a real LibreNMS, the official Compose setup (`librenms/docker` on GitHub) is the
quickest path. Create an API token for a dedicated user, point `LIBRENMS_URL` and `LIBRENMS_TOKEN`
at it, and use `/librenms status` from a Hermes session.

## Commits and pull requests

- Commit subjects are plain imperative sentences in sentence case, with no type prefix: `Refuse
  the ifName route for names that contain a slash`, `Verify a port description after the write`.
  A doc-only or single-file change may start with the file or area: `SECURITY.md: ...`,
  `docs/architecture.md: ...`, `Tests: ...`. Wrap the body at 72 columns; say why first (name the
  LibreNMS handler when its behaviour is the reason), then what changed, then which tests cover it.
- Write a control character a commit message quotes as its escape (`\u202e`) or its code point
  (U+202E), never raw: a browser showing the commit reorders the line around a bidirectional
  control.
- One change per PR with a short description of the behaviour, not the diff.
- Add a line under `[Unreleased]` in `CHANGELOG.md`.
- CI must be green: tests on every supported Python, ruff clean.

## Reporting security issues

See [SECURITY.md](SECURITY.md).
