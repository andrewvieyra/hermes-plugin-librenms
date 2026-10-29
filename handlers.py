"""Tool handlers: ``handler(args: dict, **kwargs) -> str`` (always a JSON string, never raises), and the hook
callbacks.

Handlers are thin. They parse arguments, obtain a client and the plan store, call the planner or executor, and shape
the result; every result passes through :func:`redact.mask` on its way out. Everything here is also reachable from
the ``/librenms`` slash command and the ``hermes librenms`` CLI through :mod:`commands`.

The hooks put ``librenms_apply`` and ``librenms_rollback`` in front of Hermes' approval prompt with the plan they
would run (``pre_tool_call``, audited as ``approval_requested``), keep the agent's own terminal from running
``hermes librenms apply`` around that prompt (audited as a refusal), remember the user's message for the audit trail
(``pre_llm_call``) and record the human's decision (``post_approval_response``). Hook callbacks never raise.

Named ``handlers`` rather than ``tools`` so the module can never shadow Hermes' own ``tools`` package when the
repository root is on ``sys.path`` (tests, editable checkouts).
"""

from __future__ import annotations

import contextlib
import functools
import hashlib
import json
import logging
import re
import threading
import time
from typing import Any, Callable, Dict, List, Tuple

from . import audit, sinks
from .client import LibreNMSClient, LibreNMSError, insecure_transport, is_configured, is_digits, new_error_id
from .executor import ExecutionRefused, apply_plan, pending_entries, render_journal, rollback_plan
from .planner import PlanError, build_plan, render_plan
from .redact import for_model, mask, one_line, printable
from .routes import QueryError, prepare
from .settings import Settings, get_settings
from .store import PlanStore, get_store, profile_key
from .version import __version__

logger = logging.getLogger(__name__)

WRITE_TOOLS = ("librenms_apply", "librenms_rollback")
APPROVAL_MESSAGE_CHARS = 1500
# What the model is told when its terminal or code runs `hermes librenms apply|rollback`: under write_mode full (with
# approval required) to call the tool, under the other modes what write_gate tells the write tools, and
# TERMINAL_BLOCK when the settings cannot be read.
TERMINAL_BLOCK = (
    "LibreNMS writes do not run from the agent's terminal or code; use the librenms_apply / librenms_rollback "
    "tools, or ask the user to run the command from their own terminal"
)
TERMINAL_BLOCK_FULL = (
    "{action} refused: LibreNMS writes do not run from the agent's terminal or code; call the librenms_{action} "
    "tool, which asks the user for approval"
)
TERMINAL_REASON = "blocked in the agent's terminal/execute_code"
_TRUE = frozenset({"true", "1", "yes", "on"})
_FALSE = frozenset({"false", "0", "no", "off"})
_HOOKED_TOOLS = frozenset({*WRITE_TOOLS, "terminal", "execute_code"})
# `hermes librenms apply|rollback` in a shell command, also with global options before the subcommand and in the
# argument list of code that builds one (["hermes", "librenms", "apply", ...]), and the plan named after it (options
# before it skipped). Defence in depth only: the CLI itself refuses to write from a shell an agent session started.
_CLI_WRITE_RE = re.compile(
    r"\bhermes\b[^\n;|&]*?\blibrenms[\s'\",]+(?P<action>apply|rollback)\b"
    r"(?:(?:[\s'\",]+-[\w-]*)*[\s'\",]+(?P<plan>[A-Za-z0-9_][A-Za-z0-9_.-]{0,79})(?![A-Za-z0-9_.-]))?",
    re.IGNORECASE,
)
# The rule_key pre_tool_call returns, as Hermes reports it back (prefixed "plugin_rule:").
_RULE_KEY_RE = re.compile(
    r"(?:^|:)(?P<key>librenms:(?P<tool>librenms_apply|librenms_rollback):(?P<plan>[^:]+):(?P<variant>[^:]+))$"
)
_MIN_FRAGMENT = 4  # hex digits in a plan id's random suffix
_PRUNE_INTERVAL = 3600.0
# store.profile_key() -> when this process last swept that profile's plans (absent: never)
_last_prune_at: Dict[str, float] = {}
_prune_lock = threading.Lock()
_client_factory: Callable[[], LibreNMSClient] | None = None


def parse_bool(value: Any, default: bool) -> bool:
    """A boolean tool argument: a bool, or true/false, yes/no, on/off, 1/0 as text in any case; anything else is
    *default*. The approval hook and the handlers both read flags through this, so the call a human approved is the
    call that runs."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        text = value.strip().lower()
        if text in _TRUE:
            return True
        if text in _FALSE:
            return False
    return default


def set_client_factory(factory: Callable[[], LibreNMSClient] | None) -> None:
    """Test seam: swap how handlers obtain a client; ``None`` builds it from the environment again."""
    global _client_factory
    _client_factory = factory


def make_client(settings: Settings | None = None) -> LibreNMSClient:
    """A client from the factory seam, else from LIBRENMS_* (clear-text or unverified transport only with the
    operator's ``allow_insecure_transport``). Made per call, never at import or registration."""
    if _client_factory is not None:
        return _client_factory()
    settings = settings if settings is not None else get_settings()
    return LibreNMSClient.from_env(allow_insecure=settings.allow_insecure_transport)


def reset_state() -> None:
    """Test seam: forget the last retention sweeps, so the next call that sweeps runs one."""
    with _prune_lock:
        _last_prune_at.clear()


def check_requirements() -> bool:
    """``check_fn`` for the read tools: exposed only when LIBRENMS_URL and LIBRENMS_TOKEN are set."""
    return is_configured()


def check_write_requirements() -> bool:
    """``check_fn`` for librenms_apply / librenms_rollback: hidden entirely when write_mode is read_only."""
    return is_configured() and get_settings().write_mode != "read_only"


def check_fn(name: str) -> Callable[[], bool]:
    """The ``check_fn`` tool *name* is registered with, marked uncached when Hermes offers that: both checks read
    only the environment and config.yaml, so a write_mode change hides or shows the write tools at once instead of
    after Hermes' 30 s cache."""
    check = check_write_requirements if name in WRITE_TOOLS else check_requirements
    try:
        from tools.registry import no_cache_check_fn  # type: ignore
    except Exception:
        return check
    return no_cache_check_fn(check)


def write_gate(
    actor: Dict[str, Any], action: str, plan_id: str, *, dry_run: bool = False, settings: Settings | None = None
) -> str | None:
    """Enforce ``write_mode``. Returns a refusal message, or None when the write may proceed. ``dry_run`` never
    writes and is always allowed."""
    if dry_run:
        return None
    mode = (settings if settings is not None else get_settings()).write_mode
    if mode == "read_only":
        return (
            f"{action} refused: writes are disabled (write_mode is read_only on this install); queries and plans "
            "still work"
        )
    if mode == "operator_only" and actor.get("kind") != "operator":
        return (
            f"{action} refused: write_mode is operator_only, so the model cannot write. Ask the user to run "
            f"`/librenms {action} {plan_id}` in this session or `hermes librenms {action} {plan_id}` from their own "
            "terminal."
        )
    return None


def find_plan(store: PlanStore, raw: Any) -> Tuple[str | None, Dict[str, Any] | None, List[str]]:
    """``(plan_id, plan, candidates)`` for what a caller named: an exact id, else an unambiguous suffix or substring,
    as :meth:`PlanStore.resolve` matches. The approval hook resolves the same way, so the plan a human approved is
    the plan that runs. A fragment shorter than a plan id's random suffix is not resolved: ``"1"`` would pick
    whichever single plan happens to contain a 1."""
    text = str(raw or "").strip()
    plan_id, candidates = store.resolve(text)
    if plan_id != text and len(text) < _MIN_FRAGMENT:
        plan_id = None
    plan = store.load(plan_id) if plan_id else None
    return (plan_id, plan, candidates) if plan is not None else (None, None, candidates)


def _unknown(raw: Any, candidates: List[str]) -> str:
    shown = str(raw or "").strip()[:80]
    if len(candidates) > 1:
        listed = ", ".join(candidates[:5]) + (", ..." if len(candidates) > 5 else "")
        return f"plan_id {shown!r} matches {len(candidates)} plans ({listed}); pass the full plan_id"
    return f"unknown plan_id {shown!r}"


def journal_summary(journal: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Per-entry summary for tool output (no snapshots or inverse payloads; librenms_plans returns those)."""
    out = []
    for e in journal:
        item = {
            "index": e.get("index"),
            "action": e.get("action"),
            "resource": e.get("resource"),
            "object_id": e.get("object_id"),
            "label": e.get("label"),
            "status": e.get("status"),
            "inverse_kind": e.get("inverse_kind"),
            "http_status": (e.get("request") or {}).get("status"),
        }
        if e.get("error"):
            item["error"] = e["error"]
        if e.get("wrote"):
            item["wrote"] = True
        for key in ("eventlog_ids", "revert_eventlog_ids"):
            if e.get(key) is not None:
                item[key] = e[key]
        if e.get("revert_status"):
            item["revert_status"] = e["revert_status"]
            revert = e.get("revert") or {}
            for key, name in (("error", "revert_error"), ("note", "revert_note"), ("new_object_id", "new_object_id")):
                if revert.get(key) is not None:
                    item[name] = revert[key]
        out.append(item)
    return out


def prune_plans(
    *, days: int | None = None, dry_run: bool = False, actor: Dict[str, Any] | None = None
) -> Dict[str, Any]:
    """Remove plans older than *days* (default ``plan_retention_days``); audited as ``plans_pruned``."""
    max_age = get_settings().plan_retention_days if days is None else int(days)
    removed = get_store().prune(max_age, dry_run=dry_run)
    if removed and not dry_run:
        audit.emit(
            "plans_pruned",
            plan_id=None,
            actor=actor,
            librenms_url=None,
            max_age_days=max_age,
            count=len(removed),
            plan_ids=[r["id"] for r in removed],
        )
    return {"max_age_days": max_age, "dry_run": dry_run, "removed": removed}


def maybe_prune(actor: Dict[str, Any] | Callable[[], Dict[str, Any]]) -> None:
    """Opportunistic retention sweep of the active profile's plans, at most once an hour per profile in this
    process: planning, listing plans, status and every ``/librenms`` or ``hermes librenms`` command call it, so a
    profile that stops planning is still swept. *actor* (or a function making it, called only when a sweep runs)
    is recorded on ``plans_pruned``. Never raises: retention is housekeeping and must not affect the call."""
    with contextlib.suppress(Exception):
        if get_settings().plan_retention_days <= 0:
            return
        key, now = profile_key(), time.monotonic()
        with _prune_lock:
            last = _last_prune_at.get(key)
            if last is not None and now - last < _PRUNE_INTERVAL:
                return
            _last_prune_at[key] = now
        prune_plans(actor=actor() if callable(actor) else actor)


def status_report(settings: Settings | None = None) -> Dict[str, Any]:
    """What ``librenms_query`` action status and ``/librenms status`` show: the LibreNMS version, how the plugin
    reaches it (no host, path or proxy address), the plugin's version and public settings, and what an operator
    should know about them. Raises the client's error when LibreNMS cannot be configured or reached."""
    settings = settings if settings is not None else get_settings()
    client = make_client(settings)
    system = client.system()
    warnings = []
    if settings.allow_insecure_transport:
        problems = insecure_transport(client.base_url, client.verify)
        warnings.append(
            "allow_insecure_transport is on: "
            + ("; ".join(problems) if problems else "LibreNMS is reached over verified https, audit sinks may not be")
        )
    if settings.write_mode == "full" and not settings.require_approval:
        warnings.append(
            "write_mode is full and require_approval is false: the model can apply and roll back plans without "
            "anyone approving them"
        )
    warnings += sinks.literal_credential_warnings()
    return {
        "librenms_url": client.base_url,
        "librenms": for_model(system),
        "transport": client.posture(),
        "plugin_version": __version__,
        "write_mode": settings.write_mode,
        "apply_available": settings.write_mode == "full",  # whether the model's librenms_apply may write
        "settings": settings.public(),
        "settings_errors": list(settings.errors),
        "warnings": warnings,
    }


# -- plumbing -------------------------------------------------------------------------------------


def _json(payload: Dict[str, Any]) -> str:
    """Serialise a tool result. Credential-bearing keys are masked at any depth: steps and journals carry what
    LibreNMS returned (the plan file on disk stays unmasked, rollback needs it)."""
    return json.dumps(mask(payload), ensure_ascii=False, default=str)


def _ok(**payload: Any) -> str:
    return _json({"success": True, **payload})


def _fail(message: str, **extra: Any) -> str:
    return _json({"success": False, "error": message, **extra})


def guarded(fn: Callable[..., str]) -> Callable[..., str]:
    """Convert every exception class the handler can meet into a structured error result. An unexpected one is
    reported by error id only; its message may hold paths or LibreNMS data, so the detail goes to the log."""

    @functools.wraps(fn)
    def wrapper(args: Dict[str, Any] | None = None, **kwargs: Any) -> str:
        try:
            return fn(dict(args or {}), **kwargs)
        except PlanError as exc:
            return _fail("plan not created: fix the listed operations and re-plan", errors=exc.errors)
        except ExecutionRefused as exc:
            return _fail(str(exc), refused=True)
        except LibreNMSError as exc:
            return _fail(str(exc), librenms=exc.to_dict())
        except Exception as exc:  # never let a handler raise into the agent loop
            error_id = new_error_id()
            logger.error("librenms %s: unexpected %s (%s)", fn.__name__, type(exc).__name__, error_id, exc_info=exc)
            return _fail(f"unexpected error {error_id} ({type(exc).__name__}); see the Hermes log")

    return wrapper


def _int(value: Any, default: int, *, minimum: int = 1, maximum: int | None = None) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = default
    if maximum is not None:
        number = min(number, maximum)
    return max(minimum, number)


def _actor_from(kwargs: Dict[str, Any]) -> Dict[str, Any]:
    """Operator paths (slash command, CLI) pass a ready-made ``_actor``; a model tool call gets one captured from
    Hermes' session context plus the ``task_id`` / ``session_id`` kwargs it passes. The model controls ``args``
    only, so it can never claim to be an operator."""
    given = kwargs.get("_actor")
    return dict(given) if isinstance(given, dict) else audit.capture_actor(kwargs, via=audit.VIA_MODEL)


def _plan_summary(plan: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "plan_id": plan["id"],
        "status": plan["status"],
        "description": plan.get("description", ""),
        "created_at": plan.get("created_at"),
        "summary": plan.get("summary", {}),
        "librenms_url": plan.get("librenms_url"),
    }


def _rollback_summary(rb: Dict[str, Any] | None) -> Dict[str, Any] | None:
    if not rb:
        return None
    keys = (
        "started_at",
        "finished_at",
        "reason",
        "force",
        "entries",
        "reverted",
        "conflict",
        "failed",
        "irreversible",
        "skipped",
        "recovered",
        "eventlog",
    )
    return {k: rb.get(k) for k in keys}


def _project(value: Any, fields: List[str] | None) -> Any:
    if fields and isinstance(value, dict):
        return {key: value[key] for key in fields if key in value}
    return value


def _listing(rows: List[Any], body: Any, fields: List[str] | None, limit: int, start: int) -> Dict[str, Any]:
    """*rows* as a tool result. ``truncated`` says whether more rows exist than were shown: past the client-side
    limit, or (logs routes) past *start* plus what this page returned."""
    if len(rows) == 1 and isinstance(rows[0], list):  # LibreNMS wraps service rows in one more list
        rows = rows[0]
    shown = [_project(row, fields) for row in rows[:limit]]
    out: Dict[str, Any] = {"count": len(rows)}
    total = body.get("total") if isinstance(body, dict) else None
    if is_digits(total):  # logs routes: every matching row, of which ``count`` were returned from ``start`` on
        out["total"] = int(total)
    more = "total" in out and out["total"] > start + len(rows)
    out.update(returned=len(shown), truncated=len(shown) < len(rows) or more, results=for_model(shown))
    return out


# -- handlers -------------------------------------------------------------------------------------


@guarded
def librenms_query(args: Dict[str, Any], **kwargs: Any) -> str:
    settings = get_settings()
    action = str(args.get("action") or "get").strip().lower()
    if action == "status":
        maybe_prune(lambda: _actor_from(kwargs))
        return _ok(**status_report(settings))
    if action != "get":
        return _fail(f"action must be get or status (got {action[:40]!r})")
    fields = args.get("fields")
    if fields is not None and not (isinstance(fields, list) and all(isinstance(f, str) for f in fields)):
        return _fail("fields must be a list of key names")
    client = make_client(settings)
    raw_path = args.get("path")
    try:
        prepared = prepare(
            client, "" if raw_path is None else raw_path, args.get("params"), args.get("limit"), settings
        )
    except QueryError as exc:
        audit.emit(
            "query_refused",
            plan_id=None,
            actor=_actor_from(kwargs),
            librenms_url=client.base_url,
            path=str(raw_path or "")[:200],
            reason=str(exc),
        )
        return _fail(str(exc), refused=True)
    route = prepared.route
    where = {"path": prepared.path, "route": route.name}
    try:
        body = client.get(prepared.request_path, prepared.params or None)
    except LibreNMSError as exc:
        if exc.kind != "not_found":
            raise
        # LibreNMS answers an empty list with a 404 and a message ("No ports found")
        note = exc.body.get("message") if isinstance(exc.body, dict) else None
        return _ok(**where, count=0, returned=0, truncated=False, results=[], note=for_model(note or str(exc)))
    value = LibreNMSClient.result(body, route.list_key) if route.list_key else body
    if isinstance(value, list):
        start = int(prepared.params["start"]) if route.paginated else 0
        return _ok(**where, **_listing(value, body, fields, prepared.limit, start))
    return _ok(**where, result=for_model(_project(value, fields)))


@guarded
def librenms_plan(args: Dict[str, Any], **kwargs: Any) -> str:
    settings = get_settings()
    client = make_client(settings)
    actor = _actor_from(kwargs)
    description = str(args.get("description") or "")
    operations = args.get("operations")
    try:
        plan = build_plan(client, operations, description, settings, client.base_url, actor=actor)
    except PlanError as exc:
        audit.emit(
            "plan_rejected",
            plan_id=None,
            actor=actor,
            librenms_url=client.base_url,
            description=description,
            operations=len(operations) if isinstance(operations, list) else None,
            errors=len(exc.errors),
            first_error=exc.errors[0].get("error") if exc.errors else None,
        )
        raise
    get_store().create(plan)  # may give the plan a new id on a collision: read plan["id"] only after this
    maybe_prune(actor)
    audit.emit(
        "plan_created",
        plan_id=plan["id"],
        actor=actor,
        librenms_url=plan["librenms_url"],
        description=plan["description"],
        summary=plan["summary"],
        steps=len(plan["steps"]),
        warnings=len(plan["warnings"]),
        irreversible=plan["irreversible"],
    )
    summary = plan["summary"]
    if sum(summary.get(key, 0) for key in ("create", "update", "delete", "action")) == 0:
        next_step = "Nothing to apply: every operation already matches LibreNMS."
    else:
        next_step = "Show this diff to the user and call librenms_apply only after they explicitly say yes."
        if plan["irreversible"]:
            next_step += f" Tell them that steps {plan['irreversible']} cannot be rolled back."
    return _ok(
        **_plan_summary(plan),
        diff=render_plan(plan),
        steps=plan["steps"],
        warnings=plan["warnings"],
        irreversible=plan["irreversible"],
        next_step=next_step,
    )


@guarded
def librenms_apply(args: Dict[str, Any], **kwargs: Any) -> str:
    store = get_store()
    actor = _actor_from(kwargs)
    _plan_id, plan, candidates = find_plan(store, args.get("plan_id"))
    if plan is None:
        reason = _unknown(args.get("plan_id"), candidates)
        audit.emit("apply_refused", plan_id=None, actor=actor, librenms_url=None, reason=reason)
        return _fail(reason)
    settings = get_settings()
    dry_run = parse_bool(args.get("dry_run"), False)
    refusal = write_gate(actor, "apply", plan["id"], dry_run=dry_run, settings=settings)
    if refusal:
        audit.emit(
            "apply_refused",
            plan_id=plan["id"],
            actor=actor,
            librenms_url=plan.get("librenms_url"),
            reason=refusal,
            dry_run=dry_run,
            write_mode=settings.write_mode,
        )
        return _fail(refusal, refused=True, write_mode=settings.write_mode)
    client = make_client(settings)
    rollback = parse_bool(args.get("rollback_on_failure"), True)
    try:
        plan = apply_plan(client, plan, store, settings, rollback_on_failure=rollback, dry_run=dry_run, actor=actor)
    except ExecutionRefused as exc:
        audit.emit(
            "apply_refused",
            plan_id=plan["id"],
            actor=actor,
            librenms_url=plan.get("librenms_url"),
            reason=str(exc),
            dry_run=dry_run,
        )
        raise
    if dry_run:
        checks = plan.get("checks") or []
        if plan.get("status") != "planned" or not checks:  # claimed by another run while the checks ran
            return _fail(f"plan {plan['id']} is {plan.get('status')}; the check was not recorded", refused=True)
        conflicts = checks[-1]["conflicts"]
        return _ok(**_plan_summary(plan), dry_run=True, applicable=not conflicts, conflicts=conflicts)
    apply = plan.get("apply") or {}
    payload = {
        "success": apply.get("outcome") == "applied",
        **_plan_summary(plan),
        "outcome": apply.get("outcome"),
        "failure": apply.get("failure"),
        "eventlog": apply.get("eventlog"),
        "rollback": _rollback_summary(plan.get("rollback")),
        "journal": journal_summary(plan["journal"]),
        "report": render_journal(plan),
    }
    if apply.get("auto_rollback_error"):
        payload["auto_rollback_error"] = apply["auto_rollback_error"]
    return _json(payload)


@guarded
def librenms_rollback(args: Dict[str, Any], **kwargs: Any) -> str:
    store = get_store()
    actor = _actor_from(kwargs)
    _plan_id, plan, candidates = find_plan(store, args.get("plan_id"))
    if plan is None:
        reason = _unknown(args.get("plan_id"), candidates)
        audit.emit("rollback_refused", plan_id=None, actor=actor, librenms_url=None, reason=reason)
        return _fail(reason)
    settings = get_settings()
    force = parse_bool(args.get("force"), False)
    refusal = write_gate(actor, "rollback", plan["id"], settings=settings)
    if refusal:
        audit.emit(
            "rollback_refused",
            plan_id=plan["id"],
            actor=actor,
            librenms_url=plan.get("librenms_url"),
            reason=refusal,
            force=force,
            write_mode=settings.write_mode,
        )
        return _fail(refusal, refused=True, write_mode=settings.write_mode)
    client = make_client(settings)
    try:
        plan = rollback_plan(client, plan, store, settings, force=force, reason="requested", actor=actor)
    except ExecutionRefused as exc:
        audit.emit(
            "rollback_refused",
            plan_id=plan["id"],
            actor=actor,
            librenms_url=plan.get("librenms_url"),
            reason=str(exc),
            force=force,
        )
        raise
    rb = plan.get("rollback") or {}
    return _json(
        {
            "success": plan["status"] == "rolled_back",
            **_plan_summary(plan),
            "rollback": _rollback_summary(rb),
            "journal": journal_summary(plan["journal"]),
            "report": render_journal(plan),
        }
    )


@guarded
def librenms_plans(args: Dict[str, Any], **kwargs: Any) -> str:
    maybe_prune(lambda: _actor_from(kwargs))
    store = get_store()
    if str(args.get("plan_id") or "").strip():
        _plan_id, plan, candidates = find_plan(store, args.get("plan_id"))
        if plan is None:
            return _fail(_unknown(args.get("plan_id"), candidates))
        return _ok(
            **_plan_summary(plan),
            diff=render_plan(plan),
            steps=plan["steps"],
            warnings=plan.get("warnings", []),
            irreversible=plan.get("irreversible", []),
            checks=plan.get("checks", []),
            journal=plan.get("journal", []),
            apply=plan.get("apply"),
            rollback=plan.get("rollback"),
            report=render_journal(plan),
        )
    limit = _int(args.get("limit"), 20, maximum=200)
    status = args.get("status")
    plans = store.list(status=str(status) if status else None, limit=limit)
    return _ok(count=len(plans), plans=[_plan_summary(p) for p in plans])


HANDLERS = {
    "librenms_query": librenms_query,
    "librenms_plan": librenms_plan,
    "librenms_apply": librenms_apply,
    "librenms_rollback": librenms_rollback,
    "librenms_plans": librenms_plans,
}


# -- hooks ----------------------------------------------------------------------------------------


def pre_tool_call(tool_name: Any = None, args: Any = None, **kwargs: Any) -> Dict[str, Any] | None:
    """Hermes ``pre_tool_call``: fires for every tool call, so anything but our two write tools and the agent's
    terminal returns at once, without reading settings or plans. A callback that raises would block the call it
    was asked about, so neither branch raises; when in doubt they ask a human (apply, rollback) or block (terminal).
    An approval asked for is audited as ``approval_requested``: Hermes may refuse it (cron, unattended platforms)
    without a ``post_approval_response``, and the attempt must still show in the trail."""
    if not isinstance(tool_name, str) or tool_name not in _HOOKED_TOOLS:
        return None
    if tool_name not in WRITE_TOOLS:
        return _terminal_guard(tool_name, args, kwargs)
    directive = _approval(tool_name, args)
    if directive is not None:
        found = _RULE_KEY_RE.search(directive["rule_key"])
        plan_id = found.group("plan") if found is not None and found.group("plan") != "unresolved" else None
        _audit_hook("approval_requested", kwargs, plan_id, None, tool=tool_name, rule_key=directive["rule_key"])
    return directive


def _audit_hook(
    event: str, hook_kwargs: Dict[str, Any], plan_id: str | None, librenms_url: str | None, **details: Any
) -> None:
    """Audit what a hook decided, as the model's act (Hermes passes the hook its ``task_id`` and ``session_id``).
    A hook never raises, so neither does this."""
    try:
        actor = audit.capture_actor(hook_kwargs, via=audit.VIA_MODEL)
        audit.emit(event, plan_id=plan_id, actor=actor, librenms_url=librenms_url, **details)
    except Exception as exc:
        logger.warning("librenms hook audit failed: %s", type(exc).__name__)


def _approval(tool: str, args: Any) -> Dict[str, Any] | None:
    """``approve`` with the rendered plan (apply) or journal (rollback) when ``require_approval`` is on in ``full``
    mode; in the other modes the handler refuses the model and audits it. The rule_key names the canonical plan id
    and the flag that changes what runs, so an "always" answer never carries over to another plan or variant."""
    raw = ""
    try:
        settings = get_settings()
        if not settings.require_approval or settings.write_mode != "full":
            return None
        raw = str(args.get("plan_id") or "")
        if tool == "librenms_apply" and parse_bool(args.get("dry_run"), False):
            return None
        plan_id, plan, _candidates = find_plan(get_store(), raw)
        if plan_id is None or plan is None:  # the handler will refuse it; still ask rather than let it through
            return _unresolved(tool, raw, "It was not found locally, so what it would change is unknown.")
        if tool == "librenms_apply":
            rollback = parse_bool(args.get("rollback_on_failure"), True)
            summary = plan.get("summary") or {}
            counts = ", ".join(f"{summary.get(key, 0)} {key}" for key in ("create", "update", "delete", "action"))
            irreversible = ", ".join(str(index) for index in plan.get("irreversible") or [])
            header = (
                f"Apply LibreNMS plan {plan_id} to {plan.get('librenms_url')}: {counts}; irreversible steps "
                f"[{irreversible}]; rollback_on_failure={'true' if rollback else 'false'}"
            )
            body, variant = _approval_plan(plan), "rb" if rollback else "norb"
        else:
            force = parse_bool(args.get("force"), False)
            header = f"Roll back LibreNMS plan {plan_id} ({len(pending_entries(plan))} pending entries"
            header += ", FORCE: overwrites edits made after the apply)" if force else ")"
            body, variant = render_journal(plan), "force" if force else "safe"
        return {
            "action": "approve",
            "message": _approval_message(header, body, plan_id),
            "rule_key": f"librenms:{tool}:{plan_id}:{variant}",
        }
    except Exception as exc:
        error_id = new_error_id()
        logger.warning("librenms approval hook: plan details not loaded (%s)", error_id, exc_info=exc)
        return _unresolved(tool, raw, f"Plan details could not be loaded ({error_id}).")


def _unresolved(tool: str, raw: str, sentence: str) -> Dict[str, Any]:
    digest = hashlib.sha256(raw.encode("utf-8", "surrogatepass")).hexdigest()[:12]
    return {
        "action": "approve",
        "message": printable(f"Approve {tool} for plan {raw[:80]}? {sentence}"),
        "rule_key": f"librenms:{tool}:unresolved:{digest}",
    }


def _approval_plan(plan: Dict[str, Any]) -> str:
    """The diff an apply approval shows: the plan's description, free text the model wrote, comes last and on one
    line, so it can neither pass for step lines nor push them past the clip."""
    body = render_plan({**plan, "description": ""})
    return f"{body}\nDescription: {one_line(plan['description'])}" if plan.get("description") else body


def _approval_message(header: str, body: str, plan_id: str) -> str:
    """Header, then as many whole lines of *body* as fit in :data:`APPROVAL_MESSAGE_CHARS`, then how many were left
    out. Escaped first: labels, notes and descriptions come from LibreNMS and the model, and must not be able to
    rewrite what the human reads in a terminal approval prompt."""
    header, lines = printable(header), printable(body).split("\n")
    text = "\n".join([header, *lines])
    if len(text) <= APPROVAL_MESSAGE_CHARS:
        return text
    shown_id = printable(plan_id)
    kept: List[str] = []
    used = len(header)
    for line in lines:
        tail = f"\n… {len(lines) - len(kept) - 1} more lines; run /librenms show {shown_id}"
        if used + 1 + len(line) + len(tail) > APPROVAL_MESSAGE_CHARS:
            break
        kept.append(line)
        used += 1 + len(line)
    return "\n".join([header, *kept]) + f"\n… {len(lines) - len(kept)} more lines; run /librenms show {shown_id}"


def _terminal_guard(tool: str, args: Any, hook_kwargs: Dict[str, Any]) -> Dict[str, Any] | None:
    """Block ``hermes librenms apply|rollback`` in the agent's terminal or code unless the operator lets the model
    write without approval anyway: run there, it would skip the approval prompt and act as an operator. The model is
    told what it may do instead under this write_mode, and the attempt is audited as ``apply_refused`` /
    ``rollback_refused`` naming the tool and the plan, never the command text."""
    message = TERMINAL_BLOCK
    try:
        values = args.values() if isinstance(args, dict) else [args]
        found = _CLI_WRITE_RE.search("\n".join(value for value in values if isinstance(value, str)))
        if found is None:
            return None
        settings = get_settings()
        if settings.write_mode == "full" and not settings.require_approval:
            return None
        action, ref = found.group("action").lower(), found.group("plan")
        plan_id, plan = None, None
        with contextlib.suppress(Exception):  # the block and its audit never depend on the plan store
            plan_id, plan, _candidates = find_plan(get_store(), ref) if ref else (None, None, [])
        named = plan_id or ref
        message = write_gate({"kind": "model"}, action, named or "<plan_id>", settings=settings)
        message = message or TERMINAL_BLOCK_FULL.format(action=action)
        _audit_hook(
            f"{action}_refused",
            hook_kwargs,
            named,
            (plan or {}).get("librenms_url"),
            reason=TERMINAL_REASON,
            tool=tool,
            write_mode=settings.write_mode,
        )
    except Exception as exc:
        logger.warning("librenms terminal hook: blocking after %s", type(exc).__name__)
    return {"action": "block", "message": message}


def pre_llm_call(**kwargs: Any) -> None:
    """Hermes ``pre_llm_call``: remember the user's message for this session so the audit trail can say what the
    model was asked when it plans or applies. Injects nothing."""
    with contextlib.suppress(Exception):
        audit.remember_request(
            kwargs.get("session_id"), kwargs.get("task_id"), kwargs.get("user_message"), kwargs.get("sender_id")
        )
    return None


def post_approval_response(**kwargs: Any) -> None:
    """Hermes ``post_approval_response``: audit the human's answer to an approval about LibreNMS (our rule keys, or a
    command that mentions librenms) as ``approval_decided``. Records the choice, tool and plan id, never the command
    text."""
    try:
        keys = [str(key) for key in [kwargs.get("pattern_key"), *(kwargs.get("pattern_keys") or [])] if key]
        ours = next((found for found in map(_RULE_KEY_RE.search, keys) if found), None)
        mentioned = "librenms" in str(kwargs.get("command") or "").lower() or any("librenms" in k.lower() for k in keys)
        if ours is None and not mentioned:
            return None
        plan_id = ours.group("plan") if ours is not None and ours.group("plan") != "unresolved" else None
        where = {"rule_key": ours.group("key")} if ours is not None else {"pattern_key": keys[0] if keys else None}
        audit.emit(
            "approval_decided",
            plan_id=plan_id,
            actor=audit.capture_actor({}, via=audit.VIA_MODEL),
            librenms_url=None,
            choice=kwargs.get("choice"),
            tool=ours.group("tool") if ours is not None else None,
            decided_by=kwargs.get("decided_by"),
            surface=kwargs.get("surface"),
            **where,
        )
    except Exception as exc:
        logger.warning("librenms approval audit failed: %s", type(exc).__name__)
    return None


HOOKS = {
    "pre_tool_call": pre_tool_call,
    "pre_llm_call": pre_llm_call,
    "post_approval_response": post_approval_response,
}
