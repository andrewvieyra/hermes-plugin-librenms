"""Tool handlers: ``handler(args: dict, **kwargs) -> str`` (always a JSON string, never raises), and the hook
callbacks.

Handlers are thin. They parse arguments, obtain a client and the plan store, call the planner or executor, and shape
the result; every result passes through :func:`redact.mask` on its way out. Everything here is also reachable from
the ``/librenms`` slash command and the ``hermes librenms`` CLI through :mod:`commands`.

The hooks put ``librenms_apply`` and ``librenms_rollback`` in front of Hermes' approval prompt with a summary of the
plan they would run (``pre_tool_call``, audited as ``approval_requested``; a plan id that names no saved plan is
blocked instead), keep the agent's own terminal, code and background shells from running ``hermes librenms apply``
around that prompt (audited as a refusal), remember the user's message for the audit trail (``pre_llm_call``) and
record the human's decision (``post_approval_response``). Hook callbacks never raise.

Named ``handlers`` rather than ``tools`` so the module can never shadow Hermes' own ``tools`` package when the
repository root is on ``sys.path`` (tests, editable checkouts).
"""

from __future__ import annotations

import contextlib
import functools
import json
import logging
import re
import threading
import time
from typing import Any, Callable, Dict, List, Tuple

from . import audit, sinks
from .client import LibreNMSClient, LibreNMSError, insecure_transport, is_configured, is_digits, new_error_id
from .executor import ExecutionRefused, apply_plan, pending_entries, render_journal, rollback_plan
from .planner import DESCRIPTION_CHARS, PlanError, build_plan, render_plan
from .redact import clip, for_model, mask, one_line
from .resources import get_resource
from .routes import QueryError, Route, prepare, too_large_hint
from .settings import Settings, get_settings
from .store import PlanStore, get_store, plan_status, profile_key
from .version import __version__

logger = logging.getLogger(__name__)

WRITE_TOOLS = ("librenms_apply", "librenms_rollback")
# The approval message: at most APPROVAL_MESSAGE_CHARS in all, every line cut to APPROVAL_LINE_CHARS and a label to
# APPROVAL_LABEL_CHARS (as escaped), so no text from LibreNMS or the model can take the room the steps need. Hermes
# shows far less than the whole message: its CLI panel 9 rows of 64 columns, Discord 300 characters, Slack and
# Telegram 500.
APPROVAL_MESSAGE_CHARS = 1500
APPROVAL_LINE_CHARS = 120
APPROVAL_LABEL_CHARS = 40
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
# The shell tools: a command (terminal), code (execute_code), and what process_manage writes to the stdin of a
# shell that terminal(background=true) started, which Hermes runs no command guard on.
_SHELL_TOOLS = frozenset({"terminal", "execute_code", "process_manage"})
_STDIN_ACTIONS = frozenset({"write", "submit"})
_HOOKED_TOOLS = frozenset({*WRITE_TOOLS, *_SHELL_TOOLS})
# `librenms apply|rollback` in a shell command, also in the argument list of code that builds one (["hermes",
# "librenms", "apply", ...]), and the plan named after it (options before it skipped); _cli_write looks for the word
# hermes before it in the same command, global options allowed in between. Defence in depth only: the CLI itself
# refuses to write from a shell an agent session started.
_CLI_WRITE_RE = re.compile(
    r"\blibrenms[\s'\",]+(?P<action>apply|rollback)\b"
    r"(?:(?:[\s'\",]+-[\w-]*)*[\s'\",]+(?P<plan>[A-Za-z0-9_][A-Za-z0-9_.-]{0,79})(?![A-Za-z0-9_.-]))?",
    re.IGNORECASE,
)
_HERMES_RE = re.compile(r"\bhermes\b", re.IGNORECASE)
_COMMAND_SEPARATORS = "\n;|&"
# The rule_key pre_tool_call returns, as Hermes reports it back (prefixed "plugin_rule:"). 0.1.1 and earlier also
# returned "librenms:<tool>:unresolved:<digest>", which a remembered answer can still carry.
_RULE_KEY_RE = re.compile(
    r"(?:^|:)(?P<key>librenms:(?P<tool>librenms_apply|librenms_rollback):(?P<plan>[^:]+):(?P<variant>[^:]+))$"
)
_COUNTED = ("create", "update", "delete", "action")
# Envelope keys that carry no data of their own: LibreNMS's api_success puts them around every result.
_ENVELOPE_KEYS = frozenset({"status", "message", "count", "total"})
# What a fault or alert-log row shows of the rows its rule matched (``details.rule``): the keys that name the port,
# sensor, processor, storage, service or BGP peer it is about, at most ENTITY_ROWS rows of ENTITY_CHARS each.
# ``details`` itself holds every column of every table the rule joins and the alert's contacts (e-mail addresses),
# for every matched row, so it is returned only when ``fields`` names it, and never with its contacts.
ENTITY_KEYS = (
    "ifName",
    "ifAlias",
    "ifDescr",
    "sensor_descr",
    "sensor_class",
    "sensor_current",
    "processor_descr",
    "mempool_descr",
    "storage_descr",
    "service_type",
    "service_desc",
    "bgpPeerIdentifier",
    "bgpPeerDescr",
)
ENTITY_ROWS = 10
ENTITY_CHARS = 200
# "[12] note" in a plan's warnings: the step the warning is about
_STEP_WARNING_RE = re.compile(r"^\[(\d+)\] ")
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


def find_plan(
    store: PlanStore, raw: Any, *, exact: bool = False
) -> Tuple[str | None, Dict[str, Any] | None, List[str]]:
    """``(plan_id, plan, candidates)`` for what a caller named: an exact id, else (unless *exact*) the end of one, as
    :meth:`PlanStore.resolve` matches. ``librenms_apply``, ``librenms_rollback`` and their approval hook take only an
    exact id, so the plan a human approved is the plan that runs: a fragment resolved again after the prompt could
    name a plan created while it was open. *candidates* still lists what a fragment matches, for the refusal."""
    text = str(raw or "").strip()
    plan_id, candidates = store.resolve(text)
    if exact and plan_id != text:
        plan_id = None
    plan = store.load(plan_id) if plan_id else None
    return (plan_id, plan, candidates) if plan is not None else (None, None, candidates)


def _unknown(raw: Any, candidates: List[str]) -> str:
    shown = str(raw or "").strip()[:80]
    if len(candidates) > 1:
        listed = ", ".join(candidates[:5]) + (", ..." if len(candidates) > 5 else "")
        return f"plan_id {shown!r} matches {len(candidates)} plans ({listed}); pass the full plan_id"
    if candidates and candidates[0] != shown:
        return f"plan_id {shown!r} is only the end of {candidates[0]}; pass the full plan_id"
    return f"unknown plan_id {shown!r}"


def journal_summary(journal: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Per-entry summary for tool output (no snapshots or inverse payloads; librenms_plans with ``detail`` returns
    those)."""
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
    should know about them. When LibreNMS cannot be configured or reached, ``connection`` says why (``ok`` false,
    the client's scrubbed ``error`` and its ``kind``) and ``librenms`` is None; everything else is still there,
    because that is when the operator needs it: a mistyped ``write_mode`` read as ``read_only`` explains a refused
    apply only if status shows it."""
    settings = settings if settings is not None else get_settings()
    client: LibreNMSClient | None = None
    system: Dict[str, Any] | None = None
    connection: Dict[str, Any] = {"ok": True}
    try:
        client = make_client(settings)
        system = client.system()
    except LibreNMSError as exc:
        connection = {"ok": False, "error": str(exc), "kind": exc.kind}
    warnings = []
    if settings.allow_insecure_transport:
        if client is None:
            posture = "LibreNMS and audit sinks may be reached over plain or unverified transports"
        else:
            problems = insecure_transport(client.base_url, client.verify)
            posture = "; ".join(problems) or "LibreNMS is reached over verified https, audit sinks may not be"
        warnings.append(f"allow_insecure_transport is on: {posture}")
    if settings.write_mode == "full" and not settings.require_approval:
        warnings.append(
            "write_mode is full and require_approval is false: the model can apply and roll back plans without "
            "anyone approving them"
        )
    warnings += sinks.literal_credential_warnings()
    return {
        "librenms_url": client.base_url if client is not None else None,
        "librenms": for_model(system) if system is not None else None,
        "connection": connection,
        "transport": client.posture() if client is not None else None,
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
            failed = {"success": False, "error": "plan not created: fix the listed operations and re-plan"}
            budget = _budget(get_settings(), kwargs)
            return _json(_fit_rows({**failed, "errors": exc.errors}, "errors", budget, _errors_note(budget)))
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
    """A plan's identity, status and counts. A hand-edited or damaged file may lack any key or hold another type:
    its status reads ``unknown`` (:func:`plan_status`, which the ``status`` filter goes by too) and its counts as
    none, so one such file cannot break the listing an operator uses to find a plan to roll back
    (:meth:`PlanStore.list` gives each plan the id its file is named by)."""
    summary = plan.get("summary")
    return {
        "plan_id": plan.get("id"),
        "status": plan_status(plan),
        "description": plan.get("description", ""),
        "created_at": plan.get("created_at"),
        "summary": summary if isinstance(summary, dict) else {},
        "librenms_url": plan.get("librenms_url"),
    }


def _rollback_summary(rb: Dict[str, Any] | None, entries: List[Dict[str, Any]], compact: bool) -> Dict[str, Any] | None:
    """A rollback record for apply and rollback results, its eventlog cut to the shown journal *entries*."""
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
    summary = {k: rb.get(k) for k in keys}
    summary["eventlog"] = _eventlog(summary["eventlog"], entries, "revert_eventlog_ids", compact)
    return summary


def _public(record: Any) -> Any:
    """A run or check record of a plan for a tool result, its actor in public form (:func:`audit.public_actor`)."""
    if isinstance(record, dict) and "actor" in record:
        return {**record, "actor": audit.public_actor(record["actor"])}
    return record


def _project(value: Any, fields: List[str] | None) -> Any:
    if fields and isinstance(value, dict):
        return {key: value[key] for key in fields if key in value}
    return value


def _budget(settings: Settings, kwargs: Dict[str, Any]) -> int | None:
    """The most characters a result may serialise to: ``max_result_chars`` for the model, since Hermes replaces a
    larger one with a 1,500-character preview and a file (its threshold is 100,000 characters, less on a model with
    a small context window); none on an operator path (``_actor``), which prints the whole result."""
    return None if isinstance(kwargs.get("_actor"), dict) else settings.max_result_chars


def _size(value: Any) -> int:
    """Characters *value* takes in a tool result (:func:`_json`)."""
    return (
        len(_json(value)) if isinstance(value, dict) else len(json.dumps(mask(value), ensure_ascii=False, default=str))
    )


def _fit_rows(payload: Dict[str, Any], key: str, budget: int | None, note: Callable[[int, int], str]) -> Dict[str, Any]:
    """*payload* with as many leading entries of its list *key* as keep it within *budget* characters serialised (all
    of them without a budget). When some are left out, ``returned`` is the number kept, ``truncated`` is true and
    ``note`` says how to see the rest: *note* is given the number kept and the number there were."""
    rows = payload.get(key)
    if budget is None or not isinstance(rows, list) or _size(payload) <= budget:
        return payload
    out = {**payload, key: [], "returned": 0, "truncated": True, "note": note(len(rows), len(rows))}
    room, kept = budget - _size(out), 0
    for row in rows:
        room -= _size(row) + (2 if kept else 0)  # json.dumps separates list items with ", "
        if room < 0:
            break
        kept += 1
    while True:
        out.update({key: rows[:kept], "returned": kept, "note": note(kept, len(rows))})
        if kept == 0 or _size(out) <= budget:
            return out
        kept -= 1


def _errors_note(budget: int | None) -> Callable[[int, int], str]:
    return lambda kept, of: (
        f"{kept} of {of} errors shown, to stay within max_result_chars ({budget} characters); fix these and plan "
        "again to see the rest"
    )


def _conflicts_note(kept: int, of: int) -> str:
    return (
        f"{kept} of {of} conflicts shown, to stay within max_result_chars; librenms_plans with this plan_id and an "
        "offset shows the checks of later steps"
    )


def _plans_note(kept: int, of: int) -> str:
    return f"{kept} of {of} plans shown, to stay within max_result_chars; filter by status or ask for fewer with limit"


def _query_note(route: Route, budget: int | None, start: int) -> Callable[[int, int], str]:
    def note(kept: int, of: int) -> str:
        text = (
            f"cut at {kept} of {of} rows to stay within max_result_chars ({budget} characters): name only the keys "
            "you need in fields"
        )
        if route.paginated:
            return text + f", or read on with params start={start + kept}"
        return text + ", or narrow the query (a smaller limit returns the same first rows)"

    return note


def _alert_row(row: Any, keep_details: bool) -> Any:
    """A fault or alert-log row with ``details`` replaced by ``entities``: the label keys (:data:`ENTITY_KEYS`) of the
    rows its rule matched, so "what is alerting" names the port or sensor without the blob. With *keep_details*
    (``fields`` names it) ``details`` stays too, without its ``contacts``."""
    if not isinstance(row, dict) or "details" not in row:
        return row
    row = dict(row)
    details = row.pop("details")
    matched = details.get("rule") if isinstance(details, dict) else None
    entities: List[Dict[str, Any]] = []
    seen = set()
    for item in matched if isinstance(matched, list) else []:
        labels = {key: clip(item[key], ENTITY_CHARS) for key in ENTITY_KEYS if isinstance(item, dict) and item.get(key)}
        seen_as = json.dumps(labels, sort_keys=True, default=str)
        if labels and seen_as not in seen:  # a rule over joined tables repeats a port once per joined row
            seen.add(seen_as)
            if len(entities) < ENTITY_ROWS:
                entities.append(labels)
    row["entities"] = entities
    if len(seen) > ENTITY_ROWS:
        row["entities_total"] = len(seen)
    if keep_details:
        row["details"] = {k: v for k, v in details.items() if k != "contacts"} if isinstance(details, dict) else details
    return row


def _keyed_rows(value: Any) -> List[Dict[str, Any]] | None:
    """An object of objects keyed by id (``devices/{hostname}/components``) as rows, each carrying its key as ``id``,
    so ``limit`` and ``fields`` apply per row; None for anything else."""
    if not isinstance(value, dict) or not value or not all(isinstance(item, dict) for item in value.values()):
        return None
    return [
        item if "id" in item else {"id": int(key) if is_digits(key) else key, **item} for key, item in value.items()
    ]


def _listing(
    rows: List[Any], body: Any, fields: List[str] | None, limit: int, start: int, route: Route
) -> Dict[str, Any]:
    """*rows* as a tool result. ``truncated`` says whether more rows exist than were shown: past the client-side
    limit, or (logs routes) past *start* plus what this page returned."""
    if len(rows) == 1 and isinstance(rows[0], list):  # LibreNMS wraps service rows in one more list
        rows = rows[0]
    shown = rows[:limit]
    if route.alert_rows:
        shown = [_alert_row(row, bool(fields) and "details" in fields) for row in shown]
    shown = [_project(row, fields) for row in shown]
    out: Dict[str, Any] = {"count": len(rows)}
    total = body.get("total") if isinstance(body, dict) else None
    if is_digits(total):  # logs routes: every matching row, of which ``count`` were returned from ``start`` on
        out["total"] = int(total)
    more = "total" in out and out["total"] > start + len(rows)
    out.update(returned=len(shown), truncated=len(shown) < len(rows) or more, results=for_model(shown))
    return out


def _extra(body: Any, route: Route) -> Dict[str, Any]:
    """What the envelope carries beside the result (``resources/fdb/{mac}/detail``: the MAC as LibreNMS writes it and
    its vendor, ``mac_oui``), under ``extra``."""
    if not isinstance(body, dict) or route.list_key is None:
        return {}
    extra = {key: value for key, value in body.items() if key not in _ENVELOPE_KEYS and key != route.list_key}
    return {"extra": for_model(extra)} if extra else {}


def _in_window(item: Any, start: int, end: int) -> bool:
    index = item.get("index") if isinstance(item, dict) else None
    return isinstance(index, int) and start <= index < end


def _page(plan: Dict[str, Any], start: int, end: int) -> Dict[str, Any]:
    """*plan* cut to steps *start* up to *end*: its steps, journal entries and the warnings about them (a warning
    about no step in particular stays)."""
    warnings = []
    for warning in plan.get("warnings") or []:
        found = _STEP_WARNING_RE.match(str(warning))
        if found is None or start <= int(found.group(1)) < end:
            warnings.append(warning)
    return {
        **plan,
        "steps": [step for step in plan.get("steps") or [] if _in_window(step, start, end)],
        "journal": [entry for entry in plan.get("journal") or [] if _in_window(entry, start, end)],
        "warnings": warnings,
    }


def _irreversible(plan: Dict[str, Any], start: int, end: int) -> Dict[str, Any]:
    """The indexes of *plan*'s irreversible steps among steps *start* up to *end*, and ``irreversible_count`` when
    there are others: a plan of 1,000 deletes would otherwise repeat 1,000 indexes beside every page of steps."""
    every = plan.get("irreversible") or []
    shown = [index for index in every if start <= index < end]
    if len(shown) == len(every):
        return {"irreversible": shown}
    return {"irreversible": shown, "irreversible_count": len(every)}


def _window(
    build: Callable[[int, int, bool], Dict[str, Any]], start: int, total: int, budget: int | None
) -> Dict[str, Any]:
    """What *build* makes of a plan's steps from *start* on: all of them when that fits within *budget* characters
    serialised (or there is no budget), else as many as fit and at least one. A single step that does not fit is
    built compact (eventlog rows as counts). *build* takes the window ``(start, end, compact)`` and says what it
    shows (:func:`_paging`)."""
    whole = build(start, total, False)
    if budget is None or start >= total or _size(whole) <= budget:
        return whole
    low, high, best = start + 2, total - 1, start + 1
    while low <= high:
        middle = (low + high) // 2
        if _size(build(start, middle, False)) <= budget:
            best, low = middle, middle + 1
        else:
            high = middle - 1
    page = build(start, best, False)
    return page if best > start + 1 or _size(page) <= budget else build(start, best, True)


def _paging(payload: Dict[str, Any], start: int, end: int, total: int) -> Dict[str, Any]:
    """*payload* (a page of steps *start* up to *end* of *total*) saying which steps it shows, when that is not all of
    them: ``offset``, ``steps_shown`` and ``step_count``, and while steps follow ``truncated``, ``next_offset`` and a
    ``note``. The diff, which the user is shown verbatim, says so in its last line."""
    if (start, end) == (0, total):
        return payload
    payload.update(offset=start, steps_shown=max(0, end - start), step_count=total)
    if start >= total:
        payload["note"] = f"the plan has {total} steps, numbered from 0; offset {start} is past the last"
    elif end < total:
        shown = f"steps {start}-{end - 1} of {total} are shown"
        payload.update(
            truncated=True,
            next_offset=end,
            note=f"{shown}, to stay within max_result_chars; librenms_plans with this plan_id and offset {end} "
            "shows the next ones",
        )
        if payload.get("diff"):
            payload["diff"] += f"\n… {shown}; the next ones start at step {end}"
    elif payload.get("diff"):
        payload["diff"] += f"\n… steps {start}-{end - 1} of {total} are shown"
    return payload


def _eventlog(eventlog: Any, entries: List[Dict[str, Any]], key: str, compact: bool) -> Any:
    """A phase's linked eventlog (apply or rollback) cut to the rows the journal *entries* name under *key*
    (``eventlog_ids`` or ``revert_eventlog_ids``); *compact* counts each device's rows instead of listing them."""
    if not isinstance(eventlog, dict) or not isinstance(eventlog.get("devices"), dict):
        return eventlog
    wanted = {event_id for entry in entries for event_id in entry.get(key) or []}
    every = {row.get("event_id") for rows in eventlog["devices"].values() for row in rows if isinstance(row, dict)}
    devices = {}
    for device, rows in eventlog["devices"].items():
        kept = [row for row in rows if isinstance(row, dict) and row.get("event_id") in wanted]
        if kept or every <= wanted:  # the whole journal is shown: every device, also one without new rows
            devices[device] = len(kept) if compact else kept
    return {**eventlog, "devices": devices}


def _phase(record: Any, entries: List[Dict[str, Any]], key: str, compact: bool) -> Any:
    """A plan's ``apply`` or ``rollback`` record for a tool result: its actor in public form and its eventlog cut to
    the shown journal *entries* (:func:`_eventlog`)."""
    record = _public(record)
    if isinstance(record, dict) and "eventlog" in record:
        record = {**record, "eventlog": _eventlog(record["eventlog"], entries, key, compact)}
    return record


# -- handlers -------------------------------------------------------------------------------------


@guarded
def librenms_query(args: Dict[str, Any], **kwargs: Any) -> str:
    settings = get_settings()
    action = str(args.get("action") or "get").strip().lower()
    if action == "status":
        maybe_prune(lambda: _actor_from(kwargs))
        report = status_report(settings)
        if not report["connection"]["ok"]:  # still a failure, with the settings that may explain it
            return _fail(report["connection"]["error"], **report)
        return _ok(**report)
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
            reason=clip(str(exc), audit.REASON_LIMIT),
        )
        return _fail(str(exc), refused=True)
    route = prepared.route
    where = {"path": prepared.path, "route": route.name}
    try:
        body = client.get(prepared.request_path, prepared.params or None)
    except LibreNMSError as exc:
        if exc.kind == "too_large":  # the client's advice is generic; on most routes limit would fail alike
            return _fail(f"{exc}: {too_large_hint(route, prepared.path)}", librenms=exc.to_dict())
        if exc.kind != "not_found":
            raise
        # LibreNMS answers an empty list with a 404 and a message ("No ports found")
        note = exc.body.get("message") if isinstance(exc.body, dict) else None
        return _ok(**where, count=0, returned=0, truncated=False, results=[], note=for_model(note or str(exc)))
    budget = _budget(settings, kwargs)
    value = LibreNMSClient.result(body, route.list_key) if route.list_key else body
    rows = value if isinstance(value, list) else _keyed_rows(value)
    if rows is not None:
        start = int(prepared.params["start"]) if route.paginated else 0
        listing = {"success": True, **where, **_listing(rows, body, fields, prepared.limit, start, route)}
        return _json(
            _fit_rows({**listing, **_extra(body, route)}, "results", budget, _query_note(route, budget, start))
        )
    payload = {"success": True, **where, "result": for_model(_project(value, fields)), **_extra(body, route)}
    if budget is not None and _size(payload) > budget:
        return _fail(
            f"the result is {_size(payload)} characters, more than max_result_chars allows ({budget}); name only the "
            "keys you need in fields",
            **where,
        )
    return _json(payload)


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
            description=clip(description, DESCRIPTION_CHARS),
            operations=len(operations) if isinstance(operations, list) else None,
            errors=len(exc.errors),
            first_error=clip(exc.errors[0].get("error"), audit.REASON_LIMIT) if exc.errors else None,
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
    total = len(plan["steps"])

    def build(start: int, end: int, _compact: bool) -> Dict[str, Any]:
        irreversible = _irreversible(plan, start, end)
        if sum(summary.get(key, 0) for key in _COUNTED) == 0:
            next_step = "Nothing to apply: every operation already matches LibreNMS."
        else:
            next_step = "Show this diff to the user and call librenms_apply only after they explicitly say yes."
            if end < total:
                next_step = (
                    f"This diff shows steps 0-{end - 1} of {total}. Read the rest with librenms_plans (this plan_id, "
                    f"offset {end}), show the user every step, and call librenms_apply only after they explicitly say "
                    "yes."
                )
            if "irreversible_count" in irreversible:  # the whole list would not fit beside the steps shown
                next_step += (
                    f" Tell them that {irreversible['irreversible_count']} steps cannot be rolled back; the diff marks "
                    "each one 'rollback: none'."
                )
            elif plan["irreversible"]:
                next_step += f" Tell them that steps {plan['irreversible']} cannot be rolled back."
        page = _page(plan, start, end)
        payload = {
            "success": True,
            **_plan_summary(plan),
            "diff": render_plan(page),
            "warnings": page["warnings"],
            **irreversible,
            "next_step": next_step,
        }
        return _paging(payload, start, end, total)

    return _json(_window(build, 0, total, _budget(settings, kwargs)))


@guarded
def librenms_apply(args: Dict[str, Any], **kwargs: Any) -> str:
    store = get_store()
    actor = _actor_from(kwargs)
    _plan_id, plan, candidates = find_plan(store, args.get("plan_id"), exact=True)
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
    budget = _budget(settings, kwargs)
    if dry_run:
        checks = plan.get("checks") or []
        if plan.get("status") != "planned" or not checks:  # claimed by another run while the checks ran
            return _fail(f"plan {plan['id']} is {plan.get('status')}; the check was not recorded", refused=True)
        conflicts = checks[-1]["conflicts"]
        checked = {"success": True, **_plan_summary(plan), "dry_run": True, "applicable": not conflicts}
        return _json(_fit_rows({**checked, "conflicts": conflicts}, "conflicts", budget, _conflicts_note))
    apply = plan.get("apply") or {}

    def build(start: int, end: int, compact: bool) -> Dict[str, Any]:
        page = _page(plan, start, end)
        payload = {
            "success": apply.get("outcome") == "applied",
            **_plan_summary(plan),
            "outcome": apply.get("outcome"),
            "failure": apply.get("failure"),
            "eventlog": _eventlog(apply.get("eventlog"), page["journal"], "eventlog_ids", compact),
            "rollback": _rollback_summary(plan.get("rollback"), page["journal"], compact),
            "journal": journal_summary(page["journal"]),
            "report": render_journal(page),
        }
        if apply.get("auto_rollback_error"):
            payload["auto_rollback_error"] = apply["auto_rollback_error"]
        return _paging(payload, start, end, len(plan["steps"]))

    return _json(_window(build, 0, len(plan["steps"]), budget))


@guarded
def librenms_rollback(args: Dict[str, Any], **kwargs: Any) -> str:
    store = get_store()
    actor = _actor_from(kwargs)
    _plan_id, plan, candidates = find_plan(store, args.get("plan_id"), exact=True)
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

    def build(start: int, end: int, compact: bool) -> Dict[str, Any]:
        page = _page(plan, start, end)
        payload = {
            "success": plan["status"] == "rolled_back",
            **_plan_summary(plan),
            "rollback": _rollback_summary(plan.get("rollback") or {}, page["journal"], compact),
            "journal": journal_summary(page["journal"]),
            "report": render_journal(page),
        }
        return _paging(payload, start, end, len(plan["steps"]))

    return _json(_window(build, 0, len(plan["steps"]), _budget(settings, kwargs)))


@guarded
def librenms_plans(args: Dict[str, Any], **kwargs: Any) -> str:
    maybe_prune(lambda: _actor_from(kwargs))
    store = get_store()
    budget = _budget(get_settings(), kwargs)
    if str(args.get("plan_id") or "").strip():
        _plan_id, plan, candidates = find_plan(store, args.get("plan_id"))
        if plan is None:
            return _fail(_unknown(args.get("plan_id"), candidates))
        detail = parse_bool(args.get("detail"), False)
        total = len(plan["steps"])
        checks = plan.get("checks") or []
        latest = checks if budget is None else checks[-1:]  # a record per dry run: the model reads the latest

        def build(start: int, end: int, compact: bool) -> Dict[str, Any]:
            page = _page(plan, start, end)
            payload = {
                "success": True,
                **_plan_summary(plan),
                "diff": render_plan(page),
                "warnings": page["warnings"],
                **_irreversible(plan, start, end),
                "checks": [_check(check, start, end) for check in latest],
                "journal": page["journal"] if detail else journal_summary(page["journal"]),
                "apply": _phase(plan.get("apply"), page["journal"], "eventlog_ids", compact),
                "rollback": _phase(plan.get("rollback"), page["journal"], "revert_eventlog_ids", compact),
                "report": render_journal(page),
            }
            if len(latest) < len(checks):
                payload["check_count"] = len(checks)
            if detail:
                payload["steps"] = page["steps"]
            return _paging(payload, start, end, total)

        return _json(_window(build, _int(args.get("offset"), 0, minimum=0), total, budget))
    limit = _int(args.get("limit"), 20, maximum=200)
    status = args.get("status")
    plans = store.list(status=str(status) if status else None, limit=limit)
    listing = {"success": True, "count": len(plans), "plans": [_plan_summary(p) for p in plans]}
    return _json(_fit_rows(listing, "plans", budget, _plans_note))


def _check(check: Any, start: int, end: int) -> Any:
    """A dry-run check record for a tool result: its actor in public form, its conflicts cut to steps *start* up to
    *end*."""
    check = _public(check)
    if isinstance(check, dict) and isinstance(check.get("conflicts"), list):
        check = {**check, "conflicts": [item for item in check["conflicts"] if _in_window(item, start, end)]}
    return check


HANDLERS = {
    "librenms_query": librenms_query,
    "librenms_plan": librenms_plan,
    "librenms_apply": librenms_apply,
    "librenms_rollback": librenms_rollback,
    "librenms_plans": librenms_plans,
}


# -- hooks ----------------------------------------------------------------------------------------


def pre_tool_call(tool_name: Any = None, args: Any = None, **kwargs: Any) -> Dict[str, Any] | None:
    """Hermes ``pre_tool_call``: fires for every tool call, so anything but our two write tools and the agent's shell
    tools returns at once, without reading settings or plans. A callback that raises would block the call it was
    asked about, so neither branch raises; when in doubt they block. An approval asked for is audited as
    ``approval_requested``: Hermes may refuse it (cron, unattended platforms) without a ``post_approval_response``,
    and the attempt must still show in the trail. A block is audited as the refusal it is."""
    if not isinstance(tool_name, str) or tool_name not in _HOOKED_TOOLS:
        return None
    if tool_name not in WRITE_TOOLS:
        return _terminal_guard(tool_name, args, kwargs)
    directive = _approval(tool_name, args)
    if directive is None:
        return None
    if directive["action"] == "approve":
        found = _RULE_KEY_RE.search(directive["rule_key"])
        plan_id = found.group("plan") if found is not None else None
        _audit_hook("approval_requested", kwargs, plan_id, None, tool=tool_name, rule_key=directive["rule_key"])
    else:
        event = "apply_refused" if tool_name == "librenms_apply" else "rollback_refused"
        _audit_hook(event, kwargs, None, None, reason=directive["message"], tool=tool_name)
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
    """``approve`` with a summary of the plan (apply) or of what its rollback reverts, when ``require_approval`` is
    on in ``full`` mode; in the other modes the handler refuses the model and audits it. The rule_key names the plan
    and the flag that changes what runs, so an "always" answer never carries over to another plan or variant.
    A ``plan_id`` that is not a saved plan's exact id is blocked with the handler's own refusal, and so is any
    failure to load the plan: asking about a plan nobody can be shown would let one that comes to match while the
    prompt is open run unseen."""
    action = "apply" if tool == "librenms_apply" else "rollback"
    try:
        settings = get_settings()
        if not settings.require_approval or settings.write_mode != "full":
            return None
        args = args if isinstance(args, dict) else {}
        if tool == "librenms_apply" and parse_bool(args.get("dry_run"), False):
            return None
        plan_id, plan, candidates = find_plan(get_store(), args.get("plan_id"), exact=True)
        if plan_id is None or plan is None:
            return {"action": "block", "message": _unknown(args.get("plan_id"), candidates)}
        if tool == "librenms_apply":
            rollback = parse_bool(args.get("rollback_on_failure"), True)
            message, variant = _apply_approval(plan, plan_id, rollback), "rb" if rollback else "norb"
        else:
            force = parse_bool(args.get("force"), False)
            message, variant = _rollback_approval(plan, plan_id, force), "force" if force else "safe"
        return {"action": "approve", "message": message, "rule_key": f"librenms:{tool}:{plan_id}:{variant}"}
    except Exception as exc:
        error_id = new_error_id()
        logger.warning("librenms approval hook: plan not loaded (%s)", error_id, exc_info=exc)
        return {
            "action": "block",
            "message": f"{action} refused: the plan could not be loaded for the approval prompt ({error_id}); see "
            "the Hermes log",
        }


def _apply_approval(plan: Dict[str, Any], plan_id: str, rollback: bool) -> str:
    """One header line (the plan, its counts, the irreversible steps, ``rollback_on_failure``), one line per step
    that writes, deletes and irreversible steps first, then while room remains the field-level diff, the warnings,
    and last the plan's description, which the model wrote."""
    summary = plan.get("summary") or {}
    counts = ", ".join(f"{summary[key]} {key}" for key in _COUNTED if summary.get(key)) or "nothing to change"
    irreversible = plan.get("irreversible") or []
    header = (
        f"Apply {plan_id}: {counts}; irreversible steps: {_indexes(irreversible)}; "
        f"rollback_on_failure={'true' if rollback else 'false'}"
    )
    steps = sorted(
        (step for step in plan.get("steps") or [] if step.get("action") != "noop"),
        key=lambda step: step.get("action") != "delete" and step.get("index") not in irreversible,
    )
    lines = [_step_line(step, step.get("index") in irreversible) for step in steps]
    details: List[str] = []
    for step in steps:
        prefix = f"  [{step.get('index')}] "
        details += [prefix + line for line in get_resource(step["resource"]).describe(step)]
        if step.get("inverse_kind") in ("none", "lossy"):
            note = step.get("inverse_note")
            details.append(f"{prefix}rollback: {step['inverse_kind']}" + (f" — {one_line(note)}" if note else ""))
    details += [f"Warning: {one_line(warning)}" for warning in dict.fromkeys(plan.get("warnings") or [])]
    if plan.get("description"):
        details.append(f"Description: {one_line(plan['description'])}")
    return _approval_message(header, lines, details, plan_id)


def _rollback_approval(plan: Dict[str, Any], plan_id: str, force: bool) -> str:
    """The header (pending entries, ``FORCE``), one line per entry in the order rollback reverts them saying what
    it does to the object, then while room remains the journal."""
    pending = pending_entries(plan)
    header = f"Roll back {plan_id}: {len(pending)} pending entries"
    if force:
        header += ", FORCE: overwrites edits made after the apply"
    steps = {step.get("index"): step for step in plan.get("steps") or []}
    lines = [_revert_line(entry, steps.get(entry.get("index")) or {}) for entry in reversed(pending)]
    return _approval_message(header, lines, render_journal(plan).split("\n")[1:], plan_id)


def _target_line(item: Dict[str, Any]) -> str:
    """``[index] action resource #id "label"`` of a step or journal entry, the label cut short."""
    ident = f" #{item['object_id']}" if item.get("object_id") is not None else ""
    label = _cut(one_line(item.get("label") or ""), APPROVAL_LABEL_CHARS)
    return f'[{item.get("index")}] {item.get("action")} {item.get("resource")}{ident} "{label}"'


def _step_line(step: Dict[str, Any], irreversible: bool) -> str:
    """A step and the names of the fields it sets (an update's changes, a create's data, an action's
    arguments)."""
    line = _target_line(step) + (" (irreversible)" if irreversible else "")
    fields = {"update": step.get("changes"), "create": step.get("data")}.get(step.get("action"), step.get("params"))
    return line + (": " + ", ".join(one_line(name) for name in fields) if isinstance(fields, dict) and fields else "")


def _revert_line(entry: Dict[str, Any], step: Dict[str, Any]) -> str:
    """A journal entry and what its rollback does to the object."""
    kind, action = entry.get("inverse_kind"), entry.get("action")
    if kind == "none":
        what = "cannot be undone"
    elif kind == "not_needed":
        what = "nothing to undo"
    elif action == "create":
        what = "delete it"
    elif action == "update":
        fields = (entry.get("inverse") or {}).get("data") or step.get("changes") or {}
        what = "restore " + (", ".join(one_line(name) for name in fields) if isinstance(fields, dict) else "it")
    elif action == "delete":
        what = "re-create it (new id)"
    else:
        what = f"undo it ({kind})"
    if entry.get("status") == "unknown":
        what = f"outcome unknown; {what}"
    return f"{_target_line(entry)}: {what}"


def _indexes(indexes: List[Any]) -> str:
    if not indexes:
        return "none"
    shown = ", ".join(str(index) for index in indexes[:10])
    return f"[{shown}, … {len(indexes)} in all]" if len(indexes) > 10 else f"[{shown}]"


def _cut(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _approval_message(header: str, lines: List[str], details: List[str], plan_id: str) -> str:
    """*header*, a line per step, and *details* only when every step line fit, within
    :data:`APPROVAL_MESSAGE_CHARS`; then how many lines were left out and where the whole plan is. Every line is
    kept to one line, escaped and cut to :data:`APPROVAL_LINE_CHARS`: labels, notes and descriptions come from
    LibreNMS and the model, and must neither rewrite what the human reads in a terminal nor take the room the steps
    need. A line that does not fit is left out and counted, not the lines after it."""
    shown_id = one_line(plan_id)
    header = one_line(header)
    room = APPROVAL_MESSAGE_CHARS - len(f"\n… {len(lines) + len(details)} more lines; full plan: /librenms show ")
    room -= len(shown_id)
    kept, used, left = [header], len(header), 0
    for group in (lines, details):
        if left:  # details only below a complete list of steps
            left += len(group)
            continue
        for line in group:
            line = _cut(one_line(line), APPROVAL_LINE_CHARS)
            if used + 1 + len(line) <= room:
                kept.append(line)
                used += 1 + len(line)
            else:
                left += 1
    kept.append(
        f"… {left} more lines; full plan: /librenms show {shown_id}"
        if left
        else f"Full plan: /librenms show {shown_id}"
    )
    return "\n".join(kept)


def _shell_text(tool: str, args: Any) -> str:
    """What a shell tool call hands a shell: every string argument of ``terminal`` and ``execute_code``, and the
    ``data`` that ``process_manage`` writes or submits to a background process's stdin (as Hermes sends it,
    ``str()`` of any value)."""
    if not isinstance(args, dict):
        return args if isinstance(args, str) else ""
    if tool == "process_manage":
        action = args.get("action")
        return str(args.get("data", "")) if isinstance(action, str) and action in _STDIN_ACTIONS else ""
    return "\n".join(value for value in args.values() if isinstance(value, str))


def _cli_write(text: str) -> re.Match[str] | None:
    """The first ``librenms apply|rollback`` in *text* with the word hermes before it in the same command (no
    newline, ``;``, ``|`` or ``&`` in between). One pass: each stretch between two ``librenms`` hits is searched
    once, so a long line of ``hermes`` words (a JSON list of ``~/.hermes`` paths) costs linear time in the hook."""
    if "librenms" not in text.casefold():
        return None
    hermes, scanned = False, 0
    for found in _CLI_WRITE_RE.finditer(text):
        start = found.start()
        cut = max(text.rfind(separator, scanned, start) for separator in _COMMAND_SEPARATORS)
        if cut >= 0:
            hermes, scanned = False, cut + 1
        hermes = hermes or _HERMES_RE.search(text, scanned, start) is not None
        if hermes:
            return found
        scanned = start
    return None


def _terminal_guard(tool: str, args: Any, hook_kwargs: Dict[str, Any]) -> Dict[str, Any] | None:
    """Block ``hermes librenms apply|rollback`` in the agent's terminal, its code or a background shell's stdin unless
    the operator lets the model write without approval anyway: run there, it would skip the approval prompt and act
    as an operator. The model is told what it may do instead under this write_mode, and the attempt is audited as
    ``apply_refused`` / ``rollback_refused`` naming the tool and the plan, never the command text."""
    message = TERMINAL_BLOCK
    try:
        found = _cli_write(_shell_text(tool, args))
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
