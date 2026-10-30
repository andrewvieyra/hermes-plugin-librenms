"""Tool handlers: ``handler(args: dict, **kwargs) -> str`` (always a JSON string, never raises), and the hook
callbacks.

Handlers are thin. They parse arguments, obtain a client and the plan store, call the planner or executor, and shape
the result; every result passes through :func:`redact.mask` and :func:`redact.visible` on its way out, and one that
returns text from LibreNMS names the keys holding it (:func:`redact.mark_untrusted`). Everything here is also
reachable from the ``/librenms`` slash command and the ``hermes librenms`` CLI through :mod:`commands`.

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
import hashlib
import json
import logging
import re
import threading
import time
from typing import Any, Callable, Dict, List, NamedTuple, Tuple

from . import audit, listing, reports, sinks
from .client import LibreNMSClient, LibreNMSError, insecure_transport, is_configured, is_digits, new_error_id
from .executor import (
    EVENTLOG_MESSAGE_CHARS,
    ExecutionRefused,
    PlanChanged,
    apply_plan,
    pending_entries,
    render_journal,
    rollback_plan,
)
from .planner import DESCRIPTION_CHARS, PlanError, build_plan, render_plan
from .redact import alert_entities, clip, for_model, mark_untrusted, mask, one_line, visible
from .resources import get_resource
from .routes import PreparedQuery, QueryError, Route, prepare, too_large_hint
from .settings import Settings, get_settings
from .store import PlanStore, content_digest, get_store, plan_status, profile_key
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
# The rule_key pre_tool_call returns, as Hermes reports it back (prefixed "plugin_rule:"):
# "librenms:<tool>:<plan_id>:<variant>:<content digest>". 0.10.x and earlier left the digest out, and 0.1.1 and
# earlier also returned "librenms:<tool>:unresolved:<digest>", which a remembered answer can still carry.
_RULE_KEY_RE = re.compile(
    r"(?:^|:)(?P<key>librenms:(?P<tool>librenms_apply|librenms_rollback):(?P<plan>[^:]+):(?P<variant>[^:]+)"
    r"(?::(?P<digest>[0-9a-f]+))?)$"
)
# What a rule key's variant stands for, as the approval prompt's header says it.
_VARIANT_FLAGS = {
    "rb": "rollback_on_failure=true",
    "norb": "rollback_on_failure=false",
    "force": "force=true",
    "safe": "force=false",
}
_COUNTED = ("create", "update", "delete", "action")
# Envelope keys that carry no data of their own: LibreNMS's api_success puts them around every result.
_ENVELOPE_KEYS = frozenset({"status", "message", "count", "total"})
# After a where or sort key no row of a ports route has: LibreNMS returns only the columns asked for there, and
# without params.columns a default few (ifName on devices/{hostname}/ports, port_id and ifName on ports).
_COLUMNS_HINT = (
    "; on this route LibreNMS returns only the columns params.columns names (a default few without it): add the key "
    "there, e.g. params.columns=port_id,ifName,ifAlias"
)
# The keys of a plan, apply, rollback or plan-detail result that hold text from LibreNMS: labels and the values the
# diff compares, the notes in warnings and dry-run conflicts, LibreNMS's errors in the journal, the failure and the
# report, the linked eventlog rows, and the objects' states in the steps. A result names those it holds
# (redact.mark_untrusted); the rest (plan id, status, counts, next_step) is the plugin's own.
_PLAN_TEXT = (
    "diff",
    "warnings",
    "checks",
    "failure",
    "eventlog",
    "apply",
    "rollback",
    "journal",
    "report",
    "auto_rollback_error",
    "steps",
)
# "[12] note" in a plan's warnings: the step the warning is about
_STEP_WARNING_RE = re.compile(r"^\[(\d+)\] ")
_PRUNE_INTERVAL = 3600.0
# store.profile_key() -> when this process last swept that profile's plans (absent: never)
_last_prune_at: Dict[str, float] = {}
_prune_lock = threading.Lock()
_client_factory: Callable[[], LibreNMSClient] | None = None


class _Shown(NamedTuple):
    """What the approval prompt of a write tool call showed: the plan, the variant (``rb``/``norb``,
    ``force``/``safe``) and the plan's content digest (:func:`store.content_digest`)."""

    plan_id: str
    variant: str
    digest: str


# The argument through which bind_approval hands the handler of an apply or rollback what that call's approval prompt
# showed (a _Shown as an object, or null), by Hermes' "modify" directive. The schemas do not offer it, and the hook
# replaces whatever the model wrote there.
APPROVAL_ARG = "_librenms_approval"
# What pre_tool_call made the approval prompt of a write tool call show, until bind_approval, the next pre_tool_call
# callback of the same call, takes it: keyed by the call (_call_key). Hermes runs the callbacks of a call one after
# another, each on a worker thread of its own, so nothing per thread lasts from one to the next. At most
# _PENDING_LIMIT are kept, the oldest dropped first, in case a Hermes runs the first and not the second.
_PENDING_LIMIT = 256
_pending: Dict[Tuple[str, ...], _Shown] = {}
_pending_lock = threading.Lock()


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
    """Test seam: forget the last retention sweeps, so the next call that sweeps runs one, and what approval
    prompts showed."""
    with _prune_lock:
        _last_prune_at.clear()
    with _pending_lock:
        _pending.clear()


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


def find_plan(store: PlanStore, raw: Any, *, exact: bool = False) -> Tuple[str | None, Dict[str, Any] | None, str]:
    """``(plan_id, plan, "")`` for what a caller named: an exact id, else (unless *exact*) the end of one, as
    :meth:`PlanStore.resolve` matches; else ``(None, None, why)``, the refusal to return. ``librenms_apply``,
    ``librenms_rollback`` and their approval hook take only an exact id, so the plan a human approved is the plan that
    runs: a fragment resolved again after the prompt could name a plan created while it was open. A plan file whose
    ``id`` is not the name it is found by (edited or copied by hand) is refused too: the prompt would show one file
    and the run re-read, and save to, the file its ``id`` names."""
    text = str(raw or "").strip()
    plan_id, candidates = store.resolve(text)
    if exact and plan_id != text:
        plan_id = None
    plan = store.load(plan_id) if plan_id else None
    if plan_id is None or plan is None:
        return None, None, _unknown(raw, candidates)
    if not isinstance(plan, dict) or plan.get("id") != plan_id:
        named = plan.get("id") if isinstance(plan, dict) else None
        holds = f"plan {str(named)[:80]!r}" if named else "no plan id"
        reason = (
            f"plan file {plan_id} holds {holds}, not {plan_id}: it was edited or copied by hand, so it is neither "
            "shown nor run. Build a new plan with librenms_plan"
        )
        return None, None, reason
    return plan_id, plan, ""


def _call_key(tool: str, args: Any, hook_kwargs: Dict[str, Any]) -> Tuple[str, ...]:
    """A tool call as both of our ``pre_tool_call`` callbacks see it: the tool, the ``tool_call_id``, ``session_id``
    and ``task_id`` Hermes passes them (``""`` for none) and a digest of its arguments, so two calls Hermes makes at
    once without a ``tool_call_id`` (``handle_function_call`` called directly) are told apart unless they are the same
    call."""
    ids = (str(hook_kwargs.get(name) or "") for name in ("tool_call_id", "session_id", "task_id"))
    try:
        text = json.dumps(args, sort_keys=True, ensure_ascii=True, default=repr)
    except (TypeError, ValueError):  # keys that do not sort, a cycle: never what a model's call holds
        text = ascii(args)
    return (tool, *ids, hashlib.sha256(text.encode("ascii")).hexdigest()[:16])


def _note_shown(tool: str, args: Any, hook_kwargs: Dict[str, Any], shown: _Shown | None) -> None:
    """Keep for :func:`bind_approval` what the approval prompt of this *tool* call shows (*shown*), or that it shows
    none (None: approval off, a dry run, a block)."""
    key = _call_key(tool, args, hook_kwargs)
    with _pending_lock:
        _pending.pop(key, None)  # whatever an earlier call with the same ids left; a new one goes in last
        if shown is not None:
            _pending[key] = shown
        while len(_pending) > _PENDING_LIMIT:
            _pending.pop(next(iter(_pending)))


def _shown_in(args: Dict[str, Any], kwargs: Dict[str, Any]) -> _Shown | None:
    """What the approval prompt of this call showed, as :func:`bind_approval` put it in its arguments; None when no
    prompt was shown, and for an operator's call (``_actor``), which none precedes. It only ever adds a check: a value
    the model wrote there that no hook replaced (a Hermes without ``modify``) can make the call refuse, never run."""
    value = args.get(APPROVAL_ARG)
    if isinstance(kwargs.get("_actor"), dict) or not isinstance(value, dict):
        return None
    fields = [value.get(name) for name in _Shown._fields]
    return _Shown(*fields) if all(isinstance(field, str) and field for field in fields) else None


def _not_shown(action: str, shown: _Shown, plan_id: str, variant: str) -> str | None:
    """Why a call whose prompt showed *shown* may not run as plan *plan_id* with *variant*, or None when it is the
    call the prompt showed. Only something between the hook and the handler (another plugin's ``modify``, tool
    middleware) changes the arguments a person approved."""
    if (shown.plan_id, shown.variant) == (plan_id, variant):
        return None
    flag = _VARIANT_FLAGS.get(shown.variant, shown.variant)
    return (
        f"{action} refused: this call is not the one the approval prompt showed (plan {shown.plan_id}, {flag}); "
        f"nothing was {'applied' if action == 'apply' else 'reverted'}. Call librenms_{action} again so the user "
        "is asked about what runs"
    )


def _bound(
    action: str, args: Dict[str, Any], kwargs: Dict[str, Any], settings: Settings, plan_id: str, variant: str
) -> Tuple[str | None, str | None]:
    """``(refusal, approved_digest)`` for a write call that is not a dry run. A call whose approval prompt showed
    something (:func:`_shown_in`) runs only as that call, and the claim is handed the digest it showed. A model's call
    whose :data:`APPROVAL_ARG` is there but names no prompt (null from :func:`bind_approval`, or anything else) is
    refused while ``require_approval`` is on in ``full`` mode: no prompt showed what it would run, whatever made it so
    (a ``dry_run`` another plugin's ``modify`` or tool middleware turned false after the prompt was skipped, arguments
    changed between our two callbacks, a record lost). Without :data:`APPROVAL_ARG` (a Hermes without ``modify``) and
    for an operator's command nothing is added."""
    shown = _shown_in(args, kwargs)
    if shown is not None:
        refusal = _not_shown(action, shown, plan_id, variant)
        return refusal, None if refusal else shown.digest
    operator = isinstance(kwargs.get("_actor"), dict)
    if APPROVAL_ARG not in args or operator or not settings.require_approval or settings.write_mode != "full":
        return None, None
    return (
        f"{action} refused: no approval prompt showed this call, and require_approval is on; nothing was "
        f"{'applied' if action == 'apply' else 'reverted'}. Call librenms_{action} again so the user is asked about "
        "what runs"
    ), None


def _changed(exc: ExecutionRefused) -> Dict[str, Any]:
    """The digests a :class:`PlanChanged` refusal compared, for its audit event."""
    return {"approved_digest": exc.approved, "digest": exc.found} if isinstance(exc, PlanChanged) else {}


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


def prune_audit(*, dry_run: bool = False, actor: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """Apply the audit log's retention (``audit_keep_files``, ``audit_retention_days``): rotate the live file when
    it is due and remove the rotated files past it; audited as ``audit_pruned``. *dry_run* lists what would go now,
    the live file included when it would go as soon as it is rotated. ``error`` says why retention could not run or
    ran only in part (:class:`audit.RetentionError`; ``removed`` still names what it removed), else it is None."""
    log = audit.get_audit_log()
    retention = log.retention
    error = None
    try:
        removed = log.prune(actor=actor, dry_run=dry_run)
    except audit.RetentionError as exc:
        removed, error = exc.removed, str(exc)
    return {
        "keep_files": retention.keep_files,
        "max_age_days": retention.max_age_days,
        "dry_run": dry_run,
        "removed": removed,
        "error": error,
    }


def _audit_retention_problem() -> str | None:
    """Why the audit log can be neither rotated nor pruned (:func:`audit.retention_problem`), for status."""
    try:
        log = audit.get_audit_log()
        return audit.retention_problem(log.path, log.retention)
    except Exception:  # pragma: no cover - defensive
        return None


def maybe_prune(actor: Dict[str, Any] | Callable[[], Dict[str, Any]]) -> None:
    """Opportunistic retention sweep of the active profile's plans and audit log, at most once an hour per profile
    in this process: planning, listing plans, status and every ``/librenms`` or ``hermes librenms`` command call
    it, so a profile that stops planning is still swept, and a log nobody writes to still ages out. *actor* (or a
    function making it, called only when a sweep runs) is recorded on ``plans_pruned`` and ``audit_pruned``. Never
    raises: retention is housekeeping and must not affect the call."""
    with contextlib.suppress(Exception):
        key, now = profile_key(), time.monotonic()
        with _prune_lock:
            last = _last_prune_at.get(key)
            if last is not None and now - last < _PRUNE_INTERVAL:
                return
            _last_prune_at[key] = now
        who = actor() if callable(actor) else actor
        if get_settings().plan_retention_days > 0:
            with contextlib.suppress(Exception):  # the audit log's retention runs all the same
                prune_plans(actor=who)
        prune_audit(actor=who)


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
    if 0 < settings.audit_keep_files < settings.audit_retention_days:
        warnings.append(
            f"audit_keep_files ({settings.audit_keep_files}) is below audit_retention_days "
            f"({settings.audit_retention_days}): the audit log is rotated daily while retention is on, so only its "
            f"newest {settings.audit_keep_files} rotated files (about as many days) are kept; raise audit_keep_files "
            "or set it to 0"
        )
    problem = _audit_retention_problem()
    if problem:
        warnings.append(
            f"the audit log can be neither rotated nor pruned: {problem}. It grows and keeps every event, users' "
            "messages included, whatever audit_max_mb, audit_keep_files and audit_retention_days say; Hermes' log "
            "names the file, and docs/audit.md (Rotation and retention) says what to change"
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


def _json(payload: Any) -> str:
    """Serialise a tool result. Credential-bearing keys are masked at any depth: steps and journals carry what
    LibreNMS returned (the plan file on disk stays unmasked, rollback needs it). Every string, the plugin's own
    included, is escaped as the model should read it (:func:`redact.visible`), whatever way it took into the result
    (a row, a plan's diff, a journal error, an error quoting LibreNMS's answer): no bidirectional override, invisible
    character or control from LibreNMS reaches the model, or a terminal it is quoted to, as it is."""
    return json.dumps(visible(mask(payload)), ensure_ascii=False, default=lambda obj: visible(str(obj)))


def _fail(message: str, **extra: Any) -> str:
    return _json({"success": False, "error": message, **extra})


def _librenms_failed(message: str, exc: LibreNMSError) -> str:
    """An error result with LibreNMS's answer (:meth:`LibreNMSError.to_dict`) under ``librenms``, named as text from
    LibreNMS (:func:`redact.mark_untrusted`): its message and body are what LibreNMS said, which a device or another
    person may have written. *message* stays the plugin's ``error``."""
    return _json(mark_untrusted({"success": False, "error": message, "librenms": exc.to_dict()}, "librenms"))


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
            return _librenms_failed(str(exc), exc)
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
    """Characters *value* takes in a tool result (:func:`_json`), escapes included."""
    return len(_json(value))


def _fit_rows(
    payload: Dict[str, Any],
    key: str,
    budget: int | None,
    note: Callable[[int, int], Any],
    offset: int | None = None,
    note_key: str = "note",
) -> Dict[str, Any]:
    """*payload* with as many leading entries of its list *key* as keep it within *budget* characters serialised (all
    of them without a budget). When some are left out, ``returned`` is the number kept, ``truncated`` is true and
    *note_key* (``note``; a report's ``notes``) says how to see the rest: *note* is given the number kept and the
    number there were. Given the *offset* of the first entry in the whole listing, ``next_offset`` is that of the
    first one left out, unless that is the first entry, which does not fit on its own (:func:`_read_on`)."""
    rows = payload.get(key)
    if budget is None or not isinstance(rows, list) or _size(payload) <= budget:
        return payload

    def cut(kept: int) -> Dict[str, Any]:
        out = {**payload, key: rows[:kept], "returned": kept, "truncated": True, note_key: note(kept, len(rows))}
        return out if offset is None else _read_on(out, offset)

    # The room for rows, measured with one kept: every cut but the empty one has that shape, and the empty one's note
    # may be longer (_query_note), which would leave out rows that fit. Digits that grow with kept are cut back below.
    room, kept = (budget - _size(cut(1)) + _size(rows[0]) if rows else -1), 0
    for row in rows:
        room -= _size(row) + (2 if kept else 0)  # json.dumps separates list items with ", "
        if room < 0:
            break
        kept += 1
    while True:
        out = cut(kept)
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


def _query_note(budget: int | None, offset: int) -> Callable[[int, int], str]:
    def note(kept: int, of: int) -> str:
        if not kept:  # reading on from the same offset would show nothing again
            return (
                f"the row at offset {offset} does not fit within max_result_chars ({budget} characters) on its own: "
                f"name only the keys you need in fields (offset {offset + 1} reads on past it)"
            )
        return (
            f"cut at {kept} of {of} rows to stay within max_result_chars ({budget} characters): name only the keys "
            f"you need in fields, or read on with offset {offset + kept}"
        )

    return note


def _report_note(budget: int | None, payload: Dict[str, Any]) -> Callable[[int, int], List[str]]:
    """A report's ``notes`` once :func:`_fit_rows` cut its rows: the notes it had, then what was cut and where to read
    on."""
    offset, notes = payload.get("offset") or 0, list(payload.get("notes") or [])

    def note(kept: int, of: int) -> List[str]:
        if not kept:
            return [
                *notes,
                f"the row at offset {offset} does not fit within max_result_chars ({budget} characters) on its own; "
                f"offset {offset + 1} reads on past it",
            ]
        return [
            *notes,
            f"cut at {kept} of the {of} rows of this page to stay within max_result_chars ({budget} characters): read "
            f"on with offset {offset + kept}, or narrow the scope or filter",
        ]

    return note


def _read_on(listing: Dict[str, Any], offset: int) -> Dict[str, Any]:
    """*listing*, cut by :func:`_fit_rows`, with ``next_offset`` right after ``truncated``: the first row it no longer
    shows, also when it was cut at ``limit`` already. Without one when it shows no row: the first one does not fit on
    its own, and reading on from there would show nothing again (the note says so)."""
    out: Dict[str, Any] = {}
    for key, value in listing.items():
        if key != "next_offset":
            out[key] = value
        if key == "truncated" and listing["returned"]:
            out["next_offset"] = offset + listing["returned"]
    return out


def _alert_row(row: Any, keep_details: bool) -> Any:
    """A fault or alert-log row with ``details`` replaced by ``entities``: the label keys of the rows its rule matched
    (:func:`redact.alert_entities`), so "what is alerting" names the port or sensor without the blob. With
    *keep_details* (``fields`` names it) ``details`` stays too, without its ``contacts``."""
    if not isinstance(row, dict) or "details" not in row:
        return row
    row = dict(row)
    details = row.pop("details")
    entities, total = alert_entities(details)
    row["entities"] = entities
    if total > len(entities):
        row["entities_total"] = total
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
    rows: List[Any],
    body: Any,
    fields: List[str] | None,
    prepared: PreparedQuery,
    where: List[listing.Condition],
    sort: listing.Order | None,
) -> Dict[str, Any]:
    """*rows* as a tool result: those that pass *where*, in *sort*'s order (:func:`listing.select`), at most
    ``limit`` of them from ``offset`` on. On a logs route LibreNMS has paged them already (``start``). ``count`` is
    the rows LibreNMS returned, ``matched`` those that pass *where*, ``total`` (logs routes) every row LibreNMS
    holds for the query. ``truncated`` and ``next_offset`` say whether rows follow those shown: past the limit, or
    (logs routes) past the offset plus what this page returned. Raises :class:`listing.UnknownKey`."""
    route, offset, limit = prepared.route, prepared.offset, prepared.limit
    if len(rows) == 1 and isinstance(rows[0], list):  # LibreNMS wraps service rows in one more list
        rows = rows[0]
    kept = listing.select(rows, where, sort)
    out: Dict[str, Any] = {"count": len(rows)}
    if where:
        out["matched"] = len(kept)
    total = body.get("total") if isinstance(body, dict) else None
    if is_digits(total):  # logs routes: every matching row, of which ``count`` were returned from ``start`` on
        out["total"] = int(total)
    if route.paginated:
        shown = kept[:limit]
        every = out.get("total", offset + len(rows))
    else:
        shown = kept[offset : offset + limit]
        every = len(kept)
    if offset:
        out["offset"] = offset
    if route.alert_rows:
        shown = [_alert_row(row, bool(fields) and "details" in fields) for row in shown]
    shown = [_project(row, fields) for row in shown]
    out.update(returned=len(shown), truncated=every > offset + len(shown))
    if out["truncated"]:
        out["next_offset"] = offset + len(shown)
    elif every and offset >= every:
        out["note"] = f"offset {offset} is past the last row: there are {every}, from offset 0"
    out["results"] = for_model(shown)
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
        kept = [_event_row(row) for row in rows if isinstance(row, dict) and row.get("event_id") in wanted]
        if kept or every <= wanted:  # the whole journal is shown: every device, also one without new rows
            devices[device] = len(kept) if compact else kept
    return {**eventlog, "devices": devices}


def _event_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """A linked eventlog row with its message within :data:`EVENTLOG_MESSAGE_CHARS` as escaped. The executor stores
    it cut so, and clipping it again changes nothing; a plan linked by 0.1.x holds it cut by its raw length, which
    characters that show as nothing make ten times longer escaped."""
    message = row.get("message")
    return {**row, "message": clip(message, EVENTLOG_MESSAGE_CHARS)} if isinstance(message, str) else row


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
        return _json(mark_untrusted({"success": True, **report}, "librenms"))
    if action != "get":
        return _fail(f"action must be get or status (got {action[:40]!r})")
    fields = args.get("fields")
    if fields is not None and not (isinstance(fields, list) and all(isinstance(f, str) for f in fields)):
        return _fail("fields must be a list of key names")
    try:
        where, sort = listing.conditions(args.get("where")), listing.order(args.get("sort"))
    except listing.ListingError as exc:
        return _fail(str(exc))
    client = make_client(settings)
    raw_path = args.get("path")
    try:
        prepared = prepare(
            client,
            "" if raw_path is None else raw_path,
            args.get("params"),
            args.get("limit"),
            settings,
            offset=args.get("offset"),
            row_args=tuple(name for name, given in (("where", where), ("sort", sort)) if given),
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
    named = {"path": prepared.path, "route": route.name}
    try:
        body = client.get(prepared.request_path, prepared.params or None)
    except LibreNMSError as exc:
        if exc.kind == "too_large":  # the client's advice is generic; on most routes limit would fail alike
            return _librenms_failed(f"{exc}: {too_large_hint(route, prepared.path)}", exc)
        if exc.kind != "not_found":
            raise
        # LibreNMS answers an empty list with a 404 and a message ("No ports found")
        note = exc.body.get("message") if isinstance(exc.body, dict) else None
        empty = {"success": True, **named, **_listing([], None, fields, prepared, where, sort)}
        return _json(mark_untrusted({**empty, "note": for_model(note or str(exc))}, "note"))
    budget = _budget(settings, kwargs)
    value = LibreNMSClient.result(body, route.list_key) if route.list_key else body
    rows = value if isinstance(value, list) else _keyed_rows(value)
    if rows is not None:
        try:
            result = {"success": True, **named, **_listing(rows, body, fields, prepared, where, sort)}
        except listing.UnknownKey as exc:  # on a ports route the key may be a column not asked for
            columns = route.columns and exc.alike is None
            return _fail(str(exc) + (_COLUMNS_HINT if columns else ""), **named)
        result = mark_untrusted({**result, **_extra(body, route)}, "results", "extra")
        return _json(_fit_rows(result, "results", budget, _query_note(budget, prepared.offset), prepared.offset))
    if where or sort or prepared.offset:
        return _fail(
            f"where, sort and offset apply to listings, and {prepared.path} answers with one object; ask without them",
            **named,
        )
    payload = {"success": True, **named, "result": for_model(_project(value, fields)), **_extra(body, route)}
    payload = mark_untrusted(payload, "result", "extra")
    if budget is not None and _size(payload) > budget:
        return _fail(
            f"the result is {_size(payload)} characters, more than max_result_chars allows ({budget}); name only the "
            "keys you need in fields",
            **named,
        )
    return _json(payload)


@guarded
def librenms_report(args: Dict[str, Any], **kwargs: Any) -> str:
    """A report view (:mod:`reports`): read-only, every GET through the route allow-list; view ``help`` is answered
    from the plugin. A malformed argument is an error; a refusal (a scope that names nothing, a read off the
    allow-list) is audited as ``query_refused``, as librenms_query's are. The result is kept within
    ``max_result_chars`` by cutting its rows."""
    settings = get_settings()
    if reports.is_help(args):  # answered by the plugin: no client, no LibreNMS call
        try:
            return _json(reports.help_answer(args))
        except reports.ArgumentError as exc:
            return _fail(str(exc))
    client = make_client(settings)
    try:
        payload = reports.run(client, settings, args)
    except reports.ArgumentError as exc:
        return _fail(str(exc))
    except reports.ReportError as exc:
        audit.emit(
            "query_refused",
            plan_id=None,
            actor=_actor_from(kwargs),
            librenms_url=client.base_url,
            tool="librenms_report",
            view=str(args.get("view") or "")[:40],
            path=exc.path,
            reason=clip(str(exc), audit.REASON_LIMIT),
        )
        return _fail(str(exc), refused=True)
    budget = _budget(settings, kwargs)
    key = "candidates" if payload.get("candidates") else "rows"  # an ambiguous scope answers with candidates
    return _json(_fit_rows(payload, key, budget, _report_note(budget, payload), payload["offset"], "notes"))


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
        return _paging(mark_untrusted(payload, *_PLAN_TEXT), start, end, total)

    return _json(_window(build, 0, total, _budget(settings, kwargs)))


@guarded
def librenms_apply(args: Dict[str, Any], **kwargs: Any) -> str:
    store = get_store()
    actor = _actor_from(kwargs)
    plan_id, plan, reason = find_plan(store, args.get("plan_id"), exact=True)
    if plan_id is None or plan is None:
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
    rollback = parse_bool(args.get("rollback_on_failure"), True)
    approved = None
    if not dry_run:  # a dry run writes nothing, whatever the prompt showed
        refusal, approved = _bound("apply", args, kwargs, settings, plan_id, "rb" if rollback else "norb")
        if refusal:
            audit.emit(
                "apply_refused",
                plan_id=plan["id"],
                actor=actor,
                librenms_url=plan.get("librenms_url"),
                reason=refusal,
                dry_run=dry_run,
            )
            return _fail(refusal, refused=True)
    client = make_client(settings)
    try:
        plan = apply_plan(
            client,
            plan,
            store,
            settings,
            rollback_on_failure=rollback,
            dry_run=dry_run,
            actor=actor,
            approved_digest=approved,
        )
    except ExecutionRefused as exc:
        audit.emit(
            "apply_refused",
            plan_id=plan["id"],
            actor=actor,
            librenms_url=plan.get("librenms_url"),
            reason=str(exc),
            dry_run=dry_run,
            **_changed(exc),
        )
        raise
    budget = _budget(settings, kwargs)
    if dry_run:
        checks = plan.get("checks") or []
        if plan.get("status") != "planned" or not checks:  # claimed by another run while the checks ran
            return _fail(f"plan {plan['id']} is {plan.get('status')}; the check was not recorded", refused=True)
        conflicts = checks[-1]["conflicts"]
        checked = {"success": True, **_plan_summary(plan), "dry_run": True, "applicable": not conflicts}
        checked = mark_untrusted({**checked, "conflicts": conflicts}, "conflicts")
        return _json(_fit_rows(checked, "conflicts", budget, _conflicts_note))
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
        return _paging(mark_untrusted(payload, *_PLAN_TEXT), start, end, len(plan["steps"]))

    return _json(_window(build, 0, len(plan["steps"]), budget))


@guarded
def librenms_rollback(args: Dict[str, Any], **kwargs: Any) -> str:
    store = get_store()
    actor = _actor_from(kwargs)
    plan_id, plan, reason = find_plan(store, args.get("plan_id"), exact=True)
    if plan_id is None or plan is None:
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
    refusal, approved = _bound("rollback", args, kwargs, settings, plan_id, "force" if force else "safe")
    if refusal:
        audit.emit(
            "rollback_refused",
            plan_id=plan["id"],
            actor=actor,
            librenms_url=plan.get("librenms_url"),
            reason=refusal,
            force=force,
        )
        return _fail(refusal, refused=True)
    client = make_client(settings)
    try:
        plan = rollback_plan(
            client,
            plan,
            store,
            settings,
            force=force,
            reason="requested",
            actor=actor,
            approved_digest=approved,
        )
    except ExecutionRefused as exc:
        audit.emit(
            "rollback_refused",
            plan_id=plan["id"],
            actor=actor,
            librenms_url=plan.get("librenms_url"),
            reason=str(exc),
            force=force,
            **_changed(exc),
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
        return _paging(mark_untrusted(payload, *_PLAN_TEXT), start, end, len(plan["steps"]))

    return _json(_window(build, 0, len(plan["steps"]), _budget(settings, kwargs)))


@guarded
def librenms_plans(args: Dict[str, Any], **kwargs: Any) -> str:
    maybe_prune(lambda: _actor_from(kwargs))
    store = get_store()
    budget = _budget(get_settings(), kwargs)
    if str(args.get("plan_id") or "").strip():
        _plan_id, plan, reason = find_plan(store, args.get("plan_id"))
        if plan is None:
            return _fail(reason)
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
            return _paging(mark_untrusted(payload, *_PLAN_TEXT), start, end, total)

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
    "librenms_report": librenms_report,
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
    and the attempt must still show in the trail. A block is audited as the refusal it is. For every apply and
    rollback it also keeps what the prompt shows, or that none is shown, for :func:`bind_approval` to hand the
    handler."""
    if not isinstance(tool_name, str) or tool_name not in _HOOKED_TOOLS:
        return None
    if tool_name not in WRITE_TOOLS:
        return _terminal_guard(tool_name, args, kwargs)
    directive, shown = _approval(tool_name, args)
    _note_shown(tool_name, args, kwargs, shown)
    if directive is None:
        return None
    if shown is not None:
        _audit_hook(
            "approval_requested",
            kwargs,
            shown.plan_id,
            None,
            tool=tool_name,
            rule_key=directive["rule_key"],
            digest=shown.digest,
        )
    else:
        event = "apply_refused" if tool_name == "librenms_apply" else "rollback_refused"
        _audit_hook(event, kwargs, None, None, reason=directive["message"], tool=tool_name)
    return directive


def bind_approval(tool_name: Any = None, args: Any = None, **kwargs: Any) -> Dict[str, Any] | None:
    """Hermes ``pre_tool_call``, registered after :func:`pre_tool_call`: hand the handler of an apply or rollback what
    that call's approval prompt showed (plan, variant, content digest), or null when it showed none, in
    :data:`APPROVAL_ARG` by a ``modify`` directive, replacing whatever the model wrote there. The handler refuses a
    call that is not the one the prompt showed, and the claim a plan whose content digest is not the one the prompt
    showed. Nothing for every other tool; never raises."""
    if not isinstance(tool_name, str) or tool_name not in WRITE_TOOLS:
        return None
    key = _call_key(tool_name, args, kwargs)
    with _pending_lock:
        shown = _pending.pop(key, None)
    return {"action": "modify", "args": {APPROVAL_ARG: shown._asdict() if shown is not None else None}}


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


def _approval(tool: str, args: Any) -> Tuple[Dict[str, Any] | None, _Shown | None]:
    """The directive for this call and what its prompt shows. ``approve`` with a summary of the plan (apply) or of
    what its rollback reverts, when ``require_approval`` is on in ``full`` mode; in the other modes the handler
    refuses the model and audits it. The rule_key names the plan, the flag that changes what runs and the content
    digest of the plan as loaded for the message (:func:`store.content_digest`), so a "session" or "always" answer
    never carries over to another plan, variant or content: a plan edited after the answer is asked about again. The
    :class:`_Shown` is made from the same three values, not read back from the key; a key that would not read back
    as them is blocked, since ``approval_decided`` reads it. A ``plan_id`` that is not a saved plan's exact id is
    blocked with the handler's own refusal, and so is any failure to load the plan: asking about a plan nobody can
    be shown would let one that comes to match while the prompt is open run unseen."""
    action = "apply" if tool == "librenms_apply" else "rollback"
    try:
        settings = get_settings()
        if not settings.require_approval or settings.write_mode != "full":
            return None, None
        args = args if isinstance(args, dict) else {}
        if tool == "librenms_apply" and parse_bool(args.get("dry_run"), False):
            return None, None
        plan_id, plan, reason = find_plan(get_store(), args.get("plan_id"), exact=True)
        if plan_id is None or plan is None:
            return {"action": "block", "message": reason}, None
        digest = content_digest(plan)  # of the one load the message is made from
        if tool == "librenms_apply":
            rollback = parse_bool(args.get("rollback_on_failure"), True)
            message, variant = _apply_approval(plan, plan_id, rollback), "rb" if rollback else "norb"
        else:
            force = parse_bool(args.get("force"), False)
            message, variant = _rollback_approval(plan, plan_id, force), "force" if force else "safe"
        shown, rule_key = _Shown(plan_id, variant, digest), f"librenms:{tool}:{plan_id}:{variant}:{digest}"
        found = _RULE_KEY_RE.search(rule_key)
        if found is None or _Shown(found.group("plan"), found.group("variant"), found.group("digest")) != shown:
            return {
                "action": "block",
                "message": f"{action} refused: plan id {one_line(plan_id)} cannot be named in an approval key; "
                "build a new plan with librenms_plan",
            }, None
        return {"action": "approve", "message": message, "rule_key": rule_key}, shown
    except Exception as exc:
        error_id = new_error_id()
        logger.warning("librenms approval hook: plan not loaded (%s)", error_id, exc_info=exc)
        return {
            "action": "block",
            "message": f"{action} refused: the plan could not be loaded for the approval prompt ({error_id}); see "
            "the Hermes log",
        }, None


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
            plan_id, plan, _reason = find_plan(get_store(), ref) if ref else (None, None, "")
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
    command that mentions librenms) as ``approval_decided``. Records the choice, tool, plan id and the content digest
    the answer covers, never the command text."""
    try:
        keys = [str(key) for key in [kwargs.get("pattern_key"), *(kwargs.get("pattern_keys") or [])] if key]
        ours = next((found for found in map(_RULE_KEY_RE.search, keys) if found), None)
        mentioned = "librenms" in str(kwargs.get("command") or "").lower() or any("librenms" in k.lower() for k in keys)
        if ours is None and not mentioned:
            return None
        plan_id = ours.group("plan") if ours is not None and ours.group("plan") != "unresolved" else None
        where: Dict[str, Any] = {"pattern_key": keys[0] if keys else None}
        if ours is not None:
            where = {"rule_key": ours.group("key"), "digest": ours.group("digest")}
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


# (hook, callback) in the order they are registered: bind_approval after pre_tool_call, whose prompt it binds the
# handler to.
HOOKS = (
    ("pre_tool_call", pre_tool_call),
    ("pre_tool_call", bind_approval),
    ("pre_llm_call", pre_llm_call),
    ("post_approval_response", post_approval_response),
)
