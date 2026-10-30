"""Operator entry points that bypass the model: the ``/librenms`` slash command inside a session and the
``hermes librenms`` CLI subcommand. Both reuse the tool handlers so behaviour is identical everywhere; what they add
is the operator's identity (``via: slash`` or ``cli``), human-readable text, escaping of everything printed, and for
the CLI an exit status a script can test."""

from __future__ import annotations

import json
import logging
import os
import secrets
import shlex
import sys
from typing import Any, Dict, List, Tuple

from . import audit, handlers, timefmt
from .client import LibreNMSError
from .redact import mask, one_line, printable
from .settings import get_settings
from .store import MIN_FRAGMENT, get_store

logger = logging.getLogger(__name__)

SLASH = "/librenms"
CLI = "hermes librenms"

# What every subcommand reports beside its text, and `hermes librenms` exits with (Hermes makes an int returned by a
# CLI handler the exit status): a script running `hermes librenms apply <id> && ...` must see a failed, refused or
# rolled-back apply, and a cron job running `hermes librenms prune` must see an audit log retention that could not
# run. OK also for an empty listing and for prune with nothing to remove.
OK, FAILED, USAGE = 0, 1, 2
EXIT_STATUS = (
    "Exit status: 0 done; 1 failed, refused, not applicable, LibreNMS unreachable, no single plan named, or the "
    "audit log's retention could not run; 2 usage error."
)

_HELP = """\
{prog} — LibreNMS change management

  status                            Connectivity check, LibreNMS version, write mode and settings
  plans [status]                    List saved plans (optionally filtered by status)
  show <plan_id>                    Full diff, journal and rollback outcome of one plan
                                    (<plan_id> may be the end of one, 4+ characters, e.g. 4f1a)
  check <plan_id>                   Re-verify a plan's preconditions without writing
  apply <plan_id> [--no-rollback]   Apply a reviewed plan
  rollback <plan_id> [--force]      Revert an applied plan from its journal
  prune [--days N] [--dry-run]      Delete plans older than N days (default: plan_retention_days),
                                    and rotated audit logs past audit_keep_files or audit_retention_days
"""

# Per subcommand: its usage line, how many positional arguments it takes at most, and its options (True for one
# that takes a value). Anything else is refused rather than ignored, so a mistyped flag never changes what runs.
_SYNTAX: Dict[str, Tuple[str, int, Dict[str, bool]]] = {
    "status": ("status", 0, {}),
    "plans": ("plans [status]", 1, {}),
    "show": ("show <plan_id>", 1, {}),
    "check": ("check <plan_id>", 1, {}),
    "apply": ("apply <plan_id> [--no-rollback]", 1, {"--no-rollback": False}),
    "rollback": ("rollback <plan_id> [--force]", 1, {"--force": False}),
    "prune": ("prune [--days N] [--dry-run]", 0, {"--days": True, "--dry-run": False}),
}
_PLAN_COMMANDS = ("show", "check", "apply", "rollback")

# Hermes binds these for an agent session and its terminal tool passes them to the shells it starts. Not
# HERMES_AGENT or AI_AGENT: every `hermes` command sets those in its own environment, an operator's included.
AGENT_SESSION_VARS = ("HERMES_SESSION_ID", "HERMES_SESSION_KEY")
AGENT_SESSION_REASON = "started from a Hermes agent session"


def _parse(raw: str) -> List[str]:
    """Shell-style split of the slash command's argument string; whitespace split when the quoting is broken."""
    try:
        return shlex.split(raw or "")
    except ValueError:
        return (raw or "").split()


def _split(cmd: str, rest: List[str]) -> Tuple[List[str], Dict[str, Any]] | None:
    """The positional arguments and options *rest* gives *cmd* (``--days 3`` or ``--days=3``), or None when it
    holds an option *cmd* does not take, one given twice, or too many arguments."""
    _usage, most, allowed = _SYNTAX[cmd]
    positional: List[str] = []
    options: Dict[str, Any] = {}
    items = list(rest)
    while items:
        item = items.pop(0)
        if not item.startswith("--"):  # a plan id suffix such as -ab12 is an argument, not an option
            positional.append(item)
            continue
        name, equals, value = item.partition("=")
        if name not in allowed or name in options or (equals and not allowed[name]):
            return None
        if allowed[name] and not equals:
            if not items:
                return None
            value = items.pop(0)
        options[name] = value if allowed[name] else True
    return (positional, options) if len(positional) <= most else None


def _result(text: str) -> Tuple[str, int]:
    """Render a handler's JSON for a human, with its status: the error, else the ``report``/``diff`` text, else
    pretty JSON. A failed apply has no ``error`` key, so it prints its journal report; ``success`` is what decides
    the status (an apply that failed and was rolled back, a rollback that left conflicts)."""
    try:
        data = json.loads(text)
    except ValueError:
        return text, FAILED
    status = OK if data.get("success", True) else FAILED
    if status and data.get("error"):
        lines = [f"Error: {data['error']}"]
        for err in data.get("errors") or []:
            lines.append(f"  [{err.get('index')}] {err.get('error')}")
        return "\n".join(lines), status
    for candidate in ("report", "diff"):
        if data.get(candidate):
            return data[candidate], status
    return json.dumps(data, indent=2, ensure_ascii=False, default=str), status


def _status() -> Tuple[str, int]:
    """The status report as JSON; FAILED when LibreNMS could not be configured or reached (the report still holds
    the write mode, settings and settings errors, which say why writes may be refused)."""
    report = handlers.status_report()
    text = json.dumps(mask(report), indent=2, ensure_ascii=False, default=str)
    return text, OK if (report.get("connection") or {}).get("ok") else FAILED


def _plans(positional: List[str], actor: Dict[str, Any]) -> Tuple[str, int]:
    args: Dict[str, Any] = {"limit": 50}
    if positional:
        args["status"] = positional[0]
    data = json.loads(handlers.librenms_plans(args, _actor=actor))
    if not data.get("success"):
        return f"Error: {data.get('error')}", FAILED
    if not data.get("plans"):
        return (f"No {positional[0]} plans." if positional else "No plans saved."), OK
    lines = []
    for p in data["plans"]:
        s = p.get("summary") or {}
        counts = ", ".join(f"{s.get(a, 0)}{a[0]}" for a in ("create", "update", "delete", "action", "noop"))
        when = timefmt.local(p.get("created_at"))
        lines.append(
            f"{one_line(p.get('plan_id'))}  {one_line(p.get('status')):<21} {counts:<22} {when}  "
            f"{one_line(p.get('description'))}"
        )
    return "\n".join(lines), OK


def _prune(options: Dict[str, Any], prog: str, actor: Dict[str, Any]) -> Tuple[str, int]:
    raw = options.get("--days")
    if raw is not None and not (raw.isascii() and raw.isdigit()):
        return f"Usage: {prog} {_SYNTAX['prune'][0]}", USAGE
    days = int(raw) if raw is not None else None
    dry = bool(options.get("--dry-run"))
    verb = "Would remove" if dry else "Removed"
    result = handlers.prune_plans(days=days, dry_run=dry, actor=actor)
    if result["max_age_days"] <= 0:
        lines = ["Retention is disabled (plan_retention_days is 0); pass --days N to prune explicitly."]
    elif not result["removed"]:
        lines = [f"Nothing older than {result['max_age_days']} days."]
    else:
        lines = [f"{verb} {len(result['removed'])} plan(s) older than {result['max_age_days']} days:"]
        lines += [f"  {one_line(r['id'])}  {one_line(r['status']):<21} {r['age_days']}d" for r in result["removed"]]
    audit_result = handlers.prune_audit(dry_run=dry, actor=actor)
    return "\n".join(lines + _audit_retention(audit_result, verb)), FAILED if audit_result.get("error") else OK


def _audit_retention(result: Dict[str, Any], verb: str) -> List[str]:
    """What ``prune`` says about the audit log: its retention, the rotated files it removed (by name; the directory
    is the log's), and why it could not run or ran only in part, which is never "nothing to remove"."""
    keep, days = result["keep_files"], result["max_age_days"]
    if not keep and not days and not result.get("error"):
        return ["Audit log: retention is off (audit_keep_files and audit_retention_days are 0)."]
    policy = [f"the newest {keep}"] if keep else []
    policy += [f"none older than {days} days"] if days else []
    lines = []
    if result["removed"]:
        lines = [f"Audit log: {verb.lower()} {len(result['removed'])} rotated file(s) (keeping {', '.join(policy)}):"]
        lines += [f"  {one_line(name)}" for name in result["removed"]]
    if result.get("error"):
        return lines + [f"Audit log: {one_line(result['error'])}; see Hermes' log."]
    return lines or [f"Audit log: no rotated file to remove (keeping {', '.join(policy)})."]


def _resolve(fragment: str, prog: str) -> Tuple[str | None, str]:
    """``(plan_id, "")`` for what the operator typed, or ``(None, message)`` when it is unknown, ambiguous or too
    short to name a plan (:meth:`PlanStore.resolve`): apply and rollback run at once, so a typo must not pick
    whichever plan happens to contain it."""
    plan_id, candidates = get_store().resolve(fragment)
    if plan_id is not None:
        return plan_id, ""
    if len(candidates) > 1:
        return None, f"{fragment!r} is ambiguous; matches:\n" + "\n".join(f"  {one_line(c)}" for c in candidates)
    if len(fragment.strip()) < MIN_FRAGMENT:
        return None, (
            f"{fragment!r} is too short to name a plan: give the full plan id or its last {MIN_FRAGMENT} or more "
            f"characters (e.g. 4f1a). Use {prog} plans to list them."
        )
    return None, f"No plan matches {fragment!r}. Use {prog} plans to list them."


def _named(fragment: str, plan_id: str) -> str:
    """The line that says which plan a fragment named: its id, status and description."""
    plan = get_store().load(plan_id) or {}
    description = f": {one_line(plan['description'])}" if plan.get("description") else ""
    return f"{fragment.strip()!r} is plan {plan_id} ({one_line(plan.get('status'))}){description}"


def _agent_shell_refusal(cmd: str, plan_id: str, actor: Dict[str, Any]) -> str | None:
    """Why ``hermes librenms apply|rollback`` is refused in this shell, or None. A shell that an agent session started
    (its terminal tool passes the session variables down) lets the model write past ``operator_only`` and past the
    approval prompt, which guards only the tools; so it may write only where the tools need no approval anyway:
    ``write_mode: full`` with ``require_approval: false``. Audited as ``apply_refused`` / ``rollback_refused``."""
    present = [name for name in AGENT_SESSION_VARS if os.environ.get(name)]
    settings = get_settings()
    if not present or (settings.write_mode == "full" and not settings.require_approval):
        return None
    plan = get_store().load(plan_id) or {}
    audit.emit(
        f"{cmd}_refused",
        plan_id=plan_id,
        actor=actor,
        librenms_url=plan.get("librenms_url"),
        reason=AGENT_SESSION_REASON,
        write_mode=settings.write_mode,
        session_variables=present,
    )
    return f"{cmd} refused: this shell was started by a Hermes agent session; run the command from your own terminal"


def _plan_command(cmd: str, plan_id: str, options: Dict[str, Any], via: str, actor: Dict[str, Any]) -> Tuple[str, int]:
    if cmd == "show":  # an operator path: the whole plan, never a page of it
        data = json.loads(handlers.librenms_plans({"plan_id": plan_id}, _actor=actor))
        if not data.get("success"):
            return f"Error: {data.get('error')}", FAILED
        out = data.get("diff") or ""
        if data.get("journal"):
            out += "\n\n" + (data.get("report") or "")
        return out, OK
    if cmd == "check":  # a plan that would conflict fails, so `check <id> && apply <id>` stops there
        data = json.loads(handlers.librenms_apply({"plan_id": plan_id, "dry_run": True}, _actor=actor))
        if not data.get("success"):
            return f"Error: {data.get('error')}", FAILED
        if data.get("applicable"):
            return f"{plan_id} is applicable: all preconditions hold.", OK
        return f"{plan_id} is NOT applicable:\n" + "\n".join(
            f"  [{c.get('index')}] {c.get('error')}" for c in data.get("conflicts") or []
        ), FAILED
    refusal = _agent_shell_refusal(cmd, plan_id, actor) if via == audit.VIA_CLI else None
    if refusal:
        return f"Error: {refusal}", FAILED
    if cmd == "apply":
        args = {"plan_id": plan_id, "rollback_on_failure": not options.get("--no-rollback")}
        return _result(handlers.librenms_apply(args, _actor=actor))
    args = {"plan_id": plan_id, "force": bool(options.get("--force"))}
    return _result(handlers.librenms_rollback(args, _actor=actor))


def _help(prog: str) -> str:
    return _HELP.format(prog=prog) + (f"\n{EXIT_STATUS}\n" if prog == CLI else "")


def _run(argv: List[str], via: str, actor: Dict[str, Any]) -> Tuple[str, int]:
    prog = CLI if via == audit.VIA_CLI else SLASH
    if not argv:  # `hermes librenms` alone: nothing was asked for
        return _help(prog), USAGE
    if argv[0] in {"help", "-h", "--help"}:
        return _help(prog), OK
    cmd, rest = argv[0], argv[1:]
    if cmd not in _SYNTAX:
        return f"Unknown subcommand: {cmd}\n\n{_help(prog)}", USAGE
    parsed = _split(cmd, rest)
    if parsed is None or (cmd in _PLAN_COMMANDS and len(parsed[0]) != 1):
        return f"Usage: {prog} {_SYNTAX[cmd][0]}", USAGE
    positional, options = parsed
    if cmd != "prune":  # retention also for a profile whose plans are only ever handled from here
        handlers.maybe_prune(actor)
    if cmd == "status":
        return _status()
    if cmd == "plans":
        return _plans(positional, actor)
    if cmd == "prune":
        return _prune(options, prog, actor)
    plan_id, message = _resolve(positional[0], prog)
    if plan_id is None:
        return message, FAILED
    if cmd == "show" or positional[0].strip() == plan_id:  # the diff names it; so did the operator
        return _plan_command(cmd, plan_id, options, via, actor)
    named = _named(positional[0], plan_id)  # before the command runs: the status it names is the one it found
    text, status = _plan_command(cmd, plan_id, options, via, actor)
    return f"{named}\n{text}", status


def run_with_status(
    argv: List[str], *, via: str = audit.VIA_SLASH, caller: Dict[str, Any] | None = None
) -> Tuple[str, int]:
    """Run one subcommand: its text and its status (:data:`OK`, :data:`FAILED` or :data:`USAGE`). ``via`` names
    the operator path for the audit trail (``slash`` or ``cli``); ``caller`` holds what Hermes passed a slash
    handler (``session_id``, ``source``, ``platform``). The text is escaped with :func:`redact.printable` (plan
    labels, notes and errors come from LibreNMS and from the model), and nothing raises: a slash command's exception
    would reach the chat unescaped."""
    try:
        text, status = _run(list(argv), via, audit.capture_actor(caller or {}, via=via))
    except LibreNMSError as exc:  # the handlers return theirs; defence in depth, and messages are token-scrubbed
        text, status = f"Error: {exc}", FAILED
    except Exception:
        error_id = f"err-{secrets.token_hex(6)}"
        logger.warning("librenms command failed (%s)", error_id, exc_info=True)
        text, status = f"Error: the command failed unexpectedly ({error_id}); the Hermes log has the details", FAILED
    return printable(text), status


def run(argv: List[str], *, via: str = audit.VIA_SLASH, caller: Dict[str, Any] | None = None) -> str:
    """:func:`run_with_status` without the status: the text a slash command answers with."""
    return run_with_status(argv, via=via, caller=caller)[0]


def slash_handler(raw_args: str = "", **kwargs: Any) -> str:
    """Entry point Hermes calls for ``/librenms …``; the gateway's ``source``, ``session_id`` and ``platform``
    keywords identify who typed it."""
    caller = {key: kwargs[key] for key in ("session_id", "source", "platform") if kwargs.get(key) is not None}
    return run(_parse(raw_args), via=audit.VIA_SLASH, caller=caller)


# -- argparse wiring for ``hermes librenms ...`` --------------------------------------------------


def setup_cli(parser: Any) -> None:
    """argparse subcommands for ``hermes librenms …``."""
    parser.epilog = EXIT_STATUS
    sub = parser.add_subparsers(dest="librenms_cmd")
    sub.add_parser("status", help="Connectivity check, LibreNMS version and write mode")
    p = sub.add_parser("plans", help="List saved plans")
    p.add_argument("status", nargs="?", help="Filter by status")
    for name, help_text in (("show", "Show one plan"), ("check", "Re-verify preconditions")):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("plan_id")
    p = sub.add_parser("apply", help="Apply a reviewed plan")
    p.add_argument("plan_id")
    p.add_argument("--no-rollback", action="store_true", help="Do not revert completed steps on failure")
    p = sub.add_parser("rollback", help="Revert an applied plan")
    p.add_argument("plan_id")
    p.add_argument("--force", action="store_true", help="Override post-apply modification checks")
    p = sub.add_parser("prune", help="Delete plans and rotated audit logs past their retention")
    p.add_argument("--days", type=int, default=None, help="Override plan_retention_days")
    p.add_argument("--dry-run", action="store_true", help="List what would be removed; change nothing")


def cli_handler(args: Any) -> int:
    """Turn the parsed argparse namespace back into argv and run it as the CLI operator path. Prints the result, on
    stderr when the command did not succeed, and returns its status, which Hermes exits with."""
    cmd = getattr(args, "librenms_cmd", None)
    argv: List[str] = [cmd] if cmd else []
    for attr in ("status", "plan_id"):
        value = getattr(args, attr, None)
        if isinstance(value, str) and value:
            argv.append(value)
    if getattr(args, "no_rollback", False):
        argv.append("--no-rollback")
    if getattr(args, "force", False):
        argv.append("--force")
    if getattr(args, "days", None) is not None:
        argv += ["--days", str(args.days)]
    if getattr(args, "dry_run", False):
        argv.append("--dry-run")
    text, status = run_with_status(argv, via=audit.VIA_CLI)
    print(text, file=sys.stderr if status else sys.stdout)
    return status
