"""Operator entry points that bypass the model: the ``/librenms`` slash command inside a session and the
``hermes librenms`` CLI subcommand. Both reuse the tool handlers so behaviour is identical everywhere; what they add
is the operator's identity (``via: slash`` or ``cli``), human-readable text, and escaping of everything printed."""

from __future__ import annotations

import json
import logging
import os
import secrets
import shlex
from typing import Any, Dict, List, Tuple

from . import audit, handlers, timefmt
from .client import LibreNMSError
from .redact import mask, one_line, printable
from .settings import get_settings
from .store import get_store

logger = logging.getLogger(__name__)

SLASH = "/librenms"
CLI = "hermes librenms"

_HELP = """\
{prog} — LibreNMS change management

  status                            Connectivity check, LibreNMS version, write mode and settings
  plans [status]                    List saved plans (optionally filtered by status)
  show <plan_id>                    Full diff, journal and rollback outcome of one plan
                                    (<plan_id> may be an unambiguous suffix, e.g. 4f1a)
  check <plan_id>                   Re-verify a plan's preconditions without writing
  apply <plan_id> [--no-rollback]   Apply a reviewed plan
  rollback <plan_id> [--force]      Revert an applied plan from its journal
  prune [--days N] [--dry-run]      Delete plans older than N days (default: plan_retention_days)
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

# Hermes binds these for an agent session and its terminal tool passes them to the shells it starts.
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


def _result(text: str) -> str:
    """Render a handler's JSON for a human: the error, else the ``report``/``diff`` text, else pretty JSON. A failed
    apply has no ``error`` key, so it prints its journal report."""
    try:
        data = json.loads(text)
    except ValueError:
        return text
    if not data.get("success", True) and data.get("error"):
        lines = [f"Error: {data['error']}"]
        for err in data.get("errors") or []:
            lines.append(f"  [{err.get('index')}] {err.get('error')}")
        return "\n".join(lines)
    for candidate in ("report", "diff"):
        if data.get(candidate):
            return data[candidate]
    return json.dumps(data, indent=2, ensure_ascii=False, default=str)


def _plans(positional: List[str]) -> str:
    args: Dict[str, Any] = {"limit": 50}
    if positional:
        args["status"] = positional[0]
    data = json.loads(handlers.librenms_plans(args))
    if not data.get("success"):
        return f"Error: {data.get('error')}"
    if not data.get("plans"):
        return f"No {positional[0]} plans." if positional else "No plans saved."
    lines = []
    for p in data["plans"]:
        s = p.get("summary") or {}
        counts = ", ".join(f"{s.get(a, 0)}{a[0]}" for a in ("create", "update", "delete", "action", "noop"))
        when = timefmt.local(p.get("created_at"))
        lines.append(
            f"{one_line(p.get('plan_id'))}  {one_line(p.get('status')):<21} {counts:<22} {when}  "
            f"{one_line(p.get('description'))}"
        )
    return "\n".join(lines)


def _prune(options: Dict[str, Any], prog: str, actor: Dict[str, Any]) -> str:
    raw = options.get("--days")
    if raw is not None and not (raw.isascii() and raw.isdigit()):
        return f"Usage: {prog} {_SYNTAX['prune'][0]}"
    days = int(raw) if raw is not None else None
    dry = bool(options.get("--dry-run"))
    result = handlers.prune_plans(days=days, dry_run=dry, actor=actor)
    if result["max_age_days"] <= 0:
        return "Retention is disabled (plan_retention_days is 0); pass --days N to prune explicitly."
    if not result["removed"]:
        return f"Nothing older than {result['max_age_days']} days."
    verb = "Would remove" if dry else "Removed"
    lines = [f"{verb} {len(result['removed'])} plan(s) older than {result['max_age_days']} days:"]
    lines += [f"  {one_line(r['id'])}  {one_line(r['status']):<21} {r['age_days']}d" for r in result["removed"]]
    return "\n".join(lines)


def _resolve(fragment: str, prog: str) -> Tuple[str | None, str]:
    """``(plan_id, "")`` for what the operator typed, or ``(None, message)`` when it is unknown or ambiguous."""
    plan_id, candidates = get_store().resolve(fragment)
    if plan_id is not None:
        return plan_id, ""
    if not candidates:
        return None, f"No plan matches {fragment!r}. Use {prog} plans to list them."
    return None, f"{fragment!r} is ambiguous; matches:\n" + "\n".join(f"  {one_line(c)}" for c in candidates)


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


def _plan_command(cmd: str, plan_id: str, options: Dict[str, Any], via: str, actor: Dict[str, Any]) -> str:
    if cmd == "show":
        data = json.loads(handlers.librenms_plans({"plan_id": plan_id}))
        if not data.get("success"):
            return f"Error: {data.get('error')}"
        out = data.get("diff") or ""
        if data.get("journal"):
            out += "\n\n" + (data.get("report") or "")
        return out
    if cmd == "check":
        data = json.loads(handlers.librenms_apply({"plan_id": plan_id, "dry_run": True}, _actor=actor))
        if not data.get("success"):
            return f"Error: {data.get('error')}"
        if data.get("applicable"):
            return f"{plan_id} is applicable: all preconditions hold."
        return f"{plan_id} is NOT applicable:\n" + "\n".join(
            f"  [{c.get('index')}] {c.get('error')}" for c in data.get("conflicts") or []
        )
    refusal = _agent_shell_refusal(cmd, plan_id, actor) if via == audit.VIA_CLI else None
    if refusal:
        return f"Error: {refusal}"
    if cmd == "apply":
        args = {"plan_id": plan_id, "rollback_on_failure": not options.get("--no-rollback")}
        return _result(handlers.librenms_apply(args, _actor=actor))
    args = {"plan_id": plan_id, "force": bool(options.get("--force"))}
    return _result(handlers.librenms_rollback(args, _actor=actor))


def _run(argv: List[str], via: str, actor: Dict[str, Any]) -> str:
    prog = CLI if via == audit.VIA_CLI else SLASH
    if not argv or argv[0] in {"help", "-h", "--help"}:
        return _HELP.format(prog=prog)
    cmd, rest = argv[0], argv[1:]
    if cmd not in _SYNTAX:
        return f"Unknown subcommand: {cmd}\n\n{_HELP.format(prog=prog)}"
    parsed = _split(cmd, rest)
    if parsed is None or (cmd in _PLAN_COMMANDS and len(parsed[0]) != 1):
        return f"Usage: {prog} {_SYNTAX[cmd][0]}"
    positional, options = parsed
    if cmd == "status":
        return json.dumps(mask(handlers.status_report()), indent=2, ensure_ascii=False, default=str)
    if cmd == "plans":
        return _plans(positional)
    if cmd == "prune":
        return _prune(options, prog, actor)
    plan_id, message = _resolve(positional[0], prog)
    if plan_id is None:
        return message
    return _plan_command(cmd, plan_id, options, via, actor)


def run(argv: List[str], *, via: str = audit.VIA_SLASH, caller: Dict[str, Any] | None = None) -> str:
    """Run one subcommand and return its text. ``via`` names the operator path for the audit trail (``slash`` or
    ``cli``); ``caller`` holds what Hermes passed a slash handler (``session_id``, ``source``, ``platform``). The
    output is escaped with :func:`redact.printable` (plan labels, notes and errors come from LibreNMS and from the
    model), and nothing raises: a slash command's exception would reach the chat unescaped."""
    try:
        text = _run(list(argv), via, audit.capture_actor(caller or {}, via=via))
    except LibreNMSError as exc:  # status, or a client the handlers could not build; messages are token-scrubbed
        text = f"Error: {exc}"
    except Exception:
        error_id = f"err-{secrets.token_hex(6)}"
        logger.warning("librenms command failed (%s)", error_id, exc_info=True)
        text = f"Error: the command failed unexpectedly ({error_id}); the Hermes log has the details"
    return printable(text)


def slash_handler(raw_args: str = "", **kwargs: Any) -> str:
    """Entry point Hermes calls for ``/librenms …``; the gateway's ``source``, ``session_id`` and ``platform``
    keywords identify who typed it."""
    caller = {key: kwargs[key] for key in ("session_id", "source", "platform") if kwargs.get(key) is not None}
    return run(_parse(raw_args), via=audit.VIA_SLASH, caller=caller)


# -- argparse wiring for ``hermes librenms ...`` --------------------------------------------------


def setup_cli(parser: Any) -> None:
    """argparse subcommands for ``hermes librenms …``."""
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
    p = sub.add_parser("prune", help="Delete plans older than the retention period")
    p.add_argument("--days", type=int, default=None, help="Override plan_retention_days")
    p.add_argument("--dry-run", action="store_true", help="List what would be removed")


def cli_handler(args: Any) -> None:
    """Turn the parsed argparse namespace back into argv and run it as the CLI operator path; prints the result."""
    argv: List[str] = [getattr(args, "librenms_cmd", None) or "help"]
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
    print(run(argv, via=audit.VIA_CLI))
