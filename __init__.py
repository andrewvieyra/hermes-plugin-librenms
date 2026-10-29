"""hermes-plugin-librenms — LibreNMS change management plugin for Hermes Agent.

Registers five tools (query / plan / apply / rollback / plans), three hooks (the approval prompt for apply and
rollback, the user's request for the audit trail, the approval decision), a ``/librenms`` slash command, a
``hermes librenms`` CLI subcommand, and the bundled ``librenms:workflow`` skill. Registration performs no network
I/O; the LibreNMS client is created lazily inside each tool call.
"""

from __future__ import annotations

import logging
from pathlib import Path

from . import audit, commands, handlers, schemas, settings, sinks
from .version import __version__

__all__ = ["__version__", "register"]

logger = logging.getLogger(__name__)

_PLUGIN_DIR = Path(__file__).parent
_TOOLSET = "librenms"
_EMOJI = {
    "librenms_query": "🔎",
    "librenms_plan": "📋",
    "librenms_apply": "🚀",
    "librenms_rollback": "⏪",
    "librenms_plans": "🗂️",
}
_REQUIRES_ENV = ["LIBRENMS_URL", "LIBRENMS_TOKEN"]


def register(ctx) -> None:
    """Called once by Hermes' plugin loader."""
    settings.set_context(ctx)  # settings are read live from config.yaml from now on
    # status shows these too, but an operator who never runs it would not learn that a setting fell back
    for error in settings.get_settings().errors:
        logger.warning("librenms settings: %s", error)
    for warning in sinks.literal_credential_warnings():  # reads config.yaml through Hermes; no network
        logger.warning("librenms settings: %s", warning)
    audit.set_ctx(ctx)
    audit.set_audit_log(None)  # re-resolve path/enabled from the fresh settings
    sinks.set_worker(None)  # sinks are built lazily from the fresh settings on first event

    for schema in schemas.ALL:
        name = schema["name"]
        ctx.register_tool(
            name=name,
            toolset=_TOOLSET,
            schema=schema,
            handler=handlers.HANDLERS[name],
            check_fn=handlers.check_fn(name),
            requires_env=_REQUIRES_ENV,
            emoji=_EMOJI.get(name, ""),
            description=schema["description"].split(". ")[0],
        )

    # Not guarded: without pre_tool_call, apply and rollback would run without the approval prompt, so a Hermes
    # that cannot take the hooks must fail the load rather than run the plugin without them.
    for hook, callback in handlers.HOOKS.items():
        ctx.register_hook(hook, callback)

    ctx.register_command(
        "librenms",
        handler=commands.slash_handler,
        args_hint="<status|plans|show|check|apply|rollback|prune> [plan_id]",
        description="LibreNMS change management: list, inspect, apply or roll back plans",
    )

    try:
        ctx.register_cli_command(
            name="librenms",
            help="LibreNMS plans: status, plans, show, check, apply, rollback, prune",
            setup_fn=commands.setup_cli,
            handler_fn=commands.cli_handler,
            description="Operate on LibreNMS change plans from the shell (no model involved).",
        )
    except Exception as exc:  # host isolation, or an older Hermes without CLI registration
        logger.debug("librenms plugin: CLI command not registered: %s", exc)

    # No requires_toolsets / requires_tools: Hermes checks them against the tools the model sees directly, and under
    # its tool search (on by default) every plugin tool is deferred behind tool_search / tool_call, so a gate kept
    # the skill out of the system prompt exactly where the model needs it to find the tools. The skill says what to
    # do when they are deferred, and when they are missing.
    skill = _PLUGIN_DIR / "SKILL.md"
    if skill.exists():
        try:
            ctx.register_skill(
                "workflow",
                skill,
                description="Look up LibreNMS devices, ports, alerts and logs, and plan, review, apply and roll back "
                "changes safely",
            )
        except Exception as exc:
            logger.debug("librenms plugin: skill not registered: %s", exc)
