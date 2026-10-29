"""``librenms_report``: answers to questions about the network as LibreNMS sees it, in one read-only call.

The model asks for a *view* (``find``, ``devices``), narrows it with ``scope`` and ``filter``, and gets a summary and
rows that already carry names on both ends, units in their key names and ages counted, instead of scanning raw
listings and joining ids in its head (``librenms_query`` stays the escape hatch for everything else). A view reads
only through :meth:`context.ReportContext.get`, the same route allow-list as librenms_query, within a budget of
requests; it never writes.

Views: :mod:`.find` (what a name or phrase could mean, ranked), :mod:`.devices` (state, outages, uptime, polls and
naming checks), :mod:`.ports` (``ports``: state, speed, utilisation, errors and age of each port; ``capacity``: ports
in use and free per device), :mod:`.port` (one port in depth), :mod:`.neighbours` (LLDP/CDP links with both ends'
ports and mismatch checks), :mod:`.locate` (where an IP or MAC address is: the switch port and the ARP entries),
:mod:`.vlans` (VLANs per device, and the ports in one), :mod:`.alerts` (``alerts``: what is alerting now;
``alert_history``: what alerted over a window), :mod:`.health` (sensors, optics, processors, memory and storage
against their limits), :mod:`.routing` (BGP sessions and OSPF neighbours), :mod:`.events` (the eventlog, syslog or
authlog over a window: each entry, or per device or port) and :mod:`.bills` (each bill's 95th percentile or traffic
against its commit or quota). View ``help`` (:mod:`.help`) says what each view takes and returns, without a
LibreNMS call. Shared pieces: :mod:`.context` (reads, budgets, scope, envelope), :mod:`.fuzzy` (ranking) and
:mod:`.units` (units and times).
"""

from __future__ import annotations

from typing import Any, Dict

from . import alerts, bills, devices, events, find, health, help, locate, neighbours, port, ports, routing, vlans
from .context import Ambiguous, ArgumentError, CallBudget, ReportContext, ReportError, View, request

__all__ = ["HELP", "VIEWS", "ArgumentError", "ReportError", "help_answer", "is_help", "run"]

HELP = "help"  # the view the plugin answers itself
HELP_IGNORES = ("limit", "offset")  # paging, which help has no rows for
VIEWS: Dict[str, View] = {
    view.name: view
    for view in (
        find.VIEW, devices.VIEW, ports.VIEW, port.VIEW, ports.CAPACITY, neighbours.VIEW, locate.VIEW, vlans.VIEW,
        alerts.ALERTS, alerts.HISTORY, health.VIEW, routing.VIEW, events.VIEW, bills.VIEW,
    )
}  # fmt: skip


def is_help(args: Dict[str, Any]) -> bool:
    """Whether *args* ask for view ``help``, which needs no client."""
    name = args.get("view")
    return isinstance(name, str) and name.strip().lower() == HELP


def help_answer(args: Dict[str, Any]) -> Dict[str, Any]:
    """View ``help`` (:func:`.help.answer`): the views, or one of them (``topic``). ``limit`` and ``offset``, which
    a model may fill in with their defaults, and an empty scope or filter are ignored: help has no rows to page.
    Raises :class:`ArgumentError` for a topic that is no view, or an argument that would say help reports on
    something (a scope or filter that names anything, a sort, a term, a window)."""
    extra = sorted(
        key
        for key, value in args.items()
        if key not in ("view", "topic", *HELP_IGNORES) and value not in (None, "", {}, [])
    )
    if extra:
        raise ArgumentError(f"view help takes topic (a view's name) alone, not {', '.join(extra)}")
    return help.answer(VIEWS, args.get("topic"))


def run(client: Any, settings: Any, args: Dict[str, Any], *, call_budget: int | None = None) -> Dict[str, Any]:
    """The report *args* ask for, as a result envelope (before the handler fits it to ``max_result_chars``). Raises
    :class:`ArgumentError` for malformed arguments, :class:`ReportError` for a refusal, and the LibreNMSError of a
    read the report cannot do without."""
    name = args.get("view")
    if is_help(args):
        return help_answer(args)
    view = VIEWS.get(name.strip().lower()) if isinstance(name, str) else None
    if view is None:
        raise ArgumentError(f"view must be one of {', '.join([*VIEWS, HELP])}")
    req = request(view, args, settings)
    ctx = ReportContext(client, settings, call_budget=call_budget)
    try:
        return view.build(ctx, req)
    except Ambiguous as exc:
        return ctx.ambiguous(view.name, exc, req.offset, req.limit)
    except CallBudget:
        raise ReportError(
            f"the report needs more than its {ctx.call_budget} requests before it can answer; narrow the scope"
        ) from None
