"""``librenms_report``: answers to questions about the network as LibreNMS sees it, in one read-only call.

The model asks for a *view* (``find``, ``devices``), narrows it with ``scope`` and ``filter``, and gets a summary and
rows that already carry names on both ends, units in their key names and ages counted, instead of scanning raw
listings and joining ids in its head (``librenms_query`` stays the escape hatch for everything else). A view reads
only through :meth:`context.ReportContext.get`, the same route allow-list as librenms_query, within a budget of
requests; it never writes.

Views: :mod:`.find` (what a name or phrase could mean, ranked), :mod:`.devices` (state, outages, uptime, polls and
naming checks), :mod:`.ports` (``ports``: state, speed, utilisation, errors and age of each port; ``capacity``: ports
in use and free per device), :mod:`.port` (one port in depth), :mod:`.neighbours` (LLDP/CDP links with both ends'
ports and mismatch checks), :mod:`.locate` (where an IP or MAC address is: the switch port and the ARP entries) and
:mod:`.vlans` (VLANs per device, and the ports in one). Shared pieces: :mod:`.context` (reads, budgets, scope,
envelope), :mod:`.fuzzy` (ranking) and :mod:`.units` (units and times).
"""

from __future__ import annotations

from typing import Any, Dict

from . import devices, find, locate, neighbours, port, ports, vlans
from .context import Ambiguous, ArgumentError, CallBudget, ReportContext, ReportError, View, request

__all__ = ["VIEWS", "ArgumentError", "ReportError", "run"]

VIEWS: Dict[str, View] = {
    view.name: view
    for view in (
        find.VIEW, devices.VIEW, ports.VIEW, port.VIEW, ports.CAPACITY, neighbours.VIEW, locate.VIEW, vlans.VIEW,
    )
}  # fmt: skip


def run(client: Any, settings: Any, args: Dict[str, Any], *, call_budget: int | None = None) -> Dict[str, Any]:
    """The report *args* ask for, as a result envelope (before the handler fits it to ``max_result_chars``). Raises
    :class:`ArgumentError` for malformed arguments, :class:`ReportError` for a refusal, and the LibreNMSError of a
    read the report cannot do without."""
    name = args.get("view")
    view = VIEWS.get(name.strip().lower()) if isinstance(name, str) else None
    if view is None:
        raise ArgumentError(f"view must be one of {', '.join(VIEWS)}")
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
