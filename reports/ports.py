"""Views ``ports`` and ``capacity``: each port in scope with its state, speed, utilisation, errors and when it last
changed, and per device how many of its ethernet ports are in use and how many are free.

LibreNMS keeps raw counters in mixed units (:mod:`.units`), and the one route that computes utilisation (the ifName
route) is refused, so :func:`facts` derives what the questions need from a port row and its device's row:

- ``state``: ``disabled`` when the port is administratively down, else its operational status (``up``, ``down``,
  ``lowerLayerDown``, ``notPresent``, ...). LibreNMS counts as down every port that is administratively up and
  not up, unless it is ignored or its polling is disabled (``Port::scopeIsDown``); ``summary.not_up`` counts
  those, and ``polling_disabled`` says which ports LibreNMS no longer polls.
- ``speed_bps``: the circuit speed parsed from the description (``port_descr_speed``, ``egress/ingress``) when it
  is set, as LibreNMS's web UI measures utilisation (``Port::getSpeeds``); else ``ifSpeed``; else
  ``ifHighSpeed`` Mbit/s, which older releases kept beside an ``ifSpeed`` stuck at 4294967295. 0 is not known.
- ``in_bps``/``out_bps``: the octet rates times 8; ``in_pct`` against the ingress speed, ``out_pct`` against the
  egress speed (null when the speed is not known), ``util_pct`` the larger.
- errors in the last poll (``*_delta``) and per second over it.
- ``last_change_age_s``: the device's uptime less ``ifLastChange`` (its sysUpTime then, in hundredths of a second),
  plus the time since that poll. An ``ifLastChange`` of 0 means the port has not changed since the device's SNMP
  agent started: the age is then at least the uptime (``last_change_at_least``). Unknown when the uptime is, when
  sysUpTime may have wrapped (a 32-bit count of hundredths wraps after 497 days), or when the two disagree.
- ``stale``: the port was last polled more than two poll periods before ``data_as_of`` (a device that is down keeps
  its last rates). A stale port's rates and errors are not current: it passes neither ``util_above_pct`` nor
  ``errors``, and sorts after the ports that have current figures.
- ``no_description``: an empty ``ifAlias``, or one that only repeats ``ifName`` or ``ifDescr``.

Reads (:func:`read_ports`): ``devices/{id}/ports`` for each device of a scope of at most :data:`DEVICE_READS`
devices, ``ports/{id}`` for each port of a port group of at most :data:`PORT_READS` ports, else one ``ports``
listing of every port, filtered here; each with an explicit column list, never every column. A listing too large to
read falls back to one device at a time within the request budget, the scope's devices before any a view joins (the
far ends of links); the answer is partial only when the budget does not reach every device.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, List, Set, Tuple

from ..client import LibreNMSError, is_digits
from ..listing import natural_key
from . import units
from .context import ReportContext, Request, Scope, View, brief, hostname_order, port_label, port_state, rows_of, truthy

SCOPE_KEYS = ("device", "devices", "group", "location", "os", "type", "port_group")
# What a report asks LibreNMS for, per port: columns of the ports table, which LibreNMS checks (one it lacks is an HTTP
# 400, so never ifHighSpeed, which the current schema has folded into ifSpeed).
COLUMNS = (
    "port_id,device_id,ifIndex,ifName,ifDescr,ifAlias,ifType,ifAdminStatus,ifOperStatus,ifSpeed,ifDuplex,ifMtu,"
    "ifLastChange,port_descr_speed,ifInOctets_rate,ifOutOctets_rate,ifInErrors_delta,ifOutErrors_delta,poll_time,"
    "poll_period,ignore,disabled"
)
DEVICE_READS = 10  # devices whose ports are read one device at a time; past that, one listing of every port
PORT_READS = 10  # ports of a port group read one at a time; past that, the listing
POLL_S = 300  # LibreNMS's polling interval, for a port whose poll_period is not known
STALE_POLLS = 2  # polls a port may miss before its figures are stale
WRAP_S = 2**32 / 100  # sysUpTime, and so ifLastChange, counts hundredths of a second in 32 bits
UNKNOWN_SPEED = 4294967295  # an ifSpeed at the top of its 32 bits: faster than it can say
BUSY_PCT = 80
STATES = ("up", "down", "disabled", "lowerLayerDown", "notPresent", "dormant", "testing", "unknown")
SUMMARY_STATES = ("up", "down", "disabled", "lowerLayerDown", "notPresent")
DUPLEX = ("full", "half", "unknown")
# IANAifType names LibreNMS stores for physical ethernet ports.
ETHERNET = frozenset({"ethernetCsmacd", "iso88023Csmacd", "fastEther", "fastEtherFX", "gigabitEthernet"})
# Gi0/0/0.100, ge-0/0/0.0: a sub-interface or logical unit. Not a ':' (xe-0/0/48:0 is a channel of a broken-out
# physical port on Junos, ethernetCsmacd like any other).
_SUBINTERFACE_RE = re.compile(r"\.\d+$")
TEXT_KEYS = ("hostname", "display", "port", "description")
CAPACITY_TEXT = ("hostname", "display", "location")
IDLE_DAYS = 30
IDS_SHOWN = 10  # device ids a partial reason names


@dataclass
class Port:
    """A port's report row and what its filters, orders and summaries compare."""

    row: Dict[str, Any]
    device: Dict[str, Any]
    state: str | None
    speed: int | None
    util: float | None  # the larger of in_pct and out_pct; None when not known or not current
    errors: int  # in and out errors in the last poll; 0 when not current
    fresh: bool
    idle: int | None  # seconds since the port last went up or down
    idle_at_least: bool
    ethernet: bool
    not_up: bool  # administratively up, not up, not ignored, still polled: what LibreNMS counts as down
    names: str  # ifName, ifDescr and ifAlias, folded, for filter.text


# -- reads -----------------------------------------------------------------------------------------------------------
def read_ports(
    ctx: ReportContext, scope: Scope, *, required: bool = True, joined: Set[int] = frozenset()
) -> List[Dict[str, Any]]:
    """The port rows *scope* covers (never a deleted one), in LibreNMS's order per device: read per device, per port
    of a port group, or in one listing (see the module's docstring). The ports of a scope of one device are what the
    report is about, so a failure to read them fails it, unless they are not *required* (a view that reports
    something else and only joins the ports to it is then partial). *joined* are devices outside the scope whose
    ports the view joins to its rows too (the far end of a link): read with the scope's, after them whenever the
    ports are read one device at a time."""
    devices = ctx.devices()
    ids = None if scope.ids is None else scope.ids | set(joined)
    if scope.port_ids is not None and len(scope.port_ids) <= PORT_READS:
        rows = []
        for port_id in sorted(scope.port_ids):
            rows += rows_of(ctx.optional(f"port {port_id}", "ports", port_id))
    elif scope.ids is not None and ids is not None and len(ids) <= DEVICE_READS:
        targets = _in_order(devices, scope.ids) + _in_order(devices, ids - scope.ids)
        rows = []
        for device_id in targets:
            segments = ("devices", device_id, "ports")
            if len(targets) == 1 and required:  # the one read this report is about: a failure fails it
                rows += rows_of(ctx.get(*segments, params={"columns": COLUMNS}))
            else:
                rows += rows_of(ctx.optional(f"ports of device {device_id}", *segments, params={"columns": COLUMNS}))
    else:
        rows = _every_port(ctx, scope, required=required, joined=joined)
    rows = [row for row in rows if is_digits(row.get("port_id")) and not truthy(row.get("deleted"))]
    if ids is not None:
        rows = [row for row in rows if is_digits(row.get("device_id")) and int(row["device_id"]) in ids]
    if scope.port_ids is not None:
        rows = [row for row in rows if int(row["port_id"]) in scope.port_ids]
    return rows


def _every_port(
    ctx: ReportContext, scope: Scope, *, required: bool = True, joined: Set[int] = frozenset()
) -> List[Dict[str, Any]]:
    """One ``ports`` listing (whose failure fails the report only when the ports are *required*). When LibreNMS's
    answer is too large to read, the ports of the scope's devices one at a time, in hostname order, then those of
    the *joined* devices, as far as the request budget goes: the answer is partial when that leaves a device out (a
    read that fails is partial on its own, :meth:`ReportContext.optional`), and else says how it was read."""
    try:
        if required:
            return rows_of(ctx.get("ports", params={"columns": COLUMNS}))
        return rows_of(ctx.optional("ports", "ports", params={"columns": COLUMNS}, raising=("too_large",)))
    except LibreNMSError as exc:
        if exc.kind != "too_large":
            raise
    devices = ctx.devices()
    targets = _in_order(devices, scope.ids if scope.ids is not None else set(devices))
    others = _in_order(devices, set(joined) - set(targets)) if scope.ids is not None else []
    rows: List[Dict[str, Any]] = []
    tried = read = 0
    for device_id in targets + others:
        if ctx.calls >= ctx.call_budget:
            break
        found = ctx.optional(f"ports of device {device_id}", "devices", device_id, "ports", params={"columns": COLUMNS})
        rows += rows_of(found)
        tried += 1
        if found is not None and tried <= len(targets):
            read += 1
    left = others[max(tried - len(targets), 0) :]  # read in order, so those the budget did not reach are the last
    if tried < len(targets):
        ctx.partial(
            f"the listing of every port is too large to read, so the ports of {read} of the {len(targets)} devices "
            "in scope were read one device at a time; narrow the scope (a device, a location, a group) for the rest"
        )
    elif left:
        shown = ", ".join(str(device_id) for device_id in left[:IDS_SHOWN]) + (", ..." if len(left) > IDS_SHOWN else "")
        ctx.partial(
            "the listing of every port is too large to read, so the ports were read one device at a time, the "
            f"scope's first: those of {len(left)} of the {len(others)} devices outside the scope that the rows join "
            f"(device ids {shown}) were not, so their end of those rows is not known; a report scoped to one of them "
            "reads them"
        )
    else:
        ctx.notes.append(
            "LibreNMS's listing of every port is too large to read, so the ports were read one device at a time"
        )
    return rows


def _in_order(devices: Dict[int, Dict[str, Any]], ids: Set[int]) -> List[int]:
    """*ids* in hostname order."""
    return sorted(ids, key=lambda i: hostname_order(devices[i]))


# -- what a port row means -------------------------------------------------------------------------------------------
def facts(port: Dict[str, Any], device: Dict[str, Any], now: datetime) -> Port:
    """*port* (a ports row) on *device* (its devices row) as a report row, with what filters and orders compare."""
    state = port_state(port)
    egress, ingress, source = speeds(port)
    period = units.number(port.get("poll_period")) or POLL_S
    polled = units.utc_time(port.get("poll_time"))
    fresh = polled is not None and (units.age(polled, now) or 0) <= STALE_POLLS * period
    in_bps, out_bps = _bits(port.get("ifInOctets_rate")), _bits(port.get("ifOutOctets_rate"))
    in_pct, out_pct = units.percent(in_bps, ingress), units.percent(out_bps, egress)
    known = [pct for pct in (in_pct, out_pct) if pct is not None]
    util = max(known) if known else None
    errors_in, errors_out = _count(port.get("ifInErrors_delta")), _count(port.get("ifOutErrors_delta"))
    idle, at_least = last_change(port, device, now)
    alias = port.get("ifAlias")
    row: Dict[str, Any] = {**brief(device), "port_id": int(port["port_id"]), "port": port_label(port)}
    row.update(description=alias if isinstance(alias, str) and alias.strip() else None, type=port.get("ifType"))
    row.update(state=state, ignored=truthy(port.get("ignore")), polling_disabled=truthy(port.get("disabled")))
    fastest = max(egress or 0, ingress or 0) or None
    row.update(speed_bps=fastest, speed=_speed_text(egress, ingress), speed_source=source)
    if egress != ingress:
        row.update(in_speed_bps=ingress, out_speed_bps=egress)
    row.update(duplex=_duplex(port.get("ifDuplex")), mtu=_count(port.get("ifMtu")))
    row.update({"in_bps": in_bps, "in": units.bits_per_second(in_bps), "in_pct": in_pct})
    row.update(out_bps=out_bps, out=units.bits_per_second(out_bps), out_pct=out_pct, util_pct=util)
    row.update(in_errors_per_poll=errors_in, out_errors_per_poll=errors_out)
    row.update(in_errors_per_s=_per_second(errors_in, period), out_errors_per_s=_per_second(errors_out, period))
    row.update(last_change_age_s=idle, last_change_age=_age_text(idle, at_least))
    if at_least:
        row["last_change_at_least"] = True
    row.update(polled_at=units.iso(polled), stale=not fresh, no_description=no_description(port))
    admin_up = port.get("ifAdminStatus") == "up"
    return Port(
        row,
        device,
        state,
        fastest,
        util if fresh else None,
        (errors_in or 0) + (errors_out or 0) if fresh else 0,
        fresh,
        idle,
        at_least,
        is_ethernet(port),
        admin_up and state not in ("up", None) and not row["ignored"] and not row["polling_disabled"],
        " ".join(str(port.get(key) or "") for key in ("ifName", "ifDescr", "ifAlias")).casefold(),
    )


def speeds(port: Dict[str, Any]) -> Tuple[int | None, int | None, str | None]:
    """``(egress, ingress, source)``: the bit/s a port is measured against each way, and where they came from
    (``circuit``, ``ifSpeed``, ``ifHighSpeed``); None for a speed not known."""
    circuit = units.circuit_speeds(port.get("port_descr_speed"))
    if circuit is not None:
        return circuit[0], circuit[1], "circuit"
    speed, source = interface_speed(port)
    return speed, speed, source


def interface_speed(port: Dict[str, Any]) -> Tuple[int | None, str | None]:
    """The bit/s the interface itself runs at, never a circuit speed from its description, and where it came from:
    ``ifSpeed``, else ``ifHighSpeed`` Mbit/s, which older releases kept beside an ``ifSpeed`` stuck at 4294967295;
    ``(None, None)`` when neither is known (0)."""
    speed = units.number(port.get("ifSpeed"))
    if speed and speed > 0 and speed != UNKNOWN_SPEED:
        return int(speed), "ifSpeed"
    high = units.number(port.get("ifHighSpeed"))  # only an older LibreNMS's full row has it
    if high and high > 0:
        return int(high * 1e6), "ifHighSpeed"
    return None, None


def last_change(port: Dict[str, Any], device: Dict[str, Any], now: datetime) -> Tuple[int | None, bool]:
    """Seconds from the port's last change of state to *now*, and whether that is only a lower bound (the port has
    not changed since the device's SNMP agent started). Counted from the device's uptime at its last poll; None when
    that is not known, when sysUpTime may have wrapped (:data:`WRAP_S`), or when ``ifLastChange`` lies past it."""
    uptime = units.seconds(device.get("uptime"))
    ticks = units.number(port.get("ifLastChange"))
    if uptime is None or ticks is None or ticks < 0:
        return None, False
    polled = units.utc_time(device.get("last_polled")) or units.utc_time(port.get("poll_time"))
    since_poll = units.age(polled, now) or 0
    if ticks == 0:
        return uptime + since_poll, True
    if uptime >= WRAP_S or ticks / 100 > uptime:
        return None, False
    return int(uptime - ticks / 100) + since_poll, False


def device_stale(device: Dict[str, Any], now: datetime) -> bool:
    """Whether what LibreNMS holds of *device* from polling (sensor readings, sessions) is not current: its last poll
    is more than :data:`STALE_POLLS` polls (:data:`POLL_S`) before *now*, or it was never polled."""
    polled = units.utc_time(device.get("last_polled"))
    return polled is None or (units.age(polled, now) or 0) > STALE_POLLS * POLL_S


def no_description(port: Dict[str, Any]) -> bool:
    """Whether the port has no description of its own: ``ifAlias`` empty, or the same as its ``ifName`` or
    ``ifDescr`` (some devices copy one into it)."""
    alias = str(port.get("ifAlias") or "").strip().casefold()
    names = {str(port.get(key) or "").strip().casefold() for key in ("ifName", "ifDescr")}
    return not alias or alias in names


def is_ethernet(port: Dict[str, Any]) -> bool:
    """Whether the port is a physical ethernet port: an ethernet ifType and no sub-interface or unit number (``.100``)
    in its name."""
    name = str(port.get("ifName") or port.get("ifDescr") or "")
    return port.get("ifType") in ETHERNET and not _SUBINTERFACE_RE.search(name)


def _bits(octets: Any) -> int | None:
    rate = units.number(octets)
    return None if rate is None or rate < 0 else int(rate * 8)


def _count(value: Any) -> int | None:
    found = units.number(value)
    return None if found is None or found < 0 else int(found)


def _per_second(count: int | None, period: float) -> float | None:
    return None if count is None else round(count / period, 3)


def _duplex(value: Any) -> str | None:
    """``full``, ``half`` or ``unknown`` for LibreNMS's ``fullDuplex``, ``halfDuplex`` and ``unknown``."""
    if not value:
        return None
    text = str(value)
    return {"fullDuplex": "full", "halfDuplex": "half"}.get(text, text)


def _speed_text(egress: int | None, ingress: int | None) -> str | None:
    if egress == ingress:
        return units.speed(egress)
    return f"{units.speed(egress) or '?'}/{units.speed(ingress) or '?'}"  # egress/ingress, as the description says


def _age_text(seconds: int | None, at_least: bool) -> str | None:
    text = units.duration(seconds)
    return f"over {text}" if text and at_least else text


# -- view ports ------------------------------------------------------------------------------------------------------
def build(ctx: ReportContext, req: Request) -> Dict[str, Any]:
    """The ports in scope that pass the filter, in the order asked for, a page of them."""
    scope = ctx.scope(req.scope, VIEW)
    every = described(ctx, scope)
    kept = [item for item in every if _passes(item, req.filters)]
    kept.sort(key=_ORDERS[req.sort])
    page = kept[req.offset : req.offset + req.limit]
    by_state = dict.fromkeys(SUMMARY_STATES, 0)
    by_state["other"] = 0
    for item in kept:
        by_state[item.state if item.state in by_state else "other"] += 1
    current = [item for item in kept if item.util is not None]
    busiest = min(current, key=_ORDERS["util"], default=None)
    summary = {
        "in_scope": len(every),
        "by_state": by_state,
        "not_up": sum(item.not_up for item in kept),
        f"over_{BUSY_PCT}_pct": sum(item.util > BUSY_PCT for item in current),
        "with_errors": sum(item.errors > 0 for item in kept),
        "stale": sum(not item.fresh for item in kept),
        "no_description": sum(item.row["no_description"] for item in kept),
        "busiest": _busiest(busiest) if busiest is not None else None,
    }
    return ctx.envelope(
        "ports",
        scope=scope,
        rows=[item.row for item in page],
        count=len(kept),
        offset=req.offset,
        summary=summary,
        text_keys=TEXT_KEYS,
    )


def described(ctx: ReportContext, scope: Scope) -> List[Port]:
    """Every port in *scope*, read and derived (:func:`facts`); a port whose device the token cannot see is named
    by its device id alone."""
    devices = ctx.devices()
    out = []
    for port in read_ports(ctx, scope):
        device = devices.get(int(port["device_id"])) if is_digits(port.get("device_id")) else None
        out.append(facts(port, device or {"device_id": port.get("device_id")}, ctx.now))
    return out


def _passes(item: Port, filters: Dict[str, Any]) -> bool:
    row = item.row
    for key, wanted in filters.items():
        if key == "state" and item.state not in wanted:
            return False
        if key == "util_above_pct" and (item.util is None or item.util <= wanted):
            return False
        if key == "errors" and (item.errors > 0) != wanted:
            return False
        if key == "speed_below_mbps" and (item.speed is None or item.speed >= wanted * 1e6):
            return False
        if key == "duplex" and (row["duplex"] or "unknown") not in wanted:
            return False
        if key == "no_description" and row["no_description"] != wanted:
            return False
        if key == "type" and not _of_type(item, wanted):
            return False
        if key == "text" and wanted.casefold() not in item.names:
            return False
    return True


def _of_type(item: Port, wanted: str) -> bool:
    """``ethernet`` is every physical ethernet port (:func:`is_ethernet`); anything else an ifType, any case."""
    if wanted.casefold() == "ethernet":
        return item.ethernet
    return str(item.row["type"] or "").casefold() == wanted.casefold()


def _busiest(item: Port) -> Dict[str, Any]:
    row = item.row
    keys = ("device_id", "hostname", "port_id", "port", "util_pct", "in", "in_pct", "out", "out_pct", "speed")
    return {key: row.get(key) for key in keys}


def _by_name(item: Port) -> Tuple[Any, ...]:
    return hostname_order(item.row), natural_key(item.row["port"]), item.row["port_id"]


def _by_pct(key: str) -> Callable[[Port], Tuple[Any, ...]]:
    """Busiest first; the ports without a current figure (speed not known, stale) last."""

    def order(item: Port) -> Tuple[Any, ...]:
        value = item.row[key] if item.fresh else None
        return value is None, -(value or 0), *_by_name(item)

    return order


def _by_errors(item: Port) -> Tuple[Any, ...]:
    return not item.fresh, -item.errors, *_by_name(item)


def _by_speed(item: Port) -> Tuple[Any, ...]:
    return item.speed is None, item.speed or 0, *_by_name(item)


_ORDERS: Dict[str, Callable[[Port], Tuple[Any, ...]]] = {
    "name": _by_name,
    "util": _by_pct("util_pct"),
    "util_in": _by_pct("in_pct"),
    "util_out": _by_pct("out_pct"),
    "errors": _by_errors,
    "speed": _by_speed,
}


VIEW = View(
    "ports",
    build,
    scope_keys=SCOPE_KEYS,
    filters={
        "state": STATES,
        "util_above_pct": "number",
        "errors": "bool",
        "speed_below_mbps": "number",
        "duplex": DUPLEX,
        "no_description": "bool",
        "type": "text",
        "text": "text",
    },
    sorts=("name", "util", "util_in", "util_out", "errors", "speed"),
)


# -- view capacity ---------------------------------------------------------------------------------------------------
def build_capacity(ctx: ReportContext, req: Request) -> Dict[str, Any]:
    """Per device in scope with an ethernet port: its ethernet ports by state and how many are free."""
    scope = ctx.scope(req.scope, CAPACITY)
    idle_days = req.filters.get("idle_days", IDLE_DAYS)
    idle = idle_days * 86400
    per_device: Dict[Any, List[Port]] = {}
    for item in described(ctx, scope):
        if item.ethernet:
            per_device.setdefault(item.row["device_id"], []).append(item)
    rows = [_capacity_row(ports, idle) for ports in per_device.values()]
    rows.sort(key=_CAPACITY_ORDERS[req.sort])
    page = rows[req.offset : req.offset + req.limit]
    totals = dict.fromkeys(("ethernet_ports", "up", "down", "disabled", "free", "free_unknown"), 0)
    for row in rows:
        for key in totals:
            totals[key] += row[key]
    in_scope = len(scope.ids) if scope.ids is not None else len(ctx.devices())
    without = max(0, in_scope - len(rows))  # a port of a device the token cannot see may still be listed
    summary = {"in_scope": in_scope, "without_ethernet_ports": without, "idle_days": idle_days, **totals}
    if any(row["free_unknown"] for row in rows):
        ctx.notes.append(
            "free_unknown counts ports that are not up and whose last change cannot be dated that far back (the "
            f"device has been up less than {_days(idle_days)}, its uptime is not known, or sysUpTime wrapped): they "
            "may be free"
        )
    return ctx.envelope(
        "capacity",
        scope=scope,
        rows=page,
        count=len(rows),
        offset=req.offset,
        summary=summary,
        text_keys=CAPACITY_TEXT,
    )


def _capacity_row(ports: List[Port], idle: float) -> Dict[str, Any]:
    """One device's ethernet ports: by state, free (not up, and unchanged for *idle* seconds or more), free_unknown
    (not up, last change not known that far back), used_pct (up of all), free_by_speed, and stale when none of its
    ports has a current poll."""
    device = ports[0].device
    row: Dict[str, Any] = {**brief(device), "location": device.get("location") or None}
    up = sum(item.state == "up" for item in ports)
    disabled = sum(item.state == "disabled" for item in ports)
    free, unknown, by_speed = 0, 0, {}
    for item in ports:
        if item.state == "up":
            continue
        if item.idle is not None and item.idle >= idle:
            free += 1
            label = units.speed(item.speed) or "unknown"
            by_speed[label] = by_speed.get(label, 0) + 1
        elif item.idle is None or item.idle_at_least:
            unknown += 1
    row.update(ethernet_ports=len(ports), up=up, down=len(ports) - up - disabled, disabled=disabled)
    row.update(free=free, free_unknown=unknown, used_pct=units.percent(up, len(ports)))
    row.update(free_by_speed=dict(sorted(by_speed.items(), key=lambda pair: _speed_order(pair[0]))))
    row["stale"] = not any(item.fresh for item in ports)
    return row


def _speed_order(label: str) -> Tuple[bool, int]:
    speed = units.parse_speed(label)
    return speed is None, speed or 0


def _days(days: float) -> str:
    return f"{days:g} day" + ("" if days == 1 else "s")


_CAPACITY_ORDERS: Dict[str, Callable[[Dict[str, Any]], Tuple[Any, ...]]] = {
    "name": hostname_order,
    "free": lambda row: (-row["free"], *hostname_order(row)),
    "used_pct": lambda row: (-(row["used_pct"] or 0), *hostname_order(row)),
}


CAPACITY = View(
    "capacity",
    build_capacity,
    scope_keys=("device", "devices", "group", "location", "os", "type"),
    filters={"idle_days": "number"},
    sorts=("name", "free", "used_pct"),
)
