"""View ``port``: one port in depth, everything the ``ports`` view says of it and what only it can say.

The port is ``scope.port``: a ``port_id``, or with ``scope.device`` an interface name (``Gi1/0/5`` or
``GigabitEthernet1/0/5``, any case, a short form for a long one) or its description; without a device, a name is
searched among every port (``ports/search/ifName,ifDescr,ifAlias/...``), and one holding what that path cannot
(``#``, ``?``, ``%``, ``\\``) is a malformed argument that says to name the device. A name that could be several
ports answers ``ambiguous`` with the candidates, as a device phrase does.

Reads: the port itself (``ports/{id}?with=statistics``: every column, and its ports_statistics row for discards), then
what may fail or be past the budget, leaving the answer partial: its LLDP/CDP neighbours (``devices/{id}/links``, those
on this port), its transceivers (``ports/{id}/transceiver``; from a LibreNMS too old to have the route, not listed, with
a note and not partial), the dBm sensors of its optics (``resources/sensors``, those LibreNMS ties to the port: measured
on its ifIndex, or on one of its transceivers), and the open faults about it (``faults`` in every open state, those
whose entity is this port; never their details).
"""

from __future__ import annotations

from typing import Any, Dict, List, Set, Tuple

from ..client import LibreNMSError, is_digits
from ..listing import natural_key
from ..routes import QueryError, normalise
from . import fuzzy, units
from .context import (
    FAULT_STATES,
    MIN_SCORE,
    OPEN_FAULT_STATES,
    Ambiguous,
    ArgumentError,
    ReportContext,
    ReportError,
    Request,
    Scope,
    View,
    abbreviates,
    brief,
    folded,
    measured_on,
    port_candidate,
    rows_of,
    sensor_status,
    term_arg,
    truthy,
)
from .ports import facts

SCOPE_KEYS = ("device", "port")
LOOKUP_COLUMNS = "port_id,device_id,ifIndex,ifName,ifDescr,ifAlias,ifAdminStatus,ifOperStatus"
PORT_ENTITIES = ("interface", "port")  # a fault's entity_type for a port: LibreNMS's morph name for Port, interface
TEXT_KEYS = (
    "hostname", "display", "port", "description", "ifName", "ifDescr", "remote_hostname", "remote_port",
    "remote_platform", "remote_version", "type", "vendor", "model", "serial", "connector", "descr", "rule", "note",
)  # fmt: skip
_SEARCH_FIELDS = "ifName,ifDescr,ifAlias"


def build(ctx: ReportContext, req: Request) -> Dict[str, Any]:
    """The port ``scope.port`` names, with its neighbours, transceivers, optics and open faults."""
    raw = req.scope
    if not isinstance(raw, dict) or "port" not in raw:
        raise ArgumentError(
            "view port needs scope.port: a port_id, or an interface name or description with scope.device, e.g. "
            '{"device": "core-sw1", "port": "Gi1/0/5"}'
        )
    named = ctx.scope(raw, VIEW)
    device_id = next(iter(named.ids)) if "device" in raw and named.ids else None
    port = _read(ctx, _port_id(ctx, raw["port"], device_id))
    devices = ctx.devices()
    port_device = int(port["device_id"]) if is_digits(port.get("device_id")) else None
    device = devices.get(port_device) or {"device_id": port.get("device_id")}
    about = {"device_count": 1, "devices": [brief(device)]}  # the port's device, however the port was named
    if named.summary.get("resolved"):
        about["resolved"] = named.summary["resolved"]
    scope = Scope({port_device} if port_device is not None else set(), about)
    described = facts(port, device, ctx.now)
    row = described.row
    row.update(_identity(port))
    row.update(_statistics(port))
    port_id = row["port_id"]
    links = _neighbours(ctx, port_id, port_device)
    transceivers, entities = _transceivers(ctx, port_id)
    optics = _optics(ctx, port, entities)
    alerts = _alerts(ctx, port_id)
    row.update(neighbours=links, transceivers=transceivers, optics=optics, alerts=alerts)
    if truthy(port.get("deleted")):
        ctx.notes.append("LibreNMS marks this port deleted: the device no longer has it, and its figures are its last")
    statuses = [optic["status"] for optic in (optics or []) if optic["status"]]
    summary = {
        "state": row["state"],
        "util_pct": row["util_pct"],
        "stale": row["stale"],
        "errors_per_poll": described.errors if described.fresh else None,
        "discards_per_poll": _sum(row.get("in_discards_per_poll"), row.get("out_discards_per_poll"))
        if described.fresh
        else None,
        "neighbours": None if links is None else len(links),
        "optics": next((status for status in ("critical", "warning", "ok") if status in statuses), None),
        "open_alerts": None if alerts is None else len(alerts),
    }
    return ctx.envelope("port", scope=scope, rows=[row], count=1, offset=0, summary=summary, text_keys=TEXT_KEYS)


# -- which port ------------------------------------------------------------------------------------------------------
def _port_id(ctx: ReportContext, ref: Any, device_id: int | None) -> int:
    """The id of the port *ref* names: a port_id; with a device, one of its ports by name, short name, port_id or
    description; without one, the one port whose ifName, ifDescr or description is *ref*."""
    text = term_arg("scope.port", ref)
    if device_id is None:
        if is_digits(text):
            return int(text)
        return _search(ctx, text)
    ports = rows_of(ctx.get("devices", device_id, "ports", params={"columns": LOOKUP_COLUMNS}))
    device = ctx.devices()[device_id]
    wanted = text.casefold()
    for found in (
        [port for port in ports if wanted in (folded(port, "ifName"), folded(port, "ifDescr"))],
        [port for port in ports if is_digits(text) and str(port.get("port_id")) == text],
        [port for port in ports if abbreviates(wanted, folded(port, "ifName"), folded(port, "ifDescr"))],
        [port for port in ports if folded(port, "ifAlias") == wanted],
    ):
        if len(found) == 1:
            return int(found[0]["port_id"])
        if found:
            raise Ambiguous("port", text, _candidates(text, found, {device_id: device}))
    term = fuzzy.Term.parse(text)
    scored = [(port, _scored(term, port, None)) for port in ports]
    ranked = [port for port, found in scored if found is not None]
    full = [port for port, found in scored if found is not None and found.full]
    if len(full) == 1:
        return int(full[0]["port_id"])
    if ranked:
        raise Ambiguous("port", text, _candidates(text, ranked, {device_id: device}))
    names = ", ".join(fuzzy.shown(port.get("ifName")) for port in ports[:10]) or "none"
    raise ReportError(
        f"scope.port {fuzzy.shown(text)}: device {fuzzy.shown(device.get('hostname'))} has no port by that name, "
        f"number or description; its ports include {names}"
    )


def _search(ctx: ReportContext, text: str) -> int:
    """The one port in LibreNMS whose ifName, ifDescr or description is *text* (any case), from
    ``ports/search``; several are :class:`Ambiguous`, none a :class:`ReportError`."""
    pieces = text.split("/")
    if not _searchable(text, pieces):
        raise ArgumentError(
            f"scope.port {fuzzy.shown(text)} cannot be searched for among every port: LibreNMS's search takes it in "
            "the path, which cannot hold ?, #, %, \\, an empty part or . and ..; name the port's device with "
            "scope.device (its ports are matched by name and description as given) or give the port_id"
        )
    rows = rows_of(ctx.get("ports", "search", _SEARCH_FIELDS, *pieces, params={"columns": LOOKUP_COLUMNS}))
    wanted = text.casefold()
    exact = [port for port in rows if wanted in (folded(port, key) for key in ("ifName", "ifDescr", "ifAlias"))]
    if len(exact) == 1:
        return int(exact[0]["port_id"])
    if not rows:
        raise ReportError(
            f"scope.port {fuzzy.shown(text)}: no port's ifName, ifDescr or description holds that; name the device "
            "with scope.device, or look for the port with view find"
        )
    raise Ambiguous("port", text, _candidates(text, exact or rows, ctx.devices()))


def _searchable(text: str, pieces: List[str]) -> bool:
    """Whether ``ports/search`` can be asked for *text*, split at its slashes into *pieces* of the path: none of
    them blank, ``.`` or ``..``, and nothing the route allow-list refuses in a path (:func:`routes.normalise`)."""
    if any(piece.strip() in ("", ".", "..") for piece in pieces):
        return False
    try:
        normalise(text)
    except QueryError:
        return False
    return True


def _read(ctx: ReportContext, port_id: int) -> Dict[str, Any]:
    rows = rows_of(ctx.get("ports", port_id, params={"with": "statistics"}))
    if not rows:
        raise ReportError(f"scope.port: no LibreNMS port has id {port_id} (or this token cannot see it)")
    return rows[0]


def _scored(term: fuzzy.Term, port: Dict[str, Any], device: Dict[str, Any] | None) -> fuzzy.Match | None:
    found = fuzzy.port_match(term, port, device)
    return found if found is not None and found.score >= MIN_SCORE else None


def _candidates(text: str, ports: List[Dict[str, Any]], devices: Dict[int, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """*ports* as candidates, best first (then by hostname, name and id), each with why it may be meant."""
    term = fuzzy.Term.parse(text)
    out = []
    for port in ports:
        device = devices.get(int(port["device_id"])) if is_digits(port.get("device_id")) else None
        found = _scored(term, port, device) or fuzzy.Match(
            MIN_SCORE, f"ifName, ifDescr or description holds {fuzzy.shown(text)}", False
        )
        hostname = device.get("hostname") if device is not None else None
        key = (-found.score, natural_key(hostname), natural_key(port.get("ifName")), str(port.get("port_id")))
        out.append((key, port_candidate(port, device, found)))
    return [candidate for _key, candidate in sorted(out, key=lambda pair: pair[0])]


# -- what only this view says ----------------------------------------------------------------------------------------
def _identity(port: Dict[str, Any]) -> Dict[str, Any]:
    """The port's own names and settings, which the listing leaves out."""
    return {
        "ifIndex": port.get("ifIndex"),
        "ifName": port.get("ifName"),
        "ifDescr": port.get("ifDescr"),
        "admin_status": port.get("ifAdminStatus"),
        "oper_status": port.get("ifOperStatus"),
        "mac": port.get("ifPhysAddress") or None,
        "vlan": port.get("ifVlan") or None,
        "trunk": port.get("ifTrunk") or None,
        "in_pps": _rate(port.get("ifInUcastPkts_rate")),
        "out_pps": _rate(port.get("ifOutUcastPkts_rate")),
    }


def _statistics(port: Dict[str, Any]) -> Dict[str, Any]:
    """Discards in the last poll and per second, from the port's ports_statistics row (None when it has none)."""
    stats = next(iter(rows_of(port.get("statistics"))), {})
    period = units.number(port.get("poll_period")) or 300
    out: Dict[str, Any] = {}
    for way in ("in", "out"):
        count = _rate(stats.get(f"if{way.title()}Discards_delta"))
        out[f"{way}_discards_per_poll"] = count
        out[f"{way}_discards_per_s"] = None if count is None else round(count / period, 3)
    return out


def _neighbours(ctx: ReportContext, port_id: int, device_id: int | None) -> List[Dict[str, Any]] | None:
    """The LLDP/CDP/... neighbours LibreNMS saw on this port, the remote device named when LibreNMS monitors it."""
    if device_id is None:
        return None
    links = ctx.optional("neighbours", "devices", device_id, "links")
    if links is None:
        return None
    devices = ctx.devices()
    out = []
    for link in rows_of(links):
        if str(link.get("local_port_id")) != str(port_id):
            continue
        remote_id = int(link["remote_device_id"]) if is_digits(link.get("remote_device_id")) else 0
        item: Dict[str, Any] = {"protocol": link.get("protocol"), "remote_hostname": link.get("remote_hostname")}
        item.update(remote_port=link.get("remote_port"), remote_platform=link.get("remote_platform") or None)
        item["remote_monitored"] = remote_id in devices
        if remote_id in devices:
            item["remote_device"] = brief(devices[remote_id])
            item["remote_port_id"] = link.get("remote_port_id") or None
        item["active"] = truthy(link.get("active"))
        out.append(item)
    return out


def _transceivers(ctx: ReportContext, port_id: int) -> Tuple[List[Dict[str, Any]] | None, Set[str]]:
    """The port's transceivers (what they are, not their inventory entity), and the entities their sensors hang
    from; None when they were not read, or, with a note and not partial, from a LibreNMS without the route (an older
    release)."""
    try:
        rows = ctx.optional("transceivers", "ports", port_id, "transceiver", raising=("route",))
    except LibreNMSError as exc:
        if exc.kind != "route":
            raise
        ctx.notes.append(
            "this LibreNMS has no transceivers route (an older release): the port's transceivers are not listed, and "
            "its optics are those measured on its ifIndex"
        )
        return None, set()
    if rows is None:
        return None, set()
    keys = ("type", "vendor", "model", "serial", "connector", "distance", "ddm")
    out, entities = [], set()
    for row in rows_of(rows):
        item = {key: row.get(key) for key in keys}
        item["wavelength_nm"] = row.get("wavelength")
        out.append(item)
        if row.get("entity_physical_index") not in (None, ""):
            entities.add(str(row["entity_physical_index"]))
    return out, entities


def _optics(ctx: ReportContext, port: Dict[str, Any], entities: Set[str]) -> List[Dict[str, Any]] | None:
    """The port's dBm sensors and their state against their limits: those LibreNMS measured on the port's ifIndex
    (``entPhysicalIndex_measured`` ports), or on the entity of one of its transceivers (*entities*)."""
    sensors = ctx.optional("optic sensors", "resources", "sensors")
    if sensors is None:
        return None
    out = []
    for sensor in rows_of(sensors):
        if str(sensor.get("device_id")) != str(port.get("device_id")) or sensor.get("sensor_class") != "dbm":
            continue
        if truthy(sensor.get("sensor_deleted")) or not measured_on(sensor, port, entities):
            continue
        out.append({
            "sensor_id": sensor.get("sensor_id"),
            "descr": sensor.get("sensor_descr"),
            "dbm": units.number(sensor.get("sensor_current")),
            "limit_low": units.number(sensor.get("sensor_limit_low")),
            "limit_low_warn": units.number(sensor.get("sensor_limit_low_warn")),
            "limit_warn": units.number(sensor.get("sensor_limit_warn")),
            "limit": units.number(sensor.get("sensor_limit")),
            "status": sensor_status(sensor),
        })  # fmt: skip
    return out


def _alerts(ctx: ReportContext, port_id: int) -> List[Dict[str, Any]] | None:
    """The open faults whose entity is this port: rule, severity, state, when first seen (server-local, read in
    ``librenms_timezone``; without it as LibreNMS wrote it, with no age) and the acknowledgement note."""
    faults = ctx.optional("open alerts", "faults", params={"state": OPEN_FAULT_STATES})
    if faults is None:
        return None
    out = []
    for fault in rows_of(faults):
        if fault.get("entity_type") not in PORT_ENTITIES or str(fault.get("entity_id")) != str(port_id):
            continue
        state = int(fault["state"]) if is_digits(fault.get("state")) else None
        out.append({
            "alert_id": fault.get("id"),
            "rule": fault.get("name"),
            "severity": fault.get("severity"),
            "state": FAULT_STATES.get(state, fault.get("state")),
            **ctx.when(fault.get("first_seen"), "first_seen"),
            "note": fault.get("note") or None,
        })  # fmt: skip
    out.sort(key=lambda item: natural_key(str(item["alert_id"])))
    return out


def _rate(value: Any) -> int | None:
    found = units.number(value)
    return None if found is None or found < 0 else int(found)


def _sum(*values: Any) -> int | None:
    known = [value for value in values if value is not None]
    return sum(known) if known else None


VIEW = View("port", build, scope_keys=SCOPE_KEYS)
