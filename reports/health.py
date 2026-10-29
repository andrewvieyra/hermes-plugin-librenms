"""View ``health``: what the devices' sensors read against their limits (temperature, optic power, voltage, fans,
...), and how loaded their processors, memory and storage are.

Sensors come from one ``resources/sensors`` read, LibreNMS's only route that holds every sensor's reading and limits;
it takes no filter, so the scope and the filters apply here, and deleted sensors are left out. A reading's ``status``
is LibreNMS's (:func:`.context.sensor_status`): ``critical`` past ``sensor_limit`` or below ``sensor_limit_low``,
``warning`` past a ``_warn`` limit, a limit not set never trips; ``unknown`` without a reading, and for a ``state``
sensor, whose number means what LibreNMS's state translations say (no read route returns them). ``low_margin`` and
``high_margin`` say how far the reading is from the first limit it would cross going down or up (the warning limit,
else the critical one), in the reading's unit and negative once past it; ``margin`` is the nearer of the two. The
unit is the class's (:data:`.units.SENSOR_UNITS`). A counter sensor (``rrd_type`` COUNTER or DERIVE) reads as its
rate over the last poll, as LibreNMS shows it.

For the rows of the page, a sensor on a port is named with it: measured on the port's ifIndex, or on the inventory
entity of one of its transceivers (:func:`.context.measured_on`; the device's transceivers are read only when the
ifIndex names no port), or for a dBm sensor, a description that starts with the port's name. A dBm sensor also
carries its ``direction`` (``rx``, ``tx``) as its description says it.

When LibreNMS's answer is too large to read (past 16 MiB: tens of thousands of sensors), the sensors are read one
device at a time instead (``devices/{id}/health``, the classes; ``.../device_<class>``, the ids; then
``.../device_<class>/{id}``, a request per sensor), the scope's devices in hostname order within the request budget;
what that leaves unread makes the answer partial, and only a narrow question (one device, a class) fits.

Processors, memory pools and storage have no fleet-wide route: ``devices/{id}/health/device_processor`` lists a
device's processors and ``.../device_processor/{id}`` reads one (``mempool``, ``storage`` alike). They are read for at
most :data:`DEVICE_READS` devices of the scope, at most :data:`ITEM_READS` of a kind per device: processors and
memory pools when ``filter.class`` is not given, else the kinds it names. Their reading is a percentage, ``warning``
past LibreNMS's ``*_perc_warn``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, List, Set, Tuple

from ..client import LibreNMSError, is_digits
from ..listing import natural_key
from . import units
from .context import (
    ReportContext,
    Request,
    View,
    abbreviates,
    brief,
    folded,
    hostname_order,
    measured_on,
    port_label,
    rows_of,
    sensor_status,
    truthy,
)
from .ports import POLL_S, STALE_POLLS, device_stale

SCOPE_KEYS = ("device", "devices", "group", "location", "os", "type")
DEVICE_KINDS = ("processor", "mempool", "storage")  # read per device, a request each
DEFAULT_KINDS = ("processor", "mempool")  # read when filter.class names none
CLASSES = (*units.SENSOR_UNITS, *DEVICE_KINDS)
STATUSES = ("critical", "warning", "ok", "unknown")
DIRECTIONS = ("rx", "tx")
DEVICE_READS = 5  # devices whose processors, memory pools or storage a report reads
ITEM_READS = 8  # processors, memory pools or storage volumes of one device a report reads
IDS_SHOWN = 10  # device ids a partial reason names
TEXT_KEYS = ("hostname", "display", "descr", "port")
# Per device kind: its id, description, percentage and warning-limit keys, and the used and total bytes it has.
_KINDS: Dict[str, Tuple[str, str, str, str, str | None, str | None]] = {
    "processor": ("processor_id", "processor_descr", "processor_usage", "processor_perc_warn", None, None),
    "mempool": ("mempool_id", "mempool_descr", "mempool_perc", "mempool_perc_warn", "mempool_used", "mempool_total"),
    "storage": ("storage_id", "storage_descr", "storage_perc", "storage_perc_warn", "storage_used", "storage_size"),
}
_LABELS = {"processor": "processors", "mempool": "memory pools", "storage": "storage volumes"}
_LIMITS = ("limit_low", "limit_low_warn", "limit_warn", "limit")
_COUNTERS = frozenset({"COUNTER", "DERIVE", "DCOUNTER", "DDERIVE"})  # LibreNMS shows these as a rate per second
_STATUS_ORDER = {status: number for number, status in enumerate(STATUSES)}
_RX_RE = re.compile(r"\b(?:rx|receive)", re.IGNORECASE)
_TX_RE = re.compile(r"\b(?:tx|transmit)", re.IGNORECASE)
_BRIEF = (
    "device_id", "hostname", "sensor_id", "processor_id", "mempool_id", "storage_id", "class", "descr", "reading",
    "status", "margin", "nearest",
)  # fmt: skip


@dataclass
class _Reading:
    """A sensor's, processor's, memory pool's or storage volume's report row, and what filters and orders compare."""

    row: Dict[str, Any]
    sensor: Dict[str, Any] | None  # the sensor row, to name its port; None for a device kind
    text: str  # description and device names, folded, for filter.text

    @property
    def status(self) -> str:
        return self.row["status"]

    @property
    def margin(self) -> float | None:
        return self.row["margin"]


def build(ctx: ReportContext, req: Request) -> Dict[str, Any]:
    """The readings in scope that pass the filter, in the order asked for, a page of them with their ports named."""
    scope = ctx.scope(req.scope, VIEW.scope_keys)
    devices = ctx.devices()
    ids = scope.ids if scope.ids is not None else set(devices)
    classes = req.filters.get("class")
    every: List[_Reading] = []
    if ids and (classes is None or set(classes) - set(DEVICE_KINDS)):
        wanted = None if classes is None else set(classes) - set(DEVICE_KINDS)
        for sensor in _sensors(ctx, ids, wanted):
            device = devices.get(_id(sensor.get("device_id"))) or {"device_id": sensor.get("device_id")}
            every.append(_sensor(device, sensor, ctx.now))
    kinds = DEFAULT_KINDS if classes is None else tuple(kind for kind in DEVICE_KINDS if kind in classes)
    every += _device_kinds(ctx, ids, kinds, asked=classes is not None)
    kept = [item for item in every if _passes(item, req.filters)]
    kept.sort(key=_ORDERS[req.sort])
    page = kept[req.offset : req.offset + req.limit]
    _name_ports(ctx, page)
    _notes(ctx, every, kept, req.filters)
    return ctx.envelope(
        "health",
        scope=scope,
        rows=[item.row for item in page],
        count=len(kept),
        offset=req.offset,
        summary=_summary(every, kept),
        text_keys=TEXT_KEYS,
    )


def _id(value: Any) -> int:
    return int(value) if is_digits(value) else 0


# -- reads -----------------------------------------------------------------------------------------------------------
def _sensors(ctx: ReportContext, ids: Set[int], classes: Set[str] | None) -> List[Dict[str, Any]]:
    """The sensors of the devices *ids* (of the *classes*, when given) that LibreNMS has not deleted: from
    ``resources/sensors``, or one device at a time when that answer is too large to read."""
    try:
        rows = rows_of(ctx.get("resources", "sensors"))
    except LibreNMSError as exc:
        if exc.kind != "too_large":
            raise
        rows = _sensors_per_device(ctx, ids, classes)
    return [
        sensor
        for sensor in rows
        if _id(sensor.get("device_id")) in ids
        and not truthy(sensor.get("sensor_deleted"))
        and (classes is None or sensor.get("sensor_class") in classes)
    ]


def _sensors_per_device(ctx: ReportContext, ids: Set[int], classes: Set[str] | None) -> List[Dict[str, Any]]:
    """The sensors of the devices *ids*, in hostname order, read one at a time as far as the request budget goes:
    each device's classes (unless *classes* names them), each class's sensor ids, then each sensor."""
    devices = ctx.devices()
    targets = sorted(ids, key=lambda i: hostname_order(devices[i]))
    rows: List[Dict[str, Any]] = []
    unread: List[int] = []
    for device_id in targets:
        if ctx.calls >= ctx.call_budget:
            unread.append(device_id)
            continue
        names = sorted(classes) if classes else _classes_of(ctx, device_id)
        for name in names:
            rows += _items(ctx, device_id, name, None)
    ctx.notes.append(
        "LibreNMS's listing of every sensor is too large to read, so the sensors were read one device at a time, a "
        "request per sensor: narrow the scope (a device) and filter.class for a complete answer"
    )
    if unread:
        shown = ", ".join(str(i) for i in unread[:IDS_SHOWN]) + (", ..." if len(unread) > IDS_SHOWN else "")
        ctx.partial(
            f"the sensors of {len(unread)} of the {len(targets)} devices in scope (ids {shown}) were not read: "
            f"LibreNMS's listing of every sensor is too large to read and the report used its {ctx.call_budget} "
            "requests reading them one at a time; narrow the scope and filter.class"
        )
    return rows


def _classes_of(ctx: ReportContext, device_id: int) -> List[str]:
    """The sensor classes a device has (``devices/{id}/health``: ``device_<class>`` names), its processors, memory
    pools and storage left to :func:`_device_kinds`."""
    found = ctx.optional(f"the sensor classes of device {device_id}", "devices", device_id, "health")
    names = [str(row.get("name") or "") for row in rows_of(found)]
    out = [name[len("device_") :] for name in names if name.startswith("device_")]
    return [name for name in out if name and name not in DEVICE_KINDS]


def _items(ctx: ReportContext, device_id: int, kind: str, cap: int | None) -> List[Dict[str, Any]]:
    """The rows of one kind (a sensor class, ``processor``, ``mempool``, ``storage``) of a device: its ids from
    ``devices/{id}/health/device_<kind>``, then each from ``.../device_<kind>/{id}``, at most *cap* of them (every
    one when None) and as far as the request budget goes; what that leaves out makes the answer partial."""
    label = _LABELS.get(kind, f"{kind} sensors")
    listing = ctx.optional(f"the {label} of device {device_id}", "devices", device_id, "health", f"device_{kind}")
    item_ids = [int(row["sensor_id"]) for row in rows_of(listing) if is_digits(row.get("sensor_id"))]
    item_ids = [item_id for item_id in item_ids if item_id > 0]
    chosen = item_ids if cap is None else item_ids[:cap]
    out: List[Dict[str, Any]] = []
    for number, item_id in enumerate(chosen):
        if ctx.calls >= ctx.call_budget:
            ctx.partial(
                f"{len(chosen) - number} of the {len(item_ids)} {label} of device {device_id} were not read: the "
                f"report used its {ctx.call_budget} requests (a request each); narrow the scope or filter.class"
            )
            return out
        segments = ("devices", device_id, "health", f"device_{kind}", item_id)
        out += rows_of(ctx.optional(f"{kind} {item_id} of device {device_id}", *segments))
    if len(item_ids) > len(chosen):
        ctx.partial(
            f"device {device_id} has {len(item_ids)} {label}; the first {len(chosen)} were read (a report reads at "
            f"most {cap} of each per device, a request each)"
        )
    return out


def _device_kinds(ctx: ReportContext, ids: Set[int], kinds: Tuple[str, ...], *, asked: bool) -> List[_Reading]:
    """The processors, memory pools or storage (*kinds*) of the devices *ids*, read per device for at most
    :data:`DEVICE_READS` of them in hostname order. Past that, the rest is left out: the answer is partial when the
    kinds were *asked* for, and a note says how to get them when they were read by default."""
    if not kinds or not ids:
        return []
    devices = ctx.devices()
    targets = sorted(ids, key=lambda i: hostname_order(devices[i]))
    names = " and ".join(_LABELS[kind] for kind in kinds)
    if len(targets) > DEVICE_READS:
        if not asked:
            ctx.notes.append(
                f"{names} are read per device, for a scope of at most {DEVICE_READS} devices: narrow the scope, or "
                "ask for them with filter.class (processor, mempool, storage) to read the first ones"
            )
            return []
        ctx.partial(
            f"the {names} of {len(targets) - DEVICE_READS} of the {len(targets)} devices in scope were not read: a "
            f"report reads them per device, for at most {DEVICE_READS} devices (in hostname order); narrow the scope"
        )
        targets = targets[:DEVICE_READS]
    out = []
    for device_id in targets:
        for kind in kinds:
            for item in _items(ctx, device_id, kind, ITEM_READS):
                if not truthy(item.get(f"{kind}_deleted")):
                    out.append(_device_kind(devices[device_id], kind, item, ctx.now))
    return out


# -- what a reading means --------------------------------------------------------------------------------------------
def _sensor(device: Dict[str, Any], sensor: Dict[str, Any], now: datetime) -> _Reading:
    """A sensor row as a report row: its reading in its class's unit, its limits, status and margins."""
    kind = sensor.get("sensor_class")
    value = units.number(sensor.get("sensor_current"))
    limits = {key: units.number(sensor.get(f"sensor_{key}")) for key in _LIMITS}
    counter = sensor.get("rrd_type") in _COUNTERS
    if counter:  # LibreNMS shows a counter as its rate over the last poll
        previous = units.number(sensor.get("sensor_prev"))
        value = None if value is None or previous is None else round(max(0.0, value - previous) / POLL_S, 3)
    descr = sensor.get("sensor_descr")
    row: Dict[str, Any] = {**brief(device), "sensor_id": sensor.get("sensor_id"), "class": kind, "descr": descr}
    reading = units.sensor_reading(value, kind)
    row.update(value=value, unit=units.SENSOR_UNITS.get(kind) if isinstance(kind, str) else None)
    row.update(reading=f"{reading}/s" if counter and reading else reading, status=sensor_status(sensor) or "unknown")
    if counter:
        row["per_s"] = True
    row.update(limits)
    row.update(_margins(None if counter or kind == "state" else value, limits))
    if kind == "dbm":
        row["direction"] = _direction(descr)
    row.update(port_id=None, port=None, alerting=truthy(sensor.get("sensor_alert")), stale=device_stale(device, now))
    return _Reading(row, sensor, _folded(row))


def _device_kind(device: Dict[str, Any], kind: str, item: Dict[str, Any], now: datetime) -> _Reading:
    """A processor, memory pool or storage volume as a report row: how full it is in percent against LibreNMS's
    warning limit, and for memory and storage the bytes used of how many."""
    id_key, descr_key, value_key, warn_key, used_key, size_key = _KINDS[kind]
    value = units.number(item.get(value_key))
    warn = units.number(item.get(warn_key))
    status = "unknown" if value is None else "warning" if warn is not None and value > warn else "ok"
    row: Dict[str, Any] = {**brief(device), id_key: item.get(id_key), "class": kind, "descr": item.get(descr_key)}
    row.update(value=value, unit="%", reading=units.sensor_reading(value, "percent"), status=status)
    row.update(limit_low=None, limit_low_warn=None, limit_warn=warn, limit=None)
    row.update(_margins(value, {"limit_warn": warn}))
    if used_key and size_key:
        used, total = units.number(item.get(used_key)), units.number(item.get(size_key))
        row.update(used_bytes=None if used is None else int(used), used=units.size(used))
        row.update(size_bytes=None if total is None else int(total), size=units.size(total))
    row["stale"] = device_stale(device, now)
    return _Reading(row, None, _folded(row))


def _margins(value: float | None, limits: Dict[str, float | None]) -> Dict[str, Any]:
    """How far *value* is from the first limit it would cross going down (the low warning limit, else the low one)
    and going up (the warning limit, else the critical one), negative past it; the nearer, and which side it is."""
    low = limits.get("limit_low_warn") if limits.get("limit_low_warn") is not None else limits.get("limit_low")
    high = limits.get("limit_warn") if limits.get("limit_warn") is not None else limits.get("limit")
    to_low = None if value is None or low is None else round(value - low, 3)
    to_high = None if value is None or high is None else round(high - value, 3)
    known = [(margin, side) for margin, side in ((to_low, "low"), (to_high, "high")) if margin is not None]
    margin, nearest = min(known) if known else (None, None)
    return {"low_margin": to_low, "high_margin": to_high, "margin": margin, "nearest": nearest}


def _direction(descr: Any) -> str | None:
    """``rx`` or ``tx`` for an optic's dBm sensor whose description says which (Rx Power, Receive Power Sensor,
    Tx Power, ...); None when it says neither, or both."""
    text = str(descr or "")
    rx, tx = bool(_RX_RE.search(text)), bool(_TX_RE.search(text))
    return "rx" if rx and not tx else "tx" if tx and not rx else None


def _folded(row: Dict[str, Any]) -> str:
    return " ".join(str(row.get(key) or "") for key in ("descr", "hostname", "display")).casefold()


# -- ports -----------------------------------------------------------------------------------------------------------
def _on_a_port(sensor: Dict[str, Any] | None) -> bool:
    """Whether a sensor may be on a port: LibreNMS measured it on one, or it is an optic's dBm sensor."""
    if sensor is None:
        return False
    return sensor.get("entPhysicalIndex_measured") == "ports" or sensor.get("sensor_class") == "dbm"


def _name_ports(ctx: ReportContext, page: List[_Reading]) -> None:
    """Name the port of each sensor of *page* that is on one, from its device's port names (at most 10 devices) and,
    where its ifIndex names no port, the device's transceivers; a read that fails leaves them unnamed, partial."""
    by_device: Dict[Any, List[_Reading]] = {}
    for item in page:
        if _on_a_port(item.sensor) and item.row["device_id"] is not None:
            by_device.setdefault(item.row["device_id"], []).append(item)
    if not by_device:
        return
    ports = ctx.ports_by_device(
        by_device, "the ports of device {}'s sensors", "the ports of {} more devices' sensors were not named"
    )
    for device_id, items in by_device.items():
        if device_id not in ports:
            continue
        entities: Dict[str, Set[str]] | None = None
        for item in items:
            sensor = item.sensor or {}
            port = _measured(sensor, ports[device_id], {})
            if port is None and sensor.get("entPhysicalIndex") not in (None, ""):
                if entities is None:
                    entities = _transceivers(ctx, device_id)
                port = _measured(sensor, ports[device_id], entities) if entities else None
            if port is None and sensor.get("sensor_class") == "dbm":
                port = _named(sensor, ports[device_id])
            if port is not None:
                item.row.update(port_id=port.get("port_id"), port=port_label(port))


def _transceivers(ctx: ReportContext, device_id: Any) -> Dict[str, Set[str]]:
    """A device's transceivers' inventory entities, by the port they are in (``devices/{id}/transceivers``)."""
    found = ctx.optional(f"the transceivers of device {device_id}", "devices", device_id, "transceivers")
    out: Dict[str, Set[str]] = {}
    for row in rows_of(found):
        if row.get("entity_physical_index") not in (None, "") and row.get("port_id") not in (None, ""):
            out.setdefault(str(row["port_id"]), set()).add(str(row["entity_physical_index"]))
    return out


def _measured(
    sensor: Dict[str, Any], ports: List[Dict[str, Any]], entities: Dict[str, Set[str]]
) -> Dict[str, Any] | None:
    """The one port of *ports* that LibreNMS ties *sensor* to (:func:`.context.measured_on`), *entities* being the
    inventory entities of each port's transceivers."""
    found = [port for port in ports if measured_on(sensor, port, entities.get(str(port.get("port_id")), set()))]
    return found[0] if len(found) == 1 else None


def _named(sensor: Dict[str, Any], ports: List[Dict[str, Any]]) -> Dict[str, Any] | None:
    """The one port of *ports* whose name (ifName or ifDescr, long or short) the sensor's description starts with
    (``Gi1/0/1 Receive Power Sensor``, ``xe-2/1/4 Tx Power``)."""
    first = str(sensor.get("sensor_descr") or "").strip().split(" ", 1)[0].casefold()
    if not first:
        return None
    named = [
        port
        for port in ports
        if first in (folded(port, "ifName"), folded(port, "ifDescr"))
        or abbreviates(first, folded(port, "ifName"), folded(port, "ifDescr"))
    ]
    return named[0] if len(named) == 1 else None


# -- filters, orders, summary ----------------------------------------------------------------------------------------
def _passes(item: _Reading, filters: Dict[str, Any]) -> bool:
    row = item.row
    for key, wanted in filters.items():
        if key == "class" and row["class"] not in wanted:
            return False
        if key == "status" and item.status not in wanted:
            return False
        if key == "margin_below" and (item.margin is None or item.margin >= wanted):
            return False
        if key == "direction" and row.get("direction") not in wanted:
            return False
        if key == "text" and wanted.casefold() not in item.text:
            return False
    return True


def _by_name(item: _Reading) -> Tuple[Any, ...]:
    row = item.row
    ident = next((row[key] for key in ("sensor_id", "processor_id", "mempool_id", "storage_id") if key in row), None)
    return (*hostname_order(row), natural_key(row["class"]), natural_key(row["descr"]), _id(ident))


def _by(key: str) -> Callable[[_Reading], Tuple[Any, ...]]:
    """Smallest first, the readings without one last."""

    def order(item: _Reading) -> Tuple[Any, ...]:
        value = item.row[key]
        return value is None, value or 0, *_by_name(item)

    return order


_by_margin = _by("margin")


def _by_status(item: _Reading) -> Tuple[Any, ...]:
    """Critical first, then warning, ok, unknown; within each, nearest a limit first."""
    return _STATUS_ORDER.get(item.status, len(STATUSES)), *_by_margin(item)


def _by_value(item: _Reading) -> Tuple[Any, ...]:
    value = item.row["value"]
    return value is None, -(value or 0), *_by_name(item)


_ORDERS: Dict[str, Callable[[_Reading], Tuple[Any, ...]]] = {
    "status": _by_status,
    "margin": _by_margin,
    "low_margin": _by("low_margin"),
    "high_margin": _by("high_margin"),
    "value": _by_value,
    "name": _by_name,
}


def _brief(item: _Reading | None) -> Dict[str, Any] | None:
    if item is None:
        return None
    return {key: item.row[key] for key in _BRIEF if key in item.row}


def _limited(item: _Reading) -> bool:
    return any(item.row[key] is not None for key in _LIMITS)


def _summary(every: List[_Reading], kept: List[_Reading]) -> Dict[str, Any]:
    """Counts by status and class over the readings that passed the filter, the hottest temperature, the reading
    nearest a limit it has not crossed, and how many have no limit, alert on nothing or are not current."""
    by_status = dict.fromkeys(STATUSES, 0)
    by_class: Dict[str, int] = {}
    for item in kept:
        by_status[item.status] = by_status.get(item.status, 0) + 1
        name = str(item.row["class"])
        by_class[name] = by_class.get(name, 0) + 1
    temperatures = [item for item in kept if item.row["class"] == "temperature" and item.row["value"] is not None]
    return {
        "in_scope": len(every),
        "by_status": by_status,
        "by_class": dict(sorted(by_class.items(), key=lambda pair: (-pair[1], pair[0]))),
        "devices": len({item.row["device_id"] for item in kept}),
        "hottest": _brief(min(temperatures, key=_by_value, default=None)),
        "nearest_limit": _brief(min((item for item in kept if item.margin is not None and item.margin >= 0),
                                    key=_by_margin, default=None)),
        "without_limits": sum(item.sensor is not None and item.row["class"] != "state" and not _limited(item)
                              for item in kept),
        "alerting_off": sum(item.row.get("alerting") is False for item in kept),
        "stale": sum(item.row["stale"] for item in kept),
    }  # fmt: skip


def _notes(ctx: ReportContext, every: List[_Reading], kept: List[_Reading], filters: Dict[str, Any]) -> None:
    states = sum(item.row["class"] == "state" for item in kept)
    if states:
        ctx.notes.append(
            f"state sensors (class state): {states}; each holds a number whose meaning (ok, warning, ...) LibreNMS "
            "keeps in state translations, which its API does not return, so their status is unknown: view alerts "
            "shows those that alert"
        )
    unlimited = sum(item.sensor is not None and item.row["class"] != "state" and not _limited(item) for item in every)
    if unlimited and {"status", "margin_below"} & set(filters):
        ctx.notes.append(
            f"sensors in scope without limits: {unlimited}; they are never warning or critical and have no margin"
        )
    stale = sum(item.row["stale"] for item in kept)
    if stale:
        minutes = STALE_POLLS * POLL_S // 60
        ctx.notes.append(
            f"readings from devices LibreNMS has not polled for over {minutes} minutes (down, unreachable or "
            f"disabled): {stale}; they are the last it read (stale: true)"
        )


VIEW = View(
    "health",
    build,
    scope_keys=SCOPE_KEYS,
    filters={
        "class": CLASSES,
        "status": STATUSES,
        "margin_below": "number",
        "direction": DIRECTIONS,
        "text": "text",
    },
    sorts=("status", "margin", "low_margin", "high_margin", "value", "name"),
)
