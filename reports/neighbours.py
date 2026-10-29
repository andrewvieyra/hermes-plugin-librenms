"""View ``neighbours``: the LLDP/CDP neighbours LibreNMS discovered on the devices in scope, each link with the ports at
both ends, and the checks people ask about.

A link (LibreNMS's ``links`` table) names its local port by id, and its far end as the neighbour advertised it:
``remote_hostname``, ``remote_port``, ``remote_platform``, text that any device on the wire writes. When LibreNMS
monitors the neighbour it also holds its device id (``remote_device_id``, 0 otherwise) and, when it matched the
advertised port to one of that device's ports, its port id (``remote_port_id``). Each end is joined to its port row
(:func:`.ports.facts`), and the link is checked:

- ``speed_mismatch``, ``duplex_mismatch``: both ends up, and the speeds their interfaces run at (``ifSpeed``, never a
  circuit speed from a description) or their duplex differ. Null when an end is not up or not known: a neighbour
  LibreNMS does not monitor, or one whose port it did not match (``remote_port_id``).
- ``mtu_mismatch``: both ends' MTUs known and different. Each MTU is the device's own figure, and some systems count
  the ethernet header in it (Junos: 1514 for 1500), which a note says when one is found.
- ``description_mismatch``: the local port has a description of its own and it names neither the neighbour (the
  first label of the name it advertised, or of the monitored device's hostname, sysName or display name) nor the
  port it advertised; null without a description (``no_description``).
- ``remote_monitored``: the neighbour is a device LibreNMS monitors and this token can see.

Reads: ``devices/{id}/links`` for each device of a scope of at most :data:`.ports.DEVICE_READS` devices, else
``resources/links`` once; then the ports of the devices at both ends with :func:`.ports.read_ports` (one device at a
time up to that many devices, the local ones first, else one listing; when the listing is too large to read, one
device at a time within the request budget, the local ones first). A failed ports read leaves the links without
those ports' figures and the answer partial.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, FrozenSet, List, Tuple

from ..client import is_digits
from ..listing import natural_key
from . import fuzzy, units
from .context import (
    ReportContext,
    Request,
    Scope,
    View,
    brief,
    hostname_order,
    names_port,
    port_label,
    rows_of,
    truthy,
)
from .ports import DEVICE_READS, facts, interface_speed, read_ports

SCOPE_KEYS = ("device", "devices", "group", "location", "os", "type")
MISMATCHES = ("speed", "duplex", "mtu", "description")
HEADER_BYTES = frozenset({14, 18, 22})  # an ethernet header, with one or two VLAN tags: one MTU counts it, one not
NAMES_SHOWN = 20  # names of neighbours LibreNMS does not monitor that the summary lists
TEXT_KEYS = (
    "hostname", "display", "port", "description", "remote_hostname", "remote_port", "remote_platform",
    "remote_port_label", "unmonitored_neighbours",
)  # fmt: skip


@dataclass
class Neighbour:
    """A link's report row and what its filters and orders compare."""

    row: Dict[str, Any]
    port: Dict[str, Any] | None  # the local port's row, when it was read
    mismatches: FrozenSet[str]
    remote_known: bool  # the far end's port was matched and read: its speed, duplex and MTU can be compared
    remote_names: str  # the far end's names, folded, for filter.remote
    remote_order: Tuple[Any, ...]


# -- reads -----------------------------------------------------------------------------------------------------------
def read_links(ctx: ReportContext, scope: Scope, *, required: bool = True) -> List[Dict[str, Any]]:
    """The links whose local device is in *scope*: per device for a few, else every link in one listing. The links of
    a scope of one device, and the listing, are what the report is about, so a failure to read them fails it, unless
    they are not *required*; a failed read of one device of several leaves the answer partial."""
    devices = ctx.devices()
    if scope.ids is not None and len(scope.ids) <= DEVICE_READS:
        targets = sorted(scope.ids, key=lambda i: hostname_order(devices[i]))
        rows: List[Dict[str, Any]] = []
        for device_id in targets:
            if len(targets) == 1 and required:
                rows += rows_of(ctx.get("devices", device_id, "links"))
            else:
                rows += rows_of(ctx.optional(f"links of device {device_id}", "devices", device_id, "links"))
    elif required:
        rows = rows_of(ctx.get("resources", "links"))
    else:
        rows = rows_of(ctx.optional("links", "resources", "links"))
    rows = [row for row in rows if is_digits(row.get("local_device_id"))]
    if scope.ids is not None:
        rows = [row for row in rows if int(row["local_device_id"]) in scope.ids]
    return rows


def read_ends(ctx: ReportContext, links: List[Dict[str, Any]]) -> Dict[int, Dict[str, Any]]:
    """The port rows of both ends of *links*, by port id: the local devices' (what the report is about) and those of
    each monitored neighbour whose port LibreNMS matched, joined to them (:func:`.ports.read_ports`; read one device
    at a time, the local devices come first). A read that fails, or a device the budget leaves out, makes the answer
    partial."""
    devices = ctx.devices()
    local = {int(link["local_device_id"]) for link in links} & set(devices)
    far = {_id(link.get("remote_device_id")) for link in links if _remote_port(link)} & set(devices)
    if not local | far:
        return {}
    rows = read_ports(ctx, Scope(local, {}), required=False, joined=far - local)
    return {int(port["port_id"]): port for port in rows}


def _id(value: Any) -> int:
    return int(value) if is_digits(value) else 0


def _remote_port(link: Dict[str, Any]) -> int | None:
    port_id = _id(link.get("remote_port_id"))
    return port_id or None


# -- what a link means -----------------------------------------------------------------------------------------------
def describe(
    link: Dict[str, Any], devices: Dict[int, Dict[str, Any]], ports: Dict[int, Dict[str, Any]], now: datetime
) -> Neighbour:
    """*link* (a links row) as a report row: the local device and port, the neighbour as advertised and as LibreNMS
    knows it, and the checks."""
    local_id = int(link["local_device_id"])
    device = devices.get(local_id) or {"device_id": local_id}
    port_id = _id(link.get("local_port_id")) or None
    port = ports.get(port_id) if port_id is not None else None
    row: Dict[str, Any] = {**brief(device), "link_id": link.get("id"), "port_id": port_id}
    local = _end(port, device, now)
    row.update(port=local["port"], description=local["description"], state=local["state"])
    row.update(speed_bps=local["speed_bps"], speed=local["speed"], duplex=local["duplex"], mtu=local["mtu"])
    row.update(protocol=link.get("protocol") or None, active=truthy(link.get("active")))
    row.update(remote_hostname=link.get("remote_hostname") or None, remote_port=link.get("remote_port") or None)
    row["remote_platform"] = link.get("remote_platform") or None
    remote_id = _id(link.get("remote_device_id"))
    remote_device = devices.get(remote_id)
    row["remote_monitored"] = remote_device is not None
    row["remote_device"] = brief(remote_device) if remote_device is not None else None
    remote_port_id = _remote_port(link) if remote_device is not None else None
    remote_port = ports.get(remote_port_id) if remote_port_id is not None else None
    far = _end(remote_port, remote_device or {}, now)
    row.update(remote_port_id=remote_port_id, remote_port_label=far["port"], remote_state=far["state"])
    row.update(remote_speed_bps=far["speed_bps"], remote_speed=far["speed"], remote_duplex=far["duplex"])
    row["remote_mtu"] = far["mtu"]
    both_up = local["state"] == "up" and far["state"] == "up"
    described = local["no_description"] is False  # a description of its own, not empty nor its name again
    checks = {
        "speed": _differ(local["speed_bps"], far["speed_bps"]) if both_up else None,
        "duplex": _differ(_known(local["duplex"]), _known(far["duplex"])) if both_up else None,
        "mtu": _differ(local["mtu"], far["mtu"]),
        "description": _misdescribed(row, remote_device, remote_port) if described else None,
    }
    for kind in MISMATCHES:
        row[f"{kind}_mismatch"] = checks[kind]
    row["no_description"] = local["no_description"]
    names = [row["remote_hostname"]]
    if remote_device is not None:
        names += [remote_device.get(key) for key in ("hostname", "sysName", "display")]
    remote_name = row["remote_device"]["hostname"] if remote_device is not None else row["remote_hostname"]
    return Neighbour(
        row,
        port,
        frozenset(kind for kind, found in checks.items() if found),
        remote_port is not None,
        " ".join(str(name or "") for name in names).casefold(),
        (natural_key(remote_name), natural_key(row["remote_port"])),
    )


_END_KEYS = ("port", "description", "state", "speed_bps", "speed", "duplex", "mtu", "no_description")


def _end(port: Dict[str, Any] | None, device: Dict[str, Any], now: datetime) -> Dict[str, Any]:
    """One end of a link as its port row says it (all None when the port was not read): label, description, state,
    the speed its interface runs at, duplex, MTU, and whether it has no description of its own."""
    if port is None:
        return dict.fromkeys(_END_KEYS)
    known = facts(port, device or {"device_id": port.get("device_id")}, now).row
    speed, _source = interface_speed(port)
    out = {key: known[key] for key in ("description", "state", "duplex", "mtu", "no_description")}
    out.update(port=port_label(port), speed_bps=speed, speed=units.speed(speed))
    return out


def _known(duplex: str | None) -> str | None:
    return duplex if duplex in ("full", "half") else None


def _differ(local: Any, remote: Any) -> bool | None:
    """Whether two known values differ; None when either is not known."""
    if local in (None, 0) or remote in (None, 0):
        return None
    return local != remote


def _misdescribed(row: Dict[str, Any], device: Dict[str, Any] | None, port: Dict[str, Any] | None) -> bool | None:
    """Whether the local port's description names neither the neighbour nor its port: each name compared as words
    (:func:`.fuzzy.norm`, so ``to core_sw1`` names ``core-sw1``) and whole (``edge-rtr10`` does not name
    ``edge-rtr1``). None when there is no name to look for."""
    names = [fuzzy.label(row["remote_hostname"])]
    if device is not None:
        names += [fuzzy.label(device.get(key)) for key in ("hostname", "sysName", "display")]
    names.append(row["remote_port"])
    if port is not None:
        names += [port.get("ifName"), port.get("ifDescr")]
    wanted = {fuzzy.norm(name) for name in names if name} - {""}
    if not wanted:
        return None
    text = f" {fuzzy.norm(row['description'])} "
    return not any(f" {name} " in text for name in wanted)


# -- the view --------------------------------------------------------------------------------------------------------
def build(ctx: ReportContext, req: Request) -> Dict[str, Any]:
    """The links of the devices in scope that pass the filter, in the order asked for, a page of them."""
    scope = ctx.scope(req.scope, VIEW)
    links = read_links(ctx, scope)
    devices = ctx.devices()
    ports = read_ends(ctx, links)
    every = [describe(link, devices, ports, ctx.now) for link in links]
    kept = [item for item in every if _passes(item, req.filters)]
    kept.sort(key=_ORDERS[req.sort])
    page = kept[req.offset : req.offset + req.limit]
    rows = [item.row for item in kept]
    by_protocol: Dict[str, int] = {}
    for row in rows:
        name = str(row["protocol"] or "unknown")
        by_protocol[name] = by_protocol.get(name, 0) + 1
    summary = {
        "links": len(kept),
        "devices": len({row["device_id"] for row in rows}),
        "by_protocol": dict(sorted(by_protocol.items())),
        "remote_unmonitored": sum(not row["remote_monitored"] for row in rows),
        "unmonitored_neighbours": _unmonitored(rows),
        "remote_port_unknown": sum(not item.remote_known for item in kept),
        "mismatches": {kind: sum(kind in item.mismatches for item in kept) for kind in MISMATCHES},
        "no_description": sum(bool(row["no_description"]) for row in rows),
    }
    _notes(ctx, every, kept, req.filters)
    return ctx.envelope(
        "neighbours",
        scope=scope,
        rows=[item.row for item in page],
        count=len(kept),
        offset=req.offset,
        summary=summary,
        text_keys=TEXT_KEYS,
    )


def _notes(ctx: ReportContext, every: List[Neighbour], kept: List[Neighbour], filters: Dict[str, Any]) -> None:
    """What the model should know about the links kept: MTUs that may differ only by a header, a number in
    filter.port that kept both the port with that id and ports of that name, and, when it asked for mismatches, how
    many links of all those read could not be compared."""
    rows = [item.row for item in kept]
    headers = [row for row in rows if row["mtu_mismatch"] and abs(row["mtu"] - row["remote_mtu"]) in HEADER_BYTES]
    if headers:
        ctx.notes.append(
            f"{len(headers)} MTU mismatch(es) differ by an ethernet header (14 bytes, 18 or 22 with VLAN tags): each "
            "end reports its own figure and some systems count the header (Junos: 1514 for 1500), so check both "
            "configurations before calling it a mismatch"
        )
    wanted = filters.get("port")
    ports = {_id(row["port_id"]) for row in rows}
    if is_digits(wanted) and int(wanted) in ports and len(ports) > 1:
        ctx.notes.append(
            f"filter.port {wanted!r} kept the links of port_id {wanted} and of the ports named {wanted!r}: give "
            f"filter.port_id {wanted} for the port with that id alone"
        )
    unknown = sum(not item.remote_known for item in every)
    if unknown and filters.get("mismatch", frozenset()) & {"speed", "duplex", "mtu"}:
        ctx.notes.append(
            f"{unknown} link(s) could not be checked for a speed, duplex or MTU mismatch: LibreNMS does not monitor "
            "the neighbour, or did not match the port it advertised (remote_port_id), so its figures are not known"
        )


def _unmonitored(rows: List[Dict[str, Any]]) -> List[str]:
    """The names the neighbours LibreNMS does not monitor advertise, each once (ignoring case), at most
    :data:`NAMES_SHOWN`."""
    names: Dict[str, str] = {}
    for row in rows:
        if not row["remote_monitored"] and row["remote_hostname"]:
            names.setdefault(str(row["remote_hostname"]).casefold(), str(row["remote_hostname"]))
    return sorted(names.values(), key=natural_key)[:NAMES_SHOWN]


def _passes(item: Neighbour, filters: Dict[str, Any]) -> bool:
    row = item.row
    for key, wanted in filters.items():
        if key == "mismatch" and not item.mismatches & wanted:
            return False
        if key == "remote_unmonitored" and row["remote_monitored"] == wanted:
            return False
        if key == "port" and (item.port is None or not names_port(wanted, item.port)):
            return False
        if key == "port_id" and _id(row["port_id"]) != wanted:
            return False
        if key == "remote" and wanted.casefold() not in item.remote_names:
            return False
        if key == "protocol" and str(row["protocol"] or "").casefold() != wanted.casefold():
            return False
    return True


def _by_name(item: Neighbour) -> Tuple[Any, ...]:
    row = item.row
    return hostname_order(row), natural_key(row["port"]), _id(row["port_id"]), _id(row["link_id"])


_ORDERS: Dict[str, Callable[[Neighbour], Tuple[Any, ...]]] = {
    "name": _by_name,
    "remote": lambda item: (*item.remote_order, *_by_name(item)),
}


VIEW = View(
    "neighbours",
    build,
    scope_keys=SCOPE_KEYS,
    filters={
        "mismatch": MISMATCHES,
        "remote_unmonitored": "bool",
        "port": "text",
        "port_id": "id",
        "remote": "text",
        "protocol": "text",
    },
    sorts=("name", "remote"),
)
