"""View ``vlans``: the VLANs LibreNMS discovered on each device in scope, and, for one VLAN, the ports in it.

A row is one VLAN on one device: its tag (``vlan``), name and type. ``filter.vlan`` keeps one VLAN, by its tag, or
those whose name holds a text; when what it keeps is on at most :data:`.ports.DEVICE_READS` devices, each row also
lists the ports in that VLAN (``ports``), read with ``devices/{id}/ports?with=vlans``: ``untagged`` (an access port,
or a trunk's native VLAN: LibreNMS's ports_vlans row says so, or the VLAN is the port's own ``ifVlan``, which is how
LibreNMS's PortVlan reads it too) or ``tagged`` (a trunk carrying it), with each port's state, and counts them. The
summary counts the VLANs and devices, and names the tags that are called differently on different devices.

Reads: ``devices/{id}/vlans`` for each device of a scope of at most :data:`.ports.DEVICE_READS` devices, else
``resources/vlans`` once, filtered here; then the ports as above, each read of which may fail and leave the answer
partial.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Set, Tuple

from ..client import is_digits
from ..listing import natural_key
from . import fuzzy, units
from .context import ReportContext, Request, Scope, View, brief, hostname_order, port_label, port_state, rows_of, truthy
from .ports import DEVICE_READS

SCOPE_KEYS = ("device", "devices", "group", "location", "os", "type")
PORT_COLUMNS = "port_id,device_id,ifIndex,ifName,ifDescr,ifAlias,ifAdminStatus,ifOperStatus,ifVlan,ifTrunk"
PORTS_SHOWN = 100  # ports a row lists; the counts count them all
NAMES_SHOWN = 10  # tags called differently that the summary names
TEXT_KEYS = ("hostname", "display", "name", "port", "names")


def read_vlans(ctx: ReportContext, scope: Scope) -> List[Dict[str, Any]]:
    """The VLAN rows of the devices in *scope*, each with its ``device_id``: per device for a few (a scope of one
    device fails with its read, one of several leaves the answer partial), else one listing of every device's."""
    devices = ctx.devices()
    if scope.ids is not None and len(scope.ids) <= DEVICE_READS:
        targets = sorted(scope.ids, key=lambda i: hostname_order(devices[i]))
        rows: List[Dict[str, Any]] = []
        for device_id in targets:
            if len(targets) == 1:
                found = ctx.get("devices", device_id, "vlans")
            else:
                found = ctx.optional(f"VLANs of device {device_id}", "devices", device_id, "vlans")
            rows += [{**row, "device_id": device_id} for row in rows_of(found)]  # this route leaves the id out
        return rows
    rows = [row for row in rows_of(ctx.get("resources", "vlans")) if is_digits(row.get("device_id"))]
    if scope.ids is not None:
        rows = [row for row in rows if int(row["device_id"]) in scope.ids]
    return rows


def build(ctx: ReportContext, req: Request) -> Dict[str, Any]:
    """The VLANs of the devices in scope that pass the filter, in the order asked for, a page of them, with their
    ports when one VLAN on a few devices is asked for."""
    scope = ctx.scope(req.scope, VIEW)
    devices = ctx.devices()
    every = []
    for raw in read_vlans(ctx, scope):
        tag = _tag(raw.get("vlan_vlan"))
        device_id = int(raw["device_id"])
        if tag is None:
            continue
        device = devices.get(device_id) or {"device_id": device_id}
        row: Dict[str, Any] = {**brief(device), "vlan": tag, "name": raw.get("vlan_name") or None}
        row["type"] = raw.get("vlan_type") or None
        every.append(row)
    wanted = req.filters.get("vlan")
    kept = [row for row in every if wanted is None or _named(row, wanted)]
    kept.sort(key=_ORDERS[req.sort])
    summary: Dict[str, Any] = {
        "vlans": len({row["vlan"] for row in kept}),
        "devices": len({row["device_id"] for row in kept}),
        "named_differently": _named_differently(kept),
    }
    if wanted is not None:
        on = {int(row["device_id"]) for row in kept if is_digits(row.get("device_id"))} & set(devices)
        if kept and len(on) <= DEVICE_READS:
            _members(ctx, kept, on)
            summary["untagged_ports"] = sum(row["untagged_ports"] or 0 for row in kept)
            summary["tagged_ports"] = sum(row["tagged_ports"] or 0 for row in kept)
        elif kept:
            ctx.notes.append(
                f"those VLANs are on {len(on)} devices, and the ports in them are listed for at most {DEVICE_READS}: "
                "name a device or a few (scope) to list them"
            )
    if not kept and wanted is not None:
        ctx.notes.append(f"no device in scope has a VLAN {_wanted_text(wanted)}")
    page = kept[req.offset : req.offset + req.limit]
    return ctx.envelope(
        "vlans",
        scope=scope,
        rows=page,
        count=len(kept),
        offset=req.offset,
        summary=summary,
        text_keys=TEXT_KEYS,
    )


def _tag(value: Any) -> int | None:
    found = units.number(value)
    return int(found) if found is not None and found >= 0 and found == int(found) else None


def _named(row: Dict[str, Any], wanted: str) -> bool:
    """``filter.vlan``: a tag (its digits) is that VLAN; anything else is held in its name, any case."""
    if is_digits(wanted):
        return row["vlan"] == int(wanted)
    return wanted.casefold() in str(row["name"] or "").casefold()


def _wanted_text(wanted: str) -> str:
    return wanted if is_digits(wanted) else f"whose name holds {fuzzy.shown(wanted)}"


def _named_differently(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The tags that carry more than one name across devices (ignoring case), at most :data:`NAMES_SHOWN`."""
    names: Dict[int, Dict[str, str]] = {}
    for row in rows:
        if row["name"]:
            names.setdefault(row["vlan"], {}).setdefault(str(row["name"]).casefold(), row["name"])
    out = [
        {"vlan": tag, "names": sorted(found.values(), key=natural_key)}
        for tag, found in sorted(names.items())
        if len(found) > 1
    ]
    return out[:NAMES_SHOWN]


def _members(ctx: ReportContext, rows: List[Dict[str, Any]], device_ids: Set[int]) -> None:
    """Each row's ports: those in its VLAN on its device, untagged first, from one ``with=vlans`` read per device
    (a failed read leaves that device's rows with ``ports`` null and the answer partial)."""
    devices = ctx.devices()
    by_device: Dict[int, List[Dict[str, Any]] | None] = {}
    for device_id in sorted(device_ids, key=lambda i: hostname_order(devices[i])):
        found = ctx.optional(
            f"ports of device {device_id}",
            "devices",
            device_id,
            "ports",
            params={"columns": PORT_COLUMNS, "with": "vlans"},
        )
        by_device[device_id] = None if found is None else rows_of(found)
    cut = False
    for row in rows:
        ports = by_device.get(row["device_id"])
        if ports is None:
            row.update(untagged_ports=None, tagged_ports=None, ports=None)
            continue
        members = []
        for port in ports:
            mode = _mode(port, row["vlan"])
            if mode is not None:
                members.append((mode != "untagged", natural_key(port_label(port)), _id(port), port, mode))
        members.sort(key=lambda item: item[:3])
        listed = [
            {"port_id": _id(port), "port": port_label(port), "mode": mode, "state": port_state(port)}
            for *_key, port, mode in members
        ]
        row["untagged_ports"] = sum(item["mode"] == "untagged" for item in listed)
        row["tagged_ports"] = len(listed) - row["untagged_ports"]
        row["ports"] = listed[:PORTS_SHOWN]
        cut = cut or len(listed) > PORTS_SHOWN
    if cut:
        ctx.notes.append(f"a row lists at most {PORTS_SHOWN} ports; untagged_ports and tagged_ports count them all")


def _mode(port: Dict[str, Any], tag: int) -> str | None:
    """``untagged`` or ``tagged`` when *port* is in VLAN *tag*, else None: its ports_vlans row for the tag (untagged
    as LibreNMS reads it), else its own ``ifVlan`` (its access or native VLAN)."""
    for member in rows_of(port.get("vlans")):
        if _tag(member.get("vlan")) == tag:
            return "untagged" if truthy(member.get("untagged")) or _tag(port.get("ifVlan")) == tag else "tagged"
    return "untagged" if _tag(port.get("ifVlan")) == tag else None


def _id(port: Dict[str, Any]) -> int:
    return int(port["port_id"]) if is_digits(port.get("port_id")) else 0


_ORDERS: Dict[str, Callable[[Dict[str, Any]], Tuple[Any, ...]]] = {
    "vlan": lambda row: (row["vlan"], *hostname_order(row)),
    "name": lambda row: (*hostname_order(row), row["vlan"]),
}


VIEW = View("vlans", build, scope_keys=SCOPE_KEYS, filters={"vlan": "text"}, sorts=("vlan", "name"))
