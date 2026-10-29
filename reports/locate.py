"""View ``locate``: where an IPv4 or MAC address is on the network: the switch ports whose forwarding tables learned
the MAC, the likely edge port first, and the routers whose ARP tables pair it with an IP.

- A MAC, in any usual form (``00:11:22:33:44:55``, ``00-11-22-33-44-55``, ``0011.2233.4455``, twelve hex digits),
  is looked up in the forwarding tables LibreNMS keeps: ``ports/mac/{mac}`` gives the ports that learned it and how
  many MACs each learned, fewest first, which is LibreNMS's own guess at the edge port (an uplink learns every MAC
  behind it); ``resources/fdb/{mac}`` gives each entry's VLAN (an internal id, numbered from ``resources/vlans``) and
  when it was last updated (ISO UTC); ``resources/ip/arp/{mac}`` gives its IPv4 addresses and the routers holding
  them.
- An IPv4 address is looked up in the ARP tables (``resources/ip/arp/{ip}``), and each MAC found there (at most
  :data:`MAC_LOOKUPS`) as above. LibreNMS's API has no IPv6 neighbour table, so an IPv6 address is an argument error
  that points to view find (which matches the addresses on devices' interfaces).

Rows: ``kind`` ``port`` (a switch port that learned the MAC: ``macs_learned``, ``likely_edge`` for those of the MAC's
ports that learned the fewest, leaving out uplinks, its VLANs, ``last_seen`` and its age) before ``kind`` ``arp`` (a
router's ARP entry: the IP, the MAC and the router's interface, named by reading it, at most :data:`ARP_PORT_READS`).
The summary names the likely edge ports, the MACs and IPs found, and, for an IP, the device LibreNMS monitors at that
address.

An uplink (``uplink``) is a port whose LLDP/CDP neighbour (``neighbour``, a device LibreNMS monitors) learned the MAC
too: the MAC is behind that device, so the port is a link between switches, which learns every MAC behind it. A port to
a monitored device that did not learn the MAC (a hypervisor, an access point, a server, a switch whose forwarding table
LibreNMS does not read), or to the device at the address looked up, is not: the MAC is that device's own or behind it,
and that port is where it meets the switches LibreNMS reads.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Set, Tuple

from ..client import is_digits
from ..listing import natural_key
from ..routes import mac_hex
from . import units
from .context import (
    ArgumentError,
    ReportContext,
    Request,
    Scope,
    View,
    brief,
    hostname_order,
    port_label,
    port_state,
    rows_of,
    truthy,
)
from .neighbours import read_links

MAC_LOOKUPS = 3  # MACs of an IP whose switch ports are looked up
ARP_PORT_READS = 5  # router interfaces of ARP entries read to name them
VLAN_READS = 5  # devices whose VLANs are read one at a time to number an entry's VLAN; past that, one listing
TEXT_KEYS = ("hostname", "display", "port", "context")
_EDGE_KEYS = (
    "mac", "device_id", "hostname", "port_id", "port", "neighbour", "vlans", "macs_learned", "last_seen_age",
)  # fmt: skip
_NO_VIEW_SCOPE: Tuple[str, ...] = ()


def address(text: str) -> Tuple[str, str]:
    """``("ip", "192.0.2.50")`` or ``("mac", "001122334455")`` for a term; :class:`ArgumentError` for anything
    else."""
    try:
        found = ipaddress.ip_address(text.strip())
    except ValueError:
        found = None
    if found is not None:
        if found.version == 6:
            raise ArgumentError(
                "view locate reads LibreNMS's ARP tables, which hold IPv4 addresses only; for an IPv6 address use "
                "view find, which matches the addresses on devices' interfaces"
            )
        return "ip", str(found)
    digits = mac_hex(text)
    if digits is None:
        raise ArgumentError(
            "view locate takes an IPv4 address or a MAC address (00:11:22:33:44:55, 00-11-22-33-44-55, "
            "0011.2233.4455 or 12 hex digits); to look for a device or port by name use view find"
        )
    return "mac", digits


def readable(digits: str) -> str:
    """``00:11:22:33:44:55`` for ``001122334455``, as LibreNMS writes a MAC."""
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))


def build(ctx: ReportContext, req: Request) -> Dict[str, Any]:
    """The switch ports and ARP entries for the address in ``term``, the likely edge port first."""
    kind, value = address(req.term or "")
    scope = ctx.scope(req.scope, _NO_VIEW_SCOPE)
    devices = ctx.devices()
    if kind == "ip":
        arp = rows_of(ctx.get("resources", "ip", "arp", value))
        macs = list(dict.fromkeys(digits for row in arp if (digits := mac_hex(str(row.get("mac_address") or "")))))
        if len(macs) > MAC_LOOKUPS:
            ctx.partial(
                f"{value} pairs with {len(macs)} MACs in the ARP tables; the switch ports of the first {MAC_LOOKUPS} "
                "were looked up"
            )
        found = [port for mac in macs[:MAC_LOOKUPS] for port in _learned(ctx, mac, required=False)]
    else:
        macs = [value]
        found = _learned(ctx, value, required=True)
        arp = rows_of(ctx.optional("ARP entries", "resources", "ip", "arp", readable(value)))
    owner = _owner(value, devices) if kind == "ip" else None
    port_rows = _port_rows(ctx, found, devices, owner)
    arp_rows = _arp_rows(ctx, arp, devices)
    rows = port_rows + arp_rows
    page = rows[req.offset : req.offset + req.limit]
    edge = [row for row in port_rows if row["likely_edge"]]
    summary = {
        "address": value if kind == "ip" else readable(value),
        "kind": kind,
        "device": owner,
        "macs": [readable(mac) for mac in macs],
        "ips": sorted({row["ip"] for row in arp_rows if row["ip"]}, key=_ip_order),
        "edge": [{key: row[key] for key in _EDGE_KEYS} for row in edge],
        "ports": len(port_rows),
        "arp_entries": len(arp_rows),
    }
    _notes(ctx, kind, value, owner, macs, port_rows, arp_rows)
    return ctx.envelope(
        "locate",
        scope=scope,
        rows=page,
        count=len(rows),
        offset=req.offset,
        summary=summary,
        text_keys=TEXT_KEYS,
    )


# -- the switch ports ------------------------------------------------------------------------------------------------
def _learned(ctx: ReportContext, mac: str, *, required: bool) -> List[Dict[str, Any]]:
    """The ports that learned *mac* (``ports/mac``; every column of each, and ``fdb_entries_count``), each with the
    forwarding entries for it there (``resources/fdb``) under ``_entries``. A MAC the term named is what the report
    is about, so a failure to read its ports fails it; one an IP led to leaves the answer partial."""
    shown = readable(mac)
    if required:
        ports = ctx.get("ports", "mac", mac)
    else:
        ports = ctx.optional(f"the switch ports of {shown}", "ports", "mac", mac)
    ports = [port for port in rows_of(ports) if is_digits(port.get("port_id")) and not truthy(port.get("deleted"))]
    if not ports:
        return []
    entries = rows_of(ctx.optional(f"the forwarding entries of {shown}", "resources", "fdb", mac))
    out = []
    for port in ports:
        mine = [entry for entry in entries if str(entry.get("port_id")) == str(port["port_id"])]
        out.append({**port, "_mac": mac, "_entries": mine})
    return out


def _port_rows(
    ctx: ReportContext, found: List[Dict[str, Any]], devices: Dict[int, Dict[str, Any]], owner: Dict[str, Any] | None
) -> List[Dict]:
    """One row per port that learned a MAC. Of each MAC's ports, the likely edge ports are those that learned the
    fewest MACs (LibreNMS's own order), leaving out uplinks: a port whose LLDP/CDP neighbour LibreNMS monitors
    (:func:`_neighbours`) learned the MAC too, unless that neighbour is the device at the address looked up
    (*owner*); when every port is one, none is (a note says why). They come first, then the rest by how many MACs
    each learned, hostname and name."""
    ids = {int(port["device_id"]) for port in found if is_digits(port.get("device_id"))}
    vlans = _vlan_numbers(ctx, ids)
    neighbours = _neighbours(ctx, ids)
    learned: Dict[str, Set[int]] = {}  # the devices that learned each MAC
    for port in found:
        if is_digits(port.get("device_id")):
            learned.setdefault(port["_mac"], set()).add(int(port["device_id"]))
    owner_id = _id(owner["device_id"]) if owner is not None else None
    rows = []
    for port in found:
        device_id = int(port["device_id"]) if is_digits(port.get("device_id")) else None
        device = devices.get(device_id) if device_id is not None else None
        seen = max((units.utc_time(entry.get("updated_at")) for entry in port["_entries"]), default=None, key=_stamp)
        age = units.age(seen, ctx.now)
        numbers = {vlans.get(str(entry.get("vlan_id"))) for entry in port["_entries"]} - {None}
        row: Dict[str, Any] = {"kind": "port", "mac": readable(port["_mac"])}
        row.update(brief(device) if device is not None else {"device_id": port.get("device_id"), "hostname": None})
        row.update(port_id=int(port["port_id"]), port=port_label(port), state=port_state(port))
        row.update(macs_learned=_count(port.get("fdb_entries_count")), likely_edge=False)
        near = neighbours.get(row["port_id"], {})
        if owner_id in near:  # the port to the device at the address is where it is, whatever that device learned
            behind, neighbour = [], owner_id
        else:
            behind = [i for i in near if i in learned.get(port["_mac"], ())]  # the MAC is behind them
            neighbour = (behind or [*near, None])[0]
        row.update(neighbour=brief(near[neighbour]) if neighbour is not None else None, uplink=bool(behind))
        row["trunk"] = port.get("ifTrunk") or None
        row.update(vlans=sorted(numbers), last_seen=units.iso(seen), last_seen_age_s=age)
        row["last_seen_age"] = units.duration(age)
        rows.append(row)
    for mac in {row["mac"] for row in rows}:
        counted = [row for row in rows if row["mac"] == mac and row["macs_learned"] is not None]
        pool = [row for row in counted if not row["uplink"]]
        fewest = min((row["macs_learned"] for row in pool), default=None)
        for row in pool:
            row["likely_edge"] = row["macs_learned"] == fewest
    return sorted(rows, key=_edge_order)


def _edge_order(row: Dict[str, Any]) -> Tuple[Any, ...]:
    count = row["macs_learned"]
    head = (not row["likely_edge"], row["uplink"], count is None, count or 0)
    return (*head, hostname_order(row), natural_key(row["port"]), row["port_id"], row["mac"])


def _neighbours(ctx: ReportContext, device_ids: Set[int]) -> Dict[int, Dict[int, Dict[str, Any]]]:
    """The ports of *device_ids* that have an LLDP/CDP neighbour LibreNMS monitors, each with those devices by id, in
    hostname order (a port to an unmanaged switch may see several). A failed read leaves those ports without them,
    and the answer partial."""
    devices = ctx.devices()
    found: Dict[int, Set[int]] = {}
    for link in read_links(ctx, Scope(device_ids & set(devices), {}), required=False):
        remote = _id(link.get("remote_device_id"))
        if remote in devices and is_digits(link.get("local_port_id")):
            found.setdefault(int(link["local_port_id"]), set()).add(remote)
    return {
        port_id: {i: devices[i] for i in sorted(ids, key=lambda i: hostname_order(devices[i]))}
        for port_id, ids in found.items()
    }


def _vlan_numbers(ctx: ReportContext, device_ids: Set[int]) -> Dict[str, int]:
    """The VLAN number (``vlan_vlan``) of each VLAN id (``vlan_id``, which a forwarding entry names) on *device_ids*:
    ``resources/vlans`` for each of a few devices, else once for every device. A read that fails leaves those
    entries without their VLAN, and the answer partial."""
    if not device_ids:
        return {}
    if len(device_ids) <= VLAN_READS:
        rows: List[Dict[str, Any]] = []
        for device_id in sorted(device_ids):
            rows += rows_of(
                ctx.optional(f"VLANs of device {device_id}", "resources", "vlans", params={"hostname": device_id})
            )
    else:
        rows = rows_of(ctx.optional("VLANs", "resources", "vlans"))
    out = {}
    for row in rows:
        number = _count(row.get("vlan_vlan"))
        if number is not None and is_digits(row.get("vlan_id")):
            out[str(row["vlan_id"])] = number
    return out


# -- the ARP entries -------------------------------------------------------------------------------------------------
def _arp_rows(ctx: ReportContext, arp: List[Dict[str, Any]], devices: Dict[int, Dict[str, Any]]) -> List[Dict]:
    """One row per ARP entry: the IP, the MAC, the router and its interface (read to name it, at most
    :data:`ARP_PORT_READS` interfaces), by router hostname, IP and interface."""
    ids = list(
        dict.fromkeys(int(row["port_id"]) for row in arp if is_digits(row.get("port_id")) and int(row["port_id"]))
    )
    ports: Dict[int, Dict[str, Any]] = {}
    for port_id in ids[:ARP_PORT_READS]:
        for port in rows_of(ctx.optional(f"port {port_id}", "ports", port_id)):
            ports[port_id] = port
    if len(ids) > ARP_PORT_READS:
        ctx.notes.append(
            f"the ARP entries are on {len(ids)} router interfaces; the first {ARP_PORT_READS} are named, the rest "
            "only by port_id"
        )
    out = []
    for entry in arp:
        device_id = int(entry["device_id"]) if is_digits(entry.get("device_id")) else None
        device = devices.get(device_id) if device_id is not None else None
        port_id = int(entry["port_id"]) if is_digits(entry.get("port_id")) and int(entry["port_id"]) else None
        port = ports.get(port_id) if port_id is not None else None
        digits = mac_hex(str(entry.get("mac_address") or ""))
        row: Dict[str, Any] = {"kind": "arp", "ip": entry.get("ipv4_address") or None}
        row["mac"] = readable(digits) if digits else entry.get("mac_address")
        row.update(brief(device) if device is not None else {"device_id": entry.get("device_id"), "hostname": None})
        row.update(port_id=port_id, port=port_label(port) if port is not None else None)
        row["context"] = entry.get("context_name") or None
        out.append(row)
    out.sort(key=lambda row: (hostname_order(row), _ip_order(row["ip"]), row["port_id"] or 0, str(row["mac"])))
    return out


# -- the rest --------------------------------------------------------------------------------------------------------
def _owner(ip: str, devices: Dict[int, Dict[str, Any]]) -> Dict[str, Any] | None:
    """The device LibreNMS monitors at *ip*: its hostname, IP or overwrite_ip is that address."""
    for device_id in sorted(devices, key=lambda i: hostname_order(devices[i])):
        device = devices[device_id]
        for key in ("hostname", "ip", "overwrite_ip"):
            if _same_ip(device.get(key), ip):
                return brief(device)
    return None


def _same_ip(value: Any, ip: str) -> bool:
    try:
        return str(ipaddress.ip_address(str(value or "").strip())) == ip
    except ValueError:
        return False


def _notes(
    ctx: ReportContext,
    kind: str,
    value: str,
    owner: Dict[str, Any] | None,
    macs: List[str],
    ports: List[Dict],
    arp: List[Dict],
) -> None:
    if kind == "ip" and not arp:
        ctx.notes.append(
            f"no ARP table LibreNMS holds has {value}: no router it polls has seen it lately (its ARP tables hold "
            "IPv4 only); view find matches it against the addresses on devices' interfaces"
        )
    if macs and not ports:
        ctx.notes.append(
            "no switch port LibreNMS polls has learned "
            + ", ".join(readable(mac) for mac in macs[:MAC_LOOKUPS])
            + ": its forwarding tables do not hold it, or the switches' FDB is not read"
        )
    owner_id = _id(owner["device_id"]) if owner is not None else None
    for mac in dict.fromkeys(row["mac"] for row in ports):
        mine = [row for row in ports if row["mac"] == mac]
        edge = [row for row in mine if row["likely_edge"]]
        if len(edge) > 1:
            ctx.notes.append(
                f"{len(edge)} ports learned {mac} with as few MACs each: the device may be on any of them (an access "
                "port, or a port to a hypervisor, an access point or a switch LibreNMS does not read); ask, or "
                "compare their descriptions"
            )
        elif not edge and all(row["uplink"] for row in mine):
            ctx.notes.append(
                f"every port that learned {mac} leads to a device LibreNMS monitors that learned it too (uplink), so "
                "none is its edge port: their forwarding entries disagree (one has not aged out, or the MAC moved: "
                "compare last_seen), or the device is on an unmanaged switch between them"
            )
        neighbours = {_id(row["neighbour"]["device_id"]) for row in edge if row["neighbour"]}
        if owner_id in neighbours:
            ctx.notes.append(
                f"the likely edge port of {mac} leads to the device at {value} (neighbour, summary.device)"
            )
        elif neighbours:
            ctx.notes.append(
                f"the likely edge port of {mac} leads to a device LibreNMS monitors that did not learn it (neighbour): "
                "the MAC is that device's own, or behind it (a VM on a hypervisor, a client of an access point, a host "
                "on a switch whose forwarding table LibreNMS does not read)"
            )
    if ports:
        ctx.notes.append(
            "likely_edge: of the ports that learned the MAC, those that learned the fewest MACs (LibreNMS's own "
            "guess, as an uplink learns every MAC behind it), leaving out uplinks (the port's LLDP/CDP neighbour, a "
            "device LibreNMS monitors, learned the MAC too); last_seen is when LibreNMS last found the entry"
        )


def _ip_order(ip: Any) -> Tuple[int, int]:
    try:
        found = ipaddress.ip_address(str(ip or ""))
    except ValueError:
        return (1, 0)
    return (0, int(found))


def _id(value: Any) -> int:
    return int(value) if is_digits(value) else 0


def _count(value: Any) -> int | None:
    found = units.number(value)
    return None if found is None or found < 0 else int(found)


def _stamp(moment: Any) -> float:
    return moment.timestamp() if moment is not None else float("-inf")


VIEW = View("locate", build, sorts=("edge",), term=True, term_hint="an IPv4 or MAC address")
