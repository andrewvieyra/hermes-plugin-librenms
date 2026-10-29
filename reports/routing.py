"""View ``routing``: the BGP sessions and OSPF and OSPFv3 neighbours of the devices in scope, each named, with
whether it is up and for how long.

Reads: ``bgp``, ``ospf`` and ``ospfv3``, each once (``hostname`` the device's id for a scope of one device; for
``filter.remote_as``, ``remote_asn`` and BGP alone), kept to the scope here; the protocols ``filter.protocol`` names,
every one by default. LibreNMS lists only sessions and neighbours that have a state. Its ``ospfv3`` route answers
HTTP 500 ``Error retrieving ospfv3_nbrs`` when it has no neighbour: that answer is none, and so is the 404 of a
LibreNMS too old to have the route (with a note). Any other failed read of a protocol fails the report when it is the
only one read, and otherwise leaves it out and the answer partial.

BGP: ``established`` (``bgpPeerState``); ``enabled`` (admin status ``start`` or ``running``; ``stop`` and ``halted``
are shut down on purpose); ``up_for_s`` of an established session and ``down_for_s`` of one that is not, both from
``bgpPeerFsmEstablishedTime`` (seconds at the last poll, which the BGP MIB counts since the session was last
established, or since it last went down; 0 when it never was since the router booted or the peer was configured)
plus the time since that poll; ``last_error`` (LibreNMS's text, else the name of the BGP error code: it may predate
the current session); addresses as IPv6 is written short. OSPF: ``established`` is ``full``; ``twoWay`` is the
steady state between two routers that are neither DR nor BDR on a broadcast network, which a note says when one
shows; the router id dotted, as OSPF writes it (LibreNMS stores an OSPFv3 neighbour's as its 32-bit number, and its
peer address is link-local, so the router id is what names it). The interface an OSPF neighbour is on is named from
its device's port names, for the rows of the page.

``not_established`` keeps what LibreNMS alarms on (``BgpPeer::inAlarm``): a BGP session that is enabled and not
established, an OSPF neighbour that is not full. ``stale``: the device has not been polled lately, so its sessions'
state is the last LibreNMS read.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Tuple

from ..client import LibreNMSError, is_digits
from ..listing import natural_key
from . import units
from .context import (
    ArgumentError,
    ReportContext,
    Request,
    View,
    brief,
    failure,
    hostname_order,
    port_label,
    rows_of,
)
from .ports import device_stale

SCOPE_KEYS = ("device", "devices", "group", "location", "os", "type")
PROTOCOLS = ("bgp", "ospf", "ospfv3")
BGP_STATES = ("idle", "connect", "active", "opensent", "openconfirm", "established")
OSPF_STATES = ("down", "attempt", "init", "twoWay", "exchangeStart", "exchange", "loading", "full")
STATES = (*BGP_STATES, *OSPF_STATES)
ENABLED = frozenset({"start", "running"})  # a BGP session's admin status, as LibreNMS's inAlarm reads it
DISABLED = frozenset({"stop", "halted"})
OSPFV3_NONE = "Error retrieving ospfv3_nbrs"  # LibreNMS's HTTP 500 for no OSPFv3 neighbour at all
MAX_ASN = 2**32 - 1
_ASN_RE = re.compile(r"^\s*(?:as)?\s*(\d{1,10})(?:\.(\d{1,5}))?\s*$", re.IGNORECASE)  # 65001, AS65001, asdot 1.10
TEXT_KEYS = (
    "hostname",
    "display",
    "peer",
    "local_address",
    "router_id",
    "as_name",
    "description",
    "last_error",
    "port",
    "context",
)
_LABELS = {"bgp": "BGP sessions", "ospf": "OSPF neighbours", "ospfv3": "OSPFv3 neighbours"}
_PROTOCOL_ORDER = {protocol: number for number, protocol in enumerate(PROTOCOLS)}
# BGP NOTIFICATION error codes (RFC 4271) and the Cease subcodes (RFC 4486), for a session LibreNMS has no text for.
_BGP_ERRORS = {
    1: "Message Header Error", 2: "OPEN Message Error", 3: "UPDATE Message Error", 4: "Hold Timer Expired",
    5: "Finite State Machine Error", 6: "Cease",
}  # fmt: skip
_CEASE = {
    1: "Maximum Number of Prefixes Reached", 2: "Administrative Shutdown", 3: "Peer De-configured",
    4: "Administrative Reset", 5: "Connection Rejected", 6: "Other Configuration Change",
    7: "Connection Collision Resolution", 8: "Out of Resources",
}  # fmt: skip


@dataclass
class _Session:
    """A BGP session's or OSPF neighbour's report row, and what filters and orders compare."""

    row: Dict[str, Any]
    alarm: bool  # enabled and not established: what LibreNMS counts as down
    text: str  # names, addresses and descriptions, folded, for filter.text


def build(ctx: ReportContext, req: Request) -> Dict[str, Any]:
    """The sessions of the devices in scope that pass the filter, in the order asked for, a page of them with the
    OSPF interfaces named."""
    filters = dict(req.filters)
    if "remote_as" in filters:
        filters["remote_as"] = asn(filters["remote_as"])
    scope = ctx.scope(req.scope, VIEW)
    devices = ctx.devices()
    ids = scope.ids if scope.ids is not None else set(devices)
    protocols = [protocol for protocol in PROTOCOLS if protocol in filters.get("protocol", PROTOCOLS)]
    if "remote_as" in filters:  # only a BGP session has a remote AS
        protocols = [protocol for protocol in protocols if protocol == "bgp"]
    params: Dict[str, Any] = {}
    if scope.ids is not None and len(scope.ids) == 1:
        params["hostname"] = next(iter(scope.ids))
    sessions: List[_Session] = []
    for protocol in protocols if ids else ():  # a scope that holds no device has no session to read
        extra = {"remote_asn": filters["remote_as"]} if protocol == "bgp" and "remote_as" in filters else {}
        for row in _read(ctx, protocol, {**params, **extra}, required=len(protocols) == 1):
            if _id(row.get("device_id")) in ids:
                sessions.append((_bgp if protocol == "bgp" else _ospf)(ctx, devices, row, protocol))
    kept = [item for item in sessions if _passes(item, filters)]
    kept.sort(key=_ORDERS[req.sort])
    page = kept[req.offset : req.offset + req.limit]
    _name_ports(ctx, page)
    _notes(ctx, kept)
    return ctx.envelope(
        "routing",
        scope=scope,
        rows=[item.row for item in page],
        count=len(kept),
        offset=req.offset,
        summary=_summary(kept, protocols),
        text_keys=TEXT_KEYS,
    )


def _id(value: Any) -> int:
    return int(value) if is_digits(value) else 0


def asn(text: str) -> int:
    """filter.remote_as as the AS number LibreNMS stores: ``65001``, ``AS65001``, or asdot ``1.10`` (65546)."""
    found = _ASN_RE.match(text)
    if found is not None:
        high, low = found.group(1), found.group(2)
        if low is None and int(high) <= MAX_ASN:
            return int(high)
        if low is not None and int(high) <= 0xFFFF and int(low) <= 0xFFFF:
            return int(high) * 65536 + int(low)
    raise ArgumentError(f"filter.remote_as takes an AS number: 65001, AS65001 or asdot 1.10 (got {text[:40]!r})")


def _read(ctx: ReportContext, protocol: str, params: Dict[str, Any], *, required: bool) -> List[Dict[str, Any]]:
    """The rows of one protocol's route: none for OSPFv3's 500 that says it has none, and none, with a note, from a
    LibreNMS too old to have the route (it does not poll that protocol either); a failure fails the report when the
    protocol is *required* (the only one read), and otherwise leaves it out and the answer partial."""
    what = f"the {_LABELS[protocol]}"
    try:
        if required:
            return rows_of(ctx.get(protocol, params=params or None))
        return rows_of(ctx.optional(what, protocol, params=params or None, raising=("server", "route")))
    except LibreNMSError as exc:
        body = exc.body if isinstance(exc.body, dict) else {}
        if protocol == "ospfv3" and exc.status == 500 and body.get("message") == OSPFV3_NONE:
            return []
        if exc.kind == "route":  # also when it is the only protocol asked for
            ctx.notes.append(f"this LibreNMS has no {protocol} route (an older release): no {_LABELS[protocol]} listed")
            return []
        if required:
            raise
        ctx.partial(f"{what} not read: LibreNMS answered {failure(exc)}")
    return []


# -- what a row means ------------------------------------------------------------------------------------------------
def _device(devices: Dict[int, Dict[str, Any]], row: Dict[str, Any]) -> Dict[str, Any]:
    return devices.get(_id(row.get("device_id"))) or {"device_id": row.get("device_id")}


def _address(value: Any) -> Any:
    """An IP address as it is usually written (LibreNMS stores a BGP peer's IPv6 address in full,
    ``2001:0db8:0000:...``); anything else as it is."""
    if not isinstance(value, str) or not value.strip():
        return value or None
    try:
        return ipaddress.ip_address(value.strip()).compressed
    except ValueError:
        return value


def _whole(value: Any) -> int | None:
    found = units.number(value)
    return None if found is None or found < 0 else int(found)


def _since_poll(ctx: ReportContext, device: Dict[str, Any]) -> int:
    return units.age(units.utc_time(device.get("last_polled")), ctx.now) or 0


def _bgp(ctx: ReportContext, devices: Dict[int, Dict[str, Any]], session: Dict[str, Any], protocol: str) -> _Session:
    """A BGP session as a report row: the peer and its AS, the state, whether it is enabled and established, for
    how long, and its last error."""
    device = _device(devices, session)
    state = str(session.get("bgpPeerState") or "") or None
    admin = session.get("bgpPeerAdminStatus") or None
    enabled = True if admin in ENABLED else False if admin in DISABLED else None
    established = state == "established"
    timer = _whole(session.get("bgpPeerFsmEstablishedTime"))
    counted = None if timer is None else timer + _since_poll(ctx, device)
    up = counted if established else None
    down = counted if not established and timer else None  # 0: never established since boot or configuration
    row: Dict[str, Any] = {**brief(device), "protocol": protocol, "session_id": session.get("bgpPeer_id")}
    row.update(peer=_address(session.get("bgpPeerIdentifier")), remote_as=_whole(session.get("bgpPeerRemoteAs")))
    row.update(as_name=session.get("astext") or None, description=session.get("bgpPeerDescr") or None)
    row.update(local_address=_address(session.get("bgpLocalAddr")), state=state, admin_status=admin)
    row.update(enabled=enabled, established=established, up_for_s=up, up_for=units.duration(up))
    row.update(down_for_s=down, down_for=units.duration(down), last_error=_bgp_error(session))
    if session.get("vrf_id") not in (None, "", 0):
        row["vrf_id"] = session["vrf_id"]
    if session.get("context_name"):
        row["context"] = session["context_name"]
    row["stale"] = device_stale(device, ctx.now)
    return _Session(row, enabled is True and not established, _folded(row))


def _bgp_error(session: Dict[str, Any]) -> str | None:
    """The session's last error: LibreNMS's text for it, else the name of its BGP error code and subcode (``Cease:
    Administrative Shutdown``), with the codes; None when it has had none."""
    code, sub = _whole(session.get("bgpPeerLastErrorCode")), _whole(session.get("bgpPeerLastErrorSubCode"))
    if not code:
        return None
    text = str(session.get("bgpPeerLastErrorText") or "").strip()
    if not text:
        text = _BGP_ERRORS.get(code, "error")
        if code == 6 and sub in _CEASE:
            text = f"{text}: {_CEASE[sub]}"
    return f"{text} ({code}/{sub or 0})"


def _ospf(ctx: ReportContext, devices: Dict[int, Dict[str, Any]], nbr: Dict[str, Any], protocol: str) -> _Session:
    """An OSPF or OSPFv3 neighbour as a report row: its address and router id, its state, whether it is full, and
    the port it is on (named for the page)."""
    device = _device(devices, nbr)
    prefix = "ospfNbr" if protocol == "ospf" else "ospfv3Nbr"
    state = str(nbr.get(f"{prefix}State") or "") or None
    address = nbr.get("ospfNbrIpAddr") if protocol == "ospf" else nbr.get("ospfv3NbrAddress")
    port_id = _id(nbr.get("port_id")) or None
    row: Dict[str, Any] = {**brief(device), "protocol": protocol, "neighbour_id": nbr.get("id")}
    row.update(peer=_address(address), router_id=_router_id(nbr.get(f"{prefix}RtrId")), state=state)
    row.update(established=state == "full", port_id=port_id, port=None, priority=_whole(nbr.get(f"{prefix}Priority")))
    row.update(events=_whole(nbr.get(f"{prefix}Events")), retransmit_queue=_whole(nbr.get(f"{prefix}LsRetransQLen")))
    if nbr.get("context_name"):
        row["context"] = nbr["context_name"]
    row["stale"] = device_stale(device, ctx.now)
    return _Session(row, state != "full", _folded(row))


def _router_id(value: Any) -> Any:
    """An OSPF router id dotted, as it is written: LibreNMS stores an OSPFv3 neighbour's as the 32-bit number
    (``167797515``, 10.0.99.11) and an OSPF one's dotted already; None for none (0 is not a router id)."""
    if is_digits(value):
        number = int(value)
        if not number:
            return None
        return str(ipaddress.IPv4Address(number)) if number <= 0xFFFFFFFF else value
    return value or None


def _folded(row: Dict[str, Any]) -> str:
    keys = ("hostname", "display", "peer", "router_id", "as_name", "description")
    return " ".join(str(row.get(key) or "") for key in keys).casefold()


def _name_ports(ctx: ReportContext, page: List[_Session]) -> None:
    """Name the port each OSPF neighbour of *page* is on, from its device's port names (at most 10 devices)."""
    by_device: Dict[Any, List[_Session]] = {}
    for item in page:
        if item.row.get("port_id") and item.row["device_id"] is not None:
            by_device.setdefault(item.row["device_id"], []).append(item)
    if not by_device:
        return
    ports = ctx.ports_by_device(
        by_device,
        "the ports of device {}'s OSPF neighbours",
        "the ports of {} more devices' OSPF neighbours were not named",
        "view port names one by its port_id",
    )
    for device_id, items in by_device.items():
        names = {str(port.get("port_id")): port_label(port) for port in ports.get(device_id, ())}
        for item in items:
            item.row["port"] = names.get(str(item.row["port_id"]))


# -- filters, orders, summary ----------------------------------------------------------------------------------------
def _passes(item: _Session, filters: Dict[str, Any]) -> bool:
    row = item.row
    for key, wanted in filters.items():
        if key == "protocol" and row["protocol"] not in wanted:
            return False
        if key == "not_established" and item.alarm != wanted:
            return False
        if key == "enabled" and row.get("enabled", True) is not wanted:  # an unknown admin status matches neither
            return False
        if key == "state" and row["state"] not in wanted:
            return False
        if key == "remote_as" and row.get("remote_as") != wanted:
            return False
        if key == "text" and wanted.casefold() not in item.text:
            return False
    return True


def _by_name(item: _Session) -> Tuple[Any, ...]:
    row = item.row
    ident = row.get("session_id") if row["protocol"] == "bgp" else row.get("neighbour_id")
    return (*hostname_order(row), _PROTOCOL_ORDER[row["protocol"]], natural_key(row["peer"]), _id(ident))


def _by_state(item: _Session) -> Tuple[Any, ...]:
    """What LibreNMS counts as down first, then sessions shut down on purpose, then those that are up."""
    return (0 if item.alarm else 2 if item.row["established"] else 1), *_by_name(item)


def _by_up_for(item: _Session) -> Tuple[Any, ...]:
    """Established sessions up the shortest time first (recently reset), then the others."""
    up = item.row.get("up_for_s")
    return up is None, up or 0, *_by_name(item)


def _by_remote_as(item: _Session) -> Tuple[Any, ...]:
    remote = item.row.get("remote_as")
    return remote is None, remote or 0, *_by_name(item)


_ORDERS: Dict[str, Callable[[_Session], Tuple[Any, ...]]] = {
    "state": _by_state,
    "name": _by_name,
    "up_for": _by_up_for,
    "remote_as": _by_remote_as,
}


def _summary(kept: List[_Session], protocols: List[str]) -> Dict[str, Any]:
    """Per protocol read, the sessions and how many are up, down and (BGP) shut down; the total LibreNMS counts as
    down, the devices, and the states."""
    by_protocol: Dict[str, Dict[str, int]] = {}
    for protocol in protocols:
        mine = [item for item in kept if item.row["protocol"] == protocol]
        if protocol == "bgp":
            by_protocol[protocol] = {
                "sessions": len(mine),
                "established": sum(item.row["established"] for item in mine),
                "not_established": sum(item.alarm for item in mine),
                "disabled": sum(item.row["enabled"] is False for item in mine),
            }
        else:
            full = sum(item.row["established"] for item in mine)
            by_protocol[protocol] = {"neighbours": len(mine), "full": full, "not_full": len(mine) - full}
    by_state: Dict[str, int] = {}
    for item in kept:
        by_state[str(item.row["state"])] = by_state.get(str(item.row["state"]), 0) + 1
    return {
        "by_protocol": by_protocol,
        "not_established": sum(item.alarm for item in kept),
        "devices": len({item.row["device_id"] for item in kept}),
        "by_state": dict(sorted(by_state.items(), key=lambda pair: (-pair[1], pair[0]))),
        "stale": sum(item.row["stale"] for item in kept),
    }


def _notes(ctx: ReportContext, kept: List[_Session]) -> None:
    two_way = sum(item.row["protocol"] != "bgp" and item.row["state"] == "twoWay" for item in kept)
    if two_way:
        ctx.notes.append(
            f"OSPF neighbours in twoWay: {two_way}; that is the steady state between two routers that are neither the "
            "DR nor the BDR of a broadcast network, and a fault only on a point-to-point link or with the DR or BDR"
        )
    stale = sum(item.row["stale"] for item in kept)
    if stale:
        ctx.notes.append(
            f"sessions on devices LibreNMS has not polled lately (down, unreachable or disabled): {stale}; their state "
            "is the last it read (stale: true)"
        )


VIEW = View(
    "routing",
    build,
    scope_keys=SCOPE_KEYS,
    filters={
        "protocol": PROTOCOLS,
        "not_established": "bool",
        "enabled": "bool",
        "state": STATES,
        "remote_as": "text",
        "text": "text",
    },
    sorts=("state", "name", "up_for", "remote_as"),
)
