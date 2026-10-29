"""View ``find``: what a person's words could mean in LibreNMS, ranked, each with why it matched.

A term is matched against every device (one ``devices`` listing; :mod:`.fuzzy`), and unless it is an address against
the locations, device groups and port groups; an interface name in it (``Gi1/0/48``) is searched among the ports
(``ports/search/ifName,ifDescr/...``), and the rest of its words then match the port's device. An IP address is
matched exactly, against each device's address and the addresses on its interfaces (``devices?type=ipv4|ipv6``); a
MAC address finds the devices with an ARP entry for it (``devices?type=mac``), which see it but need not own it.
Every candidate scoring :data:`~.context.MIN_SCORE` or more is counted (``count``, ``summary``); an answer shows at
most :data:`~.context.MAX_CANDIDATES` of them, best first, and ``offset`` reads on. ``ambiguous`` when the best two
score within :data:`~.context.AMBIGUITY_GAP` of each other. The view never picks one for the person.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List, Tuple

from ..client import is_digits
from ..listing import natural_key
from . import fuzzy
from .context import (
    AMBIGUITY_GAP,
    CANDIDATE_TEXT,
    MAX_CANDIDATES,
    MIN_SCORE,
    ReportContext,
    Request,
    View,
    group_candidate,
    hostname_order,
    port_candidate,
    port_group_candidate,
    rows_of,
)

KINDS = ("device", "port", "location", "group", "port_group")
PORT_COLUMNS = "port_id,device_id,ifName,ifDescr,ifAlias,ifAdminStatus,ifOperStatus"
_ADDRESS_SCORES = {"ipv4": 95, "ipv6": 95, "mac": 80}
_NO_ADDRESS = "no-such-address"  # a devices type=ipv4|ipv6|mac query no interface or ARP table can hold

Found = Tuple[fuzzy.Match, Tuple[Any, ...], Dict[str, Any]]


def build(ctx: ReportContext, req: Request) -> Dict[str, Any]:
    """The candidates for ``term`` of the kinds ``filter.kind`` names (all by default), best first."""
    scope = ctx.scope(req.scope, VIEW)
    term = fuzzy.Term.parse(req.term or "")
    kinds = req.filters.get("kind") or frozenset(KINDS)
    found: List[Found] = []
    if "device" in kinds:
        found += _devices(ctx, term)
    if term.ip is None and term.mac is None:
        if "location" in kinds:
            found += _locations(ctx, term)
        if "group" in kinds:
            found += _groups(ctx, term)
        if "port_group" in kinds:
            found += _port_groups(ctx, term)
    if term.iface is not None and "port" in kinds:
        found += _ports(ctx, term)
    found = [item for item in found if item[0].score >= MIN_SCORE]
    found.sort(key=lambda item: (-item[0].score, item[1]))
    rows = [row for _match, _key, row in found]
    ambiguous = len(rows) >= 2 and rows[0]["score"] - rows[1]["score"] < AMBIGUITY_GAP
    if ambiguous:
        ctx.notes.append(
            "the best candidates score alike: ask the user which one they mean before you act on one or scope a "
            "report to it"
        )
    elif not rows:
        ctx.notes.append(
            "nothing matched: try part of the hostname or sysName, the IP address, the site, or fewer words"
        )
    if len(rows) > MAX_CANDIDATES:
        ctx.notes.append(
            f"{len(rows)} candidates matched and an answer shows at most {MAX_CANDIDATES}, best first: the one the "
            "user means may be further on; give more of the name, the site or the IP to narrow them"
        )
    if term.mac is not None and "device" in kinds:
        ctx.notes.append(
            "a MAC address names no device in LibreNMS: these devices see it in their ARP tables; view locate finds "
            "the switch port it is learned on"
        )
    by_kind: Dict[str, int] = {}
    for row in rows:
        by_kind[row["kind"]] = by_kind.get(row["kind"], 0) + 1
    page = rows[req.offset : req.offset + req.limit]
    return ctx.envelope(
        "find",
        scope=scope,
        rows=page,
        count=len(rows),
        offset=req.offset,
        summary={"candidates": len(rows), "by_kind": by_kind},
        text_keys=CANDIDATE_TEXT,
        extra={"ambiguous": ambiguous},
    )


def _devices(ctx: ReportContext, term: fuzzy.Term) -> List[Found]:
    """The devices that match by name, attribute or address, each at its best score."""
    devices = ctx.devices()
    scored = {device_id: matched for matched, device_id in ctx.rank_devices(term)}
    for device_id, matched in _addresses(ctx, term).items():
        if device_id not in scored or scored[device_id].score < matched.score:
            scored[device_id] = matched
    return [
        (
            matched,
            (KINDS.index("device"), *hostname_order(devices[device_id])),
            ctx.device_candidate(device_id, matched),
        )
        for device_id, matched in scored.items()
    ]


def _addresses(ctx: ReportContext, term: fuzzy.Term) -> Dict[int, fuzzy.Match]:
    """The devices with *term*'s IP on an interface, or with an ARP entry for its MAC: one ``devices`` lookup. An
    answer naming every device the token sees is checked first (:func:`_filters`): every device can hold it (two
    routers sharing an anycast address, the gateway's MAC in each one's ARP table), or LibreNMS ignored the type."""
    if term.ip is not None:
        kind, query = ("ipv6" if ":" in term.ip else "ipv4"), term.ip
        why = f"an interface holds {fuzzy.shown(term.ip)}"
    elif term.mac is not None:
        kind, query = "mac", term.mac
        why = f"its ARP table holds {fuzzy.shown(term.mac)} (it sees the MAC, which need not be its own)"
    else:
        return {}
    rows = rows_of(ctx.optional(f"devices by {kind}", "devices", params={"type": kind, "query": query}))
    devices = ctx.devices()
    ids = {int(row["device_id"]) for row in rows if is_digits(row.get("device_id"))} & set(devices)
    if ids and ids == set(devices) and not _filters(ctx, kind):
        return {}
    return {device_id: fuzzy.Match(_ADDRESS_SCORES[kind], why, True) for device_id in ids}


def _filters(ctx: ReportContext, kind: str) -> bool:
    """Whether LibreNMS filters ``devices`` by type *kind*: asked for :data:`_NO_ADDRESS`, which no interface or ARP
    table holds, it names no device. An older release reads a type it does not know as no filter and names them all
    again; that lookup is then set aside rather than shown as a match for each. A check that cannot be read leaves
    the lookup standing, and says so."""
    check = ctx.optional(
        f"the check that LibreNMS filters devices by {kind}", "devices", params={"type": kind, "query": _NO_ADDRESS}
    )
    if check is None:
        ctx.notes.append(
            f"every device answered type={kind} and the check that LibreNMS filters by {kind} was not read: these "
            "may be every device rather than those holding the address"
        )
        return True
    if rows_of(check):
        ctx.notes.append(
            f"LibreNMS answered type={kind} with every device, and with devices for an address none holds, so it "
            f"does not filter by {kind} here"
        )
        return False
    return True


def _locations(ctx: ReportContext, term: fuzzy.Term) -> List[Found]:
    """The locations whose name matches, each with how many devices are there."""
    here = Counter(str(device.get("location_id")) for device in ctx.devices().values())
    out: List[Found] = []
    for row in ctx.listing("locations", "resources", "locations", what="locations"):
        matched = fuzzy.name_match(term, "location", row.get("location"))
        if matched is None:
            continue
        candidate = {"kind": "location", "location_id": row.get("id"), "location": row.get("location")}
        candidate.update(devices=here[str(row.get("id"))], score=matched.score, why=matched.why)
        key = (KINDS.index("location"), natural_key(row.get("location")), str(row.get("id")))
        out.append((matched, key, candidate))
    return out


def _groups(ctx: ReportContext, term: fuzzy.Term) -> List[Found]:
    """The device groups whose name (or description) matches."""
    out: List[Found] = []
    for group in ctx.listing("groups", "devicegroups", what="device groups"):
        matched = fuzzy.name_match(term, "name", group.get("name"), group.get("desc"))
        if matched is not None:
            key = (KINDS.index("group"), natural_key(group.get("name")), str(group.get("id")))
            out.append((matched, key, group_candidate(group, matched)))
    return out


def _port_groups(ctx: ReportContext, term: fuzzy.Term) -> List[Found]:
    """The port groups whose name (or description) matches."""
    out: List[Found] = []
    for group in ctx.listing("port_groups", "port_groups", what="port groups"):
        matched = fuzzy.name_match(term, "name", group.get("name"), group.get("desc"))
        if matched is None:
            continue
        key = (KINDS.index("port_group"), natural_key(group.get("name")), str(group.get("id")))
        out.append((matched, key, port_group_candidate(group, matched)))
    return out


def _ports(ctx: ReportContext, term: fuzzy.Term) -> List[Found]:
    """The ports whose ifName or ifDescr holds the interface name (LibreNMS's ``LIKE``), scored with the rest of the
    term against their device."""
    pieces = (term.iface or "").split("/")
    rows = ctx.optional("ports", "ports", "search", "ifName,ifDescr", *pieces, params={"columns": PORT_COLUMNS})
    devices = ctx.devices()
    out: List[Found] = []
    for port in rows_of(rows):
        device = devices.get(int(port["device_id"])) if is_digits(port.get("device_id")) else None
        matched = fuzzy.port_match(term, port, device)
        if matched is None:
            continue
        hostname = device.get("hostname") if device is not None else None
        key = (KINDS.index("port"), natural_key(hostname), natural_key(port.get("ifName")), str(port.get("port_id")))
        out.append((matched, key, port_candidate(port, device, matched)))
    return out


VIEW = View(
    "find",
    build,
    filters={"kind": KINDS},
    sorts=("score",),
    term=True,
    max_limit=MAX_CANDIDATES,
)
