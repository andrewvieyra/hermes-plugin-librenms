"""View ``devices``: the state of each device in scope and the checks people ask about, from one ``devices`` listing.

Per device: its state as LibreNMS decides it (``disabled``, ``ignored``, ``down``, ``up``) and why it is down
(``status_reason``: icmp or snmp), since when (its open outage, ``devices/{id}/outages``, read for the down devices
on the page, at most :data:`OUTAGE_READS`), its uptime as of its last poll (``uptime_s``) and when it booted, how long
ago it was polled, what it is (os, hardware, version, type), where (location) and the naming checks: ``hostname`` and
``sysName`` that name different hosts (their first DNS labels differ, ignoring case), no location, no purpose
(LibreNMS's description field). The summary counts states and checks over the rows that pass the filter.

Device times are zone-safe: the device API writes ISO-8601 UTC, outages unix seconds, uptime seconds; ages are counted
to ``data_as_of``, LibreNMS's own clock.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Tuple

from . import fuzzy, units
from .context import STATES, ReportContext, Request, View, brief, device_state, hostname_order, rows_of, truthy

SCOPE_KEYS = ("device", "devices", "group", "location", "os", "type")
CHECKS = ("naming_mismatch", "no_location", "no_purpose")
OUTAGE_READS = 20  # down devices on one page whose outages are read
TEXT_KEYS = ("hostname", "display", "sysName", "location", "purpose", "hardware", "version", "type", "status_reason")
_STATE_ORDER = {"down": 0, "ignored": 1, "disabled": 2, "up": 3}


@dataclass
class _Device:
    """A device row and the times it was derived from, which filters and orders compare."""

    row: Dict[str, Any]
    polled: datetime | None
    booted: datetime | None
    uptime: int | None


def build(ctx: ReportContext, req: Request) -> Dict[str, Any]:
    """The devices in scope that pass the filter, in the order asked for, a page of them with their outages."""
    scope = ctx.scope(req.scope, VIEW)
    devices = ctx.devices()
    ids = scope.ids if scope.ids is not None else set(devices)
    every = [_derive(ctx, devices[device_id]) for device_id in devices if device_id in ids]
    kept = [item for item in every if _passes(item, req.filters, ctx.now)]
    kept.sort(key=_ORDERS[req.sort])
    page = kept[req.offset : req.offset + req.limit]
    _down_since(ctx, page)
    by_status = dict.fromkeys(STATES, 0)
    checks = dict.fromkeys(CHECKS, 0)
    for item in kept:
        by_status[item.row["status"]] += 1
        for check in item.row["checks"]:
            checks[check] += 1
    return ctx.envelope(
        "devices",
        scope=scope,
        rows=[item.row for item in page],
        count=len(kept),
        offset=req.offset,
        summary={"in_scope": len(every), "by_status": by_status, "checks": checks},
        text_keys=TEXT_KEYS,
    )


def _derive(ctx: ReportContext, device: Dict[str, Any]) -> _Device:
    """A ``devices`` row as a report row: state, identity, times as UTC and ages, and the checks it fails. It boots
    at its last poll less its uptime, known only while LibreNMS polls it and finds it up."""
    state = device_state(device)
    polled = units.utc_time(device.get("last_polled"))
    uptime = units.seconds(device.get("uptime"))
    booted = None
    if polled is not None and uptime and state != "disabled" and truthy(device.get("status")):
        booted = polled - timedelta(seconds=uptime)
    row: Dict[str, Any] = {**brief(device), "sysName": device.get("sysName"), "status": state}
    if not truthy(device.get("status")) and device.get("status_reason"):
        row["status_reason"] = device["status_reason"]
    for key in ("location", "purpose", "os", "hardware", "version", "type"):
        row[key] = device.get(key) if device.get(key) not in ("", None) else None
    polled_age = units.age(polled, ctx.now)
    row.update(
        uptime_s=uptime,
        uptime=units.duration(uptime),
        booted_at=units.iso(booted),
        last_polled=units.iso(polled),
        last_polled_age_s=polled_age,
        last_polled_age=units.duration(polled_age),
        checks=[check for check in CHECKS if _CHECKED[check](device)],
    )
    return _Device(row, polled, booted, uptime)


def _naming_mismatch(device: Dict[str, Any]) -> bool:
    """Whether hostname and sysName name different hosts: their first DNS labels differ, ignoring case. No sysName
    (not polled yet, or SNMP off) is no mismatch."""
    sys_name = fuzzy.label(device.get("sysName"))
    return bool(sys_name) and fuzzy.label(device.get("hostname")).casefold() != sys_name.casefold()


_CHECKED: Dict[str, Callable[[Dict[str, Any]], bool]] = {
    "naming_mismatch": _naming_mismatch,
    "no_location": lambda device: not str(device.get("location") or "").strip(),
    "no_purpose": lambda device: not str(device.get("purpose") or "").strip(),
}


def _passes(item: _Device, filters: Dict[str, Any], now: datetime) -> bool:
    row = item.row
    for key, wanted in filters.items():
        if key == "status" and row["status"] not in wanted:
            return False
        if key == "rebooted_within" and (item.booted is None or units.age(item.booted, now) > wanted):
            return False
        if key == "not_polled_for" and not _unpolled(item, wanted, now):
            return False
        if key in CHECKS and (key in row["checks"]) != wanted:
            return False
        if key in ("os", "type") and str(row[key] or "").casefold() != wanted.casefold():
            return False
    return True


def _unpolled(item: _Device, seconds: int, now: datetime) -> bool:
    """Whether a device LibreNMS polls has gone *seconds* or more without a poll, or was never polled. A disabled
    device is not polled by design."""
    if item.row["status"] == "disabled":
        return False
    return item.polled is None or (units.age(item.polled, now) or 0) >= seconds


def _by_status(item: _Device) -> Tuple[Any, ...]:
    return _STATE_ORDER[item.row["status"]], hostname_order(item.row)


def _by_uptime(item: _Device) -> Tuple[Any, ...]:
    return item.uptime is None, item.uptime or 0, hostname_order(item.row)


def _by_last_polled(item: _Device) -> Tuple[Any, ...]:
    return item.polled is not None, item.polled.timestamp() if item.polled else 0, hostname_order(item.row)


_ORDERS: Dict[str, Callable[[_Device], Tuple[Any, ...]]] = {
    "name": lambda item: hostname_order(item.row),
    "status": _by_status,
    "uptime": _by_uptime,
    "last_polled": _by_last_polled,
}


def _down_since(ctx: ReportContext, page: List[_Device]) -> None:
    """``down_since`` and how long for the down devices of *page*: the start of each one's open outage (its latest,
    while ``up_again`` is null), one ``devices/{id}/outages`` read each, at most :data:`OUTAGE_READS`. A device whose
    outages were not read is counted in ``partial_reason``; one with no open outage has ``down_since`` null."""
    down = [item for item in page if item.row["status"] == "down"]
    for number, item in enumerate(down):
        row = item.row
        row.update(down_since=None, down_for_s=None, down_for=None)
        if number >= OUTAGE_READS:
            continue
        outages = ctx.optional(f"outages of device {row['device_id']}", "devices", row["device_id"], "outages")
        if outages is None:
            continue
        open_ = [o for o in rows_of(outages) if o.get("up_again") in (None, 0, "")]
        start = max((units.utc_time(o.get("going_down")) for o in open_), default=None, key=_stamp)
        if start is not None:
            seconds = units.age(start, ctx.now)
            row.update(down_since=units.iso(start), down_for_s=seconds, down_for=units.duration(seconds))
    if len(down) > OUTAGE_READS:
        ctx.partial(
            f"down_since was read for the first {OUTAGE_READS} of the {len(down)} down devices on this page; ask for "
            f"at most {OUTAGE_READS} rows (limit) to have it for each"
        )


def _stamp(moment: datetime | None) -> float:
    return moment.timestamp() if moment is not None else float("-inf")


VIEW = View(
    "devices",
    build,
    scope_keys=SCOPE_KEYS,
    filters={
        "status": STATES,
        "rebooted_within": "duration",
        "not_polled_for": "duration",
        "naming_mismatch": "bool",
        "no_location": "bool",
        "no_purpose": "bool",
        "os": "text",
        "type": "text",
    },
    sorts=("name", "status", "uptime", "last_polled"),
)
