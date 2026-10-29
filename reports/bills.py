"""View ``bills``: each bill LibreNMS keeps and its use against what it allows: a CDR bill's 95th percentile (bit/s)
against its committed rate, a quota bill's traffic (bytes) against its quota, in the current billing period or the
last one that ended.

Reads: ``bills`` once (with ``period=previous`` for the last period that ended: LibreNMS joins each bill to its
latest history row whose period ended within the last 40 days, so a bill without one is not listed), and the device
listing for the scope and the names of the bill's ports' devices. LibreNMS lists the bills the token's user may see,
each with its ports. A bill is in a scope when one of its ports is on a device in it.

What LibreNMS works out: the 95th percentile of the bill's ports taken together over the period, inbound, outbound,
and the one it bills (``dir_95th``: the higher of the two, or the aggregate); the bytes transferred; the average
rate; when it last worked them out (``bill_last_calc``, server-local). ``used_pct`` is the 95th of the commit (CDR) or
the traffic of the quota, rounded to two places as LibreNMS rounds it; ``over`` and ``overuse`` say by how much it
is past it; both are null for a bill without a commit or quota. The previous period is measured against the commit
or quota it had then (its history row), where LibreNMS's own ``percent`` for it uses the bill's commit as it is now.
The current period runs from the bill's day of the month as LibreNMS's ``Billing::getDates`` counts it on the day of
its last calculation (a period starting on the 31st begins on the 1st after a short month, as PHP's dates roll over).

Rates use decimal prefixes (1 kbit/s is 1,000 bit/s), as LibreNMS's billing does, and so do bytes (its default
``billing.base``, 1000). Names, customer ids, references, notes and port names are text from people and devices:
:data:`TEXT_KEYS` are marked untrusted.
"""

from __future__ import annotations

from datetime import date, timedelta
from typing import Any, Callable, Dict, List, Set, Tuple

from ..client import is_digits
from ..listing import natural_key
from . import units
from .context import One, ReportContext, Request, View, row_device, rows_of

SCOPE_KEYS = ("device", "devices", "group", "location", "os", "type")
PERIODS = One(("current", "previous"))
TYPES = ("cdr", "quota")
PORTS_SHOWN = 10  # ports a bill's row lists
_DIRECTIONS = {"in": "in", "out": "out", "agg": "aggregate"}
TEXT_KEYS = ("bill", "type", "customer", "reference", "note", "hostname", "display", "port")


def bill_period(bill_day: int, today: date) -> Tuple[date, date]:
    """The billing period holding *today* for a bill that starts on *bill_day* of the month, first and last day, as
    LibreNMS's ``Billing::getDates`` counts it: past that day of this month, from it to the day before it next month;
    otherwise from it last month to the day before it this month. A day the month does not have rolls over into the
    next, as PHP's dates do (the 31st of February is the 3rd of March)."""
    if today.day > bill_day:
        start = _php_date(today.year, today.month, bill_day)
        end = _php_date(start.year, start.month + 1, start.day)
    else:
        end = _php_date(today.year, today.month, bill_day)
        start = _php_date(end.year, end.month - 1, end.day)
    return start, end - timedelta(days=1)


def _php_date(year: int, month: int, day: int) -> date:
    """``date_create("Y-m-d")`` with PHP's roll-over: a month past 12 or under 1 moves the year, a day past the
    month's last moves into the next."""
    year, month = year + (month - 1) // 12, (month - 1) % 12 + 1
    return date(year, month, 1) + timedelta(days=day - 1)


def _day(value: Any) -> date | None:
    """The date of a server-local ``Y-m-d H:i:s`` (or ``Y-m-d``); None for none or ``0000-00-00``."""
    text = str(value or "")[:10]
    try:
        return date.fromisoformat(text)
    except ValueError:
        return None


def _whole(value: Any) -> int | None:
    found = units.number(value)
    return int(found) if found is not None else None


def build(ctx: ReportContext, req: Request) -> Dict[str, Any]:
    """The bills on the devices in scope that pass the filter, for the period asked for, in the order asked for."""
    period = next(iter(req.filters.get("period", {"current"})))
    scope = ctx.scope(req.scope, VIEW)
    devices = ctx.devices()
    raw = ctx.get("bills", params={"period": "previous"} if period == "previous" else None)
    bills = [_bill(ctx, devices, row, period) for row in rows_of(raw)]
    if scope.ids is not None:
        bills = [(row, ids) for row, ids in bills if ids & scope.ids]
    kept = [row for row, _ids in bills if _passes(row, req.filters)]
    kept.sort(key=_ORDERS[req.sort])
    unmeasured = sum(row["used_pct"] is None for row in kept)
    if unmeasured:
        ctx.notes.append(f"bills without a commit or quota: {unmeasured}; their used_pct and over are null")
    if period == "previous":
        ctx.notes.append(
            "LibreNMS lists a bill for the previous period only when a billing period of it ended within the last 40 "
            "days"
        )
    if not bills and scope.ids is None and period == "current":
        ctx.notes.append("LibreNMS has no bill this token's user may see")
    return ctx.envelope(
        "bills",
        scope=scope,
        rows=kept[req.offset : req.offset + req.limit],
        count=len(kept),
        offset=req.offset,
        summary=_summary(kept, period),
        text_keys=TEXT_KEYS,
    )


def _bill(
    ctx: ReportContext, devices: Dict[int, Dict[str, Any]], bill: Dict[str, Any], period: str
) -> Tuple[Dict[str, Any], Set[int]]:
    """A bill as a report row, and the ids of the devices its ports are on."""
    kind = str(bill.get("bill_type") or "").strip().lower() or None
    quota = kind == "quota"
    row: Dict[str, Any] = {"bill_id": _whole(bill.get("bill_id")), "bill": bill.get("bill_name"), "type": kind}
    row.update(
        customer=bill.get("bill_custid") or None,
        reference=bill.get("bill_ref") or None,
        note=bill.get("bill_notes") or None,
        period=period,
    )
    if period == "previous":
        start, end = _day(bill.get("bill_datefrom")), _day(bill.get("bill_dateto"))
        allowed, used = _whole(bill.get("bill_allowed")), _whole(bill.get("bill_used"))
    else:
        today, day = _day(bill.get("bill_last_calc")), _whole(bill.get("bill_day"))
        start, end = bill_period(day, today) if today is not None and day and 1 <= day <= 31 else (None, None)
        allowed, used = None, None
    if allowed is None:
        allowed = _whole(bill.get("bill_quota" if quota else "bill_cdr"))
    if used is None:
        used = _whole(bill.get("total_data" if quota else "rate_95th"))
    row.update(period_from=start.isoformat() if start else None, period_to=end.isoformat() if end else None)
    measured = allowed is not None and allowed > 0 and used is not None
    over = max(0, used - allowed) if measured else None
    if quota:
        row.update(quota_bytes=allowed, quota=units.volume(allowed), used_bytes=used, used=units.volume(used))
    else:
        rate_in, rate_out = _whole(bill.get("rate_95th_in")), _whole(bill.get("rate_95th_out"))
        row.update(commit_bps=allowed, commit=units.bits_per_second(allowed))
        row.update(rate_95th_bps=used, rate_95th=units.bits_per_second(used))
        row.update(rate_95th_in_bps=rate_in, rate_95th_in=units.bits_per_second(rate_in))
        row.update(rate_95th_out_bps=rate_out, rate_95th_out=units.bits_per_second(rate_out))
        row["direction"] = _DIRECTIONS.get(str(bill.get("dir_95th") or ""), bill.get("dir_95th") or None)
    row["used_pct"] = round(used * 100 / allowed, 2) if measured else None
    row["over"] = over > 0 if over is not None else None
    if quota:
        row.update(overuse_bytes=over, overuse=units.volume(over))
    else:
        row.update(overuse_bps=over, overuse=units.bits_per_second(over))
    average, transferred = _whole(bill.get("rate_average")), _whole(bill.get("total_data"))
    row.update(average_bps=average, average=units.bits_per_second(average))
    row.update(transferred_bytes=transferred, transferred=units.volume(transferred))
    row.update(ctx.when(bill.get("bill_last_calc"), "last_calculated"))
    ports = [port for port in bill.get("ports") or () if isinstance(port, dict)]
    row["ports"] = [
        {**row_device(devices, port), "port_id": port.get("port_id"), "port": port.get("ifName")}
        for port in ports[:PORTS_SHOWN]
    ]
    if len(ports) > PORTS_SHOWN:
        row["ports_total"] = len(ports)
    return row, {int(port["device_id"]) for port in ports if is_digits(port.get("device_id"))}


def _passes(row: Dict[str, Any], filters: Dict[str, Any]) -> bool:
    for key, wanted in filters.items():
        if key == "over" and row["over"] is not wanted:
            return False
        if key == "type" and row["type"] not in wanted:
            return False
        if key == "used_above_pct" and (row["used_pct"] is None or row["used_pct"] <= wanted):
            return False
        if key == "text" and wanted.casefold() not in _folded(row):
            return False
    return True


def _folded(row: Dict[str, Any]) -> str:
    """The bill's name, customer id, reference and notes, and its ports and their devices' names, folded."""
    texts = [row.get(key) for key in ("bill", "customer", "reference", "note")]
    for port in row["ports"]:
        texts += [port.get("hostname"), port.get("display"), port.get("port")]
    return " ".join(str(text) for text in texts if text).casefold()


def _name(row: Dict[str, Any]) -> Tuple[Any, ...]:
    return natural_key(row["bill"]), row["bill_id"] or 0


_ORDERS: Dict[str, Callable[[Dict[str, Any]], Tuple[Any, ...]]] = {
    "used_pct": lambda row: (row["used_pct"] is None, -(row["used_pct"] or 0), *_name(row)),
    "name": _name,
    "rate_95th": lambda row: (row.get("rate_95th_bps") is None, -(row.get("rate_95th_bps") or 0), *_name(row)),
}


def _summary(kept: List[Dict[str, Any]], period: str) -> Dict[str, Any]:
    """The bills, how many are over what they allow, per type, and the fullest."""
    by_type = {kind: sum(row["type"] == kind for row in kept) for kind in TYPES}
    other = sum(row["type"] not in TYPES for row in kept)
    if other:
        by_type["other"] = other
    measured = [row for row in kept if row["used_pct"] is not None]
    fullest = min(measured, key=_ORDERS["used_pct"], default=None)
    out: Dict[str, Any] = {"period": period, "bills": len(kept), "over": sum(row["over"] is True for row in kept)}
    out.update(by_type=by_type, without_commit=len(kept) - len(measured))
    out["fullest"] = (
        None if fullest is None else {key: fullest[key] for key in ("bill_id", "bill", "type", "used_pct", "over")}
    )
    return out


VIEW = View(
    "bills",
    build,
    scope_keys=SCOPE_KEYS,
    filters={"period": PERIODS, "over": "bool", "type": TYPES, "used_above_pct": "number", "text": "text"},
    sorts=("used_pct", "name", "rate_95th"),
)
