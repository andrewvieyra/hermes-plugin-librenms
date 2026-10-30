"""View ``events``: what LibreNMS logged over a window, newest first: its eventlog (what it saw change or changed: a
port going down, a device rebooting, an edit through the API), the syslog the devices send it, or the authlog (logins
to LibreNMS itself).

Reads: the log ``filter.log`` names (``eventlog`` by default) from the window's start, newest first, through
:meth:`.context.ReportContext.read_log` (:data:`.context.LOG_PAGE` entries a request and at most :data:`MAX_ENTRIES`
a report; each device's path for a scope of at most :data:`.ports.DEVICE_READS` devices, else every device's, kept
to the scope here). For the ports the page and the summary name, the port names of their devices
(:meth:`.context.ReportContext.ports_by_device`), and for ``filter.port`` (a port's name) those of the devices whose
ports logged a change; ``filter.port_id`` needs none. ``filter.by`` shapes the rows: ``event`` (each entry),
``device`` (counts per device) or ``port`` (the eventlog's changes per port).

Severity: an eventlog entry's is LibreNMS's (``unknown``, ``ok``, ``info``, ``notice``, ``warning``, ``error``), a
syslog message's the syslog severity (``emerg`` ... ``debug``), from ``level`` or else ``priority``, which a collector
writes as the name or its number. ``filter.min_severity`` reads both on one scale, least first: ``debug``, ``info``
(an eventlog ``ok`` too), ``notice``, ``warning``, ``error`` (syslog ``err``), ``critical`` (``crit``, ``alert``,
``emerg``); an eventlog entry of ``unknown`` severity passes none.

Ports: LibreNMS logs each change it polls on a port as an eventlog entry of type ``interface`` that refers to the
port, e.g. ``ifOperStatus: up -> down`` (severity notice). ``status_changes`` counts the ``ifOperStatus`` ones,
``went_down`` those from up to anything else, ``flaps`` the times a port came back up after going down within the
window. LibreNMS reads a port's state at each poll, about five minutes apart, so a shorter bounce may not be logged.

Times are the server's local ``Y-m-d H:i:s``: read in ``librenms_timezone`` they become ISO-8601 with an age; without
it they are shown as LibreNMS wrote them, with no age, and the window is read from a bound early enough to hold it in
any zone (:meth:`.context.ReportContext.since`), counted back from LibreNMS's clock (for the authlog, which needs no
device listing, the ``Date`` of a ``ping`` read). Messages, types, programs, user names and addresses are written
by the devices, by whoever can reach the syslog collector or by people: :data:`TEXT_KEYS` are marked untrusted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Tuple

from ..client import LibreNMSError, is_digits
from ..listing import natural_key
from .context import (
    LOGS,
    ArgumentError,
    CallBudget,
    Log,
    One,
    ReportContext,
    ReportError,
    Request,
    Scope,
    View,
    help_hint,
    hostname_order,
    log_order,
    names_port,
    port_label,
    row_device,
    rows_of,
)
from .ports import DEVICE_READS

SCOPE_KEYS = ("device", "devices", "group", "location", "os", "type")
LOG_NAMES = One(("eventlog", "syslog", "authlog"))
BY = One(("event", "device", "port"))
SEVERITIES = One(("debug", "info", "notice", "warning", "error", "critical"))  # min_severity's scale, least first
MAX_ENTRIES = 2000  # log entries one report reads
TOP = 5  # devices and ports a summary names
GROUPS_SHOWN = 10  # eventlog types, syslog programs, authlog results and users a summary counts by name
ADDRESSES_SHOWN = 5  # addresses a user logged in from, in the authlog summary
# LibreNMS's eventlog Severity, and a syslog severity's name by its number (RFC 5424), with the other names collectors
# write for some of them.
EVENTLOG_SEVERITIES = {0: "unknown", 1: "ok", 2: "info", 3: "notice", 4: "warning", 5: "error"}
SYSLOG_LEVELS = ("emerg", "alert", "crit", "err", "warning", "notice", "info", "debug")
_SYSLOG_ALIASES = {
    "emergency": "emerg", "panic": "emerg", "critical": "crit", "error": "err", "warn": "warning",
    "informational": "info",
}  # fmt: skip
# Each severity's place on min_severity's scale (SEVERITIES); an eventlog entry of unknown severity has none.
_RANK = {
    "eventlog": {"ok": 1, "info": 1, "notice": 2, "warning": 3, "error": 4},
    "syslog": {"debug": 0, "info": 1, "notice": 2, "warning": 3, "err": 4, "crit": 5, "alert": 5, "emerg": 5},
}
# The order summary.by_severity counts in, worst first.
_SEVERITY_ORDER = {
    "eventlog": ("error", "warning", "notice", "info", "ok", "unknown"),
    "syslog": (*SYSLOG_LEVELS, "unknown"),
}
PORT_CHANGE_RANK = 2  # LibreNMS logs a port's changes at notice
# The columns of each log an entry is kept with once its page is read (list_logs also joins hostname and sysName).
_COLUMNS = {
    "eventlog": ("event_id", "device_id", "hostname", "datetime", "message", "type", "reference", "username",
                 "severity"),
    "syslog": ("seq", "device_id", "hostname", "timestamp", "priority", "level", "facility", "program", "tag", "msg"),
    "authlog": ("id", "datetime", "user", "address", "result"),
}  # fmt: skip
# The filters that apply to some logs only, and the logs they apply to.
_FOR_LOGS = {
    "min_severity": ("eventlog", "syslog"),
    "type": ("eventlog",),
    "program": ("syslog",),
    "port": ("eventlog",),
    "port_id": ("eventlog",),
}
_GROUP_KEY = {"eventlog": "type", "syslog": "program", "authlog": "result"}  # what a summary counts entries by
LOGGED_IN = "Logged In"  # the authlog's result for a login (AuthLoginListener)
# The keys of each log's rows and summary that hold text from LibreNMS: from the devices, from whoever can send to
# the syslog collector, from people (an eventlog entry's user, a login's user name and address).
TEXT_KEYS = {
    "eventlog": ("hostname", "display", "type", "message", "reference", "username", "port", "last_message",
                 "top_type", "last_status"),
    "syslog": ("hostname", "display", "facility", "program", "tag", "message", "last_message", "top_program"),
    "authlog": ("user", "address", "addresses", "result"),
}  # fmt: skip
_STATUS_RE = re.compile(r"^ifOperStatus: (\S+) -> (\S+)$")


@dataclass
class _Entry:
    """A log entry as the view filters, counts and shows it."""

    id: int
    logged: Any  # server-local text, as LibreNMS wrote it
    order: Tuple[int, int]  # its place in time (log_order)
    device_id: int | None
    device: Dict[str, Any]  # as rows name it; none for the authlog
    fields: Dict[str, Any]  # what an event row shows besides its id, time and device
    severity: str | None
    rank: int | None  # the severity's place on min_severity's scale
    group: str | None  # an eventlog entry's type, a syslog message's program, an authlog entry's result
    text: str  # folded, for filter.text
    port_id: int | None = None  # an eventlog entry about a port
    change: Tuple[str, str] | None = None  # its ifOperStatus change: from, to


@dataclass
class _Port:
    """What the eventlog says of one port over the window."""

    device: Dict[str, Any]
    port_id: int
    entries: int = 0
    status_changes: int = 0
    went_down: int = 0
    flaps: int = 0
    down: bool = False  # its last change in the window left it not up
    last: Tuple[int, int] = (0, 0)  # its latest entry's place in time
    last_message: Any = None
    last_change: Any = None  # server-local text of its latest ifOperStatus change
    last_status: str | None = None  # the state it changed to then


@dataclass
class _Device:
    """What a device logged over the window."""

    device: Dict[str, Any]
    entries: int = 0
    severities: Dict[str, int] = field(default_factory=dict)
    groups: Dict[str, int] = field(default_factory=dict)
    last: Tuple[int, int] = (0, 0)
    last_logged: Any = None
    last_message: Any = None


def build(ctx: ReportContext, req: Request) -> Dict[str, Any]:
    """The entries of the log asked for, on the devices in scope over the window, that pass the filter: each one, or
    counted per device or per port."""
    log = LOGS[_one(req.filters, "log", "eventlog")]
    by = _one(req.filters, "by", "event")
    _check(log, by, req)
    if log.per_device:
        scope = ctx.scope(req.scope, VIEW)
        devices = ctx.devices()
    else:  # LibreNMS's own logins: no device's, and no device listing to read, so the window is placed by its clock
        scope, devices = Scope(None, {}), {}
        ctx.clock()
    # placed after the first reads, so it is counted back from LibreNMS's clock
    since = ctx.since(req.window or VIEW.window or "24h")
    raw, logged = ctx.read_log(
        log, scope, since.bound, max_entries=MAX_ENTRIES, device_reads=DEVICE_READS, keep=_keeper(log)
    )
    entries = [_entry(log, devices, row) for row in raw]
    if scope.ids is not None:
        entries = [entry for entry in entries if entry.device_id in scope.ids]
    entries = [entry for entry in entries if _passes(entry, req.filters)]
    if "port" in req.filters:
        entries = _on_port(ctx, entries, req.filters["port"], scope)
    ports = _ports(entries)
    if by == "port":
        rows = _port_rows(ctx, ports, req.sort)
    elif by == "device":
        rows = _device_rows(ctx, log, entries, req.sort)
    else:
        rows = _event_rows(ctx, entries, req.sort)
    page = rows[req.offset : req.offset + req.limit]
    summary: Dict[str, Any] = {"log": log.name, "by": by, "window": since.window, "from": since.bound}
    summary.update(exact=since.exact, **({} if logged is None else {"logged": logged}))
    summary.update(_summary(ctx, log, entries, ports))
    _name_ports(ctx, [*page, *summary.get("top_ports", ())])
    _notes(ctx, log, by, req, entries, scope)
    return ctx.envelope(
        "events",
        scope=scope,
        rows=page,
        count=len(rows),
        offset=req.offset,
        summary=summary,
        text_keys=TEXT_KEYS[log.name],
    )


def _one(filters: Dict[str, Any], key: str, default: str) -> str:
    return next(iter(filters.get(key, {default})))


def _check(log: Log, by: str, req: Request) -> None:
    """Refuse what does not apply to *log*: a filter of another log's, rows per port but for the eventlog (which logs
    each port's changes), and for the authlog (LibreNMS's own logins) a scope or rows per device."""
    for key, logs in _FOR_LOGS.items():
        if key in req.filters and log.name not in logs:
            raise ArgumentError(
                f"filter.{key} is for filter.log {' and '.join(logs)}, not {log.name}; {help_hint(VIEW)}"
            )
    if by == "port" and log.name != "eventlog":
        raise ArgumentError(f"filter.by port counts the eventlog's port changes; the {log.name} has none")
    if not log.per_device:
        if req.scope not in (None, {}):
            raise ArgumentError("the authlog holds logins to LibreNMS itself, no device's: call it without scope")
        if by == "device":
            raise ArgumentError("the authlog holds logins to LibreNMS itself, no device's: filter.by takes event there")


def _keeper(log: Log) -> Callable[[Dict[str, Any]], Dict[str, Any]]:
    """What is kept of an entry of *log* once its page is read: the columns the view shows, counts or filters by."""
    columns = _COLUMNS[log.name]

    def keep(row: Dict[str, Any]) -> Dict[str, Any]:
        return {key: row.get(key) for key in columns}

    return keep


def _folded(values: Iterable[Any]) -> str:
    return " ".join(str(value) for value in values if value not in (None, "")).casefold()


def syslog_severity(row: Dict[str, Any]) -> str | None:
    """A syslog message's severity name (``err``, ``warning``, ...) from its ``level``, else its ``priority``:
    syslog-ng writes both as the name, rsyslog as the number (0 emerg to 7 debug), some collectors another name for
    it (``error``, ``warn``); None when neither says."""
    for key in ("level", "priority"):
        text = str(row.get(key) if row.get(key) is not None else "").strip().lower()
        if text.isascii() and text.isdigit() and int(text) < len(SYSLOG_LEVELS):
            return SYSLOG_LEVELS[int(text)]
        text = _SYSLOG_ALIASES.get(text, text)
        if text in SYSLOG_LEVELS:
            return text
    return None


def _entry(log: Log, devices: Dict[int, Dict[str, Any]], row: Dict[str, Any]) -> _Entry:
    """A kept log row (:func:`_keeper`) as the view filters, counts and shows it."""
    order = log_order(log, row)
    logged = row.get(log.time_key)
    if log.name == "authlog":
        fields = {"user": row.get("user"), "address": row.get("address") or None, "result": row.get("result") or None}
        return _Entry(
            id=order[1], logged=logged, order=order, device_id=None, device={}, fields=fields, severity=None,
            rank=None, group=fields["result"], text=_folded(fields.values()),
        )  # fmt: skip
    device_id = int(row["device_id"]) if is_digits(row.get("device_id")) else None
    device = row_device(devices, row)
    if log.name == "syslog":
        severity = syslog_severity(row)
        fields = {"severity": severity, "facility": row.get("facility") or None, "program": row.get("program") or None}
        tag = row.get("tag")
        if tag and tag != row.get("program"):
            fields["tag"] = tag
        fields["message"] = row.get("msg")
        return _Entry(
            id=order[1], logged=logged, order=order, device_id=device_id, device=device, fields=fields,
            severity=severity, rank=_RANK["syslog"].get(severity or ""), group=fields["program"],
            text=_folded((fields["program"], tag, row.get("msg"))),
        )  # fmt: skip
    number = int(row["severity"]) if is_digits(row.get("severity")) else None
    severity = EVENTLOG_SEVERITIES.get(number, "unknown") if number is not None else "unknown"
    kind = row.get("type") or None
    fields = {"type": kind, "severity": severity, "message": row.get("message")}
    reference = row.get("reference")
    port_id = int(reference) if kind == "interface" and is_digits(reference) and int(reference) else None
    change = None
    if port_id is not None:
        fields.update(port_id=port_id, port=None)
        found = _STATUS_RE.match(str(row.get("message") or "").strip())
        change = (found.group(1), found.group(2)) if found else None
    elif reference not in (None, ""):
        fields["reference"] = reference
    if row.get("username"):
        fields["username"] = row["username"]
    return _Entry(
        id=order[1], logged=logged, order=order, device_id=device_id, device=device, fields=fields, severity=severity,
        rank=_RANK["eventlog"].get(severity), group=kind, text=_folded((kind, row.get("message"), row.get("username"))),
        port_id=port_id, change=change,
    )  # fmt: skip


def _passes(entry: _Entry, filters: Dict[str, Any]) -> bool:
    """Whether an entry passes the filters on the entries themselves (filter.port, a name, is applied after)."""
    for key, wanted in filters.items():
        if key == "min_severity" and (entry.rank is None or entry.rank < SEVERITIES.index(next(iter(wanted)))):
            return False
        if key == "type" and str(entry.fields.get("type") or "").casefold() != wanted.casefold():
            return False
        if key == "program" and wanted.casefold() not in _folded((entry.group, entry.fields.get("tag"))):
            return False
        if key == "text" and wanted.casefold() not in entry.text:
            return False
        if key == "port_id" and entry.port_id != wanted:
            return False
    return True


def _on_port(ctx: ReportContext, entries: List[_Entry], wanted: str, scope: Scope) -> List[_Entry]:
    """filter.port: the entries about the ports with that name (long or short: ``Gi1/0/5``, ``GigabitEthernet1/0/5``;
    a number too, as HP and Aruba switches name their ports ``5``) on the devices whose ports logged a change (their
    port names, at most 10 devices), and for a number also those about the port with that port_id. With one device
    in scope its port of that name comes first, as in view port: the port_id counts only when it has none, and a
    note points to filter.port_id when that port_id logged changes too."""
    devices = list(dict.fromkeys(entry.device_id for entry in entries if entry.port_id is not None))
    maps = ctx.ports_by_device(
        devices,
        "the port names of device {}, for filter.port",
        "the ports of {} more devices were not searched for filter.port",
        "give the port's port_id, or narrow the scope to its device",
    )
    ids = {int(port["port_id"]) for ports in maps.values() for port in ports
           if is_digits(port.get("port_id")) and names_port(wanted, port, by_id=False)}  # fmt: skip
    one_device = scope.ids is not None and len(scope.ids) == 1
    number = int(wanted) if is_digits(wanted) and not (ids and one_device) else None
    if number is not None:
        ids.add(number)
    kept = [entry for entry in entries if entry.port_id in ids]
    logged = {entry.port_id for entry in kept}
    shown = repr(wanted[:60])
    if not kept and number is None:
        ctx.notes.append(f"no port named {shown} logged a change in the window on the devices searched")
    elif not kept:
        ctx.notes.append(
            f"no port named {shown} on the devices searched, nor port_id {number}, logged a change in the window"
        )
    elif number in logged and logged - {number}:
        ctx.notes.append(
            f"filter.port {shown} kept the entries of port_id {number} and of the ports named {shown}: give "
            f"filter.port_id {number} for the port with that id alone, or name the device with scope.device for its "
            f"port {shown} alone"
        )
    passed_over = int(wanted) if is_digits(wanted) and number is None and int(wanted) not in ids else None
    if passed_over is not None and any(entry.port_id == passed_over for entry in entries):
        ctx.notes.append(
            f"filter.port {shown} kept the entries of the port named {shown} on the device in scope, not those of "
            f"port_id {passed_over}, which logged changes too: give filter.port_id {passed_over} for that port"
        )
    return kept


def _ports(entries: List[_Entry]) -> Dict[int, _Port]:
    """What the eventlog says of each port it logged a change on, its entries read oldest first."""
    out: Dict[int, _Port] = {}
    for entry in sorted((entry for entry in entries if entry.port_id is not None), key=lambda entry: entry.order):
        tally = out.setdefault(entry.port_id, _Port(entry.device, entry.port_id))
        tally.entries += 1
        tally.last, tally.last_message = entry.order, entry.fields.get("message")
        if entry.change is None:
            continue
        old, new = entry.change
        tally.status_changes += 1
        tally.went_down += old == "up" and new != "up"
        tally.flaps += new == "up" and tally.down
        tally.down = new != "up"
        tally.last_change, tally.last_status = entry.logged, new
    return out


def _event_rows(ctx: ReportContext, entries: List[_Entry], sort: str) -> List[Dict[str, Any]]:
    """A row per entry: newest first (``most`` too), ``oldest`` first, or (``name``) by device, newest first."""
    ordered = sorted(entries, key=lambda entry: entry.order, reverse=sort != "oldest")
    if sort == "name":
        ordered.sort(key=lambda entry: hostname_order(entry.device))  # stable: newest first per device
    return [
        {"entry_id": entry.id, **ctx.when(entry.logged, "time"), **entry.device, **entry.fields} for entry in ordered
    ]


def _device_rows(ctx: ReportContext, log: Log, entries: List[_Entry], sort: str) -> List[Dict[str, Any]]:
    """A row per device that logged in the window: its entries, by severity, the type or program it logged most, and
    its latest entry."""
    tallies: Dict[Any, _Device] = {}
    for entry in entries:
        tally = tallies.setdefault(entry.device_id, _Device(entry.device))
        tally.entries += 1
        severity = entry.severity or "unknown"
        tally.severities[severity] = tally.severities.get(severity, 0) + 1
        if entry.group:
            tally.groups[entry.group] = tally.groups.get(entry.group, 0) + 1
        if entry.order > tally.last:
            tally.last, tally.last_logged, tally.last_message = entry.order, entry.logged, entry.fields.get("message")
    pairs = []
    for tally in tallies.values():
        row: Dict[str, Any] = {**tally.device, "entries": tally.entries}
        row["by_severity"] = _severity_counts(log, tally.severities)
        top = min(tally.groups, key=lambda group: (-tally.groups[group], natural_key(group)), default=None)
        row[f"top_{_GROUP_KEY[log.name]}"] = top
        row.update(ctx.when(tally.last_logged, "last"), last_message=tally.last_message)
        pairs.append((tally, row))
    orders: Dict[str, Callable[[Tuple[_Device, Dict[str, Any]]], Tuple[Any, ...]]] = {
        "newest": lambda pair: (-pair[0].last[0], -pair[0].last[1], *hostname_order(pair[1])),
        "oldest": lambda pair: (pair[0].last, *hostname_order(pair[1])),
        "most": lambda pair: (-pair[0].entries, *hostname_order(pair[1])),
        "name": lambda pair: hostname_order(pair[1]),
    }
    pairs.sort(key=orders[sort])
    return [row for _tally, row in pairs]


def _port_rows(ctx: ReportContext, ports: Dict[int, _Port], sort: str) -> List[Dict[str, Any]]:
    """A row per port the eventlog logged a change on: its status changes, how often it went down and came back up,
    its latest status change and its latest entry. Sorted by ``name``, every row's port is named first."""
    pairs = []
    for tally in ports.values():
        row: Dict[str, Any] = {**tally.device, "port_id": tally.port_id, "port": None}
        row.update(status_changes=tally.status_changes, went_down=tally.went_down, flaps=tally.flaps)
        row.update(entries=tally.entries, last_status=tally.last_status, **ctx.when(tally.last_change, "last_change"))
        row["last_message"] = tally.last_message
        pairs.append((tally, row))
    if sort == "name":
        _name_ports(ctx, [row for _tally, row in pairs])
    orders: Dict[str, Callable[[Tuple[_Port, Dict[str, Any]]], Tuple[Any, ...]]] = {
        "newest": lambda pair: (-pair[0].last[0], -pair[0].last[1], pair[0].port_id),
        "oldest": lambda pair: (pair[0].last, pair[0].port_id),
        "most": lambda pair: (-pair[0].status_changes, -pair[0].flaps, -pair[0].entries, *_port_name(pair[1])),
        "name": lambda pair: _port_name(pair[1]),
    }
    pairs.sort(key=orders[sort])
    return [row for _tally, row in pairs]


def _port_name(row: Dict[str, Any]) -> Tuple[Any, ...]:
    return (*hostname_order(row), natural_key(row.get("port")), row["port_id"])


def _name_ports(ctx: ReportContext, items: List[Dict[str, Any]]) -> None:
    """Name the ports *items* (rows, and summary entries) refer to and do not name yet, from their devices' port
    names (:meth:`ReportContext.ports_by_device`: at most 10 devices); a read that fails or is past the budget leaves
    them unnamed and the answer partial."""
    unnamed = [item for item in items if item.get("port_id") is not None and item.get("port") is None]
    if not unnamed:
        return
    ports = ctx.ports_by_device(
        [item["device_id"] for item in unnamed if item.get("device_id") is not None],
        "the names of device {}'s ports",
        "the ports of {} more devices were not named",
        "view port names one by its port_id",
    )
    names = {str(port.get("port_id")): port_label(port) for rows in ports.values() for port in rows}
    for item in unnamed:
        item["port"] = names.get(str(item["port_id"]))


def _severity_counts(log: Log, counts: Dict[str, int]) -> Dict[str, int]:
    """*counts* by severity, worst first, those of none left out."""
    order = _SEVERITY_ORDER.get(log.name, ())
    return {severity: counts[severity] for severity in order if counts.get(severity)}


def _counted(values: Iterable[Any], key: str) -> List[Dict[str, Any]]:
    """The values most often seen, as ``{key: value, "entries": n}``, most first, at most :data:`GROUPS_SHOWN`."""
    counts: Dict[Any, int] = {}
    for value in values:
        if value not in (None, ""):
            counts[value] = counts.get(value, 0) + 1
    ranked = sorted(counts.items(), key=lambda pair: (-pair[1], natural_key(str(pair[0]))))
    return [{key: value, "entries": number} for value, number in ranked[:GROUPS_SHOWN]]


def _summary(ctx: ReportContext, log: Log, entries: List[_Entry], ports: Dict[int, _Port]) -> Dict[str, Any]:
    """Totals over the entries that passed the filter: per device and severity, the types, programs or results most
    logged; for the eventlog the ports that changed, went down and flapped, and those that changed most; for the
    authlog who logged in."""
    out: Dict[str, Any] = {"entries": len(entries)}
    if log.per_device:
        per_device: Dict[Any, List[Any]] = {}
        severities: Dict[str, int] = {}
        for entry in entries:
            per_device.setdefault(entry.device_id, [entry.device, 0])[1] += 1
            severities[entry.severity or "unknown"] = severities.get(entry.severity or "unknown", 0) + 1
        ranked = sorted(per_device.values(), key=lambda pair: (-pair[1], hostname_order(pair[0])))
        out.update(devices=len(per_device), by_severity=_severity_counts(log, severities))
        out["top_devices"] = [{**device, "entries": number} for device, number in ranked[:TOP]]
    key = _GROUP_KEY[log.name]
    out[f"by_{key}"] = _counted((entry.group for entry in entries), key)
    if log.name == "eventlog":
        changed = [tally for tally in ports.values() if tally.status_changes]
        out.update(ports_changed=len(changed), ports_went_down=sum(tally.went_down > 0 for tally in changed))
        out["ports_flapped"] = sum(tally.flaps > 0 for tally in changed)
        changed.sort(
            key=lambda tally: (-tally.status_changes, -tally.flaps, *hostname_order(tally.device), tally.port_id)
        )
        out["top_ports"] = [
            {**tally.device, "port_id": tally.port_id, "port": None, "status_changes": tally.status_changes,
             "went_down": tally.went_down, "flaps": tally.flaps}
            for tally in changed[:TOP]
        ]  # fmt: skip
    if log.name == "authlog":
        out.update(_users(ctx, entries))
    return out


def _users(ctx: ReportContext, entries: List[_Entry]) -> Dict[str, Any]:
    """Who logged in to LibreNMS in the window: per user name, the logins, every entry, the addresses (at most
    :data:`ADDRESSES_SHOWN`) and the latest login; most logins first, at most :data:`GROUPS_SHOWN`."""
    users: Dict[Any, Dict[str, Any]] = {}
    for entry in sorted(entries, key=lambda entry: entry.order):
        name = entry.fields.get("user")
        user = users.setdefault(name, {"user": name, "logins": 0, "entries": 0, "addresses": [], "last": None})
        user["entries"] += 1
        address = entry.fields.get("address")
        if address and address not in user["addresses"]:
            user["addresses"].append(address)
        if entry.group == LOGGED_IN:
            user["logins"] += 1
            user["last"] = entry.logged
    ranked = sorted(users.values(), key=lambda user: (-user["logins"], -user["entries"], natural_key(user["user"])))
    out = []
    for user in ranked[:GROUPS_SHOWN]:
        last = user.pop("last")
        user["addresses"] = user["addresses"][:ADDRESSES_SHOWN]
        out.append({**user, **ctx.when(last, "last_login")})
    return {"users_logged_in": sum(user["logins"] > 0 for user in users.values()), "users": out}


def _notes(ctx: ReportContext, log: Log, by: str, req: Request, entries: List[_Entry], scope: Scope) -> None:
    if log.name == "authlog":
        ctx.notes.append(
            "the authlog records logins to and logouts from LibreNMS's web interface (result Logged In, Logged "
            "Out); requests with an API token are not in it"
        )
    wanted = req.filters.get("min_severity")
    if log.name == "eventlog" and wanted and SEVERITIES.index(next(iter(wanted))) > PORT_CHANGE_RANK:
        ctx.notes.append(
            "LibreNMS logs a port's changes (ifOperStatus: up -> down) at severity notice: filter.min_severity "
            f"{next(iter(wanted))} leaves them out"
        )
    port_id = req.filters.get("port_id")
    if port_id is not None and not entries:
        ctx.notes.append(_no_port_entries(ctx, port_id, scope))
    on_port = by == "port" or "port" in req.filters or port_id is not None
    if on_port or str(req.filters.get("type")).casefold() == "interface":
        ctx.notes.append(
            "LibreNMS reads a port's state at each poll, about five minutes apart: a shorter bounce may not be in the "
            "eventlog; views ports and port give its state now"
        )
    if log.name == "syslog" and not entries:
        ctx.notes.append(
            "LibreNMS holds syslog only from devices set to send it to its collector, and only what its syslog "
            "filters keep"
        )


def _no_port_entries(ctx: ReportContext, port_id: int, scope: Scope) -> str:
    """What a ``filter.port_id`` that kept no entry says: that nothing about the port was logged in the window, or,
    when the scope names devices and the port is on none of them (one ``ports/{id}`` read, which no answer depends
    on), whose port it is, so the model widens the scope instead of telling the user nothing happened."""
    nothing = f"no entry about port_id {port_id} passed the filter in the window"
    if scope.ids is None:
        return f"{nothing}: no change of it was logged then"
    try:
        port = next(iter(rows_of(ctx.get("ports", port_id))), None)
    except (LibreNMSError, CallBudget, ReportError):
        return f"{nothing} on the devices in scope: if the port is on another device, put that device in scope"
    if port is None:
        return f"{nothing}: LibreNMS holds no port with that id"
    device_id = int(port["device_id"]) if is_digits(port.get("device_id")) else None
    if device_id is not None and device_id not in scope.ids:
        return f"{nothing} on the devices in scope: the port is on device {device_id}, which is not in scope"
    return f"{nothing}: no change of it was logged then"


VIEW = View(
    "events",
    build,
    scope_keys=SCOPE_KEYS,
    filters={
        "log": LOG_NAMES,
        "by": BY,
        "min_severity": SEVERITIES,
        "type": "text",
        "program": "text",
        "port": "text",
        "port_id": "id",
        "text": "text",
    },
    sorts=("newest", "oldest", "most", "name"),
    window="24h",
)
