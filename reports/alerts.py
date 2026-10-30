"""Views ``alerts`` and ``alert_history``: what is alerting now, and what alerted over a window.

``alerts`` lists LibreNMS's open faults (one per rule, device and alerted object: the port, sensor, processor, ...
the rule matched) from one ``faults`` read in every open state, and the recovered ones only when ``filter.state``
asks for them. A row names the device, the rule and its severity, the state (``active``, ``acknowledged``,
``worse``, ``better``, ``changed``, ``recovered``) and ``acked``, the acknowledgement note, when the fault was first
seen and what alerted: ``entity_type`` (``port`` for LibreNMS's ``interface``, ``sensor``, ...), its id
(``port_id``, ``sensor_id``, else ``entity_id``) and ``entity``, its label, taken from the rows the rule matched
through the label allow-list of :func:`redact.alert_entities` (a port as ``ifName (ifAlias)``). A port whose fault
holds no label is named from its device's port names (:meth:`.context.ReportContext.ports_by_device`). Faults
come with LibreNMS's ``details`` (every column of every table the rule joins, and the alert's contacts): no row and
no summary carries any of it but those labels. An answer too large to read is read again one severity at a time.

``alert_history`` reads the alert log over ``window`` (``logs/alertlog``, newest first, :data:`.context.LOG_PAGE`
entries a request and at most :data:`MAX_ENTRIES` a report; the device path for a scope of at most
:data:`.ports.DEVICE_READS` devices; :meth:`.context.ReportContext.read_log`) and ``rules`` for the rules' names and
settings. ``filter.by`` shapes the rows: ``rule`` (the default: per rule; for the whole fleet every rule, also those
that logged nothing, so disabled rules and rules that notify no one are listed), ``device``, or ``event`` (each
entry, newest first). Counts: ``fired`` (entries that raised an alert, state 1), ``cleared`` (it recovered),
``flaps`` (an object that alerted again after it had cleared, within the window), ``last_fired`` and its age.

Fault and alert-log times are the server's local ``Y-m-d H:i:s``: read in ``librenms_timezone`` they become ISO-8601
with an age; without it they are shown as LibreNMS wrote them, with no age, and a window is read from a bound early
enough to hold it in any zone (:meth:`.context.ReportContext.since`).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Set, Tuple

from ..client import LibreNMSError, is_digits, json_object
from ..listing import natural_key
from ..redact import alert_entities
from . import units
from .context import (
    FAULT_STATES,
    LOGS,
    OPEN_FAULT_STATES,
    One,
    ReportContext,
    Request,
    Scope,
    View,
    hostname_order,
    port_label,
    row_device,
    rows_of,
    truthy,
)
from .ports import DEVICE_READS

SCOPE_KEYS = ("device", "devices", "group", "location", "os", "type")
SEVERITIES = ("critical", "warning", "ok")
# A fault's states in the order filter.state lists them: the open ones, then recovered (open until its recovery is
# sent, then closed), which is read only when asked for.
STATES = ("active", "acknowledged", "worse", "better", "changed", "recovered")
UNHANDLED = frozenset({"active", "worse", "better", "changed"})  # open and not acknowledged
# An alert-log entry's state (LibreNMS's AlertLogState): 1 is the alert raised for an object, 0 (and 6, newer
# releases) its recovery, 2 an acknowledgement, 3 to 5 a rule's alert on a device growing, shrinking or changing.
LOG_STATES = {0: "recovered", 1: "alerted", 2: "acknowledged", 3: "worse", 4: "better", 5: "changed", 6: "recovered"}
HISTORY_STATES = ("alerted", "recovered", "acknowledged", "worse", "better", "changed")
BY = One(("rule", "device", "event"))
PORT_ENTITIES = frozenset({"interface", "port"})  # LibreNMS's morph name for a Port is "interface"
TOP = 5  # rules and devices a history summary names
RULES_SHOWN = 10  # rules the alerts summary counts by name
MAX_ENTRIES = 2000  # alert-log entries one report reads
ALERT_TEXT = ("hostname", "display", "rule", "entity", "entities", "note", "procedure")
HISTORY_TEXT = ("hostname", "display", "rule", "entity", "top_rule")
_SEVERITY_ORDER = {severity: number for number, severity in enumerate(SEVERITIES)}
_STATE_ORDER = {"active": 0, "worse": 0, "better": 0, "changed": 0, "acknowledged": 1, "recovered": 2}
# What names an alerted object other than a port, from the label keys a rule's rows may hold: the name, and the key
# whose value is added in parentheses.
_LABELS = (
    ("sensor_descr", "sensor_class"),
    ("processor_descr", None),
    ("mempool_descr", None),
    ("storage_descr", None),
    ("bgpPeerIdentifier", "bgpPeerDescr"),
    ("service_type", "service_desc"),
)


# -- shared ----------------------------------------------------------------------------------------------------------
def entity_label(labels: Dict[str, Any]) -> str | None:
    """What alerted as people name it, from the label keys of a row the rule matched: a port as ``ifName
    (ifAlias)``, a sensor by its description and class, a processor, memory pool or storage by its description, a
    BGP peer by its address and description, a service by its type and description."""
    if labels.get("ifName") or labels.get("ifDescr"):
        return port_label(labels)
    for key, extra in _LABELS:
        if labels.get(key):
            name = str(labels[key])
            return f"{name} ({labels[extra]})" if extra and labels.get(extra) else name
    return None


def _labels(details: Any) -> Tuple[List[Dict[str, Any]], List[str], int]:
    """The label sets of what alerted (:func:`redact.alert_entities`: nothing else of *details* is read), their
    labels, and how many distinct sets there were."""
    labels, total = alert_entities(details)
    return labels, [name for name in (entity_label(item) for item in labels) if name], total


def _rule_wanted(wanted: str, rule_id: Any, name: Any) -> bool:
    """filter.rule: a rule's id, or part of its name in any case."""
    if is_digits(wanted):
        return str(rule_id) == wanted
    return wanted.casefold() in str(name or "").casefold()


def _muted(extra: Any) -> bool:
    """Whether the alert engine sends nothing for a rule muted in the LibreNMS UI: RunAlerts tests ``!
    empty($rextra['mute'])``, where PHP takes ``"0"`` as empty (as resources.alert_rule reads it). *extra* is the
    rule's as LibreNMS returns it: an object, or the JSON text of one (:func:`client.json_object`)."""
    value = (json_object(extra) or {}).get("mute")
    return bool(value) and value != "0"


def _id(value: Any) -> int:
    return int(value) if is_digits(value) else 0


# -- view alerts -----------------------------------------------------------------------------------------------------
@dataclass
class _Alert:
    """A fault's report row and what filters and orders compare."""

    row: Dict[str, Any]
    state: str
    severity: str
    seen: int  # first seen, as an order key (units.server_order)
    names: List[str]  # what alerted, every label
    port_id: int | None = None  # a port fault that holds no label, to name from its device's ports

    @property
    def text(self) -> str:
        """Device, rule, what alerted and the note, folded, for filter.text."""
        row = self.row
        return " ".join(str(row.get(key) or "") for key in ("hostname", "display", "rule", "entity", "note")).casefold()


def build_alerts(ctx: ReportContext, req: Request) -> Dict[str, Any]:
    """The faults on the devices in scope that pass the filter, in the order asked for, a page of them."""
    scope = ctx.scope(req.scope, ALERTS)
    devices = ctx.devices()
    alerts = []
    for fault in _read_faults(ctx, req.filters):
        if scope.ids is not None and _id(fault.get("device_id")) not in scope.ids:
            continue
        alerts.append(_alert(ctx, devices, fault))
    named_first = "text" in req.filters or req.sort == "name"  # a port's name is matched or ordered by
    if named_first:
        _name_ports(ctx, alerts)
    kept = [item for item in alerts if _alert_passes(item, req.filters)]
    kept.sort(key=_ALERT_ORDERS[req.sort])
    page = kept[req.offset : req.offset + req.limit]
    if not named_first:
        _name_ports(ctx, page)
    return ctx.envelope(
        "alerts",
        scope=scope,
        rows=[item.row for item in page],
        count=len(kept),
        offset=req.offset,
        summary=_alerts_summary(kept),
        text_keys=ALERT_TEXT,
    )


def _read_faults(ctx: ReportContext, filters: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The faults in the states filter.state names (every open one by default), narrowed by LibreNMS where it can: one
    severity, a rule's id. An answer too large to read is read again one severity at a time; a severity still too
    large is left out, and the answer is partial."""
    states = filters.get("state")
    numbers = sorted(number for number, label in FAULT_STATES.items() if label in states) if states else None
    params = {"state": ",".join(str(number) for number in numbers) if numbers else OPEN_FAULT_STATES}
    severities = [severity for severity in SEVERITIES if severity in filters.get("severity", SEVERITIES)]
    if len(severities) == 1:
        params["severity"] = severities[0]
    if is_digits(filters.get("rule")):
        params["alert_rule"] = filters["rule"]
    if "severity" not in params:
        try:
            return rows_of(ctx.get("faults", params=params))
        except LibreNMSError as exc:
            if exc.kind != "too_large":
                raise
        ctx.notes.append(
            "LibreNMS's answer was too large to read at once, so the alerts were read one severity at a time"
        )
    rows: List[Dict[str, Any]] = []
    for severity in severities:
        try:
            found = ctx.optional(
                f"the {severity} alerts", "faults", params={**params, "severity": severity}, raising=("too_large",)
            )
        except LibreNMSError:
            ctx.partial(
                f"the {severity} alerts were not read: LibreNMS's answer is too large to read (each alert carries "
                "every row its rule matched); narrow with filter.rule (a rule's id)"
            )
            continue
        rows += rows_of(found)
    return rows


def _alert(ctx: ReportContext, devices: Dict[int, Dict[str, Any]], fault: Dict[str, Any]) -> _Alert:
    """A fault as a report row: who, which rule, its state, since when, what alerted. Of ``details`` only the labels
    of what alerted are read (:func:`_labels`)."""
    number = int(fault["state"]) if is_digits(fault.get("state")) else None
    state = FAULT_STATES.get(number, str(fault.get("state")))
    severity = str(fault.get("severity") or "")
    row: Dict[str, Any] = {"alert_id": fault.get("id"), **row_device(devices, fault)}
    row.update(rule_id=fault.get("rule_id"), rule=fault.get("name"), severity=severity or None, state=state)
    row["acked"] = state == "acknowledged"
    kind = fault.get("entity_type") or None
    entity_id = int(fault["entity_id"]) if is_digits(fault.get("entity_id")) else None
    row["entity_type"] = "port" if kind in PORT_ENTITIES else kind
    row[{"port": "port_id", "sensor": "sensor_id"}.get(row["entity_type"], "entity_id")] = entity_id
    labels, names, total = _labels(fault.get("details"))
    row["entity"] = names[0] if names else None
    if labels and units.number(labels[0].get("sensor_current")) is not None:
        row["value"] = units.number(labels[0]["sensor_current"])  # the sensor's reading when the rule last matched
    if total > 1:
        row.update(entities=names, entities_total=total)
    seen = fault.get("first_seen") or fault.get("timestamp")  # older faults have no first_seen
    row.update(ctx.when(seen, "first_seen"))
    row.update(note=fault.get("note") or None, procedure=fault.get("proc") or None)
    unnamed = row["entity_type"] == "port" and entity_id is not None and not names
    return _Alert(row, state, severity, units.server_order(seen), names, port_id=entity_id if unnamed else None)


def _name_ports(ctx: ReportContext, alerts: List[_Alert]) -> None:
    """Name the ports of the faults among *alerts* on a port whose details hold no label, from their devices' port
    names (:meth:`ReportContext.ports_by_device`: at most 10 devices); a read that fails or is past the budget leaves
    them unnamed and the answer partial."""
    by_device: Dict[Any, List[_Alert]] = {}
    for item in alerts:
        if item.port_id is not None and item.row["device_id"] is not None:
            by_device.setdefault(item.row["device_id"], []).append(item)
    ports = ctx.ports_by_device(
        by_device,
        "the names of device {}'s alerting ports",
        "the ports of {} more devices' alerts were not named",
        "view port names one by its port_id",
    )
    for device_id, items in by_device.items():
        names = {str(port.get("port_id")): port_label(port) for port in ports.get(device_id, ())}
        for item in items:
            item.row["entity"] = names.get(str(item.port_id))


def _alert_passes(item: _Alert, filters: Dict[str, Any]) -> bool:
    row = item.row
    for key, wanted in filters.items():
        if key == "state" and item.state not in wanted:
            return False
        if key == "severity" and item.severity not in wanted:
            return False
        if key == "acked" and row["acked"] != wanted:
            return False
        if key == "rule" and not _rule_wanted(wanted, row["rule_id"], row["rule"]):
            return False
        if key == "entity_type" and not _of_kind(row["entity_type"], wanted):
            return False
        if key == "text" and wanted.casefold() not in " ".join([item.text, *item.names]).casefold():
            return False
    return True


def _of_kind(kind: str | None, wanted: str) -> bool:
    """filter.entity_type: ``port`` (``interface``, LibreNMS's word, too), ``sensor``, ..., any case; ``device``
    for a fault about no single object (a device-wide rule such as a device down)."""
    wanted = wanted.casefold()
    if kind is None:
        return wanted == "device"
    return kind.casefold() == wanted or (wanted in PORT_ENTITIES and kind == "port")


def _alerts_summary(kept: List[_Alert]) -> Dict[str, Any]:
    """Counts by state (recovered only when there are any) and severity, the alerts not acknowledged, the devices
    and rules, and the rules with the most alerts."""
    by_state = {state: 0 for state in STATES if state != "recovered"}
    by_severity = dict.fromkeys(SEVERITIES, 0)
    rules: Dict[Any, Dict[str, Any]] = {}
    for item in kept:
        by_state[item.state] = by_state.get(item.state, 0) + 1
        if item.severity in by_severity:
            by_severity[item.severity] += 1
        row = item.row
        counted = rules.setdefault(
            row["rule_id"], {"rule_id": row["rule_id"], "rule": row["rule"], "severity": row["severity"], "alerts": 0}
        )
        counted["alerts"] += 1
    ranked = sorted(rules.values(), key=lambda rule: (-rule["alerts"], natural_key(rule["rule"]), _id(rule["rule_id"])))
    return {
        "by_state": by_state,
        "by_severity": by_severity,
        "unacknowledged": sum(item.state in UNHANDLED for item in kept),
        "devices": len({item.row["device_id"] for item in kept}),
        "rules": len(rules),
        "by_rule": ranked[:RULES_SHOWN],
    }


def _by_severity(item: _Alert) -> Tuple[Any, ...]:
    """Critical first; open and not acknowledged before acknowledged, recovered last; newest first."""
    return _SEVERITY_ORDER.get(item.severity, len(SEVERITIES)), _STATE_ORDER.get(item.state, 3), *_newest(item)


def _newest(item: _Alert) -> Tuple[Any, ...]:
    return -item.seen, -_id(item.row["alert_id"])


def _oldest(item: _Alert) -> Tuple[Any, ...]:
    return item.seen == 0, item.seen, _id(item.row["alert_id"])  # a fault with no time last


def _by_name(item: _Alert) -> Tuple[Any, ...]:
    row = item.row
    return (*hostname_order(row), natural_key(row["rule"]), natural_key(row["entity"]), _id(row["alert_id"]))


_ALERT_ORDERS: Dict[str, Callable[[_Alert], Tuple[Any, ...]]] = {
    "severity": _by_severity,
    "newest": _newest,
    "oldest": _oldest,
    "name": _by_name,
}


ALERTS = View(
    "alerts",
    build_alerts,
    scope_keys=SCOPE_KEYS,
    filters={
        "state": STATES,
        "severity": SEVERITIES,
        "acked": "bool",
        "rule": "text",
        "entity_type": "text",
        "text": "text",
    },
    sorts=("severity", "newest", "oldest", "name"),
)


# -- view alert_history ----------------------------------------------------------------------------------------------
@dataclass
class _Entry:
    """An alert-log entry, as the history counts it and an event row shows it."""

    id: int
    device_id: int | None
    rule_id: int | None
    fault_id: Any
    state: str
    logged: Any  # server-local text, as LibreNMS wrote it
    device: Dict[str, Any]
    entity: str | None


@dataclass
class _Tally:
    """What a rule, a device or the whole history logged in the window."""

    entries: int = 0
    fired: int = 0
    cleared: int = 0
    flaps: int = 0
    last_fired: Any = None  # server-local text
    devices: Set[Any] = field(default_factory=set)
    rules: Dict[Any, int] = field(default_factory=dict)  # alerts raised per rule


def build_history(ctx: ReportContext, req: Request) -> Dict[str, Any]:
    """The alert log of the devices in scope over the window, counted per rule, per device, or as events."""
    by = next(iter(req.filters.get("by", {"rule"})))
    scope = ctx.scope(req.scope, HISTORY)
    rules = _rules(ctx)
    # placed after the first reads, so it is counted back from LibreNMS's clock
    since = ctx.since(req.window or HISTORY.window or "24h")
    raw, logged = _read_log(ctx, scope, since.bound)
    devices = ctx.devices()
    entries = [_entry(devices, row) for row in raw]
    if scope.ids is not None:
        entries = [entry for entry in entries if entry.device_id in scope.ids]
    entries = [entry for entry in entries if _rule_passes(entry.rule_id, _rule_of(rules, entry.rule_id), req.filters)]
    # before filter.state and filter.entity, which would drop the recoveries a flap is found by
    flaps = _flaps(entries)
    entries = [entry for entry in entries if _entry_passes(entry, req.filters)]
    if by == "event":
        rows = _event_rows(ctx, entries, rules, req)
    elif by == "device":
        rows = _device_rows(ctx, entries, flaps, rules, req)
    else:
        rows = _rule_rows(ctx, entries, flaps, rules, scope, req)
    summary: Dict[str, Any] = {"by": by, "window": since.window, "from": since.bound, "exact": since.exact}
    summary.update(_history_summary(entries, flaps, rules, logged))
    if scope.ids is None and rules is not None:
        summary["rules_disabled"] = sum(truthy(rule.get("disabled")) for rule in rules.values())
        summary["rules_without_notifications"] = sum(not _notifies(rule) for rule in rules.values())
    return ctx.envelope(
        "alert_history",
        scope=scope,
        rows=rows[req.offset : req.offset + req.limit],
        count=len(rows),
        offset=req.offset,
        summary=summary,
        text_keys=HISTORY_TEXT,
    )


def _rules(ctx: ReportContext) -> Dict[int, Dict[str, Any]] | None:
    """Every alert rule by id (one ``rules`` read), or None when that read failed, which leaves the rules unnamed and
    the answer partial."""
    rows = ctx.optional("the alert rules (names, severities and settings)", "rules")
    if rows is None:
        return None
    return {int(rule["id"]): rule for rule in rows_of(rows) if is_digits(rule.get("id"))}


def _notifies(rule: Dict[str, Any]) -> bool:
    """Whether LibreNMS sends anything when the rule alerts: it has an alert operation (null suppresses every
    notification) and is not muted in the UI."""
    return rule.get("alert_operation_id") not in (None, "", 0) and not _muted(rule.get("extra"))


def _read_log(ctx: ReportContext, scope: Scope, bound: str) -> Tuple[List[Dict[str, Any]], int | None]:
    """The alert-log entries from *bound* (server-local time) on, newest first, without their details
    (:meth:`ReportContext.read_log`: each device's for a scope of at most :data:`DEVICE_READS` devices, else every
    device's; at most :data:`MAX_ENTRIES`), and how many LibreNMS holds there for the scope when that is known."""
    return ctx.read_log(LOGS["alertlog"], scope, bound, max_entries=MAX_ENTRIES, device_reads=DEVICE_READS, keep=_slim)


def _slim(row: Dict[str, Any]) -> Dict[str, Any]:
    """An alert-log row as the history keeps it once its page is read: its own columns and the label of what alerted
    (:func:`_labels`), without ``details`` (every column the rule joined, the contacts), which may be large."""
    _found, names, _total = _labels(row.get("details"))
    kept = {key: row.get(key) for key in ("id", "device_id", "hostname", "rule_id", "fault_id", "state", "time_logged")}
    return {**kept, "entity": names[0] if names else None}


def _entry(devices: Dict[int, Dict[str, Any]], row: Dict[str, Any]) -> _Entry:
    """A kept alert-log row (:func:`_slim`) as the history counts it."""
    number = int(row["state"]) if is_digits(row.get("state")) else None
    return _Entry(
        id=_id(row.get("id")),
        device_id=int(row["device_id"]) if is_digits(row.get("device_id")) else None,
        rule_id=int(row["rule_id"]) if is_digits(row.get("rule_id")) else None,
        fault_id=row.get("fault_id"),
        state=LOG_STATES.get(number, str(row.get("state"))),
        logged=row.get("time_logged"),
        device=row_device(devices, row),
        entity=row.get("entity"),
    )


def _rule_of(rules: Dict[int, Dict[str, Any]] | None, rule_id: Any) -> Dict[str, Any] | None:
    return (rules or {}).get(rule_id) if rule_id is not None else None


def _rule_passes(rule_id: Any, rule: Dict[str, Any] | None, filters: Dict[str, Any]) -> bool:
    """Whether the filters on rules keep a rule: by its id or part of its name, its severity, disabled, whether it
    notifies. A rule that was not read passes only a filter by its id."""
    for key, wanted in filters.items():
        if key == "rule" and not _rule_wanted(wanted, rule_id, (rule or {}).get("name")):
            return False
        if key == "severity" and (rule or {}).get("severity") not in wanted:
            return False
        if key == "disabled" and (rule is None or truthy(rule.get("disabled")) != wanted):
            return False
        if key == "notifies" and (rule is None or _notifies(rule) != wanted):
            return False
    return True


def _entry_passes(entry: _Entry, filters: Dict[str, Any]) -> bool:
    """Whether an entry of a rule the filters keep counts: its state, what alerted."""
    if "state" in filters and entry.state not in filters["state"]:
        return False
    return "entity" not in filters or filters["entity"].casefold() in str(entry.entity or "").casefold()


def _flaps(entries: List[_Entry]) -> Set[int]:
    """The ids of the entries that are flaps: an alert raised again for what alerted (a rule, on a device, about the
    entity its details name: a port, a sensor, ...) that had cleared since it was last raised, within the window.

    Keyed by what alerted, not by the fault: LibreNMS reuses a fault only while it is open (``AlertRules``) and the
    dispatcher closes a recovered one within a minute (``RunAlerts``), so a port that goes down, up and down again
    over 5-minute polls is logged as two faults. Both an alert and its recovery carry the details; a recovery that
    names no entity (a rule over a table without labels, an older release) clears every entity of its rule on its
    device, and an alert that names none is its rule on its device, as in a release without faults."""
    raised: Dict[Tuple[Any, ...], int] = {}  # what alerted, or a rule on a device -> when it was last raised
    cleared: Dict[Tuple[Any, ...], int] = {}  # what alerted -> when it last recovered
    whole: Dict[Tuple[Any, ...], int] = {}  # a rule on a device -> when a recovery naming no entity cleared all of it
    latest: Dict[Tuple[Any, ...], int] = {}  # a rule on a device -> when anything of it last recovered
    out: Set[int] = set()
    ordered = sorted(entries, key=lambda entry: (units.server_order(entry.logged), entry.id))
    for at, entry in enumerate(ordered):  # *at*: the entry's place in that order, as a clock
        pair = (entry.rule_id, entry.device_id)
        key = (*pair, entry.entity) if entry.entity else pair
        if entry.state == "recovered":
            if entry.entity:
                cleared[key] = at
            else:
                whole[pair] = at
            latest[pair] = at
        elif entry.state == "alerted":
            since = max(cleared.get(key, -1), whole.get(pair, -1)) if entry.entity else latest.get(pair, -1)
            if since > raised.get(key, -1):
                out.add(entry.id)
            raised[key] = at
            raised[pair] = at  # whatever it named, the rule was raised on the device
    return out


def _tally(entries: Iterable[_Entry], flaps: Set[int]) -> _Tally:
    tally = _Tally()
    for entry in entries:
        tally.entries += 1
        tally.devices.add(entry.device_id)
        if entry.state == "alerted":
            tally.fired += 1
            tally.flaps += entry.id in flaps
            tally.rules[entry.rule_id] = tally.rules.get(entry.rule_id, 0) + 1
            if units.server_order(entry.logged) > units.server_order(tally.last_fired):
                tally.last_fired = entry.logged
        elif entry.state == "recovered":
            tally.cleared += 1
    return tally


def _grouped(entries: List[_Entry], key: Callable[[_Entry], Any]) -> Dict[Any, List[_Entry]]:
    out: Dict[Any, List[_Entry]] = {}
    for entry in entries:
        out.setdefault(key(entry), []).append(entry)
    return out


def _counts(ctx: ReportContext, tally: _Tally) -> Dict[str, Any]:
    out: Dict[str, Any] = {"entries": tally.entries, "fired": tally.fired, "cleared": tally.cleared}
    out["flaps"] = tally.flaps
    out.update(ctx.when(tally.last_fired, "last_fired"))
    return out


def _rule_fields(rule_id: Any, rule: Dict[str, Any] | None) -> Dict[str, Any]:
    """A rule as history rows name it, with its settings; one that was not read (or is gone) by its id alone."""
    if rule is None:
        return {"rule_id": rule_id, "rule": None, "severity": None}
    out = {"rule_id": rule_id, "rule": rule.get("name"), "severity": rule.get("severity")}
    out.update(disabled=truthy(rule.get("disabled")), notifies=_notifies(rule), muted=_muted(rule.get("extra")))
    return out


def _rule_rows(
    ctx: ReportContext,
    entries: List[_Entry],
    flaps: Set[int],
    rules: Dict[int, Dict[str, Any]] | None,
    scope: Scope,
    req: Request,
) -> List[Dict[str, Any]]:
    """A row per rule that logged in the window; for the whole fleet and with no filter on the entries themselves
    (state, entity), also every other rule the filters keep, with nothing counted."""
    grouped = _grouped(entries, lambda entry: entry.rule_id)
    if scope.ids is None and rules is not None and not {"state", "entity"} & set(req.filters):
        for rule_id, rule in rules.items():
            if rule_id not in grouped and _rule_passes(rule_id, rule, req.filters):
                grouped[rule_id] = []
    out = []
    for rule_id, items in grouped.items():
        tally = _tally(items, flaps)
        row = _rule_fields(rule_id, _rule_of(rules, rule_id))
        row.update(_counts(ctx, tally), devices=len(tally.devices))
        out.append((tally, row))
    kept = [pair for pair in out if _fired_passes(pair[0], req.filters)]
    kept.sort(key=_tally_order(req.sort, lambda row: (natural_key(row["rule"]), _id(row["rule_id"]))))
    return [row for _counted, row in kept]


def _device_rows(
    ctx: ReportContext, entries: List[_Entry], flaps: Set[int], rules: Dict[int, Dict[str, Any]] | None, req: Request
) -> List[Dict[str, Any]]:
    """A row per device that logged in the window: its counts, how many rules logged on it, and the rule that raised
    the most alerts there (``top_rule``)."""
    out = []
    for items in _grouped(entries, lambda entry: entry.device_id).values():
        tally = _tally(items, flaps)
        row: Dict[str, Any] = dict(items[0].device)
        row.update(_counts(ctx, tally), rules=len({entry.rule_id for entry in items}))
        top_id = min(tally.rules, key=lambda rule_id: (-tally.rules[rule_id], _id(rule_id)), default=None)
        row.update(top_rule_id=top_id, top_rule=(_rule_of(rules, top_id) or {}).get("name"))
        out.append((tally, row))
    kept = [pair for pair in out if _fired_passes(pair[0], req.filters)]
    kept.sort(key=_tally_order(req.sort, hostname_order))
    return [row for _counted, row in kept]


def _fired_passes(tally: _Tally, filters: Dict[str, Any]) -> bool:
    return "fired" not in filters or (tally.fired > 0) == filters["fired"]


def _event_rows(
    ctx: ReportContext, entries: List[_Entry], rules: Dict[int, Dict[str, Any]] | None, req: Request
) -> List[Dict[str, Any]]:
    """A row per entry, newest first (sort ``name``: by device, then newest first); filter.fired keeps the alerts
    raised (or every other entry)."""
    if "fired" in req.filters:
        entries = [entry for entry in entries if (entry.state == "alerted") == req.filters["fired"]]
    ordered = sorted(entries, key=lambda entry: (units.server_order(entry.logged), entry.id), reverse=True)
    if req.sort == "name":
        ordered.sort(key=lambda entry: hostname_order(entry.device))  # stable: newest first per device
    out = []
    for entry in ordered:
        rule = _rule_of(rules, entry.rule_id) or {}
        row: Dict[str, Any] = {"entry_id": entry.id, **ctx.when(entry.logged, "time"), **entry.device}
        row.update(rule_id=entry.rule_id, rule=rule.get("name"), severity=rule.get("severity"), state=entry.state)
        row.update(alert_id=entry.fault_id, entity=entry.entity)
        out.append(row)
    return out


def _tally_order(sort: str, name: Callable[[Dict[str, Any]], Tuple[Any, ...]]) -> Callable[..., Tuple[Any, ...]]:
    """The order of rule or device rows: ``fired`` (most first), ``flaps`` (most first), ``last_fired`` (newest
    first, those that did not fire last) or ``name``; ties by name."""

    def order(pair: Tuple[_Tally, Dict[str, Any]]) -> Tuple[Any, ...]:
        tally, row = pair
        if sort == "fired":
            return (-tally.fired, -tally.flaps, *name(row))
        if sort == "flaps":
            return (-tally.flaps, -tally.fired, *name(row))
        if sort == "last_fired":
            return (-units.server_order(tally.last_fired), *name(row))
        return name(row)

    return order


def _history_summary(
    entries: List[_Entry], flaps: Set[int], rules: Dict[int, Dict[str, Any]] | None, logged: int | None
) -> Dict[str, Any]:
    """Totals over the entries that passed the filter, and the rules and devices that raised the most alerts."""
    tally = _tally(entries, flaps)
    per_device = {
        device_id: _tally(items, flaps) for device_id, items in _grouped(entries, lambda e: e.device_id).items()
    }
    named = {entry.device_id: entry.device for entry in entries}
    top_rules = sorted(tally.rules.items(), key=lambda pair: (-pair[1], _id(pair[0])))[:TOP]
    top_devices = sorted(
        ((device_id, counted) for device_id, counted in per_device.items() if counted.fired),
        key=lambda pair: (-pair[1].fired, hostname_order(named[pair[0]])),
    )[:TOP]
    out: Dict[str, Any] = {} if logged is None else {"logged": logged}
    out.update(entries=len(entries), fired=tally.fired, cleared=tally.cleared, flaps=tally.flaps)
    out.update(rules=len({entry.rule_id for entry in entries}), devices=len(per_device))
    out["top_rules"] = [
        {"rule_id": rule_id, "rule": (_rule_of(rules, rule_id) or {}).get("name"), "fired": fired}
        for rule_id, fired in top_rules
    ]
    out["top_devices"] = [
        {**named[device_id], "fired": counted.fired, "flaps": counted.flaps} for device_id, counted in top_devices
    ]
    return out


HISTORY = View(
    "alert_history",
    build_history,
    scope_keys=SCOPE_KEYS,
    filters={
        "by": BY,
        "rule": "text",
        "severity": SEVERITIES,
        "state": HISTORY_STATES,
        "entity": "text",
        "disabled": "bool",
        "notifies": "bool",
        "fired": "bool",
    },
    sorts=("fired", "flaps", "last_fired", "name"),
    window="24h",
)
