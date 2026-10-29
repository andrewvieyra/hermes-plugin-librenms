"""What every ``librenms_report`` view shares: one :class:`ReportContext` per call, holding its reads, budgets, scope
and result envelope.

- Reads: every GET goes through :meth:`ReportContext.get`, which builds the path from fixed segments and resolved
  ids (each percent-encoded, :func:`client.path`), checks it against the read-route allow-list as librenms_query
  does (:func:`routes.match`, so a refused route stays unreachable), counts it against :data:`CALL_BUDGET`, reads
  LibreNMS's 404-for-an-empty-list as no rows and takes the rows from the route's result key. The devices,
  locations and group listings are read at most once per report; nothing is kept between calls.
- Scope: :meth:`ReportContext.scope` turns ``scope`` into a set of device ids. A device given by a phrase rather
  than its id or hostname is ranked (:mod:`.fuzzy`) and resolves only when one device matches exactly, or only one
  matches every word; otherwise the report answers ``ambiguous`` with the candidates (:class:`Ambiguous`).
- Envelope: :meth:`ReportContext.envelope` puts every view's answer in one shape (``scope``, ``data_as_of``,
  ``timezone``, ``count``/``returned``/``offset``/``truncated``/``next_offset``, ``partial``/``partial_reason``,
  ``summary``, ``rows``, ``notes``) with every string from LibreNMS clipped (:data:`LABEL_CHARS`) and the keys that
  hold one named in ``untrusted_fields``. The handler then keeps it within ``max_result_chars``.
"""

from __future__ import annotations

import email.utils
from dataclasses import dataclass, field
from datetime import datetime, timezone, tzinfo
from typing import Any, Callable, Dict, Iterable, List, Set, Tuple
from zoneinfo import ZoneInfo

from ..client import LibreNMSClient, LibreNMSError, is_digits, path
from ..listing import natural_key
from ..redact import clip, for_model, one_line, untrusted
from ..routes import QueryError, match
from ..settings import flag
from . import fuzzy, units

CALL_BUDGET = 30  # requests one report may send
LABEL_CHARS = 200  # the longest string from LibreNMS a report shows, counted as escaped
DEFAULT_LIMIT = 20
MAX_CANDIDATES = 10
MIN_SCORE = 20  # a candidate scoring less matched too little to show
AMBIGUITY_GAP = 10  # the top two candidates closer than this are both plausible
SCOPE_SHOWN = 10  # devices a scope lists by name
SCOPE_LIST = 50  # most entries scope.devices takes
TIMEZONE_UNKNOWN = "unknown — set librenms_timezone"
# The keys of a candidate row that hold text from LibreNMS.
CANDIDATE_TEXT = ("hostname", "display", "sysName", "location", "purpose", "hardware", "name", "desc", "port", "why")
# LibreNMS's device states, as its Device scopes decide them (isDisabled, isIgnored, isDown, isUp), first wins.
STATES = ("disabled", "ignored", "down", "up")
_TRUE = frozenset({"1", "true", "yes", "on"})


class ArgumentError(ValueError):
    """A malformed report argument; the message says what to send instead. Answered like a malformed librenms_query
    argument, without an audit event."""


class ReportError(Exception):
    """A report refused: its scope names nothing LibreNMS holds, or a read would leave the route allow-list. Audited
    as ``query_refused``, like a librenms_query refusal; *path* is the API path refused, when one was."""

    def __init__(self, message: str, path: str | None = None) -> None:
        super().__init__(message)
        self.path = path


class Ambiguous(Exception):
    """A scope value that could name more than one thing: the report answers with the *candidates* (rows as
    ``find`` shows them) instead of guessing."""

    def __init__(self, key: str, term: str, candidates: List[Dict[str, Any]]) -> None:
        super().__init__(f"scope.{key} {term!r} is ambiguous")
        self.key, self.term, self.candidates = key, term, candidates


class CallBudget(Exception):
    """The report has sent :data:`CALL_BUDGET` requests; the path it did not read is the message."""


@dataclass(frozen=True)
class Request:
    """A view's arguments, checked: ``term``, the raw ``scope`` (resolved by the view), ``filter`` parsed to its
    typed values, ``sort``, ``limit`` and ``offset``."""

    term: str | None
    scope: Any
    filters: Dict[str, Any]
    sort: str
    limit: int
    offset: int


@dataclass(frozen=True)
class View:
    """A report view: its builder and the arguments it takes. ``filters`` maps each filter name to its kind
    (``bool``, ``duration``, ``text``, or a tuple of the values a ``choice`` takes); ``sorts`` lists the orders, the
    default first."""

    name: str
    build: Callable[[ReportContext, Request], Dict[str, Any]]
    scope_keys: Tuple[str, ...] = ()
    filters: Dict[str, Any] = field(default_factory=dict)
    sorts: Tuple[str, ...] = ("name",)
    term: bool = False
    max_limit: int | None = None


@dataclass
class Scope:
    """A resolved scope: the device ids it covers (None: every device) and what the result says about it."""

    ids: Set[int] | None
    summary: Dict[str, Any]


def truthy(value: Any) -> bool:
    """A LibreNMS flag: ``true``, 1 or ``"1"`` (the device API writes them as booleans or numbers)."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return isinstance(value, str) and value.strip().lower() in _TRUE


def device_state(device: Dict[str, Any]) -> str:
    """``disabled``, ``ignored``, ``down`` or ``up``, as LibreNMS's own device filters decide it."""
    if truthy(device.get("disabled")):
        return "disabled"
    if truthy(device.get("ignore")):
        return "ignored"
    return "up" if truthy(device.get("status")) else "down"


def brief(device: Dict[str, Any]) -> Dict[str, Any]:
    """What every row about a device carries: ``device_id``, ``hostname`` and ``display`` when it differs."""
    out = {"device_id": device.get("device_id"), "hostname": device.get("hostname")}
    display = device.get("display")
    if isinstance(display, str) and display.strip() and display != device.get("hostname"):
        out["display"] = display
    return out


def hostname_order(device: Dict[str, Any]) -> Tuple[Any, ...]:
    return natural_key(device.get("hostname")), _id(device.get("device_id"))


def _id(value: Any) -> int:
    return int(value) if is_digits(value) else 0


def zone_of(settings: Any) -> tzinfo | None:
    """The zone of ``librenms_timezone``, or None when it is not set (settings has checked the name)."""
    name = getattr(settings, "librenms_timezone", "") or ""
    try:
        return ZoneInfo(name) if name else None
    except Exception:
        return None


def _http_date(value: Any) -> datetime | None:
    try:
        moment = email.utils.parsedate_to_datetime(value) if isinstance(value, str) else None
    except (TypeError, ValueError, IndexError):
        return None
    if moment is None:
        return None
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=timezone.utc)


def _failure(exc: LibreNMSError) -> str:
    """How a read failed, without LibreNMS's text: the status and kind."""
    return f"HTTP {exc.status} ({exc.kind})" if exc.status else f"no answer ({exc.kind})"


def _shown(value: Any) -> str:
    return repr(clip(one_line(str(value)), 60))


def term_arg(what: str, value: Any) -> str:
    """A name, id or phrase the model gave: text or a whole number, at most :data:`fuzzy.TERM_CHARS` characters."""
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ArgumentError(f"{what} takes a name, an id or a few words, not {type(value).__name__}")
    text = str(value).strip()
    if not text:
        raise ArgumentError(f"{what} is empty")
    if len(text) > fuzzy.TERM_CHARS:
        raise ArgumentError(f"{what} is {len(text)} characters; give at most {fuzzy.TERM_CHARS}")
    if not text.isprintable():
        raise ArgumentError(f"{what} must not hold control or invisible characters")
    return text


def count_arg(what: str, value: Any, default: int, minimum: int) -> int:
    """``limit`` or ``offset``: a whole number (or its digits as text) of at least *minimum*; *default* when absent."""
    if value is None:
        return default
    if isinstance(value, int) and not isinstance(value, bool):
        number = value
    elif isinstance(value, str) and value.strip().isascii() and value.strip().isdigit():
        number = int(value.strip())
    else:
        raise ArgumentError(f"{what} must be a whole number (got {_shown(value)})")
    if number < minimum:
        raise ArgumentError(f"{what} must be {minimum} or more (got {number})")
    return number


def request(view: View, args: Dict[str, Any], settings: Any) -> Request:
    """*args* checked against what *view* takes. ``limit`` defaults to :data:`DEFAULT_LIMIT` and is cut to
    ``max_query_results`` (and the view's own most); a filter or sort the view does not take is refused, naming
    those it does."""
    term = args.get("term")
    if view.term:
        if term is None:
            raise ArgumentError(f"view {view.name} needs a term: a hostname, sysName, IP, interface or a few words")
        term = term_arg("term", term)
    elif term not in (None, ""):
        raise ArgumentError(f"term is for view find; view {view.name} is narrowed with scope and filter")
    sort = args.get("sort")
    if sort is None:
        sort = view.sorts[0]
    elif not isinstance(sort, str) or sort.strip().lower() not in view.sorts:
        raise ArgumentError(f"view {view.name} sorts by {', '.join(view.sorts)} (got {_shown(sort)})")
    cap = min(settings.max_query_results, view.max_limit or settings.max_query_results)
    limit = min(count_arg("limit", args.get("limit"), min(DEFAULT_LIMIT, cap), 1), cap)
    offset = count_arg("offset", args.get("offset"), 0, 0)
    return Request(term, args.get("scope"), filters(view, args.get("filter")), sort.strip().lower(), limit, offset)


def filters(view: View, raw: Any) -> Dict[str, Any]:
    """The ``filter`` argument as typed values: a flag, a duration in seconds, a text, or the set of choices."""
    if raw is None or raw == {}:
        return {}
    if not isinstance(raw, dict):
        raise ArgumentError('filter must be an object, e.g. {"status": "down"}')
    out: Dict[str, Any] = {}
    for key, value in raw.items():
        kind = view.filters.get(key)
        if kind is None:
            takes = f"takes filter keys {', '.join(view.filters)}" if view.filters else "takes no filter"
            raise ArgumentError(f"view {view.name} {takes}, not {_shown(key)}")
        if kind == "bool":
            out[key] = flag(value)
            if out[key] is None:
                raise ArgumentError(f"filter.{key} takes true or false")
        elif kind == "duration":
            out[key] = units.parse_duration(value)
            if out[key] is None:
                raise ArgumentError(f"filter.{key} takes a duration such as 30m, 24h or 7d (at most a year)")
        elif kind == "text":
            out[key] = term_arg(f"filter.{key}", value)
        else:
            items = value if isinstance(value, list) and value else [value]
            if not all(isinstance(item, str) and item.strip().lower() in kind for item in items):
                raise ArgumentError(f"filter.{key} takes {', '.join(kind)}, or a list of them")
            out[key] = frozenset(item.strip().lower() for item in items)
    return out


def port_state(port: Dict[str, Any]) -> str | None:
    """``disabled`` (administratively down), ``up``, or the operational status otherwise (``down``,
    ``lowerLayerDown``, ``notPresent``, ...); None when the port row has neither status."""
    admin, oper = port.get("ifAdminStatus"), port.get("ifOperStatus")
    if admin == "down":
        return "disabled"
    if oper is None:
        return None
    return str(oper)


def port_label(port: Dict[str, Any]) -> str | None:
    """A port as people name it: its ifName (else ifDescr), and its description in parentheses when it has one that
    says more than the name (some devices copy ifName or ifDescr into ifAlias)."""
    name = port.get("ifName") or port.get("ifDescr")
    alias = port.get("ifAlias")
    if not name:
        return None
    if isinstance(alias, str) and alias.strip() and alias not in (port.get("ifName"), port.get("ifDescr")):
        return f"{name} ({alias})"
    return str(name)


class ReportContext:
    """One report: its client and settings, the requests it sent (``calls``, and ``read``, the route names in order),
    its memo of listings, why its data is incomplete (``partial_reasons``) and what it tells the model (``notes``).
    ``now`` is LibreNMS's clock (the ``Date`` of the first answer; the plugin's when there is none), which every age
    is counted to."""

    def __init__(self, client: Any, settings: Any, *, call_budget: int | None = None) -> None:
        self.client = client
        self.settings = settings
        self.call_budget = CALL_BUDGET if call_budget is None else call_budget
        self.calls = 0
        self.read: List[str] = []
        self.partial_reasons: List[str] = []
        self.notes: List[str] = []
        self.zone = zone_of(settings)
        self._now: datetime | None = None
        self._memo: Dict[str, Any] = {}

    # -- reads ------------------------------------------------------------------------------------------------------
    def get(self, *segments: Any, params: Dict[str, Any] | None = None) -> Any:
        """``GET`` the path made of *segments* (fixed words, ids, names; one segment each) with *params*: the value
        under the route's result key, ``[]`` for LibreNMS's 404 for an empty list. Raises :class:`ReportError` for a
        path off the allow-list, :class:`CallBudget` past the budget, and the LibreNMSError of any other failure."""
        pieces = [str(segment) for segment in segments]
        joined = "/".join(pieces)
        if any(not piece or "/" in piece for piece in pieces):
            raise ReportError(f"invalid report path {joined[:200]!r}", joined[:200])
        try:
            route, _values = match(joined)
            request_path = path(*pieces)
        except (QueryError, LibreNMSError) as exc:
            raise ReportError(f"report read refused: {exc}", joined[:200]) from None
        if self.calls >= self.call_budget:
            raise CallBudget(joined)
        if not self.calls and hasattr(self.client, "last_date"):
            self.client.last_date = None  # a reused client's Date is not this report's
        self.calls += 1
        self.read.append(route.name)
        try:
            body = self.client.get(request_path, params)
        except LibreNMSError as exc:
            if exc.kind != "not_found":
                raise
            body = None
        finally:
            if self._now is None:
                self._now = _http_date(getattr(self.client, "last_date", None))
        value = LibreNMSClient.result(body, route.list_key) if body is not None else None
        return [] if value is None else value

    def optional(self, what: str, *segments: Any, params: Dict[str, Any] | None = None) -> Any:
        """:meth:`get`, or None when the read failed or the budget is spent, which makes the report ``partial``
        (*what* names the data left out). A rejected token still fails the report."""
        try:
            return self.get(*segments, params=params)
        except CallBudget:
            self.partial(f"{what} not read: the report used its {self.call_budget} requests")
        except LibreNMSError as exc:
            if exc.kind == "auth":
                raise
            self.partial(f"{what} not read: LibreNMS answered {_failure(exc)}")
        return None

    def partial(self, reason: str) -> None:
        if reason not in self.partial_reasons:
            self.partial_reasons.append(reason)

    @property
    def now(self) -> datetime:
        if self._now is None:
            self._now = datetime.now(timezone.utc)
        return self._now

    def devices(self) -> Dict[int, Dict[str, Any]]:
        """Every device the token can see, by id, in LibreNMS's order (hostname): one ``devices`` listing."""
        if "devices" not in self._memo:
            rows = self.get("devices")
            self._memo["devices"] = {
                int(row["device_id"]): row for row in rows_of(rows) if is_digits(row.get("device_id"))
            }
        return self._memo["devices"]

    def listing(self, key: str, *segments: Any, what: str | None = None) -> List[Dict[str, Any]]:
        """The rows of a listing (``resources/locations``, ``devicegroups``, ``port_groups``), read once per report;
        with *what*, a failed read leaves them out and makes the report partial (:meth:`optional`)."""
        if key not in self._memo:
            rows = self.get(*segments) if what is None else self.optional(what, *segments)
            self._memo[key] = rows_of(rows)
        return self._memo[key]

    # -- candidates -------------------------------------------------------------------------------------------------
    def rank_devices(self, term: fuzzy.Term) -> List[Tuple[fuzzy.Match, int]]:
        """Every device that matches *term* well enough, best first (then by hostname and id)."""
        devices = self.devices()
        ranked = []
        for device_id, device in devices.items():
            found = fuzzy.device_match(term, device)
            if found is not None and found.score >= MIN_SCORE:
                ranked.append((found, device_id))
        ranked.sort(key=lambda pair: (-pair[0].score, hostname_order(devices[pair[1]])))
        return ranked

    def device_candidate(self, device_id: int, found: fuzzy.Match) -> Dict[str, Any]:
        """A device as a candidate: who it is, where, what, its state, and the score and why of its match."""
        device = self.devices()[device_id]
        row: Dict[str, Any] = {"kind": "device", **brief(device)}
        for key in ("sysName", "location", "purpose", "os", "hardware", "type"):
            if device.get(key) not in (None, ""):
                row[key] = device[key]
        row.update(status=device_state(device), score=found.score, why=found.why)
        return row

    # -- scope ------------------------------------------------------------------------------------------------------
    def scope(self, raw: Any, accepted: Tuple[str, ...]) -> Scope:
        """*raw* (the ``scope`` argument) as the device ids it names. ``device`` and ``devices`` add devices; ``group``,
        ``location``, ``os`` and ``type`` narrow to theirs (all given must hold). Raises :class:`ArgumentError` for a
        key the view does not take, :class:`Ambiguous` for a device or group that could be several, and
        :class:`ReportError` for one that is none."""
        devices = self.devices()
        if raw is None or raw == {}:
            return Scope(None, {"fleet": True, "device_count": len(devices)})
        if not isinstance(raw, dict):
            raise ArgumentError('scope must be an object, e.g. {"device": "core-sw1"} or {"location": "SFO"}')
        unknown = [_shown(key) for key in raw if key not in accepted]
        if unknown:
            takes = f"takes scope keys {', '.join(accepted)}" if accepted else "takes no scope"
            raise ArgumentError(f"this view {takes}, not {', '.join(unknown)}")
        chosen: Set[int] | None = None
        summary: Dict[str, Any] = {}
        resolved: List[Dict[str, Any]] = []
        refs = [("device", raw["device"])] if "device" in raw else []
        if "devices" in raw:
            items = raw["devices"]
            if not isinstance(items, list) or not items or len(items) > SCOPE_LIST:
                raise ArgumentError(f"scope.devices takes a list of 1 to {SCOPE_LIST} hostnames, ids or names")
            refs += [("devices", item) for item in items]
        if refs:
            chosen = set()
            for key, ref in refs:
                device_id, why = self.resolve_device(key, ref)
                chosen.add(device_id)
                if why:
                    resolved.append({"term": str(ref).strip(), **brief(devices[device_id]), "why": why})
        for key, members in (("group", self._group), ("location", self._location)):
            if key in raw:
                ids, about = members(raw[key])
                summary[key] = about
                chosen = ids if chosen is None else chosen & ids
        for key in ("os", "type"):
            if key in raw:
                wanted = term_arg(f"scope.{key}", raw[key])
                ids = {i for i, d in devices.items() if str(d.get(key) or "").casefold() == wanted.casefold()}
                if not ids:
                    held = sorted({str(d.get(key)) for d in devices.values() if d.get(key)}, key=natural_key)
                    self.notes.append(f"no device has {key} {_shown(wanted)}; the {key} values LibreNMS holds: "
                                      + ", ".join(held[:30]) + (" ..." if len(held) > 30 else ""))  # fmt: skip
                chosen = ids if chosen is None else chosen & ids
        ids = chosen if chosen is not None else set(devices)
        out: Dict[str, Any] = {"device_count": len(ids), **summary}
        if len(ids) <= SCOPE_SHOWN:
            out["devices"] = [brief(devices[i]) for i in sorted(ids, key=lambda i: hostname_order(devices[i]))]
        if resolved:
            out["resolved"] = resolved[:SCOPE_SHOWN]
            if len(resolved) > SCOPE_SHOWN:
                out["resolved_count"] = len(resolved)
        return Scope(ids, out)

    def resolve_device(self, key: str, ref: Any) -> Tuple[int, str | None]:
        """The device *ref* names: an id or exact hostname as it is; else the one device a phrase matches exactly
        (sysName, display name, first label, IP), or the only one matching every word of it, with why."""
        text = term_arg(f"scope.{key}", ref)
        devices = self.devices()
        if is_digits(text):
            if int(text) in devices:
                return int(text), None
            raise ReportError(f"scope.{key}: no LibreNMS device has id {text} (or this token cannot see it)")
        for device_id, device in devices.items():
            if str(device.get("hostname") or "").casefold() == text.casefold():
                return device_id, None
        ranked = self.rank_devices(fuzzy.Term.parse(text))
        exact = [pair for pair in ranked if pair[0].score == 100]
        full = [pair for pair in ranked if pair[0].full]
        if len(exact) == 1 or (not exact and len(full) == 1):
            found, device_id = (exact or full)[0]
            return device_id, found.why
        shortlist = exact or ranked
        if shortlist:
            raise Ambiguous(key, text, [self.device_candidate(i, found) for found, i in shortlist])
        raise ReportError(
            f"scope.{key} {_shown(text)} names no LibreNMS device: no id, hostname, sysName, display name or IP is "
            "that, and no device matches its words; ask the user, or look for it with view find"
        )

    def _group(self, ref: Any) -> Tuple[Set[int], Dict[str, Any]]:
        """The members of a device group given by id or name (any case; else the one group whose name matches the
        words), read with ``devicegroups/{id}``, never ``full=1``."""
        text = term_arg("scope.group", ref)
        groups = self.listing("groups", "devicegroups")
        found = [
            group
            for group in groups
            if (is_digits(text) and str(group.get("id")) == text)
            or str(group.get("name") or "").casefold() == text.casefold()
        ]
        if not found:
            term = fuzzy.Term.parse(text)
            ranked = []
            for group in groups:
                matched = fuzzy.name_match(term, "name", group.get("name"), group.get("desc"))
                if matched is not None and matched.score >= MIN_SCORE:
                    ranked.append((matched, group))
            ranked.sort(key=lambda pair: (-pair[0].score, natural_key(pair[1].get("name"))))
            full = [pair for pair in ranked if pair[0].full]
            if len(full) == 1:
                found = [full[0][1]]
            elif ranked:
                raise Ambiguous("group", text, [group_candidate(g, m) for m, g in ranked])
            else:
                names = ", ".join(_shown(g.get("name")) for g in groups[:10]) or "none"
                raise ReportError(f"scope.group {_shown(text)}: LibreNMS has no device group by that name or id; "
                                  f"its groups: {names}")  # fmt: skip
        group = found[0]
        if not is_digits(group.get("id")):
            raise ReportError(f"device group {_shown(group.get('name'))} has no id LibreNMS can be asked by")
        rows = self.get("devicegroups", group["id"])
        devices = self.devices()
        ids = {int(row["device_id"]) for row in rows_of(rows) if is_digits(row.get("device_id"))} & set(devices)
        return ids, {"group_id": int(group["id"]), "name": group.get("name")}

    def _location(self, ref: Any) -> Tuple[Set[int], Dict[str, Any]]:
        """The devices at a location given by id, by name (any case), or by part of a name: every location whose name
        holds it, as LibreNMS's own ``type=location`` filter reads it."""
        text = term_arg("scope.location", ref)
        devices = self.devices()
        if is_digits(text):
            ids = {i for i, d in devices.items() if str(d.get("location_id")) == text}
        else:
            wanted = text.casefold()
            ids = {i for i, d in devices.items() if str(d.get("location") or "").casefold() == wanted}
            ids = ids or {i for i, d in devices.items() if wanted in str(d.get("location") or "").casefold()}
        if not ids:
            locations = self.listing("locations", "resources", "locations")
            known = [
                row
                for row in locations
                if str(row.get("id")) == text or text.casefold() in str(row.get("location") or "").casefold()
            ]
            if not known:
                names = ", ".join(_shown(row.get("location")) for row in locations[:10]) or "none"
                raise ReportError(f"scope.location {_shown(text)} names no LibreNMS location; its locations "
                                  f"include {names}")  # fmt: skip
            self.notes.append(f"no device is at location {_shown(text)}")
        names = sorted({str(devices[i].get("location")) for i in ids if devices[i].get("location")}, key=natural_key)
        about: Dict[str, Any] = {"locations": names[:SCOPE_SHOWN]}
        if len(names) > SCOPE_SHOWN:
            about["location_count"] = len(names)
        return ids, about

    # -- the result -------------------------------------------------------------------------------------------------
    def envelope(
        self,
        view: str,
        *,
        scope: Scope,
        rows: List[Dict[str, Any]],
        count: int,
        offset: int,
        summary: Dict[str, Any],
        text_keys: Iterable[str],
        extra: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        """A view's answer: *rows* (the page from *offset* on) of *count* rows in all, the *summary*, and the rest of
        the envelope. *text_keys* are the row keys that hold text from LibreNMS, which ``untrusted_fields`` names with
        those of the scope; strings are clipped to :data:`LABEL_CHARS` as escaped."""
        out: Dict[str, Any] = {"success": True, "view": view, **(extra or {})}
        scoped = _scope_text(scope.summary)
        if rows or scoped:
            out.update(untrusted(*dict.fromkeys([*text_keys, *scoped])))
        out["scope"] = for_model(scope.summary, LABEL_CHARS)
        out.update(self._stamp())
        truncated = count > offset + len(rows)
        out.update(count=count, returned=len(rows), offset=offset, truncated=truncated)
        if truncated:
            out["next_offset"] = offset + len(rows)
        elif offset and offset >= count:
            self.notes.append(f"offset {offset} is past the last row: there are {count}, from offset 0")
        out.update(self._partial())
        out["summary"] = for_model(summary, LABEL_CHARS)
        out["rows"] = for_model(rows, LABEL_CHARS)
        out["notes"] = list(self.notes)
        return out

    def ambiguous(self, view: str, exc: Ambiguous, offset: int = 0, limit: int = MAX_CANDIDATES) -> Dict[str, Any]:
        """The answer when a scope value could be several things: no rows, the candidates (``count``, ``returned``
        and ``offset`` count them, at most :data:`MAX_CANDIDATES` an answer, best first), and what to do."""
        total = len(exc.candidates)
        self.notes.append(
            f"scope.{exc.key} {_shown(exc.term)} could be any of {total} candidates: ask the user which one they "
            "mean, then call again with its hostname or id; nothing was reported for it"
        )
        if total > MAX_CANDIDATES:
            self.notes.append(
                f"an answer shows at most {MAX_CANDIDATES} of them, best first: ask the user for more of the name, "
                "the site or the IP rather than read them all"
            )
        shown = exc.candidates[offset : offset + min(limit, MAX_CANDIDATES)]
        truncated = total > offset + len(shown)
        out: Dict[str, Any] = {"success": True, "view": view, "ambiguous": True, **untrusted(*CANDIDATE_TEXT)}
        out.update(scope={exc.key: exc.term}, **self._stamp(), count=total, returned=len(shown), offset=offset)
        out.update(truncated=truncated, **({"next_offset": offset + len(shown)} if truncated else {}))
        out.update(**self._partial(), summary={"candidates": total})
        out.update(rows=[], candidates=for_model(shown, LABEL_CHARS), notes=list(self.notes))
        return out

    def _stamp(self) -> Dict[str, Any]:
        name = getattr(self.settings, "librenms_timezone", "") or ""
        return {"data_as_of": units.iso(self.now), "timezone": name if self.zone is not None else TIMEZONE_UNKNOWN}

    def _partial(self) -> Dict[str, Any]:
        if not self.partial_reasons:
            return {"partial": False}
        return {"partial": True, "partial_reason": "; ".join(self.partial_reasons)}


def _scope_text(summary: Dict[str, Any]) -> List[str]:
    """The keys of a scope summary that hold text from LibreNMS: device names, why a phrase matched, a group's name,
    the locations."""
    keys = []
    if summary.get("devices") or summary.get("resolved"):
        keys += ["hostname", "display"]
    if summary.get("resolved"):
        keys.append("why")
    if summary.get("group"):
        keys.append("name")
    if (summary.get("location") or {}).get("locations"):
        keys.append("locations")
    return keys


def group_candidate(group: Dict[str, Any], found: fuzzy.Match) -> Dict[str, Any]:
    """A device group as a candidate: its id, name, description and type, and the score and why of its match."""
    row: Dict[str, Any] = {"kind": "group", "group_id": group.get("id"), "name": group.get("name")}
    if group.get("desc"):
        row["desc"] = group["desc"]
    if group.get("type"):
        row["type"] = group["type"]
    row.update(score=found.score, why=found.why)
    return row


def rows_of(value: Any) -> List[Dict[str, Any]]:
    """The object rows of a listing's value (anything else is none)."""
    return [row for row in value if isinstance(row, dict)] if isinstance(value, list) else []
