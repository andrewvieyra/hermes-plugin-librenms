"""What every ``librenms_report`` view shares: one :class:`ReportContext` per call, holding its reads, budgets, scope
and result envelope.

- Reads: every GET goes through :meth:`ReportContext.get`, which builds the path from fixed segments and resolved
  ids (each percent-encoded, :func:`client.path`), checks it against the read-route allow-list as librenms_query
  does (:func:`routes.match`, so a refused route stays unreachable), counts it against :data:`CALL_BUDGET`, reads
  LibreNMS's 404-for-an-empty-list as no rows and takes the rows from the route's result key. The devices,
  locations and group listings, and the port names of a device a view names ports on
  (:meth:`ReportContext.ports_by_device`), are read at most once per report; nothing is kept between calls. A log
  over a window (:data:`LOGS`: the alert log, eventlog, syslog, authlog) is read by :meth:`ReportContext.read_log`,
  newest first, a page at a time, up to the entries a view reads.
- Scope: :meth:`ReportContext.scope` turns ``scope`` into a set of device ids (and a port group into its port ids).
  A device given by a phrase rather than its id or hostname is ranked (:mod:`.fuzzy`) and resolves only when one
  device matches exactly, or only one matches every word; otherwise the report answers ``ambiguous`` with the
  candidates (:class:`Ambiguous`). A device or port group named by part of its name resolves the same way.
- Envelope: :meth:`ReportContext.envelope` puts every view's answer in one shape (``scope``, ``data_as_of``,
  ``timezone``, ``count``/``returned``/``offset``/``truncated``/``next_offset``, ``partial``/``partial_reason``,
  ``summary``, ``rows``, ``notes``) with every string from LibreNMS clipped (:data:`LABEL_CHARS`) and the keys that
  hold one named in ``untrusted_fields``. The handler then keeps it within ``max_result_chars``.
"""

from __future__ import annotations

import email.utils
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone, tzinfo
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
# What names a device's ports, and ties a sensor to one (its ifIndex), when a view names the ports its rows are about.
PORT_NAME_COLUMNS = "port_id,ifIndex,ifName,ifDescr,ifAlias"
PORT_MAP_READS = 10  # devices whose ports a report reads to name the ports its rows are about
DEFAULT_LIMIT = 20
MAX_CANDIDATES = 10
MIN_SCORE = 20  # a candidate scoring less matched too little to show
AMBIGUITY_GAP = 10  # the top two candidates closer than this are both plausible
SCOPE_SHOWN = 10  # devices a scope lists by name
SCOPE_LIST = 50  # most entries scope.devices takes
TIMEZONE_UNKNOWN = "unknown — set librenms_timezone"
TERM_VIEWS = "find and locate"  # the views that take a term
WINDOW_VIEWS = "alert_history and events"  # the views that take a window
TODAY = "today"
LOG_PAGE = 250  # log entries one request asks for
LOG_MIN_PAGE = 25  # the fewest a request asks for while LibreNMS's answer is too large to read
# How far a server-local clock may be from UTC (UTC-12 to UTC+14): without librenms_timezone, a window's start in
# LibreNMS's time is read this much earlier, so it holds the whole window whatever the server's zone.
EARLIEST_OFFSET_S = 12 * 3600
LATEST_OFFSET_S = 14 * 3600
# The keys of a candidate row that hold text from LibreNMS.
CANDIDATE_TEXT = ("hostname", "display", "sysName", "location", "purpose", "hardware", "name", "desc", "port", "why")
# LibreNMS's device states, as its Device scopes decide them (isDisabled, isIgnored, isDown, isUp), first wins.
STATES = ("disabled", "ignored", "down", "up")
# A fault's state (LibreNMS's AlertState), and the ones a fault is open in.
FAULT_STATES = {0: "recovered", 1: "active", 2: "acknowledged", 3: "worse", 4: "better", 5: "changed"}
OPEN_FAULT_STATES = "1,2,3,4,5"
_TRUE = frozenset({"1", "true", "yes", "on"})
# What names one candidate of an ambiguous scope value for certain, by scope key; a device's hostname or id otherwise.
_CALL_AGAIN_WITH = {
    "port": "its port_id",
    "group": "its group_id or exact name",
    "port_group": "its port_group_id or exact name",
}


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


class One(tuple):
    """The values of a choice filter that takes one of them, never a list (``alert_history``'s ``by``: the shape of
    its rows)."""


class CallBudget(Exception):
    """The report has sent :data:`CALL_BUDGET` requests; the path it did not read is the message."""


@dataclass(frozen=True)
class Request:
    """A view's arguments, checked: ``term``, the raw ``scope`` (resolved by the view), ``filter`` parsed to its
    typed values, ``sort``, ``limit``, ``offset`` and ``window`` (``today`` or a duration as given, for a view that
    takes one; :meth:`ReportContext.since` places it)."""

    term: str | None
    scope: Any
    filters: Dict[str, Any]
    sort: str
    limit: int
    offset: int
    window: str | None = None


@dataclass(frozen=True)
class Since:
    """Where a window starts: ``bound``, the server-local ``Y-m-d H:i:s`` LibreNMS's ``from`` compares its log times
    with, and ``exact``, whether that is the window's start (``librenms_timezone`` is set) or earlier by up to
    :data:`EARLIEST_OFFSET_S` plus :data:`LATEST_OFFSET_S`, which holds the window in any zone."""

    window: str
    bound: str
    exact: bool


@dataclass(frozen=True)
class Log:
    """A LibreNMS log a view reads over a window (``logs/<name>``, which LibreNMS pages with ``start`` and ``limit``):
    what a partial reason calls it, the time column LibreNMS orders it by and bounds with ``from`` (server-local
    ``Y-m-d H:i:s``), its id column, and whether it has a path per device (``logs/<name>/<device_id>``; the authlog,
    LibreNMS's own logins, has none)."""

    name: str
    what: str
    time_key: str
    id_key: str
    per_device: bool = True


LOGS = {
    log.name: log
    for log in (
        Log("alertlog", "the alert log", "time_logged", "id"),
        Log("eventlog", "the eventlog", "datetime", "event_id"),
        Log("syslog", "the syslog", "timestamp", "seq"),
        Log("authlog", "the authlog", "datetime", "id", per_device=False),
    )
}


@dataclass(frozen=True)
class View:
    """A report view: its builder and the arguments it takes. ``filters`` maps each filter name to its kind
    (``bool``, ``duration``, ``number``, ``id`` (a whole number, 1 or more), ``text``, or a tuple of the values a
    ``choice`` takes, one or a list of them; :class:`One` for a choice of one alone); ``sorts`` lists the orders, the
    default first; ``term`` says whether it takes a term (:data:`TERM_VIEWS`); ``window`` is the window a view that
    takes one reads by default (:data:`WINDOW_VIEWS`). View ``help`` (:mod:`.help`) says what each filter and sort
    means."""

    name: str
    build: Callable[[ReportContext, Request], Dict[str, Any]]
    scope_keys: Tuple[str, ...] = ()
    filters: Dict[str, Any] = field(default_factory=dict)
    sorts: Tuple[str, ...] = ("name",)
    term: bool = False
    max_limit: int | None = None
    term_hint: str = "a hostname, sysName, IP, interface or a few words"  # what the view's term is, when it takes one
    window: str | None = None


@dataclass
class Scope:
    """A resolved scope: the device ids it covers (None: every device, when no key narrows the devices), the port
    ids of its port group (None: no port group was given), and what the result says about it."""

    ids: Set[int] | None
    summary: Dict[str, Any]
    port_ids: Set[int] | None = None


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


def log_order(log: Log, row: Dict[str, Any]) -> Tuple[int, int]:
    """A log entry's place in time: its server-local time, then its id (entries logged in the same second)."""
    return units.server_order(row.get(log.time_key)), _id(row.get(log.id_key))


def row_device(devices: Dict[int, Dict[str, Any]], row: Dict[str, Any]) -> Dict[str, Any]:
    """The device a fault or log row is about, as rows name it (:func:`brief`); one the token cannot see (or that is
    gone) by the id and hostname the row carries."""
    device_id = int(row["device_id"]) if is_digits(row.get("device_id")) else None
    if device_id in devices:
        return brief(devices[device_id])
    return {"device_id": device_id, "hostname": row.get("hostname")}


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


def failure(exc: LibreNMSError) -> str:
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


def help_hint(view: View) -> str:
    """Where the model reads what *view*'s filters and sorts mean, said after refusing one."""
    return f'view help with topic "{view.name}" says what each does'


def request(view: View, args: Dict[str, Any], settings: Any) -> Request:
    """*args* checked against what *view* takes. ``limit`` defaults to :data:`DEFAULT_LIMIT` and is cut to
    ``max_query_results`` (and the view's own most); a filter or sort the view does not take is refused, naming
    those it does and where they are explained."""
    term = args.get("term")
    if view.term:
        if term is None:
            raise ArgumentError(f"view {view.name} needs a term: {view.term_hint}")
        term = term_arg("term", term)
    elif term not in (None, ""):
        raise ArgumentError(f"term is for views {TERM_VIEWS}; view {view.name} is narrowed with scope and filter")
    if args.get("topic") not in (None, ""):
        raise ArgumentError(
            f'topic is for view help, which explains a view: {{"view": "help", "topic": "{view.name}"}}'
        )
    sort = args.get("sort")
    if sort is None:
        sort = view.sorts[0]
    elif not isinstance(sort, str) or sort.strip().lower() not in view.sorts:
        raise ArgumentError(
            f"view {view.name} sorts by {', '.join(view.sorts)} (got {_shown(sort)}); {help_hint(view)}"
        )
    cap = min(settings.max_query_results, view.max_limit or settings.max_query_results)
    limit = min(count_arg("limit", args.get("limit"), min(DEFAULT_LIMIT, cap), 1), cap)
    offset = count_arg("offset", args.get("offset"), 0, 0)
    window = window_arg(view, args.get("window"), settings)
    return Request(
        term, args.get("scope"), filters(view, args.get("filter")), sort.strip().lower(), limit, offset, window
    )


def window_arg(view: View, value: Any, settings: Any) -> str | None:
    """``window``: ``today`` (since midnight in ``librenms_timezone``, which it needs) or a duration such as ``1h``,
    ``24h``, ``7d`` or ``30d`` (at most a year), for a view that takes one; its default when absent."""
    if view.window is None:
        if value not in (None, ""):
            raise ArgumentError(f"window is for views {WINDOW_VIEWS}; view {view.name} reads what LibreNMS holds now")
        return None
    if value is None or value == "":
        return view.window
    text = value.strip().lower() if isinstance(value, str) else None
    if text == TODAY:
        if zone_of(settings) is None:
            raise ArgumentError(
                "window today needs librenms_timezone (the zone LibreNMS writes its times in), which is not set; "
                "give a duration such as 24h"
            )
        return TODAY
    if text is None or units.parse_duration(text) is None:
        raise ArgumentError(f"window takes today or a duration such as 1h, 24h, 7d or 30d (got {_shown(value)})")
    return text


def number_arg(what: str, value: Any) -> float:
    """A number the model gave (or its digits as text): finite, 0 or more."""
    found = None if isinstance(value, bool) else units.number(value)
    if found is None or found < 0:
        raise ArgumentError(f"{what} takes a number, 0 or more (got {_shown(value)})")
    return found


def filters(view: View, raw: Any) -> Dict[str, Any]:
    """The ``filter`` argument as typed values: a flag, a duration in seconds, a number, an id, a text, or the set of
    choices (any letter case; held as the view spells them)."""
    if raw is None or raw == {}:
        return {}
    if not isinstance(raw, dict):
        raise ArgumentError('filter must be an object, e.g. {"status": "down"}')
    out: Dict[str, Any] = {}
    for key, value in raw.items():
        kind = view.filters.get(key)
        if kind is None:
            if not view.filters:
                raise ArgumentError(f"view {view.name} takes no filter, not {_shown(key)}")
            raise ArgumentError(
                f"view {view.name} takes filter keys {', '.join(view.filters)}, not {_shown(key)}; {help_hint(view)}"
            )
        if kind == "bool":
            out[key] = flag(value)
            if out[key] is None:
                raise ArgumentError(f"filter.{key} takes true or false")
        elif kind == "duration":
            out[key] = units.parse_duration(value)
            if out[key] is None:
                raise ArgumentError(f"filter.{key} takes a duration such as 30m, 24h or 7d (at most a year)")
        elif kind == "number":
            out[key] = number_arg(f"filter.{key}", value)
        elif kind == "id":
            text = str(value).strip() if isinstance(value, (str, int)) and not isinstance(value, bool) else ""
            if not is_digits(text) or not int(text):
                raise ArgumentError(f"filter.{key} takes a row's {key}, a whole number (got {_shown(value)})")
            out[key] = int(text)
        elif kind == "text":
            out[key] = term_arg(f"filter.{key}", value)
        else:
            spelled = {choice.casefold(): choice for choice in kind}
            items = value if isinstance(value, list) and value else [value]
            if isinstance(kind, One) and len(items) != 1:
                raise ArgumentError(f"filter.{key} takes one of {', '.join(kind)}")
            if not all(isinstance(item, str) and item.strip().casefold() in spelled for item in items):
                one = isinstance(kind, One)
                raise ArgumentError(f"filter.{key} takes {', '.join(kind)}" + ("" if one else ", or a list of them"))
            out[key] = frozenset(spelled[item.strip().casefold()] for item in items)
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


def folded(port: Dict[str, Any], key: str) -> str:
    """A port's *key* (``ifName``, ``ifDescr``, ``ifAlias``) as compared with a name the model gave: trimmed, any
    case."""
    return str(port.get(key) or "").strip().casefold()


def abbreviates(text: str, *names: str) -> bool:
    """Whether *text* is a short form of one of *names* (all folded): the same numbers after a prefix of its letters
    (``gi1/0/5`` for ``gigabitethernet1/0/5``, ``te1/1/1`` for ``tengigabitethernet1/1/1``)."""
    letters = text.rstrip("0123456789/.:-")
    if not letters or not letters.isalpha() or letters == text:
        return False
    for name in names:
        long = name.rstrip("0123456789/.:-")
        if long.isalpha() and long.startswith(letters) and name[len(long) :] == text[len(letters) :]:
            return True
    return False


def names_port(text: str, port: Dict[str, Any], *, by_id: bool = True) -> bool:
    """Whether *text* names *port* (a ports row) by its ifName or ifDescr in any case (a number too: HP and Aruba
    switches name their ports ``5``), a short form of one (:func:`abbreviates`), or (*by_id*) its port_id."""
    wanted = text.strip().casefold()
    name, descr = folded(port, "ifName"), folded(port, "ifDescr")
    if wanted in (name, descr) or abbreviates(wanted, name, descr):
        return True
    return by_id and wanted == str(port.get("port_id"))


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
        return self._read(segments, params)[0]

    def page(self, *segments: Any, params: Dict[str, Any] | None = None) -> Tuple[List[Dict[str, Any]], int | None]:
        """:meth:`get` on a logs route, which LibreNMS pages: the rows, and ``total``, every row it holds for the
        query (None when its answer says none: a 404 for no rows is 0)."""
        value, body = self._read(segments, params)
        total = body.get("total") if isinstance(body, dict) else 0 if body is None else None
        return rows_of(value), int(total) if is_digits(total) else None

    def _read(self, segments: Tuple[Any, ...], params: Dict[str, Any] | None) -> Tuple[Any, Any]:
        """:meth:`get`'s value, and the whole answer it came in (None for a 404)."""
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
        return ([] if value is None else value), body

    def optional(
        self, what: str, *segments: Any, params: Dict[str, Any] | None = None, raising: Tuple[str, ...] = ()
    ) -> Any:
        """:meth:`get`, or None when the read failed or the budget is spent, which makes the report ``partial``
        (*what* names the data left out). A rejected token still fails the report, and so does a failure of a kind
        in *raising*, which the caller handles (``too_large``, to read the same rows another way)."""
        try:
            return self.get(*segments, params=params)
        except CallBudget:
            self.partial(f"{what} not read: the report used its {self.call_budget} requests")
        except LibreNMSError as exc:
            if exc.kind == "auth" or exc.kind in raising:
                raise
            self.partial(f"{what} not read: LibreNMS answered {failure(exc)}")
        return None

    def partial(self, reason: str) -> None:
        if reason not in self.partial_reasons:
            self.partial_reasons.append(reason)

    @property
    def now(self) -> datetime:
        if self._now is None:
            self._now = datetime.now(timezone.utc)
        return self._now

    def clock(self) -> datetime:
        """LibreNMS's clock, for a view that must place a window before its first read: the ``Date`` of its smallest
        answer (``ping``: ``pong``, which any token may read and LibreNMS answers without a query) when no read has
        given one yet. A failed read still carries one; an answer without a ``Date`` leaves the plugin's clock. A
        rejected token fails the report."""
        if self._now is None and not self.calls:
            try:
                self.get("ping")
            except LibreNMSError as exc:
                if exc.kind == "auth":
                    raise
        return self.now

    def since(self, window: str) -> Since:
        """Where *window* (``today`` or a duration, :func:`window_arg`) starts in LibreNMS's server-local time, counted
        back from :attr:`now`. Without ``librenms_timezone`` that time cannot be placed exactly: the bound is then
        read as if LibreNMS's clock were as far behind UTC as any zone's, so it holds the whole window, and a note
        says how much more it may hold."""
        if window == TODAY:
            local = self.now.astimezone(self.zone)  # window_arg has checked there is one
            return Since(window, local.strftime("%Y-%m-%d 00:00:00"), True)
        start = self.now - timedelta(seconds=units.parse_duration(window) or 0)
        if self.zone is not None:
            return Since(window, start.astimezone(self.zone).strftime("%Y-%m-%d %H:%M:%S"), True)
        bound = (start - timedelta(seconds=EARLIEST_OFFSET_S)).strftime("%Y-%m-%d %H:%M:%S")
        spare = units.duration(EARLIEST_OFFSET_S + LATEST_OFFSET_S)
        self.notes.append(
            f"librenms_timezone is not set, so the window cannot be placed exactly in LibreNMS's server time: entries "
            f"from {bound} (server time) on were read, which holds the last {window} in any zone and up to {spare} "
            "before it; set librenms_timezone for an exact window"
        )
        return Since(window, bound, False)

    def when(self, value: Any, prefix: str) -> Dict[str, Any]:
        """``<prefix>``: a fault, log or bill time, ISO-8601 in ``librenms_timezone`` (without it as LibreNMS wrote
        it), and its age in seconds (``<prefix>_age_s``) and in words (``<prefix>_age``), none without a zone."""
        moment = units.server_time(value, self.zone)
        age = units.age(moment, self.now)
        shown = units.iso(moment) if moment is not None else (value or None)
        return {prefix: shown, f"{prefix}_age_s": age, f"{prefix}_age": units.duration(age)}

    def read_log(
        self,
        log: Log,
        scope: Scope,
        bound: str,
        *,
        max_entries: int,
        device_reads: int,
        keep: Callable[[Dict[str, Any]], Dict[str, Any]] = dict,
    ) -> Tuple[List[Dict[str, Any]], int | None]:
        """*log*'s entries from *bound* (server-local time) on, newest first, each as *keep* makes it once its page is
        read: each device's for a scope of at most *device_reads* devices, else every device's (the caller keeps the
        scope's); at most *max_entries*. Also how many entries LibreNMS holds there for the scope (None when it read
        every device's for a narrower scope, left a device unread, or a read did not say). What the cap, the request
        budget or a failed read leaves out makes the answer partial."""
        whole = not log.per_device or scope.ids is None or len(scope.ids) > device_reads  # every device's log
        if whole:
            targets: List[Tuple[Any, ...]] = [("logs", log.name)]
        else:  # none for a scope of no device (an empty group, a location or os no device has): nothing to read
            devices = self.devices()
            ids = sorted(scope.ids or (), key=lambda i: hostname_order(devices[i]))
            targets = [("logs", log.name, i) for i in ids]
        out: Dict[Any, Dict[str, Any]] = {}
        logged: int | None = 0
        unread = []
        for segments in targets:
            if len(out) >= max_entries or self.calls >= self.call_budget:
                unread.append(str(segments[-1]))
                continue
            holds = self._log_pages(log, segments, bound, out, max_entries, keep, required=len(targets) == 1)
            logged = None if logged is None or holds is None else logged + holds
        rows = sorted(out.values(), key=lambda row: log_order(log, row), reverse=True)
        if logged is not None and len(rows) < logged:
            self.partial(
                f"{log.what} holds {logged} entries from {bound} (server time) on for what was read; the newest "
                f"{len(rows)} were read (a report reads at most {max_entries}, {LOG_PAGE} a request): narrow the "
                "window or the scope"
            )
        if unread:
            self.partial(
                f"{log.what} of devices {', '.join(unread)} was not read: the report had read its {max_entries} "
                f"entries or used its {self.call_budget} requests; narrow the window or the scope"
            )
        narrower = whole and scope.ids is not None  # LibreNMS's count is every device's, not the scope's
        return rows, None if narrower or unread else logged

    def _log_pages(
        self,
        log: Log,
        segments: Tuple[Any, ...],
        bound: str,
        out: Dict[Any, Dict[str, Any]],
        max_entries: int,
        keep: Callable[[Dict[str, Any]], Dict[str, Any]],
        *,
        required: bool,
    ) -> int | None:
        """Read one log path page by page into *out*, by entry id (an entry logged while it is paged moves the rest
        on, so one may come twice), until the path is read, *out* holds *max_entries* or the request budget is spent.
        Returns LibreNMS's total for the path (None when not known). A failure fails the report when the path is
        *required* and nothing was read from it; otherwise it leaves the answer partial."""
        size, start, total = LOG_PAGE, 0, None
        where = "/".join(map(str, segments))
        while len(out) < max_entries:
            params = {"from": bound, "sortorder": "DESC", "limit": min(size, max_entries - len(out)), "start": start}
            try:
                rows, holds = self.page(*segments, params=params)
            except CallBudget:
                self.partial(
                    f"{log.what} was not read past entry {start} of {where}: the report used its {self.call_budget} "
                    "requests; narrow the window or the scope"
                )
                break
            except LibreNMSError as exc:
                if exc.kind == "too_large" and size > LOG_MIN_PAGE:
                    size = max(LOG_MIN_PAGE, size // 2)  # an alert-log entry carries every row its rule matched
                    continue
                if exc.kind == "auth" or (required and not start):
                    raise
                self.partial(f"{log.what} of {where} was not read past entry {start}: LibreNMS answered {exc.kind}")
                break
            total = holds if total is None else total
            for row in rows:
                out.setdefault(row.get(log.id_key), keep(row))
            start += len(rows)
            if len(rows) < params["limit"] or (total is not None and start >= total):
                break
        return total

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

    def ports_by_device(
        self, device_ids: Iterable[Any], what: str, rest: str, advice: str = ""
    ) -> Dict[Any, List[Dict[str, Any]]]:
        """The ports of each of *device_ids*, in that order, by name (:data:`PORT_NAME_COLUMNS`, never every column),
        for at most :data:`PORT_MAP_READS` devices, each read once per report. A read that fails or is past the
        budget leaves that device out and the answer partial, *what* naming what was not read (``{}``: the device's
        id); a note counts the devices past the cap in *rest*'s words (``{}``: how many), then *advice*."""
        ids = list(dict.fromkeys(device_ids))
        out: Dict[Any, List[Dict[str, Any]]] = {}
        for number, device_id in enumerate(ids):
            if number >= PORT_MAP_READS:
                self.notes.append(
                    f"{rest.format(len(ids) - PORT_MAP_READS)} (a report reads the ports of at most {PORT_MAP_READS} "
                    "devices for it)" + (f": {advice}" if advice else "")
                )
                break
            key = f"ports_of:{device_id}"
            if key not in self._memo:
                found = self.optional(
                    what.format(device_id), "devices", device_id, "ports", params={"columns": PORT_NAME_COLUMNS}
                )
                self._memo[key] = None if found is None else rows_of(found)
            if self._memo[key] is not None:
                out[device_id] = self._memo[key]
        return out

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
        ``location``, ``os`` and ``type`` narrow to theirs (all given must hold); ``port_group`` names the ports the
        view keeps (:attr:`Scope.port_ids`). Raises :class:`ArgumentError` for a key the view does not take,
        :class:`Ambiguous` for a device or group that could be several, and :class:`ReportError` for one that is
        none."""
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
        port_ids = None
        if "port_group" in raw:
            port_ids, summary["port_group"] = self._port_group(raw["port_group"])
        ids = chosen if chosen is not None else set(devices)
        out: Dict[str, Any] = {"device_count": len(ids), **summary}
        if len(ids) <= SCOPE_SHOWN:
            out["devices"] = [brief(devices[i]) for i in sorted(ids, key=lambda i: hostname_order(devices[i]))]
        if resolved:
            out["resolved"] = resolved[:SCOPE_SHOWN]
            if len(resolved) > SCOPE_SHOWN:
                out["resolved_count"] = len(resolved)
        return Scope(chosen, out, port_ids)

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
        """The members of a device group given by id or name (:meth:`_named_group`), read with
        ``devicegroups/{id}``, never ``full=1``."""
        groups = self.listing("groups", "devicegroups")
        group = self._named_group("group", "device group", groups, ref, group_candidate)
        rows = self.get("devicegroups", group["id"])
        devices = self.devices()
        ids = {int(row["device_id"]) for row in rows_of(rows) if is_digits(row.get("device_id"))} & set(devices)
        return ids, {"group_id": int(group["id"]), "name": group.get("name")}

    def _port_group(self, ref: Any) -> Tuple[Set[int], Dict[str, Any]]:
        """The port ids of a port group given by id or name (:meth:`_named_group`), read with ``port_groups/{id}``,
        never ``full=1`` (which returns every column of every port)."""
        groups = self.listing("port_groups", "port_groups")
        group = self._named_group("port_group", "port group", groups, ref, port_group_candidate)
        rows = self.get("port_groups", group["id"])
        ids = {int(row["port_id"]) for row in rows_of(rows) if is_digits(row.get("port_id"))}
        if not ids:
            self.notes.append(f"port group {_shown(group.get('name'))} holds no ports")
        return ids, {"port_group_id": int(group["id"]), "name": group.get("name"), "ports": len(ids)}

    def _named_group(
        self, key: str, what: str, groups: List[Dict[str, Any]], ref: Any, candidate: Callable[..., Dict[str, Any]]
    ) -> Dict[str, Any]:
        """The device or port group (one of *groups*) that *ref* names: its id, its name in any case, else the one
        group whose name (or description) matches every word of it. Several that could be meant are
        :class:`Ambiguous`; none is a :class:`ReportError` naming the groups there are."""
        text = term_arg(f"scope.{key}", ref)
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
                raise Ambiguous(key, text, [candidate(g, m) for m, g in ranked])
            else:
                names = ", ".join(_shown(g.get("name")) for g in groups[:10]) or "none"
                listed = "groups" if key == "group" else f"{what}s"
                raise ReportError(f"scope.{key} {_shown(text)}: LibreNMS has no {what} by that name or id; its "
                                  f"{listed}: {names}")  # fmt: skip
        group = found[0]
        if not is_digits(group.get("id")):
            raise ReportError(f"{what} {_shown(group.get('name'))} has no id LibreNMS can be asked by")
        return group

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
        naming = _CALL_AGAIN_WITH.get(exc.key, "its hostname or id")
        self.notes.append(
            f"scope.{exc.key} {_shown(exc.term)} could be any of {total} candidates: ask the user which one they "
            f"mean, then call again with {naming}; nothing was reported for it"
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
    if summary.get("group") or summary.get("port_group"):
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


def port_group_candidate(group: Dict[str, Any], found: fuzzy.Match) -> Dict[str, Any]:
    """A port group as a candidate: its id, name and description, and the score and why of its match."""
    row: Dict[str, Any] = {"kind": "port_group", "port_group_id": group.get("id"), "name": group.get("name")}
    if group.get("desc"):
        row["desc"] = group["desc"]
    row.update(score=found.score, why=found.why)
    return row


def port_candidate(port: Dict[str, Any], device: Dict[str, Any] | None, found: fuzzy.Match) -> Dict[str, Any]:
    """A port as a candidate: its id, its device, its label and state, and the score and why of its match."""
    row: Dict[str, Any] = {"kind": "port", "port_id": port.get("port_id")}
    row.update(brief(device) if device is not None else {"device_id": port.get("device_id")})
    row.update(port=port_label(port), status=port_state(port), score=found.score, why=found.why)
    return row


def sensor_status(sensor: Dict[str, Any]) -> str | None:
    """``critical``, ``warning`` or ``ok`` as LibreNMS's Sensor scopes decide it: past ``sensor_limit`` or below
    ``sensor_limit_low`` is critical, past the ``_warn`` limits a warning (a limit not set never trips); None
    without a current value, and for a ``state`` sensor, whose number means what LibreNMS's state translations say
    (none of its read routes returns them)."""
    current = units.number(sensor.get("sensor_current"))
    if current is None or sensor.get("sensor_class") == "state":
        return None

    def past(high: str, low: str) -> bool:
        top, bottom = units.number(sensor.get(high)), units.number(sensor.get(low))
        return (top is not None and current > top) or (bottom is not None and current < bottom)

    if past("sensor_limit", "sensor_limit_low"):
        return "critical"
    return "warning" if past("sensor_limit_warn", "sensor_limit_low_warn") else "ok"


def measured_on(sensor: Dict[str, Any], port: Dict[str, Any], entities: Set[str]) -> bool:
    """Whether LibreNMS ties *sensor* to *port* (both of one device): measured on the port's ifIndex
    (``entPhysicalIndex_measured`` ``ports``), or on the inventory entity of one of its transceivers (*entities*,
    their ``entity_physical_index``), as an optic's dBm, temperature and bias sensors are."""
    index = str(sensor.get("entPhysicalIndex") or "")
    if not index:
        return False
    on_port = sensor.get("entPhysicalIndex_measured") == "ports" and index == str(port.get("ifIndex"))
    return on_port or index in entities


def rows_of(value: Any) -> List[Dict[str, Any]]:
    """The object rows of a listing's value (anything else is none)."""
    return [row for row in value if isinstance(row, dict)] if isinstance(value, list) else []
