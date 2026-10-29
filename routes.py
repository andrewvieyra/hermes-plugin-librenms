"""The read-route allow-list behind ``librenms_query``, and turning a model's path into a request that is safe to send.

LibreNMS matches a GET against its routes in registration order (``routes/api.php``) and the first match wins, so
some routes shadow others: ``devices/{hostname}/{type}`` takes every device sub-path registered after it and
renders a graph, and ``ports/{portid}/fdb`` answers ``ports/mac/fdb``. :data:`ROUTES` keeps that order, so
:func:`match` decides exactly as LibreNMS would, and marks the routes the tool refuses (graph images, Oxidized
configurations, the GET that schedules a rediscovery, the ifName route).

:func:`prepare` also checks device references (hostnames and ids) and resolves them to ids before the query is sent,
and refuses a ``hostname`` param on a route that does not read it: LibreNMS answers an unknown device in several
filters, and a param a route ignores, with every device's rows. Likewise it refuses an object id LibreNMS would read
as no filter (``faults/0``, ``poller_group/0``) or as another id (``ports/1abc``), a params name PHP would read as
another name (`` limit``, ``hostname[]``), and a MAC that the exact-match MAC routes could never find; and it trims
the column lists LibreNMS would otherwise fail on. It sends ``offset`` as ``start`` on the logs routes, the only ones
LibreNMS pages, and refuses a ``start`` param on any other, which would answer with its first rows again.
"""

from __future__ import annotations

import functools
import math
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

from .client import API_PREFIX, LibreNMSClient, LibreNMSError, is_digits, path, seg
from .redact import clip, one_line


class QueryError(Exception):
    """A query refused before anything was sent; the message says why and is shown to the model."""


@dataclass(frozen=True)
class Route:
    """One GET route of the LibreNMS v0 API."""

    name: str  # LibreNMS route name, e.g. "get_device_ports" (legacy_* and index have none upstream)
    template: str  # "devices/{hostname}/ports"; {x?} marks an optional trailing parameter
    device_params: Tuple[str, ...] = ()  # path params that are device references, resolved to ids
    list_key: str | None = None  # envelope key holding the result
    paginated: bool = False  # logs routes (start/limit/sortorder)
    query_device_param: bool = False  # ?hostname= is honoured, and silently broadened when unknown
    refused: str | None = None  # why librenms_query does not call it
    rest: str | None = None  # path param that takes the rest of the path (LibreNMS `->where(x, '.*')`)
    id_params: Tuple[str, ...] = ()  # path params read as no filter (every object) when 0, or as another id when text
    mac_params: Tuple[str, ...] = ()  # path params compared exactly with the 12 hex digits LibreNMS stores
    alert_rows: bool = False  # rows carry the alert engine's ``details`` (the rule's query rows and contacts)
    columns: bool = False  # takes ``params.columns``, the only way to make its answer smaller


@dataclass
class PreparedQuery:
    """What :func:`prepare` hands the handler: ``client.get(request_path, params)``, then at most ``limit`` rows from
    ``offset`` on (sent as ``start`` on a logs route, which LibreNMS pages)."""

    route: Route
    request_path: str  # encoded segments, device references replaced by ids
    params: Dict[str, str]
    limit: int
    path: str = ""  # the normalised path as the model gave it (hostnames, not ids)
    offset: int = 0


_DEVICE = ("hostname",)
_ID = ("id",)
_PORT = ("portid",)
_BILL = ("bill_id",)
_SENSOR = ("sensor_id",)
_MAC = ("mac",)
_GRAPH = (
    "it returns a graph image, which this tool does not fetch; devices/{hostname}/graphs, .../health and "
    ".../wireless list the graphs that exist"
)
_GRAPH_FALLBACK = (
    "LibreNMS serves every devices/{hostname}/<name> path it has no other route for as a graph image, so a "
    "mistyped device sub-path lands here too; query the path '' for the route names"
)
_DISCOVER = "this GET schedules a rediscovery (a write); plan it with librenms_plan, op discover"
_OXIDIZED_SEARCH = (
    "it searches every stored device configuration, which would confirm whether a guessed password or community "
    "is in use"
)
_OXIDIZED_CONFIG = "it returns a device's full stored configuration, secrets included"
_IFNAME = (
    "ifName routes misread names that contain /; find the port_id with devices/{hostname}/ports (params "
    "columns=port_id,ifName) and query ports/{port_id}"
)

# Every GET route of routes/api.php, in registration order (specs/ln-route-index.md, section A).
ROUTES: Tuple[Route, ...] = (
    Route("ping", "ping"),
    Route("server_info", "system", list_key="system"),
    Route("index", ""),
    Route("get_alert_template", "alert_templates/{id}", list_key="alert_templates", id_params=_ID),
    Route("list_alert_templates", "alert_templates", list_key="alert_templates"),
    Route("list_pollers", "pollers", list_key="pollers"),
    Route("list_poller_log", "pollers/log", list_key="log"),
    Route("list_bgp", "bgp", list_key="bgp_sessions", query_device_param=True),
    Route("get_bgp", "bgp/{id}", list_key="bgp_session"),
    Route("list_ospf", "ospf", list_key="ospf_neighbours", query_device_param=True),
    Route("list_ospf_ports", "ospf_ports", list_key="ospf_ports"),
    Route("list_ospfv3", "ospfv3", list_key="ospfv3_neighbours", query_device_param=True),
    Route("list_ospfv3_ports", "ospfv3_ports", list_key="ospfv3_ports", query_device_param=True),
    # exact hostname match only (no id resolution upstream), so the value is sent as given
    Route("list_oxidized", "oxidized/{hostname?}"),
    Route("search_oxidized", "oxidized/config/search/{searchstring}", refused=_OXIDIZED_SEARCH),
    Route("get_oxidized_config", "oxidized/config/{device_name}", refused=_OXIDIZED_CONFIG),
    Route("get_devices_by_group", "devicegroups/{name}", list_key="devices"),
    Route("get_device_groups", "devicegroups", list_key="groups"),
    Route("get_port_groups", "port_groups", list_key="groups"),
    Route("get_ports_by_group", "port_groups/{name}", list_key="ports"),
    Route("get_graph_by_portgroup_multiport_bits", "portgroups/multiport/bits/{id}", refused=_GRAPH),
    Route("get_graph_by_portgroup", "portgroups/{group}", refused=_GRAPH),
    Route("get_alert", "faults/{id}", list_key="alerts", id_params=_ID, alert_rows=True),
    Route("list_alerts", "faults", list_key="alerts", alert_rows=True),
    Route("legacy_get_alert", "alerts/{id}", list_key="alerts", id_params=_ID, alert_rows=True),
    Route("legacy_list_alerts", "alerts", list_key="alerts", alert_rows=True),
    Route("get_alert_rule", "rules/{id}", list_key="rules", id_params=_ID),
    Route("list_alert_rules", "rules", list_key="rules"),
    Route("get_vrf", "routing/vrf/{id}", list_key="vrf"),
    Route("list_ipsec", "routing/ipsec/data/{hostname}", device_params=_DEVICE, list_key="ipsec"),
    Route("list_services", "services", list_key="services"),
    Route("list_services_device", "services/{hostname}", device_params=_DEVICE, list_key="services"),
    Route("get_poller_group", "poller_group/{poller_group_id_or_name?}", list_key="get_poller_group"),
    Route("get_device", "devices/{hostname}", device_params=_DEVICE, list_key="devices"),
    Route("trigger_device_discovery", "devices/{hostname}/discover", refused=_DISCOVER),
    Route("device_availability", "devices/{hostname}/availability", device_params=_DEVICE, list_key="availability"),
    Route("device_outages", "devices/{hostname}/outages", device_params=_DEVICE, list_key="outages"),
    Route("get_health_graph", "devices/{hostname}/graphs/health/{type}/{sensor_id?}", refused=_GRAPH),
    Route("get_wireless_graph", "devices/{hostname}/graphs/wireless/{type}/{sensor_id?}", refused=_GRAPH),
    Route("get_vlans", "devices/{hostname}/vlans", device_params=_DEVICE, list_key="vlans"),
    Route("list_links_device", "devices/{hostname}/links", device_params=_DEVICE, list_key="links"),
    Route("get_graphs", "devices/{hostname}/graphs", device_params=_DEVICE, list_key="graphs"),
    Route("get_fdb", "devices/{hostname}/fdb", device_params=_DEVICE, list_key="ports_fdb"),
    Route("get_nac", "devices/{hostname}/nac", device_params=_DEVICE, list_key="ports_nac"),
    Route(
        "list_available_health_graphs",
        "devices/{hostname}/health/{type?}/{sensor_id?}",
        device_params=_DEVICE,
        list_key="graphs",
        id_params=_SENSOR,
    ),
    Route(
        "list_available_wireless_graphs",
        "devices/{hostname}/wireless/{type?}/{sensor_id?}",
        device_params=_DEVICE,
        list_key="graphs",
        id_params=_SENSOR,
    ),
    Route(
        "get_device_wireless_sensors",
        "devices/{hostname}/wireless-sensors",
        device_params=_DEVICE,
        list_key="wireless_sensors",
    ),
    Route("get_device_ports", "devices/{hostname}/ports", device_params=_DEVICE, list_key="ports", columns=True),
    Route("get_ip_addresses", "devices/{hostname}/ip", device_params=_DEVICE, list_key="addresses"),
    Route("get_port_stack", "devices/{hostname}/port_stack", device_params=_DEVICE, list_key="mappings"),
    Route("get_transceivers", "devices/{hostname}/transceivers", device_params=_DEVICE, list_key="transceivers"),
    Route("get_components", "devices/{hostname}/components", device_params=_DEVICE, list_key="components"),
    Route("get_device_groups_device", "devices/{hostname}/groups", device_params=_DEVICE, list_key="groups"),
    Route(
        "device_under_maintenance",
        "devices/{hostname}/maintenance",
        device_params=_DEVICE,
        list_key="is_under_maintenance",
    ),
    Route("get_port_stats_by_port_hostname", "devices/{hostname}/ports/{ifname}", refused=_IFNAME, rest="ifname"),
    Route("get_graph_by_port_hostname", "devices/{hostname}/ports/{ifname}/{type}", refused=_GRAPH),
    Route("get_graph_by_service", "devices/{hostname}/services/{id}/graphs/{datasource}", refused=_GRAPH),
    Route("get_graph_generic_by_hostname", "devices/{hostname}/{type}", refused=_GRAPH_FALLBACK),
    Route("list_devices", "devices", list_key="devices"),
    Route("list_eventlog", "logs/eventlog/{hostname?}", device_params=_DEVICE, list_key="logs", paginated=True),
    Route("list_syslog", "logs/syslog/{hostname?}", device_params=_DEVICE, list_key="logs", paginated=True),
    Route(
        "list_alertlog",
        "logs/alertlog/{hostname?}",
        device_params=_DEVICE,
        list_key="logs",
        paginated=True,
        alert_rows=True,
    ),
    Route("list_authlog", "logs/authlog", list_key="logs", paginated=True),
    Route("get_port_info", "ports/{portid}", list_key="port", id_params=_PORT),
    Route("get_port_fdb", "ports/{portid}/fdb", list_key="macs", id_params=_PORT),
    Route("get_port_ip_info", "ports/{portid}/ip", list_key="addresses", id_params=_PORT),
    Route("get_port_transceiver", "ports/{portid}/transceiver", list_key="transceivers", id_params=_PORT),
    Route("search_ports", "ports/search/{field}/{search?}", list_key="ports", rest="search", columns=True),
    Route("search_mac", "ports/mac/{search}", list_key="ports"),
    Route("get_all_ports", "ports", list_key="ports", columns=True),
    Route("get_port_description", "ports/{portid}/description", list_key="port_description", id_params=_PORT),
    Route("list_bills", "bills", list_key="bills"),
    Route("get_bill", "bills/{bill_id}", list_key="bills", id_params=_BILL),
    Route("get_bill_graph", "bills/{bill_id}/graphs/{graph_type}", refused=_GRAPH),
    Route("get_bill_graphdata", "bills/{bill_id}/graphdata/{graph_type}", list_key="graph_data", id_params=_BILL),
    Route("get_bill_history", "bills/{bill_id}/history", list_key="bill_history", id_params=_BILL),
    Route("get_bill_history_graph", "bills/{bill_id}/history/{bill_hist_id}/graphs/{graph_type}", refused=_GRAPH),
    Route(
        "get_bill_history_graphdata",
        "bills/{bill_id}/history/{bill_hist_id}/graphdata/{graph_type}",
        list_key="graph_data",
        id_params=_BILL,
    ),
    Route("list_cbgp", "routing/bgp/cbgp", list_key="bgp_counters", query_device_param=True),
    Route("list_vrf", "routing/vrf", list_key="vrfs", query_device_param=True),
    Route("list_mpls_services", "routing/mpls/services", list_key="mpls_services", query_device_param=True),
    Route("list_mpls_saps", "routing/mpls/saps", list_key="saps", query_device_param=True),
    Route("list_fdb", "resources/fdb", list_key="ports_fdb"),
    Route("list_fdb_mac", "resources/fdb/{mac}", list_key="ports_fdb", mac_params=_MAC),
    Route("list_fdb_detail", "resources/fdb/{mac}/detail", list_key="ports_fdb"),
    Route("list_ip_addresses", "resources/ip/addresses/{address_family?}", list_key="ip_addresses"),
    Route("list_arp", "resources/ip/arp/{query}/{cidr?}", list_key="arp"),
    Route("list_ip_networks", "resources/ip/networks/{address_family?}", list_key="ip_networks"),
    Route("get_network_ip_addresses", "resources/ip/networks/{id}/ip", list_key="addresses", id_params=_ID),
    Route("list_links", "resources/links", list_key="links"),
    Route("get_link", "resources/links/{id}", list_key="link"),
    Route("list_nac", "resources/nac", list_key="ports_nac"),
    Route("list_nac_mac", "resources/nac/{mac}", list_key="ports_nac", mac_params=_MAC),
    Route("list_sensors", "resources/sensors", list_key="sensors"),
    Route("list_vlans", "resources/vlans", list_key="vlans", query_device_param=True),
    Route("list_locations", "resources/locations", list_key="locations"),
    Route("get_inventory", "inventory/{hostname}", device_params=_DEVICE, list_key="inventory"),
    Route("get_inventory_for_device", "inventory/{hostname}/all", device_params=_DEVICE, list_key="inventory"),
    Route("get_port_security_by_port", "port_security/port/{portid}", list_key="port", id_params=_PORT),
    Route("get_port_security_by_hostname", "port_security/device/{hostname}", device_params=_DEVICE, list_key="port"),
    Route("get_port_security", "port_security", list_key="port"),
    Route("get_location", "location/{location_id_or_name}", list_key="get_location"),
)

DEFAULT_LIMIT = 50
_CONTROL_RE = re.compile("[\x00-\x1f\x7f-\x9f\ud800-\udfff]")
_INTEGER_RE = re.compile(r"^\s*-?\d+\s*$")
_COLUMN_RE = re.compile(r"^[A-Za-z0-9_]+$")
# The spellings of a whole MAC address: bare, six groups of one or two hex digits joined by : or -, or Cisco's three
# groups of four joined by dots.
_MAC_RE = re.compile(
    r"^(?:[0-9a-f]{12}|[0-9a-f]{1,2}(?::[0-9a-f]{1,2}){5}|[0-9a-f]{1,2}(?:-[0-9a-f]{1,2}){5}"
    r"|[0-9a-f]{4}(?:\.[0-9a-f]{4}){2})$",
    re.IGNORECASE,
)
# Names prepare() reads or rewrites itself: written in another letter case, LibreNMS (whose names are
# case-sensitive) would ignore the param while the plugin's view of the query differs.
_READ_NAMES = ("hostname", "limit", "start", "sortorder", "columns")
_CANDIDATES = 5
_REFUSED_PARAMS = {
    "api_token": "params.api_token is not allowed: the token is sent only in the X-Auth-Token header",
    "_method": "params._method is not allowed: Laravel reads it as an HTTP method override",
}
_FORBIDDEN_HOSTNAME = (
    "LibreNMS answered 403 for hostname '{0}': it does not exist or this token cannot see it (LibreNMS returns 403 "
    "for unknown hostnames to tokens without global read); use the device id or a token with global read"
)
_FORBIDDEN_ID = "LibreNMS answered 403 for device id {0}: this token cannot see that device"


@functools.cache
def _parts(template: str) -> Tuple[Tuple[str, bool, bool], ...]:
    """``(text, is_param, optional)`` per template segment: ``("devices", False, False)``, ``("type", True, True)``."""
    parts = []
    for piece in template.split("/") if template else ():
        if piece.startswith("{"):
            name = piece.strip("{}")
            parts.append((name.rstrip("?"), True, name.endswith("?")))
        else:
            parts.append((piece, False, False))
    return tuple(parts)


def _bind(route: Route, segments: list) -> Dict[str, str] | None:
    """The path params when *segments* match *route*'s template as Laravel matches it, else ``None``."""
    values: Dict[str, str] = {}
    index = 0
    for text, is_param, optional in _parts(route.template):
        if index >= len(segments):
            if optional:  # an optional parameter ends the template (Laravel allows them only at the end)
                break
            return None
        if not is_param:
            if segments[index] != text:
                return None
            index += 1
        elif text == route.rest:
            values[text] = "/".join(segments[index:])
            index = len(segments)
        else:
            values[text] = segments[index]
            index += 1
    return values if index == len(segments) else None


def normalise(path_: Any) -> str:
    """The path relative to ``/api/v0`` without surrounding slashes (``/api/v0/devices/`` -> ``devices``). Refuses
    what would change which route or host is reached: a scheme or host, a query string or fragment, percent
    escapes, backslashes, control characters, empty and dot segments. Names and hostnames are given unencoded."""
    if not isinstance(path_, str):
        raise QueryError(f"path must be a string (got {type(path_).__name__})")
    text = path_.strip()
    if _CONTROL_RE.search(text):
        raise QueryError("path must not contain control characters")
    if "://" in text or text.startswith("//"):
        raise QueryError(f"path must be relative to /{API_PREFIX}, without a scheme or host")
    if "?" in text:
        raise QueryError("put query parameters in params, not in the path")
    for char in "#%\\":
        if char in text:
            raise QueryError(f"path must not contain {char!r}; give names and hostnames unencoded")
    text = text.strip("/")
    if text == API_PREFIX:
        text = ""
    elif text.startswith(f"{API_PREFIX}/"):
        text = text[len(API_PREFIX) + 1 :]
    segments = text.split("/") if text else []
    if "" in segments:
        raise QueryError("path must not contain an empty segment (//)")
    if any(segment in (".", "..") for segment in segments):
        raise QueryError("path must not contain . or .. segments")
    return "/".join(segments)


def match(path_: str) -> Tuple[Route, Dict[str, str]]:
    """The route LibreNMS would answer *path_* with, and its path params (as given, not encoded). Raises QueryError
    for a malformed path, a path no read route matches, and a match on a refused route."""
    normalised = normalise(path_)
    segments = normalised.split("/") if normalised else []
    for route in ROUTES:
        values = _bind(route, segments)
        if values is None:
            continue
        if route.refused:
            raise QueryError(
                f"GET /{API_PREFIX}/{normalised} is LibreNMS's {route.name}, which is refused: {route.refused}"
            )
        return route, values
    raise QueryError(f"no LibreNMS v0 read route matches {normalised!r}; query the path '' for the route names")


def _php_name(key: str) -> Tuple[str, bool]:
    """The name LibreNMS reads query parameter *key* as, and whether PHP hands it over as an array. PHP drops the
    spaces before the name and turns the spaces and dots in it into underscores (``" limit"`` is ``limit``,
    ``"host.name"`` is ``host_name``); a ``[`` with a ``]`` after it makes an array of the name before it
    (``hostname[]`` and ``hostname[0]`` are both ``hostname``), and one without becomes an underscore too."""
    name = key.lstrip(" ")
    head, bracket, tail = name.partition("[")
    head = head.replace(" ", "_").replace(".", "_")
    if bracket and "]" in tail:
        return head, True
    if bracket:
        return head + "_" + re.sub(r"[ .\[]", "_", tail), False
    return head, False


def _scalar(key: str, value: Any) -> str:
    if isinstance(value, bool):  # PHP reads the string "false" as true
        return "1" if value else "0"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float) and math.isfinite(value):
        return str(value)
    if isinstance(value, str):
        if _CONTROL_RE.search(value):
            raise QueryError(f"params.{key} must not contain control characters")
        return value
    raise QueryError(f"params.{key} must be a string, a number, a boolean or a list of them")


def _query(params: Any) -> Dict[str, str]:
    """*params* as the query LibreNMS gets: text values, lists joined with commas (``state=0,1,2``), and the
    ``columns`` list trimmed. Every name must be one PHP reads as written, so the query the plugin checks and clamps
    is the query LibreNMS runs: PHP keeps the last of two names it reads alike, so ``{"limit": 5, " limit": -1}``
    would reach LibreNMS as ``limit=-1``, and ``hostname[]`` as a ``hostname`` the device check never saw."""
    if params is None:
        return {}
    if not isinstance(params, dict):
        raise QueryError("params must be an object of query parameters")
    query: Dict[str, str] = {}
    for key, value in params.items():
        if not isinstance(key, str) or not key.strip() or _CONTROL_RE.search(key):
            raise QueryError("params keys must be non-empty text without control characters")
        name, array = _php_name(key)
        refused = _REFUSED_PARAMS.get(name.lower())
        if refused:
            raise QueryError(refused)
        if array:
            raise QueryError(
                f"params key {key[:40]!r} reaches LibreNMS as an array named {name[:40]!r}; use plain names (a list "
                "value is sent joined with commas)"
            )
        if name != key:
            raise QueryError(
                f"params key {key[:40]!r} reaches LibreNMS as {name[:40]!r} (PHP drops leading spaces and turns "
                "spaces, dots and [ into _); write the name LibreNMS reads"
            )
        if key.lower() in _READ_NAMES and key != key.lower():
            raise QueryError(f"params key {key!r}: LibreNMS reads names as written; write it as {key.lower()!r}")
        items = value if isinstance(value, (list, tuple)) else [value]
        query[key] = ",".join(_scalar(key, item) for item in items)
        if key == "columns":
            query[key] = _column_list(query[key], "params.columns")
    return query


def _column_list(text: str, what: str) -> str:
    """A comma-separated list of column names with the blanks around each dropped. LibreNMS checks the trimmed names
    but selects them as sent, so ``"port_id, ifName"`` fails in SQL as an opaque HTTP 500."""
    names = [name.strip() for name in text.split(",") if name.strip()]
    for name in names:
        if not _COLUMN_RE.match(name):
            raise QueryError(
                f"{what} takes column names separated by commas, e.g. port_id,ifName,ifAlias; {name[:40]!r} is not one"
            )
    return ",".join(names)


def _object_id(route: Route, name: str, value: str) -> str:
    """*value* when it is a positive whole number. Several of LibreNMS's handlers behind these routes filter by id
    only when it is set (``when($id)``, ``$id > 0``, ``is_numeric``, ``if ($port_id)``, ``$sensor_id ? …``), so
    ``faults/0`` lists every open fault, ``bills/x`` every bill, ``port_security/port/0`` every port's entries and
    ``devices/{hostname}/health/{type}/0`` every sensor of the class, under a path that names one; and the others
    compare the text with an integer column, which MySQL reads as its leading number (``ports/1abc`` is port 1)."""
    if is_digits(value) and int(value) > 0:
        return str(int(value))
    raise QueryError(
        f"{{{name}}} must be a positive whole number (got {value[:40]!r}): LibreNMS's {route.name} reads 0 or text "
        "as no filter, or as another id, and would answer with other objects"
    )


def _mac(route: Route, value: str) -> str:
    """*value* as the 12 lowercase hex digits LibreNMS stores. ``resources/fdb/{mac}`` and ``resources/nac/{mac}``
    compare the segment with the column exactly, so a MAC written with separators is never found and the empty
    answer would read as "not on the network"; and ``0`` reads as no filter at all."""
    text = value.strip()
    if not _MAC_RE.match(text):
        raise QueryError(
            f"{route.template} takes a whole MAC address (00:11:22:33:44:55, 00-11-22-33-44-55, 0011.2233.4455 or "
            f"001122334455), not {value[:40]!r}"
        )
    if ":" in text or "-" in text:  # by the separator, not the length: 0:0:c:7:ac:1 is 12 characters too
        return "".join(part.zfill(2) for part in re.split("[:-]", text)).lower()
    return text.replace(".", "").lower()


def _integer(name: str, value: Any) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str) and _INTEGER_RE.match(value):
        return int(value)
    raise QueryError(f"{name} must be an integer (got {str(value)[:40]!r})")


def _limit(value: Any, cap: int) -> int:
    """At least 1 and at most *cap*: LibreNMS reads a negative logs limit as no limit at all."""
    return max(1, min(DEFAULT_LIMIT if value is None else _integer("limit", value), cap))


def _offset(value: Any) -> int:
    number = _integer("offset", value)
    if number < 0:
        raise QueryError(f"offset must be 0 or more (got {number}): it counts the rows to skip")
    return number


def _sortorder(value: str | None) -> str:
    """``ASC`` or ``DESC`` exactly: LibreNMS sorts descending only for the exact string ``DESC``."""
    if value is None:
        return "DESC"
    if value.strip().lower() not in ("asc", "desc"):
        raise QueryError(f"sortorder must be asc or desc (got {value[:40]!r})")
    return value.strip().upper()


def _device_id(client: Any, value: str) -> str:
    """The numeric id for a device reference, checked with ``GET devices/{reference}``, which reads digits as an id
    and anything else as an exact hostname. An id is checked too: several LibreNMS filters read an unknown id, or
    ``0``, as no filter at all."""
    numeric = is_digits(value)
    if numeric and int(value) == 0:
        raise QueryError("no LibreNMS device has id 0 (LibreNMS reads 0 as no device filter at all)")
    if "/" in value:
        raise QueryError(f"invalid device reference {value[:100]!r}: no hostname holds a '/'")
    what = f"id {value}" if numeric else f"hostname '{value}'"
    try:
        target = path("devices", value)
    except LibreNMSError as exc:
        raise QueryError(f"invalid device reference: {exc}") from None
    try:
        body = client.get(target)
    except LibreNMSError as exc:
        if exc.kind == "not_found" and not numeric:
            raise QueryError(_unknown_hostname(client, value)) from None
        if exc.kind == "not_found":
            raise QueryError(f"no LibreNMS device has {what}") from None
        if exc.kind == "forbidden":
            raise QueryError((_FORBIDDEN_ID if numeric else _FORBIDDEN_HOSTNAME).format(value)) from None
        raise
    rows = LibreNMSClient.result(body, "devices")
    found = rows[0].get("device_id") if isinstance(rows, list) and rows and isinstance(rows[0], dict) else None
    if found is None or not is_digits(str(found)):
        raise QueryError(f"LibreNMS returned no device id for {what}")
    return str(found)


def _unknown_hostname(client: Any, value: str) -> str:
    """The refusal for a hostname LibreNMS does not hold, naming up to :data:`_CANDIDATES` hostnames that contain its
    first label (``core-sw1`` for ``core-sw1.example.com``), or display names that do, so the model can ask the user
    instead of guessing. A label shorter than three characters, or one holding ``%`` (a LIKE wildcard), would match
    half the inventory and is not searched; a failed search only leaves the candidates out."""
    message = f"no LibreNMS device has hostname '{value}' (hostnames match exactly)"
    label = value.strip().split(".", 1)[0]
    found: List[str] = []
    if len(label) >= 3 and "%" not in label:
        for kind in ("hostname", "display"):
            try:
                rows = LibreNMSClient.result(client.get("devices", {"type": kind, "query": label}), "devices")
            except Exception:  # only a hint: the refusal stands without it
                break
            found = [
                row["hostname"] for row in rows or [] if isinstance(row, dict) and isinstance(row.get("hostname"), str)
            ]
            if found:
                break
    if not found:
        return message + "; find the stored one with the path 'devices' and params type=hostname, query=<part of it>"
    lowered = label.lower()
    found.sort(key=lambda name: (not name.lower().startswith(lowered), len(name), name))
    shown = ", ".join(clip(one_line(name), 100) for name in found[:_CANDIDATES])
    more = f" and {len(found) - _CANDIDATES} more" if len(found) > _CANDIDATES else ""
    return f"{message}; devices whose hostname or display name contains '{label}': {shown}{more}"


def too_large_hint(route: Route, normalised: str) -> str:
    """How to get *route*'s answer under the client's size cap. ``limit`` helps only on the logs routes, which LibreNMS
    pages; everywhere else it sends every row and the limit applies to what was read, as do ``offset``, ``where`` and
    ``sort``, so asking with them fails alike."""
    if route.paginated:
        return "ask for fewer rows at a time with a smaller limit, and page with offset"
    hints = []
    if route.columns:
        hints.append("select fewer columns with params.columns (e.g. port_id,ifName,ifOperStatus)")
    if route.name == "list_devices":
        hints.append("filter with params type and query (e.g. type=location, query=SFO-1)")
    if route.query_device_param:
        hints.append("filter by device with params.hostname")
    where = _device_filter_path(normalised) or _NARROWER.get(route.name)
    if where:
        hints.append(f"query the path '{where}' for one device's rows")
    if not hints:
        hints.append("read one object's or one device's path instead")
    return "; ".join(hints) + (
        " (limit, offset, where and sort do not help here: LibreNMS sends every row and they apply after)"
    )


# Where a fleet-wide route has a per-device counterpart elsewhere in the tree.
_NARROWER = {
    "list_devices": "devices/<hostname>",
    "get_all_ports": "devices/<hostname>/ports",
    "search_ports": "devices/<hostname>/ports",
    "list_fdb": "devices/<hostname>/fdb",
    "list_nac": "devices/<hostname>/nac",
    "list_links": "devices/<hostname>/links",
    "list_sensors": "devices/<hostname>/health",
    "list_ip_addresses": "devices/<hostname>/ip",
    "list_vlans": "devices/<hostname>/vlans",
}


def _device_filter_path(normalised: str) -> str | None:
    """The path that gives *normalised*'s rows for one device, when LibreNMS has one (``logs/eventlog`` ->
    ``logs/eventlog/<hostname>``, ``services`` -> ``services/<hostname>``)."""
    candidate = f"{normalised}/<hostname>" if normalised else "<hostname>"
    try:
        _route, values = match(candidate)
    except QueryError:
        return None
    return candidate if values.get("hostname") == "<hostname>" else None


def _request_path(route: Route, values: Dict[str, str]) -> str:
    pieces = []
    for text, is_param, _optional in _parts(route.template):
        if not is_param:
            pieces.append(text)
        elif text in values:
            raw = values[text]
            pieces.extend(seg(piece) for piece in (raw.split("/") if text == route.rest else [raw]))
        else:
            break
    return "/".join(pieces)


def prepare(
    client: Any,
    path_: Any,
    params: Any,
    limit: Any,
    settings: Any,
    offset: Any = None,
    row_args: Tuple[str, ...] = (),
) -> PreparedQuery:
    """Everything between the model's ``path``/``params``/``limit``/``offset`` and the request: normalise and match
    the path, check and join the params, apply the logs defaults and every clamp, check object ids, normalise MACs and
    column lists, resolve device references (path params and ``?hostname=``) to ids, and build the request path from
    encoded segments. A ``hostname`` param on a route that does not read it is refused: LibreNMS would ignore it and
    return every device's rows. ``offset`` is sent as ``start`` on a logs route and applied by the handler to the rows
    read elsewhere, where a ``start`` param, which LibreNMS ignores there, is refused; *row_args* names the other
    arguments the handler applies to the rows read (``where``, ``sort``), which a logs route refuses: LibreNMS pages
    it, so they would see one page. Local checks run before any lookup is sent. Every refusal is a QueryError; a
    failed lookup other than 403/404 raises the LibreNMSError."""
    normalised = normalise(path_)
    route, values = match(normalised)
    query = _query(params)
    if "hostname" in query and not route.query_device_param:
        where = _device_filter_path(normalised)
        raise QueryError(
            f"LibreNMS's {route.name} does not read params.hostname, so it would return every device's rows"
            + (f"; query the path '{where}' for one device's rows" if where else "")
        )
    if "offset" in query:
        raise QueryError("LibreNMS reads no params.offset; page with the offset argument (a result's next_offset)")
    for name in route.id_params:
        if name in values:
            values[name] = _object_id(route, name, values[name])
    for name in route.mac_params:
        if name in values:
            values[name] = _mac(route, values[name])
    if route.name == "get_poller_group" and values.get("poller_group_id_or_name") == "0":  # PHP's empty("0") is true
        raise QueryError(
            "poller group 0 is LibreNMS's General group, which has no poller_groups row, and LibreNMS reads "
            "poller_group/0 as no group at all and answers with every poller group; a device with poller_group 0 is "
            "in the General group"
        )
    if route.name == "search_ports" and "search" in values:  # {field} is a column list only when a search follows
        values["field"] = _column_list(values["field"], "the {field} of ports/search/{field}/{search}")
        if not values["field"]:
            raise QueryError("ports/search/{field}/{search} needs column names in {field}, e.g. ifAlias,ifName")
    cap = settings.max_query_results
    skip = None if offset is None else _offset(offset)
    if route.paginated:
        if row_args:
            device = _device_filter_path(normalised)  # logs/syslog/<hostname>; none on logs/authlog or a device's path
            raise QueryError(
                f"{' and '.join(row_args)} cannot apply to {normalised}: LibreNMS pages the logs routes itself, so "
                "they would see one page only; narrow with "
                + (f"the device path ({device}) and " if device else "")
                + "params from/to (a time or an id), order with params.sortorder (asc/desc), and page with offset"
            )
        count = _limit(query.get("limit") if limit is None else limit, cap)
        start = max(0, _integer("start", query["start"])) if query.get("start") else None
        if skip is not None and start is not None and skip != start:
            raise QueryError(f"offset {skip} and params.start {start} disagree; page with offset alone")
        skip = start if skip is None else skip
        query["limit"] = str(count)
        query["start"] = str(skip or 0)
        query["sortorder"] = _sortorder(query.get("sortorder"))
    else:
        if "start" in query:
            raise QueryError(
                f"LibreNMS's {route.name} does not read params.start (it pages the logs routes only), so it would "
                "answer with the first rows again; page with offset, which is applied to the rows read"
            )
        count = _limit(limit, cap)
    for name in route.device_params:
        if name in values:
            values[name] = _device_id(client, values[name])
    if "hostname" in query:
        query["hostname"] = _device_id(client, query["hostname"])
    return PreparedQuery(route, _request_path(route, values), query, count, normalised, skip or 0)
