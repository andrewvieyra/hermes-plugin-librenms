"""The read-route allow-list behind ``librenms_query``, and turning a model's path into a request that is safe to send.

LibreNMS matches a GET against its routes in registration order (``routes/api.php``) and the first match wins, so
some routes shadow others: ``devices/{hostname}/{type}`` takes every device sub-path registered after it and
renders a graph, and ``ports/{portid}/fdb`` answers ``ports/mac/fdb``. :data:`ROUTES` keeps that order, so
:func:`match` decides exactly as LibreNMS would, and marks the routes the tool refuses (graph images, Oxidized
configurations, the GET that schedules a rediscovery, the ifName route).

:func:`prepare` also checks device references (hostnames and ids) and resolves them to ids before the query is sent,
and refuses a ``hostname`` param on a route that does not read it: LibreNMS answers an unknown device in several
filters, and a param a route ignores, with every device's rows.
"""

from __future__ import annotations

import functools
import math
import re
from dataclasses import dataclass
from typing import Any, Dict, Tuple

from .client import API_PREFIX, LibreNMSClient, LibreNMSError, is_digits, path, seg


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


@dataclass
class PreparedQuery:
    """What :func:`prepare` hands the handler: ``client.get(request_path, params)``, then at most ``limit`` rows."""

    route: Route
    request_path: str  # encoded segments, device references replaced by ids
    params: Dict[str, str]
    limit: int
    path: str = ""  # the normalised path as the model gave it (hostnames, not ids)


_DEVICE = ("hostname",)
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
    Route("get_alert_template", "alert_templates/{id}", list_key="alert_templates"),
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
    Route("get_alert", "faults/{id}", list_key="alerts"),
    Route("list_alerts", "faults", list_key="alerts"),
    Route("legacy_get_alert", "alerts/{id}", list_key="alerts"),
    Route("legacy_list_alerts", "alerts", list_key="alerts"),
    Route("get_alert_rule", "rules/{id}", list_key="rules"),
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
    ),
    Route(
        "list_available_wireless_graphs",
        "devices/{hostname}/wireless/{type?}/{sensor_id?}",
        device_params=_DEVICE,
        list_key="graphs",
    ),
    Route(
        "get_device_wireless_sensors",
        "devices/{hostname}/wireless-sensors",
        device_params=_DEVICE,
        list_key="wireless_sensors",
    ),
    Route("get_device_ports", "devices/{hostname}/ports", device_params=_DEVICE, list_key="ports"),
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
    Route("list_alertlog", "logs/alertlog/{hostname?}", device_params=_DEVICE, list_key="logs", paginated=True),
    Route("list_authlog", "logs/authlog", list_key="logs", paginated=True),
    Route("get_port_info", "ports/{portid}", list_key="port"),
    Route("get_port_fdb", "ports/{portid}/fdb", list_key="macs"),
    Route("get_port_ip_info", "ports/{portid}/ip", list_key="addresses"),
    Route("get_port_transceiver", "ports/{portid}/transceiver", list_key="transceivers"),
    Route("search_ports", "ports/search/{field}/{search?}", list_key="ports", rest="search"),
    Route("search_mac", "ports/mac/{search}", list_key="ports"),
    Route("get_all_ports", "ports", list_key="ports"),
    Route("get_port_description", "ports/{portid}/description", list_key="port_description"),
    Route("list_bills", "bills", list_key="bills"),
    Route("get_bill", "bills/{bill_id}", list_key="bills"),
    Route("get_bill_graph", "bills/{bill_id}/graphs/{graph_type}", refused=_GRAPH),
    Route("get_bill_graphdata", "bills/{bill_id}/graphdata/{graph_type}", list_key="graph_data"),
    Route("get_bill_history", "bills/{bill_id}/history", list_key="bill_history"),
    Route("get_bill_history_graph", "bills/{bill_id}/history/{bill_hist_id}/graphs/{graph_type}", refused=_GRAPH),
    Route(
        "get_bill_history_graphdata",
        "bills/{bill_id}/history/{bill_hist_id}/graphdata/{graph_type}",
        list_key="graph_data",
    ),
    Route("list_cbgp", "routing/bgp/cbgp", list_key="bgp_counters", query_device_param=True),
    Route("list_vrf", "routing/vrf", list_key="vrfs", query_device_param=True),
    Route("list_mpls_services", "routing/mpls/services", list_key="mpls_services", query_device_param=True),
    Route("list_mpls_saps", "routing/mpls/saps", list_key="saps", query_device_param=True),
    Route("list_fdb", "resources/fdb", list_key="ports_fdb"),
    Route("list_fdb_mac", "resources/fdb/{mac}", list_key="ports_fdb"),
    Route("list_fdb_detail", "resources/fdb/{mac}/detail", list_key="ports_fdb"),
    Route("list_ip_addresses", "resources/ip/addresses/{address_family?}", list_key="ip_addresses"),
    Route("list_arp", "resources/ip/arp/{query}/{cidr?}", list_key="arp"),
    Route("list_ip_networks", "resources/ip/networks/{address_family?}", list_key="ip_networks"),
    Route("get_network_ip_addresses", "resources/ip/networks/{id}/ip", list_key="addresses"),
    Route("list_links", "resources/links", list_key="links"),
    Route("get_link", "resources/links/{id}", list_key="link"),
    Route("list_nac", "resources/nac", list_key="ports_nac"),
    Route("list_nac_mac", "resources/nac/{mac}", list_key="ports_nac"),
    Route("list_sensors", "resources/sensors", list_key="sensors"),
    Route("list_vlans", "resources/vlans", list_key="vlans", query_device_param=True),
    Route("list_locations", "resources/locations", list_key="locations"),
    Route("get_inventory", "inventory/{hostname}", device_params=_DEVICE, list_key="inventory"),
    Route("get_inventory_for_device", "inventory/{hostname}/all", device_params=_DEVICE, list_key="inventory"),
    Route("get_port_security_by_port", "port_security/port/{portid}", list_key="port"),
    Route("get_port_security_by_hostname", "port_security/device/{hostname}", device_params=_DEVICE, list_key="port"),
    Route("get_port_security", "port_security", list_key="port"),
    Route("get_location", "location/{location_id_or_name}", list_key="get_location"),
)

DEFAULT_LIMIT = 50
_CONTROL_RE = re.compile("[\x00-\x1f\x7f-\x9f\ud800-\udfff]")
_INTEGER_RE = re.compile(r"^\s*-?\d+\s*$")
# PHP turns spaces, dots and [ in query parameter names into underscores before Laravel reads them
_PHP_NAME_RE = re.compile(r"[ .\[]")
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


def _php_name(key: str) -> str:
    """The name LibreNMS reads query parameter *key* as: PHP drops the blanks before it and turns spaces, dots and
    ``[`` into underscores, so ``" hostname"`` reaches Laravel as ``hostname`` and ``"host.name"`` as ``host_name``.
    Blanks after it are dropped too, which errs towards a match."""
    return _PHP_NAME_RE.sub("_", key.strip())


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
    """*params* as the query LibreNMS gets: text values, lists joined with commas (``state=0,1,2``)."""
    if params is None:
        return {}
    if not isinstance(params, dict):
        raise QueryError("params must be an object of query parameters")
    query: Dict[str, str] = {}
    for key, value in params.items():
        if not isinstance(key, str) or not key.strip() or _CONTROL_RE.search(key):
            raise QueryError("params keys must be non-empty text without control characters")
        refused = _REFUSED_PARAMS.get(_php_name(key).lower())
        if refused:
            raise QueryError(refused)
        items = value if isinstance(value, (list, tuple)) else [value]
        query[key] = ",".join(_scalar(key, item) for item in items)
    return query


def _integer(name: str, value: Any) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str) and _INTEGER_RE.match(value):
        return int(value)
    raise QueryError(f"{name} must be an integer (got {str(value)[:40]!r})")


def _limit(value: Any, cap: int) -> int:
    """At least 1 and at most *cap*: LibreNMS reads a negative logs limit as no limit at all."""
    return max(1, min(DEFAULT_LIMIT if value is None else _integer("limit", value), cap))


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


def prepare(client: Any, path_: Any, params: Any, limit: Any, settings: Any) -> PreparedQuery:
    """Everything between the model's ``path``/``params``/``limit`` and the request: normalise and match the path,
    check and join the params, apply the logs defaults and every clamp, resolve device references (path params and
    ``?hostname=``) to ids, and build the request path from encoded segments. A ``hostname`` param on a route that
    does not read it is refused: LibreNMS would ignore it and return every device's rows. Local checks run before
    any lookup is sent. Every refusal is a QueryError; a failed lookup other than 403/404 raises the
    LibreNMSError."""
    normalised = normalise(path_)
    route, values = match(normalised)
    query = _query(params)
    hostname_keys = [key for key in query if _php_name(key) == "hostname"]
    if hostname_keys and not route.query_device_param:
        where = _device_filter_path(normalised)
        raise QueryError(
            f"LibreNMS's {route.name} does not read params.hostname, so it would return every device's rows"
            + (f"; query the path '{where}' for one device's rows" if where else "")
        )
    cap = settings.max_query_results
    if route.paginated:
        count = _limit(query.get("limit") if limit is None else limit, cap)
        query["limit"] = str(count)
        query["start"] = str(max(0, _integer("start", query.get("start") or 0)))
        query["sortorder"] = _sortorder(query.get("sortorder"))
    else:
        count = _limit(limit, cap)
    for name in route.device_params:
        if name in values:
            values[name] = _device_id(client, values[name])
    for key in hostname_keys:
        query[key] = _device_id(client, query[key])
    return PreparedQuery(route, _request_path(route, values), query, count, normalised)
