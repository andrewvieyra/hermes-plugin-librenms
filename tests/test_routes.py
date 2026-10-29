import types
import unittest
from urllib.parse import unquote

from .helpers import submodule

client_mod = submodule("client")
routes = submodule("routes")

LONE = chr(0xD800)  # a lone surrogate, as JSON can carry
UNKNOWN = (
    "no LibreNMS device has hostname '{}' (hostnames match exactly); find the stored one with the path 'devices' and "
    "params type=hostname, query=<part of it>"
)
SETTINGS = types.SimpleNamespace(max_query_results=500)
# Each read route's result key: the second argument of the api_success() its LibreNMS handler answers with
# (includes/html/api_functions.inc.php, checked route by route against LibreNMS 26.10). A wrong key makes the result
# null while the tool reports success, so a change here needs that check again.
LIST_KEYS = {
    "server_info": "system", "get_alert_template": "alert_templates", "list_alert_templates": "alert_templates",
    "list_pollers": "pollers", "list_poller_log": "log", "list_bgp": "bgp_sessions", "get_bgp": "bgp_session",
    "list_ospf": "ospf_neighbours", "list_ospf_ports": "ospf_ports", "list_ospfv3": "ospfv3_neighbours",
    "list_ospfv3_ports": "ospfv3_ports", "get_devices_by_group": "devices", "get_device_groups": "groups",
    "get_port_groups": "groups", "get_ports_by_group": "ports", "get_alert": "alerts", "list_alerts": "alerts",
    "legacy_get_alert": "alerts", "legacy_list_alerts": "alerts", "get_alert_rule": "rules",
    "list_alert_rules": "rules", "get_vrf": "vrf", "list_ipsec": "ipsec", "list_services": "services",
    "list_services_device": "services", "get_poller_group": "get_poller_group", "get_device": "devices",
    "device_availability": "availability", "device_outages": "outages", "get_vlans": "vlans",
    "list_links_device": "links", "get_graphs": "graphs", "get_fdb": "ports_fdb", "get_nac": "ports_nac",
    "list_available_health_graphs": "graphs", "list_available_wireless_graphs": "graphs",
    "get_device_wireless_sensors": "wireless_sensors", "get_device_ports": "ports", "get_ip_addresses": "addresses",
    "get_port_stack": "mappings", "get_transceivers": "transceivers", "get_components": "components",
    "get_device_groups_device": "groups", "device_under_maintenance": "is_under_maintenance",
    "list_devices": "devices", "list_eventlog": "logs", "list_syslog": "logs", "list_alertlog": "logs",
    "list_authlog": "logs", "get_port_info": "port", "get_port_fdb": "macs", "get_port_ip_info": "addresses",
    "get_port_transceiver": "transceivers", "search_ports": "ports", "search_mac": "ports", "get_all_ports": "ports",
    "get_port_description": "port_description", "list_bills": "bills", "get_bill": "bills",
    "get_bill_graphdata": "graph_data", "get_bill_history": "bill_history",
    "get_bill_history_graphdata": "graph_data", "list_cbgp": "bgp_counters", "list_vrf": "vrfs",
    "list_mpls_services": "mpls_services", "list_mpls_saps": "saps", "list_fdb": "ports_fdb",
    "list_fdb_mac": "ports_fdb", "list_fdb_detail": "ports_fdb", "list_ip_addresses": "ip_addresses",
    "list_arp": "arp", "list_ip_networks": "ip_networks", "get_network_ip_addresses": "addresses",
    "list_links": "links", "get_link": "link", "list_nac": "ports_nac", "list_nac_mac": "ports_nac",
    "list_sensors": "sensors", "list_vlans": "vlans", "list_locations": "locations", "get_inventory": "inventory",
    "get_inventory_for_device": "inventory", "get_port_security_by_port": "port",
    "get_port_security_by_hostname": "port", "get_port_security": "port", "get_location": "get_location",
}  # fmt: skip


class StubClient:
    """Answers ``GET devices/{hostname}`` and ``GET devices/{id}`` (digits, as LibreNMS reads them) from a table, and
    ``GET devices?type=hostname|display&query=x`` with the hostnames containing x; records every path asked for."""

    def __init__(self, devices=None, errors=None):
        self.devices = {"sw1": 12, "core switch": 7} if devices is None else devices
        self.errors = errors or {}
        self.asked = []

    def get(self, path, params=None):
        self.asked.append(path)
        if path == "devices":
            query = (params or {}).get("query", "").lower()
            found = [{"device_id": i, "hostname": h} for h, i in self.devices.items() if query in h.lower()]
            return {"status": "ok", "devices": found, "count": len(found)}
        name = unquote(path.split("/", 1)[1])
        if name in self.errors:
            raise self.errors[name]
        if name.isdigit():
            name = next((host for host, found in self.devices.items() if found == int(name)), name)
        if name in self.devices:
            return {"status": "ok", "devices": [{"device_id": self.devices[name], "hostname": name}], "count": 1}
        raise client_mod.LibreNMSError(
            f"GET /api/v0/{path} -> HTTP 404: Device {name} does not exist", status=404, kind="not_found"
        )


def prepare(path, params=None, limit=None, client=None, settings=SETTINGS, **paging):
    return routes.prepare(client or StubClient(), path, params, limit, settings, **paging)


def names():
    return [route.name for route in routes.ROUTES]


class Table(unittest.TestCase):
    def test_routes_keep_librenms_registration_order(self):
        order = names()
        self.assertEqual(order[:3], ["ping", "server_info", "index"])
        for chain in (
            ("get_device", "trigger_device_discovery", "get_vlans", "get_device_ports"),
            ("get_device_ports", "get_port_stats_by_port_hostname", "get_graph_by_port_hostname"),
            ("get_graph_by_service", "get_graph_generic_by_hostname", "list_devices"),
            ("get_port_info", "get_port_fdb", "get_port_ip_info", "search_ports", "search_mac", "get_all_ports"),
            ("list_oxidized", "search_oxidized", "get_oxidized_config"),
            ("list_ip_networks", "get_network_ip_addresses"),
        ):
            positions = [order.index(name) for name in chain]
            self.assertEqual(positions, sorted(positions), chain)

    def test_every_get_route_appears_once_and_is_well_formed(self):
        self.assertEqual(len(routes.ROUTES), 102)  # every GET registration of routes/api.php
        self.assertEqual(len(set(names())), len(routes.ROUTES))
        self.assertEqual(len({route.template for route in routes.ROUTES}), len(routes.ROUTES))
        for route in routes.ROUTES:
            params = [part.strip("{}?") for part in route.template.split("/") if part.startswith("{")]
            for name in route.device_params:
                self.assertIn(name, params, route.name)
            if route.rest:
                self.assertEqual(params[-1], route.rest, route.name)
            optional = [part.endswith("?}") for part in route.template.split("/") if part.startswith("{")]
            self.assertEqual(optional, sorted(optional), route.name)  # optional parameters only at the end
            self.assertFalse(route.refused and (route.device_params or route.list_key), route.name)

    def test_the_refused_and_special_routes(self):
        refused = {route.name for route in routes.ROUTES if route.refused}
        self.assertEqual(
            refused,
            {
                "get_graph_by_portgroup_multiport_bits",
                "get_graph_by_portgroup",
                "search_oxidized",
                "get_oxidized_config",
                "trigger_device_discovery",
                "get_health_graph",
                "get_wireless_graph",
                "get_port_stats_by_port_hostname",
                "get_graph_by_port_hostname",
                "get_graph_by_service",
                "get_graph_generic_by_hostname",
                "get_bill_graph",
                "get_bill_history_graph",
            },
        )
        self.assertEqual(
            {route.name for route in routes.ROUTES if route.query_device_param},
            {
                "list_bgp",
                "list_ospf",
                "list_ospfv3",
                "list_ospfv3_ports",
                "list_cbgp",
                "list_vrf",
                "list_mpls_services",
                "list_mpls_saps",
                "list_vlans",
            },
        )
        self.assertEqual(
            {route.name for route in routes.ROUTES if route.paginated},
            {"list_eventlog", "list_syslog", "list_alertlog", "list_authlog"},
        )
        oxidized = next(route for route in routes.ROUTES if route.name == "list_oxidized")
        self.assertEqual(oxidized.device_params, ())  # LibreNMS matches the hostname column only
        self.assertEqual(
            {route.name: route.id_params for route in routes.ROUTES if route.id_params},
            {
                "get_alert_template": ("id",),
                "get_alert": ("id",),
                "legacy_get_alert": ("id",),
                "get_alert_rule": ("id",),
                "list_available_health_graphs": ("sensor_id",),
                "list_available_wireless_graphs": ("sensor_id",),
                "get_port_info": ("portid",),
                "get_port_fdb": ("portid",),
                "get_port_ip_info": ("portid",),
                "get_port_transceiver": ("portid",),
                "get_port_description": ("portid",),
                "get_bill": ("bill_id",),
                "get_bill_graphdata": ("bill_id",),
                "get_bill_history": ("bill_id",),
                "get_bill_history_graphdata": ("bill_id",),
                "get_network_ip_addresses": ("id",),
                "get_port_security_by_port": ("portid",),
            },
        )
        self.assertEqual({route.name for route in routes.ROUTES if route.mac_params}, {"list_fdb_mac", "list_nac_mac"})
        self.assertEqual(
            {route.name for route in routes.ROUTES if route.alert_rows},
            {"get_alert", "list_alerts", "legacy_get_alert", "legacy_list_alerts", "list_alertlog"},
        )
        self.assertEqual(
            {route.name for route in routes.ROUTES if route.columns},
            {"get_device_ports", "search_ports", "get_all_ports"},
        )

    def test_every_read_route_names_the_key_librenms_answers_with(self):
        readable = {route.name: route.list_key for route in routes.ROUTES if not route.refused}
        self.assertEqual({name: key for name, key in readable.items() if key}, LIST_KEYS)
        self.assertEqual({name for name, key in readable.items() if not key}, {"ping", "index", "list_oxidized"})


class TooLargeHint(unittest.TestCase):
    def hint(self, path):
        return routes.too_large_hint(routes.match(path)[0], path)

    def test_limit_is_offered_only_where_librenms_pages(self):
        self.assertEqual(
            self.hint("logs/syslog"), "ask for fewer rows at a time with a smaller limit, and page with offset"
        )
        for path in ("devices", "ports", "resources/sensors", "faults", "devices/sw1/ports", "resources/vlans"):
            self.assertTrue(self.hint(path).endswith("(limit, offset, where and sort do not help here: LibreNMS sends "
                                                     "every row and they apply after)"), path)  # fmt: skip

    def test_each_route_gets_the_narrowing_it_takes(self):
        self.assertIn("filter with params type and query", self.hint("devices"))
        self.assertIn("query the path 'devices/<hostname>' for one device's rows", self.hint("devices"))
        self.assertIn("params.columns", self.hint("ports"))
        self.assertIn("'devices/<hostname>/ports'", self.hint("ports"))
        self.assertIn("params.columns", self.hint("devices/sw1/ports"))
        self.assertIn("'devices/<hostname>/health'", self.hint("resources/sensors"))
        self.assertIn("filter by device with params.hostname", self.hint("bgp"))
        self.assertIn("'services/<hostname>'", self.hint("services"))
        self.assertTrue(self.hint("faults").startswith("read one object's or one device's path instead"))


class Normalise(unittest.TestCase):
    def test_accepted_spellings(self):
        for given, expected in (
            (" /api/v0/devices/ ", "devices"),
            ("api/v0", ""),
            ("/api/v0/", ""),
            ("/", ""),
            ("", ""),
            ("devices/core switch/vlans", "devices/core switch/vlans"),
        ):
            self.assertEqual(routes.normalise(given), expected, given)

    def test_refused_spellings(self):
        for given, said in (
            ("devices?type=os", "params"),
            ("https://evil.example.com/api/v0/devices", "scheme"),
            ("//evil.example.com/devices", "scheme"),
            ("devices#x", "'#'"),
            ("devices/sw%201", "'%'"),
            ("devices\\x", "'\\\\'"),
            ("devices//x", "empty segment"),
            ("devices/../system", ". or .."),
            ("devices/./x", ". or .."),
            ("devices/sw1\x1b[2K", "control"),
            ("devices/sw\r1", "control"),
            ("devices/" + LONE, "control"),
            (12, "string"),
            (None, "string"),
        ):
            with self.assertRaises(routes.QueryError, msg=repr(given)) as caught:
                routes.normalise(given)
            self.assertIn(said, str(caught.exception), given)


class Match(unittest.TestCase):
    def matched(self, path):
        route, values = routes.match(path)
        return route.name, values

    def refused(self, path):
        with self.assertRaises(routes.QueryError, msg=path) as caught:
            routes.match(path)
        return str(caught.exception)

    def test_device_sub_paths_registered_before_the_graph_fallback_are_allowed(self):
        self.assertEqual(self.matched("devices/sw1"), ("get_device", {"hostname": "sw1"}))
        self.assertEqual(self.matched("devices/sw1/vlans"), ("get_vlans", {"hostname": "sw1"}))
        self.assertEqual(self.matched("devices/sw1/ports"), ("get_device_ports", {"hostname": "sw1"}))
        self.assertEqual(self.matched("devices/sw1/wireless-sensors")[0], "get_device_wireless_sensors")
        self.assertEqual(self.matched("devices/sw1/health"), ("list_available_health_graphs", {"hostname": "sw1"}))
        self.assertEqual(
            self.matched("devices/sw1/health/device_temperature/5"),
            ("list_available_health_graphs", {"hostname": "sw1", "type": "device_temperature", "sensor_id": "5"}),
        )
        self.assertEqual(self.matched("devices")[0], "list_devices")

    def test_the_graph_fallback_and_the_other_refused_routes(self):
        message = self.refused("devices/sw1/foo")
        self.assertIn("get_graph_generic_by_hostname", message)
        self.assertIn("refused", message)
        self.assertIn("get_graph_generic_by_hostname", self.refused("devices/sw1/eventlog"))  # POST only upstream
        self.assertIn("librenms_plan", self.refused("devices/sw1/discover"))
        for path in ("devices/sw1/ports/Gi1/0/1", "devices/sw1/ports/eth0/bits", "devices/sw1/ports/eth0"):
            self.assertIn("get_port_stats_by_port_hostname", self.refused(path))  # its ifname takes the rest
        for path, name in (
            ("devices/sw1/graphs/health/device_temperature", "get_health_graph"),
            ("devices/sw1/graphs/wireless/clients/3", "get_wireless_graph"),
            ("devices/sw1/services/4/graphs/rtt", "get_graph_by_service"),
            ("bills/1/graphs/bits", "get_bill_graph"),
            ("bills/1/history/2/graphs/bits", "get_bill_history_graph"),
            ("portgroups/core", "get_graph_by_portgroup"),
            ("portgroups/multiport/bits/1,2", "get_graph_by_portgroup_multiport_bits"),
            ("oxidized/config/sw1", "get_oxidized_config"),
            ("oxidized/config/search/public", "search_oxidized"),
        ):
            self.assertIn(name, self.refused(path))

    def test_ports_search_and_mac_are_not_shadowed_by_port_ids(self):
        self.assertEqual(
            self.matched("ports/search/ifAlias/core"), ("search_ports", {"field": "ifAlias", "search": "core"})
        )
        self.assertEqual(self.matched("ports/search/ifName/Gi1/0/1")[1], {"field": "ifName", "search": "Gi1/0/1"})
        self.assertEqual(self.matched("ports/search/ifName"), ("search_ports", {"field": "ifName"}))
        self.assertEqual(self.matched("ports/mac/aabbccddeeff"), ("search_mac", {"search": "aabbccddeeff"}))
        self.assertEqual(self.matched("ports/12"), ("get_port_info", {"portid": "12"}))
        self.assertEqual(self.matched("ports/12/description")[0], "get_port_description")
        self.assertEqual(self.matched("ports")[0], "get_all_ports")
        # LibreNMS's own shadowing, kept: ports/{portid}/fdb is registered first
        self.assertEqual(self.matched("ports/mac/fdb"), ("get_port_fdb", {"portid": "mac"}))

    def test_optional_parameters_and_the_index(self):
        self.assertEqual(self.matched(""), ("index", {}))
        self.assertEqual(self.matched("/api/v0/"), ("index", {}))
        self.assertEqual(self.matched("logs/eventlog"), ("list_eventlog", {}))
        self.assertEqual(self.matched("logs/eventlog/sw1"), ("list_eventlog", {"hostname": "sw1"}))
        self.assertEqual(self.matched("logs/authlog"), ("list_authlog", {}))
        self.assertEqual(self.matched("poller_group"), ("get_poller_group", {}))
        self.assertEqual(self.matched("oxidized"), ("list_oxidized", {}))
        self.assertEqual(self.matched("oxidized/config"), ("list_oxidized", {"hostname": "config"}))
        self.assertEqual(self.matched("resources/ip/networks/ipv4")[0], "list_ip_networks")
        self.assertEqual(self.matched("resources/ip/networks/5/ip"), ("get_network_ip_addresses", {"id": "5"}))
        self.assertEqual(
            self.matched("resources/ip/arp/10.0.0.0/24"), ("list_arp", {"query": "10.0.0.0", "cidr": "24"})
        )

    def test_paths_no_read_route_matches(self):
        for path in ("nope", "logs/eventlog/sw1/extra", "system/x", "Devices", "devices/sw1/vlans/x/y", "locations"):
            self.assertIn("no LibreNMS v0 read route matches", self.refused(path), path)


class Prepare(unittest.TestCase):
    def test_hostname_path_params_are_resolved_to_ids(self):
        client = StubClient()
        query = prepare("/api/v0/devices/sw1/ports", {"columns": "port_id,ifName"}, client=client)
        self.assertEqual(query.route.name, "get_device_ports")
        self.assertEqual(query.request_path, "devices/12/ports")
        self.assertEqual(query.params, {"columns": "port_id,ifName"})
        self.assertEqual((query.limit, query.path), (50, "devices/sw1/ports"))
        self.assertEqual(client.asked, ["devices/sw1"])
        client = StubClient()
        self.assertEqual(prepare("devices/12/ports", client=client).request_path, "devices/12/ports")
        self.assertEqual(client.asked, ["devices/12"])  # an id is checked too
        self.assertEqual(prepare("devices/0012/ports").request_path, "devices/12/ports")

    def test_names_are_encoded_segment_by_segment(self):
        client = StubClient()
        self.assertEqual(prepare("devices/core switch/vlans", client=client).request_path, "devices/7/vlans")
        self.assertEqual(client.asked, ["devices/core%20switch"])
        self.assertEqual(prepare("devicegroups/core switches").request_path, "devicegroups/core%20switches")
        self.assertEqual(prepare("location/Zürich HQ").request_path, "location/Z%C3%BCrich%20HQ")
        self.assertEqual(prepare("services/sw1").request_path, "services/12")
        self.assertEqual(prepare("ports/search/ifName/Gi1/0/1").request_path, "ports/search/ifName/Gi1/0/1")
        self.assertEqual(prepare("ports/search/ifAlias/core uplink").request_path, "ports/search/ifAlias/core%20uplink")
        self.assertEqual(prepare("").request_path, "")

    def test_oxidized_hostnames_are_sent_as_given(self):
        client = StubClient()
        self.assertEqual(prepare("oxidized/sw9.example.net", client=client).request_path, "oxidized/sw9.example.net")
        self.assertEqual(client.asked, [])

    def test_unknown_and_invisible_hostnames_are_refused(self):
        with self.assertRaises(routes.QueryError) as caught:
            prepare("devices/sw9/vlans")
        self.assertEqual(str(caught.exception), UNKNOWN.format("sw9"))
        forbidden = client_mod.LibreNMSError("GET -> HTTP 403", status=403, kind="forbidden")
        with self.assertRaises(routes.QueryError) as caught:
            prepare("logs/syslog/sw8", client=StubClient(errors={"sw8": forbidden}))
        self.assertTrue(str(caught.exception).startswith("LibreNMS answered 403 for hostname 'sw8': it does not exist"))
        self.assertIn("global read", str(caught.exception))
        for failure in (
            client_mod.LibreNMSError("GET -> HTTP 500", status=500, kind="server"),
            client_mod.TransportError("could not reach LibreNMS (timeout) err-0123456789ab"),
        ):
            with self.assertRaises(client_mod.LibreNMSError) as caught:
                prepare("devices/sw7", client=StubClient(errors={"sw7": failure}))
            self.assertIs(caught.exception, failure)

    def test_an_answer_without_a_device_id_is_refused(self):
        class Odd(StubClient):
            def get(self, path, params=None):
                return {"status": "ok", "devices": [{"hostname": "sw1"}]}

        with self.assertRaises(routes.QueryError) as caught:
            prepare("devices/sw1/fdb", client=Odd())
        self.assertIn("no device id", str(caught.exception))

    def test_query_hostnames_are_resolved_where_an_unknown_one_would_broaden_the_filter(self):
        client = StubClient()
        self.assertEqual(prepare("bgp", {"hostname": "sw1"}, client=client).params, {"hostname": "12"})
        self.assertEqual(prepare("resources/vlans", {"hostname": "12"}, client=client).params, {"hostname": "12"})
        self.assertEqual(client.asked, ["devices/sw1", "devices/12"])
        for bad in ("sw9", ""):
            with self.assertRaises(routes.QueryError, msg=bad):
                prepare("routing/vrf", {"hostname": bad})

    def test_a_params_name_php_reads_as_another_is_refused(self):
        # PHP drops leading spaces, turns spaces, dots and an unclosed [ into _, reads name[...] as an array called
        # name, and keeps the last of two names it reads alike: none of these may reach LibreNMS unchecked
        for key, read in (
            (" hostname", "'hostname'"),
            ("  limit", "'limit'"),
            ("hostname ", "'hostname_'"),
            ("host name", "'host_name'"),
            ("hostname.", "'hostname_'"),
            ("hostname[", "'hostname_'"),
            ("a[b.c", "'a_b_c'"),
        ):
            client = StubClient()
            with self.assertRaises(routes.QueryError, msg=key) as caught:
                prepare("ospf", {key: "sw1"}, client=client)
            self.assertEqual(
                str(caught.exception),
                f"params key {key!r} reaches LibreNMS as {read} (PHP drops leading spaces and turns spaces, dots and "
                "[ into _); write the name LibreNMS reads",
            )
            self.assertEqual(client.asked, [], key)
        for key in ("hostname[]", "hostname[0]", " hostname[x].y"):
            with self.assertRaises(routes.QueryError, msg=key) as caught:
                prepare("logs/eventlog", {key: "no-such-device"})
            self.assertEqual(
                str(caught.exception),
                f"params key {key!r} reaches LibreNMS as an array named 'hostname'; use plain names (a list value is "
                "sent joined with commas)",
            )
        # names are case-sensitive: LibreNMS would ignore these, while the plugin checks and clamps the real ones
        for key in ("Hostname", "LIMIT", "Start", "sortOrder", "Columns"):
            with self.assertRaises(routes.QueryError, msg=key) as caught:
                prepare("logs/eventlog", {key: "1"})
            self.assertEqual(
                str(caught.exception),
                f"params key {key!r}: LibreNMS reads names as written; write it as {key.lower()!r}",
            )
        self.assertEqual(prepare("ospf", {"hostname": "sw1"}).params, {"hostname": "12"})
        self.assertEqual(prepare("faults", {"host_name": "x"}).params, {"host_name": "x"})  # a name PHP keeps

    def test_a_paging_name_php_reads_alike_never_reaches_the_wire(self):
        # {"limit": 5, " limit": -1} was sent as limit=5&+limit=-1, which LibreNMS read as no limit at all
        for params in ({"limit": 5, " limit": -1}, {" limit": "-1"}, {"start": 0, "start ": 9}, {" sortorder": "ASC"}):
            with self.assertRaises(routes.QueryError, msg=params) as caught:
                prepare("logs/syslog", params)
            self.assertIn("reaches LibreNMS as", str(caught.exception))
        self.assertEqual(prepare("logs/syslog", {"limit": 5}).params, {"limit": "5", "start": "0", "sortorder": "DESC"})

    def test_a_hostname_param_a_route_ignores_is_refused_naming_the_path_form(self):
        # list_logs and list_services read only the path's hostname and list_alerts has no device filter: the param
        # would be dropped and every device's rows returned for whatever hostname was asked for
        for path, params, form in (
            ("logs/eventlog", {"hostname": "no-such-device"}, "logs/eventlog/<hostname>"),
            ("logs/syslog", {"hostname": "sw1"}, "logs/syslog/<hostname>"),
            ("services", {"hostname": "sw1"}, "services/<hostname>"),
            ("devices", {"type": "hostname", "query": "sw", "hostname": "x"}, "devices/<hostname>"),
            ("oxidized", {"hostname": "sw1"}, "oxidized/<hostname>"),
            ("faults", {"hostname": "sw1"}, None),
            ("logs/authlog", {"hostname": "sw1"}, None),
            ("logs/eventlog/sw1", {"hostname": "sw1"}, None),
            ("devicegroups", {"hostname": "sw1"}, None),
        ):
            client = StubClient()
            with self.assertRaises(routes.QueryError, msg=path) as caught:
                prepare(path, params, client=client)
            message = str(caught.exception)
            route = routes.match(path)[0].name
            self.assertTrue(
                message.startswith(f"LibreNMS's {route} does not read params.hostname, so it would return every"),
                message,
            )
            if form:
                self.assertTrue(message.endswith(f"; query the path '{form}' for one device's rows"), message)
            else:
                self.assertNotIn("query the path", message)
            self.assertEqual(client.asked, [], path)

    def test_an_id_is_checked_and_0_is_refused(self):
        # list_ospfv3 reads an unknown id, and several routes read 0, as no device filter at all
        client = StubClient()
        for path, params in (("ospfv3", {"hostname": 1234}), ("ospfv3_ports", {"hostname": "1234"})):
            with self.assertRaises(routes.QueryError, msg=path) as caught:
                prepare(path, params, client=client)
            self.assertEqual(str(caught.exception), "no LibreNMS device has id 1234")
        self.assertEqual(client.asked, ["devices/1234", "devices/1234"])
        self.assertEqual(prepare("ospfv3", {"hostname": "0012"}).params, {"hostname": "12"})
        client = StubClient()
        for path, params in (
            ("routing/mpls/services", {"hostname": 0}),
            ("routing/mpls/saps", {"hostname": "0"}),
            ("bgp", {"hostname": "00"}),
            ("devices/0/groups", None),
            ("logs/eventlog/0", None),
        ):
            with self.assertRaises(routes.QueryError, msg=path) as caught:
                prepare(path, params, client=client)
            self.assertTrue(str(caught.exception).startswith("no LibreNMS device has id 0 "), path)
        self.assertEqual(client.asked, [])
        forbidden = client_mod.LibreNMSError("GET -> HTTP 403", status=403, kind="forbidden")
        with self.assertRaises(routes.QueryError) as caught:
            prepare("devices/31/vlans", client=StubClient(errors={"31": forbidden}))
        self.assertEqual(
            str(caught.exception), "LibreNMS answered 403 for device id 31: this token cannot see that device"
        )

    def test_a_slash_in_a_device_reference_is_refused_before_any_lookup(self):
        # devices/1%2Fdiscover is decoded by Laravel before routing: the lookup would schedule a rediscovery
        client = StubClient()
        for value in ("1/discover", "core-sw1.example.net/discover"):
            with self.assertRaises(routes.QueryError, msg=value) as caught:
                prepare("routing/vrf", {"hostname": value}, client=client)
            self.assertEqual(str(caught.exception), f"invalid device reference {value!r}: no hostname holds a '/'")
        self.assertEqual(client.asked, [])

    def test_params_are_checked_and_joined(self):
        query = prepare(
            "faults",
            {"state": [0, 1, 2], "full": True, "flag": False, "lat": 1.5, "q": "a b", "order": "timestamp desc"},
        )
        self.assertEqual(
            query.params,
            {"state": "0,1,2", "full": "1", "flag": "0", "lat": "1.5", "q": "a b", "order": "timestamp desc"},
        )
        self.assertEqual(prepare("faults", None).params, {})
        for params, said in (
            ("state=1", "object"),
            ({"a": None}, "params.a"),
            ({"a": {"b": 1}}, "params.a"),
            ({"a": [[1]]}, "params.a"),
            ({"a": float("nan")}, "params.a"),
            ({"api_token": "t"}, "X-Auth-Token"),
            ({"API_TOKEN": "t"}, "X-Auth-Token"),
            ({"api.token": "t"}, "X-Auth-Token"),  # PHP reads it as api_token
            ({"_method": "DELETE"}, "method override"),
            ({"": "x"}, "keys"),
            ({1: "x"}, "keys"),
            ({"q\n": "x"}, "keys"),
            ({"q": "a\nb"}, "control"),
            ({"q": ["a", "b" + LONE]}, "control"),
        ):
            with self.assertRaises(routes.QueryError, msg=repr(params)) as caught:
                prepare("faults", params)
            self.assertIn(said, str(caught.exception), params)

    def test_an_object_id_librenms_would_read_as_no_filter_is_refused(self):
        # list_alerts filters only when $id > 0, the rule and template lists when($id), bills when is_numeric,
        # get_port_security if ($port_id), the health list $sensor_id ? where : list: so faults/0, rules/0, bills/x,
        # port_security/port/0 or .../health/{type}/0 answered with every object under a path that names one; and the
        # port, bill, network and sensor routes compare the text with an integer column, where MySQL reads 1abc as 1
        for path in ("faults/0", "faults/-1", "alerts/0", "rules/0", "rules/1abc", "alert_templates/0", "bills/x",
                     "bills/0", "faults/1.0", "rules/²", "port_security/port/0", "port_security/port/1abc",
                     "ports/0", "ports/1abc", "ports/1abc/fdb", "ports/x/ip", "ports/0/transceiver",
                     "ports/1abc/description", "ports/search", "ports/mac/fdb", "bills/1abc/history",
                     "bills/0/graphdata/bits", "bills/x/history/2/graphdata/bits", "resources/ip/networks/1abc/ip",
                     "devices/sw1/health/device_temperature/0", "devices/sw1/health/device_temperature/1abc",
                     "devices/sw1/wireless/device_wireless_clients/0"):  # fmt: skip
            client = StubClient()
            with self.assertRaises(routes.QueryError, msg=path) as caught:
                prepare(path, client=client)
            message = str(caught.exception)
            self.assertRegex(
                message, r"^\{(id|bill_id|portid|sensor_id)\} must be a positive whole number \(got ", path
            )
            self.assertIn(f"LibreNMS's {routes.match(path)[0].name} reads 0 or text as no filter", message)
            self.assertEqual(client.asked, [], path)
        for path, sent in (
            ("faults/5", "faults/5"),
            ("rules/007", "rules/7"),
            ("bills/2", "bills/2"),
            ("ports/12/fdb", "ports/12/fdb"),
            ("port_security/port/3", "port_security/port/3"),
            ("bills/2/history/7/graphdata/bits", "bills/2/history/7/graphdata/bits"),
            ("resources/ip/networks/5/ip", "resources/ip/networks/5/ip"),
            ("devices/sw1/health/device_temperature/4", "devices/12/health/device_temperature/4"),
            ("devices/sw1/health/device_temperature", "devices/12/health/device_temperature"),  # every sensor: asked
        ):
            self.assertEqual(prepare(path).request_path, sent)
        self.assertEqual(prepare("bgp/0").request_path, "bgp/0")  # get_bgp answers 0 with a 404, not a list

    def test_poller_group_0_is_refused_and_names_are_sent(self):
        # get_poller_group answers empty($poller_group) with every group, and PHP's empty("0") is true; devices are in
        # group 0 (General, no poller_groups row) by default
        with self.assertRaises(routes.QueryError) as caught:
            prepare("poller_group/0")
        self.assertIn("LibreNMS reads poller_group/0 as no group at all", str(caught.exception))
        for path in ("poller_group", "poller_group/1", "poller_group/00", "poller_group/core-pollers"):
            self.assertEqual(prepare(path).request_path, path)

    def test_macs_are_sent_as_the_12_hex_digits_librenms_stores(self):
        # list_fdb and list_nac compare {mac} with the column exactly: a MAC with separators was never found, and
        # the empty answer read as "not on the network"; 0 is read as no filter at all
        for given, sent in (
            ("00:11:22:33:44:55", "001122334455"),
            ("00-11-22-33-44-55", "001122334455"),
            ("0011.2233.4455", "001122334455"),
            ("AABBCCDDEEFF", "aabbccddeeff"),
            ("0:11:22:33:44:5", "001122334405"),  # SNMP drops leading zeros
            ("0:0:c:7:ac:1", "00000c07ac01"),  # 12 characters with its separators, like the bare form
            ("0-0-5e-0-1-a", "00005e00010a"),
            ("00:1:2:3:4:5", "000102030405"),
            ("00:11:22:33:44:55 ", "001122334455"),
        ):
            for route in ("fdb", "nac"):
                query = prepare(f"resources/{route}/{given}")
                self.assertEqual(query.request_path, f"resources/{route}/{sent}", given)
                self.assertEqual(query.path, f"resources/{route}/{given.strip()}")  # as the model wrote it
        for bad in ("0", "001122", "00:11:22:33:44", "00:11-22:33:44:55", "0011.2233", "zz:11:22:33:44:55", "all"):
            with self.assertRaises(routes.QueryError, msg=bad) as caught:
                prepare(f"resources/fdb/{bad}")
            self.assertIn("takes a whole MAC address", str(caught.exception))
        # the detail route and ports/mac parse the MAC themselves
        self.assertEqual(prepare("resources/fdb/00:11:22:33:44:55/detail").request_path,
                         "resources/fdb/00%3A11%3A22%3A33%3A44%3A55/detail")  # fmt: skip

    def test_column_lists_are_trimmed_and_checked(self):
        # LibreNMS checks the trimmed names but selects them as sent: "port_id, ifName" was an opaque HTTP 500
        for given in ("port_id, ifName, ifAlias", " port_id,ifName ,ifAlias", ["port_id", " ifName", "ifAlias "],
                      "port_id,,ifName,ifAlias,"):  # fmt: skip
            self.assertEqual(
                prepare("devices/sw1/ports", {"columns": given}).params["columns"], "port_id,ifName,ifAlias", given
            )
        self.assertEqual(prepare("ports", {"columns": ""}).params, {"columns": ""})  # LibreNMS's default columns
        for bad in ("port_id;drop", "*", "if Name", "ports.ifName"):
            with self.assertRaises(routes.QueryError, msg=bad) as caught:
                prepare("ports", {"columns": bad})
            self.assertIn("params.columns takes column names separated by commas", str(caught.exception))

    def test_the_ports_search_field_list_is_trimmed_only_when_a_search_follows(self):
        query = prepare("ports/search/ifAlias, ifName/core uplink")
        self.assertEqual(query.request_path, "ports/search/ifAlias%2CifName/core%20uplink")
        # with one segment LibreNMS reads it as the search term over ifAlias, ifDescr and ifName
        self.assertEqual(prepare("ports/search/core, uplink").request_path, "ports/search/core%2C%20uplink")
        for path in ("ports/search/if-Alias/core", "ports/search/ , /core"):
            with self.assertRaises(routes.QueryError, msg=path):
                prepare(path)

    def test_an_unknown_hostname_names_the_hostnames_that_contain_its_first_label(self):
        devices = {f"core-sw{i}.example.net": i for i in range(1, 8)} | {"edge-rtr1.example.net": 20}
        client = StubClient(devices=devices)
        with self.assertRaises(routes.QueryError) as caught:
            prepare("devices/core-sw1.example.com/ports", client=client)
        self.assertEqual(
            str(caught.exception),
            "no LibreNMS device has hostname 'core-sw1.example.com' (hostnames match exactly); devices whose hostname "
            "or display name contains 'core-sw1': core-sw1.example.net",
        )
        with self.assertRaises(routes.QueryError) as caught:
            prepare("logs/eventlog/core-sw", client=client)
        self.assertTrue(str(caught.exception).endswith(
            "contains 'core-sw': core-sw1.example.net, core-sw2.example.net, core-sw3.example.net, "
            "core-sw4.example.net, core-sw5.example.net and 2 more"
        ))  # fmt: skip
        self.assertEqual(client.asked[-2:], ["devices/core-sw", "devices"])
        # a short label or a LIKE wildcard would match half the inventory: not searched
        for value in ("sw", "s%.example.net"):
            client = StubClient()
            with self.assertRaises(routes.QueryError):
                prepare("bgp", {"hostname": value}, client=client)
            self.assertEqual(client.asked, [f"devices/{value.replace('%', '%25')}"], value)
        # an id is not searched; a failed search only leaves the candidates out
        client = StubClient()
        with self.assertRaises(routes.QueryError) as caught:
            prepare("devices/99/ports", client=client)
        self.assertEqual((str(caught.exception), client.asked), ("no LibreNMS device has id 99", ["devices/99"]))

        class Failing(StubClient):
            def get(self, path, params=None):
                if path == "devices":
                    raise client_mod.LibreNMSError("GET devices -> HTTP 500", status=500, kind="server")
                return super().get(path, params)

        with self.assertRaises(routes.QueryError) as caught:
            prepare("devices/core-sw9/ports", client=Failing())
        self.assertEqual(str(caught.exception), UNKNOWN.format("core-sw9"))

    def test_logs_defaults_and_clamps(self):
        query = prepare("logs/eventlog/sw1")
        self.assertEqual(query.request_path, "logs/eventlog/12")
        self.assertEqual(query.params, {"limit": "50", "start": "0", "sortorder": "DESC"})
        self.assertEqual(query.limit, 50)
        for limit, sent in ((10_000, 500), (-1, 1), (0, 1), ("20", 20), (" 7 ", 7)):
            query = prepare("logs/syslog", limit=limit)
            self.assertEqual((query.params["limit"], query.limit), (str(sent), sent), limit)
        self.assertEqual(prepare("logs/authlog", {"limit": "30"}).params["limit"], "30")
        self.assertEqual(prepare("logs/authlog", {"limit": "30"}, limit=5).params["limit"], "5")
        self.assertEqual(
            prepare("logs/alertlog", limit=900, settings=types.SimpleNamespace(max_query_results=5000)).limit, 900
        )
        for given, sent in (("asc", "ASC"), ("Desc", "DESC"), (" ASC ", "ASC")):
            self.assertEqual(prepare("logs/eventlog", {"sortorder": given}).params["sortorder"], sent)
        for given, sent in (("-5", "0"), ("40", "40"), (12, "12"), ("", "0")):
            self.assertEqual(prepare("logs/eventlog", {"start": given}).params["start"], sent, given)
        window = {"from": "2026-10-01 00:00:00", "to": "100"}
        self.assertEqual({k: prepare("logs/eventlog", window).params[k] for k in window}, window)
        for params, limit in (
            (None, "x"),
            (None, 1.5),
            (None, True),
            ({"limit": "lots"}, None),
            ({"sortorder": "random"}, None),
            ({"sortorder": "DESC LIMIT 1"}, None),
            ({"start": "x"}, None),
            ({"start": 1.5}, None),
        ):
            with self.assertRaises(routes.QueryError, msg=(params, limit)):
                prepare("logs/eventlog", params, limit)

    def test_other_routes_get_a_client_side_limit_only(self):
        self.assertEqual(prepare("devices").limit, 50)
        self.assertEqual(prepare("devices", limit=10_000).limit, 500)
        self.assertEqual(prepare("devices", limit=0).limit, 1)
        query = prepare("devices", {"limit": "5"})
        self.assertEqual((query.limit, query.params), (50, {"limit": "5"}))
        with self.assertRaises(routes.QueryError):
            prepare("devices", limit="many")

    def test_offset_is_sent_as_start_on_a_logs_route_and_kept_for_the_handler_elsewhere(self):
        query = prepare("logs/syslog/sw1", offset=40, limit=10)
        self.assertEqual((query.offset, query.params["start"], query.params["limit"]), (40, "40", "10"))
        self.assertEqual(prepare("logs/syslog", {"start": "40"}).offset, 40)  # LibreNMS's own name pages too
        self.assertEqual(prepare("logs/syslog", {"start": "40"}, offset="40").params["start"], "40")  # agreeing
        self.assertEqual((prepare("logs/syslog").offset, prepare("logs/syslog", offset=0).params["start"]), (0, "0"))
        query = prepare("devices/sw1/ports", offset=" 500 ")
        self.assertEqual((query.offset, query.params), (500, {}))  # applied to the rows read, never sent
        self.assertEqual(prepare("ports").offset, 0)
        for path, params, offset, message in (
            ("devices", None, -1, "offset must be 0 or more (got -1): it counts the rows to skip"),
            ("logs/eventlog", None, "-3", "offset must be 0 or more (got -3): it counts the rows to skip"),
            ("devices", None, "next", "offset must be an integer (got 'next')"),
            ("devices", None, 2.5, "offset must be an integer (got '2.5')"),
            ("logs/eventlog", {"start": 10}, 20, "offset 20 and params.start 10 disagree; page with offset alone"),
            (
                "devices/sw1/ports",
                {"start": 500},
                None,
                "LibreNMS's get_device_ports does not read params.start (it pages the logs routes only), so it would "
                "answer with the first rows again; page with offset, which is applied to the rows read",
            ),
            (
                "logs/eventlog",
                {"offset": 5},
                None,
                "LibreNMS reads no params.offset; page with the offset argument (a result's next_offset)",
            ),
        ):
            with self.assertRaises(routes.QueryError, msg=(path, params, offset)) as caught:
                prepare(path, params, offset=offset)
            self.assertEqual(str(caught.exception), message)

    def test_where_and_sort_are_refused_on_a_logs_route_which_librenms_pages(self):
        for row_args in (("where",), ("sort",), ("where", "sort")):
            with self.assertRaises(routes.QueryError) as caught:
                prepare("logs/syslog", row_args=row_args)
            self.assertEqual(
                str(caught.exception),
                f"{' and '.join(row_args)} cannot apply to logs/syslog: LibreNMS pages the logs routes itself, so "
                "they would see one page only; narrow with the device path (logs/syslog/<hostname>) and params "
                "from/to (a time or an id), order with params.sortorder (asc/desc), and page with offset",
            )
        # the device path where the route has one and the query is not on it yet (logs/authlog has none)
        for path, device in (
            ("logs/alertlog", "the device path (logs/alertlog/<hostname>) and "),
            ("logs/eventlog/", "the device path (logs/eventlog/<hostname>) and "),
            ("logs/syslog/sw1", ""),
            ("logs/authlog", ""),
        ):
            with self.assertRaises(routes.QueryError, msg=path) as caught:
                prepare(path, row_args=("sort",))
            self.assertIn(f"; narrow with {device}params from/to (a time or an id), ", str(caught.exception))
        self.assertEqual(prepare("devices/sw1/ports", row_args=("where", "sort")).request_path, "devices/12/ports")

    def test_refusals_come_before_any_lookup(self):
        client = StubClient()
        for path, params, limit in (
            ("devices/sw1/foo", None, None),
            ("devices/sw1/ports", {"api_token": "x"}, None),
            ("logs/eventlog/sw1", None, "x"),
            ("logs/eventlog/sw1", {"sortorder": "sideways"}, None),
            ("devices/sw1/ports", {"start": 50}, None),
        ):
            with self.assertRaises(routes.QueryError):
                routes.prepare(client, path, params, limit, SETTINGS)
        for offset, row_args in ((-1, ()), ("x", ()), (None, ("where",))):
            with self.assertRaises(routes.QueryError):
                routes.prepare(client, "logs/eventlog/sw1", None, None, SETTINGS, offset=offset, row_args=row_args)
        self.assertEqual(client.asked, [])


if __name__ == "__main__":
    unittest.main()
