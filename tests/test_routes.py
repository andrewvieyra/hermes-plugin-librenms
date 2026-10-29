import types
import unittest
from urllib.parse import unquote

from .helpers import submodule

client_mod = submodule("client")
routes = submodule("routes")

LONE = chr(0xD800)  # a lone surrogate, as JSON can carry
SETTINGS = types.SimpleNamespace(max_query_results=500)


class StubClient:
    """Answers ``GET devices/{hostname}`` and ``GET devices/{id}`` (digits, as LibreNMS reads them) from a table;
    records every path asked for."""

    def __init__(self, devices=None, errors=None):
        self.devices = {"sw1": 12, "core switch": 7} if devices is None else devices
        self.errors = errors or {}
        self.asked = []

    def get(self, path, params=None):
        self.asked.append(path)
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


def prepare(path, params=None, limit=None, client=None, settings=SETTINGS):
    return routes.prepare(client or StubClient(), path, params, limit, settings)


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
        self.assertEqual(str(caught.exception), "no LibreNMS device has hostname 'sw9'")
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

    def test_a_hostname_param_is_matched_by_the_name_php_reads(self):
        # PHP drops leading blanks, so these reach LibreNMS as hostname (a trailing blank is taken as one too):
        # none of them may skip the lookup
        for key in (" hostname", "  hostname", "hostname "):
            client = StubClient()
            self.assertEqual(prepare("ospf", {key: "sw1"}, client=client).params, {key: "12"}, key)
            self.assertEqual(client.asked, ["devices/sw1"], key)
            with self.assertRaises(routes.QueryError, msg=key) as caught:
                prepare("ospf", {key: "sw9"})
            self.assertEqual(str(caught.exception), "no LibreNMS device has hostname 'sw9'")
        # PHP names are case-sensitive, and it turns . and [ into _: LibreNMS reads none of these as hostname
        for key in ("Hostname", "hostname.", "hostname["):
            client = StubClient()
            self.assertEqual(prepare("ospf", {key: "sw9"}, client=client).params, {key: "sw9"}, key)
            self.assertEqual(client.asked, [], key)

    def test_a_hostname_param_a_route_ignores_is_refused_naming_the_path_form(self):
        # list_logs and list_services read only the path's hostname and list_alerts has no device filter: the param
        # would be dropped and every device's rows returned for whatever hostname was asked for
        for path, params, form in (
            ("logs/eventlog", {"hostname": "no-such-device"}, "logs/eventlog/<hostname>"),
            ("logs/syslog", {"hostname ": "sw1"}, "logs/syslog/<hostname>"),
            ("services", {" hostname": "sw1"}, "services/<hostname>"),
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

    def test_refusals_come_before_any_lookup(self):
        client = StubClient()
        for path, params, limit in (
            ("devices/sw1/foo", None, None),
            ("devices/sw1/ports", {"api_token": "x"}, None),
            ("logs/eventlog/sw1", None, "x"),
            ("logs/eventlog/sw1", {"sortorder": "sideways"}, None),
        ):
            with self.assertRaises(routes.QueryError):
                routes.prepare(client, path, params, limit, SETTINGS)
        self.assertEqual(client.asked, [])


if __name__ == "__main__":
    unittest.main()
