"""librenms_query over the read routes: every allow-listed route end to end against a stub answering with its
LibreNMS result key, the routes the report views read against the fake (ports, links, sensors, transceivers, BGP,
OSPF, syslog and alert log, FDB, ARP, VLANs, outages, availability, bills, port groups), what fault and alert-log
rows show of their details, envelope extras and keyed objects, and the advice for an answer too large to read."""

import functools
from urllib.parse import unquote

from .helpers import submodule
from .test_handlers import HandlerCase
from .test_routes import LIST_KEYS

routes = submodule("routes")
# A value for each path parameter that reaches the route it names (ids, a MAC, a column, a device).
VALUES = {
    "hostname": "sw1",
    "id": "3",
    "bill_id": "3",
    "portid": "4",
    "sensor_id": "5",
    "mac": "001122334455",
    "field": "ifName",
    "search": "Gi1",
    "query": "all",
}


class Stub:
    """A client answering every GET with the envelope its LibreNMS handler uses: one row ``{"k": "v"}`` under the
    route's result key (the device lookups answer with device 1). Records the paths asked for."""

    base_url = "https://librenms.test"

    def __init__(self):
        self.asked = []

    def get(self, path, params=None):
        self.asked.append(path)
        route, _values = routes.match(unquote(path))
        row = {"device_id": 1, "k": "v"} if route.name == "get_device" else {"k": "v"}
        if route.list_key:
            return {"status": "ok", route.list_key: [row], "count": 1}
        return [row] if route.name == "list_oxidized" else {"k": "v"}


class EveryReadRoute(HandlerCase):
    """A route whose result key drifted from LibreNMS's would come back as a null result while the tool reports
    success; here every allow-listed route has to hand its row through."""

    def test_every_route_returns_what_its_handler_answers_with(self):
        checked = set()
        for route in routes.ROUTES:
            if route.refused:
                continue
            path = "/".join(
                VALUES.get(text, "x") if is_param else text
                for text, is_param, _optional in routes._parts(route.template)
            )
            stub = Stub()
            self.handlers.set_client_factory(lambda stub=stub: stub)
            out = self.call("librenms_query", path=path)
            self.assertTrue(out["success"], (route.name, out))
            self.assertEqual(out["route"], route.name, path)
            shown = out["results"][0] if "results" in out else out["result"]
            self.assertEqual(shown["k"], "v", route.name)
            self.assertEqual(LIST_KEYS.get(route.name), route.list_key, route.name)
            checked.add(route.name)
        self.assertEqual(len(checked), 89)  # 102 routes, 13 of them refused


class ReportRoutes(HandlerCase):
    """The routes the report views read, end to end against the fake."""

    def query(self, path, **args):
        return self.call("librenms_query", path=path, **args)

    def test_ports_fleet_wide_by_search_and_by_mac(self):
        out = self.query("ports", params={"columns": "port_id, ifName, ifOperStatus"})
        self.assertEqual(out["results"][0], {"port_id": 1, "ifName": "Gi1/0/1", "ifOperStatus": "up"})
        self.assertEqual(out["count"], 5)  # the deleted port is not listed
        self.assertEqual(self.gets()[-1]["params"], {"columns": "port_id,ifName,ifOperStatus"})
        out = self.query("ports/search/ifAlias, ifName/WAN", params={"columns": ["port_id", " ifAlias"]})
        self.assertEqual(
            out["results"], [{"port_id": 5, "ifAlias": "WAN: transit-a"}, {"port_id": 6, "ifAlias": "WAN: transit-b"}]
        )
        self.assertEqual(self.gets()[-1]["path"], "ports/search/ifAlias,ifName/WAN")
        self.assertEqual([row["port_id"] for row in self.query("ports/search/uplink")["results"]], [1])
        out = self.query("ports/mac/00:11:22:33:44:55")
        self.assertEqual([(row["port_id"], row["fdb_entries_count"]) for row in out["results"]], [(9, 1), (2, 2)])
        out = self.query("ports/mac/0011.2233.4455", params={"filter": "first"}, fields=["port_id", "ifName"])
        self.assertEqual(out["result"], {"port_id": 9, "ifName": "Gi1/0/48"})  # the likely edge port, as an object

    def test_neighbours_sensors_and_transceivers(self):
        out = self.query("devices/core-sw1.example.net/links", fields=["local_port_id", "remote_hostname", "protocol"])
        self.assertEqual(
            out["results"],
            [
                {"local_port_id": 1, "remote_hostname": "edge-rtr1", "protocol": "cdp"},
                {"local_port_id": 2, "remote_hostname": "access-sw2.example.net", "protocol": "lldp"},
            ],
        )
        self.assertEqual(self.query("resources/links")["count"], 4)
        self.assertEqual(self.query("devices/lab-fw1.example.net/links")["note"], "Links do not exist")
        self.assertEqual(self.query("resources/links/4")["results"][0]["remote_device_id"], 0)  # not monitored
        self.assertIn("Link 9 does not exist", self.query("resources/links/9")["note"])
        out = self.query("resources/sensors", fields=["sensor_id", "sensor_class", "sensor_current", "sensor_limit"])
        self.assertEqual(out["results"][3], {"sensor_id": 4, "sensor_class": "temperature", "sensor_current": 71,
                                             "sensor_limit": 70})  # fmt: skip
        out = self.query("devices/core-sw1.example.net/transceivers", fields=["port_id", "model", "ddm", "wavelength"])
        self.assertEqual(out["results"], [{"port_id": 1, "model": "GLC-LH-SMD", "ddm": True, "wavelength": 1310}])

    def test_routing_sessions_are_filtered_by_a_resolved_device(self):
        out = self.query(
            "bgp", params={"hostname": "edge-rtr1.example.net"}, fields=["bgpPeerIdentifier", "bgpPeerState"]
        )
        self.assertEqual(
            out["results"],
            [
                {"bgpPeerIdentifier": "203.0.113.1", "bgpPeerState": "established"},
                {"bgpPeerIdentifier": "198.51.100.9", "bgpPeerState": "idle"},
            ],
        )
        self.assertEqual(self.gets()[-1]["params"], {"hostname": "2"})
        self.assertEqual(self.query("bgp")["count"], 2)  # a session without a state is not listed
        self.assertEqual(self.query("bgp/2")["results"][0]["bgpPeerLastErrorText"], "Administrative Shutdown")
        out = self.query("ospf", params={"hostname": "core-sw1.example.net"}, fields=["ospfNbrRtrId", "ospfNbrState"])
        self.assertEqual(out["results"], [{"ospfNbrRtrId": "198.51.100.2", "ospfNbrState": "full"}])

    def test_syslog_and_the_alert_log_page_with_a_total(self):
        out = self.query("logs/syslog/edge-rtr1.example.net", limit=1, fields=["seq", "msg"])
        self.assertEqual((out["count"], out["total"], out["truncated"]), (1, 2, True))
        self.assertEqual(out["results"], [{"seq": 3, "msg": "neighbor 198.51.100.9 Down BGP Notification sent"}])
        self.assertEqual(self.gets()[-1]["params"], {"limit": "1", "start": "0", "sortorder": "DESC"})
        out = self.query("logs/alertlog/edge-rtr1.example.net", params={"sortorder": "asc"})
        self.assertEqual([row["id"] for row in out["results"]], [2, 3, 1])
        self.assertEqual(out["total"], 3)

    def test_where_a_mac_is(self):
        for mac in ("00:11:22:33:44:55", "00-11-22-33-44-55", "0011.2233.4455", "001122334455"):
            out = self.query(f"resources/fdb/{mac}")
            self.assertEqual([row["port_id"] for row in out["results"]], [9, 2], mac)
            self.assertEqual(self.gets()[-1]["path"], "resources/fdb/001122334455")
            self.assertEqual(self.query(f"resources/nac/{mac}")["results"][0]["port_id"], 9)
        # the HSRP virtual MAC with single-digit groups is 12 characters long, separators and all
        self.fake.seed(
            "ports_fdb",
            {
                "port_id": 2,
                "mac_address": "00000c07ac01",
                "vlan_id": 1,
                "device_id": 1,
                "created_at": "2026-10-28 10:00:00",
                "updated_at": "2026-10-28 10:00:00",
            },
        )
        for mac in ("00:00:0c:07:ac:01", "0:0:c:7:ac:1", "0-0-c-7-ac-1"):
            self.assertEqual([row["port_id"] for row in self.query(f"resources/fdb/{mac}")["results"]], [2], mac)
            self.assertEqual(self.gets()[-1]["path"], "resources/fdb/00000c07ac01")
        out = self.query("resources/fdb/00:11:22:33:44:55/detail")
        self.assertEqual(out["extra"], {"mac": "00:11:22:33:44:55", "mac_oui": "CIMSYS Inc"})
        self.assertEqual((out["results"][0]["ifName"], out["results"][0]["last_seen"]), ("Gi1/0/48", "1 hour ago"))
        self.assertEqual(self.query("resources/ip/arp/192.0.2.50")["results"][0]["mac_address"], "001122334455")
        self.assertEqual(self.query("resources/ip/arp/192.0.2.0/24")["count"], 2)
        out = self.query("resources/ip/arp/all", params={"device": "core-sw1.example.net"})
        self.assertEqual([row["ipv4_address"] for row in out["results"]], ["192.0.2.254"])

    def test_vlans_outages_availability_bills_and_port_groups(self):
        out = self.query("devices/core-sw1.example.net/vlans", fields=["vlan_vlan", "vlan_name"])
        self.assertEqual([row["vlan_vlan"] for row in out["results"]], [1, 10, 20])
        out = self.query("resources/vlans", params={"hostname": "access-sw2.example.net"})
        self.assertEqual([(row["device_id"], row["vlan_vlan"]) for row in out["results"]], [(3, 10)])
        out = self.query("devices/lab-fw1.example.net/outages")
        self.assertEqual(out["results"], [{"going_down": 1761600000, "up_again": None}])
        out = self.query("devices/edge-rtr1.example.net/availability")
        self.assertEqual(out["results"][1], {"duration": 604800, "availability_perc": 99.4})
        out = self.query("bills", fields=["bill_name", "percent", "overuse", "ports"])
        self.assertEqual(out["results"][1]["percent"], 124.0)  # Transit B, over its commit
        self.assertEqual(out["results"][1]["ports"], [{"device_id": 2, "port_id": 6, "ifName": "Gi0/0/1"}])
        self.assertEqual(self.query("bills/2")["count"], 1)
        self.assertTrue(self.query("bills/transit")["refused"])  # LibreNMS would answer with every bill
        self.assertEqual(self.query("port_groups/uplinks")["results"], [{"port_id": 1}, {"port_id": 5}, {"port_id": 6}])
        self.assertEqual(self.query("port_groups/spare")["note"], "No ports found in group spare")
        self.assertEqual([row["name"] for row in self.query("port_groups")["results"]], ["spare", "uplinks"])

    def test_a_params_name_php_reads_as_another_never_reaches_librenms(self):
        # {"limit": 5, " limit": -1} reached LibreNMS as limit=-1 (no limit); hostname[] as an unchecked hostname
        for path, params in (
            ("logs/syslog", {"limit": 5, " limit": -1}),
            ("logs/eventlog", {"hostname[]": "no-such-device.example.net"}),
            ("faults", {"hostname[0]": "core-sw1.example.net"}),
        ):
            out = self.query(path, params=params)
            self.assertTrue(out["refused"], path)
            self.assertIn("reaches LibreNMS as", out["error"])
        self.assertEqual(self.fake.calls, [])
        self.assertEqual(len(self.events("query_refused")), 3)

    def test_poller_group_0_never_reaches_librenms(self):
        # get_poller_group answers poller_group/0 with every group (PHP's empty("0")), so a device in the General
        # group, poller_group 0 and the default, read as one in core-pollers
        self.assertEqual(self.query("poller_group/1")["result"]["group_name"], "core-pollers")
        self.assertEqual(self.query("poller_group/core-pollers")["result"]["id"], 1)
        asked = len(self.fake.calls)
        out = self.query("poller_group/0")
        self.assertTrue(out["refused"])
        self.assertIn("poller group 0 is LibreNMS's General group", out["error"])
        self.assertEqual(len(self.fake.calls), asked)

    def test_an_unknown_hostname_names_the_devices_it_may_mean(self):
        out = self.query("devices/core-sw1/ports")
        self.assertEqual(
            out["error"],
            "no LibreNMS device has hostname 'core-sw1' (hostnames match exactly); devices whose hostname or display "
            "name contains 'core-sw1': core-sw1.example.net",
        )
        self.assertEqual(self.gets()[-1]["params"], {"type": "hostname", "query": "core-sw1"})
        self.assertIn("core-sw1.example.net", self.events("query_refused")[-1]["reason"])


class AlertRows(HandlerCase):
    """Fault and alert-log rows: ``details`` holds every row the rule matched, every column of every table it joins,
    and the alert's contacts; the rows show only the labels of what alerted."""

    def setUp(self):
        super().setUp()
        rows = [
            {"device_id": 2, "port_id": 5, "ifName": f"Gi0/0/{i}", "ifAlias": "WAN " + "x" * 300,
             "ifOperStatus": "down", "sysContact": "noc@example.net", "community": "c0re-Community!"}
            for i in range(40)
        ]  # fmt: skip
        self.fake.tables["faults"][1]["details"] = {"contacts": {"jane.doe@example.net": "Jane Doe"}, "rule": rows}

    def test_faults_carry_the_entities_not_the_details(self):
        out = self.call("librenms_query", path="faults")
        fault = next(row for row in out["results"] if row["id"] == 1)
        self.assertNotIn("details", fault)
        self.assertEqual((len(fault["entities"]), fault["entities_total"]), (10, 40))
        self.assertEqual(set(fault["entities"][0]), {"ifName", "ifAlias"})
        self.assertEqual(fault["entities"][0]["ifAlias"], "WAN " + "x" * 196 + "… [truncated 104 chars]")
        self.assertEqual(next(row for row in out["results"] if row["id"] == 3)["entities"], [])  # no details yet
        for text in ("jane.doe", "noc@example.net", "c0re-Community!", "ifOperStatus"):
            self.assertNotIn(text, self.outputs[-1])
        self.assertLess(len(self.outputs[-1]), 6000)

    def test_naming_details_in_fields_returns_it_without_the_contacts(self):
        out = self.call("librenms_query", path="faults/1", fields=["id", "details", "entities"])
        details = out["results"][0]["details"]
        self.assertEqual((set(details), len(details["rule"])), ({"rule"}, 40))
        self.assertEqual(details["rule"][0]["community"], "<redacted>")
        self.assertNotIn("jane.doe", self.outputs[-1])
        self.assertEqual(len(out["results"][0]["entities"]), 10)

    def test_the_alert_log_and_the_legacy_routes_alike(self):
        out = self.call("librenms_query", path="logs/alertlog/edge-rtr1.example.net")
        self.assertEqual(out["results"][0]["entities"], [{"ifName": "Gi0/0/0", "ifAlias": "WAN: transit-a"}])
        self.assertNotIn("contacts", self.outputs[-1])
        cpu = self.call("librenms_query", path="logs/alertlog/1", params={"sortorder": "asc"})["results"][0]
        self.assertEqual(cpu["entities"], [{"processor_descr": "CPU 0"}])
        self.assertNotIn("details", self.call("librenms_query", path="alerts")["results"][0])


class Envelopes(HandlerCase):
    def test_extras_beside_the_result_are_returned(self):
        out = self.call("librenms_query", path="resources/fdb/001122334455/detail", fields=["hostname"])
        self.assertEqual(out["extra"], {"mac": "00:11:22:33:44:55", "mac_oui": "CIMSYS Inc"})
        self.assertNotIn("extra", self.call("librenms_query", path="devicegroups"))  # message and count are no data

    def test_an_object_keyed_by_id_is_listed_as_rows(self):
        # get_components answers {"7": {...}, "8": {...}}: limit and fields did not apply, fields matched the ids
        out = self.call("librenms_query", path="devices/core-sw1.example.net/components", limit=1,
                        fields=["id", "label", "status"])  # fmt: skip
        self.assertEqual((out["count"], out["returned"], out["truncated"]), (2, 1, True))
        self.assertEqual(out["results"], [{"id": 7, "label": "192.0.2.123", "status": 0}])
        out = self.call("librenms_query", path="devices/core-sw1.example.net/components", params={"status": 2})
        self.assertEqual(out["results"][0]["error"], "Peer unreachable")
        self.assertIsNone(self.call("librenms_query", path="devices/2/components")["result"])
        # an object that is not keyed rows stays an object
        self.assertEqual(self.call("librenms_query", path="location/1", fields=["location"])["result"],
                         {"location": "SFO-1"})  # fmt: skip


class TooLarge(HandlerCase):
    def test_the_advice_names_what_narrows_each_route(self):
        # read with a 3,000-byte cap: one device fits, the listing does not
        self.client.request = functools.partial(type(self.client).request, self.client, max_bytes=3000)
        out = self.call("librenms_query", path="devices", limit=2)
        self.assertEqual((out["success"], out["librenms"]["kind"]), (False, "too_large"))
        self.assertTrue(
            out["error"].startswith(
                "GET /api/v0/devices -> HTTP 200: the answer is larger than 3000 bytes and was not read; narrow the "
                "query: filter with params type and query"
            )
        )
        self.assertTrue(
            out["error"].endswith("(limit does not help here: LibreNMS sends every row and the limit applies after)")
        )
        self.assertNotIn("columns", out["error"])
        out = self.call("librenms_query", path="devices/core-sw1.example.net/ports", params={"columns": "port_id"})
        self.assertTrue(out["success"])  # small enough
        self.fake.tables["eventlog"][1]["message"] = "x" * 5000
        out = self.call("librenms_query", path="logs/eventlog/core-sw1.example.net")
        self.assertTrue(
            out["error"].endswith(
                "narrow the query: ask for fewer rows at a time with a smaller limit, and page with start"
            )
        )
