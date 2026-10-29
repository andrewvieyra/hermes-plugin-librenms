"""librenms_report views ports, port and capacity against the fake LibreNMS: how each reads (per device, per port of a
port group, one listing, and the fallback when that listing is too large), the derived figures in the rows and the
summary, filters, sorts and paging, the call and output budgets, untrusted marking, the single port's neighbours,
transceivers, optics, discards and faults, free ports, and the operator questions of the conversational audit about
ports, utilisation, speeds, duplex, descriptions and free ports, each answered in one or two calls."""

import json

from .helpers import submodule
from .test_reports import SECRETS, ReportCase

routes = submodule("routes")
reports = submodule("reports")
ports_mod = submodule("reports.ports")
natural_key = submodule("listing").natural_key

POLLED = 1793188500  # 2026-10-28T11:55:00Z: LibreNMS's last poll, five minutes before the fake's clock
LAST_POLLED = "2026-10-28T11:55:00.000000Z"
DAY = 86400


def ticks(uptime_s, seconds_before_poll):
    """The ifLastChange of a change *seconds_before_poll* before a poll that found the device up *uptime_s*."""
    return (uptime_s - seconds_before_poll) * 100


class PortCase(ReportCase):
    def setUp(self):
        super().setUp()
        # every device polled five minutes ago; core-sw1 up 100 days, edge-rtr1 50 days, access-sw2 about 13.9 days
        for device_id in (1, 2, 3):
            self.fake.touch("devices", device_id, last_polled=LAST_POLLED)
        polled = {"poll_time": POLLED, "poll_period": 300, "ifDuplex": "fullDuplex", "ifInOctets_rate": 0,
                  "ifOutOctets_rate": 0, "ifInErrors_delta": 0, "ifOutErrors_delta": 0}  # fmt: skip
        for port_id in (1, 2, 5, 6, 9):
            self.fake.touch("ports", port_id, **polled)
        # the core uplink: 100 Mbit/s in, 800 Mbit/s out of 1G, up since three days before the poll
        self.fake.touch("ports", 1, ifInOctets_rate=12_500_000, ifOutOctets_rate=100_000_000,
                        ifLastChange=ticks(8_640_000, 3 * DAY))  # fmt: skip
        # transit-a went down two hours before the poll; Gi1/0/2 and transit-b have not changed since boot
        self.fake.touch("ports", 5, ifLastChange=ticks(4_320_000, 7200))
        self.fake.touch("ports", 9, ifInOctets_rate=1_250_000, ifOutOctets_rate=250_000)  # 10 and 2 Mbit/s

    def port_row(self, out, port_id):
        return next(row for row in out["rows"] if row["port_id"] == port_id)

    def ids(self, out):
        return [row["port_id"] for row in out["rows"]]

    def seed_port(self, **row):
        defaults = {"ifType": "ethernetCsmacd", "ifSpeed": 1_000_000_000, "ifAdminStatus": "up", "ifOperStatus": "up",
                    "poll_time": POLLED, "poll_period": 300, "ifDuplex": "fullDuplex"}  # fmt: skip
        port = self.fake.seed("ports", {**defaults, **row})
        self.fake.now = self.fake.now.replace(hour=12, minute=0, second=0)
        return port

    def reads(self, prefix):
        return [call for call in self.fake.calls if call["path"] == prefix or call["path"].startswith(prefix + "/")]


class Ports(PortCase):
    def test_every_port_in_one_listing(self):
        out = self.report(view="ports")
        self.assertEqual(self.ids(out), [9, 1, 2, 5, 6])  # by hostname, then name
        [listing] = self.reads("ports")
        self.assertEqual(listing["params"], {"columns": ports_mod.COLUMNS})
        self.assertNotIn("ifHighSpeed", ports_mod.COLUMNS)  # not a column of the current ports table: a 400
        uplink = self.port_row(out, 1)
        self.assertEqual(
            {k: uplink[k] for k in ("hostname", "port", "description", "state", "speed", "in", "in_pct", "out",
                                    "out_pct", "util_pct", "duplex", "last_change_age", "polled_at", "stale")},
            {"hostname": "core-sw1.example.net", "port": "Gi1/0/1 (uplink to edge-rtr1)",
             "description": "uplink to edge-rtr1", "state": "up", "speed": "1G", "in": "100 Mbit/s", "in_pct": 10.0,
             "out": "800 Mbit/s", "out_pct": 80.0, "util_pct": 80.0, "duplex": "full", "last_change_age": "3d 0h",
             "polled_at": "2026-10-28T11:55:00Z", "stale": False},
        )  # fmt: skip
        self.assertEqual(
            out["summary"],
            {"in_scope": 5, "by_state": {"up": 2, "down": 3, "disabled": 0, "lowerLayerDown": 0, "notPresent": 0,
                                         "other": 0},
             "not_up": 3, "over_80_pct": 0, "with_errors": 0, "stale": 0, "no_description": 1,
             "busiest": {"device_id": 1, "hostname": "core-sw1.example.net", "port_id": 1,
                         "port": "Gi1/0/1 (uplink to edge-rtr1)", "util_pct": 80.0, "in": "100 Mbit/s",
                         "in_pct": 10.0, "out": "800 Mbit/s", "out_pct": 80.0, "speed": "1G"}},
        )  # fmt: skip
        self.assertNotIn(3, self.ids(out))  # deleted
        self.assertEqual(out["untrusted_fields"], ["hostname", "display", "port", "description"])

    def test_a_few_devices_are_read_one_at_a_time(self):
        out = self.report(view="ports", scope={"devices": ["core-sw1", "access-sw2"]})
        self.assertEqual(self.ids(out), [9, 1, 2])
        self.assertEqual([c["path"] for c in self.reads("devices") if c["path"] != "devices"],
                         ["devices/3/ports", "devices/1/ports"])  # fmt: skip
        self.assertTrue(all(c["params"] == {"columns": ports_mod.COLUMNS} for c in self.reads("devices/1")))
        self.assertEqual(self.reads("ports"), [])

    def test_more_than_ten_devices_read_one_listing(self):
        names = []
        for number in range(11):
            device = self.seed_device(hostname=f"acc{number:02d}.example.net", sysName=f"acc{number:02d}")
            self.seed_port(device_id=device["device_id"], ifIndex=1, ifName="Gi1/0/1")
            names.append(device["hostname"])
        out = self.report(view="ports", scope={"devices": names})
        self.assertEqual(out["count"], 11)
        self.assertEqual(len(self.reads("ports")), 1)
        self.assertEqual([c for c in self.fake.calls if c["path"].endswith("/ports")], [])

    def test_a_port_group(self):
        out = self.report(view="ports", scope={"port_group": "uplinks"})
        self.assertEqual(self.ids(out), [1, 5, 6])
        self.assertEqual(out["scope"]["port_group"], {"port_group_id": 1, "name": "uplinks", "ports": 3})
        self.assertIn("name", out["untrusted_fields"])
        self.assertEqual([c["path"] for c in self.reads("ports")], ["ports/1", "ports/5", "ports/6"])
        self.assertTrue(all("full" not in c["params"] for c in self.reads("port_groups")))
        # a larger group: one listing, filtered to its ports; with a device, only that device's
        members = [self.seed_port(device_id=3, ifIndex=100 + n, ifName=f"Gi2/0/{n}")["port_id"] for n in range(11)]
        self.fake.seed("port_groups", {"id": 3, "name": "access-uplinks", "ports": members})
        self.fake.calls.clear()
        out = self.report(view="ports", scope={"port_group": 3, "device": "access-sw2"})
        self.assertEqual(sorted(self.ids(out)), members)
        self.assertEqual([c["path"] for c in self.reads("ports")], [])  # one device: its own ports
        out = self.report(view="ports", scope={"port_group": "access-uplinks"})
        self.assertEqual(len(self.reads("ports")), 1)
        self.assertEqual(out["count"], 11)

    def test_a_port_group_by_part_of_its_name_or_nobody_has(self):
        self.fake.seed("port_groups", {"id": 3, "name": "uplinks-dc2", "ports": [9]})
        out = self.report(view="ports", scope={"port_group": "uplink"})
        self.assertTrue(out["ambiguous"])
        self.assertEqual([c["name"] for c in out["candidates"]], ["uplinks", "uplinks-dc2"])
        self.assertEqual(out["candidates"][0]["kind"], "port_group")
        self.assertIn("then call again with its port_group_id or exact name", out["notes"][0])
        out = self.report(view="ports", scope={"port_group": "Uplinks"})  # the exact name, in any case, is that one
        self.assertEqual(out["scope"]["port_group"]["name"], "uplinks")
        out = self.report(view="ports", scope={"port_group": "transit"})
        self.assertTrue(out["refused"])
        self.assertIn("LibreNMS has no port group by that name or id; its port groups: 'spare', 'uplinks'",
                      out["error"])  # fmt: skip
        out = self.report(view="ports", scope={"port_group": "spare"})  # LibreNMS's 404: no ports in it
        self.assertEqual((out["count"], out["notes"]), (0, ["port group 'spare' holds no ports"]))

    def test_filters(self):
        lower = self.seed_port(device_id=1, ifIndex=20, ifName="Gi1/0/20", ifAlias="Gi1/0/20",
                               ifOperStatus="lowerLayerDown")["port_id"]  # fmt: skip
        printer = self.seed_port(device_id=1, ifIndex=21, ifName="Fa0/1", ifAlias="printer", ifSpeed=100_000_000,
                                 ifDuplex="halfDuplex", ifInErrors_delta=12)["port_id"]  # fmt: skip
        lag = self.seed_port(device_id=1, ifIndex=22, ifName="Po1", ifType="ieee8023adLag", ifAlias="to dist",
                             ifAdminStatus="down", ifOperStatus="down")["port_id"]  # fmt: skip

        def ids(**filters):
            return self.ids(self.report(view="ports", scope={"device": 1}, filter=filters, limit=50))

        self.assertEqual(ids(state="down"), [2])
        self.assertEqual(ids(state=["LOWERLAYERDOWN", "disabled"]), [lower, lag])  # any case, held as LibreNMS's
        self.assertEqual(ids(util_above_pct=79.9), [1])
        self.assertEqual(ids(util_above_pct="80"), [])  # above, not at
        self.assertEqual(ids(errors=True), [printer])
        self.assertEqual(ids(speed_below_mbps=1000), [printer])
        self.assertEqual(ids(duplex="half"), [printer])
        self.assertEqual(ids(no_description=True), [2, lower])  # empty, and only its own name
        self.assertEqual(ids(type="ethernet"), [printer, 1, 2, lower])
        self.assertEqual(ids(type="ieee8023adlag"), [lag])
        self.assertEqual(ids(text="EDGE"), [1])  # in the description
        self.assertEqual(ids(text="gigabitethernet1/0/2"), [2])  # in ifDescr, which the label leaves out
        out = self.report(view="ports", filter={"state": "up", "util_above_pct": 5})  # every one must hold
        self.assertEqual(self.ids(out), [1])
        for bad, message in (({"util_above_pct": -1}, "takes a number, 0 or more"),
                             ({"util_above_pct": True}, "takes a number"),
                             ({"state": "broken"}, "filter.state takes up, down, disabled, lowerLayerDown"),
                             ({"duplex": "simplex"}, "filter.duplex takes full, half, unknown"),
                             ({"idle_days": 3}, "view ports takes filter keys state, util_above_pct")):  # fmt: skip
            out = self.report(view="ports", filter=bad)
            self.assertIn(message, out["error"], bad)

    def test_a_stale_port_has_no_current_figures(self):
        # edge-rtr1 stopped answering: its ports keep the rates and errors of their last poll, an hour ago
        for port_id in (5, 6):
            self.fake.touch("ports", port_id, poll_time=POLLED - 3300, ifInOctets_rate=124_000_000,
                            ifInErrors_delta=900)  # fmt: skip
        out = self.report(view="ports", sort="util")
        self.assertEqual(self.ids(out), [1, 9, 2, 5, 6])  # current figures first; Gi1/0/2 has 0 %
        stale = self.port_row(out, 5)
        self.assertEqual((stale["stale"], stale["util_pct"], stale["polled_at"]), (True, 99.2, "2026-10-28T11:00:00Z"))
        self.assertEqual((out["summary"]["stale"], out["summary"]["over_80_pct"], out["summary"]["with_errors"]),
                         (2, 0, 0))  # fmt: skip
        self.assertEqual(self.ids(self.report(view="ports", filter={"util_above_pct": 80})), [])
        self.assertEqual(self.ids(self.report(view="ports", filter={"errors": True})), [])

    def test_sorts_and_stable_paging(self):
        for number in range(45):
            self.seed_port(device_id=3, ifIndex=100 + number, ifName=f"Gi2/0/{number}",
                           ifInOctets_rate=(number * 7919) % 13 * 1_000_000, ifOutOctets_rate=0,
                           ifInErrors_delta=number % 4, ifSpeed=[10**9, 10**8, 10**10][number % 3])  # fmt: skip
        every = self.report(view="ports", sort="util", limit=500)
        seen, offset = [], 0
        while offset is not None:
            out = self.report(view="ports", sort="util", limit=7, offset=offset)
            seen += self.ids(out)
            offset = out.get("next_offset")
        self.assertEqual(seen, self.ids(every))
        self.assertEqual(len(set(seen)), 50)
        utils = [row["util_pct"] for row in every["rows"] if row["util_pct"] is not None]
        self.assertEqual(utils, sorted(utils, reverse=True))
        ties = [row for row in every["rows"] if row["util_pct"] == 0.0]  # equals by name: Gi2/0/2 before Gi2/0/10
        self.assertEqual(ties, sorted(ties, key=lambda row: (row["hostname"], natural_key(row["port"]))))
        errors = self.report(view="ports", sort="errors", limit=500)["rows"]
        self.assertEqual([r["in_errors_per_poll"] for r in errors[:3]], [3, 3, 3])
        speeds = [row["speed_bps"] for row in self.report(view="ports", sort="speed", limit=500)["rows"]]
        self.assertEqual(speeds, sorted(speeds))
        for sort, key in (("util_in", "in_pct"), ("util_out", "out_pct")):
            rows = self.report(view="ports", sort=sort, limit=500)["rows"]
            values = [row[key] for row in rows if row[key] is not None]
            self.assertEqual((rows[0][key], values), (max(values), sorted(values, reverse=True)), sort)
        self.assertEqual(self.report(view="ports", sort="util_out")["rows"][0]["port_id"], 1)

    def test_the_output_budget_cuts_rows_and_reads_on(self):
        for number in range(300):
            self.seed_port(device_id=3, ifIndex=100 + number, ifName=f"Gi2/0/{number}", ifAlias="x" * 150)
        self.settings_with(max_result_chars=8000, max_query_results=500)
        seen, offset = [], 0
        while offset is not None:
            out = self.report(view="ports", limit=500, offset=offset)
            self.assertLessEqual(len(self.outputs[-1]), 8000)
            seen += self.ids(out)
            if out.get("next_offset") is not None:
                self.assertTrue(out["truncated"])
                self.assertEqual(out["summary"]["in_scope"], 305)
            offset = out.get("next_offset")
        self.assertEqual((len(seen), len(set(seen))), (305, 305))

    def test_the_call_budget_makes_the_answer_partial(self):
        out = reports.run(self.client, self.settings, {"view": "ports", "scope": {"devices": [1, 2, 3]}},
                          call_budget=3)  # fmt: skip
        self.assertTrue(out["partial"])
        self.assertEqual(out["partial_reason"], "ports of device 2 not read: the report used its 3 requests")
        self.assertEqual(sorted(row["device_id"] for row in out["rows"]), [1, 1, 3])

    def test_a_failed_read_of_one_device_of_several_is_partial_of_the_only_one_fails(self):
        self.fake.fail_on("GET", "devices/3/ports", 500)
        out = self.report(view="ports", scope={"devices": ["core-sw1", "access-sw2"]})
        self.assertEqual((out["partial"], self.ids(out)), (True, [1, 2]))
        self.assertEqual(out["partial_reason"], "ports of device 3 not read: LibreNMS answered HTTP 500 (server)")
        out = self.report(view="ports", scope={"device": "access-sw2"})
        self.assertFalse(out["success"])

    def test_a_listing_too_large_to_read_falls_back_to_each_device(self):
        real = self.client.get

        def get(path, params=None):
            if path == "ports":
                raise self.client_mod.LibreNMSError("too large", status=200, kind="too_large")
            return real(path, params)

        self.client.get = get
        out = reports.run(self.client, self.settings, {"view": "ports"})
        self.assertEqual(sorted(self.ids(out)), [1, 2, 5, 6, 9])
        self.assertFalse(out["partial"])  # every device in scope was read: nothing is missing
        self.assertEqual(
            out["notes"],
            ["LibreNMS's listing of every port is too large to read, so the ports were read one device at a time"],
        )
        self.assertEqual(len([c for c in self.fake.calls if c["path"].endswith("/ports")]), 4)
        out = reports.run(self.client, self.settings, {"view": "ports"}, call_budget=3)
        self.assertTrue(out["partial"])
        self.assertIn("the ports of 1 of the 4 devices in scope were read", out["partial_reason"])
        # a device whose read fails is partial on its own, and not counted among those read
        self.fake.fail_on("GET", "devices/3/ports", 500)
        out = reports.run(self.client, self.settings, {"view": "ports"})
        self.assertEqual((out["partial"], sorted(self.ids(out))), (True, [1, 2, 5, 6]))
        self.assertEqual(out["partial_reason"], "ports of device 3 not read: LibreNMS answered HTTP 500 (server)")
        out = reports.run(self.client, self.settings, {"view": "ports"}, call_budget=4)
        self.assertIn("the ports of 1 of the 4 devices in scope were read", out["partial_reason"])

    def test_text_from_librenms_is_escaped_clipped_and_marked(self):
        self.fake.touch("ports", 9, ifAlias="to core‮-sw1 " + "y" * 600)
        out = self.report(view="ports", scope={"device": 3})
        row = self.port_row(out, 9)
        self.assertTrue(row["description"].startswith("to core\\u202e-sw1 yyy"))
        self.assertIn("… [truncated", row["description"])
        self.assertNotIn("‮", self.outputs[-1])
        self.assertIn("description", out["untrusted_fields"])

    def test_every_read_is_an_allowed_get_and_nothing_is_written(self):
        self.report(view="ports")
        self.report(view="ports", scope={"device": "core-sw1", "port_group": "uplinks"})
        self.report(view="capacity", scope={"location": "SFO"})
        self.report(view="port", scope={"device": "core-sw1", "port": "Gi1/0/1"})
        self.report(view="port", scope={"port": "Gi1/0/48"})
        self.assert_reads_only_allowed_gets()
        read = {routes.match(call["path"])[0].name for call in self.fake.calls}
        self.assertEqual(
            read,
            {"list_devices", "get_all_ports", "get_device_ports", "get_port_groups", "get_ports_by_group",
             "get_port_info", "list_links_device", "get_port_transceiver", "list_sensors", "list_alerts",
             "search_ports"},
        )  # fmt: skip
        for raw in self.outputs:
            for secret in SECRETS:
                self.assertNotIn(secret, raw)
            self.assertNotIn("details", raw)  # never a fault's details, nor its contacts
            self.assertNotIn("noc@example.net", raw)


class Port(PortCase):
    def test_one_port_in_depth(self):
        out = self.report(view="port", scope={"device": "core-sw1", "port": "Gi1/0/1"})
        [row] = out["rows"]
        self.assertEqual((row["port_id"], row["util_pct"], row["ifDescr"]), (1, 80.0, "GigabitEthernet1/0/1"))
        self.assertEqual(
            (row["in_discards_per_poll"], row["out_discards_per_poll"], row["out_discards_per_s"]), (0, 42, 0.14)
        )
        self.assertEqual(row["neighbours"], [
            {"protocol": "cdp", "remote_hostname": "edge-rtr1", "remote_port": "GigabitEthernet0/0/2",
             "remote_platform": "cisco ISR4451-X/K9", "remote_monitored": True,
             "remote_device": {"device_id": 2, "hostname": "edge-rtr1.example.net", "display": "edge-rtr1"},
             "remote_port_id": None, "active": True},
        ])  # fmt: skip
        self.assertEqual(
            row["transceivers"],
            [{"type": "1000BASE-LX SFP", "vendor": "CISCO-FINISAR", "model": "GLC-LH-SMD", "serial": "FNS12345ABC",
              "connector": "LC", "distance": 10000, "ddm": True, "wavelength_nm": 1310}],
        )  # fmt: skip
        self.assertEqual(
            row["optics"],
            [{"sensor_id": 2, "descr": "Gi1/0/1 Receive Power Sensor", "dbm": -3.2, "limit_low": -14.4,
              "limit_low_warn": None, "limit_warn": None, "limit": 1.0, "status": "ok"}],
        )  # fmt: skip
        self.assertEqual(row["alerts"], [])
        self.assertEqual(
            out["summary"],
            {"state": "up", "util_pct": 80.0, "stale": False, "errors_per_poll": 0, "discards_per_poll": 42,
             "neighbours": 1, "optics": "ok", "open_alerts": 0},
        )  # fmt: skip
        self.assertEqual(self.reads("ports")[0]["params"], {"with": "statistics"})
        for key in ("remote_hostname", "remote_port", "vendor", "descr", "rule", "note", "description"):
            self.assertIn(key, out["untrusted_fields"])

    def test_a_port_by_id_name_short_name_or_description(self):
        long = self.seed_port(device_id=2, ifIndex=7, ifName="GigabitEthernet0/0/7", ifDescr="GigabitEthernet0/0/7")
        cases = (
            ({"port": 9}, 9),
            ({"port": "9"}, 9),
            ({"port": "Gi1/0/48"}, 9),  # the one port with that name anywhere
            ({"port": "to core-sw1"}, 9),  # or that description
            ({"device": "core-sw1", "port": "gigabitethernet1/0/2"}, 2),
            ({"device": "core-sw1", "port": "2"}, 2),  # a port_id among its ports
            ({"device": "edge-rtr1", "port": "Gi0/0/7"}, long["port_id"]),  # the short form of a long name
            ({"device": "edge-rtr1", "port": "WAN: transit-b"}, 6),
            ({"device": "edge-rtr1", "port": "transit b"}, 6),  # every word of it
        )
        for scope, port_id in cases:
            out = self.report(view="port", scope=scope)
            self.assertEqual(out["rows"][0]["port_id"], port_id, scope)

    def test_a_name_that_could_be_several_ports_is_not_guessed(self):
        out = self.report(view="port", scope={"port": "Gi0/0"})
        self.assertTrue(out["ambiguous"])
        self.assertEqual([(c["kind"], c["port_id"]) for c in out["candidates"]], [("port", 5), ("port", 6)])
        self.assertIn("then call again with its port_id", out["notes"][0])
        out = self.report(view="port", scope={"device": "edge-rtr1", "port": "transit"})
        self.assertEqual([c["port_id"] for c in out["candidates"]], [5, 6])
        self.assertEqual(out["candidates"][0]["hostname"], "edge-rtr1.example.net")

    def test_a_port_nobody_has_is_refused_and_audited(self):
        for scope, message in (
            ({"device": "core-sw1", "port": "Gi9/9/9"}, "has no port by that name, number or description; its ports "
                                                        "include 'Gi1/0/1', 'Gi1/0/2'"),
            ({"port": 999}, "no LibreNMS port has id 999"),
            ({"port": "Te7/7/7"}, "no port's ifName, ifDescr or description holds that"),
        ):  # fmt: skip
            out = self.report(view="port", scope=scope)
            self.assertTrue(out["refused"], scope)
            self.assertIn(message, out["error"])
        self.assertEqual([e["view"] for e in self.events("query_refused")], ["port"] * 3)

    def test_malformed_port_arguments(self):
        for scope, message in (
            (None, "view port needs scope.port"),
            ({"device": "core-sw1"}, "view port needs scope.port"),
            ({"port": "Gi1/0/1", "port_group": "uplinks"}, "view port takes scope keys device, port, not"),
            ({"port": True}, "scope.port takes a name, an id or a few words"),
        ):
            out = self.report(view="port", scope=scope)
            self.assertFalse(out["success"], scope)
            self.assertIn(message, out["error"], scope)
            self.assertNotIn("refused", out)
        # what a path cannot hold cannot be searched for fleet-wide: say to name the device, never audit a refusal
        for name in ("50%", "Gi1//1", "Gi1/0/1/", "./x", "Circuit #4411", "cust ACME?", "x\\y", "http://x"):
            out = self.report(view="port", scope={"port": name})
            self.assertFalse(out["success"], name)
            self.assertNotIn("refused", out, name)
            self.assertIn("cannot be searched for among every port", out["error"], name)
            self.assertIn("name the port's device with scope.device", out["error"], name)
        self.assertEqual(self.events("query_refused"), [])
        self.assertEqual([c for c in self.fake.calls if "search" in c["path"]], [])
        # on its device, the same description is matched as given
        port_id = self.seed_port(device_id=3, ifIndex=77, ifName="Gi1/0/7", ifAlias="Circuit #4411")["port_id"]
        out = self.report(view="port", scope={"device": "access-sw2", "port": "Circuit #4411"})
        self.assertEqual(out["rows"][0]["port_id"], port_id)

    def test_optics_on_the_port_and_their_limits(self):
        # a Tx sensor LibreNMS measured on the port's ifIndex, past its high warning
        self.fake.seed("sensors", {"device_id": 1, "sensor_class": "dbm", "sensor_type": "cisco-entity-sensor",
                                   "sensor_descr": "Gi1/0/1 Transmit Power Sensor", "sensor_current": 0.4,
                                   "sensor_limit": 1, "sensor_limit_warn": 0, "sensor_limit_low": -9.5,
                                   "entPhysicalIndex": "1", "entPhysicalIndex_measured": "ports"})  # fmt: skip
        self.fake.seed("sensors", {"device_id": 1, "sensor_class": "dbm", "sensor_descr": "Gi1/0/2 Rx",
                                   "sensor_current": -40, "sensor_limit_low": -20, "entPhysicalIndex": "2",
                                   "entPhysicalIndex_measured": "ports"})  # fmt: skip
        out = self.report(view="port", scope={"device": 1, "port": "Gi1/0/1"})
        self.assertEqual(
            [(o["descr"], o["status"]) for o in out["rows"][0]["optics"]],
            [("Gi1/0/1 Receive Power Sensor", "ok"), ("Gi1/0/1 Transmit Power Sensor", "warning")],
        )
        self.assertEqual(out["summary"]["optics"], "warning")
        out = self.report(view="port", scope={"device": 1, "port": "Gi1/0/2"})
        self.assertEqual(out["summary"]["optics"], "critical")

    def test_open_alerts_about_the_port(self):
        out = self.report(view="port", scope={"device": "edge-rtr1", "port": "Gi0/0/1"})
        [alert] = out["rows"][0]["alerts"]
        self.assertEqual(
            alert,
            {"alert_id": 2, "rule": "Port down", "severity": "warning", "state": "acknowledged",
             "first_seen": "2026-10-28 09:10:00", "first_seen_age_s": None, "first_seen_age": None,
             "note": "2026-10-28 09:15:00 - Ack (alice) carrier ticket 4411"},
        )  # fmt: skip
        [faults] = self.reads("faults")
        self.assertEqual(faults["params"], {"state": "1,2,3,4,5"})
        self.settings_with(librenms_timezone="Europe/Amsterdam")  # server-local times read in LibreNMS's zone
        [alert] = self.report(view="port", scope={"port": 5})["rows"][0]["alerts"]
        self.assertEqual((alert["first_seen"], alert["first_seen_age"]), ("2026-10-28T10:02:00+01:00", "2h 58m"))

    def test_what_cannot_be_read_leaves_the_answer_partial(self):
        self.fake.fail_on("GET", "resources/sensors", 500)
        self.fake.fail_on("GET", "faults", 503)
        out = self.report(view="port", scope={"port": 1})
        row = out["rows"][0]
        self.assertEqual((row["optics"], row["alerts"], out["summary"]["open_alerts"]), (None, None, None))
        self.assertTrue(out["partial"])
        self.assertIn("optic sensors not read: LibreNMS answered HTTP 500", out["partial_reason"])
        self.assertIn("open alerts not read: LibreNMS answered HTTP 503", out["partial_reason"])
        self.assertEqual(len(row["neighbours"]), 1)  # what could be read is there
        self.assertEqual(list(row["transceivers"][0])[-1], "wavelength_nm")  # its inventory entity stays out
        self.assertEqual(
            out["scope"],
            {
                "device_count": 1,
                "devices": [{"device_id": 1, "hostname": "core-sw1.example.net", "display": "core-sw1"}],
            },
        )  # the port's device

    def test_a_librenms_without_the_transceivers_route_is_not_partial(self):
        self.fake.missing_routes.add("get_port_transceiver")  # an older LibreNMS
        out = self.report(view="port", scope={"port": 1})
        row = out["rows"][0]
        # Gi1/0/1's optic hangs from its transceiver's entity, which this LibreNMS cannot say
        self.assertEqual((row["transceivers"], row["optics"], out["partial"]), (None, [], False))
        self.assertIn(
            "this LibreNMS has no transceivers route (an older release): the port's transceivers are not listed, and "
            "its optics are those measured on its ifIndex",
            out["notes"],
        )
        self.fake.missing_routes.clear()
        self.fake.fail_on("GET", "ports/1/transceiver", 500)  # a real failure still is partial
        out = self.report(view="port", scope={"port": 1})
        self.assertEqual((out["rows"][0]["transceivers"], out["partial"]), (None, True))
        self.assertEqual(out["partial_reason"], "transceivers not read: LibreNMS answered HTTP 500 (server)")

    def test_a_deleted_port(self):
        out = self.report(view="port", scope={"port": 3})
        self.assertEqual(out["rows"][0]["port_id"], 3)
        self.assertIn("LibreNMS marks this port deleted", out["notes"][-1])


class Capacity(PortCase):
    def test_free_ports_per_device(self):
        out = self.report(view="capacity")
        rows = {row["hostname"]: row for row in out["rows"]}
        self.assertEqual(list(rows), ["access-sw2.example.net", "core-sw1.example.net", "edge-rtr1.example.net"])
        core, edge = rows["core-sw1.example.net"], rows["edge-rtr1.example.net"]
        self.assertEqual(
            {k: core[k] for k in ("ethernet_ports", "up", "down", "disabled", "free", "free_unknown", "used_pct",
                                  "free_by_speed", "location", "stale")},
            {"ethernet_ports": 2, "up": 1, "down": 1, "disabled": 0, "free": 1, "free_unknown": 0, "used_pct": 50.0,
             "free_by_speed": {"1G": 1}, "location": "SFO-1", "stale": False},
        )  # fmt: skip
        self.assertEqual((edge["free"], edge["down"]), (1, 2))  # transit-a went down two hours ago: not free
        self.assertEqual(
            out["summary"],
            {"in_scope": 4, "without_ethernet_ports": 1, "idle_days": 30, "ethernet_ports": 5, "up": 2, "down": 3,
             "disabled": 0, "free": 2, "free_unknown": 0},
        )  # fmt: skip
        self.assertEqual(self.report(view="capacity", filter={"idle_days": 0.05})["summary"]["free"], 3)

    def test_a_device_up_less_than_idle_days_cannot_say(self):
        self.seed_port(device_id=3, ifIndex=1, ifName="Gi1/0/1", ifOperStatus="notPresent", ifSpeed=10**10)
        self.seed_port(device_id=3, ifIndex=2, ifName="Gi1/0/2", ifOperStatus="down",
                       ifLastChange=ticks(1_200_000, 12 * DAY))  # fmt: skip
        out = self.report(view="capacity", scope={"device": "access-sw2"})
        [row] = out["rows"]  # up 13.9 days: a port unchanged since boot may be free at 30 days, or not
        self.assertEqual((row["free"], row["free_unknown"], row["down"]), (0, 1, 2))
        self.assertIn("free_unknown counts ports that are not up", out["notes"][0])
        [row] = self.report(view="capacity", scope={"device": 3}, filter={"idle_days": 7})["rows"]
        self.assertEqual((row["free"], row["free_unknown"], row["free_by_speed"]), (2, 0, {"1G": 1, "10G": 1}))

    def test_only_physical_ethernet_ports_count(self):
        self.seed_port(device_id=1, ifIndex=30, ifName="Gi1/0/1.100", ifOperStatus="down")
        self.seed_port(device_id=1, ifIndex=31, ifName="Po1", ifType="ieee8023adLag")
        self.seed_port(device_id=1, ifIndex=32, ifName="Vlan10", ifType="propVirtual")
        [row] = self.report(view="capacity", scope={"device": 1})["rows"]
        self.assertEqual(row["ethernet_ports"], 2)

    def test_sorts_and_arguments(self):
        for number in range(3):
            self.seed_port(device_id=3, ifIndex=10 + number, ifName=f"Gi1/0/{number}", ifOperStatus="down")
        self.fake.touch("devices", 3, uptime=60 * DAY)
        self.assertEqual(self.hostnames(self.report(view="capacity", sort="free"))[0], "access-sw2.example.net")
        self.assertEqual(self.hostnames(self.report(view="capacity", sort="used_pct"))[0], "core-sw1.example.net")
        out = self.report(view="capacity", scope={"port_group": "uplinks"})
        self.assertIn("view capacity takes scope keys device, devices, group, location, os, type", out["error"])
        self.assertIn(
            "filter.idle_days takes a number", self.report(view="capacity", filter={"idle_days": "x"})["error"]
        )


class OperatorQuestions(PortCase):
    """The conversational audit's questions about ports, utilisation, speeds, duplex, descriptions and free ports,
    each answered by one or two librenms_report calls from the summary or the rows. (Discards are per port, in view
    port; flaps, err-disabled ports and history are not in what the API keeps: the skill says so.)"""

    def test_which_ports_on_a_switch_are_down(self):  # 1
        out = self.report(view="ports", scope={"device": "core switch sfo"}, filter={"state": "down"})
        self.assertEqual([(row["port"], row["state"]) for row in out["rows"]], [("Gi1/0/2", "down")])

    def test_which_ports_fleet_wide_are_down_that_should_be_up(self):  # 2
        self.fake.touch("ports", 6, ignore=1)  # someone told LibreNMS to ignore transit-b
        out = self.report(view="ports", filter={"state": ["down", "lowerLayerDown", "notPresent"]}, limit=1)
        self.assertEqual((out["count"], out["summary"]["not_up"]), (3, 2))  # LibreNMS does not count it down
        self.fake.touch("ports", 2, disabled=1)  # nor a port whose polling someone disabled
        out = self.report(view="ports", filter={"state": ["down", "lowerLayerDown", "notPresent"]})
        self.assertEqual((out["count"], out["summary"]["not_up"]), (3, 1))
        self.assertEqual([(row["port_id"], row["ignored"], row["polling_disabled"]) for row in out["rows"]],
                         [(2, False, True), (5, False, False), (6, True, False)])  # fmt: skip

    def test_which_ports_have_errors_now(self):  # 3
        self.fake.touch("ports", 9, ifInErrors_delta=1500, ifOutErrors_delta=3)
        out = self.report(view="ports", filter={"errors": True}, sort="errors")
        [row] = out["rows"]
        self.assertEqual((row["port"], row["in_errors_per_poll"], row["in_errors_per_s"]),
                         ("Gi1/0/48 (to core-sw1)", 1500, 5.0))  # fmt: skip
        self.assertEqual(out["summary"]["with_errors"], 1)

    def test_discards_on_a_port(self):  # 4, for one port
        summary = self.report(view="port", scope={"device": "core-sw1", "port": "Gi1/0/1"})["summary"]
        self.assertEqual(summary["discards_per_poll"], 42)

    def test_when_did_a_port_last_change_state(self):  # 5
        [row] = self.report(view="ports", scope={"device": "edge-rtr1"}, filter={"text": "Gi0/0/0"})["rows"]
        self.assertEqual((row["state"], row["last_change_age"]), ("down", "2h 5m"))

    def test_how_busy_is_the_uplink_of_a_switch(self):  # 8, and the failure scenario of both findings
        self.fake.touch("ports", 1, ifInOctets_rate=125_000_000)
        [row] = self.report(view="ports", scope={"device": "core-sw1"}, filter={"text": "uplink"})["rows"]
        self.assertEqual(
            (row["in"], row["in_pct"], row["out"], row["out_pct"]), ("1 Gbit/s", 100.0, "800 Mbit/s", 80.0)
        )

    def test_top_busiest_ports_in_the_network_and_on_one_switch(self):  # 9, 10
        for number in range(12):
            self.seed_port(device_id=3, ifIndex=100 + number, ifName=f"Te1/1/{number}", ifSpeed=10**10,
                           ifInOctets_rate=number * 100_000_000, ifOutOctets_rate=0)  # fmt: skip
        out = self.report(view="ports", sort="util", limit=10)
        # Te1/1/10 and the core uplink both run at 80 %: by hostname, access-sw2 first
        self.assertEqual([(row["port"], row["util_pct"]) for row in out["rows"][:4]],
                         [("Te1/1/11", 88.0), ("Te1/1/10", 80.0), ("Gi1/0/1 (uplink to edge-rtr1)", 80.0),
                          ("Te1/1/9", 72.0)])  # fmt: skip
        self.assertEqual(out["summary"]["busiest"]["port"], "Te1/1/11")
        out = self.report(view="ports", scope={"device": "core-sw1"}, sort="util", limit=1)
        self.assertEqual(out["rows"][0]["port_id"], 1)

    def test_which_links_are_above_80_percent(self):  # 11
        self.fake.touch("ports", 1, ifOutOctets_rate=110_000_000)
        out = self.report(view="ports", filter={"util_above_pct": 80})
        self.assertEqual((self.ids(out), out["summary"]["over_80_pct"]), ([1], 1))

    def test_utilisation_of_a_device_group_and_a_port_group(self):  # 14, 15
        out = self.report(view="ports", scope={"group": "core-switches"}, sort="util")
        self.assertEqual(self.ids(out), [1, 2])
        out = self.report(view="ports", scope={"port_group": "uplinks"}, sort="util")
        self.assertEqual((out["rows"][0]["port_id"], out["rows"][0]["util_pct"]), (1, 80.0))

    def test_ports_at_100m_or_half_duplex(self):  # 16, in two calls
        self.seed_port(device_id=3, ifIndex=2, ifName="Fa0/2", ifSpeed=100_000_000)
        self.seed_port(device_id=3, ifIndex=3, ifName="Gi1/0/3", ifDuplex="halfDuplex")
        slow = self.report(view="ports", filter={"state": "up", "speed_below_mbps": 1000})
        half = self.report(view="ports", filter={"state": "up", "duplex": "half"})
        self.assertEqual(([r["port"] for r in slow["rows"]], [r["port"] for r in half["rows"]]),
                         (["Fa0/2"], ["Gi1/0/3"]))  # fmt: skip

    def test_ports_without_a_description(self):  # 21, 22
        self.seed_port(device_id=3, ifIndex=4, ifName="Gi1/0/4", ifAlias="Gi1/0/4")  # some OSes copy the name
        out = self.report(view="ports", scope={"device": "core-sw1"}, filter={"no_description": True})
        self.assertEqual(self.ids(out), [2])
        out = self.report(view="ports", filter={"state": "up", "no_description": True})
        self.assertEqual([row["port"] for row in out["rows"]], ["Gi1/0/4"])
        self.assertEqual(self.report(view="ports", limit=1)["summary"]["no_description"], 2)

    def test_how_many_free_ports_on_each_access_switch(self):  # 53
        self.fake.touch("devices", 3, uptime=60 * DAY)
        for number in range(4):
            self.seed_port(device_id=3, ifIndex=10 + number, ifName=f"Gi1/0/{number + 1}", ifOperStatus="down",
                           ifLastChange=ticks(60 * DAY, 40 * DAY))  # fmt: skip
        out = self.report(view="capacity", scope={"location": "NYC"}, sort="free")
        [row] = out["rows"]
        self.assertEqual((row["hostname"], row["free"], row["ethernet_ports"]), ("access-sw2.example.net", 4, 5))

    def test_a_customer_port_on_a_circuit_slower_than_the_interface(self):
        # described "[100M/20M]" on a 1G interface: LibreNMS's web UI measures it against the circuit
        self.fake.touch("ports", 9, port_descr_speed="100M/20M", ifInOctets_rate=2_400_000, ifOutOctets_rate=0)
        [row] = self.report(view="ports", scope={"device": 3}, filter={"util_above_pct": 90})["rows"]
        self.assertEqual((row["speed"], row["in"], row["in_pct"]), ("100M/20M", "19.2 Mbit/s", 96.0))

    def test_answers_stay_small(self):
        for number in range(400):
            self.seed_port(device_id=3, ifIndex=100 + number, ifName=f"Gi2/0/{number}", ifAlias=f"desk {number}")
        out = self.report(view="ports", sort="util", limit=10)
        self.assertEqual((out["count"], out["returned"]), (405, 10))
        self.assertLess(len(json.dumps(out)), 12000)
