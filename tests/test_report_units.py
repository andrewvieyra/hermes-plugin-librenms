"""The report views' shared pieces that need no LibreNMS: units and times (reports/units.py), the ranking of names
and phrases (reports/fuzzy.py), with the near misses that decide whether a phrase names one device or several, and
what a port row means (reports/ports.py: speeds, utilisation, errors, staleness and the age of its last change), and
sensor readings in their units, their status and the port a sensor is on (reports/units.py, reports/context.py)."""

import unittest
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from .helpers import submodule

units = submodule("reports.units")
fuzzy = submodule("reports.fuzzy")
ports = submodule("reports.ports")
context = submodule("reports.context")

NOW = datetime(2026, 10, 28, 12, 0, 0, tzinfo=timezone.utc)
CORE = {
    "device_id": 1,
    "hostname": "core-sw1.example.net",
    "sysName": "core-sw1",
    "display": "core-sw1",
    "location": "SFO-1",
    "purpose": "core",
    "os": "ios",
    "type": "network",
    "hardware": "WS-C3850-48T",
    "serial": "FOC1234X0AB",
    "ip": "192.0.2.1",
}


class Rates(unittest.TestCase):
    def test_bits_per_second_with_decimal_prefixes(self):
        cases = {
            812_000_000: "812 Mbit/s",
            1_000_000_000: "1 Gbit/s",
            1_250_000_000: "1.25 Gbit/s",
            999.6: "1 kbit/s",  # rounded before the prefix is chosen, never "1000 bit/s"
            0: "0 bit/s",
            "750000000": "750 Mbit/s",  # LibreNMS writes some rates as text
            12_345: "12.3 kbit/s",
        }
        for value, shown in cases.items():
            self.assertEqual(units.bits_per_second(value), shown, value)
        for value in (None, "fast", True, float("nan"), float("inf"), [1]):
            self.assertIsNone(units.bits_per_second(value), value)

    def test_speed_as_it_is_written_on_the_box(self):
        cases = {10_000_000_000: "10G", 100_000_000: "100M", 2_500_000_000: "2.5G", 1_544_000: "1.54M", 400e9: "400G"}
        for value, shown in cases.items():
            self.assertEqual(units.speed(value), shown, value)
        for value in (0, None, -1, "", "x"):  # LibreNMS stores 0 for a speed it does not know
            self.assertIsNone(units.speed(value), value)

    def test_parse_speed(self):
        cases = {"10G": 10**10, "100M": 10**8, "2.5 Gbit/s": 25 * 10**8, "1000000": 10**6, "1gbps": 10**9}
        for text, bps in cases.items():
            self.assertEqual(units.parse_speed(text), bps, text)
        self.assertEqual(units.parse_speed(1000), 1000)
        for text in ("fast", "-1G", "10 X", None, True, float("nan")):
            self.assertIsNone(units.parse_speed(text), text)

    def test_circuit_speeds_as_librenms_reads_them(self):
        # port_descr_speed is egress/ingress (Port::circuitSpeeds), each side read like Number::toBytes
        cases = {
            "100M/20M": (100_000_000, 20_000_000),
            "1G": (10**9, 10**9),
            "10Mbit": (10**7, 10**7),
            "2.5g": (25 * 10**8, 25 * 10**8),
            "1Mi/512Ki": (2**20, 2**19),
            "1500": (1500, 1500),
        }
        for text, both in cases.items():
            self.assertEqual(units.circuit_speeds(text), both, text)
        for text in (None, "", "0", "fast", "100M/0", "0/20M", "100 M", "-1G", "1.2.3G", 100, "100M/x"):
            self.assertIsNone(units.circuit_speeds(text), text)

    def test_seconds_a_counter_holds(self):
        self.assertEqual((units.seconds(8_640_000), units.seconds("3600")), (8_640_000, 3600))
        for value in (0, -5, None, "x", "1.5", 101 * 366 * 86400, float("inf")):
            self.assertIsNone(units.seconds(value), value)

    def test_percent_of_a_speed(self):
        self.assertEqual(units.percent(1_000_000_000 * 8, 10_000_000_000), 80.0)  # 1 GB/s on a 10G port
        self.assertEqual(units.percent(1, 3), 33.3)
        for part, whole in ((1, 0), (1, None), (None, 10), (1, -5), ("x", 10)):
            self.assertIsNone(units.percent(part, whole), (part, whole))


class Durations(unittest.TestCase):
    def test_the_two_largest_units_rounded_down(self):
        cases = {8_640_000: "100d 0h", 3 * 86400 + 4 * 3600 + 59: "3d 4h", 7500: "2h 5m", 298: "4m 58s", 12: "12s"}
        for seconds, shown in cases.items():
            self.assertEqual(units.duration(seconds), shown, seconds)
        self.assertEqual(units.duration(0), "0s")
        self.assertEqual(units.duration("3600"), "1h 0m")
        for seconds in (-5, None, "x", 10**12):  # a negative or a century-long one is a wrapped or unset counter
            self.assertIsNone(units.duration(seconds), seconds)

    def test_parse_duration(self):
        cases = {"30m": 1800, "24h": 86400, "7d": 604800, "2w": 1209600, "90s": 90, " 24H ": 86400}
        for text, seconds in cases.items():
            self.assertEqual(units.parse_duration(text), seconds, text)
        for text in ("0h", "400d", "1.5h", "24", 24, "-1h", "1 day", None, "1h30m"):
            self.assertIsNone(units.parse_duration(text), text)


class Times(unittest.TestCase):
    def test_zone_safe_times_are_exact(self):
        polled = units.utc_time("2026-10-28T11:55:02.000000Z")  # the device API
        self.assertEqual(polled, datetime(2026, 10, 28, 11, 55, 2, tzinfo=timezone.utc))
        self.assertEqual(units.utc_time("2026-10-28T13:55:02+02:00"), polled)
        self.assertEqual(units.utc_time(1761600000), datetime(2025, 10, 27, 21, 20, tzinfo=timezone.utc))  # outages
        self.assertEqual(units.utc_time("1761600000"), units.utc_time(1761600000))
        self.assertEqual(units.iso(polled), "2026-10-28T11:55:02Z")
        self.assertEqual(units.age(polled, NOW), 298)
        self.assertEqual(units.age(NOW + timedelta(seconds=5), NOW), 0)  # clocks apart: not a negative age
        self.assertIsNone(units.age(None, NOW))
        for value in (0, None, "", "soon", True, "2026-10-28 10:02:00", 10**12):
            self.assertIsNone(units.utc_time(value), value)

    def test_server_local_times_need_the_zone(self):
        # conv-timezone-ages: LibreNMS in Europe/Amsterdam (UTC+1 on 28 October 2026), Hermes in UTC. A fault first
        # seen at "2026-10-28 10:02:00" server time has been open 2 h 58 min at 12:00 UTC, not 1 h 58 min.
        raw = "2026-10-28 10:02:00"
        self.assertIsNone(units.server_time(raw, None))  # no zone: no time, so no age is made up
        seen = units.server_time(raw, ZoneInfo("Europe/Amsterdam"))
        self.assertEqual(units.iso(seen), "2026-10-28T10:02:00+01:00")
        self.assertEqual(units.duration(units.age(seen, NOW)), "2h 58m")
        summer = units.server_time("2026-07-01 10:00:00", ZoneInfo("Europe/Amsterdam"))
        self.assertEqual(units.iso(summer), "2026-07-01T10:00:00+02:00")
        self.assertEqual(units.iso(units.server_time(raw, ZoneInfo("UTC"))), "2026-10-28T10:02:00Z")
        # a zone-safe value is read as it is, with or without the setting
        self.assertEqual(units.server_time("2026-10-28T11:55:02Z", None), units.utc_time("2026-10-28T11:55:02Z"))
        self.assertIsNone(units.server_time("2026-13-45 10:00:00", ZoneInfo("UTC")))


class Terms(unittest.TestCase):
    def test_words_and_labels(self):
        self.assertEqual(fuzzy.norm("Core-SW1.example.net"), "core sw1 example net")
        self.assertEqual(fuzzy.norm(None), "")
        self.assertEqual(fuzzy.label("core-sw1.example.net"), "core-sw1")
        self.assertEqual(fuzzy.label("192.0.2.1"), "192.0.2.1")  # an IP is not cut at its first dot

    def test_a_term_taken_apart(self):
        term = fuzzy.Term.parse("the core switch in Amsterdam")
        self.assertEqual(
            (term.words, term.iface, term.ip, term.mac), (("core", "switch", "amsterdam"), None, None, None)
        )
        term = fuzzy.Term.parse("Gi1/0/48 on access-sw2")
        self.assertEqual((term.iface, term.words, term.parts), ("gi1/0/48", ("access", "sw2"), 3))
        self.assertEqual(fuzzy.Term.parse("xe-0/0/1.100").iface, "xe-0/0/1.100")
        self.assertEqual(fuzzy.Term.parse("192.0.2.1").ip, "192.0.2.1")
        self.assertEqual(fuzzy.Term.parse("2001:DB8::2").ip, "2001:db8::2")
        self.assertEqual(fuzzy.Term.parse("'::1'").ip, "::1")
        self.assertEqual(fuzzy.Term.parse("00:11:22:33:44:55").mac, "001122334455")
        self.assertEqual(fuzzy.Term.parse("0011.2233.4455").mac, "001122334455")
        bare = fuzzy.Term.parse("001122334455")  # may as well be a serial number
        self.assertEqual((bare.mac, bare.words), (None, ("001122334455",)))
        self.assertIsNone(fuzzy.Term.parse("core-sw1.example.net").iface)
        self.assertIsNone(fuzzy.Term.parse("sfo-1").iface)

    def test_levels(self):
        value = "core sw1 example net"
        cases = {
            "core sw1 example net": 100,
            "core sw1": 92,
            "core s": 88,
            "example": 85,
            "exam": 80,
            "ore": 70,
            "re": 0,
            "edge": 0,
        }
        for term, found in cases.items():
            self.assertEqual(fuzzy.level(term, value), found, term)


class DeviceMatches(unittest.TestCase):
    def match(self, text, device=None):
        return fuzzy.device_match(fuzzy.Term.parse(text), device or CORE)

    def test_any_name_a_person_gives(self):
        cases = {
            "core-sw1": (100, "sysName equals 'core-sw1'"),
            "CORE-SW1.example.net": (100, "hostname equals 'core-sw1.example.net'"),
            "core sw1": (100, "sysName equals 'core-sw1'"),  # punctuation aside
            "192.0.2.1": (100, "IP equals '192.0.2.1'"),
            "core": (92, "hostname starts with 'core-sw1.example.net'"),
        }
        for text, (score, why) in cases.items():
            found = self.match(text)
            self.assertEqual((found.score, found.why, found.full), (score, why, True), text)

    def test_a_phrase_of_role_and_site_words(self):
        found = self.match("the core switch in SFO")
        self.assertTrue(found.full)
        self.assertEqual(found.score, 76)
        self.assertIn("'switch' as 'sw1' in hostname", found.why)
        self.assertIn("'sfo' in location 'SFO-1'", found.why)
        partly = self.match("core router sfo")  # router matches nothing on a switch
        self.assertFalse(partly.full)
        self.assertLess(partly.score, found.score)
        edge = {"hostname": "edge-rtr1.example.net", "sysName": "edge-rtr1", "purpose": "edge"}
        self.assertTrue(self.match("edge router", edge).full)

    def test_near_misses_rank_below_the_device_named(self):
        ten = {**CORE, "hostname": "core-sw10.example.net", "sysName": "core-sw10", "display": "core-sw10"}
        self.assertEqual(self.match("core-sw1").score, 100)
        self.assertEqual(self.match("core-sw1", ten).score, 88)  # a prefix of core-sw10, not core-sw10
        self.assertIsNone(self.match("192.0.2.1", {**CORE, "ip": "192.0.2.12"}))  # an IP matches whole or not at all
        self.assertFalse(self.match("ore").full)  # inside a word only: not a name anyone gave

    def test_attributes(self):
        self.assertEqual(self.match("FOC1234X0AB").why, "serial equals 'FOC1234X0AB'")
        self.assertTrue(self.match("ios").full)
        self.assertIsNone(self.match("juniper"))
        self.assertIsNone(self.match("00:11:22:33:44:55"))  # a MAC is the find view's lookup
        other = {**CORE, "hostname": "core-sw2.example.net", "sysName": "core-sw2", "display": "core-sw2"}
        self.assertFalse(self.match("core 1", other).full)  # the 1 of location SFO-1 names no device


class OtherMatches(unittest.TestCase):
    def test_names_of_locations_and_groups(self):
        term = fuzzy.Term.parse("sfo")
        self.assertEqual(fuzzy.name_match(term, "location", "SFO-1").score, 92)
        group = fuzzy.name_match(fuzzy.Term.parse("wan uplinks"), "name", "uplinks", "Core and WAN uplinks")
        self.assertTrue(group.full)
        self.assertIsNone(fuzzy.name_match(term, "name", "uplinks", "Core and WAN uplinks"))

    def test_ports_by_interface_name_and_device(self):
        port = {"ifName": "Gi1/0/48", "ifDescr": "GigabitEthernet1/0/48", "ifAlias": "to core-sw1"}
        access = {"hostname": "access-sw2.example.net", "sysName": "access-sw2"}
        alone = fuzzy.port_match(fuzzy.Term.parse("Gi1/0/48"), port, access)
        self.assertEqual((alone.score, alone.why), (100, "ifName equals 'Gi1/0/48'"))
        self.assertEqual(fuzzy.port_match(fuzzy.Term.parse("GigabitEthernet1/0/48"), port, access).score, 100)
        here = fuzzy.port_match(fuzzy.Term.parse("Gi1/0/48 on access-sw2"), port, access)
        self.assertTrue(here.full)
        elsewhere = fuzzy.port_match(fuzzy.Term.parse("Gi1/0/48 on edge-rtr1"), port, access)
        self.assertFalse(elsewhere.full)
        self.assertLess(elsewhere.score, here.score)


POLLED = 1793188500  # 2026-10-28T11:55:00Z, five minutes before NOW
DEVICE = {"device_id": 1, "hostname": "core-sw1.example.net", "uptime": 8_640_000,
          "last_polled": "2026-10-28T11:55:00.000000Z"}  # fmt: skip


def port(**values):
    row = {"port_id": 1, "device_id": 1, "ifIndex": 1, "ifName": "Te1/1/1", "ifDescr": "TenGigabitEthernet1/1/1",
           "ifAlias": "uplink", "ifType": "ethernetCsmacd", "ifAdminStatus": "up", "ifOperStatus": "up",
           "ifSpeed": 10_000_000_000, "ifInOctets_rate": 0, "ifOutOctets_rate": 0, "poll_time": POLLED,
           "poll_period": 300, "ifLastChange": 0}  # fmt: skip
    return {**row, **values}


def facts(device=None, **values):
    return ports.facts(port(**values), {**DEVICE, **(device or {})}, NOW)


class PortFacts(unittest.TestCase):
    def test_a_10g_port_at_1_gigabyte_a_second_is_80_percent(self):
        # conv-units-derived-values: ifInOctets_rate is bytes/s, ifSpeed bit/s; read raw they make 10 %
        row = facts(ifInOctets_rate=1_000_000_000, ifOutOctets_rate="12500000").row
        self.assertEqual(
            {k: row[k] for k in ("speed_bps", "speed", "speed_source", "in_bps", "in", "in_pct", "out_bps", "out",
                                 "out_pct", "util_pct")},
            {"speed_bps": 10**10, "speed": "10G", "speed_source": "ifSpeed", "in_bps": 8 * 10**9, "in": "8 Gbit/s",
             "in_pct": 80.0, "out_bps": 100_000_000, "out": "100 Mbit/s", "out_pct": 1.0, "util_pct": 80.0},
        )  # fmt: skip
        self.assertNotIn("in_speed_bps", row)

    def test_the_failure_scenario_of_the_uplink_running_full(self):
        # feat-port-utilisation-derived: 125000000 bytes/s on a 1G uplink is 1 Gbit/s and 100 %, not 125 Mbps, 12.5 %
        row = facts(ifSpeed=10**9, ifInOctets_rate=125_000_000).row
        self.assertEqual((row["in"], row["in_pct"]), ("1 Gbit/s", 100.0))

    def test_a_circuit_speed_in_the_description_wins_each_way(self):
        # a customer port described [100M/20M]: 100 Mbit/s out (egress), 20 Mbit/s in (ingress), on a 1G interface
        row = facts(ifSpeed=10**9, port_descr_speed="100M/20M", ifInOctets_rate=2_500_000,
                    ifOutOctets_rate=6_250_000).row  # fmt: skip
        self.assertEqual(
            {k: row[k] for k in ("speed_bps", "speed", "speed_source", "in_speed_bps", "out_speed_bps", "in_pct",
                                 "out_pct", "util_pct")},
            {"speed_bps": 100_000_000, "speed": "100M/20M", "speed_source": "circuit", "in_speed_bps": 20_000_000,
             "out_speed_bps": 100_000_000, "in_pct": 100.0, "out_pct": 50.0, "util_pct": 100.0},
        )  # fmt: skip
        self.assertEqual(facts(port_descr_speed="1G").row["speed_source"], "circuit")
        self.assertEqual(facts(port_descr_speed="100Mbps x").row["speed_source"], "ifSpeed")  # unreadable: ifSpeed

    def test_a_speed_not_known_gives_no_percentage(self):
        for values in ({"ifSpeed": 0}, {"ifSpeed": None}, {"ifSpeed": 4294967295}):
            row = facts(ifInOctets_rate=1000, **values).row
            self.assertEqual((row["speed_bps"], row["speed"], row["in_pct"], row["util_pct"]), (None, None, None, None))
            self.assertEqual(row["in_bps"], 8000)
        old = facts(ifSpeed=4294967295, ifHighSpeed=10000, ifInOctets_rate=125_000_000).row  # an older LibreNMS
        self.assertEqual((old["speed"], old["speed_source"], old["in_pct"]), ("10G", "ifHighSpeed", 10.0))

    def test_a_stale_poll_has_no_current_figures(self):
        fresh = facts(poll_time=POLLED - 300, ifInOctets_rate=1_000_000_000)  # ten minutes old: two polls
        self.assertEqual((fresh.row["stale"], fresh.util), (False, 80.0))
        stale = facts(poll_time=POLLED - 301, ifInOctets_rate=1_000_000_000, ifInErrors_delta=5)
        self.assertEqual((stale.row["stale"], stale.row["util_pct"], stale.util, stale.errors), (True, 80.0, None, 0))
        self.assertEqual(stale.row["polled_at"], "2026-10-28T11:49:59Z")
        slow = facts(poll_time=POLLED - 800, poll_period=600)  # within two of its own polls, not two of 300 s
        self.assertFalse(slow.row["stale"])
        self.assertTrue(facts(poll_time=None).row["stale"])  # never polled
        self.assertFalse(facts(poll_period=None).row["stale"])  # 300 s when LibreNMS does not say

    def test_the_age_of_the_last_change(self):
        # ifLastChange is sysUpTime in hundredths of a second; the device was up 100 days at its poll, 5 min ago
        found = facts(ifLastChange=8_640_000 * 100 - 360_000)  # an hour before that poll
        self.assertEqual((found.row["last_change_age_s"], found.row["last_change_age"]), (3900, "1h 5m"))
        self.assertNotIn("last_change_at_least", found.row)
        boot = facts(ifLastChange=0)  # not changed since the agent started: at least the uptime
        self.assertEqual((boot.row["last_change_age_s"], boot.row["last_change_age"]), (8_640_300, "over 100d 0h"))
        self.assertTrue(boot.row["last_change_at_least"] and boot.idle_at_least)
        for device, values in (
            ({"uptime": 500 * 86400}, {"ifLastChange": 100}),  # past 497 days sysUpTime may have wrapped
            ({}, {"ifLastChange": 8_640_001 * 100}),  # after the uptime: the two do not agree
            ({"uptime": 0}, {"ifLastChange": 100}),  # no uptime
            ({}, {"ifLastChange": None}),
        ):
            row = facts(device, **values).row
            self.assertEqual((row["last_change_age_s"], row["last_change_age"]), (None, None), (device, values))
        unpolled = facts({"last_polled": None}, ifLastChange=8_640_000 * 100 - 360_000)  # the port's poll instead
        self.assertEqual(unpolled.row["last_change_age_s"], 3900)

    def test_errors_per_poll_and_per_second(self):
        row = facts(ifInErrors_delta="45", ifOutErrors_delta=0, poll_period=300).row
        self.assertEqual(
            (row["in_errors_per_poll"], row["in_errors_per_s"], row["out_errors_per_poll"], row["out_errors_per_s"]),
            (45, 0.15, 0, 0.0),
        )
        self.assertEqual(facts(ifInErrors_delta=45).errors, 45)

    def test_states_duplex_and_descriptions(self):
        self.assertEqual(facts(ifAdminStatus="down", ifOperStatus="down").row["state"], "disabled")
        self.assertEqual(facts(ifOperStatus="lowerLayerDown").row["state"], "lowerLayerDown")
        self.assertTrue(facts(ifOperStatus="down").not_up)
        self.assertFalse(facts(ifOperStatus="down", ignore=1).not_up)  # an ignored port is not counted down
        unpolled = facts(ifOperStatus="down", disabled=1)  # nor one whose polling is disabled (Port::scopeIsDown)
        self.assertEqual((unpolled.not_up, unpolled.row["polling_disabled"]), (False, True))
        self.assertFalse(facts(ifOperStatus="down").row["polling_disabled"])
        self.assertFalse(facts(ifAdminStatus="down", ifOperStatus="down").not_up)
        duplex = {"fullDuplex": "full", "halfDuplex": "half", "unknown": "unknown", "": None, None: None}
        for raw, shown in duplex.items():
            self.assertEqual(facts(ifDuplex=raw).row["duplex"], shown, raw)
        for alias, missing in (("", True), (None, True), ("  ", True), ("te1/1/1", True),
                               ("TenGigabitEthernet1/1/1", True), ("uplink", False)):  # fmt: skip
            self.assertEqual(facts(ifAlias=alias).row["no_description"], missing, alias)
        self.assertEqual(facts(ifAlias="te1/1/1").row["port"], "Te1/1/1 (te1/1/1)")

    def test_physical_ethernet_ports(self):
        self.assertTrue(ports.is_ethernet(port()))
        self.assertTrue(ports.is_ethernet(port(ifType="gigabitEthernet")))
        self.assertTrue(ports.is_ethernet(port(ifName="xe-0/0/48:0")))  # a channel of a broken-out Junos port
        for values in ({"ifName": "Gi0/0/0.100"}, {"ifName": "ge-0/0/0.0"}, {"ifName": "xe-0/0/48:0.0"},
                       {"ifType": "ieee8023adLag"}, {"ifType": "l2vlan"}):  # fmt: skip
            self.assertFalse(ports.is_ethernet(port(**values)), values)

    def test_sensor_states_as_librenms_scopes_decide_them(self):
        sensor = {"sensor_limit": 1, "sensor_limit_warn": -1, "sensor_limit_low": -14.4, "sensor_limit_low_warn": -12}
        for current, status in ((-3.2, "ok"), (-0.5, "warning"), (2, "critical"), (-13, "warning"), (-15, "critical"),
                                (None, None), ("-3.2", "ok")):  # fmt: skip
            self.assertEqual(context.sensor_status({**sensor, "sensor_current": current}), status, current)
        self.assertEqual(context.sensor_status({"sensor_current": 99}), "ok")  # no limit set never trips
        # a state sensor's number means what its state translations say, which the API does not return
        self.assertIsNone(context.sensor_status({"sensor_class": "state", "sensor_current": 1, "sensor_limit": 0}))

    def test_a_sensor_on_a_port(self):
        port = {"port_id": 9, "ifIndex": 48}
        on_index = {"entPhysicalIndex": "48", "entPhysicalIndex_measured": "ports"}
        self.assertTrue(context.measured_on(on_index, port, set()))
        self.assertFalse(context.measured_on({**on_index, "entPhysicalIndex_measured": None}, port, set()))
        self.assertTrue(context.measured_on({"entPhysicalIndex": 1011}, port, {"1011"}))  # its transceiver's entity
        self.assertFalse(context.measured_on({}, port, {""}))


class SensorReadings(unittest.TestCase):
    def test_a_reading_in_its_class_unit(self):
        for value, kind, shown in (
            (41, "temperature", "41 °C"), (-3.2, "dbm", "-3.2 dBm"), ("12.1", "voltage", "12.1 V"),
            (4520, "fanspeed", "4520 RPM"), (2400, "power", "2.4 kW"), (12.5, "current", "12.5 A"),
            (90, "runtime", "1h 30m"), (1, "state", "1"), (0.333333, "power_factor", "0.333"),
            (45, "humidity", "45 %"), (5, "a_class_added_since", "5"), (None, "temperature", None),
        ):  # fmt: skip
            self.assertEqual(units.sensor_reading(value, kind), shown, (value, kind))
        self.assertEqual(set(units.SENSOR_UNITS) & {"processor", "mempool", "storage"}, set())

    def test_sizes_with_binary_prefixes(self):
        for value, shown in ((4294967296, "4 GiB"), (1761607680, "1.64 GiB"), (1073636966, "1024 MiB"), (512, "512 B"),
                             (None, None), (-1, None)):  # fmt: skip
            self.assertEqual(units.size(value), shown, value)


if __name__ == "__main__":
    unittest.main()
