"""librenms_report views alerts and alert_history against the fake LibreNMS, view help, and the restructured tool
schema: the open faults with what alerted named and nothing of their details or contacts, the alert log over a
window counted per rule, device and event, every read an allowed GET within the budgets, and the operator questions
of the conversational audit about alerts (28 to 35), each answered in one or two calls."""

import json
from unittest import mock

from .helpers import submodule
from .test_reports import NOON, ReportCase

reports = submodule("reports")
alerts_mod = submodule("reports.alerts")
help_mod = submodule("reports.help")
schemas = submodule("schemas")

CONTACTS = {"noc@example.net": "NOC", "jane.doe@example.net": "Jane Doe"}
# What a fault's or an alert-log entry's details hold beside the labels: every column the rule joined, the contacts.
LEAKS = ("noc@example.net", "jane.doe@example.net", "contacts", "sysContact", "c0re-Community!", "details")


class AlertCase(ReportCase):
    def reads(self, prefix):
        return [call for call in self.fake.calls if call["path"] == prefix or call["path"].startswith(prefix + "/")]

    def ids(self, out, key="alert_id"):
        return [row[key] for row in out["rows"]]

    def assert_nothing_of_the_details(self, out):
        text = json.dumps(out)
        for leak in LEAKS:
            self.assertNotIn(leak, text)

    def seed_rule(self, **row):
        defaults = {"severity": "warning", "builder": {"condition": "AND", "rules": []}, "alert_operation_id": 1}
        return self.fake.seed("rules", {**defaults, **row})

    def seed_log(self, **row):
        return self.fake.seed("alert_log", row)


class Schema(AlertCase):
    def test_the_description_names_every_view_and_help_explains_them(self):
        report = schemas.LIBRENMS_REPORT
        self.assertEqual(report["parameters"]["properties"]["view"]["enum"], [*reports.VIEWS, "help"])
        for name in [*reports.VIEWS, "help"]:
            self.assertIn(f"{name}", report["description"])
        # per-view filters and sorts live in view help, not in the schema the model is sent every turn
        self.assertNotIn("enum", report["parameters"]["properties"]["sort"])
        self.assertNotIn("util_above_pct", json.dumps(report))
        self.assertLessEqual(len(json.dumps(schemas.ALL)), 16 * 1024)


class Help(AlertCase):
    def test_help_lists_the_views_without_a_librenms_call(self):
        self.handlers.set_client_factory(lambda *_a, **_k: self.fail("view help made a client"))
        out = self.report(view="help")
        self.assertEqual(list(out["views"]), list(reports.VIEWS))
        for key in ("scope", "filter", "sort", "paging", "window", "units", "text"):
            self.assertIn(key, out)
        self.assertEqual(self.fake.calls, [])

    def test_each_topic_explains_every_filter_and_sort_of_its_view(self):
        for name, view in reports.VIEWS.items():
            out = self.report(view="help", topic=name.upper())
            self.assertEqual((out["topic"], out["default_sort"]), (name, view.sorts[0]))
            self.assertEqual(list(out["filters"]), list(view.filters), name)
            self.assertEqual(list(out["sorts"]), list(view.sorts), name)
            self.assertEqual(set(help_mod.TOPICS[name]["filters"]), set(view.filters), name)  # no line for nothing
            self.assertEqual(set(help_mod.TOPICS[name]["sorts"]), set(view.sorts), name)
            self.assertEqual(out["scope"], list(view.scope_keys))
            self.assertEqual("term" in out, view.term, name)
            self.assertTrue(out["examples"] and out["rows"] and out["summary"], name)
        out = self.report(view="help", topic="alerts")
        severity = "one of critical, warning, ok, or a list of them: Of rules of this severity."
        self.assertEqual(out["filters"]["severity"], severity)
        self.assertEqual(out["filters"]["acked"], "true or false: Acknowledged (true) or not.")
        history = self.report(view="help", topic="alert_history")
        self.assertIn("1h, 24h (default)", history["window"])
        self.assertEqual(
            history["filters"]["by"], "one of rule, device, event: Rows per rule (default), device, or event."
        )
        self.assertEqual(self.fake.calls, [])

    def test_every_example_runs(self):
        self.settings_with(librenms_timezone="Europe/Amsterdam")
        self.fake.seed("device_groups", {"id": 3, "name": "access-switches", "type": "static", "devices": [3]})
        for name in reports.VIEWS:
            for example in help_mod.examples(name):
                out = self.report(**example)
                self.assertTrue(out["success"], (example, out))
                self.assertFalse(out.get("ambiguous"), example)

    def test_what_help_does_not_take(self):
        for args, said in (
            ({"view": "help", "topic": "graphs"}, "topic takes a view: find, devices, ports, port, capacity"),
            ({"view": "help", "topic": 3}, "topic takes a view"),
            (
                {"view": "help", "scope": {"device": "core-sw1"}},
                "view help takes topic (a view's name) alone, not scope",
            ),
            ({"view": "alerts", "topic": "alerts"}, 'topic is for view help, which explains a view: {"view": "help"'),
        ):
            out = self.report(**args)
            self.assertFalse(out["success"], args)
            self.assertIn(said, out["error"])

    def test_a_filter_or_sort_a_view_does_not_take_points_to_help(self):
        for args, said in (
            ({"view": "alerts", "filter": {"status": "down"}},
             "view alerts takes filter keys state, severity, acked, rule, entity_type, text, not 'status'; view help "
             'with topic "alerts" says what each does'),
            ({"view": "alert_history", "sort": "util"},
             "view alert_history sorts by fired, flaps, last_fired, name (got 'util'); view help with topic "
             '"alert_history" says what each does'),
            ({"view": "alert_history", "filter": {"by": ["rule", "device"]}}, "filter.by takes one of rule, device"),
            ({"view": "alerts", "filter": {"severity": "major"}}, "filter.severity takes critical, warning, ok"),
        ):  # fmt: skip
            out = self.report(**args)
            self.assertFalse(out["success"], args)
            self.assertIn(said, out["error"])
        self.assertIn("view must be one of find, devices, ports, port, capacity, neighbours, locate, vlans, alerts, "
                      "alert_history, health, routing, help", self.report(view="graphs")["error"])  # fmt: skip


class Window(AlertCase):
    def test_a_window_only_where_a_view_takes_one(self):
        for args, said in (
            ({"view": "alerts", "window": "24h"}, "window is for view alert_history; view alerts reads what LibreNMS "
                                                  "holds now"),
            ({"view": "alert_history", "window": "yesterday"}, "window takes today or a duration such as 1h, 24h"),
            ({"view": "alert_history", "window": "400d"}, "window takes today or a duration"),
            ({"view": "alert_history", "window": "today"}, "window today needs librenms_timezone"),
        ):  # fmt: skip
            out = self.report(**args)
            self.assertFalse(out["success"], args)
            self.assertIn(said, out["error"])
        self.assertEqual(self.fake.calls, [])

    def test_with_a_time_zone_the_window_starts_exactly(self):
        self.settings_with(librenms_timezone="Europe/Amsterdam")  # noon UTC is 13:00 there (CET)
        for window, bound in (("24h", "2026-10-27 13:00:00"), ("1h", "2026-10-28 12:00:00"),
                              ("today", "2026-10-28 00:00:00")):  # fmt: skip
            self.fake.calls.clear()
            out = self.report(view="alert_history", window=window)
            self.assertEqual((out["summary"]["from"], out["summary"]["exact"]), (bound, True), window)
            self.assertEqual(self.reads("logs/alertlog")[0]["params"]["from"], bound)
            self.assertFalse(any("librenms_timezone" in note for note in out["notes"]))
        out = self.report(view="alert_history")
        self.assertEqual(out["summary"]["window"], "24h")

    def test_without_one_the_window_holds_every_zone_and_says_so(self):
        out = self.report(view="alert_history", window="24h")
        # noon UTC less 24h, less the 12h a server clock may be behind UTC; up to 26h more than the window
        self.assertEqual((out["summary"]["from"], out["summary"]["exact"]), ("2026-10-27 00:00:00", False))
        self.assertIn("which holds the last 24h in any zone and up to 1d 2h before it; set librenms_timezone for an "
                      "exact window", " ".join(out["notes"]))  # fmt: skip
        self.assertEqual(self.reads("logs/alertlog")[0]["params"]["from"], "2026-10-27 00:00:00")
        # the 21:00 and 22:00 entries of the 27th are inside that bound, whatever zone LibreNMS runs in
        self.assertEqual(out["summary"]["entries"], 5)


class Alerts(AlertCase):
    def test_what_is_alerting_with_what_alerted_named(self):
        out = self.report(view="alerts")
        self.assertEqual(self.ids(out), [4, 1, 3, 2])  # critical first; then unacknowledged, newest first
        row = out["rows"][1]
        self.assertEqual(
            {key: row[key] for key in ("hostname", "rule", "severity", "state", "acked", "entity_type", "port_id",
                                       "entity", "procedure")},
            {"hostname": "edge-rtr1.example.net", "rule": "Port down", "severity": "warning", "state": "active",
             "acked": False, "entity_type": "port", "port_id": 5, "entity": "Gi0/0/0",
             "procedure": "https://wiki.example.net/runbooks/port-down"},
        )  # fmt: skip
        # fault 3 holds no details: its port is named from its device's port names, never every column
        self.assertEqual(out["rows"][2]["entity"], "Gi1/0/48 (to core-sw1)")
        [ports] = self.reads("devices/3/ports")
        self.assertEqual(ports["params"], {"columns": "port_id,ifIndex,ifName,ifDescr,ifAlias"})
        self.assertEqual(self.reads("faults")[0]["params"], {"state": "1,2,3,4,5"})
        self.assertEqual(
            out["summary"],
            {"by_state": {"active": 3, "acknowledged": 1, "worse": 0, "better": 0, "changed": 0},
             "by_severity": {"critical": 1, "warning": 3, "ok": 0}, "unacknowledged": 3, "devices": 3, "rules": 2,
             "by_rule": [{"rule_id": 1, "rule": "Port down", "severity": "warning", "alerts": 3},
                         {"rule_id": 2, "rule": "High CPU", "severity": "critical", "alerts": 1}]},
        )  # fmt: skip
        self.assertEqual(out["timezone"], "unknown — set librenms_timezone")
        self.assertEqual((row["first_seen"], row["first_seen_age_s"]), ("2026-10-28 10:02:00", None))
        self.assert_reads_only_allowed_gets()

    def test_a_fault_with_a_label_needs_no_ports_read(self):
        self.fake.touch("faults", 3, details={"rule": [{"port_id": 9, "ifName": "Gi1/0/48", "ifAlias": "to core-sw1"}]})
        self.fake.touch("faults", 2, details={"rule": [{"port_id": 6, "ifName": "Gi0/0/1"}]})
        out = self.report(view="alerts")
        self.assertEqual([row["entity"] for row in out["rows"][2:]], ["Gi1/0/48 (to core-sw1)", "Gi0/0/1"])
        self.assertEqual(self.reads("devices"), [self.reads("devices")[0]])  # the device listing alone

    def test_nothing_of_the_details_or_contacts_reaches_the_model(self):
        joined = {"device_id": 2, "port_id": 5, "ifName": "Gi0/0/0", "ifAlias": "WAN: transit-a", "community":
                  "c0re-Community!", "sysContact": "noc@example.net", "hostname": "edge-rtr1.example.net"}  # fmt: skip
        self.fake.touch("faults", 1, details={"contacts": CONTACTS, "rule": [joined, joined]})
        for args in ({"view": "alerts"}, {"view": "alerts", "filter": {"text": "noc@"}}, {"view": "port",
                     "scope": {"port": 5}}):  # fmt: skip
            out = self.report(**args)
            self.assert_nothing_of_the_details(out)
        out = self.report(view="alerts", filter={"text": "transit-a"})
        self.assertEqual((self.ids(out), out["rows"][0]["entity"]), ([1], "Gi0/0/0 (WAN: transit-a)"))
        self.assertNotIn("entities", out["rows"][0])  # one port, joined twice

    def test_a_sensor_and_a_fault_about_several_objects(self):
        self.fake.seed("faults", {
            "id": 6, "rule_id": 2, "device_id": 1, "entity_type": "sensor", "entity_id": 1, "state": 1,
            "timestamp": "2026-10-28 11:50:00", "first_seen": "2026-10-28 11:50:00",
            "details": {"contacts": CONTACTS, "rule": [{"sensor_id": 1, "sensor_descr": "Chassis Temperature",
                                                        "sensor_class": "temperature", "sensor_current": 71}]},
        })  # fmt: skip
        self.fake.seed("faults", {
            "id": 7, "rule_id": 1, "device_id": 1, "state": 1, "timestamp": "2026-10-28 11:55:00",
            "details": {"rule": [{"ifName": f"Gi1/0/{n}", "port_id": n} for n in range(1, 13)]},
        })  # fmt: skip
        out = self.report(view="alerts", scope={"device": "core-sw1"}, sort="newest")
        self.assertEqual(self.ids(out), [7, 6, 4])
        sensor = out["rows"][1]
        self.assertEqual((sensor["entity_type"], sensor["sensor_id"], sensor["entity"], sensor["value"]),
                         ("sensor", 1, "Chassis Temperature (temperature)", 71))  # fmt: skip
        several = out["rows"][0]
        self.assertEqual((several["entity_type"], several["entity"], several["entities_total"]),
                         (None, "Gi1/0/1", 12))  # fmt: skip
        self.assertEqual(len(several["entities"]), 10)  # at most ENTITY_ROWS labels
        self.assertEqual(self.ids(self.report(view="alerts", filter={"entity_type": "sensor"})), [6])
        self.assertEqual(self.ids(self.report(view="alerts", filter={"entity_type": "interface"})), [1, 3, 2])
        self.assertEqual(self.ids(self.report(view="alerts", filter={"entity_type": "device"})), [4, 7])
        self.assert_nothing_of_the_details(out)

    def test_filters_narrow_at_librenms_where_they_can(self):
        for filters, ids, params in (
            ({"severity": "critical"}, [4], {"state": "1,2,3,4,5", "severity": "critical"}),
            ({"severity": ["warning", "critical"]}, [4, 1, 3, 2], {"state": "1,2,3,4,5"}),
            ({"acked": True}, [2], {"state": "1,2,3,4,5"}),
            ({"acked": False, "severity": "warning"}, [1, 3], {"state": "1,2,3,4,5", "severity": "warning"}),
            ({"state": "acknowledged"}, [2], {"state": "2"}),
            ({"state": ["active", "recovered"]}, [4, 5, 1, 3], {"state": "0,1"}),
            ({"rule": "2"}, [4], {"state": "1,2,3,4,5", "alert_rule": "2"}),
            ({"rule": "port"}, [1, 3, 2], {"state": "1,2,3,4,5"}),
            ({"text": "carrier ticket"}, [2], {"state": "1,2,3,4,5"}),
            ({"text": "access-sw2"}, [3], {"state": "1,2,3,4,5"}),
        ):
            self.fake.calls.clear()
            out = self.report(view="alerts", filter=filters)
            self.assertEqual(self.ids(out), ids, filters)
            self.assertEqual(self.reads("faults")[0]["params"], params, filters)
        out = self.report(view="alerts", filter={"state": ["active", "recovered"]})
        self.assertEqual(out["summary"]["by_state"]["recovered"], 1)

    def test_scope_sorts_and_paging(self):
        self.assertEqual(self.ids(self.report(view="alerts", scope={"device": "edge-rtr1"})), [1, 2])
        self.assertEqual(self.ids(self.report(view="alerts", scope={"location": "SFO"})), [4, 1, 2])
        self.assertEqual(self.ids(self.report(view="alerts", sort="newest")), [4, 1, 2, 3])
        self.assertEqual(self.ids(self.report(view="alerts", sort="oldest")), [3, 2, 1, 4])
        self.assertEqual(self.ids(self.report(view="alerts", sort="name")), [3, 4, 1, 2])
        first = self.report(view="alerts", limit=3)
        self.assertEqual((self.ids(first), first["truncated"], first["next_offset"]), ([4, 1, 3], True, 3))
        rest = self.report(view="alerts", limit=3, offset=3)
        self.assertEqual((self.ids(rest), rest["truncated"], rest["summary"]["devices"]), ([2], False, 3))

    def test_with_a_time_zone_first_seen_has_an_age(self):
        self.settings_with(librenms_timezone="Europe/Amsterdam")
        out = self.report(view="alerts", scope={"device": "access-sw2"})
        row = out["rows"][0]
        # 08:30 in Amsterdam (CET, +01:00) is 07:30Z, four and a half hours before noon UTC
        self.assertEqual((row["first_seen"], row["first_seen_age_s"], row["first_seen_age"]),
                         ("2026-10-28T08:30:00+01:00", 16200, "4h 30m"))  # fmt: skip
        self.assertEqual(out["timezone"], "Europe/Amsterdam")

    def test_an_answer_too_large_to_read_is_read_one_severity_at_a_time(self):
        real = self.client.get

        def get(path, params=None):
            if path == "faults" and params.get("severity") in (None, "critical"):
                raise self.client_mod.LibreNMSError("too large", status=200, kind="too_large")
            return real(path, params)

        self.client.get = get
        out = reports.run(self.client, self.settings, {"view": "alerts"})
        self.assertEqual(self.ids(out), [1, 3, 2])
        self.assertTrue(out["partial"])
        self.assertIn(
            "the critical alerts were not read: LibreNMS's answer is too large to read", out["partial_reason"]
        )
        self.assertIn("one severity at a time", " ".join(out["notes"]))
        self.assertEqual([c["params"].get("severity") for c in self.reads("faults")], ["warning", "ok"])

    def test_a_failed_ports_read_leaves_the_port_unnamed_and_the_answer_partial(self):
        self.fake.fail_on("GET", "devices/3/ports", 500)
        out = self.report(view="alerts")
        self.assertIsNone(out["rows"][2]["entity"])
        self.assertEqual(
            out["partial_reason"],
            "the names of device 3's alerting ports not read: LibreNMS answered HTTP 500 (server)",
        )

    def test_text_from_librenms_is_escaped_clipped_and_marked(self):
        self.fake.touch("faults", 2, note="ack ‮evil‬ " + "x" * 400)
        out = self.report(view="alerts", filter={"acked": True})
        note = out["rows"][0]["note"]
        self.assertIn("\\u202e", note)
        self.assertLessEqual(len(note), 200 + len("… [truncated 1000 chars]"))
        for key in ("hostname", "rule", "entity", "note", "procedure"):
            self.assertIn(key, out["untrusted_fields"])


class AlertHistory(AlertCase):
    def test_per_rule_every_rule_of_the_fleet_is_listed(self):
        self.seed_rule(id=3, name="Disk full", disabled=1)
        self.seed_rule(id=4, name="BGP down", severity="critical", alert_operation_id=None)
        self.seed_rule(id=5, name="Fan failed", extra={"mute": True, "options": {}})
        out = self.report(view="alert_history", window="7d")
        self.assertEqual([(r["rule_id"], r["fired"], r["cleared"]) for r in out["rows"]],
                         [(1, 2, 0), (2, 1, 1), (4, 0, 0), (3, 0, 0), (5, 0, 0)])  # fmt: skip
        self.assertEqual([(r["disabled"], r["notifies"], r["muted"]) for r in out["rows"][2:]],
                         [(False, False, False), (True, True, False), (False, False, True)])  # fmt: skip
        cpu = out["rows"][1]
        self.assertEqual((cpu["rule"], cpu["severity"], cpu["entries"], cpu["devices"], cpu["last_fired"]),
                         ("High CPU", "critical", 2, 1, "2026-10-27 21:00:00"))  # fmt: skip
        summary = out["summary"]
        self.assertEqual(
            {key: summary[key] for key in ("by", "logged", "entries", "fired", "cleared", "flaps", "rules", "devices",
                                           "rules_disabled", "rules_without_notifications")},
            {"by": "rule", "logged": 5, "entries": 5, "fired": 3, "cleared": 1, "flaps": 0, "rules": 2, "devices": 2,
             "rules_disabled": 1, "rules_without_notifications": 2},
        )  # fmt: skip
        self.assertEqual(summary["top_rules"], [{"rule_id": 1, "rule": "Port down", "fired": 2},
                                                {"rule_id": 2, "rule": "High CPU", "fired": 1}])  # fmt: skip
        self.assertEqual([r["rule_id"] for r in self.report(view="alert_history", filter={"fired": False})["rows"]],
                         [4, 3, 5])  # fmt: skip
        self.assert_reads_only_allowed_gets()

    def test_per_device_and_per_event(self):
        out = self.report(view="alert_history", window="7d", filter={"by": "device"})
        self.assertEqual(
            [(r["hostname"], r["fired"], r["rules"], r["top_rule"]) for r in out["rows"]],
            [("edge-rtr1.example.net", 2, 1, "Port down"), ("core-sw1.example.net", 1, 1, "High CPU")],
        )
        out = self.report(view="alert_history", window="7d", filter={"by": "event"})
        self.assertEqual(
            [(r["entry_id"], r["state"], r["entity"]) for r in out["rows"]],
            [
                (1, "alerted", "Gi0/0/0 (WAN: transit-a)"),
                (3, "acknowledged", None),
                (2, "alerted", "Gi0/0/1 (WAN: transit-b)"),
                (5, "recovered", None),
                (4, "alerted", "CPU 0"),
            ],
        )
        self.assertEqual((out["rows"][0]["alert_id"], out["rows"][0]["rule"]), (1, "Port down"))
        self.assert_nothing_of_the_details(out)
        events = self.report(view="alert_history", window="7d", filter={"by": "event", "fired": True}, sort="name")
        self.assertEqual([r["entry_id"] for r in events["rows"]], [4, 1, 2])  # by device, newest first

    def test_one_device_reads_its_own_path(self):
        out = self.report(view="alert_history", window="7d", scope={"device": "core-sw1"}, filter={"by": "event"})
        self.assertEqual([r["entry_id"] for r in out["rows"]], [5, 4])
        [read] = self.reads("logs/alertlog")
        self.assertEqual(read["path"], "logs/alertlog/1")
        self.assertEqual(read["params"], {"from": "2026-10-21 00:00:00", "sortorder": "DESC", "limit": "250",
                                          "start": "0"})  # fmt: skip
        self.assertEqual(out["summary"]["logged"], 2)
        # a scope of more devices than are read one at a time: every device's log, kept to the scope
        self.fake.calls.clear()
        with mock.patch.object(alerts_mod, "DEVICE_READS", 1):
            out = self.report(view="alert_history", window="7d", scope={"devices": ["core-sw1", "access-sw2"]},
                              filter={"by": "event"})  # fmt: skip
        self.assertEqual([r["entry_id"] for r in out["rows"]], [5, 4])
        self.assertEqual([c["path"] for c in self.reads("logs/alertlog")], ["logs/alertlog"])
        self.assertNotIn("logged", out["summary"])  # LibreNMS's count was the fleet's, not the scope's

    def test_devices_past_the_cap_are_named_unread(self):
        with mock.patch.object(alerts_mod, "MAX_ENTRIES", 2):
            out = self.report(view="alert_history", window="7d", scope={"devices": ["core-sw1", "edge-rtr1"]},
                              filter={"by": "event"})  # fmt: skip
        self.assertEqual([r["entry_id"] for r in out["rows"]], [5, 4])  # core-sw1's, read first: by hostname
        self.assertEqual([c["path"] for c in self.reads("logs/alertlog")], ["logs/alertlog/1"])
        self.assertEqual(out["partial_reason"], "the alert log of devices 2 was not read: the report had read its 2 "
                                                "entries or used its 30 requests; narrow the window or the scope")  # fmt: skip
        self.assertNotIn("logged", out["summary"])

    def test_a_scope_of_no_device_reads_no_log_and_answers_none(self):
        self.fake.seed("device_groups", {"id": 7, "name": "empty-group", "type": "static", "devices": []})
        for scope, note in (
            ({"location": "LON-3"}, "no device is at location 'LON-3'"),  # a location no device is at
            ({"os": "junos"}, "no device has os 'junos'; the os values LibreNMS holds: asa, ios, iosxe"),
            ({"group": "empty-group"}, None),  # the scope says it: device_count 0
        ):
            for by in ("rule", "device", "event"):
                self.fake.calls.clear()
                out = self.report(view="alert_history", window="7d", scope=scope, filter={"by": by})
                self.assertEqual((out["success"], out["count"], out["rows"], out["partial"]), (True, 0, [], False))
                self.assertEqual((out["scope"]["device_count"], out["summary"]["logged"], out["summary"]["entries"]),
                                 (0, 0, 0))  # fmt: skip
                notes = [text for text in out["notes"] if "librenms_timezone" not in text]  # the window's aside
                self.assertEqual(notes, [note] if note else [], scope)
                self.assertEqual(self.reads("logs/alertlog"), [])  # nothing to read
        self.assertEqual(self.report(view="alert_history", scope={"group": "empty-group"})["scope"]["group"],
                         {"group_id": 7, "name": "empty-group"})  # fmt: skip

    def test_flaps(self):
        for when, state in (("2026-10-28 10:30:00", 0), ("2026-10-28 11:00:00", 1), ("2026-10-28 11:10:00", 0),
                            ("2026-10-28 11:20:00", 1)):  # fmt: skip
            self.seed_log(rule_id=1, device_id=2, fault_id=1, state=state, time_logged=when)
        out = self.report(view="alert_history", window="7d", sort="flaps")
        self.assertEqual((out["rows"][0]["rule_id"], out["rows"][0]["fired"], out["rows"][0]["flaps"]), (1, 4, 2))
        self.assertEqual(out["rows"][0]["last_fired"], "2026-10-28 11:20:00")
        self.assertEqual(out["summary"]["top_devices"][0]["flaps"], 2)

    def test_filters_on_entries_and_rules(self):
        for filters, ids in (
            ({"by": "event", "rule": "high"}, [5, 4]),
            ({"by": "event", "severity": "warning"}, [1, 3, 2]),
            ({"by": "event", "state": "recovered"}, [5]),
            ({"by": "event", "entity": "transit-b"}, [2]),
            ({"by": "event", "disabled": True}, []),
            ({"by": "event", "notifies": True}, [1, 3, 2, 5, 4]),
        ):
            out = self.report(view="alert_history", window="7d", filter=filters)
            self.assertEqual([r["entry_id"] for r in out["rows"]], ids, filters)
        # a filter on the entries themselves lists only the rules that logged them
        out = self.report(view="alert_history", window="7d", filter={"state": "recovered"})
        self.assertEqual([(r["rule_id"], r["entries"]) for r in out["rows"]], [(2, 1)])

    def test_paging_the_log_the_cap_and_a_page_too_large_to_read(self):
        for n in range(300):
            self.seed_log(rule_id=1, device_id=2, fault_id=1, state=n % 2, time_logged=f"2026-10-28 11:{n // 60:02d}:"
                          f"{n % 60:02d}")  # fmt: skip
        out = self.report(view="alert_history", window="7d")
        self.assertEqual((out["summary"]["logged"], out["summary"]["entries"], out["partial"]), (305, 305, False))
        self.assertEqual([c["params"]["start"] for c in self.reads("logs/alertlog")], ["0", "250"])
        self.fake.calls.clear()
        with mock.patch.object(alerts_mod, "MAX_ENTRIES", 100):
            out = self.report(view="alert_history", window="7d")
        self.assertEqual((out["summary"]["entries"], out["partial"]), (100, True))
        self.assertIn("the alert log holds 305 entries from 2026-10-21 00:00:00 (server time) on for what was read; "
                      "the newest 100 were read", out["partial_reason"])  # fmt: skip
        self.fake.calls.clear()
        real = self.client.get

        def get(path, params=None):
            if path == "logs/alertlog" and int(params["limit"]) > 100:
                raise self.client_mod.LibreNMSError("too large", status=200, kind="too_large")
            return real(path, params)

        self.client.get = get
        out = reports.run(self.client, self.settings, {"view": "alert_history", "window": "7d"})
        self.assertEqual((out["summary"]["entries"], out["partial"]), (305, False))
        self.assertEqual([c["params"]["limit"] for c in self.reads("logs/alertlog")], ["62"] * 5)  # 250, 125: too large

    def test_the_call_budget_and_a_failed_rules_read_make_it_partial(self):
        for n in range(300):
            self.seed_log(rule_id=1, device_id=2, state=1, time_logged=f"2026-10-28 10:{n // 60:02d}:{n % 60:02d}")
        out = reports.run(self.client, self.settings, {"view": "alert_history", "window": "7d"}, call_budget=3)
        self.assertTrue(out["partial"])
        self.assertIn("the alert log was not read past entry 250 of logs/alertlog: the report used its 3 requests",
                      out["partial_reason"])  # fmt: skip
        self.fake.fail_on("GET", "rules", 500)
        out = self.report(view="alert_history", window="7d")
        self.assertEqual(out["partial_reason"], "the alert rules (names, severities and settings) not read: LibreNMS "
                                                "answered HTTP 500 (server)")  # fmt: skip
        self.assertEqual({row["rule"] for row in out["rows"]}, {None})
        self.fake.fail_on("GET", "logs/alertlog", 500)
        self.assertFalse(self.report(view="alert_history")["success"])  # the log is what it reports


class OperatorQuestions(AlertCase):
    """The conversational audit's questions about alerts, each answered by one or two librenms_report calls from
    the summary or the rows."""

    def setUp(self):
        super().setUp()
        self.settings_with(librenms_timezone="UTC")

    def test_what_is_alerting_right_now(self):  # 28
        out = self.report(view="alerts")
        self.assertEqual((out["count"], out["summary"]["unacknowledged"], out["summary"]["by_severity"]["critical"]),
                         (4, 3, 1))  # fmt: skip
        self.assertEqual([(r["hostname"], r["rule"], r["entity"]) for r in out["rows"][:2]],
                         [("core-sw1.example.net", "High CPU", None),
                          ("edge-rtr1.example.net", "Port down", "Gi0/0/0")])  # fmt: skip

    def test_since_when(self):  # 29
        out = self.report(view="alerts", sort="oldest", limit=1)
        row = out["rows"][0]
        self.assertEqual((row["hostname"], row["first_seen"], row["first_seen_age"]),
                         ("access-sw2.example.net", "2026-10-28T08:30:00Z", "3h 30m"))  # fmt: skip

    def test_unacknowledged_critical_alerts(self):  # 30
        out = self.report(view="alerts", filter={"severity": "critical", "acked": False})
        self.assertEqual([(r["alert_id"], r["rule"]) for r in out["rows"]], [(4, "High CPU")])

    def test_what_was_acknowledged_and_with_what_note(self):  # 31
        out = self.report(view="alerts", filter={"acked": True})
        self.assertEqual(
            [(r["entity"], r["note"]) for r in out["rows"]],
            [("Gi0/0/1 (WAN: transit-b)", "2026-10-28 09:15:00 - Ack (alice) carrier ticket 4411")],
        )

    def test_which_port_or_sensor_an_alert_is_about(self):  # 32
        out = self.report(view="alerts", filter={"rule": "Port down"}, sort="name")
        self.assertEqual([(r["hostname"], r["port_id"], r["entity"]) for r in out["rows"]],
                         [("access-sw2.example.net", 9, "Gi1/0/48 (to core-sw1)"),
                          ("edge-rtr1.example.net", 5, "Gi0/0/0"),
                          ("edge-rtr1.example.net", 6, "Gi0/0/1 (WAN: transit-b)")])  # fmt: skip
        # the second call, for the port in depth, by the port_id the first one gave
        port = self.report(view="port", scope={"port": out["rows"][0]["port_id"]})
        self.assertEqual(port["rows"][0]["alerts"][0]["rule"], "Port down")

    def test_the_noisiest_rules_this_week(self):  # 33
        for when in ("2026-10-25 10:00:00", "2026-10-26 10:00:00", "2026-10-27 10:00:00"):
            self.seed_log(rule_id=2, device_id=1, fault_id=5, state=1, time_logged=when)
        out = self.report(view="alert_history", window="7d", limit=3)
        self.assertEqual(out["summary"]["top_rules"], [{"rule_id": 2, "rule": "High CPU", "fired": 4},
                                                       {"rule_id": 1, "rule": "Port down", "fired": 2}])  # fmt: skip
        self.assertEqual(out["rows"][0]["rule"], "High CPU")

    def test_the_alert_history_of_a_device(self):  # 34
        out = self.report(view="alert_history", scope={"device": "edge-rtr1"}, window="7d", filter={"by": "event"})
        self.assertEqual([(r["time"], r["rule"], r["state"], r["entity"]) for r in out["rows"]],
                         [("2026-10-28T10:02:00Z", "Port down", "alerted", "Gi0/0/0 (WAN: transit-a)"),
                          ("2026-10-28T09:15:00Z", "Port down", "acknowledged", None),
                          ("2026-10-28T09:10:00Z", "Port down", "alerted", "Gi0/0/1 (WAN: transit-b)")])  # fmt: skip
        self.assertEqual(out["rows"][0]["time_age"], "1h 58m")

    def test_disabled_rules_and_rules_without_notifications(self):  # 35
        self.seed_rule(id=3, name="Disk full", disabled=1)
        self.seed_rule(id=4, name="BGP down", alert_operation_id=None)
        disabled = self.report(view="alert_history", filter={"disabled": True})
        self.assertEqual([r["rule"] for r in disabled["rows"]], ["Disk full"])
        silent = self.report(view="alert_history", filter={"notifies": False})
        self.assertEqual([r["rule"] for r in silent["rows"]], ["BGP down"])
        self.assertEqual(silent["summary"]["rules_without_notifications"], 1)

    def test_alerts_about_a_sensor(self):  # 39, from the alert side
        self.fake.seed("faults", {
            "id": 6, "rule_id": 2, "device_id": 1, "entity_type": "sensor", "entity_id": 1, "state": 1,
            "timestamp": "2026-10-28 11:50:00", "first_seen": "2026-10-28 11:50:00",
            "details": {"rule": [{"sensor_descr": "Chassis Temperature", "sensor_class": "temperature",
                                  "sensor_current": 71}]},
        })  # fmt: skip
        out = self.report(view="alerts", filter={"entity_type": "sensor"})
        self.assertEqual([(r["entity"], r["value"], r["first_seen_age"]) for r in out["rows"]],
                         [("Chassis Temperature (temperature)", 71, "10m 0s")])  # fmt: skip

    def test_answers_stay_small(self):
        for args in ({"view": "alerts"}, {"view": "alert_history", "window": "30d"},
                     {"view": "alert_history", "window": "30d", "filter": {"by": "event"}}):  # fmt: skip
            self.assertLess(len(json.dumps(self.report(**args))), 12000, args)


class Safety(AlertCase):
    def test_every_read_is_an_allowed_get_and_nothing_is_written(self):
        for args in (
            {"view": "alerts"},
            {"view": "alerts", "filter": {"state": "recovered"}},
            {"view": "alert_history", "window": "30d"},
            {"view": "alert_history", "scope": {"device": "edge-rtr1"}, "filter": {"by": "device"}},
        ):
            self.assertTrue(self.report(**args)["success"], args)
        self.assert_reads_only_allowed_gets()
        self.assertEqual(NOON.hour, 12)
