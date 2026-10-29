"""librenms_query's where, sort and offset: the typed filter and the stable, numeric-aware sort (listing.py) on their
own, then through the handler against the fake: every row of a route LibreNMS does not page is reachable with
offset, next_offset follows the limit and the result budget, logs routes page on the server, and neither a filter nor
an order tells anything about a value the result masks."""

import json
import unittest

from .helpers import submodule
from .test_handlers import HandlerCase

listing = submodule("listing")
CORE_PORTS = "devices/core-sw1.example.net/ports"


def seed_ports(fake, count, device_id=1):
    """*count* ports on one device, numbered from 1: every 7th down, ifAlias on every 3rd, a rate per port."""
    for i in range(1, count + 1):
        fake.seed("ports", {
            "device_id": device_id, "ifIndex": 1000 + i, "ifName": f"Gi1/0/{i}", "ifDescr": f"GigabitEthernet1/0/{i}",
            "ifAlias": "" if i % 3 else f"uplink to rack {i}", "ifType": "ethernetCsmacd", "ifSpeed": 1_000_000_000,
            "ifAdminStatus": "up", "ifOperStatus": "up" if i % 7 else "down", "ifInOctets_rate": (i * 7919) % 1000,
        })  # fmt: skip


def select(rows, where=None, sort=None):
    return [row["id"] for row in listing.select(rows, listing.conditions(where), listing.order(sort))]


class Sort(unittest.TestCase):
    def test_numbers_by_value_text_in_natural_order_and_empty_values_last(self):
        values = ["Gi1/0/10", 9, "", "1000000000", None, "gi1/0/2", 2.5, "-3", "Gi1/0/2", "007", True, {"a": 1}]
        rows = [{"id": i, "v": value} for i, value in enumerate(values)] + [{"id": 99}]
        self.assertEqual(select(rows, sort={"key": "v"}), [7, 10, 6, 1, 3, 9, 8, 5, 0, 11, 2, 4, 99])
        self.assertEqual(select(rows, sort={"key": "v", "order": "desc"}), [3, 1, 6, 10, 7, 0, 5, 8, 9, 11, 2, 4, 99])

    def test_digits_compare_by_value_in_text_too(self):
        rows = [{"id": i, "v": v} for i, v in enumerate(["10.0.0.10", "10.0.0.2", "Te1/1/1", "2026-10-28 09:00:00",
                                                          "2026-10-28 10:00:00", "2026-10-03 23:00:00"])]  # fmt: skip
        self.assertEqual(select(rows, sort={"key": "v"}), [1, 0, 5, 3, 4, 2])
        long = [{"id": i, "v": f"x{'9' * (5000 + i)}"} for i in (2, 0, 1)]  # no int() of 5,000 digits
        self.assertEqual(select(long, sort={"key": "v", "order": "desc"}), [2, 1, 0])
        macs = [{"id": i, "v": v} for i, v in enumerate(["aabbccddeeff", "123456789012", "001122334455"])]
        self.assertEqual(select(macs, sort={"key": "v"}), [1, 2, 0])  # a MAC of digits only is a number

    def test_a_number_whose_exponent_has_more_than_four_digits_is_text(self):
        # Decimal() raises on an exponent past about 10**18: one ifAlias written so stopped every sort of its route
        values = ["1e99999999999999999999", 5, "1e9999", "abc", "-1E-9999"]
        rows = [{"id": i, "v": value} for i, value in enumerate(values)]
        self.assertEqual(select(rows, sort={"key": "v"}), [4, 1, 2, 0, 3])
        self.assertEqual(select(rows, sort={"key": "v", "order": "desc"}), [2, 1, 4, 3, 0])

    def test_equal_values_keep_the_order_read_in_either_direction(self):
        rows = [{"id": i, "v": v} for i, v in enumerate([1, "1", 1.0, True, "1.0", 0.1, "0.1", "up", "up"])]
        self.assertEqual(select(rows, sort={"key": "v"}), [5, 6, 0, 1, 2, 3, 4, 7, 8])
        self.assertEqual(select(rows, sort={"key": "v", "order": "desc"}), [0, 1, 2, 3, 4, 5, 6, 7, 8])

    def test_objects_and_lists_sort_in_the_order_read_so_the_order_tells_nothing_of_them(self):
        rows = [{"id": i, "details": {"contacts": {f"{name}@example.net": name}}} for i, name in enumerate("zam")]
        rows.append({"id": 3, "details": ["b", "a"]})
        for order in ("asc", "desc"):
            self.assertEqual(select(rows, sort={"key": "details", "order": order}), [0, 1, 2, 3])


class Where(unittest.TestCase):
    ROWS = [
        {"id": 0, "s": "up", "n": 10, "t": "Gi1/0/2", "x": ""},
        {"id": 1, "s": "Down", "n": "9.5", "t": "Gi1/0/10", "x": None},
        {"id": 2, "s": "UP", "n": True, "t": "Te1/1/1"},
        {"id": 3, "s": None, "n": "abc", "t": "uplink to core", "x": "set"},
        {"id": 4, "s": {"a": 1}, "n": [1], "t": 12, "x": 0},
    ]

    def test_each_operator(self):
        for condition, kept in (
            (("s", "eq", "up"), [0, 2]),  # text ignoring case
            (("s", "ne", "up"), [1, 3, 4]),  # every row eq does not keep, the empty ones too
            (("s", "eq", None), [3]),
            (("x", "eq", ""), [0, 1, 2]),  # "", null and a missing key are all empty
            (("x", "eq", None), [0, 1, 2]),
            (("x", "ne", None), [3, 4]),  # 0 is a number, not empty
            (("n", "eq", 1), [2]),  # true is 1
            (("n", "eq", "10"), [0]),  # a number written as text is a number
            (("n", "eq", 9.5), [1]),
            (("n", "gt", 9), [0, 1]),
            (("n", "lt", 10), [1, 2]),  # never "abc" or a list
            (("t", "gt", "Gi1/0/9"), [1, 2, 3]),  # natural order; never the number 12
            (("t", "lt", "gi1/0/10"), [0]),
            (("t", "contains", "1/0"), [0, 1]),
            (("t", "contains", "UPLINK"), [3]),
            (("t", "contains", 12), [4]),  # a number as JSON writes it
            (("t", "contains", "2"), [0, 4]),
            (("s", "contains", "u"), [0, 2]),  # never null or an object
            (("s", "eq", {"a": 1}.get("a")), []),
        ):
            key, op, value = condition
            self.assertEqual(select(self.ROWS, [{"key": key, "op": op, "value": value}]), kept, condition)

    def test_a_number_and_a_text_that_both_start_with_a_digit_compare_as_texts(self):
        # LibreNMS's versions are text: "16" read as a number compared with none of them, and lt "16" matched 0
        values = ["15.2(4)E", "12.2(55)SE", "16.9.4", "15", "N/A", 17, "16.12.4", None]
        rows = [{"id": i, "version": value} for i, value in enumerate(values)]
        for op, value, kept in (
            ("lt", "15", [1]),
            ("lt", 16, [0, 1, 3]),  # 16.9.4 and 16.12.4 come after 16, as in natural order
            ("gt", "16.9", [2, 5, 6]),  # 15 and 17 by value
            ("lt", "16.1.0", [0, 1, 3]),  # 15 as the text "15"
            ("gt", 0, [0, 1, 2, 3, 5, 6]),  # never "N/A" with a number,
            ("lt", "N/A", [0, 1, 2, 6]),  # nor a number with a text that does not start with a digit,
            ("gt", -1, [3, 5]),  # nor a text with a number that does not
        ):
            self.assertEqual(select(rows, [{"key": "version", "op": op, "value": value}]), kept, (op, value))
        self.assertEqual(select(rows, [{"key": "version", "op": "eq", "value": 15}]), [3])  # eq stays exact

    def test_a_number_whose_exponent_has_more_than_four_digits_is_text(self):
        rows = [{"id": 0, "v": "1e99999999999999999999"}, {"id": 1, "v": 5}, {"id": 2, "v": "1e9999"}]
        for condition, kept in (
            (("v", "eq", ""), []),
            (("v", "ne", "x"), [0, 1, 2]),
            (("v", "eq", "1E99999999999999999999"), [0]),  # a text, equal ignoring case
            (("v", "ne", "1e99999999999999999999"), [1, 2]),
            (("v", "gt", "1e9999"), [0]),  # a number and a text that start with a digit: as texts
        ):
            key, op, value = condition
            self.assertEqual(select(rows, [{"key": key, "op": op, "value": value}]), kept, condition)

    def test_every_condition_must_hold_and_an_operator_is_read_in_any_case(self):
        where = [{"key": "s", "op": " EQ ", "value": "up"}, {"key": "n", "op": "gt", "value": "5"}]
        self.assertEqual(select(self.ROWS, where), [0])
        self.assertEqual(select(self.ROWS, []), [0, 1, 2, 3, 4])

    def test_a_credential_compares_as_its_mask(self):
        rows = [{"id": 0, "community": "public"}, {"id": 1, "community": ""}, {"id": 2, "community": "private"}]
        for value, op, kept in (
            ("public", "eq", []),
            ("pub", "contains", []),
            ("private", "gt", []),
            ("<redacted>", "eq", [0, 2]),
            ("", "eq", [1]),
        ):
            self.assertEqual(select(rows, [{"key": "community", "op": op, "value": value}]), kept, (op, value))
        for order in ("asc", "desc"):  # "public" < "private" would reverse the read order
            self.assertEqual(select(rows, sort={"key": "community", "order": order}), [0, 2, 1])
        self.assertEqual(
            select([{"id": 0, "AuthPass": "b"}, {"id": 1, "AuthPass": "a"}], sort={"key": "AuthPass"}), [0, 1]
        )

    def test_a_key_no_row_has_is_refused(self):
        rows = [{"id": 0, "ifName": "Gi1/0/1", "ifOperStatus": "up"}, "not a row"]
        with self.assertRaises(listing.UnknownKey) as caught:
            select(rows, [{"key": "ifoperstatus", "op": "eq", "value": "up"}])
        self.assertEqual(
            str(caught.exception),
            "no row has the key 'ifoperstatus' (keys match as written); did you mean 'ifOperStatus'?",
        )
        with self.assertRaises(listing.UnknownKey) as caught:
            select(rows, sort={"key": "speed"})
        self.assertEqual(
            str(caught.exception),
            "no row has the key 'speed' (keys match as written); the rows have id, ifName, ifOperStatus",
        )
        with self.assertRaises(listing.UnknownKey) as caught:
            select(["a", "b"], sort={"key": "id"})
        self.assertEqual(
            str(caught.exception), "no row has the key 'id' (keys match as written); the rows are not objects"
        )
        self.assertEqual(select([], [{"key": "anything", "op": "eq", "value": 1}], {"key": "else"}), [])

    def test_malformed_arguments_are_refused_saying_what_to_write(self):
        cond = {"key": "a", "op": "eq", "value": 1}
        for where, sort, message in (
            ("down", None, 'where must be a list of conditions, e.g. [{"key": "ifOperStatus", "op": "eq", "value": '
                           '"down"}]'),
            ([cond] * 11, None, "where takes at most 10 conditions (got 11)"),
            ([1], None, "where[0] must be an object with key, op and value"),
            ([cond, {**cond, "field": "b"}], None, "where[1] takes key, op, value, not 'field'"),
            ([{"op": "eq", "value": 1}], None, "where[0].key must name a key of the rows, e.g. ifName"),
            ([{**cond, "key": " "}], None, "where[0].key must name a key of the rows, e.g. ifName"),
            ([{**cond, "key": "k" * 101}], None, "where[0].key is 101 characters; no key of a LibreNMS row is that long"),
            ([{**cond, "op": "=="}], None, "where[0].op must be one of eq, ne, contains, gt, lt (got '==')"),
            ([{**cond, "op": None}], None, "where[0].op must be one of eq, ne, contains, gt, lt (got None)"),
            ([{"key": "a", "op": "eq"}], None, 'where[0] needs a value (eq with null or "" matches an empty one)'),
            ([{**cond, "value": [1]}], None, "where[0].value must be text, a number, true, false or null"),
            ([{**cond, "value": float("nan")}], None, "where[0].value must be text, a number, true, false or null"),
            ([{**cond, "value": "v" * 201}], None, "where[0].value is 201 characters; at most 200 are compared"),
            ([{**cond, "op": "contains", "value": ""}], None,
             "where[0]: contains looks for text (or a number) in a value; give it some"),
            ([{**cond, "op": "contains", "value": True}], None,
             "where[0]: contains looks for text (or a number) in a value; give it some"),
            ([{**cond, "op": "gt", "value": None}], None, "where[0]: gt compares with a number or a text; give it one"),
            ([{**cond, "op": "lt", "value": False}], None, "where[0]: lt compares with a number or a text; give it one"),
            ([{**cond, "op": "gt", "value": "1e99999999999999999999"}], None,
             "where[0]: gt compares with a number whose exponent has at most four digits"),
            (None, "ifName", 'sort must be an object, e.g. {"key": "ifInOctets_rate", "order": "desc"}'),
            (None, {"field": "a"}, "sort takes key, order, not 'field'"),
            (None, {"key": "a", "order": "down"}, "sort.order must be asc or desc (got 'down')"),
            (None, {"key": 3}, "sort.key must name a key of the rows, e.g. ifName"),
        ):  # fmt: skip
            with self.assertRaises(listing.ListingError, msg=(where, sort)) as caught:
                listing.conditions(where)
                listing.order(sort)
            self.assertEqual(str(caught.exception), message)
        self.assertEqual(listing.order({"key": " ifName ", "order": " DESC "}), listing.Order("ifName", True))
        self.assertEqual(listing.order({"key": "ifName", "order": None}), listing.Order("ifName", False))
        self.assertEqual((listing.conditions(None), listing.order(None)), ([], None))


class Query(HandlerCase):
    def setUp(self):
        super().setUp()
        self.settings_mod.set_settings(self.settings_mod.Settings(max_query_results=500))

    def ports(self, **args):
        args = {"path": CORE_PORTS, "params": {"columns": "port_id,ifName,ifOperStatus,ifInOctets_rate"}, **args}
        return self.call("librenms_query", **args)

    def test_rows_past_max_query_results_are_read_with_offset(self):
        seed_ports(self.fake, 600)
        first = self.ports(limit=5000)
        self.assertEqual((first["count"], first["returned"], first["truncated"]), (602, 500, True))
        self.assertEqual((first["next_offset"], "offset" in first), (500, False))
        second = self.ports(limit=5000, offset=first["next_offset"])
        self.assertEqual((second["offset"], second["returned"], second["truncated"]), (500, 102, False))
        self.assertNotIn("next_offset", second)
        names = [row["ifName"] for row in first["results"] + second["results"]]
        # in LibreNMS's order (ifIndex): the two seeded ports, then the 600
        self.assertEqual(names, ["Gi1/0/1", "Gi1/0/2"] + [f"Gi1/0/{i}" for i in range(1, 601)])
        self.assertTrue(all(call["params"] == {"columns": "port_id,ifName,ifOperStatus,ifInOctets_rate"}
                            for call in self.gets() if call["path"] == "devices/1/ports"))  # fmt: skip

    def test_the_busiest_down_ports_from_every_row_paged(self):
        seed_ports(self.fake, 600)
        down = sorted(
            (row for row in self.fake.tables["ports"].values() if row["device_id"] == 1 and not row["deleted"]
             and row["ifOperStatus"] == "down"),
            key=lambda row: -(row["ifInOctets_rate"] if row["ifInOctets_rate"] is not None else -1),
        )  # fmt: skip
        where = [{"key": "ifOperStatus", "op": "eq", "value": "down"}]
        sort = {"key": "ifInOctets_rate", "order": "desc"}
        out = self.ports(where=where, sort=sort, limit=10, offset=10, fields=["port_id"])
        self.assertEqual((out["count"], out["matched"], out["offset"]), (602, len(down), 10))
        self.assertEqual((out["returned"], out["truncated"], out["next_offset"]), (10, True, 20))
        self.assertEqual([row["port_id"] for row in out["results"]], [row["port_id"] for row in down[10:20]])
        last = self.ports(where=where, sort=sort, offset=len(down) - 1)  # port 2 has no rate: last
        self.assertEqual((last["returned"], last["truncated"], last["results"][0]["port_id"]), (1, False, 2))
        self.assertNotIn("next_offset", last)

    def test_top_talkers_fleet_wide_with_rates_as_numbers_and_as_text(self):
        for port_id, rate in ((101, 5000), (102, "750000000"), (103, 1_000_000_000), (104, 12.5), (105, "0")):
            self.fake.seed("ports", {"port_id": port_id, "device_id": 3, "ifIndex": port_id, "ifName": f"Te{port_id}",
                                     "ifInOctets_rate": rate})  # fmt: skip
        args = {"path": "ports", "params": {"columns": "port_id,ifInOctets_rate"}}
        out = self.call("librenms_query", **args, sort={"key": "ifInOctets_rate", "order": "desc"}, limit=3)
        self.assertEqual([row["port_id"] for row in out["results"]], [103, 102, 101])
        self.assertEqual((out["returned"], out["next_offset"]), (3, 3))
        out = self.call("librenms_query", **args, sort={"key": "ifInOctets_rate"}, limit=50)
        self.assertEqual([row["port_id"] for row in out["results"]][:5], [105, 104, 101, 102, 103])
        self.assertEqual({row["ifInOctets_rate"] for row in out["results"][5:]}, {None})  # unpolled ports last

    def test_open_alerts_on_one_device(self):
        out = self.call(
            "librenms_query",
            path="faults",
            params={"state": [1, 2]},
            where=[{"key": "device_id", "op": "eq", "value": "2"}],
        )
        self.assertEqual((out["count"], out["matched"], out["returned"], out["truncated"]), (4, 2, 2, False))
        self.assertEqual([row["id"] for row in out["results"]], [1, 2])
        self.assertEqual(out["results"][0]["entities"], [{"ifName": "Gi0/0/0"}])  # still no details
        self.assertNotIn("details", out["results"][0])

    def test_a_cut_listing_reads_on_from_the_first_row_it_left_out(self):
        self.settings_mod.set_settings(self.settings_mod.Settings(max_query_results=5000, max_result_chars=8000))
        seed_ports(self.fake, 600)
        where = [{"key": "ifOperStatus", "op": "ne", "value": "down"}]
        sort = {"key": "ifName", "order": "desc"}
        expected = [f"Gi1/0/{i}" for i in range(600, 0, -1) if i % 7] + ["Gi1/0/1"]  # Gi1/0/2 is down
        seen, offset, cut = [], 0, 0
        while offset is not None:
            raw = self.handlers.librenms_query(
                {"path": CORE_PORTS, "params": {"columns": "port_id,ifName,ifAlias,ifOperStatus"}, "where": where,
                 "sort": sort, "offset": offset, "limit": 5000}
            )  # fmt: skip
            self.assertLessEqual(len(raw), 8000)
            out = json.loads(raw)
            self.assertEqual((out["matched"], out.get("offset", 0)), (len(expected), offset))
            seen += [row["ifName"] for row in out["results"]]
            if "note" in out:
                cut += 1
                self.assertTrue(out["note"].endswith(f"or read on with offset {offset + out['returned']}"), out["note"])
            offset = out.get("next_offset")
            if offset is not None:
                self.assertEqual((offset, out["truncated"]), (len(seen), True))
        self.assertGreater(cut, 3)
        self.assertEqual(seen, expected)  # every row once, in order

    def test_offset_past_the_last_row_says_so(self):
        out = self.call("librenms_query", path="devices", offset=10, fields=["hostname"])
        self.assertEqual((out["count"], out["offset"], out["returned"], out["truncated"]), (4, 10, 0, False))
        self.assertEqual(out["note"], "offset 10 is past the last row: there are 4, from offset 0")
        out = self.call("librenms_query", path="logs/eventlog", offset=500)
        self.assertEqual((out["total"], out["returned"], out["truncated"]), (6, 0, False))
        self.assertEqual(out["note"], "offset 500 is past the last row: there are 6, from offset 0")

    def test_logs_routes_page_on_the_server_with_offset(self):
        out = self.call("librenms_query", path="logs/eventlog", offset=2, limit=3, fields=["event_id"])
        self.assertEqual(self.gets()[-1]["params"], {"limit": "3", "start": "2", "sortorder": "DESC"})
        self.assertEqual((out["count"], out["total"], out["offset"], out["returned"]), (3, 6, 2, 3))
        self.assertEqual((out["truncated"], out["next_offset"]), (True, 5))
        self.assertEqual([row["event_id"] for row in out["results"]], [4, 3, 2])
        out = self.call("librenms_query", path="logs/eventlog", offset=out["next_offset"], limit=3)
        self.assertEqual(
            (out["returned"], out["truncated"], [row["event_id"] for row in out["results"]]), (1, False, [1])
        )
        self.assertNotIn("next_offset", out)

    def test_where_and_sort_on_a_logs_route_are_refused_before_anything_is_sent(self):
        for args in ({"where": [{"key": "type", "op": "eq", "value": "interface"}]}, {"sort": {"key": "datetime"}}):
            out = self.call("librenms_query", path="logs/eventlog/core-sw1.example.net", **args)
            self.assertEqual((out["success"], out["refused"]), (False, True))
            self.assertIn("LibreNMS pages the logs routes itself", out["error"])
        self.assertEqual(self.gets(), [])
        self.assertEqual(
            [event["path"] for event in self.events("query_refused")], ["logs/eventlog/core-sw1.example.net"] * 2
        )

    def test_params_start_where_librenms_reads_none_is_refused(self):
        out = self.call("librenms_query", path=CORE_PORTS, params={"start": 500})
        self.assertEqual((out["success"], out["refused"]), (False, True))
        self.assertTrue(out["error"].startswith("LibreNMS's get_device_ports does not read params.start"), out["error"])
        self.assertEqual(self.gets(), [])

    def test_malformed_where_or_sort_is_refused_before_anything_is_sent(self):
        out = self.call("librenms_query", path="devices", where={"key": "os", "op": "eq", "value": "ios"})
        self.assertEqual(out, {"success": False, "error": out["error"]})
        self.assertTrue(out["error"].startswith("where must be a list of conditions"))
        out = self.call("librenms_query", path="devices", sort={"key": "hostname", "order": "up"})
        self.assertEqual(out["error"], "sort.order must be asc or desc (got 'up')")
        self.assertEqual(self.call("librenms_query", path="devices", offset=-1)["refused"], True)
        self.assertEqual(self.gets(), [])

    def test_a_key_no_row_has_names_the_keys_there_are(self):
        hint = (
            "; on this route LibreNMS returns only the columns params.columns names (a default few without it): add "
            "the key there, e.g. params.columns=port_id,ifName,ifAlias"
        )
        out = self.ports(
            params={"columns": "port_id,ifName"}, where=[{"key": "ifOperStatus", "op": "eq", "value": "down"}]
        )
        self.assertEqual((out["success"], out["path"], out["route"]), (False, CORE_PORTS, "get_device_ports"))
        self.assertEqual(
            out["error"],
            "no row has the key 'ifOperStatus' (keys match as written); the rows have port_id, ifName" + hint,
        )
        # without params.columns, where it matters most: LibreNMS sends ifName (port_id and ifName on ports) alone
        for path, keys in ((CORE_PORTS, "ifName"), ("ports", "port_id, ifName")):
            out = self.call("librenms_query", path=path, where=[{"key": "ifAlias", "op": "eq", "value": ""}])
            self.assertEqual(
                out["error"], f"no row has the key 'ifAlias' (keys match as written); the rows have {keys}" + hint
            )
        out = self.call("librenms_query", path=CORE_PORTS, sort={"key": "ifname"})  # a case slip: not a column
        self.assertEqual(out["error"], "no row has the key 'ifname' (keys match as written); did you mean 'ifName'?")
        out = self.call("librenms_query", path="devices", sort={"key": "HOSTNAME"})
        self.assertEqual(
            out["error"], "no row has the key 'HOSTNAME' (keys match as written); did you mean 'hostname'?"
        )
        out = self.call("librenms_query", path="devices", sort={"key": "speed"})  # a route without params.columns
        self.assertRegex(out["error"], r"^no row has the key 'speed' \(keys match as written\); the rows have device_id, "
                         r"hostname, .* and \d+ more$")  # fmt: skip

    def test_ports_without_a_description_and_a_description_that_reads_as_a_huge_number(self):
        # anyone who manages the device writes ifAlias; one that Decimal() raised on stopped every where and sort
        self.fake.seed(
            "ports", {"device_id": 1, "ifIndex": 4242, "ifName": "Gi9/9/9", "ifAlias": "1e99999999999999999999"}
        )
        args = {"path": CORE_PORTS, "params": {"columns": "port_id,ifName,ifAlias"}, "fields": ["ifName"]}
        for extra, names in (
            ({"where": [{"key": "ifAlias", "op": "eq", "value": ""}]}, ["Gi1/0/2"]),  # SKILL's example
            ({"where": [{"key": "ifAlias", "op": "ne", "value": "x"}]}, ["Gi1/0/1", "Gi1/0/2", "Gi9/9/9"]),
            ({"sort": {"key": "ifAlias"}}, ["Gi9/9/9", "Gi1/0/1", "Gi1/0/2"]),  # a text starting with a digit
        ):
            out = self.call("librenms_query", **args, **extra)
            self.assertEqual([row["ifName"] for row in out["results"]], names, extra)
        huge = {"key": "device_id", "op": "eq", "value": "1e99999999999999999999"}
        out = self.call("librenms_query", path="devices", where=[huge])
        self.assertEqual((out["success"], out["count"], out["matched"]), (True, 4, 0))
        sent = len(self.gets())
        out = self.call("librenms_query", path="devices", where=[{**huge, "op": "gt"}])  # an error saying why
        self.assertEqual(out, {"success": False, "error": out["error"]})
        self.assertEqual(out["error"], "where[0]: gt compares with a number whose exponent has at most four digits")
        self.assertEqual(len(self.gets()), sent)

    def test_a_version_compares_with_a_number_as_text(self):
        for op, value, matched in (("lt", "16", 0), ("lt", 17, 1), ("gt", 16, 1), ("lt", "16.12.10", 1)):
            out = self.call(
                "librenms_query",
                path="devices",
                where=[{"key": "version", "op": op, "value": value}],
                fields=["hostname"],
            )
            self.assertEqual(out["matched"], matched, (op, value))  # core-sw1 runs 16.12.4; the others have none
            self.assertEqual([row["hostname"] for row in out["results"]], ["core-sw1.example.net"] * matched)

    def test_where_sort_and_offset_on_one_object_are_an_error(self):
        for args in (
            {"where": [{"key": "location", "op": "eq", "value": "SFO-1"}]},
            {"sort": {"key": "lat"}},
            {"offset": 1},
        ):
            out = self.call("librenms_query", path="location/1", **args)
            self.assertEqual(
                out["error"],
                "where, sort and offset apply to listings, and location/1 answers with one object; ask without them",
            )
        self.assertEqual(self.call("librenms_query", path="location/1", offset=0)["result"]["location"], "SFO-1")

    def test_an_empty_answer_counts_no_match(self):
        out = self.call(
            "librenms_query", path="devices/4/ports", where=[{"key": "ifOperStatus", "op": "eq", "value": "up"}]
        )
        self.assertEqual((out["count"], out["matched"], out["returned"], out["results"]), (0, 0, 0, []))
        self.assertEqual(out["note"], "No ports found")

    def test_a_filter_or_an_order_tells_nothing_of_a_masked_credential(self):
        for value, op, matched in (("c0re-Community!", "eq", 0), ("Community", "contains", 0), ("<redacted>", "eq", 3)):
            out = self.call("librenms_query", path="devices", where=[{"key": "community", "op": op, "value": value}])
            self.assertEqual(out["matched"], matched, (op, value))
        by_name = [row["hostname"] for row in self.call("librenms_query", path="devices")["results"]]
        for key in ("community", "authpass"):
            for order in ("asc", "desc"):
                out = self.call("librenms_query", path="devices", sort={"key": key, "order": order})
                with_value = [row["hostname"] for row in out["results"] if row[key]]
                self.assertEqual(with_value, [name for name in by_name if name in with_value], (key, order))
        for raw in self.outputs:
            for secret in ("c0re-Community!", "Auth-S3cret-v3", "acc3ss-Community"):
                self.assertNotIn(secret, raw)


if __name__ == "__main__":
    unittest.main()
