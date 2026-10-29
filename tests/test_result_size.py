"""Result size: every result for the model stays within ``max_result_chars`` (Hermes shows only a 1,500-character
preview of a larger one). Listings are cut, saying how to see the rest; a plan, its journal, its apply and its
rollback are shown a range of steps at a time with ``next_offset``; the operator paths are never cut. Measured with
1,000 devices, 1,000 log rows, a 1,000-step plan and one of 1,000 irreversible steps checked 200 times."""

import json
import re
import unittest

from .helpers import submodule
from .test_handlers import HandlerCase

BUDGET = 60000


def steps_in(diff):
    return [int(index) for index in re.findall(r"^\[(\d+)\] create", diff, re.M)]


class Listings(HandlerCase):
    def setUp(self):
        super().setUp()
        self.settings_mod.set_settings(self.settings_mod.Settings(max_query_results=5000))

    def raw(self, **args):
        raw = self.handlers.librenms_query(args)
        self.assertLessEqual(len(raw), BUDGET, args)
        return json.loads(raw)

    def test_a_long_listing_is_cut_to_the_budget_saying_how_to_see_the_rest(self):
        for i in range(1000):
            self.fake.seed(
                "devices",
                {"hostname": f"sw{i:04d}.example.net", "sysName": f"sw{i:04d}", "sysDescr": "Cisco IOS " + "x" * 300},
            )
        out = self.raw(path="devices", limit=5000)
        self.assertEqual((out["count"], out["truncated"]), (1004, True))
        self.assertEqual(len(out["results"]), out["returned"])
        self.assertGreater(out["returned"], 20)
        self.assertEqual(
            out["note"],
            f"cut at {out['returned']} of 1004 rows to stay within max_result_chars ({BUDGET} characters): name only "
            f"the keys you need in fields, or read on with offset {out['returned']}",
        )
        self.assertEqual(out["next_offset"], out["returned"])  # the first row not shown
        self.assertEqual(list(out)[list(out).index("truncated") + 1], "next_offset")
        cut = self.raw(path="devices", limit=500, offset=7)  # past limit, then cut by the budget
        self.assertEqual((cut["truncated"], cut["next_offset"]), (True, 7 + cut["returned"]))
        self.assertLess(cut["returned"], 500)
        out = self.raw(path="devices", limit=5000, fields=["hostname", "status"])
        self.assertEqual((out["returned"], out["truncated"]), (1004, False))
        self.assertNotIn("note", out)
        self.assertNotIn("next_offset", out)

    def test_a_logs_page_cut_by_the_budget_says_where_to_read_on(self):
        for i in range(1000):
            self.fake.seed("eventlog", {"device_id": 1, "datetime": f"2026-10-28 {i // 60 % 24:02d}:{i % 60:02d}:00",
                                        "message": f"event {i} " + "z" * 300})  # fmt: skip
        every = [row["event_id"] for row in self.raw(path="logs/eventlog", limit=5000, fields=["event_id"])["results"]]
        first = self.raw(path="logs/eventlog", limit=500)
        kept = first["returned"]
        self.assertTrue(first["truncated"])
        self.assertEqual(first["next_offset"], kept)
        self.assertTrue(first["note"].endswith(f"or read on with offset {kept}"), first["note"])
        self.assertEqual([row["event_id"] for row in first["results"]], every[:kept])
        for after in (
            self.raw(path="logs/eventlog", limit=500, offset=kept),
            self.raw(path="logs/eventlog", limit=500, params={"start": kept}),  # the LibreNMS name still pages
        ):
            self.assertEqual(after["offset"], kept)
            shown = [row["event_id"] for row in after["results"]]
            self.assertEqual(shown, every[kept : kept + len(shown)])  # no row skipped or shown twice
            self.assertEqual(after["next_offset"], kept + len(shown))

    def test_a_row_too_large_on_its_own_gives_no_offset_to_read_on_from(self):
        # strings are clipped and lists are not: a fault's details (fields ['details']) can hold many matched rows
        self.settings_mod.set_settings(self.settings_mod.Settings(max_query_results=5000, max_result_chars=8000))
        wide = ("ifAlias", "ifDescr", "ifPhysAddress", "ifType")
        for i in range(3):
            self.fake.seed("ports", {"device_id": 1, "ifIndex": 5000 + i, "ifName": f"X{i}",
                                     **{key: key[2] * 1900 for key in wide}})  # fmt: skip
        args = {
            "path": "devices/core-sw1.example.net/ports",
            "params": {"columns": "port_id,ifName," + ",".join(wide)},
            "where": [{"key": "ifName", "op": "contains", "value": "X"}],
        }
        for offset in (0, 2):
            raw = self.handlers.librenms_query({**args, "offset": offset})
            self.assertLessEqual(len(raw), 8000)
            out = json.loads(raw)
            self.assertEqual((out["matched"], out["returned"], out["truncated"]), (3, 0, True))
            self.assertNotIn("next_offset", out)  # it pointed at the same row again: a loop
            self.assertEqual(
                out["note"],
                f"the row at offset {offset} does not fit within max_result_chars (8000 characters) on its own: name "
                f"only the keys you need in fields (offset {offset + 1} reads on past it)",
            )
        out = self.call("librenms_query", **args, fields=["ifName", "ifAlias"])
        self.assertEqual((out["returned"], out["truncated"]), (3, False))

    def test_a_single_object_too_large_is_refused_with_the_fields_advice(self):
        self.settings_mod.set_settings(self.settings_mod.Settings(max_result_chars=8000))
        location = {f"k{i}": "v" * 100 for i in range(200)}
        real = self.client.get
        self.client.get = lambda path, params=None: (
            {"status": "ok", "get_location": location} if path == "location/1" else real(path, params)
        )
        out = json.loads(self.handlers.librenms_query({"path": "location/1"}))
        self.assertFalse(out["success"])
        self.assertRegex(
            out["error"],
            r"^the result is \d+ characters, more than max_result_chars allows \(8000\); name only the keys you need",
        )
        self.assertEqual(self.call("librenms_query", path="location/1", fields=["k1"])["result"], {"k1": "v" * 100})

    def test_plan_errors_and_the_plan_listing_are_cut_too(self):
        self.settings_mod.set_settings(self.settings_mod.Settings(max_result_chars=8000, max_operations=1000))
        bad = [{"op": "update", "resource": "device", "id": 1, "data": {"sysName": "x" * 50}}] * 300
        raw = self.handlers.librenms_plan({"description": "bad", "operations": bad})
        self.assertLessEqual(len(raw), 8000)
        out = json.loads(raw)
        self.assertEqual((out["success"], out["truncated"]), (False, True))
        self.assertEqual(len(out["errors"]), out["returned"])
        self.assertTrue(out["note"].startswith(f"{out['returned']} of "))
        for i in range(40):
            self.plan([{"op": "update", "resource": "device", "id": 1, "data": {"notes": f"note {i}"}}], "d" * 150)
        raw = self.handlers.librenms_plans({"limit": 200})
        self.assertLessEqual(len(raw), 8000)
        out = json.loads(raw)
        self.assertEqual((out["count"], out["truncated"]), (40, True))
        self.assertEqual(len(out["plans"]), out["returned"])


class LargePlan(HandlerCase):
    """A plan at max_operations' upper limit: 1,000 location creates."""

    def setUp(self):
        super().setUp()
        self.settings_mod.set_settings(
            self.settings_mod.Settings(max_operations=1000, allow_delete=True, max_query_results=5000)
        )
        operations = [
            {"op": "create", "resource": "location",
             "data": {"location": f"DC{i:04d} Building {i} Floor 2 Room 2.{i % 100:02d}", "lat": 52 + i / 10000,
                      "lng": 4 + i / 10000}}
            for i in range(1000)
        ]  # fmt: skip
        self.planned = self.measured("librenms_plan", description="Add 1000 sites", operations=operations)
        self.pid = self.planned["plan_id"]

    def measured(self, name, **args):
        raw = self.handlers.HANDLERS[name](args)
        self.assertLessEqual(len(raw), BUDGET, (name, args))
        return json.loads(raw)

    def test_the_plan_shows_a_range_of_steps_and_where_the_rest_is(self):
        out = self.planned
        end = out["next_offset"]
        self.assertNotIn("steps", out)  # librenms_plans has them; the diff carried the same content twice
        self.assertEqual((out["offset"], out["steps_shown"], out["step_count"], out["truncated"]), (0, end, 1000, True))
        self.assertEqual(steps_in(out["diff"]), list(range(end)))
        self.assertTrue(
            out["diff"].endswith(f"… steps 0-{end - 1} of 1000 are shown; the next ones start at step {end}")
        )
        self.assertIn(f"Read the rest with librenms_plans (this plan_id, offset {end}), show the user every step",
                      out["next_step"])  # fmt: skip
        seen, offset = steps_in(out["diff"]), end
        while offset is not None:
            page = self.measured("librenms_plans", plan_id=self.pid, offset=offset)
            self.assertEqual((page["offset"], steps_in(page["diff"])[0]), (offset, offset))
            self.assertTrue(page["diff"].startswith(f"Plan {self.pid} (planned)"))
            self.assertIn("Summary: 1000 create, 0 update, 0 delete, 0 action, 0 noop", page["diff"])
            seen += steps_in(page["diff"])
            offset = page.get("next_offset")
        self.assertEqual(seen, list(range(1000)))
        self.assertNotIn("note", page)
        self.assertTrue(page["diff"].endswith(" of 1000 are shown"))

    def test_detail_pages_carry_the_steps(self):
        page = self.measured("librenms_plans", plan_id=self.pid, offset=990, detail=True)
        self.assertEqual([step["index"] for step in page["steps"]], list(range(990, 1000)))
        self.assertNotIn("truncated", page)
        past = self.measured("librenms_plans", plan_id=self.pid, offset=5000)
        self.assertEqual((past["steps_shown"], past["note"]), (0, "the plan has 1000 steps, numbered from 0; offset "
                                                                   "5000 is past the last"))  # fmt: skip

    def test_apply_and_rollback_results_stay_within_the_budget(self):
        # applying 1,000 steps journals the plan file 2,000 times; 150 steps against an 8,000-character budget make
        # the same pages
        self.settings = self.settings_mod.Settings(max_operations=1000, allow_delete=True, max_result_chars=8000)
        self.settings_mod.set_settings(self.settings)
        pid = self.plan([{"op": "update", "resource": "device", "id": 1, "data": {"type": "server"}}] + [
            {"op": "create", "resource": "location", "data": {"location": f"Site {i:03d}", "lat": 52 + i / 1000,
                                                               "lng": 4 + i / 1000}}
            for i in range(149)
        ])["id"]  # fmt: skip
        raw = self.handlers.librenms_apply({"plan_id": pid})
        self.assertLessEqual(len(raw), 8000)
        applied = json.loads(raw)
        self.assertEqual((applied["outcome"], applied["truncated"]), ("applied", True))
        end = applied["next_offset"]
        self.assertEqual([entry["index"] for entry in applied["journal"]], list(range(end)))
        self.assertIn(f"librenms_plans with this plan_id and offset {end} shows the next ones", applied["note"])
        self.assertEqual(applied["eventlog"]["devices"]["1"][0]["message"], "type: network -> server")  # step 0's
        page = json.loads(self.handlers.librenms_plans({"plan_id": pid, "offset": end, "detail": True}))
        self.assertEqual((page["journal"][0]["index"], page["apply"]["eventlog"]["devices"]), (end, {}))
        self.assertIn("inverse", page["journal"][0])
        raw = self.handlers.librenms_rollback({"plan_id": pid})
        self.assertLessEqual(len(raw), 8000)
        rolled = json.loads(raw)
        self.assertEqual((rolled["success"], rolled["rollback"]["reverted"], rolled["truncated"]), (True, 150, True))
        self.assertEqual((len(self.fake.tables["locations"]), self.fake.tables["devices"][1]["type"]), (3, "network"))
        self.assertLessEqual(len(self.handlers.librenms_plans({"plan_id": pid})), 8000)

    def test_an_operator_sees_the_whole_plan(self):
        text = submodule("commands").run(["show", self.pid])
        self.assertGreater(len(text), BUDGET)
        self.assertEqual(steps_in(text), list(range(1000)))
        self.assertNotIn("are shown", text)
        whole = json.loads(self.handlers.librenms_plans({"plan_id": self.pid}, _actor={"kind": "operator"}))
        self.assertNotIn("next_offset", whole)

    def test_a_single_step_too_large_for_the_budget_lists_its_eventlog_as_counts(self):
        # a step is never split: when one does not fit, its device's eventlog rows are counted instead of listed
        self.settings = self.settings_mod.Settings(max_result_chars=8000)
        self.settings_mod.set_settings(self.settings)
        pid = self.plan([{"op": "update", "resource": "device", "id": n, "data": {"type": "server"}} for n in (1, 2)])[
            "id"
        ]
        self.handlers.librenms_apply({"plan_id": pid})
        plan = self.store.load(pid)
        rows = [{"event_id": 1000 + i, "type": "system", "message": "m" * 300} for i in range(40)]
        plan["apply"]["eventlog"]["devices"]["1"] = rows
        plan["journal"][0]["eventlog_ids"] = [row["event_id"] for row in rows]
        self.store.save(plan)
        raw = self.handlers.librenms_plans({"plan_id": pid})
        self.assertLessEqual(len(raw), 8000)
        page = json.loads(raw)
        self.assertEqual((page["steps_shown"], page["next_offset"]), (1, 1))
        self.assertEqual(page["apply"]["eventlog"]["devices"], {"1": 40})
        rest = json.loads(self.handlers.librenms_plans({"plan_id": pid, "offset": 1}))
        self.assertEqual(list(rest["apply"]["eventlog"]["devices"]), ["2"])
        self.assertIsInstance(rest["apply"]["eventlog"]["devices"]["2"], list)


class IrreversiblePlan(HandlerCase):
    """1,000 deletes of locations without coordinates at the smallest budget: none can be rolled back, so the plan's
    irreversible steps are as many as its steps, and it has been checked again and again."""

    def setUp(self):
        super().setUp()
        self.settings_mod.set_settings(
            self.settings_mod.Settings(max_operations=1000, allow_delete=True, max_result_chars=8000)
        )
        operations = [
            {"op": "delete", "resource": "location",
             "match": {"location": self.fake.seed("locations", {"location": f"Old site {i:04d}"})["location"]}}
            for i in range(1000)
        ]  # fmt: skip
        self.planned = self.measured("librenms_plan", description="Remove the old sites", operations=operations)
        self.pid = self.planned["plan_id"]

    def measured(self, name, **args):
        raw = self.handlers.HANDLERS[name](args)
        self.assertLessEqual(len(raw), 8000, (name, {k: v for k, v in args.items() if k != "operations"}))
        return json.loads(raw)

    def test_every_page_lists_only_the_irreversible_steps_it_shows(self):
        out = self.planned
        end = out["next_offset"]
        self.assertEqual((out["irreversible"], out["irreversible_count"]), (list(range(end)), 1000))
        self.assertEqual(out["diff"].count("\n      rollback: none"), end)
        self.assertIn(
            "Tell them that 1000 steps cannot be rolled back; the diff marks each one 'rollback: none'.",
            out["next_step"],
        )
        seen, offset = list(out["irreversible"]), end
        while offset is not None:
            page = self.measured("librenms_plans", plan_id=self.pid, offset=offset)
            self.assertEqual(page["irreversible_count"], 1000)
            self.assertEqual(page["irreversible"], list(range(offset, page.get("next_offset") or 1000)))
            seen += page["irreversible"]
            offset = page.get("next_offset")
        self.assertEqual(seen, list(range(1000)))
        whole = json.loads(self.handlers.librenms_plans({"plan_id": self.pid}, _actor={"kind": "operator"}))
        self.assertEqual(whole["irreversible"], list(range(1000)))
        self.assertNotIn("irreversible_count", whole)

    def test_the_model_reads_the_latest_check_of_many(self):
        # a record per dry run, kept for the operator; each one repeated the conflicts of the steps shown
        self.measured("librenms_apply", plan_id=self.pid, dry_run=True)
        plan = self.store.load(self.pid)
        record = plan["checks"][0]
        plan["checks"] = [
            {**record, "at": f"2026-10-28T{i // 60:02d}:{i % 60:02d}:00Z",
             "conflicts": [{"index": n, "error": f"location {n} changed since the plan was made"} for n in range(5)]}
            for i in range(199)
        ] + [record]  # fmt: skip
        self.store.save(plan)
        for args in ({}, {"offset": 3}, {"detail": True}):
            page = self.measured("librenms_plans", plan_id=self.pid, **args)
            [check] = page["checks"]
            self.assertEqual((check["at"], check["conflicts"], page["check_count"]), (record["at"], [], 200))
        whole = json.loads(self.handlers.librenms_plans({"plan_id": self.pid}, _actor={"kind": "operator"}))
        self.assertEqual(len(whole["checks"]), 200)
        self.assertNotIn("check_count", whole)


class FitRows(unittest.TestCase):
    """``_fit_rows`` on its own, at every budget: a cut fits, and one more row would not."""

    def test_a_cut_keeps_every_row_that_fits_and_no_more(self):
        handlers = submodule("handlers")
        rows = [{"id": i, "name": "x" * (i * 37 % 90)} for i in range(30)]
        payload = {"success": True, "count": 30, "returned": 30, "truncated": False, "results": rows}
        offset = 95  # next_offset and the note's offset grow a digit at 100, returned and the count of kept at 10
        for budget in range(100, handlers._size(payload)):  # where the estimate overshoots too (cut back)
            note = handlers._query_note(budget, offset)
            out = handlers._fit_rows(payload, "results", budget, note, offset)
            kept = out["returned"]
            self.assertEqual(out["results"], rows[:kept])
            if kept:
                self.assertLessEqual(handlers._size(out), budget, budget)
                self.assertEqual(out["next_offset"], offset + kept)
            more = {**payload, "results": rows[: kept + 1], "returned": kept + 1, "truncated": True}
            more = handlers._read_on({**more, "note": note(kept + 1, len(rows))}, offset)
            self.assertGreater(handlers._size(more), budget, budget)  # the next row would not have fit
