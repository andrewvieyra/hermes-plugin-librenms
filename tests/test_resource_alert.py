"""The alert (fault) resource against the fake LibreNMS: ack and unmute, their sibling faults, verification and
rollback.

Seeded faults: #1 (active) and #2 (acknowledged by alice) are open on edge-rtr1 under rule #1 "Port down", which
does not notify per entity; #3 is the only open fault of access-sw2 under that rule; #4 (active) and #5 (cleared)
belong to core-sw1 under rule #2 "High CPU", which notifies per entity.
"""

from __future__ import annotations

import json

from .base import PluginTestCase
from .fake_librenms import SECRETS
from .helpers import submodule

alert = submodule("resources.alert")
base = submodule("resources.base")
LibreNMSError = submodule("client").LibreNMSError
StepError, PartialWrite = base.StepError, base.PartialWrite

PLAN_ID = "lnp-20261028T190000Z-ab12"
TAG = f"[hermes:{PLAN_ID}]"


class AfterWrite:
    """The test client, running *hook* once LibreNMS has answered the first write: an edit racing the step."""

    def __init__(self, client, hook):
        self._client = client
        self._hook = hook

    def __getattr__(self, name):
        return getattr(self._client, name)

    def request(self, method, path, **kwargs):
        answer = self._client.request(method, path, **kwargs)
        if method != "GET" and self._hook is not None:
            hook, self._hook = self._hook, None
            hook()
        return answer


def entry_for(step, result=None, status="done", **extra):
    """A journal entry as the executor writes it, after a trip through the plan file."""
    keys = ("index", "action", "resource", "object_id", "label", "parent_id", "inverse_kind")
    entry = {key: step.get(key) for key in keys}
    entry.update(status=status, at="2026-10-28T19:00:00Z", **(result or {}), **extra)
    return json.loads(json.dumps(entry))


class AlertCase(PluginTestCase):
    def setUp(self):
        super().setUp()
        self.res = alert.RESOURCE
        self.context = {"plan_id": PLAN_ID, "settings": self.settings, "actor": None}

    def fault(self, fault_id):
        return self.fake.tables["faults"][fault_id]

    def planned(self, kind, fault_id, **data):
        op = {"op": kind, "resource": "alert", "id": fault_id, "match": None, "data": data}
        return json.loads(json.dumps(self.res.plan_step(self.client, 0, op, self.settings)))

    def apply(self, step, client=None):
        return self.res.execute(client or self.client, step, self.context)

    def applied(self, kind, fault_id, **data):
        step = self.planned(kind, fault_id, **data)
        return step, entry_for(step, self.apply(step))

    def revert(self, entry, force=False, step=None, client=None):
        context = dict(self.context, step=step) if step is not None else self.context
        return self.res.revert(client or self.client, entry, force, context)

    def writes(self):
        return [(call["method"], call["path"], call["json"]) for call in self.fake.writes()]

    def open_fault(self, fault_id, rule_id, device_id, state=1):
        stamp = "2026-10-28 11:50:00"
        self.fake.seed(
            "faults",
            {"id": fault_id, "rule_id": rule_id, "device_id": device_id, "state": state, "timestamp": stamp,
             "first_seen": stamp, "last_seen": stamp},
        )  # fmt: skip


class Validation(AlertCase):
    def test_valid_data_needs_no_gate(self):
        closed = self.settings_mod.Settings()  # every allow_* off: acknowledging is not gated
        self.assertEqual(self.res.validate("ack", {"note": "investigating", "until_clear": "true"}, closed), [])
        self.assertEqual(self.res.validate("ack", {"note": "x" * alert.NOTE_LIMIT}, closed), [])
        self.assertEqual(self.res.validate("unmute", {"note": "carrier fixed it"}, closed), [])

    def test_unknown_fields_are_rejected(self):
        self.assertEqual(
            self.res.validate("ack", {"note": "x", "state": 2, "sticky": True}, self.settings),
            ["cannot ack alert field(s) state, sticky; allowed: note, until_clear"],
        )
        self.assertEqual(
            self.res.validate("unmute", {"note": "x", "until_clear": False}, self.settings),
            ["cannot unmute alert field(s) until_clear; allowed: note"],
        )

    def test_note_is_required_bounded_and_one_line(self):
        required = "note is required to ack an alert; LibreNMS appends it to the fault's history"
        cases = {
            None: required,
            "": required,
            "   ": required,
            5: "note: expected a string, got 5",
            "x" * 501: "note is 501 characters long; the limit is 500",
            "fixed\n2026-10-28 09:15:00 - Ack (alice) ok": (
                "note must be one line without control characters; it becomes a line of the fault's history"
            ),
            "\x1b[2Kok": "note must be one line without control characters; it becomes a line of the fault's history",
        }
        for note, message in cases.items():
            with self.subTest(note=note):
                data = {} if note is None else {"note": note}
                self.assertEqual(self.res.validate("ack", data, self.settings), [message])
        self.assertEqual(
            self.res.validate("unmute", {}, self.settings),
            ["note is required to unmute an alert; LibreNMS appends it to the fault's history"],
        )

    def test_until_clear_must_be_a_boolean(self):
        for value, message in (
            ("maybe", 'until_clear: expected true or false, got "maybe"'),
            (2, "until_clear: expected true or false, got 2"),
            (None, "until_clear: null is not allowed"),
            ([True], "until_clear: expected true or false, got list"),
        ):
            with self.subTest(value=value):
                self.assertEqual(
                    self.res.validate("ack", {"note": "x", "until_clear": value}, self.settings), [message]
                )

    def test_resolve_normalises_into_a_new_dict(self):
        data = {"note": "investigating", "until_clear": "yes"}
        resolved = self.res.resolve(self.client, "ack", data)
        self.assertEqual(resolved, {"note": "investigating", "until_clear": True})
        self.assertIsNot(resolved, data)
        self.assertEqual(self.res.resolve(self.client, "ack", {"note": "x"}), {"note": "x", "until_clear": False})
        self.assertEqual(self.res.resolve(self.client, "unmute", {"note": "x"}), {"note": "x"})
        with self.assertRaisesRegex(StepError, '^until_clear: expected true or false, got "maybe"$'):
            self.res.resolve(self.client, "ack", {"note": "x", "until_clear": "maybe"})


class Reads(AlertCase):
    def test_get_asks_for_every_state(self):
        self.assertEqual(self.res.get(self.client, 2)["state"], 2)  # a plain GET faults/2 would answer nothing
        self.assertEqual(self.res.get(self.client, 5)["open"], 0)
        call = self.fake.calls[-1]
        self.assertEqual((call["method"], call["path"], call["params"]), ("GET", "faults/5", {"state": "0,1,2,3,4,5"}))
        self.assertIsNone(self.res.get(self.client, 99))

    def test_get_drops_rule_rows_and_masks(self):
        self.fake.touch("faults", 1, details={"rule": [{"hostname": "edge-rtr1", "community": SECRETS[0]}]})
        obj = self.res.get(self.client, 1)
        self.assertNotIn("details", obj)
        self.assertNotIn(SECRETS[0], json.dumps(obj))
        self.assertEqual((obj["hostname"], obj["name"]), ("edge-rtr1.example.net", "Port down"))

    def test_get_refuses_ids_that_would_list_every_fault(self):
        before = len(self.fake.calls)
        for bad in (0, -1, "0", "1x", "²", True, None):
            with self.subTest(bad=bad):
                self.assertIsNone(self.res.get(self.client, bad))
        self.assertEqual(len(self.fake.calls), before)

    def test_get_keeps_only_the_requested_fault(self):
        other = {"status": "ok", "alerts": [{"id": 3, "rule_id": 1, "device_id": 3, "state": 1, "open": 1}], "count": 1}
        self.fake.fail_on("GET", "faults/1", 200, other)
        self.assertIsNone(self.res.get(self.client, 1))

    def test_state_is_normalised(self):
        self.fake.touch("faults", 1, state=3, info={"until_clear": True})
        expected = {"id": 1, "rule_id": 1, "device_id": 2, "hostname": "edge-rtr1.example.net", "state": 3,
                    "open": True, "until_clear": True}  # fmt: skip
        self.assertEqual(self.res.state(self.client, self.res.get(self.client, 1)), expected)
        raw = {"id": "1", "rule_id": "1", "device_id": "2", "hostname": "edge-rtr1.example.net", "state": "3",
               "open": "1", "info": '{"until_clear":"1"}'}  # fmt: skip
        self.assertEqual(self.res.state(self.client, raw), expected)  # numeric strings, as some PDO drivers answer
        for info, until_clear in ((None, False), ([], False), ({"until_clear": "false"}, False), ({}, False)):
            with self.subTest(info=info):
                self.fake.touch("faults", 1, info=info)
                self.assertIs(self.res.state(self.client, self.res.get(self.client, 1))["until_clear"], until_clear)
        self.assertIs(self.res.state(self.client, {"info": "not json", "open": 0})["until_clear"], False)
        # until_clear is stored verbatim from whoever acknowledged; a value no boolean spelling covers counts as PHP
        # would read it
        self.assertIs(self.res.state(self.client, {"info": '{"until_clear":"always"}'})["until_clear"], True)

    def test_label_names_rule_and_host(self):
        self.assertEqual(self.res.label(self.res.get(self.client, 1)), "Port down on edge-rtr1.example.net")
        self.assertEqual(self.res.label({"id": 7}), "#7")

    def test_alerts_are_addressed_by_id_only(self):
        with self.assertRaisesRegex(StepError, "cannot be looked up by match"):
            self.res.find(self.client, {"hostname": "edge-rtr1.example.net"})


class Planning(AlertCase):
    def test_ack_on_a_rule_without_per_entity_records_the_siblings(self):
        step = self.planned("ack", 1, note="investigating")
        self.assertEqual(
            {key: step[key] for key in ("action", "resource", "object_id", "label", "requested_op", "resolved_by")},
            {"action": "ack", "resource": "alert", "object_id": 1, "label": "Port down on edge-rtr1.example.net",
             "requested_op": "ack", "resolved_by": "id"},
        )  # fmt: skip
        self.assertEqual(step["parent_id"], 2)
        self.assertEqual(step["params"], {"note": "investigating", "until_clear": False})
        self.assertEqual(
            step["precondition"],
            {"state": {"id": 1, "rule_id": 1, "device_id": 2, "hostname": "edge-rtr1.example.net", "state": 1,
                       "open": True, "until_clear": False},
             "note_length": 0, "per_entity": False, "siblings": {"1": 1, "2": 2}},
        )  # fmt: skip
        self.assertEqual((step["inverse_kind"], step["inverse_note"]), ("lossy", self.res.inverse["ack"][1]))
        self.assertEqual(
            step["notes"],
            ["rule #1 does not notify per entity: LibreNMS acknowledges every open fault of this device and rule, "
             "here also #2"],
        )  # fmt: skip
        self.assertEqual(
            self.res.describe(step),
            ['note "investigating", until_clear false', "state: 1 (active) -> 2 (acknowledged)",
             "may also change: #2 (state 2)"],
        )  # fmt: skip
        reads = [(c["path"], c["params"]) for c in self.fake.calls]
        self.assertIn(("faults", {"alert_rule": "1", "state": "0,1,2,3,4,5"}), reads)
        self.assertIn(("rules/1", {}), reads)
        self.assertEqual(self.fake.writes(), [])

    def test_ack_on_a_per_entity_rule_reaches_one_fault(self):
        step = self.planned("ack", 4, note="known load test", until_clear=True)
        self.assertEqual(step["parent_id"], 1)
        self.assertEqual((step["precondition"]["per_entity"], step["precondition"]["siblings"]), (True, {"4": 1}))
        self.assertEqual(step["notes"], [])
        self.assertEqual(
            self.res.describe(step),
            ['note "known load test", until_clear true', "state: 1 (active) -> 2 (acknowledged)"],
        )

    def test_per_entity_ends_beyond_max_entities(self):
        self.open_fault(6, rule_id=2, device_id=1, state=2)
        self.fake.touch("rules", 2, max_entities=1)
        step = self.planned("ack", 4, note="x")
        self.assertEqual(
            (step["precondition"]["per_entity"], step["precondition"]["siblings"]), (False, {"4": 1, "6": 2})
        )
        self.assertEqual(self.res.describe(step)[-1], "may also change: #6 (state 2)")

    def test_without_max_entities_per_entity_is_certain_only_for_one_fault(self):
        # LibreNMS's own default limit (alert_rule.default_max_entities) applies, and the API cannot read it
        self.open_fault(6, rule_id=2, device_id=1)
        step = self.planned("ack", 4, note="x")
        self.assertEqual(
            (step["precondition"]["per_entity"], step["precondition"]["siblings"]), (False, {"4": 1, "6": 1})
        )
        self.assertEqual(
            step["notes"],
            ["rule #2 sets no max_entities, so whether it notifies per entity with 2 open faults depends on LibreNMS's "
             "default limit (alert_rule.default_max_entities, 20 unless changed), which the API cannot read; this plan "
             "assumes LibreNMS acknowledges every open fault of this device and rule, here also #6"],
        )  # fmt: skip
        self.assertEqual(self.res.describe(step)[-1], "may also change: #6 (state 1)")
        self.fake.touch("rules", 2, max_entities=2)
        step = self.planned("ack", 4, note="x")
        self.assertEqual((step["precondition"]["per_entity"], step["notes"]), (True, []))

    def test_twenty_one_open_faults_exceed_the_default_limit(self):
        for fault_id in range(100, 120):  # with #4: 21 open faults on core-sw1, one acknowledged by an operator
            self.open_fault(fault_id, rule_id=2, device_id=1, state=2 if fault_id == 100 else 1)
        step = self.planned("ack", 4, note="x")
        self.assertIs(step["precondition"]["per_entity"], False)
        self.assertIn("with 21 open faults depends on LibreNMS's default limit", step["notes"][0])
        self.assertTrue(self.res.describe(step)[-1].startswith("may also change: #100 (state 2), #101 (state 1), "))
        entry = entry_for(step, self.apply(step))
        self.assertEqual({self.fault(i)["state"] for i in (4, *range(100, 120))}, {2})  # LibreNMS acknowledged all 21
        self.assertEqual(entry["inverse"]["also_changes"], [100])
        self.assertEqual(self.revert(entry)[0], "conflict")
        self.assertEqual(self.fault(100)["state"], 2)
        with self.assertRaises(StepError) as caught:
            self.planned("unmute", 4, note="x")
        self.assertTrue(
            str(caught.exception).startswith(
                "unmute cannot be limited to one fault; it would also unmute faults #100, #101, "
            )
        )
        self.assertTrue(str(caught.exception).endswith("which the API cannot read)"))

    def test_clear_faults_do_not_count_against_max_entities(self):
        self.open_fault(7, rule_id=2, device_id=1, state=0)  # recovered, not yet closed
        self.fake.touch("rules", 2, max_entities=1)
        step = self.planned("ack", 4, note="x")
        self.assertEqual(
            (step["precondition"]["per_entity"], step["precondition"]["siblings"]), (True, {"4": 1, "7": 0})
        )
        self.apply(step)
        self.assertEqual((self.fault(4)["state"], self.fault(7)["state"]), (2, 0))

    def test_ack_of_a_worse_fault(self):
        self.fake.touch("faults", 3, state=3)
        step = self.planned("ack", 3, note="x")
        self.assertEqual(step["action"], "ack")
        self.assertEqual(step["notes"], [])
        self.assertEqual(self.res.describe(step)[1], "state: 3 (worse) -> 2 (acknowledged)")

    def test_noops(self):
        step = self.planned("ack", 2, note="x")
        self.assertEqual((step["action"], step["reason"]), ("noop", "already acknowledged"))
        self.assertNotIn("precondition", step)
        self.assertNotIn("inverse_kind", step)
        self.assertEqual(self.res.describe(step), ["already acknowledged"])
        self.assertEqual(
            self.planned("ack", 2, note="x", until_clear=True)["reason"],
            "already acknowledged (until_clear is false; unmute it and acknowledge it again to change that)",
        )
        step = self.planned("unmute", 1, note="x")
        self.assertEqual((step["action"], step["reason"]), ("noop", "already active (not acknowledged)"))
        self.assertIsNone(self.res.check(self.client, step))

    def test_refusals(self):
        self.fake.touch("faults", 3, state=0)
        cases = (
            ("ack", 5, "alert #5 is closed (the fault cleared); there is nothing to ack"),
            ("unmute", 5, "alert #5 is closed (the fault cleared); there is nothing to unmute"),
            ("ack", 3, "alert #3 is in state 0 (clear); it cannot be acknowledged"),
            ("ack", 99, "alert #99 does not exist"),
        )
        for kind, fault_id, message in cases:
            with self.subTest(kind=kind, fault_id=fault_id), self.assertRaises(StepError) as caught:
                self.planned(kind, fault_id, note="x")
            self.assertEqual(str(caught.exception), message)
        self.fake.touch("faults", 3, state=4)
        with self.assertRaises(StepError) as caught:
            self.planned("unmute", 3, note="x")
        self.assertEqual(
            str(caught.exception),
            "alert #3 is in state 4 (better), not acknowledged; unmute would only reset it to active",
        )

    def test_unmute_step(self):
        step = self.planned("unmute", 2, note="carrier fixed it")
        self.assertEqual(step["action"], "unmute")
        self.assertEqual(step["params"], {"note": "carrier fixed it"})
        self.assertEqual(step["precondition"]["note_length"], len(self.fault(2)["note"]))
        self.assertEqual((step["inverse_kind"], step["inverse_note"]), ("lossy", self.res.inverse["unmute"][1]))
        self.assertEqual(
            step["notes"],
            ["rule #1 does not notify per entity: LibreNMS unmutes every open fault of this device and rule, here "
             "also #1"],
        )  # fmt: skip
        self.assertEqual(
            self.res.describe(step),
            ['note "carrier fixed it"', "state: 2 (acknowledged) -> 1 (active)", "may also change: #1 (state 1)"],
        )

    def test_unmute_is_refused_when_it_would_unmute_a_fault_someone_acknowledged(self):
        self.fake.touch("faults", 1, state=2)
        with self.assertRaises(StepError) as caught:
            self.planned("unmute", 2, note="x")
        self.assertEqual(
            str(caught.exception),
            "unmute cannot be limited to one fault; it would also unmute faults #1 that were acknowledged before this "
            "plan",
        )
        self.open_fault(6, rule_id=2, device_id=1, state=2)  # per entity: the other acknowledged fault is not reached
        self.fake.touch("faults", 4, state=2)
        self.fake.touch("rules", 2, max_entities=5)
        self.assertEqual(self.planned("unmute", 4, note="x")["action"], "unmute")


class Check(AlertCase):
    def test_unchanged_fault_passes(self):
        self.assertIsNone(self.res.check(self.client, self.planned("ack", 1, note="x")))
        self.assertIsNone(self.res.check(self.client, self.planned("unmute", 2, note="x")))

    def test_target_moved(self):
        step = self.planned("ack", 3, note="x")
        self.fake.touch("faults", 3, state=2)
        self.assertEqual(
            self.res.check(self.client, step),
            "alert #3 is in state 2 (acknowledged) now; ack needs it active, worse, better or changed",
        )
        step = self.planned("unmute", 2, note="x")
        self.fake.touch("faults", 2, state=3)
        self.assertEqual(
            self.res.check(self.client, step), "alert #2 is in state 3 (worse) now; unmute needs it acknowledged"
        )

    def test_target_closed_or_gone(self):
        step = self.planned("ack", 3, note="x")
        self.fake.touch("faults", 3, open=0, state=0)
        self.assertEqual(self.res.check(self.client, step), "alert #3 is closed now (the fault cleared)")
        del self.fake.tables["faults"][3]
        self.assertEqual(self.res.check(self.client, step), "alert #3 no longer exists")

    def test_other_state_drift(self):
        step = self.planned("unmute", 2, note="x")
        self.fake.touch("faults", 2, info={"until_clear": True})
        self.assertEqual(
            self.res.check(self.client, step), "alert #2 changed since planning (until_clear: false -> true)"
        )

    def test_siblings_moved(self):
        step = self.planned("ack", 1, note="x")
        self.fake.touch("faults", 2, state=1)
        self.assertEqual(
            self.res.check(self.client, step),
            "the open faults of rule #1 on edge-rtr1.example.net changed since planning (#2: state 2 -> 1)",
        )
        self.fake.touch("faults", 2, state=0, open=0)
        self.open_fault(6, rule_id=1, device_id=2)
        self.open_fault(7, rule_id=1, device_id=3)  # another device: never reached
        self.assertEqual(
            self.res.check(self.client, step),
            "the open faults of rule #1 on edge-rtr1.example.net changed since planning (#2: no longer open, #6: "
            "newly open (state 1))",
        )

    def test_target_moving_within_the_precondition_is_fine_per_entity(self):
        self.fake.touch("rules", 2, max_entities=5)
        step = self.planned("ack", 4, note="x")
        self.fake.touch("faults", 4, state=3)
        self.open_fault(6, rule_id=2, device_id=1, state=2)
        self.assertIsNone(self.res.check(self.client, step))

    def test_per_entity_flip(self):
        step = self.planned("ack", 4, note="x")
        self.fake.touch("rules", 2, max_entities=1)
        self.open_fault(6, rule_id=2, device_id=1)
        self.assertEqual(
            self.res.check(self.client, step),
            "rule #2 no longer notifies per entity for this device, so the ack would reach other faults than planned",
        )
        self.fake.touch("rules", 1, notify_per_entity=True)
        step = self.planned("ack", 3, note="x")
        self.fake.touch("rules", 1, notify_per_entity=False)
        self.assertIn("rule #1 no longer notifies per entity", self.res.check(self.client, step))
        step = self.planned("ack", 3, note="x")
        self.fake.touch("rules", 1, notify_per_entity=True)
        self.assertEqual(
            self.res.check(self.client, step),
            "rule #1 now notifies per entity for this device, so the ack would reach other faults than planned",
        )


class Execute(AlertCase):
    def test_ack(self):
        step = self.planned("ack", 1, note="investigating")
        result = self.apply(step)
        self.assertEqual(self.writes(), [("PUT", "faults/1", {"note": f"{TAG} investigating", "until_clear": False})])
        self.assertEqual(
            result,
            {"object_id": 1, "inverse": {"action": "unmute", "object_id": 1, "also_changes": [2], "per_entity": False,
                                         "siblings": {"2": 2}},
             "after_state": {**step["precondition"]["state"], "state": 2}, "notes": []},
        )  # fmt: skip
        self.assertIn(f"Ack (hermes) {TAG} investigating", self.fault(1)["note"])
        self.assertIn(f"Ack (hermes) {TAG} investigating", self.fault(2)["note"])  # the sibling got the note too
        self.assertIs(self.fault(1)["info"]["until_clear"], False)

    def test_ack_until_clear_is_sent_as_a_boolean(self):
        result = self.apply(self.planned("ack", 3, note="x", until_clear="1"))
        self.assertIs(self.fake.writes()[0]["json"]["until_clear"], True)
        self.assertEqual(result["after_state"]["until_clear"], True)
        self.assertEqual(
            result["inverse"],
            {"action": "unmute", "object_id": 3, "also_changes": [], "per_entity": False, "siblings": {}},
        )

    def test_unmute_keeps_until_clear(self):
        self.fake.touch("faults", 2, info={"until_clear": True})
        result = self.apply(self.planned("unmute", 2, note="carrier fixed it"))
        self.assertEqual(self.writes(), [("PUT", "faults/unmute/2", {"note": f"{TAG} carrier fixed it"})])
        self.assertEqual((result["after_state"]["state"], result["after_state"]["until_clear"]), (1, True))
        self.assertEqual(
            result["inverse"],
            {"action": "ack", "object_id": 2, "until_clear": True, "also_changes": [1], "per_entity": False,
             "siblings": {"1": 1}},
        )  # fmt: skip
        self.assertEqual(result["notes"], [])
        self.assertTrue(self.fault(2)["note"].startswith("2026-10-28 09:15:00 - Ack (alice) carrier ticket 4411\n"))

    def test_no_alert_by_that_id_is_a_failure(self):
        for kind, fault_id, route, message in (
            ("ack", 3, "faults/3", "No Alert by that ID"),
            ("unmute", 2, "faults/unmute/2", "No alert by that ID"),
        ):
            with self.subTest(kind=kind):
                step = self.planned(kind, fault_id, note="x")
                self.fake.fail_on("PUT", route, 200, {"status": "ok", "message": message}, times=1)
                with self.assertRaises(StepError) as caught:
                    self.apply(step)
                self.assertEqual(
                    str(caught.exception),
                    f"LibreNMS answered {message!r} to the {kind} of alert #{fault_id}: no fault was changed",
                )

    def test_accepted_but_unchanged_is_a_plain_failure(self):
        step = self.planned("ack", 3, note="x")
        self.fake.fail_on("PUT", "faults/3", 200, {"status": "ok", "message": "Alert has been acknowledged"})
        with self.assertRaises(StepError) as caught:
            self.apply(step)
        self.assertEqual(
            str(caught.exception),
            "LibreNMS accepted the ack but alert #3 is in state 1 (active), expected 2 (acknowledged)",
        )

    def test_accepted_but_moved_elsewhere_is_a_partial_write(self):
        step = self.planned("ack", 3, note="x")
        racing = AfterWrite(self.client, lambda: self.fake.touch("faults", 3, state=3))
        with self.assertRaises(PartialWrite) as caught:
            self.apply(step, racing)
        self.assertIn("is in state 3 (worse), expected 2 (acknowledged)", str(caught.exception))
        self.assertIn("rollback reverts it", str(caught.exception))
        entry = caught.exception.entry
        self.assertEqual(
            entry["inverse"],
            {"action": "unmute", "object_id": 3, "also_changes": [], "per_entity": False, "siblings": {}},
        )
        self.assertEqual(entry["after_state"]["state"], 3)

    def test_server_error_after_the_write_is_a_partial_write(self):
        step = self.planned("ack", 3, note="x")
        self.fake.fail_on("PUT", "faults/3", 500, commit=True)
        with self.assertRaises(PartialWrite) as caught:
            self.apply(step)
        entry = caught.exception.entry
        self.assertEqual((entry["object_id"], entry["after_state"]["state"]), (3, 2))
        self.assertEqual(
            self.revert(entry_for(step, entry, error=str(caught.exception), wrote=True)), ("reverted", {"state": 1})
        )
        self.assertEqual(self.fault(3)["state"], 1)

    def test_server_error_without_a_change_is_the_original_error(self):
        step = self.planned("ack", 3, note="x")
        self.fake.fail_on("PUT", "faults/3", 500)
        with self.assertRaises(LibreNMSError) as caught:
            self.apply(step)
        self.assertEqual(caught.exception.kind, "server")
        self.assertEqual(self.fault(3)["state"], 1)

    def test_refused_write_is_not_reread(self):
        step = self.planned("ack", 3, note="x")
        body = {"status": "error", "message": "Insufficient permissions to update this alert"}
        self.fake.fail_on("PUT", "faults/3", 403, body)
        with self.assertRaises(LibreNMSError) as caught:
            self.apply(step)
        self.assertEqual(caught.exception.kind, "forbidden")
        self.assertEqual((self.fake.calls[-1]["method"], self.fake.calls[-1]["path"]), ("PUT", "faults/3"))

    def test_transport_failure_after_the_write_is_a_partial_write(self):
        step = self.planned("unmute", 2, note="x")
        self.fake.fail_on("PUT", "faults/unmute/2", exc=ConnectionError("connection reset by peer"), commit=True)
        with self.assertRaises(PartialWrite) as caught, self.assertLogs("hermes_plugins.librenms.client", "WARNING"):
            self.apply(step)
        entry = caught.exception.entry
        self.assertEqual(
            entry["inverse"],
            {"action": "ack", "object_id": 2, "until_clear": False, "also_changes": [1], "per_entity": False,
             "siblings": {"1": 1}},
        )  # fmt: skip
        self.assertEqual(entry["after_state"]["state"], 1)

    def test_failed_reread_is_an_unknown_outcome(self):
        step = self.planned("ack", 3, note="x")
        self.fake.fail_on("GET", "faults/3", 500)
        with self.assertRaises(PartialWrite) as caught:
            self.apply(step)
        entry = caught.exception.entry
        self.assertIsNone(entry["after_state"])
        self.assertEqual(
            entry["inverse"],
            {"action": "unmute", "object_id": 3, "also_changes": [], "per_entity": False, "siblings": {}},
        )
        self.assertTrue(entry["notes"][0].startswith("outcome unknown: re-reading the alert after the failed write"))

    def test_fault_cleared_during_the_apply(self):
        step = self.planned("ack", 3, note="x")
        result = self.apply(step, AfterWrite(self.client, lambda: self.fake.touch("faults", 3, open=0, state=0)))
        self.assertEqual(result["notes"], ["the fault cleared during the apply; nothing is left to do"])
        self.assertIs(result["after_state"]["open"], False)

    def test_missing_note_line_is_journaled(self):
        step = self.planned("ack", 3, note="x")
        result = self.apply(step, AfterWrite(self.client, lambda: self.fake.touch("faults", 3, note="")))
        self.assertEqual(result["notes"], ["LibreNMS did not add the note to the fault's history"])


class Revert(AlertCase):
    def test_revert_ack(self):
        step, entry = self.applied("ack", 3, note="investigating")
        self.assertEqual(self.revert(entry), ("reverted", {"state": 1}))
        self.assertEqual(self.writes()[-1], ("PUT", "faults/unmute/3", {"note": f"{TAG} rollback"}))
        self.assertEqual(self.fault(3)["state"], 1)
        history = self.fault(3)["note"]  # lossy: both lines stay
        self.assertIn(f"{TAG} investigating", history)
        self.assertIn(f"{TAG} rollback", history)

    def test_revert_ack_per_entity(self):
        step, entry = self.applied("ack", 4, note="x")
        self.assertEqual(self.revert(entry), ("reverted", {"state": 1}))

    def test_revert_ack_would_unmute_a_fault_someone_acknowledged(self):
        step, entry = self.applied("ack", 1, note="x")
        writes = len(self.fake.writes())
        self.assertEqual(
            self.revert(entry),
            ("conflict", {"error": "unmute cannot be limited to one fault; it would also unmute faults #2 that were "
                                   "acknowledged before this plan; use force to unmute them all"}),
        )  # fmt: skip
        self.assertEqual(len(self.fake.writes()), writes)
        self.assertEqual(self.revert(entry, force=True), ("reverted", {"state": 1}))
        self.assertEqual((self.fault(1)["state"], self.fault(2)["state"]), (1, 1))

    def test_revert_ack_after_the_state_moved(self):
        step, entry = self.applied("ack", 3, note="x")
        self.fake.touch("faults", 3, state=1)
        self.assertEqual(
            self.revert(entry),
            ("conflict", {"error": "alert #3 is in state 1 (active), not 2 (acknowledged) as the apply left it; use "
                                   "force to unmute it anyway"}),
        )  # fmt: skip
        writes = len(self.fake.writes())
        self.assertEqual(self.revert(entry, force=True), ("reverted", {"note": "alert #3 is already active"}))
        self.assertEqual(len(self.fake.writes()), writes)
        self.fake.touch("faults", 3, state=5)
        self.assertEqual(self.revert(entry)[0], "conflict")
        self.assertEqual(self.revert(entry, force=True), ("reverted", {"state": 1}))

    def test_cleared_or_deleted_fault_is_left_alone(self):
        step, entry = self.applied("ack", 4, note="x")
        self.fake.touch("faults", 4, open=0, state=0)
        writes = len(self.fake.writes())
        # an unmute of a closed per-entity fault would set state 1 on it
        self.assertEqual(self.revert(entry, force=True), ("reverted", {"note": "fault cleared; nothing to undo"}))
        self.assertEqual(self.fault(4)["state"], 0)
        del self.fake.tables["faults"][4]
        self.assertEqual(self.revert(entry), ("reverted", {"note": "the fault no longer exists; nothing to undo"}))
        self.assertEqual(len(self.fake.writes()), writes)

    def test_revert_unmute_acknowledges_with_the_previous_until_clear(self):
        self.fake.touch("faults", 1, open=0, state=0)
        self.fake.touch("faults", 2, info={"until_clear": True})
        step, entry = self.applied("unmute", 2, note="x")
        self.assertEqual(self.revert(entry), ("reverted", {"state": 2}))
        self.assertEqual(self.writes()[-1], ("PUT", "faults/2", {"note": f"{TAG} rollback", "until_clear": True}))
        self.assertEqual(self.fault(2)["state"], 2)

    def test_revert_unmute_would_acknowledge_other_open_faults(self):
        step, entry = self.applied("unmute", 2, note="x")
        self.assertEqual(
            self.revert(entry),
            ("conflict", {"error": "ack cannot be limited to one fault; it would also acknowledge faults #1 that were "
                                   "not acknowledged before this plan; use force to ack them all"}),
        )  # fmt: skip
        self.assertEqual(self.revert(entry, force=True), ("reverted", {"state": 2}))
        self.assertEqual((self.fault(1)["state"], self.fault(2)["state"]), (2, 2))

    def test_revert_does_not_reach_a_fault_opened_since_the_apply(self):
        self.fake.touch("faults", 3, state=2)
        step, entry = self.applied("unmute", 3, note="x")
        self.open_fault(31, rule_id=1, device_id=3)  # another port went down on access-sw2
        writes = len(self.fake.writes())
        self.assertEqual(
            self.revert(entry),
            ("conflict", {"error": "the open faults of rule #1 on access-sw2.example.net changed since the apply (#31: "
                                   "newly open (state 1)); use force to ack them all"}),
        )  # fmt: skip
        self.assertEqual((len(self.fake.writes()), self.fault(31)["state"]), (writes, 1))
        self.assertEqual(self.revert(entry, force=True), ("reverted", {"state": 2}))
        self.assertEqual(self.fault(31)["state"], 2)

    def test_revert_does_not_unmute_an_acknowledgement_made_since_the_apply(self):
        step, entry = self.applied("ack", 3, note="x")
        self.open_fault(30, rule_id=1, device_id=3, state=2)  # opened and acknowledged by an operator
        self.assertEqual(
            self.revert(entry),
            ("conflict", {"error": "the open faults of rule #1 on access-sw2.example.net changed since the apply (#30: "
                                   "newly open (state 2)); use force to unmute them all"}),
        )  # fmt: skip
        self.assertEqual((self.fault(3)["state"], self.fault(30)["state"]), (2, 2))

    def test_revert_refuses_when_a_fault_the_apply_reached_moved(self):
        self.fake.touch("faults", 2, state=1)
        step, entry = self.applied("ack", 1, note="x")
        self.assertEqual(entry["inverse"]["siblings"], {"2": 2})
        self.fake.touch("faults", 2, state=1)  # unmuted by an operator after the apply
        self.assertEqual(
            self.revert(entry),
            ("conflict", {"error": "the open faults of rule #1 on edge-rtr1.example.net changed since the apply (#2: "
                                   "state 2 -> 1); use force to unmute them all"}),
        )  # fmt: skip
        self.fake.touch("faults", 2, state=0, open=0)  # cleared: the rollback no longer reaches it
        self.assertEqual(self.revert(entry), ("reverted", {"state": 1}))

    def test_revert_refuses_when_the_rule_no_longer_notifies_per_entity(self):
        step, entry = self.applied("ack", 4, note="x")
        self.open_fault(6, rule_id=2, device_id=1)
        self.assertEqual(
            self.revert(entry),
            ("conflict", {"error": "rule #2 no longer notifies per entity for this device, so the unmute would reach "
                                   "other faults than the apply did; use force to unmute anyway"}),
        )  # fmt: skip
        self.assertEqual(self.fault(6)["state"], 1)

    def test_revert_compares_what_the_apply_left_not_what_it_assumed(self):
        self.open_fault(6, rule_id=2, device_id=1)
        step, entry = self.applied("ack", 4, note="x")  # planned as reaching #6; LibreNMS's default kept it per entity
        self.assertEqual((self.fault(4)["state"], self.fault(6)["state"]), (2, 1))
        self.assertEqual(entry["inverse"]["siblings"], {"6": 1})
        self.assertEqual(self.revert(entry), ("reverted", {"state": 1}))
        self.assertEqual(self.fault(6)["state"], 1)

    def test_rollback_write_that_changed_nothing_fails(self):
        step, entry = self.applied("ack", 3, note="x")
        self.fake.fail_on("PUT", "faults/unmute/3", 200, {"status": "ok", "message": "No alert by that ID"}, times=1)
        self.assertEqual(
            self.revert(entry),
            ("failed", {"error": "LibreNMS answered 'No alert by that ID' to the unmute of alert #3: no fault was "
                                 "changed"}),
        )  # fmt: skip
        self.fake.fail_on("PUT", "faults/unmute/3", 200, {"status": "ok", "message": "Alert has been unmuted"}, times=1)
        self.assertEqual(
            self.revert(entry),
            ("failed", {"error": "LibreNMS accepted the unmute but alert #3 is in state 2 (acknowledged), expected 1 "
                                 "(active)"}),
        )  # fmt: skip
        self.assertEqual(self.fault(3)["state"], 2)

    def test_fault_cleared_by_the_rollback_write(self):
        step, entry = self.applied("ack", 3, note="x")
        racing = AfterWrite(self.client, lambda: self.fake.touch("faults", 3, open=0, state=0))
        self.assertEqual(self.revert(entry, client=racing), ("reverted", {"note": "fault cleared"}))

    def test_inverse_comes_from_the_plan_step_when_the_entry_lacks_it(self):
        step, entry = self.applied("ack", 3, note="x")
        del entry["inverse"]
        self.assertEqual(
            self.revert(entry),
            ("failed", {"error": "no rollback information was recorded for this step; check alert Port down on "
                                 "access-sw2.example.net in LibreNMS"}),
        )  # fmt: skip
        self.assertEqual(self.revert(entry, step=step), ("reverted", {"state": 1}))

    def test_unknown_outcome_is_not_guessed(self):
        step = self.planned("ack", 3, note="x")
        status, details = self.revert(entry_for(step, status="unknown", wrote=True), step=step)
        self.assertEqual(status, "failed")
        self.assertIn("outcome of this step is unknown", details["error"])

    def test_both_inverses_are_lossy(self):
        self.assertEqual(
            {op: kind for op, (kind, _note) in self.res.inverse.items()}, {"ack": "lossy", "unmute": "lossy"}
        )
        self.assertIn("note stays in the fault's history", self.res.inverse["ack"][1])
