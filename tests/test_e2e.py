"""End to end through the five tool handlers (and the operator's slash command where the model is refused) against
the fake LibreNMS with the real resources: query, plan, apply, automatic and manual rollback, write modes, and the
irreversible and lossy steps a reviewer must be told about. Every scenario ends by proving that the token and the
seeded secrets (SNMP credentials, a password in a service's parameters) reached no tool result, plan file or audit
line."""

import json
import os
import unittest

from .base import PluginTestCase, _restore_env
from .fake_librenms import SECRETS, TOKEN
from .helpers import submodule

LOCATION = {"location": "PDX-4", "lat": 45.5152, "lng": -122.6784}
MOVE = [
    {
        "op": "update",
        "resource": "device",
        "match": {"hostname": "core-sw1.example.net"},
        "data": {"purpose": "spine", "notes": "moved to the spine layer"},
    },
    {"op": "create", "resource": "location", "match": {"location": "PDX-4"}, "data": LOCATION},
]
SPINE = {"op": "update", "resource": "device", "id": 1, "data": {"purpose": "spine"}}
GROUP_DESC = {"op": "update", "resource": "device_group", "id": 1, "data": {"desc": "Spine and core switches"}}


class EndToEnd(PluginTestCase):
    def setUp(self):
        super().setUp()
        self.commands = submodule("commands")
        self.outputs = []

    def call(self, name, _kwargs=None, **args):
        raw = self.handlers.HANDLERS[name](args, **(_kwargs or {}))
        self.assertIsInstance(raw, str)
        self.outputs.append(raw)
        return json.loads(raw)

    def plan_ops(self, operations, description="e2e"):
        out = self.call("librenms_plan", description=description, operations=operations)
        self.assertTrue(out["success"], out)
        return out

    def names(self):
        return [event["event"] for event in self.events()]

    def assert_nothing_leaked(self):
        """The token and every seeded secret are absent from every tool result, plan file and audit line."""
        files = sorted(self.store.directory.glob("lnp-*.json"))
        texts = [("tool result", raw) for raw in self.outputs]
        texts += [(path.name, path.read_text(encoding="utf-8")) for path in files]
        texts += [("audit line", line) for line in self.audit_path.read_text(encoding="utf-8").splitlines()]
        self.assertTrue(files and self.outputs, "the scenario produced nothing to check")
        for where, text in texts:
            for secret in (TOKEN, *SECRETS):
                self.assertNotIn(secret, text, f"{secret!r} leaked into a {where}")

    def test_query_devices_and_their_ports_with_secrets_masked(self):
        devices = self.call("librenms_query", path="devices")
        self.assertEqual((devices["route"], devices["count"]), ("list_devices", 4))
        by_name = {row["hostname"]: row for row in devices["results"]}
        self.assertEqual(by_name["core-sw1.example.net"]["community"], "<redacted>")
        v3 = by_name["edge-rtr1.example.net"]
        self.assertEqual((v3["authpass"], v3["cryptopass"], v3["authname"]), ("<redacted>",) * 3)
        self.assertEqual(v3["snmpver"], "v3")  # what is not a credential stays readable

        one = self.call("librenms_query", path="devices/edge-rtr1.example.net", fields=["hostname", "authpass"])
        self.assertEqual(one["results"], [{"hostname": "edge-rtr1.example.net", "authpass": "<redacted>"}])

        ports = self.call("librenms_query", path="devices/core-sw1.example.net/ports", params={"columns": "ifName"})
        self.assertEqual(ports["route"], "get_device_ports")
        self.assertEqual([row["ifName"] for row in ports["results"]], ["Gi1/0/1", "Gi1/0/2"])
        # the hostname was resolved to the device id before the request went out
        self.assertEqual(self.fake.calls[-1]["path"], "devices/1/ports")

        services = self.call("librenms_query", path="services")
        params = [row["service_param"] for row in services["results"]]
        self.assertEqual(sorted(params), ["", "<redacted>", "<redacted>"])

        self.assertEqual(self.fake.writes(), [])
        self.call("librenms_plan", operations=[SPINE])  # gives the leak check a plan file too
        self.assert_nothing_leaked()

    def test_plan_apply_and_roll_back_a_device_update_and_a_location_create(self):
        plan = self.plan_ops(MOVE, "Move core-sw1 to the spine")
        pid = plan["plan_id"]
        self.assertEqual(plan["summary"], {"create": 1, "update": 1, "delete": 0, "action": 0, "noop": 0})
        self.assertIn('purpose: "core" -> "spine"', plan["diff"])
        self.assertIn('[1] create      location "PDX-4"', plan["diff"])
        self.assertEqual(plan["irreversible"], [])
        self.assertEqual(self.fake.writes(), [])  # planning is read-only

        applied = self.call("librenms_apply", plan_id=pid)
        self.assertTrue(applied["success"], applied)
        self.assertEqual((applied["status"], applied["outcome"]), ("applied", "applied"))
        device = self.fake.tables["devices"][1]
        self.assertEqual((device["purpose"], device["notes"]), ("spine", "moved to the spine layer"))
        [created] = [row for row in self.fake.tables["locations"].values() if row["location"] == "PDX-4"]
        self.assertEqual((float(created["lat"]), float(created["lng"])), (LOCATION["lat"], LOCATION["lng"]))
        self.assertEqual([e["object_id"] for e in applied["journal"]], [1, created["id"]])
        self.assertEqual(
            [(c["method"], c["path"]) for c in self.fake.writes()],
            [("PATCH", "devices/1"), ("POST", "locations")],
        )
        lifecycle = ["plan_created", "apply_started", "step_done", "step_done", "eventlog_linked", "apply_finished"]
        self.assertEqual(self.names(), lifecycle)
        self.assertEqual({e["plan_id"] for e in self.events()}, {pid})
        self.assertEqual({e["actor"]["kind"] for e in self.events()}, {"model"})
        self.assertEqual(self.store.load(pid)["status"], "applied")

        rolled = self.call("librenms_rollback", plan_id=pid)
        self.assertTrue(rolled["success"], rolled)
        self.assertEqual(rolled["status"], "rolled_back")
        self.assertEqual([e["revert_status"] for e in rolled["journal"]], ["reverted", "reverted"])
        device = self.fake.tables["devices"][1]
        self.assertEqual((device["purpose"], device["notes"]), ("core", ""))
        self.assertNotIn("PDX-4", [row["location"] for row in self.fake.tables["locations"].values()])
        self.assertEqual(
            [(c["method"], c["path"]) for c in self.fake.writes()[2:]],  # newest first
            [("DELETE", f"locations/{created['id']}"), ("PATCH", "devices/1")],
        )
        reverts = ["rollback_started", "revert_reverted", "revert_reverted", "eventlog_linked", "rollback_finished"]
        self.assertEqual(self.names(), lifecycle + reverts)
        self.assertEqual(self.events("rollback_finished")[0]["status"], "rolled_back")

        again = self.call("librenms_apply", plan_id=pid)
        self.assertEqual((again["success"], again["refused"]), (False, True))  # a plan applies at most once
        self.assert_nothing_leaked()

    def test_a_failing_second_step_rolls_the_first_back_automatically(self):
        # LibreNMS refuses the group edit and its error echoes the token; nothing of the group was written
        self.fake.fail_on("PATCH", r"devicegroups/1", 400, {"status": "error", "message": f"refused for {TOKEN}"})
        pid = self.plan_ops([SPINE, GROUP_DESC])["plan_id"]

        out = self.call("librenms_apply", plan_id=pid)
        self.assertFalse(out["success"])
        self.assertEqual((out["outcome"], out["status"]), ("failed", "rolled_back"))
        self.assertEqual(out["failure"]["index"], 1)
        self.assertIn("refused for <token>", out["failure"]["error"])
        self.assertEqual([e["status"] for e in out["journal"]], ["done", "failed"])
        self.assertEqual(out["journal"][0]["revert_status"], "reverted")
        self.assertNotIn("revert_status", out["journal"][1])  # it wrote nothing, so there is nothing to undo
        self.assertEqual(
            (out["rollback"]["reason"], out["rollback"]["reverted"]), ("automatic after failure at step 1", 1)
        )
        self.assertEqual(self.fake.tables["devices"][1]["purpose"], "core")
        self.assertEqual(self.fake.tables["device_groups"][1]["desc"], "Core layer switches")
        failed = ["plan_created", "apply_started", "step_done", "step_failed", "eventlog_linked", "apply_finished"]
        reverted = ["rollback_started", "revert_reverted", "eventlog_linked", "rollback_finished"]
        self.assertEqual(self.names(), failed + reverted)
        self.assert_nothing_leaked()

    def test_a_step_that_failed_after_writing_is_rolled_back_too(self):
        # the group edit lands, then LibreNMS answers 500: the step "may have written" and is reverted with step 0
        self.fake.fail_on("PATCH", r"devicegroups/1", 500, commit=True, times=1)
        pid = self.plan_ops([SPINE, GROUP_DESC])["plan_id"]

        out = self.call("librenms_apply", plan_id=pid)
        self.assertEqual((out["success"], out["status"]), (False, "rolled_back"))
        self.assertEqual([(e["status"], e.get("wrote")) for e in out["journal"]], [("done", None), ("failed", True)])
        self.assertEqual([e["revert_status"] for e in out["journal"]], ["reverted", "reverted"])
        self.assertEqual(self.events("step_failed")[0]["wrote"], True)
        self.assertEqual(self.fake.tables["devices"][1]["purpose"], "core")
        self.assertEqual(self.fake.tables["device_groups"][1]["desc"], "Core layer switches")
        self.assert_nothing_leaked()

    def test_operator_only_refuses_the_model_and_names_the_command_to_relay(self):
        self.settings_mod.set_settings(self.settings_mod.Settings(write_mode="operator_only"))
        pid = self.plan_ops([SPINE])["plan_id"]  # planning stays open to the model
        # no approval prompt either: the handler refuses, so asking a human would only mislead
        self.assertIsNone(self.handlers.pre_tool_call("librenms_apply", {"plan_id": pid}))

        out = self.call("librenms_apply", plan_id=pid)
        self.assertEqual((out["success"], out["refused"], out["write_mode"]), (False, True, "operator_only"))
        self.assertIn(f"`/librenms apply {pid}`", out["error"])
        self.assertIn(f"`hermes librenms apply {pid}`", out["error"])
        self.assertEqual(self.fake.writes(), [])
        self.assertEqual(self.store.load(pid)["status"], "planned")
        [refused] = self.events("apply_refused")
        self.assertEqual((refused["write_mode"], refused["actor"]["kind"]), ("operator_only", "model"))
        dry = self.call("librenms_apply", plan_id=pid, dry_run=True)  # a check never writes, so it is allowed
        self.assertEqual((dry["success"], dry["applicable"]), (True, True))

        # the person runs the relayed command; it goes through the same handler as an operator
        text = self.commands.slash_handler(f"apply {pid}", session_id="s-1", platform="signal")
        self.assertIn("(applied)", text)
        self.assertEqual(self.fake.tables["devices"][1]["purpose"], "spine")
        self.assertEqual(self.events("apply_started")[0]["actor"]["via"], "slash")

        out = self.call("librenms_rollback", plan_id=pid)
        self.assertEqual((out["success"], out["refused"]), (False, True))
        self.assertIn(f"`/librenms rollback {pid}`", out["error"])
        self.assertEqual(self.fake.tables["devices"][1]["purpose"], "spine")
        self.outputs.append(text)
        self.assert_nothing_leaked()

    def test_maintenance_and_ack_show_what_rollback_cannot_undo(self):
        ops = [
            {
                "op": "maintenance",
                "resource": "device",
                "match": {"hostname": "access-sw2.example.net"},
                "data": {"duration": "2:00", "title": "Uplink swap", "notes": "swap Gi1/0/48"},
            },
            {"op": "ack", "resource": "alert", "id": 3, "data": {"note": "uplink swap in progress"}},
        ]
        plan = self.plan_ops(ops, "Uplink swap on access-sw2")
        pid = plan["plan_id"]
        self.assertEqual(plan["summary"]["action"], 2)
        self.assertEqual(plan["irreversible"], [0])
        self.assertIn("rollback: none — LibreNMS API v0 cannot end or delete maintenance", plan["diff"])
        self.assertIn("rollback: lossy — ", plan["diff"])
        self.assertIn("the acknowledgement note stays in the fault's history", plan["diff"])
        self.assertIn("steps [0] cannot be rolled back", plan["next_step"])
        self.assertIn("[0] LibreNMS may append these notes to the device notes", "\n".join(plan["warnings"]))
        approval = self.handlers.pre_tool_call("librenms_apply", {"plan_id": pid})
        self.assertEqual(approval["action"], "approve")
        self.assertEqual(
            approval["message"].split("\n")[0],
            f"Apply {pid}: 2 action; irreversible steps: [0]; rollback_on_failure=true",
        )
        self.assertTrue(approval["message"].split("\n")[1].startswith('[0] maintenance device #3 "access-sw2'))
        self.outputs.append(approval["message"])

        applied = self.call("librenms_apply", plan_id=pid)
        self.assertTrue(applied["success"], applied)
        self.assertEqual(self.fake.tables["faults"][3]["state"], 2)
        [schedule] = self.fake.schedules
        self.assertEqual(schedule["title"], f"[hermes:{pid}] Uplink swap")

        rolled = self.call("librenms_rollback", plan_id=pid)
        self.assertFalse(rolled["success"])
        self.assertEqual(rolled["status"], "partially_rolled_back")
        self.assertEqual([e["revert_status"] for e in rolled["journal"]], ["irreversible", "reverted"])
        self.assertIn("cannot end or delete maintenance", rolled["journal"][0]["revert_note"])
        self.assertEqual((rolled["rollback"]["reverted"], rolled["rollback"]["irreversible"]), (1, 1))
        self.assertEqual(self.fake.tables["faults"][3]["state"], 1)  # unmuted
        self.assertEqual(len(self.fake.schedules), 1)  # the maintenance window stays until it expires
        self.assertEqual(
            self.names()[-4:], ["revert_reverted", "revert_irreversible", "eventlog_linked", "rollback_finished"]
        )

        again = self.call("librenms_rollback", plan_id=pid)
        self.assertEqual((again["success"], again["refused"]), (False, True))
        self.assertIn("nothing left to roll back; irreversible steps: [0]", again["error"])
        self.assert_nothing_leaked()

    def test_a_token_pasted_into_chat_reaches_neither_results_nor_the_audit_trail(self):
        # as in production, the plugin knows its token from the environment, so it can mask it wherever it appears
        self.addCleanup(_restore_env, "LIBRENMS_TOKEN", os.environ.get("LIBRENMS_TOKEN"))
        os.environ["LIBRENMS_TOKEN"] = TOKEN
        session = {"session_id": "s-9", "task_id": "t-9"}
        message = f"use {TOKEN} with snmp_community=c0re-Community! to move core-sw1"
        self.handlers.pre_llm_call(**session, user_message=message, sender_id="u1")
        pid = self.plan_ops([SPINE])["plan_id"]
        self.call("librenms_query", session, path="devices/core-sw1.example.net")
        self.call("librenms_query", session, path="logs/eventlog/core-sw1.example.net", limit=5)
        self.call("librenms_query", session, action="status")
        self.call("librenms_apply", session, plan_id=pid, dry_run="true")
        self.call("librenms_apply", session, plan_id=pid)
        self.call("librenms_plans", session)
        self.call("librenms_plans", session, plan_id=pid)
        self.call("librenms_rollback", session, plan_id=pid)
        self.call("librenms_query", session, path="devices/core-sw1.example.net/../../system")  # refused
        [request] = {e["actor"]["request"] for e in self.events("apply_started")}
        self.assertEqual(request, "use <token> with snmp_community=<redacted> to move core-sw1")
        self.assertEqual(self.store.load(pid)["status"], "rolled_back")
        self.assert_nothing_leaked()


if __name__ == "__main__":
    unittest.main()
