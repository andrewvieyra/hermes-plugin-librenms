"""write_mode as the handlers enforce it: full lets the model write, operator_only refuses the model (naming the
command a person can run) but not the slash command or the CLI, read_only refuses everyone and hides the write tools;
every refusal is audited, dry runs stay allowed, the mode is read live from config.yaml, and the model cannot claim
to be an operator. Also the compact apply/rollback output against the full one librenms_plans returns."""

import contextlib
import json
import os
import unittest

from .base import PluginTestCase
from .helpers import submodule

ENV = {"LIBRENMS_URL": "https://librenms.test", "LIBRENMS_TOKEN": "0123456789abcdef"}
AGENT_SESSION_VARS = ("HERMES_SESSION_ID", "HERMES_SESSION_KEY")


@contextlib.contextmanager
def environ(**values):
    """Set (a str) or unset (None) environment variables for the block, restoring them afterwards."""
    saved = {name: os.environ.get(name) for name in values}
    try:
        for name, value in values.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        yield
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def operator_shell():
    """A shell the operator opened, not one an agent session started (the CLI refuses those in operator_only)."""
    return environ(**dict.fromkeys(AGENT_SESSION_VARS))


class Ctx:
    """The one PluginContext method settings read, over a dict the test edits as an operator edits config.yaml."""

    def __init__(self, config):
        self.config = config

    def get_config(self, key, default=None):
        return self.config.get(key, default)


class WriteMode(PluginTestCase):
    def call(self, name, args, **kwargs):
        return json.loads(self.handlers.HANDLERS[name](args, **kwargs))

    def mode(self, value, **extra):
        self.settings_mod.set_settings(self.settings_mod.Settings(allow_delete=True, write_mode=value, **extra))

    def planned(self):
        return self.plan([{"op": "update", "resource": "device", "id": 1, "data": {"purpose": "spine"}}])["id"]

    def test_full_lets_the_model_write(self):
        self.mode("full")
        self.assertTrue(self.call("librenms_apply", {"plan_id": self.planned()})["success"])

    def test_operator_only_refuses_model_and_names_the_command(self):
        self.mode("operator_only")
        pid = self.planned()
        out = self.call("librenms_apply", {"plan_id": pid})
        self.assertFalse(out["success"])
        self.assertTrue(out["refused"])
        self.assertEqual(out["write_mode"], "operator_only")
        self.assertIn(f"/librenms apply {pid}", out["error"])
        self.assertIn(f"hermes librenms apply {pid}", out["error"])
        self.assertEqual(self.fake.writes(), [])
        refused = self.events("apply_refused")[-1]
        self.assertEqual((refused["write_mode"], refused["dry_run"], refused["plan_id"]), ("operator_only", False, pid))
        # a dry run is a read and stays allowed
        self.assertTrue(self.call("librenms_apply", {"plan_id": pid, "dry_run": True})["applicable"])

    def test_the_model_cannot_claim_to_be_an_operator(self):
        self.mode("operator_only")
        pid = self.planned()
        args = {"plan_id": pid, "_actor": {"kind": "operator", "via": "cli"}}
        self.assertTrue(self.call("librenms_apply", args)["refused"])
        self.assertEqual(self.events("apply_refused")[-1]["actor"]["kind"], "model")
        operator = self.audit.capture_actor({}, via=self.audit.VIA_SLASH)
        self.assertTrue(self.call("librenms_apply", {"plan_id": pid}, _actor=operator)["success"])

    def test_operator_only_allows_slash_and_cli(self):
        self.mode("operator_only")
        commands = submodule("commands")
        pid = self.planned()
        self.assertIn("-> done", commands.slash_handler(f"apply {pid}"))
        with operator_shell():
            self.assertIn("Rollback: 1 reverted", commands.run(["rollback", pid], via=self.audit.VIA_CLI))
        self.assertEqual(self.fake.tables["devices"][1]["purpose"], "core")

    def test_operator_only_refuses_model_rollback(self):
        self.mode("full")
        pid = self.planned()
        self.call("librenms_apply", {"plan_id": pid})
        self.mode("operator_only")
        out = self.call("librenms_rollback", {"plan_id": pid})
        self.assertFalse(out["success"])
        self.assertIn(f"/librenms rollback {pid}", out["error"])
        self.assertEqual(self.fake.tables["devices"][1]["purpose"], "spine")
        refused = self.events("rollback_refused")[-1]
        self.assertEqual((refused["plan_id"], refused["write_mode"]), (pid, "operator_only"))

    def test_read_only_refuses_everyone_and_hides_tools(self):
        self.mode("read_only")
        commands = submodule("commands")
        pid = self.planned()
        self.assertIn("read_only", self.call("librenms_apply", {"plan_id": pid})["error"])
        self.assertIn("read_only", self.call("librenms_rollback", {"plan_id": pid})["error"])
        self.assertIn("read_only", commands.slash_handler(f"apply {pid}"))
        with operator_shell():
            self.assertIn("read_only", commands.run(["rollback", pid], via=self.audit.VIA_CLI))
        self.assertEqual(self.fake.writes(), [])
        with environ(**ENV):
            self.assertFalse(self.handlers.check_write_requirements())
            self.assertTrue(self.handlers.check_requirements())
            self.assertFalse(self.handlers.check_fn("librenms_rollback")())
            self.assertTrue(self.handlers.check_fn("librenms_query")())
            self.mode("operator_only")
            self.assertTrue(self.handlers.check_write_requirements())
        with environ(LIBRENMS_URL=None, LIBRENMS_TOKEN=None):
            self.assertFalse(self.handlers.check_requirements())
        self.mode("read_only")
        # queries, planning and dry runs keep working
        self.assertTrue(self.call("librenms_query", {"action": "status"})["success"])
        self.assertTrue(self.call("librenms_apply", {"plan_id": pid, "dry_run": True})["applicable"])
        discover = {"op": "discover", "resource": "device", "id": 1}
        self.assertTrue(self.call("librenms_plan", {"description": "x", "operations": [discover]})["success"])

    def test_the_mode_is_read_live_and_an_invalid_one_fails_closed(self):
        self.settings_mod.set_settings(None)  # unpinned: read from the context on every call
        config = {"write_mode": "full"}
        self.settings_mod.set_context(Ctx(config))
        pid = self.planned()
        with environ(**ENV):
            self.assertTrue(self.handlers.check_write_requirements())
            config["write_mode"] = "yolo"
            self.assertFalse(self.handlers.check_write_requirements())
        out = self.call("librenms_apply", {"plan_id": pid})
        self.assertEqual(out["write_mode"], "read_only")
        self.assertEqual(self.fake.writes(), [])
        status = self.call("librenms_query", {"action": "status"})
        self.assertEqual((status["write_mode"], status["apply_available"]), ("read_only", False))
        self.assertTrue(any("write_mode" in error for error in status["settings_errors"]))

    def test_status_reports_mode_and_version(self):
        self.mode("operator_only")
        out = self.call("librenms_query", {"action": "status"})
        self.assertEqual((out["write_mode"], out["apply_available"]), ("operator_only", False))
        self.assertEqual(out["plugin_version"], submodule("version").__version__)


class CompactOutput(PluginTestCase):
    def call(self, name, args, **kwargs):
        return json.loads(self.handlers.HANDLERS[name](args, **kwargs))

    def test_apply_output_has_no_snapshots_but_plans_does(self):
        pid = self.plan([{"op": "delete", "resource": "location", "id": 3}])["id"]
        out = self.call("librenms_apply", {"plan_id": pid})
        entry = out["journal"][0]
        self.assertEqual((entry["status"], entry["inverse_kind"]), ("done", "lossy"))
        self.assertIsInstance(entry["http_status"], int)
        self.assertNotIn("inverse", entry)
        self.assertNotIn("snapshot", json.dumps(out))
        self.assertNotIn(3, self.fake.tables["locations"])
        shown = self.call("librenms_plans", {"plan_id": pid})
        self.assertNotIn("steps", shown)
        self.assertNotIn("snapshot", json.dumps(shown))  # the journal in summary, as apply returns it
        full = self.call("librenms_plans", {"plan_id": pid, "detail": True})
        self.assertIn("snapshot", json.dumps(full["steps"][0]))
        self.assertIsNotNone(full["journal"][0]["inverse"])
        rolled = self.call("librenms_rollback", {"plan_id": pid})
        self.assertTrue(rolled["success"])
        self.assertEqual(rolled["journal"][0]["revert_status"], "reverted")
        self.assertIn("new_object_id", rolled["journal"][0])
        self.assertEqual(
            set(rolled["rollback"]),
            {
                "started_at",
                "finished_at",
                "reason",
                "force",
                "entries",
                "reverted",
                "conflict",
                "failed",
                "irreversible",
                "skipped",
                "recovered",
                "eventlog",
            },
        )
        self.assertEqual(rolled["rollback"]["reason"], "requested")

    def test_irreversible_steps_leave_the_plan_partially_rolled_back(self):
        op = {"op": "maintenance", "resource": "device", "id": 1, "data": {"duration": "1:00"}}
        pid = self.plan([op])["id"]
        self.assertTrue(self.call("librenms_apply", {"plan_id": pid})["success"])
        rolled = self.call("librenms_rollback", {"plan_id": pid})
        self.assertFalse(rolled["success"])
        self.assertEqual(rolled["status"], "partially_rolled_back")
        self.assertEqual(rolled["journal"][0]["revert_status"], "irreversible")
        self.assertIn("cannot end or delete maintenance", rolled["journal"][0]["revert_note"])
        again = self.call("librenms_rollback", {"plan_id": pid})
        self.assertTrue(again["refused"])
        self.assertIn("nothing left to roll back", again["error"])
        self.assertIn("nothing left", self.events("rollback_refused")[-1]["reason"])


if __name__ == "__main__":
    unittest.main()
