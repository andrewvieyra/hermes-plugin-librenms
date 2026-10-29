"""The operator surface: ``/librenms`` and ``hermes librenms`` run the same handlers as the tools (same plans, write
gate and audit events) and add the operator's identity, strict argument parsing, escaped output, and the refusal of
apply and rollback from a shell an agent session started."""

import argparse
import dataclasses
import io
import json
import os
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any, Dict

from .base import PluginTestCase
from .fake_librenms import TOKEN
from .helpers import submodule

PURPOSE = {"op": "update", "resource": "device", "id": 1, "data": {"purpose": "spine"}}
NOTES = {"op": "update", "resource": "device", "id": 3, "data": {"notes": "rack C1"}}
AGENT_MESSAGE = "this shell was started by a Hermes agent session; run the command from your own terminal"


def _restore_env(name: str, value: str | None) -> None:
    if value is None:
        os.environ.pop(name, None)
    else:
        os.environ[name] = value


class CommandCase(PluginTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.commands = submodule("commands")
        for name in self.commands.AGENT_SESSION_VARS:  # the suite itself may run in a shell a Hermes session started
            self.addCleanup(_restore_env, name, os.environ.pop(name, None))

    def configure(self, **changes: Any) -> None:
        self.settings_mod.set_settings(dataclasses.replace(self.settings, **changes))

    def planned(self, *operations: Dict[str, Any], description: str = "test") -> str:
        return self.plan(list(operations or [PURPOSE]), description)["id"]

    def purpose(self) -> str:
        return self.fake.tables["devices"][1]["purpose"]

    def cli(self, *argv: str) -> str:
        """``hermes librenms <argv>`` through a real argparse tree, as Hermes wires it; returns what it printed."""
        parser = argparse.ArgumentParser()
        self.commands.setup_cli(parser)
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertIsNone(self.commands.cli_handler(parser.parse_args(list(argv))))
        return out.getvalue()


class Slash(CommandCase):
    def test_help_and_unknown_subcommands(self):
        for raw in ("", "help", "-h", "--help"):
            self.assertIn("/librenms — LibreNMS change management", self.commands.slash_handler(raw))
        text = self.commands.slash_handler("frobnicate")
        self.assertTrue(text.startswith("Unknown subcommand: frobnicate\n\n/librenms —"), text)
        self.assertIn("hermes librenms — LibreNMS change management", self.commands.run([], via=self.audit.VIA_CLI))

    def test_slash_flow(self):
        self.assertEqual(self.commands.slash_handler("plans"), "No plans saved.")
        pid = self.planned(description="slash demo")
        listing = self.commands.slash_handler("plans")
        self.assertIn(pid, listing)
        self.assertIn("planned", listing)
        self.assertIn("0c, 1u, 0d, 0a, 0n", listing)
        self.assertIn("slash demo", listing)
        shown = self.commands.slash_handler(f"show {pid}")
        self.assertIn(f"Plan {pid} (planned) — slash demo", shown)
        self.assertIn('purpose: "core" -> "spine"', shown)
        self.assertEqual(self.commands.slash_handler(f"check {pid}"), f"{pid} is applicable: all preconditions hold.")
        self.assertEqual(self.fake.writes(), [])
        self.assertIn("-> done", self.commands.slash_handler(f"apply {pid}"))
        self.assertEqual(self.purpose(), "spine")
        self.assertIn("applied", self.commands.slash_handler("plans applied"))
        self.assertEqual(self.commands.slash_handler("plans rolled_back"), "No rolled_back plans.")
        shown = self.commands.slash_handler(f"show {pid}")
        self.assertIn('purpose: "core" -> "spine"', shown)
        self.assertIn("-> done", shown.split("\n\n", 1)[1])  # the journal follows the diff
        self.assertIn("Rollback: 1 reverted", self.commands.slash_handler(f"rollback {pid}"))
        self.assertEqual(self.purpose(), "core")

    def test_fragments_resolve_like_the_store(self):
        pid = self.planned()
        suffix = pid.rsplit("-", 1)[1]
        self.assertIn(pid, self.commands.slash_handler(f"show {suffix}"))
        self.assertIn(pid, self.commands.slash_handler(f"show -{suffix}"))  # an argument, not an unknown option
        self.assertEqual(
            self.commands.slash_handler("show lnp-x"), "No plan matches 'lnp-x'. Use /librenms plans to list them."
        )
        self.assertIn("Use hermes librenms plans", self.commands.run(["show", "nope"], via=self.audit.VIA_CLI))
        first = self.plan([NOTES], plan_id="lnp-20261028T190000Z-ab12")["id"]
        second = self.plan([NOTES], plan_id="lnp-20261028T190100Z-ab12")["id"]
        text = self.commands.slash_handler("apply ab12")
        self.assertEqual(text, f"'ab12' is ambiguous; matches:\n  {first}\n  {second}")
        self.assertEqual(self.fake.writes(), [])

    def test_a_short_or_inner_fragment_names_no_plan(self):
        # every id holds 2026, T, Z and -: with one plan saved, "apply 2" applied it, at once
        pid = self.planned()
        too_short = "is too short to name a plan: give the full plan id or its last 4 or more characters (e.g. 4f1a)"
        for cmd in ("apply", "rollback", "check", "show"):
            for fragment in ("2", "-", "Z", pid[-3:]):
                for text, prog in (
                    (self.commands.slash_handler(f"{cmd} {fragment}"), "/librenms"),
                    (self.cli(cmd, fragment), "hermes librenms"),
                ):
                    self.assertTrue(text.strip().startswith(f"{fragment!r} {too_short}"), (cmd, fragment, text))
                    self.assertIn(f"Use {prog} plans to list them.", text)
            for inner in ("2026", pid[4:12], "lnp-2"):  # not the end of an id
                self.assertEqual(
                    self.commands.slash_handler(f"{cmd} {inner}"),
                    f"No plan matches {inner!r}. Use /librenms plans to list them.",
                )
        self.assertEqual(self.fake.writes(), [])
        self.assertEqual(self.store.load(pid)["status"], "planned")

    def test_a_fragment_says_which_plan_it_named(self):
        pid = self.planned(description="tidy\nports")
        suffix = pid.rsplit("-", 1)[1]
        named = f"'{suffix}' is plan {pid} (planned): tidy\\nports"
        applicable = f"{pid} is applicable: all preconditions hold."
        self.assertEqual(self.commands.slash_handler(f"check {suffix}"), f"{named}\n{applicable}")
        self.assertEqual(self.commands.slash_handler(f"check {pid}"), applicable)  # the operator named it in full
        applied = self.commands.slash_handler(f"apply {suffix}").split("\n")
        self.assertEqual(applied[:2], [named, f"Plan {pid} (applied)"])
        rolled = self.cli("rollback", pid[-9:]).split("\n")
        self.assertEqual(
            rolled[:2], [f"'{pid[-9:]}' is plan {pid} (applied): tidy\\nports", f"Plan {pid} (rolled_back)"]
        )
        # show's diff names the plan itself
        self.assertTrue(self.commands.slash_handler(f"show {suffix}").startswith(f"Plan {pid} (rolled_back) — tidy"))

    def test_status_reports_librenms_and_never_the_token(self):
        text = self.commands.slash_handler("status")
        self.assertIn("26.10.0", text)
        self.assertIn("write_mode", text)
        self.assertNotIn(TOKEN, text)

    def test_a_client_that_cannot_be_built_is_an_error_line(self):
        def unconfigured(*_args: Any, **_kwargs: Any) -> Any:
            raise self.client_mod.ConfigError("LIBRENMS_URL is not set")

        self.handlers.set_client_factory(unconfigured)
        self.assertIn("LIBRENMS_URL is not set", self.commands.slash_handler("status"))
        pid = self.planned()
        text = self.commands.slash_handler(f"apply {pid}")
        self.assertTrue(text.startswith("Error: "), text)
        self.assertIn("LIBRENMS_URL is not set", text)

    def test_usage_and_strict_options(self):
        pid = self.planned()
        cases = {
            "apply": "Usage: /librenms apply <plan_id> [--no-rollback]",
            f"apply {pid} --no-rolback": "Usage: /librenms apply <plan_id> [--no-rollback]",
            f"apply {pid} --no-rollback --no-rollback": "Usage: /librenms apply <plan_id> [--no-rollback]",
            f"apply {pid} --no-rollback=yes": "Usage: /librenms apply <plan_id> [--no-rollback]",
            f"apply {pid} {pid}": "Usage: /librenms apply <plan_id> [--no-rollback]",
            f"apply {pid} --help": "Usage: /librenms apply <plan_id> [--no-rollback]",
            f"rollback {pid} --forse": "Usage: /librenms rollback <plan_id> [--force]",
            "show": "Usage: /librenms show <plan_id>",
            f"check {pid} --force": "Usage: /librenms check <plan_id>",
            "status now": "Usage: /librenms status",
            "plans planned applied": "Usage: /librenms plans [status]",
            "prune --days": "Usage: /librenms prune [--days N] [--dry-run]",
            "prune --frobnicate": "Usage: /librenms prune [--days N] [--dry-run]",
            "prune old": "Usage: /librenms prune [--days N] [--dry-run]",
        }
        for raw, usage in cases.items():
            self.assertEqual(self.commands.slash_handler(raw), usage, raw)
        self.assertEqual(self.commands.run(["show"], via=self.audit.VIA_CLI), "Usage: hermes librenms show <plan_id>")
        self.assertEqual(self.fake.writes(), [])
        self.assertEqual(self.store.load(pid)["status"], "planned")

    def test_shlex_fallback(self):
        self.assertIn("No plan matches", self.commands.slash_handler("show 'unbalanced"))

    def test_handler_errors_are_rendered(self):
        pid = self.planned()
        self.assertIn("Error: ", self.commands.slash_handler(f"rollback {pid}"))  # nothing applied yet
        self.commands.slash_handler(f"apply {pid}")
        writes = len(self.fake.writes())
        text = self.commands.slash_handler(f"apply {pid}")
        self.assertTrue(text.startswith("Error: "), text)
        self.assertEqual(len(self.fake.writes()), writes)
        errors = [{"index": 0, "error": "unknown resource"}, {"index": 2, "error": "id must be positive"}]
        rejected = json.dumps({"success": False, "error": "bad", "errors": errors})
        self.assertEqual(
            self.commands._result(rejected), "Error: bad\n  [0] unknown resource\n  [2] id must be positive"
        )
        self.assertEqual(self.commands._result("not json"), "not json")
        self.assertEqual(self.commands._result('{"success": true, "a": 1}'), '{\n  "success": true,\n  "a": 1\n}')

    def test_check_lists_conflicts(self):
        pid = self.planned()
        self.fake.touch("devices", 1, purpose="edge")
        text = self.commands.slash_handler(f"check {pid}")
        self.assertTrue(text.startswith(f"{pid} is NOT applicable:\n  [0] "), text)
        self.assertIn("changed since planning", text)
        self.assertEqual(self.fake.writes(), [])

    def test_a_failed_apply_prints_its_journal_and_no_rollback_reaches_the_executor(self):
        self.fake.fail_on("PATCH", r"devices/3", 400, {"status": "error", "message": "refused"})
        pid = self.planned(PURPOSE, NOTES)
        text = self.commands.slash_handler(f"apply {pid} --no-rollback")
        self.assertIn("Apply FAILED at step 1", text)
        self.assertIn("-> failed", text)
        plan = self.store.load(pid)
        self.assertIs(plan["apply"]["rollback_on_failure"], False)
        self.assertEqual((plan["status"], self.purpose()), ("failed", "spine"))
        self.fake.touch("devices", 1, purpose="core")
        pid = self.planned(PURPOSE, NOTES)
        self.commands.slash_handler(f"apply {pid}")
        plan = self.store.load(pid)
        self.assertIs(plan["apply"]["rollback_on_failure"], True)
        self.assertEqual(self.purpose(), "core")  # reverted automatically

    def test_output_cannot_drive_the_terminal(self):
        trick = "\x1b[2J\rcleared\u202e\nlnp-20000101T000000Z-dead  applied"
        self.fake.touch("devices", 1, hostname="core-sw1\x1b[8m\u202e.example.net")  # the label comes from LibreNMS
        pid = self.planned(description=trick)
        listing = self.commands.slash_handler("plans")
        self.assertEqual(len(listing.splitlines()), 1, listing)  # the description cannot forge a second plan
        self.assertIn("\\x1b[2J\\rcleared\\u202e\\nlnp-20000101T000000Z-dead", listing)
        shown = self.commands.slash_handler(f"show {pid}")
        applied = self.commands.slash_handler(f"apply {pid}")
        for text in (listing, shown, applied):
            for raw in ("\x1b", "\r", "\u202e"):
                self.assertNotIn(raw, text)
        for text in (shown, applied):
            self.assertIn('"core-sw1\\x1b[8m\\u202e.example.net"', text)

    def test_unexpected_errors_are_reported_not_raised(self):
        def broken() -> Any:
            raise RuntimeError(f"kaboom {TOKEN}")

        original = self.handlers.status_report
        self.addCleanup(setattr, self.handlers, "status_report", original)
        self.handlers.status_report = broken
        with self.assertLogs(self.commands.logger, "WARNING"):
            text = self.commands.slash_handler("status")
        self.assertRegex(text, r"^Error: the command failed unexpectedly \(err-[0-9a-f]{12}\)")
        self.assertNotIn("kaboom", text)


class Actor(CommandCase):
    def test_slash_actor_comes_from_the_gateway_keywords(self):
        pid = self.planned()
        source = SimpleNamespace(
            platform="telegram", user_id="42", user_name="Andrew", chat_id="-100", chat_type="group"
        )
        text = self.commands.slash_handler(
            f"apply {pid}", session_id="sess-9", session_key="k", platform="telegram", source=source
        )
        self.assertIn("-> done", text)
        actor = self.events("apply_started")[-1]["actor"]
        self.assertEqual((actor["kind"], actor["via"]), ("operator", "slash"))
        self.assertEqual(
            (actor["session_id"], actor["platform"], actor["user_name"], actor["chat_type"]),
            ("sess-9", "telegram", "Andrew", "group"),
        )
        self.assertEqual(self.store.load(pid)["apply"]["actor"]["user_id"], "42")
        self.assertIn("by operator via slash on telegram for Andrew", text)

    def test_operator_paths_are_labelled(self):
        pid = self.planned()
        self.commands.slash_handler(f"apply {pid}")
        self.cli("rollback", pid)
        started = self.events("apply_started") + self.events("rollback_started")
        self.assertEqual(
            [(e["actor"]["kind"], e["actor"]["via"]) for e in started], [("operator", "slash"), ("operator", "cli")]
        )


class Cli(CommandCase):
    def test_cli_wiring(self):
        pid = self.planned()
        self.assertIn("hermes librenms — LibreNMS change management", self.cli())
        self.assertIn(pid, self.cli("plans"))
        self.assertIn('purpose: "core" -> "spine"', self.cli("show", pid))
        self.assertIn("all preconditions hold", self.cli("check", pid))
        self.assertIn("-> done", self.cli("apply", pid, "--no-rollback"))
        self.assertIs(self.store.load(pid)["apply"]["rollback_on_failure"], False)
        self.assertIn("Rollback: 1 reverted", self.cli("rollback", pid, "--force"))
        self.assertIs(self.store.load(pid)["rollback"]["force"], True)
        self.assertIn(pid, self.cli("plans", "rolled_back"))
        self.assertIn("26.10.0", self.cli("status"))
        self.assertIn("Nothing older than 5 days.", self.cli("prune", "--days", "5", "--dry-run"))
        self.assertIn("Usage: hermes librenms prune", self.cli("prune", "--days", "-1"))

    def test_cli_output_is_escaped(self):
        pid = self.planned(description="\x1b]0;owned\x07")
        text = self.cli("plans")
        self.assertNotIn("\x1b", text)
        self.assertIn("\\x1b]0;owned\\x07", text)
        self.assertNotIn("\x07", self.cli("show", pid))


class WriteMode(CommandCase):
    def test_read_only_refuses_slash_and_cli(self):
        pid = self.planned()
        self.configure(write_mode="read_only")
        self.assertIn("read_only", self.commands.slash_handler(f"apply {pid}"))
        self.assertIn("read_only", self.cli("apply", pid))
        self.assertIn("read_only", self.commands.run(["rollback", pid], via=self.audit.VIA_CLI))
        self.assertIn("read_only", self.commands.slash_handler(f"rollback {pid}"))
        self.assertEqual(self.fake.writes(), [])
        self.assertEqual(len(self.events("apply_refused")), 2)
        self.assertEqual(len(self.events("rollback_refused")), 2)
        # a check never writes, so it stays available
        self.assertIn("all preconditions hold", self.commands.slash_handler(f"check {pid}"))

    def test_operator_only_allows_slash_and_cli(self):
        self.configure(write_mode="operator_only")
        pid = self.planned()
        self.assertIn("-> done", self.commands.slash_handler(f"apply {pid}"))
        self.assertIn("Rollback: 1 reverted", self.commands.run(["rollback", pid], via=self.audit.VIA_CLI))
        self.assertEqual(self.purpose(), "core")


class AgentShell(CommandCase):
    """A shell the agent's terminal tool started carries the session's variables; ``hermes librenms apply`` run there
    is the model writing past ``operator_only`` and past the approval prompt."""

    def enter_session(self, name: str = "HERMES_SESSION_ID", value: str = "sess-agent") -> None:
        os.environ[name] = value

    def test_cli_apply_is_refused_and_audited(self):
        for name in self.commands.AGENT_SESSION_VARS:
            with self.subTest(name=name):
                for other in self.commands.AGENT_SESSION_VARS:
                    os.environ.pop(other, None)
                self.configure(write_mode="operator_only")
                pid = self.planned()
                self.enter_session(name)
                self.assertEqual(self.cli("apply", pid).strip(), f"Error: apply refused: {AGENT_MESSAGE}")
                self.assertEqual(self.fake.writes(), [])
                self.assertEqual(self.store.load(pid)["status"], "planned")
                event = self.events("apply_refused")[-1]
                self.assertEqual(event["plan_id"], pid)
                self.assertEqual(event["reason"], self.commands.AGENT_SESSION_REASON)
                self.assertEqual(event["reason"], "started from a Hermes agent session")
                self.assertEqual((event["write_mode"], event["session_variables"]), ("operator_only", [name]))
                self.assertEqual(event["librenms_url"], self.client.base_url)
                self.assertEqual((event["actor"]["kind"], event["actor"]["via"]), ("operator", "cli"))
                self.assertEqual(self.events("apply_started"), [])

    def test_cli_rollback_is_refused_and_audited(self):
        pid = self.planned()
        self.configure(write_mode="operator_only")
        self.enter_session()
        self.assertIn("-> done", self.commands.slash_handler(f"apply {pid}"))  # the slash command is a person in a chat
        self.assertEqual(self.cli("rollback", pid, "--force").strip(), f"Error: rollback refused: {AGENT_MESSAGE}")
        self.assertEqual(self.purpose(), "spine")
        event = self.events("rollback_refused")[-1]
        self.assertEqual((event["plan_id"], event["reason"]), (pid, "started from a Hermes agent session"))
        self.assertEqual(self.events("rollback_started"), [])

    def test_only_full_mode_without_approval_lets_the_shell_write(self):
        pid = self.planned()
        self.enter_session("HERMES_SESSION_KEY", "telegram:dm:42")
        for changes in ({"write_mode": "full"}, {"write_mode": "operator_only", "require_approval": False}):
            self.configure(**changes)
            self.assertIn(AGENT_MESSAGE, self.cli("apply", pid))
        self.configure(write_mode="read_only", require_approval=False)
        self.assertIn(AGENT_MESSAGE, self.cli("apply", pid))
        self.assertEqual(self.fake.writes(), [])
        self.configure(write_mode="full", require_approval=False)  # the tools would write unprompted anyway
        self.assertIn("-> done", self.cli("apply", pid))
        self.assertIn("Rollback: 1 reverted", self.cli("rollback", pid))

    def test_reads_and_checks_stay_available(self):
        pid = self.planned()
        self.configure(write_mode="operator_only")
        self.enter_session()
        self.assertIn("all preconditions hold", self.cli("check", pid))
        self.assertIn(pid, self.cli("plans"))
        self.assertIn('purpose: "core" -> "spine"', self.cli("show", pid))
        self.assertIn("26.10.0", self.cli("status"))
        self.assertIn("Nothing older than 90 days.", self.cli("prune"))
        self.assertEqual(self.events("apply_refused"), [])

    def test_an_empty_variable_is_not_a_session(self):
        pid = self.planned()
        self.configure(write_mode="operator_only")
        self.enter_session(value="")
        self.assertIn("-> done", self.cli("apply", pid))


class Prune(CommandCase):
    def age(self, plan_id: str, days: int) -> None:
        path = self.store.directory / f"{plan_id}.json"
        doc = json.loads(path.read_text(encoding="utf-8"))
        doc["updated_at"] = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat().replace("+00:00", "Z")
        path.write_text(json.dumps(doc), encoding="utf-8")

    def test_prune_command_and_audit(self):
        self.assertEqual(self.commands.slash_handler("prune"), "Nothing older than 90 days.")
        self.assertIn("Usage", self.commands.slash_handler("prune --days x"))
        self.assertIn("Usage", self.commands.slash_handler("prune --days -1"))
        self.assertIn("Usage", self.commands.slash_handler("prune --days ²"))
        pid = self.planned()
        self.assertIn("Retention is disabled", self.commands.slash_handler("prune --days 0"))
        self.age(pid, 5)
        text = self.commands.slash_handler("prune --days=3 --dry-run")
        self.assertTrue(text.startswith("Would remove 1 plan(s) older than 3 days:\n"), text)
        self.assertIn(f"  {pid}  planned", text)
        self.assertIsNotNone(self.store.load(pid))
        self.assertEqual(self.events("plans_pruned"), [])
        self.assertIn("Removed 1 plan", self.commands.run(["prune", "--days", "3"], via=self.audit.VIA_CLI))
        self.assertIsNone(self.store.load(pid))
        pruned = self.events("plans_pruned")
        self.assertEqual(pruned[-1]["plan_ids"], [pid])
        self.assertEqual(pruned[-1]["actor"]["via"], "cli")

    def test_retention_setting_is_the_default(self):
        pid = self.planned()
        self.age(pid, 10)
        self.configure(plan_retention_days=0)
        self.assertIn("Retention is disabled", self.commands.slash_handler("prune"))
        self.configure(plan_retention_days=7)
        self.assertIn("Removed 1 plan(s) older than 7 days", self.commands.slash_handler("prune"))

    def test_every_other_command_sweeps_old_plans_too(self):
        # an install whose plans are only ever handled by an operator still keeps to plan_retention_days
        self.configure(plan_retention_days=7)
        for argv in (["status"], ["plans"], ["show", "nothing-like-it"]):
            self.handlers.reset_state()
            pid = self.planned()
            self.age(pid, 10)
            self.commands.run(argv, via=self.audit.VIA_CLI)
            self.assertIsNone(self.store.load(pid), argv)
            self.assertEqual(self.events("plans_pruned")[-1]["actor"]["via"], "cli")
        self.handlers.reset_state()
        pid = self.planned()
        self.age(pid, 10)
        self.commands.run(["help"], via=self.audit.VIA_CLI)  # usage only: nothing runs
        self.assertIsNotNone(self.store.load(pid))


if __name__ == "__main__":
    unittest.main()
