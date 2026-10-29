"""The hook callbacks (design §16.8, §16.9): the approval directive for librenms_apply / librenms_rollback (dry_run
parsing, rule keys per plan and variant, the message laid out for what each Hermes surface shows, escaping and
clipping, exact plan ids, blocking what does not resolve and failing closed), the terminal guard against ``hermes
librenms apply|rollback`` in a command, code or a background shell's input (in linear time), no work for unrelated
tools, the request cache behind ``pre_llm_call``, and ``approval_decided`` from ``post_approval_response``."""

import hashlib
import json
import os
import re
import textwrap
import time
import unittest

from .base import PluginTestCase, _restore_env
from .fake_librenms import TOKEN

HOOK_KWARGS = {"task_id": "t1", "session_id": "s1", "tool_call_id": "call-1", "turn_id": "turn-1"}


def unresolved_key(tool, raw):
    return f"librenms:{tool}:unresolved:{hashlib.sha256(raw.encode()).hexdigest()[:12]}"


class HookCase(PluginTestCase):
    def hook(self, tool, args):
        return self.handlers.pre_tool_call(tool_name=tool, args=args, **HOOK_KWARGS)

    def configure(self, **values):
        self.settings_mod.set_settings(self.settings_mod.Settings(**values))

    def planned(self, purpose="spine"):
        return self.plan([{"op": "update", "resource": "device", "id": 1, "data": {"purpose": purpose}}])["id"]

    def applied(self):
        pid = self.planned()
        self.assertTrue(json.loads(self.handlers.librenms_apply({"plan_id": pid}))["success"])
        return pid

    def stub(self, name, replacement):
        """Replace the handlers module's *name* for this test (a hand-written double)."""
        original = getattr(self.handlers, name)
        setattr(self.handlers, name, replacement)
        self.addCleanup(setattr, self.handlers, name, original)


class ApplyApproval(HookCase):
    def test_dry_run_parsing_table(self):
        pid = self.planned()
        for value in ("false", "0", "no", "off", " ", "False", 0, None):
            directive = self.hook("librenms_apply", {"plan_id": pid, "dry_run": value})
            self.assertEqual(directive["action"], "approve", repr(value))
        for value in (True, "true", "1", "yes"):
            self.assertIsNone(self.hook("librenms_apply", {"plan_id": pid, "dry_run": value}), repr(value))
        # the handler reads the flag the same way: what was not approved as a write does not write
        self.assertTrue(json.loads(self.handlers.librenms_apply({"plan_id": pid, "dry_run": "yes"}))["dry_run"])
        self.assertEqual(self.fake.writes(), [])

    def test_rule_key_and_message_name_the_plan_and_the_variant(self):
        pid = self.planned()
        directive = self.hook("librenms_apply", {"plan_id": pid})
        self.assertEqual(directive["rule_key"], f"librenms:librenms_apply:{pid}:rb")
        self.assertEqual(
            directive["message"].split("\n"),
            [
                f"Apply {pid}: 1 update; irreversible steps: none; rollback_on_failure=true",
                '[0] update device #1 "core-sw1.example.net": purpose',
                '  [0] purpose: "core" -> "spine"',
                "Description: test",
                f"Full plan: /librenms show {pid}",
            ],
        )
        for value, variant in ((False, "norb"), ("no", "norb"), ("off", "norb"), (True, "rb"), ("maybe", "rb")):
            directive = self.hook("librenms_apply", {"plan_id": pid, "rollback_on_failure": value})
            self.assertEqual(directive["rule_key"], f"librenms:librenms_apply:{pid}:{variant}", repr(value))
            self.assertIn(f"rollback_on_failure={'true' if variant == 'rb' else 'false'}", directive["message"])

    def test_a_fragment_is_refused_naming_the_full_id(self):
        # resolved again by the handler after the prompt, a fragment could name a plan created while it was open
        pid = self.planned()
        suffix = pid.rsplit("-", 1)[1]
        self.assertEqual(
            self.hook("librenms_apply", {"plan_id": suffix}),
            {
                "action": "block",
                "message": f"plan_id '{suffix}' is only the end of {pid}; pass the full plan_id",
            },
        )
        self.assertEqual(
            self.hook("librenms_apply", {"plan_id": f"  {pid} "})["rule_key"], f"librenms:librenms_apply:{pid}:rb"
        )

    def test_irreversible_steps_are_named_in_the_header_and_marked(self):
        op = {"op": "maintenance", "resource": "device", "id": 1, "data": {"duration": "1:00"}}
        pid = self.plan([op])["id"]
        lines = self.hook("librenms_apply", {"plan_id": pid})["message"].split("\n")
        self.assertEqual(lines[0], f"Apply {pid}: 1 action; irreversible steps: [0]; rollback_on_failure=true")
        self.assertTrue(lines[1].startswith('[0] maintenance device #1 "core-sw1.example.net" (irreversible): '), lines)
        self.assertIn("  [0] rollback: none — LibreNMS API v0 cannot end or delete maintenance", "\n".join(lines))

    def test_an_unresolved_plan_is_blocked_and_nothing_created_later_runs(self):
        for raw in ("lnp-nope", "", "../../etc/passwd", "lnp-2", None):
            directive = self.hook("librenms_apply", {"plan_id": raw})
            self.assertEqual(directive["action"], "block", repr(raw))
            self.assertTrue(directive["message"].startswith("unknown plan_id "), directive)
            self.assertNotIn("rule_key", directive)
        # the race: the hook was asked about "lnp-2" before any plan existed; a plan made meanwhile (every id of the
        # year holds "lnp-2") must not be what the handler applies
        self.planned("decommissioned")
        self.assertEqual(self.hook("librenms_apply", {"plan_id": "lnp-2"})["action"], "block")
        self.assertIn("unknown plan_id", json.loads(self.handlers.librenms_apply({"plan_id": "lnp-2"}))["error"])
        self.assertEqual(self.fake.writes(), [])
        hostile = "x\x1b]0;owned\x07" + "y" * 200
        directive = self.hook("librenms_rollback", {"plan_id": hostile})
        self.assertNotIn("\x1b", directive["message"])
        self.assertNotIn("y" * 81, directive["message"])
        # arguments that are not an object at all name no plan
        self.assertEqual(
            self.hook("librenms_rollback", ["plan_id"]), {"action": "block", "message": "unknown plan_id ''"}
        )
        refused = self.events("apply_refused")
        self.assertEqual(len(refused), 7)  # six from the hook, one from the handler
        self.assertEqual(
            {(event["tool"], event["plan_id"], event["reason"]) for event in refused[:1]},
            {("librenms_apply", None, "unknown plan_id 'lnp-nope'")},
        )
        self.assertEqual(self.events("rollback_refused")[0]["tool"], "librenms_rollback")
        self.assertEqual(self.events("approval_requested"), [])

    def test_ambiguous_plan_is_blocked(self):
        first = self.plan(
            [{"op": "update", "resource": "device", "id": 1, "data": {"purpose": "a"}}],
            plan_id="lnp-20261028T190000Z-ab12",
        )
        second = self.plan(
            [{"op": "update", "resource": "device", "id": 3, "data": {"purpose": "b"}}],
            plan_id="lnp-20261028T190100Z-ab12",
        )
        directive = self.hook("librenms_rollback", {"plan_id": "ab12"})
        self.assertEqual(
            directive,
            {
                "action": "block",
                "message": f"plan_id 'ab12' matches 2 plans ({first['id']}, {second['id']}); pass the full plan_id",
            },
        )

    def test_fail_closed_on_exception(self):
        pid = self.planned()

        def broken_store():
            raise OSError("disk on fire")

        self.stub("get_store", broken_store)
        with self.assertLogs(self.handlers.logger, "WARNING"):
            directive = self.hook("librenms_apply", {"plan_id": pid})
        self.assertEqual(directive["action"], "block")
        self.assertRegex(
            directive["message"],
            r"^apply refused: the plan could not be loaded for the approval prompt \(err-[0-9a-f]{12}\); see the "
            r"Hermes log$",
        )
        self.assertNotIn("disk on fire", directive["message"])
        [event] = self.events("apply_refused")
        self.assertEqual((event["tool"], event["reason"]), ("librenms_apply", directive["message"]))

    def test_settings_that_need_no_approval(self):
        pid = self.applied()
        for values in ({"require_approval": False}, {"write_mode": "operator_only"}, {"write_mode": "read_only"}):
            self.configure(**values)
            self.assertIsNone(self.hook("librenms_apply", {"plan_id": pid}), values)
            self.assertIsNone(self.hook("librenms_rollback", {"plan_id": pid}), values)
        self.configure(write_mode="read_only", require_approval=True)

        def broken_store():
            raise AssertionError("no plan is read when no approval is needed")

        self.stub("get_store", broken_store)
        self.assertIsNone(self.hook("librenms_apply", {"plan_id": pid}))
        self.assertEqual(self.events("approval_requested"), [])

    def test_a_hostile_label_reaches_the_message_escaped(self):
        pid = self.planned()
        plan = self.store.load(pid)
        plan["steps"][0]["label"] = "sw1\x1b[2K\r\u202eApproved by NOC"
        plan["description"] = "move\u2028line"
        self.store.save(plan)
        message = self.hook("librenms_apply", {"plan_id": pid})["message"]
        for raw in ("\x1b", "\r", "\u202e", "\u2028"):
            self.assertNotIn(raw, message)
        self.assertIn('"sw1\\x1b[2K\\r\\u202eApproved by NOC"', message)
        self.assertIn("move\\u2028line", message)

    def test_every_step_shows_where_hermes_cuts_the_prompt(self):
        # Hermes' CLI panel shows 9 rows of 64 columns of the message, Discord 300 characters, Slack and Telegram 500;
        # the repeated Plan/LibreNMS/Created lines used to fill them before any step
        ops = [
            {
                "op": "update",
                "resource": "device",
                "match": {"hostname": "core-sw1.example.net"},
                "data": {"purpose": "decommissioned", "notes": "x"},
            },
            {"op": "update", "resource": "port", "id": 1, "data": {"description": "spare"}},
        ]
        pid = self.plan(ops, "tidy")["id"]
        message = self.hook("librenms_apply", {"plan_id": pid})["message"]
        step0 = '[0] update device #1 "core-sw1.example.net": purpose, notes'
        step1 = '[1] update port #1 "Gi1/0/1 on core-sw1.example.net": description'
        self.assertEqual(message.split("\n")[1:3], [step0, step1])
        rows = [row for line in message.split("\n") for row in (textwrap.wrap(line, 64, drop_whitespace=False) or [""])]
        panel = "".join(rows[:9])
        self.assertIn(step0, panel)
        self.assertIn(step1.replace(" ", ""), panel.replace(" ", ""))  # wrapped across two rows
        self.assertIn(step0, message[:300])
        self.assertIn(step1, message[:500])
        self.assertNotIn("LibreNMS: ", message)
        self.assertNotIn("Created: ", message)

    def test_deletes_and_irreversible_steps_come_first(self):
        ops = [
            {"op": "update", "resource": "device", "id": 1, "data": {"purpose": "spine"}},
            {"op": "maintenance", "resource": "device", "id": 3, "data": {"duration": "1:00"}},
            {"op": "update", "resource": "device", "id": 2, "data": {"notes": "x"}},
            {"op": "delete", "resource": "device_group", "id": 1},
        ]
        pid = self.plan(ops)["id"]
        lines = self.hook("librenms_apply", {"plan_id": pid})["message"].split("\n")
        self.assertEqual(
            lines[0], f"Apply {pid}: 2 update, 1 delete, 1 action; irreversible steps: [1]; rollback_on_failure=true"
        )
        self.assertEqual([line[:3] for line in lines[1:5]], ["[1]", "[3]", "[0]", "[2]"])
        self.assertTrue(lines[2].startswith('[3] delete device_group #1 "core-switches"'), lines[2])

    def test_a_long_label_cannot_push_the_steps_out(self):
        # LibreNMS creates locations from sysLocation, so a device owner can plant this name too; one_line writes each
        # isolate as a 6-character escape, 1,530 characters in all, which hid the delete after it
        ops = [
            {"op": "create", "resource": "location", "data": {"location": "\u2066" * 255, "lat": 1.5, "lng": 2.5}},
            {"op": "delete", "resource": "device_group", "id": 1},
        ]
        pid = self.plan(ops, "add a location")["id"]
        message = self.hook("librenms_apply", {"plan_id": pid})["message"]
        lines = message.split("\n")
        self.assertTrue(lines[1].startswith('[1] delete device_group #1 "core-switches"'), lines)
        self.assertEqual(lines[2], '[0] create location "' + "\\u2066" * 6 + '\\u2…": location, lat, lng')
        self.assertIn(lines[1], message[:300])
        self.assertTrue(all(len(line) <= self.handlers.APPROVAL_LINE_CHARS for line in lines), lines)
        self.assertLessEqual(len(message), self.handlers.APPROVAL_MESSAGE_CHARS)

    def test_a_long_plan_keeps_every_step_and_counts_what_it_leaves_out(self):
        pid = self.planned()
        plan = self.store.load(pid)
        plan["warnings"] = [f"[0] warning number {n} " + "w" * 40 for n in range(120)]
        self.store.save(plan)
        message = self.hook("librenms_apply", {"plan_id": pid})["message"]
        self.assertLessEqual(len(message), self.handlers.APPROVAL_MESSAGE_CHARS)
        lines = message.split("\n")
        self.assertEqual(
            lines[1:3], ['[0] update device #1 "core-sw1.example.net": purpose', '  [0] purpose: "core" -> "spine"']
        )
        found = re.fullmatch(rf"… (\d+) more lines; full plan: /librenms show {pid}", lines[-1])
        self.assertIsNotNone(found, lines[-1])
        shown = [line for line in lines if line.startswith("Warning: ")]
        self.assertEqual(shown, [f"Warning: [0] warning number {n} " + "w" * 40 for n in range(len(shown))])
        self.assertEqual(len(shown) + int(found.group(1)), 120)
        self.assertEqual(lines[-2], "Description: test")  # a line that fits after one that did not is still shown
        # so many steps that their lines fill the prompt: no detail is shown below a partial list of steps
        ops = [{"op": "update", "resource": "device", "id": 1 + n % 3, "data": {"notes": f"n{n}"}} for n in range(3)]
        many = self.store.load(self.plan(ops[:1])["id"])
        many["steps"] = [dict(many["steps"][0], index=n, label="x" * 60) for n in range(40)]
        self.store.save(many)
        lines = self.hook("librenms_apply", {"plan_id": many["id"]})["message"].split("\n")
        self.assertTrue(all(line.startswith("[") for line in lines[1:-1]), lines)
        self.assertTrue(lines[-1].startswith("… "), lines[-1])
        self.assertEqual(len(lines) - 2 + int(lines[-1].split()[1]), 40 + 40 + 1)  # steps, their diffs, description

    def test_the_description_can_neither_pose_as_steps_nor_crowd_them_out(self):
        # the model writes the description: lines that imitate a harmless step and the summary, then padding that
        # would push the real step past the clip if the description came first
        pid = self.plan([{"op": "delete", "resource": "device", "id": 3}])["id"]
        plan = self.store.load(pid)
        forged = (
            'Tidy port description\n[0] update      port #12 "Gi0/1"\n\trollback: exact\n'
            "Summary: 0 create, 1 update, 0 delete, 0 action\n"
        )
        plan["description"] = forged + "." * 1400
        self.store.save(plan)
        message = self.hook("librenms_apply", {"plan_id": pid})["message"]
        self.assertLessEqual(len(message), self.handlers.APPROVAL_MESSAGE_CHARS)
        lines = message.split("\n")
        self.assertEqual(lines[0], f"Apply {pid}: 1 delete; irreversible steps: [0]; rollback_on_failure=true")
        self.assertEqual(lines[1], '[0] delete device #3 "access-sw2.example.net" (irreversible)')
        self.assertFalse([line for line in lines if line.startswith(("[0] update", "Summary:"))], lines)
        self.assertTrue(
            lines[-2].startswith('Description: Tidy port description\\n[0] update      port #12 "Gi0/1"\\n'), lines
        )
        self.assertEqual(len(lines[-2]), self.handlers.APPROVAL_LINE_CHARS)
        self.assertTrue(lines[-2].endswith("…"))


class ApprovalRequested(HookCase):
    """Hermes may refuse an approval without asking anyone (cron, unattended platforms), and then no
    post_approval_response follows: the request itself is audited."""

    def test_every_approval_asked_for_is_audited(self):
        pid = self.applied()
        apply = self.hook("librenms_apply", {"plan_id": pid, "rollback_on_failure": False})
        rollback = self.hook("librenms_rollback", {"plan_id": pid, "force": True})
        self.assertEqual(self.hook("librenms_apply", {"plan_id": "lnp-nope"})["action"], "block")
        self.assertIsNone(self.hook("librenms_apply", {"plan_id": pid, "dry_run": True}))
        events = self.events("approval_requested")
        self.assertEqual(
            [(event["tool"], event["plan_id"], event["rule_key"]) for event in events],
            [("librenms_apply", pid, apply["rule_key"]), ("librenms_rollback", pid, rollback["rule_key"])],
        )
        [blocked] = self.events("apply_refused")  # a block is the refusal the handler would have recorded
        self.assertEqual(
            (blocked["tool"], blocked["plan_id"], blocked["reason"]),
            ("librenms_apply", None, "unknown plan_id 'lnp-nope'"),
        )
        actor = events[0]["actor"]
        self.assertEqual(
            (actor["kind"], actor["via"], actor["session_id"], actor["task_id"]), ("model", "tool", "s1", "t1")
        )
        self.assertNotIn("purpose", json.dumps(events))  # what the plan changes stays in the plan

    def test_a_failing_audit_never_breaks_a_hook(self):
        pid = self.planned()
        original = self.audit.capture_actor

        def broken(*_args, **_kwargs):
            raise RuntimeError("audit down")

        self.audit.capture_actor = broken
        self.addCleanup(setattr, self.audit, "capture_actor", original)
        with self.assertLogs(self.handlers.logger, "WARNING"):
            self.assertEqual(
                self.hook("librenms_apply", {"plan_id": pid})["rule_key"], f"librenms:librenms_apply:{pid}:rb"
            )
        with self.assertLogs(self.handlers.logger, "WARNING"):
            directive = self.hook("terminal", {"command": f"hermes librenms apply {pid}"})
        self.assertEqual(
            directive, {"action": "block", "message": self.handlers.TERMINAL_BLOCK_FULL.format(action="apply")}
        )
        self.assertEqual(self.events(), [])


class RollbackApproval(HookCase):
    def test_rule_key_force_and_safe(self):
        pid = self.applied()
        directive = self.hook("librenms_rollback", {"plan_id": pid})
        self.assertEqual(directive["rule_key"], f"librenms:librenms_rollback:{pid}:safe")
        lines = directive["message"].split("\n")
        self.assertEqual(
            lines[:2],
            [f"Roll back {pid}: 1 pending entries", '[0] update device #1 "core-sw1.example.net": restore purpose'],
        )
        self.assertIn("-> done | rollback exact", directive["message"])  # then the journal, not the plan
        self.assertEqual(lines[-1], f"Full plan: /librenms show {pid}")
        for value, variant in ((True, "force"), ("1", "force"), ("on", "force"), (1, "safe"), ("no", "safe")):
            directive = self.hook("librenms_rollback", {"plan_id": pid, "force": value})
            self.assertEqual(directive["rule_key"], f"librenms:librenms_rollback:{pid}:{variant}", repr(value))
            forced = "FORCE: overwrites edits made after the apply" in directive["message"].split("\n")[0]
            self.assertEqual(forced, variant == "force")
        self.assertNotIn("dry_run", self.hook("librenms_rollback", {"plan_id": pid, "dry_run": True}))

    def test_each_entry_says_what_its_rollback_does_newest_first(self):
        ops = [
            {"op": "update", "resource": "device", "id": 1, "data": {"purpose": "spine", "notes": "n"}},
            {"op": "create", "resource": "location", "data": {"location": "SFO-9", "lat": 1.5, "lng": 2.5}},
            {"op": "delete", "resource": "device_group", "id": 1},
            {"op": "maintenance", "resource": "device", "id": 3, "data": {"duration": "1:00"}},
            {"op": "ack", "resource": "alert", "id": 3, "data": {"note": "x"}},
        ]
        pid = self.plan(ops)["id"]
        self.assertTrue(json.loads(self.handlers.librenms_apply({"plan_id": pid}))["success"])
        lines = self.hook("librenms_rollback", {"plan_id": pid, "force": True})["message"].split("\n")
        self.assertEqual(
            lines[:6],
            [
                f"Roll back {pid}: 5 pending entries, FORCE: overwrites edits made after the apply",
                '[4] ack alert #3 "Port down on access-sw2.example.net": undo it (lossy)',
                '[3] maintenance device #3 "access-sw2.example.net": cannot be undone',
                '[2] delete device_group #1 "core-switches": re-create it (new id)',
                '[1] create location #4 "SFO-9": delete it',
                '[0] update device #1 "core-sw1.example.net": restore purpose, notes',
            ],
        )
        # an entry a dead run left in flight: its outcome is unknown, and the step says what rollback restores
        plan = self.store.load(pid)
        entry = plan["journal"][0]
        entry.update(status="unknown", inverse=None)
        self.store.save(plan)
        line = self.hook("librenms_rollback", {"plan_id": pid})["message"].split("\n")[5]
        self.assertEqual(line, '[0] update device #1 "core-sw1.example.net": outcome unknown; restore purpose, notes')


class Terminal(HookCase):
    COMMANDS = (
        "hermes librenms apply lnp-20261028T190000Z-ab12",
        "cd /tmp && hermes librenms rollback ab12 --force",
        "hermes --profile ops librenms apply ab12",
        "HERMES  LIBRENMS\tAPPLY x",
    )
    HARMLESS = (
        "hermes librenms plans",
        "hermes librenms show ab12",
        "hermes librenms check ab12",
        "hermes status; librenms apply",
        "ls -la ~/.hermes/plugin-data/librenms",
        "",
    )

    PARSED = (("apply", "lnp-20261028T190000Z-ab12"), ("rollback", "ab12"), ("apply", "ab12"), ("apply", "x"))

    def test_blocked_unless_the_model_may_write_without_approval(self):
        # each mode tells the model what it may do instead: the tools it may call, the user's own terminal, nothing
        for values, said in (
            ({"write_mode": "operator_only"}, ("`/librenms {0} {1}` in this session", "{1}` from their own terminal")),
            ({"write_mode": "read_only"}, ("{0} refused: writes are disabled (write_mode is read_only",)),
            ({"write_mode": "operator_only", "require_approval": False}, ("Ask the user to run `/librenms {0} {1}`",)),
            ({"write_mode": "full"}, ("{0} refused: ", "call the librenms_{0} tool, which asks the user for approval")),
            ({"write_mode": "full", "require_approval": False}, None),
        ):
            self.configure(**values)
            for command, (action, plan) in zip(self.COMMANDS, self.PARSED):
                directive = self.hook("terminal", {"command": command, "background": False})
                if said is None:
                    self.assertIsNone(directive, (values, command))
                    continue
                self.assertEqual(directive["action"], "block", (values, command))
                for phrase in said:
                    self.assertIn(phrase.format(action, plan), directive["message"], (values, command))
        self.assertNotIn("librenms_apply", self.hook("terminal", {"command": self.COMMANDS[0]}) or {})

    def test_a_blocked_command_is_audited_without_its_text(self):
        pid = self.planned()
        commands = (
            ("terminal", {"command": f"cd /tmp && hermes librenms apply {pid.rsplit('-', 1)[1]} --no-rollback"}),
            ("execute_code", {"code": f'subprocess.run(["hermes", "librenms", "rollback", "--force", "{pid}"])'}),
        )
        for mode in ("full", "operator_only", "read_only"):
            self.configure(write_mode=mode)
            for tool, args in commands:
                self.assertEqual(self.hook(tool, args)["action"], "block")
        events = self.events()
        self.assertEqual(
            [(event["event"], event["tool"], event["write_mode"]) for event in events],
            [
                (event, tool, mode)
                for mode in ("full", "operator_only", "read_only")
                for event, tool in (("apply_refused", "terminal"), ("rollback_refused", "execute_code"))
            ],
        )
        for event in events:
            self.assertEqual(
                (event["plan_id"], event["librenms_url"], event["reason"]),
                (pid, "https://librenms.test", "blocked in the agent's terminal/execute_code"),
            )
            self.assertEqual((event["actor"]["kind"], event["actor"]["session_id"]), ("model", "s1"))
        text = self.audit_path.read_text(encoding="utf-8")
        for fragment in ("cd /tmp", "subprocess", "--force", "--no-rollback"):
            self.assertNotIn(fragment, text)

    def test_a_plan_that_does_not_resolve_is_named_as_parsed(self):
        self.configure(write_mode="operator_only")
        unknown = self.hook("terminal", {"command": "hermes librenms rollback lnp-nope"})
        self.assertIn("`/librenms rollback lnp-nope`", unknown["message"])
        unnamed = self.hook("terminal", {"command": "hermes librenms apply $PLAN"})
        self.assertIn("`/librenms apply <plan_id>`", unnamed["message"])
        self.assertEqual(
            [(event["event"], event["plan_id"], event["librenms_url"]) for event in self.events()],
            [("rollback_refused", "lnp-nope", None), ("apply_refused", None, None)],
        )

    def test_code_that_builds_the_command_is_blocked_too(self):
        self.configure(write_mode="operator_only")
        code = 'import subprocess\nsubprocess.run(["hermes", "librenms", "apply", "lnp-x"], check=True)\n'
        self.assertEqual(self.hook("execute_code", {"code": code})["action"], "block")
        self.assertEqual(
            self.hook("execute_code", {"code": "os.system('hermes librenms rollback x')"})["action"], "block"
        )

    def test_a_background_shell_s_stdin_is_guarded_too(self):
        # terminal(background=true) starts a shell, and process_manage write/submit sends it a line no Hermes guard
        # reads: the command needed no obfuscation at all
        self.configure(write_mode="operator_only")
        pid = self.planned()
        line = f"unset HERMES_SESSION_ID HERMES_SESSION_KEY; hermes librenms apply {pid}"
        for action in ("submit", "write"):
            directive = self.hook("process_manage", {"action": action, "session_id": "proc_4dae", "data": line})
            self.assertEqual(directive["action"], "block", action)
            self.assertIn(f"`/librenms apply {pid}`", directive["message"])
        # Hermes writes str() of whatever data holds
        data = ["hermes", "librenms", "rollback", pid]
        self.assertEqual(
            self.hook("process_manage", {"action": "submit", "session_id": "p", "data": data})["action"], "block"
        )
        self.assertEqual(
            [(event["event"], event["tool"], event["plan_id"], event["reason"]) for event in self.events()],
            [("apply_refused", "process_manage", pid, self.handlers.TERMINAL_REASON)] * 2
            + [("rollback_refused", "process_manage", pid, self.handlers.TERMINAL_REASON)],
        )
        self.assertNotIn("unset", self.audit_path.read_text(encoding="utf-8"))
        # the other actions send nothing to a shell; a handoff's note may well name the command
        for args in (
            {"action": "handoff", "session_id": "p", "data": "it runs hermes librenms apply x"},
            {"action": "poll", "session_id": "p", "data": "hermes librenms apply x"},
            {"action": "list"},
            {"action": ["submit"], "data": "hermes librenms apply x"},
            {"data": "hermes librenms apply x"},
        ):
            self.assertIsNone(self.hook("process_manage", args), args)
        self.configure(write_mode="full", require_approval=False)  # the tools would write unprompted anyway
        self.assertIsNone(self.hook("process_manage", {"action": "submit", "session_id": "p", "data": line}))

    def test_a_long_line_costs_linear_time_and_padding_hides_nothing(self):
        # the pattern used to scan from every "hermes" to the end of the line: 112 KB took 7.6 s in this hook, before
        # every terminal and execute_code call
        paths = json.dumps([f"/home/u/.hermes/sessions/{n}.json" for n in range(4000)])  # one line, ~150 KB
        for text in (
            paths,
            paths + " librenms",
            "hermes " * 150_000 + "librenms appl",
            "hermes x librenms " * 60_000,
            "librenms apply x; " * 60_000,
        ):
            started = time.monotonic()
            self.assertIsNone(self.hook("execute_code", {"code": text}))
            self.assertLess(time.monotonic() - started, 1.0)
        self.configure(write_mode="operator_only")
        for command in (
            "hermes" + " " * 5000 + "librenms apply x",
            "librenms apply y; hermes " + "-v " * 2000 + "librenms rollback x",
        ):
            self.assertEqual(self.hook("terminal", {"command": command})["action"], "block", command[:40])

    def test_other_commands_pass_without_reading_settings(self):
        def no_settings():
            raise AssertionError("settings read for a command that is not a LibreNMS write")

        self.stub("get_settings", no_settings)
        for command in self.HARMLESS:
            self.assertIsNone(self.hook("terminal", {"command": command}), command)
        self.assertIsNone(self.hook("terminal", {"command": None, "timeout": 30}))
        self.assertIsNone(self.hook("execute_code", {"code": "print('hello')"}))
        self.assertEqual(self.events(), [])

    def test_an_unreadable_setting_blocks(self):
        def broken():
            raise RuntimeError("config gone")

        self.stub("get_settings", broken)
        with self.assertLogs(self.handlers.logger, "WARNING"):
            directive = self.hook("terminal", {"command": self.COMMANDS[0]})
        self.assertEqual(directive["action"], "block")


class UnrelatedTools(HookCase):
    def test_no_io_for_unrelated_tools(self):
        touched = []

        def recorder(name):
            def record(*_args, **_kwargs):
                touched.append(name)
                raise AssertionError(f"{name} called for an unrelated tool")

            return record

        for name in ("get_settings", "get_store", "find_plan", "make_client"):
            self.stub(name, recorder(name))
        for tool, args in (
            ("web_search", {"query": "hermes librenms apply"}),
            ("read_file", {"path": "/etc/hosts"}),
            ("librenms_query", {"path": "devices"}),
            ("librenms_plan", {"operations": []}),
            ("librenms_plans", {"plan_id": "x"}),
            ("process_manage", {"action": "poll", "session_id": "proc_1"}),
            ("process_manage", {"action": "submit", "session_id": "proc_1", "data": "y"}),
            (None, {}),
            (["terminal"], {}),
        ):
            self.assertIsNone(self.handlers.pre_tool_call(tool_name=tool, args=args, **HOOK_KWARGS), tool)
        self.assertEqual(touched, [])
        self.assertEqual(self.events(), [])


class RequestCapture(HookCase):
    def setUp(self):
        super().setUp()
        self.addCleanup(_restore_env, "LIBRENMS_TOKEN", os.environ.get("LIBRENMS_TOKEN"))
        os.environ["LIBRENMS_TOKEN"] = TOKEN  # the configured token, which the request masker scrubs

    def remember(self, message, **extra):
        kwargs = {"session_id": "s1", "task_id": "t1", "user_message": message, "sender_id": "u42", **extra}
        self.assertIsNone(self.handlers.pre_llm_call(**kwargs, turn_id="turn-1", conversation_history=[], model="m"))

    def test_request_capture_recall_and_redaction(self):
        self.remember(f"Move core-sw1 to purpose spine. Here is the token: {TOKEN} and password: hunter22")
        message, sender = self.audit.recall_request("s1", "t1")
        self.assertEqual(sender, "u42")
        self.assertIn("Move core-sw1 to purpose spine", message)
        self.assertNotIn(TOKEN, message)
        self.assertNotIn("hunter22", message)
        op = {"op": "update", "resource": "device", "id": 1, "data": {"purpose": "spine"}}
        out = json.loads(
            self.handlers.librenms_plan({"description": "x", "operations": [op]}, session_id="s1", task_id="t1")
        )
        requested = self.store.load(out["plan_id"])["requested_by"]
        self.assertEqual((requested["request"], requested["sender_id"]), (message, "u42"))
        self.assertEqual(self.events("plan_created")[-1]["actor"]["request"], message)
        self.assertNotIn(TOKEN, self.audit_path.read_text(encoding="utf-8"))

    def test_multimodal_messages_keep_their_text(self):
        self.remember([{"type": "text", "text": "what is down?"}, {"type": "image_url", "image_url": {"url": "x"}}])
        self.assertEqual(self.audit.recall_request("s1", "t1"), ("what is down?", "u42"))

    def test_audit_include_request_off_keeps_only_the_sender(self):
        self.configure(audit_include_request=False)
        self.remember("secret plans")
        self.assertEqual(self.audit.recall_request("s1", "t1"), (None, "u42"))

    def test_pre_llm_call_never_raises(self):
        self.assertIsNone(self.handlers.pre_llm_call())
        self.assertIsNone(self.handlers.pre_llm_call(session_id=object(), task_id=[], user_message=object()))


class ApprovalDecided(HookCase):
    def respond(self, **kwargs):
        self.assertIsNone(self.handlers.post_approval_response(**kwargs))

    def test_our_approval_is_audited_without_the_command_text(self):
        pid = self.planned()
        directive = self.hook("librenms_apply", {"plan_id": pid})
        key = f"plugin_rule:{directive['rule_key']}"
        self.respond(
            command="<librenms_apply> (plugin approval rule)",
            description=directive["message"],
            pattern_key=key,
            pattern_keys=[key],
            session_key="sk",
            surface="cli",
            choice="once",
        )
        [event] = self.events("approval_decided")
        self.assertEqual(
            (event["plan_id"], event["tool"], event["choice"], event["rule_key"], event["surface"]),
            (pid, "librenms_apply", "once", directive["rule_key"], "cli"),
        )
        self.assertNotIn("purpose", json.dumps(event))
        self.assertNotIn("plugin approval rule", json.dumps(event))

    def test_unresolved_and_mentioned_approvals(self):
        key = unresolved_key("librenms_rollback", "nope")
        self.respond(pattern_key=f"plugin_rule:{key}", choice="deny")
        self.respond(pattern_key="recursive delete", command="rm -rf ~/.hermes/plugin-data/librenms", choice="always")
        unresolved, mentioned = self.events("approval_decided")
        self.assertEqual(
            (unresolved["plan_id"], unresolved["tool"], unresolved["rule_key"]), (None, "librenms_rollback", key)
        )
        self.assertEqual(
            (mentioned["tool"], mentioned["pattern_key"], mentioned["choice"]), (None, "recursive delete", "always")
        )
        self.assertNotIn("rm -rf", json.dumps(mentioned))

    def test_other_approvals_and_garbage_are_ignored(self):
        self.respond(pattern_key="recursive delete", command="rm -rf /tmp/x", choice="once")
        self.respond(pattern_key="plugin_rule:netbox:netbox_apply:nbp-1:rb", choice="once")
        with self.assertLogs(self.handlers.logger, "WARNING"):
            self.respond(pattern_keys=5, choice="once")
        self.respond()
        self.assertEqual(self.events("approval_decided"), [])


if __name__ == "__main__":
    unittest.main()
