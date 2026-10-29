"""The hook callbacks (design §16.8, §16.9): the approval directive for librenms_apply / librenms_rollback (dry_run
parsing, rule keys per plan and variant, unresolved plans, failing closed, escaping and clipping of the message), the
terminal guard against ``hermes librenms apply|rollback``, no work for unrelated tools, the request cache behind
``pre_llm_call``, and ``approval_decided`` from ``post_approval_response``."""

import hashlib
import json
import os
import re
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
        lines = directive["message"].split("\n")
        self.assertEqual(
            lines[0],
            f"Apply LibreNMS plan {pid} to https://librenms.test: 0 create, 1 update, 0 delete, 0 action; "
            "irreversible steps []; rollback_on_failure=true",
        )
        self.assertTrue(lines[1].startswith(f"Plan {pid} (planned)"))
        self.assertIn('purpose: "core" -> "spine"', directive["message"])
        for value, variant in ((False, "norb"), ("no", "norb"), ("off", "norb"), (True, "rb"), ("maybe", "rb")):
            directive = self.hook("librenms_apply", {"plan_id": pid, "rollback_on_failure": value})
            self.assertEqual(directive["rule_key"], f"librenms:librenms_apply:{pid}:{variant}", repr(value))
            self.assertIn(f"rollback_on_failure={'true' if variant == 'rb' else 'false'}", directive["message"])

    def test_a_fragment_is_resolved_to_the_canonical_id(self):
        pid = self.planned()
        for raw in (pid.rsplit("-", 1)[1], f"  {pid} "):
            directive = self.hook("librenms_apply", {"plan_id": raw})
            self.assertEqual(directive["rule_key"], f"librenms:librenms_apply:{pid}:rb")
            self.assertIn(f"Apply LibreNMS plan {pid} ", directive["message"])

    def test_irreversible_steps_are_named_in_the_header(self):
        op = {"op": "maintenance", "resource": "device", "id": 1, "data": {"duration": "1:00"}}
        pid = self.plan([op])["id"]
        header = self.hook("librenms_apply", {"plan_id": pid})["message"].split("\n")[0]
        self.assertIn("0 create, 0 update, 0 delete, 1 action; irreversible steps [0]", header)

    def test_unresolved_plan_still_asks(self):
        for raw in ("lnp-nope", "", "../../etc/passwd"):
            directive = self.hook("librenms_apply", {"plan_id": raw})
            self.assertEqual(directive["action"], "approve")
            self.assertEqual(directive["rule_key"], unresolved_key("librenms_apply", raw))
            self.assertIn("not found locally", directive["message"])
        self.planned()
        self.planned("edge")
        ambiguous = self.hook("librenms_rollback", {"plan_id": "lnp-"})  # matches both: not resolved
        self.assertEqual(ambiguous["rule_key"], unresolved_key("librenms_rollback", "lnp-"))
        hostile = "x\x1b]0;owned\x07" + "y" * 200
        directive = self.hook("librenms_apply", {"plan_id": hostile})
        self.assertNotIn("\x1b", directive["message"])
        self.assertIn("\\x1b]0;owned\\x07", directive["message"])
        self.assertNotIn("y" * 81, directive["message"])
        self.assertEqual(directive["rule_key"], unresolved_key("librenms_apply", hostile))

    def test_fail_closed_on_exception(self):
        pid = self.planned()

        def broken_store():
            raise OSError("disk on fire")

        self.stub("get_store", broken_store)
        with self.assertLogs(self.handlers.logger, "WARNING"):
            directive = self.hook("librenms_apply", {"plan_id": pid})
        self.assertEqual(directive["action"], "approve")
        self.assertEqual(directive["rule_key"], unresolved_key("librenms_apply", pid))
        self.assertRegex(
            directive["message"],
            rf"^Approve librenms_apply for plan {pid}\? Plan details could not be loaded \(err-[0-9a-f]{{12}}\)\.$",
        )
        self.assertNotIn("disk on fire", directive["message"])
        # arguments that are not an object at all
        with self.assertLogs(self.handlers.logger, "WARNING"):
            directive = self.hook("librenms_rollback", ["plan_id", pid])
        self.assertEqual(directive["rule_key"], unresolved_key("librenms_rollback", ""))

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

    def test_a_long_plan_is_clipped_to_whole_lines(self):
        pid = self.planned()
        plan = self.store.load(pid)
        plan["warnings"] = [f"[0] warning number {n} " + "w" * 40 for n in range(120)]
        self.store.save(plan)
        message = self.hook("librenms_apply", {"plan_id": pid})["message"]
        self.assertLessEqual(len(message), self.handlers.APPROVAL_MESSAGE_CHARS)
        lines = message.split("\n")
        self.assertTrue(lines[0].startswith(f"Apply LibreNMS plan {pid} "))
        found = re.fullmatch(rf"… (\d+) more lines; run /librenms show {pid}", lines[-1])
        self.assertIsNotNone(found, lines[-1])
        body = self.planner.render_plan({**self.store.load(pid), "description": ""}).split("\n") + ["Description: test"]
        self.assertEqual(lines[1:-1], body[: len(lines) - 2])
        self.assertEqual(len(lines) - 2 + int(found.group(1)), len(body))
        # a short one is not clipped
        short = self.handlers._approval_message("head", "a\nb", pid)
        self.assertEqual(short, "head\na\nb")

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
        self.assertEqual(lines[1], f"Plan {pid} (planned)")
        self.assertTrue(lines[4].startswith('[0] delete      device #3 "access-sw2.example.net"'), lines[4])
        self.assertTrue(any(line.startswith("Summary: 0 create, 0 update, 1 delete") for line in lines), lines)
        self.assertFalse([line for line in lines if line.startswith(("[0] update", "Summary: 0 create, 1 update"))])
        self.assertTrue(lines[-1].startswith("… 1 more lines; run /librenms show"), lines[-1])  # the description
        plan["description"] = forged
        self.store.save(plan)
        last = self.hook("librenms_apply", {"plan_id": pid})["message"].split("\n")[-1]
        self.assertEqual(
            last,
            'Description: Tidy port description\\n[0] update      port #12 "Gi0/1"\\n\\trollback: exact\\n'
            "Summary: 0 create, 1 update, 0 delete, 0 action\\n",
        )


class ApprovalRequested(HookCase):
    """Hermes may refuse an approval without asking anyone (cron, unattended platforms), and then no
    post_approval_response follows: the request itself is audited."""

    def test_every_approval_asked_for_is_audited(self):
        pid = self.applied()
        apply = self.hook("librenms_apply", {"plan_id": pid, "rollback_on_failure": False})
        rollback = self.hook("librenms_rollback", {"plan_id": pid, "force": True})
        unresolved = self.hook("librenms_apply", {"plan_id": "lnp-nope"})
        self.assertIsNone(self.hook("librenms_apply", {"plan_id": pid, "dry_run": True}))
        events = self.events("approval_requested")
        self.assertEqual(
            [(event["tool"], event["plan_id"], event["rule_key"]) for event in events],
            [
                ("librenms_apply", pid, apply["rule_key"]),
                ("librenms_rollback", pid, rollback["rule_key"]),
                ("librenms_apply", None, unresolved["rule_key"]),
            ],
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
        self.assertEqual(lines[0], f"Roll back LibreNMS plan {pid} (1 pending entries)")
        self.assertIn("-> done", directive["message"])  # the journal, not the plan
        for value, variant in ((True, "force"), ("1", "force"), ("on", "force"), (1, "safe"), ("no", "safe")):
            directive = self.hook("librenms_rollback", {"plan_id": pid, "force": value})
            self.assertEqual(directive["rule_key"], f"librenms:librenms_rollback:{pid}:{variant}", repr(value))
            forced = "FORCE: overwrites edits made after the apply" in directive["message"].split("\n")[0]
            self.assertEqual(forced, variant == "force")
        self.assertNotIn("dry_run", self.hook("librenms_rollback", {"plan_id": pid, "dry_run": True}))


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
