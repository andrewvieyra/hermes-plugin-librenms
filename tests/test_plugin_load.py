"""``register(ctx)``: against a hand-written context everywhere, and through Hermes' real ``PluginManager`` when a
Hermes checkout is importable (set ``HERMES_AGENT_ROOT``, or run where ``hermes_cli`` imports).
"""

import importlib.util
import json
import os
import shutil
import sys
import tempfile
import types
import unittest
from pathlib import Path

from .base import PluginTestCase, _restore_env
from .fake_librenms import TOKEN, seeded
from .helpers import load_plugin, submodule

REPO_ROOT = Path(__file__).resolve().parents[1]
TOOLS = ("librenms_query", "librenms_report", "librenms_plan", "librenms_apply", "librenms_rollback", "librenms_plans")
HOOKS = ("pre_tool_call", "pre_tool_call", "pre_llm_call", "post_approval_response")
SKILLS = {"workflow": REPO_ROOT / "SKILL.md", "ask": REPO_ROOT / "skills" / "ask" / "SKILL.md"}
ENV = {"LIBRENMS_URL": "https://librenms.test", "LIBRENMS_TOKEN": "0123456789abcdef"}


class FakeContext:
    """The ``PluginContext`` surface ``register`` uses, recording every call. ``old=True`` is a Hermes that predates
    CLI, skill and blueprint registration; ``hookless=True`` one that cannot take hooks."""

    def __init__(self, config=None, *, old=False, hookless=False):
        self.config = dict(config or {})
        self.old = old
        self.hookless = hookless
        self.tools = {}
        self.commands = {}
        self.cli = []
        self.skills = []
        self.hooks = []
        self.blueprints = []

    def get_config(self, key, default=None):
        return self.config.get(key, default)

    def register_tool(self, **kwargs):
        self.tools[kwargs["name"]] = kwargs

    def register_command(self, name, **kwargs):
        self.commands[name] = kwargs

    def register_hook(self, name, callback):
        if self.hookless:
            raise AttributeError("'PluginContext' object has no attribute 'register_hook'")
        self.hooks.append((name, callback))

    def register_cli_command(self, **kwargs):
        if self.old:
            raise AttributeError("'PluginContext' object has no attribute 'register_cli_command'")
        self.cli.append(kwargs)

    def register_skill(self, name, path, **kwargs):
        if self.old:
            raise AttributeError("'PluginContext' object has no attribute 'register_skill'")
        self.skills.append((name, Path(path), kwargs))

    def register_automation_blueprint(self, key, **kwargs):
        if self.old:
            raise AttributeError("'PluginContext' object has no attribute 'register_automation_blueprint'")
        self.blueprints.append((key, kwargs))
        return "registration"


class _Worker:
    closed = False

    def close(self, _timeout):
        self.closed = True


class RegisterWithAFakeContext(PluginTestCase):
    def setUp(self):
        super().setUp()
        self.plugin = load_plugin()
        self.commands = submodule("commands")
        self.sinks = submodule("sinks")
        self.clients = []
        self.handlers.set_client_factory(lambda: self.clients.append(1) or self.client)
        for name in ENV:
            self.addCleanup(_restore_env, name, os.environ.get(name))

    def register(self, ctx):
        self.plugin.register(ctx)
        self.audit.set_audit_log(self.audit.AuditLog(self.audit_path))  # keep any event out of the profile
        return ctx

    def plugin_dir(self, path):
        original = self.plugin._PLUGIN_DIR
        self.plugin._PLUGIN_DIR = path
        self.addCleanup(setattr, self.plugin, "_PLUGIN_DIR", original)

    def test_every_tool_hook_command_cli_and_both_skills_are_registered(self):
        self.plugin_dir(REPO_ROOT)  # the checkout's skills, also after the real-loader test removed its copy
        ctx = self.register(FakeContext())
        schemas = submodule("schemas")
        self.assertEqual(tuple(ctx.tools), TOOLS)
        self.assertEqual([schema["name"] for schema in schemas.ALL], list(TOOLS))
        for schema in schemas.ALL:
            tool = ctx.tools[schema["name"]]
            self.assertEqual(
                (tool["toolset"], tool["schema"], tool["handler"], tool["requires_env"]),
                ("librenms", schema, self.handlers.HANDLERS[schema["name"]], ["LIBRENMS_URL", "LIBRENMS_TOKEN"]),
            )
            self.assertTrue(tool["emoji"])
            self.assertTrue(schema["description"].startswith(tool["description"]))
            write = schema["name"] in self.handlers.WRITE_TOOLS
            expected = self.handlers.check_write_requirements if write else self.handlers.check_requirements
            self.assertIs(tool["check_fn"], expected)
        self.assertEqual(ctx.hooks, list(self.handlers.HOOKS))
        self.assertEqual([name for name, _callback in ctx.hooks], list(HOOKS))
        # the approval prompt's callback first, then the one handing its handler what the prompt showed
        self.assertEqual(
            ctx.hooks[:2],
            [("pre_tool_call", self.handlers.pre_tool_call), ("pre_tool_call", self.handlers.bind_approval)],
        )
        command = ctx.commands["librenms"]
        self.assertIs(command["handler"], self.commands.slash_handler)
        for word in ("status", "plans", "show", "check", "apply", "rollback", "prune"):
            self.assertIn(word, command["args_hint"])
        [cli] = ctx.cli
        self.assertEqual(cli["name"], "librenms")
        self.assertIs(cli["setup_fn"], self.commands.setup_cli)
        self.assertIs(cli["handler_fn"], self.commands.cli_handler)
        self.assertEqual([(name, path) for name, path, _options in ctx.skills], list(SKILLS.items()))
        for name, _path, options in ctx.skills:
            # no requires_toolsets: under Hermes' tool search the tools are deferred and such a gate hid the skill
            self.assertEqual(options.get("frontmatter") or {}, {}, name)
        # what Hermes lists in <available_skills>: when to load each
        workflow, ask = (options["description"] for _name, _path, options in ctx.skills)
        self.assertIn("changes", workflow)
        for subject in ("questions", "down", "ports", "utilisation", "link speeds", "MAC", "alerts", "follow-ups"):
            self.assertIn(subject, ask)
        self.assertEqual(ctx.blueprints, [("network-digest", submodule("digest").BLUEPRINT)])
        self.assertEqual((self.clients, self.fake.calls), ([], []))  # registration makes no client, so no I/O

    def test_schemas_fit_the_budget(self):
        schemas = submodule("schemas")
        self.assertLessEqual(len(json.dumps(schemas.ALL)), 16 * 1024)
        for schema in schemas.ALL:
            self.assertFalse(schema["parameters"]["additionalProperties"], schema["name"])

    def test_settings_come_from_the_context_and_reset_the_audit_log_and_sinks(self):
        self.settings_mod.set_settings(None)  # unpinned, as in production
        worker = _Worker()
        self.sinks.set_worker(worker)
        config = {
            "write_mode": "Read_Only",
            "allow_delete": "yes",
            "max_operations": "7",
            "audit_log_path": "/var/log/hermes/LibreNMS.jsonl",
            "audit_sinks": [{"type": "syslog", "host": "hermes-01"}],
        }
        self.plugin.register(FakeContext(config))
        settings = self.settings_mod.get_settings()
        self.assertEqual(
            (settings.write_mode, settings.allow_delete, settings.max_operations, len(settings.audit_sinks)),
            ("read_only", True, 7, 1),
        )
        self.assertEqual(self.audit.get_audit_log().path, Path("/var/log/hermes/LibreNMS.jsonl"))  # case kept
        self.assertTrue(worker.closed)
        self.audit.set_audit_log(self.audit.AuditLog(self.audit_path))
        os.environ.update(ENV)
        ctx = self.register(FakeContext(config))
        shown = {name for name, tool in ctx.tools.items() if tool["check_fn"]()}
        self.assertEqual(shown, set(TOOLS) - set(self.handlers.WRITE_TOOLS))  # read_only hides the write tools
        ctx.config["write_mode"] = "operator_only"  # read live: no re-registration
        self.assertEqual({name for name, tool in ctx.tools.items() if tool["check_fn"]()}, set(TOOLS))
        os.environ["LIBRENMS_TOKEN"] = ""
        self.assertFalse(any(tool["check_fn"]() for tool in ctx.tools.values()))

    def test_every_setting_that_fell_back_is_logged_once(self):
        self.settings_mod.set_settings(None)
        config = {"write_mode": "yolo", "allow_delete": ["true"], "audit_sinks": ["syslog://x"]}
        with self.assertLogs(self.plugin.logger, "WARNING") as logs:
            self.register(FakeContext(config))
        errors = self.settings_mod.get_settings().errors
        self.assertEqual(len(errors), 3)
        self.assertEqual([record.getMessage() for record in logs.records], [f"librenms settings: {e}" for e in errors])
        self.assertIn("write_mode: expected one of full, operator_only, read_only, got 'yolo'; using read_only", errors)
        with self.assertNoLogs(self.plugin.logger, "WARNING"):
            self.register(FakeContext({"write_mode": "operator_only"}))

    def test_a_sink_credential_written_into_config_yaml_is_logged_without_its_value(self):
        self.settings_mod.set_settings(None)
        for name in ("hermes_cli", "hermes_cli.config"):  # outside Hermes the settings are what config.yaml holds
            self.addCleanup(_restore_module, name, sys.modules.get(name))
            sys.modules[name] = None
        sink = {"type": "http", "url": "https://hec.example.com", "headers": {"Authorization": "Splunk 3f2a9c1e"}}
        with self.assertLogs(self.plugin.logger, "WARNING") as logs:
            self.register(FakeContext({"audit_sinks": [sink]}))
        [message] = [record.getMessage() for record in logs.records]
        self.assertTrue(message.startswith("librenms settings: audit_sinks[0] header Authorization holds a credential"))
        self.assertNotIn("3f2a9c1e", message)

    def test_an_older_hermes_without_cli_or_skill_registration_still_loads(self):
        self.plugin_dir(REPO_ROOT)
        ctx = self.register(FakeContext(old=True))
        self.assertEqual(len(ctx.tools), 6)
        self.assertIn("librenms", ctx.commands)
        self.assertEqual((ctx.cli, ctx.skills, ctx.blueprints, len(ctx.hooks)), ([], [], [], 4))

    def test_a_hermes_that_cannot_take_the_hooks_fails_the_load(self):
        # without pre_tool_call nothing would ask before apply or rollback; better no plugin than that
        with self.assertRaises(AttributeError):
            self.register(FakeContext(hookless=True))

    def test_a_skill_hermes_refuses_leaves_the_other(self):
        class Refusing(FakeContext):
            def register_skill(self, name, path, **kwargs):
                if name == "workflow":
                    raise ValueError("Plugin skill 'librenms:workflow' is already registered")
                super().register_skill(name, path, **kwargs)

        self.plugin_dir(REPO_ROOT)
        ctx = self.register(Refusing())
        self.assertEqual([name for name, _path, _options in ctx.skills], ["ask"])

    def test_without_skill_md_no_skill_is_registered(self):
        with tempfile.TemporaryDirectory() as empty:
            self.plugin_dir(Path(empty))
            ctx = self.register(FakeContext())
        self.assertEqual(ctx.skills, [])
        self.assertEqual(len(ctx.tools), 6)


def _hermes_importable() -> bool:
    """Put the Hermes checkout first on ``sys.path``, as its launcher does: an editable install can expose
    ``hermes_cli`` without the checkout's top-level modules (``hermes_yaml`` ...), which then fail to import."""
    root = os.environ.get("HERMES_AGENT_ROOT")
    if not root:
        spec = importlib.util.find_spec("hermes_cli")
        if spec is None or not spec.origin:
            return False
        root = str(Path(spec.origin).resolve().parents[1])
    if root not in sys.path:
        sys.path.insert(0, root)
    return importlib.util.find_spec("hermes_cli") is not None


@unittest.skipUnless(_hermes_importable(), "hermes_cli not importable (set HERMES_AGENT_ROOT)")
class LoadThroughPluginManager(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.home = Path(self.tmp) / "hermes-home"
        (self.home / "plugins").mkdir(parents=True)
        shutil.copytree(
            REPO_ROOT,
            self.home / "plugins" / "librenms",
            ignore=shutil.ignore_patterns("tests", ".git", "__pycache__", ".github", ".ruff_cache", ".claude"),
        )
        (self.home / "config.yaml").write_text(
            "plugins:\n  enabled: [librenms]\n  entries:\n    librenms:\n      settings:\n        allow_delete: true\n"
            "        max_operations: 7\n        max_query_results: lots\n        audit_log: false\n"
            "        audit_sinks:\n          - type: http\n            url: https://hec.example.com/services/collector\n"
            '            headers: {Authorization: "Splunk ${HEC_TEST_SECRET}", X-Splunk-Token: literal-in-config}\n'
        )
        self._env = dict(os.environ)
        # Hermes loads the copy as hermes_plugins.librenms, replacing the modules every other test module bound
        # when it was imported; put them back, or those tests set settings on modules the handlers never read
        self._modules = {k: v for k, v in sys.modules.items() if k.split(".")[0] == "hermes_plugins"}
        os.environ["HERMES_HOME"] = str(self.home)
        os.environ.update(ENV, HEC_TEST_SECRET="hec-from-env")  # Hermes expands it in the settings
        for name in ("HERMES_SESSION_ID", "HERMES_SESSION_KEY"):
            os.environ.pop(name, None)
        self.mgr = None
        self.discovered = False

    def tearDown(self):
        if self.mgr is not None:
            self.mgr.unload("librenms")  # the tool registry is process-wide
        if self.discovered:  # the profile's own manager loaded every enabled and bundled plugin: unload them all
            from hermes_cli import plugins

            plugins._reset_plugin_managers_for_tests()
        os.environ.clear()
        os.environ.update(self._env)
        for name in [k for k in sys.modules if k.split(".")[0] == "hermes_plugins"]:
            del sys.modules[name]
        sys.modules.update(self._modules)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_registration_through_real_loader(self):
        from hermes_cli.plugins import PluginManager
        from tools.registry import registry

        self.mgr = mgr = PluginManager()
        with self.assertLogs("hermes_plugins.librenms", "WARNING") as logs:
            mgr.discover_and_load()
        fell_back = "max_query_results: expected a whole number of 1 or more, got 'lots'; using 500"
        self.assertEqual(logs.output[0], f"WARNING:hermes_plugins.librenms:librenms settings: {fell_back}")
        # config.yaml as written decides: the expanded placeholder is no literal, the X-Splunk-Token header is
        [literal] = logs.output[1:]
        self.assertIn("librenms settings: audit_sinks[0] header X-Splunk-Token holds a credential written", literal)
        self.assertNotIn("literal-in-config", literal)
        loaded = {p["name"]: p for p in mgr.list_plugins()}
        self.assertIn("librenms", loaded, loaded)
        self.assertIsNone(loaded["librenms"]["error"])
        self.assertEqual((loaded["librenms"]["tools"], loaded["librenms"]["hooks"]), (6, 4))
        self.assertGreaterEqual(loaded["librenms"]["commands"], 1)
        for name in TOOLS:
            self.assertIsNotNone(registry.get_schema(name), name)
            self.assertEqual(registry.get_toolset_for_tool(name), "librenms")
        for name in SKILLS:
            self.assertIsNotNone(mgr.find_plugin_skill(f"librenms:{name}"), name)
            [skill] = [s for s in mgr.list_plugin_skill_metadata() if s["name"] == f"librenms:{name}"]
            self.assertEqual(skill["frontmatter"], {})
        # Hermes validated the digest blueprint at load (it fills one whose blanks all have defaults) and kept it
        self.assertEqual([bp.key for bp in mgr.list_automation_blueprints()], ["librenms:network-digest"])

        # settings flowed from config.yaml into the plugin, and the bad one fell back
        mod = sys.modules["hermes_plugins.librenms"]
        settings = mod.settings.get_settings()
        self.assertEqual((settings.max_operations, settings.allow_delete), (7, True))
        self.assertEqual(settings.audit_sinks[0]["headers"]["Authorization"], "Splunk hec-from-env")
        self.assertEqual(settings.max_query_results, 500)
        self.assertEqual(len(settings.errors), 1)

        # a dispatched call goes through the registry and comes back as structured JSON (no LibreNMS needed)
        out = json.loads(registry.dispatch("librenms_plans", {}))
        self.assertTrue(out["success"])
        self.assertEqual(out["count"], 0)

        # the approval hooks as Hermes invokes them: ours blocks an unknown plan with the handler's refusal (and hands
        # the handler no prompt), and stays out of other tools
        directives = mgr.invoke_hook(
            "pre_tool_call", tool_name="librenms_apply", args={"plan_id": "lnp-nope"}, task_id="t", session_id="s"
        )
        self.assertEqual(
            directives,
            [
                {"action": "block", "message": "unknown plan_id 'lnp-nope'"},
                {"action": "modify", "args": {"_librenms_approval": None}},
            ],
        )
        self.assertEqual(mgr.invoke_hook("pre_tool_call", tool_name="web_search", args={"query": "x"}), [])

        # the shell guard as Hermes invokes it: a secret read by name is blocked, a .env read asked about, a plain
        # command left alone
        def shell(command):
            return mgr.invoke_hook(
                "pre_tool_call", tool_name="terminal", args={"command": command}, task_id="t", session_id="s"
            )

        [blocked] = shell('curl -H "X-Auth-Token: $LIBRENMS_TOKEN" "$LIBRENMS_URL/api/v0/devices"')
        self.assertEqual(blocked, {"action": "block", "message": mod.handlers.API_BLOCK})
        [asked] = shell("cat ~/.hermes/.env")
        self.assertEqual(asked["action"], "approve")
        self.assertTrue(asked["rule_key"].startswith("librenms:secret:terminal:env_file:"))
        self.assertEqual(shell("ls -la"), [])

    def test_under_the_default_tool_search_the_tools_are_deferred_yet_found_and_approved(self):
        # tools.tool_search.enabled is "auto" by default: the model is given tool_search / tool_describe / tool_call
        # and a catalog line per plugin tool, the first sentence of its description cut at 60 characters
        from hermes_cli.plugins import discover_plugins, get_plugin_manager

        discover_plugins()  # the profile's own manager, which the skill index reads (not a private one)
        self.discovered = True
        self.mgr = get_plugin_manager()
        import model_tools
        from agent import prompt_builder
        from agent.tool_executor import _unwrap_tool_search_call
        from tools.registry import registry
        from tools.tool_search_catalog import _short_desc

        defs = model_tools.get_tool_definitions(enabled_toolsets=["librenms", "skills"], quiet_mode=True)
        names = {d["function"]["name"] for d in defs}
        self.assertTrue(names.isdisjoint(TOOLS), names)
        self.assertIn("tool_call", names)
        [catalog] = [d["function"]["description"] for d in defs if d["function"]["name"] == "tool_search"]
        # the profile's manager may load it as hermes_plugins.librenms__home_<digest>: find it by its handler
        plugin = sys.modules[registry.get_entry("librenms_plan").handler.__module__.rpartition(".")[0]]
        for schema in plugin.schemas.ALL:  # each line says what the tool answers or does, uncut
            first = schema["description"].split(". ")[0] + "."
            self.assertEqual(_short_desc(schema["description"]), first)
            self.assertIn(f"- {schema['name']}: {first}", catalog)

        # the workflow skill is still offered, and tells the model how to reach the deferred tools
        toolsets = {model_tools.get_toolset_for_tool(name) for name in names} - {None, ""}
        index = prompt_builder.build_skills_system_prompt(available_tools=names, available_toolsets=toolsets)
        self.assertIn("librenms:workflow", index)

        # Hermes unwraps tool_call before pre_tool_call, so an apply through the bridge meets the approval prompt
        fake = seeded()
        client = plugin.client.LibreNMSClient(fake.base_url, TOKEN, session=fake)
        plugin.handlers.set_client_factory(lambda: client)
        operation = {"op": "update", "resource": "device", "id": 1, "data": {"purpose": "spine"}}
        planned = json.loads(registry.dispatch("librenms_plan", {"description": "t", "operations": [operation]}))
        plan_id = planned["plan_id"]
        agent = types.SimpleNamespace(enabled_toolsets=["librenms"], disabled_toolsets=None)
        call = {"calls": [{"name": "librenms_apply", "arguments": {"plan_id": plan_id}}]}
        unwrapped = _unwrap_tool_search_call(agent, "tool_call", call)
        self.assertEqual(unwrapped, ("librenms_apply", {"plan_id": plan_id}, None))
        directive, bound = self.mgr.invoke_hook(
            "pre_tool_call", tool_name=unwrapped[0], args=unwrapped[1], task_id="t", session_id="s"
        )
        self.assertEqual(directive["action"], "approve")
        self.assertIn(f"librenms:librenms_apply:{plan_id}:", directive["rule_key"])
        self.assertEqual(bound["args"]["_librenms_approval"]["plan_id"], plan_id)
        self.assertEqual(fake.writes(), [])

    def _dispatching_plugin(self):
        """The plugin loaded into the profile's own manager, its handlers on a fake LibreNMS, and a planned change
        (device 1's purpose to spine): ``(plugin, fake, plan_id)``. (Tests using it are named to run after
        test_registration_through_real_loader, as test_the_second_skill... says why.)"""
        from hermes_cli.plugins import discover_plugins, get_plugin_manager
        from tools.registry import registry

        discover_plugins()
        self.discovered = True
        self.mgr = get_plugin_manager()
        plugin = sys.modules[registry.get_entry("librenms_plan").handler.__module__.rpartition(".")[0]]
        fake = seeded()
        client = plugin.client.LibreNMSClient(fake.base_url, TOKEN, session=fake)
        plugin.handlers.set_client_factory(lambda: client)
        self.addCleanup(plugin.handlers.set_client_factory, None)
        operation = {"op": "update", "resource": "device", "id": 1, "data": {"purpose": "spine"}}
        planned = json.loads(registry.dispatch("librenms_plan", {"description": "t", "operations": [operation]}))
        return plugin, fake, planned["plan_id"]

    @staticmethod
    def _decommission(plugin, plan_id):
        """Change the saved plan as a file tool could: its step now sets purpose decommissioned."""
        store = plugin.store.get_store()
        plan = store.load(plan_id)
        plan["steps"][0]["changes"]["purpose"]["to"] = "decommissioned"
        plan["steps"][0]["payload"]["data"] = ["decommissioned"]
        store.save(plan)

    def test_the_session_answer_does_not_cover_the_plan_once_it_changed(self):
        # Hermes' own gate, as it runs for a model's tool call: a "session" answer is remembered by rule key, and
        # with nobody to ask (no interactive terminal here) whatever it does not cover is blocked
        import model_tools
        from tools import approval
        from tools.approval_context import get_current_session_key

        plugin, fake, plan_id = self._dispatching_plugin()
        directive, _bound = self.mgr.invoke_hook("pre_tool_call", tool_name="librenms_apply", args={"plan_id": plan_id})
        session_key = get_current_session_key()
        approval.approve_session(session_key, f"plugin_rule:{directive['rule_key']}")
        self.addCleanup(approval.clear_session, session_key)
        self._decommission(plugin, plan_id)
        call = {"task_id": "t", "session_id": "s", "tool_call_id": "call-1"}
        out = json.loads(model_tools.handle_function_call("librenms_apply", {"plan_id": plan_id}, **call))
        self.assertIn("BLOCKED", out["error"])
        self.assertEqual(fake.writes(), [])
        # the plan as it was when the person answered is still covered, and applies without a prompt
        store = plugin.store.get_store()
        plan = store.load(plan_id)
        plan["steps"][0]["changes"]["purpose"]["to"] = "spine"
        plan["steps"][0]["payload"]["data"] = ["spine"]
        store.save(plan)
        out = json.loads(model_tools.handle_function_call("librenms_apply", {"plan_id": plan_id}, **call))
        self.assertTrue(out["success"], out)
        self.assertEqual(fake.tables["devices"][1]["purpose"], "spine")

    def test_the_plan_changed_while_its_prompt_is_open_is_refused(self):
        # through Hermes' own dispatch: both pre_tool_call callbacks (each on a worker thread of Hermes'), the gate,
        # answered here after the file changed under it, and the handler, which bind_approval's modify directive
        # tells what the prompt showed
        import model_tools
        from tools import approval

        plugin, fake, plan_id = self._dispatching_plugin()
        asked = []

        def gate(tool_name, reason, *, rule_key="", approval_callback=None):
            asked.append((tool_name, reason.split("\n")[2], rule_key))
            if len(asked) == 1:
                self._decommission(plugin, plan_id)  # while the person reads "spine"
            return {"approved": True, "message": None}

        original = approval.request_tool_approval
        approval.request_tool_approval = gate
        self.addCleanup(setattr, approval, "request_tool_approval", original)
        call = {"task_id": "t", "session_id": "s"}
        first = json.loads(
            model_tools.handle_function_call("librenms_apply", {"plan_id": plan_id}, **call, tool_call_id="call-1")
        )
        self.assertTrue(first["error"].startswith(f"plan {plan_id} changed after the approval prompt showed it"))
        self.assertEqual(fake.writes(), [])
        second = json.loads(
            model_tools.handle_function_call("librenms_apply", {"plan_id": plan_id}, **call, tool_call_id="call-2")
        )
        self.assertTrue(second["success"], second)
        self.assertEqual(fake.tables["devices"][1]["purpose"], "decommissioned")
        (_tool, shown, first_key), (_tool, shown_again, second_key) = asked
        self.assertEqual(
            (shown, shown_again), ('  [0] purpose: "core" -> "spine"', '  [0] purpose: "core" -> "decommissioned"')
        )
        self.assertNotEqual(first_key, second_key)

    def test_the_dry_run_another_hook_turns_into_an_apply_is_refused(self):
        # through Hermes' own dispatch: our callbacks see a dry run and ask nothing, another plugin's modify directive
        # makes it an apply, and the handler gets the null bind_approval handed over, so it does not run unbound
        import model_tools
        from tools import approval

        plugin, fake, plan_id = self._dispatching_plugin()
        asked = []

        def gate(tool_name, reason, *, rule_key="", approval_callback=None):
            asked.append(rule_key)
            return {"approved": True, "message": None}

        def flip(tool_name=None, args=None, **_kwargs):
            return {"action": "modify", "args": {"dry_run": False}} if tool_name == "librenms_apply" else None

        original = approval.request_tool_approval
        approval.request_tool_approval = gate
        self.addCleanup(setattr, approval, "request_tool_approval", original)
        callbacks = self.mgr._hooks.setdefault("pre_tool_call", [])
        callbacks.append(flip)
        self.addCleanup(callbacks.remove, flip)
        call = {"task_id": "t", "session_id": "s", "tool_call_id": "call-1"}
        args = {"plan_id": plan_id, "dry_run": True}
        out = json.loads(model_tools.handle_function_call("librenms_apply", args, **call))
        self.assertTrue(out["error"].startswith("apply refused: no approval prompt showed this call"), out)
        self.assertEqual((asked, fake.writes()), ([], []))
        self.assertEqual(plugin.store.get_store().load(plan_id)["status"], "planned")

    def test_the_second_skill_is_offered_viewed_and_invoked_like_the_first(self):
        # the question skill reaches the model as the workflow does: a line in <available_skills>, skill_view by its
        # qualified name (with Hermes' banner naming its sibling), and a /librenms:ask slash command. (Named to run
        # after test_registration_through_real_loader: the first manager in a process to load the plugin imports
        # it as hermes_plugins.librenms, the name that test reads its logs and module by.)
        from hermes_cli.plugins import discover_plugins, get_plugin_manager

        discover_plugins()
        self.discovered = True
        self.mgr = get_plugin_manager()
        from agent import prompt_builder
        from agent.skill_commands import get_plugin_skill_commands
        from tools.skills_tool import skill_view

        index = prompt_builder.build_skills_system_prompt(available_tools=set(), available_toolsets=set())
        for name in SKILLS:
            self.assertIn(f"librenms:{name}", index)
        self.assertIn("Answer questions about the network from LibreNMS", index)
        with self.assertNoLogs("tools.skills_tool", "WARNING"):  # Hermes warns of a skill that reads like injection
            views = {name: json.loads(skill_view(f"librenms:{name}")) for name in SKILLS}
        for name, other in (("workflow", "ask"), ("ask", "workflow")):
            view = views[name]
            self.assertTrue(view["success"], view)
            self.assertIn(f"Sibling skills: {other}.", view["content"])
            self.assertIn(f"`librenms:{other}`", view["content"])  # and the skill itself says when to load it
        self.assertIn("## Questions and the call that answers them", views["ask"]["content"])
        self.assertTrue(views["ask"]["description"].startswith("Answer questions about the network"))
        command = get_plugin_skill_commands()["/librenms:ask"]
        self.assertEqual(Path(command["skill_md_path"]).parts[-3:], ("skills", "ask", "SKILL.md"))

    def test_the_digest_is_in_the_catalog_fills_a_job_and_its_run_writes_nothing(self):
        # Hermes' own catalog, filler, chat seed, cron prompt scan and cron run identity, with our hooks as Hermes
        # invokes them. (Named to run after test_registration_through_real_loader, as _dispatching_plugin says.)
        from cron.blueprint_catalog import (
            BlueprintFillError,
            blueprint_catalog_entry,
            fill_blueprint,
            get_blueprint,
        )
        from cron.execution_identity import enter_cron_execution, exit_cron_execution
        from cron.jobs import parse_schedule
        from hermes_cli.blueprint_cmd import build_blueprint_seed, match_blueprint
        from tools.cronjob_prompt_scan import _scan_cron_prompt
        from tools.registry import registry

        plugin, fake, plan_id = self._dispatching_plugin()
        digest = plugin.digest
        blueprint = get_blueprint("librenms:network-digest")  # what /blueprint, the dashboard and the Desktop list
        self.assertIsNotNone(blueprint)
        self.assertEqual((blueprint.plugin, blueprint.title, blueprint.skills), ("librenms", digest.TITLE, ()))
        self.assertIs(match_blueprint("network-digest")[0], blueprint)  # /blueprint network-digest finds it
        entry = blueprint_catalog_entry(blueprint)
        self.assertEqual((entry["source"], entry["scheduleHuman"]), ("plugin", "everyday at 08:00"))
        self.assertEqual(
            entry["command"],
            '/blueprint librenms:network-digest time=08:00 recurrence=everyday group="all" rows=10 all_clear=send '
            "deliver=origin",
        )
        spec = fill_blueprint(blueprint, {})
        self.assertEqual(
            {key: spec[key] for key in ("schedule", "name", "deliver")},
            {"schedule": "0 8 * * *", "name": digest.TITLE, "deliver": "origin"},
        )
        self.assertNotIn("skills", spec)
        self.assertEqual(spec["prompt"], digest.PROMPT.format(group="all", rows="10", all_clear="send"))
        self.assertEqual(_scan_cron_prompt(spec["prompt"]), "")  # the strict scan a cron job's own prompt gets
        parse_schedule(spec["schedule"])
        chosen = {"time": "06:30", "recurrence": "weekdays", "group": "edge-routers", "rows": "5", "all_clear": "skip"}
        filled = fill_blueprint(blueprint, {**chosen, "deliver": "telegram"})
        self.assertEqual((filled["schedule"], filled["deliver"]), ("30 6 * * 1-5", "telegram"))
        for text in ("Devices: edge-routers.", "limit 5 ", "All-clear days: skip."):
            self.assertIn(text, filled["prompt"])
        self.assertEqual(fill_blueprint(blueprint, {"recurrence": "weekends"})["schedule"], "0 8 * * 0,6")
        for wrong in ({"rows": "7"}, {"time": "8am"}, {"recurrence": "mondays"}, {"tiem": "07:15"}):
            with self.assertRaises(BlueprintFillError, msg=wrong):
                fill_blueprint(blueprint, wrong)
        # /blueprint network-digest with no values hands the agent the template to copy: nothing in it to unescape
        seed = build_blueprint_seed(blueprint)
        self.assertIn(digest.MARKER, seed)
        self.assertNotIn("{{", seed)

        # a run of the job: Hermes binds its identity, then starts the turn with the prompt (pre_llm_call)
        token = enter_cron_execution({"id": "job-digest", "name": digest.TITLE}, "exec-1", {"source": "builtin"})
        try:
            self.mgr.invoke_hook("pre_llm_call", session_id="cron_s", task_id="cron_t", user_message=spec["prompt"])
            directives = self.mgr.invoke_hook(
                "pre_tool_call", tool_name="librenms_apply", args={"plan_id": plan_id}, task_id="cron_t",
                session_id="cron_s",
            )  # fmt: skip
            self.assertIn({"action": "block", "message": digest.REFUSAL.format(action="apply")}, directives)
            self.assertFalse([d for d in directives if d.get("action") == "approve"], directives)
            out = json.loads(registry.dispatch("librenms_plan", {"description": "t", "operations": [{
                "op": "update", "resource": "device", "id": 1, "data": {"purpose": "leaf"}}]}))  # fmt: skip
            self.assertEqual(out["error"], digest.REFUSAL.format(action="plan"))
            out = json.loads(registry.dispatch("librenms_report", {"view": "alerts", "limit": 5}))
            self.assertTrue(out["success"], out)  # the reads the digest is for
        finally:
            exit_cron_execution(token)
        self.assertEqual(fake.writes(), [])
        # the run is over: the same session's next call is a chat's again
        directive, _bound = self.mgr.invoke_hook("pre_tool_call", tool_name="librenms_apply", args={"plan_id": plan_id})
        self.assertEqual(directive["action"], "approve")

    def test_the_digest_run_starts_no_other_agent(self):
        # Hermes gives a delegated child no cron identity, so the run itself must not delegate: the pre_tool_call
        # dispatch the agent loop runs blocks delegate_task and cronjob_manage in the run, and only there. (Named to
        # run after test_registration_through_real_loader, as _dispatching_plugin says.)
        import model_tools  # noqa: F401  (registers Hermes' own tools)
        from agent.delegation_context import delegated_child_context
        from agent.tool_executor import _canonical_tool_name
        from cron.execution_identity import current_cron_execution, enter_cron_execution, exit_cron_execution
        from hermes_cli.plugins import _dispatch_pre_tool_call_hooks
        from tools.registry import registry

        plugin, fake, _plan_id = self._dispatching_plugin()
        digest = plugin.digest
        for name in digest.DELEGATION_TOOLS:  # Hermes' own names for the tools that start another agent
            self.assertIsNotNone(registry.get_entry(name), name)
        self.assertEqual(_canonical_tool_name("cronjob"), "cronjob_manage")  # the legacy name reaches hooks as this
        goal = {"goal": "set device 1's purpose to leaf and apply it", "toolsets": ["librenms"]}
        job = {"action": "run", "job_id": "job-other"}
        ids = {"task_id": "cron_t", "session_id": "cron_s"}
        self.assertEqual(_dispatch_pre_tool_call_hooks("delegate_task", goal, **ids), (None, None))  # a chat's
        token = enter_cron_execution({"id": "job-digest", "name": digest.TITLE}, "exec-1", {"source": "builtin"})
        try:
            prompt = digest.PROMPT.format(group="all", rows="10", all_clear="send")
            self.mgr.invoke_hook("pre_llm_call", session_id="cron_s", task_id="cron_t", user_message=prompt)
            for name, args in (("delegate_task", goal), ("cronjob_manage", job)):
                block, _modified = _dispatch_pre_tool_call_hooks(name, args, **ids)
                self.assertEqual(block, digest.DELEGATION_REFUSAL.format(tool=name))
            # why: the child delegate_task would start reads no cron run, so the write tools would not refuse in it
            with delegated_child_context("child_s"):
                self.assertIsNone(current_cron_execution())
                self.assertFalse(digest.in_digest_run())
        finally:
            exit_cron_execution(token)
        self.assertEqual(fake.writes(), [])
        self.assertEqual(_dispatch_pre_tool_call_hooks("delegate_task", goal, **ids), (None, None))  # the run is over

    def test_report_times_use_the_zone_hermes_uses(self):
        # timefmt rebuilds hermes_time.get_timezone from public modules; both must name the same zone
        import hermes_time

        timefmt = submodule("timefmt")
        config = self.home / "config.yaml"
        config.write_text(config.read_text() + "timezone: Asia/Kolkata\n")
        os.environ.pop("HERMES_TIMEZONE", None)
        hermes_time.reset_cache()
        self.assertEqual((str(timefmt.get_zone()), timefmt.get_zone()), ("Asia/Kolkata", hermes_time.get_timezone()))
        os.environ["HERMES_TIMEZONE"] = "Pacific/Auckland"
        hermes_time.reset_cache()
        self.assertEqual(
            (str(timefmt.get_zone()), timefmt.get_zone()), ("Pacific/Auckland", hermes_time.get_timezone())
        )


def _restore_module(name, module):
    if module is None:
        sys.modules.pop(name, None)
    else:
        sys.modules[name] = module


if __name__ == "__main__":
    unittest.main()
