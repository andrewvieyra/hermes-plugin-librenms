"""``register(ctx)``: against a hand-written context everywhere, and through Hermes' real ``PluginManager`` when a
Hermes checkout is importable (set ``HERMES_AGENT_ROOT``, or run where ``hermes_cli`` imports).
"""

import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

from .base import PluginTestCase, _restore_env
from .helpers import load_plugin, submodule

REPO_ROOT = Path(__file__).resolve().parents[1]
TOOLS = ("librenms_query", "librenms_plan", "librenms_apply", "librenms_rollback", "librenms_plans")
HOOKS = ("pre_tool_call", "pre_llm_call", "post_approval_response")
ENV = {"LIBRENMS_URL": "https://librenms.test", "LIBRENMS_TOKEN": "0123456789abcdef"}


class FakeContext:
    """The ``PluginContext`` surface ``register`` uses, recording every call. ``old=True`` is a Hermes that predates
    CLI and skill registration; ``hookless=True`` one that cannot take hooks."""

    def __init__(self, config=None, *, old=False, hookless=False):
        self.config = dict(config or {})
        self.old = old
        self.hookless = hookless
        self.tools = {}
        self.commands = {}
        self.cli = []
        self.skills = []
        self.hooks = []

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

    def test_every_tool_hook_command_cli_and_the_skill_are_registered(self):
        self.plugin_dir(REPO_ROOT)  # the checkout's SKILL.md, also after the real-loader test removed its copy
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
        self.assertEqual(ctx.hooks, [(name, self.handlers.HOOKS[name]) for name in HOOKS])
        command = ctx.commands["librenms"]
        self.assertIs(command["handler"], self.commands.slash_handler)
        for word in ("status", "plans", "show", "check", "apply", "rollback", "prune"):
            self.assertIn(word, command["args_hint"])
        [cli] = ctx.cli
        self.assertEqual(cli["name"], "librenms")
        self.assertIs(cli["setup_fn"], self.commands.setup_cli)
        self.assertIs(cli["handler_fn"], self.commands.cli_handler)
        [(name, path, options)] = ctx.skills
        self.assertEqual((name, path), ("workflow", REPO_ROOT / "SKILL.md"))
        self.assertEqual(options["frontmatter"], {"metadata": {"hermes": {"requires_toolsets": ["librenms"]}}})
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
        self.assertEqual(len(ctx.tools), 5)
        self.assertIn("librenms", ctx.commands)
        self.assertEqual((ctx.cli, ctx.skills, len(ctx.hooks)), ([], [], 3))

    def test_a_hermes_that_cannot_take_the_hooks_fails_the_load(self):
        # without pre_tool_call nothing would ask before apply or rollback; better no plugin than that
        with self.assertRaises(AttributeError):
            self.register(FakeContext(hookless=True))

    def test_without_skill_md_no_skill_is_registered(self):
        with tempfile.TemporaryDirectory() as empty:
            self.plugin_dir(Path(empty))
            ctx = self.register(FakeContext())
        self.assertEqual(ctx.skills, [])
        self.assertEqual(len(ctx.tools), 5)


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

    def tearDown(self):
        if self.mgr is not None:
            self.mgr.unload("librenms")  # the tool registry is process-wide
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
        self.assertEqual((loaded["librenms"]["tools"], loaded["librenms"]["hooks"]), (5, 3))
        self.assertGreaterEqual(loaded["librenms"]["commands"], 1)
        for name in TOOLS:
            self.assertIsNotNone(registry.get_schema(name), name)
            self.assertEqual(registry.get_toolset_for_tool(name), "librenms")
        self.assertIsNotNone(mgr.find_plugin_skill("librenms:workflow"))
        [skill] = [s for s in mgr.list_plugin_skill_metadata() if s["name"] == "librenms:workflow"]
        self.assertEqual(skill["frontmatter"]["metadata"]["hermes"]["requires_toolsets"], ["librenms"])

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

        # the approval hook as Hermes invokes it: ours asks for an unknown plan too, and stays out of other tools
        [directive] = mgr.invoke_hook(
            "pre_tool_call", tool_name="librenms_apply", args={"plan_id": "lnp-nope"}, task_id="t", session_id="s"
        )
        self.assertEqual(directive["action"], "approve")
        self.assertTrue(directive["rule_key"].startswith("librenms:librenms_apply:unresolved:"))
        self.assertEqual(mgr.invoke_hook("pre_tool_call", tool_name="web_search", args={"query": "x"}), [])


def _restore_module(name, module):
    if module is None:
        sys.modules.pop(name, None)
    else:
        sys.modules[name] = module


if __name__ == "__main__":
    unittest.main()
