"""Consistency of what ships beside the code: one version everywhere, a manifest that declares every tool, hook and
setting the code registers or reads (as Hermes' validate checks), README and SKILL documenting all of them, the
schema budget, the requests floor, and examples that still plan."""

from __future__ import annotations

import inspect
import json
import os
import re
import unittest
from typing import Any, Dict, List

from .base import PluginTestCase
from .helpers import REPO_ROOT, load_plugin, submodule

# Every tool schema is sent to the model on every turn, so all five together stay under this many bytes of JSON
# (``json.dumps`` defaults). Raise it only with a reason in the CHANGELOG.
SCHEMA_BUDGET_BYTES = 16 * 1024
# 2.32.4 fixes CVE-2024-47081 (.netrc credentials sent to another host) and, from 2.32.0, CVE-2024-35195
# (verify=False sticking to a pooled connection).
REQUESTS = "requests>=2.32.4,<3"
SCHEMA_TYPES = {"bool": bool, "int": int, "str": str, "list": list}
# config_schema entries of type secret: the Desktop stores them in the profile's .env under this name
SECRET_FIELDS = {"audit_sink_secret": "LIBRENMS_AUDIT_SINK_SECRET"}
# What the skill's untrusted-content section must name: text that devices and strangers, not users, write.
UNTRUSTED_SOURCES = (
    "syslog",
    "sysDescr",
    "sysLocation",
    "sysContact",
    "ifAlias",
    "LLDP",
    "CDP",
    "eventlog",
    "notes",
    "autodiscovery",
)

_LINE = re.compile(r"(?P<indent> *)(?P<dash>- )?(?:(?P<key>[A-Za-z_]\w*):(?: (?P<value>.+))?|(?P<item>.+))")


def scalar(text: str) -> Any:
    """One YAML flow value as plugin.yaml writes them: a double-quoted string, a flow list, a bool, an int, null or
    a plain string."""
    text = text.strip()
    if text.startswith('"'):
        return json.loads(text)
    if text.startswith("[") and text.endswith("]"):
        return [scalar(part) for part in text[1:-1].split(",") if part.strip()]
    if " #" in text or text.startswith(("'", "{", "&", "*", "|", ">")):
        raise ValueError(f"{text[:40]!r} is outside the YAML subset this test reads")
    if text in ("true", "false"):
        return text == "true"
    if text in ("null", "~"):
        return None
    return int(text) if text.isdigit() else text


def read_manifest(text: str) -> Dict[str, Any]:
    """plugin.yaml read with the subset of YAML it is written in, because CI installs nothing but requests. A line
    outside that subset fails the test, so nothing below runs on a misread manifest."""
    manifest: Dict[str, Any] = {}
    block: str | None = None
    current: Dict[str, Any] | None = None
    for number, raw in enumerate(text.splitlines(), 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        line = _LINE.fullmatch(raw)
        indent, dash, key, value = len(line["indent"]), line["dash"], line["key"], line["value"]
        if indent == 0 and not dash and key:
            block, current = (None, None) if value else (key, None)
            manifest[key] = scalar(value) if value else None
        elif indent == 2 and dash and (value or not key) and block and isinstance(manifest[block] or [], list):
            items = manifest[block] = manifest[block] or []
            current = {key: scalar(value)} if key else None
            items.append(current if key else scalar(line["item"]))
        elif indent == 2 and not dash and key and not value and block and isinstance(manifest[block] or {}, dict):
            entries = manifest[block] = manifest[block] or {}
            current = entries[key] = {}
        elif indent == 4 and not dash and key and value and current is not None:
            current[key] = scalar(value)
        else:
            raise ValueError(f"plugin.yaml:{number} is outside the YAML subset this test reads: {raw!r}")
    return manifest


def manifest() -> Dict[str, Any]:
    return read_manifest((REPO_ROOT / "plugin.yaml").read_text(encoding="utf-8"))


def mentions(text: str, name: str) -> bool:
    """*name* appears as a whole identifier (``audit_log`` is not found inside ``audit_log_path``)."""
    return re.search(rf"(?<![\w]){re.escape(name)}(?![\w])", text) is not None


def section(markdown: str, heading: str) -> str:
    """The body of the ``## heading`` section, up to the next heading of the same level."""
    found = re.search(rf"(?ms)^## {re.escape(heading)}\n(.*?)(?=^## |\Z)", markdown)
    return found.group(1) if found else ""


def project_table() -> str:
    """The ``[project]`` table of pyproject.toml (``tomllib`` is 3.11+, and the suite runs on 3.10)."""
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    return re.search(r"(?ms)^\[project\]\n(.*?)(?=^\[|\Z)", text).group(1)


def settings_defaults() -> Dict[str, Any]:
    return submodule("settings").Settings().to_dict()


class RecordingContext:
    """What Hermes' validate probe hands ``register``: the config's defaults, and a record of every registration.
    Anything else raises AttributeError, since registration must not reach for more (no I/O, no manifest)."""

    profile_name = "default"
    plugin_id = "librenms"

    def __init__(self) -> None:
        self.tools: List[str] = []
        self.hooks: Dict[str, Any] = {}
        self.commands: List[str] = []
        self.cli_commands: List[str] = []
        self.skills: List[str] = []

    def get_config(self, key: str, default: Any = None) -> Any:
        return default

    def register_tool(self, name: str, *args: Any, **kwargs: Any) -> None:
        self.tools.append(name)

    def register_hook(self, hook_name: str, callback: Any) -> None:
        self.hooks[hook_name] = callback

    def register_command(self, name: str, *args: Any, **kwargs: Any) -> None:
        self.commands.append(name)

    def register_cli_command(self, name: str, *args: Any, **kwargs: Any) -> None:
        self.cli_commands.append(name)

    def register_skill(self, name: str, *args: Any, **kwargs: Any) -> None:
        self.skills.append(name)


class VersionConsistency(unittest.TestCase):
    def test_all_versions_agree(self):
        version = submodule("version").__version__
        self.assertEqual(manifest()["version"], version, "plugin.yaml")
        self.assertRegex(project_table(), rf'(?m)^version = "{re.escape(version)}"$', "pyproject.toml [project]")
        skill = (REPO_ROOT / "SKILL.md").read_text(encoding="utf-8")
        frontmatter = skill.split("---\n")[1]
        self.assertRegex(frontmatter, rf"(?m)^version: {re.escape(version)}$", "SKILL.md")
        changelog = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertRegex(changelog, rf"(?m)^## \[{re.escape(version)}\] - \d{{4}}-\d{{2}}-\d{{2}}$", "CHANGELOG.md")

    def test_the_requests_floor_is_the_same_everywhere_and_past_the_netrc_fix(self):
        self.assertEqual((REPO_ROOT / "requirements.txt").read_text(encoding="utf-8").split(), [REQUESTS])
        self.assertEqual(manifest()["python_dependencies"], [REQUESTS])
        # Hermes' package manager reads a pyproject.toml beside plugin.yaml before the manifest, so both must say it
        self.assertRegex(project_table(), rf'(?m)^dependencies = \["{re.escape(REQUESTS)}"\]$')


class Manifest(unittest.TestCase):
    def test_the_manifest_declares_what_hermes_needs(self):
        data = manifest()
        self.assertEqual(data["name"], "librenms")
        self.assertEqual((data["manifest_version"], data["api_version"]), (2, 1))
        # ctx.session_surface(), which the audit actor records, arrived in Hermes 0.22.3
        self.assertEqual(data["requires_hermes"], ">=0.22.3")
        self.assertEqual([entry["name"] for entry in data["requires_env"]], ["LIBRENMS_URL", "LIBRENMS_TOKEN"])
        self.assertEqual([entry["secret"] for entry in data["requires_env"]], [False, True])
        self.assertEqual(data["optional_env"], ["LIBRENMS_VERIFY_SSL", "LIBRENMS_TIMEOUT", "LIBRENMS_PROXY"])
        self.assertTrue(data["description"])

    def test_the_manifest_lists_every_tool_schema(self):
        names = [schema["name"] for schema in submodule("schemas").ALL]
        self.assertEqual(len(names), 5)
        self.assertEqual(manifest()["provides_tools"], names)

    def test_every_setting_has_a_schema_entry_with_its_type_default_and_description(self):
        schema = manifest()["config_schema"]
        defaults = settings_defaults()
        # the Desktop settings form follows this order; the secret fields, which the plugin never reads (Hermes
        # expands their ${VAR} in the settings that name them), come last
        self.assertEqual(list(schema), [*defaults, *SECRET_FIELDS])
        sinks = submodule("sinks")  # what status tells an operator to use for a collector token
        self.assertEqual(SECRET_FIELDS, {sinks.SECRET_FIELD: sinks.SECRET_ENV})
        for name, env in SECRET_FIELDS.items():
            entry = schema[name]
            self.assertEqual((entry["type"], entry["env"]), ("secret", env), name)
            self.assertEqual(set(entry), {"type", "env", "description"}, name)  # no default: it lives in .env
            self.assertIn(f"${{{env}}}", entry["description"], name)
            # a name Hermes masks whenever the agent's terminal prints the environment
            self.assertRegex(env, r"^LIBRENMS_[A-Z0-9_]+_(SECRET|PASS|PASSWORD)$", name)
        for name, default in defaults.items():
            entry = schema[name]
            self.assertIs(SCHEMA_TYPES[entry["type"]], type(default), name)
            self.assertEqual(entry["default"], default, name)
            self.assertTrue(entry["description"].strip(), name)
            self.assertLessEqual(set(entry), {"type", "default", "choices", "description"}, name)
        # Hermes enforces choices when the Desktop saves the setting, so an invalid write_mode cannot be stored
        self.assertEqual(schema["write_mode"]["choices"], list(submodule("settings").WRITE_MODES))
        self.assertEqual([name for name, entry in schema.items() if "choices" in entry], ["write_mode"])

    def test_the_subset_reader_agrees_with_a_yaml_parser(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML is not installed")
        self.assertEqual(manifest(), yaml.safe_load((REPO_ROOT / "plugin.yaml").read_text(encoding="utf-8")))


class Registration(PluginTestCase):
    """``register`` as Hermes' validate probe runs it: what it registers must be what the manifest declares, since
    validate fails a plugin that registers a tool or hook it did not declare."""

    def registered(self) -> RecordingContext:
        ctx = RecordingContext()
        load_plugin().register(ctx)
        return ctx

    def test_registered_tools_and_hooks_are_the_declared_ones(self):
        ctx = self.registered()
        data = manifest()
        self.assertEqual(sorted(ctx.tools), sorted(data["provides_tools"]))
        self.assertEqual(sorted(ctx.hooks), sorted(data["provides_hooks"]))
        self.assertEqual(ctx.commands, ["librenms"])
        self.assertEqual(ctx.cli_commands, ["librenms"])
        self.assertEqual(ctx.skills, ["workflow"])

    def test_every_hook_callback_takes_keyword_arguments_it_does_not_know(self):
        # Hermes passes hooks more keywords over time; `hermes plugins doctor` fails a callback without **kwargs
        for name, callback in self.registered().hooks.items():
            kinds = [parameter.kind for parameter in inspect.signature(callback).parameters.values()]
            self.assertIn(inspect.Parameter.VAR_KEYWORD, kinds, name)


class Documentation(unittest.TestCase):
    def setUp(self):
        self.readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.skill = (REPO_ROOT / "SKILL.md").read_text(encoding="utf-8")

    def test_readme_and_skill_document_every_tool(self):
        for schema in submodule("schemas").ALL:
            name = schema["name"]
            self.assertIn(f"| `{name}` |", self.readme, name)  # the README's tool table
            self.assertIn(f"| `{name}` |", self.skill, name)  # the model's own tool table

    def test_readme_and_skill_document_every_setting(self):
        for name in settings_defaults():
            self.assertTrue(mentions(self.readme, name), f"README.md does not mention {name}")
            self.assertTrue(mentions(self.skill, name), f"SKILL.md does not mention {name}")

    def test_the_readme_configuration_block_shows_every_default(self):
        block = re.search(r"(?ms)^### Configuration\n.*?```yaml\n(.*?)```", self.readme).group(1)
        shown = {
            found["name"]: scalar(found["value"])
            for found in re.finditer(r"(?m)^ {8}(?P<name>\w+): (?P<value>\S+)", block)
        }
        self.assertEqual(shown, settings_defaults())

    def test_the_skill_names_the_untrusted_sources(self):
        text = section(self.skill, "Untrusted content")
        for source in UNTRUSTED_SOURCES:
            self.assertIn(source, text, source)

    def test_the_skill_frontmatter_names_and_describes_it(self):
        frontmatter = self.skill.split("---\n")[1]
        self.assertRegex(frontmatter, r"(?m)^name: librenms-workflow$")
        self.assertRegex(frontmatter, r"(?m)^description: \S.{40,}$")


class Schemas(unittest.TestCase):
    def test_schemas_stay_inside_their_budget(self):
        schemas = submodule("schemas").ALL
        size = len(json.dumps(schemas).encode("utf-8"))
        sizes = ", ".join(f"{s['name']} {len(json.dumps(s))}" for s in schemas)
        self.assertLessEqual(size, SCHEMA_BUDGET_BYTES, f"tool schemas are {size} bytes of JSON ({sizes})")


class Examples(PluginTestCase):
    """Every file in examples/ is a payload librenms_plan accepts, planned against the seeded fake LibreNMS whose
    names the examples use."""

    def test_every_example_plans(self):
        for name in ("LIBRENMS_SNMP_V3_USER", "LIBRENMS_SNMP_V3_AUTH_PASS", "LIBRENMS_SNMP_V3_PRIV_PASS"):
            self.addCleanup(_restore_env, name, os.environ.get(name))
            os.environ[name] = f"example value of {name}"
        planner = submodule("planner")
        files = sorted((REPO_ROOT / "examples").glob("*.json"))
        self.assertGreaterEqual(len(files), 4)
        for path in files:
            with self.subTest(example=path.name):
                payload = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(sorted(payload), ["description", "operations"])
                try:
                    plan = planner.build_plan(
                        self.client, payload["operations"], payload["description"], self.settings, self.client.base_url
                    )
                except planner.PlanError as exc:
                    self.fail(f"{path.name}: {exc.errors}")
                summary = plan["summary"]
                self.assertEqual(summary["noop"], 0, path.name)
                self.assertGreater(summary["create"] + summary["update"] + summary["delete"] + summary["action"], 0)

    def test_the_examples_readme_lists_every_example(self):
        readme = (REPO_ROOT / "examples" / "README.md").read_text(encoding="utf-8")
        for path in (REPO_ROOT / "examples").glob("*.json"):
            self.assertIn(f"`{path.name}`", readme)


def _restore_env(name: str, value: str | None) -> None:
    if value is None:
        os.environ.pop(name, None)
    else:
        os.environ[name] = value


if __name__ == "__main__":
    unittest.main()
