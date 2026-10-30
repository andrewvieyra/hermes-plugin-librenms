"""Consistency of what ships beside the code: one version everywhere, a manifest that declares every tool, hook and
setting the code registers or reads (as Hermes' validate checks), README and the two skills documenting them, the
install notes, the schema budget, the requests floor, and examples that still plan."""

from __future__ import annotations

import inspect
import json
import os
import re
import unicodedata
import unittest
from typing import Any, Dict, List

from .base import PluginTestCase
from .helpers import REPO_ROOT, load_plugin, submodule

# Every tool schema is sent to the model on every turn, so all six together stay under this many bytes of JSON
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

# The bundled skills: name -> SKILL.md (the workflow's at the root, where earlier releases had it).
SKILLS = {"workflow": REPO_ROOT / "SKILL.md", "ask": REPO_ROOT / "skills" / "ask" / "SKILL.md"}
# What Hermes' skill_view logs as possible prompt injection in a plugin skill (tools/skills_tool_plugin.py), and what
# its SKILL.md preprocessing would run or substitute (agent/skill_preprocessing.py): an inline shell snippet, a
# template token. A skill holds none of them.
HERMES_INJECTION_PATTERNS = (
    "ignore previous instructions",
    "ignore all previous",
    "you are now",
    "disregard your",
    "forget your instructions",
    "new instructions:",
    "system prompt:",
    "<system>",
    "]]>",
)
HERMES_EXPANDS = ("!`", "${HERMES_")

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
        for name, path in SKILLS.items():
            frontmatter = path.read_text(encoding="utf-8").split("---\n")[1]
            self.assertRegex(frontmatter, rf"(?m)^version: {re.escape(version)}$", name)
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
        self.assertEqual(len(names), 6)
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

    def test_every_bounded_setting_states_its_limit(self):
        # what 0.14.1 left out for plan_retention_days, whose value past 3650 is lowered with a settings error
        settings = submodule("settings")
        schema = manifest()["config_schema"]
        for name, limit in settings.LIMITS.items():
            least = settings.MINIMUMS.get(name)
            said = f"{least} to {limit}" if least else f"at most {limit}"
            self.assertIn(said, schema[name]["description"], name)

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
        self.assertEqual(ctx.skills, list(SKILLS))

    def test_every_hook_callback_takes_keyword_arguments_it_does_not_know(self):
        # Hermes passes hooks more keywords over time; `hermes plugins doctor` fails a callback without **kwargs
        for name, callback in self.registered().hooks.items():
            kinds = [parameter.kind for parameter in inspect.signature(callback).parameters.values()]
            self.assertIn(inspect.Parameter.VAR_KEYWORD, kinds, name)


class Documentation(unittest.TestCase):
    def setUp(self):
        self.readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.skills = {name: path.read_text(encoding="utf-8") for name, path in SKILLS.items()}
        self.skill = self.skills["workflow"]

    def test_readme_and_skill_document_every_tool(self):
        for schema in submodule("schemas").ALL:
            name = schema["name"]
            self.assertIn(f"| `{name}` |", self.readme, name)  # the README's tool table
            self.assertIn(f"| `{name}` |", self.skill, name)  # the model's own tool table
        for name in ("librenms_report", "librenms_query"):  # the question skill's: the read tools
            self.assertIn(f"| `{name}` |", self.skills["ask"], name)

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

    def test_the_skills_name_the_untrusted_sources(self):
        for name, skill in self.skills.items():
            text = section(skill, "Untrusted content")
            for source in UNTRUSTED_SOURCES:
                self.assertIn(source, text, f"{name}: {source}")

    def test_the_skill_frontmatter_names_and_describes_it(self):
        for name, skill in self.skills.items():
            frontmatter = skill.split("---\n")[1]
            self.assertRegex(frontmatter, rf"(?m)^name: librenms-{name}$")
            self.assertRegex(frontmatter, r"(?m)^description: \S.{40,}$")
            # Hermes checks these against the tools the model sees directly; under its tool search the librenms tools
            # are deferred, and the skill would be hidden where it is needed
            self.assertNotRegex(frontmatter, r"requires_tool|fallback_for")

    def test_each_skill_says_when_to_load_the_other(self):
        workflow, ask = (" ".join(skill.split("---\n")[1].split()) for skill in self.skills.values())
        self.assertIn("for questions that change nothing, load librenms:ask", workflow)
        self.assertIn("load `librenms:workflow`", self.skills["ask"])
        self.assertIn("Load when the user asks", ask)

    def test_the_skills_hold_nothing_hermes_reads_as_injection_or_runs(self):
        for name, skill in self.skills.items():
            for pattern in HERMES_INJECTION_PATTERNS:
                self.assertNotIn(pattern, skill.lower(), name)
            for token in HERMES_EXPANDS:
                self.assertNotIn(token, skill, name)
            # the escapes it quotes (‮) as text: never the character, which would not show where people read it
            hidden = [f"U+{ord(c):04X}" for c in skill if unicodedata.category(c) in ("Cf", "Cc") and c not in "\n\t"]
            self.assertEqual(hidden, [], name)

    def test_the_skills_say_how_to_reach_deferred_tools(self):
        for name, skill in self.skills.items():
            self.assertIn("`tool_describe`", skill, name)
            example = re.search(r'`(\{"calls": \[.*?\]\})`', skill).group(1)
            [call] = json.loads(example)["calls"]
            self.assertIn(call["name"], [schema["name"] for schema in submodule("schemas").ALL])
        self.assertIn('`{"calls": [{"name": "librenms_query", "arguments": {"action": "status"}}]}`', self.skill)

    def test_the_skills_name_both_reasons_the_tools_can_be_missing(self):
        # offered whenever the plugin is enabled, a skill also reaches sessions where the librenms toolset is off for
        # the platform or task: there, telling the user to set variables that are already set sends them wrong
        for name, skill in self.skills.items():
            paragraph = re.search(r"(?ms)^If no `librenms_\*` tool is in your tool list.*?(?=\n\n)", skill).group(0)
            paragraph = " ".join(paragraph.split())  # line breaks fall anywhere
            missing = paragraph[paragraph.index("Treat them as missing only") :]
            self.assertIn("`tool_search`", missing, name)  # a catalog listed in groups, or not at all, names no tool
            for cause in ("`LIBRENMS_URL`", "`LIBRENMS_TOKEN`", "`librenms` toolset", "`hermes tools`"):
                self.assertIn(cause, missing, name)
            self.assertIn("Tell the user both", missing, name)

    def test_the_readme_shows_asking_questions(self):
        text = section(self.readme, "Asking questions")
        for word in ("`librenms:ask`", "/librenms:ask", "examples/conversations/"):
            self.assertIn(word, text)
        self.assertGreaterEqual(text.count("you    >"), 4)  # dialogues, with follow-ups


class ModuleTable(unittest.TestCase):
    """docs/architecture.md's module table, which says each module imports only those listed above it."""

    def test_each_module_is_listed_after_what_it_imports(self):
        # what 0.14.1 said held and did not: client imported redact, listed below it, and planner, executor and
        # audit imported modules listed after them
        doc = (REPO_ROOT / "docs" / "architecture.md").read_text(encoding="utf-8")
        table = doc.split("## Modules", 1)[1].split("\n\n", 2)[1]
        rows = [line for line in table.splitlines() if line.startswith("| `")]
        place: Dict[str, Any] = {}  # a module's row, and its place in a row that names several
        for at, line in enumerate(rows):
            for within, name in enumerate(re.findall(r"`([\w/*]+)`", line.split("|")[1])):
                place[name] = (at, within)
        self.assertIn("Each module imports only modules listed above it", doc)
        for path in sorted(REPO_ROOT.rglob("*.py")):
            relative = path.relative_to(REPO_ROOT)
            if relative.parts[0] in ("tests", "examples") or any(part.startswith(".") for part in relative.parts):
                continue
            module = _table_name(relative.with_suffix("").parts)
            self.assertIn(module, place, f"{relative} has no row")
            for imported in _imports(path, relative):
                name = _table_name(imported)
                if name != module and name in place and module != "__init__":
                    self.assertLess(place[name], place[module], f"{module} imports {name}, listed after it")


def _table_name(parts: Any) -> str:
    """A module as the table names it: resources/* for every resource module, reports for its registry."""
    parts = [part for part in parts if part != "__init__"]
    if parts and parts[0] == "resources":
        return "resources/*"
    return "/".join(parts) or "__init__"


def _imports(path: Any, relative: Any) -> List[List[str]]:
    """The plugin's modules *path* imports at run time (relative imports outside ``if TYPE_CHECKING``)."""
    import ast

    tree = ast.parse(path.read_text(encoding="utf-8"))
    typing_only = {id(node) for block in ast.walk(tree) if isinstance(block, ast.If)
                   and "TYPE_CHECKING" in ast.unparse(block.test) for node in ast.walk(block)}  # fmt: skip
    package = list(relative.parent.parts)
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level and id(node) not in typing_only:
            base = package[: len(package) - (node.level - 1)] if node.level > 1 else package
            module = base + (node.module.split(".") if node.module else [])
            if node.module:
                out.append(module)
            for alias in node.names:  # from . import audit, digest: modules, not names
                if REPO_ROOT.joinpath(*module, alias.name + ".py").exists():
                    out.append([*module, alias.name])
    return out


class AfterInstall(unittest.TestCase):
    """after-install.md: what ``hermes plugins install`` prints (as Markdown, in place of its generic panel) once it has
    asked for the variables, the one moment a user is sure to read setup text. Hermes' install scan reads it as text
    a model is given, at full severity."""

    def setUp(self):
        path = REPO_ROOT / "after-install.md"  # Hermes reads <plugin dir>/after-install.md
        self.assertTrue(path.is_file(), "after-install.md is missing")
        self.text = path.read_text(encoding="utf-8")
        self.flat = " ".join(self.text.split())

    def test_it_gives_the_security_setup_steps(self):
        for step in (
            "least-privilege token",
            "`global-read`",
            "never `admin`",
            "`write_mode: operator_only`",
            "`plugins.entries.librenms.settings`",
            "`require_approval: true`",
            "YOLO",
            "container or remote backend",
            "`hermes plugins enable librenms`",
            "`/librenms status`",
            "SECURITY.md",
        ):
            self.assertIn(step, self.flat)

    def test_what_it_names_exists(self):
        defaults, modes = settings_defaults(), submodule("settings").WRITE_MODES
        named = re.findall(r"`(\w+): (\w+)`", self.text)
        self.assertGreaterEqual({name for name, _value in named}, {"write_mode", "require_approval"})
        for name, value in named:
            if name in defaults:
                self.assertEqual(type(scalar(value)), type(defaults[name]), name)
            if name == "write_mode":
                self.assertIn(value, modes)
        for mode in re.findall(r"`(\w+_only)`", self.text):
            self.assertIn(mode, modes)
        for name in ("README.md", "SECURITY.md"):  # where an install from the Desktop, which shows none of it, points
            self.assertIn("[after-install.md](after-install.md)", (REPO_ROOT / name).read_text(encoding="utf-8"))

    def test_it_holds_nothing_the_install_scan_or_a_model_would_act_on(self):
        lowered = self.text.lower()
        for pattern in HERMES_INJECTION_PATTERNS:
            self.assertNotIn(pattern, lowered)
        for token in (*HERMES_EXPANDS, "${", "curl ", "wget ", "| sh", "| bash"):
            self.assertNotIn(token, self.text)
        hidden = [f"U+{ord(c):04X}" for c in self.text if unicodedata.category(c) in ("Cf", "Cc") and c != "\n"]
        self.assertEqual(hidden, [])


# Hermes' rule for a deferred tool's catalog line (tools/tool_search_catalog.py, _short_desc): the description's
# first sentence (., ! or ? before whitespace or the end; not e.g., i.e. or etc.), clipped past 60 characters
_SENTENCE_END = re.compile(r"(?<!\be\.g)(?<!\bi\.e)(?<!\betc)[.!?](?=\s|$)")


class Schemas(unittest.TestCase):
    def test_each_description_opens_with_a_whole_catalog_line(self):
        schemas = submodule("schemas")
        for schema in schemas.ALL:
            text = " ".join(schema["description"].split())
            first = text[: _SENTENCE_END.search(text).end()]
            self.assertLessEqual(len(first), schemas.CATALOG_CHARS, first)
            self.assertTrue(first.endswith(".") and "LibreNMS" in first, first)
            self.assertTrue(schema["description"].endswith(f" {schemas.DEFERRED}"), schema["name"])
        query = schemas.LIBRENMS_QUERY["description"].split(". ")[0]
        for subject in ("devices", "ports", "alerts", "logs"):  # what people ask about
            self.assertIn(subject, query)

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
        examples = REPO_ROOT / "examples"
        readme = (examples / "README.md").read_text(encoding="utf-8")
        for path in examples.glob("**/*.json"):  # plans, and the conversations tests/test_conversation.py runs
            self.assertIn(f"`{path.relative_to(examples).as_posix()}`", readme)


def _restore_env(name: str, value: str | None) -> None:
    if value is None:
        os.environ.pop(name, None)
    else:
        os.environ[name] = value


if __name__ == "__main__":
    unittest.main()
