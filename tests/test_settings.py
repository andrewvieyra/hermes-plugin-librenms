"""Operator settings: the coercion of every setting, the fail-closed fallbacks and the errors they record, the
public view and digest, and how get_settings follows the Hermes context."""

import hashlib
import json
import os
import subprocess
import sys
import unittest

from .helpers import REPO_ROOT, submodule

settings_mod = submodule("settings")
Settings = settings_mod.Settings

# Every flag and the value an unreadable one takes: whatever lets the model do least.
FAIL_CLOSED_FLAGS = {
    "require_approval": True,
    "allow_delete": False,
    "allow_device_add": False,
    "allow_services": False,
    "allow_insecure_transport": False,
    "audit_log": True,
    "audit_include_request": True,
    "link_eventlog": True,
}
# Every count: (default, upper limit).
COUNTS = {
    "max_operations": (100, 1000),
    "max_query_results": (500, 5000),
    "max_plan_age_hours": (24, 720),
    "max_maintenance_hours": (72, 8760),
    "plan_retention_days": (90, 3650),
}
TEXTS = ("write_mode", "audit_log_path")
LISTS = ("audit_sinks",)


class Ctx:
    """The one ``PluginContext`` method settings read; a key in *broken* raises like a bad config read."""

    def __init__(self, values=None, broken=()):
        self.values = dict(values or {})
        self.broken = set(broken)

    def get_config(self, key, default=None):
        if key in self.broken:
            raise RuntimeError(f"config read failed for {key}")
        return self.values.get(key, default)


class Undeepcopyable(dict):
    """A config value whose copy fails, so that building the settings as a whole raises."""

    def __deepcopy__(self, memo):
        raise RuntimeError("cannot copy")


def built(name, raw):
    """``(value, errors)`` for one raw setting."""
    settings = Settings.from_mapping({name: raw})
    return getattr(settings, name), settings.errors


class EverySettingIsCovered(unittest.TestCase):
    def test_the_tables_here_name_every_setting(self):
        # a new setting must get its coercion tested here
        names = set(FAIL_CLOSED_FLAGS) | set(COUNTS) | set(TEXTS) | set(LISTS)
        self.assertEqual(names, set(Settings().to_dict()))
        self.assertEqual(set(settings_mod.LIMITS), set(COUNTS))
        for name, (default, limit) in COUNTS.items():
            self.assertEqual((getattr(Settings(), name), settings_mod.LIMITS[name]), (default, limit), name)

    def test_defaults_are_the_conservative_ones(self):
        defaults = Settings()
        self.assertEqual(defaults.write_mode, "full")
        self.assertEqual(settings_mod.WRITE_MODES, ("full", "operator_only", "read_only"))
        for name in FAIL_CLOSED_FLAGS:
            self.assertEqual(getattr(defaults, name), FAIL_CLOSED_FLAGS[name], name)
        self.assertEqual((defaults.audit_log_path, defaults.audit_sinks, defaults.errors), ("", [], []))

    def test_absent_empty_and_unknown_keys_keep_the_defaults(self):
        self.assertEqual(Settings.from_mapping({name: None for name in Settings().to_dict()}), Settings())
        unknown = Settings.from_mapping({"bogus": 1, "Allow_Delete": True, "unknown_keys": ["x"]})
        self.assertEqual((unknown, unknown.errors), (Settings(), []))  # unknown keys are not read at all
        for raw in (None, ["allow_delete"], "allow_delete: true"):
            self.assertEqual(Settings.from_mapping(raw), Settings(), raw)


class Flags(unittest.TestCase):
    def test_true_and_false_in_every_spelling(self):
        for name in FAIL_CLOSED_FLAGS:
            for raw in (True, "true", " Yes ", "ON", "1", 1):
                self.assertEqual(built(name, raw), (True, []), (name, raw))
            for raw in (False, "FALSE", "no", " off ", "0", 0):
                self.assertEqual(built(name, raw), (False, []), (name, raw))

    def test_anything_else_is_the_fail_closed_value_and_an_error(self):
        # bool() would read ["false"] or 2 as true and switch allow_delete on
        for name, safe in FAIL_CLOSED_FLAGS.items():
            for raw in ("", "maybe", "enabled", 2, -1, 1.0, 0.0, [], ["false"], {"a": 1}):
                value, errors = built(name, raw)
                self.assertIs(value, safe, (name, raw))
                self.assertEqual(len(errors), 1, (name, raw))
                self.assertTrue(errors[0].startswith(f"{name}: expected true or false, got "), errors)
                self.assertTrue(errors[0].endswith(f"; using {str(safe).lower()}"), errors)
        self.assertEqual(
            built("allow_delete", ["true"])[1], ["allow_delete: expected true or false, got list; using false"]
        )
        self.assertEqual(
            built("require_approval", "maybe")[1], ["require_approval: expected true or false, got 'maybe'; using true"]
        )
        self.assertEqual(built("link_eventlog", 2)[1], ["link_eventlog: expected true or false, got 2; using true"])

    def test_flag_reader(self):
        self.assertEqual(
            [settings_mod.flag(raw) for raw in (True, " On ", 1, "0", "no", 0, False)], [True] * 3 + [False] * 4
        )
        for raw in (None, "", "y", 2, 1.0, [], ["true"]):
            self.assertIsNone(settings_mod.flag(raw), raw)

    def test_a_bad_value_is_quoted_only_when_short_and_on_one_line(self):
        # a long string or a structure may hold a credential pasted into the wrong key
        self.assertEqual(
            built("allow_delete", "x" * 38)[1], [f"allow_delete: expected true or false, got '{'x' * 38}'; using false"]
        )
        for raw in ("x" * 39, "line\nbreak", {"password": "hunter2"}, ("a",)):
            errors = built("allow_delete", raw)[1]
            self.assertEqual(errors, [f"allow_delete: expected true or false, got {type(raw).__name__}; using false"])


class Counts(unittest.TestCase):
    def test_ints_and_digit_strings(self):
        for name, (_default, limit) in COUNTS.items():
            self.assertEqual(built(name, 7), (7, []), name)
            self.assertEqual(built(name, " 12 "), (12, []), name)
            self.assertEqual(built(name, limit), (limit, []), name)
            self.assertEqual(built(name, str(limit)), (limit, []), name)

    def test_junk_fractions_and_negatives_keep_the_default(self):
        # int() would truncate 0.5 retention days to 0, which keeps plans forever, and read True as 1
        junk = (
            "many",
            "1.5",
            1.5,
            7.0,
            True,
            False,
            float("nan"),
            float("inf"),
            -1,
            "-5",
            "+5",
            "²",
            "١",
            "",
            [3],
            {"a": 1},
        )
        for name, (default, _limit) in COUNTS.items():
            least = 0 if name == "plan_retention_days" else 1
            for raw in junk:
                value, errors = built(name, raw)
                self.assertEqual(value, default, (name, raw))
                self.assertEqual(len(errors), 1, (name, raw))
                self.assertTrue(errors[0].startswith(f"{name}: expected a whole number of {least} or more, got "))
                self.assertTrue(errors[0].endswith(f"; using {default}"), errors)
        self.assertEqual(
            built("plan_retention_days", 0.5),
            (90, ["plan_retention_days: expected a whole number of 0 or more, got 0.5; using 90"]),
        )
        self.assertEqual(
            built("max_operations", "9" * 5000),  # more digits than int() converts
            (100, ["max_operations: expected a whole number of 1 or more, got str; using 100"]),
        )

    def test_zero_is_no_cap_so_only_retention_takes_it(self):
        self.assertEqual(built("plan_retention_days", 0), (0, []))
        self.assertEqual(built("plan_retention_days", "0"), (0, []))
        for name, (default, _limit) in COUNTS.items():
            if name == "plan_retention_days":
                continue
            for raw in (0, "0"):
                self.assertEqual(
                    built(name, raw),
                    (default, [f"{name}: expected a whole number of 1 or more, got {raw!r}; using {default}"]),
                )

    def test_values_above_the_limit_are_lowered_to_it(self):
        for name, (_default, limit) in COUNTS.items():
            for raw in (limit + 1, str(limit * 10), 10**30):
                value, errors = built(name, raw)
                self.assertEqual(value, limit, (name, raw))
                self.assertEqual(len(errors), 1)
                self.assertTrue(errors[0].startswith(f"{name}: expected at most {limit}, got "), errors)
                self.assertTrue(errors[0].endswith(f"; using {limit}"), errors)
        self.assertEqual(
            built("max_operations", 5000), (1000, ["max_operations: expected at most 1000, got 5000; using 1000"])
        )


class Texts(unittest.TestCase):
    def test_write_mode_in_any_case(self):
        self.assertEqual(built("write_mode", " READ_ONLY "), ("read_only", []))
        self.assertEqual(built("write_mode", "Operator_Only"), ("operator_only", []))
        self.assertEqual(built("write_mode", "full"), ("full", []))
        self.assertEqual(built("write_mode", None), ("full", []))  # absent is the default

    def test_an_unknown_write_mode_is_read_only(self):
        # NetBox fell back to full, the most permissive mode, on a typo
        for raw in ("readonly", "", "operator-only", "FULL!", 1, True, ["full"], {"mode": "full"}):
            value, errors = built("write_mode", raw)
            self.assertEqual(value, "read_only", raw)
            self.assertEqual(len(errors), 1)
            self.assertTrue(errors[0].startswith("write_mode: expected one of full, operator_only, read_only, got "))
            self.assertTrue(errors[0].endswith("; using read_only"), errors)
        self.assertEqual(
            built("write_mode", "readonly")[1],
            ["write_mode: expected one of full, operator_only, read_only, got 'readonly'; using read_only"],
        )

    def test_audit_log_path_keeps_its_case(self):
        # NetBox lowercased every text setting, which broke paths on case-sensitive file systems
        self.assertEqual(built("audit_log_path", "/Users/Andrew/Audit.JSONL"), ("/Users/Andrew/Audit.JSONL", []))
        self.assertEqual(built("audit_log_path", "  /var/Log/LibreNMS.jsonl \n"), ("/var/Log/LibreNMS.jsonl", []))
        self.assertEqual(built("audit_log_path", 42), ("", ["audit_log_path: expected text, got 42; using ''"]))
        self.assertEqual(built("audit_log_path", ["/x"]), ("", ["audit_log_path: expected text, got list; using ''"]))

    def test_audit_log_path_must_be_absolute(self):
        # a relative path lands in each process's working directory (a repository the gateway started in)
        relative = ["audit_log_path: expected an absolute path (~ is expanded), got a relative path; using ''"]
        for path in ("logs/librenms-audit.jsonl", "./audit.jsonl", "audit.jsonl", "~alice-x-nobody/a.jsonl"):
            self.assertEqual(built("audit_log_path", path), ("", relative), path)
        self.assertEqual(built("audit_log_path", "~/logs/audit.jsonl"), ("~/logs/audit.jsonl", []))
        self.assertEqual(built("audit_log_path", "  "), ("", []))  # empty: the default file


class Sinks(unittest.TestCase):
    def test_mappings_are_kept_as_deep_copies(self):
        # Hermes hands out its cached config objects; editing them would corrupt the cache
        raw = [{"type": "syslog", "host": "10.0.0.5", "options": {"tags": ["a"]}}, {"type": "http"}]
        settings = Settings.from_mapping({"audit_sinks": raw})
        self.assertEqual((settings.audit_sinks, settings.errors), (raw, []))
        settings.audit_sinks[0]["options"]["tags"].append("b")
        self.assertEqual(raw[0]["options"]["tags"], ["a"])

    def test_other_entries_are_dropped_by_index_without_quoting_them(self):
        raw = [{"type": "http"}, "https://user:s3cret@collector/", 5, ["x"], {"type": "syslog"}]
        settings = Settings.from_mapping({"audit_sinks": raw})
        self.assertEqual(settings.audit_sinks, [{"type": "http"}, {"type": "syslog"}])
        self.assertEqual(settings.errors, [f"audit_sinks[{i}]: expected a mapping; entry ignored" for i in (1, 2, 3)])
        # the kept entries remember where they stand in config.yaml, so sink warnings name the same positions
        self.assertEqual(settings.audit_sink_numbers, [0, 4])
        self.assertNotIn("audit_sink_numbers", settings.to_dict())

    def test_a_value_that_is_not_a_list_is_named_by_its_type_only(self):
        for raw, kind in (("https://collector/?token=abc", "str"), ({"type": "http"}, "dict"), (3, "int")):
            self.assertEqual(built("audit_sinks", raw), ([], [f"audit_sinks: expected a list, got {kind}; using []"]))


class FromCtx(unittest.TestCase):
    def test_reads_every_setting_through_the_context(self):
        sinks = [{"type": "http", "headers": {"Authorization": "Splunk t"}}]
        ctx = Ctx({"write_mode": "Operator_Only", "allow_delete": "yes", "max_operations": "50", "audit_sinks": sinks})
        settings = Settings.from_ctx(ctx)
        self.assertEqual(
            (settings.write_mode, settings.allow_delete, settings.max_operations, settings.errors),
            ("operator_only", True, 50, []),
        )
        settings.audit_sinks[0]["headers"]["Authorization"] = "changed"
        self.assertEqual(ctx.values["audit_sinks"][0]["headers"]["Authorization"], "Splunk t")
        self.assertEqual(Settings.from_ctx(Ctx()), Settings())

    def test_a_read_that_raises_fails_closed(self):
        broken = ("write_mode", "allow_delete", "require_approval", "max_operations", "audit_sinks")
        settings = Settings.from_ctx(Ctx({"allow_delete": True}, broken=broken))
        self.assertEqual(
            (settings.write_mode, settings.allow_delete, settings.require_approval, settings.max_operations),
            ("read_only", False, True, 100),
        )
        self.assertEqual(settings.audit_sinks, [])
        self.assertEqual(len(settings.errors), len(broken))
        self.assertIn(
            "write_mode: could not be read from the Hermes config (RuntimeError); using read_only", settings.errors
        )
        self.assertIn(
            "allow_delete: could not be read from the Hermes config (RuntimeError); using false", settings.errors
        )
        self.assertNotIn("config read failed", " ".join(settings.errors))  # the exception's text is not repeated

    def test_a_context_without_config_reads_fails_closed_everywhere(self):
        settings = Settings.from_ctx(object())
        self.assertEqual(settings.write_mode, "read_only")
        self.assertEqual(len(settings.errors), len(Settings().to_dict()))

    def test_to_dict_holds_settings_only(self):
        settings = Settings(errors=["x"])
        self.assertEqual(list(settings.to_dict()), list(Settings().to_dict()))
        self.assertNotIn("errors", settings.to_dict())
        self.assertEqual(settings, Settings())  # errors do not take part in equality


class PublicAndDigest(unittest.TestCase):
    SINKS = [
        {"type": "Syslog", "host": "10.0.0.5", "port": 6514},
        {"type": "http", "url": "https://collector.example/?token=abc123", "headers": {"Authorization": "Splunk s3"}},
        {"type": "http", "url": "https://other.example/"},
        {"type": ["odd"]},
    ]

    def test_public_replaces_sink_configuration_with_a_count_and_types(self):
        settings = Settings(audit_sinks=self.SINKS, errors=["e"])
        public = settings.public()
        self.assertEqual(public["audit_sinks"], {"count": 4, "types": ["http", "syslog", "unknown"]})
        self.assertEqual(
            {k: v for k, v in public.items() if k != "audit_sinks"},
            {k: v for k, v in settings.to_dict().items() if k != "audit_sinks"},
        )
        text = json.dumps(public)
        for secret in ("abc123", "s3", "10.0.0.5", "collector.example"):
            self.assertNotIn(secret, text)
        self.assertNotIn("errors", public)

    def test_public_says_only_whether_audit_log_path_is_set(self):
        # status reaches the model, and a path names the OS account
        self.assertEqual(Settings().public()["audit_log_path"], "")
        public = Settings(audit_log_path="/home/alice/hermes/librenms-audit.jsonl").public()
        self.assertEqual(public["audit_log_path"], "custom")
        self.assertNotIn("alice", json.dumps(public))

    def test_digest_is_short_canonical_and_stable(self):
        settings = Settings(audit_sinks=self.SINKS)
        digest = settings.digest()
        self.assertRegex(digest, r"^[0-9a-f]{12}$")
        summary = dict(settings.to_dict(), audit_sinks={"count": 4, "types": ["http", "syslog", "unknown"]})
        canonical = json.dumps(summary, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        self.assertEqual(digest, hashlib.sha256(canonical.encode("ascii")).hexdigest()[:12])
        # what 0.1.0 gave, so an upgrade raises no alert on an unapproved configuration
        self.assertEqual(Settings().digest(), "82752853a9ac")
        self.assertEqual(Settings(audit_log_path="/var/log/hermes/librenms-audit.jsonl").digest(), "0a6839d34d47")
        self.assertEqual(Settings(audit_sinks=list(reversed(self.SINKS))).digest(), digest)  # types are a set
        self.assertEqual(Settings(audit_sinks=self.SINKS, errors=["x"]).digest(), digest)
        rotated = [dict(spec) for spec in self.SINKS]
        rotated[1]["headers"] = {"Authorization": "Splunk rotated"}  # a collector token rotation is no policy change
        self.assertEqual(Settings(audit_sinks=rotated).digest(), digest)
        self.assertNotEqual(Settings(audit_sinks=self.SINKS[:3]).digest(), digest)

    def test_every_setting_changes_the_digest(self):
        base = Settings()
        changed = {
            "write_mode": "read_only",
            "audit_log_path": "/var/log/x.jsonl",
            "audit_sinks": [{"type": "http"}],
            **{name: not value for name, value in FAIL_CLOSED_FLAGS.items()},
            **{name: default + 1 for name, (default, _limit) in COUNTS.items()},
        }
        self.assertEqual(set(changed), set(base.to_dict()))
        digests = {base.digest()}
        for name, value in changed.items():
            digests.add(Settings(**{name: value}).digest())
        self.assertEqual(len(digests), len(changed) + 1)

    def test_the_same_settings_give_the_same_digest_in_another_process(self):
        raw = {"write_mode": "operator_only", "allow_delete": True, "audit_sinks": self.SINKS}
        script = (
            "import json, sys; sys.path.insert(0, sys.argv[1]); from tests.helpers import submodule; "
            "print(submodule('settings').Settings.from_mapping(json.loads(sys.argv[2])).digest())"
        )
        env = dict(os.environ, PYTHONHASHSEED="12345")
        out = subprocess.run(
            [sys.executable, "-c", script, str(REPO_ROOT), json.dumps(raw)],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
            check=True,
        )
        self.assertEqual(out.stdout.strip(), Settings.from_mapping(raw).digest())


class LiveSettings(unittest.TestCase):
    def setUp(self):
        settings_mod.set_settings(None)
        settings_mod.set_context(None)

    def tearDown(self):
        settings_mod.set_settings(None)
        settings_mod.set_context(None)

    def test_defaults_without_a_context(self):
        self.assertEqual(settings_mod.get_settings(), Settings())

    def test_the_context_is_read_on_every_call(self):
        # Hermes caches config.yaml by mtime, so an edit (the Desktop settings form) applies without a restart
        ctx = Ctx({"allow_delete": True})
        settings_mod.set_context(ctx)
        self.assertTrue(settings_mod.get_settings().allow_delete)
        ctx.values["allow_delete"] = False
        ctx.values["write_mode"] = "nonsense"
        current = settings_mod.get_settings()
        self.assertEqual((current.allow_delete, current.write_mode), (False, "read_only"))
        self.assertEqual(len(current.errors), 1)

    def test_pinned_settings_win_until_unpinned(self):
        pinned = Settings(max_operations=7)
        settings_mod.set_settings(pinned)
        settings_mod.set_context(Ctx({"max_operations": 9}))
        self.assertIs(settings_mod.get_settings(), pinned)
        settings_mod.set_settings(None)
        self.assertEqual(settings_mod.get_settings().max_operations, 9)
        settings_mod.set_context(None)
        settings_mod.set_settings(None)
        self.assertEqual(settings_mod.get_settings(), Settings())

    def test_a_read_that_fails_as_a_whole_keeps_the_last_good_settings(self):
        ctx = Ctx({"max_operations": 9})
        settings_mod.set_context(ctx)
        self.assertEqual(settings_mod.get_settings().max_operations, 9)
        ctx.values.update(max_operations=11, audit_sinks=[Undeepcopyable(type="http")])
        with self.assertRaises(RuntimeError):
            Settings.from_ctx(ctx)
        self.assertEqual(settings_mod.get_settings().max_operations, 9)
        del ctx.values["audit_sinks"]
        self.assertEqual(settings_mod.get_settings().max_operations, 11)


if __name__ == "__main__":
    unittest.main()
