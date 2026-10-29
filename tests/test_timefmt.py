"""Report times: stored UTC stamps shown in the zone Hermes uses, found as Hermes finds it but through its public
modules (``agent.secret_scope``, ``hermes_cli.config``). Hand-written stand-ins for those two go in ``sys.modules``;
the real loader test compares the result with Hermes' own resolver."""

import os
import sys
import types
import unittest

from .helpers import submodule

timefmt = submodule("timefmt")
STAMP = "2026-10-28T19:00:00Z"


class Zone(unittest.TestCase):
    def setUp(self):
        self.addCleanup(_restore_env, "HERMES_TIMEZONE", os.environ.pop("HERMES_TIMEZONE", None))
        self.multiplexed = False
        self.config = {"timezone": "America/Chicago", "model": {"default": "x"}}
        self.reads = 0
        self.install("agent.secret_scope", is_multiplex_active=lambda: self.multiplexed)
        self.install("hermes_cli.config", load_config_readonly=self.load_config_readonly)

    def load_config_readonly(self):
        self.reads += 1
        return self.config

    def install(self, name, **attributes):
        module = types.ModuleType(name)
        module.__dict__.update(attributes)
        self.addCleanup(_restore_module, name, sys.modules.get(name))
        sys.modules[name] = module

    def zone(self):
        found = timefmt.get_zone()
        return None if found is None else str(found)

    def test_the_variable_wins_then_the_profiles_setting(self):
        os.environ["HERMES_TIMEZONE"] = " Asia/Tokyo "
        self.assertEqual(self.zone(), "Asia/Tokyo")
        self.assertEqual(self.reads, 0)
        self.assertEqual(timefmt.local(STAMP), "2026-10-29 04:00:00 JST")
        del os.environ["HERMES_TIMEZONE"]
        self.assertEqual(self.zone(), "America/Chicago")
        self.assertEqual(timefmt.local(STAMP), "2026-10-28 14:00:00 CDT")

    def test_a_process_serving_several_profiles_reads_the_profiles_own_setting(self):
        # the variable then holds the default profile's zone, not the routed profile's
        os.environ["HERMES_TIMEZONE"] = "Asia/Tokyo"
        self.multiplexed = True
        self.assertEqual(self.zone(), "America/Chicago")

    def test_hermes_shared_config_is_never_modified(self):
        before = repr(self.config)
        timefmt.get_zone()
        self.assertEqual(repr(self.config), before)

    def test_no_zone_or_one_that_is_not_a_zone_is_the_hosts_local_zone(self):
        for value in ("", "  ", None, 5, ["UTC"], "Mars/Olympus_Mons", "../etc/passwd"):
            with self.subTest(value=value):
                self.config = {"timezone": value}
                self.assertIsNone(timefmt.get_zone())
        self.config = {}
        self.assertIsNone(timefmt.get_zone())
        host = timefmt.parse_utc(STAMP).astimezone()  # rendered in the host's zone
        self.assertEqual(timefmt.local(STAMP), f"{host:%Y-%m-%d %H:%M:%S} {host.tzname()}")

    def test_outside_hermes_only_the_variable_counts(self):
        for name in ("agent.secret_scope", "hermes_cli.config"):
            sys.modules[name] = None  # import fails, as without Hermes (setUp's cleanup restores it)
        self.assertIsNone(timefmt.get_zone())
        os.environ["HERMES_TIMEZONE"] = "Europe/Amsterdam"
        self.assertEqual(self.zone(), "Europe/Amsterdam")

    def test_a_resolver_that_raises_is_no_zone(self):
        def broken():
            raise RuntimeError("config.yaml is unreadable")

        self.install("hermes_cli.config", load_config_readonly=broken)
        self.install("agent.secret_scope", is_multiplex_active=broken)
        self.assertIsNone(timefmt.get_zone())


class Stamps(unittest.TestCase):
    def test_what_does_not_parse_is_shown_as_it_is(self):
        # an edited plan file may hold anything where a stamp belongs
        for value, shown in ((None, ""), ("", ""), ("yesterday", "yesterday"), (5, "5"), (["x"], "['x']")):
            with self.subTest(value=value):
                self.assertIsNone(timefmt.parse_utc(value))
                self.assertEqual(timefmt.local(value), shown)

    def test_a_stamp_without_a_zone_is_utc(self):
        self.assertEqual(timefmt.parse_utc("2026-10-28T19:00:00"), timefmt.parse_utc(STAMP))
        self.assertEqual(timefmt.parse_utc(STAMP).utcoffset().total_seconds(), 0)


def _restore_env(name, value):
    if value is None:
        os.environ.pop(name, None)
    else:
        os.environ[name] = value


def _restore_module(name, module):
    if module is None:
        sys.modules.pop(name, None)
    else:
        sys.modules[name] = module


if __name__ == "__main__":
    unittest.main()
