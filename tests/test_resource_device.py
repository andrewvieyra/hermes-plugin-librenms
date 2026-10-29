"""The device resource against the fake LibreNMS: validation and gates, plans, preconditions, verified writes,
partial writes, rollback, and the LibreNMS quirks the resource exists to absorb."""

from __future__ import annotations

import json
import os

from .base import PluginTestCase
from .fake_librenms import SECRETS
from .helpers import submodule

PLAN_ID = "lnp-20261028T120000Z-ab12"
CLIENT_LOG = "hermes_plugins.librenms.client"  # transport failures are detailed there, under their error id
ENV = "LIBRENMS_SNMP_COMMUNITY_SECRET"
COMMUNITY = "Env-Comm-9x!"  # the value behind ENV: it may reach LibreNMS and nothing else
OVERRIDE = (
    "LibreNMS re-assigns the location from SNMP sysLocation on every poll unless override_sysLocation is true; "
    'add "override_sysLocation": true'
)
RETARGET = (
    "retargeting a device changes which host LibreNMS polls with this device's SNMP credentials; set "
    "plugins.entries.librenms.settings.allow_device_add: true"
)
LITERAL = (
    "SNMP credentials are never written into a plan; set an environment variable such as "
    'LIBRENMS_SNMP_COMMUNITY_SECRET and pass {"env": "LIBRENMS_SNMP_COMMUNITY_SECRET"}, or omit the field to use '
    "LibreNMS's default credentials"
)
DELETE_NOTE = (
    "deleting a device removes its RRD history, ports, alerts and group membership; LibreNMS cannot restore it and "
    "re-adding creates a new device"
)
NOTES_APPENDED = "LibreNMS may append these notes to the device notes (user preference add_schedule_note_to_device)"
UPDATE_ALLOWED = (
    "disable_notify, disabled, display_template, hostname, icon, ignore, ignore_status, location, location_id, notes, "
    "override_sysLocation, overwrite_ip, poller_group, purpose, type"
)


def entry_for(step, result=None, status="done", **extra):
    """A journal entry as the executor writes it."""
    keys = ("index", "action", "resource", "object_id", "label", "parent_id", "inverse_kind")
    entry = {key: step.get(key) for key in keys}
    entry.update(status=status, at="2026-10-28T19:00:00Z", **(result or {}), **extra)
    return entry


class DeviceCase(PluginTestCase):
    def setUp(self):
        super().setUp()
        self.base = submodule("resources.base")
        self.resources = submodule("resources")
        self.module = submodule("resources.device")
        self.res = self.module.RESOURCE
        self.LibreNMSError = self.client_mod.LibreNMSError
        self.Settings = self.settings_mod.Settings
        self.context = {"plan_id": PLAN_ID, "settings": self.settings, "actor": None}
        self.addCleanup(os.environ.pop, ENV, None)

    def plan(self, kind, data=None, id=None, match=None, settings=None):
        op = {"op": kind, "resource": "device", "id": id, "match": match, "data": data or {}}
        return self.res.plan_step(self.client, 0, op, settings or self.settings)

    def apply(self, step, settings=None):
        context = dict(self.context, settings=settings) if settings is not None else self.context
        return self.res.execute(self.client, step, context)

    def applied(self, kind, data=None, id=None):
        step = self.plan(kind, data, id=id)
        return step, entry_for(step, self.apply(step))

    def revert(self, entry, force=False, step=None, settings=None):
        context = dict(self.context, step=step) if step is not None else dict(self.context)
        if settings is not None:
            context["settings"] = settings
        return self.res.revert(self.client, entry, force, context)

    def validate(self, op, data):
        return self.res.validate(op, data, self.settings)

    def device(self, device_id):
        return self.fake.tables["devices"][device_id]

    def writes(self):
        return [(c["method"], c["path"], c["json"]) for c in self.fake.writes()]

    def paths(self, method="GET"):
        return [c["path"] for c in self.fake.calls if c["method"] == method]


class Registry(DeviceCase):
    def test_module_resource_is_registered_under_its_name(self):
        self.assertIs(self.resources.get_resource("device"), self.res)
        self.assertEqual(self.res.ops, ("create", "update", "delete", "maintenance", "discover"))
        self.assertEqual(
            {op: kind for op, (kind, _note) in self.res.inverse.items()},
            {"create": "exact", "update": "exact", "delete": "none", "maintenance": "none", "discover": "not_needed"},
        )


class Validation(DeviceCase):
    def test_update_refuses_fields_outside_the_allowed_set(self):
        errors = self.validate("update", {"sysName": "x", "status": 0, "display": "d", "ip": "192.0.2.9", "notes": ""})
        self.assertEqual(
            errors, [f"cannot update device field(s) display, ip, status, sysName; allowed: {UPDATE_ALLOWED}"]
        )
        errors = self.validate("update", {"port_association_mode": "ifName"})
        self.assertEqual(errors, [f"cannot update device field(s) port_association_mode; allowed: {UPDATE_ALLOWED}"])

    def test_snmp_settings_of_an_existing_device_get_their_own_message(self):
        errors = self.validate("update", {"community": {"env": ENV}, "snmpver": "v3", "port": 0, "purpose": "x"})
        self.assertEqual(
            errors,
            [
                "LibreNMS API v0 cannot change SNMP settings or credentials of an existing device "
                "(community, port, snmpver)"
            ],
        )

    def test_value_types_ranges_and_nulls(self):
        errors = self.validate(
            "update", {"disabled": "maybe", "poller_group": -1, "location_id": 0, "hostname": "12345", "ignore": None}
        )
        self.assertEqual(
            errors,
            [
                'disabled: expected true or false, got "maybe"',
                "ignore: null is not allowed",
                "hostname: LibreNMS reads an all-digit hostname as a device id; use a name or an IP",
                "location_id: expected an integer 1 or more, got 0",
                "poller_group: expected an integer 0 or more, got -1",
            ],
        )
        self.assertEqual(self.validate("update", {"disabled": "true", "ignore": 0, "notes": None, "icon": None}), [])

    def test_location_shapes_and_hostname_syntax(self):
        errors = self.validate("update", {"location": " ", "location_id": 2, "hostname": "sw 1/x"})
        self.assertEqual(
            errors,
            [
                "hostname: expected a host name or IP address (letters, digits, '.', '-', '_', ':'), got \"sw 1/x\"",
                "give location (a name) or location_id, not both",
                "location: expected a location name, got an empty string",
            ],
        )
        self.assertEqual(self.validate("update", {"location": None}), [])
        self.assertEqual(self.validate("update", {"hostname": "2001:db8::10"}), [])
        self.assertIn("hostname: expected a host name", self.validate("update", {"hostname": ".."})[0])

    def test_create_requires_hostname_and_refuses_update_only_fields(self):
        errors = self.validate("create", {"purpose": "x", "port": 70000})
        self.assertTrue(errors[0].startswith("cannot create device field(s) purpose; allowed: "))
        self.assertEqual(
            errors[1:],
            ["hostname is required to create a device", "port: expected an integer between 1 and 65535, got 70000"],
        )

    def test_literal_credentials_are_refused_without_quoting_them(self):
        errors = self.validate("create", {"hostname": "new.example.net", "community": "public-Secret-1"})
        self.assertEqual(errors, [f"community: {LITERAL}"])
        self.assertNotIn("public-Secret-1", "\n".join(errors))
        errors = self.validate("create", {"hostname": "new.example.net", "community": {"env": "Sup3r-Secret"}})
        self.assertEqual(
            errors, ["community: the environment variable must be named LIBRENMS_SNMP_<NAME> (A-Z, 0-9 and _)"]
        )
        self.assertNotIn("Sup3r-Secret", "\n".join(errors))

    def test_credential_reference_must_name_a_set_variable(self):
        data = {"hostname": "new.example.net", "community": {"env": ENV}}
        self.assertEqual(
            self.validate("create", data), [f"community: {ENV} is not set in this Hermes profile's environment"]
        )
        os.environ[ENV] = COMMUNITY
        self.assertEqual(self.validate("create", data), [])
        self.assertEqual(self.validate("create", {"hostname": "new.example.net", "community": None}), [])

    def test_a_secret_lives_in_a_variable_whose_name_hermes_masks(self):
        # Hermes masks an environment dump's value by the variable's name: always for *_SECRET, *_PASS and
        # *_PASSWORD, never for LIBRENMS_SNMP_COMMUNITY or LIBRENMS_SNMP_V3_PRIV (0.1.0's suggestions)
        unmasked = (
            "the environment variable must be named LIBRENMS_SNMP_<NAME> ending in _SECRET, _PASS or _PASSWORD (A-Z, "
            "0-9 and _), such as LIBRENMS_SNMP_COMMUNITY_SECRET or LIBRENMS_SNMP_V3_AUTH_PASS: Hermes masks only "
            "such names when the agent's terminal prints the environment"
        )
        names = ("LIBRENMS_SNMP_COMMUNITY", "LIBRENMS_SNMP_V3_PRIV", "LIBRENMS_SNMP_CORE_KEY", "LIBRENMS_SNMP_XSECRET")
        for name in names:
            self.addCleanup(os.environ.pop, name, None)
            os.environ[name] = COMMUNITY
            for field in ("community", "authpass", "cryptopass"):
                errors = self.validate("create", {"hostname": "new.example.net", field: {"env": name}})
                self.assertIn(f"{field}: {unmasked}", errors, (field, name))
        names = ("LIBRENMS_SNMP_SECRET", "LIBRENMS_SNMP_V3_AUTH_PASS", "LIBRENMS_SNMP_EDGE_2_PASSWORD")
        for name in names:
            self.addCleanup(os.environ.pop, name, None)
            os.environ[name] = COMMUNITY
            self.assertEqual(self.validate("create", {"hostname": "new.example.net", "community": {"env": name}}), [])
        # the SNMPv3 user name is no password: any LIBRENMS_SNMP_ name will do
        os.environ["LIBRENMS_SNMP_COMMUNITY"] = "snmp-user"
        data = {"hostname": "new.example.net", "snmpver": "v3", "authlevel": "noAuthNoPriv",
                "authname": {"env": "LIBRENMS_SNMP_COMMUNITY"}}  # fmt: skip
        self.assertEqual(self.validate("create", data), [])

    def test_snmpv3_fields_must_agree(self):
        os.environ[ENV] = COMMUNITY
        ref = {"env": ENV}
        errors = self.validate(
            "create", {"hostname": "h.example.net", "snmpver": "v2c", "authpass": ref, "authlevel": "authPriv"}
        )
        self.assertEqual(
            errors, ['authlevel, authpass: SNMPv3 settings need "snmpver": "v3"', "authlevel authPriv needs cryptopass"]
        )
        errors = self.validate("create", {"hostname": "h.example.net", "snmpver": "v3", "community": ref})
        self.assertEqual(
            errors, ["community is an SNMPv1/v2c credential; SNMPv3 uses authname, authpass and cryptopass"]
        )
        data = {"hostname": "h.example.net", "snmpver": "v3", "authlevel": "authPriv", "authname": ref,
                "authpass": ref, "authalgo": "SHA-256", "cryptopass": ref, "cryptoalgo": "AES-256"}  # fmt: skip
        self.assertEqual(self.validate("create", data), [])
        self.assertEqual(
            self.validate("create", {"hostname": "h.example.net", "authalgo": "SHA-1"}),
            [
                'authalgo: expected one of MD5, SHA, SHA-224, SHA-256, SHA-384, SHA-512, got "SHA-1"',
                'authalgo: SNMPv3 settings need "snmpver": "v3"',
            ],
        )

    def test_maintenance_data(self):
        self.assertEqual(
            self.validate("maintenance", {"duration": "120"}), ['duration is required as "H:MM" (for example "2:00")']
        )
        self.assertEqual(self.validate("maintenance", {"duration": "0:00"}), ["duration must be longer than 0:00"])
        self.assertEqual(
            self.validate("maintenance", {"duration": "72:01"}),
            ["duration 72:01 is longer than max_maintenance_hours allows (72 hours)"],
        )
        errors = self.validate(
            "maintenance",
            {"duration": "2:00", "start": "2026-10-28T13:00", "behavior": "panic", "title": 5, "until": "x"},
        )
        self.assertEqual(
            errors,
            [
                "maintenance does not take until; allowed: behavior, duration, notes, start, title",
                'start must be "YYYY-MM-DD HH:MM:SS" in LibreNMS server time, or null for now',
                "title: expected a string of at most 200 characters",
                "behavior must be one of skip_alerts, mute_alerts, run_alerts (or 1, 2, 3)",
            ],
        )
        self.assertEqual(len(self.validate("maintenance", {"duration": "1:00", "start": "2026-02-30 01:00:00"})), 1)
        self.assertEqual(
            self.validate("maintenance", {"duration": "1:00", "title": "x" * 201}),
            ["title: expected a string of at most 200 characters"],
        )
        valid = {"duration": "72:00", "start": "2026-10-29 01:00:00", "behavior": 2, "title": "IOS", "notes": "n"}
        self.assertEqual(self.validate("maintenance", valid), [])
        self.assertEqual(self.validate("maintenance", {"duration": "1:30", "behavior": "3"}), [])

    def test_delete_and_discover_have_no_data_rules(self):
        self.assertEqual(self.validate("delete", {}), [])
        self.assertEqual(self.validate("discover", {}), [])


class Planning(DeviceCase):
    def test_update_step(self):
        step = self.plan("update", {"purpose": "spine", "disabled": "true", "notes": None}, id=1)
        self.assertEqual(
            (step["action"], step["object_id"], step["label"], step["resolved_by"], step["parent_id"]),
            ("update", 1, "core-sw1.example.net", "id", None),
        )
        self.assertEqual(
            step["changes"], {"purpose": {"from": "core", "to": "spine"}, "disabled": {"from": False, "to": True}}
        )
        self.assertEqual(step["payload"], {"field": ["purpose", "disabled"], "data": ["spine", True]})
        self.assertEqual(
            step["precondition"]["state"],
            {
                "device_id": 1, "hostname": "core-sw1.example.net", "inserted": self.device(1)["inserted"],
                "notes": "", "purpose": "core", "display_template": "", "overwrite_ip": "", "poller_group": 0,
                "location_id": 1, "disabled": False, "ignore": False, "disable_notify": False, "ignore_status": False,
                "override_sysLocation": True, "type": "network", "icon": "",
            },
        )  # fmt: skip
        self.assertEqual((step["inverse_kind"], step["inverse_note"], step["notes"]), ("exact", "", []))
        self.assertEqual(self.res.describe(step), ["disabled: false -> true", 'purpose: "core" -> "spine"'])
        self.assertEqual(self.writes(), [])

    def test_noop(self):
        step = self.plan("update", {"purpose": "core", "ignore": 0, "override_sysLocation": "1", "notes": None}, id=1)
        self.assertEqual((step["action"], step["reason"]), ("noop", "already matches desired state"))
        self.assertNotIn("inverse_kind", step)

    def test_match_by_hostname(self):
        step = self.plan("update", {"purpose": "spine"}, match={"hostname": "CORE-SW1.example.net"})
        self.assertEqual((step["object_id"], step["resolved_by"]), (1, "match"))
        with self.assertRaisesRegex(self.base.StepError, r"^all-digit hostnames cannot be looked up by name; use id$"):
            self.plan("update", {"purpose": "x"}, match={"hostname": "1234"})
        with self.assertRaisesRegex(self.base.StepError, r'^no device matches \{"hostname": "ghost.example.net"\}$'):
            self.plan("update", {"purpose": "x"}, match={"hostname": "ghost.example.net"})

    def test_a_403_for_a_hostname_is_explained(self):
        denied = {"status": "error", "message": "Insufficient permissions to access this device"}
        self.fake.fail_on("GET", r"devices/ghost\.example\.net", 403, denied)
        with self.assertRaises(self.base.StepError) as ctx:
            self.plan("update", {"purpose": "x"}, match={"hostname": "ghost.example.net"})
        self.assertEqual(
            str(ctx.exception),
            'LibreNMS answered 403 for hostname "ghost.example.net": it does not exist or this token cannot see it '
            "(LibreNMS returns 403 for unknown hostnames to tokens without global read); use the device id or a "
            "token with global read",
        )

    def test_unknown_id(self):
        with self.assertRaisesRegex(self.base.StepError, r"^device #99 does not exist$"):
            self.plan("delete", id=99)

    def test_location_by_name_needs_override_and_is_labelled(self):
        with self.assertRaises(self.base.StepError) as ctx:
            self.plan("update", {"location": "LON-3"}, id=4)
        self.assertEqual(str(ctx.exception), OVERRIDE)
        step = self.plan("update", {"location": "LON-3", "override_sysLocation": True}, id=4)
        self.assertEqual(
            step["changes"],
            {
                "override_sysLocation": {"from": False, "to": True},
                "location_id": {"from": None, "to": 3, "to_label": "LON-3"},
            },
        )
        self.assertEqual(step["payload"], {"field": ["override_sysLocation", "location_id"], "data": [True, 3]})
        self.assertEqual(
            self.res.describe(step), ["location_id: null -> 3 (LON-3)", "override_sysLocation: false -> true"]
        )
        step = self.plan("update", {"location": "nyc-2"}, id=1)  # device 1 already overrides sysLocation
        self.assertEqual(
            step["changes"], {"location_id": {"from": 1, "to": 2, "from_label": "SFO-1", "to_label": "NYC-2"}}
        )
        step = self.plan("update", {"location": None}, id=1)
        self.assertEqual(step["changes"], {"location_id": {"from": 1, "to": None, "from_label": "SFO-1"}})
        with self.assertRaises(self.base.StepError) as ctx:
            self.plan("update", {"location": "Atlantis", "override_sysLocation": True}, id=4)
        self.assertEqual(
            str(ctx.exception),
            'no location is named "Atlantis"; create it first (resource location) or use location_id',
        )
        self.assertEqual(len(self.fake.tables["locations"]), 3)  # the name is never sent, so nothing was created

    def test_an_unchanged_location_needs_no_override(self):
        self.fake.touch("devices", 4, location_id=2)
        self.assertEqual(self.plan("update", {"location_id": 2}, id=4)["action"], "noop")

    def test_location_id_must_exist(self):
        with self.assertRaisesRegex(self.base.StepError, r"^location #99 does not exist$"):
            self.plan("update", {"location_id": 99}, id=1)

    def test_poller_group_must_exist_and_group_zero_is_never_fetched(self):
        step = self.plan("update", {"poller_group": 0}, id=2)
        self.assertEqual(step["changes"], {"poller_group": {"from": 1, "to": 0}})
        self.assertNotIn("poller_group/0", self.paths())
        step = self.plan("update", {"poller_group": "1"}, id=1)
        self.assertEqual(step["changes"], {"poller_group": {"from": 0, "to": 1}})
        self.assertIn("poller_group/1", self.paths())
        with self.assertRaisesRegex(
            self.base.StepError, r"^poller group #7 does not exist \(0 is the default group\)$"
        ):
            self.plan("update", {"poller_group": 7}, id=1)

    def test_retargeting_needs_allow_device_add(self):
        strict = self.Settings(allow_device_add=False)
        for data in ({"hostname": "core-sw1b.example.net"}, {"overwrite_ip": "192.0.2.200"}):
            with self.assertRaises(self.base.StepError) as ctx:
                self.plan("update", data, id=1, settings=strict)
            self.assertEqual(str(ctx.exception), RETARGET)
        self.assertEqual(self.plan("update", {"overwrite_ip": "198.51.100.2"}, id=2, settings=strict)["action"], "noop")
        self.assertEqual(self.plan("update", {"purpose": "x"}, id=1, settings=strict)["action"], "update")

    def test_rename(self):
        step = self.plan("update", {"hostname": "core-sw1b.example.net", "notes": "moved"}, id=1)
        self.assertEqual(step["payload"], {"field": ["notes"], "data": ["moved"], "rename": "core-sw1b.example.net"})
        self.assertEqual(
            self.res.describe(step),
            [
                'hostname: "core-sw1.example.net" -> "core-sw1b.example.net"',
                'notes: "" -> "moved"',
                'poll target: "core-sw1.example.net" -> "core-sw1b.example.net"',
            ],
        )
        step = self.plan("update", {"overwrite_ip": "198.51.100.20"}, id=2)
        self.assertEqual(self.res.describe(step)[-1], 'poll target: "198.51.100.2" -> "198.51.100.20"')
        with self.assertRaises(self.base.StepError) as ctx:
            self.plan("update", {"hostname": "edge-rtr1.example.net"}, id=1)
        self.assertEqual(str(ctx.exception), 'hostname "edge-rtr1.example.net" is already used by device #2')

    def test_a_rename_that_only_changes_case_is_no_retarget(self):
        strict = self.Settings(allow_device_add=False)  # the same host: LibreNMS polls the same address
        step = self.plan("update", {"hostname": "Core-SW1.example.net"}, id=1, settings=strict)
        self.assertEqual(step["changes"], {"hostname": {"from": "core-sw1.example.net", "to": "Core-SW1.example.net"}})
        self.assertEqual(step["payload"], {"rename": "Core-SW1.example.net"})
        self.assertIsNone(self.res.check(self.client, step))  # the device itself does not hold the name
        with self.assertRaises(self.base.StepError) as ctx:
            self.plan("update", {"hostname": "Core-SW1b.example.net"}, id=1, settings=strict)
        self.assertEqual(str(ctx.exception), RETARGET)

    def test_an_upsert_matched_in_other_letter_case_keeps_librenms_spelling(self):
        data = {"hostname": "CORE-SW1.EXAMPLE.NET", "purpose": "spine"}
        step = self.plan("create", data, match={"hostname": "CORE-SW1.EXAMPLE.NET"})
        self.assertEqual((step["action"], step["object_id"]), ("update", 1))
        self.assertEqual(step["changes"], {"purpose": {"from": "core", "to": "spine"}})
        self.assertEqual(
            step["notes"],
            ['hostname: the match found "core-sw1.example.net", the same host in other letter case; LibreNMS\'s '
             "spelling is kept"],
        )  # fmt: skip
        step = self.plan("create", {"hostname": "Core-SW1.example.net"}, match={"hostname": "core-sw1.example.net"})
        self.assertEqual(step["action"], "noop")

    def test_a_hostname_with_a_slash_matches_nothing_and_is_never_sent(self):
        with self.assertRaisesRegex(self.base.StepError, r'^no device matches \{"hostname": "sw1/x"\}$'):
            self.plan("update", {"purpose": "x"}, match={"hostname": "sw1/x"})
        self.assertEqual(self.fake.calls, [])

    def test_discovery_owned_fields_carry_a_warning(self):
        step = self.plan("update", {"type": "server", "icon": "linux.svg"}, id=1)
        self.assertEqual(step["notes"], ["icon: discovery may overwrite this", "type: discovery may overwrite this"])

    def test_create_step(self):
        os.environ[ENV] = COMMUNITY
        data = {"hostname": "new-sw9.example.net", "community": {"env": ENV}, "location": "LON-3",
                "override_sysLocation": "yes", "snmpver": "v2c", "port": "1161", "force_add": False}  # fmt: skip
        step = self.plan("create", data)
        self.assertEqual(
            (step["action"], step["object_id"], step["label"], step["resolved_by"]),
            ("create", None, "new-sw9.example.net", None),
        )
        self.assertEqual(
            step["data"],
            {"hostname": "new-sw9.example.net", "community": {"env": ENV}, "override_sysLocation": True,
             "snmpver": "v2c", "port": 1161, "force_add": False, "location_id": 3},
        )  # fmt: skip
        self.assertEqual(step["exists_check"], {"hostname": "new-sw9.example.net"})
        self.assertEqual(
            (step["inverse_kind"], step["inverse_note"]),
            ("exact", "removes the device; LibreNMS keeps the SNMP credential record it created"),
        )
        self.assertEqual(step["notes"], [])
        self.assertEqual(
            self.res.describe(step),
            [
                'hostname="new-sw9.example.net", community=$LIBRENMS_SNMP_COMMUNITY_SECRET, '
                'override_sysLocation=true, snmpver="v2c", port=1161, force_add=false, location_id=3',
                'precondition: no device matches {"hostname": "new-sw9.example.net"}',
            ],
        )
        self.assertNotIn(COMMUNITY, json.dumps(step))
        self.assertEqual(self.writes(), [])

    def test_create_leaves_poller_group_0_to_librenms(self):
        step = self.plan("create", {"hostname": "new.example.net", "snmp_disable": True, "poller_group": 0})
        self.assertEqual(step["data"], {"hostname": "new.example.net", "snmp_disable": True})
        self.assertEqual(
            step["notes"],
            ["poller_group 0 is not sent: LibreNMS puts a new device without a group in its default poller group "
             "(setting default_poller_group, 0 unless changed); set poller_group with an update after the add if it "
             "must be 0"],
        )  # fmt: skip
        step = self.plan("create", {"hostname": "new.example.net", "snmp_disable": True, "poller_group": 1})
        self.assertEqual((step["data"]["poller_group"], step["notes"]), (1, []))

    def test_create_notes_default_credentials_and_refuses_an_existing_hostname(self):
        step = self.plan("create", {"hostname": "new.example.net"})
        self.assertEqual(
            step["notes"], ["no SNMP credentials given: LibreNMS tries its configured default credentials"]
        )
        self.assertEqual(self.plan("create", {"hostname": "new.example.net", "snmp_disable": True})["notes"], [])
        with self.assertRaises(self.base.StepError) as ctx:
            self.plan("create", {"hostname": "access-sw2.example.net"})
        self.assertEqual(
            str(ctx.exception),
            'device "access-sw2.example.net" already exists (#3); change it with update, or create with match to '
            "upsert",
        )
        with self.assertRaises(self.base.StepError) as ctx:
            self.plan("create", {"hostname": "new.example.net", "location_id": 2})
        self.assertEqual(str(ctx.exception), OVERRIDE)

    def test_upsert(self):
        os.environ[ENV] = COMMUNITY
        data = {"hostname": "access-sw2.example.net", "display_template": "{{ $hostname }}",
                "community": {"env": ENV}, "snmpver": "v2c"}  # fmt: skip
        step = self.plan("create", data, match={"hostname": "access-sw2.example.net"})
        self.assertEqual((step["action"], step["upsert"], step["object_id"]), ("update", True, 3))
        self.assertEqual(step["changes"], {"display_template": {"from": "", "to": "{{ $hostname }}"}})
        self.assertEqual(
            step["notes"],
            [
                "community cannot be changed on an existing device; the matched one keeps its own value",
                "snmpver cannot be changed on an existing device; the matched one keeps its own value",
            ],
        )
        step = self.plan("create", {"hostname": "access-sw2.example.net"}, match={"hostname": "access-sw2.example.net"})
        self.assertEqual(step["action"], "noop")
        step = self.plan("create", {"hostname": "new.example.net"}, match={"hostname": "new.example.net"})
        self.assertEqual((step["action"], step["resolved_by"]), ("create", "match"))

    def test_delete_step_keeps_a_masked_snapshot(self):
        step = self.plan("delete", id=2)
        snapshot = step["snapshot"]
        self.assertEqual(snapshot["hostname"], "edge-rtr1.example.net")
        for key in ("authname", "authpass", "cryptopass"):
            self.assertEqual(snapshot[key], "<redacted>")
        self.assertEqual((step["inverse_kind"], step["inverse_note"]), ("none", DELETE_NOTE))
        self.assertEqual(step["precondition"]["state"]["hostname"], "edge-rtr1.example.net")
        self.assertEqual(
            self.res.describe(step),
            [
                "the device is deleted with its ports, services, alerts, eventlog and RRD history (sysName "
                '"edge-rtr1", os "iosxe", hardware "ISR4451-X/K9", serial null, location "SFO-1")'
            ],
        )

    def test_maintenance_step(self):
        step = self.plan("maintenance", {"duration": "2:00", "notes": "IOS upgrade", "behavior": 2}, id=1)
        self.assertEqual(
            step["params"],
            {"duration": "2:00", "start": None, "title": None, "notes": "IOS upgrade", "behavior": "mute_alerts"},
        )
        self.assertEqual(step["inverse_kind"], "none")
        self.assertEqual(
            step["inverse_note"],
            "LibreNMS API v0 cannot end or delete maintenance; it expires after 2:00. To end it early, delete the "
            "schedule whose title starts with [hermes:<plan id>] under Alerts → Scheduled Maintenance.",
        )
        self.assertEqual(step["notes"], [NOTES_APPENDED])
        self.assertEqual(
            self.res.describe(step),
            ['duration 2:00, behavior mute_alerts, title "core-sw1.example.net", starts now, notes "IOS upgrade"'],
        )
        step = self.plan("maintenance", {"duration": "0:30", "start": "2026-10-29 02:00:00", "title": "PSU"}, id=3)
        self.assertEqual((step["params"]["behavior"], step["params"]["notes"], step["notes"]), ("skip_alerts", "", []))
        self.assertEqual(
            self.res.describe(step),
            ['duration 0:30, behavior skip_alerts, title "PSU", start 2026-10-29 02:00:00 (LibreNMS server time)'],
        )

    def test_discover_step(self):
        step = self.plan("discover", id=4)
        self.assertEqual((step["action"], step["params"], step["inverse_kind"]), ("discover", {}, "not_needed"))
        self.assertEqual(self.res.describe(step), ["LibreNMS rediscovers the device at its next discovery run"])

    def test_no_device_secret_reaches_a_step(self):
        steps = [
            self.plan("update", {"purpose": "wan-edge"}, id=2),
            self.plan("delete", id=1),
            self.plan("maintenance", {"duration": "1:00"}, id=3),
            self.plan("discover", id=4),
        ]
        text = json.dumps(steps)
        for secret in SECRETS:
            self.assertNotIn(secret, text)


class Check(DeviceCase):
    def test_unchanged_device_passes_and_an_edit_conflicts(self):
        step = self.plan("update", {"purpose": "spine"}, id=1)
        self.assertIsNone(self.res.check(self.client, step))
        self.fake.touch("devices", 1, notes="changed by hand", disabled=1)
        self.assertEqual(
            self.res.check(self.client, step),
            'device #1 changed since planning (disabled: false -> true, notes: "" -> "changed by hand")',
        )

    def test_poller_churn_is_ignored_unless_the_step_writes_it(self):
        step = self.plan("update", {"purpose": "spine"}, id=1)
        self.fake.touch("devices", 1, type="server", icon="ios.svg", uptime=5, status=0, sysName="other")
        self.assertIsNone(self.res.check(self.client, step))
        step = self.plan("update", {"type": "server"}, id=3)
        self.fake.touch("devices", 3, type="wireless")
        self.assertEqual(
            self.res.check(self.client, step), 'device #3 changed since planning (type: "network" -> "wireless")'
        )

    def test_location_is_volatile_only_without_override(self):
        step = self.plan("update", {"purpose": "x"}, id=4)
        self.fake.touch("devices", 4, location_id=2)  # the poller follows sysLocation on this device
        self.assertIsNone(self.res.check(self.client, step))
        step = self.plan("update", {"purpose": "x"}, id=3)
        self.fake.touch("devices", 3, location_id=1)
        self.assertEqual(self.res.check(self.client, step), "device #3 changed since planning (location_id: 2 -> 1)")

    def test_identity_and_existence(self):
        step = self.plan("delete", id=3)
        inserted = self.device(3)["inserted"]
        self.fake.touch("devices", 3, inserted="2026-10-28T13:00:00.000000Z")  # deleted and added again
        self.assertEqual(
            self.res.check(self.client, step),
            f'device #3 changed since planning (inserted: "{inserted}" -> "2026-10-28T13:00:00.000000Z")',
        )
        del self.fake.tables["devices"][3]
        self.assertEqual(self.res.check(self.client, step), "device #3 no longer exists")

    def test_rename_target_taken_and_location_gone_since_planning(self):
        step = self.plan("update", {"hostname": "core-sw1b.example.net"}, id=1)
        self.fake.touch("devices", 3, hostname="core-sw1b.example.net")
        self.assertEqual(
            self.res.check(self.client, step), 'hostname "core-sw1b.example.net" is already used by device #3'
        )
        step = self.plan("update", {"location_id": 3}, id=1)
        del self.fake.tables["locations"][3]
        self.assertEqual(self.res.check(self.client, step), "location #3 no longer exists")

    def test_create_conflicts_when_the_hostname_appeared(self):
        step = self.plan("create", {"hostname": "new-sw9.example.net"})
        self.assertIsNone(self.res.check(self.client, step))
        self.fake.seed("devices", {"hostname": "new-sw9.example.net"})
        self.assertEqual(
            self.res.check(self.client, step),
            '1 device(s) now match {"hostname": "new-sw9.example.net"}; expected none',
        )

    def test_actions_need_only_the_device(self):
        step = self.plan("maintenance", {"duration": "1:00"}, id=1)
        self.fake.touch("devices", 1, purpose="edited")
        self.assertIsNone(self.res.check(self.client, step))
        del self.fake.tables["devices"][1]
        self.assertEqual(self.res.check(self.client, step), "device #1 no longer exists")


class Execute(DeviceCase):
    def test_update_is_one_multi_field_patch_with_json_booleans(self):
        step = self.plan("update", {"purpose": "spine", "disabled": "true", "ignore": "0"}, id=1)
        result = self.apply(step)
        self.assertEqual(
            self.writes(), [("PATCH", "devices/1", {"field": ["purpose", "disabled"], "data": ["spine", True]})]
        )
        self.assertEqual((self.device(1)["purpose"], self.device(1)["disabled"]), ("spine", 1))
        self.assertEqual(set(result), {"object_id", "inverse", "after_state", "notes"})
        self.assertEqual(
            result["inverse"], {"action": "update", "object_id": 1, "data": {"purpose": "core", "disabled": False}}
        )
        self.assertEqual((result["after_state"]["purpose"], result["after_state"]["disabled"]), ("spine", True))

    def test_rename_patches_fields_then_renames_by_id(self):
        step = self.plan("update", {"notes": "moved to v6", "hostname": "2001:db8::10"}, id=3)
        result = self.apply(step)
        self.assertEqual(
            self.writes(),
            [
                ("PATCH", "devices/3", {"field": ["notes"], "data": ["moved to v6"]}),
                ("PATCH", "devices/3/rename/2001:db8::10", None),
            ],
        )
        self.assertIn("/api/v0/devices/3/rename/2001%3Adb8%3A%3A10", [c["path"] for c in self.client.calls])
        self.assertEqual(self.device(3)["hostname"], "2001:db8::10")
        self.assertEqual(result["inverse"]["data"], {"notes": "rack B4", "hostname": "access-sw2.example.net"})

    def test_location_is_sent_as_location_id(self):
        self.apply(self.plan("update", {"location": "LON-3", "override_sysLocation": True}, id=4))
        self.assertEqual(
            self.writes(),
            [("PATCH", "devices/4", {"field": ["override_sysLocation", "location_id"], "data": [True, 3]})],
        )
        self.assertEqual((self.device(4)["location_id"], len(self.fake.tables["locations"])), (3, 3))

    def test_a_write_librenms_accepts_but_ignores_is_partial(self):
        ok = {"status": "ok", "message": "Device fields have been updated"}
        self.fake.fail_on("PATCH", r"devices/1", 200, ok)  # what an unknown field name gets
        step = self.plan("update", {"purpose": "spine"}, id=1)
        with self.assertRaises(self.base.PartialWrite) as ctx:
            self.apply(step)
        self.assertEqual(str(ctx.exception), 'LibreNMS accepted the write but purpose is "core", expected "spine"')
        self.assertEqual(
            ctx.exception.entry["inverse"], {"action": "update", "object_id": 1, "data": {"purpose": "core"}}
        )

    def test_rename_failure_after_the_patch_is_partial_and_rolls_back(self):
        step = self.plan("update", {"purpose": "spine", "hostname": "core-sw1b.example.net"}, id=1)
        failed = {"status": "error", "message": "Renaming of core-sw1.example.net failed because the RRD directory "
                  "rename failed"}  # fmt: skip
        self.fake.fail_on("PATCH", r"devices/1/rename/.*", 500, failed)
        with self.assertRaises(self.base.PartialWrite) as ctx:
            self.apply(step)
        self.assertTrue(str(ctx.exception).endswith("(LibreNMS applied part of the step; rollback reverts it)"))
        entry = ctx.exception.entry
        self.assertEqual(
            (entry["after_state"]["purpose"], entry["after_state"]["hostname"]), ("spine", "core-sw1.example.net")
        )
        self.assertEqual(entry["inverse"]["data"], {"purpose": "core", "hostname": "core-sw1.example.net"})
        self.fake.calls.clear()
        self.assertEqual(
            self.revert(entry_for(step, entry, "failed", wrote=True)), ("reverted", {"restored_fields": ["purpose"]})
        )
        self.assertEqual(self.writes(), [("PATCH", "devices/1", {"field": ["purpose"], "data": ["core"]})])

    def test_server_error_after_the_write_landed_is_partial(self):
        self.fake.fail_on("PATCH", r"devices/1", 500, commit=True)
        step = self.plan("update", {"purpose": "spine"}, id=1)
        with self.assertRaises(self.base.PartialWrite) as ctx:
            self.apply(step)
        self.assertTrue(
            str(ctx.exception).startswith(
                "PATCH /api/v0/devices/1 -> HTTP 500: LibreNMS server error (details withheld; see the LibreNMS log)"
            )
        )
        self.fake.failures.clear()
        entry = entry_for(step, ctx.exception.entry, "failed", wrote=True)
        self.assertEqual(self.revert(entry), ("reverted", {"restored_fields": ["purpose"]}))
        self.assertEqual(self.device(1)["purpose"], "core")

    def test_rename_refused_as_a_duplicate_at_apply_is_a_plain_failure(self):
        step = self.plan("update", {"hostname": "core-sw1b.example.net"}, id=1)
        self.fake.touch("devices", 3, hostname="core-sw1b.example.net")  # taken between check and execute
        with self.assertRaises(self.LibreNMSError) as ctx:
            self.apply(step)
        self.assertEqual(
            str(ctx.exception),
            "PATCH /api/v0/devices/1/rename/core-sw1b.example.net -> HTTP 500: Renaming of core-sw1.example.net "
            "failed because there is already a device with the hostname core-sw1b.example.net",
        )
        self.assertEqual(self.device(1)["hostname"], "core-sw1.example.net")

    def test_failures_that_changed_nothing_propagate_unchanged(self):
        step = self.plan("update", {"purpose": "spine"}, id=1)
        refused = {"status": "error", "message": "Device field to patch has not been supplied"}
        self.fake.fail_on("PATCH", r"devices/1", 400, refused, times=1)
        with self.assertRaises(self.LibreNMSError) as ctx:
            self.apply(step)
        self.assertEqual(ctx.exception.kind, "api")
        self.fake.fail_on("PATCH", r"devices/1", exc=ConnectionRefusedError("connection refused"), times=1)
        with self.assertLogs(CLIENT_LOG, "WARNING"), self.assertRaises(self.LibreNMSError) as ctx:
            self.apply(step)
        self.assertEqual(ctx.exception.kind, "transport")
        self.assertEqual(self.paths()[-1], "devices/1")  # the re-read that proved nothing changed
        self.assertEqual(self.device(1)["purpose"], "core")

    def test_retargeting_is_checked_again_at_apply(self):
        step = self.plan("update", {"overwrite_ip": "192.0.2.200"}, id=1)
        with self.assertRaises(self.base.StepError) as ctx:
            self.apply(step, settings=self.Settings(allow_device_add=False))
        self.assertEqual(str(ctx.exception), RETARGET)
        self.assertEqual(self.writes(), [])
        self.apply(step)
        self.assertEqual(self.device(1)["overwrite_ip"], "192.0.2.200")

    def test_create_reads_the_credential_at_apply_and_verifies(self):
        os.environ[ENV] = COMMUNITY
        data = {"hostname": "new-sw9.example.net", "community": {"env": ENV}, "location": "LON-3",
                "override_sysLocation": True, "force_add": False, "ping_fallback": True}  # fmt: skip
        step = self.plan("create", data)
        result = self.apply(step)
        (post,) = self.fake.writes()
        self.assertEqual(post["path"], "devices")
        self.assertEqual(
            post["json"],
            {"hostname": "new-sw9.example.net", "community": COMMUNITY, "override_sysLocation": True,
             "ping_fallback": True, "location_id": 3},
        )  # fmt: skip
        self.assertEqual(post["timeout"], (10.0, 120.0))  # LibreNMS probes the host before it answers
        self.assertEqual(result["object_id"], 5)
        self.assertEqual(result["inverse"], {"action": "delete", "object_id": 5})
        self.assertEqual(
            (result["after_state"]["location_id"], result["after_state"]["hostname"]), (3, "new-sw9.example.net")
        )
        self.assertEqual(self.device(5)["community"], COMMUNITY)
        self.assertNotIn(COMMUNITY, json.dumps([step, result]))

    def test_create_with_poller_group_0_lands_in_the_default_group(self):
        self.fake.default_poller_group = 1
        step = self.plan("create", {"hostname": "new-sw9.example.net", "snmp_disable": True, "poller_group": 0})
        result = self.apply(step)
        (post,) = self.fake.writes()
        self.assertNotIn("poller_group", post["json"])
        self.assertEqual((result["object_id"], self.device(5)["poller_group"]), (5, 1))

    def test_a_rename_that_only_changes_case_is_applied_and_rolled_back(self):
        strict = self.Settings(allow_device_add=False)
        step = self.plan("update", {"hostname": "Core-SW1.example.net"}, id=1, settings=strict)
        entry = entry_for(step, self.apply(step, settings=strict))
        self.assertEqual(self.writes(), [("PATCH", "devices/1/rename/Core-SW1.example.net", None)])
        self.assertEqual(self.device(1)["hostname"], "Core-SW1.example.net")
        self.assertEqual(self.revert(entry, settings=strict), ("reverted", {"restored_fields": ["hostname"]}))
        self.assertEqual(self.device(1)["hostname"], "core-sw1.example.net")

    def test_create_with_the_variable_gone_fails_before_any_write(self):
        os.environ[ENV] = COMMUNITY
        step = self.plan("create", {"hostname": "new-sw9.example.net", "community": {"env": ENV}})
        del os.environ[ENV]
        with self.assertRaises(self.base.StepError) as ctx:
            self.apply(step)
        self.assertEqual(
            str(ctx.exception),
            f"community: {ENV} is not set in this Hermes profile's environment; set it and apply",
        )
        self.assertEqual(self.writes(), [])

    def test_create_error_quoting_the_credential_is_scrubbed(self):
        os.environ[ENV] = COMMUNITY
        step = self.plan("create", {"hostname": "new-sw9.example.net", "community": {"env": ENV}})
        echoed = {"status": "error", "message": f'SNMP v2c: No reply using community "{COMMUNITY}"'}
        self.fake.fail_on("POST", r"devices", 400, echoed)
        with self.assertRaises(self.LibreNMSError) as ctx:
            self.apply(step)
        self.assertEqual((ctx.exception.kind, ctx.exception.status), ("api", 400))
        self.assertIn('community "<redacted>"', str(ctx.exception))
        self.assertNotIn(COMMUNITY, json.dumps(ctx.exception.to_dict()))

    def test_a_community_shorter_than_four_characters_is_scrubbed_too(self):
        os.environ[ENV] = "pub"
        step = self.plan("create", {"hostname": "new-sw9.example.net", "community": {"env": ENV}})
        echoed = {"status": "error", "message": "SNMP v2c: No reply using pub (public, published)"}
        self.fake.fail_on("POST", r"devices", 400, echoed)
        with self.assertRaises(self.LibreNMSError) as ctx:
            self.apply(step)
        # where it stands alone; inside a longer word it would mask half the message
        self.assertEqual(
            str(ctx.exception),
            "POST /api/v0/devices -> HTTP 400: SNMP v2c: No reply using <redacted> (public, published)",
        )

    def test_create_whose_answer_was_lost_is_found_and_rolled_back(self):
        self.fake.fail_on("POST", r"devices", exc=TimeoutError("read timed out"), commit=True)
        step = self.plan("create", {"hostname": "new-sw9.example.net", "snmp_disable": True})
        with self.assertLogs(CLIENT_LOG, "WARNING"), self.assertRaises(self.base.PartialWrite) as ctx:
            self.apply(step)
        self.assertIn("could not reach LibreNMS (timeout)", str(ctx.exception))
        entry = ctx.exception.entry
        self.assertEqual((entry["object_id"], entry["inverse"]), (5, {"action": "delete", "object_id": 5}))
        self.assertEqual(entry["after_state"]["hostname"], "new-sw9.example.net")
        strict = self.Settings(allow_delete=False, allow_device_add=False)  # rollback is exempt from the gates
        journal = entry_for(step, entry, "failed", wrote=True)
        self.assertEqual(self.revert(journal, settings=strict), ("reverted", {"object_id": 5}))
        self.assertNotIn(5, self.fake.tables["devices"])

    def test_create_answer_without_an_id_is_located_by_hostname(self):
        self.fake.fail_on("POST", r"devices", 200, {"status": "ok", "message": "Device added"}, commit=True)
        result = self.apply(self.plan("create", {"hostname": "new-sw9.example.net", "snmp_disable": True}))
        self.assertEqual(result["object_id"], 5)

    def test_create_refused_by_librenms_is_a_plain_failure(self):
        step = self.plan("create", {"hostname": "new-sw9.example.net"})
        self.fake.seed("devices", {"hostname": "new-sw9.example.net"})
        with self.assertRaises(self.LibreNMSError) as ctx:
            self.apply(step)
        self.assertEqual(
            str(ctx.exception), "POST /api/v0/devices -> HTTP 400: Device new-sw9.example.net already exists"
        )

    def test_delete_is_verified_and_irreversible(self):
        step = self.plan("delete", id=3)
        result = self.apply(step)
        self.assertEqual(self.writes(), [("DELETE", "devices/3", None)])
        self.assertEqual(self.fake.writes()[0]["timeout"], (10.0, 120.0))  # LibreNMS removes every row and RRD file
        self.assertNotIn(3, self.fake.tables["devices"])
        self.assertEqual(result, {"object_id": 3, "inverse": None, "after_state": None, "notes": []})
        self.assertEqual(self.revert(entry_for(step, result)), ("irreversible", {"note": DELETE_NOTE}))

    def test_maintenance_posts_a_tagged_title_and_the_behavior_number(self):
        step = self.plan("maintenance", {"duration": "2:00", "title": "IOS upgrade", "behavior": "mute_alerts"}, id=1)
        result = self.apply(step)
        title = f"[hermes:{PLAN_ID}] IOS upgrade"
        self.assertEqual(
            self.writes(),
            [("POST", "devices/1/maintenance", {"duration": "2:00", "title": title, "notes": "", "behavior": 2})],
        )
        schedule = self.fake.schedules[-1]
        self.assertEqual((schedule["title"], schedule["behavior"], schedule["devices"]), (title, 2, [1]))
        self.assertIn("devices/1/maintenance", self.paths())
        self.assertEqual(
            result, {"object_id": 1, "inverse": None, "after_state": None, "notes": [f"schedule title: {title}"]}
        )
        status, details = self.revert(entry_for(step, result), step=step)
        self.assertEqual((status, details), ("irreversible", {"note": step["inverse_note"]}))

    def test_maintenance_with_a_start_is_not_checked_for_now(self):
        step = self.plan("maintenance", {"duration": "1:00", "start": "2026-10-29 02:00:00"}, id=1)
        result = self.apply(step)
        title = f"[hermes:{PLAN_ID}] core-sw1.example.net"
        self.assertEqual(
            self.writes(),
            [("POST", "devices/1/maintenance", {"duration": "1:00", "title": title, "notes": "", "behavior": 1,
                                                "start": "2026-10-29 02:00:00"})],
        )  # fmt: skip
        self.assertNotIn("devices/1/maintenance", self.paths())
        self.assertEqual(result["notes"], [f"schedule title: {title}"])

    def test_maintenance_notes_librenms_appended_are_journaled(self):
        step = self.plan("maintenance", {"duration": "0:30", "notes": "swap PSU"}, id=3)
        self.assertEqual(len(self.apply(step)["notes"]), 1)  # the preference is off: the device notes stay
        self.fake.add_schedule_note_to_device = True
        result = self.apply(step)
        self.assertEqual(
            result["notes"][-1],
            'LibreNMS appended the maintenance notes to the device notes; previous_notes: "rack B4"',
        )
        self.assertEqual(set(result), {"object_id", "inverse", "after_state", "notes"})  # all the executor journals
        self.assertIn("Alerts delayed: swap PSU", self.device(3)["notes"])

    def test_maintenance_post_that_may_have_landed_is_partial(self):
        step = self.plan("maintenance", {"duration": "1:00"}, id=1)
        self.fake.fail_on("POST", r"devices/1/maintenance", 500, commit=True, times=1)
        with self.assertRaises(self.base.PartialWrite) as ctx:
            self.apply(step)
        self.assertTrue(str(ctx.exception).endswith("(LibreNMS may have saved the maintenance schedule)"))
        title = f"[hermes:{PLAN_ID}] core-sw1.example.net"
        self.assertEqual(
            ctx.exception.entry,
            {"object_id": 1, "inverse": None, "after_state": None, "notes": [
                f"schedule title: {title}",
                "outcome unknown: look for the schedule title under Alerts → Scheduled Maintenance",
            ]},
        )  # fmt: skip
        self.assertEqual(self.fake.schedules[-1]["title"], title)
        journal = entry_for(step, ctx.exception.entry, "failed", wrote=True)
        self.assertEqual(self.revert(journal, step=step), ("irreversible", {"note": step["inverse_note"]}))
        self.fake.fail_on("POST", r"devices/1/maintenance", 404, {"status": "error", "message": "Device 1 not found"})
        with self.assertRaises(self.LibreNMSError) as ctx:  # refused before anything was saved: a plain failure
            self.apply(step)
        self.assertEqual(ctx.exception.kind, "not_found")
        self.assertEqual(len(self.fake.schedules), 1)

    def test_maintenance_title_fits_its_column(self):
        self.fake.touch("devices", 3, hostname="a" * 250 + ".net")
        step = self.plan("maintenance", {"duration": "1:00"}, id=3)
        self.apply(step)
        title = self.fake.schedules[-1]["title"]
        self.assertEqual((len(title), title[:36]), (255, f"[hermes:{PLAN_ID}] a"))

    def test_maintenance_verification_is_best_effort(self):
        step = self.plan("maintenance", {"duration": "1:00"}, id=1)
        self.fake.fail_on(
            "GET", r"devices/1/maintenance", 200, {"status": "ok", "is_under_maintenance": False}, times=1
        )
        self.assertEqual(self.apply(step)["notes"][-1], "LibreNMS does not report the device under maintenance yet")
        self.fake.fail_on("GET", r"devices/1/maintenance", 500)
        note = self.apply(step)["notes"][-1]
        self.assertTrue(
            note.startswith("the maintenance was accepted but could not be verified: GET /api/v0/devices/1/maintenance")
        )
        self.assertEqual(len(self.fake.schedules), 2)

    def test_discover(self):
        step = self.plan("discover", id=1)
        result = self.apply(step)
        self.assertIsNone(self.device(1)["last_discovered"])
        self.assertEqual(self.writes(), [])  # a GET, even though it changes state
        self.assertEqual(
            result, {"object_id": 1, "inverse": None, "after_state": None, "notes": ["Device will be rediscovered"]}
        )
        self.assertEqual(
            self.revert(entry_for(step, result)), ("skipped", {"note": "rediscovery only schedules a discovery run"})
        )

    def test_no_device_secret_reaches_a_result(self):
        step = self.plan("update", {"purpose": "wan-edge"}, id=2)
        result = self.apply(step)
        text = json.dumps([step, result])
        for secret in SECRETS:
            self.assertNotIn(secret, text)


class Revert(DeviceCase):
    def test_update_rollback_restores_fields_and_renames_back_by_id(self):
        step, entry = self.applied("update", {"hostname": "core-sw1b.example.net", "purpose": "spine"}, id=1)
        self.fake.calls.clear()
        self.assertEqual(self.revert(entry), ("reverted", {"restored_fields": ["hostname", "purpose"]}))
        self.assertEqual(
            self.writes(),
            [
                ("PATCH", "devices/1", {"field": ["purpose"], "data": ["core"]}),
                ("PATCH", "devices/1/rename/core-sw1.example.net", None),
            ],
        )
        self.assertEqual((self.device(1)["hostname"], self.device(1)["purpose"]), ("core-sw1.example.net", "core"))

    def test_update_rollback_conflicts_unless_forced(self):
        step, entry = self.applied("update", {"purpose": "spine"}, id=3)
        self.fake.touch("devices", 3, purpose="leaf", notes="edited later")
        status, details = self.revert(entry)
        self.assertEqual(status, "conflict")
        self.assertEqual(
            details["error"],
            'device #3 was modified after apply (notes: "rack B4" -> "edited later", purpose: "spine" -> "leaf"); use '
            "force to overwrite",
        )
        self.assertEqual(self.revert(entry, force=True), ("reverted", {"restored_fields": ["purpose"]}))
        self.assertEqual((self.device(3)["purpose"], self.device(3)["notes"]), ("access", "edited later"))

    def test_update_rollback_ignores_discovery_churn(self):
        step, entry = self.applied("update", {"purpose": "spine"}, id=1)
        self.fake.touch("devices", 1, type="server", icon="linux.svg")
        self.assertEqual(self.revert(entry), ("reverted", {"restored_fields": ["purpose"]}))

    def test_create_rollback_deletes_without_allow_delete_unless_modified(self):
        step, entry = self.applied("create", {"hostname": "new-sw9.example.net", "snmp_disable": True})
        self.assertEqual(entry["object_id"], 5)
        self.fake.touch("devices", 5, type="server", purpose="claimed by someone")
        strict = self.Settings(allow_delete=False, allow_device_add=False)
        status, details = self.revert(entry, settings=strict)
        self.assertEqual(status, "conflict")
        self.assertEqual(
            details["error"],
            'device #5 was modified after apply (purpose: "" -> "claimed by someone"); use force to delete anyway',
        )
        self.assertEqual(self.revert(entry, force=True, settings=strict), ("reverted", {"object_id": 5}))
        self.assertEqual(self.writes()[-1], ("DELETE", "devices/5", None))
        self.assertEqual(self.revert(entry), ("reverted", {"note": "object already gone"}))

    def test_update_of_unknown_outcome_restores_what_landed(self):
        step = self.plan("update", {"purpose": "spine", "hostname": "core-sw1b.example.net"}, id=1)
        self.fake.touch("devices", 1, purpose="spine")  # the process died after the PATCH, before the rename
        entry = entry_for(step, status="unknown", wrote=True)
        self.assertEqual(self.revert(entry, step=step), ("reverted", {"restored_fields": ["purpose"]}))
        self.assertEqual(self.writes(), [("PATCH", "devices/1", {"field": ["purpose"], "data": ["core"]})])
        self.fake.touch("devices", 1, purpose="leaf")  # neither the planned nor the previous value
        status, details = self.revert(entry, step=step)
        self.assertEqual(status, "conflict")
        self.assertIn("purpose on device #1 match neither the planned nor the previous value", details["error"])

    def test_create_of_unknown_outcome_is_found_and_deleted(self):
        step = self.plan("create", {"hostname": "new-sw9.example.net", "snmp_disable": True})
        self.fake.seed("devices", {"hostname": "new-sw9.example.net", "snmp_disable": 1, "type": "server"})
        entry = entry_for(step, status="unknown", wrote=True)  # the process died during the POST
        self.assertEqual(self.revert(entry, step=step), ("reverted", {"object_id": 5}))
        self.assertNotIn(5, self.fake.tables["devices"])
