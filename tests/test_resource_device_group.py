"""The device_group resource against the fake LibreNMS: validation, planning, apply-time checks, verified writes,
partial writes and rollback, for static groups (member lists) and dynamic ones (rules), and group maintenance."""

import json

from .base import PluginTestCase
from .fake_librenms import SECRETS
from .helpers import submodule

base = submodule("resources.base")
resources = submodule("resources")
client_mod = submodule("client")
LibreNMSError = client_mod.LibreNMSError

PLAN_ID = "lnp-20261028T120000Z-ab12"
EDGE_RULES = {
    "condition": "AND",
    "rules": [
        {
            "field": "devices.hostname",
            "id": "devices.hostname",
            "input": "text",
            "operator": "begins_with",
            "type": "string",
            "value": "edge-",
        }
    ],
    "valid": True,
}
LAB_RULES = {
    "condition": "OR",
    "rules": [
        {
            "field": "devices.purpose",
            "id": "devices.purpose",
            "input": "text",
            "operator": "equal",
            "type": "string",
            "value": "lab",
        }
    ],
    "valid": True,
}
CORE = {"id": 1, "name": "core-switches", "desc": "Core layer switches", "type": "static", "devices": [1]}
MAINTENANCE_NOTE = (
    "LibreNMS API v0 cannot end or delete maintenance; it expires after 2:00. To end it early, delete the schedule "
    "whose title starts with [hermes:<plan id>] under Alerts → Scheduled Maintenance."
)
DELETE_NOTE = (
    "re-created with a new id; alert rules, user permissions and maintenance linked to the old id are not restored"
)


class Died(BaseException):
    """The process dying during a request (Ctrl-C, OOM, a gateway restart): nothing in the plugin catches it."""


def resumable(context, entry):
    """*context* with the executor's ``checkpoint``: it merges progress into the entry's ``revert_progress``."""

    def checkpoint(progress):
        entry["revert_progress"] = {**(entry.get("revert_progress") or {}), **progress}

    return dict(context, checkpoint=checkpoint)


def entry_for(step, result=None, status="done", **extra):
    """A journal entry as the executor writes it."""
    entry = {
        key: step.get(key) for key in ("index", "action", "resource", "object_id", "label", "parent_id", "inverse_kind")
    }
    entry.update(status=status, at="2026-10-28T19:00:00Z", **(result or {}), **extra)
    return entry


class GroupCase(PluginTestCase):
    def setUp(self):
        super().setUp()
        self.res = resources.get_resource("device_group")
        self.context = {"plan_id": PLAN_ID, "settings": self.settings, "actor": None}

    def step(self, kind, data=None, id=None, match=None):
        op = {"op": kind, "resource": "device_group", "id": id, "match": match, "data": data or {}}
        return self.res.plan_step(self.client, 0, op, self.settings)

    def apply(self, step):
        self.fake.calls.clear()
        return self.res.execute(self.client, step, self.context)

    def revert(self, step, result=None, force=False, status="done"):
        self.fake.calls.clear()
        entry = entry_for(step, result, status)
        return self.res.revert(self.client, entry, force, dict(self.context, step=step))

    def group(self, group_id):
        return self.fake.tables["device_groups"].get(group_id)

    def writes(self):
        return [(call["method"], call["path"], call["json"]) for call in self.fake.writes()]

    def paths(self):
        return [f"{call['method']} {call['path']}" for call in self.fake.calls]


class Registry(GroupCase):
    def test_module_resource_is_registered_with_an_inverse_per_op(self):
        self.assertIs(self.res, submodule("resources.device_group").RESOURCE)
        self.assertEqual(self.res.ops, ("create", "update", "delete", "maintenance"))
        self.assertEqual(set(self.res.inverse), set(self.res.ops))
        self.assertEqual(self.res.inverse["delete"], ("lossy", DELETE_NOTE))
        self.assertEqual(self.res.inverse["maintenance"][0], "none")


class Validation(GroupCase):
    def errors(self, op, data):
        return self.res.validate(op, data, self.settings)

    def test_create_requires_name_and_type_and_rejects_unknown_fields(self):
        self.assertEqual(
            self.errors("create", {"devices_add": [1], "pattern": "x"}),
            [
                "cannot create device group field(s) devices_add, pattern; allowed: desc, devices, name, rules, type",
                "name is required to create a device group",
                "type is required to create a device group",
            ],
        )
        self.assertEqual(
            self.errors("update", {"bogus": 1}),
            [
                "cannot update device group field(s) bogus; allowed: desc, devices, devices_add, devices_remove, "
                "name, rules, type"
            ],
        )

    def test_value_kinds(self):
        self.assertEqual(
            self.errors("create", {"name": 5, "type": "smart", "desc": 7}),
            ["desc: expected a string, got 7", "name: expected a string, got 5", 'type: expected one of static, '
             'dynamic, got "smart"'],
        )  # fmt: skip
        self.assertEqual(
            self.errors("update", {"name": None, "type": None, "rules": None}),
            ["name: null is not allowed", "rules: null is not allowed", "type: null is not allowed"],
        )

    def test_member_lists_take_ids_and_hostnames_only(self):
        data = {
            "name": "g",
            "type": "static",
            "devices": [1, "3", "core-sw1.example.net", True, "", 0, None, 1.5, "a/b", "sw\x1b1"],
        }
        self.assertEqual(
            self.errors("create", data),
            ['devices: expected a list of device ids or hostnames, got [true, "", 0, null, 1.5, "a/b", "sw\\u001b1"]'],
        )
        self.assertEqual(
            self.errors("update", {"devices_add": "core-sw1.example.net"}),
            ['devices_add: expected a list of device ids or hostnames, got "core-sw1.example.net"'],
        )

    def test_update_membership_and_text_rules(self):
        data = {
            "devices": [1],
            "devices_add": ["core-sw1.example.net", 3],
            "devices_remove": [" 3 ", "x"],
            "desc": None,
            "name": "  ",
        }
        self.assertEqual(
            self.errors("update", data),
            [
                "give devices (the complete member list) or devices_add / devices_remove, not both",
                "#3 cannot be in both devices_add and devices_remove",
                "name must not be blank",
                'desc: null is not allowed; use "" to clear it',
            ],
        )
        self.assertEqual(self.errors("create", {"name": "g", "type": "static", "desc": None}), [])
        self.assertEqual(
            self.errors("create", {"name": "x" * 256, "type": "static", "desc": "d" * 300}),
            ["name: at most 255 characters (got 256)", "desc: at most 255 characters (got 300)"],
        )

    def test_rules_shape_and_group_type(self):
        shape = 'rules: expected a query-builder object with "condition" ("AND" or "OR") and a non-empty "rules" list'
        self.assertEqual(self.errors("create", {"name": "g", "type": "dynamic", "rules": LAB_RULES}), [])
        self.assertEqual(self.errors("create", {"name": "g", "type": "dynamic", "rules": json.dumps(LAB_RULES)}), [])
        self.assertEqual(
            self.errors("create", {"name": "g", "type": "dynamic"}),
            ["rules is required to create a dynamic device group"],
        )
        self.assertEqual(
            self.errors("create", {"name": "g", "type": "dynamic", "rules": {"condition": "AND"}, "devices": [1]}),
            [shape, "devices: a dynamic group's members follow its rules; give rules instead"],
        )
        self.assertEqual(
            self.errors("create", {"name": "g", "type": "static", "rules": LAB_RULES}),
            ["rules: only a dynamic group has rules; a static group lists its devices"],
        )
        self.assertEqual(self.errors("update", {"rules": []}), [shape])
        self.assertEqual(self.errors("update", {"rules": {"condition": "XOR", "rules": [{}]}}), [shape])
        self.assertEqual(
            self.errors("update", {"rules": "not json"}), ['rules: expected a JSON object or array, got "not json"']
        )

    def test_maintenance_data(self):
        self.assertEqual(self.errors("maintenance", {"duration": "2:00"}), [])
        full = {"duration": "0:30", "start": "2026-10-29 01:00:00", "title": "t", "notes": "n", "behavior": 2}
        self.assertEqual(self.errors("maintenance", full), [])
        self.assertEqual(
            self.errors(
                "maintenance",
                {"duration": "2", "start": "2026-10-29T01:00:00", "title": 5, "behavior": "silence", "foo": 1},
            ),
            [
                "maintenance does not take foo; allowed: duration, start, title, notes, behavior",
                'duration is required as hours:minutes, such as "2:00" or "0:30"',
                'start: expected "YYYY-MM-DD HH:MM:SS" in the LibreNMS server\'s time zone, or null to start on apply',
                "title: expected a string of at most 200 characters",
                'behavior: expected one of skip_alerts, mute_alerts, run_alerts (or 1-3), got "silence"',
            ],
        )
        self.assertEqual(self.errors("maintenance", {"duration": "0:00"}), ["duration must be longer than 0:00"])
        self.assertEqual(
            self.errors("maintenance", {"duration": "72:01"}), ["duration 72:01 exceeds max_maintenance_hours (72)"]
        )
        self.assertEqual(len(self.errors("maintenance", {"duration": "2:60"})), 1)
        self.assertEqual(len(self.errors("maintenance", {"duration": "1:00", "start": "2026-02-30 01:00:00"})), 1)
        self.assertEqual(len(self.errors("maintenance", {"duration": "1:00", "behavior": True})), 1)
        self.assertEqual(self.errors("maintenance", {"duration": "1:00", "title": "t" * 200}), [])
        self.assertEqual(
            self.errors("maintenance", {"duration": "1:00", "title": "t" * 201, "notes": 5}),
            ["title: expected a string of at most 200 characters", "notes: expected a string"],
        )
        self.assertEqual(
            self.errors("maintenance", {}), ['duration is required as hours:minutes, such as "2:00" or "0:30"']
        )

    def test_delete_takes_nothing_to_check(self):
        self.assertEqual(self.errors("delete", {}), [])


class Planning(GroupCase):
    def test_update_of_static_group_writes_only_changed_keys(self):
        step = self.step("update", {"name": "core-switches", "desc": "Core and distribution"}, id=1)
        self.assertEqual(step["action"], "update")
        self.assertEqual(
            (step["object_id"], step["label"], step["resolved_by"], step["parent_id"]), (1, "core-switches", "id", None)
        )
        self.assertEqual(step["changes"], {"desc": {"from": "Core layer switches", "to": "Core and distribution"}})
        self.assertEqual(step["payload"], {"desc": "Core and distribution"})
        self.assertEqual(step["precondition"], {"state": CORE})
        self.assertEqual((step["inverse_kind"], step["inverse_note"], step["notes"]), ("exact", "", []))
        self.assertEqual(self.res.describe(step), ['desc: "Core layer switches" -> "Core and distribution"'])

    def test_noop_when_nothing_differs(self):
        data = {"desc": "Core layer switches", "type": "static", "devices": ["core-sw1.example.net"]}
        step = self.step("update", data, id=1)
        self.assertEqual((step["action"], step["reason"]), ("noop", "already matches desired state"))
        self.assertNotIn("precondition", step)
        self.assertEqual(self.res.describe(step), ["already matches desired state"])

    def test_devices_by_hostname_or_id_resolve_to_a_full_id_list(self):
        step = self.step("update", {"devices": ["access-sw2.example.net", 4, "1", " 4 "]}, id=1)
        self.assertEqual(step["changes"], {"devices": {"from": [1], "to": [1, 3, 4]}})
        self.assertEqual(step["payload"], {"devices": [1, 3, 4]})
        self.assertEqual(self.res.describe(step), ["devices: add #3, #4 (1 -> 3 members)"])
        lookups = [p for p in self.paths() if p.startswith("GET devices/")]
        self.assertEqual(lookups, ["GET devices/access-sw2.example.net", "GET devices/4", "GET devices/1"])
        members = [c for c in self.fake.calls if c["path"] == "devicegroups/1"]
        self.assertTrue(members and all(c["params"] == {} for c in members))  # never ?full (SNMP credentials)
        rendered = json.dumps(step)
        self.assertFalse([secret for secret in SECRETS if secret in rendered])

    def test_devices_add_and_remove_merge_with_current_members(self):
        step = self.step("update", {"devices_add": ["access-sw2.example.net", 1], "devices_remove": [4]}, id=1)
        self.assertEqual(step["changes"], {"devices": {"from": [1], "to": [1, 3]}})
        self.assertEqual(step["payload"], {"devices": [1, 3]})
        self.assertEqual(step["notes"], ["devices_add: #1 already in the group", "devices_remove: #4 not in the group"])
        step = self.step("update", {"devices_remove": ["core-sw1.example.net"]}, id=1)
        self.assertEqual(step["payload"], {"devices": []})
        self.assertEqual(self.res.describe(step), ["devices: remove #1 (1 -> 0 members)"])
        self.assertEqual(self.step("update", {"devices_add": [1]}, id=1)["action"], "noop")

    def test_device_lookup_failures(self):
        with self.assertRaisesRegex(base.StepError, r'^no LibreNMS device matches "ghost.example.net", #99$'):
            self.step("update", {"devices": ["ghost.example.net", 99, 3]}, id=1)
        with self.assertRaisesRegex(base.StepError, r"^devices #3 cannot be in both devices_add and devices_remove$"):
            self.step("update", {"devices_add": ["access-sw2.example.net"], "devices_remove": [3]}, id=1)
        self.fake.fail_on("GET", r"devices/hidden\.example\.net", 403, {"status": "error", "message": "Forbidden"})
        with self.assertRaises(base.StepError) as ctx:
            self.step("update", {"devices_add": ["hidden.example.net"]}, id=1)
        self.assertEqual(
            str(ctx.exception),
            "LibreNMS answered 403 for hostname hidden.example.net: it does not exist or this token cannot see it "
            "(LibreNMS returns 403 for unknown hostnames to tokens without global read); use the device id or a token "
            "with global read",
        )

    def test_dynamic_rules_compare_and_send_without_joins(self):
        wanted = {**LAB_RULES, "joins": [["devices", "devices.device_id", "x"]]}
        step = self.step("update", {"rules": wanted}, id=2)
        self.assertEqual(step["changes"], {"rules": {"from": EDGE_RULES, "to": LAB_RULES}})
        self.assertIsInstance(step["payload"]["rules"], str)
        self.assertEqual(json.loads(step["payload"]["rules"]), LAB_RULES)
        self.assertEqual(
            step["precondition"]["state"],
            {"id": 2, "name": "edge-routers", "desc": "", "type": "dynamic", "rules": EDGE_RULES},
        )
        line = self.res.describe(step)[0]
        self.assertTrue(line.startswith('rules: {"condition": "AND"'))
        self.assertTrue(line.endswith(json.dumps(LAB_RULES, sort_keys=True)))  # the new rules are shown whole
        stored = json.dumps({**EDGE_RULES, "joins": []})  # what a read returns, as a JSON string
        self.assertEqual(self.step("update", {"rules": stored}, id=2)["action"], "noop")

    def test_group_type_decides_what_can_change(self):
        with self.assertRaisesRegex(
            base.StepError, r"^device group #2 is dynamic: its members follow its rules, so devices cannot be set"
        ):
            self.step("update", {"devices": [1]}, id=2)
        with self.assertRaisesRegex(base.StepError, r"so devices_add cannot be set"):
            self.step("update", {"devices_add": [1]}, id=2)
        with self.assertRaisesRegex(base.StepError, r"^device group #1 is static: only a dynamic group has rules$"):
            self.step("update", {"rules": EDGE_RULES}, id=1)
        with self.assertRaisesRegex(
            base.StepError,
            r"^device group #1 is static: changing a group's type is not supported; create a new group$",
        ):
            self.step("update", {"type": "dynamic"}, id=1)
        self.assertEqual(self.step("update", {"type": "static", "desc": "x"}, id=1)["payload"], {"desc": "x"})

    def test_renames(self):
        with self.assertRaisesRegex(
            base.StepError, r"^LibreNMS cannot change only the letter case or trailing spaces of a group name"
        ):
            self.step("update", {"name": "Core-Switches"}, id=1)
        with self.assertRaisesRegex(base.StepError, r"^LibreNMS cannot change only the letter case or trailing"):
            self.step("update", {"name": "core-switches  "}, id=1)  # MySQL's PAD SPACE collation: the same name
        with self.assertRaisesRegex(base.StepError, r'^a device group named "EDGE-routers" already exists \(#2\)$'):
            self.step("update", {"name": "EDGE-routers"}, id=1)
        step = self.step("update", {"name": "core-switching"}, id=1)
        self.assertEqual(step["payload"], {"name": "core-switching"})

    def test_create_static_carries_defaults_and_exists_check(self):
        step = self.step("create", {"name": "lab", "type": "static", "devices": ["lab-fw1.example.net"]})
        self.assertEqual(
            (step["action"], step["object_id"], step["label"], step["resolved_by"]), ("create", None, "lab", None)
        )
        self.assertEqual(step["data"], {"name": "lab", "type": "static", "desc": "", "devices": [4]})
        self.assertEqual(step["exists_check"], {"name": "lab"})
        self.assertEqual(step["inverse_kind"], "exact")
        self.assertNotIn("precondition", step)
        self.assertEqual(
            self.res.describe(step),
            [
                'name "lab", type static, desc ""',
                "devices (1): #4",
                'precondition: no device group matches {"name": "lab"}',
            ],
        )
        self.assertEqual(self.step("create", {"name": "lab", "type": "static"})["data"]["devices"], [])

    def test_create_dynamic_group(self):
        step = self.step(
            "create", {"name": "lab-devices", "type": "dynamic", "rules": json.dumps(LAB_RULES), "desc": "Lab"}
        )
        self.assertEqual(step["data"], {"name": "lab-devices", "type": "dynamic", "desc": "Lab", "rules": LAB_RULES})
        self.assertEqual(self.res.describe(step)[1], f"rules: {json.dumps(LAB_RULES, sort_keys=True)}")

    def test_create_refused_when_the_name_is_taken(self):
        for name in ("Core-Switches", "core-switches "):
            with self.assertRaises(base.StepError) as ctx:
                self.step("create", {"name": name, "type": "static"})
            self.assertEqual(
                str(ctx.exception),
                'a device group named "core-switches" already exists (#1); update it by id, or give match '
                '{"name": ...} to update it if it exists',
            )

    def test_upserts(self):
        data = {"name": "core-switches", "type": "static", "devices": [1, 3]}
        step = self.step("create", data, match={"name": "core-switches"})
        self.assertEqual(
            (step["action"], step["upsert"], step["requested_op"], step["resolved_by"]),
            ("update", True, "create", "match"),
        )
        self.assertEqual(step["changes"], {"devices": {"from": [1], "to": [1, 3]}})
        step = self.step(
            "create", {"name": "CORE-SWITCHES", "type": "static", "desc": "Core"}, match={"name": "CORE-SWITCHES"}
        )
        self.assertEqual(step["payload"], {"desc": "Core"})
        self.assertEqual(
            step["notes"],
            [
                "name: LibreNMS cannot change only the letter case or trailing spaces of a group name; it stays "
                '"core-switches"'
            ],
        )
        with self.assertRaisesRegex(base.StepError, r"^device group #2 is dynamic: changing a group's type"):
            self.step("create", {"name": "edge-routers", "type": "static"}, match={"name": "edge-routers"})
        noop = self.step(
            "create", {"name": "core-switches", "type": "static", "devices": [1]}, match={"name": "core-switches"}
        )
        self.assertEqual(noop["action"], "noop")
        step = self.step("create", {"name": "lab", "type": "static"}, match={"name": "lab"})
        self.assertEqual(
            (step["action"], step["resolved_by"], step["exists_check"]), ("create", "match", {"name": "lab"})
        )

    def test_delete_keeps_snapshot_and_shows_what_it_takes_along(self):
        step = self.step("delete", id=1)
        self.assertEqual(
            step["snapshot"], {"name": "core-switches", "desc": "Core layer switches", "type": "static", "devices": [1]}
        )
        self.assertEqual((step["inverse_kind"], step["inverse_note"]), ("lossy", DELETE_NOTE))
        self.assertEqual(step["precondition"], {"state": CORE})
        self.assertEqual(step["member_count"], 1)
        self.assertEqual(
            step["notes"],
            ['alert rule(s) #2 "High CPU" are scoped to this group; deleting it removes that scope and a rollback does '
             "not restore it"],
        )  # fmt: skip
        self.assertEqual(
            self.res.describe(step),
            ["the device group is deleted; its configuration is kept in the plan", "1 member device(s) now"],
        )
        step = self.step("delete", match={"name": "edge-routers"})
        self.assertEqual(step["snapshot"], {"name": "edge-routers", "desc": "", "type": "dynamic", "rules": EDGE_RULES})
        self.assertEqual((step["member_count"], step["notes"]), (1, []))  # dynamic members come from devicegroups/2

    def test_delete_when_alert_rules_cannot_be_listed(self):
        self.fake.fail_on("GET", "rules", 500)
        step = self.step("delete", id=1)
        self.assertEqual(len(step["notes"]), 1)
        self.assertTrue(
            step["notes"][0].startswith("could not list the alert rules that use this group: GET /api/v0/rules")
        )

    def test_maintenance_step(self):
        step = self.step("maintenance", {"duration": "2:00", "notes": "IOS upgrade"}, match={"name": "core-switches"})
        self.assertEqual((step["action"], step["object_id"], step["resolved_by"]), ("maintenance", 1, "match"))
        self.assertEqual(
            step["params"],
            {"duration": "2:00", "start": None, "title": None, "notes": "IOS upgrade", "behavior": "skip_alerts"},
        )
        self.assertEqual((step["inverse_kind"], step["inverse_note"]), ("none", MAINTENANCE_NOTE))
        self.assertEqual((step["member_count"], step["notes"]), (1, []))
        self.assertEqual(step["precondition"], {"state": CORE})
        self.assertEqual(
            self.res.describe(step),
            ['duration 2:00, behavior skip_alerts, title "core-switches", starting on apply, notes "IOS upgrade"',
             "1 member device(s) now"],
        )  # fmt: skip
        data = {"duration": "0:45", "start": "2026-10-29 01:00:00", "title": "Window", "behavior": 3}
        step = self.step("maintenance", data, id=2)
        self.assertEqual(step["params"]["behavior"], "run_alerts")
        self.assertEqual(
            self.res.describe(step)[0],
            'duration 0:45, behavior run_alerts, title "Window", start "2026-10-29 01:00:00"',
        )
        self.assertEqual(step["member_count"], 1)

    def test_maintenance_of_an_empty_group_is_a_warning(self):
        self.fake.seed("device_groups", {"id": 3, "name": "spare", "type": "static", "devices": []})
        step = self.step("maintenance", {"duration": "1:00"}, id=3)
        self.assertEqual(step["member_count"], 0)
        self.assertEqual(
            step["notes"],
            ['device group "spare" has no members now; the maintenance covers devices that join it before it ends'],
        )


class Reads(GroupCase):
    def test_no_groups_at_all_is_a_404_list(self):
        self.fake.tables["device_groups"].clear()
        self.assertIsNone(self.res.get(self.client, 1))
        self.assertEqual(self.res.find(self.client, {"name": "core-switches"}), (0, None))
        with self.assertRaisesRegex(base.StepError, r'^no device group matches \{"name": "core-switches"\}$'):
            self.step("update", {"desc": "x"}, match={"name": "core-switches"})

    def test_empty_static_group_has_no_members(self):
        self.fake.touch("device_groups", 1, devices=[])
        obj = self.res.get(self.client, 1)
        self.assertEqual(self.res.state(self.client, obj), {**CORE, "devices": []})

    def test_find_compares_names_as_the_collation_does(self):
        count, obj = self.res.find(self.client, {"name": "CORE-switches  "})
        self.assertEqual((count, obj["id"]), (1, 1))
        self.assertEqual(self.res.find(self.client, {"name": " core-switches"}), (0, None))

    def test_find_ignores_letter_case_and_paths_use_ids(self):
        self.fake.seed("device_groups", {"id": 7, "name": "lab/racks ?#1", "type": "static", "devices": [4]})
        count, obj = self.res.find(self.client, {"name": "LAB/Racks ?#1"})
        self.assertEqual((count, obj["id"], obj["devices"]), (1, 7, [4]))
        step = self.step("update", {"desc": "racks"}, match={"name": "lab/racks ?#1"})
        self.apply(step)
        self.assertEqual(self.writes(), [("PATCH", "devicegroups/7", {"desc": "racks"})])


class Check(GroupCase):
    def check(self, step):
        return self.res.check(self.client, step)

    def test_unchanged_group_passes(self):
        for step in (
            self.step("update", {"devices_add": [3], "name": "core-switching"}, id=1),
            self.step("create", {"name": "lab", "type": "static", "devices": [4]}),
            self.step("delete", id=2),
            self.step("maintenance", {"duration": "1:00"}, id=2),
        ):
            self.assertIsNone(self.check(step))

    def test_out_of_band_edits_conflict(self):
        step = self.step("update", {"desc": "x"}, id=1)
        self.fake.touch("device_groups", 1, devices=[1, 3], name="core")
        self.assertEqual(
            self.check(step),
            'device group #1 changed since planning (devices: [1] -> [1, 3], name: "core-switches" -> "core")',
        )
        del self.fake.tables["device_groups"][1]
        self.assertEqual(self.check(step), "device group #1 no longer exists")

    def test_rules_conflict_but_regenerated_joins_do_not(self):
        step = self.step("update", {"desc": "edge"}, id=2)
        self.fake.touch("device_groups", 2, rules={**EDGE_RULES, "joins": [["devices", "devices.device_id", "x"]]})
        self.assertIsNone(self.check(step))
        self.fake.touch("device_groups", 2, rules={**LAB_RULES, "joins": []})
        self.assertTrue(
            self.check(step).startswith('device group #2 changed since planning (rules: {"condition": "AND"')
        )

    def test_delete_conflicts_when_membership_moved(self):
        step = self.step("delete", id=1)
        self.fake.touch("device_groups", 1, devices=[])
        self.assertEqual(self.check(step), "device group #1 changed since planning (devices: [1] -> [])")

    def test_create_conflicts(self):
        step = self.step("create", {"name": "lab", "type": "static", "devices": [4]})
        del self.fake.tables["devices"][4]
        self.assertEqual(self.check(step), "device(s) #4 no longer exist")
        self.fake.seed("device_groups", {"name": "LAB", "type": "static"})
        self.assertEqual(self.check(step), '1 device group(s) now match {"name": "lab"}; expected none')

    def test_update_conflicts_on_added_device_or_taken_name(self):
        step = self.step("update", {"devices_add": [3, 4], "devices_remove": [1]}, id=1)
        del self.fake.tables["devices"][3]
        self.assertEqual(self.check(step), "device(s) #3 no longer exist")
        step = self.step("update", {"name": "lab"}, id=1)
        self.fake.seed("device_groups", {"name": "Lab", "type": "dynamic", "rules": LAB_RULES})
        self.assertEqual(self.check(step), 'a device group named "lab" now exists')

    def test_maintenance_needs_the_group_with_its_type(self):
        step = self.step("maintenance", {"duration": "1:00"}, id=1)
        self.fake.touch("device_groups", 1, desc="changed", devices=[1, 3])
        self.assertIsNone(self.check(step))  # an action only needs the group, whatever its fields
        self.fake.touch("device_groups", 1, type="dynamic", rules=LAB_RULES)
        self.assertEqual(self.check(step), "device group #1 changed type since planning (static -> dynamic)")
        del self.fake.tables["device_groups"][1]
        self.assertEqual(self.check(step), "device group #1 no longer exists")


class Execute(GroupCase):
    def test_update_patches_only_changed_keys_and_verifies(self):
        step = self.step("update", {"name": "core-switches", "desc": "Core and distribution", "devices_add": [3]}, id=1)
        result = self.apply(step)
        self.assertEqual(
            self.writes(), [("PATCH", "devicegroups/1", {"desc": "Core and distribution", "devices": [1, 3]})]
        )
        self.assertEqual(
            result,
            {
                "object_id": 1,
                "inverse": {
                    "action": "update",
                    "object_id": 1,
                    "data": {"desc": "Core layer switches", "devices": [1]},
                },
                "after_state": {**CORE, "desc": "Core and distribution", "devices": [1, 3]},
                "notes": [],
            },
        )
        self.assertEqual((self.group(1)["desc"], self.group(1)["devices"]), ("Core and distribution", [1, 3]))

    def test_rename_and_removal_use_patch_with_the_full_list(self):
        step = self.step("update", {"name": "core-switching", "devices_remove": [1]}, id=1)
        self.apply(step)
        self.assertEqual(self.writes(), [("PATCH", "devicegroups/1", {"name": "core-switching", "devices": []})])
        self.assertEqual((self.group(1)["name"], self.group(1)["devices"]), ("core-switching", []))

    def test_rules_are_sent_as_a_json_string(self):
        result = self.apply(self.step("update", {"rules": LAB_RULES}, id=2))
        body = self.writes()[0][2]
        self.assertIsInstance(body["rules"], str)
        self.assertEqual(json.loads(body["rules"]), LAB_RULES)
        self.assertEqual(self.group(2)["rules"], {**LAB_RULES, "joins": []})
        self.assertEqual(result["after_state"]["rules"], LAB_RULES)

    def test_create_static_sends_every_key(self):
        result = self.apply(self.step("create", {"name": "lab", "type": "static"}))
        self.assertEqual(
            self.writes(), [("POST", "devicegroups", {"name": "lab", "type": "static", "desc": "", "devices": []})]
        )
        self.assertEqual(
            result,
            {
                "object_id": 3,
                "inverse": {"action": "delete", "object_id": 3},
                "after_state": {"id": 3, "name": "lab", "desc": "", "type": "static", "devices": []},
                "notes": [],
            },
        )

    def test_create_dynamic_sends_rules_as_a_string(self):
        result = self.apply(self.step("create", {"name": "lab-devices", "type": "dynamic", "rules": LAB_RULES}))
        method, where, body = self.writes()[0]
        self.assertEqual((method, where, sorted(body)), ("POST", "devicegroups", ["desc", "name", "rules", "type"]))
        self.assertEqual(json.loads(body["rules"]), LAB_RULES)
        self.assertEqual(
            result["after_state"], {"id": 3, "name": "lab-devices", "desc": "", "type": "dynamic", "rules": LAB_RULES}
        )

    def test_create_finds_its_id_by_name_when_the_answer_has_none(self):
        self.fake.fail_on(
            "POST", "devicegroups", 201, {"status": "ok", "message": "Device group lab created"}, commit=True
        )
        result = self.apply(self.step("create", {"name": "lab", "type": "static", "devices": [3, 4]}))
        self.assertEqual(result["object_id"], 3)
        self.assertEqual(result["after_state"]["devices"], [3, 4])

    def test_delete(self):
        step = self.step("delete", id=1)
        result = self.apply(step)
        self.assertEqual(self.writes(), [("DELETE", "devicegroups/1", None)])
        self.assertIsNone(self.group(1))
        self.assertEqual(
            result,
            {
                "object_id": 1,
                "inverse": {"action": "create", "snapshot": step["snapshot"]},
                "after_state": None,
                "notes": [],
            },
        )

    def test_maintenance_posts_a_tagged_title_and_checks_a_member(self):
        result = self.apply(self.step("maintenance", {"duration": "2:00", "notes": "IOS upgrade"}, id=1))
        body = {"title": f"[hermes:{PLAN_ID}] core-switches", "duration": "2:00", "notes": "IOS upgrade", "behavior": 1}
        self.assertEqual(self.writes(), [("POST", "devicegroups/1/maintenance", body)])
        self.assertEqual(
            result,
            {"object_id": 1, "inverse": None, "after_state": None, "notes": [f"schedule title: {body['title']}"]},
        )
        self.assertEqual(
            (self.fake.schedules[-1]["device_groups"], self.fake.schedules[-1]["title"]), ([1], body["title"])
        )
        self.assertIn("GET devices/1/maintenance", self.paths())

    def test_maintenance_with_start_title_and_behavior(self):
        data = {"duration": "0:30", "start": "2026-10-29 01:00:00", "title": "Window", "behavior": "mute_alerts"}
        result = self.apply(self.step("maintenance", data, id=2))
        body = {
            "title": f"[hermes:{PLAN_ID}] Window",
            "duration": "0:30",
            "notes": "",
            "behavior": 2,
            "start": data["start"],
        }
        self.assertEqual(self.writes(), [("POST", "devicegroups/2/maintenance", body)])
        self.assertEqual(result["notes"], [f"schedule title: {body['title']}"])
        self.assertEqual(self.paths(), ["POST devicegroups/2/maintenance"])  # a future start is not checked

    def test_maintenance_check_problems_are_notes_not_failures(self):
        self.fake.seed("device_groups", {"id": 3, "name": "spare", "type": "static", "devices": []})
        result = self.apply(self.step("maintenance", {"duration": "1:00"}, id=3))
        self.assertEqual(
            result["notes"][1:], ["the group has no members, so the maintenance could not be checked on a device"]
        )
        self.fake.fail_on("GET", "devices/1/maintenance", 200, {"status": "ok", "is_under_maintenance": False}, times=1)
        result = self.apply(self.step("maintenance", {"duration": "1:00"}, id=1))
        self.assertEqual(
            result["notes"],
            [
                f"schedule title: [hermes:{PLAN_ID}] core-switches",
                "device #1 in the group does not report maintenance yet; check the schedule in LibreNMS",
            ],
        )
        self.fake.fail_on("GET", "devices/1/maintenance", 500)
        result = self.apply(self.step("maintenance", {"duration": "1:00"}, id=1))
        self.assertTrue(result["notes"][1].startswith("the maintenance could not be checked on a member device: GET"))
        self.assertEqual(len(self.fake.schedules), 3)


class PartialWrites(GroupCase):
    def test_server_error_after_the_update_landed(self):
        step = self.step("update", {"desc": "x"}, id=1)
        self.fake.fail_on("PATCH", "devicegroups/1", 500, commit=True)
        with self.assertRaises(base.PartialWrite) as ctx:
            self.apply(step)
        self.assertTrue(str(ctx.exception).startswith("PATCH /api/v0/devicegroups/1 -> HTTP 500"))
        self.assertEqual(
            ctx.exception.entry,
            {
                "object_id": 1,
                "inverse": {"action": "update", "object_id": 1, "data": {"desc": "Core layer switches"}},
                "after_state": {**CORE, "desc": "x"},
                "notes": [],
            },
        )

    def test_membership_sync_failing_part_way_is_partial_and_reverts(self):
        step = self.step("update", {"devices": [3, 4]}, id=1)
        del self.fake.tables["devices"][4]  # after planning: LibreNMS detaches #1, attaches #3, then fails on #4
        with self.assertRaises(base.PartialWrite) as ctx:
            self.apply(step)
        entry = ctx.exception.entry
        self.assertEqual(entry["after_state"]["devices"], [3])
        self.assertEqual(entry["inverse"]["data"], {"devices": [1]})
        status, details = self.revert(step, entry, status="failed")
        self.assertEqual((status, details), ("reverted", {"restored_fields": ["devices"]}))
        self.assertEqual(self.group(1)["devices"], [1])

    def test_failure_that_changed_nothing_raises_the_original_error(self):
        step = self.step("update", {"devices": [1, 3]}, id=1)
        del self.fake.tables["devices"][3]  # #1 is kept, #3 fails: membership is as before
        with self.assertRaises(LibreNMSError) as ctx:
            self.apply(step)
        self.assertNotIsInstance(ctx.exception, base.PartialWrite)
        self.assertEqual(ctx.exception.kind, "server")
        self.assertEqual(self.group(1)["devices"], [1])

    def test_transport_error_before_or_after_the_change(self):
        step = self.step("update", {"desc": "x"}, id=1)
        self.fake.fail_on("PATCH", "devicegroups/1", exc=ConnectionRefusedError("refused"), times=1)
        with self.assertRaises(LibreNMSError) as ctx, self.assertLogs(client_mod.logger, "WARNING"):
            self.apply(step)
        self.assertEqual(ctx.exception.kind, "transport")
        self.fake.fail_on("PATCH", "devicegroups/1", exc=ConnectionError("reset"), commit=True, times=1)
        with self.assertRaises(base.PartialWrite) as ctx, self.assertLogs(client_mod.logger, "WARNING"):
            self.apply(step)
        self.assertEqual(ctx.exception.entry["after_state"]["desc"], "x")

    def test_client_error_on_the_first_write_propagates_without_a_reread(self):
        body = {"status": "error", "message": {"name": ["The name has already been taken."]}}
        self.fake.fail_on("PATCH", "devicegroups/1", 422, body)
        with self.assertRaises(LibreNMSError) as ctx:
            self.apply(self.step("update", {"desc": "x"}, id=1))
        self.assertEqual(ctx.exception.kind, "validation")
        self.assertEqual(self.paths()[-1], "PATCH devicegroups/1")

    def test_create_failing_after_the_insert_is_partial_and_reverts(self):
        step = self.step("create", {"name": "lab", "type": "static", "devices": [3, 4]})
        del self.fake.tables["devices"][4]  # LibreNMS saves the group, attaches #3, then fails on #4
        with self.assertRaises(base.PartialWrite) as ctx:
            self.apply(step)
        entry = ctx.exception.entry
        self.assertEqual((entry["object_id"], entry["inverse"]), (3, {"action": "delete", "object_id": 3}))
        self.assertEqual(entry["after_state"]["devices"], [3])
        self.assertEqual(self.revert(step, entry, status="failed"), ("reverted", {"object_id": 3}))
        self.assertIsNone(self.group(3))

    def test_create_server_error_with_nothing_created(self):
        self.fake.fail_on("POST", "devicegroups", 500)
        with self.assertRaises(LibreNMSError) as ctx:
            self.apply(self.step("create", {"name": "lab", "type": "static"}))
        self.assertNotIsInstance(ctx.exception, base.PartialWrite)
        self.assertEqual(self.res.find(self.client, {"name": "lab"}), (0, None))

    def test_create_whose_outcome_cannot_be_read_is_found_by_name_on_rollback(self):
        step = self.step("create", {"name": "lab", "type": "static", "devices": [4]})
        self.fake.fail_on("POST", "devicegroups", exc=ConnectionError("reset"), commit=True, times=1)
        self.fake.fail_on("GET", "devicegroups", 503)  # the re-read fails too (after its retries)
        with self.assertRaises(base.PartialWrite) as ctx, self.assertLogs(client_mod.logger, "WARNING"):
            self.apply(step)
        entry = ctx.exception.entry
        self.assertEqual(entry["inverse"], {"action": "delete", "object_id": None, "find": {"name": "lab"}})
        self.assertTrue(entry["notes"][0].startswith("outcome unknown"))
        self.fake.failures.clear()
        self.assertEqual(self.revert(step, entry, status="failed"), ("reverted", {"object_id": 3}))
        self.assertIsNone(self.group(3))

    def test_delete_error_after_the_delete_is_partial(self):
        step = self.step("delete", id=1)
        self.fake.fail_on("DELETE", "devicegroups/1", 500, commit=True)
        with self.assertRaises(base.PartialWrite) as ctx:
            self.apply(step)
        self.assertEqual(ctx.exception.entry["inverse"], {"action": "create", "snapshot": step["snapshot"]})
        self.assertIsNone(ctx.exception.entry["after_state"])

    def test_maintenance_error_that_may_have_created_a_schedule(self):
        step = self.step("maintenance", {"duration": "1:00"}, id=1)
        self.fake.fail_on("POST", "devicegroups/1/maintenance", 500, commit=True, times=1)
        with self.assertRaises(base.PartialWrite) as ctx:
            self.apply(step)
        self.assertTrue(str(ctx.exception).endswith("(LibreNMS may have created the maintenance schedule anyway)"))
        entry = ctx.exception.entry
        self.assertEqual((entry["object_id"], entry["inverse"], entry["after_state"]), (1, None, None))
        self.assertEqual(
            entry["notes"],
            [f'look for a schedule titled "[hermes:{PLAN_ID}] core-switches" under Alerts → Scheduled Maintenance; '
             "API v0 cannot read it back"],
        )  # fmt: skip
        self.assertEqual(len(self.fake.schedules), 1)
        self.assertEqual(
            self.revert(step, entry, status="failed"),
            ("irreversible", {"note": MAINTENANCE_NOTE.replace("2:00", "1:00")}),
        )

    def test_maintenance_refused_by_librenms_is_a_plain_failure(self):
        self.fake.fail_on(
            "POST", "devicegroups/1/maintenance", 400, {"status": "error", "message": "Duration not provided"}
        )
        with self.assertRaises(LibreNMSError) as ctx:
            self.apply(self.step("maintenance", {"duration": "1:00"}, id=1))
        self.assertNotIsInstance(ctx.exception, base.PartialWrite)
        self.assertEqual(self.fake.schedules, [])


class Revert(GroupCase):
    def test_create_is_reverted_by_deleting_the_group(self):
        step = self.step("create", {"name": "lab", "type": "static", "devices": [4]})
        result = self.apply(step)
        self.assertEqual(self.revert(step, result), ("reverted", {"object_id": 3}))
        self.assertEqual(self.writes(), [("DELETE", "devicegroups/3", None)])
        self.assertIsNone(self.group(3))

    def test_create_revert_conflicts_on_later_edits_unless_forced(self):
        step = self.step("create", {"name": "lab", "type": "static"})
        result = self.apply(step)
        self.fake.touch("device_groups", 3, desc="mine")
        self.assertEqual(
            self.revert(step, result),
            (
                "conflict",
                {"error": 'device group #3 was modified after apply (desc: "" -> "mine"); use force to delete anyway'},
            ),
        )
        self.assertEqual(self.revert(step, result, force=True), ("reverted", {"object_id": 3}))

    def test_update_is_reverted_exactly(self):
        step = self.step("update", {"name": "core-switching", "desc": "x", "devices_add": [3]}, id=1)
        result = self.apply(step)
        self.assertEqual(self.revert(step, result), ("reverted", {"restored_fields": ["desc", "devices", "name"]}))
        self.assertEqual(
            self.writes(),
            [("PATCH", "devicegroups/1", {"name": "core-switches", "desc": "Core layer switches", "devices": [1]})],
        )
        self.assertEqual(self.res.state(self.client, self.res.get(self.client, 1)), CORE)

    def test_a_revert_never_resends_a_name_that_is_already_back(self):
        step = self.step("update", {"name": "core-switching", "desc": "x"}, id=1)
        result = self.apply(step)
        self.fake.touch("device_groups", 1, name="core-switches")  # renamed back by hand: what the revert writes
        self.assertEqual(self.revert(step, result), ("reverted", {"restored_fields": ["desc"]}))
        self.assertEqual(self.writes(), [("PATCH", "devicegroups/1", {"desc": "Core layer switches"})])  # no 422

    def test_rules_update_is_reverted_with_a_json_string(self):
        step = self.step("update", {"rules": LAB_RULES}, id=2)
        result = self.apply(step)
        self.assertEqual(self.revert(step, result), ("reverted", {"restored_fields": ["rules"]}))
        self.assertEqual(json.loads(self.writes()[0][2]["rules"]), EDGE_RULES)
        self.assertEqual(self.group(2)["rules"], {**EDGE_RULES, "joins": []})

    def test_update_with_unknown_outcome_is_reverted_from_the_step(self):
        step = self.step("update", {"desc": "x"}, id=1)
        self.apply(step)  # the write landed, then the process died before journaling
        self.assertEqual(self.revert(step, status="unknown"), ("reverted", {"restored_fields": ["desc"]}))
        self.assertEqual(self.group(1)["desc"], "Core layer switches")

    def test_delete_is_reverted_by_recreating_with_a_new_id(self):
        step = self.step("delete", id=1)
        result = self.apply(step)
        self.assertEqual(self.revert(step, result), ("reverted", {"new_object_id": 3, "skipped_devices": []}))
        body = {"name": "core-switches", "type": "static", "desc": "Core layer switches", "devices": [1]}
        self.assertEqual(self.writes(), [("POST", "devicegroups", body)])
        self.assertEqual(self.res.state(self.client, self.res.get(self.client, 3)), {**CORE, "id": 3})

    def test_delete_rollback_that_died_after_its_post_adopts_that_group(self):
        step = self.step("delete", id=1)
        entry = entry_for(step, self.apply(step))
        context = resumable(dict(self.context, step=step), entry)
        self.fake.fail_on("POST", "devicegroups", exc=Died(), commit=True, times=1)
        with self.assertRaises(Died):
            self.res.revert(self.client, entry, False, context)
        self.assertEqual((entry["revert_progress"], self.group(3)["name"]), ({"recreating": True}, "core-switches"))
        self.fake.calls.clear()
        self.assertEqual(
            self.res.revert(self.client, entry, False, context),
            ("reverted", {"new_object_id": 3, "skipped_devices": [], "note": "re-created by an earlier rollback"}),
        )
        self.assertEqual(self.writes(), [])
        self.assertEqual(sorted(self.fake.tables["device_groups"]), [2, 3])

    def test_dynamic_delete_is_reverted_with_its_rules(self):
        step = self.step("delete", id=2)
        result = self.apply(step)
        self.assertEqual(self.revert(step, result), ("reverted", {"new_object_id": 3}))  # ids are never reused
        body = self.writes()[0][2]
        self.assertEqual((body["desc"], json.loads(body["rules"])), ("", EDGE_RULES))
        self.assertNotIn("devices", body)
        self.assertEqual(self.group(3)["rules"], {**EDGE_RULES, "joins": []})

    def test_delete_revert_leaves_out_devices_deleted_since(self):
        self.fake.touch("device_groups", 1, devices=[1, 3])
        step = self.step("delete", id=1)
        result = self.apply(step)
        del self.fake.tables["devices"][3]
        self.assertEqual(self.revert(step, result), ("reverted", {"new_object_id": 3, "skipped_devices": [3]}))
        self.assertEqual(self.group(3)["devices"], [1])

    def test_delete_revert_conflicts_when_the_name_is_taken_again(self):
        step = self.step("delete", id=1)
        result = self.apply(step)
        self.fake.seed("device_groups", {"name": "Core-Switches", "type": "static"})
        self.assertEqual(
            self.revert(step, result),
            ("conflict", {"error": 'a device group matching {"name": "core-switches"} exists again; remove or rename '
                                   "it before rolling back"}),
        )  # fmt: skip
        self.assertEqual(self.writes(), [])

    def test_recreate_that_does_not_match_the_snapshot_fails(self):
        step = self.step("delete", id=1)
        result = self.apply(step)
        self.fake.fail_on("POST", "devicegroups", 201, {"status": "ok", "id": 2}, commit=True)  # answers another id
        status, details = self.revert(step, result)
        self.assertEqual(status, "failed")
        self.assertTrue(details["error"].startswith('re-created device group #2 but name is "edge-routers"'))

    def test_maintenance_is_irreversible(self):
        step = self.step("maintenance", {"duration": "2:00"}, id=1)
        result = self.apply(step)
        self.assertEqual(self.revert(step, result), ("irreversible", {"note": MAINTENANCE_NOTE}))
        self.assertEqual(self.fake.calls, [])
        status, details = self.res.revert(self.client, entry_for(step, result), False, self.context)  # no step
        self.assertEqual(status, "irreversible")
        self.assertTrue(details["note"].startswith("LibreNMS API v0 cannot end or delete maintenance; it expires on"))
