"""The port resource against the fake LibreNMS: description updates, the poller pin, repoll and lossy rollback."""

from __future__ import annotations

import json

from .base import PluginTestCase
from .fake_librenms import SECRETS
from .helpers import submodule

PINNED = (
    "a description set through the API is pinned: the poller stops copying the device's ifAlias into it until the "
    'description is cleared with ""'
)
RELEASED = (
    'clearing hands the description back to the poller: LibreNMS shows "repoll" until the next poll copies the '
    "device's ifAlias"
)
CLIENT_LOG = "hermes_plugins.librenms.client"  # transport failures are detailed there, under their error id
REPOLLED = "description was repolled from the device before rollback"
LOSSY = (
    "restores the previous description text; whether the poller was allowed to overwrite it cannot be read through "
    "the API"
)


def entry_for(step, result=None, status="done", **extra):
    """A journal entry as the executor writes it."""
    keys = ("index", "action", "resource", "object_id", "label", "parent_id", "inverse_kind")
    entry = {key: step.get(key) for key in keys}
    entry.update(status=status, at="2026-10-28T19:00:00Z", **(result or {}), **extra)
    return entry


class PortCase(PluginTestCase):
    def setUp(self):
        super().setUp()
        self.base = submodule("resources.base")
        self.res = submodule("resources.port").RESOURCE
        self.LibreNMSError = self.client_mod.LibreNMSError
        self.context = {"plan_id": "lnp-test", "settings": self.settings, "actor": None}

    def plan(self, data=None, id=None, match=None, kind="update"):
        op = {"op": kind, "resource": "port", "id": id, "match": match, "data": data or {}}
        return self.res.plan_step(self.client, 0, op, self.settings)

    def apply(self, step):
        return self.res.execute(self.client, step, self.context)

    def applied(self, data, id):
        step = self.plan(data, id=id)
        return step, entry_for(step, self.apply(step))

    def revert(self, entry, force=False, step=None):
        context = dict(self.context, step=step) if step is not None else self.context
        return self.res.revert(self.client, entry, force, context)

    def alias(self, port_id):
        return self.fake.tables["ports"][port_id]["ifAlias"]

    def pinned(self, port_id):
        port = self.fake.tables["ports"][port_id]
        return f"ifName:{port['ifName']}" in self.fake.attribs.get(port["device_id"], {})

    def paths(self, method=None):
        return [c["path"] for c in self.fake.calls if method is None or c["method"] == method]


class Registry(PortCase):
    def test_module_resource_is_registered_under_its_name(self):
        self.assertIs(submodule("resources").get_resource("port"), self.res)
        self.assertEqual(
            (self.res.ops, self.res.id_key, self.res.match_keys),
            (("update",), "port_id", ("device", "ifName", "ifDescr")),
        )
        self.assertEqual(self.res.inverse, {"update": ("lossy", LOSSY)})


class Validation(PortCase):
    def test_only_description_can_be_updated(self):
        self.assertEqual(
            self.res.validate("update", {"ifAlias": "x", "description": "ok"}, self.settings),
            ["cannot update port field(s) ifAlias; allowed: description"],
        )

    def test_value_types(self):
        self.assertEqual(
            self.res.validate("update", {"description": 5}, self.settings), ["description: expected a string, got 5"]
        )
        self.assertEqual(
            self.res.validate("update", {"description": ["a"]}, self.settings),
            ["description: expected a string, got list"],
        )

    def test_accepted_values(self):
        for value in ("x" * 255, "", None, "  padded  ", "Repoll", "00", "repoll me"):
            self.assertEqual(self.res.validate("update", {"description": value}, self.settings), [], value)

    def test_values_librenms_would_store_as_something_else(self):
        cases = {
            "x" * 256: "description: at most 255 characters, got 256 (LibreNMS would cut it silently)",
            "0": 'description: "0" cannot be set; LibreNMS reads it as empty and clears the description (use "" to '
            "clear)",
            "repoll": 'description: "repoll" cannot be set; LibreNMS reads it as the marker of a cleared description '
            '(use "" to clear)',
        }
        for value, message in cases.items():
            self.assertEqual(self.res.validate("update", {"description": value}, self.settings), [message])

    def test_no_gate_applies(self):
        closed = self.settings_mod.Settings(write_mode="read_only")
        self.assertEqual(self.res.validate("update", {"description": "x"}, closed), [])


class Reads(PortCase):
    def test_get_and_state(self):
        obj = self.res.get(self.client, 5)
        self.assertEqual(
            self.res.state(self.client, obj),
            {"port_id": 5, "device_id": 2, "ifName": "Gi0/0/0", "deleted": False, "description": "WAN: transit-a"},
        )
        self.assertEqual(self.paths(), ["ports/5", "ports/5/description"])

    def test_null_empty_and_repoll_are_no_description(self):
        for value in (None, "", "repoll"):
            self.fake.touch("ports", 2, ifAlias=value)
            self.assertEqual(self.res.state(self.client, self.res.get(self.client, 2))["description"], "", value)
        self.fake.touch("ports", 2, ifAlias="Repoll")
        self.assertEqual(self.res.state(self.client, self.res.get(self.client, 2))["description"], "Repoll")

    def test_missing_and_deleted_ports(self):
        self.assertIsNone(self.res.get(self.client, 99))
        self.assertEqual(self.paths(), ["ports/99"])
        state = self.res.state(self.client, self.res.get(self.client, 3))
        self.assertEqual((state["deleted"], state["description"]), (True, ""))

    def test_find_by_hostname_and_ifname(self):
        count, obj = self.res.find(self.client, {"device": "edge-rtr1.example.net", "ifName": "Gi0/0/0"})
        self.assertEqual((count, obj["port_id"]), (1, 5))
        listing = next(c for c in self.fake.calls if c["path"] == "devices/2/ports")
        self.assertEqual(listing["params"], {"columns": "port_id,ifName,ifDescr,ifAlias"})

    def test_find_by_device_id_and_ifdescr(self):
        for device in (1, "1"):
            count, obj = self.res.find(self.client, {"device": device, "ifDescr": "GigabitEthernet1/0/2"})
            self.assertEqual((count, obj["port_id"]), (1, 2))

    def test_find_is_exact_and_needs_every_given_key(self):
        self.assertEqual(self.res.find(self.client, {"device": 2, "ifName": "gi0/0/0"}), (0, None))
        both = {"device": 1, "ifName": "Gi1/0/1", "ifDescr": "GigabitEthernet1/0/2"}
        self.assertEqual(self.res.find(self.client, both), (0, None))
        self.assertEqual(self.res.find(self.client, {"device": 1, "ifName": "Gi1/0/3"}), (0, None))  # deleted
        self.assertEqual(self.res.find(self.client, {"device": 4, "ifName": "Gi1/0/1"}), (0, None))  # 404 no ports

    def test_find_reports_ports_sharing_an_ifname(self):
        self.fake.seed("ports", {"port_id": 10, "device_id": 1, "ifIndex": 10, "ifName": "Gi1/0/1"})
        self.assertEqual(self.res.find(self.client, {"device": 1, "ifName": "Gi1/0/1"}), (2, None))

    def test_bad_matches(self):
        cases = [
            ({"ifName": "Gi0/0/0"}, "a port match needs device (hostname or id) and ifName or ifDescr"),
            ({"device": 2}, "a port match needs device (hostname or id) and ifName or ifDescr"),
            ({"device": 2, "ifName": 7}, "match ifName must be a non-empty string"),
            ({"device": 2, "ifDescr": ""}, "match ifDescr must be a non-empty string"),
            ({"device": True, "ifName": "x"}, "match device must be a device hostname or id"),
            ({"device": {"id": 2}, "ifName": "x"}, "match device must be a device hostname or id"),
            ({"device": "nope.example.net", "ifName": "x"}, "no LibreNMS device has hostname 'nope.example.net'"),
            ({"device": 99, "ifName": "x"}, "device #99 does not exist"),
        ]
        for match, message in cases:
            with self.assertRaises(self.base.StepError, msg=match) as ctx:
                self.res.find(self.client, match)
            self.assertEqual(str(ctx.exception), message)

    def test_hostname_answered_with_403(self):
        denied = {"status": "error", "message": "Insufficient permissions to access this device"}
        self.fake.fail_on("GET", r"devices/core-sw1\.example\.net", 403, denied)
        with self.assertRaises(self.base.StepError) as ctx:
            self.res.find(self.client, {"device": "core-sw1.example.net", "ifName": "Gi1/0/1"})
        self.assertEqual(
            str(ctx.exception),
            "LibreNMS answered 403 for hostname core-sw1.example.net: it does not exist or this token cannot see it "
            "(LibreNMS returns 403 for unknown hostnames to tokens without global read); use the device id or a "
            "token with global read",
        )
        self.fake.fail_on("GET", "devices/1", 403, denied)
        with self.assertRaises(self.LibreNMSError) as ctx:
            self.res.find(self.client, {"device": 1, "ifName": "Gi1/0/1"})
        self.assertEqual(ctx.exception.kind, "forbidden")

    def test_hostname_is_one_encoded_path_segment(self):
        with self.assertRaises(self.base.StepError):
            self.res.find(self.client, {"device": "sw 1+x", "ifName": "x"})
        self.assertEqual(self.client.calls[-1]["path"], "/api/v0/devices/sw%201%2Bx")

    def test_a_device_reference_with_a_slash_is_never_looked_up(self):
        with self.assertRaises(self.base.StepError) as ctx:  # encoded, it would reach the rediscovery route
            self.res.find(self.client, {"device": "2/discover", "ifName": "Gi0/0/0"})
        self.assertEqual(str(ctx.exception), "no LibreNMS device has hostname '2/discover'")
        self.assertEqual(self.fake.calls, [])

    def test_port_ids_must_be_digits(self):
        with self.assertRaisesRegex(self.base.StepError, r"^a port id must be a non-negative integer, got '12abc'$"):
            self.res.get(self.client, "12abc")
        self.assertEqual(self.fake.calls, [])


class Planning(PortCase):
    def test_update_by_id(self):
        step = self.plan({"description": "WAN: transit-c"}, id=5)
        self.assertEqual(
            step,
            {
                "index": 0,
                "action": "update",
                "resource": "port",
                "object_id": 5,
                "label": "Gi0/0/0 on edge-rtr1.example.net",
                "requested_op": "update",
                "resolved_by": "id",
                "parent_id": 2,
                "notes": [PINNED],
                "changes": {"description": {"from": "WAN: transit-a", "to": "WAN: transit-c"}},
                "payload": {"description": "WAN: transit-c"},
                "precondition": {
                    "state": {
                        "port_id": 5,
                        "device_id": 2,
                        "ifName": "Gi0/0/0",
                        "deleted": False,
                        "description": "WAN: transit-a",
                    }
                },
                "inverse_kind": "lossy",
                "inverse_note": LOSSY,
            },
        )
        self.assertEqual(self.fake.writes(), [])

    def test_update_by_match_looks_up_by_numeric_id_once_resolved(self):
        step = self.plan({"description": "x"}, match={"device": "edge-rtr1.example.net", "ifName": "Gi0/0/1"})
        self.assertEqual((step["resolved_by"], step["object_id"], step["parent_id"]), ("match", 6, 2))
        self.assertEqual(step["label"], "Gi0/0/1 on edge-rtr1.example.net")
        self.assertEqual(
            self.paths(),
            ["devices/edge-rtr1.example.net", "devices/2/ports", "ports/6", "ports/6/description", "devices/2"],
        )

    def test_clear(self):
        step = self.plan({"description": ""}, id=5)
        self.assertEqual(step["changes"], {"description": {"from": "WAN: transit-a", "to": ""}})
        self.assertEqual(step["payload"], {"description": ""})
        self.assertEqual(step["notes"], [RELEASED])
        self.assertEqual(self.res.describe(step), ['description: "WAN: transit-a" -> ""'])

    def test_null_clears_too(self):
        self.assertEqual(self.plan({"description": None}, id=5)["payload"], {"description": ""})

    def test_noop(self):
        cases = [(5, "WAN: transit-a", "WAN: transit-a"), (2, "", ""), (2, None, ""), (9, "", "repoll"), (9, "", None)]
        for port_id, desired, live in cases:
            self.fake.touch("ports", port_id, ifAlias=live)
            step = self.plan({"description": desired}, id=port_id)
            self.assertEqual((step["action"], step["reason"]), ("noop", "already matches desired state"))
            self.assertEqual(step["notes"], [])
            for key in ("changes", "payload", "precondition", "inverse_kind"):
                self.assertNotIn(key, step)

    def test_whitespace_is_kept(self):
        self.assertEqual(self.plan({"description": "  core link "}, id=2)["payload"], {"description": "  core link "})

    def test_deleted_and_unknown_ports_are_refused(self):
        with self.assertRaises(self.base.StepError) as ctx:
            self.plan({"description": "x"}, id=3)
        self.assertEqual(
            str(ctx.exception), "port #3 (Gi1/0/3) is marked deleted in LibreNMS: the device no longer has it"
        )
        with self.assertRaisesRegex(self.base.StepError, r"^port #99 does not exist$"):
            self.plan({"description": "x"}, id=99)
        with self.assertRaisesRegex(self.base.StepError, r'^no port matches \{"device": 1, "ifName": "Gi9"\}$'):
            self.plan({"description": "x"}, match={"device": 1, "ifName": "Gi9"})

    def test_label_falls_back_to_the_ifname(self):
        self.fake.fail_on("GET", "devices/2", 403)
        self.assertEqual(self.plan({"description": "x"}, id=5)["label"], "Gi0/0/0")

    def test_no_device_secret_reaches_the_step(self):
        text = json.dumps(
            self.plan({"description": "x"}, match={"device": "core-sw1.example.net", "ifName": "Gi1/0/1"})
        )
        for secret in SECRETS:
            self.assertNotIn(secret, text)


class Check(PortCase):
    def test_unchanged_port_passes(self):
        self.assertIsNone(self.res.check(self.client, self.plan({"description": "x"}, id=5)))

    def test_description_edited_elsewhere(self):
        step = self.plan({"description": "x"}, id=5)
        self.fake.touch("ports", 5, ifAlias="changed by the NOC")
        self.assertEqual(
            self.res.check(self.client, step),
            'port #5 changed since planning (description: "WAN: transit-a" -> "changed by the NOC")',
        )

    def test_poller_refresh_of_an_unpinned_port(self):
        step = self.plan({"description": "x"}, id=9)
        self.fake.poll(9, "to core-sw1 (renumbered)")
        self.assertEqual(
            self.res.check(self.client, step),
            'port #9 changed since planning (description: "to core-sw1" -> "to core-sw1 (renumbered)")',
        )

    def test_repoll_marker_is_not_a_change(self):
        step = self.plan({"description": "x"}, id=2)
        self.fake.touch("ports", 2, ifAlias="repoll")
        self.assertIsNone(self.res.check(self.client, step))

    def test_identity_changes(self):
        step = self.plan({"description": "x"}, id=5)
        self.fake.touch("ports", 5, deleted=1)
        self.assertEqual(self.res.check(self.client, step), "port #5 changed since planning (deleted: false -> true)")
        self.fake.touch("ports", 5, deleted=0, ifName="Gi0/0/9")
        self.assertEqual(
            self.res.check(self.client, step), 'port #5 changed since planning (ifName: "Gi0/0/0" -> "Gi0/0/9")'
        )
        del self.fake.tables["ports"][5]
        self.assertEqual(self.res.check(self.client, step), "port #5 no longer exists")


class Execute(PortCase):
    def test_set_writes_pins_and_verifies(self):
        step = self.plan({"description": "to core-sw1 Gi1/0/48"}, id=9)
        self.assertFalse(self.pinned(9))
        result = self.apply(step)
        self.assertEqual(
            result,
            {
                "object_id": 9,
                "inverse": {"action": "update", "object_id": 9, "data": {"description": "to core-sw1"}},
                "after_state": {
                    "port_id": 9,
                    "device_id": 3,
                    "ifName": "Gi1/0/48",
                    "deleted": False,
                    "description": "to core-sw1 Gi1/0/48",
                },
                "notes": [],
            },
        )
        writes = self.fake.writes()
        self.assertEqual(
            [(w["method"], w["path"], w["json"]) for w in writes],
            [("PATCH", "ports/9/description", {"description": "to core-sw1 Gi1/0/48"})],
        )
        self.assertTrue(self.pinned(9))
        self.fake.poll(9, "from the device")
        self.assertEqual(self.alias(9), "to core-sw1 Gi1/0/48")
        messages = [row["message"] for row in self.fake.tables["eventlog"].values()]
        self.assertIn("Gi1/0/48 Port ifAlias set via API: to core-sw1 Gi1/0/48", messages)

    def test_clear_hands_the_port_back_to_the_poller(self):
        result = self.apply(self.plan({"description": ""}, id=5))
        self.assertEqual(self.fake.writes()[-1]["json"], {"description": ""})
        self.assertEqual((self.alias(5), self.pinned(5)), ("repoll", False))
        self.assertEqual(result["after_state"]["description"], "")
        self.assertEqual(result["inverse"]["data"], {"description": "WAN: transit-a"})
        self.fake.poll(5, "WAN: from the device")
        self.assertEqual(self.alias(5), "WAN: from the device")

    def test_a_step_planned_by_match_writes_by_id(self):
        step = self.plan(
            {"description": "x"}, match={"device": "core-sw1.example.net", "ifDescr": "GigabitEthernet1/0/2"}
        )
        self.apply(step)
        self.assertEqual(self.paths("PATCH"), ["ports/2/description"])

    def test_whitespace_is_stored_verbatim(self):
        self.apply(self.plan({"description": "  spaced  "}, id=2))
        self.assertEqual(self.alias(2), "  spaced  ")


class PartialWrites(PortCase):
    def test_server_error_after_the_write_landed(self):
        self.fake.fail_on("PATCH", r"ports/5/description", 500, commit=True)
        step = self.plan({"description": "WAN: transit-c"}, id=5)
        with self.assertRaises(self.base.PartialWrite) as ctx:
            self.apply(step)
        self.assertTrue(str(ctx.exception).startswith("PATCH /api/v0/ports/5/description -> HTTP 500"))
        self.assertIn("LibreNMS applied part of the step; rollback reverts it", str(ctx.exception))
        entry = ctx.exception.entry
        self.assertEqual(
            entry["inverse"], {"action": "update", "object_id": 5, "data": {"description": "WAN: transit-a"}}
        )
        self.assertEqual(entry["after_state"]["description"], "WAN: transit-c")
        self.fake.failures.clear()
        failed = entry_for(step, entry, "failed", wrote=True, error=str(ctx.exception))
        self.assertEqual(self.revert(failed), ("reverted", {"restored_fields": ["description"]}))
        self.assertEqual(self.alias(5), "WAN: transit-a")

    def test_server_error_that_changed_nothing_is_the_original_error(self):
        self.fake.fail_on("PATCH", r"ports/5/description", 500)
        with self.assertRaises(self.LibreNMSError) as ctx:
            self.apply(self.plan({"description": "WAN: transit-c"}, id=5))
        self.assertEqual(ctx.exception.kind, "server")
        self.assertEqual(self.alias(5), "WAN: transit-a")
        self.assertEqual(self.paths()[-2:], ["ports/5", "ports/5/description"])  # the re-read that proved it

    def test_transport_failure_after_the_write_landed(self):
        step = self.plan({"description": ""}, id=5)
        self.fake.fail_on("PATCH", r"ports/5/description", exc=ConnectionError("reset"), commit=True)
        with self.assertLogs(CLIENT_LOG, "WARNING"), self.assertRaises(self.base.PartialWrite) as ctx:
            self.apply(step)
        self.assertIn("could not reach LibreNMS", str(ctx.exception))
        self.assertEqual(ctx.exception.entry["after_state"]["description"], "")

    def test_rejected_first_write_is_not_reread(self):
        self.fake.fail_on("PATCH", r"ports/5/description", 400, {"status": "error", "message": "Invalid port ID."})
        with self.assertRaises(self.LibreNMSError) as ctx:
            self.apply(self.plan({"description": "x"}, id=5))
        self.assertEqual(ctx.exception.kind, "api")
        self.assertEqual(self.fake.calls[-1]["method"], "PATCH")

    def test_accepted_but_not_stored(self):
        answer = {"status": "ok", "message": "Port description updated."}
        self.fake.fail_on("PATCH", r"ports/5/description", 200, answer)
        with self.assertRaises(self.base.PartialWrite) as ctx:
            self.apply(self.plan({"description": "WAN: transit-c"}, id=5))
        self.assertEqual(
            str(ctx.exception),
            'LibreNMS accepted the write but description is "WAN: transit-a", expected "WAN: transit-c"',
        )
        self.assertEqual(ctx.exception.entry["inverse"]["data"], {"description": "WAN: transit-a"})

    def test_reread_failure_leaves_the_outcome_to_rollback(self):
        step = self.plan({"description": "WAN: transit-c"}, id=5)
        self.fake.fail_on("PATCH", r"ports/5/description", exc=ConnectionError("reset"), commit=True)
        self.fake.fail_on("GET", r"ports/5", exc=TimeoutError("read timed out"))
        with self.assertLogs(CLIENT_LOG, "WARNING"), self.assertRaises(self.base.PartialWrite) as ctx:
            self.apply(step)
        entry = ctx.exception.entry
        self.assertIsNone(entry["after_state"])
        self.assertIn("outcome unknown", entry["notes"][0])
        self.fake.failures.clear()
        failed = entry_for(step, entry, "failed", wrote=True)
        self.assertEqual(self.revert(failed, step=step), ("reverted", {"restored_fields": ["description"]}))
        self.assertEqual(self.alias(5), "WAN: transit-a")


class Revert(PortCase):
    def test_restores_the_text_but_not_the_poller_lock(self):
        step, entry = self.applied({"description": "patched to core-sw1"}, id=9)
        self.assertEqual(step["inverse_kind"], "lossy")
        self.assertEqual(self.revert(entry), ("reverted", {"restored_fields": ["description"]}))
        self.assertEqual(self.alias(9), "to core-sw1")
        self.assertTrue(self.pinned(9))  # the lossy part: it was poller-managed before the plan

    def test_a_port_without_description_is_handed_back_to_the_poller(self):
        step, entry = self.applied({"description": "spare"}, id=2)
        self.assertEqual(entry["inverse"]["data"], {"description": ""})
        self.assertEqual(self.revert(entry), ("reverted", {"restored_fields": ["description"]}))
        self.assertEqual(self.fake.writes()[-1]["json"], {"description": ""})
        self.assertEqual((self.alias(2), self.pinned(2)), ("repoll", False))

    def test_previous_zero_is_restored_by_clearing(self):
        self.fake.touch("ports", 9, ifAlias="0")  # only the poller can store "0"
        step, entry = self.applied({"description": "x"}, id=9)
        self.assertEqual(step["changes"]["description"]["from"], "0")
        self.assertEqual(entry["inverse"]["data"], {"description": ""})
        self.assertEqual(self.revert(entry), ("reverted", {"restored_fields": ["description"]}))
        self.assertEqual((self.alias(9), self.pinned(9)), ("repoll", False))

    def test_conflict_unless_forced(self):
        step, entry = self.applied({"description": "WAN: transit-c"}, id=5)
        self.fake.touch("ports", 5, ifAlias="edited by the NOC")
        status, details = self.revert(entry)
        self.assertEqual(status, "conflict")
        self.assertEqual(
            details["error"],
            'port #5 was modified after apply (description: "WAN: transit-c" -> "edited by the NOC"); use force to '
            "overwrite",
        )
        self.assertEqual(self.alias(5), "edited by the NOC")
        self.assertEqual(self.revert(entry, force=True), ("reverted", {"restored_fields": ["description"]}))
        self.assertEqual(self.alias(5), "WAN: transit-a")

    def test_forward_clear_accepts_a_repolled_description(self):
        step, entry = self.applied({"description": ""}, id=5)
        self.fake.poll(5, "WAN: from the device")
        self.assertEqual(self.revert(entry), ("reverted", {"restored_fields": ["description"], "note": REPOLLED}))
        self.assertEqual((self.alias(5), self.pinned(5)), ("WAN: transit-a", True))

    def test_forward_clear_before_the_poll(self):
        step, entry = self.applied({"description": ""}, id=5)
        self.assertEqual(self.revert(entry), ("reverted", {"restored_fields": ["description"]}))
        self.assertEqual(self.alias(5), "WAN: transit-a")

    def test_forward_clear_of_a_poller_managed_port_restores_exactly(self):
        step, entry = self.applied({"description": ""}, id=9)
        self.fake.poll(9, "to core-sw1")
        writes = len(self.fake.writes())
        self.assertEqual(
            self.revert(entry),
            ("reverted", {"restored_fields": [], "note": f"{REPOLLED}; fields already had their previous values"}),
        )
        self.assertEqual(len(self.fake.writes()), writes)
        self.assertFalse(self.pinned(9))

    def test_forward_clear_still_guards_the_port_identity(self):
        step, entry = self.applied({"description": ""}, id=5)
        self.fake.touch("ports", 5, ifName="Gi0/0/7", ifAlias="from the device")
        status, details = self.revert(entry)
        self.assertEqual(status, "conflict")
        self.assertEqual(
            details["error"],
            'port #5 was modified after apply (ifName: "Gi0/0/0" -> "Gi0/0/7"); use force to overwrite',
        )

    def test_gone_port(self):
        step, entry = self.applied({"description": "x"}, id=5)
        del self.fake.tables["ports"][5]
        self.assertEqual(self.revert(entry), ("failed", {"error": "port #5 no longer exists; cannot restore fields"}))
        step, entry = self.applied({"description": ""}, id=6)
        del self.fake.tables["ports"][6]
        self.assertEqual(self.revert(entry), ("failed", {"error": "port #6 no longer exists; cannot restore fields"}))

    def test_unknown_outcome_after_a_crash(self):
        step = self.plan({"description": "WAN: transit-c"}, id=5)
        self.fake.touch("ports", 5, ifAlias="WAN: transit-c")  # the write landed before the process died
        entry = entry_for(step, status="unknown", wrote=True)
        self.assertEqual(self.revert(entry, step=step), ("reverted", {"restored_fields": ["description"]}))
        self.assertEqual(self.alias(5), "WAN: transit-a")


if __name__ == "__main__":
    import unittest

    unittest.main()
