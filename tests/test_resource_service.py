"""The service resource against the fake LibreNMS: validation, planning, preconditions, verified writes, partial
writes and rollback (design §8.3 service, §16.5-16.7; specs/ln-groups.md SV-1..SV-5).

Seeded services: #1 http "core-web" and #3 icmp "ping" (from template #2) on core-sw1 (device 1, no overwrite_ip),
#2 http "intranet" on access-sw2 (device 3), whose param carries a password."""

from __future__ import annotations

import json

from .base import PluginTestCase
from .fake_librenms import SECRETS
from .helpers import submodule

service = submodule("resources.service")
base = submodule("resources.base")
diff = submodule("diff")
LibreNMSError = submodule("client").LibreNMSError

WEB_PARAM = "-u /health -t 10"
INTRANET_PARAM = "-H intranet.example.net -a monitor:Sup3rS3cret!"
ADDED = {"status": "ok", "message": "Service added"}  # an add answer that does not say which id it made


class Died(BaseException):
    """The process dying during a request (Ctrl-C, OOM, a gateway restart): nothing in the plugin catches it."""


def resumable(context, entry):
    """*context* with the executor's ``checkpoint``: it merges progress into the entry's ``revert_progress``."""

    def checkpoint(progress):
        entry["revert_progress"] = {**(entry.get("revert_progress") or {}), **progress}

    return dict(context, checkpoint=checkpoint)


class ServiceCase(PluginTestCase):
    def setUp(self):
        super().setUp()
        self.res = service.RESOURCE
        self.context = {"plan_id": "lnp-test", "settings": self.settings, "actor": None}

    def op(self, kind, data=None, id=None, match=None):
        return {"op": kind, "resource": "service", "id": id, "match": match, "data": data or {}}

    def plan(self, kind, data=None, id=None, match=None):
        operation = self.op(kind, data, id, match)
        self.assertEqual(self.res.validate(kind, operation["data"], self.settings), [])
        return self.res.plan_step(self.client, 0, operation, self.settings)

    def apply(self, step):
        self.fake.calls.clear()
        return self.res.execute(self.client, step, self.context)

    def entry(self, step, result=None, status="done", **extra):
        """A journal entry as the executor writes it."""
        keys = ("index", "action", "resource", "object_id", "label", "parent_id", "inverse_kind")
        entry = {key: step.get(key) for key in keys}
        entry.update(status=status, at="2026-10-28T19:00:00Z", **(result or {}), **extra)
        return entry

    def revert(self, entry, force=False, step=None):
        self.fake.calls.clear()
        context = dict(self.context, step=step) if step is not None else self.context
        return self.res.revert(self.client, entry, force, context)

    def writes(self):
        return [(call["method"], call["path"], call["json"]) for call in self.fake.writes()]

    def row(self, service_id):
        return self.fake.tables["services"].get(service_id)

    def create_ssh(self, **data):
        return self.plan("create", {"device": "core-sw1.example.net", "type": "tcp", "name": "ssh", **data})

    def create_ssh_with(self, match):
        return self.plan("create", {"device": "core-sw1.example.net", "type": "tcp", "name": "ssh"}, match=match)


class Validation(ServiceCase):
    def validate(self, op, data):
        return self.res.validate(op, data, self.settings)

    def test_create_requires_device_and_type(self):
        self.assertEqual(
            self.validate("create", {"desc": "x"}),
            ["device is required to create a service", "type is required to create a service"],
        )

    def test_unknown_fields_and_column_names_are_rejected(self):
        self.assertEqual(
            self.validate("create", {"device": 1, "type": "http", "service_param": "-x", "device_id": 1}),
            [
                "cannot create service field(s) device_id, service_param; allowed: desc, disabled, ignore, ip, name, "
                "param, type"
            ],
        )
        self.assertIn(
            "cannot update service field(s) service_template_id", self.validate("update", {"service_template_id": 0})[0]
        )

    def test_value_kinds(self):
        errors = self.validate(
            "create", {"device": 1, "type": "http", "ignore": "maybe", "disabled": None, "ip": 5, "desc": None}
        )
        self.assertEqual(
            errors,
            [
                "disabled: null is not allowed",
                'ignore: expected true or false, got "maybe"',
                "ip: expected a string, got 5",
            ],
        )
        self.assertEqual(self.validate("update", {"ignore": "yes", "disabled": 0, "param": None}), [])

    def test_device_reference(self):
        for good in (1, "1", "core-sw1.example.net"):
            self.assertEqual(self.validate("create", {"device": good, "type": "http"}), [], good)
        for bad in (True, 0, "0", -1, " ", {"id": 1}, [1], "..", "sw1\nsw2", "2/discover"):
            errors = self.validate("create", {"device": bad, "type": "http"})
            self.assertEqual(len(errors), 1, bad)
            self.assertRegex(errors[0], r"^device: expected a device id or hostname, got ")

    def test_type_must_name_a_check(self):
        self.assertEqual(self.validate("create", {"device": 1, "type": "esxi_hardware.py"}), [])
        for bad in ("http -H evil", "../../bin/sh", "a\\b", "x" * 256, "tab\there"):
            errors = self.validate("update", {"type": bad})
            self.assertEqual(len(errors), 1, bad)
            self.assertIn("type: expected the name of a Nagios check", errors[0])
        self.assertEqual(self.validate("update", {"type": None}), ["type: null is not allowed"])
        self.assertIn("type: expected the name of a Nagios check", self.validate("update", {"type": ""})[0])
        self.assertEqual(self.validate("create", {"device": 1, "type": ""}), ["type is required to create a service"])

    def test_add_route_reads_zero_as_empty(self):
        self.assertEqual(
            self.validate("create", {"device": 1, "type": "http", "desc": "0", "param": "0", "name": "0"}),
            [
                'desc: LibreNMS adds a service with desc "0" as an empty one (PHP reads "0" as false); add it without '
                "desc, then set it with an update",
                'param: LibreNMS adds a service with param "0" as an empty one (PHP reads "0" as false); add it '
                "without param, then set it with an update",
            ],
        )
        self.assertEqual(self.validate("update", {"desc": "0", "param": "0"}), [])  # the edit route stores it as sent

    def test_name_fits_its_column(self):
        self.assertEqual(self.validate("update", {"name": "n" * 255}), [])
        self.assertEqual(
            self.validate("update", {"name": "n" * 256}), ["name: at most 255 characters (LibreNMS would cut it)"]
        )

    def test_device_cannot_change(self):
        self.assertEqual(
            self.validate("update", {"device": 2, "desc": "x"}),
            ["device cannot be changed: delete the service and create it on the other device"],
        )

    def test_delete_takes_no_data(self):
        self.assertEqual(self.validate("delete", {}), [])

    def test_every_operation_can_be_undone(self):
        self.assertEqual(
            {op: kind for op, (kind, _note) in self.res.inverse.items()},
            {"create": "exact", "update": "exact", "delete": "lossy"},
        )

    def test_allow_services_gates_every_operation(self):
        if self.planner is None:
            self.skipTest("planner.py is not written yet")
        self.settings.allow_services = False
        for operation in (
            self.op("create", {"device": 1, "type": "http"}),
            self.op("update", {"desc": "x"}, id=1),
            self.op("delete", id=1),
        ):
            with self.assertRaises(self.planner.PlanError) as ctx:
                self.planner.build_plan(self.client, [operation], "t", self.settings, self.client.base_url)
            self.assertTrue(any("allow_services" in error["error"] for error in ctx.exception.errors))
        self.assertEqual(self.fake.writes(), [])


class Planning(ServiceCase):
    def test_a_device_reference_with_a_slash_is_never_looked_up(self):
        for operation in (  # encoded, it would reach the rediscovery route
            self.op("create", {"device": "2/discover", "type": "http"}),
            self.op("update", {"desc": "x"}, match={"device": "2/discover", "type": "http"}),
        ):
            with self.subTest(op=operation["op"]), self.assertRaises(base.StepError) as ctx:
                self.res.plan_step(self.client, 0, operation, self.settings)
            self.assertIn('device: expected a device id or hostname, got "2/discover"', str(ctx.exception))
        self.assertEqual(self.fake.calls, [])

    def test_create_with_empty_ip_records_the_poller_target(self):
        step = self.create_ssh(param="-p 22", desc="SSH")
        self.assertEqual(
            (step["action"], step["object_id"], step["parent_id"], step["label"]),
            ("create", None, 1, "ssh on core-sw1.example.net"),
        )
        self.assertEqual(step["data"], {"type": "tcp", "name": "ssh", "param": "-p 22", "desc": "SSH", "device_id": 1})
        self.assertEqual(step["expected_ip"], "core-sw1.example.net")
        self.assertEqual(step["max_service_id"], 3)
        self.assertNotIn("exists_check", step)  # identical services are allowed: no precondition without match
        self.assertEqual((step["inverse_kind"], step["inverse_note"], step["notes"]), ("exact", "", []))
        self.assertEqual(
            self.res.describe(step),
            ['type="tcp", ip="core-sw1.example.net" (poller target), desc="SSH", name="ssh"', 'param: "-p 22"'],
        )

    def test_poller_target_is_overwrite_ip_first(self):
        step = self.plan("create", {"device": 2, "type": "icmp", "ip": ""})
        self.assertEqual((step["expected_ip"], step["label"]), ("198.51.100.2", "icmp on edge-rtr1.example.net"))

    def test_explicit_ip_is_kept(self):
        step = self.plan("create", {"device": "1", "type": "dns", "ip": "10.0.0.53"})
        self.assertNotIn("expected_ip", step)
        self.assertEqual(step["data"]["ip"], "10.0.0.53")
        self.assertEqual(self.res.describe(step), ['type="dns", ip="10.0.0.53"'])

    def test_unknown_device(self):
        with self.assertRaisesRegex(base.StepError, r'^no LibreNMS device has hostname "ghost.example.net"$'):
            self.plan("create", {"device": "ghost.example.net", "type": "http"})
        with self.assertRaisesRegex(base.StepError, r"^no LibreNMS device has id 99$"):
            self.plan("create", {"device": 99, "type": "http"})

    def test_hostname_answered_403(self):
        self.fake.fail_on("GET", "devices/hidden.example.net", 403, {"status": "error", "message": "Forbidden"})
        with self.assertRaisesRegex(base.StepError, r"^LibreNMS answered 403 for hostname hidden.example.net: .*id"):
            self.plan("create", {"device": "hidden.example.net", "type": "http"})

    def test_device_credentials_never_reach_the_step(self):
        step = self.create_ssh()
        text = json.dumps(step)
        self.assertFalse([secret for secret in SECRETS if secret in text])

    def test_identical_service_is_a_warning(self):
        step = self.plan(
            "create", {"device": 1, "type": "http", "ip": "192.0.2.1", "param": WEB_PARAM, "name": "core-web"}
        )
        self.assertEqual(step["action"], "create")
        self.assertEqual(len(step["notes"]), 1)
        self.assertRegex(step["notes"][0], r"^core-sw1.example.net already has service #1 with this type, ip, param")
        self.assertIn("LibreNMS allows duplicates", step["notes"][0])

    def test_create_with_match_that_finds_nothing_has_a_precondition(self):
        match = {"device": "core-sw1.example.net", "type": "tcp", "name": "ssh"}
        step = self.plan("create", {"device": "core-sw1.example.net", "type": "tcp", "name": "ssh"}, match=match)
        self.assertEqual((step["action"], step["resolved_by"]), ("create", "match"))
        self.assertEqual(step["exists_check"], {"device": 1, "type": "tcp", "name": "ssh"})
        self.assertEqual(
            self.res.describe(step)[-1], 'precondition: no service matches {"device": 1, "name": "ssh", "type": "tcp"}'
        )

    def test_upsert_updates_the_matched_service(self):
        step = self.plan(
            "create",
            {"device": "core-sw1.example.net", "type": "http", "desc": "Web UI v2"},
            match={"device": "core-sw1.example.net", "name": "core-web"},
        )
        self.assertEqual((step["action"], step["upsert"], step["object_id"], step["parent_id"]), ("update", True, 1, 1))
        self.assertEqual(step["label"], "core-web on core-sw1.example.net")
        self.assertEqual(step["changes"], {"desc": {"from": "Web UI", "to": "Web UI v2"}})
        self.assertEqual(step["payload"], {"service_desc": "Web UI v2"})

    def test_upsert_noop(self):
        step = self.plan("create", {"device": 1, "type": "http", "desc": "Web UI"}, match={"device": 1, "type": "http"})
        self.assertEqual((step["action"], step["reason"]), ("noop", "already matches desired state"))
        self.assertNotIn("upsert", step)
        self.assertNotIn("precondition", step)

    def test_upsert_with_empty_ip_means_the_poller_target(self):
        step = self.plan("create", {"device": 1, "type": "http", "ip": ""}, match={"device": 1, "name": "core-web"})
        self.assertEqual(
            step["changes"], {"ip": {"from": "192.0.2.1", "to": "core-sw1.example.net", "to_label": "poller target"}}
        )
        self.assertEqual(self.res.describe(step), ['ip: "192.0.2.1" -> "core-sw1.example.net" (poller target)'])

    def test_create_with_match_on_another_device_is_refused(self):
        for match in (
            {"device": 2, "name": "ssh"},
            {"device": "edge-rtr1.example.net", "name": "ssh"},
            {"device": "ghost.example.net", "name": "ssh"},
        ):
            with self.assertRaisesRegex(
                base.StepError, r"but data adds it to device #1; name the same device in both$"
            ):
                self.create_ssh_with(match)
        self.assertEqual(self.create_ssh_with({"device": 1, "name": "ssh"})["action"], "create")

    def test_upsert_cannot_move_a_service(self):
        with self.assertRaisesRegex(
            base.StepError, r"on device #1, but data names device #2; a service cannot be moved"
        ):
            self.plan("create", {"device": 2, "type": "http"}, match={"device": 1, "name": "core-web"})

    def test_update_by_id(self):
        step = self.plan("update", {"desc": "Web", "ignore": "true", "param": "-u /ready", "type": "http"}, id=1)
        self.assertEqual(
            (step["action"], step["resolved_by"], step["object_id"], step["parent_id"]), ("update", "id", 1, 1)
        )
        self.assertEqual(step["label"], "core-web on core-sw1.example.net")
        self.assertEqual(
            step["changes"],
            {
                "desc": {"from": "Web UI", "to": "Web"},
                "ignore": {"from": False, "to": True},
                "param": {"from": WEB_PARAM, "to": "-u /ready"},
            },
        )
        self.assertEqual(step["payload"], {"service_desc": "Web", "service_ignore": 1, "service_param": "-u /ready"})
        self.assertEqual((step["inverse_kind"], step["inverse_note"]), ("exact", ""))
        self.assertEqual(
            step["precondition"]["state"],
            {
                "service_id": 1,
                "device_id": 1,
                "type": "http",
                "ip": "192.0.2.1",
                "desc": "Web UI",
                "param": WEB_PARAM,
                "ignore": False,
                "disabled": False,
                "name": "core-web",
                "template_id": 0,
            },
        )
        self.assertEqual(
            self.res.describe(step),
            ['desc: "Web UI" -> "Web"', "ignore: false -> true", f'param: {diff.redacted(WEB_PARAM)} -> "-u /ready"'],
        )
        self.assertEqual(step["notes"], [])

    def test_new_param_is_shown_whole_and_the_old_one_never(self):
        new = "-H intranet.example.net -a monitor:" + "x" * 300
        lines = self.res.describe(self.plan("update", {"param": new}, id=2))
        self.assertEqual(lines, [f"param: {diff.redacted(INTRANET_PARAM)} -> {json.dumps(new)}"])
        self.assertNotIn("Sup3rS3cret!", "\n".join(lines))

    def test_update_noop(self):
        step = self.plan("update", {"desc": "Web UI", "ignore": 0, "name": "core-web"}, id=1)
        self.assertEqual(step["action"], "noop")

    def test_update_of_templated_service_warns(self):
        step = self.plan("update", {"desc": "keepalive"}, id=3)
        self.assertEqual(
            step["notes"],
            ["service #3 comes from service template #2; applying that template again may undo this change"],
        )
        self.assertEqual(self.plan("update", {"name": "ping"}, id=3)["notes"], [])  # a noop warns about nothing

    def test_type_change_warns_that_the_check_is_not_verified(self):
        step = self.plan("update", {"type": "ssh", "desc": "Web UI"}, id=1)
        self.assertEqual(
            step["notes"],
            [
                "type: LibreNMS checks that check_ssh exists on the poller when a service is added, not when one is "
                "edited; make sure it is installed"
            ],
        )

    def test_plain_update_sends_empty_ip_as_it_is(self):
        step = self.plan("update", {"ip": ""}, id=1)
        self.assertEqual(step["changes"], {"ip": {"from": "192.0.2.1", "to": ""}})
        self.assertNotIn("expected_ip", step)

    def test_update_by_match(self):
        step = self.plan("update", {"desc": "ping"}, match={"device": "core-sw1.example.net", "type": "icmp"})
        self.assertEqual((step["object_id"], step["resolved_by"]), (3, "match"))

    def test_delete_keeps_the_configuration(self):
        step = self.plan("delete", id=2)
        state = {
            "service_id": 2,
            "device_id": 3,
            "type": "http",
            "ip": "access-sw2.example.net",
            "desc": "Intranet login",
            "param": INTRANET_PARAM,
            "ignore": False,
            "disabled": False,
            "name": "intranet",
            "template_id": 0,
        }
        self.assertEqual(step["snapshot"], state)
        self.assertEqual(step["precondition"], {"state": state})
        self.assertEqual((step["label"], step["parent_id"]), ("intranet on access-sw2.example.net", 3))
        self.assertEqual(
            (step["inverse_kind"], step["inverse_note"]),
            ("lossy", "re-created with a new service id; its graph history stays attached to the old id"),
        )
        self.assertEqual(self.res.describe(step), ["the service is deleted; its configuration is kept in the plan"])

    def test_delete_of_templated_service_warns(self):
        self.assertEqual(
            self.plan("delete", id=3)["notes"],
            ["service #3 comes from service template #2; applying that template again may re-create it"],
        )

    def test_missing_service(self):
        with self.assertRaisesRegex(base.StepError, r"^service #99 does not exist$"):
            self.plan("update", {"desc": "x"}, id=99)

    def test_by_id_reads_every_service_then_only_its_device(self):
        self.fake.calls.clear()
        step = self.plan("update", {"desc": "x"}, id=2)
        self.assertIn("services", [call["path"] for call in self.fake.calls])
        self.fake.calls.clear()
        self.assertIsNone(self.res.check(self.client, step))
        self.assertEqual([call["path"] for call in self.fake.calls], ["services/3"])


class Matching(ServiceCase):
    def find(self, match):
        count, obj = self.res.find(self.client, match)
        return count, obj and obj["service_id"]

    def test_filters_on_the_given_keys(self):
        self.assertEqual(self.find({"device": 1, "ip": "192.0.2.1"}), (2, None))
        self.assertEqual(self.find({"device": "core-sw1.example.net", "type": "icmp"}), (1, 3))
        self.assertEqual(self.find({"device": 3, "desc": "Intranet login", "name": "intranet"}), (1, 2))
        self.assertEqual(self.find({"device": 1, "name": "intranet"}), (0, None))
        self.assertEqual(self.find({"device": "ghost.example.net"}), (0, None))

    def test_empty_ip_matches_the_poller_target(self):
        self.fake.seed("services", {"device_id": 1, "service_ip": "core-sw1.example.net", "service_type": "tcp"})
        self.assertEqual(self.find({"device": 1, "ip": ""}), (1, 4))

    def test_match_errors(self):
        for match, message in (
            ({"type": "http"}, "a service match needs device"),
            ({"device": True}, "match device: expected a device id or hostname"),
            ({"device": 1, "type": 5}, "match type: expected a string, got 5"),
            ({"device": 1, "param": WEB_PARAM}, "cannot match a service on param"),
        ):
            with self.assertRaisesRegex(base.StepError, message):
                self.res.find(self.client, match)

    def test_ambiguous_match(self):
        with self.assertRaisesRegex(base.StepError, r"is ambiguous \(2 services\)$"):
            self.plan("update", {"desc": "x"}, match={"device": 1, "ip": "192.0.2.1"})

    def test_listing_without_the_extra_wrapping_is_read_too(self):
        row = dict(self.row(1))
        self.fake.fail_on("GET", "services/1", 200, {"status": "ok", "services": [row], "count": 1})
        self.assertEqual(self.res.get(self.client, 1, {"parent_id": 1})["service_name"], "core-web")


class Preconditions(ServiceCase):
    def test_poller_churn_is_not_a_change(self):
        step = self.plan("update", {"desc": "Web"}, id=1)
        self.fake.touch(
            "services", 1, service_status=2, service_message="CRITICAL", service_changed=1761700000, service_ds="{}"
        )
        self.assertIsNone(self.res.check(self.client, step))

    def test_config_change_is_a_conflict(self):
        step = self.plan("update", {"name": "web"}, id=1)
        self.fake.touch("services", 1, service_desc="edited in the UI")
        self.assertEqual(
            self.res.check(self.client, step),
            'service #1 changed since planning (desc: "Web UI" -> "edited in the UI")',
        )

    def test_param_change_is_shown_as_digests(self):
        step = self.plan("update", {"desc": "x"}, id=2)
        self.fake.touch("services", 2, service_param="-a monitor:N3wS3cret")
        message = self.res.check(self.client, step)
        self.assertEqual(
            message,
            f"service #2 changed since planning (param: {diff.redacted(INTRANET_PARAM)} -> "
            f"{diff.redacted('-a monitor:N3wS3cret')})",
        )

    def test_service_gone(self):
        step = self.plan("delete", id=1)
        del self.fake.tables["services"][1]
        self.assertEqual(self.res.check(self.client, step), "service #1 no longer exists")

    def test_create_with_match_conflicts_when_one_appears(self):
        match = {"device": 1, "type": "tcp", "name": "ssh"}
        step = self.plan("create", {"device": 1, "type": "tcp", "name": "ssh"}, match=match)
        self.assertIsNone(self.res.check(self.client, step))
        self.fake.seed("services", {"device_id": 1, "service_ip": "x", "service_type": "tcp", "service_name": "ssh"})
        self.assertRegex(self.res.check(self.client, step), r"^1 service\(s\) now match .*; expected none$")

    def test_create_conflicts_when_the_poller_target_moved(self):
        step = self.create_ssh()
        self.fake.touch("devices", 1, overwrite_ip="192.0.2.99")
        self.assertEqual(
            self.res.check(self.client, step),
            'the poller target of device #1 is now "192.0.2.99", not "core-sw1.example.net" as planned',
        )
        explicit = self.create_ssh(ip="10.0.0.22")
        self.assertIsNone(self.res.check(self.client, explicit))

    def test_create_conflicts_when_the_device_is_gone(self):
        step = self.create_ssh()
        del self.fake.tables["devices"][1]
        self.assertEqual(self.res.check(self.client, step), "device #1 no longer exists")


class Execute(ServiceCase):
    def test_create_sends_every_key_and_verifies(self):
        step = self.create_ssh(param="-p 22")
        result = self.apply(step)
        self.assertEqual(
            self.writes(),
            [
                (
                    "POST",
                    "services/1",
                    {
                        "type": "tcp",
                        "ip": "",
                        "desc": "",
                        "param": "-p 22",
                        "ignore": False,
                        "disable": False,
                        "name": "ssh",
                    },
                )
            ],
        )
        self.assertEqual(result["object_id"], 4)
        self.assertEqual(result["inverse"], {"action": "delete", "object_id": 4})
        self.assertEqual(result["after_state"]["ip"], "core-sw1.example.net")
        self.assertEqual(result["notes"], [])
        self.assertEqual(self.row(4)["service_ip"], "core-sw1.example.net")
        self.assertNotIn("has been added", json.dumps(result))  # the answer carries param; it is never kept

    def test_create_flags_and_explicit_ip(self):
        step = self.plan("create", {"device": 2, "type": "icmp", "ip": "10.1.1.1", "ignore": True, "disabled": "yes"})
        result = self.apply(step)
        body = self.writes()[0][2]
        self.assertEqual((body["ip"], body["ignore"], body["disable"]), ("10.1.1.1", True, True))
        self.assertEqual((self.row(4)["service_ignore"], self.row(4)["service_disabled"]), (1, 1))
        self.assertEqual((result["after_state"]["ignore"], result["after_state"]["disabled"]), (True, True))

    def test_update_sends_only_changed_columns(self):
        step = self.plan("update", {"desc": "Web", "ignore": True, "type": "http"}, id=1)
        result = self.apply(step)
        self.assertEqual(self.writes(), [("PATCH", "services/1", {"service_desc": "Web", "service_ignore": 1})])
        self.assertEqual(
            result["inverse"], {"action": "update", "object_id": 1, "data": {"desc": "Web UI", "ignore": False}}
        )
        self.assertEqual((result["after_state"]["desc"], result["after_state"]["ignore"]), ("Web", True))
        self.assertEqual([call["path"] for call in self.fake.calls if call["method"] == "GET"], ["services/1"])

    def test_update_to_empty_ip_is_stored_empty(self):
        result = self.apply(self.plan("update", {"ip": ""}, id=1))
        self.assertEqual(self.writes(), [("PATCH", "services/1", {"service_ip": ""})])
        self.assertEqual((self.row(1)["service_ip"], result["after_state"]["ip"]), ("", ""))

    def test_delete(self):
        step = self.plan("delete", id=2)
        result = self.apply(step)
        self.assertEqual(self.writes(), [("DELETE", "services/2", None)])
        self.assertIsNone(self.row(2))
        self.assertEqual(
            result,
            {
                "object_id": 2,
                "inverse": {"action": "create", "snapshot": step["snapshot"]},
                "after_state": None,
                "notes": [],
            },
        )


class NewServiceId(ServiceCase):
    def test_param_that_looks_like_the_message_does_not_confuse_the_parse(self):
        result = self.apply(self.create_ssh(param='-s "(#7)" -e "service_id":7)'))
        self.assertEqual(result["object_id"], 4)

    def test_bare_id_form(self):
        added = {"status": "ok", "message": "Service tcp has been added to device 1 (#4)"}
        self.fake.fail_on("POST", "services/1", 201, added, commit=True)
        self.assertEqual(self.apply(self.create_ssh())["object_id"], 4)

    def test_cut_off_json_form(self):
        added = {"status": "ok", "message": 'Service tcp has been added to device 1 (#{"device_id":1,"service_id":4'}
        self.fake.fail_on("POST", "services/1", 201, added, commit=True)
        self.assertEqual(self.apply(self.create_ssh())["object_id"], 4)

    def test_id_is_looked_up_when_the_answer_does_not_say(self):
        self.fake.fail_on("POST", "services/1", 201, ADDED, commit=True)
        result = self.apply(self.create_ssh())
        self.assertEqual((result["object_id"], result["inverse"]), (4, {"action": "delete", "object_id": 4}))

    def test_lookup_skips_an_identical_older_service(self):
        step = self.plan(
            "create", {"device": 1, "type": "http", "ip": "192.0.2.1", "desc": "Web UI", "name": "core-web"}
        )
        self.fake.fail_on("POST", "services/1", 201, ADDED, commit=True)
        self.assertEqual(self.apply(step)["object_id"], 4)
        self.assertIsNotNone(self.row(1))


class PartialWrites(ServiceCase):
    def test_create_that_landed_before_a_500_is_partial_and_reverts(self):
        step = self.create_ssh()
        self.fake.fail_on("POST", r"services/\d+", 500, commit=True)
        with self.assertRaises(base.PartialWrite) as ctx:
            self.apply(step)
        self.assertIn("rollback reverts it", str(ctx.exception))
        entry = ctx.exception.entry
        self.assertEqual((entry["object_id"], entry["inverse"]), (4, {"action": "delete", "object_id": 4}))
        self.assertEqual(entry["after_state"]["name"], "ssh")
        status, details = self.revert(self.entry(step, entry, status="failed", wrote=True))
        self.assertEqual((status, details), ("reverted", {"object_id": 4}))
        self.assertIsNone(self.row(4))

    def test_create_cut_off_by_the_network_is_partial(self):
        self.fake.fail_on("POST", "services/1", exc=ConnectionError("connection reset"), commit=True)
        with self.assertRaises(base.PartialWrite) as ctx, self.assertLogs("hermes_plugins.librenms.client", "WARNING"):
            self.apply(self.create_ssh())
        self.assertEqual(ctx.exception.entry["object_id"], 4)

    def test_create_that_never_landed_raises_the_original(self):
        step = self.plan(
            "create", {"device": 1, "type": "http", "ip": "192.0.2.1", "desc": "Web UI", "name": "core-web"}
        )
        self.fake.fail_on("POST", "services/1", 500)
        with self.assertRaises(LibreNMSError) as ctx:
            self.apply(step)
        self.assertEqual(ctx.exception.kind, "server")
        self.assertEqual(sorted(self.fake.tables["services"]), [1, 2, 3])  # the identical older one was not taken

    def test_rejected_create_is_not_reread(self):
        step = self.create_ssh()
        self.fake.service_types.remove("tcp")
        with self.assertRaises(LibreNMSError) as ctx:
            self.apply(step)
        self.assertEqual((ctx.exception.kind, ctx.exception.status), ("api", 400))
        self.assertEqual(self.fake.calls[-1]["method"], "POST")

    def test_create_with_match_is_found_by_its_precondition(self):
        match = {"device": 1, "type": "tcp", "name": "ssh"}
        step = self.plan("create", {"device": 1, "type": "tcp", "name": "ssh"}, match=match)
        self.fake.fail_on("POST", "services/1", 502, commit=True)
        with self.assertRaises(base.PartialWrite) as ctx:
            self.apply(step)
        self.assertEqual(ctx.exception.entry["object_id"], 4)

    def test_create_that_cannot_be_told_apart_is_a_conflict_on_rollback(self):
        step = self.create_ssh()
        twin = {"device_id": 1, "service_ip": "core-sw1.example.net", "service_type": "tcp", "service_name": "ssh"}
        self.fake.seed("services", twin)  # made by someone else after the plan
        self.fake.fail_on("POST", "services/1", 500, commit=True)
        with self.assertRaises(base.PartialWrite) as ctx:
            self.apply(step)
        entry = ctx.exception.entry
        self.assertIsNone(entry["object_id"])
        self.assertEqual(
            entry["inverse"],
            {
                "action": "delete",
                "object_id": None,
                "find": {
                    "device": 1,
                    "type": "tcp",
                    "ip": "core-sw1.example.net",
                    "desc": "",
                    "name": "ssh",
                    "service_id_above": 3,
                },
            },
        )
        status, details = self.revert(self.entry(step, entry, status="failed", wrote=True))
        self.assertEqual(status, "conflict")
        self.assertRegex(details["error"], r"^2 services match .*cannot tell which one this plan created$")
        self.assertEqual(self.writes(), [])

    def test_update_that_landed_before_a_500_is_partial_and_reverts(self):
        step = self.plan("update", {"desc": "Web", "param": "-u /ready"}, id=1)
        self.fake.fail_on("PATCH", "services/1", 500, commit=True)
        with self.assertRaises(base.PartialWrite) as ctx:
            self.apply(step)
        entry = ctx.exception.entry
        self.assertEqual(
            entry["inverse"], {"action": "update", "object_id": 1, "data": {"desc": "Web UI", "param": WEB_PARAM}}
        )
        self.assertEqual(entry["after_state"]["desc"], "Web")
        self.fake.failures.clear()
        status, _ = self.revert(self.entry(step, entry, status="failed", wrote=True))
        self.assertEqual(status, "reverted")
        self.assertEqual((self.row(1)["service_desc"], self.row(1)["service_param"]), ("Web UI", WEB_PARAM))

    def test_update_that_never_landed_raises_the_original(self):
        self.fake.fail_on("PATCH", "services/1", 500)
        with self.assertRaises(LibreNMSError):
            self.apply(self.plan("update", {"desc": "Web"}, id=1))
        self.assertEqual(self.row(1)["service_desc"], "Web UI")

    def test_update_accepted_but_not_applied(self):
        self.fake.fail_on("PATCH", "services/1", 201, {"status": "ok", "message": "Service updated successfully"})
        with self.assertRaises(base.PartialWrite) as ctx:
            self.apply(self.plan("update", {"desc": "Web"}, id=1))
        self.assertEqual(str(ctx.exception), 'LibreNMS accepted the write but desc is "Web UI", expected "Web"')

    def test_error_text_never_carries_a_param(self):
        new = "-H intranet.example.net -a monitor:N3wS3cret!"
        step = self.plan("update", {"param": new}, id=2)
        body = {"status": "error", "message": f"cannot store {new} over {INTRANET_PARAM}"}
        self.fake.fail_on("PATCH", "services/2", 500, body)
        with self.assertRaises(base.StepError) as ctx:
            self.apply(step)
        self.assertNotIn("S3cret", str(ctx.exception))
        self.assertIn("<redacted>", str(ctx.exception))

    def test_delete_that_landed_before_a_500_is_partial_and_reverts(self):
        step = self.plan("delete", id=2)
        self.fake.fail_on("DELETE", "services/2", 500, commit=True)
        with self.assertRaises(base.PartialWrite) as ctx:
            self.apply(step)
        entry = ctx.exception.entry
        self.assertEqual(
            (entry["inverse"], entry["after_state"]), ({"action": "create", "snapshot": step["snapshot"]}, None)
        )
        status, details = self.revert(self.entry(step, entry, status="failed", wrote=True))
        self.assertEqual((status, details), ("reverted", {"new_object_id": 4}))

    def test_delete_accepted_but_still_there(self):
        self.fake.fail_on(
            "DELETE", "services/2", 201, {"status": "ok", "message": "Service has been deleted successfully"}
        )
        with self.assertRaisesRegex(base.StepError, r"^LibreNMS accepted the delete but service #2 still exists$"):
            self.apply(self.plan("delete", id=2))


class Rollback(ServiceCase):
    def applied(self, step):
        return step, self.entry(step, self.apply(step))

    def test_create_revert_deletes_unless_modified(self):
        step, entry = self.applied(self.create_ssh())
        self.fake.touch("services", 4, service_desc="claimed by someone")
        status, details = self.revert(entry)
        self.assertEqual(status, "conflict")
        self.assertEqual(
            details["error"],
            'service #4 was modified after apply (desc: "" -> "claimed by someone"); use force to delete anyway',
        )
        self.assertEqual(self.revert(entry, force=True), ("reverted", {"object_id": 4}))
        self.assertEqual(self.writes(), [("DELETE", "services/4", None)])
        self.assertEqual(self.revert(entry), ("reverted", {"note": "object already gone"}))
        self.assertEqual(self.writes(), [])  # a second delete would be a 500

    def test_update_revert_restores_exactly(self):
        _, entry = self.applied(self.plan("update", {"desc": "Web", "param": "-u /ready", "ignore": True}, id=1))
        self.assertEqual(self.revert(entry), ("reverted", {"restored_fields": ["desc", "ignore", "param"]}))
        self.assertEqual(
            self.writes(),
            [("PATCH", "services/1", {"service_desc": "Web UI", "service_param": WEB_PARAM, "service_ignore": 0})],
        )

    def test_update_revert_conflict_and_force(self):
        _, entry = self.applied(self.plan("update", {"desc": "Web"}, id=1))
        self.fake.touch("services", 1, service_name="renamed")
        status, details = self.revert(entry)
        self.assertEqual(
            (status, details["error"]),
            ("conflict", 'service #1 was modified after apply (name: "core-web" -> "renamed"); use force to overwrite'),
        )
        self.assertEqual(self.revert(entry, force=True), ("reverted", {"restored_fields": ["desc"]}))
        self.assertEqual(self.writes(), [("PATCH", "services/1", {"service_desc": "Web UI"})])

    def test_update_revert_sends_nothing_for_fields_already_restored(self):
        _, entry = self.applied(self.plan("update", {"desc": "Web", "name": "web"}, id=1))
        self.fake.touch("services", 1, service_desc="Web UI")
        self.assertEqual(self.revert(entry, force=True), ("reverted", {"restored_fields": ["name"]}))
        self.assertEqual(self.writes(), [("PATCH", "services/1", {"service_name": "core-web"})])
        self.fake.touch("services", 1, service_name="core-web")
        self.assertEqual(
            self.revert(entry, force=True),
            ("reverted", {"restored_fields": [], "note": "fields already had their previous values"}),
        )
        self.assertEqual(self.writes(), [])  # an edit that changes nothing would be a 500

    def test_delete_revert_recreates_from_the_snapshot(self):
        _, entry = self.applied(self.plan("delete", id=2))
        self.assertEqual(self.revert(entry), ("reverted", {"new_object_id": 4}))
        self.assertEqual(
            self.writes(),
            [
                (
                    "POST",
                    "services/3",
                    {
                        "type": "http",
                        "ip": "access-sw2.example.net",
                        "desc": "Intranet login",
                        "param": INTRANET_PARAM,
                        "ignore": False,
                        "disable": False,
                        "name": "intranet",
                    },
                )
            ],
        )
        self.assertEqual(self.row(4)["service_param"], INTRANET_PARAM)

    def test_delete_revert_restores_empty_ip_and_template_link(self):
        self.fake.touch("services", 2, service_ip="", service_template_id=5)
        _, entry = self.applied(self.plan("delete", id=2))
        self.assertEqual(self.revert(entry), ("reverted", {"new_object_id": 4}))
        self.assertEqual([write[:2] for write in self.writes()], [("POST", "services/3"), ("PATCH", "services/4")])
        self.assertEqual(self.writes()[0][2]["ip"], "")
        self.assertEqual(self.writes()[1][2], {"service_ip": "", "service_template_id": 5})
        self.assertEqual((self.row(4)["service_ip"], self.row(4)["service_template_id"]), ("", 5))

    def test_delete_revert_finds_the_new_id_when_the_answer_does_not_say(self):
        _, entry = self.applied(self.plan("delete", id=2))
        self.fake.fail_on("POST", "services/3", 201, ADDED, commit=True)
        self.assertEqual(self.revert(entry), ("reverted", {"new_object_id": 4}))

    def test_delete_revert_that_landed_before_a_500(self):
        _, entry = self.applied(self.plan("delete", id=2))
        self.fake.fail_on("POST", "services/3", 500, commit=True)
        self.assertEqual(self.revert(entry), ("reverted", {"new_object_id": 4}))

    def test_delete_revert_that_never_landed_raises(self):
        _, entry = self.applied(self.plan("delete", id=2))
        self.fake.fail_on("POST", "services/3", 500)
        with self.assertRaises(LibreNMSError):
            self.revert(entry)
        self.assertEqual(sorted(self.fake.tables["services"]), [1, 3])

    def test_delete_revert_when_the_check_was_uninstalled(self):
        _, entry = self.applied(self.plan("delete", id=2))
        self.fake.service_types.remove("http")
        with self.assertRaisesRegex(LibreNMSError, "The service http does not exist"):
            self.revert(entry)

    def failed_relink(self):
        """A delete rolled back once: the service was added again as #4, but restoring its template link failed."""
        self.fake.touch("services", 2, service_template_id=5)
        _, entry = self.applied(self.plan("delete", id=2))
        self.fake.fail_on("PATCH", "services/4", 500)
        status, details = self.revert(entry)
        self.fake.failures.clear()
        entry.update(revert_status=status, revert=details)  # as the executor journals it
        return entry

    def test_delete_revert_reports_the_new_id_when_relinking_fails(self):
        details = self.failed_relink()["revert"]
        self.assertEqual((details["new_object_id"], self.row(4)["service_template_id"]), (4, 0))
        self.assertRegex(details["error"], r"^re-created service #4, but restoring service_template_id failed: ")

    def test_next_rollback_finishes_the_service_it_re_created(self):
        entry = self.failed_relink()
        self.assertEqual(self.revert(entry), ("reverted", {"new_object_id": 4}))
        self.assertEqual(self.writes(), [("PATCH", "services/4", {"service_template_id": 5})])
        self.assertEqual(sorted(self.fake.tables["services"]), [1, 3, 4])  # no second copy

    def test_next_rollback_adds_again_when_the_earlier_copy_was_removed(self):
        entry = self.failed_relink()
        del self.fake.tables["services"][4]
        status, details = self.revert(entry)
        new_id = details["new_object_id"]
        self.assertEqual(status, "reverted")
        self.assertEqual(
            [write[:2] for write in self.writes()], [("POST", "services/3"), ("PATCH", f"services/{new_id}")]
        )
        self.assertEqual(self.row(new_id)["service_template_id"], 5)

    def test_a_rollback_that_died_after_its_add_is_finished_by_the_next(self):
        self.fake.touch("services", 2, service_template_id=5)
        _, entry = self.applied(self.plan("delete", id=2))
        self.fake.fail_on("POST", "services/3", exc=Died(), commit=True, times=1)
        with self.assertRaises(Died):
            self.res.revert(self.client, entry, False, resumable(self.context, entry))
        self.assertEqual((entry["revert_progress"], sorted(self.fake.tables["services"])), ({"floor": 0}, [1, 3, 4]))
        self.fake.calls.clear()
        self.assertEqual(
            self.res.revert(self.client, entry, False, resumable(self.context, entry)),
            ("reverted", {"new_object_id": 4, "note": "re-created by an earlier rollback"}),
        )
        self.assertEqual(self.writes(), [("PATCH", "services/4", {"service_template_id": 5})])  # finished, not re-added
        self.assertEqual(sorted(self.fake.tables["services"]), [1, 3, 4])

    def test_a_rollback_that_died_before_its_add_landed_adds_it(self):
        _, entry = self.applied(self.plan("delete", id=2))
        self.fake.fail_on("POST", "services/3", exc=Died(), times=1)
        with self.assertRaises(Died):
            self.res.revert(self.client, entry, False, resumable(self.context, entry))
        self.assertEqual(sorted(self.fake.tables["services"]), [1, 3])
        self.assertEqual(
            self.res.revert(self.client, entry, False, resumable(self.context, entry)),
            ("reverted", {"new_object_id": 4}),
        )
        self.assertEqual(sorted(self.fake.tables["services"]), [1, 3, 4])

    def test_a_resumed_rollback_that_cannot_tell_its_service_apart(self):
        _, entry = self.applied(self.plan("delete", id=2))
        self.fake.fail_on("POST", "services/3", exc=Died(), commit=True, times=1)
        with self.assertRaises(Died):
            self.res.revert(self.client, entry, False, resumable(self.context, entry))
        self.fake.seed("services", {"device_id": 3, "service_type": "http", "service_name": "intranet"})
        self.assertEqual(
            self.res.revert(self.client, entry, False, resumable(self.context, entry)),
            ("failed", {"error": "2 http services on device #3 are newer than the ones an interrupted rollback "
                                 "listed before re-creating this one; check them in LibreNMS"}),
        )  # fmt: skip
        self.assertEqual(sorted(self.fake.tables["services"]), [1, 3, 4, 5])

    def test_delete_whose_outcome_is_unknown_and_left_the_service_is_not_re_added(self):
        step = self.plan("delete", id=2)
        self.fake.fail_on("DELETE", "services/2", 504)  # a gateway gave up while LibreNMS was still working
        with self.assertRaises(base.PartialWrite) as ctx:
            self.apply(step)
        entry = self.entry(step, ctx.exception.entry, status="failed", wrote=True)
        self.assertEqual(self.revert(entry)[0], "failed")  # until the delete can no longer be running
        entry["settles_at"] = "2026-10-28T19:10:00Z"
        self.assertEqual(self.revert(entry), ("reverted", {"note": "nothing was deleted"}))
        self.assertEqual((self.writes(), sorted(self.fake.tables["services"])), ([], [1, 2, 3]))

    def test_delete_revert_restores_a_zero_the_add_route_drops(self):
        self.fake.touch("services", 2, service_desc="0")
        _, entry = self.applied(self.plan("delete", id=2))
        self.assertEqual(self.revert(entry), ("reverted", {"new_object_id": 4}))  # LibreNMS's ?: stored "" for "0"
        self.assertEqual(self.writes()[1], ("PATCH", "services/4", {"service_desc": "0"}))
        self.assertEqual(self.row(4)["service_desc"], "0")

    def test_delete_revert_that_cannot_tell_its_service_apart(self):
        _, entry = self.applied(self.plan("delete", id=2))
        racer = {"device_id": 3, "service_ip": "x", "service_type": "http", "service_name": "intranet"}
        self.fake.after("add_service_for_host", lambda: self.fake.seed("services", racer))  # landing at that moment
        self.fake.fail_on("POST", "services/3", 201, ADDED, commit=True)
        self.assertEqual(
            self.revert(entry),
            (
                "failed",
                {
                    "error": "LibreNMS accepted the re-create but 2 new http services on device #3 could be it; "
                    "check them in LibreNMS"
                },
            ),
        )

    def test_create_with_unknown_outcome(self):
        step = self.create_ssh()
        unknown = self.entry(step, status="unknown", wrote=True)
        self.assertEqual(self.revert(unknown, step=step), ("reverted", {"note": "nothing was written"}))
        self.apply(step)
        self.assertEqual(self.revert(unknown, step=step), ("reverted", {"object_id": 4}))
        self.assertIsNone(self.row(4))

    def test_update_with_unknown_outcome(self):
        step = self.plan("update", {"desc": "Web"}, id=1)
        unknown = self.entry(step, status="unknown", wrote=True)
        self.assertEqual(self.revert(unknown, step=step)[1]["note"], "nothing was written")
        self.apply(step)
        self.assertEqual(self.revert(unknown, step=step), ("reverted", {"restored_fields": ["desc"]}))
        self.assertEqual(self.row(1)["service_desc"], "Web UI")

    def test_delete_with_unknown_outcome_is_left_to_a_person(self):
        step = self.plan("delete", id=2)
        status, details = self.revert(self.entry(step, status="unknown", wrote=True), step=step)
        self.assertEqual(status, "failed")
        self.assertIn("outcome of this step is unknown", details["error"])
