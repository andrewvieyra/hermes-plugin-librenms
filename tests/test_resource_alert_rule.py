"""The alert_rule resource against the fake LibreNMS: whole-rule writes, scoping, snapshots and lossy re-creation."""

from __future__ import annotations

import copy
import json
import unittest

from .base import PluginTestCase, optional
from .fake_librenms import SECRETS, TOKEN, FakeResponse
from .helpers import submodule


def leaf(**changes):
    """One query-builder rule (a BGP peer that is not established), with *changes* on top."""
    rule = {"id": "bgpPeers.bgpPeerState", "field": "bgpPeers.bgpPeerState", "type": "string", "input": "text",
            "operator": "not_equal", "value": "established"}  # fmt: skip
    rule.update(changes)
    return rule


BGP_DOWN = {"condition": "AND", "valid": True, "rules": [leaf()]}
BGP_DOWN_SENT = {key: value for key, value in BGP_DOWN.items() if key != "valid"}
NEEDS_OPERATION = (
    "alert_operation_id is required: pass the id of an existing alert operation (copy it from a rule that already "
    "notifies the right people), or null to create the rule with notifications suppressed"
)
NEEDS_SCOPE = (
    'a new alert rule needs devices, groups or locations to scope it, or "global": true to apply it to every device'
)
GLOBAL_NOTE = "the rule applies to every device: it has no device, group or location mapping"
UNLOCATED = "rule was created but could not be located by name; delete it in the UI"
LOSSY_DELETE = (
    "re-created with a new id; its alert history and template mappings are not restored, and it may notify again for "
    "devices that are currently failing"
)
CREATE_NOTE = "deletes the rule again, with any alerts it raised in the meantime"
RECREATED = "re-created with a new id; its alert history and template mappings are not restored"
OVERRIDE_SQL = "SELECT * FROM devices WHERE devices.status = 0"
CLIENT_LOG = "hermes_plugins.librenms.client"  # transport failures are detailed there, under their error id


class Died(BaseException):
    """The process dying during a request (Ctrl-C, OOM, a gateway restart): nothing in the plugin catches it."""


def resumable(context, entry):
    """*context* with the executor's ``checkpoint``: it merges progress into the entry's ``revert_progress``."""

    def checkpoint(progress):
        entry["revert_progress"] = {**(entry.get("revert_progress") or {}), **progress}

    return dict(context, checkpoint=checkpoint)


def refused(key, rule_id=2):
    return (
        f"this LibreNMS version does not return {key} from GET rules/{rule_id}; alert-rule update and delete are "
        "refused because an exact snapshot is impossible"
    )


def entry_for(step, result=None, status="done", **extra):
    """A journal entry as the executor writes it."""
    keys = ("index", "action", "resource", "object_id", "label", "parent_id", "inverse_kind")
    entry = {key: step.get(key) for key in keys}
    entry.update(status=status, at="2026-10-28T19:00:00Z", **(result or {}), **extra)
    return entry


class Reshaping:
    """The fake behind a session that edits every rule a ``GET rules`` answer carries, as another LibreNMS version
    might shape it (the fake itself always returns the full 26.10 shape)."""

    def __init__(self, fake, edit):
        self.fake = fake
        self.edit = edit

    def request(self, method, url, **kwargs):
        response = self.fake.request(method, url, **kwargs)
        if method.upper() != "GET" or "/api/v0/rules" not in url:
            return response
        body = json.loads(response.text)
        for row in body.get("rules", []):
            self.edit(row)
        return FakeResponse(response.status_code, dict(response.headers), json.dumps(body).encode())


class Rewriting:
    """The fake behind a session that edits each ``POST rules`` body on its way, as a LibreNMS that ignores a key
    would."""

    def __init__(self, fake, edit):
        self.fake = fake
        self.edit = edit

    def request(self, method, url, data=None, **kwargs):
        if method.upper() == "POST" and url.endswith("/api/v0/rules"):
            body = json.loads(data)
            self.edit(body)
            data = json.dumps(body)
        return self.fake.request(method, url, data=data, **kwargs)


class RuleCase(PluginTestCase):
    def setUp(self):
        super().setUp()
        self.base = submodule("resources.base")
        self.res = submodule("resources.alert_rule").RESOURCE
        self.LibreNMSError = self.client_mod.LibreNMSError
        self.context = {"plan_id": "lnp-test", "settings": self.settings, "actor": None}

    def new_rule(self, **changes):
        data = {"name": "BGP session down", "severity": "critical", "builder": copy.deepcopy(BGP_DOWN),
                "alert_operation_id": 1, "devices": ["edge-rtr1.example.net"]}  # fmt: skip
        data.update(changes)
        return {key: value for key, value in data.items() if value is not ...}

    def step(self, kind, data=None, id=None, match=None, client=None):
        op = {"op": kind, "resource": "alert_rule", "id": id, "match": match, "data": data or {}}
        return self.res.plan_step(client or self.client, 0, op, self.settings)

    def apply(self, step):
        return self.res.execute(self.client, step, self.context)

    def applied(self, kind, data=None, id=None):
        step = self.step(kind, data, id=id)
        return step, entry_for(step, self.apply(step))

    def revert(self, entry, force=False, step=None):
        context = dict(self.context, step=step) if step is not None else self.context
        return self.res.revert(self.client, entry, force, context)

    def rule(self, rule_id):
        return self.fake.tables["rules"].get(rule_id)

    def named(self, name):
        """The id of the fake's rule called *name* (a re-created rule's id is LibreNMS's to choose)."""
        (rule_id,) = [rule_id for rule_id, row in self.fake.tables["rules"].items() if row["name"] == name]
        return rule_id

    def bodies(self, method):
        return [c["json"] for c in self.fake.calls if c["method"] == method and c["path"].startswith("rules")]

    def client_for(self, session):
        client = self.client_mod.LibreNMSClient(self.fake.base_url, TOKEN, session=session)
        client.retry_sleep = lambda _seconds: None
        return client


class Registry(RuleCase):
    def test_module_resource_is_registered_under_its_name(self):
        self.assertIs(submodule("resources").get_resource("alert_rule"), self.res)
        self.assertEqual(
            (self.res.ops, self.res.match_keys, self.res.natural_key),
            (("create", "update", "delete"), ("name",), "name"),
        )
        self.assertEqual(
            self.res.inverse,
            {"create": ("exact", CREATE_NOTE), "update": ("exact", ""), "delete": ("lossy", LOSSY_DELETE)},
        )


class Validation(RuleCase):
    def test_create_needs_name_severity_builder_an_operation_and_a_scope(self):
        errors = self.res.validate("create", {}, self.settings)
        for name in ("builder", "name", "severity"):
            self.assertIn(f"{name} is required to create a alert rule", errors)
        self.assertIn(NEEDS_OPERATION, errors)
        self.assertIn(NEEDS_SCOPE, errors)
        self.assertEqual(self.res.validate("create", self.new_rule(), self.settings), [])

    def test_null_operation_and_flags_are_accepted_but_not_a_null_name(self):
        data = self.new_rule(alert_operation_id=None, invert=None, max_entities=None, notes=None)
        self.assertEqual(self.res.validate("create", data, self.settings), [])
        self.assertEqual(self.res.validate("update", {"name": None}, self.settings), ["name: null is not allowed"])

    def test_keys_that_create_operations_or_run_sql_are_refused_with_their_reason(self):
        data = {"operations": [], "mute": True, "count": 1, "default_operation_step_duration": "5 m",
                "adv_query": "SELECT 1", "override_query": True, "query": "SELECT 1", "rule": "%devices.os = 'x'",
                "rule_id": 3, "colour": "red"}  # fmt: skip
        errors = self.res.validate("update", data, self.settings)
        operation = "creates a new global alert operation that no API call can delete; pass alert_operation_id instead"
        sql = "a hand-written SQL query runs as-is in the alert engine; describe the condition with builder"
        for key in ("operations", "mute", "count"):
            self.assertIn(f"{key} is not accepted: {operation}", errors)
        for key in ("adv_query", "override_query", "query"):
            self.assertIn(f"{key} is not accepted: {sql}", errors)
        self.assertIn(
            "default_operation_step_duration is not accepted: it changes the alert operation shared by every rule that "
            "uses it; change it in the LibreNMS UI",
            errors,
        )
        self.assertIn("rule_id is not accepted: the rule is chosen by the operation's id or match", errors)
        self.assertIn(
            "rule is not accepted: the legacy rule text is not supported; describe the condition with builder "
            "(query-builder JSON)",
            errors,
        )
        unknown = [error for error in errors if error.startswith("cannot update")]
        self.assertEqual(len(unknown), 1)
        self.assertTrue(unknown[0].startswith("cannot update alert rule field(s) colour; allowed: acknowledgement, "))
        self.assertEqual(len(errors), 10)

    def test_values_are_checked_by_type(self):
        data = {"severity": "Critical", "disabled": "maybe", "invert": "perhaps", "max_entities": 0,
                "alert_operation_id": 0, "groups": [True], "locations": [0], "devices": "core-sw1"}  # fmt: skip
        self.assertEqual(
            sorted(self.res.validate("update", data, self.settings)),
            sorted([
                'severity: expected one of ok, warning, critical, got "Critical"',
                'disabled: expected true or false, got "maybe"',
                'invert: expected true or false, got "perhaps"',
                "max_entities must be at least 1, or null for no limit",
                "alert_operation_id must be a positive id, or null",
                "groups: expected a list of device group ids or names",
                "locations: expected a list of location ids or names",
                "devices: expected a list of device ids or hostnames",
            ]),
        )  # fmt: skip
        self.assertEqual(
            self.res.validate("update", {"devices": [1, "-1"]}, self.settings),
            ['devices: expected a list of device ids or hostnames; use "global": true for a rule that applies to every '
             "device"],
        )  # fmt: skip

    def test_builder_must_be_a_query_builder_group(self):
        shape = 'builder must be a query-builder object with "condition" (AND or OR) and a non-empty "rules" list'
        for builder in ({"rules": []}, {"condition": "XOR", "rules": [{}]}, [], json.dumps({"condition": "AND"})):
            self.assertEqual(self.res.validate("update", {"builder": builder}, self.settings), [shape], builder)
        self.assertEqual(
            self.res.validate("update", {"builder": "{not json"}, self.settings),
            ['builder: expected a JSON object or array, got "{not json"'],
        )
        self.assertEqual(self.res.validate("update", {"builder": json.dumps(BGP_DOWN)}, self.settings), [])

    def builder_errors(self, *rules, **group):
        builder = {"condition": "AND", "rules": list(rules), **group}
        return self.res.validate("update", {"builder": builder}, self.settings)

    def test_builders_that_would_paste_sql_are_refused(self):
        value = (
            "value must be a number or a string without quotes, backslashes or backticks (LibreNMS pastes it into the "
            "rule's SQL unescaped); to compare with another field use `table.column`"
        )
        cases = (
            (leaf(value='x" OR 1=1 OR "'), value),
            (leaf(operator="contains", value="x' OR 1=1 OR '"), value),
            (leaf(value="x\\"), value),
            (leaf(value=["a", "b"]), value),
            (leaf(value="`1) OR (SELECT 1`"), "a value in backticks is pasted into the SQL; it may only name a field, "
                                              "`table.column`"),
            (leaf(operator="is_null", value="`1 OR 1=1`"), "a value in backticks is pasted into the SQL; it may only "
                                                            "name a field, `table.column`"),
            (leaf(field="devices.hostname OR 1=1"), "field must be <table>.<column> or macros.<name>"),
            (leaf(field="hostname"), "field must be <table>.<column> or macros.<name>"),
            (leaf(operator="between", value=["1 OR 1=1", 5]), "between needs a list of two numbers, which LibreNMS "
                                                               "pastes into the SQL unquoted"),
            (leaf(operator="not_between", value=[1, 2, 3]), "not_between needs a list of two numbers, which LibreNMS "
                                                             "pastes into the SQL unquoted"),
            (leaf(operator="in", value="a,b"), "LibreNMS writes in without the parentheses SQL needs, so the rule "
                                               "could not run; use one equal rule per value joined with OR"),
        )  # fmt: skip
        for rule, message in cases:
            self.assertEqual(self.builder_errors(rule), [f"builder.rules[0]: {message}"], rule)
        self.assertEqual(
            self.builder_errors("devices.status = 0"), ["builder.rules[0] must be a rule object or a group"]
        )
        (unknown,) = self.builder_errors(leaf(operator="sounds_like"))
        self.assertTrue(unknown.startswith("builder.rules[0]: operator must be one of begins_with, between, "), unknown)
        injected = json.dumps({"condition": "AND", "rules": [leaf(value='" OR 1=1 OR "')]})
        self.assertEqual(
            self.res.validate("update", {"builder": injected}, self.settings), [f"builder.rules[0]: {value}"]
        )

    def test_nested_groups_are_checked_and_not_is_refused(self):
        shape = 'must be a query-builder group with "condition" (AND or OR) and a non-empty "rules" list'
        ignored = '"not" is ignored by LibreNMS, so the rule would match the opposite; negate the operators instead'
        nested = {"condition": "AND 1=1 OR", "rules": [leaf()]}
        self.assertEqual(self.builder_errors(leaf(), nested), [f"builder.rules[1] {shape}"])
        negated = {"condition": "OR", "not": True, "rules": [leaf(), leaf(field="macros.device_down", value="1")]}
        self.assertEqual(self.builder_errors(negated), [f"builder.rules[0]: {ignored}"])
        self.assertEqual(self.builder_errors(leaf(), **{"not": True}), [f"builder: {ignored}"])

    def test_builders_the_ui_writes_are_accepted(self):
        rules = (
            leaf(),
            leaf(field="macros.device_down", type="integer", value=1),
            leaf(field="devices.sysName", value="`devices.hostname`"),
            leaf(operator="between", value=["10", 20.5]),
            leaf(operator="is_null", value=None),
            leaf(operator="regex", value="^core-[a-z]+[0-9]{2}$"),
            {"condition": "OR", "not": False, "valid": True, "rules": [leaf(operator="begins_with", value="edge-")]},
        )
        self.assertEqual(self.builder_errors(*rules, valid=True), [])

    def test_text_librenms_would_alter_is_refused(self):
        data = {"name": "<b>core</b> down", "notes": "see <a href=x>runbook</a>", "proc": "https://wiki/<x>"}
        self.assertEqual(
            self.res.validate("update", data, self.settings),
            [
                "name must not contain '<': LibreNMS strips HTML tags, and the rule is found again by name",
                "notes must not contain '<': LibreNMS strips HTML tags from them",
                "proc must not contain '<': LibreNMS strips HTML tags from it",
            ],
        )
        long = {"name": "x" * 256, "proc": "https://wiki.example.net/" + "a" * 60}
        self.assertEqual(
            self.res.validate("update", long, self.settings),
            ["name must be 1 to 255 characters", "proc must be at most 80 characters: LibreNMS cuts it to 80"],
        )
        self.assertEqual(self.res.validate("update", {"name": ""}, self.settings), ["name must be 1 to 255 characters"])

    def test_global_replaces_the_scope_and_excludes_mappings(self):
        data = self.new_rule(devices=..., **{"global": True})
        self.assertEqual(self.res.validate("create", data, self.settings), [])
        self.assertEqual(
            self.res.validate("update", {"global": "yes", "groups": ["core-switches"]}, self.settings),
            ['"global": true cannot be combined with devices, groups or locations'],
        )
        self.assertEqual(self.res.validate("update", {"global": True}, self.settings), [])

    def test_delete_takes_no_data_checks(self):
        self.assertEqual(self.res.validate("delete", {}, self.settings), [])

    def test_delete_is_gated_by_allow_delete(self):
        planner = optional("planner")
        if planner is None:
            self.skipTest("planner.py is not written yet")
        self.settings.allow_delete = False
        with self.assertRaises(planner.PlanError) as caught:
            self.plan_via_planner(planner)
        self.assertIn("allow_delete", json.dumps(caught.exception.errors))

    def plan_via_planner(self, planner):
        operations = [{"op": "delete", "resource": "alert_rule", "id": 2}]
        return planner.build_plan(self.client, operations, "test", self.settings, self.client.base_url)


class Reads(RuleCase):
    def test_state_of_the_seeded_rules(self):
        port_down = {key: value for key, value in self.rule(1)["builder"].items() if key != "valid"}
        self.assertEqual(
            self.res.state(self.client, self.res.get(self.client, 1)),
            {"id": 1, "name": "Port down", "severity": "warning", "disabled": False, "builder": port_down,
             "invert": False, "recovery": True, "acknowledgement": True, "mute": False, "override_query": False,
             "notes": "Page the NOC for core links", "proc": "https://wiki.example.net/runbooks/port-down",
             "invert_map": False, "notify_per_entity": False, "max_entities": None, "alert_operation_id": 1,
             "devices": [], "groups": [], "locations": []},
        )  # fmt: skip
        state = self.res.state(self.client, self.res.get(self.client, 2))
        self.assertEqual((state["invert"], state["recovery"], state["acknowledgement"]), (None, None, None))
        self.assertEqual((state["devices"], state["groups"], state["proc"]), ([1], [1], ""))

    def test_find_matches_the_name_case_insensitively(self):
        count, obj = self.res.find(self.client, {"name": "port DOWN"})
        self.assertEqual((count, obj["id"]), (1, 1))
        self.assertEqual(self.res.find(self.client, {"name": "Port"}), (0, None))
        self.assertIsNone(self.res.get(self.client, 99))

    def test_json_strings_and_mapping_objects_are_read(self):
        expected = self.res.state(self.client, self.res.get(self.client, 2))
        row = self.rule(2)
        self.fake.touch(
            "rules", 2, builder=json.dumps(row["builder"]), extra=json.dumps(row["extra"]), devices=["1"],
            groups=[{"id": 1}], locations=[],
        )  # fmt: skip
        self.assertEqual(self.res.state(self.client, self.res.get(self.client, 2)), expected)
        self.fake.touch("rules", 2, devices=[{"device_id": "1"}], extra=None)
        self.assertEqual(self.res.state(self.client, self.res.get(self.client, 2)), expected)

    def test_override_query_is_on_only_for_true_or_on(self):
        for flag, on in ((True, True), ("on", True), ("off", False), (1, False), (None, False)):
            self.fake.touch("rules", 2, extra={"options": {"override_query": flag}}, query=OVERRIDE_SQL)
            state = self.res.state(self.client, self.res.get(self.client, 2))
            self.assertIs(state["override_query"], on, flag)
            self.assertEqual(state.get("query"), OVERRIDE_SQL if on else None, flag)

    def test_a_rule_without_every_field_is_refused(self):
        def drop_devices(row):
            del row["devices"]

        client = self.client_for(Reshaping(self.fake, drop_devices))
        with self.assertRaisesRegex(self.base.StepError, f"^{refused('devices')}$"):
            self.res.get(client, 2)
        for kind, data in (("update", {"notes": "x"}), ("delete", None)):
            with self.assertRaisesRegex(self.base.StepError, "^this LibreNMS version does not return devices"):
                self.step(kind, data, id=2, client=client)

    def test_a_field_in_an_unknown_shape_is_refused(self):
        edits = {
            "groups": lambda row: row.update(groups="1,2"),
            "builder": lambda row: row.update(builder="SELECT 1"),
            "extra": lambda row: row.update(extra={"options": "on"}),
            "query": lambda row: row.update(extra={"options": {"override_query": "on"}}, query=None),
        }
        for key, edit in edits.items():
            with self.assertRaisesRegex(self.base.StepError, f"^{refused(key)}$", msg=key):
                self.res.get(self.client_for(Reshaping(self.fake, edit)), 2)


class Planning(RuleCase):
    def test_create_step(self):
        step = self.step("create", self.new_rule())
        self.assertEqual(
            {key: step[key] for key in ("action", "object_id", "label", "requested_op", "resolved_by", "parent_id")},
            {"action": "create", "object_id": None, "label": "BGP session down", "requested_op": "create",
             "resolved_by": None, "parent_id": None},
        )  # fmt: skip
        self.assertEqual(
            step["data"],
            {"name": "BGP session down", "severity": "critical", "builder": BGP_DOWN_SENT, "alert_operation_id": 1,
             "devices": [2], "groups": [], "locations": []},
        )  # fmt: skip
        self.assertEqual(step["exists_check"], {"name": "BGP session down"})
        self.assertEqual((step["inverse_kind"], step["inverse_note"], step["notes"]), ("exact", CREATE_NOTE, []))
        lines = self.res.describe(step)
        self.assertEqual(lines[1], f"builder: {json.dumps(BGP_DOWN_SENT, sort_keys=True)}")
        self.assertNotIn("builder=", lines[0])
        self.assertEqual(lines[2], 'precondition: no alert rule matches {"name": "BGP session down"}')
        json.dumps(step)  # plans are stored as JSON

    def test_mappings_are_resolved_from_names_and_ids(self):
        data = self.new_rule(devices=[1, "edge-rtr1.example.net", "1"], groups=["CORE-switches", 2],
                             locations=["nyc-2", "3"])  # fmt: skip
        step = self.step("create", data)
        self.assertEqual((step["data"]["devices"], step["data"]["groups"], step["data"]["locations"]),
                         ([1, 2], [1, 2], [2, 3]))  # fmt: skip

    def test_mappings_that_do_not_exist_are_refused(self):
        cases = (
            ({"devices": ["nosuch.example.net"]}, "no LibreNMS device has hostname 'nosuch.example.net'"),
            ({"devices": [99]}, "device #99 does not exist"),
            ({"groups": ["nope"]}, "no device group is named 'nope'"),
            ({"locations": [9]}, "location #9 does not exist"),
        )
        for data, message in cases:
            with self.assertRaisesRegex(self.base.StepError, f"^{message}$"):
                self.step("create", self.new_rule(**data))
        self.fake.tables["device_groups"].clear()  # the list answers 404 when there is none
        with self.assertRaisesRegex(self.base.StepError, "^device group #1 does not exist$"):
            self.step("update", {"groups": [1]}, id=2)

    def test_a_hostname_the_token_cannot_see_is_explained(self):
        self.fake.fail_on("GET", "devices/hidden.example.net", 403, {"message": "This action is unauthorized."})
        with self.assertRaisesRegex(self.base.StepError, "^LibreNMS answered 403 for hostname hidden.example.net: it "):
            self.step("create", self.new_rule(devices=["hidden.example.net"]))

    def test_a_device_reference_with_a_slash_is_never_looked_up(self):
        discovered = self.fake.tables["devices"][2]["last_discovered"]
        with self.assertRaises(self.base.StepError) as caught:  # encoded, it would reach the rediscovery route
            self.step("create", self.new_rule(devices=["2/discover"]))
        self.assertEqual(str(caught.exception), "no LibreNMS device has hostname '2/discover'")
        self.assertEqual([c["path"] for c in self.fake.calls if c["path"].startswith("devices")], [])
        self.assertEqual(self.fake.tables["devices"][2]["last_discovered"], discovered)

    def test_device_lookups_leave_no_credentials_in_the_step(self):
        hosts = ["core-sw1.example.net", "edge-rtr1.example.net", "access-sw2.example.net", "lab-fw1.example.net"]
        text = json.dumps(self.step("create", self.new_rule(devices=hosts)))
        self.assertEqual([secret for secret in SECRETS if secret in text], [])

    def test_global_and_group_scoped_creates(self):
        step = self.step("create", self.new_rule(devices=..., **{"global": True}))
        self.assertEqual([step["data"][key] for key in ("devices", "groups", "locations")], [[], [], []])
        self.assertNotIn("global", step["data"])
        self.assertEqual(step["notes"], [GLOBAL_NOTE])
        step = self.step("create", self.new_rule(devices=..., groups=["core-switches"]))
        self.assertEqual([step["data"][key] for key in ("devices", "groups", "locations")], [[], [1], []])
        self.assertEqual(step["notes"], [])

    def test_notes_on_the_alert_operation(self):
        step = self.step("create", self.new_rule(alert_operation_id=None))
        self.assertEqual(step["notes"], ["alert_operation_id is null: LibreNMS sends no notifications for this rule"])
        step = self.step("create", self.new_rule(alert_operation_id=7))
        self.assertEqual(
            step["notes"],
            ["alert operation #7 is not used by any alert rule; LibreNMS does not check that it exists, so make sure "
             "it is the operation you mean"],
        )  # fmt: skip
        self.assertEqual(self.step("update", {"alert_operation_id": 1, "notes": "x"}, id=2)["notes"], [])

    def test_create_with_match_is_an_upsert(self):
        same = {"name": "High CPU", "severity": "critical", "builder": self.rule(2)["builder"],
                "alert_operation_id": 1, "devices": ["core-sw1.example.net"], "groups": ["core-switches"]}  # fmt: skip
        step = self.step("create", same, match={"name": "high cpu"})
        self.assertEqual(
            (step["action"], step["object_id"], step["reason"]), ("noop", 2, "already matches desired state")
        )
        self.assertFalse({"snapshot_body", "upsert", "inverse_kind", "precondition"} & set(step))
        step = self.step("create", dict(same, severity="warning"), match={"name": "High CPU"})
        self.assertEqual((step["action"], step["upsert"], step["resolved_by"]), ("update", True, "match"))
        self.assertEqual(step["changes"], {"severity": {"from": "critical", "to": "warning"}})
        self.assertEqual((step["payload"]["rule_id"], step["payload"]["groups"]), (2, [1]))

    def test_update_sends_the_whole_rule(self):
        step = self.step("update", {"notes": "x"}, id=2)
        self.assertEqual(step["changes"], {"notes": {"from": "", "to": "x"}})
        row = self.rule(2)
        snapshot = {"name": "High CPU", "severity": "critical", "disabled": 0, "builder": row["builder"], "notes": "",
                    "proc": "", "invert_map": False, "notify_per_entity": True, "max_entities": None,
                    "alert_operation_id": 1, "devices": [1], "groups": [1], "locations": []}  # fmt: skip
        self.assertEqual(step["snapshot_body"], snapshot)
        self.assertEqual(step["payload"], {"rule_id": 2, **snapshot, "notes": "x"})
        self.assertEqual(step["precondition"]["state"], self.res.state(self.client, self.res.get(self.client, 2)))
        self.assertEqual((step["inverse_kind"], step["notes"]), ("exact", []))

    def test_extra_flags_are_tri_state(self):
        step = self.step("update", {"recovery": False}, id=2)
        self.assertEqual(step["changes"], {"recovery": {"from": None, "to": False}})
        self.assertEqual(self.res.describe(step), ["recovery: unset (engine default) -> false"])
        step = self.step("update", {"invert": None, "recovery": "1"}, id=1)
        self.assertEqual(step["changes"], {"invert": {"from": False, "to": None}})
        self.assertEqual(self.res.describe(step), ["invert: false -> unset (engine default)"])
        self.assertNotIn("invert", step["payload"])
        self.assertEqual((step["payload"]["recovery"], step["payload"]["acknowledgement"]), (True, True))

    def test_a_builder_change_is_shown_in_full(self):
        step = self.step("update", {"builder": BGP_DOWN}, id=2)
        (line,) = self.res.describe(step)
        self.assertTrue(line.endswith(f"-> {json.dumps(BGP_DOWN_SENT, sort_keys=True)}"), line)

    def test_removing_every_mapping_needs_global(self):
        with self.assertRaisesRegex(
            self.base.StepError,
            r"^this change removes every device, group and location from rule #2, which makes it apply to every "
            r'device; pass "global": true to confirm$',
        ):
            self.step("update", {"devices": [], "groups": []}, id=2)
        step = self.step("update", {"global": True}, id=2)
        self.assertEqual(step["changes"], {"devices": {"from": [1], "to": []}, "groups": {"from": [1], "to": []}})
        self.assertEqual(step["notes"], [GLOBAL_NOTE])
        self.assertEqual(self.step("update", {"global": True}, id=1)["action"], "noop")

    def test_a_rename_to_a_name_another_rule_has_is_refused(self):
        for name in ("Port down", "PORT DOWN"):
            with self.assertRaisesRegex(
                self.base.StepError, f"^alert rule #1 is already named '{name}'; alert rule names are unique$"
            ):
                self.step("update", {"name": name}, id=2)
        step = self.step("update", {"name": "high cpu"}, id=2)  # its own name in another case is free
        self.assertEqual(step["changes"], {"name": {"from": "High CPU", "to": "high cpu"}})
        self.assertIsNone(self.res.check(self.client, step))

    def test_one_mapping_list_changes_and_the_others_stay(self):
        step = self.step("update", {"locations": ["SFO-1"]}, id=2)
        self.assertEqual(step["changes"], {"locations": {"from": [], "to": [1]}})
        self.assertEqual([step["payload"][key] for key in ("devices", "groups", "locations")], [[1], [1], [1]])

    def test_a_rule_with_hand_written_sql_keeps_it(self):
        self.fake.touch("rules", 2, extra={"options": {"override_query": "on"}}, query=OVERRIDE_SQL)
        step = self.step("update", {"notes": "x"}, id=2)
        self.assertEqual((step["payload"]["override_query"], step["payload"]["adv_query"]), (True, OVERRIDE_SQL))
        self.assertEqual(step["notes"], [])
        step = self.step("update", {"builder": BGP_DOWN}, id=2)
        self.assertEqual(
            step["notes"],
            ["this rule runs a hand-written SQL query (override_query); a new builder does not change what it matches"],
        )

    def test_extra_keys_librenms_drops_make_the_update_lossy(self):
        extra = {**self.rule(1)["extra"], "delay": 300, "options": {"override_query": False, "legacy": 1}}
        self.fake.touch("rules", 1, extra=extra)
        note = (
            "rule #1 has extra keys delay, options.legacy that LibreNMS drops on every API write; neither this step "
            "nor its rollback keeps them"
        )
        step = self.step("update", {"notes": "x"}, id=1)
        self.assertEqual(step["extra_unknown_keys"], ["delay", "options.legacy"])
        self.assertEqual(step["notes"], [note])
        self.assertEqual(
            (step["inverse_kind"], step["inverse_note"]),
            ("lossy", "restores every field except the extra keys delay, options.legacy, which LibreNMS drops"),
        )
        step = self.step("delete", id=1)
        self.assertEqual((step["notes"], step["inverse_kind"], step["inverse_note"]), ([note], "lossy", LOSSY_DELETE))
        noop = self.step("update", {"notes": "Page the NOC for core links"}, id=1)
        self.assertEqual((noop["action"], noop.get("extra_unknown_keys"), noop["notes"]), ("noop", None, []))

    def test_mute_off_is_dropped_without_a_note(self):
        self.assertIs(self.rule(1)["extra"]["mute"], False)  # the UI writes mute on every save
        for step in (self.step("update", {"notes": "x"}, id=1), self.step("delete", id=1)):
            self.assertEqual((step.get("extra_unknown_keys"), step["notes"]), (None, []), step["action"])
        self.assertEqual(self.step("update", {"notes": "x"}, id=1)["inverse_kind"], "exact")

    def test_a_rule_muted_in_the_ui_is_not_written(self):
        muted = (
            "rule #1 is muted in the LibreNMS UI (extra.mute); every API write unmutes it and notifications resume, "
            "and rollback cannot re-mute it; unmute or edit it in the UI"
        )
        for value in (True, 1, "1", "false"):  # what PHP's ! empty() takes as set
            self.fake.touch("rules", 1, extra={**self.rule(1)["extra"], "mute": value})
            for kind, data in (("update", {"severity": "critical"}), ("delete", None)):
                with self.subTest(value=value, kind=kind), self.assertRaises(self.base.StepError) as caught:
                    self.step(kind, data, id=1)
                self.assertEqual(str(caught.exception), muted)
        with self.assertRaises(self.base.StepError) as caught:  # an upsert that finds it
            self.step("create", {"name": "Port down", "severity": "critical"}, match={"name": "Port down"})
        self.assertEqual(str(caught.exception), muted)
        self.assertEqual(self.step("update", {"severity": "warning"}, id=1)["action"], "noop")  # nothing is written
        self.fake.touch("rules", 1, extra={**self.rule(1)["extra"], "mute": "0"})
        self.assertEqual(self.step("update", {"severity": "critical"}, id=1)["action"], "update")
        self.assertEqual(self.fake.writes(), [])

    def test_delete_step_keeps_the_rule_body(self):
        step = self.step("delete", id=2)
        self.assertEqual(step["snapshot"], self.step("update", {"notes": "x"}, id=2)["snapshot_body"])
        self.assertNotIn("snapshot_body", step)
        self.assertEqual(step["precondition"]["state"]["devices"], [1])
        self.assertEqual((step["inverse_kind"], step["inverse_note"]), ("lossy", LOSSY_DELETE))
        self.assertEqual(self.res.describe(step), ["the alert rule is deleted; its configuration is kept in the plan"])


class Check(RuleCase):
    def test_untouched_steps_may_run(self):
        for step in (self.step("create", self.new_rule()), self.step("update", {"notes": "x"}, id=2),
                     self.step("delete", id=2)):  # fmt: skip
            self.assertIsNone(self.res.check(self.client, step), step["action"])

    def test_an_outside_edit_is_a_conflict(self):
        step = self.step("update", {"severity": "warning"}, id=2)
        self.fake.touch("rules", 2, notes="edited in the UI", devices=[1, 3])
        self.assertEqual(
            self.res.check(self.client, step),
            'alert rule #2 changed since planning (devices: [1] -> [1, 3], notes: "" -> "edited in the UI")',
        )

    def test_a_deleted_rule_is_a_conflict(self):
        step = self.step("delete", id=2)
        del self.fake.tables["rules"][2]
        self.assertEqual(self.res.check(self.client, step), "alert rule #2 no longer exists")

    def test_a_create_conflicts_once_the_name_is_taken(self):
        step = self.step("create", self.new_rule())
        self.fake.seed("rules", {"name": "bgp SESSION down", "severity": "ok", "builder": BGP_DOWN})
        self.assertEqual(
            self.res.check(self.client, step), '1 alert rule(s) now match {"name": "BGP session down"}; expected none'
        )

    def test_a_rule_muted_after_planning_is_a_conflict(self):
        step = self.step("update", {"severity": "critical"}, id=1)
        self.fake.touch("rules", 1, extra={**self.rule(1)["extra"], "mute": True})
        self.assertEqual(
            self.res.check(self.client, step), "alert rule #1 changed since planning (mute: false -> true)"
        )

    def test_a_rename_conflicts_once_the_name_is_taken(self):
        step = self.step("update", {"name": "CPU hot"}, id=2)
        self.fake.seed("rules", {"name": "cpu HOT", "severity": "ok", "builder": BGP_DOWN})
        self.assertEqual(
            self.res.check(self.client, step), "alert rule #3 is already named 'CPU hot'; alert rule names are unique"
        )


class Execute(RuleCase):
    def test_create_posts_the_rule_and_finds_its_id(self):
        step = self.step("create", self.new_rule(proc=None, invert=False))
        result = self.apply(step)
        self.assertEqual(
            self.bodies("POST"),
            [{"name": "BGP session down", "severity": "critical", "builder": BGP_DOWN_SENT, "alert_operation_id": 1,
              "devices": [2], "groups": [], "locations": [], "proc": "", "invert": False}],
        )  # fmt: skip
        self.assertEqual(result["object_id"], 3)
        self.assertEqual(result["inverse"], {"action": "delete", "object_id": 3})
        self.assertEqual(result["after_state"], self.res.state(self.client, self.res.get(self.client, 3)))
        self.assertEqual((self.rule(3)["devices"], self.rule(3)["extra"]["invert"]), ([2], False))

    def test_a_create_without_devices_sends_minus_one(self):
        self.apply(self.step("create", self.new_rule(devices=..., **{"global": True})))
        self.apply(self.step("create", self.new_rule(name="Core BGP", devices=..., groups=["core-switches"])))
        self.assertEqual([body["devices"] for body in self.bodies("POST")], [[-1], [-1]])
        self.assertEqual((self.rule(3)["devices"], self.rule(3)["groups"]), ([], []))
        self.assertEqual((self.rule(4)["devices"], self.rule(4)["groups"]), ([], [1]))

    def test_an_update_keeps_everything_it_does_not_change(self):
        self.fake.touch("rules", 1, disabled=1)
        step = self.step("update", {"notes": "x"}, id=1)
        result = self.apply(step)
        self.assertEqual(self.bodies("PUT"), [step["payload"]])
        row = self.rule(1)
        self.assertEqual(
            (row["disabled"], row["notes"], row["proc"]), (1, "x", "https://wiki.example.net/runbooks/port-down")
        )
        self.assertEqual(row["extra"], {"options": {"override_query": False}, "invert": False, "recovery": True,
                                        "acknowledgement": True})  # fmt: skip
        self.assertEqual(
            result["inverse"], {"action": "update", "object_id": 1, "data": {"notes": "Page the NOC for core links"}}
        )
        self.apply(self.step("update", {"severity": "warning"}, id=2))
        self.assertEqual((self.rule(2)["devices"], self.rule(2)["groups"]), ([1], [1]))

    def test_a_write_that_did_not_stick_is_a_partial_write(self):
        step = self.step("update", {"notes": "x"}, id=2)
        self.fake.fail_on("PUT", "rules", 200, {"status": "ok"})
        with self.assertRaises(self.base.PartialWrite) as caught:
            self.apply(step)
        self.assertEqual(str(caught.exception), 'LibreNMS accepted the write but notes is "", expected "x"')
        self.assertEqual(caught.exception.entry["inverse"], {"action": "update", "object_id": 2, "data": {"notes": ""}})

    def test_delete(self):
        step = self.step("delete", id=2)
        result = self.apply(step)
        self.assertIsNone(self.rule(2))
        self.assertEqual([c["path"] for c in self.fake.writes()], ["rules/2"])
        self.assertEqual(result, {"object_id": 2, "inverse": {"action": "create", "snapshot": step["snapshot"]},
                                  "after_state": None, "notes": []})  # fmt: skip


class PartialWrites(RuleCase):
    def test_a_server_error_after_the_put_is_settled_and_rolled_back(self):
        step = self.step("update", {"severity": "warning"}, id=2)
        self.fake.fail_on("PUT", "rules", 500, commit=True, times=1)
        with self.assertRaises(self.base.PartialWrite) as caught:
            self.apply(step)
        self.assertTrue(str(caught.exception).endswith("(LibreNMS applied part of the step; rollback reverts it)"))
        entry = entry_for(step, caught.exception.entry, status="failed", wrote=True)
        self.assertEqual(entry["after_state"]["severity"], "warning")
        self.assertEqual(self.revert(entry), ("reverted", {"restored_fields": ["severity"]}))
        self.assertEqual(self.rule(2)["severity"], "critical")

    def test_a_server_error_before_the_put_is_the_original_error(self):
        step = self.step("update", {"severity": "warning"}, id=2)
        self.fake.fail_on("PUT", "rules", 500)
        with self.assertRaises(self.LibreNMSError) as caught:
            self.apply(step)
        self.assertEqual((caught.exception.kind, self.rule(2)["severity"]), ("server", "critical"))

    def test_a_refused_put_propagates_unchanged(self):
        step = self.step("update", {"severity": "warning"}, id=2)
        self.fake.fail_on("PUT", "rules", 400, {"status": "error", "message": "Missing the severity"})
        with self.assertRaises(self.LibreNMSError) as caught:
            self.apply(step)
        self.assertEqual((caught.exception.kind, caught.exception.status), ("api", 400))

    def test_a_rename_librenms_refuses_is_a_plain_failure(self):
        step = self.step("update", {"name": "CPU hot", "severity": "warning"}, id=2)
        self.fake.seed("rules", {"name": "CPU hot", "severity": "ok", "builder": BGP_DOWN})
        with self.assertRaisesRegex(
            self.base.StepError, "^LibreNMS refused the write: another alert rule is named 'CPU hot'$"
        ):
            self.apply(step)  # LibreNMS's own answer is 500 "Update failed : Invalid rule id"
        self.assertEqual((self.rule(2)["name"], self.rule(2)["severity"]), ("High CPU", "critical"))

    def test_an_update_of_a_rule_deleted_after_the_check_writes_nothing(self):
        step = self.step("update", {"severity": "warning"}, id=2)
        del self.fake.tables["rules"][2]
        with self.assertRaisesRegex(self.base.StepError, "^alert rule #2 no longer exists$"):
            self.apply(step)
        self.assertEqual(self.fake.writes(), [])

    def test_a_post_that_times_out_after_creating(self):
        step = self.step("create", self.new_rule())
        self.fake.fail_on("POST", "rules", exc=TimeoutError("read timed out"), commit=True)
        with self.assertRaises(self.base.PartialWrite) as caught, self.assertLogs(CLIENT_LOG, "WARNING"):
            self.apply(step)
        entry = caught.exception.entry
        self.assertEqual((entry["object_id"], entry["inverse"]), (3, {"action": "delete", "object_id": 3}))
        self.assertEqual(
            self.revert(entry_for(step, entry, status="failed", wrote=True)), ("reverted", {"object_id": 3})
        )
        self.assertIsNone(self.rule(3))

    def test_a_post_that_fails_before_creating(self):
        step = self.step("create", self.new_rule())
        self.fake.fail_on("POST", "rules", exc=ConnectionRefusedError("connection refused"))
        with self.assertRaises(self.client_mod.TransportError), self.assertLogs(CLIENT_LOG, "WARNING"):
            self.apply(step)
        self.assertEqual(sorted(self.fake.tables["rules"]), [1, 2])

    def test_a_rule_that_cannot_be_found_after_the_post_is_irreversible(self):
        step = self.step("create", self.new_rule())
        self.fake.fail_on("POST", "rules", 200, {"status": "ok"})
        with self.assertRaises(self.base.PartialWrite) as caught:
            self.apply(step)
        self.assertEqual(
            str(caught.exception),
            "LibreNMS accepted the new alert rule but no single rule named 'BGP session down' can be found",
        )
        entry = caught.exception.entry
        self.assertEqual(
            entry,
            {"object_id": None, "inverse": {"action": "delete", "object_id": None, "located": False},
             "after_state": None, "notes": [UNLOCATED]},
        )  # fmt: skip
        reverted = self.revert(entry_for(step, entry, status="failed", wrote=True), step=step)
        self.assertEqual(reverted, ("irreversible", {"note": UNLOCATED}))

    def test_a_name_taken_after_the_check_fails_without_touching_the_other_rule(self):
        step = self.step("create", self.new_rule())
        other = self.fake.seed("rules", {"name": "BGP Session Down", "severity": "ok", "builder": BGP_DOWN})
        with self.assertRaisesRegex(
            self.base.StepError, "^LibreNMS refused the rule: an alert rule named 'BGP session down' already exists$"
        ):
            self.apply(step)
        self.assertEqual((sorted(self.fake.tables["rules"]), self.rule(3)), ([1, 2, 3], other))

    def test_a_lookup_that_fails_after_the_post_leaves_the_outcome_to_rollback(self):
        step = self.step("create", self.new_rule())
        self.fake.fail_on("GET", "rules", exc=ConnectionResetError("connection reset"))
        with self.assertRaises(self.base.PartialWrite) as caught, self.assertLogs(CLIENT_LOG, "WARNING"):
            self.apply(step)
        entry = caught.exception.entry
        self.assertEqual(
            entry["inverse"], {"action": "delete", "object_id": None, "find": {"name": "BGP session down"}}
        )
        self.assertTrue(
            entry["notes"][0].startswith("outcome unknown: re-reading the alert rule after the failed write")
        )
        self.assertEqual(self.rule(3)["name"], "BGP session down")
        self.fake.failures.clear()
        self.assertEqual(
            self.revert(entry_for(step, entry, status="failed", wrote=True)), ("reverted", {"object_id": 3})
        )
        self.assertIsNone(self.rule(3))

    def test_a_delete_that_fails_after_deleting_is_re_created_by_rollback(self):
        step = self.step("delete", id=2)
        self.fake.fail_on("DELETE", "rules/2", 500, commit=True)
        with self.assertRaises(self.base.PartialWrite) as caught:
            self.apply(step)
        entry = entry_for(step, caught.exception.entry, status="failed", wrote=True)
        self.assertEqual(entry["inverse"], {"action": "create", "snapshot": step["snapshot"]})
        status, details = self.revert(entry)
        self.assertEqual((status, details["new_object_id"]), ("reverted", self.named("High CPU")))
        row = self.rule(details["new_object_id"])
        self.assertEqual((row["devices"], row["groups"]), ([1], [1]))


class Revert(RuleCase):
    def test_a_create_is_undone_by_deleting_the_rule(self):
        step, entry = self.applied("create", self.new_rule())
        self.assertEqual(self.revert(entry), ("reverted", {"object_id": 3}))
        self.assertIsNone(self.rule(3))
        self.assertEqual(self.revert(entry), ("reverted", {"note": "object already gone"}))

    def test_a_create_edited_after_apply_needs_force(self):
        step, entry = self.applied("create", self.new_rule())
        self.fake.touch("rules", 3, severity="warning")
        self.assertEqual(
            self.revert(entry),
            ("conflict", {"error": 'alert rule #3 was modified after apply (severity: "critical" -> "warning"); use '
                                   "force to delete anyway"}),
        )  # fmt: skip
        self.assertEqual(self.revert(entry, force=True), ("reverted", {"object_id": 3}))

    def test_an_update_is_undone_field_by_field_with_a_whole_rule_write(self):
        data = {"severity": "warning", "devices": [1, 3], "recovery": False, "notes": "x"}
        step, entry = self.applied("update", data, id=2)
        before = len(self.bodies("PUT"))
        status, details = self.revert(entry)
        self.assertEqual(
            (status, details), ("reverted", {"restored_fields": ["devices", "notes", "recovery", "severity"]})
        )
        body = self.bodies("PUT")[before]
        self.assertEqual((body["rule_id"], body["groups"], body["devices"], "recovery" in body), (2, [1], [1], False))
        row = self.rule(2)
        self.assertEqual(
            (row["severity"], row["notes"], row["extra"]), ("critical", "", {"options": {"override_query": False}})
        )
        self.assertEqual(self.res.state(self.client, self.res.get(self.client, 2)), step["precondition"]["state"])

    def test_an_update_edited_after_apply_needs_force_and_keeps_the_other_edit(self):
        step, entry = self.applied("update", {"severity": "warning"}, id=2)
        self.fake.touch("rules", 2, notes="edited by hand")
        self.assertEqual(
            self.revert(entry),
            ("conflict", {"error": 'alert rule #2 was modified after apply (notes: "" -> "edited by hand"); use force '
                                   "to overwrite"}),
        )  # fmt: skip
        self.assertEqual(self.revert(entry, force=True), ("reverted", {"restored_fields": ["severity"]}))
        self.assertEqual((self.rule(2)["severity"], self.rule(2)["notes"]), ("critical", "edited by hand"))

    def test_a_rename_is_not_undone_onto_a_name_taken_since(self):
        step, entry = self.applied("update", {"name": "CPU hot"}, id=2)
        self.fake.seed("rules", {"name": "High CPU", "severity": "ok", "builder": BGP_DOWN})
        self.assertEqual(
            self.revert(entry),
            ("failed", {"error": "LibreNMS refused the write: another alert rule is named 'High CPU'"}),
        )
        self.assertEqual(self.rule(2)["name"], "CPU hot")

    def test_a_delete_is_undone_by_re_creating_the_rule(self):
        step, entry = self.applied("delete", id=2)
        status, details = self.revert(entry)
        new_id = self.named("High CPU")
        self.assertEqual(
            (status, details),
            ("reverted", {"new_object_id": new_id, "note": RECREATED}),
        )
        (body,) = self.bodies("POST")
        self.assertEqual(body, step["snapshot"])
        state = self.res.state(self.client, self.res.get(self.client, new_id))
        self.assertEqual(state, {**step["precondition"]["state"], "id": new_id})

    def test_a_delete_rollback_that_died_after_its_post_adopts_that_rule(self):
        step, entry = self.applied("delete", id=2)
        context = resumable(self.context, entry)
        self.fake.fail_on("POST", "rules", exc=Died(), commit=True, times=1)
        with self.assertRaises(Died):
            self.res.revert(self.client, entry, False, context)
        self.assertEqual((entry["revert_progress"], self.named("High CPU")), ({"recreating": True}, 3))
        self.fake.calls.clear()
        self.assertEqual(
            self.res.revert(self.client, entry, False, context),
            ("reverted", {"new_object_id": 3, "note": "re-created with a new id by an earlier rollback; its alert "
                                                      "history and template mappings are not restored"}),
        )  # fmt: skip
        self.assertEqual(self.bodies("POST"), [])
        self.assertEqual(sorted(self.fake.tables["rules"]), [1, 3])

    def test_a_deleted_global_rule_comes_back_global_with_its_flags(self):
        step, entry = self.applied("delete", id=1)
        self.assertEqual(self.revert(entry)[0], "reverted")
        (body,) = self.bodies("POST")
        self.assertEqual(
            (body["devices"], body["invert"], body["recovery"], body["acknowledgement"]), ([-1], False, True, True)
        )
        new_id = self.named("Port down")
        self.assertEqual(
            self.res.state(self.client, self.res.get(self.client, new_id)),
            {**step["precondition"]["state"], "id": new_id},
        )

    def test_a_deleted_rule_with_hand_written_sql_comes_back_with_it(self):
        self.fake.touch("rules", 2, extra={"options": {"override_query": "on"}}, query=OVERRIDE_SQL)
        step, entry = self.applied("delete", id=2)
        self.assertEqual(self.revert(entry)[0], "reverted")
        (body,) = self.bodies("POST")
        self.assertEqual((body["override_query"], body["adv_query"]), (True, OVERRIDE_SQL))
        self.assertEqual(self.rule(self.named("High CPU"))["query"], OVERRIDE_SQL)

    def test_a_re_created_rule_that_differs_is_a_failure(self):
        step, entry = self.applied("delete", id=2)
        client = self.client_for(Rewriting(self.fake, lambda body: body.update(groups=[])))
        status, details = self.res.revert(client, entry, False, self.context)
        error = f"LibreNMS re-created alert rule #{self.named('High CPU')} but groups is [], expected [1]"
        self.assertEqual((status, details), ("failed", {"error": error}))

    def test_a_delete_is_not_undone_over_a_rule_of_the_same_name(self):
        step, entry = self.applied("delete", id=2)
        self.fake.seed("rules", {"name": "high cpu", "severity": "ok", "builder": BGP_DOWN})
        self.assertEqual(
            self.revert(entry),
            ("conflict", {"error": 'a alert rule matching {"name": "High CPU"} exists again; remove or rename it '
                                   "before rolling back"}),
        )  # fmt: skip

    def test_a_create_whose_outcome_is_unknown(self):
        step = self.step("create", self.new_rule())
        crashed = entry_for(step, status="unknown", wrote=True)
        self.assertEqual(self.revert(crashed, step=step), ("reverted", {"note": "nothing was written"}))
        self.apply(step)
        self.assertEqual(self.revert(crashed, step=step), ("reverted", {"object_id": 3}))
        self.assertIsNone(self.rule(3))


if __name__ == "__main__":
    unittest.main()
