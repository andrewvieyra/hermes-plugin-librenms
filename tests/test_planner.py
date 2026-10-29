"""The planner: operation shape checks in the contract's order, the operator's gates, the resource handoff, the
duplicate-target rule, the plan and step shapes, warnings lifted from step notes, and the rendered plan.

The resources are exercised through a stub (``Widget``) installed with ``resources.register()``. Its objects live in
:class:`WidgetBackend`, a session in front of the fake LibreNMS that serves an in-memory ``widgets`` API, so the
plugin's real client records every call and raises its real errors. ``test_executor`` reuses this fixture."""

import json
import re
import unittest
from datetime import datetime, timezone
from typing import Any, Dict, List
from urllib.parse import unquote

from .base import PluginTestCase
from .fake_librenms import TOKEN, FakeResponse
from .helpers import submodule

resources = submodule("resources")
diff = submodule("diff")
timefmt = submodule("timefmt")
Field = resources.Field

SETTINGS_KEY = "plugins.entries.librenms.settings"


def _reply(status: int, payload: Dict[str, Any]) -> FakeResponse:
    return FakeResponse(status, {"Content-Type": "application/json"}, json.dumps(payload).encode())


class WidgetBackend:
    """The test client's session: ``widgets`` paths are answered from ``rows``, every other path by the fake
    LibreNMS (system, eventlog). A widget write appends an eventlog row for the widget's device (or, with
    ``devices``, for the widget itself), as LibreNMS's observers do."""

    def __init__(self, fake: Any):
        self.fake = fake
        self.prefix = f"{fake.base_url}/api/v0/"
        self.rows: Dict[int, Dict[str, Any]] = {}
        self.next_id = 1
        self.failures: List[Dict[str, Any]] = []
        self.ignored: set = set()  # fields a PATCH accepts and does not store
        self.devices = False  # widgets stand for devices: their eventlog rows carry their own id
        self.on_write = None  # callable(method, path), run before a widget write is answered
        self.calls: List[Dict[str, Any]] = []
        self.logged = 0

    def add(self, **row: Any) -> Dict[str, Any]:
        row = {"name": "", "color": "red", "size": 0, "device_id": None, "notes": "", "overwrite_ip": "", **row}
        row["id"] = row.get("id") or self.next_id
        self.next_id = max(self.next_id, row["id"]) + 1
        self.rows[row["id"]] = row
        return row

    def fail(self, method: str, path_regex: str, status: int = 500, *, commit=False, exc=None, times=1) -> None:
        """Answer *method* on a matching widget path with *status* (or raise *exc*), after the change took effect
        when *commit*, at most *times* times."""
        self.failures.append(
            {"method": method, "regex": re.compile(path_regex), "status": status, "commit": commit, "exc": exc,
             "times": times}
        )  # fmt: skip

    def writes(self) -> List[str]:
        return [f"{c['method']} {c['path']}" for c in self.calls if c["method"] != "GET"]

    def request(self, method: str, url: str, params=None, data=None, headers=None, **kwargs: Any) -> FakeResponse:
        rest = url[len(self.prefix) :] if url.startswith(self.prefix) else ""
        if rest.split("/")[0] != "widgets":
            return self.fake.request(method, url, params=params, data=data, headers=headers, **kwargs)
        method, path = method.upper(), unquote(rest)
        call = {"method": method, "path": path, "params": dict(params or {}), "status": None}
        self.calls.append(call)
        if method != "GET" and self.on_write is not None:
            self.on_write(method, path)
        response = self._forced(method, path, commit=False)
        if response is None:
            response = self._answer(method, path, dict(params or {}), json.loads(data) if data else {})
            response = self._forced(method, path, commit=True) or response
        call["status"] = response.status_code
        return response

    def _forced(self, method: str, path: str, *, commit: bool) -> FakeResponse | None:
        for rule in self.failures:
            if rule["commit"] != commit or not rule["times"] or rule["method"] not in ("*", method):
                continue
            if rule["regex"].fullmatch(path):
                rule["times"] -= 1
                if rule["exc"] is not None:
                    raise rule["exc"]
                return _reply(rule["status"], {"status": "error", "message": "forced failure"})
        return None

    def _answer(self, method: str, path: str, params: Dict[str, Any], body: Dict[str, Any]) -> FakeResponse:
        parts = path.split("/")
        if parts == ["widgets"] and method == "GET":
            rows = [r for r in self.rows.values() if all(str(r.get(k)) == str(v) for k, v in params.items())]
            return _reply(200, {"status": "ok", "widgets": rows, "count": len(rows)})
        if parts == ["widgets"] and method == "POST":
            row = self.add(**{k: v for k, v in body.items() if k != "id"})
            self._log(row, "created")
            return _reply(201, {"status": "ok", "id": row["id"], "message": f"Widget {row['id']} added"})
        row = self.rows.get(int(parts[1])) if parts[1].isdigit() else None
        if row is None:
            return _reply(404, {"status": "error", "message": f"Widget {parts[1]} does not exist"})
        tail = (method, *parts[2:])
        if tail == ("GET",):
            return _reply(200, {"status": "ok", "widgets": [row], "count": 1})
        if tail == ("PATCH",):
            row.update({k: v for k, v in body.items() if k not in self.ignored and k != "id"})
            self._log(row, "updated")
        elif tail == ("DELETE",):
            del self.rows[row["id"]]
            self._log(row, "deleted")
        elif tail == ("POST", "maintenance"):
            row["maintenance"] = body
            self._log(row, "put in maintenance")
        elif tail != ("GET", "discover"):
            return _reply(404, {"status": "error", "message": "This API route doesn't exist."})
        return _reply(200, {"status": "ok", "message": "done"})

    def _log(self, row: Dict[str, Any], verb: str) -> None:
        device_id = row["id"] if self.devices else row.get("device_id")
        if device_id:
            self.logged += 1
            stamp = f"2026-10-28 13:00:{self.logged:02d}"
            self.fake.seed("eventlog", {"device_id": device_id, "datetime": stamp, "message": f"{row['name']} {verb}"})


class Widget(resources.Resource):
    """A stub resource with one op per inverse kind, written against the hooks of resources/base.py."""

    title = "widget"
    id_key = "id"
    label_key = "name"
    match_keys = ("name", "color")
    natural_key = "name"
    parent_key = "device_id"
    fields = {
        "name": Field("name", "str", required=True),
        "color": Field("color", "enum", choices=("red", "green", "blue")),
        "size": Field("size", "int"),
        "device_id": Field("device_id", "int", update=False, nullable=True),
        "notes": Field("notes", "text", note="the poller may overwrite notes"),
        "overwrite_ip": Field("overwrite_ip", "text"),
    }
    ops = ("create", "update", "delete", "maintenance", "discover")
    inverse = {
        "create": ("exact", "deletes the widget"),
        "update": ("exact", "restores the previous values"),
        "delete": ("lossy", "re-created with a new id"),
        "maintenance": ("none", "maintenance cannot be ended through the API"),
        "discover": ("not_needed", "discovery changes nothing"),
    }

    def __init__(self, name: str = "widget", **attributes: Any):
        self.name = name
        self.before_check = None  # callable(step) run at the start of every check()
        for key, value in attributes.items():
            setattr(self, key, value)

    def get(self, client, object_id, step=None):
        body = client.get_or_none(f"widgets/{object_id}")
        rows = client.result(body, "widgets") if body else None
        return rows[0] if rows else None

    def find(self, client, match):
        rows = client.result(client.get("widgets", match), "widgets") or []
        return len(rows), (rows[0] if len(rows) == 1 else None)

    def state(self, client, obj):
        return {"id": int(obj["id"]), **{name: diff.normalise(f, obj.get(name)) for name, f in self.fields.items()}}

    def validate(self, op, data, settings):
        errors = super().validate(op, data, settings)
        if op == "maintenance" and "duration" not in data:
            errors.append("duration is required")
        return errors

    def check(self, client, step):
        if self.before_check is not None:
            self.before_check(step)
        return super().check(client, step)

    def _create_call(self, client, step, context):
        return int(client.request("POST", "widgets", json=step["data"])["id"])

    def _update_call(self, client, object_id, data, record, context):
        client.request("PATCH", f"widgets/{object_id}", json=data)

    def _delete_call(self, client, object_id, record, context):
        client.request("DELETE", f"widgets/{object_id}")

    def _recreate_call(self, client, entry, context):
        snapshot = entry["inverse"]["snapshot"]
        if context.get("resuming"):  # a rollback that died after this point may have created it: adopt that one
            count, obj = self.find(client, {"name": snapshot["name"]})
            if count == 1:
                return int(obj["id"]), {"note": "adopted"}
        body = client.request("POST", "widgets", json={k: snapshot.get(k) for k in self.fields})
        return int(body["id"]), {"note": "re-created with a new id"}

    def _execute_action(self, client, step, context):
        if step["action"] == "maintenance":
            title = f"[hermes:{context['plan_id']}] {step['label']}"
            client.request("POST", f"widgets/{step['object_id']}/maintenance", json={**step["params"], "title": title})
        else:
            client.get(f"widgets/{step['object_id']}/discover")
        return self._entry(step["object_id"], None, None, [f"{step['action']} sent"])


class WidgetCase(PluginTestCase):
    """PluginTestCase whose client talks to a WidgetBackend, with the widget stub installed and three widgets: w1
    (device 2), w2 (no device) and w3 (device 3)."""

    def setUp(self) -> None:
        super().setUp()
        self.backend = WidgetBackend(self.fake)
        self.client = self.client_mod.LibreNMSClient(self.fake.base_url, TOKEN, session=self.backend)
        self.client.retry_sleep = lambda _seconds: None
        self.widgets = self.install(Widget())
        self.backend.add(name="w1", color="red", size=1, device_id=2)
        self.backend.add(name="w2", color="green", size=2)
        self.backend.add(name="w3", color="blue", size=3, device_id=3)

    def install(self, resource: Widget) -> Widget:
        resources.register(resource)
        self.addCleanup(resources.unregister, resource.name)
        return resource

    def build(self, operations: List[Dict[str, Any]], settings=None, **kwargs: Any) -> Dict[str, Any]:
        settings = settings or self.settings
        return self.planner.build_plan(self.client, operations, "test", settings, self.client.base_url, **kwargs)

    def errors(self, operations: List[Any], settings=None) -> List[Dict[str, Any]]:
        with self.assertRaises(self.planner.PlanError) as caught:
            self.build(operations, settings)
        return caught.exception.errors


def update(object_id: Any = 1, **data: Any) -> Dict[str, Any]:
    return {"op": "update", "resource": "widget", "id": object_id, "data": data}


class Validation(WidgetCase):
    def messages(self, operation: Any, settings=None) -> List[str]:
        errors = self.errors([operation], settings)
        self.assertEqual({e["index"] for e in errors}, {0})
        return [e["error"] for e in errors]

    def test_operation_must_be_an_object(self):
        self.assertEqual(self.messages("update widget 1"), ["operation must be an object"])

    def test_unknown_resource(self):
        names = "device, location, device_group, service, alert_rule, port, alert"
        self.assertEqual(
            self.messages({"op": "update", "resource": "gizmo", "id": 1, "data": {"x": 1}}),
            [f'resource must be one of {names} (got "gizmo")'],
        )
        self.assertEqual(self.messages({"op": "update"}), [f"resource must be one of {names} (got null)"])

    def test_op_must_be_one_the_resource_supports(self):
        self.assertEqual(
            self.messages({"op": "ack", "resource": "widget", "id": 1, "data": {"note": "x"}}),
            ['op must be one of create, update, delete, maintenance, discover for a widget (got "ack")'],
        )

    def test_resource_and_op_are_case_insensitive(self):
        plan = self.build([{"op": " Update", "resource": "WIDGET ", "id": "1", "data": {"size": 5}}])
        self.assertEqual((plan["steps"][0]["action"], plan["steps"][0]["object_id"]), ("update", 1))

    def test_id_must_be_a_positive_integer(self):
        for bad, shown in ((True, "true"), (0, "0"), (-3, "-3"), ("x", '"x"'), ("٧", '"٧"'), (1.5, "1.5")):
            with self.subTest(id=bad):
                self.assertEqual(self.messages(update(bad, size=5)), [f"id must be a positive integer (got {shown})"])

    def test_match_keys(self):
        cases = (
            ({}, "match must be a non-empty object with keys among name, color"),
            ("w1", "match must be a non-empty object with keys among name, color"),
            ({"size": 1, "name": "w1"}, "match keys must be among name, color (got size)"),
        )
        for match, message in cases:
            with self.subTest(match=match):
                operation = {"op": "update", "resource": "widget", "match": match, "data": {"size": 5}}
                self.assertEqual(self.messages(operation), [message])

    def test_id_or_match(self):
        operation = {"op": "update", "resource": "widget", "id": 1, "match": {"name": "w1"}, "data": {"size": 5}}
        self.assertEqual(self.messages(operation), ["give id or match, not both"])
        operation = {"op": "update", "resource": "widget", "data": {"size": 5}}
        self.assertEqual(self.messages(operation), ["update requires id or match"])
        operation = {"op": "create", "resource": "widget", "id": 4, "data": {"name": "w4"}}
        self.assertEqual(self.messages(operation), ["create does not take id; use match for upsert semantics"])

    def test_a_resource_without_match_keys_takes_an_id_only(self):
        self.install(Widget("alert", title="fault", match_keys=()))
        operation = {"op": "update", "resource": "alert", "match": {"name": "w1"}, "data": {"size": 5}}
        self.assertEqual(self.messages(operation), ["fault operations take an id, not match"])
        self.assertEqual(
            self.messages({"op": "update", "resource": "alert", "data": {"size": 5}}), ["update requires id"]
        )

    def test_data_shape_per_op(self):
        self.assertEqual(self.messages(update(1)), ["update requires a non-empty data object"])
        self.assertEqual(
            self.messages({"op": "maintenance", "resource": "widget", "id": 1, "data": ["2:00"]}),
            ["maintenance requires a non-empty data object"],
        )
        self.assertEqual(
            self.messages({"op": "delete", "resource": "widget", "id": 1, "data": {"size": 1}}),
            ["delete does not take data"],
        )
        plan = self.build([{"op": "discover", "resource": "widget", "id": 1, "data": {}}])
        self.assertEqual(plan["steps"][0]["params"], {})

    def test_resource_validate_runs_after_the_shape_checks(self):
        self.assertEqual(
            self.messages(update(1, colour="red")),
            ["cannot update widget field(s) colour; allowed: color, name, notes, overwrite_ip, size"],
        )
        self.assertEqual(
            self.messages({"op": "maintenance", "resource": "widget", "id": 1, "data": {"notes": "x"}}),
            ["duration is required"],
        )

    def test_every_problem_of_an_operation_is_reported_in_order(self):
        operation = {"op": "update", "resource": "widget", "id": "x", "match": {}, "data": []}
        self.assertEqual(
            self.messages(operation),
            [
                'id must be a positive integer (got "x")',
                "match must be a non-empty object with keys among name, color",
                "give id or match, not both",
                "update requires a non-empty data object",
            ],
        )

    def test_unknown_operation_keys_are_rejected(self):
        operation = {"op": "delete", "resource": "widget", "id": 2, "force": True, "where": {}}
        self.assertEqual(
            self.messages(operation), ["unknown operation key(s) force, where; allowed: op, resource, id, match, data"]
        )

    def test_every_operation_is_checked(self):
        operations = [update(1, size=5), "nope", update(2, size="big"), update(99, size=1)]
        errors = self.errors(operations)
        self.assertEqual(
            errors,
            [
                {"index": 1, "error": "operation must be an object"},
                {"index": 2, "error": 'size: expected an integer, got "big"'},
                {"index": 3, "error": "widget #99 does not exist"},
            ],
        )

    def test_plan_level_limits(self):
        for operations in ([], None, {"op": "update"}):
            with self.subTest(operations=operations):
                self.assertEqual(
                    self.errors(operations), [{"index": -1, "error": "operations must be a non-empty list"}]
                )
        self.settings.max_operations = 2
        self.assertEqual(
            self.errors([update(1, size=5)] * 3),
            [{"index": -1, "error": "plan has 3 operations; max_operations is 2"}],
        )
        self.assertEqual(self.backend.calls, [])


class Gates(WidgetCase):
    def gate(self, operation, **settings: Any) -> List[str]:
        for key, value in settings.items():
            setattr(self.settings, key, value)
        return [e["error"] for e in self.errors([operation])]

    def test_delete_needs_allow_delete(self):
        self.assertEqual(
            self.gate({"op": "delete", "resource": "widget", "id": 2}, allow_delete=False),
            [f"delete operations are disabled; set {SETTINGS_KEY}.allow_delete: true in config.yaml to permit them"],
        )

    def test_every_service_op_needs_allow_services(self):
        self.install(Widget("service"))
        operation = {"op": "discover", "resource": "service", "id": 1}
        self.assertEqual(
            self.gate(operation, allow_services=False),
            [
                "service operations are disabled because a service runs a Nagios plugin with these arguments on the "
                f"poller; set {SETTINGS_KEY}.allow_services: true in config.yaml to permit them"
            ],
        )

    def test_adding_a_device_needs_allow_device_add(self):
        self.install(Widget("device"))
        operation = {"op": "create", "resource": "device", "data": {"name": "new-sw"}}
        self.assertEqual(
            self.gate(operation, allow_device_add=False),
            [
                "adding a device makes LibreNMS probe a host the model chose over ICMP and SNMP; set "
                f"{SETTINGS_KEY}.allow_device_add: true in config.yaml to permit it"
            ],
        )

    def test_retargeting_a_device_needs_allow_device_add(self):
        self.install(Widget("device"))
        self.settings.allow_device_add = False
        retarget = {"op": "update", "resource": "device", "id": 1, "data": {"overwrite_ip": "192.0.2.99"}}
        self.assertEqual(
            self.gate(retarget),
            [
                "retargeting a device changes which host LibreNMS polls with this device's SNMP credentials; set "
                f"{SETTINGS_KEY}.allow_device_add: true"
            ],
        )
        same = {"op": "update", "resource": "device", "id": 1, "data": {"overwrite_ip": "", "size": 4}}
        self.assertEqual(self.build([same])["steps"][0]["changes"], {"size": {"from": 1, "to": 4}})

    def test_gate_errors_come_with_the_other_problems(self):
        self.settings.allow_delete = False
        errors = self.errors([{"op": "delete", "resource": "widget", "id": 0}])
        self.assertEqual([e["error"].split(";")[0] for e in errors], ["id must be a positive integer (got 0)",
                                                                       "delete operations are disabled"])  # fmt: skip


class Handoff(WidgetCase):
    def test_step_errors_become_plan_errors(self):
        operations = [
            update(99, size=1),
            {"op": "update", "resource": "widget", "match": {"name": "nope"}, "data": {"size": 1}},
        ]
        self.assertEqual(
            self.errors(operations),
            [
                {"index": 0, "error": "widget #99 does not exist"},
                {"index": 1, "error": 'no widget matches {"name": "nope"}'},
            ],
        )

    def test_librenms_errors_carry_the_error_details(self):
        self.backend.fail("GET", r"widgets/1", 500)
        [error] = self.errors([update(1, size=5)])
        self.assertEqual(error["index"], 0)
        self.assertIn("HTTP 500", error["error"])
        self.assertEqual((error["librenms"]["status"], error["librenms"]["kind"]), (500, "server"))

    def test_the_resource_gets_a_normalised_operation(self):
        seen = []
        original = self.widgets.plan_step
        self.widgets.plan_step = lambda client, index, op, settings: (
            seen.append(op) or original(client, index, op, settings)
        )
        self.build([{"op": "Update", "resource": "widget", "id": "2", "data": {"size": 4}}])
        self.build([{"op": "discover", "resource": "widget", "match": {"name": "w1"}}])
        self.assertEqual(
            seen,
            [
                {"op": "update", "resource": "widget", "id": 2, "match": None, "data": {"size": 4}},
                {"op": "discover", "resource": "widget", "id": None, "match": {"name": "w1"}, "data": {}},
            ],
        )

    def test_duplicate_targets_are_refused(self):
        operations = [
            update(1, size=5),
            {"op": "update", "resource": "widget", "match": {"name": "w1"}, "data": {"color": "blue"}},
            {"op": "delete", "resource": "widget", "id": 1},
        ]
        self.assertEqual(
            self.errors(operations),
            [
                {"index": 1, "error": "operations [0] and [1] both target widget #1; combine them into one operation"},
                {"index": 2, "error": "operations [0] and [2] both target widget #1; combine them into one operation"},
            ],
        )

    def test_two_creates_of_one_natural_key_are_refused(self):
        create = {"op": "create", "resource": "widget", "data": {"name": "w9"}}
        upsert = {"op": "create", "resource": "widget", "match": {"name": "w9"}, "data": {"name": "w9", "size": 2}}
        self.assertEqual(
            self.errors([create, upsert]),
            [
                {
                    "index": 1,
                    "error": 'operations [0] and [1] both target widget {"name": "w9"}; combine them into one '
                    "operation",
                }
            ],
        )

    def test_actions_and_noops_may_share_a_target(self):
        plan = self.build(
            [
                update(1, size=5),
                {"op": "maintenance", "resource": "widget", "id": 1, "data": {"duration": "2:00"}},
                {"op": "discover", "resource": "widget", "id": 1},
                update(1, color="red"),
            ]
        )
        self.assertEqual([s["action"] for s in plan["steps"]], ["update", "maintenance", "discover", "noop"])

    def test_creates_without_a_natural_key_are_not_compared(self):
        self.install(Widget("service", natural_key=None))
        create = {"op": "create", "resource": "service", "data": {"name": "w9"}}
        plan = self.build([create, create])
        self.assertEqual([s.get("exists_check") for s in plan["steps"]], [None, None])


class PlanShape(WidgetCase):
    def operations(self) -> List[Dict[str, Any]]:
        return [
            update(1, color="green"),
            {"op": "update", "resource": "widget", "match": {"name": "w2"}, "data": {"size": 2}},
            {"op": "create", "resource": "widget", "data": {"name": "w4", "color": "blue", "notes": "hand-made"}},
            {"op": "maintenance", "resource": "widget", "id": 3, "data": {"duration": "2:00"}},
            {"op": "delete", "resource": "widget", "match": {"name": "w2", "color": "green"}},
        ]

    def test_plan(self):
        actor = {"kind": "model", "via": "tool", "platform": "signal"}
        before = datetime.now(timezone.utc).replace(microsecond=0)
        plan = self.planner.build_plan(self.client, self.operations(), "  Move widgets \n", self.settings, actor=actor)
        self.assertRegex(plan["id"], r"^lnp-\d{8}T\d{6}Z-[0-9a-f]{4}$")
        self.assertGreaterEqual(datetime.fromisoformat(plan["created_at"].replace("Z", "+00:00")), before)
        self.assertEqual(
            {k: plan[k] for k in ("version", "status", "description", "librenms_url", "journal", "requested_by")},
            {
                "version": 1,
                "status": "planned",
                "description": "Move widgets",
                "librenms_url": "https://librenms.test",
                "journal": [],
                "requested_by": actor,
            },
        )
        self.assertEqual(plan["summary"], {"create": 1, "update": 1, "delete": 1, "action": 1, "noop": 1})
        self.assertEqual(plan["irreversible"], [3])
        self.assertEqual(plan["warnings"], ["[2] notes: the poller may overwrite notes"])
        audit = plan["audit"]
        self.assertEqual(
            (audit["librenms_version"], audit["librenms_sha"], audit["db_schema"]),
            ("26.10.0", self.fake.system["local_sha"], self.fake.system["db_schema"]),
        )
        for key in ("host", "os_user", "python", "plugin_version", "hermes_home"):
            self.assertIn(key, audit)
        self.assertEqual(json.loads(json.dumps(plan)), plan)  # what the store writes reads back the same
        self.assertEqual(self.backend.writes(), [])

    def test_steps(self):
        steps = self.build(self.operations())["steps"]
        self.assertEqual(
            steps[0],
            {
                "index": 0,
                "action": "update",
                "resource": "widget",
                "object_id": 1,
                "label": "w1",
                "requested_op": "update",
                "resolved_by": "id",
                "parent_id": 2,
                "notes": [],
                "changes": {"color": {"from": "red", "to": "green"}},
                "payload": {"color": "green"},
                "precondition": {"state": self.widgets.state(self.client, self.backend.rows[1])},
                "inverse_kind": "exact",
                "inverse_note": "restores the previous values",
            },
        )
        self.assertEqual(
            {k: steps[1][k] for k in ("action", "resolved_by", "reason")},
            {"action": "noop", "resolved_by": "match", "reason": "already matches desired state"},
        )
        self.assertNotIn("inverse_kind", steps[1])
        self.assertEqual(
            {k: steps[2].get(k) for k in ("action", "object_id", "label", "data", "exists_check", "inverse_kind")},
            {
                "action": "create",
                "object_id": None,
                "label": "w4",
                "data": {"name": "w4", "color": "blue", "notes": "hand-made"},
                "exists_check": {"name": "w4"},
                "inverse_kind": "exact",
            },
        )
        self.assertEqual(
            {k: steps[3].get(k) for k in ("action", "object_id", "parent_id", "params", "inverse_kind")},
            {"action": "maintenance", "object_id": 3, "parent_id": 3, "params": {"duration": "2:00"},
             "inverse_kind": "none"},
        )  # fmt: skip
        self.assertEqual(
            {k: steps[4].get(k) for k in ("action", "object_id", "resolved_by", "inverse_kind", "inverse_note")},
            {"action": "delete", "object_id": 2, "resolved_by": "match", "inverse_kind": "lossy",
             "inverse_note": "re-created with a new id"},
        )  # fmt: skip
        self.assertEqual(steps[4]["snapshot"]["name"], "w2")

    def test_an_upsert_that_found_its_object_is_an_update(self):
        operation = {"op": "create", "resource": "widget", "match": {"name": "w3"}, "data": {"name": "w3", "size": 7}}
        [step] = self.build([operation])["steps"]
        self.assertEqual(
            {k: step.get(k) for k in ("action", "requested_op", "upsert", "object_id", "inverse_kind", "inverse_note")},
            {"action": "update", "requested_op": "create", "upsert": True, "object_id": 3, "inverse_kind": "exact",
             "inverse_note": "restores the previous values"},
        )  # fmt: skip

    def test_a_long_description_is_cut_with_a_warning(self):
        cut = "the description was longer than 200 characters and was cut"
        plan = self.planner.build_plan(self.client, [update(1, size=5)], "d" * 200, self.settings)
        self.assertEqual((plan["description"], plan["warnings"]), ("d" * 200, []))
        plan = self.planner.build_plan(self.client, [update(1, notes="x")], "d" * 300, self.settings)
        self.assertEqual(plan["description"], "d" * 199 + "…")
        self.assertEqual(plan["warnings"], [cut, "[0] notes: the poller may overwrite notes"])
        # Counted as shown: 100 right-to-left overrides are 600 characters once escaped.
        plan = self.planner.build_plan(self.client, [update(1, size=5)], "\u202e" * 100, self.settings)
        self.assertEqual((plan["description"], plan["warnings"]), ("\u202e" * 33 + "…", [cut]))

    def test_the_url_defaults_to_the_clients(self):
        plan = self.planner.build_plan(self.client, [update(1, size=5)], "", self.settings)
        self.assertEqual((plan["librenms_url"], plan["description"]), (self.client.base_url, ""))

    def test_an_unreadable_version_does_not_fail_planning(self):
        self.fake.fail_on("GET", "system", 500)
        audit = self.build([update(1, size=5)])["audit"]
        self.assertEqual((audit["librenms_version"], audit["librenms_sha"], audit["db_schema"]), (None, None, None))


class Rendering(WidgetCase):
    def test_render_plan(self):
        plan = self.build(
            [
                update(1, color="green"),
                {"op": "maintenance", "resource": "widget", "id": 3, "data": {"duration": "2:00"}},
                {"op": "create", "resource": "widget", "data": {"name": "w4", "color": "blue", "notes": "hand-made"}},
                update(2, color="green"),
            ]
        )
        plan["description"] = "Move widgets"
        created = timefmt.local(plan["created_at"])
        self.assertEqual(
            self.planner.render_plan(plan),
            "\n".join(
                [
                    f"Plan {plan['id']} (planned) — Move widgets",
                    "LibreNMS: https://librenms.test",
                    f"Created: {created} by unknown",
                    '[0] update      widget #1 "w1"',
                    '      color: "red" -> "green"',
                    "      rollback: exact — restores the previous values",
                    '[1] maintenance widget #3 "w3"',
                    '      duration "2:00"',
                    "      rollback: none — maintenance cannot be ended through the API",
                    '[2] create      widget "w4"',
                    '      name="w4", color="blue", notes="hand-made"',
                    '      precondition: no widget matches {"name": "w4"}',
                    "      rollback: exact — deletes the widget",
                    '[3] noop        widget #2 "w2"',
                    "      already matches desired state",
                    "Summary: 1 create, 1 update, 0 delete, 1 action, 1 noop",
                    "Warning: [2] notes: the poller may overwrite notes",
                ]
            ),
        )

    def test_render_step_leaves_notes_to_the_plan(self):
        plan = self.build([update(1, notes="patched")])
        self.assertEqual(
            self.planner.render_step(plan["steps"][0]),
            ['[0] update      widget #1 "w1"', '      notes: "" -> "patched"',
             "      rollback: exact — restores the previous values"],
        )  # fmt: skip
        self.assertEqual(self.planner.render_plan(plan).count("the poller may overwrite notes"), 1)

    def test_rollback_line_without_a_note(self):
        self.install(Widget("widget", inverse={**Widget.inverse, "update": ("exact", "")}))
        self.assertEqual(
            self.planner.render_step(self.build([update(1, size=4)])["steps"][0])[-1], "      rollback: exact"
        )

    def test_free_text_cannot_start_a_line(self):
        forged = '\n[0] update      widget #2 "w2"\n      rollback: exact\nSummary: 0 create, 1 update, 0 delete'
        actor = {"kind": "model", "via": "tool", "platform": "telegram", "chat_type": "group", "chat_name": forged}
        plan = self.build([update(1, size=4), {"op": "delete", "resource": "widget", "id": 3}], actor=actor)
        plan["description"] = "Tidy up" + forged
        plan["steps"][1]["label"] = "w3" + forged  # a name read from LibreNMS
        plan["steps"][1]["inverse_note"] = "re-created" + forged
        plan["warnings"] = ["[1] a note" + forged]
        lines = self.planner.render_plan(plan).splitlines()
        self.assertEqual(len(lines), 11)  # header 3, step 0 3, step 1 3, summary, warning
        escaped = forged.replace("\n", "\\n")
        self.assertEqual(lines[0], f"Plan {plan['id']} (planned) — Tidy up{escaped}")
        self.assertTrue(lines[2].endswith(f" in group {escaped}"), lines[2])
        self.assertEqual(lines[6], f'[1] delete      widget #3 "w3{escaped}"')
        self.assertEqual(lines[8], f"      rollback: lossy — re-created{escaped}")
        self.assertEqual(lines[10], f"Warning: [1] a note{escaped}")

    def test_requester_and_empty_description(self):
        plan = self.build([update(1, size=4)], actor={"kind": "operator", "via": "cli", "os_user": "ops"})
        plan["description"] = ""
        lines = self.planner.render_plan(plan).splitlines()
        self.assertEqual(lines[0], f"Plan {plan['id']} (planned)")
        self.assertTrue(lines[2].endswith(" by operator via cli (ops)"), lines[2])


if __name__ == "__main__":
    unittest.main()
