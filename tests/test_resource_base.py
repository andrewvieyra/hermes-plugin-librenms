"""The generic plan / check / execute / revert logic of resources.base, over an in-memory stub resource."""

import unittest
from datetime import datetime, timedelta, timezone

from .base import PluginTestCase
from .helpers import submodule

base = submodule("resources.base")
resources = submodule("resources")
diff = submodule("diff")
timefmt = submodule("timefmt")
LibreNMSError = submodule("client").LibreNMSError
Field = base.Field

CONTEXT = {"plan_id": "lnp-test", "settings": None, "actor": None}
SECRET = "hunter2-old-param"


def server_error(method="PATCH"):
    return LibreNMSError(f"{method} /api/v0/widgets -> HTTP 500: boom", status=500, method=method, kind="server")


def transport_error(method="PATCH"):
    return LibreNMSError("could not reach LibreNMS (timeout) err-0123456789ab", method=method, kind="transport")


def gateway_error(method="PATCH", status=504):
    return LibreNMSError(f"{method} /api/v0/widgets -> HTTP {status}: gateway", status=status, kind="server")


def refused_error(method="PATCH"):
    return submodule("client").TransportError(
        "could not reach LibreNMS (refused) err-0123456789ab", method=method, failure="refused"
    )


class StubClient:
    """Widgets in a dict behind ``request``, with failures that strike before or after the change is made."""

    def __init__(self):
        self.rows = {}
        self.next_id = 1
        self.calls = []
        self.bodies = []
        self.failures = []
        self.ignored = set()  # fields PATCH accepts and silently does not apply

    def add(self, **row):
        row.setdefault("id", self.next_id)
        self.next_id = max(self.next_id, row["id"]) + 1
        self.rows[row["id"]] = row
        return row["id"]

    def fail(self, method, exc, *, commit=False):
        self.failures.append((method, exc, commit))

    def request(self, method, path, *, params=None, json=None, timeout=None):
        self.calls.append((method, path))
        if method != "GET":
            self.bodies.append((method, path, json))
        failure = next((f for f in self.failures if f[0] == method), None)
        if failure is not None:
            self.failures.remove(failure)
            if not failure[2]:
                raise failure[1]
        result = self._handle(method, path, params or {}, json or {})
        if failure is not None:
            raise failure[1]
        return result

    def _handle(self, method, path, params, body):
        parts = path.split("/")
        if method == "GET" and path == "widgets":
            rows = [r for r in self.rows.values() if all(str(r.get(k)) == str(v) for k, v in params.items())]
            return {"widgets": [dict(r) for r in rows]}
        object_id = int(parts[1]) if len(parts) > 1 else None
        if method == "GET":
            row = self.rows.get(object_id)
            return {"widgets": [dict(row)] if row else []}
        if method == "POST" and len(parts) == 1:
            return {"id": self.add(**body)}
        if method == "POST":
            self.rows[object_id]["pokes"] = self.rows[object_id].get("pokes", 0) + 1
            return {"status": "ok"}
        if method == "PATCH":
            self.rows[object_id].update({k: v for k, v in body.items() if k not in self.ignored})
            return {"status": "ok"}
        if method == "DELETE":
            del self.rows[object_id]
            return {"status": "ok"}
        raise AssertionError(f"unexpected {method} {path}")


class Widget(base.Resource):
    name = "widget"
    title = "widget"
    id_key = "id"
    label_key = "name"
    match_keys = ("name", "color")
    natural_key = "name"
    fields = {
        "name": Field("name", "str", required=True),
        "color": Field("color", "enum", choices=("red", "green", "blue")),
        "size": Field("size", "int", nullable=True),
        "enabled": Field("enabled", "bool"),
        "secret": Field("secret", "text", sensitive=True),
        "shape": Field("shape", "str", update=False),
        "polled": Field("polled", "text", note="the poller may overwrite this"),
        "key_ref": Field("key_ref", "env", update=False),
    }
    ops = ("create", "update", "delete", "poke", "freeze")
    inverse = {
        "create": ("exact", ""),
        "update": ("exact", ""),
        "delete": ("lossy", "re-created with a new id"),
        "poke": ("not_needed", "poking changes nothing"),
        "freeze": ("none", "a frozen widget cannot be thawed"),
    }
    explode_after_write = None  # an exception the write hooks raise after their request (a parse failure)

    def get(self, client, object_id, step=None):
        rows = client.request("GET", f"widgets/{object_id}")["widgets"]
        return rows[0] if rows else None

    def find(self, client, match):
        rows = client.request("GET", "widgets", params=match)["widgets"]
        return len(rows), (rows[0] if len(rows) == 1 else None)

    def state(self, client, obj):
        state = {"id": int(obj["id"])}
        for name, field in self.fields.items():
            if name != "key_ref":
                state[name] = diff.normalise(field, obj.get(name))
        return state

    def volatile_fields(self, state):
        return {"polled"}

    def _explode(self):
        if self.explode_after_write is not None:
            raise self.explode_after_write

    def _create_call(self, client, step, context):
        data = {k: v for k, v in step["data"].items() if k != "key_ref"}
        new_id = client.request("POST", "widgets", json=data)["id"]
        self._explode()
        return new_id

    def _update_call(self, client, object_id, data, record, context):
        client.request("PATCH", f"widgets/{object_id}", json=data)
        self._explode()

    def _delete_call(self, client, object_id, record, context):
        client.request("DELETE", f"widgets/{object_id}")

    def _recreate_call(self, client, entry, context):
        snapshot = entry["inverse"]["snapshot"]
        body = {k: v for k, v in snapshot.items() if k in self.fields}
        return client.request("POST", "widgets", json=body)["id"], {"note": "re-created"}

    def _execute_action(self, client, step, context):
        client.request("POST", f"widgets/{step['object_id']}/{step['action']}")
        return self._entry(step["object_id"], None, None, [f"{step['action']} sent"])


SETTLED = {"settles_at": "2026-10-28T19:10:00Z"}  # an unknown outcome whose write can no longer be running


def entry_for(step, result=None, status="done", **extra):
    """A journal entry as the executor writes it."""
    entry = {
        key: step.get(key) for key in ("index", "action", "resource", "object_id", "label", "parent_id", "inverse_kind")
    }
    entry.update(status=status, at="2026-10-28T19:00:00Z", **(result or {}), **extra)
    return entry


class ResourceCase(unittest.TestCase):
    def setUp(self):
        self.client = StubClient()
        self.client.add(name="w1", color="red", size=3, enabled=1, secret=SECRET, shape="round", polled="up")
        self.res = Widget()

    def op(self, kind, data=None, id=None, match=None):
        return {"op": kind, "resource": "widget", "id": id, "match": match, "data": data or {}}

    def plan(self, kind, data=None, id=None, match=None, index=0):
        return self.res.plan_step(self.client, index, self.op(kind, data, id, match), None)

    def apply(self, step):
        return self.res.execute(self.client, step, CONTEXT)

    def revert(self, entry, force=False, step=None):
        context = dict(CONTEXT, step=step) if step is not None else CONTEXT
        return self.res.revert(self.client, entry, force, context)


class Planning(ResourceCase):
    def test_update_step(self):
        step = self.plan("update", {"color": "blue", "size": "5", "enabled": "1"}, id=1)
        self.assertEqual(step["action"], "update")
        self.assertEqual(step["resource"], "widget")
        self.assertEqual((step["object_id"], step["label"], step["resolved_by"]), (1, "w1", "id"))
        self.assertEqual(step["requested_op"], "update")
        self.assertIsNone(step["parent_id"])
        self.assertEqual(step["changes"], {"color": {"from": "red", "to": "blue"}, "size": {"from": 3, "to": 5}})
        self.assertEqual(step["payload"], {"color": "blue", "size": 5})
        self.assertEqual(step["precondition"]["state"]["secret"], SECRET)
        self.assertEqual((step["inverse_kind"], step["inverse_note"]), ("exact", ""))
        self.assertEqual(step["notes"], [])

    def test_update_by_match_and_target_errors(self):
        self.assertEqual(self.plan("update", {"size": 4}, match={"name": "w1"})["resolved_by"], "match")
        self.client.add(name="w2", color="red")
        with self.assertRaisesRegex(base.StepError, r'^match \{"color": "red"\} is ambiguous \(2 widgets\)$'):
            self.plan("update", {"size": 4}, match={"color": "red"})
        with self.assertRaisesRegex(base.StepError, r'^no widget matches \{"color": "blue"\}$'):
            self.plan("update", {"size": 4}, match={"color": "blue"})
        with self.assertRaisesRegex(base.StepError, r"^widget #9 does not exist$"):
            self.plan("update", {"size": 4}, id=9)

    def test_noop_when_nothing_differs(self):
        step = self.plan("update", {"color": "red", "enabled": True, "size": "3"}, id=1)
        self.assertEqual(step["action"], "noop")
        self.assertEqual(step["reason"], "already matches desired state")
        for key in ("inverse_kind", "precondition", "changes", "payload"):
            self.assertNotIn(key, step)

    def test_upsert_of_existing_object_becomes_update(self):
        step = self.plan("create", {"name": "w1", "color": "green", "shape": "square"}, match={"name": "w1"})
        self.assertEqual(step["action"], "update")
        self.assertTrue(step["upsert"])
        self.assertEqual((step["requested_op"], step["resolved_by"], step["object_id"]), ("create", "match", 1))
        self.assertEqual(step["changes"], {"color": {"from": "red", "to": "green"}})
        self.assertEqual(step["inverse_kind"], "exact")
        self.assertEqual(
            step["notes"], ["shape cannot be changed on an existing widget; the matched one keeps its own value"]
        )

    def test_upsert_noop(self):
        step = self.plan("create", {"name": "w1", "color": "red", "shape": "round"}, match={"name": "w1"})
        self.assertEqual(step["action"], "noop")
        self.assertNotIn("upsert", step)
        self.assertEqual(step["notes"], [])

    def test_upsert_of_absent_object_creates_with_exists_check(self):
        step = self.plan("create", {"name": "w9", "size": "4", "enabled": "yes"}, match={"name": "w9"})
        self.assertEqual(step["action"], "create")
        self.assertEqual(step["data"], {"name": "w9", "size": 4, "enabled": True})
        self.assertEqual(step["exists_check"], {"name": "w9"})
        self.assertEqual((step["label"], step["resolved_by"], step["object_id"]), ("w9", "match", None))
        self.assertEqual(step["inverse_kind"], "exact")
        self.assertNotIn("precondition", step)

    def test_plain_create_carries_natural_key_exists_check(self):
        step = self.plan("create", {"name": "w9"})
        self.assertIsNone(step["resolved_by"])
        self.assertEqual(step["exists_check"], {"name": "w9"})

    def test_match_that_disagrees_with_data_is_a_warning(self):
        step = self.plan("create", {"name": "w10"}, match={"name": "w9"})
        self.assertEqual(step["exists_check"], {"name": "w10"})
        self.assertEqual(
            step["notes"], ['match name="w9" is not what data sets; the new widget will not match its own lookup']
        )

    def test_field_note_is_a_step_note_when_written(self):
        step = self.plan("update", {"polled": "down", "size": 4}, id=1)
        self.assertEqual(step["notes"], ["polled: the poller may overwrite this"])
        self.assertEqual(self.plan("update", {"size": 5}, id=1)["notes"], [])

    def test_delete_step_keeps_snapshot_and_state(self):
        step = self.plan("delete", id=1)
        self.assertEqual(step["snapshot"]["shape"], "round")
        self.assertEqual(step["precondition"]["state"]["color"], "red")
        self.assertEqual((step["inverse_kind"], step["inverse_note"]), ("lossy", "re-created with a new id"))

    def test_action_step(self):
        step = self.plan("poke", {"times": 2}, id=1)
        self.assertEqual(step["action"], "poke")
        self.assertEqual(step["params"], {"times": 2})
        self.assertEqual(step["precondition"]["state"]["id"], 1)
        self.assertEqual(step["inverse_kind"], "not_needed")


class Validation(unittest.TestCase):
    res = Widget()

    def test_create_requires_and_rejects(self):
        errors = self.res.validate("create", {"color": "pink", "bogus": 1, "polled": None}, None)
        self.assertEqual(
            errors,
            [
                "cannot create widget field(s) bogus; allowed: color, enabled, key_ref, name, polled, secret, shape, "
                "size",
                "name is required to create a widget",
                'color: expected one of red, green, blue, got "pink"',
            ],
        )

    def test_update_rejects_create_only_fields_and_null(self):
        errors = self.res.validate("update", {"shape": "x", "enabled": None, "size": None, "secret": None}, None)
        self.assertEqual(
            errors,
            [
                "cannot update widget field(s) shape; allowed: color, enabled, name, polled, secret, size",
                "enabled: null is not allowed",
            ],
        )

    def test_empty_required_value_and_env_reference(self):
        self.assertEqual(self.res.validate("create", {"name": ""}, None), ["name is required to create a widget"])
        self.assertEqual(self.res.validate("create", {"name": "a", "key_ref": {"env": "LIBRENMS_SNMP_X"}}, None), [])
        self.assertEqual(
            self.res.validate("create", {"name": "a", "key_ref": "literal"}, None),
            ['key_ref: expected {"env": "<VARIABLE NAME>"}, got "literal"'],
        )

    def test_actions_are_left_to_the_resource(self):
        self.assertEqual(self.res.validate("poke", {"anything": 1}, None), [])


class Check(ResourceCase):
    def test_unchanged_object_passes(self):
        self.assertIsNone(self.res.check(self.client, self.plan("update", {"size": 5}, id=1)))

    def test_conflict_wording(self):
        step = self.plan("update", {"color": "blue"}, id=1)
        self.client.rows[1].update(size=9, enabled=0)
        self.assertEqual(
            self.res.check(self.client, step), "widget #1 changed since planning (enabled: true -> false, size: 3 -> 9)"
        )

    def test_sensitive_field_conflict_shows_digests(self):
        step = self.plan("update", {"color": "blue"}, id=1)
        self.client.rows[1]["secret"] = "brand-new-secret"
        message = self.res.check(self.client, step)
        old, new = diff.redacted(SECRET), diff.redacted("brand-new-secret")
        self.assertEqual(message, f"widget #1 changed since planning (secret: {old} -> {new})")
        self.assertNotIn(SECRET, message)

    def test_volatile_field_ignored_unless_written(self):
        step = self.plan("update", {"size": 5}, id=1)
        self.client.rows[1]["polled"] = "down"
        self.assertIsNone(self.res.check(self.client, step))
        self.client.rows[1]["polled"] = "up"
        step = self.plan("update", {"polled": "maintenance"}, id=1)
        self.client.rows[1]["polled"] = "down"
        self.assertEqual(self.res.check(self.client, step), 'widget #1 changed since planning (polled: "up" -> "down")')

    def test_object_gone(self):
        step = self.plan("delete", id=1)
        del self.client.rows[1]
        self.assertEqual(self.res.check(self.client, step), "widget #1 no longer exists")

    def test_create_refused_when_natural_key_now_exists(self):
        step = self.plan("create", {"name": "w9"})
        self.assertIsNone(self.res.check(self.client, step))
        self.client.add(name="w9")
        self.assertEqual(self.res.check(self.client, step), '1 widget(s) now match {"name": "w9"}; expected none')

    def test_noop_and_action(self):
        self.assertIsNone(self.res.check(self.client, self.plan("update", {"size": 3}, id=1)))
        step = self.plan("poke", id=1)
        self.client.rows[1]["size"] = 99  # an action only needs the object to exist
        self.assertIsNone(self.res.check(self.client, step))


class Execute(ResourceCase):
    def test_update_writes_verifies_and_journals_inverse(self):
        step = self.plan("update", {"color": "blue", "size": 5}, id=1)
        result = self.apply(step)
        self.assertEqual(set(result), {"object_id", "inverse", "after_state", "notes"})
        self.assertEqual(result["object_id"], 1)
        self.assertEqual(result["inverse"], {"action": "update", "object_id": 1, "data": {"color": "red", "size": 3}})
        self.assertEqual((result["after_state"]["color"], result["after_state"]["size"]), ("blue", 5))
        self.assertEqual(self.client.bodies, [("PATCH", "widgets/1", {"color": "blue", "size": 5})])

    def test_create_and_delete(self):
        step = self.plan("create", {"name": "w9", "color": "green", "key_ref": {"env": "LIBRENMS_SNMP_X"}})
        result = self.apply(step)
        new_id = result["object_id"]
        self.assertEqual(self.client.rows[new_id]["name"], "w9")
        self.assertEqual(result["inverse"], {"action": "delete", "object_id": new_id})
        self.assertEqual(result["after_state"]["color"], "green")
        step = self.plan("delete", id=1)
        result = self.apply(step)
        self.assertNotIn(1, self.client.rows)
        self.assertEqual(result["inverse"]["action"], "create")
        self.assertEqual(result["inverse"]["snapshot"]["name"], "w1")
        self.assertIsNone(result["after_state"])

    def test_action_and_inverse_kinds_without_inverse(self):
        result = self.apply(self.plan("poke", id=1))
        self.assertEqual(result, {"object_id": 1, "inverse": None, "after_state": None, "notes": ["poke sent"]})

    def test_mismatch_after_accepted_write_is_partial(self):
        self.client.ignored = {"size"}
        step = self.plan("update", {"color": "blue", "size": 5}, id=1)
        with self.assertRaises(base.PartialWrite) as ctx:
            self.apply(step)
        self.assertEqual(str(ctx.exception), "LibreNMS accepted the write but size is 3, expected 5")
        entry = ctx.exception.entry
        self.assertEqual(entry["inverse"]["data"], {"color": "red", "size": 3})
        self.assertEqual(entry["after_state"]["color"], "blue")

    def test_sensitive_mismatch_hides_the_value_read_from_librenms(self):
        self.client.ignored = {"secret"}
        with self.assertRaises(base.PartialWrite) as ctx:
            self.apply(self.plan("update", {"secret": "new-param"}, id=1))
        message = str(ctx.exception)
        self.assertEqual(
            message, f'LibreNMS accepted the write but secret is {diff.redacted(SECRET)}, expected "new-param"'
        )

    def test_server_error_after_the_change_landed_is_partial(self):
        self.client.fail("PATCH", server_error(), commit=True)
        with self.assertRaises(base.PartialWrite) as ctx:
            self.apply(self.plan("update", {"color": "blue"}, id=1))
        self.assertTrue(str(ctx.exception).startswith("PATCH /api/v0/widgets -> HTTP 500: boom"))
        entry = ctx.exception.entry
        self.assertEqual(entry["object_id"], 1)
        self.assertEqual(entry["inverse"], {"action": "update", "object_id": 1, "data": {"color": "red"}})
        self.assertEqual(entry["after_state"]["color"], "blue")
        self.assertNotIn("settles_at", entry)  # LibreNMS answered: it is no longer working on the write

    def test_a_lost_answer_with_nothing_changed_yet_is_an_unknown_outcome(self):
        # LibreNMS may still be running the request when the re-read comes back unchanged, and commit after it.
        for error in (transport_error(), gateway_error(), gateway_error(status=502), gateway_error(status=503)):
            self.client.fail("PATCH", error)
            with self.assertRaises(base.PartialWrite) as ctx:
                self.apply(self.plan("update", {"color": "blue"}, id=1))
            self.assertIs(ctx.exception.__cause__, error)
            self.assertEqual(str(ctx.exception), f"{error} (LibreNMS may have applied the write)")
            self.assertEqual(self.client.calls[-1], ("GET", "widgets/1"))  # the re-read, which proves nothing
            entry = ctx.exception.entry
            self.assertEqual(entry["inverse"], {"action": "update", "object_id": 1, "data": {"color": "red"}})
            self.assertIsNone(entry["after_state"])  # rollback re-reads: previous or planned values only
            self.assertTrue(entry["notes"][0].startswith("outcome unknown: LibreNMS may still be working"))
            settles = timefmt.parse_utc(entry["settles_at"]) - datetime.now(timezone.utc)
            self.assertTrue(base.SETTLE_AFTER - timedelta(seconds=5) < settles <= base.SETTLE_AFTER, settles)

    def test_an_answer_that_proves_nothing_was_done_raises_the_original(self):
        for error in (server_error(), refused_error()):
            self.client.fail("PATCH", error)
            with self.assertRaises(LibreNMSError) as ctx:
                self.apply(self.plan("update", {"color": "blue"}, id=1))
            self.assertIs(ctx.exception, error)
            self.assertEqual(self.client.calls[-1], ("GET", "widgets/1"))  # the re-read that proved nothing changed

    def test_a_create_whose_gateway_timed_out_is_looked_up_again_at_rollback(self):
        self.client.fail("POST", gateway_error("POST"))
        step = self.plan("create", {"name": "w9", "color": "blue"})
        with self.assertRaises(base.PartialWrite) as ctx:
            self.apply(step)
        entry = ctx.exception.entry
        self.assertEqual(
            (entry["object_id"], entry["after_state"], entry["inverse"]),
            (None, None, {"action": "delete", "object_id": None, "find": {"name": "w9"}}),
        )
        new_id = self.client.add(name="w9", color="blue")  # LibreNMS finishes the add after the re-read
        entry = entry_for(step, entry, "failed", wrote=True, error=str(ctx.exception))
        self.assertEqual(self.revert(entry, step=step), ("reverted", {"object_id": new_id}))
        self.assertNotIn(new_id, self.client.rows)

    def test_a_delete_whose_answer_was_lost_is_reverted_only_if_it_happened(self):
        step = self.plan("delete", id=1)
        self.client.fail("DELETE", transport_error("DELETE"))
        with self.assertRaises(base.PartialWrite) as ctx:
            self.apply(step)
        entry = entry_for(step, ctx.exception.entry, "failed", wrote=True)
        self.assertEqual(entry["inverse"]["action"], "create")
        self.client.bodies.clear()
        status, details = self.revert(entry)  # LibreNMS may still be deleting it: the entry stays pending
        self.assertEqual(status, "failed")
        self.assertTrue(details["error"].startswith("nothing was deleted so far, but LibreNMS may still be carrying"))
        self.assertEqual(self.revert({**entry, **SETTLED}), ("reverted", {"note": "nothing was deleted"}))
        self.assertEqual(self.client.bodies, [])
        del self.client.rows[1]  # LibreNMS finishes the delete after all
        status, details = self.revert(entry)
        self.assertEqual((status, self.client.rows[details["new_object_id"]]["name"]), ("reverted", "w1"))

    def test_client_error_on_first_write_propagates_without_reread(self):
        error = LibreNMSError("PATCH /api/v0/widgets/1 -> HTTP 422: size: bad", status=422, kind="validation")
        self.client.fail("PATCH", error)
        with self.assertRaises(LibreNMSError) as ctx:
            self.apply(self.plan("update", {"size": 5}, id=1))
        self.assertIs(ctx.exception, error)
        self.assertEqual(self.client.calls[-1], ("PATCH", "widgets/1"))

    def test_error_text_carrying_a_secret_is_scrubbed(self):
        error = LibreNMSError(f"PATCH /api/v0/widgets/1 -> HTTP 422: {SECRET} is no good", status=422, kind="api")
        self.client.fail("PATCH", error)
        with self.assertRaises(base.StepError) as ctx:
            self.apply(self.plan("update", {"secret": "new-param"}, id=1))
        self.assertNotIn(SECRET, str(ctx.exception))
        self.assertIn("<redacted> is no good", str(ctx.exception))

    def test_failure_after_completed_write_with_no_effect_raises_step_error(self):
        self.client.ignored = {"color"}
        self.res.explode_after_write = RuntimeError("answer could not be parsed")
        with self.assertRaises(base.StepError) as ctx:
            self.apply(self.plan("update", {"color": "blue"}, id=1))
        self.assertEqual(str(ctx.exception), "answer could not be parsed")

    def test_parse_failure_after_create_is_partial_with_the_found_id(self):
        self.res.explode_after_write = KeyError("id")
        with self.assertRaises(base.PartialWrite) as ctx:
            self.apply(self.plan("create", {"name": "w9"}))
        entry = ctx.exception.entry
        new_id = next(i for i, r in self.client.rows.items() if r["name"] == "w9")
        self.assertEqual(entry["object_id"], new_id)
        self.assertEqual(entry["inverse"], {"action": "delete", "object_id": new_id})
        self.assertEqual(entry["after_state"]["name"], "w9")

    def test_failed_create_that_created_nothing_raises_the_original(self):
        error = server_error("POST")
        self.client.fail("POST", error)
        with self.assertRaises(LibreNMSError) as ctx:
            self.apply(self.plan("create", {"name": "w9"}))
        self.assertIs(ctx.exception, error)

    def test_create_with_unknown_outcome_and_id(self):
        self.client.fail("POST", transport_error("POST"), commit=True)
        self.client.fail("GET", transport_error("GET"))  # the lookup after the failure breaks too
        with self.assertRaises(base.PartialWrite) as ctx:
            self.apply(self.plan("create", {"name": "w9"}))
        self.assertIn("may have applied", str(ctx.exception))
        entry = ctx.exception.entry
        self.assertIsNone(entry["object_id"])
        self.assertEqual(entry["inverse"], {"action": "delete", "object_id": None, "find": {"name": "w9"}})
        self.assertIsNone(entry["after_state"])
        self.assertIn("outcome unknown", entry["notes"][0])

    def test_delete_that_did_not_delete(self):
        self.client.ignored = set()
        self.res._delete_call = lambda client, object_id, record, context: client.request("PATCH", "widgets/1", json={})
        with self.assertRaisesRegex(base.StepError, r"^LibreNMS accepted the delete but widget #1 still exists$"):
            self.apply(self.plan("delete", id=1))


class Revert(ResourceCase):
    def applied(self, kind, data=None, id=None):
        step = self.plan(kind, data, id=id)
        return step, entry_for(step, self.apply(step))

    def test_update_restores_previous_values(self):
        step, entry = self.applied("update", {"color": "blue", "size": 5}, id=1)
        status, details = self.revert(entry)
        self.assertEqual((status, details), ("reverted", {"restored_fields": ["color", "size"]}))
        self.assertEqual((self.client.rows[1]["color"], self.client.rows[1]["size"]), ("red", 3))

    def test_update_conflict_unless_forced_and_equal_fields_not_sent(self):
        step, entry = self.applied("update", {"color": "blue", "size": 5}, id=1)
        self.client.rows[1].update(color="red", enabled=0)  # color is back at its previous value: not an edit to keep
        status, details = self.revert(entry)
        self.assertEqual(status, "conflict")
        self.assertEqual(
            details["error"], "widget #1 was modified after apply (enabled: true -> false); use force to overwrite"
        )
        self.client.bodies.clear()
        self.assertEqual(self.revert(entry, force=True), ("reverted", {"restored_fields": ["size"]}))
        self.assertEqual(self.client.bodies, [("PATCH", "widgets/1", {"size": 3})])

    def test_update_revert_whose_write_already_landed(self):
        step, entry = self.applied("update", {"color": "blue", "size": 5}, id=1)
        self.client.rows[1].update(color="red", size=3)  # a rollback that died after its write had landed
        self.client.bodies.clear()
        self.assertEqual(
            self.revert(entry),
            ("reverted", {"restored_fields": [], "note": "fields already had their previous values"}),
        )
        self.client.rows[1]["size"] = 5  # half of it: the rest is written
        self.assertEqual(self.revert(entry), ("reverted", {"restored_fields": ["size"]}))
        self.assertEqual(self.client.bodies, [("PATCH", "widgets/1", {"size": 3})])

    def test_update_revert_ignores_poller_churn_on_unwritten_volatile_fields(self):
        step, entry = self.applied("update", {"size": 5}, id=1)
        self.client.rows[1]["polled"] = "down"
        self.assertEqual(self.revert(entry)[0], "reverted")

    def test_update_revert_of_a_gone_object_fails(self):
        step, entry = self.applied("update", {"size": 5}, id=1)
        del self.client.rows[1]
        self.assertEqual(self.revert(entry), ("failed", {"error": "widget #1 no longer exists; cannot restore fields"}))

    def test_create_revert_deletes_and_guards(self):
        step, entry = self.applied("create", {"name": "w9", "color": "green"})
        new_id = entry["object_id"]
        self.client.rows[new_id]["polled"] = "churn"  # volatile: no conflict
        self.client.rows[new_id]["size"] = 7
        status, details = self.revert(entry)
        self.assertEqual(status, "conflict")
        self.assertEqual(
            details["error"], f"widget #{new_id} was modified after apply (size: null -> 7); use force to delete anyway"
        )
        self.assertEqual(self.revert(entry, force=True), ("reverted", {"object_id": new_id}))
        self.assertNotIn(new_id, self.client.rows)
        self.assertEqual(self.revert(entry), ("reverted", {"note": "object already gone"}))

    def test_create_with_unknown_id_is_found_by_lookup(self):
        step = self.plan("create", {"name": "w9"})
        inverse = {"action": "delete", "object_id": None, "find": {"name": "w9"}}
        entry = entry_for(step, {"object_id": None, "inverse": inverse, "after_state": None, "notes": []}, "failed")
        entry["wrote"] = True
        self.assertEqual(self.revert(entry), ("reverted", {"note": "nothing was created"}))
        new_id = self.client.add(name="w9")
        self.assertEqual(self.revert(entry), ("reverted", {"object_id": new_id}))
        self.assertNotIn(new_id, self.client.rows)
        self.client.add(name="w9")
        self.client.add(name="w9")
        status, details = self.revert(entry)
        self.assertEqual(status, "conflict")
        self.assertEqual(details["error"], '2 widgets match {"name": "w9"}; cannot tell which one this plan created')

    def test_create_unknown_end_to_end(self):
        self.client.fail("POST", transport_error("POST"), commit=True)
        self.client.fail("GET", transport_error("GET"))
        step = self.plan("create", {"name": "w9"})
        with self.assertRaises(base.PartialWrite) as ctx:
            self.apply(step)
        entry = entry_for(step, ctx.exception.entry, "failed", wrote=True, error=str(ctx.exception))
        status, details = self.revert(entry)
        self.assertEqual(status, "reverted")
        self.assertEqual([r["name"] for r in self.client.rows.values()], ["w1"])

    def test_delete_revert_recreates(self):
        step, entry = self.applied("delete", id=1)
        status, details = self.revert(entry)
        self.assertEqual(status, "reverted")
        self.assertEqual(details["note"], "re-created")
        recreated = self.client.rows[details["new_object_id"]]
        self.assertEqual((recreated["name"], recreated["shape"], recreated["secret"]), ("w1", "round", SECRET))

    def test_delete_revert_conflicts_when_the_name_is_taken_again(self):
        step, entry = self.applied("delete", id=1)
        self.client.add(name="w1")
        status, details = self.revert(entry, force=True)
        self.assertEqual(status, "conflict")
        self.assertEqual(
            details["error"], 'a widget matching {"name": "w1"} exists again; remove or rename it before rolling back'
        )

    def test_delete_revert_saves_its_progress_before_re_creating(self):
        step, entry = self.applied("delete", id=1)
        saved = []
        context = dict(CONTEXT, checkpoint=lambda progress: saved.append((progress, len(self.client.bodies))))
        status, details = self.res.revert(self.client, entry, False, context)
        self.assertEqual(status, "reverted")
        self.assertEqual(saved, [({"recreating": True}, 1)])  # after the DELETE of the apply, before the POST
        self.assertEqual(self.client.bodies[-1][:2], ("POST", "widgets"))
        self.assertNotIn("resuming", context)

    def test_a_resumed_delete_revert_adopts_what_the_dead_run_created(self):
        step, entry = self.applied("delete", id=1)
        dead_runs = self.client.add(name="w1", shape="round")  # the rollback that died had re-created it
        entry["revert_progress"] = {"recreating": True}

        def adopt(client, entry, context):
            self.assertTrue(context.get("resuming"))  # instead of "a widget matching w1 exists again"
            return self.res._id_of(self.res.find(client, {"name": "w1"})[1]), {"note": "adopted"}

        self.res._recreate_call = adopt
        self.assertEqual(self.revert(entry), ("reverted", {"new_object_id": dead_runs, "note": "adopted"}))
        self.assertEqual([r["name"] for r in self.client.rows.values()], ["w1"])

    def test_inverse_none_and_not_needed(self):
        step, entry = self.applied("freeze", id=1)
        self.assertEqual(self.revert(entry), ("irreversible", {"note": "a frozen widget cannot be thawed"}))
        step, entry = self.applied("poke", id=1)
        self.assertEqual(self.revert(entry), ("skipped", {"note": "poking changes nothing"}))

    def test_partial_update_reverts_from_its_entry(self):
        self.client.fail("PATCH", server_error(), commit=True)
        step = self.plan("update", {"color": "blue"}, id=1)
        with self.assertRaises(base.PartialWrite) as ctx:
            self.apply(step)
        entry = entry_for(step, ctx.exception.entry, "failed", wrote=True)
        self.assertEqual(self.revert(entry), ("reverted", {"restored_fields": ["color"]}))
        self.assertEqual(self.client.rows[1]["color"], "red")

    def test_partial_update_whose_reread_failed_checks_before_writing(self):
        step = self.plan("update", {"color": "blue"}, id=1)
        self.client.fail("PATCH", transport_error())
        self.client.fail("GET", transport_error("GET"))
        with self.assertRaises(base.PartialWrite) as ctx:
            self.apply(step)
        entry = entry_for(step, ctx.exception.entry, "failed", wrote=True)
        self.assertIsNone(entry["after_state"])
        self.assertEqual(self.revert(entry)[0], "failed")  # the PATCH whose answer was lost may still land
        entry.update(SETTLED)
        self.assertEqual(self.revert(entry), ("reverted", {"restored_fields": [], "note": "nothing was written"}))
        self.client.rows[1]["color"] = "green"
        self.assertEqual(self.revert(entry)[0], "conflict")

    def test_resource_blockers_and_extra_checks(self):
        step, entry = self.applied("create", {"name": "w9"})
        self.res._revert_create_blocker = lambda client, object_id, entry: f"widget #{object_id} is in use"
        self.res._extra_check = lambda client, step, obj, current: "the widget is busy"
        self.assertEqual(self.revert(entry), ("conflict", {"error": f"widget #{entry['object_id']} is in use"}))
        self.assertEqual(self.revert(entry, force=True)[0], "reverted")
        self.assertEqual(self.res.check(self.client, self.plan("update", {"size": 5}, id=1)), "the widget is busy")
        self.assertEqual(self.res.check(self.client, self.plan("create", {"name": "w10"})), "the widget is busy")

    def test_rollback_write_error_is_scrubbed(self):
        step, entry = self.applied("update", {"secret": "new-param"}, id=1)
        self.client.fail("PATCH", LibreNMSError(f"HTTP 422: {SECRET} rejected", status=422, kind="validation"))
        status, details = self.revert(entry)
        self.assertEqual(status, "failed")
        self.assertEqual(details["error"], "HTTP 422: <redacted> rejected")


class RevertUnknown(ResourceCase):
    """Entries a crashed run left as ``unknown``: no inverse was journaled; the step comes in the context."""

    def test_update_found_with_planned_values_is_restored(self):
        step = self.plan("update", {"color": "blue", "size": 5}, id=1)
        self.client.rows[1].update(color="blue", size=5)
        entry = entry_for(step, status="unknown", wrote=True)
        self.assertEqual(self.revert(entry, step=step), ("reverted", {"restored_fields": ["color", "size"]}))
        self.assertEqual(self.client.rows[1]["color"], "red")

    def test_update_half_written_restores_only_what_landed(self):
        step = self.plan("update", {"color": "blue", "size": 5}, id=1)
        self.client.rows[1]["color"] = "blue"
        entry = entry_for(step, status="unknown", wrote=True)
        self.assertEqual(self.revert(entry, step=step), ("reverted", {"restored_fields": ["color"]}))

    def test_update_never_written(self):
        step = self.plan("update", {"color": "blue"}, id=1)
        entry = entry_for(step, status="unknown", wrote=True)
        self.assertEqual(
            self.revert(entry, step=step), ("reverted", {"restored_fields": [], "note": "nothing was written"})
        )

    def test_update_matching_neither_is_a_conflict_unless_forced(self):
        step = self.plan("update", {"color": "blue"}, id=1)
        self.client.rows[1]["color"] = "green"
        entry = entry_for(step, status="unknown", wrote=True)
        status, details = self.revert(entry, step=step)
        self.assertEqual(status, "conflict")
        self.assertIn("color on widget #1 match neither the planned nor the previous value", details["error"])
        self.assertEqual(self.revert(entry, force=True, step=step), ("reverted", {"restored_fields": ["color"]}))

    def test_update_without_the_step_cannot_be_reverted(self):
        step = self.plan("update", {"color": "blue"}, id=1)
        status, details = self.revert(entry_for(step, status="unknown", wrote=True))
        self.assertEqual(status, "failed")
        self.assertEqual(
            details["error"], "no rollback information was recorded for this step; check widget w1 in LibreNMS"
        )

    def test_create_nothing_written(self):
        step = self.plan("create", {"name": "w9", "color": "blue"})
        entry = entry_for(step, status="unknown", wrote=True)
        self.assertEqual(self.revert(entry, step=step), ("reverted", {"note": "nothing was written"}))

    def test_create_found_and_matching_is_deleted(self):
        step = self.plan("create", {"name": "w9", "color": "blue"})
        new_id = self.client.add(name="w9", color="blue", polled="x")
        entry = entry_for(step, status="unknown", wrote=True)
        self.assertEqual(self.revert(entry, step=step), ("reverted", {"object_id": new_id}))
        self.assertNotIn(new_id, self.client.rows)

    def test_create_found_but_different_is_a_conflict(self):
        step = self.plan("create", {"name": "w9", "color": "blue"})
        new_id = self.client.add(name="w9", color="red")
        entry = entry_for(step, status="unknown", wrote=True)
        status, details = self.revert(entry, step=step)
        self.assertEqual(status, "conflict")
        self.assertEqual(
            details["error"],
            f'widget #{new_id} is not what this step creates (color is "red", expected "blue"); use force to delete '
            "anyway",
        )

    def test_delete_and_actions_report_unknown_outcome(self):
        step = self.plan("delete", id=1)
        status, details = self.revert(entry_for(step, status="unknown", wrote=True), step=step)
        self.assertEqual(status, "failed")
        self.assertEqual(
            details["error"],
            "outcome of this step is unknown (the process died during the write); check widget w1 in LibreNMS",
        )
        step = self.plan("freeze", id=1)
        self.assertEqual(self.revert(entry_for(step, status="unknown", wrote=True), step=step)[0], "failed")
        step = self.plan("poke", id=1)
        self.assertEqual(self.revert(entry_for(step, status="unknown", wrote=True), step=step)[0], "skipped")


class Describe(ResourceCase):
    def test_update_lines_sensitive_from_is_digest_to_is_verbatim(self):
        step = self.plan("update", {"secret": "new-param", "size": 4}, id=1)
        lines = self.res.describe(step)
        self.assertEqual(lines, [f'secret: {diff.redacted(SECRET)} -> "new-param"', "size: 3 -> 4"])
        self.assertNotIn(SECRET, "\n".join(lines))

    def test_create_lines_show_operation_values_and_env_references(self):
        step = self.plan("create", {"name": "w9", "secret": "op-param", "key_ref": {"env": "LIBRENMS_SNMP_X"}})
        self.assertEqual(
            self.res.describe(step),
            [
                'name="w9", secret="op-param", key_ref=$LIBRENMS_SNMP_X',
                'precondition: no widget matches {"name": "w9"}',
            ],
        )

    def test_delete_noop_and_action_lines(self):
        self.assertEqual(
            self.res.describe(self.plan("delete", id=1)),
            ["the widget is deleted; its configuration is kept in the plan"],
        )
        self.assertEqual(self.res.describe(self.plan("update", {"size": 3}, id=1)), ["already matches desired state"])
        self.assertEqual(
            self.res.describe(self.plan("poke", {"times": 2, "why": "test"}, id=1)), ['times 2, why "test"']
        )
        self.assertEqual(self.res.describe(self.plan("poke", id=1)), [])


class Registry(unittest.TestCase):
    def tearDown(self):
        resources.unregister("widget")
        resources.unregister("device")

    def test_register_and_unregister(self):
        widget = Widget()
        resources.register(widget)
        self.assertIs(resources.get_resource("widget"), widget)
        resources.unregister("widget")
        with self.assertRaises(KeyError):
            resources.get_resource("widget")
        resources.unregister("widget")  # removing twice is harmless

    def test_override_wins_over_a_module(self):
        stand_in = Widget()
        stand_in.name = "device"
        resources.register(stand_in)
        self.assertIs(resources.get_resource("device"), stand_in)

    def test_names_and_reexports(self):
        self.assertEqual(
            resources.RESOURCE_NAMES, ("device", "location", "device_group", "service", "alert_rule", "port", "alert")
        )
        with self.assertRaises(KeyError):
            resources.get_resource("bogus")
        self.assertIs(resources.StepError, base.StepError)
        self.assertIs(resources.PartialWrite, base.PartialWrite)
        self.assertIs(resources.Field, base.Field)
        self.assertIs(resources.Resource, base.Resource)
        self.assertEqual(resources.INVERSE_KINDS, ("exact", "lossy", "none", "not_needed"))


class MaintenanceChecks(unittest.TestCase):
    """The maintenance checks the device, device group and location resources share (one copy since 0.14.3: the
    three had drifted, and two read a duration in any script's digits)."""

    def test_a_duration_is_hours_and_minutes_in_ascii_digits(self):
        for duration, minutes in (("2:00", 120), ("0:30", 30), ("9999:59", 599999), ("0:00", 0)):
            self.assertEqual(base.maintenance_minutes(duration), minutes, duration)
        # PHP reads (float)"\uff12" as 0: a fullwidth or Arabic-Indic hour is a window that ends as it starts
        for duration in ("\uff12:00", "\u0662:00", "2:\uff10\uff10", "120", "2:60", " 2:00", 2, None, "10000:00"):
            self.assertIsNone(base.maintenance_minutes(duration), duration)

    def test_a_start_and_a_behavior(self):
        self.assertTrue(base.valid_maintenance_start("2026-10-29 01:00:00"))
        for start in ("2026-02-30 01:00:00", "2026-10-29T01:00:00", "\uff12026-10-29 01:00:00", None):
            self.assertFalse(base.valid_maintenance_start(start), start)
        for value, name in (("mute_alerts", "mute_alerts"), (2, "mute_alerts"), ("3", "run_alerts")):
            self.assertEqual(base.maintenance_behavior(value), name, value)
        for value in ("pause", 4, "\uff12", True, "-1", None):
            self.assertIsNone(base.maintenance_behavior(value), value)


class MaintenancePlans(PluginTestCase):
    def test_every_resource_that_schedules_maintenance_checks_it_alike(self):
        # what 0.14.1 planned and applied for a device or a device group: "\uff12:00", which LibreNMS saves as a
        # window that ends as it starts, while a location refused it
        planner = submodule("planner")
        targets = (
            ("device", {"hostname": "core-sw1.example.net"}),
            ("device_group", {"name": "core-switches"}),
            ("location", {"location": "SFO-1"}),
        )
        for resource, match in targets:
            for data in ({"duration": "\uff12:00"}, {"duration": "2:00", "start": "\uff12026-10-29 01:00:00"}):
                operation = {"op": "maintenance", "resource": resource, "match": match, "data": data}
                with self.assertRaises(planner.PlanError, msg=(resource, data)) as caught:
                    self.plan([operation])
                [error] = caught.exception.errors
                self.assertRegex(error["error"], "^(duration|start)", (resource, data))
            # a behavior's number as digits is its name everywhere (only the device took "2" before)
            operation = {"op": "maintenance", "resource": resource, "match": match,
                         "data": {"duration": "2:00", "behavior": "2"}}  # fmt: skip
            [step] = self.plan([operation])["steps"]
            self.assertEqual(step["params"]["behavior"], "mute_alerts", resource)
        self.assertEqual(self.fake.writes(), [])


if __name__ == "__main__":
    unittest.main()
