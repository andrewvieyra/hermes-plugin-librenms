"""The executor: preflight, apply with a write-ahead journal, conflicts and failures with automatic rollback (under
the apply's own run lock), PartialWrite, manual rollback statuses and counts, crash recovery and the one-run-at-a-time
rule across processes, the approved content digest under the claim, dry runs, eventlog linking, the audit event
sequence, and the rendered journal.

Every step runs through the widget stub of ``test_planner`` (an in-memory resource behind the plugin's real client),
so these tests do not depend on any of the seven LibreNMS resources."""

import contextlib
import copy
import json
import subprocess
import sys
import threading
import unittest
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterator, List

from .fake_librenms import TOKEN
from .helpers import REPO_ROOT, submodule
from .test_planner import Widget, WidgetCase, update

timefmt = submodule("timefmt")

# A second process holding a plan's run lock ("run") or the plan store's lock ("store") until its stdin closes.
CHILD = """
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1])
from tests.helpers import submodule

store = submodule("store").PlanStore(Path(sys.argv[2]))
with store.run_lock(sys.argv[4]) if sys.argv[3] == "run" else store.exclusive():
    print("locked", flush=True)
    sys.stdin.read()
"""


class Died(BaseException):
    """The process killed mid-request: nothing between the request and the test may handle it."""


def create(name: str, resource: str = "widget", **data: Any) -> Dict[str, Any]:
    return {"op": "create", "resource": resource, "data": {"name": name, **data}}


def action(op: str, object_id: int, **data: Any) -> Dict[str, Any]:
    return {"op": op, "resource": "widget", "id": object_id, **({"data": data} if data else {})}


class ExecutorCase(WidgetCase):
    def apply(self, plan: Dict[str, Any], client: Any = None, **kwargs: Any) -> Dict[str, Any]:
        return self.executor.apply_plan(client or self.client, plan, self.store, self.settings, **kwargs)

    def rollback(self, plan_id: str, **kwargs: Any) -> Dict[str, Any]:
        return self.executor.rollback_plan(self.client, self.store.load(plan_id), self.store, self.settings, **kwargs)

    def refusal(self, function: Callable[..., Any], *args: Any, **kwargs: Any) -> str:
        with self.assertRaises(self.executor.ExecutionRefused) as caught:
            function(*args, **kwargs)
        return str(caught.exception)

    def journal(self, plan: Dict[str, Any]) -> List[tuple]:
        return [(e["index"], e["status"], e.get("revert_status")) for e in plan["journal"]]

    def settle(self, plan_id: str) -> None:
        """Let the time pass after which a write whose answer was lost can no longer be running in LibreNMS."""
        plan = self.store.load(plan_id)
        for entry in plan["journal"]:
            if "settles_at" in entry:
                entry["settles_at"] = "2026-10-28T19:10:00Z"
        self.store.save(plan)

    def names(self) -> List[str]:
        return [event["event"] for event in self.events()]

    def hold(self, lock: str, plan_id: str = "") -> Callable[[], None]:
        """Hold a lock from another process; returns the function that releases it (also run at cleanup)."""
        command = [sys.executable, "-c", CHILD, str(REPO_ROOT), str(self.store.directory), lock, plan_id]
        proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)

        def release() -> None:
            if not proc.stdin.closed:
                proc.stdin.close()
            proc.wait(10)
            proc.stdout.close()

        self.addCleanup(release)
        self.assertEqual(proc.stdout.readline().strip(), "locked")
        return release


class Apply(ExecutorCase):
    def test_applies_every_step_in_order(self):
        plan = self.plan(
            [update(1, color="green"), update(2, color="green"), create("w4", size=4), action("discover", 3)]
        )
        self.assertIs(self.apply(plan), plan)
        self.assertEqual(plan["status"], "applied")
        self.assertEqual(
            self.journal(plan), [(0, "done", None), (1, "skipped", None), (2, "done", None), (3, "done", None)]
        )
        self.assertEqual((self.backend.rows[1]["color"], self.backend.rows[4]["name"]), ("green", "w4"))
        self.assertEqual(self.backend.writes(), ["PATCH widgets/1", "POST widgets"])
        self.assertEqual(self.store.load(plan["id"]), plan)
        self.assertEqual(
            {k: plan["apply"][k] for k in ("rollback_on_failure", "actor", "outcome")},
            {"rollback_on_failure": True, "actor": None, "outcome": "applied"},
        )
        self.assertLessEqual(plan["apply"]["started_at"], plan["apply"]["finished_at"])
        self.assertTrue(self.store.run_lock_free(plan["id"]))

    def test_journal_entries(self):
        plan = self.plan([update(1, color="green"), update(2, color="green"), create("w4")])
        self.apply(plan)
        done, skipped, created = plan["journal"]
        self.assertEqual(
            sorted(done),
            sorted(["index", "action", "resource", "object_id", "label", "parent_id", "inverse_kind", "status", "at",
                    "inverse", "after_state", "notes", "requests", "request", "eventlog_ids"]),
        )  # fmt: skip
        self.assertEqual(
            {k: done[k] for k in ("index", "action", "resource", "object_id", "label", "parent_id", "inverse_kind")},
            {"index": 0, "action": "update", "resource": "widget", "object_id": 1, "label": "w1", "parent_id": 2,
             "inverse_kind": "exact"},
        )  # fmt: skip
        self.assertEqual(done["inverse"], {"action": "update", "object_id": 1, "data": {"color": "red"}})
        self.assertEqual(done["after_state"], self.widgets.state(self.client, self.backend.rows[1]))
        self.assertEqual(done["notes"], [])
        self.assertEqual(
            skipped,
            {"index": 1, "action": "noop", "resource": "widget", "object_id": 2, "label": "w2", "parent_id": None,
             "inverse_kind": None, "status": "skipped", "at": skipped["at"]},
        )  # fmt: skip
        self.assertEqual((created["object_id"], created["inverse"]), (4, {"action": "delete", "object_id": 4}))
        self.assertNotIn("eventlog_ids", created)  # w4 belongs to no device

    def test_entries_record_their_requests(self):
        plan = self.plan([update(1, color="green"), action("discover", 3)])
        self.apply(plan)
        update_entry, discover_entry = plan["journal"]
        self.assertEqual(
            [(c["method"], c["path"], c["status"]) for c in update_entry["requests"]],
            [("GET", "/api/v0/widgets/1", 200), ("PATCH", "/api/v0/widgets/1", 200), ("GET", "/api/v0/widgets/1", 200)],
        )  # the eventlog baseline read before the step is not the step's
        self.assertEqual(update_entry["request"], update_entry["requests"][1])
        self.assertEqual(sorted(update_entry["request"]), ["duration_ms", "method", "path", "status"])
        self.assertEqual(discover_entry["request"]["path"], "/api/v0/widgets/3/discover")  # no write: the last call
        self.rollback(plan["id"])
        entry = self.store.load(plan["id"])["journal"][0]
        self.assertEqual([c["method"] for c in entry["revert_requests"]], ["GET", "PATCH", "GET"])
        self.assertEqual(entry["revert_request"], entry["revert_requests"][1])

    def test_entries_are_saved_as_running_before_their_write(self):
        plan = self.plan([update(1, color="green")])
        seen = []
        self.backend.on_write = lambda method, path: seen.append(self.store.load(plan["id"])["journal"][-1])
        self.apply(plan)
        self.rollback(plan["id"])
        (applying, reverting) = seen
        self.assertEqual((applying["status"], applying["index"], applying["parent_id"]), ("running", 0, 2))
        self.assertNotIn("inverse", applying)
        self.assertEqual((reverting["status"], reverting["revert_status"]), ("done", "running"))


class Failures(ExecutorCase):
    def test_a_conflict_stops_the_run_and_rolls_back(self):
        plan = self.plan([update(1, color="green"), update(2, size=9), update(3, size=7)])
        self.backend.rows[2]["size"] = 5  # edited in the web UI after planning
        self.apply(plan)
        conflict = "widget #2 changed since planning (size: 2 -> 5)"
        self.assertEqual(self.journal(plan), [(0, "done", "reverted"), (1, "conflict", None)])
        self.assertEqual(plan["journal"][1]["error"], conflict)
        self.assertEqual(plan["apply"]["failure"], {"index": 1, "kind": "conflict", "error": conflict})
        self.assertEqual((plan["apply"]["outcome"], plan["apply"]["failed_step"]), ("failed", 1))
        self.assertEqual(plan["status"], "rolled_back")
        self.assertEqual(plan["rollback"]["reason"], "automatic after failure at step 1")
        self.assertEqual((self.backend.rows[1]["color"], self.backend.rows[3]["size"]), ("red", 3))

    def test_a_failure_rolls_back_under_the_applys_run_lock(self):
        plan = self.plan([update(1, color="green"), update(2, size=9)])
        self.backend.fail("PATCH", r"widgets/2", 400)
        held = []

        def on_write(method, path):
            if self.store.load(plan["id"])["status"] == "rolling_back":
                held.append(self.store.run_lock_free(plan["id"]))

        self.backend.on_write = on_write
        self.apply(plan)
        failed = plan["journal"][1]
        self.assertEqual(
            (failed["status"], failed["error"]), ("failed", "PATCH /api/v0/widgets/2 -> HTTP 400: forced failure")
        )
        self.assertEqual((failed["librenms"]["status"], failed["librenms"]["kind"]), (400, "api"))
        self.assertNotIn("wrote", failed)
        self.assertNotIn("inverse", failed)
        self.assertEqual(plan["status"], "rolled_back")
        self.assertNotIn("auto_rollback_error", plan["apply"])
        self.assertEqual(held, [False])  # the revert ran while this process held the lock
        self.assertTrue(self.store.run_lock_free(plan["id"]))
        self.assertEqual(self.backend.rows[1]["color"], "red")

    def test_rollback_on_failure_off_leaves_the_writes(self):
        plan = self.plan([update(1, color="green"), update(2, size=9)])
        self.backend.fail("PATCH", r"widgets/2", 400)
        self.apply(plan, rollback_on_failure=False)
        self.assertEqual((plan["status"], self.journal(plan)), ("failed", [(0, "done", None), (1, "failed", None)]))
        self.assertNotIn("rollback", plan)
        self.assertEqual(self.backend.rows[1]["color"], "green")
        self.assertEqual(self.rollback(plan["id"])["status"], "rolled_back")
        self.assertEqual(self.backend.rows[1]["color"], "red")

    def test_a_partial_write_is_journaled_with_its_inverse_and_reverted(self):
        plan = self.plan([update(1, color="green"), update(2, size=9)])
        self.backend.fail("PATCH", r"widgets/2", 500, commit=True)  # LibreNMS saved, then failed
        self.apply(plan)
        entry = plan["journal"][1]
        self.assertEqual((entry["status"], entry["wrote"]), ("failed", True))
        self.assertTrue(entry["error"].endswith("(LibreNMS applied part of the step; rollback reverts it)"), entry)
        self.assertEqual(entry["inverse"], {"action": "update", "object_id": 2, "data": {"size": 2}})
        self.assertEqual(entry["after_state"]["size"], 9)
        self.assertNotIn("librenms", entry)
        self.assertEqual(self.journal(plan), [(0, "done", "reverted"), (1, "failed", "reverted")])
        self.assertEqual(plan["status"], "rolled_back")
        self.assertEqual((self.backend.rows[1]["color"], self.backend.rows[2]["size"]), ("red", 2))
        self.assertTrue(self.events("step_failed")[0]["wrote"])

    def test_a_create_whose_answer_was_lost_is_found_and_deleted(self):
        plan = self.plan([create("w4", size=4)])
        self.backend.fail("POST", "widgets", commit=True, exc=ConnectionResetError("connection reset by peer"))
        with self.assertLogs("hermes_plugins.librenms.client", "WARNING"):  # the transport detail, under its id
            self.apply(plan)
        entry = plan["journal"][0]
        self.assertEqual((entry["status"], entry["wrote"], entry["object_id"]), ("failed", True, 4))
        self.assertEqual(entry["inverse"], {"action": "delete", "object_id": 4})
        self.assertEqual((plan["status"], entry["revert_status"]), ("rolled_back", "reverted"))
        self.assertNotIn(4, self.backend.rows)

    def test_a_write_whose_gateway_timed_out_is_journaled_as_may_have_written(self):
        plan = self.plan([create("w4", size=4)])
        self.backend.fail("POST", "widgets", 504)  # the proxy gave up; LibreNMS is still adding it
        self.apply(plan, rollback_on_failure=False)
        entry = plan["journal"][0]
        self.assertEqual(
            (entry["status"], entry["wrote"], entry["error"]),
            ("failed", True, "POST /api/v0/widgets -> HTTP 504: forced failure (LibreNMS may have applied the write)"),
        )
        self.assertEqual(entry["inverse"], {"action": "delete", "object_id": None, "find": {"name": "w4"}})
        self.assertEqual(self.executor.pending_entries(plan), [entry])
        self.assertTrue(self.events("step_failed")[0]["wrote"])
        late = self.backend.add(name="w4", size=4)["id"]  # the add commits after the re-read
        plan = self.rollback(plan["id"])
        self.assertEqual((plan["status"], plan["journal"][0]["revert"]), ("rolled_back", {"object_id": late}))
        self.assertNotIn(late, self.backend.rows)

    def test_the_automatic_rollback_does_not_settle_a_write_that_may_still_land(self):
        plan = self.plan([create("w4", size=4)])
        self.backend.fail("POST", "widgets", 504)  # LibreNMS is still adding it when the automatic rollback looks
        self.apply(plan)
        entry = plan["journal"][0]
        self.assertEqual((plan["status"], entry["revert_status"]), ("partially_rolled_back", "failed"))
        self.assertTrue(entry["revert"]["error"].startswith("nothing was created so far, but LibreNMS may still be"))
        late = self.backend.add(name="w4", size=4)["id"]  # then the add commits
        plan = self.rollback(plan["id"])
        self.assertEqual((plan["status"], plan["journal"][0]["revert"]), ("rolled_back", {"object_id": late}))
        self.assertNotIn(late, self.backend.rows)

        plan = self.plan([create("w5", size=5)])
        self.backend.fail("POST", "widgets", 504)  # this add never lands
        self.assertEqual(self.apply(plan)["status"], "partially_rolled_back")
        self.settle(plan["id"])
        plan = self.rollback(plan["id"])
        self.assertEqual(
            (plan["status"], plan["journal"][0]["revert"]), ("rolled_back", {"note": "nothing was created"})
        )

    def test_an_unverified_write_is_reverted(self):
        self.backend.ignored = {"size"}  # LibreNMS answers 200 and drops the field
        plan = self.plan([update(2, color="blue", size=9)])
        self.apply(plan)
        entry = plan["journal"][0]
        self.assertEqual(entry["error"], "LibreNMS accepted the write but size is 2, expected 9")
        self.assertEqual((entry["wrote"], entry["revert"]), (True, {"restored_fields": ["color"]}))
        self.assertEqual((plan["status"], self.backend.rows[2]["color"]), ("rolled_back", "green"))

    def test_an_unexpected_error_is_journaled_with_an_error_id(self):
        def explode(*_args):
            raise RuntimeError("bug in a resource: secret-ish detail")

        self.widgets._update_call = explode
        plan = self.plan([update(1, size=4)])
        with self.assertLogs("hermes_plugins.librenms.executor", "ERROR") as logs:
            self.apply(plan)
        error = plan["journal"][0]["error"]
        self.assertRegex(error, r"^unexpected error err-[0-9a-f]{12} \(RuntimeError\); see the Hermes log$")
        self.assertIn(error.split()[2], logs.output[0])
        self.assertNotIn("secret-ish", json.dumps(plan))
        self.assertEqual((plan["status"], plan["apply"]["failure"]["kind"]), ("failed", "error"))

    def test_a_failed_precondition_read_is_a_conflict(self):
        plan = self.plan([update(1, size=4)])
        self.backend.fail("GET", r"widgets/1", 500)
        self.apply(plan)
        entry = plan["journal"][0]
        self.assertEqual(entry["status"], "conflict")
        self.assertTrue(entry["error"].startswith("precondition check failed: GET /api/v0/widgets/1 -> HTTP 500"))
        self.assertEqual(self.backend.writes(), [])

    def test_a_refused_automatic_rollback_is_recorded_and_audited(self):
        self.store.claim_timeout = 0.2
        plan = self.plan([update(1, size=4), update(2, size=9)])
        self.backend.fail("PATCH", r"widgets/2", 400)
        released: List[Callable[[], None]] = []
        self.backend.on_write = lambda method, path: path == "widgets/2" and released.append(self.hold("store"))
        self.apply(plan)
        error = "plan store is locked by another process; another apply or rollback is in progress, try again shortly"
        self.assertEqual((plan["status"], plan["apply"]["auto_rollback_error"]), ("failed", error))
        self.assertEqual(self.store.load(plan["id"]), plan)
        [refused] = self.events("rollback_refused")
        self.assertEqual((refused["reason"], refused["automatic"], refused["pending"]), (error, True, 1))
        self.assertIn(f"Automatic rollback refused: {error}", self.executor.render_journal(plan))
        self.assertEqual(self.backend.rows[1]["size"], 4)
        released[0]()
        self.assertEqual(self.rollback(plan["id"])["status"], "rolled_back")
        self.assertEqual(self.backend.rows[1]["size"], 1)

    def test_a_create_that_cannot_be_identified_is_left_for_a_person(self):
        self.install(Widget("service", natural_key=None))  # duplicates allowed: no exists_check to look it up by
        plan = self.plan([create("w9", "service")])
        self.backend.fail("POST", "widgets", commit=True, exc=ConnectionResetError("connection reset by peer"))
        with self.assertLogs("hermes_plugins.librenms.client", "WARNING"):
            self.apply(plan)
        entry = plan["journal"][0]
        self.assertEqual((entry["status"], entry["wrote"], entry["object_id"]), ("failed", True, None))
        self.assertEqual(entry["inverse"], {"action": "delete", "object_id": None, "find": None})
        self.assertEqual(entry["revert_status"], "failed")
        self.assertEqual(
            entry["revert"]["error"], "the widget this step may have created cannot be identified; check w9 in LibreNMS"
        )
        self.assertEqual(plan["status"], "partially_rolled_back")

    def test_an_unknown_resource_in_a_plan_file_is_a_conflict(self):
        plan = self.plan([update(1, size=4)])
        plan["steps"][0]["resource"] = "gizmo"
        self.store.save(plan)
        self.apply(plan)
        self.assertEqual(plan["journal"][0]["error"], "precondition check failed: this plugin has no resource 'gizmo'")
        self.assertEqual((plan["status"], self.backend.writes()), ("failed", []))


class Rollback(ExecutorCase):
    def test_every_write_is_reverted_newest_first(self):
        plan = self.plan([update(1, color="green"), create("w4"), {"op": "delete", "resource": "widget", "id": 2}])
        self.apply(plan)
        actor = {"kind": "operator", "via": "cli", "os_user": "ops"}
        self.rollback(plan["id"], reason="change window closed", actor=actor)
        plan = self.store.load(plan["id"])
        self.assertEqual(plan["status"], "rolled_back")
        self.assertEqual([e["revert_status"] for e in plan["journal"]], ["reverted"] * 3)
        self.assertEqual(plan["journal"][2]["revert"], {"new_object_id": 5, "note": "re-created with a new id"})
        self.assertEqual(plan["journal"][1]["revert"], {"object_id": 4})
        self.assertEqual(plan["journal"][0]["revert"], {"restored_fields": ["color"]})
        rollback = {k: v for k, v in plan["rollback"].items() if k not in ("started_at", "finished_at", "eventlog")}
        self.assertEqual(
            rollback,
            {"force": False, "reason": "change window closed", "entries": 3, "actor": actor, "reverted": 3,
             "conflict": 0, "failed": 0, "irreversible": 0, "skipped": 0},
        )  # fmt: skip
        self.assertEqual(
            [(e["index"], e["status"]) for e in self.events() if e["event"].startswith("revert_")],
            [(2, "reverted"), (1, "reverted"), (0, "reverted")],
        )
        self.assertEqual((self.backend.rows[1]["color"], self.backend.rows[5]["name"]), ("red", "w2"))
        self.assertNotIn(4, self.backend.rows)

    def test_a_later_edit_is_a_conflict_unless_forced(self):
        plan = self.plan([update(1, color="green")])
        self.apply(plan)
        self.backend.rows[1]["size"] = 5
        plan = self.rollback(plan["id"])
        self.assertEqual((plan["status"], plan["rollback"]["conflict"]), ("partially_rolled_back", 1))
        self.assertEqual(
            plan["journal"][0]["revert"],
            {"error": "widget #1 was modified after apply (size: 1 -> 5); use force to overwrite"},
        )
        self.assertEqual(self.events("revert_conflict")[0]["error"], plan["journal"][0]["revert"]["error"])
        self.assertEqual(self.backend.rows[1]["color"], "green")
        plan = self.rollback(plan["id"], force=True)
        self.assertEqual((plan["status"], plan["rollback"]["force"]), ("rolled_back", True))
        self.assertEqual((self.backend.rows[1]["color"], self.backend.rows[1]["size"]), ("red", 5))

    def test_an_irreversible_step_leaves_the_plan_partially_rolled_back(self):
        plan = self.plan([action("maintenance", 1, duration="1:00"), update(2, size=9)])
        self.apply(plan)
        self.assertEqual(
            self.backend.rows[1]["maintenance"], {"duration": "1:00", "title": f"[hermes:{plan['id']}] w1"}
        )
        plan = self.rollback(plan["id"])
        self.assertEqual(plan["status"], "partially_rolled_back")
        self.assertEqual([e["revert_status"] for e in plan["journal"]], ["irreversible", "reverted"])
        self.assertEqual(plan["journal"][0]["revert"], {"note": "maintenance cannot be ended through the API"})
        self.assertEqual((plan["rollback"]["irreversible"], plan["rollback"]["reverted"]), (1, 1))
        self.assertEqual(self.names()[-3:], ["revert_reverted", "revert_irreversible", "rollback_finished"])
        message = self.refusal(self.rollback, plan["id"])
        self.assertEqual(message, f"plan {plan['id']} has nothing left to roll back; irreversible steps: [0]")
        self.assertEqual(self.store.load(plan["id"])["status"], "partially_rolled_back")

    def test_a_step_with_nothing_to_undo_is_skipped(self):
        plan = self.plan([action("discover", 3), update(2, size=9)])
        self.apply(plan)
        plan = self.rollback(plan["id"])
        self.assertEqual(plan["status"], "rolled_back")
        self.assertEqual(plan["journal"][0]["revert"], {"note": "discovery changes nothing"})
        self.assertEqual((plan["rollback"]["skipped"], plan["rollback"]["reverted"]), (1, 1))
        self.assertIn("revert_skipped", self.names())

    def test_rollback_ignores_the_gates(self):
        self.install(Widget("device"))
        self.install(Widget("service"))
        plan = self.plan([create("dev-new", "device"), {"op": "delete", "resource": "service", "id": 2}])
        self.apply(plan)
        for key in ("allow_delete", "allow_device_add", "allow_services"):
            setattr(self.settings, key, False)
        self.assertEqual(self.rollback(plan["id"])["status"], "rolled_back")
        self.assertEqual(sorted(row["name"] for row in self.backend.rows.values()), ["w1", "w2", "w3"])

    def test_a_plan_that_wrote_nothing_rolls_back_with_no_entries(self):
        plan = self.plan([update(1, size=4)])
        self.backend.rows[1]["size"] = 7
        self.apply(plan)
        self.assertEqual((plan["status"], self.journal(plan)), ("failed", [(0, "conflict", None)]))
        self.assertNotIn("rollback", plan)  # nothing was pending, so no automatic rollback
        plan = self.executor.rollback_plan(self.client, self.store.load(plan["id"]), self.store)  # settings default
        self.assertEqual(
            (plan["status"], plan["rollback"]["entries"], plan["rollback"]["reverted"]), ("rolled_back", 0, 0)
        )

    def test_only_a_finished_run_rolls_back(self):
        plan = self.plan([update(1, size=4)])
        needs = "rollback needs one of applied, failed, partially_rolled_back"
        self.assertEqual(self.refusal(self.rollback, plan["id"]), f"plan {plan['id']} is planned; {needs}")
        stale = copy.deepcopy(self.apply(plan))
        self.rollback(plan["id"])
        self.assertEqual(self.refusal(self.rollback, plan["id"]), f"plan {plan['id']} is rolled_back; {needs}")
        message = self.refusal(self.executor.rollback_plan, self.client, stale, self.store, self.settings)
        self.assertEqual(message, f"plan {plan['id']} is rolled_back; {needs}")  # re-read under the lock

    def test_a_revert_that_fails_is_retried_by_the_next_rollback(self):
        plan = self.apply(self.plan([update(1, color="green"), update(2, size=9)]))
        self.backend.fail("GET", r"widgets/1", 500)
        plan = self.rollback(plan["id"])
        failed = plan["journal"][0]
        self.assertEqual(failed["revert_status"], "failed")
        self.assertEqual(
            (failed["revert"]["librenms"]["status"], failed["revert"]["librenms"]["kind"]), (500, "server")
        )
        self.assertTrue(failed["revert"]["error"].startswith("GET /api/v0/widgets/1 -> HTTP 500"))
        self.assertEqual(
            (plan["status"], plan["rollback"]["failed"], plan["rollback"]["reverted"]), ("partially_rolled_back", 1, 1)
        )
        plan = self.rollback(plan["id"])
        self.assertEqual((plan["status"], plan["rollback"]["entries"]), ("rolled_back", 1))
        self.assertEqual(self.backend.rows[1]["color"], "red")

    def test_a_resource_error_during_a_revert_is_a_failed_revert(self):
        plan = self.apply(self.plan([update(1, color="green"), update(2, size=9)]))
        self.widgets.revert = lambda client, entry, force, context: ("undone", {})
        plan = self.rollback(plan["id"])
        self.assertEqual(
            [e["revert"] for e in plan["journal"]],
            [{"error": "the widget resource reported no usable rollback outcome"}] * 2,
        )
        del self.widgets.revert

        def explode(*_args):
            raise RuntimeError("bug in a resource")

        self.widgets._update_call = explode
        with self.assertLogs("hermes_plugins.librenms.executor", "ERROR"):
            plan = self.rollback(plan["id"])
        self.assertRegex(plan["journal"][0]["revert"]["error"], r"^unexpected error err-[0-9a-f]{12} \(RuntimeError\)")
        self.assertEqual((plan["status"], plan["rollback"]["failed"]), ("partially_rolled_back", 2))

    def test_rollback_needs_the_same_librenms(self):
        plan = self.apply(self.plan([update(1, size=4)]))
        other = self.client_mod.LibreNMSClient("https://other.test", TOKEN, session=self.backend)
        message = self.refusal(self.executor.rollback_plan, other, plan, self.store, self.settings)
        self.assertEqual(
            message, "plan was applied against https://librenms.test but LIBRENMS_URL is now https://other.test"
        )


class Recovery(ExecutorCase):
    def test_a_dead_apply_whose_write_landed(self):
        plan = self.plan([update(1, color="green"), update(2, size=9), update(3, size=7)])
        self.backend.fail("PATCH", r"widgets/2", commit=True, exc=Died("gateway killed"))
        with self.assertRaises(Died):
            self.apply(plan)
        stored = self.store.load(plan["id"])
        self.assertEqual(
            (stored["status"], self.journal(stored)), ("applying", [(0, "done", None), (1, "running", None)])
        )
        self.assertTrue(self.store.run_lock_free(plan["id"]))  # the run is gone
        plan = self.rollback(plan["id"])
        self.assertEqual(plan["status"], "rolled_back")
        self.assertEqual(self.journal(plan), [(0, "done", "reverted"), (1, "unknown", "reverted")])
        self.assertTrue(plan["journal"][1]["wrote"])
        self.assertEqual(plan["journal"][1]["revert"], {"restored_fields": ["size"]})
        self.assertEqual([self.backend.rows[i]["size"] for i in (1, 2, 3)], [1, 2, 3])
        [event] = self.events("run_recovered")
        self.assertEqual((event["previous_status"], event["dangling_indexes"]), ("applying", [1]))
        self.assertEqual(plan["rollback"]["recovered"], {"previous_status": "applying", "dangling_indexes": [1]})
        self.assertEqual(
            self.names()[-6:],
            ["run_recovered", "rollback_started", "revert_reverted", "revert_reverted", "eventlog_linked",
             "rollback_finished"],
        )  # fmt: skip
        self.assertIn(
            "Recovered: the run died while the plan was applying; entries [1] were in flight",
            self.executor.render_journal(plan),
        )

    def test_a_dead_apply_whose_writes_never_landed(self):
        plan = self.plan([update(2, size=9), create("w4")])
        self.backend.fail("PATCH", r"widgets/2", exc=Died("gateway killed"))
        with self.assertRaises(Died):
            self.apply(plan)
        plan = self.rollback(plan["id"])  # straight after the crash, LibreNMS may still be running the PATCH
        self.assertEqual((plan["status"], self.journal(plan)), ("partially_rolled_back", [(0, "unknown", "failed")]))
        entry = plan["journal"][0]
        self.assertEqual(timefmt.parse_utc(entry["settles_at"]) - timefmt.parse_utc(entry["at"]), timedelta(minutes=10))
        self.assertIn("nothing was written so far, but LibreNMS may still be carrying", entry["revert"]["error"])
        self.settle(plan["id"])
        plan = self.rollback(plan["id"])
        self.assertEqual((plan["status"], self.journal(plan)), ("rolled_back", [(0, "unknown", "reverted")]))
        self.assertEqual(plan["journal"][0]["revert"], {"restored_fields": [], "note": "nothing was written"})
        self.assertEqual(self.backend.writes(), ["PATCH widgets/2"])  # the attempt only: rollback sent nothing

        plan = self.plan([create("w4")])
        self.backend.fail("POST", "widgets", exc=Died("gateway killed"))
        with self.assertRaises(Died):
            self.apply(plan)
        self.assertEqual(self.journal(self.rollback(plan["id"])), [(0, "unknown", "failed")])
        self.settle(plan["id"])
        plan = self.rollback(plan["id"])
        self.assertEqual(plan["journal"][0]["revert"], {"note": "nothing was written"})
        self.assertEqual(plan["status"], "rolled_back")

    def test_a_dead_rollback_is_resumed(self):
        plan = self.apply(self.plan([update(1, color="green"), update(2, size=9)]))
        self.backend.fail("PATCH", r"widgets/1", exc=Died("gateway killed"))
        with self.assertRaises(Died):
            self.rollback(plan["id"])
        stored = self.store.load(plan["id"])
        in_flight = [(0, "done", "running"), (1, "done", "reverted")]
        self.assertEqual((stored["status"], self.journal(stored)), ("rolling_back", in_flight))
        plan = self.rollback(plan["id"])
        self.assertEqual((plan["status"], plan["rollback"]["entries"]), ("rolled_back", 1))
        self.assertEqual(self.events("run_recovered")[0]["previous_status"], "rolling_back")
        self.assertEqual(self.backend.rows[1]["color"], "red")

    def test_a_dead_rollback_whose_write_landed_is_finished(self):
        plan = self.apply(self.plan([update(1, color="green")]))
        self.backend.fail("PATCH", r"widgets/1", commit=True, exc=Died("gateway killed"))
        with self.assertRaises(Died):
            self.rollback(plan["id"])
        self.assertEqual(self.backend.rows[1]["color"], "red")  # restored, but the run died before saying so
        plan = self.rollback(plan["id"])
        self.assertEqual(
            (plan["status"], plan["journal"][0]["revert"]),
            ("rolled_back", {"restored_fields": [], "note": "fields already had their previous values"}),
        )

    def test_a_dead_rollback_that_re_created_an_object_adopts_it(self):
        plan = self.apply(self.plan([{"op": "delete", "resource": "widget", "id": 2}]))
        self.backend.fail("POST", "widgets", commit=True, exc=Died("gateway killed"))
        with self.assertRaises(Died):
            self.rollback(plan["id"])
        stored = self.store.load(plan["id"])
        self.assertEqual(self.journal(stored), [(0, "done", "running")])
        self.assertEqual(stored["journal"][0]["revert_progress"], {"recreating": True})  # saved before the POST
        [created] = [row["id"] for row in self.backend.rows.values() if row["name"] == "w2"]
        plan = self.rollback(plan["id"])
        self.assertEqual(plan["status"], "rolled_back")
        self.assertEqual(plan["journal"][0]["revert"], {"new_object_id": created, "note": "adopted"})
        self.assertEqual(plan["journal"][0]["revert_progress"], {"recreating": True})
        self.assertEqual(self.backend.writes(), ["DELETE widgets/2", "POST widgets"])  # not created a second time

    def test_no_run_starts_before_a_failed_applys_automatic_rollback(self):
        plan = self.plan([update(1, color="green"), update(2, size=9)])
        other = self.plan([update(3, size=7)])
        self.backend.fail("PATCH", r"widgets/2", 400)
        outcome: List[str] = []
        emit = self.audit.emit
        self.addCleanup(setattr, self.audit, "emit", emit)

        def run_other() -> None:
            try:
                outcome.append(self.apply(other)["status"])
            except self.executor.ExecutionRefused as exc:
                outcome.append(str(exc))

        def claim_in_the_gap(event: str, **fields: Any) -> None:
            emit(event, **fields)
            if event == "apply_finished" and fields["plan_id"] == plan["id"]:
                # Saved "failed", not yet claimed for its rollback: a gateway thread or a CLI apply claims now.
                thread = threading.Thread(target=run_other)
                thread.start()
                thread.join(10)

        self.audit.emit = claim_in_the_gap
        self.apply(plan)
        running = f"plan {plan['id']} is still running; wait for it to finish (librenms_plans shows its status)"
        self.assertEqual(outcome, [running])
        self.assertEqual(plan["status"], "rolled_back")
        self.assertNotIn("auto_rollback_error", plan["apply"])
        self.assertEqual((self.backend.rows[1]["color"], self.backend.rows[3]["size"]), ("red", 3))
        self.assertEqual(self.store.load(other["id"])["status"], "planned")

    def test_a_refused_claim_drops_its_run_lock_before_the_store_lock(self):
        # Every held run lock counts as a live run: a claim made the moment a refused one let go of the store lock
        # (a failed apply's automatic rollback) must not find the refused plan's lock still held.
        applied = self.apply(self.plan([update(2, size=5)]))
        alive, refused = self.plan([update(3, size=9)]), self.plan([update(1, size=4)])
        self.hold("run", alive["id"])
        seen: List[List[str]] = []
        exclusive = self.store.exclusive

        @contextlib.contextmanager
        def watched(*args: Any, **kwargs: Any) -> Iterator[None]:
            with exclusive(*args, **kwargs):
                try:
                    yield
                finally:
                    seen.append(self.store.running())  # as the next claim would find them

        self.store.exclusive = watched
        self.refusal(self.apply, refused)
        self.refusal(self.rollback, applied["id"])
        self.assertEqual(seen, [[alive["id"]], [alive["id"]]])

    def test_a_run_held_by_another_process_is_not_recovered(self):
        plan = self.plan([update(1, size=4)])
        plan["status"] = "applying"
        self.store.save(plan)
        self.hold("run", plan["id"])
        message = self.refusal(self.rollback, plan["id"])
        self.assertEqual(
            message, f"plan {plan['id']} is still being applied by another process; try again when it finishes"
        )
        self.assertEqual(self.store.load(plan["id"])["status"], "applying")
        self.assertEqual(self.events("run_recovered"), [])

    def test_a_run_of_this_process_is_not_recovered(self):
        plan = self.plan([update(1, size=4)])
        plan["status"] = "applying"
        self.store.save(plan)
        with self.store.run_lock(plan["id"]):
            message = self.refusal(self.rollback, plan["id"])
        self.assertEqual(
            message, f"plan {plan['id']} is still being applied by another process; try again when it finishes"
        )
        self.assertTrue(self.store.run_lock_free(plan["id"]))

    def test_apply_is_refused_while_the_plans_run_lock_is_held(self):
        plan = self.plan([update(1, size=4)])
        self.hold("run", plan["id"])
        message = self.refusal(self.apply, plan)
        self.assertEqual(
            message, f"plan {plan['id']} is still being applied by another process; try again when it finishes"
        )
        self.assertEqual((self.store.load(plan["id"])["status"], self.backend.writes()), ("planned", []))

    def test_one_run_at_a_time(self):
        other = self.plan([update(3, size=9)])
        other["status"] = "applying"
        self.store.save(other)
        plan = self.plan([update(1, size=4)])
        running = f"plan {other['id']} is still running; wait for it to finish (librenms_plans shows its status)"
        release = self.hold("run", other["id"])
        self.assertEqual(self.refusal(self.apply, plan), running)
        self.assertEqual(self.store.load(plan["id"])["status"], "planned")
        release()
        self.assertEqual(self.apply(plan)["status"], "applied")  # a dead run blocks nothing
        release = self.hold("run", other["id"])
        self.assertEqual(self.refusal(self.rollback, plan["id"]), running)
        release()
        self.assertEqual(self.rollback(plan["id"])["status"], "rolled_back")

    def test_a_hand_edited_plan_file_does_not_block_every_run(self):
        edited = self.plan([update(3, size=9)])
        edited.update(id="../elsewhere", status="applying")
        (self.store.directory / "lnp-20261028T000000Z-0000.json").write_text(json.dumps(edited), encoding="utf-8")
        self.assertEqual(self.apply(self.plan([update(1, size=4)]))["status"], "applied")


class Preflight(ExecutorCase):
    def test_only_a_planned_plan_applies(self):
        plan = self.apply(self.plan([update(1, size=4)]))
        self.assertEqual(
            self.refusal(self.apply, plan),
            f"plan {plan['id']} is applied; only a 'planned' plan can be applied (build a new plan with librenms_plan)",
        )

    def test_the_status_is_read_again_under_the_lock(self):
        plan = self.plan([update(1, size=4)])
        stale = copy.deepcopy(plan)
        self.apply(plan)
        self.assertEqual(self.refusal(self.apply, stale), f"plan {plan['id']} is applied; refusing to apply twice")
        self.assertEqual(self.backend.writes(), ["PATCH widgets/1"])

    def test_max_plan_age(self):
        plan = self.plan([update(1, size=4)])
        plan["created_at"] = (datetime.now(timezone.utc) - timedelta(hours=30)).isoformat().replace("+00:00", "Z")
        self.assertEqual(
            self.refusal(self.apply, plan), "plan is 30.0h old; max_plan_age_hours is 24. Re-run librenms_plan."
        )
        for stamp in ("yesterday", None, 20261028):
            plan["created_at"] = stamp
            self.assertEqual(self.refusal(self.apply, plan), "plan has no valid created_at stamp")
        self.assertEqual(self.backend.writes(), [])

    def test_the_librenms_url_must_match(self):
        plan = self.plan([update(1, size=4)])
        other = self.client_mod.LibreNMSClient("https://other.test", TOKEN, session=self.backend)
        self.assertEqual(
            self.refusal(self.apply, plan, other),
            "plan was built against https://librenms.test but LIBRENMS_URL is now https://other.test",
        )
        plan["librenms_url"] = ""
        self.assertEqual(
            self.refusal(self.apply, plan), f"plan {plan['id']} does not record which LibreNMS it was built against"
        )
        plan["librenms_url"] = "https://librenms.test/"
        self.assertEqual(self.apply(plan)["status"], "applied")

    def test_the_gates_are_checked_again(self):
        self.install(Widget("service"))
        self.install(Widget("device"))
        settings_key = "plugins.entries.librenms.settings"
        cases = (
            ({"op": "delete", "resource": "widget", "id": 2}, "allow_delete", "delete operations are disabled"),
            ({"op": "update", "resource": "service", "id": 2, "data": {"size": 4}}, "allow_services",
             "service operations are disabled because a service runs a Nagios plugin"),
            (create("dev-new", "device"), "allow_device_add", "adding a device makes LibreNMS probe a host"),
            ({"op": "update", "resource": "device", "id": 1, "data": {"overwrite_ip": "192.0.2.9"}}, "allow_device_add",
             "retargeting a device changes which host LibreNMS polls"),
        )  # fmt: skip
        for operation, key, message in cases:
            with self.subTest(key=key, op=operation["op"]):
                plan = self.plan([update(3, size=8), operation])
                setattr(self.settings, key, False)
                for dry_run in (False, True):
                    refused = self.refusal(self.apply, plan, dry_run=dry_run)
                    self.assertTrue(refused.startswith(f"plan step [1] is not allowed: {message}"), refused)
                    self.assertIn(f"{settings_key}.{key}: true", refused)
                setattr(self.settings, key, True)
        self.assertEqual(self.backend.writes(), [])
        self.assertEqual(self.events("apply_started"), [])


class Approved(ExecutorCase):
    """``approved_digest``: the plan under the claim must be the plan the approval prompt showed, whatever the
    handler loaded before it."""

    def digest(self, plan_id: str) -> str:
        return self.store_mod.content_digest(self.store.load(plan_id))

    def edit(self, plan_id: str, change: Callable[[Dict[str, Any]], Any]) -> None:
        plan = self.store.load(plan_id)
        change(plan)
        self.store.save(plan)

    def changed(self, function: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        with self.assertRaises(self.executor.PlanChanged) as caught:
            function(*args, **kwargs)
        return caught.exception

    def test_an_apply_runs_only_the_plan_the_prompt_showed(self):
        plan = self.plan([update(1, size=4)])
        shown = self.digest(plan["id"])
        loaded = self.store.load(plan["id"])  # what the handler loads once the person said yes
        self.edit(plan["id"], lambda p: p["steps"][0]["payload"].update(size=99))  # and then the file changes
        refused = self.changed(self.apply, loaded, approved_digest=shown)
        self.assertEqual(
            str(refused),
            f"plan {plan['id']} changed after the approval prompt showed it, so the approval does not cover it; "
            "nothing was applied. Show the user the plan as it is now (librenms_plans with this plan_id) and call "
            "librenms_apply again only if they say yes to it",
        )
        self.assertIsInstance(refused, self.executor.ExecutionRefused)
        self.assertEqual((refused.approved, refused.found), (shown, self.digest(plan["id"])))
        self.assertEqual((self.backend.writes(), self.events("apply_started")), ([], []))
        self.assertEqual(self.store.load(plan["id"])["status"], "planned")
        self.assertTrue(self.store.run_lock_free(plan["id"]))  # the refused claim let go of the run lock
        # as it was shown, it applies: a dry run in between (a check, a new updated_at) changes nothing that runs
        self.edit(plan["id"], lambda p: p["steps"][0]["payload"].update(size=4))
        self.apply(self.store.load(plan["id"]), dry_run=True)
        self.assertEqual(self.apply(loaded, approved_digest=shown)["status"], "applied")
        self.assertEqual(self.backend.rows[1]["size"], 4)
        # applied once, it is refused as before, whatever digest is given
        self.assertEqual(
            self.refusal(self.apply, loaded, approved_digest=shown),
            f"plan {plan['id']} is applied; only a 'planned' plan can be applied (build a new plan with librenms_plan)",
        )

    def test_another_plan_saved_under_the_same_id_is_refused(self):
        plan = self.plan([update(1, size=4)])
        shown = self.digest(plan["id"])
        (self.store.directory / f"{plan['id']}.json").unlink()
        again = self.build([update(1, size=5)])
        again["id"] = plan["id"]
        self.store.create(again)
        self.changed(self.apply, self.store.load(plan["id"]), approved_digest=shown)
        self.assertEqual(self.backend.writes(), [])

    def test_a_rollback_runs_only_the_journal_the_prompt_showed(self):
        plan = self.apply(self.plan([update(1, color="green"), update(2, size=9)]))
        shown = self.digest(plan["id"])
        # what an entry's rollback writes, changed after the prompt: the colour it restores
        self.edit(plan["id"], lambda p: p["journal"][0]["inverse"]["data"].update(color="black"))
        refused = self.changed(self.rollback, plan["id"], approved_digest=shown)
        self.assertIn("nothing was reverted. Show the user what its rollback reverts as it is now", str(refused))
        self.assertEqual(self.store.load(plan["id"])["status"], "applied")
        self.assertEqual(self.backend.writes(), ["PATCH widgets/1", "PATCH widgets/2"])  # the apply's own
        self.assertEqual(self.events("rollback_started"), [])
        self.assertTrue(self.store.run_lock_free(plan["id"]))
        self.edit(plan["id"], lambda p: p["journal"][0]["inverse"]["data"].update(color="red"))
        self.assertEqual(self.rollback(plan["id"], approved_digest=shown)["status"], "rolled_back")
        self.assertEqual((self.backend.rows[1]["color"], self.backend.rows[2]["size"]), ("red", 2))

    def test_what_runs_is_the_plan_the_claim_digested_whole(self):
        # the handler's own load (here with steps, or a journal) never fills in a key the file under the claim lacks:
        # the prompt showed that file ("nothing to change", "0 pending entries"), so that is all that may run
        plan = self.plan([update(1, size=4)])
        loaded = self.store.load(plan["id"])
        self.edit(plan["id"], lambda p: (p.pop("steps"), p.update(summary={})))
        refused = self.refusal(self.apply, loaded, approved_digest=self.digest(plan["id"]))
        self.assertEqual(refused, f"plan {plan['id']} has no list of steps; build a new plan with librenms_plan")
        self.assertEqual((self.backend.writes(), self.events("apply_started")), ([], []))
        self.assertTrue(self.store.run_lock_free(plan["id"]))
        self.assertNotIn("steps", self.store.load(plan["id"]))  # and the refused claim saved nothing
        applied = self.apply(self.plan([update(1, color="green"), update(2, size=9)]))
        loaded = self.store.load(applied["id"])  # with the journal of the two writes
        self.edit(applied["id"], lambda p: p.pop("journal"))
        shown = self.digest(applied["id"])
        done = self.executor.rollback_plan(self.client, loaded, self.store, self.settings, approved_digest=shown)
        self.assertEqual((done["rollback"]["entries"], "journal" in done), (0, False))
        self.assertEqual(self.backend.writes(), ["PATCH widgets/1", "PATCH widgets/2"])  # the apply's own
        self.assertEqual((self.backend.rows[1]["color"], self.backend.rows[2]["size"]), ("green", 9))

    def test_a_file_that_holds_another_id_by_the_claim_is_refused(self):
        # every save of the run would go to the file that id names: an apply, a rollback and a dry run alike
        plan = self.plan([update(1, size=4)])
        other = self.plan([update(2, size=8)])
        loaded = self.store.load(plan["id"])
        path = self.store.directory / f"{plan['id']}.json"
        path.write_text(json.dumps({**loaded, "id": other["id"]}), encoding="utf-8")
        for dry_run, done in ((False, "applied"), (True, "checked")):
            self.assertEqual(
                self.refusal(self.apply, copy.deepcopy(loaded), dry_run=dry_run),
                f"plan file {plan['id']} no longer holds plan {plan['id']} (it was edited by hand); nothing was {done}",
            )
        self.assertTrue(self.store.run_lock_free(plan["id"]))
        applied = self.apply(self.store.load(other["id"]))
        loaded = self.store.load(other["id"])
        path = self.store.directory / f"{other['id']}.json"
        path.write_text(json.dumps({**loaded, "id": plan["id"]}), encoding="utf-8")
        self.assertIn(
            "nothing was reverted", self.refusal(self.executor.rollback_plan, self.client, loaded, self.store)
        )
        self.assertEqual(self.backend.writes(), ["PATCH widgets/2"])  # the apply's own
        self.assertEqual((self.store.load(other["id"])["status"], applied["status"]), ("applied", "applied"))
        self.assertEqual(self.store.load(plan["id"])["status"], "planned")

    def test_the_preflight_is_checked_again_on_what_the_claim_read(self):
        # a step added to the file after the handler's load is gated like the others, whatever the approval
        self.settings.allow_delete = True
        steps = self.build([update(1, size=4), {"op": "delete", "resource": "widget", "id": 2}])["steps"]
        self.settings.allow_delete = False
        plan = self.plan([update(1, size=4)])
        loaded = self.store.load(plan["id"])
        self.edit(plan["id"], lambda p: p.update(steps=steps))
        refused = self.refusal(self.apply, loaded, approved_digest=self.digest(plan["id"]))
        self.assertTrue(refused.startswith("plan step [1] is not allowed: delete operations are disabled"), refused)
        self.edit(plan["id"], lambda p: p.update(librenms_url="https://other.test", steps=loaded["steps"]))
        self.assertEqual(
            self.refusal(self.apply, loaded),
            "plan was built against https://other.test but LIBRENMS_URL is now https://librenms.test",
        )
        self.assertEqual((self.backend.writes(), self.store.load(plan["id"])["status"]), ([], "planned"))
        applied = self.apply(self.plan([update(1, size=4)]))
        loaded = self.store.load(applied["id"])
        self.edit(applied["id"], lambda p: p.update(librenms_url="https://other.test"))
        self.assertEqual(
            self.refusal(self.executor.rollback_plan, self.client, loaded, self.store),
            "plan was applied against https://other.test but LIBRENMS_URL is now https://librenms.test",
        )
        self.assertEqual(self.backend.writes(), ["PATCH widgets/1"])  # the apply's own

    def test_a_rollback_asked_about_while_the_apply_ran_is_refused_once_it_wrote_more(self):
        plan = self.apply(self.plan([update(1, color="green"), update(2, size=9)]))
        self.edit(plan["id"], lambda p: p.update(status="applying", journal=p["journal"][:1]))
        shown = self.digest(plan["id"])  # the prompt showed the one entry a run still going had journaled
        self.store.save(plan)  # the run journaled the second and finished
        self.changed(self.rollback, plan["id"], approved_digest=shown)
        self.assertEqual(self.store.load(plan["id"])["status"], "applied")
        self.assertEqual((self.backend.rows[1]["color"], self.backend.rows[2]["size"]), ("green", 9))


class DryRun(ExecutorCase):
    def test_a_dry_run_checks_every_step_and_writes_nothing(self):
        plan = self.plan([update(1, size=4), update(2, size=9), update(3, color="blue")])
        self.backend.rows[2]["size"] = 5
        self.backend.rows[3]["size"] = 6  # a noop has nothing to check
        result = self.apply(plan, dry_run=True)
        self.assertEqual((result["status"], result["journal"]), ("planned", []))
        [check] = result["checks"]
        self.assertEqual(check["conflicts"], [{"index": 1, "error": "widget #2 changed since planning (size: 2 -> 5)"}])
        self.assertEqual(self.store.load(plan["id"])["checks"], result["checks"])
        self.assertEqual(self.backend.writes(), [])
        self.assertFalse((self.store.directory / f"{plan['id']}.run").exists())  # no run lock either
        self.backend.rows[2]["size"] = 2
        result = self.apply(result, dry_run=True)
        self.assertEqual([c["conflicts"] for c in result["checks"]][1:], [[]])
        self.assertEqual(
            [(e["conflicts"], e["applicable"]) for e in self.events("plan_checked")], [(1, False), (0, True)]
        )
        self.assertEqual(self.apply(result)["status"], "applied")

    def test_a_check_that_cannot_read_is_a_conflict(self):
        plan = self.plan([update(1, size=4), update(2, size=9)])
        self.backend.fail("GET", r"widgets/2", 500)
        [conflict] = self.apply(plan, dry_run=True)["checks"][0]["conflicts"]
        self.assertEqual(conflict["index"], 1)
        self.assertTrue(conflict["error"].startswith("precondition check failed: GET /api/v0/widgets/2 -> HTTP 500"))

    def test_the_checks_run_outside_the_store_lock(self):
        plan = self.plan([update(1, size=4)])
        free = []

        def probe(_step):
            def other_thread():
                taken = self.store.lock.acquire(blocking=False)
                free.append(taken)
                if taken:
                    self.store.lock.release()

            thread = threading.Thread(target=other_thread)
            thread.start()
            thread.join(5)

        self.widgets.before_check = probe
        self.apply(plan, dry_run=True)
        self.assertEqual(free, [True])

    def test_a_check_is_discarded_when_the_plan_moved_on(self):
        plan = self.plan([update(1, size=4)])

        def applied_elsewhere(_step):
            moved = self.store.load(plan["id"])
            moved["status"] = "applied"
            self.store.save(moved)

        self.widgets.before_check = applied_elsewhere
        result = self.apply(plan, dry_run=True)
        self.assertEqual(result["status"], "applied")
        self.assertNotIn("checks", result)
        self.assertNotIn("checks", self.store.load(plan["id"]))
        self.assertEqual(self.events("plan_checked"), [])


class Audit(ExecutorCase):
    def test_the_events_of_a_failed_apply_and_its_rollback(self):
        actor = {"kind": "model", "via": "tool", "platform": "signal"}
        plan = self.plan([update(1, color="green"), update(3, color="blue"), update(2, size=9)])
        self.backend.fail("PATCH", r"widgets/2", 400)
        self.apply(plan, actor=actor)
        self.assertEqual(
            self.names(),
            ["apply_started", "step_done", "step_skipped", "step_failed", "eventlog_linked", "apply_finished",
             "rollback_started", "revert_reverted", "eventlog_linked", "rollback_finished"],
        )  # fmt: skip
        events = self.events()
        for event in events:
            self.assertEqual(
                (event["plan_id"], event["librenms_url"], event["actor"]), (plan["id"], self.client.base_url, actor)
            )
        started, done, skipped, failed, linked, finished, rb_started, reverted, rb_linked, rb_finished = events
        self.assertEqual(
            (started["steps"], started["summary"], started["rollback_on_failure"]),
            (3, {"create": 0, "update": 2, "delete": 0, "action": 0, "noop": 1}, True),
        )
        self.assertEqual(
            {k: done[k] for k in ("index", "action", "resource", "object_id", "label", "status", "http_status")},
            {"index": 0, "action": "update", "resource": "widget", "object_id": 1, "label": "w1", "status": "done",
             "http_status": 200},
        )  # fmt: skip
        self.assertEqual(done["request"]["method"], "PATCH")
        self.assertEqual((skipped["index"], skipped["status"]), (1, "skipped"))
        self.assertEqual(
            (failed["index"], failed["status"], failed["http_status"], failed["error"]),
            (2, "failed", 400, "PATCH /api/v0/widgets/2 -> HTTP 400: forced failure"),
        )
        self.assertNotIn("wrote", failed)
        self.assertEqual(
            (linked["phase"], linked["linked"], linked["devices"], linked["events"]), ("apply", True, 1, 1)
        )
        self.assertEqual(
            {k: finished[k] for k in ("outcome", "status", "failed_step", "failure_kind", "done")},
            {"outcome": "failed", "status": "failed", "failed_step": 2, "failure_kind": "error", "done": 1},
        )
        self.assertEqual(
            (rb_started["entries"], rb_started["force"], rb_started["reason"]),
            (1, False, "automatic after failure at step 2"),
        )
        self.assertEqual((reverted["index"], reverted["status"], reverted["http_status"]), (0, "reverted", 200))
        self.assertEqual(rb_linked["phase"], "rollback")
        self.assertEqual(
            {k: rb_finished[k] for k in ("status", "reverted", "conflict", "failed", "irreversible", "skipped")},
            {"status": "rolled_back", "reverted": 1, "conflict": 0, "failed": 0, "irreversible": 0, "skipped": 0},
        )

    def test_a_conflict_event(self):
        plan = self.plan([update(2, size=9)])
        self.backend.rows[2]["size"] = 5
        self.apply(plan)
        [conflict] = self.events("step_conflict")
        self.assertEqual(
            (conflict["index"], conflict["status"], conflict["error"]),
            (0, "conflict", "widget #2 changed since planning (size: 2 -> 5)"),
        )
        self.assertEqual(self.names(), ["apply_started", "step_conflict", "apply_finished"])


class Eventlog(ExecutorCase):
    def test_rows_written_during_a_run_are_linked(self):
        plan = self.apply(self.plan([update(1, color="green"), update(3, size=7)]))
        eventlog = plan["apply"]["eventlog"]
        self.assertEqual(
            eventlog,
            {
                "linked": True,
                "devices": {
                    "2": [
                        {"event_id": 7, "datetime": "2026-10-28 13:00:01", "type": "system", "message": "w1 updated"}
                    ],
                    "3": [
                        {"event_id": 8, "datetime": "2026-10-28 13:00:02", "type": "system", "message": "w3 updated"}
                    ],
                },
            },
        )  # the seeded rows (up to #6) were there before
        self.assertEqual([e["eventlog_ids"] for e in plan["journal"]], [[7], [8]])
        reads = [c["params"] for c in self.fake.calls if c["path"] == "logs/eventlog/2"]
        self.assertEqual(
            reads, [{"sortorder": "DESC", "limit": "50"}, {"from": "7", "sortorder": "ASC", "limit": "200"}]
        )
        plan = self.rollback(plan["id"])
        self.assertEqual([e["revert_eventlog_ids"] for e in plan["journal"]], [[10], [9]])
        self.assertEqual([e["eventlog_ids"] for e in plan["journal"]], [[7], [8]])
        self.assertEqual(plan["rollback"]["eventlog"]["devices"]["2"][0]["message"], "w1 updated")

    def test_a_device_the_plan_created_is_read_from_its_first_row(self):
        self.install(Widget("device"))
        self.backend.devices = True  # widget #4 is LibreNMS device #4, which has no eventlog rows yet
        plan = self.apply(self.plan([create("dev-new", "device")]))
        self.assertEqual(
            plan["apply"]["eventlog"]["devices"],
            {"4": [{"event_id": 7, "datetime": "2026-10-28 13:00:01", "type": "system", "message": "dev-new created"}]},
        )
        reads = [(c["path"], c["params"].get("from")) for c in self.fake.calls if c["path"].startswith("logs/eventlog")]
        self.assertEqual(reads, [("logs/eventlog/4", "1")])

    def test_an_unreadable_eventlog_is_recorded_and_never_fatal(self):
        self.fake.fail_on("GET", r"logs/eventlog/2", 500)
        plan = self.apply(self.plan([update(1, color="green")]))
        self.assertEqual(plan["status"], "applied")
        eventlog = plan["apply"]["eventlog"]
        self.assertEqual((eventlog["linked"], eventlog["status"]), (False, 500))
        self.assertIn("HTTP 500", eventlog["error"])
        self.assertNotIn("eventlog_ids", plan["journal"][0])
        [event] = self.events("eventlog_linked")
        self.assertEqual((event["phase"], event["linked"], event["http_status"]), ("apply", False, 500))

    def test_a_failure_after_the_run_is_recorded_too(self):
        plan = self.plan([update(1, color="green")])
        self.backend.on_write = lambda method, path: self.fake.fail_on("GET", r"logs/eventlog/2", 404)
        self.apply(plan)  # the baseline was read before the write; the link after it fails
        self.assertEqual(plan["status"], "applied")
        eventlog = plan["apply"]["eventlog"]
        self.assertEqual((eventlog["linked"], eventlog["status"]), (False, 404))
        self.assertNotIn("eventlog_ids", plan["journal"][0])

    def test_linking_can_be_turned_off(self):
        self.settings.link_eventlog = False
        plan = self.apply(self.plan([update(1, color="green")]))
        plan = self.rollback(plan["id"])
        self.assertNotIn("eventlog", plan["apply"])
        self.assertNotIn("eventlog", plan["rollback"])
        self.assertEqual([c for c in self.fake.calls if c["path"].startswith("logs/")], [])
        self.assertNotIn("eventlog_linked", self.names())


class Rendering(ExecutorCase):
    def test_render_journal(self):
        plan = self.plan([action("maintenance", 1, duration="1:00"), action("discover", 3), create("w4"),
                          update(2, size=9)])  # fmt: skip
        self.backend.fail("PATCH", r"widgets/2", 400)
        self.apply(plan)
        error = "PATCH /api/v0/widgets/2 -> HTTP 400: forced failure"
        self.assertEqual(
            self.executor.render_journal(plan),
            "\n".join(
                [
                    f"Plan {plan['id']} (partially_rolled_back)",
                    f"Applied: {timefmt.local(plan['apply']['started_at'])} by unknown",
                    f"Apply FAILED at step 3: {error}",
                    '[0] maintenance widget #1 "w1" -> done | rollback none: irreversible (maintenance cannot be ended '
                    "through the API)",
                    '[1] discover    widget #3 "w3" -> done | rollback not_needed: skipped (discovery changes nothing)',
                    '[2] create      widget #4 "w4" -> done | rollback exact: reverted',
                    f'[3] update      widget #2 "w2" -> failed: {error}',
                    f"Rolled back: {timefmt.local(plan['rollback']['started_at'])} by unknown",
                    "Rollback: 1 reverted, 0 conflicts, 0 failed, 1 irreversible, 1 skipped "
                    "(automatic after failure at step 3)",
                ]
            ),
        )

    def test_a_re_created_object_shows_its_new_id(self):
        plan = self.apply(self.plan([{"op": "delete", "resource": "widget", "id": 2}]))
        self.rollback(plan["id"])
        self.assertIn(
            '[0] delete      widget #2 "w2" -> done | rollback lossy: reverted (re-created as #4)',
            self.executor.render_journal(self.store.load(plan["id"])).splitlines(),
        )

    def test_free_text_in_the_journal_stays_on_its_line(self):
        forged = '\n[1] update      widget #2 "w2" -> done | rollback exact: reverted'
        plan = self.plan([update(1, size=4), update(2, size=9)])
        self.backend.fail("PATCH", r"widgets/2", 400)
        self.apply(plan)
        plan["journal"][0]["label"] += forged  # names and errors come from LibreNMS
        plan["journal"][0]["revert"] = {"note": "a note" + forged}
        plan["journal"][1]["error"] += forged
        plan["apply"]["failure"]["error"] += forged
        plan["apply"]["auto_rollback_error"] = "refused" + forged
        plan["apply"]["actor"] = {"kind": "model", "via": "tool", "user_name": "eve" + forged}
        plan["rollback"]["reason"] += forged
        lines = self.executor.render_journal(plan).splitlines()
        self.assertEqual(len(lines), 8)
        self.assertEqual([line[:3] for line in lines if line.startswith("[")], ["[0]", "[1]"])
        escaped = forged.replace("\n", "\\n")
        self.assertTrue(lines[1].endswith(f" by model via tool for eve{escaped}"), lines[1])
        self.assertEqual(lines[3], f"Automatic rollback refused: refused{escaped}")
        self.assertEqual(
            lines[4], f'[0] update      widget #1 "w1{escaped}" -> done | rollback exact: reverted (a note{escaped})'
        )
        self.assertTrue(lines[-1].endswith(f"(automatic after failure at step 1{escaped})"), lines[-1])

    def test_a_planned_plan_has_an_empty_journal(self):
        plan = self.plan([update(1, size=4)])
        self.assertEqual(self.executor.render_journal(plan), f"Plan {plan['id']} (planned)")

    def test_a_conflicting_revert_shows_its_error(self):
        plan = self.apply(self.plan([update(1, color="green")]))
        self.backend.rows[1]["size"] = 5
        self.rollback(plan["id"])
        lines = self.executor.render_journal(self.store.load(plan["id"])).splitlines()
        self.assertIn(
            '[0] update      widget #1 "w1" -> done | rollback exact: conflict (widget #1 was modified after apply '
            "(size: 1 -> 5); use force to overwrite)",
            lines,
        )
        self.assertEqual(lines[-1], "Rollback: 0 reverted, 1 conflicts, 0 failed, 0 irreversible, 0 skipped")


if __name__ == "__main__":
    unittest.main()
