"""Apply a plan step by step with a persisted journal, and roll a plan back from that journal.

Guarantees the executor enforces on every run:

* A plan applies at most once, only against the LibreNMS it was built for, only while it is fresh and only while the
  operator's gates still allow every step: ``planned -> applying`` is flipped under the store lock.
* A call a person approved runs only the plan they were shown: under the claim, the plan's content digest must be
  the one the approval prompt showed (``approved_digest``), for an apply and a rollback alike. What runs is the plan
  as the claim read it, whole (no key kept from an earlier read), from the file its id names, and the preflight is
  checked again on it.
* One run at a time. A run holds its plan's run lock from the claim to its last save, and no apply or rollback
  starts while another plan's run is alive. A refused claim drops the run lock it took before the store lock. A plan left ``applying`` or ``rolling_back`` whose run lock is free
  belongs to a run that died; rollback recovers it.
* Write-ahead journal: a step's entry is saved as ``running`` before its first request, so a run that dies mid-write
  leaves a trace that rollback treats as "may have written". A revert saves its progress (``revert_progress``) before
  a write it must not repeat, so a rollback that resumes after a dead one adopts what that run created.
* Every step re-checks the state the planner saw and a conflict stops the run like an error does. Every write is
  verified by its resource, and a failure after LibreNMS may have changed something is journaled with its inverse
  (``wrote: true``), so rollback reverts it too. LibreNMS may still be carrying out a write whose answer was lost
  until the entry's ``settles_at``: a rollback before then that finds it not done leaves it pending.
* On failure the steps that wrote are reverted in reverse order (unless ``rollback_on_failure`` is off), still under
  the apply's run lock; the outcome of every revert is journaled.
* Rollback later refuses to clobber a change somebody made after the apply (``force`` overrides). It never asks the
  operator's gates: undoing a write must stay possible after a gate is closed.
"""

from __future__ import annotations

import contextlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterator, List

from . import audit, timefmt
from .client import LibreNMSClient, LibreNMSError, new_error_id, path
from .planner import gate_errors
from .redact import clip, one_line
from .resources import PartialWrite, Resource, StepError, get_resource, settles_at
from .settings import Settings, get_settings
from .store import IN_FLIGHT, PlanStore, RunLockBusy, content_digest, now_iso

logger = logging.getLogger(__name__)

APPLYABLE = ("planned",)
ROLLBACKABLE = ("applied", "failed", "partially_rolled_back")
REVERT_STATUSES = ("reverted", "conflict", "failed", "irreversible", "skipped")
_SETTLED = ("reverted", "skipped", "irreversible")  # a revert that is never tried again
_UNDONE = ("reverted", "skipped")
_ENTRY_KEYS = ("index", "action", "resource", "object_id", "label", "parent_id", "inverse_kind")
_TARGET_KEYS = ("index", "action", "resource", "object_id", "label")
EVENTLOG_BASELINE_ROWS = 50
EVENTLOG_LINK_ROWS = 200
EVENTLOG_MESSAGE_CHARS = 300  # as escaped (redact.clip): what the model reads of a linked row's message


class ExecutionRefused(Exception):
    """Preflight or the claim rejected the request (wrong status, stale plan, other LibreNMS, a gate, a run in
    progress ...). Nothing was written."""


class PlanChanged(ExecutionRefused):
    """The plan under the claim is not the one the approval prompt showed: its :func:`store.content_digest` is
    *found*, the prompt's was *approved*."""

    def __init__(self, message: str, approved: str, found: str) -> None:
        super().__init__(message)
        self.approved = approved
        self.found = found


def _emit(event: str, plan: Dict[str, Any], actor: Dict[str, Any] | None, **details: Any) -> None:
    audit.emit(event, plan_id=plan.get("id"), actor=actor, librenms_url=plan.get("librenms_url"), **details)


def _resource(name: Any) -> Resource:
    try:
        return get_resource(name)
    except KeyError:
        raise StepError(f"this plugin has no resource {name!r}") from None


def _error_text(exc: BaseException) -> str:
    """What the journal says about *exc*: the message of the errors resources and the client raise (scrubbed when
    they were made); for anything else an error id, with the detail only in the log."""
    if isinstance(exc, (LibreNMSError, StepError, PartialWrite)):
        return str(exc) or type(exc).__name__
    error_id = new_error_id()
    logger.error("librenms executor: unexpected %s (%s)", type(exc).__name__, error_id, exc_info=exc)
    return f"unexpected error {error_id} ({type(exc).__name__}); see the Hermes log"


def _new_entry(step: Dict[str, Any], status: str) -> Dict[str, Any]:
    entry = {key: step.get(key) for key in _ENTRY_KEYS}
    entry.update(status=status, at=now_iso())
    return entry


def _finish(entry: Dict[str, Any], status: str, result: Dict[str, Any] | None = None, **extra: Any) -> None:
    """Settle a write-ahead entry in place with what ``execute`` returned (or a PartialWrite carried)."""
    entry.update(status=status, at=now_iso())
    if result is not None:
        if result.get("object_id") is not None:  # a create learns its id here
            entry["object_id"] = result["object_id"]
        entry.update(
            inverse=result.get("inverse"),
            after_state=result.get("after_state"),
            notes=list(result.get("notes") or []),
        )
        if result.get("settles_at"):  # the answer was lost: LibreNMS may still be carrying the write out
            entry["settles_at"] = result["settles_at"]
    entry.update(extra)


def _last_request(requests: List[Dict[str, Any]]) -> Dict[str, Any] | None:
    """The call that best stands for a step: its last write, else its last read (a verification GET says less)."""
    writes = [call for call in requests if call.get("method") != "GET"]
    return (writes or requests or [None])[-1]


def _record_requests(entry: Dict[str, Any], requests: List[Dict[str, Any]], prefix: str = "") -> None:
    entry[f"{prefix}requests"] = requests
    entry[f"{prefix}request"] = _last_request(requests)


def _target(entry: Dict[str, Any]) -> Dict[str, Any]:
    """What a step or revert event says about the object it concerns."""
    return {key: entry.get(key) for key in _TARGET_KEYS}


def _wrote(entry: Dict[str, Any]) -> bool:
    """Whether LibreNMS may hold this entry's write: done, outcome unknown, or failed after a write."""
    return entry.get("status") in ("done", "unknown") or bool(entry.get("wrote"))


def pending_entries(plan: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The journal entries a rollback would revert, in journal order."""
    return [e for e in plan.get("journal") or [] if _wrote(e) and e.get("revert_status") not in _SETTLED]


# -- preflight -----------------------------------------------------------------------------------


def _created(plan: Dict[str, Any]) -> datetime | None:
    stamp = plan.get("created_at")
    return timefmt.parse_utc(stamp) if isinstance(stamp, str) else None


def _same_librenms(plan: Dict[str, Any], client: LibreNMSClient, verb: str) -> None:
    url = str(plan.get("librenms_url") or "").rstrip("/")
    if not url:
        raise ExecutionRefused(f"plan {plan['id']} does not record which LibreNMS it was {verb} against")
    if url != client.base_url:
        raise ExecutionRefused(
            f"plan was {verb} against {plan['librenms_url']} but LIBRENMS_URL is now {client.base_url}"
        )


def preflight_apply(plan: Dict[str, Any], client: LibreNMSClient, settings: Settings) -> None:
    """Refuse *plan* unless it may run now: planned, a list of steps, fresh, built against this LibreNMS and every
    step allowed by the operator's gates. Checked before the claim and again, under it, on the plan as re-read."""
    if plan.get("status") not in APPLYABLE:
        raise ExecutionRefused(
            f"plan {plan['id']} is {plan.get('status')}; only a 'planned' plan can be applied "
            "(build a new plan with librenms_plan)"
        )
    created = _created(plan)
    if created is None:
        raise ExecutionRefused("plan has no valid created_at stamp")
    age = datetime.now(timezone.utc) - created
    if age > timedelta(hours=settings.max_plan_age_hours):
        raise ExecutionRefused(
            f"plan is {age.total_seconds() / 3600:.1f}h old; max_plan_age_hours is "
            f"{settings.max_plan_age_hours}. Re-run librenms_plan."
        )
    _same_librenms(plan, client, "built")
    if not isinstance(plan.get("steps"), list):
        raise ExecutionRefused(f"plan {plan['id']} has no list of steps; build a new plan with librenms_plan")
    for step in plan["steps"]:
        if step.get("action") == "noop":
            continue
        refused = gate_errors(step.get("resource"), step.get("action"), settings, step.get("changes"))
        if refused:
            raise ExecutionRefused(f"plan step [{step.get('index')}] is not allowed: {refused[0]}")


def check_step_precondition(client: LibreNMSClient, step: Dict[str, Any]) -> str | None:
    """A conflict message when LibreNMS no longer matches what the planner saw, else None."""
    if step["action"] == "noop":
        return None
    return _resource(step["resource"]).check(client, step)


def check_preconditions(client: LibreNMSClient, plan: Dict[str, Any]) -> List[Dict[str, Any]]:
    conflicts = []
    for step in plan["steps"]:
        try:
            message = check_step_precondition(client, step)
        except Exception as exc:
            message = f"precondition check failed: {_error_text(exc)}"
        if message:
            conflicts.append({"index": step["index"], "error": message})
    return conflicts


# -- claims and locks -----------------------------------------------------------------------------


@contextlib.contextmanager
def _claiming(store: PlanStore) -> Iterator[None]:
    """The store lock under which a run is claimed; a lock held too long by someone else is a refusal."""
    try:
        with store.exclusive(timeout=store.claim_timeout):
            yield
    except TimeoutError as exc:
        raise ExecutionRefused(f"{exc}; another apply or rollback is in progress, try again shortly") from exc


def _hold_run_lock(store: PlanStore, plan_id: str, claim: contextlib.ExitStack) -> None:
    """Take *plan_id*'s run lock into *claim*, the stack of a claim under the store lock. A claim that succeeds moves
    it to the run's stack; one that is refused drops it on its way out, still under the store lock, because every
    held run lock counts as a live run (:func:`_refuse_concurrent`)."""
    try:
        claim.enter_context(store.run_lock(plan_id))
    except RunLockBusy as exc:
        raise ExecutionRefused(
            f"plan {plan_id} is still being applied by another process; try again when it finishes"
        ) from exc


def _reload(store: PlanStore, plan: Dict[str, Any], done: str) -> Dict[str, Any]:
    """*plan* as its file holds it now, read under the claim; *plan* itself when the file is gone. A file that holds
    another id than the one it is named by (edited or copied by hand) is refused: everything the run saves would go
    to that other plan's file. *done* says what did not happen ("applied", "reverted", "checked")."""
    current = store.load(plan["id"])
    if current is None:
        return plan
    if not isinstance(current, dict) or current.get("id") != plan["id"]:
        raise ExecutionRefused(
            f"plan file {plan['id']} no longer holds plan {plan['id']} (it was edited by hand); nothing was {done}"
        )
    return current


def _adopt(plan: Dict[str, Any], current: Dict[str, Any]) -> None:
    """Make *plan* the plan the claim read, key for key: what the claim checked (its status, its content digest, the
    preflight) is all that runs. A key the file no longer holds is dropped, never kept from an earlier read."""
    if current is not plan:
        plan.clear()
        plan.update(current)


def _refuse_changed(plan: Dict[str, Any], approved_digest: str | None, action: str) -> None:
    """Refuse when *plan*, as loaded under the claim, is not the plan the approval prompt showed: its content digest
    is not *approved_digest* (none when no prompt was shown for this call). Checked under the store lock, after the
    last load before the run, so nothing can change the file between this check and the run's first save."""
    if approved_digest is None:
        return
    found = content_digest(plan)
    if found == approved_digest:
        return
    shows = "the plan" if action == "apply" else "what its rollback reverts"
    raise PlanChanged(
        f"plan {plan.get('id')} changed after the approval prompt showed it, so the approval does not cover it; "
        f"nothing was {'applied' if action == 'apply' else 'reverted'}. Show the user {shows} as it is now "
        f"(librenms_plans with this plan_id) and call librenms_{action} again only if they say yes to it",
        approved_digest,
        found,
    )


def _refuse_concurrent(store: PlanStore, plan_id: str) -> None:
    """Refuse while another plan's run is alive: two runs writing the same objects would trip over each other's
    preconditions and rollbacks. A run is alive while it holds its run lock, whatever its plan's status says: a failed
    apply has saved ``failed`` before its automatic rollback claims. A plan left in flight by a dead run does not
    block."""
    for other_id in store.running():
        if other_id != plan_id:
            raise ExecutionRefused(
                f"plan {other_id} is still running; wait for it to finish (librenms_plans shows its status)"
            )


# -- LibreNMS eventlog cross-reference -----------------------------------------------------------------


def _device_ids(records: List[Dict[str, Any]]) -> List[int]:
    """Devices whose eventlog the steps or entries in *records* may write to: the device a device record is about,
    and the owning device of every other record."""
    ids = set()
    for record in records:
        if record.get("resource") == "device" and record.get("object_id") is not None:
            ids.add(record["object_id"])
        if record.get("parent_id") is not None:
            ids.add(record["parent_id"])
    return sorted(ids)


def _event_id(row: Dict[str, Any]) -> int:
    return int(row.get("event_id") or 0)  # a row without a numeric id fails the linking, which is recorded


def _eventlog(client: LibreNMSClient, device_id: int, params: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = client.result(client.get(path("logs", "eventlog", device_id), params), "logs")
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def _not_linked(
    plan: Dict[str, Any], store: PlanStore, phase: str, exc: BaseException, actor: Dict[str, Any] | None
) -> None:
    status = exc.status if isinstance(exc, LibreNMSError) else 0
    error = _error_text(exc)
    plan[phase]["eventlog"] = {"linked": False, "error": error, "status": status}
    store.save(plan)
    _emit("eventlog_linked", plan, actor, phase=phase, linked=False, error=error, http_status=status)


def _eventlog_baseline(
    client: LibreNMSClient,
    plan: Dict[str, Any],
    store: PlanStore,
    phase: str,
    records: List[Dict[str, Any]],
    actor: Dict[str, Any] | None,
    settings: Settings,
) -> Dict[int, int] | None:
    """The newest eventlog id of every device *records* touch, read before the run so that linking afterwards
    picks up only rows written since. LibreNMS orders the log by time alone, so the newest id is the largest of the
    latest rows, not the first. None when linking is off or the read failed (recorded and audited, never fatal)."""
    if not settings.link_eventlog:
        return None
    params = {"sortorder": "DESC", "limit": EVENTLOG_BASELINE_ROWS}
    try:
        return {
            device_id: max((_event_id(row) for row in _eventlog(client, device_id, params)), default=0)
            for device_id in _device_ids(records)
        }
    except Exception as exc:
        _not_linked(plan, store, phase, exc, actor)
        return None


def _link_eventlog(
    client: LibreNMSClient,
    plan: Dict[str, Any],
    store: PlanStore,
    phase: str,
    baseline: Dict[int, int] | None,
    entries: List[Dict[str, Any]],
    actor: Dict[str, Any] | None,
) -> None:
    """Attach the eventlog rows LibreNMS wrote since *baseline* for each device the phase's *entries* wrote to.
    A numeric ``from`` compares event ids, so no clock or time zone is involved; a device the plan created has no
    baseline and is read from its first row. Best effort: a failure is recorded and never fails the run."""
    if baseline is None:
        return
    device_ids = _device_ids(entries)
    if not device_ids:
        return
    found: Dict[int, List[Dict[str, Any]]] = {}
    try:
        for device_id in device_ids:
            after = baseline.get(device_id, 0)
            params = {"from": after + 1, "sortorder": "ASC", "limit": EVENTLOG_LINK_ROWS}
            found[device_id] = [
                {
                    "event_id": _event_id(row),
                    "datetime": row.get("datetime"),
                    "type": row.get("type"),
                    "message": clip(row.get("message"), EVENTLOG_MESSAGE_CHARS),
                }
                for row in _eventlog(client, device_id, params)
                if _event_id(row) > after  # also when a LibreNMS ignores ``from``
            ]
    except Exception as exc:
        _not_linked(plan, store, phase, exc, actor)
        return
    key = "eventlog_ids" if phase == "apply" else "revert_eventlog_ids"
    for entry in entries:
        ids = _device_ids([entry])
        if ids:
            entry[key] = [row["event_id"] for device_id in ids for row in found[device_id]]
    plan[phase]["eventlog"] = {"linked": True, "devices": {str(d): rows for d, rows in found.items()}}
    store.save(plan)
    _emit(
        "eventlog_linked",
        plan,
        actor,
        phase=phase,
        linked=True,
        devices=len(found),
        events=sum(len(rows) for rows in found.values()),
    )


# -- apply ----------------------------------------------------------------------------------------


def _dry_run(
    client: LibreNMSClient, plan: Dict[str, Any], store: PlanStore, actor: Dict[str, Any] | None
) -> Dict[str, Any]:
    """Check every precondition without writing. The checks run outside the store lock (each is a request that can
    take a while, and the lock serialises every claim); the result is recorded only if the plan is still planned."""
    conflicts = check_preconditions(client, plan)
    with _claiming(store):
        current = _reload(store, plan, "checked")
        _adopt(plan, current)
        if current.get("status") not in APPLYABLE:
            return plan
        plan.setdefault("checks", []).append({"at": now_iso(), "conflicts": conflicts, "actor": actor})
        store.save(plan)
    _emit("plan_checked", plan, actor, conflicts=len(conflicts), applicable=not conflicts)
    return plan


def _apply_steps(
    client: LibreNMSClient, plan: Dict[str, Any], store: PlanStore, settings: Settings, actor: Dict[str, Any] | None
) -> Dict[str, Any] | None:
    """Run the steps in order until one conflicts or fails; returns that failure, or None."""
    context = {"plan_id": plan["id"], "settings": settings, "actor": actor}
    for step in plan["steps"]:
        if step["action"] == "noop":
            entry = _new_entry(step, "skipped")
            plan["journal"].append(entry)
            store.save(plan)
            _emit("step_skipped", plan, actor, **_target(entry), status="skipped")
            continue
        client.reset_calls()  # what was read before (claim, eventlog baseline) is not this step's
        try:
            resource = _resource(step["resource"])
            conflict = resource.check(client, step)
        except Exception as exc:
            conflict = f"precondition check failed: {_error_text(exc)}"
        if conflict:
            entry = _new_entry(step, "conflict")
            entry["error"] = conflict
            _record_requests(entry, client.reset_calls())
            plan["journal"].append(entry)
            store.save(plan)
            _emit("step_conflict", plan, actor, **_target(entry), status="conflict", error=conflict)
            return {"index": step["index"], "kind": "conflict", "error": conflict}

        entry = _new_entry(step, "running")
        plan["journal"].append(entry)
        store.save(plan)  # write-ahead: a run that dies from here on leaves an entry rollback acts on
        try:
            _finish(entry, "done", resource.execute(client, step, context))
        except PartialWrite as exc:
            _finish(entry, "failed", exc.entry, error=str(exc), wrote=True)
        except LibreNMSError as exc:
            _finish(entry, "failed", error=str(exc), librenms=exc.to_dict())
        except Exception as exc:
            _finish(entry, "failed", error=_error_text(exc))
        _record_requests(entry, client.reset_calls())
        store.save(plan)
        request = entry["request"] or {}
        fields = {**_target(entry), "status": entry["status"]}  # a create learns its object_id in execute
        if entry["status"] == "done":
            _emit("step_done", plan, actor, **fields, http_status=request.get("status"), request=entry["request"])
            continue
        wrote = {"wrote": True} if entry.get("wrote") else {}
        _emit(
            "step_failed",
            plan,
            actor,
            **fields,
            error=entry["error"],
            http_status=request.get("status"),
            request=entry["request"],
            **wrote,
        )
        return {"index": step["index"], "kind": "error", "error": entry["error"]}
    return None


def apply_plan(
    client: LibreNMSClient,
    plan: Dict[str, Any],
    store: PlanStore,
    settings: Settings,
    *,
    rollback_on_failure: bool = True,
    dry_run: bool = False,
    actor: Dict[str, Any] | None = None,
    approved_digest: str | None = None,
) -> Dict[str, Any]:
    """Apply *plan* in order. Mutates and persists *plan*; returns it. Raises ExecutionRefused when preflight or
    the claim refuses; every LibreNMS error during the run is journaled instead. *approved_digest* is the content
    digest of the plan the approval prompt showed for this call: the claim refuses (:class:`PlanChanged`) a plan
    that no longer has it."""
    preflight_apply(plan, client, settings)
    if dry_run:
        return _dry_run(client, plan, store, actor)

    with contextlib.ExitStack() as running:
        # Claim under the store lock, taking the run lock first, so that no rollback can mistake this run for a
        # dead one and no second apply (gateway vs CLI) can claim the same plan.
        with _claiming(store), contextlib.ExitStack() as claim:
            _hold_run_lock(store, plan["id"], claim)
            current = _reload(store, plan, "applied")
            if current.get("status") not in APPLYABLE:
                raise ExecutionRefused(f"plan {plan['id']} is {current.get('status')}; refusing to apply twice")
            _refuse_changed(current, approved_digest, "apply")
            if current is not plan:  # the file may have changed since the preflight above
                preflight_apply(current, client, settings)
            _refuse_concurrent(store, plan["id"])
            _adopt(plan, current)
            plan["status"] = "applying"
            plan["journal"] = []
            plan["apply"] = {"started_at": now_iso(), "rollback_on_failure": rollback_on_failure, "actor": actor}
            store.save(plan)
            running.enter_context(claim.pop_all())
        _emit(
            "apply_started",
            plan,
            actor,
            steps=len(plan["steps"]),
            summary=plan.get("summary"),
            rollback_on_failure=rollback_on_failure,
        )
        steps = [step for step in plan["steps"] if step["action"] != "noop"]
        baseline = _eventlog_baseline(client, plan, store, "apply", steps, actor, settings)
        failure = _apply_steps(client, plan, store, settings, actor)

        plan["apply"]["finished_at"] = now_iso()
        _link_eventlog(client, plan, store, "apply", baseline, [e for e in plan["journal"] if _wrote(e)], actor)
        done = sum(1 for e in plan["journal"] if e.get("status") == "done")
        if failure is None:
            plan["status"] = "applied"
            plan["apply"]["outcome"] = "applied"
            store.save(plan)
            _emit("apply_finished", plan, actor, outcome="applied", status=plan["status"], done=done)
            return plan

        plan["status"] = "failed"
        plan["apply"].update(outcome="failed", failed_step=failure["index"], failure=failure)
        store.save(plan)
        _emit(
            "apply_finished",
            plan,
            actor,
            outcome="failed",
            status=plan["status"],
            failed_step=failure["index"],
            failure_kind=failure["kind"],
            error=failure["error"],
            done=done,
        )
        pending = pending_entries(plan)
        if rollback_on_failure and pending:
            # Still under this run's lock: rollback_plan takes it again (re-entrant) instead of being refused.
            try:
                rollback_plan(
                    client,
                    plan,
                    store,
                    settings,
                    reason=f"automatic after failure at step {failure['index']}",
                    actor=actor,
                )
            except ExecutionRefused as exc:
                plan["apply"]["auto_rollback_error"] = str(exc)
                store.save(plan)
                _emit("rollback_refused", plan, actor, reason=str(exc), automatic=True, pending=len(pending))
        return plan


# -- rollback -------------------------------------------------------------------------------------


def _recover(plan: Dict[str, Any]) -> List[Any]:
    """Settle what a dead run left in flight: a step that was writing may have written (``unknown``: rollback looks
    before it acts, and LibreNMS may still be carrying that write out until ``settles_at``), and a revert that was
    running is tried again, keeping its ``revert_progress`` so the resource resumes it instead of repeating a write.
    Returns the indexes of those entries."""
    dangling = []
    for entry in plan.get("journal") or []:
        if entry.get("status") == "running":
            entry.update(status="unknown", wrote=True, settles_at=settles_at(timefmt.parse_utc(entry.get("at"))))
            dangling.append(entry.get("index"))
        if entry.get("revert_status") == "running":
            entry["revert_status"] = None
            dangling.append(entry.get("index"))
    return dangling


def _not_rollbackable(plan_id: str, status: Any) -> ExecutionRefused:
    return ExecutionRefused(f"plan {plan_id} is {status}; rollback needs one of {', '.join(ROLLBACKABLE)}")


def _revert_entry(
    client: LibreNMSClient,
    plan: Dict[str, Any],
    store: PlanStore,
    entry: Dict[str, Any],
    force: bool,
    context: Dict[str, Any],
    actor: Dict[str, Any] | None,
) -> str:
    """Undo one journal entry through its resource and journal the outcome; returns the revert status. The resource
    gets ``context["checkpoint"]``: it merges a dict into the entry's ``revert_progress`` and saves the plan, before a
    write a rollback resuming after this one dies must not repeat."""
    entry["revert_status"] = "running"
    store.save(plan)  # write-ahead, as for a step

    def checkpoint(progress: Dict[str, Any]) -> None:
        entry["revert_progress"] = {**(entry.get("revert_progress") or {}), **progress}
        store.save(plan)

    context = {**context, "checkpoint": checkpoint}
    client.reset_calls()
    try:
        status, details = _resource(entry["resource"]).revert(client, entry, force, context)
    except LibreNMSError as exc:
        status, details = "failed", {"error": str(exc), "librenms": exc.to_dict()}
    except Exception as exc:
        status, details = "failed", {"error": _error_text(exc)}
    if status not in REVERT_STATUSES or not isinstance(details, dict):
        status, details = "failed", {"error": f"the {entry['resource']} resource reported no usable rollback outcome"}
    entry.update(revert_status=status, revert_at=now_iso(), revert=details)
    _record_requests(entry, client.reset_calls(), "revert_")
    store.save(plan)
    request = entry["revert_request"] or {}
    _emit(
        f"revert_{status}",
        plan,
        actor,
        **_target(entry),
        status=status,
        error=details.get("error"),
        new_object_id=details.get("new_object_id"),
        http_status=request.get("status"),
        request=entry["revert_request"],
    )
    return status


def rollback_plan(
    client: LibreNMSClient,
    plan: Dict[str, Any],
    store: PlanStore,
    settings: Settings | None = None,
    *,
    force: bool = False,
    reason: str = "",
    actor: Dict[str, Any] | None = None,
    approved_digest: str | None = None,
) -> Dict[str, Any]:
    """Revert every entry that wrote and is not settled yet, in reverse order. Mutates and persists *plan*; returns
    it. A plan left in flight by a dead run is recovered first. Raises ExecutionRefused when the claim refuses, and
    :class:`PlanChanged` when the plan under the claim no longer has *approved_digest*, the content digest of the
    plan the approval prompt showed for this call (its journal included: an apply that went on writing after the
    prompt leaves more to revert than it showed)."""
    settings = settings if settings is not None else get_settings()
    if plan.get("status") not in ROLLBACKABLE + IN_FLIGHT:
        raise _not_rollbackable(plan["id"], plan.get("status"))
    _same_librenms(plan, client, "applied")

    with contextlib.ExitStack() as running:
        with _claiming(store), contextlib.ExitStack() as claim:
            free = store.run_lock_free(plan["id"])
            _hold_run_lock(store, plan["id"], claim)
            current = _reload(store, plan, "reverted")
            previous = current.get("status")
            recovering = previous in IN_FLIGHT
            if recovering and not free:  # this process is running it
                raise ExecutionRefused(
                    f"plan {plan['id']} is still being applied by another process; try again when it finishes"
                )
            if not recovering and previous not in ROLLBACKABLE:
                raise _not_rollbackable(plan["id"], previous)
            _refuse_changed(current, approved_digest, "rollback")
            _same_librenms(current, client, "applied")
            _refuse_concurrent(store, plan["id"])
            _adopt(plan, current)
            dangling = _recover(plan) if recovering else []
            pending = pending_entries(plan)
            journal = plan.get("journal") or []
            if not pending and not recovering and any(_wrote(e) for e in journal):
                irreversible = [e.get("index") for e in journal if e.get("revert_status") == "irreversible"]
                raise ExecutionRefused(
                    f"plan {plan['id']} has nothing left to roll back; irreversible steps: {irreversible}"
                )
            plan["status"] = "rolling_back"
            plan["rollback"] = {
                "started_at": now_iso(),
                "force": force,
                "reason": reason,
                "entries": len(pending),
                "actor": actor,
            }
            if recovering:
                plan["rollback"]["recovered"] = {"previous_status": previous, "dangling_indexes": dangling}
            store.save(plan)
            running.enter_context(claim.pop_all())
        if recovering:
            _emit("run_recovered", plan, actor, previous_status=previous, dangling_indexes=dangling)
        _emit("rollback_started", plan, actor, entries=len(pending), force=force, reason=reason)
        baseline = _eventlog_baseline(client, plan, store, "rollback", pending, actor, settings)

        counts = dict.fromkeys(REVERT_STATUSES, 0)
        steps = {step.get("index"): step for step in plan.get("steps") or []}
        context = {"plan_id": plan["id"], "settings": settings, "actor": actor}
        for entry in reversed(pending):
            # The step lets a resource revert an entry whose outcome is unknown: a dead run journaled no inverse.
            step_context = {**context, "step": steps.get(entry.get("index"))}
            counts[_revert_entry(client, plan, store, entry, force, step_context, actor)] += 1

        plan["rollback"].update(finished_at=now_iso(), **counts)
        written = [e for e in pending if e.get("revert_status") in ("reverted", "failed")]
        _link_eventlog(client, plan, store, "rollback", baseline, written, actor)
        # Over the whole journal: a step left irreversible by an earlier run keeps the plan partially rolled back.
        undone = all(e.get("revert_status") in _UNDONE for e in plan.get("journal") or [] if _wrote(e))
        plan["status"] = "rolled_back" if undone else "partially_rolled_back"
        store.save(plan)
        _emit("rollback_finished", plan, actor, status=plan["status"], force=force, reason=reason, **counts)
        return plan


# -- rendering ------------------------------------------------------------------------------------


def _journal_line(entry: Dict[str, Any]) -> str:
    ident = f" #{entry['object_id']}" if entry.get("object_id") is not None else ""
    label = f' "{one_line(entry["label"])}"' if entry.get("label") not in (None, "") else ""
    line = f"[{entry.get('index')}] {entry.get('action') or '':<11} {entry.get('resource') or ''}{ident}{label}"
    line += f" -> {entry.get('status')}"
    if entry.get("error"):
        line += f": {one_line(entry['error'])}"
    if not _wrote(entry):
        return line
    line += f" | rollback {entry.get('inverse_kind') or 'unknown'}"
    if entry.get("revert_status"):
        line += f": {entry['revert_status']}"
        details = entry.get("revert") or {}
        if details.get("error"):
            line += f" ({one_line(details['error'])})"
        elif details.get("new_object_id") is not None:
            line += f" (re-created as #{details['new_object_id']})"
        elif details.get("note"):
            line += f" ({one_line(details['note'])})"
    return line


def render_journal(plan: Dict[str, Any]) -> str:
    """What happened to each step and to its rollback. Like :func:`planner.render_plan`, every free-text value
    (labels, errors and notes from LibreNMS, who ran it, the reason) is kept on its line with :func:`.redact.one_line`;
    callers still pass the result through ``redact.printable``."""
    lines = [f"Plan {plan['id']} ({plan['status']})"]
    apply = plan.get("apply") or {}
    if apply.get("started_at"):
        by = one_line(audit.describe_actor(apply.get("actor")))
        lines.append(f"Applied: {timefmt.local(apply['started_at'])} by {by}")
    if apply.get("outcome") == "failed":
        failure = apply.get("failure") or {}
        lines.append(f"Apply FAILED at step {failure.get('index')}: {one_line(failure.get('error'))}")
    if apply.get("auto_rollback_error"):
        lines.append(f"Automatic rollback refused: {one_line(apply['auto_rollback_error'])}")
    rollback = plan.get("rollback") or {}
    recovered = rollback.get("recovered")
    if recovered:
        lines.append(
            f"Recovered: the run died while the plan was {recovered.get('previous_status')}; "
            f"entries {recovered.get('dangling_indexes')} were in flight"
        )
    lines += [_journal_line(entry) for entry in plan.get("journal") or []]
    if rollback.get("started_at"):
        by = one_line(audit.describe_actor(rollback.get("actor")))
        lines.append(f"Rolled back: {timefmt.local(rollback['started_at'])} by {by}")
    if "reverted" in rollback:
        lines.append(
            f"Rollback: {rollback.get('reverted', 0)} reverted, {rollback.get('conflict', 0)} conflicts, "
            f"{rollback.get('failed', 0)} failed, {rollback.get('irreversible', 0)} irreversible, "
            f"{rollback.get('skipped', 0)} skipped"
            + (f" ({one_line(rollback['reason'])})" if rollback.get("reason") else "")
        )
    return "\n".join(lines)
