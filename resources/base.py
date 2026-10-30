"""What every LibreNMS resource shares: field specs, planning, preconditions, verified writes and rollback.

LibreNMS has no modification stamps (no ``updated_at``, no ETag), so every comparison here is between normalised
``state()`` dicts: the planner records the state it saw, ``check`` refuses to run when the owned, non-volatile
fields moved, every write is verified by re-reading, and rollback refuses to clobber an edit made after the apply.
A resource module supplies the reads and the requests; the generic create/update/delete logic lives here.

Hook contract for resource modules (override only what differs; call ``super()`` where noted)
--------------------------------------------------------------------------------------------
Attributes: ``name``, ``title`` (messages), ``id_key``/``label_key`` (keys of the raw object and of ``state()``),
``match_keys``, ``fields`` ({name: Field}), ``ops``, ``inverse`` ({op: (kind, explanation)}, kind in INVERSE_KINDS,
one entry per op). Optional: ``natural_key`` (unique name key: every create carries ``exists_check = {key:
value}``), ``identity_keys`` (always compared; ``id_key`` is implied), ``parent_key`` (state key of the owning
device, copied to ``step["parent_id"]``).

Reads (return None / count 0 for a missing object; never raise on 404):
  get(client, object_id, step=None) -> raw object | None   step may be a journal entry (both carry ``parent_id``);
        mask credentials (``redact.mask``) except what rollback must restore (service param)
  find(client, match) -> (count, object | None)   the object (shaped like get()) only when count == 1
  state(client, obj) -> {Field name: normalised value} plus identity; never poller-only data (uptime, status)
  volatile_fields(state) -> set   owned keys the poller may also rewrite; compared only when the step writes them
  label(obj_or_data) -> str   default: ``label_key``, else ``#id``
Planning:
  validate(op, data, settings) -> [errors]   super() checks create/update keys (unknown, read-only, kind, null
        unless ``Field.nullable``, required); add action ops and cross-field rules
  resolve(client, op, data) -> new dict   super() normalises create/update Field values; resolve names -> ids
  _prepare(client, step, data, current, settings) -> data   once the target is known (``current`` = plan-time
        state, None for a create): merge relative changes, refuse with StepError, add ``step["notes"]``
  _plan_action(client, step, data, obj, current, settings) -> step   non-CRUD ops: set ``params``; may make
        the step a noop (``action = "noop"``, ``reason``); may set ``inverse_note``
  _snapshot(client, obj, current) -> dict   what a delete keeps (default: the raw object)
  _exists_check(data, match) -> match | None   a create's precondition (default: natural key, else ``match``)
  _payload(data, record) -> dict   request body for an update of ``data`` (also stored as ``step["payload"]``)
  plan_step / describe may be overridden to post-process the base result (change labels, extra gates)
Execution (send writes with ``client.request(method, path, json=...)``: the base class counts them):
  _create_call(client, step, context) -> new id | None   None: the id is looked up with _create_lookup(step)
  _update_call(client, object_id, data, record, context)   data = {name: normalised value}; also rollback's
        write (record = step on apply, journal entry on rollback)
  _delete_call(client, object_id, record, context)
  _recreate_call(client, entry, context) -> (new id | None, details)   rollback of a delete with a lossy inverse;
        with ``context["resuming"]`` an earlier rollback died after this point and may have created the object:
        adopt it rather than create a second one. ``context["checkpoint"](dict)`` (from the executor) saves the
        dict into the entry's ``revert_progress`` before a write a resumed rollback must not repeat
  _execute_action(client, step, context) -> _entry(...)   ; _revert_action(client, entry, force, context)
  _inverse(step, object_id) -> dict | None   override for actions whose inverse is exact or lossy
  _extra_check(client, step, obj, current) -> conflict | None   apply-time checks beyond state equality
  _revert_create_blocker(client, object_id, entry) -> conflict | None   e.g. devices now use the location
  _create_lookup(step) -> match | None   ;  _expected_after_create(step, after) -> {name: value} to verify
  _secrets(record) -> [str]   sensitive values a step or entry holds (scrubbed from error text)
Hooks raise StepError for a plain failure and may raise PartialWrite themselves. Any other exception once a write
was sent is settled here: re-read, then PartialWrite when LibreNMS changed something or the outcome cannot be known
(the answer was lost, or a gateway answered while LibreNMS may still be working), else the original error. Such a
write carries ``settles_at``: until then, a rollback that finds it not carried out leaves it pending.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Set, Tuple

from .. import diff, redact, timefmt
from ..client import LibreNMSError, is_digits

INVERSE_KINDS = ("exact", "lossy", "none", "not_needed")
CRUD = ("create", "update", "delete")
GATEWAY_STATUSES = (502, 503, 504)
SETTLE_AFTER = timedelta(minutes=10)
# Maintenance, as the device, device group and location routes take it (maintenance_device, maintenance_devicegroup,
# maintenance_location): LibreNMS's MaintenanceBehavior numbers, a duration it splits at ":" and reads with (float),
# and a start Carbon parses as Y-m-d H:i:s. ASCII digits only: PHP reads a numeric string in ASCII alone, so a
# fullwidth "２:00" is a window of 0 hours that ends as it starts.
MAINTENANCE_BEHAVIORS = {"skip_alerts": 1, "mute_alerts": 2, "run_alerts": 3}
_MAINTENANCE_DURATION = re.compile(r"([0-9]{1,4}):([0-5][0-9])")
_MAINTENANCE_START = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}")


class StepError(Exception):
    """Planning or execution problem for one step; message is shown to the model/operator."""


class PartialWrite(Exception):
    """A step failed after LibreNMS may have changed state. ``entry`` holds what rollback needs:
    ``object_id`` (None when unknown), ``inverse``, ``after_state`` (None when it could not be read) and ``notes``."""

    def __init__(self, message: str, entry: Dict[str, Any]):
        super().__init__(message)
        self.entry = entry


@dataclass(frozen=True)
class Field:
    """One writable attribute, under the friendly name used in operation data and in ``state()``."""

    name: str
    kind: str  # one of diff.KINDS; "text" treats None as "", "env" is an {"env": NAME} reference
    choices: Tuple[str, ...] = ()
    create: bool = True  # allowed on create
    update: bool = True  # allowed on update
    required: bool = False  # required on create
    sensitive: bool = False  # LibreNMS's value is shown only as a digest (service param)
    note: str = ""  # plan warning whenever the field is written
    nullable: bool = False  # an operation may set null (LibreNMS may always report null)

    def __post_init__(self) -> None:
        if self.kind not in diff.KINDS:
            raise ValueError(f"{self.name}: unknown field kind {self.kind!r}")


def _as_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(str(value))
    except ValueError:
        return None


def _maybe_committed(exc: BaseException) -> bool:
    """A failed write LibreNMS may still have carried out: it broke on the way back, the server failed part-way,
    or it answered 2xx with something the client could not use."""
    status = getattr(exc, "status", 0) or 0
    return getattr(exc, "kind", "") in ("transport", "server") or 200 <= status < 300


def maintenance_minutes(duration: Any) -> int | None:
    """The minutes of a maintenance ``duration`` written ``H:MM`` in ASCII digits ("2:00", "0:30"), or None for
    anything else: LibreNMS answers 201 for a duration without a colon, or in other digits, and saves a window that
    has already ended."""
    found = _MAINTENANCE_DURATION.fullmatch(duration) if isinstance(duration, str) else None
    return None if found is None else int(found.group(1)) * 60 + int(found.group(2))


def valid_maintenance_start(value: Any) -> bool:
    """``Y-m-d H:i:s`` in ASCII digits and a real date: anything else makes LibreNMS's Carbon parse fail with a
    500."""
    if not isinstance(value, str) or not _MAINTENANCE_START.fullmatch(value):
        return False
    try:
        datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return False
    return True


def maintenance_behavior(value: Any) -> str | None:
    """A maintenance behaviour's name from its name or its number 1-3 (an int, or ASCII digits), or None for anything
    else, which LibreNMS would replace silently."""
    if isinstance(value, str) and value in MAINTENANCE_BEHAVIORS:
        return value
    number = int(value) if is_digits(value) else None
    return next((name for name, code in MAINTENANCE_BEHAVIORS.items() if code == number), None)


def settles_at(start: datetime | None = None) -> str:
    """When finding a write not carried out proves it never will be: LibreNMS keeps running a request whose answer
    was lost (a device add probing SNMP credentials, a large device's delete) after the proxy or the client gave up,
    so until :data:`SETTLE_AFTER` past *start* (default: now) a look that finds nothing proves nothing."""
    moment = (start or datetime.now(timezone.utc)) + SETTLE_AFTER
    return moment.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _outcome_unknown(exc: BaseException) -> bool:
    """A failed write a re-read made at once cannot settle: the answer was lost on the way back (a timeout, a reset)
    or came from a gateway (502/503/504) while LibreNMS may still be running the request (a device add probes for
    longer than a proxy waits) and commit after the re-read. A connection refused or a name not resolved never
    reached it."""
    if getattr(exc, "kind", "") == "transport":
        return getattr(exc, "failure", "") not in ("refused", "dns")
    return getattr(exc, "status", 0) in GATEWAY_STATUSES


class _WriteCounter:
    """Client proxy counting the write requests a step sends, so a failure can be placed before anything was sent
    (it propagates unchanged) or after LibreNMS may have changed state (it is settled by a re-read)."""

    def __init__(self, client: Any):
        self._client = client
        self.sent = 0
        self.answered = 0

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)

    def request(self, method: str, path: str, **kwargs: Any) -> Any:
        if str(method).upper() == "GET":
            return self._client.request(method, path, **kwargs)
        self.sent += 1
        result = self._client.request(method, path, **kwargs)
        self.answered += 1
        return result

    def may_have_written(self, exc: BaseException) -> bool:
        return bool(self.answered) or (bool(self.sent) and _maybe_committed(exc))


class Resource:
    """One LibreNMS object type. See the module docstring for the attributes and hooks a subclass supplies."""

    name: str = ""
    title: str = ""
    id_key: str = "id"
    label_key: str = "name"
    match_keys: Tuple[str, ...] = ()
    natural_key: str | None = None
    identity_keys: Tuple[str, ...] = ()
    parent_key: str | None = None
    fields: Dict[str, Field] = {}
    ops: Tuple[str, ...] = ()
    inverse: Dict[str, Tuple[str, str]] = {}

    # -- reads ------------------------------------------------------------------------------------------------------

    def get(self, client: Any, object_id: int, step: Dict[str, Any] | None = None) -> Dict[str, Any] | None:
        """The object as LibreNMS returns it (credentials masked), or None when it does not exist."""
        raise NotImplementedError

    def find(self, client: Any, match: Dict[str, Any]) -> Tuple[int, Dict[str, Any] | None]:
        """``(count, object)`` for the objects *match* selects; the object only when exactly one does."""
        raise StepError(f"a {self.title} cannot be looked up by match; use its id")

    def state(self, client: Any, obj: Dict[str, Any]) -> Dict[str, Any]:
        """Identity plus every owned field, normalised: what plans, preconditions and rollback compare."""
        raise NotImplementedError

    def volatile_fields(self, state: Dict[str, Any]) -> Set[str]:
        return set()

    def label(self, obj_or_data: Dict[str, Any]) -> str:
        value = obj_or_data.get(self.label_key)
        if value not in (None, ""):
            return str(value)
        ident = obj_or_data.get(self.id_key)
        return f"#{ident}" if ident is not None else "(new)"

    # -- planning ---------------------------------------------------------------------------------------------------

    def validate(self, op: str, data: Dict[str, Any], settings: Any) -> List[str]:
        """Static checks of create/update *data* against ``fields``; every problem is reported, none dropped."""
        if op not in ("create", "update"):
            return []
        allowed = {name for name, field in self.fields.items() if (field.create if op == "create" else field.update)}
        errors: List[str] = []
        unknown = sorted(set(data) - allowed)
        if unknown:
            errors.append(
                f"cannot {op} {self.title} field(s) {', '.join(unknown)}; allowed: {', '.join(sorted(allowed))}"
            )
        missing: Set[str] = set()
        if op == "create":
            missing = {name for name in allowed if self.fields[name].required and data.get(name) in (None, "")}
            errors += [f"{name} is required to create a {self.title}" for name in sorted(missing)]
        for name in sorted((set(data) & allowed) - missing):
            field, value = self.fields[name], data[name]
            if value is None and field.kind != "text" and not field.nullable:
                errors.append(f"{name}: null is not allowed")
                continue
            try:
                diff.normalise(field, value)
            except ValueError as exc:
                errors.append(str(exc))
        return errors

    def resolve(self, client: Any, op: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """A new dict with every create/update Field value normalised; subclasses add lookups (names -> ids)."""
        if op not in ("create", "update"):
            return dict(data)
        resolved: Dict[str, Any] = {}
        for name, value in data.items():
            field = self.fields.get(name)
            try:
                resolved[name] = value if field is None else diff.normalise(field, value)
            except ValueError as exc:
                raise StepError(str(exc)) from None
        return resolved

    def plan_step(self, client: Any, index: int, op: Dict[str, Any], settings: Any) -> Dict[str, Any]:
        """The complete plan step for one validated operation ``{op, resource, id, match, data}``."""
        kind = op["op"]
        data = self.resolve(client, kind, op.get("data") or {})
        if kind == "create":
            return self._plan_create(client, index, op, data, settings)
        obj, how = self._target(client, op)
        current = self.state(client, obj)
        step = self._new_step(index, kind, op, obj, how, current)
        if kind == "update":
            return self._plan_update(client, step, data, current, settings)
        step["precondition"] = {"state": current}
        if kind == "delete":
            step["snapshot"] = self._snapshot(client, obj, current)
            return self._finish(step)
        return self._finish(self._plan_action(client, step, data, obj, current, settings))

    def _target(self, client: Any, op: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        if op.get("id") is not None:
            obj = self.get(client, op["id"])
            if obj is None:
                raise StepError(f"{self.title} #{op['id']} does not exist")
            return obj, "id"
        count, obj = self.find(client, op["match"])
        self._unambiguous(count, op["match"])
        if obj is None:
            raise StepError(f"no {self.title} matches {diff.format_value(op['match'])}")
        return obj, "match"

    def _unambiguous(self, count: int, match: Dict[str, Any]) -> None:
        if count > 1:
            raise StepError(f"match {diff.format_value(match)} is ambiguous ({count} {self.title}s)")

    def _new_step(
        self,
        index: int,
        action: str,
        op: Dict[str, Any],
        obj: Dict[str, Any] | None,
        resolved_by: str | None,
        values: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Step skeleton; *values* is the plan-time state of an existing object or the data of a create."""
        return {
            "index": index,
            "action": action,
            "resource": self.name,
            "object_id": self._id_of(obj) if obj is not None else None,
            "label": self.label(obj if obj is not None else values),
            "requested_op": op["op"],
            "resolved_by": resolved_by,
            "parent_id": self._parent_id(values),
            "notes": [],
        }

    def _plan_create(
        self, client: Any, index: int, op: Dict[str, Any], data: Dict[str, Any], settings: Any
    ) -> Dict[str, Any]:
        """A create, or with ``match`` an upsert: one match becomes an update (or noop), none stays a create."""
        match = op.get("match")
        if match:
            count, obj = self.find(client, match)
            self._unambiguous(count, match)
            if obj is not None:
                current = self.state(client, obj)
                step = self._new_step(index, "update", op, obj, "match", current)
                step["upsert"] = True
                return self._plan_update(client, step, self._updatable(step, data, current), current, settings)
        step = self._new_step(index, "create", op, None, "match" if match else None, data)
        data = self._prepare(client, step, data, None, settings)
        step["data"] = data
        exists = self._exists_check(data, match)
        if exists:
            step["exists_check"] = exists
        for key, value in (match or {}).items():
            field = self.fields.get(key)
            if field is not None and (key not in data or not diff.values_equal(field, value, data[key])):
                step["notes"].append(
                    f"match {key}={diff.format_value(value)} is not what data sets; the new {self.title} will not "
                    "match its own lookup"
                )
        self._note_fields(step, data)
        return self._finish(step)

    def _exists_check(self, data: Dict[str, Any], match: Dict[str, Any] | None) -> Dict[str, Any] | None:
        if self.natural_key and data.get(self.natural_key) not in (None, ""):
            return {self.natural_key: data[self.natural_key]}
        return dict(match) if match else None

    def _updatable(self, step: Dict[str, Any], data: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
        """Upsert data an update can apply; create-only keys that would differ are reported, not sent."""
        keep: Dict[str, Any] = {}
        for name, value in data.items():
            field = self.fields.get(name)
            if field is None or field.update:
                keep[name] = value
            elif name not in current or not diff.values_equal(field, value, current[name]):
                step["notes"].append(
                    f"{name} cannot be changed on an existing {self.title}; the matched one keeps its own value"
                )
        return keep

    def _plan_update(
        self, client: Any, step: Dict[str, Any], data: Dict[str, Any], current: Dict[str, Any], settings: Any
    ) -> Dict[str, Any]:
        data = self._prepare(client, step, data, current, settings)
        try:
            changes = diff.compute_changes(data, current, self.fields)
        except ValueError as exc:
            raise StepError(str(exc)) from None
        if not changes:
            step.pop("upsert", None)
            step.update(action="noop", reason="already matches desired state")
            return self._finish(step)
        step["changes"] = changes
        step["payload"] = self._payload({name: change["to"] for name, change in changes.items()}, step)
        step["precondition"] = {"state": current}
        self._note_fields(step, changes)
        return self._finish(step)

    def _note_fields(self, step: Dict[str, Any], names: Any) -> None:
        for name in sorted(names):
            field = self.fields.get(name)
            if field is not None and field.note:
                step["notes"].append(f"{name}: {field.note}")

    def _finish(self, step: Dict[str, Any]) -> Dict[str, Any]:
        """Attach the inverse kind of the final action (an upsert that became an update uses ``update``)."""
        if step["action"] == "noop":
            step.pop("precondition", None)
            return step
        kind, note = self.inverse[step["action"]]
        step.setdefault("inverse_kind", kind)
        step.setdefault("inverse_note", note)
        return step

    def describe(self, step: Dict[str, Any]) -> List[str]:
        """Detail lines of a step for the plan the human reviews (header and rollback line are the planner's)."""
        action = step["action"]
        if action == "update":
            return diff.render_changes(step.get("changes") or {}, self.fields)
        if action == "create":
            data = step.get("data") or {}
            lines = [", ".join(f"{key}={diff.format_value(value, 40)}" for key, value in data.items())] if data else []
            if step.get("exists_check"):
                lines.append(f"precondition: no {self.title} matches {diff.format_value(step['exists_check'])}")
            return lines
        if action == "delete":
            return [f"the {self.title} is deleted; its configuration is kept in the plan"]
        if action == "noop":
            return [step.get("reason") or "no change"]
        params = step.get("params") or {}
        return [", ".join(f"{key} {diff.format_value(value, 40)}" for key, value in params.items())] if params else []

    # -- apply ------------------------------------------------------------------------------------------------------

    def check(self, client: Any, step: Dict[str, Any]) -> str | None:
        """Apply-time precondition: a conflict message, or None when the step may run."""
        action = step["action"]
        if action == "noop":
            return None
        if action == "create":
            exists = step.get("exists_check")
            if exists:
                count, _ = self.find(client, exists)
                if count:
                    return f"{count} {self.title}(s) now match {diff.format_value(exists)}; expected none"
            return self._extra_check(client, step, None, None)
        obj = self.get(client, step["object_id"], step)
        if obj is None:
            return f"{self.title} #{step['object_id']} no longer exists"
        current = self.state(client, obj)
        expected = (step.get("precondition") or {}).get("state")
        if action in CRUD and expected is not None:
            drift = self._drift(expected, current, set(step.get("changes") or {}))
            if drift:
                return f"{self.title} #{step['object_id']} changed since planning ({', '.join(drift)})"
        return self._extra_check(client, step, obj, current)

    def execute(self, client: Any, step: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Perform *step* and verify it by re-reading; returns ``{"object_id", "inverse", "after_state", "notes"}``.

        Raises PartialWrite when LibreNMS may have changed something (rollback reverts the entry), and the original
        StepError / LibreNMSError when nothing was sent or a re-read proves nothing changed."""
        counter = _WriteCounter(client)
        known: Dict[str, Any] = {}
        try:
            action = step["action"]
            if action == "create":
                return self._execute_create(counter, step, context, known)
            if action == "update":
                return self._execute_update(counter, step, context)
            if action == "delete":
                return self._execute_delete(counter, step, context)
            return self._execute_action(counter, step, context)
        except PartialWrite:
            raise
        except Exception as exc:
            if counter.may_have_written(exc):
                settled = self._settle(client, step, exc, known.get("object_id"))
            else:
                settled = self._clean(exc, step)
            if settled is exc:
                raise
            raise settled from exc

    def _execute_create(
        self, client: Any, step: Dict[str, Any], context: Dict[str, Any], known: Dict[str, Any]
    ) -> Dict[str, Any]:
        new_id = self._create_call(client, step, context)
        if new_id is None:
            new_id = self._locate_created(client, step)
        known["object_id"] = new_id
        inverse = self._inverse(step, new_id)
        obj = self.get(client, new_id, step)
        if obj is None:
            raise PartialWrite(
                f"LibreNMS reported creating {self.title} #{new_id} but it cannot be read back",
                self._entry(new_id, inverse, None),
            )
        after = self.state(client, obj)
        wrong = self._mismatches(self._expected_after_create(step, after), after, from_operation=True)
        if wrong:
            raise PartialWrite(f"LibreNMS accepted the write but {wrong}", self._entry(new_id, inverse, after))
        return self._entry(new_id, inverse, after)

    def _locate_created(self, client: Any, step: Dict[str, Any]) -> int:
        """The id of what a create made when the answer did not say; PartialWrite when it cannot be told."""
        lookup = self._create_lookup(step)
        if lookup:
            count, obj = self.find(client, lookup)
            new_id = self._id_of(obj) if count == 1 and obj is not None else None
            if new_id is not None:
                return new_id
        raise PartialWrite(
            f"LibreNMS accepted the create but the new {self.title} could not be identified",
            self._entry(None, self._inverse(step, None), None, ["rollback looks the object up again before acting"]),
        )

    def _execute_update(self, client: Any, step: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        object_id = step["object_id"]
        desired = {name: change["to"] for name, change in step["changes"].items()}
        self._update_call(client, object_id, desired, step, context)
        inverse = self._inverse(step, object_id)
        obj = self.get(client, object_id, step)
        if obj is None:
            raise PartialWrite(
                f"{self.title} #{object_id} disappeared after the update", self._entry(object_id, inverse, None)
            )
        after = self.state(client, obj)
        wrong = self._mismatches(desired, after, from_operation=True)
        if wrong:
            raise PartialWrite(f"LibreNMS accepted the write but {wrong}", self._entry(object_id, inverse, after))
        return self._entry(object_id, inverse, after)

    def _execute_delete(self, client: Any, step: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        object_id = step["object_id"]
        self._delete_call(client, object_id, step, context)
        if self.get(client, object_id, step) is not None:
            raise StepError(f"LibreNMS accepted the delete but {self.title} #{object_id} still exists")
        return self._entry(object_id, self._inverse(step, object_id), None)

    def _settle(self, client: Any, step: Dict[str, Any], exc: BaseException, known_id: int | None) -> BaseException:
        """What a failure after a write means: PartialWrite when a re-read shows LibreNMS changed something, cannot
        be made, or cannot prove anything (:func:`_outcome_unknown`), otherwise the original error (non-LibreNMS
        errors as StepError)."""
        error = self.scrub(str(exc) or type(exc).__name__, step)
        object_id = known_id if step["action"] == "create" else step.get("object_id")
        unsettled = {"settles_at": settles_at()} if _outcome_unknown(exc) else {}
        try:
            changed, object_id, after = self._reread(client, step, object_id)
        except Exception as read_exc:
            note = (
                f"outcome unknown: re-reading the {self.title} after the failed write also failed "
                f"({self.scrub(str(read_exc), step)}); rollback looks again before acting"
            )
            entry = self._entry(object_id, self._inverse(step, object_id), None, [note])
            return PartialWrite(f"{error} (LibreNMS may have applied the write)", {**entry, **unsettled})
        if changed:
            entry = self._entry(object_id, self._inverse(step, object_id), after)
            return PartialWrite(f"{error} (LibreNMS applied part of the step; rollback reverts it)", entry)
        if unsettled:
            note = (
                f"outcome unknown: LibreNMS may still be working on the request, so reading the {self.title} back at "
                "once proved nothing; rollback looks again before acting"
            )
            entry = self._entry(object_id, self._inverse(step, object_id), None, [note])
            return PartialWrite(f"{error} (LibreNMS may have applied the write)", {**entry, **unsettled})
        return self._clean(exc, step) if isinstance(exc, (StepError, LibreNMSError)) else StepError(error)

    def _reread(
        self, client: Any, step: Dict[str, Any], object_id: int | None
    ) -> Tuple[bool, int | None, Dict[str, Any] | None]:
        """``(changed, object_id, after_state)`` after a failed write."""
        if step["action"] == "create":
            if object_id is None:
                lookup = self._create_lookup(step)
                if not lookup:
                    raise StepError(f"there is no way to look up the new {self.title}")
                count, obj = self.find(client, lookup)
                if count > 1:
                    return True, None, None
                object_id = self._id_of(obj) if obj is not None else None
            else:
                obj = self.get(client, object_id, step)
            return (obj is not None), object_id, (self.state(client, obj) if obj is not None else None)
        obj = self.get(client, object_id, step)
        if obj is None:
            return True, object_id, None
        after = self.state(client, obj)
        expected = (step.get("precondition") or {}).get("state") or {}
        return bool(self._drift(expected, after, set(step.get("changes") or {}))), object_id, after

    @staticmethod
    def _entry(
        object_id: int | None,
        inverse: Dict[str, Any] | None,
        after_state: Dict[str, Any] | None,
        notes: List[str] | None = None,
    ) -> Dict[str, Any]:
        """The journal fields execute returns (and a PartialWrite carries)."""
        return {"object_id": object_id, "inverse": inverse, "after_state": after_state, "notes": list(notes or [])}

    def _inverse(self, step: Dict[str, Any], object_id: int | None) -> Dict[str, Any] | None:
        """How rollback undoes *step*; None for inverse kinds ``none`` and ``not_needed``."""
        if step.get("inverse_kind") in ("none", "not_needed"):
            return None
        action = step["action"]
        if action == "create":
            if object_id is None:
                return {"action": "delete", "object_id": None, "find": self._create_lookup(step)}
            return {"action": "delete", "object_id": object_id}
        if action == "update":
            previous = {name: change["from"] for name, change in step["changes"].items()}
            return {"action": "update", "object_id": object_id, "data": previous}
        if action == "delete":
            return {"action": "create", "snapshot": step.get("snapshot")}
        return None

    # -- rollback ---------------------------------------------------------------------------------------------------

    def revert(
        self, client: Any, entry: Dict[str, Any], force: bool, context: Dict[str, Any]
    ) -> Tuple[str, Dict[str, Any]]:
        """Undo one journal entry: ``(status, details)``, status in reverted|conflict|failed|irreversible|skipped.

        ``context["step"]`` (the plan step of *entry*), when the executor passes it, lets an entry whose outcome is
        unknown be reverted: a process that died during the write journaled no inverse."""
        step = context.get("step") or {}
        try:
            return self._revert(client, entry, step, force, context)
        except StepError as exc:
            return "failed", {"error": self.scrub(str(exc), entry, step)}
        except Exception as exc:
            clean = self._clean(exc, entry, step)
            if clean is exc:
                raise
            return "failed", {"error": str(clean)}

    def _revert(
        self, client: Any, entry: Dict[str, Any], step: Dict[str, Any], force: bool, context: Dict[str, Any]
    ) -> Tuple[str, Dict[str, Any]]:
        action = entry.get("action")
        kind = entry.get("inverse_kind")
        note = entry.get("inverse_note") or step.get("inverse_note") or self.inverse.get(action, ("", ""))[1]
        if kind == "not_needed":
            return "skipped", {"note": note}
        if entry.get("status") == "unknown" and action not in ("create", "update"):
            return "failed", {
                "error": f"outcome of this step is unknown (the process died during the write); check "
                f"{self.title} {entry.get('label')} in LibreNMS"
            }
        if kind == "none":
            return "irreversible", {"note": note}
        inverse = entry.get("inverse")
        if inverse is None and step:
            inverse = self._inverse(step, entry.get("object_id"))
        if action in CRUD and not inverse:
            return "failed", {
                "error": f"no rollback information was recorded for this step; check {self.title} "
                f"{entry.get('label')} in LibreNMS"
            }
        if action == "create":
            return self._revert_create(client, entry, inverse, step, force, context)
        if action == "update":
            return self._revert_update(client, entry, inverse, step, force, context)
        if action == "delete":
            return self._revert_delete(client, entry, inverse, context)
        return self._revert_action(client, entry, force, context)

    def _revert_create(
        self,
        client: Any,
        entry: Dict[str, Any],
        inverse: Dict[str, Any],
        step: Dict[str, Any],
        force: bool,
        context: Dict[str, Any],
    ) -> Tuple[str, Dict[str, Any]]:
        object_id = inverse.get("object_id")
        if object_id is None:
            lookup = inverse.get("find")
            if not lookup:
                return "failed", {
                    "error": f"the {self.title} this step may have created cannot be identified; check "
                    f"{entry.get('label')} in LibreNMS"
                }
            count, obj = self.find(client, lookup)
            if count == 0:
                return self._not_carried_out(
                    entry, "nothing was written" if entry.get("status") == "unknown" else "nothing was created"
                )
            if count > 1 or obj is None:
                return "conflict", {
                    "error": f"{count} {self.title}s match {diff.format_value(lookup)}; cannot tell which one this "
                    "plan created"
                }
            object_id = self._id_of(obj)
        else:
            obj = self.get(client, object_id, entry)
            if obj is None:
                return "reverted", {"note": "object already gone"}
        if not force:
            conflict = self._created_drift(entry, step, self.state(client, obj), object_id)
            conflict = conflict or self._revert_create_blocker(client, object_id, entry)
            if conflict:
                return "conflict", {"error": conflict}
        self._delete_call(client, object_id, entry, context)
        if self.get(client, object_id, entry) is not None:
            return "failed", {"error": f"LibreNMS accepted the delete but {self.title} #{object_id} still exists"}
        return "reverted", {"object_id": object_id}

    def _created_drift(
        self, entry: Dict[str, Any], step: Dict[str, Any], current: Dict[str, Any], object_id: Any
    ) -> str | None:
        expected = entry.get("after_state")
        if expected is not None:
            drift = self._drift(expected, current, set())
            if drift:
                return (
                    f"{self.title} #{object_id} was modified after apply ({', '.join(drift)}); use force to delete "
                    "anyway"
                )
            return None
        if step:  # outcome unknown: delete only what this step would have created
            wrong = self._mismatches(self._expected_after_create(step, current), current, from_operation=True)
            if wrong:
                return f"{self.title} #{object_id} is not what this step creates ({wrong}); use force to delete anyway"
        return None

    def _revert_update(
        self,
        client: Any,
        entry: Dict[str, Any],
        inverse: Dict[str, Any],
        step: Dict[str, Any],
        force: bool,
        context: Dict[str, Any],
    ) -> Tuple[str, Dict[str, Any]]:
        object_id = inverse.get("object_id", entry.get("object_id"))
        previous = inverse.get("data") or {}
        obj = self.get(client, object_id, entry)
        if obj is None:
            return "failed", {"error": f"{self.title} #{object_id} no longer exists; cannot restore fields"}
        current = self.state(client, obj)
        expected = entry.get("after_state")
        if not force:
            conflict = self._updated_drift(expected, current, previous, step, object_id)
            if conflict:
                return "conflict", {"error": conflict}
        pending = {name: value for name, value in previous.items() if not self._same(name, current.get(name), value)}
        if not pending and expected is None:
            status, details = self._not_carried_out(entry, "nothing was written")
            return status, ({"restored_fields": [], **details} if status == "reverted" else details)
        if not pending:
            return "reverted", {"restored_fields": [], "note": "fields already had their previous values"}
        self._update_call(client, object_id, pending, entry, context)
        obj = self.get(client, object_id, entry)
        if obj is None:
            return "failed", {"error": f"{self.title} #{object_id} disappeared during the rollback"}
        wrong = self._mismatches(pending, self.state(client, obj), from_operation=False)
        if wrong:
            return "failed", {"error": f"LibreNMS accepted the rollback write but {wrong}"}
        return "reverted", {"restored_fields": sorted(pending)}

    def _updated_drift(
        self,
        expected: Dict[str, Any] | None,
        current: Dict[str, Any],
        previous: Dict[str, Any],
        step: Dict[str, Any],
        object_id: Any,
    ) -> str | None:
        if expected is not None:
            # A field back at its previous value holds what this rollback writes (one that died after its write
            # landed, or a person who restored it): nothing to protect there.
            restored = {
                name: current.get(name)
                for name, value in previous.items()
                if self._same(name, current.get(name), value)
            }
            drift = self._drift({**expected, **restored}, current, set(previous))
            if drift:
                return (
                    f"{self.title} #{object_id} was modified after apply ({', '.join(drift)}); use force to overwrite"
                )
            return None
        # Outcome unknown: each field must hold either its previous value or the planned one.
        desired = {name: change.get("to") for name, change in (step.get("changes") or {}).items()}
        odd = [
            name
            for name, value in previous.items()
            if not self._same(name, current.get(name), value)
            and not (name in desired and self._same(name, current.get(name), desired[name]))
        ]
        if odd:
            return (
                f"the outcome of the write is unknown and {', '.join(sorted(odd))} on {self.title} #{object_id} "
                "match neither the planned nor the previous value; use force to restore the previous values"
            )
        return None

    def _revert_delete(
        self, client: Any, entry: Dict[str, Any], inverse: Dict[str, Any], context: Dict[str, Any]
    ) -> Tuple[str, Dict[str, Any]]:
        """Re-create what the delete removed. A delete that failed with an unknown outcome needs nothing when the
        object is still there. ``revert_progress.recreating`` is saved before ``_recreate_call``: a rollback that
        finds it resumes one that died from there on, so the object its natural key finds may be that run's own
        re-creation, and ``context["resuming"]`` tells ``_recreate_call`` to adopt it."""
        snapshot = inverse.get("snapshot") or {}
        if entry.get("status") != "done" and self.get(client, entry["object_id"], entry) is not None:
            return self._not_carried_out(entry, "nothing was deleted")
        if (entry.get("revert_progress") or {}).get("recreating"):
            context = {**context, "resuming": True}
        elif self.natural_key and snapshot.get(self.natural_key) not in (None, ""):
            lookup = {self.natural_key: snapshot[self.natural_key]}
            count, _ = self.find(client, lookup)
            if count:
                return "conflict", {
                    "error": f"a {self.title} matching {diff.format_value(lookup)} exists again; remove or rename it "
                    "before rolling back"
                }
        if context.get("checkpoint") is not None:
            context["checkpoint"]({"recreating": True})
        new_id, details = self._recreate_call(client, entry, context)
        if new_id is not None and self.get(client, new_id, entry) is None:
            return "failed", {
                "error": f"re-created {self.title} #{new_id} cannot be read back",
                "new_object_id": new_id,
            }
        return "reverted", {"new_object_id": new_id, **details}

    @staticmethod
    def _not_carried_out(entry: Dict[str, Any], note: str) -> Tuple[str, Dict[str, Any]]:
        """The revert of an entry whose write LibreNMS shows no trace of: settled by *note*, unless the write may
        still be running (before the entry's ``settles_at``, :func:`settles_at`). Then the entry stays pending
        ("failed"), so a later rollback looks again and undoes the write if it landed meanwhile."""
        settles = timefmt.parse_utc(entry.get("settles_at"))
        if settles is None or datetime.now(timezone.utc) >= settles:
            return "reverted", {"note": note}
        return "failed", {
            "error": f"{note} so far, but LibreNMS may still be carrying out the write (its answer was lost); roll "
            f"back again after {timefmt.local(entry['settles_at'])} to look again"
        }

    # -- comparison and redaction helpers ---------------------------------------------------------------------------

    def _id_of(self, obj: Dict[str, Any]) -> int | None:
        return _as_int(obj.get(self.id_key))

    def _same(self, name: str, a: Any, b: Any) -> bool:
        field = self.fields.get(name)
        return diff.values_equal(field, a, b) if field is not None else a == b

    def _drift(self, expected: Dict[str, Any], current: Dict[str, Any], written: Set[str]) -> List[str]:
        """``key: old -> new`` for each compared key that differs: identity, non-volatile fields, and volatile
        fields only when the step writes them. Both sides came from LibreNMS (sensitive values as digests)."""
        skip = set(self.volatile_fields(expected)) - set(written) - {self.id_key, *self.identity_keys}
        lines = []
        for key in sorted((set(expected) | set(current)) - skip):
            old, new = expected.get(key), current.get(key)
            if not self._same(key, old, new):
                field = self.fields.get(key)
                lines.append(f"{key}: {diff.format_live(field, old)} -> {diff.format_live(field, new)}")
        return lines

    def _mismatches(self, expected: Dict[str, Any], after: Dict[str, Any], *, from_operation: bool) -> str:
        """``name is <x>, expected <y>; ...`` for each expected value *after* does not hold."""
        wrong = []
        for name, want in expected.items():
            have = after.get(name)
            if not self._same(name, have, want):
                field = self.fields.get(name)
                shown = diff.format_value(want) if from_operation else diff.format_live(field, want)
                wrong.append(f"{name} is {diff.format_live(field, have)}, expected {shown}")
        return "; ".join(wrong)

    def _secrets(self, record: Dict[str, Any] | None) -> List[str]:
        """Sensitive values a step or journal entry holds (operation and LibreNMS side), for scrubbing errors."""
        if not isinstance(record, dict):
            return []
        inverse = record.get("inverse") or {}
        holders = [
            record.get("data"),
            record.get("snapshot"),
            record.get("after_state"),
            (record.get("precondition") or {}).get("state"),
            inverse.get("data"),
            inverse.get("snapshot"),
        ]
        values: List[str] = []
        for name, field in self.fields.items():
            if not field.sensitive:
                continue
            change = (record.get("changes") or {}).get(name) or {}
            candidates = [holder.get(name) for holder in holders if isinstance(holder, dict)]
            values += [v for v in (*candidates, change.get("from"), change.get("to")) if isinstance(v, str) and v]
        return values

    def scrub(self, text: str, *records: Dict[str, Any] | None) -> str:
        """*text* without the sensitive values *records* hold (and credential ``key: value`` pairs)."""
        return redact.scrub_text(text, None, extra=[value for record in records for value in self._secrets(record)])

    def _clean(self, exc: BaseException, *records: Dict[str, Any] | None) -> BaseException:
        """*exc*, or a StepError with scrubbed text when its message or body carries a sensitive value."""
        values = [value for record in records for value in self._secrets(record)]
        body = str(getattr(exc, "body", "") or "")
        if redact.holds_any(str(exc), values) or redact.holds_any(body, values):
            return StepError(self.scrub(str(exc), *records))
        return exc

    # -- default hooks (see the module docstring) ---------------------------------------------------------------------

    def _parent_id(self, values: Dict[str, Any]) -> int | None:
        return _as_int(values.get(self.parent_key)) if self.parent_key else None

    def _prepare(
        self, client: Any, step: Dict[str, Any], data: Dict[str, Any], current: Dict[str, Any] | None, settings: Any
    ) -> Dict[str, Any]:
        return data

    def _plan_action(
        self,
        client: Any,
        step: Dict[str, Any],
        data: Dict[str, Any],
        obj: Dict[str, Any],
        current: Dict[str, Any],
        settings: Any,
    ) -> Dict[str, Any]:
        step["params"] = data
        return step

    def _snapshot(self, client: Any, obj: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
        return dict(obj)

    def _payload(self, data: Dict[str, Any], record: Dict[str, Any]) -> Dict[str, Any]:
        return dict(data)

    def _create_lookup(self, step: Dict[str, Any]) -> Dict[str, Any] | None:
        return step.get("exists_check") or None

    def _expected_after_create(self, step: Dict[str, Any], after: Dict[str, Any]) -> Dict[str, Any]:
        volatile = self.volatile_fields(after)
        return {k: v for k, v in (step.get("data") or {}).items() if k in after and k not in volatile}

    def _extra_check(
        self, client: Any, step: Dict[str, Any], obj: Dict[str, Any] | None, current: Dict[str, Any] | None
    ) -> str | None:
        return None

    def _revert_create_blocker(self, client: Any, object_id: int, entry: Dict[str, Any]) -> str | None:
        return None

    def _create_call(self, client: Any, step: Dict[str, Any], context: Dict[str, Any]) -> int | None:
        raise StepError(f"creating a {self.title} is not supported")

    def _update_call(
        self, client: Any, object_id: int, data: Dict[str, Any], record: Dict[str, Any], context: Dict[str, Any]
    ) -> None:
        raise StepError(f"updating a {self.title} is not supported")

    def _delete_call(self, client: Any, object_id: int, record: Dict[str, Any], context: Dict[str, Any]) -> None:
        raise StepError(f"deleting a {self.title} is not supported")

    def _recreate_call(
        self, client: Any, entry: Dict[str, Any], context: Dict[str, Any]
    ) -> Tuple[int | None, Dict[str, Any]]:
        raise StepError(f"a deleted {self.title} cannot be re-created")

    def _execute_action(self, client: Any, step: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        raise StepError(f"{step['action']} is not supported for a {self.title}")

    def _revert_action(
        self, client: Any, entry: Dict[str, Any], force: bool, context: Dict[str, Any]
    ) -> Tuple[str, Dict[str, Any]]:
        return "failed", {"error": f"no rollback is defined for {entry.get('action')} on a {self.title}"}
