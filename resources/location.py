"""LibreNMS locations: create, update (name and coordinates), delete, and maintenance of every device at one.

What LibreNMS does here (specs/ln-groups.md §2.2, LO-1..LO-6) and how this module copes:

- ``GET location/{id}`` (singular) is the read: float coordinates, a bool ``fixed_coordinates`` and a ``timestamp``
  that every save bumps, the geocoder's included, so the timestamp is kept in the state but never compared.
  ``GET resources/locations`` (decimal strings, 404 when empty) only serves name lookups, which follow the unique
  index's ``utf8mb4_unicode_ci`` collation: case, accents and trailing spaces do not count.
- A location is created only with non-zero ``lat`` and ``lng``, its id comes back only inside the message
  (``Location added with id #N``), and ``fixed_coordinates`` can be set only then.
- An edit answers 201 whatever it did, so every write is verified by re-reading.
- A delete detaches every device at the location (``location_id`` becomes null) and then deletes the row, outside a
  transaction. The plan records those devices; rollback re-creates the location under a new id and attaches them.
- A device that follows its SNMP sysLocation (``override_sysLocation`` off) is moved by polling to a location named
  after it, re-created when missing, which can undo a rename or a delete within one polling cycle.
- Maintenance creates an alert schedule that no v0 route can read, end or delete.

Every path names the location by numeric id: an all-digit name would be read as an id, and one holding ``/`` cannot
be routed at all.
"""

from __future__ import annotations

import re
import unicodedata
from datetime import datetime
from typing import Any, Dict, List, Set, Tuple

from .. import diff, redact
from ..client import LibreNMSError, is_digits, path
from .base import Field, PartialWrite, Resource, StepError, _outcome_unknown, settles_at

BEHAVIORS = {"skip_alerts": 1, "mute_alerts": 2, "run_alerts": 3}
MAINTENANCE_KEYS = ("behavior", "duration", "notes", "start", "title")
MAX_NAME = 255  # locations.location is varchar(255); LibreNMS truncates longer names without a word
# alert_schedule.title is varchar(255), and the "[hermes:<plan id>] " prefix takes 35 of it
MAX_TITLE = 200
_SHOWN_IDS = 10
_DURATION_RE = re.compile(r"([0-9]{1,4}):([0-5][0-9])")
_START_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}")
_ADDED_RE = re.compile(r"#([0-9]+)$")

FIELDS = {
    "location": Field("location", "str", required=True),
    "lat": Field("lat", "float", nullable=True),
    "lng": Field("lng", "float", nullable=True),
    "fixed_coordinates": Field("fixed_coordinates", "bool", update=False),
}
_FIXED_AT_CREATE_ONLY = (
    "fixed_coordinates can only be set when a location is created; LibreNMS API v0 ignores it on an edit"
)
_REGEOCODE = "fixed_coordinates is false: LibreNMS may re-geocode lat/lng; a later rollback may report a conflict"
_NO_COORDINATES = (
    "the location has no coordinates, and LibreNMS API v0 cannot create a location without them; re-create it in "
    "the web UI and set its devices' location again"
)


def _maintenance_note(duration: str | None) -> str:
    expiry = f"it expires after {duration}" if duration else "it expires on its own"
    return (
        f"LibreNMS API v0 cannot end or delete maintenance; {expiry}. To end it early, delete the schedule whose title "
        "starts with [hermes:<plan id>] under Alerts → Scheduled Maintenance."
    )


class Location(Resource):
    """``locations`` rows, addressed by id; ``location`` (the name) is the natural key."""

    name = "location"
    title = "location"
    id_key = "id"
    label_key = "location"
    match_keys = ("location",)
    natural_key = "location"
    fields = FIELDS
    ops = ("create", "update", "delete", "maintenance")
    inverse = {
        "create": ("exact", "deletes the location; refused while a device uses it unless forced"),
        "update": ("exact", ""),
        "delete": (
            "lossy",
            "re-created with a new id; alert-rule scoping and maintenance links to the old id are lost",
        ),
        "maintenance": ("none", _maintenance_note(None)),
    }

    # -- reads ------------------------------------------------------------------------------------------------------

    def get(self, client: Any, object_id: int, step: Dict[str, Any] | None = None) -> Dict[str, Any] | None:
        body = client.get_or_none(path("location", object_id))
        obj = client.result(body, "get_location") if body is not None else None
        if isinstance(obj, list) and len(obj) == 1:  # the shape the API docs show: a one-element list
            obj = obj[0]
        return dict(obj) if isinstance(obj, dict) else None

    def find(self, client: Any, match: Dict[str, Any]) -> Tuple[int, Dict[str, Any] | None]:
        name = match.get("location")
        if not isinstance(name, str) or not name:
            raise StepError('a location is matched by its name: {"location": "<name>"}')
        body = client.get_or_none("resources/locations")
        rows = client.result(body, "locations") if body is not None else None
        hits = [row for row in rows or [] if isinstance(row, dict) and _same_name(row.get("location"), name)]
        if len(hits) != 1:
            return len(hits), None
        obj = self.get(client, hits[0].get("id"))
        return (1, obj) if obj is not None else (0, None)

    def state(self, client: Any, obj: Dict[str, Any]) -> Dict[str, Any]:
        state: Dict[str, Any] = {"id": self._id_of(obj)}
        for name, field in self.fields.items():
            state[name] = _normalised(field, obj.get(name))
        state["timestamp"] = obj.get("timestamp")
        return state

    def volatile_fields(self, state: Dict[str, Any]) -> Set[str]:
        return {"timestamp"}

    # -- planning ---------------------------------------------------------------------------------------------------

    def validate(self, op: str, data: Dict[str, Any], settings: Any) -> List[str]:
        if op == "maintenance":
            return _maintenance_errors(data, settings)
        errors: List[str] = []
        if op == "update" and "fixed_coordinates" in data:
            errors.append(_FIXED_AT_CREATE_ONLY)
            data = {key: value for key, value in data.items() if key != "fixed_coordinates"}
        errors += super().validate(op, data, settings)
        if op in ("create", "update"):
            errors += _value_errors(op, data)
        return errors

    def plan_step(self, client: Any, index: int, op: Dict[str, Any], settings: Any) -> Dict[str, Any]:
        step = super().plan_step(client, index, op, settings)
        if step["action"] == "update":
            self._note_update(client, step)
        elif step["action"] == "delete":
            self._note_delete(step)
        return step

    def _note_update(self, client: Any, step: Dict[str, Any]) -> None:
        before = step["precondition"]["state"]
        if not before.get("fixed_coordinates"):
            step["notes"].append(_REGEOCODE)
        if "location" in step["changes"]:
            loose = _following_syslocation(self._devices_at(client, step["object_id"]))
            if loose:
                step["notes"].append(_syslocation_note(loose, before.get("location"), ""))

    def _note_delete(self, step: Dict[str, Any]) -> None:
        snapshot = step["snapshot"]
        restorable = bool(snapshot.get("lat")) and bool(snapshot.get("lng"))
        if not restorable:
            step["inverse_kind"], step["inverse_note"] = "none", _NO_COORDINATES
        if snapshot["device_ids"]:
            then = "; rollback re-creates the location and attaches them again" if restorable else ""
            step["notes"].append(
                f"LibreNMS detaches device(s) {_ids(snapshot['device_ids'])} from this location (their location_id "
                f"becomes null){then}"
            )
        if snapshot["sysLocation_device_ids"]:
            then = ", under a new id; a rollback then reports a conflict" if restorable else ", under a new id"
            step["notes"].append(_syslocation_note(snapshot["sysLocation_device_ids"], snapshot["location"], then))

    def _prepare(
        self, client: Any, step: Dict[str, Any], data: Dict[str, Any], current: Dict[str, Any] | None, settings: Any
    ) -> Dict[str, Any]:
        if current is None:
            taken = self._name_taken(client, data["location"], None)
            if taken:
                step["notes"].append(f"{taken}; this create is refused at apply unless an earlier step frees the name")
        elif "location" in data and data["location"] != current.get("location"):
            taken = self._name_taken(client, data["location"], step["object_id"])
            if taken:
                raise StepError(taken)
        return data

    def _name_taken(self, client: Any, name: str, object_id: int | None) -> str | None:
        """Why *name* cannot be given to location *object_id* (None: a new one), or None when it is free."""
        count, obj = self.find(client, {"location": name})
        if obj is not None and self._id_of(obj) != object_id:
            return (
                f"a location named {diff.format_value(obj.get('location'))} already exists (#{self._id_of(obj)}); "
                "LibreNMS location names are unique, ignoring case and accents"
            )
        if count > 1:
            return f"{count} locations are named {diff.format_value(name)}"
        return None

    def _snapshot(self, client: Any, obj: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
        devices = self._devices_at(client, current["id"])
        snapshot = {key: current[key] for key in ("location", "lat", "lng", "fixed_coordinates")}
        snapshot["device_ids"] = _device_ids(devices)
        snapshot["sysLocation_device_ids"] = _following_syslocation(devices)
        return snapshot

    def _plan_action(
        self,
        client: Any,
        step: Dict[str, Any],
        data: Dict[str, Any],
        obj: Dict[str, Any],
        current: Dict[str, Any],
        settings: Any,
    ) -> Dict[str, Any]:
        step["params"] = {
            "duration": data["duration"],
            "start": data.get("start"),
            "title": data.get("title") or None,
            "notes": data.get("notes") or "",
            "behavior": _behavior_name(data.get("behavior")),
        }
        step["device_ids"] = _device_ids(self._devices_at(client, step["object_id"]))
        step["inverse_note"] = _maintenance_note(data["duration"])
        return step

    def describe(self, step: Dict[str, Any]) -> List[str]:
        if step["action"] != "maintenance":
            return super().describe(step)
        params = step.get("params") or {}
        parts = [
            f"duration {params.get('duration')}",
            f"behavior {params.get('behavior')}",
            f"title {diff.format_value(params.get('title') or step.get('label'))}",
            f"start {params['start']} (LibreNMS server time)" if params.get("start") else "starts now",
        ]
        if params.get("notes"):
            parts.append(f"notes {diff.format_value(params['notes'])}")
        lines = [", ".join(parts)]
        ids = step.get("device_ids") or []
        lines.append(f"covers device(s) {_ids(ids)} at this location" if ids else "no device is at this location now")
        return lines

    # -- apply ------------------------------------------------------------------------------------------------------

    def _extra_check(
        self, client: Any, step: Dict[str, Any], obj: Dict[str, Any] | None, current: Dict[str, Any] | None
    ) -> str | None:
        if step["action"] == "update" and "location" in step["changes"]:
            return self._name_taken(client, step["changes"]["location"]["to"], step["object_id"])
        if step["action"] == "delete":
            expected = sorted(step["snapshot"]["device_ids"])
            now = _device_ids(self._devices_at(client, step["object_id"]))
            if now != expected:
                return (
                    f"the devices at location #{step['object_id']} changed since planning ({_ids(expected)} -> "
                    f"{_ids(now)})"
                )
        return None

    def _create_call(self, client: Any, step: Dict[str, Any], context: Dict[str, Any]) -> int | None:
        return _added_id(client.request("POST", "locations", json=dict(step["data"])))

    def _update_call(
        self, client: Any, object_id: int, data: Dict[str, Any], record: Dict[str, Any], context: Dict[str, Any]
    ) -> None:
        if "location" in data:
            # A clash is a bare 500 from the unique index; name it instead (a rollback has no precondition check).
            taken = self._name_taken(client, data["location"], object_id)
            if taken:
                raise StepError(taken)
        client.request("PATCH", path("locations", object_id), json=dict(data))

    def _delete_call(self, client: Any, object_id: int, record: Dict[str, Any], context: Dict[str, Any]) -> None:
        try:
            client.request("DELETE", path("locations", object_id))
        except LibreNMSError as exc:
            if record.get("action") == "delete" and _maybe_applied(exc):
                self._detached_before_failing(client, object_id, record, exc)
            raise

    def _detached_before_failing(self, client: Any, object_id: int, step: Dict[str, Any], exc: LibreNMSError) -> None:
        """PartialWrite when the location survived a failed delete but its devices lost it (LibreNMS detaches them
        first), or when that cannot be told: the location's own state does not show it. A location that is gone or
        devices that are untouched are left to the generic settlement."""
        inverse = self._inverse(step, object_id)
        error = self.scrub(str(exc), step)
        try:
            obj = self.get(client, object_id, step)
            if obj is None:
                return
            devices = [(i, self._device(client, i)) for i in step["snapshot"]["device_ids"]]
        except LibreNMSError as read_exc:
            note = (
                f"outcome unknown: re-reading location #{object_id} and its devices after the failed delete also "
                f"failed ({self.scrub(str(read_exc), step)}); rollback looks again before acting"
            )
            entry = self._entry(object_id, inverse, None, [note])
            if _outcome_unknown(exc):  # the delete may still be running, as in the generic settlement
                entry["settles_at"] = settles_at()
            raise PartialWrite(f"{error} (LibreNMS may have applied the write)", entry) from exc
        detached = [i for i, device in devices if device is not None and device.get("location_id") is None]
        if detached:
            then = "rollback attaches them again" if inverse else "set their location again by hand"
            raise PartialWrite(
                f"{error} (LibreNMS detached device(s) {_ids(detached)} but kept the location; {then})",
                self._entry(object_id, inverse, self.state(client, obj)),
            ) from exc

    def _execute_action(self, client: Any, step: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        params = step["params"]
        title = f"[hermes:{context['plan_id']}] {params.get('title') or step['label']}"
        body = {
            "duration": params["duration"],
            "title": title,
            "notes": params.get("notes") or "",
            "behavior": BEHAVIORS[params["behavior"]],
        }
        if params.get("start"):
            body["start"] = params["start"]
        shown = diff.format_value(title, 120)
        try:
            client.request("POST", path("locations", step["object_id"], "maintenance"), json=body)
        except LibreNMSError as exc:
            # A broken or failed answer can follow the insert, and no v0 route reads schedules back to tell.
            if _maybe_applied(exc):
                note = f"look for a schedule titled {shown} under Alerts → Scheduled Maintenance before trying again"
                raise PartialWrite(
                    f"{self.scrub(str(exc), step)} (LibreNMS may have created the schedule)",
                    self._entry(step["object_id"], None, None, [note]),
                ) from exc
            raise
        return self._entry(step["object_id"], None, None, [f"maintenance {shown} scheduled for {params['duration']}"])

    # -- rollback ---------------------------------------------------------------------------------------------------

    def _revert_create_blocker(self, client: Any, object_id: int, entry: Dict[str, Any]) -> str | None:
        ids = _device_ids(self._devices_at(client, object_id))
        if ids:
            return (
                f"device(s) {_ids(ids)} now use location #{object_id}; deleting it would detach them (use force to "
                "delete anyway)"
            )
        return None

    def _revert_delete(
        self, client: Any, entry: Dict[str, Any], inverse: Dict[str, Any], context: Dict[str, Any]
    ) -> Tuple[str, Dict[str, Any]]:
        snapshot = inverse.get("snapshot") or {}
        target, details = self._kept_location(client, entry, snapshot)
        if details.get("object_id") is not None:  # LibreNMS may still be deleting it, detaching the devices again
            status, unsettled = self._not_carried_out(entry, "nothing was deleted")
            if status != "reverted":
                return status, unsettled
        if target is None:
            status, details = super()._revert_delete(client, entry, inverse, context)
            if status != "reverted":
                return status, details
            target = details["new_object_id"]
        attached, failed = self._reattach(client, snapshot.get("device_ids") or [], target)
        notes = [note for note in (details.pop("note", None), attached.pop("note", None)) if note]
        details.update(attached)
        if notes:
            details["note"] = "; ".join(notes)
        if failed:
            error = f"could not attach {'; '.join(failed)} to location #{target}; set their location by hand"
            return "failed", {"error": self.scrub(error, entry), **details}
        return "reverted", details

    def _kept_location(
        self, client: Any, entry: Dict[str, Any], snapshot: Dict[str, Any]
    ) -> Tuple[int | None, Dict[str, Any]]:
        """The location the devices go back to without re-creating one: the original, when the delete failed after
        detaching them, or the one an earlier rollback re-created before it failed to attach every device."""
        earlier = (entry.get("revert") or {}).get("new_object_id")
        for object_id, key, note in (
            (entry.get("object_id"), "object_id", "the location was never deleted"),
            (earlier, "new_object_id", "re-created by an earlier rollback"),
        ):
            if object_id is None:
                continue
            obj = self.get(client, object_id, entry)
            if obj is not None and _same_name(obj.get("location"), snapshot.get("location")):
                return object_id, {key: object_id, "note": note}
        return None, {}

    def _recreate_call(
        self, client: Any, entry: Dict[str, Any], context: Dict[str, Any]
    ) -> Tuple[int | None, Dict[str, Any]]:
        """``POST locations`` from the snapshot. Resuming a rollback that died after its POST, the location of that
        name is the one it created when it holds the snapshot's coordinates."""
        snapshot = (entry.get("inverse") or {}).get("snapshot") or {}
        body = {key: snapshot.get(key) for key in ("location", "lat", "lng")}
        body["fixed_coordinates"] = bool(snapshot.get("fixed_coordinates"))
        if context.get("resuming"):
            count, obj = self.find(client, {"location": body["location"]})
            if count == 1 and obj is not None:
                wrong = self._mismatches(body, self.state(client, obj), from_operation=False)
                if wrong:
                    raise StepError(
                        f"location #{self._id_of(obj)} has the deleted one's name but {wrong}, so it may not be the "
                        "one an interrupted rollback re-created; check it, then remove or rename it before rolling back"
                    )
                return self._id_of(obj), {"note": "re-created by an earlier rollback"}
        failure: LibreNMSError | None = None
        try:
            new_id = _added_id(client.request("POST", "locations", json=body))
        except LibreNMSError as exc:
            if not _maybe_applied(exc):
                raise
            new_id, failure = None, exc  # the insert may have happened; the name was free a moment ago
        if new_id is None:
            count, obj = self.find(client, {"location": body["location"]})
            new_id = self._id_of(obj) if count == 1 and obj is not None else None
        if new_id is None:
            if failure is not None:
                raise failure
            raise StepError(
                f"LibreNMS accepted re-creating location {diff.format_value(body['location'])} but it cannot be "
                f"found; set the location of device(s) {_ids(snapshot.get('device_ids') or [])} by hand"
            )
        return new_id, {}

    def _reattach(self, client: Any, device_ids: List[int], location_id: int) -> Tuple[Dict[str, Any], List[str]]:
        """Point each former device that is still without a location at *location_id*. One that was given another
        location since (by a person, or by polling from its sysLocation) keeps it. Returns the journal details and a
        description of each device that could not be attached."""
        repointed: List[int] = []
        skipped: List[Tuple[int, str]] = []
        failed: List[str] = []
        for device_id in device_ids:
            try:
                device = self._device(client, device_id)
                have = None if device is None else device.get("location_id")
                if device is not None and str(have) == str(location_id):
                    repointed.append(device_id)  # attached by an earlier, interrupted rollback
                    continue
                if device is None or have is not None:
                    skipped.append((device_id, "gone" if device is None else f"now at #{have}"))
                    continue
                client.request("PATCH", path("devices", device_id), json={"field": "location_id", "data": location_id})
                device = self._device(client, device_id)
            except LibreNMSError as exc:
                failed.append(f"device #{device_id} ({exc})")
                continue
            have = None if device is None else device.get("location_id")
            if str(have) == str(location_id):
                repointed.append(device_id)
            else:
                failed.append(f"device #{device_id} (its location_id is {diff.format_value(have)})")
        details: Dict[str, Any] = {"repointed_devices": repointed, "skipped_devices": [i for i, _ in skipped]}
        if skipped:
            details["note"] = "not attached again: " + ", ".join(f"#{i} ({why})" for i, why in skipped)
        return details, failed

    # -- device reads -----------------------------------------------------------------------------------------------

    @staticmethod
    def _devices_at(client: Any, location_id: int) -> List[Dict[str, Any]]:
        """The devices at a location, credentials masked: an admin token gets SNMP secrets in every device object."""
        body = client.get_or_none("devices", {"type": "location_id", "query": location_id})
        rows = client.result(body, "devices") if body is not None else None
        return [redact.mask(row) for row in rows or [] if isinstance(row, dict)]

    @staticmethod
    def _device(client: Any, device_id: int) -> Dict[str, Any] | None:
        body = client.get_or_none(path("devices", device_id))
        rows = client.result(body, "devices") if body is not None else None
        return redact.mask(rows[0]) if isinstance(rows, list) and rows and isinstance(rows[0], dict) else None


def _normalised(field: Field, value: Any) -> Any:
    try:
        return diff.normalise(field, value)
    except ValueError:
        return value  # LibreNMS's own spelling, compared as it is


def _same_name(a: Any, b: Any) -> bool:
    """Names as the unique index compares them: utf8mb4_unicode_ci ignores case, accents and trailing spaces."""
    return isinstance(a, str) and isinstance(b, str) and _folded(a) == _folded(b)


def _folded(name: str) -> str:
    decomposed = unicodedata.normalize("NFKD", name)
    return "".join(c for c in decomposed if not unicodedata.combining(c)).rstrip(" ").casefold()


def _maybe_applied(exc: LibreNMSError) -> bool:
    """A failed write LibreNMS may still have carried out: the answer broke, or the server failed part-way."""
    return exc.kind in ("transport", "server") or 200 <= exc.status < 300


def _flag(value: Any) -> bool:
    return value in (1, "1", "true")


def _device_ids(devices: List[Dict[str, Any]]) -> List[int]:
    return sorted({int(d["device_id"]) for d in devices if is_digits(d.get("device_id"))})


def _following_syslocation(devices: List[Dict[str, Any]]) -> List[int]:
    return _device_ids([d for d in devices if not _flag(d.get("override_sysLocation"))])


def _syslocation_note(ids: List[int], name: Any, then: str) -> str:
    return (
        f"device(s) {_ids(ids)} here follow SNMP sysLocation (override_sysLocation is off): while their sysLocation "
        f"reads {diff.format_value(name)}, polling re-creates a location of that name and moves them to it{then}"
    )


def _ids(ids: List[int]) -> str:
    if not ids:
        return "none"
    shown = ", ".join(f"#{i}" for i in ids[:_SHOWN_IDS])
    return shown if len(ids) <= _SHOWN_IDS else f"{shown} and {len(ids) - _SHOWN_IDS} more"


def _added_id(answer: Any) -> int | None:
    """The new id from ``Location added with id #N``; None when the message does not carry one."""
    message = answer.get("message") if isinstance(answer, dict) else None
    found = _ADDED_RE.search(message.strip()) if isinstance(message, str) else None
    return int(found.group(1)) if found else None


def _value_errors(op: str, data: Dict[str, Any]) -> List[str]:
    """What the field kinds do not catch: LibreNMS validates neither names nor coordinates and silently truncates,
    clamps or zeroes what does not fit."""
    errors: List[str] = []
    name = data.get("location")
    if isinstance(name, str):
        if op == "update" and not name:
            errors.append("location: a location name cannot be empty")
        elif name != name.strip():
            errors.append("location: leading or trailing spaces are not allowed (LibreNMS trims them on an edit only)")
        elif len(name) > MAX_NAME:
            errors.append(f"location: at most {MAX_NAME} characters")
    missing = []
    for key, bound in (("lat", 90), ("lng", 180)):
        try:
            value = diff.normalise(FIELDS[key], data.get(key))
        except ValueError:
            continue  # reported by the kind check
        if value is not None and abs(value) > bound:
            errors.append(f"{key}: must be between -{bound} and {bound}, got {diff.format_value(value)}")
        elif op == "create" and not value:
            missing.append(key)
    if missing:
        verb = "is" if len(missing) == 1 else "are"
        errors.append(
            f"{' and '.join(missing)} {verb} required to create a location and must not be 0: LibreNMS API v0 cannot "
            "create a location without coordinates"
        )
    return errors


def _maintenance_errors(data: Dict[str, Any], settings: Any) -> List[str]:
    errors: List[str] = []
    unknown = sorted(set(data) - set(MAINTENANCE_KEYS))
    if unknown:
        errors.append(
            f"cannot schedule maintenance with field(s) {', '.join(unknown)}; allowed: {', '.join(MAINTENANCE_KEYS)}"
        )
    duration = data.get("duration")
    parts = _DURATION_RE.fullmatch(duration) if isinstance(duration, str) else None
    if duration is None:
        errors.append('duration is required: hours:minutes, such as "2:00"')
    elif parts is None:
        errors.append(
            f'duration: expected hours:minutes such as "2:00", got {diff.format_value(duration, 40)}; LibreNMS turns '
            "a value without a colon into a schedule that has already ended"
        )
    else:
        minutes = int(parts.group(1)) * 60 + int(parts.group(2))
        limit = settings.max_maintenance_hours
        if minutes == 0:
            errors.append("duration must be longer than 0:00")
        elif minutes > limit * 60:
            errors.append(
                f"duration {duration} is longer than max_maintenance_hours ({limit}); raise "
                "plugins.entries.librenms.settings.max_maintenance_hours to allow it"
            )
    start = data.get("start")
    if start is not None and not _valid_start(start):
        errors.append(
            f'start: expected "YYYY-MM-DD HH:MM:SS" in the LibreNMS server\'s time zone, got '
            f"{diff.format_value(start, 40)}"
        )
    title = data.get("title")
    if title is not None and not (isinstance(title, str) and len(title) <= MAX_TITLE):
        errors.append(f"title: expected a string of at most {MAX_TITLE} characters")
    if data.get("notes") is not None and not isinstance(data["notes"], str):
        errors.append("notes: expected a string")
    behavior = data.get("behavior")
    if behavior is not None and _behavior_name(behavior) is None:
        errors.append(
            f"behavior: expected one of {', '.join(BEHAVIORS)} (or 1, 2, 3), got {diff.format_value(behavior, 40)}"
        )
    return errors


def _valid_start(value: Any) -> bool:
    """LibreNMS parses ``start`` with ``Y-m-d H:i:s`` exactly and answers 500 for anything else."""
    if not isinstance(value, str) or not _START_RE.fullmatch(value):
        return False
    try:
        datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return False
    return True


def _behavior_name(value: Any) -> str | None:
    """The behavior's name (``skip_alerts`` when not given); None for a value LibreNMS would silently replace."""
    if value is None:
        return "skip_alerts"
    if isinstance(value, str):
        return value if value in BEHAVIORS else None
    if isinstance(value, int) and not isinstance(value, bool):
        return next((name for name, number in BEHAVIORS.items() if number == value), None)
    return None


RESOURCE = Location()
