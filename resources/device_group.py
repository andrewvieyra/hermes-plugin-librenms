"""Device groups: static groups list their devices, dynamic groups take theirs from query-builder rules.

LibreNMS keeps no change stamp on a group, so what planning records and apply re-checks is the row itself plus, for a
static group, its sorted member ids (a dynamic group's members move with polling and are left out). The API's traps
shape every request (``add_device_group``, ``update_device_group`` and its ``devices`` routes, ``delete_device_group``
and ``maintenance_devicegroup`` in ``includes/html/api_functions.inc.php``):

- ``rules`` travel as a JSON *string* and come back with a ``joins`` key LibreNMS generates; joins are dropped
  before comparing and never sent.
- Names are compared as LibreNMS's collation does (letter case and trailing spaces ignored). An update that repeats
  the group's current name fails the unique check against the group itself (422), so ``name`` is sent only when it
  changes, and a rename that changes only letter case is impossible.
- Membership is always written as the full list through ``PATCH devicegroups/{id}``: the remove-members route
  deletes every member when its body goes missing.
- Maintenance schedules cannot be read, ended or deleted through API v0, so that action has no inverse.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Tuple

from .. import diff, redact
from ..client import LibreNMSError, is_digits, path
from .base import (
    MAINTENANCE_BEHAVIORS,
    Field,
    PartialWrite,
    Resource,
    StepError,
    _as_int,
    _maybe_committed,
    maintenance_behavior,
    maintenance_minutes,
    valid_maintenance_start,
)

MEMBER_KEYS = ("devices", "devices_add", "devices_remove")
MAINTENANCE_KEYS = ("duration", "start", "title", "notes", "behavior")
BEHAVIORS = MAINTENANCE_BEHAVIORS
TEXT_LIMIT = 255  # name and desc are varchar(255); LibreNMS runs with sql_mode='' and would truncate silently
# alert_schedule.title is varchar(255), and the "[hermes:<plan id>] " prefix takes 35 of it
MAX_TITLE = 200
RULES_SHOWN = 2000  # rules decide which devices a group holds, so a plan shows the new ones whole
RULES_FIELD = Field("rules", "json")
_FORBIDDEN_HOSTNAME = (
    "LibreNMS answered 403 for hostname {}: it does not exist or this token cannot see it (LibreNMS returns 403 for "
    "unknown hostnames to tokens without global read); use the device id or a token with global read"
)


def _name_key(name: Any) -> str:
    """A group name as the unique index compares it (``utf8mb4_unicode_ci`` ignores case and trailing spaces)."""
    return str(name).casefold().rstrip(" ")


def _normalised(field: Field, value: Any) -> Any:
    """*value* in *field*'s canonical form, or as LibreNMS sent it when it has none (compared as it is)."""
    try:
        return diff.normalise(field, value)
    except ValueError:
        return value


def _without_joins(value: Any) -> Any:
    """Rules as compared and sent: canonical JSON without the ``joins`` LibreNMS adds whenever it saves them."""
    rules = _normalised(RULES_FIELD, value)
    if isinstance(rules, dict):
        rules.pop("joins", None)
    return rules


def _rules_shaped(rules: Any) -> bool:
    """What LibreNMS's QueryBuilderParser turns into SQL: a top-level condition and at least one rule."""
    return (
        isinstance(rules, dict)
        and rules.get("condition") in ("AND", "OR")
        and isinstance(rules.get("rules"), list)
        and bool(rules["rules"])
    )


def _device_ref(value: Any) -> str | None:
    """A device reference as its path segment: a positive id's digits or a hostname; None for anything else. A
    hostname never holds ``/`` (LibreNMS cannot route it even encoded) or unprintable characters."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return str(value) if value > 0 else None
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if is_digits(text):
        return str(int(text)) if int(text) > 0 else None
    return text if text.isprintable() and "/" not in text else None


def _refs(value: Any) -> set:
    return {_device_ref(item) for item in value} - {None} if isinstance(value, list) else set()


def _shown_ref(ref: str) -> str:
    return f"#{ref}" if is_digits(ref) else diff.format_value(ref)


def _ids(ids: Iterable[Any]) -> str:
    return ", ".join(f"#{i}" for i in ids)


def _id_set(value: Any) -> set:
    """Ids from a LibreNMS id list: ints, numeric strings or objects carrying ``id``."""
    items = value if isinstance(value, list) else []
    return {_as_int(item.get("id") if isinstance(item, dict) else item) for item in items} - {None}


def _device_id(client: Any, ref: str) -> int | None:
    """The id of the device *ref* names (an id's digits, or an exact hostname), or None when there is none. The
    device object carries SNMP credentials for an admin token, so it is masked although only its id is kept."""
    try:
        body = client.get_or_none(path("devices", ref))
    except LibreNMSError as exc:
        if exc.kind == "forbidden" and not is_digits(ref):
            raise StepError(_FORBIDDEN_HOSTNAME.format(ref)) from None
        raise
    rows = redact.mask(client.result(body, "devices")) if body is not None else None
    if isinstance(rows, list) and rows and isinstance(rows[0], dict):
        return _as_int(rows[0].get("device_id"))
    return None


def _create_body(values: Dict[str, Any]) -> Dict[str, Any]:
    """``POST devicegroups``: every key LibreNMS reads is sent (it reads optional keys without isset, which fails on
    debug installs), ``rules`` as the JSON string its validator requires."""
    body = {"name": values["name"], "type": values["type"], "desc": values.get("desc") or ""}
    if values["type"] == "static":
        body["devices"] = list(values.get("devices") or [])
    else:
        body["rules"] = json.dumps(values.get("rules"))
    return body


def _maintenance_note(duration: str | None) -> str:
    expiry = f"it expires after {duration}" if duration else "it expires on its own"
    return (
        f"LibreNMS API v0 cannot end or delete maintenance; {expiry}. To end it early, delete the schedule whose "
        "title starts with [hermes:<plan id>] under Alerts → Scheduled Maintenance."
    )


def _maintenance_errors(data: Dict[str, Any], settings: Any) -> List[str]:
    """LibreNMS accepts a duration without a colon and creates a schedule that has already ended, and a start in any
    other format fails with a 500, so both are checked here."""
    errors: List[str] = []
    unknown = sorted(set(data) - set(MAINTENANCE_KEYS))
    if unknown:
        errors.append(f"maintenance does not take {', '.join(unknown)}; allowed: {', '.join(MAINTENANCE_KEYS)}")
    duration = data.get("duration")
    minutes = maintenance_minutes(duration)
    if minutes is None:
        errors.append('duration is required as hours:minutes, such as "2:00" or "0:30"')
    else:
        limit = settings.max_maintenance_hours
        if minutes == 0:
            errors.append("duration must be longer than 0:00")
        elif minutes > limit * 60:
            errors.append(f"duration {duration} exceeds max_maintenance_hours ({limit})")
    if data.get("start") is not None and not valid_maintenance_start(data["start"]):
        errors.append(
            'start: expected "YYYY-MM-DD HH:MM:SS" in the LibreNMS server\'s time zone, or null to start on apply'
        )
    title = data.get("title")
    if title is not None and not (isinstance(title, str) and len(title) <= MAX_TITLE):
        errors.append(f"title: expected a string of at most {MAX_TITLE} characters")
    if data.get("notes") is not None and not isinstance(data["notes"], str):
        errors.append("notes: expected a string")
    if data.get("behavior") is not None and maintenance_behavior(data["behavior"]) is None:
        errors.append(
            f"behavior: expected one of {', '.join(BEHAVIORS)} (or 1-3), got {diff.format_value(data['behavior'])}"
        )
    return errors


def _maintenance_params(data: Dict[str, Any]) -> Dict[str, Any]:
    behavior = data.get("behavior")
    return {
        "duration": data["duration"],
        "start": data.get("start"),
        "title": data.get("title") or None,
        "notes": data.get("notes") or "",
        "behavior": "skip_alerts" if behavior is None else maintenance_behavior(behavior),
    }


def _change_line(name: str, change: Dict[str, Any], fields: Dict[str, Field]) -> str:
    """Membership as added and removed ids (a long list clipped to one line would hide what changes); rules whole."""
    if name == "devices":
        old, new = set(change.get("from") or []), set(change.get("to") or [])
        parts = [
            f"add {_ids(sorted(new - old))}" if new - old else "",
            f"remove {_ids(sorted(old - new))}" if old - new else "",
        ]
        return f"devices: {'; '.join(part for part in parts if part)} ({len(old)} -> {len(new)} members)"
    if name == "rules":
        return (
            f"rules: {diff.format_value(change.get('from'), 200)} -> {diff.format_value(change.get('to'), RULES_SHOWN)}"
        )
    return diff.render_changes({name: change}, fields)[0]


class DeviceGroup(Resource):
    name = "device_group"
    title = "device group"
    id_key = "id"
    label_key = "name"
    match_keys = ("name",)
    natural_key = "name"
    fields = {
        "name": Field("name", "str", required=True),
        "type": Field("type", "enum", choices=("static", "dynamic"), required=True),
        "desc": Field("desc", "text"),
        "devices": Field("devices", "list_int"),
        "devices_add": Field("devices_add", "list_int", create=False),
        "devices_remove": Field("devices_remove", "list_int", create=False),
        "rules": RULES_FIELD,
    }
    ops = ("create", "update", "delete", "maintenance")
    inverse = {
        "create": ("exact", ""),
        "update": ("exact", ""),
        "delete": (
            "lossy",
            "re-created with a new id; alert rules, user permissions and maintenance linked to the old id are not "
            "restored",
        ),
        "maintenance": ("none", _maintenance_note(None)),
    }

    # -- reads ------------------------------------------------------------------------------------------------------

    def get(self, client: Any, object_id: int, step: Dict[str, Any] | None = None) -> Dict[str, Any] | None:
        """The group from ``GET devicegroups`` (there is no single-group read: ``devicegroups/{id}`` lists members)."""
        wanted = _as_int(object_id)
        row = next((row for row in self._groups(client) if _as_int(row.get("id")) == wanted), None)
        return None if row is None else self._with_members(client, row)

    def find(self, client: Any, match: Dict[str, Any]) -> Tuple[int, Dict[str, Any] | None]:
        rows = self._named(client, match.get("name"))
        if len(rows) != 1:
            return len(rows), None
        return 1, self._with_members(client, rows[0])

    def state(self, client: Any, obj: Dict[str, Any]) -> Dict[str, Any]:
        state = {
            "id": _as_int(obj.get("id")),
            "name": _normalised(self.fields["name"], obj.get("name")),
            "desc": _normalised(self.fields["desc"], obj.get("desc")),
            "type": obj.get("type"),
        }
        if state["type"] == "static":
            state["devices"] = _normalised(self.fields["devices"], obj.get("devices") or [])
        else:
            state["rules"] = _without_joins(obj.get("rules"))
        return state

    def _groups(self, client: Any) -> List[Dict[str, Any]]:
        """Every group; LibreNMS answers 404 rather than an empty list when there is none."""
        body = client.get_or_none("devicegroups")
        rows = client.result(body, "groups") if body is not None else None
        return [row for row in rows or [] if isinstance(row, dict)]

    def _named(self, client: Any, name: Any) -> List[Dict[str, Any]]:
        """Groups whose name equals *name* as LibreNMS's unique index compares them."""
        wanted = _name_key(name)
        return [row for row in self._groups(client) if _name_key(row.get("name") or "") == wanted]

    def _member_ids(self, client: Any, group_id: Any) -> List[int]:
        """Member device ids, from the id-only form of ``GET devicegroups/{id}`` (``?full`` returns SNMP
        credentials); LibreNMS answers 404 for an empty group."""
        body = client.get_or_none(path("devicegroups", group_id))
        rows = client.result(body, "devices") if body is not None else None
        return sorted({_as_int(row.get("device_id")) for row in rows or [] if isinstance(row, dict)} - {None})

    def _with_members(self, client: Any, row: Dict[str, Any]) -> Dict[str, Any]:
        obj = dict(row)
        if obj.get("type") == "static":
            obj["devices"] = self._member_ids(client, _as_int(obj.get("id")))
        return obj

    # -- planning ---------------------------------------------------------------------------------------------------

    def validate(self, op: str, data: Dict[str, Any], settings: Any) -> List[str]:
        if op == "maintenance":
            return _maintenance_errors(data, settings)
        if op not in ("create", "update"):
            return super().validate(op, data, settings)
        # Member lists take hostnames as well as ids, which the list_int kind does not: they are checked here.
        lists = {key: data[key] for key in MEMBER_KEYS if key in data and (op == "update" or key == "devices")}
        errors = super().validate(op, {key: value for key, value in data.items() if key not in lists}, settings)
        for key, value in lists.items():
            bad = value if not isinstance(value, list) else [item for item in value if _device_ref(item) is None]
            if not isinstance(value, list) or bad:
                errors.append(f"{key}: expected a list of device ids or hostnames, got {diff.format_value(bad)}")
        if "devices" in lists and len(lists) > 1:
            errors.append("give devices (the complete member list) or devices_add / devices_remove, not both")
        both = sorted(_refs(lists.get("devices_add")) & _refs(lists.get("devices_remove")))
        if both:
            errors.append(
                f"{', '.join(_shown_ref(ref) for ref in both)} cannot be in both devices_add and devices_remove"
            )
        errors += self._text_errors(op, data)
        rules = _normalised(RULES_FIELD, data.get("rules"))
        if isinstance(rules, (dict, list)) and not _rules_shaped(rules):
            errors.append(
                'rules: expected a query-builder object with "condition" ("AND" or "OR") and a non-empty "rules" list'
            )
        if op == "create":
            kind = data.get("type")
            if kind == "static" and "rules" in data:
                errors.append("rules: only a dynamic group has rules; a static group lists its devices")
            if kind == "dynamic" and "devices" in data:
                errors.append("devices: a dynamic group's members follow its rules; give rules instead")
            if kind == "dynamic" and "rules" not in data:
                errors.append("rules is required to create a dynamic device group")
        return errors

    @staticmethod
    def _text_errors(op: str, data: Dict[str, Any]) -> List[str]:
        errors: List[str] = []
        name, desc = data.get("name"), data.get("desc")
        if isinstance(name, str) and not name.strip() and (name or op == "update"):
            errors.append("name must not be blank")
        if op == "update" and "desc" in data and desc is None:
            errors.append('desc: null is not allowed; use "" to clear it')
        for key, value in (("name", name), ("desc", desc)):
            if isinstance(value, str) and len(value) > TEXT_LIMIT:
                errors.append(f"{key}: at most {TEXT_LIMIT} characters (got {len(value)})")
        return errors

    def resolve(self, client: Any, op: str, data: Dict[str, Any]) -> Dict[str, Any]:
        if op == "maintenance":
            return _maintenance_params(data)
        lists = {key: data[key] for key in MEMBER_KEYS if key in data} if op in ("create", "update") else {}
        resolved = super().resolve(client, op, {key: value for key, value in data.items() if key not in lists})
        if "rules" in resolved:
            resolved["rules"] = _without_joins(resolved["rules"])
        if lists:
            ids = self._device_ids(client, [ref for refs in lists.values() for ref in refs])
            for key, refs in lists.items():
                resolved[key] = sorted({ids[_device_ref(ref)] for ref in refs})
        return resolved

    def _device_ids(self, client: Any, refs: List[Any]) -> Dict[str, int]:
        """``{reference: device_id}`` for every reference; StepError naming each one that matches no device."""
        found: Dict[str, int] = {}
        missing: List[str] = []
        for ref in dict.fromkeys(_device_ref(item) for item in refs):
            device_id = _device_id(client, ref)
            if device_id is None:
                missing.append(ref)
            else:
                found[ref] = device_id
        if missing:
            raise StepError(f"no LibreNMS device matches {', '.join(_shown_ref(ref) for ref in missing)}")
        return found

    def plan_step(self, client: Any, index: int, op: Dict[str, Any], settings: Any) -> Dict[str, Any]:
        step = super().plan_step(client, index, op, settings)
        if step["action"] == "delete":
            self._note_blast_radius(client, step)
        return step

    def _prepare(
        self, client: Any, step: Dict[str, Any], data: Dict[str, Any], current: Dict[str, Any] | None, settings: Any
    ) -> Dict[str, Any]:
        data = dict(data)
        if current is None:
            taken = self._named(client, data["name"])
            if taken:
                raise StepError(
                    f"a device group named {diff.format_value(taken[0].get('name'))} already exists "
                    f'(#{taken[0].get("id")}); update it by id, or give match {{"name": ...}} to update it if it exists'
                )
            data.setdefault("desc", "")
            if data["type"] == "static":
                data.setdefault("devices", [])
            return data
        group = f"device group #{current['id']}"
        if "type" in data and data["type"] != current["type"]:
            raise StepError(
                f"{group} is {current['type']}: changing a group's type is not supported; create a new group"
            )
        given = [key for key in MEMBER_KEYS if key in data]
        if current["type"] == "dynamic" and given:
            raise StepError(
                f"{group} is dynamic: its members follow its rules, so {given[0]} cannot be set; change rules"
            )
        if current["type"] == "static" and "rules" in data:
            raise StepError(f"{group} is static: only a dynamic group has rules")
        if "devices_add" in data or "devices_remove" in data:
            add, remove = data.pop("devices_add", []), data.pop("devices_remove", [])
            data["devices"] = self._merged(step, current["devices"], add, remove)
        if "name" in data and data["name"] != current["name"]:
            if _name_key(data["name"]) != _name_key(current["name"]):
                taken = self._named(client, data["name"])
                if taken:
                    raise StepError(
                        f"a device group named {diff.format_value(data['name'])} already exists (#{taken[0].get('id')})"
                    )
            elif step.get("upsert"):
                data.pop("name")
                step["notes"].append(
                    f"name: LibreNMS cannot change only the letter case or trailing spaces of a group name; it "
                    f"stays {diff.format_value(current['name'])}"
                )
            else:
                raise StepError(
                    "LibreNMS cannot change only the letter case or trailing spaces of a group name: its unique check "
                    "matches the group itself"
                )
        return data

    @staticmethod
    def _merged(step: Dict[str, Any], have: List[int], add: List[int], remove: List[int]) -> List[int]:
        """The full member list devices_add / devices_remove describe (LibreNMS is sent whole lists only)."""
        both = sorted(set(add) & set(remove))
        if both:
            raise StepError(f"devices {_ids(both)} cannot be in both devices_add and devices_remove")
        present, absent = sorted(set(add) & set(have)), sorted(set(remove) - set(have))
        if present:
            step["notes"].append(f"devices_add: {_ids(present)} already in the group")
        if absent:
            step["notes"].append(f"devices_remove: {_ids(absent)} not in the group")
        return sorted((set(have) | set(add)) - set(remove))

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
        step["inverse_note"] = _maintenance_note(data["duration"])
        members = self._members_now(client, step["object_id"], current)
        step["member_count"] = len(members)
        if not members:
            step["notes"].append(
                f"device group {diff.format_value(step['label'])} has no members now; the maintenance covers devices "
                "that join it before it ends"
            )
        return step

    def _snapshot(self, client: Any, obj: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
        """What re-creating the group needs: name, type, desc and its members or rules (rules without joins)."""
        return {key: value for key, value in current.items() if key != "id"}

    def _members_now(self, client: Any, group_id: int, current: Dict[str, Any]) -> List[int]:
        return current["devices"] if current["type"] == "static" else self._member_ids(client, group_id)

    def _note_blast_radius(self, client: Any, step: Dict[str, Any]) -> None:
        """What a delete takes with it beyond the row: its members' scope and the alert rules mapped to it."""
        group_id = step["object_id"]
        step["member_count"] = len(self._members_now(client, group_id, step["precondition"]["state"]))
        try:
            body = client.get_or_none("rules")
        except LibreNMSError as exc:
            step["notes"].append(f"could not list the alert rules that use this group: {exc}")
            return
        rules = client.result(body, "rules") if body is not None else None
        users = [
            f"#{rule.get('id')} {diff.format_value(rule.get('name'))}"
            for rule in rules or []
            if isinstance(rule, dict) and group_id in _id_set(rule.get("groups"))
        ]
        if users:
            step["notes"].append(
                f"alert rule(s) {', '.join(users)} are scoped to this group; deleting it removes that scope and a "
                "rollback does not restore it"
            )

    def describe(self, step: Dict[str, Any]) -> List[str]:
        action = step["action"]
        if action == "create":
            data = step.get("data") or {}
            lines = [
                f"name {diff.format_value(data.get('name'))}, type {data.get('type')}, "
                f"desc {diff.format_value(data.get('desc', ''))}"
            ]
            if "devices" in data:
                lines.append(f"devices ({len(data['devices'])}): {_ids(data['devices']) or 'none'}")
            if "rules" in data:
                lines.append(f"rules: {diff.format_value(data['rules'], RULES_SHOWN)}")
            if step.get("exists_check"):
                lines.append(f"precondition: no device group matches {diff.format_value(step['exists_check'])}")
            return lines
        if action == "update":
            return [_change_line(name, change, self.fields) for name, change in sorted(step["changes"].items())]
        lines = [self._maintenance_line(step)] if action == "maintenance" else super().describe(step)
        if "member_count" in step:
            lines.append(f"{step['member_count']} member device(s) now")
        return lines

    @staticmethod
    def _maintenance_line(step: Dict[str, Any]) -> str:
        params = step.get("params") or {}
        parts = [
            f"duration {params.get('duration')}",
            f"behavior {params.get('behavior')}",
            f"title {diff.format_value(params.get('title') or step.get('label'))}",
            f"start {diff.format_value(params['start'])}" if params.get("start") else "starting on apply",
        ]
        if params.get("notes"):
            parts.append(f"notes {diff.format_value(params['notes'])}")
        return ", ".join(parts)

    # -- apply ------------------------------------------------------------------------------------------------------

    def _extra_check(
        self, client: Any, step: Dict[str, Any], obj: Dict[str, Any] | None, current: Dict[str, Any] | None
    ) -> str | None:
        """Maintenance needs the group to keep its type; a write fails part-way when a device it adds is gone (the
        group or the members before it stay changed), and a rename when another group took the name."""
        if step["action"] == "maintenance":
            planned = step["precondition"]["state"]["type"]
            if current["type"] != planned:
                return f"device group #{step['object_id']} changed type since planning ({planned} -> {current['type']})"
            return None
        rename = (step.get("changes") or {}).get("name")
        if rename and self._named(client, rename["to"]):
            return f"a device group named {diff.format_value(rename['to'])} now exists"
        if step["action"] == "create":
            added = step["data"].get("devices") or []
        else:
            change = (step.get("changes") or {}).get("devices") or {}
            added = sorted(set(change.get("to") or []) - set(change.get("from") or []))
        gone = [device_id for device_id in added if _device_id(client, str(device_id)) is None]
        if gone:
            return f"device(s) {_ids(gone)} no longer exist"
        return None

    def _payload(self, data: Dict[str, Any], record: Dict[str, Any]) -> Dict[str, Any]:
        return {key: json.dumps(value) if key == "rules" else value for key, value in data.items()}

    def _create_call(self, client: Any, step: Dict[str, Any], context: Dict[str, Any]) -> int | None:
        answer = client.request("POST", "devicegroups", json=_create_body(step["data"]))
        return _as_int(client.result(answer, "id"))

    def _update_call(
        self, client: Any, object_id: int, data: Dict[str, Any], record: Dict[str, Any], context: Dict[str, Any]
    ) -> None:
        client.request("PATCH", path("devicegroups", object_id), json=self._payload(data, record))

    def _delete_call(self, client: Any, object_id: int, record: Dict[str, Any], context: Dict[str, Any]) -> None:
        client.request("DELETE", path("devicegroups", object_id))

    def _recreate_call(
        self, client: Any, entry: Dict[str, Any], context: Dict[str, Any]
    ) -> Tuple[int | None, Dict[str, Any]]:
        """``POST devicegroups`` from the delete's snapshot. Members deleted since are left out, because LibreNMS
        would fail on them after creating the group; the result is verified against the snapshot. Resuming a
        rollback that died after its POST, the group of that name is the one it created and is verified instead."""
        snapshot = dict((entry.get("inverse") or {}).get("snapshot") or {})
        details: Dict[str, Any] = {}
        if snapshot.get("type") == "static":
            devices = list(snapshot.get("devices") or [])
            gone = [device_id for device_id in devices if _device_id(client, str(device_id)) is None]
            snapshot["devices"] = [device_id for device_id in devices if device_id not in gone]
            details["skipped_devices"] = gone
        new_id = None
        if context.get("resuming"):
            count, obj = self.find(client, {"name": snapshot["name"]})
            new_id = self._id_of(obj) if count == 1 and obj is not None else None
            if new_id is not None:
                details["note"] = "re-created by an earlier rollback"
        if new_id is None:
            answer = client.request("POST", "devicegroups", json=_create_body(snapshot))
            new_id = _as_int(client.result(answer, "id"))
        if new_id is None:
            _, obj = self.find(client, {"name": snapshot["name"]})
            new_id = self._id_of(obj) if obj is not None else None
        obj = self.get(client, new_id) if new_id is not None else None
        if obj is None:
            name = diff.format_value(snapshot.get("name"))
            raise StepError(f"LibreNMS accepted the re-create of {name} but it cannot be read back")
        expected = {key: value for key, value in snapshot.items() if key in self.fields}
        wrong = self._mismatches(expected, self.state(client, obj), from_operation=False)
        if wrong:
            raise StepError(f"re-created device group #{new_id} but {wrong}")
        return new_id, details

    def _execute_action(self, client: Any, step: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """``POST devicegroups/{id}/maintenance``, titled with the plan id: API v0 cannot read schedules back, so the
        title is how a person finds this one later. A failure that may have created it is a PartialWrite."""
        params, object_id = step["params"], step["object_id"]
        body = {
            "title": f"[hermes:{context['plan_id']}] {params.get('title') or step['label']}",
            "duration": params["duration"],
            "notes": params.get("notes") or "",
            "behavior": BEHAVIORS[params.get("behavior") or "skip_alerts"],
        }
        if params.get("start"):
            body["start"] = params["start"]
        try:
            client.request("POST", path("devicegroups", object_id, "maintenance"), json=body)
        except LibreNMSError as exc:
            if not _maybe_committed(exc):
                raise
            note = (
                f"look for a schedule titled {diff.format_value(body['title'], 120)} under Alerts → Scheduled "
                "Maintenance; API v0 cannot read it back"
            )
            raise PartialWrite(
                f"{self.scrub(str(exc), step)} (LibreNMS may have created the maintenance schedule anyway)",
                self._entry(object_id, None, None, [note]),
            ) from exc
        notes = [f"schedule title: {body['title']}"]
        if not params.get("start"):
            notes += self._verify_maintenance(client, step)
        return self._entry(object_id, None, None, notes)

    def _verify_maintenance(self, client: Any, step: Dict[str, Any]) -> List[str]:
        """A note when a member does not report the maintenance that just started. Never a failure: the schedule
        exists whatever this read says, and failing the step would hide that."""
        try:
            members = self._member_ids(client, step["object_id"])
            if not members:
                return ["the group has no members, so the maintenance could not be checked on a device"]
            body = client.get(path("devices", members[0], "maintenance"))
            if client.result(body, "is_under_maintenance") is True:
                return []
            return [
                f"device #{members[0]} in the group does not report maintenance yet; check the schedule in LibreNMS"
            ]
        except Exception as exc:
            return [f"the maintenance could not be checked on a member device: {self.scrub(str(exc), step)}"]


RESOURCE = DeviceGroup()
