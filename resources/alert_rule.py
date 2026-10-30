"""LibreNMS alert rules: create, update and delete through ``POST``/``PUT rules`` and ``DELETE rules/{id}``.

LibreNMS has one handler for both writes (``add_edit_rule`` in ``includes/html/api_functions.inc.php``) and it
rebuilds the rule from each request: a key the body leaves out is reset (the device, group and location mappings are
emptied, which makes a scoped rule apply to every device; ``disabled`` becomes 0; ``notes`` are cleared; the ``extra``
flags are dropped). So every write here sends the whole rule, read back just before, with the requested values on top.
It never sends ``operations`` or the legacy timing keys (they make LibreNMS create alert operations no API call can
delete) nor hand-written SQL (LibreNMS pastes builder values into the rule's query unescaped, so the builder is
checked for that too), and always sends ``alert_operation_id`` so neither branch can run. A create answers without an
id; rule names are unique, so the new rule is found again by its name. The UI's "Mute alerts" flag (``extra.mute``) is
one of the keys every API write drops, and the alert engine reads it live: update and delete of a muted rule are
refused.
"""

from __future__ import annotations

import copy
import re
from typing import Any, Dict, List, Tuple

from .. import diff, redact
from ..client import LibreNMSError, is_digits, json_object, path
from .base import Field, PartialWrite, Resource, StepError

_FLAGS = ("invert", "recovery", "acknowledgement")  # stored in the rule's ``extra``; absent = the engine's default
_MAPS = ("devices", "groups", "locations")
_EXTRA_KEYS = frozenset({"options", *_FLAGS})  # what add_edit_rule writes into ``extra``; anything else is lost
_MUTED = (
    "rule #{rule_id} is muted in the LibreNMS UI (extra.mute); every API write unmutes it and notifications resume, "
    "and rollback cannot re-mute it; unmute or edit it in the UI"
)
# GET rules/{id} must carry these for an exact snapshot (AlertRule::toArray plus the eager-loaded mapping ids)
_REQUIRED = (
    "id", "name", "severity", "disabled", "builder", "extra", "notes", "proc", "invert_map", "notify_per_entity",
    "max_entities", "alert_operation_id", *_MAPS,
)  # fmt: skip
_UNSET = "unset (engine default)"
_BUILDER_SHOWN = 500  # the builder is what a reviewer must read; the usual 60-character clip hides it
_UNLOCATED = "rule was created but could not be located by name; delete it in the UI"
_OPERATION = "creates a new global alert operation that no API call can delete; pass alert_operation_id instead"
_SQL = "a hand-written SQL query runs as-is in the alert engine; describe the condition with builder"
_REJECTED = {
    "operations": _OPERATION,
    "count": _OPERATION,
    "delay": _OPERATION,
    "interval": _OPERATION,
    "mute": _OPERATION,
    "default_operation_step_duration": "it changes the alert operation shared by every rule that uses it; change it "
    "in the LibreNMS UI",
    "adv_query": _SQL,
    "override_query": _SQL,
    "query": _SQL,
    "rule": "the legacy rule text is not supported; describe the condition with builder (query-builder JSON)",
    "rule_id": "the rule is chosen by the operation's id or match",
}
# data key -> (title, list route, envelope key, name column)
_NAMED = {
    "groups": ("device group", ("devicegroups",), "groups", "name"),
    "locations": ("location", ("resources", "locations"), "locations", "location"),
}
_WHAT = {
    "devices": "device ids or hostnames",
    "groups": "device group ids or names",
    "locations": "location ids or names",
}
# QueryBuilderParser (lnsrc LibreNMS/Alerting) pastes a rule's field, operator and value into the SQL unescaped
_FIELD = r"[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*"  # <table>.<column> or macros.<name>
_FIELD_RE = re.compile(_FIELD)
_FIELD_VALUE = re.compile(f"`{_FIELD}`")  # a value in backticks is pasted as SQL, so it may only name a field
_NUMBER = re.compile(r"-?[0-9]+(\.[0-9]+)?")
_OPERATORS = frozenset({
    "equal", "not_equal", "less", "less_or_equal", "greater", "greater_or_equal", "between", "not_between",
    "begins_with", "not_begins_with", "contains", "not_contains", "ends_with", "not_ends_with", "is_empty",
    "is_not_empty", "is_null", "is_not_null", "regex", "not_regex",
})  # fmt: skip
_VALUELESS = frozenset({"is_empty", "is_not_empty", "is_null", "is_not_null"})
_BETWEEN = frozenset({"between", "not_between"})


def _ids(value: Any, key: str) -> List[int] | None:
    """Sorted mapping ids from ints, digit strings or objects carrying *key*; None for any other shape."""
    if not isinstance(value, list):
        return None
    ids = set()
    for item in value:
        if isinstance(item, dict):
            item = item.get(key)
        if not is_digits(item):
            return None
        ids.add(int(item))
    return sorted(ids)


def _int_or_none(value: Any) -> int | None:
    return int(value) if is_digits(value) else None


def _muted(extra: Dict[str, Any]) -> bool:
    """Whether the alert engine sends nothing for the rule: RunAlerts tests ``! empty($rextra['mute'])``, where PHP
    takes ``"0"`` as empty and ``"false"`` as set."""
    value = extra.get("mute")
    return bool(value) and value != "0"


def _override(extra: Dict[str, Any]) -> bool:
    """Whether the rule runs its stored SQL instead of the builder's, exactly as add_edit_rule decides it."""
    flag = (extra.get("options") or {}).get("override_query")
    return flag is True or flag == "on"


def _canonical_builder(group: Any) -> Any:
    """The query-builder JSON without what the UI adds and the parser ignores (``valid``, ``"not": false``), so a
    rule read back compares equal to the builder that was sent."""
    if not isinstance(group, dict):
        return group
    out = {key: value for key, value in group.items() if key != "valid" and not (key == "not" and value is False)}
    if isinstance(out.get("rules"), list):
        out["rules"] = [
            _canonical_builder(rule) if isinstance(rule, dict) and "condition" in rule else rule
            for rule in out["rules"]
        ]
    return out


def _builder_errors(group: Any, where: str = "builder") -> List[str]:
    """Why LibreNMS would not turn *group* into the SQL it describes. Its parser pastes conditions, fields and values
    into the query unescaped (so nothing may leave its quotes: that would be hand-written SQL again) and ignores
    ``not``; a nested entry is a group when it has a ``condition``, as the parser decides."""
    if not (
        isinstance(group, dict)
        and group.get("condition") in ("AND", "OR")
        and isinstance(group.get("rules"), list)
        and group["rules"]
    ):
        what = "object" if where == "builder" else "group"
        return [f'{where} must be a query-builder {what} with "condition" (AND or OR) and a non-empty "rules" list']
    errors = []
    if group.get("not") not in (None, False):
        errors.append(
            f'{where}: "not" is ignored by LibreNMS, so the rule would match the opposite; negate the operators instead'
        )
    for position, rule in enumerate(group["rules"]):
        at = f"{where}.rules[{position}]"
        errors += (
            _builder_errors(rule, at) if isinstance(rule, dict) and "condition" in rule else _leaf_errors(rule, at)
        )
    return errors


def _leaf_errors(rule: Any, at: str) -> List[str]:
    if not isinstance(rule, dict):
        return [f"{at} must be a rule object or a group"]
    errors = []
    if not (isinstance(rule.get("field"), str) and _FIELD_RE.fullmatch(rule["field"])):
        errors.append(f"{at}: field must be <table>.<column> or macros.<name>")
    operator, value = rule.get("operator"), rule.get("value")
    if operator in ("in", "not_in"):
        errors.append(
            f"{at}: LibreNMS writes {operator} without the parentheses SQL needs, so the rule could not run; use one "
            "equal rule per value joined with OR"
        )
    elif operator not in _OPERATORS:
        errors.append(f"{at}: operator must be one of {', '.join(sorted(_OPERATORS))}")
    elif isinstance(value, str) and value[:1] == "`" == value[-1:]:
        if not _FIELD_VALUE.fullmatch(value):
            errors.append(
                f"{at}: a value in backticks is pasted into the SQL; it may only name a field, `table.column`"
            )
    elif operator in _BETWEEN:
        if not (isinstance(value, list) and len(value) == 2 and all(_number(item) for item in value)):
            errors.append(f"{at}: {operator} needs a list of two numbers, which LibreNMS pastes into the SQL unquoted")
    elif operator not in _VALUELESS and not (
        isinstance(value, (int, float)) or (isinstance(value, str) and not set(value) & set("\"'\\`"))
    ):
        errors.append(
            f"{at}: value must be a number or a string without quotes, backslashes or backticks (LibreNMS pastes it "
            "into the rule's SQL unescaped); to compare with another field use `table.column`"
        )
    return errors


def _number(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    return isinstance(value, (int, float)) or (isinstance(value, str) and bool(_NUMBER.fullmatch(value)))


def _reference(item: Any) -> bool:
    """A mapping entry the operation may give: a positive id, or a name (``-1``, LibreNMS's "global", is not one)."""
    if isinstance(item, bool):
        return False
    if isinstance(item, int):
        return item > 0
    text = item.strip() if isinstance(item, str) else ""
    return text not in ("", "-1") and not (is_digits(text) and int(text) == 0)


class AlertRule(Resource):
    name = "alert_rule"
    title = "alert rule"
    id_key = "id"
    label_key = "name"
    match_keys = ("name",)
    natural_key = "name"
    fields = {
        field.name: field
        for field in (
            Field("name", "str", required=True),
            Field("severity", "enum", choices=("ok", "warning", "critical"), required=True),
            Field("disabled", "bool"),
            Field("builder", "json", required=True),
            Field("notes", "text"),
            Field("proc", "text"),
            Field("invert", "bool", nullable=True),
            Field("recovery", "bool", nullable=True),
            Field("acknowledgement", "bool", nullable=True),
            Field("invert_map", "bool"),
            Field("notify_per_entity", "bool"),
            Field("max_entities", "int", nullable=True),
            Field("alert_operation_id", "int", nullable=True),
            Field("devices", "list_int"),
            Field("groups", "list_int"),
            Field("locations", "list_int"),
            Field("global", "bool"),  # data only: all three mappings empty, the rule applies to every device
        )
    }
    ops = ("create", "update", "delete")
    inverse = {
        "create": ("exact", "deletes the rule again, with any alerts it raised in the meantime"),
        "update": ("exact", ""),
        "delete": (
            "lossy",
            "re-created with a new id; its alert history and template mappings are not restored, and it may notify "
            "again for devices that are currently failing",
        ),
    }

    # -- reads ------------------------------------------------------------------------------------------------------

    def get(self, client: Any, object_id: int, step: Dict[str, Any] | None = None) -> Dict[str, Any] | None:
        body = client.get_or_none(path("rules", object_id))
        rows = client.result(body, "rules") if isinstance(body, dict) else None
        return self._rule(rows[0]) if isinstance(rows, list) and rows else None

    def find(self, client: Any, match: Dict[str, Any]) -> Tuple[int, Dict[str, Any] | None]:
        hits = self._named(client, match.get("name", ""))
        return len(hits), (self._rule(hits[0]) if len(hits) == 1 else None)

    @staticmethod
    def _named(client: Any, name: Any) -> List[Dict[str, Any]]:
        """The rules called *name*, compared case-insensitively as LibreNMS's unique check does."""
        rows = client.result(client.get("rules"), "rules") or []
        wanted = str(name).lower()
        return [row for row in rows if isinstance(row, dict) and str(row.get("name", "")).lower() == wanted]

    def _name_taken(self, client: Any, name: str, rule_id: int) -> str | None:
        """Why rule *rule_id* cannot be renamed to *name*: LibreNMS refuses a name another rule has, with the
        misleading answer ``Update failed : Invalid rule id``."""
        others = sorted({_int_or_none(row.get("id")) or 0 for row in self._named(client, name)} - {rule_id})
        if others:
            return f"alert rule #{others[0]} is already named {name!r}; alert rule names are unique"
        return None

    def _rule(self, raw: Any) -> Dict[str, Any]:
        """*raw* with ``extra`` and ``builder`` decoded and the mapping ids as sorted ints. A rule without every
        field cannot be written back whole (a missing mapping list would make the rule global), so it is refused."""

        def refused(key: str) -> StepError:
            rule_id = raw.get("id") if isinstance(raw, dict) else None
            return StepError(
                f"this LibreNMS version does not return {key} from GET rules/{rule_id}; alert-rule update and delete "
                "are refused because an exact snapshot is impossible"
            )

        if not isinstance(raw, dict):
            raise refused("the rule")
        for key in _REQUIRED:
            if key not in raw:
                raise refused(key)
        extra = {} if raw["extra"] in (None, "", "[]", []) else json_object(raw["extra"])  # PHP encodes {} as []
        if extra is None or not isinstance(extra.get("options") or {}, dict):
            raise refused("extra")
        builder = json_object(raw["builder"])
        if builder is None:
            raise refused("builder")
        rule = {**raw, "extra": extra, "builder": builder}
        for key, id_key in (("devices", "device_id"), ("groups", "id"), ("locations", "id")):
            rule[key] = _ids(raw[key], id_key)
            if rule[key] is None:
                raise refused(key)
        if _override(extra) and not isinstance(raw.get("query"), str):
            raise refused("query")
        return rule

    def _norm(self, name: str, value: Any) -> Any:
        """*value* normalised for field *name*; a value LibreNMS spells in a way the field does not know is kept."""
        try:
            return diff.normalise(self.fields[name], value)
        except ValueError:
            return value

    def state(self, client: Any, obj: Dict[str, Any]) -> Dict[str, Any]:
        extra = obj["extra"]
        state = {"id": int(str(obj["id"]))}
        for name in _REQUIRED:
            if name not in ("id", "builder", "extra"):
                state[name] = self._norm(name, obj[name])
        state["builder"] = _canonical_builder(obj["builder"])
        for flag in _FLAGS:
            state[flag] = self._norm(flag, extra.get(flag))
        state["mute"] = _muted(extra)
        state["override_query"] = _override(extra)
        if state["override_query"]:
            state["query"] = obj["query"]
        return state

    def _body(self, obj: Dict[str, Any]) -> Dict[str, Any]:
        """The write body that recreates *obj* as it is: every key add_edit_rule would otherwise reset, the
        ``extra`` flags the rule has (and no others), and its stored SQL when it overrides the builder."""
        extra = obj["extra"]
        body = {
            "name": obj["name"],
            "severity": obj["severity"],
            "disabled": 1 if self._norm("disabled", obj["disabled"]) is True else 0,
            "builder": copy.deepcopy(obj["builder"]),
            "notes": obj["notes"] or "",
            "proc": obj["proc"] or "",  # written only when the key is present
            "invert_map": self._norm("invert_map", obj["invert_map"]),
            "notify_per_entity": self._norm("notify_per_entity", obj["notify_per_entity"]),
            "max_entities": self._norm("max_entities", obj["max_entities"]),
            "alert_operation_id": self._norm("alert_operation_id", obj["alert_operation_id"]),
            **{key: list(obj[key]) for key in _MAPS},
        }
        body.update({flag: self._norm(flag, extra[flag]) for flag in _FLAGS if flag in extra})
        if _override(extra):
            body.update(override_query=True, adv_query=obj["query"])
        return body

    @staticmethod
    def _merge(body: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
        """*body* with the resolved *data* on top; a flag set to null is left out, which unsets it."""
        merged = dict(body)
        for name, value in data.items():
            if name in _FLAGS and value is None:
                merged.pop(name, None)
            elif name == "disabled":
                merged[name] = int(bool(value))  # anything but 0/1 is stored as 0
            else:
                merged[name] = value
        return merged

    # -- planning ---------------------------------------------------------------------------------------------------

    def validate(self, op: str, data: Dict[str, Any], settings: Any) -> List[str]:
        if op not in ("create", "update"):
            return []
        errors = [f"{key} is not accepted: {reason}" for key, reason in _REJECTED.items() if key in data]
        maps = {key: data[key] for key in _MAPS if key in data}
        errors += super().validate(
            op, {k: v for k, v in data.items() if k not in _REJECTED and k not in maps}, settings
        )
        for key, value in maps.items():
            if not isinstance(value, list) or not all(_reference(item) for item in value):
                hint = ""
                if key == "devices" and isinstance(value, list) and any(item in (-1, "-1") for item in value):
                    hint = '; use "global": true for a rule that applies to every device'
                errors.append(f"{key}: expected a list of {_WHAT[key]}{hint}")
        errors += self._value_errors(data)
        wants_global = self._norm("global", data.get("global")) is True
        if wants_global and any(maps.values()):
            errors.append('"global": true cannot be combined with devices, groups or locations')
        if op == "create":
            if "alert_operation_id" not in data:
                errors.append(
                    "alert_operation_id is required: pass the id of an existing alert operation (copy it from a rule "
                    "that already notifies the right people), or null to create the rule with notifications suppressed"
                )
            if not wants_global and not any(maps.values()):
                errors.append(
                    'a new alert rule needs devices, groups or locations to scope it, or "global": true to apply it '
                    "to every device"
                )
        return errors

    def _value_errors(self, data: Dict[str, Any]) -> List[str]:
        """What LibreNMS would silently alter (``strip_tags``, column truncation) or reject only after saving."""
        errors = []
        name, notes, proc = data.get("name"), data.get("notes"), data.get("proc")
        if isinstance(name, str) and not 1 <= len(name) <= 255:
            errors.append("name must be 1 to 255 characters")
        if isinstance(name, str) and "<" in name:
            errors.append("name must not contain '<': LibreNMS strips HTML tags, and the rule is found again by name")
        if isinstance(notes, str) and "<" in notes:
            errors.append("notes must not contain '<': LibreNMS strips HTML tags from them")
        if isinstance(proc, str) and len(proc) > 80:
            errors.append("proc must be at most 80 characters: LibreNMS cuts it to 80")
        if isinstance(proc, str) and "<" in proc:
            errors.append("proc must not contain '<': LibreNMS strips HTML tags from it")
        for key, message in (
            ("max_entities", "max_entities must be at least 1, or null for no limit"),
            ("alert_operation_id", "alert_operation_id must be a positive id, or null"),
        ):
            number = self._norm(key, data.get(key))
            if isinstance(number, int) and not isinstance(number, bool) and number < 1:
                errors.append(message)
        builder = self._norm("builder", data.get("builder")) if "builder" in data else None
        if isinstance(builder, (dict, list)):  # anything else was reported as a wrong type
            errors += _builder_errors(builder)
        return errors

    def resolve(self, client: Any, op: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalised data with device hostnames and group and location names turned into ids that exist (LibreNMS
        checks none of them, and maps an unknown hostname to null after the rule was saved)."""
        maps = {key: data[key] for key in _MAPS if key in data}
        resolved = super().resolve(client, op, {k: v for k, v in data.items() if k not in maps})
        if "builder" in resolved:
            resolved["builder"] = _canonical_builder(resolved["builder"])
        if "devices" in maps:
            resolved["devices"] = sorted({self._device_id(client, ref) for ref in maps["devices"]})
        for key in ("groups", "locations"):
            if key in maps:
                resolved[key] = self._named_ids(client, key, maps[key])
        return resolved

    def _device_id(self, client: Any, ref: Any) -> int:
        """The id of a device given by id or hostname; an all-digit value is an id, as LibreNMS reads it. No hostname
        holds a ``/`` (add_device refuses one), and an encoded one would reach another route: it is not looked up."""
        text = str(ref).strip()
        if "/" in text:
            raise StepError(f"no LibreNMS device has hostname {text!r}")
        try:
            body = client.get_or_none(path("devices", text))
        except LibreNMSError as exc:
            if exc.kind == "forbidden" and not is_digits(text):
                raise StepError(
                    f"LibreNMS answered 403 for hostname {text}: it does not exist or this token cannot see it "
                    "(LibreNMS returns 403 for unknown hostnames to tokens without global read); use the device id or "
                    "a token with global read"
                ) from None
            raise
        rows = client.result(body, "devices") if isinstance(body, dict) else None
        device = redact.mask(rows[0]) if isinstance(rows, list) and rows and isinstance(rows[0], dict) else None
        device_id = _int_or_none((device or {}).get("device_id"))
        if device_id is None:
            raise StepError(
                f"device #{text} does not exist" if is_digits(text) else f"no LibreNMS device has hostname {text!r}"
            )
        return device_id

    def _named_ids(self, client: Any, key: str, refs: List[Any]) -> List[int]:
        title, route, list_key, name_key = _NAMED[key]
        if not refs:
            return []
        body = client.get_or_none(path(*route))  # both lists answer 404 when there is nothing to list
        rows = client.result(body, list_key) if isinstance(body, dict) else None
        rows = [row for row in rows or [] if isinstance(row, dict)]
        ids = set()
        for ref in refs:
            text = str(ref).strip()
            if is_digits(text):
                hits = [row for row in rows if _int_or_none(row.get("id")) == int(text)]
                if not hits:
                    raise StepError(f"{title} #{text} does not exist")
            else:
                hits = [row for row in rows if str(row.get(name_key) or "").lower() == text.lower()]
                if not hits:
                    raise StepError(f"no {title} is named {text!r}")
                if len(hits) > 1:
                    raise StepError(f"{len(hits)} {title}s are named {text!r}; use the id")
            ids.add(int(str(hits[0]["id"])))
        return sorted(ids)

    def plan_step(self, client: Any, index: int, op: Dict[str, Any], settings: Any) -> Dict[str, Any]:
        step = super().plan_step(client, index, op, settings)
        if step["action"] in ("update", "delete") and step["precondition"]["state"]["mute"]:
            raise StepError(_MUTED.format(rule_id=step["object_id"]))
        if step["action"] == "noop":
            step.pop("snapshot_body", None)
            step.pop("extra_unknown_keys", None)
            return step
        unknown = step.get("extra_unknown_keys")
        if unknown and step["action"] in ("update", "delete"):
            shown = ", ".join(unknown)
            step["notes"].append(
                f"rule #{step['object_id']} has extra keys {shown} that LibreNMS drops on every API write; neither "
                "this step nor its rollback keeps them"
            )
            if step["action"] == "update":
                step["inverse_kind"] = "lossy"
                step["inverse_note"] = f"restores every field except the extra keys {shown}, which LibreNMS drops"
        return step

    def _new_step(
        self,
        index: int,
        action: str,
        op: Dict[str, Any],
        obj: Dict[str, Any] | None,
        resolved_by: str | None,
        values: Dict[str, Any],
    ) -> Dict[str, Any]:
        """The base skeleton, plus what only the raw rule shows: the body that restores it exactly (an update's
        rollback) and the ``extra`` keys LibreNMS will drop."""
        step = super()._new_step(index, action, op, obj, resolved_by, values)
        if obj is not None:
            if action == "update":
                step["snapshot_body"] = self._body(obj)
            unknown = sorted(set(obj["extra"]) - _EXTRA_KEYS - {"mute"})  # mute: dropped when off, refused when on
            unknown += sorted(f"options.{key}" for key in obj["extra"].get("options") or {} if key != "override_query")
            if unknown:
                step["extra_unknown_keys"] = unknown
        return step

    def _prepare(
        self, client: Any, step: Dict[str, Any], data: Dict[str, Any], current: Dict[str, Any] | None, settings: Any
    ) -> Dict[str, Any]:
        data = dict(data)
        wants_global = bool(data.pop("global", False))
        if wants_global:
            data.update({key: [] for key in _MAPS})
        if current is None:
            for key in _MAPS:
                data.setdefault(key, [])
            mapped, was_mapped = any(data[key] for key in _MAPS), False
        else:
            mapped = any(data.get(key, current.get(key)) for key in _MAPS)
            was_mapped = any(current.get(key) for key in _MAPS)
            if was_mapped and not mapped and not wants_global:
                raise StepError(
                    f"this change removes every device, group and location from rule #{current['id']}, which makes it "
                    'apply to every device; pass "global": true to confirm'
                )
            if data.get("name", current["name"]) != current["name"]:
                taken = self._name_taken(client, data["name"], current["id"])
                if taken:
                    raise StepError(taken)
        if not mapped and (current is None or was_mapped):
            step["notes"].append("the rule applies to every device: it has no device, group or location mapping")
        self._note_operation(client, step, data, current)
        if current and current.get("override_query") and data.get("builder", current["builder"]) != current["builder"]:
            step["notes"].append(
                "this rule runs a hand-written SQL query (override_query); a new builder does not change what it "
                "matches"
            )
        return data

    def _note_operation(
        self, client: Any, step: Dict[str, Any], data: Dict[str, Any], current: Dict[str, Any] | None
    ) -> None:
        """LibreNMS does not check ``alert_operation_id``; say what a null or an unfamiliar id means."""
        if "alert_operation_id" not in data:
            return
        wanted = data["alert_operation_id"]
        if current is not None and wanted == current.get("alert_operation_id"):
            return
        if wanted is None:
            step["notes"].append("alert_operation_id is null: LibreNMS sends no notifications for this rule")
            return
        rows = client.result(client.get("rules"), "rules") or []
        if wanted not in {_int_or_none(row.get("alert_operation_id")) for row in rows if isinstance(row, dict)}:
            step["notes"].append(
                f"alert operation #{wanted} is not used by any alert rule; LibreNMS does not check that it exists, so "
                "make sure it is the operation you mean"
            )

    def _snapshot(self, client: Any, obj: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
        return self._body(obj)

    def _payload(self, data: Dict[str, Any], record: Dict[str, Any]) -> Dict[str, Any]:
        return copy.deepcopy({"rule_id": record["object_id"], **self._merge(record["snapshot_body"], data)})

    def describe(self, step: Dict[str, Any]) -> List[str]:
        action = step["action"]
        if action == "update":
            return [
                f"{name}: {self._shown(name, change.get('from'), live=True)} -> "
                f"{self._shown(name, change.get('to'), live=False)}"
                for name, change in sorted((step.get("changes") or {}).items())
            ]
        if action == "create":
            data = dict(step.get("data") or {})
            builder = data.pop("builder", None)
            lines = super().describe({**step, "data": data})
            return [*lines[:1], f"builder: {diff.format_value(builder, _BUILDER_SHOWN)}", *lines[1:]]
        return super().describe(step)

    def _shown(self, name: str, value: Any, *, live: bool) -> str:
        if name in _FLAGS and value is None:
            return _UNSET
        limit = _BUILDER_SHOWN if name == "builder" else 60
        return diff.format_live(self.fields.get(name), value, limit) if live else diff.format_value(value, limit)

    # -- writes -----------------------------------------------------------------------------------------------------

    def _extra_check(
        self, client: Any, step: Dict[str, Any], obj: Dict[str, Any] | None, current: Dict[str, Any] | None
    ) -> str | None:
        rename = (step.get("changes") or {}).get("name")
        if step["action"] == "update" and rename:
            return self._name_taken(client, rename["to"], step["object_id"])
        return None

    def _post(self, client: Any, body: Dict[str, Any]) -> None:
        """``POST rules`` (never with ``rule_id``, which would edit another rule). LibreNMS refuses a create without
        devices, so a rule scoped only by groups or locations, or by nothing, sends ``[-1]``, which it drops."""
        body = {**body, "devices": body.get("devices") or [-1]}
        body.setdefault("proc", "")
        try:
            client.request("POST", "rules", json=body)
        except LibreNMSError as exc:
            # checked before anything is saved; settling it by name would take the other rule for this one
            if exc.status == 500 and "name has already been used" in str(exc).lower():
                raise StepError(
                    f"LibreNMS refused the rule: an alert rule named {body['name']!r} already exists"
                ) from None
            raise

    def _find_id(self, client: Any, name: str) -> int | None:
        count, obj = self.find(client, {"name": name})
        return self._id_of(obj) if count == 1 and obj is not None else None

    def _create_call(self, client: Any, step: Dict[str, Any], context: Dict[str, Any]) -> int | None:
        name = step["data"]["name"]
        self._post(client, self._merge({}, step["data"]))
        new_id = self._find_id(client, name)
        if new_id is None:
            raise PartialWrite(
                f"LibreNMS accepted the new alert rule but no single rule named {name!r} can be found",
                self._entry(None, {"action": "delete", "object_id": None, "located": False}, None, [_UNLOCATED]),
            )
        return new_id

    def _update_call(
        self, client: Any, object_id: int, data: Dict[str, Any], record: Dict[str, Any], context: Dict[str, Any]
    ) -> None:
        """Read the rule and send all of it with *data* on top: a key left out would be reset."""
        live = self.get(client, object_id, record)
        if live is None:
            raise StepError(f"alert rule #{object_id} no longer exists")
        body = {"rule_id": int(object_id), **self._merge(self._body(live), data)}
        try:
            client.request("PUT", "rules", json=body)
        except LibreNMSError as exc:
            # LibreNMS's answer for a name another rule has, checked before anything is saved
            if exc.status == 500 and "update failed : invalid rule id" in str(exc).lower():
                raise StepError(f"LibreNMS refused the write: another alert rule is named {body['name']!r}") from None
            raise

    def _delete_call(self, client: Any, object_id: int, record: Dict[str, Any], context: Dict[str, Any]) -> None:
        client.request("DELETE", path("rules", object_id))

    def _recreate_call(
        self, client: Any, entry: Dict[str, Any], context: Dict[str, Any]
    ) -> Tuple[int | None, Dict[str, Any]]:
        """``POST rules`` from the snapshot; the rule, found by its name, must hold it. Resuming a rollback that died
        after its POST, the rule of that name is the one it created and is verified instead."""
        snapshot = (entry.get("inverse") or {}).get("snapshot") or (context.get("step") or {}).get("snapshot")
        if not snapshot:
            raise StepError("the deleted rule's configuration was not recorded; it cannot be re-created")
        adopted = self._find_id(client, snapshot["name"]) if context.get("resuming") else None
        new_id = adopted
        if new_id is None:
            self._post(client, snapshot)
            new_id = self._find_id(client, snapshot["name"])
        if new_id is None:
            raise StepError(
                f"LibreNMS accepted re-creating alert rule {snapshot['name']!r} but it cannot be found by name; check "
                "it in the LibreNMS UI"
            )
        obj = self.get(client, new_id)
        if obj is not None:
            expected = {key: value for key, value in snapshot.items() if key in self.fields}
            expected["builder"] = _canonical_builder(snapshot["builder"])
            if snapshot.get("override_query"):
                expected["query"] = snapshot["adv_query"]
            wrong = self._mismatches(expected, self.state(client, obj), from_operation=False)
            if wrong:
                raise StepError(f"LibreNMS re-created alert rule #{new_id} but {wrong}")
        by = "" if adopted is None else " by an earlier rollback"
        note = f"re-created with a new id{by}; its alert history and template mappings are not restored"
        return new_id, {"note": note}

    def revert(
        self, client: Any, entry: Dict[str, Any], force: bool, context: Dict[str, Any]
    ) -> Tuple[str, Dict[str, Any]]:
        if entry.get("action") == "create" and (entry.get("inverse") or {}).get("located") is False:
            return "irreversible", {"note": _UNLOCATED}
        return super().revert(client, entry, force, context)


RESOURCE = AlertRule()
