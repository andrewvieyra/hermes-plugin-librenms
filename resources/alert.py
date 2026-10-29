"""Alert faults: acknowledge and unmute.

What API v0 calls an alert is an ``alert_faults`` row: one entity on one device for one rule. Three LibreNMS quirks
shape this module. A plain ``GET faults/{id}`` answers only active faults, so every read asks for all states. Ack
and unmute answer HTTP 200 ``No Alert by that ID`` when they changed nothing. And unless the rule notifies per entity
(and the device's open faults stay within its limit), LibreNMS applies an ack or unmute to every open fault of the
same device and rule, whatever its state: the plan records those siblings and shows them, apply refuses when they
moved, and rollback refuses (unless forced) to reach faults whose acknowledgement this plan did not make or remove,
or faults that opened or moved since the apply. Neither action is exactly reversible: the note history is
append-only, unmute always returns a fault to active (1) and notifications already sent stay sent.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Tuple

from .. import diff, redact
from ..client import is_digits, path
from .base import Field, Resource, StepError

CLEAR = 0
ACTIVE = 1
ACKNOWLEDGED = 2
ACKABLE = (1, 3, 4, 5)  # active, worse, better, changed
STATE_NAMES = {0: "clear", 1: "active", 2: "acknowledged", 3: "worse", 4: "better", 5: "changed"}
ALL_STATES = "0,1,2,3,4,5"  # without it LibreNMS hides every fault that is not active
NOTE_LIMIT = 500
_DATA_KEYS = {"ack": ("note", "until_clear"), "unmute": ("note",)}
_NO_ALERT = re.compile(r"no alert by that id", re.IGNORECASE)  # ack says "Alert", unmute "alert"
# The note becomes one line of the fault's history: a line break could forge an "Ack (<someone>)" line under it.
_CONTROL = re.compile("[\x00-\x1f\x7f-\x9f\u2028\u2029]")
_FLAG = Field("flag", "bool")


def _number(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        return int(str(value))
    except ValueError:
        return None


def _flag(value: Any) -> bool:
    """A flag as LibreNMS stores it: ``1``/``"1"``/``true``, and ``info.until_clear`` verbatim from an ack body."""
    try:
        return bool(diff.normalise(_FLAG, value))
    except ValueError:
        return bool(value)


def _info(obj: Dict[str, Any]) -> Dict[str, Any]:
    """``info`` is read raw: a JSON string, ``"[]"`` or null."""
    info = obj.get("info")
    if isinstance(info, str):
        try:
            info = json.loads(info)
        except ValueError:
            return {}
    return info if isinstance(info, dict) else {}


def _rejected(field: Field, value: Any) -> str | None:
    """diff's message for a value *field* cannot hold, else None."""
    try:
        diff.normalise(field, value)
    except ValueError as exc:
        return str(exc)
    return None


def _rows(body: Any, key: str) -> List[Dict[str, Any]]:
    rows = body.get(key) if isinstance(body, dict) else None
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def _shown(state: Any) -> str:
    return f"{state} ({STATE_NAMES[state]})" if state in STATE_NAMES else diff.format_value(state)


def _ids(fault_ids: Any) -> str:
    return ", ".join(f"#{fault_id}" for fault_id in sorted(fault_ids, key=int))


def _spread(action: str, fault_ids: Any) -> str:
    """Why an ack or unmute cannot be confined to one fault of a rule that does not notify per entity."""
    if action == "unmute":
        return (
            f"unmute cannot be limited to one fault; it would also unmute faults {_ids(fault_ids)} that were "
            "acknowledged before this plan"
        )
    return (
        f"ack cannot be limited to one fault; it would also acknowledge faults {_ids(fault_ids)} that were not "
        "acknowledged before this plan"
    )


def _default_limit(rule_id: Any, siblings: Dict[str, Any]) -> str:
    """Why a rule that notifies per entity is planned as if it did not: it leaves its limit to a setting."""
    count = sum(1 for state in siblings.values() if state != CLEAR)
    return (
        f"rule #{rule_id} sets no max_entities, so whether it notifies per entity with {count} open faults depends on "
        "LibreNMS's default limit (alert_rule.default_max_entities, 20 unless changed), which the API cannot read"
    )


def _sibling_drift(before: Dict[str, Any], after: Dict[str, Any]) -> List[str]:
    lines = []
    for fault_id in sorted(set(before) | set(after), key=int):
        old, new = before.get(fault_id), after.get(fault_id)
        if old is None:
            lines.append(f"#{fault_id}: newly open (state {new})")
        elif new is None:
            lines.append(f"#{fault_id}: no longer open")
        elif old != new:
            lines.append(f"#{fault_id}: state {old} -> {new}")
    return lines


class Alert(Resource):
    name = "alert"
    title = "alert"
    id_key = "id"
    label_key = "hostname"
    parent_key = "device_id"
    fields = {"note": Field("note", "str"), "until_clear": Field("until_clear", "bool")}
    ops = ("ack", "unmute")
    inverse = {
        "ack": (
            "lossy",
            "rollback unmutes the fault: the state returns to active (also from worse, better or changed), the "
            "acknowledgement note stays in the fault's history and notifications already sent are not recalled",
        ),
        "unmute": (
            "lossy",
            "rollback acknowledges the fault again with its previous until_clear; both notes stay in the fault's "
            "history and notifications sent in between are not recalled",
        ),
    }

    # -- reads ------------------------------------------------------------------------------------------------------

    def get(self, client: Any, object_id: int, step: Dict[str, Any] | None = None) -> Dict[str, Any] | None:
        """The fault in any state, or None. ``details`` (the rule query's rows: any column of any joined table,
        SNMP credentials and contacts included) is dropped and credential keys are masked."""
        if not is_digits(object_id) or int(object_id) <= 0:
            return None  # LibreNMS ignores an id filter that is 0 or not a number and lists every fault
        wanted = int(object_id)
        rows = _rows(client.get(path("faults", wanted), {"state": ALL_STATES}), "alerts")
        row = next((row for row in rows if _number(row.get("id")) == wanted), None)
        return None if row is None else redact.mask({key: value for key, value in row.items() if key != "details"})

    def state(self, client: Any, obj: Dict[str, Any]) -> Dict[str, Any]:
        """Identity, state, open and until_clear. The note is left out: it is append-only history, not state."""
        return {
            "id": _number(obj.get("id")),
            "rule_id": _number(obj.get("rule_id")),
            "device_id": _number(obj.get("device_id")),
            "hostname": str(obj.get("hostname") or ""),
            "state": _number(obj.get("state")),
            "open": _flag(obj.get("open")),
            "until_clear": _flag(_info(obj).get("until_clear")),
        }

    def label(self, obj_or_data: Dict[str, Any]) -> str:
        rule, host = obj_or_data.get("name"), obj_or_data.get("hostname")
        return f"{rule} on {host}" if rule and host else super().label(obj_or_data)

    def _open_faults(self, client: Any, current: Dict[str, Any]) -> Dict[str, int]:
        """``{fault id: state}`` of the open faults of this fault's device and rule, itself included."""
        body = client.get("faults", {"alert_rule": current["rule_id"], "state": ALL_STATES})
        return {
            str(_number(row.get("id"))): _number(row.get("state"))
            for row in _rows(body, "alerts")
            if _number(row.get("device_id")) == current["device_id"] and _flag(row.get("open"))
        }

    def _siblings(self, client: Any, current: Dict[str, Any]) -> Tuple[bool, Dict[str, int], bool]:
        """``(per_entity, {fault id: state}, assumed)`` over the open faults of this fault's device and rule. As
        LibreNMS's AlertUtil decides it, an ack or unmute reaches only this fault while the rule notifies per entity
        and the open faults that are not clear (0) number at most ``max(1, max_entities)``; otherwise all of them.
        A null ``max_entities`` means LibreNMS's own default, which the API cannot read: per entity is then certain
        only for a single fault, and ``assumed`` says it was taken as off."""
        siblings = self._open_faults(client, current)
        rules = _rows(client.get(path("rules", current["rule_id"])), "rules")
        rule = rules[0] if rules else {}
        notify, limit = _flag(rule.get("notify_per_entity")), _number(rule.get("max_entities"))
        count = sum(1 for state in siblings.values() if state != CLEAR)
        within = count <= (1 if limit is None else max(1, limit))
        return notify and within, siblings, notify and not within and limit is None

    @staticmethod
    def _others(step: Dict[str, Any]) -> Dict[str, int]:
        """The other open faults the step's write reaches: none when the rule notifies per entity."""
        precondition = step.get("precondition") or {}
        if precondition.get("per_entity", True):
            return {}
        own = str(step["object_id"])
        return {fault_id: state for fault_id, state in (precondition.get("siblings") or {}).items() if fault_id != own}

    # -- planning ---------------------------------------------------------------------------------------------------

    def validate(self, op: str, data: Dict[str, Any], settings: Any) -> List[str]:
        if op not in _DATA_KEYS:
            return super().validate(op, data, settings)
        allowed = _DATA_KEYS[op]
        errors: List[str] = []
        unknown = sorted(set(data) - set(allowed))
        if unknown:
            errors.append(f"cannot {op} {self.title} field(s) {', '.join(unknown)}; allowed: {', '.join(allowed)}")
        note = data.get("note")
        if note is None or (isinstance(note, str) and not note.strip()):
            errors.append(f"note is required to {op} an alert; LibreNMS appends it to the fault's history")
        elif not isinstance(note, str):
            errors.append(_rejected(self.fields["note"], note))
        elif len(note) > NOTE_LIMIT:
            errors.append(f"note is {len(note)} characters long; the limit is {NOTE_LIMIT}")
        elif _CONTROL.search(note):
            errors.append("note must be one line without control characters; it becomes a line of the fault's history")
        if "until_clear" in allowed and "until_clear" in data:
            value = data["until_clear"]
            problem = (
                "until_clear: null is not allowed" if value is None else _rejected(self.fields["until_clear"], value)
            )
            if problem:
                errors.append(problem)
        return errors

    def resolve(self, client: Any, op: str, data: Dict[str, Any]) -> Dict[str, Any]:
        if op not in _DATA_KEYS:
            return super().resolve(client, op, data)
        resolved = {"note": data.get("note")}
        if op == "ack":
            resolved["until_clear"] = data.get("until_clear", False)
        try:
            return {name: diff.normalise(self.fields[name], value) for name, value in resolved.items()}
        except ValueError as exc:
            raise StepError(str(exc)) from None

    def _plan_action(
        self,
        client: Any,
        step: Dict[str, Any],
        data: Dict[str, Any],
        obj: Dict[str, Any],
        current: Dict[str, Any],
        settings: Any,
    ) -> Dict[str, Any]:
        action, fault = step["action"], f"alert #{step['object_id']}"
        if not current["open"]:
            raise StepError(f"{fault} is closed (the fault cleared); there is nothing to {action}")
        if action == "ack":
            if current["state"] == ACKNOWLEDGED:
                reason = "already acknowledged"
                if current["until_clear"] != data["until_clear"]:
                    reason += (
                        f" (until_clear is {diff.format_value(current['until_clear'])}; unmute it and acknowledge it "
                        "again to change that)"
                    )
                step.update(action="noop", reason=reason)
                return step
            if current["state"] not in ACKABLE:
                raise StepError(f"{fault} is in state {_shown(current['state'])}; it cannot be acknowledged")
        elif current["state"] == ACTIVE:
            step.update(action="noop", reason="already active (not acknowledged)")
            return step
        elif current["state"] != ACKNOWLEDGED:
            raise StepError(
                f"{fault} is in state {_shown(current['state'])}, not acknowledged; unmute would only reset it to "
                "active"
            )
        per_entity, siblings, assumed = self._siblings(client, current)
        step["params"] = data
        step["precondition"].update(
            note_length=len(str(obj.get("note") or "")), per_entity=per_entity, siblings=siblings
        )
        others = self._others(step)
        why = _default_limit(current["rule_id"], siblings) if assumed else ""
        if action == "unmute":
            acknowledged = [fault_id for fault_id, state in others.items() if state == ACKNOWLEDGED]
            if acknowledged:
                problem = _spread("unmute", acknowledged)
                raise StepError(f"{problem} ({why})" if why else problem)
        if others:
            verb = "acknowledges" if action == "ack" else "unmutes"
            head = f"{why}; this plan assumes" if why else f"rule #{current['rule_id']} does not notify per entity:"
            step["notes"].append(
                f"{head} LibreNMS {verb} every open fault of this device and rule, here also {_ids(others)}"
            )
        return step

    def describe(self, step: Dict[str, Any]) -> List[str]:
        action = step["action"]
        if action not in self.ops:
            return super().describe(step)
        params = step.get("params") or {}
        line = f"note {diff.format_value(params.get('note'), NOTE_LIMIT + 10)}"
        if action == "ack":
            line += f", until_clear {diff.format_value(params.get('until_clear'))}"
        before = ((step.get("precondition") or {}).get("state") or {}).get("state")
        lines = [line, f"state: {_shown(before)} -> {_shown(ACKNOWLEDGED if action == 'ack' else ACTIVE)}"]
        others = self._others(step)
        if others:
            ordered = sorted(others.items(), key=lambda item: int(item[0]))
            lines.append("may also change: " + ", ".join(f"#{fault_id} (state {state})" for fault_id, state in ordered))
        return lines

    # -- apply ------------------------------------------------------------------------------------------------------

    def _extra_check(
        self, client: Any, step: Dict[str, Any], obj: Dict[str, Any] | None, current: Dict[str, Any] | None
    ) -> str | None:
        """Ack needs an open fault in state 1, 3, 4 or 5 and unmute one in state 2. The rest of the fault, the rule's
        per-entity behaviour and, when the write reaches them, the sibling faults must be as planned."""
        action = step["action"]
        precondition = step.get("precondition") or {}
        fault = f"alert #{step['object_id']}"
        if not current["open"]:
            return f"{fault} is closed now (the fault cleared)"
        if current["state"] not in (ACKABLE if action == "ack" else (ACKNOWLEDGED,)):
            needed = "active, worse, better or changed" if action == "ack" else "acknowledged"
            return f"{fault} is in state {_shown(current['state'])} now; {action} needs it {needed}"
        expected = {key: value for key, value in (precondition.get("state") or {}).items() if key != "state"}
        drift = self._drift(expected, {key: value for key, value in current.items() if key != "state"}, set())
        if drift:
            return f"{fault} changed since planning ({', '.join(drift)})"
        per_entity, siblings, _ = self._siblings(client, current)
        if per_entity != precondition.get("per_entity"):
            how = "now notifies" if per_entity else "no longer notifies"
            return (
                f"rule #{current['rule_id']} {how} per entity for this device, so the {action} would reach "
                "other faults than planned"
            )
        moved = [] if per_entity else _sibling_drift(precondition.get("siblings") or {}, siblings)
        if moved:
            return (
                f"the open faults of rule #{current['rule_id']} on {current['hostname']} changed since planning "
                f"({', '.join(moved)})"
            )
        return None

    def _send(self, client: Any, action: str, object_id: int, note: str, until_clear: Any = None) -> None:
        """``PUT faults/{id}`` (ack) or ``PUT faults/unmute/{id}``; a 200 that changed nothing is a failure."""
        if action == "ack":
            body = {"note": note, "until_clear": bool(until_clear)}
            answer = client.request("PUT", path("faults", object_id), json=body)
        else:
            answer = client.request("PUT", path("faults", "unmute", object_id), json={"note": note})
        message = str(answer.get("message") or "").strip() if isinstance(answer, dict) else ""
        if _NO_ALERT.fullmatch(message):
            raise StepError(
                f"LibreNMS answered {message!r} to the {action} of alert #{object_id}: no fault was changed"
            )

    def _execute_action(self, client: Any, step: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        action, object_id = step["action"], step["object_id"]
        tag = f"[hermes:{context['plan_id']}]"
        params = step.get("params") or {}
        self._send(client, action, object_id, f"{tag} {params.get('note')}", params.get("until_clear"))
        inverse = self._inverse(step, object_id)
        obj = self.get(client, object_id, step)
        after = None if obj is None else self.state(client, obj)
        if after is None or not after["open"]:
            return self._entry(object_id, inverse, after, ["the fault cleared during the apply; nothing is left to do"])
        want = ACKNOWLEDGED if action == "ack" else ACTIVE
        if after["state"] != want:  # settled by the base class: PartialWrite if the fault moved, else this error
            raise StepError(
                f"LibreNMS accepted the {action} but alert #{object_id} is in state {_shown(after['state'])}, "
                f"expected {_shown(want)}"
            )
        appended = str(obj.get("note") or "")[(step.get("precondition") or {}).get("note_length") or 0 :]
        notes = [] if tag in appended else ["LibreNMS did not add the note to the fault's history"]
        if inverse["siblings"]:  # what the write did to them, which rollback checks before writing again
            now = self._open_faults(client, after)
            inverse["siblings"] = {fault_id: now[fault_id] for fault_id in inverse["siblings"] if fault_id in now}
        return self._entry(object_id, inverse, after, notes)

    def _inverse(self, step: Dict[str, Any], object_id: int | None) -> Dict[str, Any] | None:
        """The opposite action, plus what its reach is checked against: ``also_changes``, the other faults it would
        reach whose acknowledgement is not this plan's doing (an ack's: those acknowledged before the plan; an
        unmute's: every other open one, which acknowledging again would silence); ``per_entity`` as planned; and
        ``siblings``, the other faults the apply reached with the state it left them in (until a re-read after the
        write says otherwise, the state the write sets)."""
        others = self._others(step)
        per_entity = (step.get("precondition") or {}).get("per_entity")
        if step["action"] == "ack":
            spread = [fault_id for fault_id, state in others.items() if state == ACKNOWLEDGED]
            return {
                "action": "unmute",
                "object_id": object_id,
                "also_changes": sorted(map(int, spread)),
                "per_entity": per_entity,
                "siblings": dict.fromkeys(others, ACKNOWLEDGED),
            }
        if step["action"] == "unmute":
            until_clear = ((step.get("precondition") or {}).get("state") or {}).get("until_clear")
            return {
                "action": "ack",
                "object_id": object_id,
                "until_clear": bool(until_clear),
                "also_changes": sorted(map(int, others)),
                "per_entity": per_entity,
                "siblings": dict.fromkeys(others, ACTIVE),
            }
        return super()._inverse(step, object_id)

    # -- rollback ---------------------------------------------------------------------------------------------------

    def _revert_action(
        self, client: Any, entry: Dict[str, Any], force: bool, context: Dict[str, Any]
    ) -> Tuple[str, Dict[str, Any]]:
        step = context.get("step") or {}
        inverse = entry.get("inverse")
        if not inverse and step.get("action") in self.ops:
            inverse = self._inverse(step, entry.get("object_id"))
        if not inverse or inverse.get("action") not in self.ops:
            return "failed", {
                "error": f"no rollback information was recorded for this step; check alert {entry.get('label')} in "
                "LibreNMS"
            }
        undo, object_id = inverse["action"], inverse.get("object_id", entry.get("object_id"))
        obj = self.get(client, object_id, entry)
        if obj is None:
            return "reverted", {"note": "the fault no longer exists; nothing to undo"}
        current = self.state(client, obj)
        if not current["open"]:
            return "reverted", {"note": "fault cleared; nothing to undo"}
        target, left = (ACTIVE, ACKNOWLEDGED) if undo == "unmute" else (ACKNOWLEDGED, ACTIVE)
        if not force:
            if current["state"] != left:
                return "conflict", {
                    "error": f"alert #{object_id} is in state {_shown(current['state'])}, not {_shown(left)} as the "
                    f"apply left it; use force to {undo} it anyway"
                }
            if inverse.get("also_changes"):
                return "conflict", {"error": f"{_spread(undo, inverse['also_changes'])}; use force to {undo} them all"}
            moved = self._reach_moved(client, current, inverse, undo)
            if moved:
                return "conflict", {"error": moved}
        if current["state"] == target:
            return "reverted", {"note": f"alert #{object_id} is already {STATE_NAMES[target]}"}
        self._send(client, undo, object_id, f"[hermes:{context['plan_id']}] rollback", inverse.get("until_clear"))
        obj = self.get(client, object_id, entry)
        after = None if obj is None else self.state(client, obj)
        if after is None or not after["open"]:
            return "reverted", {"note": "fault cleared"}
        if after["state"] != target:
            return "failed", {
                "error": f"LibreNMS accepted the {undo} but alert #{object_id} is in state {_shown(after['state'])}, "
                f"expected {_shown(target)}"
            }
        return "reverted", {"state": target}

    def _reach_moved(self, client: Any, current: Dict[str, Any], inverse: Dict[str, Any], undo: str) -> str | None:
        """Why the rollback write would reach other faults than the apply did, as LibreNMS decides now: the rule's
        per-entity behaviour changed, or (when it does not notify per entity) a fault opened since the apply or a
        fault the apply reached is no longer in the state it left."""
        per_entity, siblings, _ = self._siblings(client, current)
        rule = f"rule #{current['rule_id']}"
        if per_entity != inverse.get("per_entity"):
            how = "now notifies" if per_entity else "no longer notifies"
            return (
                f"{rule} {how} per entity for this device, so the {undo} would reach other faults than the apply did; "
                f"use force to {undo} anyway"
            )
        if per_entity:
            return None
        now = {fault_id: state for fault_id, state in siblings.items() if fault_id != str(current["id"])}
        left = {fault_id: state for fault_id, state in (inverse.get("siblings") or {}).items() if fault_id in now}
        moved = _sibling_drift(left, now)
        if moved:
            return (
                f"the open faults of {rule} on {current['hostname']} changed since the apply ({', '.join(moved)}); use "
                f"force to {undo} them all"
            )
        return None


RESOURCE = Alert()
