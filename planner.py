"""Turn a list of desired operations into a reviewed, persisted plan.

Planning is read-only. The planner checks the shape of every operation and the operator's gates, then hands it to
its resource (:mod:`.resources`), which resolves names to ids, reads the object, computes the field-level diff and
records the state it saw, so that :mod:`.executor` can refuse to run against an object that changed in between.

Operation shapes accepted from the model::

    {"op": "update", "resource": "device", "id": 12, "data": {"purpose": "core"}}
    {"op": "update", "resource": "device", "match": {"hostname": "sw1"}, "data": {"location": "SFO-1"}}
    {"op": "create", "resource": "location", "match": {"location": "SFO-1"}, "data": {...}}   # match optional
    {"op": "delete", "resource": "device_group", "id": 3}
    {"op": "maintenance", "resource": "device", "match": {"hostname": "sw1"}, "data": {"duration": "2:00"}}
    {"op": "ack", "resource": "alert", "id": 501, "data": {"note": "investigating"}}

A ``create`` with ``match`` is an upsert: when exactly one object matches it becomes an ``update`` (or a ``noop``);
when nothing matches it stays a ``create`` whose apply-time precondition is "still no match". Every operation is
resolved against live state on its own, so two operations that would write one object are refused here rather than
left to conflict with each other at apply time.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Tuple

from . import timefmt
from .audit import describe_actor, environment
from .client import LibreNMSClient, LibreNMSError, is_digits
from .diff import format_value
from .redact import one_line
from .resources import RESOURCE_NAMES, Resource, StepError, get_resource
from .settings import Settings
from .store import new_plan_id, now_iso

CRUD = ("create", "update", "delete")
OPERATION_KEYS = ("op", "resource", "id", "match", "data")
SUMMARY_KEYS = ("create", "update", "delete", "action", "noop")
NO_DATA_OPS = ("delete", "discover")
SETTINGS_KEY = "plugins.entries.librenms.settings"
RETARGET_FIELDS = frozenset({"hostname", "overwrite_ip"})
DESCRIPTION_CHARS = 200


class PlanError(Exception):
    """Raised when the operation list cannot be turned into a plan. ``errors`` is per-operation."""

    def __init__(self, errors: List[Dict[str, Any]]):
        super().__init__(f"{len(errors)} invalid operation(s)")
        self.errors = errors


def _err(index: int, message: str, **extra: Any) -> Dict[str, Any]:
    return {"index": index, "error": message, **extra}


def _shown(value: Any) -> str:
    return format_value(value, 40)


def _positive_int(value: Any) -> int | None:
    """``value`` as a positive int (``"7"`` counts, ``True`` and ``"٧"`` do not), else ``None``."""
    if not is_digits(value):
        return None
    number = int(value)
    return number if number > 0 else None


def gate_errors(resource: str, action: str, settings: Settings, changes: Dict[str, Any] | None = None) -> List[str]:
    """What the operator's gates refuse of one operation or step. Checked when planning and again when applying,
    because the settings may change in between; rollback never asks, so a write can always be undone."""
    refused = []
    if action == "delete" and not settings.allow_delete:
        refused.append(
            f"delete operations are disabled; set {SETTINGS_KEY}.allow_delete: true in config.yaml to permit them"
        )
    if resource == "device" and action == "create" and not settings.allow_device_add:
        refused.append(
            "adding a device makes LibreNMS probe a host the model chose over ICMP and SNMP; set "
            f"{SETTINGS_KEY}.allow_device_add: true in config.yaml to permit it"
        )
    if resource == "device" and RETARGET_FIELDS & set(changes or ()) and not settings.allow_device_add:
        refused.append(
            "retargeting a device changes which host LibreNMS polls with this device's SNMP credentials; set "
            f"{SETTINGS_KEY}.allow_device_add: true"
        )
    if resource == "service" and action != "noop" and not settings.allow_services:
        refused.append(
            "service operations are disabled because a service runs a Nagios plugin with these arguments on the "
            f"poller; set {SETTINGS_KEY}.allow_services: true in config.yaml to permit them"
        )
    return refused


def _match_error(resource: Resource, match: Any) -> str | None:
    if not resource.match_keys:
        return f"{resource.title} operations take an id, not match"
    if not isinstance(match, dict) or not match:
        return f"match must be a non-empty object with keys among {', '.join(resource.match_keys)}"
    unknown = sorted(str(key) for key in match if key not in resource.match_keys)
    if unknown:
        return f"match keys must be among {', '.join(resource.match_keys)} (got {', '.join(unknown)})"
    return None


def _validate_operation(
    index: int, raw: Any, settings: Settings
) -> Tuple[Dict[str, Any] | None, Resource | None, List[Dict[str, Any]]]:
    """Normalise one raw operation; returns ``(clean_op, resource, errors)``. Every problem of a well-formed
    operation is reported at once; an unknown resource or op stops the checks, since the rest depend on them."""
    if not isinstance(raw, dict):
        return None, None, [_err(index, "operation must be an object")]
    try:
        resource = get_resource(str(raw.get("resource") or "").strip().lower())
    except KeyError:
        message = f"resource must be one of {', '.join(RESOURCE_NAMES)} (got {_shown(raw.get('resource'))})"
        return None, None, [_err(index, message)]
    kind = str(raw.get("op") or "").strip().lower()
    if kind not in resource.ops:
        message = f"op must be one of {', '.join(resource.ops)} for a {resource.title} (got {_shown(raw.get('op'))})"
        return None, None, [_err(index, message)]

    errors: List[Dict[str, Any]] = []
    unknown = sorted(str(key) for key in raw if key not in OPERATION_KEYS)
    if unknown:  # a stray "force" or "where" must not be silently ignored
        errors.append(
            _err(index, f"unknown operation key(s) {', '.join(unknown)}; allowed: {', '.join(OPERATION_KEYS)}")
        )
    has_id, has_match = raw.get("id") is not None, raw.get("match") is not None
    object_id = _positive_int(raw.get("id"))
    if has_id and object_id is None:
        errors.append(_err(index, f"id must be a positive integer (got {_shown(raw.get('id'))})"))
    match = raw.get("match") if has_match else None
    problem = _match_error(resource, match) if has_match else None
    if problem:
        errors.append(_err(index, problem))
    if kind == "create" and has_id:
        errors.append(_err(index, "create does not take id; use match for upsert semantics"))
    if kind != "create" and not has_id and not has_match:
        errors.append(_err(index, f"{kind} requires id" + (" or match" if resource.match_keys else "")))
    if kind != "create" and has_id and has_match:
        errors.append(_err(index, "give id or match, not both"))
    data = raw.get("data")
    if kind in NO_DATA_OPS:
        if data:
            errors.append(_err(index, f"{kind} does not take data"))
        data = {}
    elif not isinstance(data, dict) or not data:
        errors.append(_err(index, f"{kind} requires a non-empty data object"))
        data = None
    errors += [_err(index, message) for message in gate_errors(resource.name, kind, settings)]
    if data is not None:
        errors += [_err(index, message) for message in resource.validate(kind, data, settings)]
    if errors:
        return None, None, errors
    return {"op": kind, "resource": resource.name, "id": object_id, "match": match, "data": data}, resource, []


def _duplicate_targets(planned: List[Tuple[Resource, Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """Two writes to one object would each be checked against the state seen before either ran, so the second one
    would always conflict. Actions (maintenance, discover, ack, unmute) do not write the object's state and run in
    the given order."""
    errors: List[Dict[str, Any]] = []
    seen: Dict[Tuple[str, str, str], int] = {}
    for resource, step in planned:
        if step["action"] not in CRUD:
            continue
        if step.get("object_id") is not None:
            key = (resource.name, "id", str(step["object_id"]))
            target = f"{resource.title} #{step['object_id']}"
        elif step.get("exists_check"):
            key = (resource.name, "new", json.dumps(step["exists_check"], sort_keys=True, default=str))
            target = f"{resource.title} {format_value(step['exists_check'])}"
        else:  # a create LibreNMS allows twice (a service without match)
            continue
        if key in seen:
            errors.append(
                _err(
                    step["index"],
                    f"operations [{seen[key]}] and [{step['index']}] both target {target}; "
                    "combine them into one operation",
                )
            )
        else:
            seen[key] = step["index"]
    return errors


def _librenms_version(client: LibreNMSClient) -> Dict[str, Any]:
    """Recorded for audit; a failure here must not fail planning."""
    try:
        system = client.system()
    except Exception:
        system = {}
    return {
        "librenms_version": str(system.get("local_ver") or "") or None,
        "librenms_sha": str(system.get("local_sha") or "") or None,
        "db_schema": str(system.get("db_schema") or "") or None,
    }


def _description(text: Any) -> Tuple[str, List[str]]:
    """The plan's description, and a warning when it had to be cut. It heads the plan the human approves, so it is
    capped at :data:`DESCRIPTION_CHARS` as shown (an escaped character counts as its escape): a long one would push
    the steps out of the approval prompt."""
    text = str(text or "").strip()
    if len(one_line(text)) <= DESCRIPTION_CHARS:
        return text, []
    kept = text[: DESCRIPTION_CHARS - 1]
    while len(one_line(kept)) > DESCRIPTION_CHARS - 1:
        kept = kept[:-1]
    return kept + "…", [f"the description was longer than {DESCRIPTION_CHARS} characters and was cut"]


def _summary(steps: List[Dict[str, Any]]) -> Dict[str, int]:
    summary = dict.fromkeys(SUMMARY_KEYS, 0)
    for step in steps:
        summary[step["action"] if step["action"] in summary else "action"] += 1
    return summary


def build_plan(
    client: LibreNMSClient,
    operations: Any,
    description: str,
    settings: Settings,
    librenms_url: str = "",
    *,
    actor: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """Validate, resolve and diff every operation; return a persisted-ready plan dict. Raises PlanError with every
    problem found, so the model can fix them all in one go. ``actor`` (see :mod:`audit`) is recorded as
    ``requested_by``."""
    if not isinstance(operations, list) or not operations:
        raise PlanError([_err(-1, "operations must be a non-empty list")])
    if len(operations) > settings.max_operations:
        raise PlanError(
            [_err(-1, f"plan has {len(operations)} operations; max_operations is {settings.max_operations}")]
        )

    errors: List[Dict[str, Any]] = []
    planned: List[Tuple[Resource, Dict[str, Any]]] = []
    for index, raw in enumerate(operations):
        op, resource, op_errors = _validate_operation(index, raw, settings)
        if op is None or resource is None:
            errors.extend(op_errors)
            continue
        try:
            step = resource.plan_step(client, index, op, settings)
        except LibreNMSError as exc:
            errors.append(_err(index, str(exc), librenms=exc.to_dict()))
            continue
        except StepError as exc:
            errors.append(_err(index, str(exc)))
            continue
        # Only the resolved step shows whether an update moves a device to another host.
        refused = gate_errors(resource.name, step["action"], settings, step.get("changes"))
        if refused:
            errors += [_err(index, message) for message in refused]
            continue
        planned.append((resource, step))
    errors += _duplicate_targets(planned)
    if errors:
        raise PlanError(errors)

    steps = [step for _resource, step in planned]
    description, warnings = _description(description)
    return {
        "id": new_plan_id(),
        "version": 1,
        "created_at": now_iso(),
        "status": "planned",
        "description": description,
        "librenms_url": librenms_url or client.base_url,
        "summary": _summary(steps),
        "warnings": warnings + [f"[{step['index']}] {note}" for step in steps for note in step.get("notes") or []],
        "irreversible": [step["index"] for step in steps if step.get("inverse_kind") == "none"],
        "steps": steps,
        "journal": [],
        "requested_by": actor,
        "audit": {**environment(), **_librenms_version(client)},
    }


# -- rendering ---------------------------------------------------------------------------------


def render_step(step: Dict[str, Any]) -> List[str]:
    """The step's header, its resource's detail lines and how rollback undoes it. Notes are not repeated here:
    :func:`render_plan` prints them once, as warnings. The label, every detail line and the rollback note may carry
    text from LibreNMS or the model, so each stays on its own line (:func:`.redact.one_line`)."""
    header = f"[{step['index']}] {step['action']:<11} {step['resource']}"
    if step.get("object_id") is not None:
        header += f" #{step['object_id']}"
    lines = [f'{header} "{one_line(step.get("label", ""))}"']
    lines += [f"      {one_line(line)}" for line in get_resource(step["resource"]).describe(step)]
    if step.get("inverse_kind"):
        note = step.get("inverse_note")
        lines.append(f"      rollback: {step['inverse_kind']}" + (f" — {one_line(note)}" if note else ""))
    return lines


def render_plan(plan: Dict[str, Any]) -> str:
    """The diff a human reviews before approving. Every free-text value (the description, who asked, labels, details
    and warnings) is kept on its line with :func:`.redact.one_line`, so none can pass for a step or a summary line;
    callers that print to a terminal or an approval prompt still pass the result through ``redact.printable``."""
    description = f" — {one_line(plan['description'])}" if plan.get("description") else ""
    lines = [
        f"Plan {plan['id']} ({plan['status']}){description}",
        f"LibreNMS: {plan.get('librenms_url', '')}",
        f"Created: {timefmt.local(plan.get('created_at'))} by {one_line(describe_actor(plan.get('requested_by')))}",
    ]
    for step in plan["steps"]:
        lines += render_step(step)
    summary = plan.get("summary") or {}
    lines.append("Summary: " + ", ".join(f"{summary.get(key, 0)} {key}" for key in SUMMARY_KEYS))
    lines += [f"Warning: {one_line(warning)}" for warning in dict.fromkeys(plan.get("warnings") or [])]
    return "\n".join(lines)
