"""LibreNMS services: the Nagios checks a poller runs against a device (``list_services``, ``add_service_for_host``,
``edit_service_for_host`` and ``del_service_from_host`` in ``includes/html/api_functions.inc.php``).

Every operation sits behind ``allow_services``: ``param`` becomes command-line arguments of ``check_<type>`` on the
poller, and the parameters already stored often carry passwords, so LibreNMS's value of ``param`` is only ever shown
as a digest. What the API makes awkward is absorbed here:

- there is no single-service read: a service is picked from its device's listing (``services/{device_id}``) or,
  by id alone, from the full listing, both wrapped in one more list "for backwards compat";
- ``services/X`` is a device for GET and POST but a service for PATCH and DELETE, so every path is a numeric id;
- the add route takes short keys (``disable``, not ``disabled``) and must get every one of them, while the edit
  route takes raw column names and answers 500 when nothing changed, so only changed columns are sent;
- the add route reads ``desc`` and ``param`` with PHP's ``?:``, so ``"0"`` is stored as ``""``; the edit route
  does not check that ``check_<type>`` exists on the poller, the add route does;
- an add answers with the new row as JSON inside its message, ``param`` included: the id is parsed out of it and
  the message is never kept;
- ``ip: ""`` on an add stores the device's poller target (``overwrite_ip``, else ``hostname``): the plan records
  that address as ``expected_ip`` for lookups and verification while the POST still sends ``""``;
- identical services are allowed, so a create without ``match`` has no precondition, a create whose answer was lost
  is looked for only among services newer than the plan (``max_service_id``), never an older twin, and a rollback
  that re-created a deleted service but failed to finish it, or died after its add, is finished by the next run
  instead of adding another.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Tuple

from .. import diff, redact
from ..client import LibreNMSError, is_digits, path
from .base import Field, Resource, StepError, _as_int, _maybe_committed

# Operation field -> ``services`` column, which the edit route takes as its keys.
COLUMNS = {
    "type": "service_type",
    "ip": "service_ip",
    "desc": "service_desc",
    "param": "service_param",
    "ignore": "service_ignore",
    "disabled": "service_disabled",
    "name": "service_name",
}
# What a delete's rollback puts back: the fields, and the template link the add route always sets to 0.
_RESTORED = {**COLUMNS, "template_id": "service_template_id"}
_LOOKUP_KEYS = ("type", "name", "ip", "desc")
_ABOVE = "service_id_above"  # lookup key of our own: only services created after the plan read the device
_VARCHAR = 255  # type and name; LibreNMS runs without strict SQL mode and would cut a longer value silently
_PARAM_SHOWN = 1000  # the reviewer must read the arguments that will run on the poller, not the first 60 characters
# A check is the file check_<type> in the poller's plugin directory: no separators, spaces or controls.
_CHECK_NAME = re.compile(rf"[^\s/\\\x00-\x1f\x7f]{{1,{_VARCHAR}}}")
_ID_IN_JSON = re.compile(r'"service_id":(\d+)')
_ID_AT_END = re.compile(r"#(\d+)\)$")


def _id(value: Any) -> Any:
    return int(value) if is_digits(value) else value


def _norm(field: Field, value: Any) -> Any:
    """*value* in *field*'s canonical form; LibreNMS's own spelling when it has none (compared as it is)."""
    try:
        return diff.normalise(field, value)
    except ValueError:
        return value


def _device_problem(ref: Any) -> str | None:
    """Why *ref* cannot name a device (a positive id, or a hostname), or None when it can. No hostname holds a ``/``
    (add_device refuses one), and an encoded one would reach another route."""
    if is_digits(ref):
        if int(ref) > 0:
            return None
    elif isinstance(ref, str) and ref.strip() and ref.isprintable() and "/" not in ref and ref not in (".", ".."):
        return None
    return f"device: expected a device id or hostname, got {diff.format_value(ref, 40)}"


def _device(client: Any, ref: Any) -> Dict[str, Any] | None:
    """The device *ref* names (an id, or an exact hostname) with its SNMP credentials masked, or None."""
    try:
        body = client.get_or_none(path("devices", ref))
    except LibreNMSError as exc:
        if exc.kind == "forbidden" and not is_digits(ref):
            raise StepError(
                f"LibreNMS answered 403 for hostname {ref}: it does not exist or this token cannot see it (LibreNMS "
                "returns 403 for unknown hostnames to tokens without global read); use the device id or a token with "
                "global read"
            ) from None
        raise
    rows = body.get("devices") if isinstance(body, dict) else None
    return redact.mask(rows[0]) if isinstance(rows, list) and rows and isinstance(rows[0], dict) else None


def _target(device: Dict[str, Any]) -> str:
    """The address LibreNMS stores for a service added with ``ip: ""``."""
    return str(device.get("overwrite_ip") or device.get("hostname") or "")


def _on(label: str, device: Dict[str, Any] | None, device_id: Any) -> str:
    host = (device or {}).get("hostname")
    return f"{label} on {host}" if host else f"{label} on device #{device_id}"


def _rows(client: Any, device_id: int | None = None) -> List[Dict[str, Any]]:
    """The service rows of one device, or of every device the token can see."""
    body = client.get("services" if device_id is None else path("services", device_id))
    services = body.get("services") if isinstance(body, dict) else None
    if isinstance(services, list) and services and isinstance(services[0], list):
        services = services[0]
    return [row for row in services or [] if isinstance(row, dict)]


def _newest(rows: List[Dict[str, Any]]) -> int:
    return max((int(row["service_id"]) for row in rows if is_digits(row.get("service_id"))), default=0)


def _created_id(answer: Any) -> int | None:
    """The new service's id from an add answer, ``"Service <type> has been added to device <x> (#<row JSON>)"``,
    with the fallbacks LN-gr SV-3 lists; None when the message does not say."""
    message = answer.get("message") if isinstance(answer, dict) else None
    if not isinstance(message, str):
        return None
    start, end = message.find("(#"), message.rfind(")")
    if 0 <= start < end:
        try:
            row = json.loads(message[start + 2 : end])
        except ValueError:
            row = None
        if isinstance(row, dict) and is_digits(row.get("service_id")):
            return int(row["service_id"])
    found = _ID_IN_JSON.findall(message) or _ID_AT_END.findall(message.strip())
    return int(found[-1]) if found else None


def _columns(values: Dict[str, Any]) -> Dict[str, Any]:
    """Edit body: column names, flags as 0/1 (tinyint columns)."""
    return {_RESTORED[name]: int(value) if isinstance(value, bool) else value for name, value in values.items()}


def _add_body(values: Dict[str, Any]) -> Dict[str, Any]:
    """``POST services/{device_id}`` body from operation data or a snapshot. Every key is sent: the handler reads
    them without ``isset`` (a missing ``ip`` is a 500), and ``ignore``/``disable`` go as JSON booleans because PHP
    truthiness makes ``"false"`` true."""
    return {
        "type": values["type"],
        "ip": values.get("ip") or "",
        "desc": values.get("desc") or "",
        "param": values.get("param") or "",
        "ignore": bool(values.get("ignore")),
        "disable": bool(values.get("disabled")),
        "name": values.get("name") or "",
    }


def _readded(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    """What finds the service a rollback's add of *snapshot* made before ``_restore`` edits it: the add stores the
    type and name as given, while ip, desc and param may still differ."""
    return {"device": snapshot["device_id"], "type": snapshot["type"], "name": snapshot.get("name") or ""}


def _identity(values: Dict[str, Any], ip: str | None = None) -> Dict[str, Any]:
    """What finds the service an add of *values* made (``param`` is left out: lookups end up in messages)."""
    return {
        "device": values["device_id"],
        "type": values["type"],
        "ip": (values.get("ip") or "") if ip is None else ip,
        "desc": values.get("desc") or "",
        "name": values.get("name") or "",
    }


class Service(Resource):
    name = "service"
    title = "service"
    id_key = "service_id"
    label_key = "service_name"
    match_keys = ("device", *_LOOKUP_KEYS)
    parent_key = "device_id"
    fields = {
        "type": Field("type", "str", required=True),
        "ip": Field("ip", "text"),
        "desc": Field("desc", "text"),
        "param": Field("param", "text", sensitive=True),
        "ignore": Field("ignore", "bool"),
        "disabled": Field("disabled", "bool"),
        "name": Field("name", "text"),
    }
    ops = ("create", "update", "delete")
    inverse = {
        "create": ("exact", ""),
        "update": ("exact", ""),
        "delete": ("lossy", "re-created with a new service id; its graph history stays attached to the old id"),
    }

    # -- reads ------------------------------------------------------------------------------------------------------

    def get(self, client: Any, object_id: int, step: Dict[str, Any] | None = None) -> Dict[str, Any] | None:
        """The service row (``param`` in clear: rollback restores it), from its device's listing when the step knows
        the device, else from the full listing."""
        rows = _rows(client, (step or {}).get("parent_id"))
        return next((row for row in rows if _id(row.get("service_id")) == int(object_id)), None)

    def find(self, client: Any, match: Dict[str, Any]) -> Tuple[int, Dict[str, Any] | None]:
        unknown = sorted(set(match) - {*self.match_keys, _ABOVE})
        if unknown:
            raise StepError(f"cannot match a service on {', '.join(unknown)}; use {', '.join(self.match_keys)}")
        ref = match.get("device")
        if ref is None:
            raise StepError("a service match needs device (the id or hostname of the service's device)")
        problem = _device_problem(ref)
        if problem:
            raise StepError(f"match {problem}")
        wanted = self._wanted(match)
        device = None
        if is_digits(ref):
            device_id = int(ref)
        else:
            device = _device(client, ref)
            if device is None:
                return 0, None
            device_id = int(device["device_id"])
        if wanted.get("ip") == "":
            device = device or _device(client, device_id)
            if device is None:
                return 0, None
            wanted["ip"] = _target(device)
        floor = match.get(_ABOVE)
        rows = [
            row
            for row in _rows(client, device_id)
            if all(self._same(name, row.get(COLUMNS[name]), value) for name, value in wanted.items())
            and (floor is None or int(row["service_id"]) > floor)
        ]
        return len(rows), (rows[0] if len(rows) == 1 else None)

    def _wanted(self, match: Dict[str, Any]) -> Dict[str, Any]:
        wanted: Dict[str, Any] = {}
        for name in _LOOKUP_KEYS:
            if name in match:
                try:
                    wanted[name] = diff.normalise(self.fields[name], match[name])
                except ValueError as exc:
                    raise StepError(f"match {exc}") from None
        return wanted

    def state(self, client: Any, obj: Dict[str, Any]) -> Dict[str, Any]:
        """Config columns only: status, message, perf-data and change time are the poller's and move every cycle."""
        current = {"service_id": _id(obj.get("service_id")), "device_id": _id(obj.get("device_id"))}
        for name, column in COLUMNS.items():
            current[name] = _norm(self.fields[name], obj.get(column))
        current["template_id"] = _id(obj.get("service_template_id") or 0)
        return current

    def label(self, obj_or_data: Dict[str, Any]) -> str:
        for key in ("name", "service_name", "type", "service_type"):
            value = obj_or_data.get(key)
            if value not in (None, ""):
                return str(value)
        return super().label(obj_or_data)

    # -- planning ---------------------------------------------------------------------------------------------------

    def validate(self, op: str, data: Dict[str, Any], settings: Any) -> List[str]:
        errors: List[str] = []
        if op == "create":
            if data.get("device") in (None, ""):
                errors.append("device is required to create a service")
            elif _device_problem(data["device"]):
                errors.append(_device_problem(data["device"]))
        elif op == "update" and "device" in data:
            errors.append("device cannot be changed: delete the service and create it on the other device")
        errors += super().validate(op, {k: v for k, v in data.items() if k != "device"}, settings)
        if op not in ("create", "update"):
            return errors
        kind = data.get("type")
        if isinstance(kind, str) and (kind or op == "update") and not _CHECK_NAME.fullmatch(kind):
            errors.append(
                f"type: expected the name of a Nagios check such as http or icmp (check_<type> on the poller): no "
                f"spaces or slashes, at most {_VARCHAR} characters"
            )
        name = data.get("name")
        if isinstance(name, str) and len(name) > _VARCHAR:
            errors.append(f"name: at most {_VARCHAR} characters (LibreNMS would cut it)")
        if op == "create":
            errors += [
                f'{key}: LibreNMS adds a service with {key} "0" as an empty one (PHP reads "0" as false); add it '
                f"without {key}, then set it with an update"
                for key in ("desc", "param")
                if data.get(key) == "0"
            ]
        return errors

    def resolve(self, client: Any, op: str, data: Dict[str, Any]) -> Dict[str, Any]:
        resolved = super().resolve(client, op, {k: v for k, v in data.items() if k != "device"})
        if op == "create":
            ref = data["device"]
            problem = _device_problem(ref)
            if problem:
                raise StepError(problem)
            device = _device(client, ref)
            if device is None:
                kind = "id" if is_digits(ref) else "hostname"
                raise StepError(f"no LibreNMS device has {kind} {diff.format_value(ref, 80)}")
            resolved["device_id"] = int(device["device_id"])
        return resolved

    def plan_step(self, client: Any, index: int, op: Dict[str, Any], settings: Any) -> Dict[str, Any]:
        step = super().plan_step(client, index, op, settings)
        action = step["action"]
        if action == "create" and op.get("match"):
            self._same_device(client, op["match"]["device"], step["data"]["device_id"])
        if action == "delete":
            step["label"] = _on(step["label"], _device(client, step["parent_id"]), step["parent_id"])
        kind = (step.get("changes") or {}).get("type")
        if kind is not None:
            step["notes"].append(
                f"type: LibreNMS checks that check_{kind['to']} exists on the poller when a service is added, not when "
                "one is edited; make sure it is installed"
            )
        template = ((step.get("precondition") or {}).get("state") or {}).get("template_id")
        if template and action == "update":
            step["notes"].append(
                f"service #{step['object_id']} comes from service template #{template}; applying that template "
                "again may undo this change"
            )
        elif template and action == "delete":
            step["notes"].append(
                f"service #{step['object_id']} comes from service template #{template}; applying that template "
                "again may re-create it"
            )
        ip_change = (step.get("changes") or {}).get("ip")
        if ip_change is not None and step.get("expected_ip") is not None:
            ip_change["to_label"] = "poller target"
        return step

    @staticmethod
    def _same_device(client: Any, ref: Any, device_id: int) -> None:
        """A create whose match found nothing adds the service where data says; refuse when match looked elsewhere."""
        matched = int(ref) if is_digits(ref) else _as_int((_device(client, ref) or {}).get("device_id"))
        if matched != device_id:
            raise StepError(
                f"match looks for the service on device {diff.format_value(ref, 80)}, but data adds it to device "
                f"#{device_id}; name the same device in both"
            )

    def _prepare(
        self, client: Any, step: Dict[str, Any], data: Dict[str, Any], current: Dict[str, Any] | None, settings: Any
    ) -> Dict[str, Any]:
        device_id = data["device_id"] if current is None else current["device_id"]
        device = _device(client, device_id)
        step["label"] = _on(step["label"], device, device_id)
        if current is not None:
            return self._prepare_update(step, data, current, device)
        if device is None:
            raise StepError(f"device #{device_id} does not exist")
        rows = _rows(client, device_id)
        step["max_service_id"] = _newest(rows)
        ip = data.get("ip") or ""
        if not ip:
            step["expected_ip"] = ip = _target(device)
        same = {"type": data["type"], "ip": ip, "param": data.get("param"), "name": data.get("name")}
        twins = [
            str(row["service_id"])
            for row in rows
            if all(self._same(name, row.get(COLUMNS[name]), value) for name, value in same.items())
        ]
        if twins:
            step["notes"].append(
                f"{device.get('hostname')} already has service #{', #'.join(twins)} with this type, ip, param and "
                "name; LibreNMS allows duplicates, so this adds another (give match to update it instead)"
            )
        return data

    def _prepare_update(
        self, step: Dict[str, Any], data: Dict[str, Any], current: Dict[str, Any], device: Dict[str, Any] | None
    ) -> Dict[str, Any]:
        """An upsert updates the service on the device its match found, and its ``ip: ""`` means the poller target
        as on a create. A plain update sends ``""`` as it is (the poller then checks the hostname)."""
        data = dict(data)
        device_id = data.pop("device_id", current["device_id"])
        if device_id != current["device_id"]:
            raise StepError(
                f"match found service #{current['service_id']} on device #{current['device_id']}, but data names "
                f"device #{device_id}; a service cannot be moved"
            )
        if step.get("upsert") and data.get("ip") == "" and device is not None:
            step["expected_ip"] = data["ip"] = _target(device)
        return data

    def _exists_check(self, data: Dict[str, Any], match: Dict[str, Any] | None) -> Dict[str, Any] | None:
        """Only with ``match``: identical services are allowed, so without one a create has no precondition. The
        device is the one data names (where the service is added)."""
        return {"device": data["device_id"], **self._wanted(match)} if match else None

    def describe(self, step: Dict[str, Any]) -> List[str]:
        """``param`` from the operation is shown in full: it is what will run on the poller."""
        action = step["action"]
        if action == "create":
            data = step.get("data") or {}
            pairs = []
            for name in ("type", "ip", "desc", "name", "ignore", "disabled"):
                if name == "ip" and step.get("expected_ip") is not None:
                    pairs.append(f"ip={diff.format_value(step['expected_ip'], 40)} (poller target)")
                elif name in data:
                    pairs.append(f"{name}={diff.format_value(data[name], 40)}")
            lines = [", ".join(pairs)]
            if data.get("param"):
                lines.append(f"param: {diff.format_value(data['param'], _PARAM_SHOWN)}")
            if step.get("exists_check"):
                lines.append(f"precondition: no service matches {diff.format_value(step['exists_check'])}")
            return lines
        if action == "update":
            lines = []
            for name, change in sorted((step.get("changes") or {}).items()):
                if name == "param":
                    old = diff.format_live(self.fields["param"], change.get("from"))
                    lines.append(f"param: {old} -> {diff.format_value(change.get('to'), _PARAM_SHOWN)}")
                else:
                    lines += diff.render_changes({name: change}, self.fields)
            return lines
        return super().describe(step)

    # -- apply ------------------------------------------------------------------------------------------------------

    def _extra_check(
        self, client: Any, step: Dict[str, Any], obj: Dict[str, Any] | None, current: Dict[str, Any] | None
    ) -> str | None:
        if step["action"] != "create":
            return None
        device_id = step["data"]["device_id"]
        device = _device(client, device_id)
        if device is None:
            return f"device #{device_id} no longer exists"
        expected = step.get("expected_ip")
        if expected is not None and _target(device) != expected:
            return (
                f"the poller target of device #{device_id} is now {diff.format_value(_target(device))}, not "
                f"{diff.format_value(expected)} as planned"
            )
        return None

    def _create_lookup(self, step: Dict[str, Any]) -> Dict[str, Any] | None:
        lookup = step.get("exists_check") or _identity(step["data"], step.get("expected_ip"))
        return {**lookup, _ABOVE: step.get("max_service_id", 0)}

    def _expected_after_create(self, step: Dict[str, Any], after: Dict[str, Any]) -> Dict[str, Any]:
        expected = super()._expected_after_create(step, after)
        if step.get("expected_ip") is not None:
            expected["ip"] = step["expected_ip"]
        return expected

    def _payload(self, data: Dict[str, Any], record: Dict[str, Any]) -> Dict[str, Any]:
        return _columns(data)

    def _create_call(self, client: Any, step: Dict[str, Any], context: Dict[str, Any]) -> int | None:
        data = step["data"]
        return _created_id(client.request("POST", path("services", data["device_id"]), json=_add_body(data)))

    def _update_call(
        self, client: Any, object_id: int, data: Dict[str, Any], record: Dict[str, Any], context: Dict[str, Any]
    ) -> None:
        client.request("PATCH", path("services", object_id), json=self._payload(data, record))

    def _delete_call(self, client: Any, object_id: int, record: Dict[str, Any], context: Dict[str, Any]) -> None:
        client.request("DELETE", path("services", object_id))

    def _snapshot(self, client: Any, obj: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
        return dict(current)

    def _revert_delete(
        self, client: Any, entry: Dict[str, Any], inverse: Dict[str, Any], context: Dict[str, Any]
    ) -> Tuple[str, Dict[str, Any]]:
        """Add the snapshot again (LN-gr SV-5 c), then edit in what the add route cannot set: an empty ip (it stores
        the poller target), the template link, a ``"0"`` desc or param. A failure after the add reports the new id,
        and a later run finishes that service: nothing else would stop it from adding an identical second one. A run
        that died after its add left only the floor it saved first; the service it added is the one above it.
        A delete whose outcome is unknown needs nothing when the service is still there."""
        snapshot = inverse.get("snapshot") or {}
        if entry.get("status") != "done" and self.get(client, entry["object_id"], entry) is not None:
            return self._not_carried_out(entry, "nothing was deleted")
        earlier = _as_int((entry.get("revert") or {}).get("new_object_id"))
        details: Dict[str, Any] = {}
        if earlier is not None and self.get(client, earlier, entry) is not None:
            new_id = earlier
        else:
            new_id = self._added_before(client, entry, snapshot)
            if new_id is None:
                new_id = self._add_again(client, snapshot, context)
            else:
                details["note"] = "re-created by an earlier rollback"
        try:
            self._restore(client, new_id, snapshot, entry)
        except (StepError, LibreNMSError) as exc:
            error = f"re-created service #{new_id}, but {self.scrub(str(exc), entry)}"
            return "failed", {"error": error, "new_object_id": new_id, **details}
        return "reverted", {"new_object_id": new_id, **details}

    def _added_before(self, client: Any, entry: Dict[str, Any], snapshot: Dict[str, Any]) -> int | None:
        """The service an earlier rollback added before it died: the one above the floor it saved before its POST,
        of the snapshot's type and name (what the add sets as given); None when that add did not land."""
        floor = (entry.get("revert_progress") or {}).get("floor")
        if floor is None:
            return None
        count, obj = self.find(client, {**_readded(snapshot), _ABOVE: floor})
        if count > 1:
            raise StepError(
                f"{count} {snapshot['type']} services on device #{snapshot['device_id']} are newer than the ones an "
                "interrupted rollback listed before re-creating this one; check them in LibreNMS"
            )
        return int(obj["service_id"]) if obj is not None else None

    def _add_again(self, client: Any, snapshot: Dict[str, Any], context: Dict[str, Any]) -> int:
        """The id of the service a POST of *snapshot* adds. A failure that may have added it (or an answer without
        the id) is settled by the device's services newer than the ones listed just before the POST; that floor is
        saved first, for a rollback that resumes after this one dies."""
        device_id = snapshot["device_id"]
        floor = _newest(_rows(client, device_id))
        if context.get("checkpoint") is not None:
            context["checkpoint"]({"floor": floor})
        failure = None
        try:
            answer = client.request("POST", path("services", device_id), json=_add_body(snapshot))
        except LibreNMSError as exc:
            if not _maybe_committed(exc):
                raise
            answer, failure = None, exc
        new_id = _created_id(answer)
        if new_id is not None:
            return new_id
        count, obj = self.find(client, {**_readded(snapshot), _ABOVE: floor})
        if count == 1 and obj is not None:
            return int(obj["service_id"])
        if failure is not None and count == 0:
            raise failure
        raise StepError(
            f"LibreNMS accepted the re-create but {count} new {snapshot['type']} services on device #{device_id} "
            "could be it; check them in LibreNMS"
        )

    def _restore(self, client: Any, service_id: int, snapshot: Dict[str, Any], entry: Dict[str, Any]) -> None:
        """Edit service *service_id* until it holds the snapshot's configuration; StepError saying what is off."""
        obj = self.get(client, service_id, entry)
        if obj is None:
            raise StepError("it cannot be read back")
        current = self.state(client, obj)
        wanted = {name: snapshot.get(name) for name in _RESTORED}
        pending = {name: value for name, value in wanted.items() if not self._same(name, current.get(name), value)}
        if not pending:
            return
        try:
            client.request("PATCH", path("services", service_id), json=_columns(pending))
        except LibreNMSError as exc:
            raise StepError(f"restoring {', '.join(_RESTORED[name] for name in pending)} failed: {exc}") from None
        obj = self.get(client, service_id, entry)
        if obj is None:
            raise StepError("it disappeared while its configuration was restored")
        wrong = self._mismatches(wanted, self.state(client, obj), from_operation=False)
        if wrong:
            raise StepError(wrong)


RESOURCE = Service()
