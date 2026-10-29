"""Port descriptions (``ifAlias``): the one port attribute API v0 can both write and read back.

LibreNMS gives the description two meanings. A non-empty value set through the API is stored and *pinned*: a
``devices_attribs`` row keyed by the port's ifName stops the poller from copying the device's ifAlias over it. An
empty one (``""``, ``"0"``, a missing key, a body that is not JSON, or the literal ``"repoll"``) stores ``"repoll"``
and hands the port back to the poller, which fills in the device's value at its next run. The pin cannot be read
through the API, so rollback restores the text but not whether the poller was allowed to overwrite it: the inverse
is lossy. Requests name the port by its numeric id (MySQL reads ``12abc`` as port 12) and always carry the
``description`` key.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from .. import redact
from ..client import LibreNMSError, is_digits, path
from .base import Field, Resource, StepError

# ports.ifAlias is varchar(255) and API requests run without strict SQL mode: a longer value is cut without an error.
MAX_DESCRIPTION = 255
_REPOLL = "repoll"
_PORT_COLUMNS = "port_id,ifName,ifDescr,ifAlias"
_PINNED = (
    "a description set through the API is pinned: the poller stops copying the device's ifAlias into it until the "
    'description is cleared with ""'
)
_RELEASED = (
    'clearing hands the description back to the poller: LibreNMS shows "repoll" until the next poll copies the '
    "device's ifAlias"
)
_REPOLLED = "description was repolled from the device before rollback"


def _description(value: Any) -> str:
    """The description as plans compare it: NULL, ``""`` and ``"repoll"`` all mean "none, the poller's to fill"."""
    text = "" if value is None else str(value)
    return "" if text == _REPOLL else text


def _port_path(object_id: Any, *rest: str) -> str:
    if not is_digits(object_id):
        raise StepError(f"a port id must be a non-negative integer, got {str(object_id)[:40]!r}")
    return path("ports", object_id, *rest)


class Port(Resource):
    name = "port"
    title = "port"
    id_key = "port_id"
    label_key = "ifName"
    match_keys = ("device", "ifName", "ifDescr")
    parent_key = "device_id"
    fields = {"description": Field("description", "text", create=False)}
    ops = ("update",)
    inverse = {
        "update": (
            "lossy",
            "restores the previous description text; whether the poller was allowed to overwrite it cannot be read "
            "through the API",
        )
    }

    # -- reads ------------------------------------------------------------------------------------------------------

    def get(self, client: Any, object_id: int, step: Dict[str, Any] | None = None) -> Dict[str, Any] | None:
        """``GET ports/{id}`` (deleted ports included; an unknown id is an empty list) plus the description from
        ``GET ports/{id}/description``, which leaves its key out when the column is NULL."""
        rows = client.result(client.get(_port_path(object_id)), "port")
        if not isinstance(rows, list) or not rows or not isinstance(rows[0], dict):
            return None
        description = client.result(client.get(_port_path(object_id, "description")), "port_description")
        return {**rows[0], "port_description": description}

    def find(self, client: Any, match: Dict[str, Any]) -> Tuple[int, Dict[str, Any] | None]:
        """Ports of ``match["device"]`` (hostname or id) whose ifName and/or ifDescr equal the given text exactly.
        LibreNMS lists only ports that are not deleted, and answers 404 when there are none."""
        keys = [key for key in ("ifName", "ifDescr") if key in match]
        if "device" not in match or not keys:
            raise StepError("a port match needs device (hostname or id) and ifName or ifDescr")
        for key in keys:
            if not isinstance(match[key], str) or not match[key]:
                raise StepError(f"match {key} must be a non-empty string")
        device_id, _hostname = self._device(client, match["device"])
        body = client.get_or_none(path("devices", device_id, "ports"), {"columns": _PORT_COLUMNS})
        rows = client.result(body, "ports") if body is not None else None
        hits = [row for row in rows or [] if isinstance(row, dict) and all(row.get(k) == match[k] for k in keys)]
        if len(hits) != 1:
            return len(hits), None
        return 1, self.get(client, int(str(hits[0]["port_id"])))

    def state(self, client: Any, obj: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "port_id": int(str(obj["port_id"])),
            "device_id": int(str(obj["device_id"])),
            "ifName": "" if obj.get("ifName") is None else str(obj["ifName"]),
            "deleted": str(obj.get("deleted")).strip().lower() in ("1", "true"),
            "description": _description(obj.get("port_description")),
        }

    def _device(self, client: Any, ref: Any) -> Tuple[int, str]:
        """``(device_id, hostname)`` of a device named by id or hostname: ``GET devices/{ref}``, where LibreNMS reads
        all digits as an id. The object is masked, since an admin token gets SNMP credentials in it. No hostname holds
        a ``/`` (add_device refuses one), and an encoded one would reach another route: it is not looked up."""
        if isinstance(ref, bool) or not isinstance(ref, (str, int)) or not str(ref).strip():
            raise StepError("match device must be a device hostname or id")
        by_id = is_digits(ref)
        if "/" in str(ref):
            raise StepError(f"no LibreNMS device has hostname {ref!r}")
        try:
            body = client.get_or_none(path("devices", ref))
        except LibreNMSError as exc:
            if exc.kind != "forbidden" or by_id:
                raise
            raise StepError(
                f"LibreNMS answered 403 for hostname {ref}: it does not exist or this token cannot see it (LibreNMS "
                "returns 403 for unknown hostnames to tokens without global read); use the device id or a token with "
                "global read"
            ) from None
        rows = client.result(body, "devices") if body is not None else None
        device = redact.mask(rows[0]) if isinstance(rows, list) and rows and isinstance(rows[0], dict) else None
        if device is None or not is_digits(device.get("device_id")):
            raise StepError(f"device #{ref} does not exist" if by_id else f"no LibreNMS device has hostname {ref!r}")
        return int(device["device_id"]), str(device.get("hostname") or "")

    # -- planning ---------------------------------------------------------------------------------------------------

    def validate(self, op: str, data: Dict[str, Any], settings: Any) -> List[str]:
        """Beyond the type check: the values LibreNMS would store as something else are refused, not sent."""
        errors = super().validate(op, data, settings)
        value = data.get("description")
        if op != "update" or not isinstance(value, str):
            return errors
        if len(value) > MAX_DESCRIPTION:
            errors.append(
                f"description: at most {MAX_DESCRIPTION} characters, got {len(value)} (LibreNMS would cut it silently)"
            )
        elif value == "0":
            errors.append(
                'description: "0" cannot be set; LibreNMS reads it as empty and clears the description (use "" to '
                "clear)"
            )
        elif value == _REPOLL:
            errors.append(
                'description: "repoll" cannot be set; LibreNMS reads it as the marker of a cleared description (use '
                '"" to clear)'
            )
        return errors

    def plan_step(self, client: Any, index: int, op: Dict[str, Any], settings: Any) -> Dict[str, Any]:
        """The base update, labelled with the device's hostname (an ifName alone does not say which device), noting
        whether the write pins the description or hands it back to the poller."""
        step = super().plan_step(client, index, op, settings)
        hostname = self._hostname(client, step["parent_id"])
        if hostname:
            step["label"] = f"{step['label']} on {hostname}"
        if step["action"] == "update":
            step["notes"].append(_PINNED if step["changes"]["description"]["to"] else _RELEASED)
        return step

    def _hostname(self, client: Any, device_id: Any) -> str:
        """The device's hostname for the plan label; the label stays the ifName when the device cannot be read."""
        try:
            return self._device(client, device_id)[1]
        except (StepError, LibreNMSError):
            return ""

    def _prepare(
        self, client: Any, step: Dict[str, Any], data: Dict[str, Any], current: Dict[str, Any] | None, settings: Any
    ) -> Dict[str, Any]:
        if current and current["deleted"]:
            raise StepError(
                f"port #{current['port_id']} ({current['ifName']}) is marked deleted in LibreNMS: the device no "
                "longer has it"
            )
        return data

    # -- apply and rollback -----------------------------------------------------------------------------------------

    def _update_call(
        self, client: Any, object_id: int, data: Dict[str, Any], record: Dict[str, Any], context: Dict[str, Any]
    ) -> None:
        # The key is always sent: a body without it clears the description just like "" does
        client.request("PATCH", _port_path(object_id, "description"), json={"description": data["description"]})

    def _inverse(self, step: Dict[str, Any], object_id: int | None) -> Dict[str, Any] | None:
        inverse = super()._inverse(step, object_id)
        data = (inverse or {}).get("data") or {}
        if data.get("description") == "0":
            # LibreNMS reads "0" as empty, so only the poller can have stored it: handing the port back restores it
            data["description"] = ""
        return inverse

    def _revert_update(
        self,
        client: Any,
        entry: Dict[str, Any],
        inverse: Dict[str, Any],
        step: Dict[str, Any],
        force: bool,
        context: Dict[str, Any],
    ) -> Tuple[str, Dict[str, Any]]:
        """After an apply that left the description to the poller, whatever it holds now is the device's ifAlias, not
        an edit to protect: the rest of the port is compared as usual and the old text is restored over it."""
        after = entry.get("after_state")
        if not after or after.get("description") != "":
            return super()._revert_update(client, entry, inverse, step, force, context)
        obj = self.get(client, inverse.get("object_id", entry.get("object_id")), entry)
        current = self.state(client, obj)["description"] if obj is not None else ""
        if not current:
            return super()._revert_update(client, entry, inverse, step, force, context)
        entry = {**entry, "after_state": {**after, "description": current}}
        status, details = super()._revert_update(client, entry, inverse, step, force, context)
        if status == "reverted":
            details["note"] = f"{_REPOLLED}; {details['note']}" if details.get("note") else _REPOLLED
        return status, details


RESOURCE = Port()
