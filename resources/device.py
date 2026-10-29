"""Devices: field updates and renames, adds, deletes, maintenance windows and rediscovery.

A device is the object whose writes reach the network. Adding one makes LibreNMS probe a host over ICMP and SNMP,
and changing its ``hostname`` or ``overwrite_ip`` moves where the poller sends this device's stored SNMP
credentials, so both need ``allow_device_add``. Everything else is a user-owned column written with
``update_device_field``, which accepts any field name and silently ignores the ones it does not know: every key
outside the allowed set is refused here, and every write is verified by re-reading.

LibreNMS facts this module leans on (specs/ln-devices.md): the device object carries SNMP secrets in clear for an
admin token, so every read is masked; an all-digit path segment is always a device id; the poller rewrites ``type``
and ``icon``, and ``location_id`` unless ``override_sysLocation`` is set; SNMP settings and credentials of an
existing device cannot be changed through API v0; a maintenance window cannot be ended, nor even read back.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, List, Set, Tuple

from .. import diff, redact
from ..client import LibreNMSError, is_digits, path, secret
from . import get_resource
from .base import Field, PartialWrite, Resource, StepError, _as_int, _maybe_committed

# The SNMP settings of an existing device live in device_polling_methods and secrets, which update_device_field
# cannot reach: it would answer 200 and change nothing.
SNMP_KEYS = frozenset(
    {
        "community",
        "authlevel",
        "authname",
        "authpass",
        "authalgo",
        "cryptopass",
        "cryptoalgo",
        "snmpver",
        "version",
        "port",
        "transport",
        "timeout",
        "retries",
        "snmp_disable",
    }
)
CREDENTIALS = ("community", "authname", "authpass", "cryptopass")
V3_KEYS = ("authlevel", "authname", "authpass", "authalgo", "cryptopass", "cryptoalgo")
# add_device reads these with !empty(): the string "false" would switch them on, so they are sent only when true.
SEND_WHEN_TRUE = ("force_add", "ping_fallback", "snmp_disable")
ENV_NAME = re.compile(r"LIBRENMS_SNMP_[A-Z0-9_]{1,64}")
# A community or an SNMPv3 password must live in a variable whose name ends in a word Hermes always masks when an
# environment dump reaches the model through its terminal tool (TOKEN and KEY are masked only for long values):
# Hermes hands the profile's .env to that tool's shells. The SNMPv3 user name (authname) may be named freely.
SECRET_ENV_NAME = re.compile(r"LIBRENMS_SNMP_(?:[A-Z0-9_]{0,55}_)?(?:SECRET|PASS|PASSWORD)")
SECRET_ENV_SUFFIXES = "_SECRET, _PASS or _PASSWORD"
# What add_device accepts as a host name or an IP address; a "/" or a space could not be put in a rename path.
HOSTNAME = re.compile(r"(?=.*[A-Za-z0-9])[A-Za-z0-9_.:-]{1,253}")
# add_device probes the host (ping, then SNMP with each default credential) before it answers, and del_device
# removes every row of the device and its RRD directory: a read timeout would leave the outcome unknown.
SLOW_READ_TIMEOUT = 120.0
STATE_FIELDS = (
    "notes",
    "purpose",
    "display_template",
    "overwrite_ip",
    "poller_group",
    "location_id",
    "disabled",
    "ignore",
    "disable_notify",
    "ignore_status",
    "override_sysLocation",
    "type",
    "icon",
)

MAINTENANCE_KEYS = ("behavior", "duration", "notes", "start", "title")
BEHAVIORS = {"skip_alerts": 1, "mute_alerts": 2, "run_alerts": 3}
# alert_schedule.title is varchar(255), and the "[hermes:<plan id>] " prefix takes 35 of it
TITLE_COLUMN = 255
MAX_TITLE = 200
_DURATION = re.compile(r"(\d{1,4}):([0-5]\d)")
_START = re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}")
_START_FORMAT = "%Y-%m-%d %H:%M:%S"

_LITERAL_CREDENTIAL = (
    "SNMP credentials are never written into a plan; set an environment variable such as "
    'LIBRENMS_SNMP_COMMUNITY_SECRET and pass {"env": "LIBRENMS_SNMP_COMMUNITY_SECRET"}, or omit the field to use '
    "LibreNMS's default credentials"
)
_UNMASKED_NAME = (
    f"the environment variable must be named LIBRENMS_SNMP_<NAME> ending in {SECRET_ENV_SUFFIXES} (A-Z, 0-9 and "
    "_), such as LIBRENMS_SNMP_COMMUNITY_SECRET or LIBRENMS_SNMP_V3_AUTH_PASS: Hermes masks only such names when "
    "the agent's terminal prints the environment"
)
_SNMP_UPDATE = "LibreNMS API v0 cannot change SNMP settings or credentials of an existing device"
_RETARGET = (
    "retargeting a device changes which host LibreNMS polls with this device's SNMP credentials; set "
    "plugins.entries.librenms.settings.allow_device_add: true"
)
_OVERRIDE = (
    "LibreNMS re-assigns the location from SNMP sysLocation on every poll unless override_sysLocation is true; "
    'add "override_sysLocation": true'
)
_FORBIDDEN = (
    "LibreNMS answered 403 for hostname {hostname}: it does not exist or this token cannot see it (LibreNMS returns "
    "403 for unknown hostnames to tokens without global read); use the device id or a token with global read"
)
_NOTES_APPENDED = "LibreNMS may append these notes to the device notes (user preference add_schedule_note_to_device)"
_DEFAULT_GROUP = (
    "poller_group 0 is not sent: LibreNMS puts a new device without a group in its default poller group (setting "
    "default_poller_group, 0 unless changed); set poller_group with an update after the add if it must be 0"
)


# -- maintenance -------------------------------------------------------------------------------------------------------


def _behavior(value: Any) -> str | None:
    """The behaviour's name from a name or its number 1-3 (LibreNMS's MaintenanceBehavior)."""
    if isinstance(value, str) and value in BEHAVIORS:
        return value
    number = int(value) if is_digits(value) else None
    return next((name for name, code in BEHAVIORS.items() if code == number), None)


def _valid_start(value: Any) -> bool:
    """``Y-m-d H:i:s`` and a real date: anything else makes LibreNMS's Carbon parse fail with a 500."""
    if not isinstance(value, str) or not _START.fullmatch(value):
        return False
    try:
        datetime.strptime(value, _START_FORMAT)
    except ValueError:
        return False
    return True


def _maintenance_errors(data: Dict[str, Any], max_hours: int) -> List[str]:
    """Static checks of a maintenance operation's data. A duration without a colon is the trap: LibreNMS answers
    201 and saves a window that ended before it began."""
    errors: List[str] = []
    unknown = sorted(set(data) - set(MAINTENANCE_KEYS))
    if unknown:
        errors.append(f"maintenance does not take {', '.join(unknown)}; allowed: {', '.join(MAINTENANCE_KEYS)}")
    duration = data.get("duration")
    found = _DURATION.fullmatch(duration) if isinstance(duration, str) else None
    if found is None:
        errors.append('duration is required as "H:MM" (for example "2:00")')
    else:
        minutes = int(found.group(1)) * 60 + int(found.group(2))
        if minutes == 0:
            errors.append("duration must be longer than 0:00")
        elif minutes > max_hours * 60:
            errors.append(f"duration {duration} is longer than max_maintenance_hours allows ({max_hours} hours)")
    if data.get("start") is not None and not _valid_start(data["start"]):
        errors.append('start must be "YYYY-MM-DD HH:MM:SS" in LibreNMS server time, or null for now')
    title = data.get("title")
    if title is not None and not (isinstance(title, str) and len(title) <= MAX_TITLE):
        errors.append(f"title: expected a string of at most {MAX_TITLE} characters")
    if data.get("notes") is not None and not isinstance(data["notes"], str):
        errors.append("notes: expected a string")
    if data.get("behavior") is not None and _behavior(data["behavior"]) is None:
        errors.append(f"behavior must be one of {', '.join(BEHAVIORS)} (or 1, 2, 3)")
    return errors


def _maintenance_params(data: Dict[str, Any]) -> Dict[str, Any]:
    """Every parameter spelled out, so the plan shows what is sent rather than an install-specific default."""
    return {
        "duration": data["duration"],
        "start": data.get("start"),
        "title": data.get("title") or None,
        "notes": data.get("notes") or "",
        "behavior": _behavior(data.get("behavior")) or "skip_alerts",
    }


def _maintenance_title(params: Dict[str, Any], label: str, plan_id: Any) -> str:
    """The schedule's title, tagged with the plan id: the only handle a person has to find and end it early. A
    hostname used as the title can be long enough to overflow the column."""
    return f"[hermes:{plan_id}] {params['title'] or label}"[:TITLE_COLUMN]


def _maintenance_body(params: Dict[str, Any], title: str) -> Dict[str, Any]:
    body = {
        "duration": params["duration"],
        "title": title,
        "notes": params["notes"],
        "behavior": BEHAVIORS[params["behavior"]],
    }
    if params["start"] is not None:
        body["start"] = params["start"]
    return body


def _maintenance_inverse_note(duration: str | None) -> str:
    expiry = f"it expires after {duration}" if duration else "it expires on its own"
    return (
        f"LibreNMS API v0 cannot end or delete maintenance; {expiry}. To end it early, delete the schedule whose "
        "title starts with [hermes:<plan id>] under Alerts → Scheduled Maintenance."
    )


def _describe_maintenance(params: Dict[str, Any], label: str) -> List[str]:
    parts = [f"duration {params['duration']}", f"behavior {params['behavior']}"]
    parts.append(f"title {diff.format_value(params['title'] or label)}")
    parts.append(f"start {params['start']} (LibreNMS server time)" if params["start"] else "starts now")
    if params["notes"]:
        parts.append(f"notes {diff.format_value(params['notes'])}")
    return [", ".join(parts)]


# -- helpers -----------------------------------------------------------------------------------------------------------


def _normalised(field: Field, value: Any) -> Any:
    """*value* in *field*'s canonical form, or as LibreNMS sent it when it has none (compared as it is)."""
    try:
        return diff.normalise(field, value)
    except ValueError:
        return value


def _number(field: Field, value: Any) -> int | None:
    try:
        number = diff.normalise(field, value)
    except ValueError:
        return None  # the kind error is reported by Resource.validate
    return number if isinstance(number, int) else None


def _credential_problem(name: str, value: Any) -> str | None:
    """Why an SNMP credential cannot be planned: only a reference to a set LIBRENMS_SNMP_* variable can, and for
    a community or password one whose name Hermes masks (:data:`SECRET_ENV_NAME`). A literal is never quoted back
    (it is the secret)."""
    if value is None:
        return None
    env = diff.env_name(value)
    if env is None:
        return f"{name}: {_LITERAL_CREDENTIAL}"
    if not ENV_NAME.fullmatch(env):
        return f"{name}: the environment variable must be named LIBRENMS_SNMP_<NAME> (A-Z, 0-9 and _)"
    if name != "authname" and not SECRET_ENV_NAME.fullmatch(env):
        return f"{name}: {_UNMASKED_NAME}"
    try:
        present = bool(secret(env))
    except LibreNMSError as exc:
        return f"{name}: {exc}"
    return None if present else f"{name}: {env} is not set in this Hermes profile's environment"


def _without_secrets(exc: LibreNMSError, secrets: List[str]) -> LibreNMSError:
    """*exc*, or a copy of the same kind and status whose text no longer carries a resolved SNMP credential (the
    kind and status decide whether the write may have happened)."""
    body = "" if exc.body is None else str(exc.body)
    if not (redact.holds_any(str(exc), secrets) or redact.holds_any(body, secrets)):
        return exc
    message = redact.scrub_text(str(exc), None, extra=secrets)
    return LibreNMSError(message, status=exc.status, method=exc.method, path=exc.path, kind=exc.kind)


def _poll_target(state: Dict[str, Any]) -> Any:
    return state.get("overwrite_ip") or state.get("hostname")


def _case_only(old: Any, new: Any) -> bool:
    """Whether two hostnames differ only in letter case: the same host to DNS and to LibreNMS's lookups."""
    return isinstance(old, str) and isinstance(new, str) and old != new and old.lower() == new.lower()


def _retargets(name: str, old: Any, new: Any) -> bool:
    """Whether a new ``hostname`` or ``overwrite_ip`` sends this device's SNMP credentials to another host."""
    return new != old and not (name == "hostname" and _case_only(old, new))


def _slow(client: Any) -> Tuple[float, float]:
    """The client's timeouts with the read stretched for a call LibreNMS takes long to answer."""
    connect, read = client.timeout
    return connect, max(read, SLOW_READ_TIMEOUT)


class Device(Resource):
    name = "device"
    title = "device"
    id_key = "device_id"
    label_key = "hostname"
    match_keys = ("hostname",)
    natural_key = "hostname"
    identity_keys = ("hostname", "inserted")
    fields = {
        "hostname": Field("hostname", "str", required=True),
        "notes": Field("notes", "text", create=False),
        "purpose": Field("purpose", "text", create=False),
        "display_template": Field("display_template", "text"),
        "overwrite_ip": Field("overwrite_ip", "text"),
        "poller_group": Field("poller_group", "int"),
        "location_id": Field("location_id", "int", nullable=True),
        "location": Field("location", "str", nullable=True),  # a name, resolved to location_id; never sent
        "override_sysLocation": Field("override_sysLocation", "bool"),
        "disabled": Field("disabled", "bool", create=False),
        "ignore": Field("ignore", "bool", create=False),
        "disable_notify": Field("disable_notify", "bool", create=False),
        "ignore_status": Field("ignore_status", "bool", create=False),
        "type": Field("type", "text", create=False, note="discovery may overwrite this"),
        "icon": Field("icon", "text", create=False, note="discovery may overwrite this"),
        "snmpver": Field("snmpver", "enum", ("v1", "v2c", "v3"), update=False),
        "port": Field("port", "int", update=False),
        "transport": Field("transport", "enum", ("udp", "tcp", "udp6", "tcp6"), update=False),
        "port_association_mode": Field(
            "port_association_mode", "enum", ("ifIndex", "ifName", "ifDescr", "ifAlias"), update=False
        ),
        "force_add": Field("force_add", "bool", update=False),
        "ping_fallback": Field("ping_fallback", "bool", update=False),
        "snmp_disable": Field("snmp_disable", "bool", update=False),
        "sysName": Field("sysName", "str", update=False),
        "hardware": Field("hardware", "str", update=False),
        "os": Field("os", "str", update=False),
        "community": Field("community", "env", update=False),
        "authlevel": Field("authlevel", "enum", ("noAuthNoPriv", "authNoPriv", "authPriv"), update=False),
        "authname": Field("authname", "env", update=False),
        "authpass": Field("authpass", "env", update=False),
        "authalgo": Field("authalgo", "enum", ("MD5", "SHA", "SHA-224", "SHA-256", "SHA-384", "SHA-512"), update=False),
        "cryptopass": Field("cryptopass", "env", update=False),
        "cryptoalgo": Field(
            "cryptoalgo", "enum", ("DES", "AES", "AES-192", "AES-256", "AES-192-C", "AES-256-C"), update=False
        ),
    }
    ops = ("create", "update", "delete", "maintenance", "discover")
    inverse = {
        "create": ("exact", "removes the device; LibreNMS keeps the SNMP credential record it created"),
        "update": ("exact", ""),
        "delete": (
            "none",
            "deleting a device removes its RRD history, ports, alerts and group membership; LibreNMS cannot restore "
            "it and re-adding creates a new device",
        ),
        "maintenance": ("none", _maintenance_inverse_note(None)),
        "discover": ("not_needed", "rediscovery only schedules a discovery run"),
    }

    # -- reads ------------------------------------------------------------------------------------------------------

    def get(self, client: Any, object_id: int, step: Dict[str, Any] | None = None) -> Dict[str, Any] | None:
        """``GET devices/{id}`` -> ``devices[0]``, credentials masked (an admin token gets them in clear)."""
        return self._first(client, client.get_or_none(path("devices", object_id)))

    def find(self, client: Any, match: Dict[str, Any]) -> Tuple[int, Dict[str, Any] | None]:
        """``GET devices/{hostname}``: LibreNMS matches the hostname column exactly (case-insensitively), and reads
        an all-digit segment as a device id, so such a hostname cannot be looked up by name at all. No hostname
        holds a ``/`` (add_device validates it, a rename takes one path segment), and an encoded one would reach
        another route."""
        hostname = match.get("hostname")
        if not isinstance(hostname, str) or not hostname:
            raise StepError("a device is matched by hostname, a non-empty string")
        if is_digits(hostname):
            raise StepError("all-digit hostnames cannot be looked up by name; use id")
        if "/" in hostname:
            return 0, None
        try:
            body = client.get_or_none(path("devices", hostname))
        except LibreNMSError as exc:
            if exc.kind == "forbidden":
                raise StepError(_FORBIDDEN.format(hostname=diff.format_value(hostname))) from None
            raise
        obj = self._first(client, body)
        return (0, None) if obj is None else (1, obj)

    @staticmethod
    def _first(client: Any, body: Any) -> Dict[str, Any] | None:
        rows = client.result(body, "devices") if body is not None else None
        if isinstance(rows, list) and rows and isinstance(rows[0], dict):
            return redact.mask(rows[0])
        return None

    def state(self, client: Any, obj: Dict[str, Any]) -> Dict[str, Any]:
        """Identity (``device_id``, ``hostname``, ``inserted``: the creation time tells a re-added device apart) and
        the user-owned columns; never poller data such as ``status``, ``uptime`` or ``sysName``."""
        state = {
            "device_id": _as_int(obj.get("device_id")),
            "hostname": _normalised(self.fields["hostname"], obj.get("hostname")),
            "inserted": obj.get("inserted"),
        }
        for name in STATE_FIELDS:
            state[name] = _normalised(self.fields[name], obj.get(name))
        return state

    def volatile_fields(self, state: Dict[str, Any]) -> Set[str]:
        """Discovery may reset ``type`` and ``icon``; the poller re-assigns ``location_id`` from sysLocation unless
        ``override_sysLocation`` is set."""
        volatile = {"type", "icon"}
        if not state.get("override_sysLocation"):
            volatile.add("location_id")
        return volatile

    # -- planning ---------------------------------------------------------------------------------------------------

    def validate(self, op: str, data: Dict[str, Any], settings: Any) -> List[str]:
        if op == "maintenance":
            return _maintenance_errors(data, settings.max_maintenance_hours)
        if op not in ("create", "update"):
            return []
        errors: List[str] = []
        if op == "update":
            skip = set(data) & SNMP_KEYS
            if skip:
                errors.append(f"{_SNMP_UPDATE} ({', '.join(sorted(skip))})")
        else:
            skip = set(data) & set(CREDENTIALS)
            for name in sorted(skip):
                problem = _credential_problem(name, data[name])
                if problem:
                    errors.append(problem)
        checked = {key: value for key, value in data.items() if key not in skip}
        errors += super().validate(op, checked, settings)
        errors += self._value_errors(checked)
        if op == "create":
            errors += self._snmp_errors(data)
        return errors

    def _value_errors(self, data: Dict[str, Any]) -> List[str]:
        """Ranges and shapes the field kinds do not cover."""
        errors: List[str] = []
        hostname = data.get("hostname")
        if isinstance(hostname, str) and hostname:
            if is_digits(hostname):
                errors.append("hostname: LibreNMS reads an all-digit hostname as a device id; use a name or an IP")
            elif not HOSTNAME.fullmatch(hostname):
                errors.append(
                    f"hostname: expected a host name or IP address (letters, digits, '.', '-', '_', ':'), got "
                    f"{diff.format_value(hostname)}"
                )
        if "location" in data and "location_id" in data:
            errors.append("give location (a name) or location_id, not both")
        if isinstance(data.get("location"), str) and not data["location"].strip():
            errors.append("location: expected a location name, got an empty string")
        bounds = (("location_id", 1, None), ("poller_group", 0, None), ("port", 1, 65535))
        for name, low, high in bounds:
            number = _number(self.fields[name], data.get(name))
            if number is not None and (number < low or (high is not None and number > high)):
                limit = f"between {low} and {high}" if high is not None else f"{low} or more"
                errors.append(f"{name}: expected an integer {limit}, got {number}")
        return errors

    @staticmethod
    def _snmp_errors(data: Dict[str, Any]) -> List[str]:
        """SNMPv3 fields without ``snmpver: v3`` (or a community with it) make LibreNMS pick the other secret type and
        drop what was given; a security level without its passwords fails its secret validation."""
        errors: List[str] = []
        given = [key for key in V3_KEYS if data.get(key) is not None]
        if given and data.get("snmpver") != "v3":
            errors.append(f'{", ".join(given)}: SNMPv3 settings need "snmpver": "v3"')
        if data.get("community") is not None and data.get("snmpver") == "v3":
            errors.append("community is an SNMPv1/v2c credential; SNMPv3 uses authname, authpass and cryptopass")
        level = data.get("authlevel")
        if level in ("authNoPriv", "authPriv") and data.get("authpass") is None:
            errors.append(f"authlevel {level} needs authpass")
        if level == "authPriv" and data.get("cryptopass") is None:
            errors.append("authlevel authPriv needs cryptopass")
        return errors

    def resolve(self, client: Any, op: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalised values, the location name replaced by its id (``location`` would make LibreNMS create a
        location it does not know), and the location and poller group proved to exist: LibreNMS accepts dangling
        ids, and a device in a poller group that does not exist is never polled."""
        resolved = super().resolve(client, op, data)
        if op not in ("create", "update"):
            return resolved
        if "location" in resolved:
            name = resolved.pop("location")
            resolved["location_id"] = None if name is None else self._location_id(client, name)
        elif resolved.get("location_id") is not None and self._location(client, resolved["location_id"]) is None:
            raise StepError(f"location #{resolved['location_id']} does not exist")
        group = resolved.get("poller_group")
        if group and not self._poller_group_exists(client, group):
            raise StepError(f"poller group #{group} does not exist (0 is the default group)")
        return resolved

    def _location_id(self, client: Any, name: str) -> int:
        count, obj = get_resource("location").find(client, {"location": name})
        if count > 1:
            raise StepError(f"{count} locations are named {diff.format_value(name)}; use location_id")
        location_id = _as_int((obj or {}).get("id"))
        if location_id is None:
            raise StepError(
                f"no location is named {diff.format_value(name)}; create it first (resource location) or use "
                "location_id"
            )
        return location_id

    @staticmethod
    def _location(client: Any, location_id: int) -> Dict[str, Any] | None:
        return get_resource("location").get(client, location_id)

    @staticmethod
    def _poller_group_exists(client: Any, group_id: int) -> bool:
        """``GET poller_group/{id}`` names one group; never called for 0, which LibreNMS answers with every group."""
        body = client.get_or_none(path("poller_group", group_id))
        found = client.result(body, "get_poller_group") if body is not None else None
        rows = found if isinstance(found, list) else [found]
        return any(isinstance(row, dict) and _as_int(row.get("id")) == group_id for row in rows)

    def plan_step(self, client: Any, index: int, op: Dict[str, Any], settings: Any) -> Dict[str, Any]:
        """The base step, with location names next to a changed ``location_id`` for the person reviewing it."""
        step = super().plan_step(client, index, op, settings)
        change = (step.get("changes") or {}).get("location_id")
        for side in ("from", "to") if change else ():
            found = self._location(client, change[side]) if change[side] is not None else None
            if found and found.get("location"):
                change[f"{side}_label"] = str(found["location"])
        return step

    def _prepare(
        self, client: Any, step: Dict[str, Any], data: Dict[str, Any], current: Dict[str, Any] | None, settings: Any
    ) -> Dict[str, Any]:
        before = current or {}
        relocates = "location_id" in data and data["location_id"] != before.get("location_id")
        if relocates and not data.get("override_sysLocation", before.get("override_sysLocation", False)):
            raise StepError(_OVERRIDE)
        if current is None:
            count, obj = self.find(client, {"hostname": data["hostname"]})
            if count:
                raise StepError(
                    f"device {diff.format_value(data['hostname'])} already exists (#{(obj or {}).get('device_id')}); "
                    "change it with update, or create with match to upsert"
                )
            if all(data.get(name) is None for name in CREDENTIALS) and not data.get("snmp_disable"):
                step["notes"].append("no SNMP credentials given: LibreNMS tries its configured default credentials")
            if data.get("poller_group") == 0:  # add_device stores 0 as default_poller_group, so 0 cannot be verified
                data = {name: value for name, value in data.items() if name != "poller_group"}
                step["notes"].append(_DEFAULT_GROUP)
            return data
        if step.get("upsert") and _case_only(before.get("hostname"), data.get("hostname")):
            data = {name: value for name, value in data.items() if name != "hostname"}
            step["notes"].append(
                f"hostname: the match found {diff.format_value(before['hostname'])}, the same host in other letter "
                "case; LibreNMS's spelling is kept"
            )
        moved = [name for name in ("hostname", "overwrite_ip") if name in data and data[name] != before.get(name)]
        retargets = any(_retargets(name, before.get(name), data[name]) for name in moved)
        if retargets and not getattr(settings, "allow_device_add", False):
            raise StepError(_RETARGET)
        if "hostname" in moved:
            taken = self._hostname_taken(client, data["hostname"], step["object_id"])
            if taken:
                raise StepError(taken)
        return data

    def _hostname_taken(self, client: Any, hostname: str, object_id: int) -> str | None:
        """Why a rename to *hostname* would fail: another device already has it. LibreNMS compares hostnames without
        regard to case and leaves the device itself out, so a rename that only changes case is free."""
        count, obj = self.find(client, {"hostname": hostname})
        other = _as_int((obj or {}).get("device_id"))
        if not count or other == object_id:
            return None
        return f"hostname {diff.format_value(hostname)} is already used by device #{other}"

    def _plan_action(
        self,
        client: Any,
        step: Dict[str, Any],
        data: Dict[str, Any],
        obj: Dict[str, Any],
        current: Dict[str, Any],
        settings: Any,
    ) -> Dict[str, Any]:
        if step["action"] != "maintenance":
            return super()._plan_action(client, step, data, obj, current, settings)
        params = _maintenance_params(data)
        step["params"] = params
        step["inverse_note"] = _maintenance_inverse_note(params["duration"])
        if params["notes"]:
            step["notes"].append(_NOTES_APPENDED)
        return step

    def _payload(self, data: Dict[str, Any], record: Dict[str, Any]) -> Dict[str, Any]:
        """The ``update_device_field`` body, and the new hostname, which goes through its own rename route."""
        fields = {name: value for name, value in data.items() if name != "hostname"}
        payload: Dict[str, Any] = {"field": list(fields), "data": list(fields.values())} if fields else {}
        if "hostname" in data:
            payload["rename"] = data["hostname"]
        return payload

    def describe(self, step: Dict[str, Any]) -> List[str]:
        action = step["action"]
        if action == "maintenance":
            return _describe_maintenance(step.get("params") or {}, step.get("label") or "")
        if action == "discover":
            return ["LibreNMS rediscovers the device at its next discovery run"]
        if action == "delete":
            snapshot = step.get("snapshot") or {}
            seen = ", ".join(
                f"{key} {diff.format_value(snapshot.get(key), 40)}"
                for key in ("sysName", "os", "hardware", "serial", "location")
            )
            return [f"the device is deleted with its ports, services, alerts, eventlog and RRD history ({seen})"]
        lines = super().describe(step)
        changes = step.get("changes") or {}
        if action == "update" and {"hostname", "overwrite_ip"} & set(changes):
            before = (step.get("precondition") or {}).get("state") or {}
            after = {**before, **{name: change["to"] for name, change in changes.items()}}
            lines.append(
                f"poll target: {diff.format_value(_poll_target(before))} -> {diff.format_value(_poll_target(after))}"
            )
        return lines

    # -- apply ------------------------------------------------------------------------------------------------------

    def execute(self, client: Any, step: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """The base execution, after the retargeting gate is checked again against the settings in force now."""
        changes = step.get("changes") or {}
        retargets = any(
            _retargets(name, changes[name]["from"], changes[name]["to"])
            for name in ("hostname", "overwrite_ip")
            if name in changes
        )
        if step["action"] == "update" and retargets and not getattr(context.get("settings"), "allow_device_add", False):
            raise StepError(_RETARGET)
        return super().execute(client, step, context)

    def _extra_check(
        self, client: Any, step: Dict[str, Any], obj: Dict[str, Any] | None, current: Dict[str, Any] | None
    ) -> str | None:
        """What the step points at must still be there: a free hostname for a rename, the location, the group."""
        action = step["action"]
        if action == "create":
            values = step.get("data") or {}
        elif action == "update":
            values = {name: change["to"] for name, change in (step.get("changes") or {}).items()}
        else:
            return None
        if action == "update" and "hostname" in values:
            taken = self._hostname_taken(client, values["hostname"], step["object_id"])
            if taken:
                return taken
        if values.get("location_id") is not None and self._location(client, values["location_id"]) is None:
            return f"location #{values['location_id']} no longer exists"
        if values.get("poller_group") and not self._poller_group_exists(client, values["poller_group"]):
            return f"poller group #{values['poller_group']} no longer exists"
        return None

    def _create_call(self, client: Any, step: Dict[str, Any], context: Dict[str, Any]) -> int | None:
        """``POST devices`` with the credentials read from the environment now (never stored), and a read timeout
        long enough for LibreNMS's probing. The id comes from ``devices[0]``; the answer's copy of the device,
        which carries the credentials in clear, is not kept."""
        body, secrets = self._create_body(step.get("data") or {})
        try:
            answer = client.request("POST", "devices", json=body, timeout=_slow(client))
        except LibreNMSError as exc:
            clean = _without_secrets(exc, secrets)
            if clean is exc:
                raise
            raise clean from None
        rows = client.result(answer, "devices")
        first = rows[0] if isinstance(rows, list) and rows and isinstance(rows[0], dict) else {}
        return _as_int(first.get("device_id"))

    @staticmethod
    def _create_body(data: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
        body: Dict[str, Any] = {}
        secrets: List[str] = []
        for name, value in data.items():
            if name in CREDENTIALS:
                if value is None:
                    continue
                env = diff.env_name(value) or ""
                resolved = secret(env)
                if not resolved:
                    raise StepError(f"{name}: {env} is not set in this Hermes profile's environment; set it and apply")
                body[name] = resolved
                secrets.append(resolved)
            elif name in SEND_WHEN_TRUE:
                if value:
                    body[name] = True
            elif value is not None and value != "":
                body[name] = value
        return body, secrets

    def _update_call(
        self, client: Any, object_id: int, data: Dict[str, Any], record: Dict[str, Any], context: Dict[str, Any]
    ) -> None:
        """One multi-field PATCH (booleans as JSON true/false: a string "false" is a silent no-op), then the rename
        by id, the only route that changes a hostname. Rollback renames back the same way."""
        fields = {name: value for name, value in data.items() if name != "hostname"}
        if fields:
            client.request("PATCH", path("devices", object_id), json=self._payload(fields, record))
        if "hostname" in data:
            client.request("PATCH", path("devices", object_id, "rename", data["hostname"]))

    def _delete_call(self, client: Any, object_id: int, record: Dict[str, Any], context: Dict[str, Any]) -> None:
        client.request("DELETE", path("devices", object_id), timeout=_slow(client))

    def _execute_action(self, client: Any, step: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        object_id = step["object_id"]
        if step["action"] == "maintenance":
            return self._maintenance(client, step, context)
        # A GET that changes state: it clears last_discovered, so the next discovery run takes the device.
        result = client.result(client.get(path("devices", object_id, "discover")), "result")
        message = result.get("message") if isinstance(result, dict) else None
        return self._entry(object_id, None, None, [str(message)] if message else [])

    def _maintenance(self, client: Any, step: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """``POST devices/{id}/maintenance``. LibreNMS returns no schedule id and no route reads schedules back, so a
        POST that may have landed is a partial write (a re-read cannot prove otherwise), and verification is best
        effort, never failing a window that was accepted: whether the device reports being under maintenance (when
        it starts now), and whether LibreNMS appended the notes to the device's notes."""
        object_id, params = step["object_id"], step["params"]
        title = _maintenance_title(params, step["label"], context.get("plan_id"))
        notes = [f"schedule title: {title}"]
        try:
            client.request("POST", path("devices", object_id, "maintenance"), json=_maintenance_body(params, title))
        except LibreNMSError as exc:
            if not _maybe_committed(exc):
                raise
            notes.append("outcome unknown: look for the schedule title under Alerts → Scheduled Maintenance")
            entry = self._entry(object_id, None, None, notes)
            raise PartialWrite(f"{exc} (LibreNMS may have saved the maintenance schedule)", entry) from exc
        previous = ((step.get("precondition") or {}).get("state") or {}).get("notes", "")
        try:
            if params["start"] is None:
                answer = client.get(path("devices", object_id, "maintenance"))
                if client.result(answer, "is_under_maintenance") is not True:
                    notes.append("LibreNMS does not report the device under maintenance yet")
            obj = self.get(client, object_id, step) if params["notes"] else None
            if obj is not None and not self._same("notes", self.state(client, obj)["notes"], previous):
                # The executor journals only the notes of a step; the plan keeps the full value in its precondition.
                notes.append(
                    "LibreNMS appended the maintenance notes to the device notes; previous_notes: "
                    + diff.format_value(previous, 500)
                )
        except LibreNMSError as exc:
            notes.append(f"the maintenance was accepted but could not be verified: {exc}")
        return self._entry(object_id, None, None, notes)


RESOURCE = Device()
