"""Operator-tunable settings, read from ``plugins.entries.librenms.settings`` in config.yaml.

Defaults are conservative: deletes, device adds and services are off, writes ask for approval, plans are capped,
and stale plans are refused. A value that cannot be read as its setting's type fails closed: a flag takes the
value that lets the model do least, a number its default (or its upper limit when it is too large), and
``write_mode`` becomes ``read_only``. Each fallback is recorded in :attr:`Settings.errors`, which status shows and
``register`` logs. Nothing here is read from the environment; connection settings live in :mod:`client`.
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import json
import os
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List

WRITE_MODES = ("full", "operator_only", "read_only")
# Upper limits: a larger value is lowered to the limit. plan_retention_days is the one count where 0 means
# something (keep plans forever); for the others 0 would be no cap at all, so it keeps the default.
LIMITS = {
    "max_operations": 1000,
    "max_query_results": 5000,
    "max_plan_age_hours": 720,
    "max_maintenance_hours": 8760,
    "plan_retention_days": 3650,
}
_ZERO_ALLOWED = frozenset({"plan_retention_days"})
# What an unreadable value becomes when that is not simply the default: whatever lets the model do least. Every
# flag listed here equals its default today; the table keeps it so when a default changes.
_FAIL_CLOSED: Dict[str, Any] = {
    "write_mode": "read_only",
    "require_approval": True,
    "allow_delete": False,
    "allow_device_add": False,
    "allow_services": False,
    "allow_insecure_transport": False,
    "audit_log": True,
    "link_eventlog": True,
}
_TRUE = frozenset({"true", "yes", "on", "1"})
_FALSE = frozenset({"false", "no", "off", "0"})
_SHOWN_CHARS = 40


@dataclass
class Settings:
    write_mode: str = "full"  # full | operator_only | read_only
    require_approval: bool = True  # escalate librenms_apply / librenms_rollback to Hermes' approval prompt
    allow_delete: bool = False
    allow_device_add: bool = False  # adding or retargeting a device makes LibreNMS probe a model-chosen host
    allow_services: bool = False  # services run Nagios plugins with model-supplied arguments on the poller
    allow_insecure_transport: bool = False  # http:// or LIBRENMS_VERIFY_SSL=false (also for audit sinks)
    max_operations: int = 100
    max_query_results: int = 500
    max_plan_age_hours: int = 24
    max_maintenance_hours: int = 72
    plan_retention_days: int = 90  # 0 keeps plans forever
    audit_log: bool = True
    audit_log_path: str = ""  # absolute; empty = <HERMES_HOME>/plugin-data/librenms/audit.jsonl
    audit_include_request: bool = True
    link_eventlog: bool = True  # cross-reference LibreNMS' eventlog after apply/rollback
    audit_sinks: List[Dict[str, Any]] = field(default_factory=list)  # see sinks.py
    # Not settings: what reading the others found wrong and fell back from, and where each kept audit_sinks entry
    # stands in config.yaml (an entry that is not a mapping is dropped; sink warnings must not renumber the rest).
    errors: List[str] = field(default_factory=list, compare=False)
    audit_sink_numbers: List[int] = field(default_factory=list, compare=False, repr=False)

    @classmethod
    def from_ctx(cls, ctx: Any) -> Settings:
        """Build from a Hermes ``PluginContext``. Every read is guarded so registration never fails: a read that
        raises gives that setting its fail-closed value and an error."""
        return cls._build(lambda name: ctx.get_config(name, default=None))

    @classmethod
    def from_mapping(cls, raw: Dict[str, Any]) -> Settings:
        """Build from a plain mapping of setting names to raw values, with the same coercion as :meth:`from_ctx`."""
        values = raw if isinstance(raw, Mapping) else {}
        return cls._build(values.get)

    @classmethod
    def _build(cls, read: Callable[[str], Any]) -> Settings:
        errors: List[str] = []
        values: Dict[str, Any] = {}
        numbers: List[int] = []
        for name, default in cls().to_dict().items():
            try:
                raw = read(name)
            except Exception as exc:
                values[name] = _fallback(name, default)
                errors.append(
                    f"{name}: could not be read from the Hermes config ({type(exc).__name__}); "
                    f"using {_text(values[name])}"
                )
                continue
            values[name] = coerce(name, raw, default, errors)
            if name == "audit_sinks" and isinstance(raw, list):
                numbers = [index for index, spec in enumerate(raw) if isinstance(spec, dict)]
        return cls(**values, errors=errors, audit_sink_numbers=numbers)

    def to_dict(self) -> Dict[str, Any]:
        """Every setting (``errors`` and ``audit_sink_numbers`` are not settings)."""
        values = asdict(self)
        values.pop("errors")
        values.pop("audit_sink_numbers")
        return values

    def public(self) -> Dict[str, Any]:
        """What status may show the model: sink entries become a count and their types, because a sink's url or
        headers can carry a collector's credentials, and ``audit_log_path`` only whether it is set (``custom``),
        because a path names the OS account."""
        values = self._summary()
        values["audit_log_path"] = "custom" if self.audit_log_path else ""
        return values

    def _summary(self) -> Dict[str, Any]:
        """Every setting, with sink entries reduced to their count and types (what :meth:`digest` covers)."""
        values = self.to_dict()
        values["audit_sinks"] = {
            "count": len(self.audit_sinks),
            "types": sorted({_sink_type(spec) for spec in self.audit_sinks}),
        }
        return values

    def digest(self) -> str:
        """Short SHA-256 of the settings as canonical JSON, sink entries reduced to their count and types: the same
        settings give the same digest in every process, so audit events can show which configuration a run used
        without carrying it. A different ``audit_log_path`` gives a different digest, though status shows neither
        path."""
        text = json.dumps(self._summary(), sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
        return hashlib.sha256(text.encode("ascii")).hexdigest()[:12]


def coerce(name: str, raw: Any, default: Any, errors: List[str]) -> Any:
    """One raw config value as its setting's type (taken from *default*). ``None`` (absent or empty) is the
    default; anything unusable falls back as described in the module docstring and appends to *errors*."""
    if raw is None:
        return copy.deepcopy(default)
    if isinstance(default, bool):
        return _coerce_flag(name, raw, default, errors)
    if isinstance(default, int):
        return _coerce_int(name, raw, default, errors)
    if isinstance(default, list):
        return _coerce_sinks(raw, errors)
    if name == "write_mode":
        text = raw.strip().lower() if isinstance(raw, str) else None
        if text in WRITE_MODES:
            return text
        return _reject(name, f"one of {', '.join(WRITE_MODES)}", _shown(raw), _FAIL_CLOSED[name], errors)
    if not isinstance(raw, str):
        return _reject(name, "text", _shown(raw), default, errors)
    text = raw.strip()  # paths keep their case
    if name == "audit_log_path" and text and not os.path.isabs(os.path.expanduser(text)):
        # a relative path would land in whatever directory each process (gateway, cron, CLI) was started from; the
        # path itself is not quoted, since it names the OS account and status shows errors to the model
        return _reject(name, "an absolute path (~ is expanded)", "a relative path", default, errors)
    return text


def flag(raw: Any) -> bool | None:
    """*raw* as true or false: a bool, the ints 0 and 1, or true/false, yes/no, on/off, 1/0 as text in any case.
    ``None`` for anything else; ``bool()`` would read ``["false"]`` as true."""
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, int) and raw in (0, 1):
        return raw == 1
    text = raw.strip().lower() if isinstance(raw, str) else None
    if text in _TRUE or text in _FALSE:
        return text in _TRUE
    return None


def _coerce_flag(name: str, raw: Any, default: bool, errors: List[str]) -> bool:
    value = flag(raw)
    if value is not None:
        return value
    return _reject(name, "true or false", _shown(raw), _fallback(name, default), errors)


def _coerce_int(name: str, raw: Any, default: int, errors: List[str]) -> int:
    """A whole number from an int or a string of ASCII digits. ``int()`` alone would truncate ``0.5`` to 0 (keep
    plans forever) and read ``True`` as 1."""
    value: int | None = None
    if isinstance(raw, int) and not isinstance(raw, bool):
        value = raw
    elif isinstance(raw, str) and raw.strip().isascii() and raw.strip().isdigit():
        with contextlib.suppress(ValueError):  # more digits than int() converts: the default is the safe answer
            value = int(raw.strip())
    least = 0 if name in _ZERO_ALLOWED else 1
    if value is None or value < least:
        return _reject(name, f"a whole number of {least} or more", _shown(raw), default, errors)
    limit = LIMITS.get(name)
    if limit is not None and value > limit:
        return _reject(name, f"at most {limit}", _shown(raw), limit, errors)
    return value


def _coerce_sinks(raw: Any, errors: List[str]) -> List[Dict[str, Any]]:
    """``audit_sinks`` as a list of mappings, deep-copied so later edits never reach Hermes' cached config. Errors
    name only types and positions: a sink's url or headers can hold a credential."""
    if not isinstance(raw, list):
        return _reject("audit_sinks", "a list", type(raw).__name__, [], errors)
    sinks: List[Dict[str, Any]] = []
    for index, spec in enumerate(raw):
        if isinstance(spec, dict):
            sinks.append(copy.deepcopy(spec))
        else:
            errors.append(f"audit_sinks[{index}]: expected a mapping; entry ignored")
    return sinks


def _reject(name: str, expected: str, shown: str, value: Any, errors: List[str]) -> Any:
    errors.append(f"{name}: expected {expected}, got {shown}; using {_text(value)}")
    return value


def _fallback(name: str, default: Any) -> Any:
    return _FAIL_CLOSED.get(name, copy.deepcopy(default))


def _shown(raw: Any) -> str:
    """A bad value as an error may quote it: a short scalar as written, anything else by its type only (a
    mapping or a long string may hold a credential)."""
    if isinstance(raw, (str, int, float)) and "\n" not in str(raw) and len(repr(raw)) <= _SHOWN_CHARS:
        return repr(raw)
    return type(raw).__name__


def _text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str) and not value:
        return "''"
    return str(value)


def _sink_type(spec: Dict[str, Any]) -> str:
    kind = spec.get("type")
    if isinstance(kind, str) and kind.strip() and len(kind) <= _SHOWN_CHARS and kind.strip().isprintable():
        return kind.strip().lower()
    return "unknown"


_current = Settings()
_ctx: Any | None = None
_pinned = False


def set_context(ctx: Any | None) -> None:
    """Remember the plugin context (``register``) so :func:`get_settings` reads config.yaml live; ``None``
    forgets it."""
    global _ctx
    _ctx = ctx


def get_settings() -> Settings:
    """The settings in force: read from the context on every call unless pinned (Hermes caches config.yaml by
    mtime, so this is cheap and picks up edits without a restart), else the last good read."""
    global _current
    ctx = _ctx
    if ctx is None or _pinned:
        return _current
    try:
        settings = Settings.from_ctx(ctx)
    except Exception:
        return _current
    _current = settings
    return settings


def set_settings(settings: Settings | None) -> None:
    """Test seam: pin *settings* so they win over the context; ``None`` unpins and restores the defaults."""
    global _current, _pinned
    _pinned = settings is not None
    _current = settings if settings is not None else Settings()
