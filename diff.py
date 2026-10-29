"""Field values as the plugin compares, records and shows them.

LibreNMS hands the same value back in several shapes: booleans as ``0``/``1``, ``"0"``/``"1"`` or JSON
``true``; ids as numbers or digit strings; coordinates as floats or decimal strings; JSON columns (alert-rule
builders, group rules) as objects or as strings. The model writes them in yet other shapes. :func:`normalise`
maps every accepted shape of a value onto one canonical form per :class:`~.resources.base.Field` kind, so a
plan never shows a change that is only a change of spelling, and never sends ``"false"`` where LibreNMS
expects ``false``.

Rendering follows one rule for sensitive fields (service ``param``): a value the operation supplies is shown
verbatim, because the person approving the plan must see what will be sent; a value read from LibreNMS is
shown only as a digest (:func:`redacted`), because it may be a secret nobody in the conversation has seen.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import math
import re
from typing import TYPE_CHECKING, Any, Dict, List

from .redact import one_line

if TYPE_CHECKING:
    from .resources.base import Field

KINDS = ("str", "text", "int", "bool", "float", "list_int", "json", "enum", "env")

_DIGITS = re.compile(r"[0-9]+")
_TRUE = frozenset({"1", "true", "yes"})
_FALSE = frozenset({"0", "false", "no"})
_SHOWN_CHARS = 40


def env_name(value: Any) -> str | None:
    """The variable name of an environment reference ``{"env": "NAME"}``, else None."""
    if isinstance(value, dict) and len(value) == 1 and isinstance(value.get("env"), str) and value["env"]:
        return value["env"]
    return None


def _got(value: Any) -> str:
    """The rejected value itself when it is a short scalar, else only its type (it may be long or secret)."""
    if isinstance(value, (bool, int, float)) or (
        isinstance(value, str) and len(value) <= _SHOWN_CHARS and value.isprintable()
    ):
        return json.dumps(value, ensure_ascii=False)
    return type(value).__name__


def _expected(field: Field) -> str:
    if field.kind == "enum":
        return "one of " + ", ".join(field.choices)
    return {
        "str": "a string",
        "text": "a string",
        "int": "an integer",
        "bool": "true or false",
        "float": "a number",
        "list_int": "a list of integers",
        "json": "a JSON object or array",
        "env": '{"env": "<VARIABLE NAME>"}',
    }.get(field.kind, field.kind)


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and _DIGITS.fullmatch(value.strip()):
        return int(value.strip())
    return None


def _convert(kind: str, value: Any, choices: tuple) -> Any:
    """The canonical form of *value*, or ``ValueError`` (message filled in by :func:`normalise`)."""
    if kind in ("str", "text"):
        if isinstance(value, str):
            return value
    elif kind == "int":
        number = _int(value)
        if number is not None:
            return number
    elif kind == "bool":
        if isinstance(value, bool):
            return value
        if isinstance(value, int) and value in (0, 1):
            return bool(value)
        if isinstance(value, str) and value.strip().lower() in _TRUE | _FALSE:
            return value.strip().lower() in _TRUE
    elif kind == "float":
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            number = float(value)
        elif isinstance(value, str):
            try:
                number = float(value.strip())
            except ValueError:
                number = math.nan
        else:
            number = math.nan
        if math.isfinite(number):
            return round(number, 8)
    elif kind == "list_int":
        if isinstance(value, list):
            items = [_int(item) for item in value]
            if None not in items:
                return sorted(set(items))
    elif kind == "json":
        parsed = value
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
            except ValueError:
                parsed = None
        if isinstance(parsed, (dict, list)):
            try:
                return json.loads(json.dumps(parsed, sort_keys=True))
            except (TypeError, ValueError):
                pass
    elif kind == "enum":
        if isinstance(value, str) and value in choices:
            return value
    elif kind == "env":
        name = env_name(value)
        if name is not None:
            return {"env": name}
    raise ValueError(kind)


def normalise(field: Field, value: Any) -> Any:
    """*value* in the canonical form of *field*'s kind; ``ValueError`` naming the field when it has none.

    ``None`` stands for "not set" and passes through (``text`` maps it to ``""``): LibreNMS reports null columns,
    and :meth:`Resource.validate <.resources.base.Resource.validate>` decides where an operation may send null.
    """
    if value is None:
        return "" if field.kind == "text" else None
    try:
        return _convert(field.kind, value, field.choices)
    except ValueError:
        raise ValueError(f"{field.name}: expected {_expected(field)}, got {_got(value)}") from None


def values_equal(field: Field, a: Any, b: Any) -> bool:
    """Equality after normalising both sides; a side that cannot be normalised is compared as it is."""
    try:
        return normalise(field, a) == normalise(field, b)
    except ValueError:
        return a == b


def compute_changes(desired: Dict[str, Any], current_state: Dict[str, Any], fields: Dict[str, Field]) -> Dict[str, Any]:
    """``{name: {"from": <current>, "to": <desired>}}`` (both normalised) for every desired value that differs.

    A key missing from *current_state* counts as null. Keys without a :class:`Field` are compared as they are.
    """
    changes: Dict[str, Dict[str, Any]] = {}
    for name, want in desired.items():
        have = current_state.get(name)
        field = fields.get(name)
        if field is not None:
            want = normalise(field, want)
            with contextlib.suppress(ValueError):  # LibreNMS's spelling is kept when it has no canonical form
                have = normalise(field, have)
        if want != have:
            changes[name] = {"from": have, "to": want}
    return changes


def format_value(value: Any, limit: int = 60) -> str:
    """Compact single-line rendering: strings quoted, ``null``, ``true``/``false``, JSON for objects and lists,
    ``$NAME`` for environment references. Escapes keep control characters visible and every value on one line
    (:func:`.redact.one_line`): a value from LibreNMS or the model must not forge a line of the plan."""
    name = env_name(value)
    if name is not None:
        text = f"${name}"
    elif value is None:
        text = "null"
    elif isinstance(value, bool):
        text = "true" if value else "false"
    elif isinstance(value, (int, float)):
        text = str(value)
    else:
        text = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    text = one_line(text)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def redacted(value: Any) -> str:
    """``<redacted sha256:<8 hex>>``: enough to see that a secret changed, not enough to recover it. An empty
    value hides nothing and is shown as it is."""
    if value is None or value == "":
        return format_value(value)
    text = value if isinstance(value, str) else json.dumps(value, sort_keys=True, default=str)
    return f"<redacted sha256:{hashlib.sha256(text.encode('utf-8', 'surrogatepass')).hexdigest()[:8]}>"


def format_live(field: Field | None, value: Any, limit: int = 60) -> str:
    """Render a value read from LibreNMS: a digest for sensitive fields, else :func:`format_value`."""
    if field is not None and field.sensitive:
        return redacted(value)
    return format_value(value, limit)


def render_changes(changes: Dict[str, Dict[str, Any]], fields: Dict[str, Field]) -> List[str]:
    """``name: <from>[ (from_label)] -> <to>[ (to_label)]`` per change, sorted by name. ``from`` came from LibreNMS
    (digest when sensitive); ``to`` came from the operation (verbatim). Labels are names read from LibreNMS, kept on
    the line like every value."""
    lines = []
    for name, change in sorted(changes.items()):
        old = format_live(fields.get(name), change.get("from"))
        new = format_value(change.get("to"))
        if change.get("from_label"):
            old += f" ({one_line(change['from_label'])})"
        if change.get("to_label"):
            new += f" ({one_line(change['to_label'])})"
        lines.append(f"{name}: {old} -> {new}")
    return lines
