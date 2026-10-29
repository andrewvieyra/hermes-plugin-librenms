"""What ``librenms_query`` does to the rows LibreNMS returned before it pages them: keep those that pass a small typed
filter (``where``) and put them in order by one key (``sort``). The handler then shows ``limit`` of them from
``offset`` on.

LibreNMS filters, orders and pages its listings only in part: only the logs routes page (``start``), ``ports`` has no
filter and no order, ``faults`` has no device filter, and ports, sensors, links and FDB entries come in no defined
order. Those routes send every row anyway, so the tool can answer "the ten busiest ports" or "the open alerts on
device 12" from all of them instead of the first ``max_query_results``. There are no expressions: a condition is one
top-level key, one operator and one value, and a row is kept when every condition holds.

Values compare the way a person reads them, by kind:

- empty: a missing key, ``null`` or ``""``. ``eq`` with ``null`` or ``""`` matches one; ``contains``, ``gt`` and
  ``lt`` never do; a sort puts them last in either order.
- number: a JSON number, ``true``/``false`` as 1/0, or text that is a number as a database writes one (``"12"``,
  ``"-0.5"``, ``"2e3"``; not ``"007"``, ``"1.2.3"`` or ``"1e99999"``, whose exponent has more than four digits,
  which are text; ``gt`` and ``lt`` refuse a value of that last kind). Compared by value, exactly. A MAC of digits
  only (``"123456789012"``) is one too, and sorts before the MACs with letters.
- text: equal ignoring case; in natural order ignoring case, a run of digits by its value (``Gi1/0/2`` before
  ``Gi1/0/10``, ``10.0.0.2`` before ``10.0.0.10``; ``Y-m-d H:i:s`` times in time order).
- other (an object or a list): matches ``ne`` only, and sorts after text in the order read, so the order says nothing
  about what it holds (a fault's ``details`` holds the alert's contacts).

``gt`` and ``lt`` compare a number and a text as two texts in natural order when both start with a digit, as versions
do (``"15.2(4)E"`` is ``lt`` 16 and ``"16.12.4"`` is not), and never hold between a number and other text (``"N/A"``,
``Gi1/0/1``). Numbers sort before text in either order, and rows that compare equal keep LibreNMS's order (the sort
is stable). A credential key compares as the result shows it, :data:`redact.MASK` when set (:func:`redact.mask`), so
neither a filter nor an order tells anything about a secret the result masks.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Dict, List, Tuple

from .redact import SECRET_KEYS, clip, mask, one_line

OPERATORS = ("eq", "ne", "contains", "gt", "lt")
MAX_CONDITIONS = 10
VALUE_CHARS = 200  # the longest text a condition compares with
KEY_CHARS = 100
_KEYS_SHOWN = 40  # keys an unknown-key refusal lists
_KEYS_FROM = 100  # rows it takes them from

_NUMBER, _TEXT, _OTHER, _EMPTY = range(4)  # kinds, in the order a sort puts them
# A number as a database writes one: a minus at most, no leading zeros, no blanks, an exponent of at most four digits
# (a double's is at most 308; Decimal() raises on one past about 10**18). A longer text is not one.
_NUMBER_RE = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][-+]?[0-9]{1,4})?")
_PAST_RE = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?[eE][-+]?[0-9]{5,}")  # one with a longer exponent
_NUMBER_CHARS = 100
_DIGITS_RE = re.compile(r"([0-9]+)")


class ListingError(ValueError):
    """A ``where`` or ``sort`` the tool cannot apply; the message says why and is shown to the model."""


class UnknownKey(ListingError):
    """A ``where`` or ``sort`` key that no row has. *alike* is a key the rows have that differs from it in case only,
    which the message suggests, else None."""

    def __init__(self, message: str, alike: str | None = None) -> None:
        super().__init__(message)
        self.alike = alike


@dataclass(frozen=True)
class Condition:
    """One ``where`` condition, its value in the form it is compared in (:func:`_classify`)."""

    key: str
    op: str
    kind: int
    value: Any
    needle: str = ""  # contains: the text to look for, case-folded
    digits_first: Tuple[Any, ...] | None = None  # gt, lt: the value as a text compares, when it starts with a digit


@dataclass(frozen=True)
class Order:
    """A ``sort``: one top-level key, ascending unless *descending*."""

    key: str
    descending: bool = False


def conditions(where: Any) -> List[Condition]:
    """The ``where`` argument as conditions, checked: a list of at most :data:`MAX_CONDITIONS` objects, each a
    top-level ``key``, an ``op`` of :data:`OPERATORS` and a ``value`` that op takes. None and ``[]`` are none."""
    if where is None:
        return []
    if not isinstance(where, list):
        raise ListingError(
            'where must be a list of conditions, e.g. [{"key": "ifOperStatus", "op": "eq", "value": "down"}]'
        )
    if len(where) > MAX_CONDITIONS:
        raise ListingError(f"where takes at most {MAX_CONDITIONS} conditions (got {len(where)})")
    return [_condition(f"where[{index}]", item) for index, item in enumerate(where)]


def _condition(what: str, item: Any) -> Condition:
    if not isinstance(item, dict):
        raise ListingError(f"{what} must be an object with key, op and value")
    _only(what, item, ("key", "op", "value"))
    key = _key(what, item.get("key"))
    op = item.get("op")
    if not isinstance(op, str) or op.strip().lower() not in OPERATORS:
        raise ListingError(f"{what}.op must be one of {', '.join(OPERATORS)} (got {_shown(op)})")
    op = op.strip().lower()
    if "value" not in item:
        raise ListingError(f'{what} needs a value (eq with null or "" matches an empty one)')
    value = item["value"]
    if not isinstance(value, (str, int, float, type(None))) or (isinstance(value, float) and not math.isfinite(value)):
        raise ListingError(f"{what}.value must be text, a number, true, false or null")
    if isinstance(value, str) and len(value) > VALUE_CHARS:
        raise ListingError(f"{what}.value is {len(value)} characters; at most {VALUE_CHARS} are compared")
    kind, comparable = _classify(value)
    if op == "contains":
        if isinstance(value, bool) or kind == _EMPTY:
            raise ListingError(f"{what}: contains looks for text (or a number) in a value; give it some")
        return Condition(key, op, kind, comparable, _text(value).casefold())
    if op not in ("gt", "lt"):
        return Condition(key, op, kind, comparable)
    if isinstance(value, bool) or kind == _EMPTY:
        raise ListingError(f"{what}: {op} compares with a number or a text; give it one")
    if isinstance(value, str) and _PAST_RE.fullmatch(value):  # as text it would compare digit run by digit run
        raise ListingError(f"{what}: {op} compares with a number whose exponent has at most four digits")
    text = _text(value)
    return Condition(key, op, kind, comparable, digits_first=_natural(text)[:2] if _DIGITS_RE.match(text) else None)


def order(sort: Any) -> Order | None:
    """The ``sort`` argument, checked: ``{"key": ..., "order": "asc" | "desc"}``, ascending by default. None is
    none."""
    if sort is None:
        return None
    if not isinstance(sort, dict):
        raise ListingError('sort must be an object, e.g. {"key": "ifInOctets_rate", "order": "desc"}')
    _only("sort", sort, ("key", "order"))
    key = _key("sort", sort.get("key"))
    direction = sort.get("order")
    if direction is None:
        return Order(key)
    if not isinstance(direction, str) or direction.strip().lower() not in ("asc", "desc"):
        raise ListingError(f"sort.order must be asc or desc (got {_shown(direction)})")
    return Order(key, direction.strip().lower() == "desc")


def _only(what: str, item: Dict[Any, Any], names: Tuple[str, ...]) -> None:
    unknown = [str(name) for name in item if name not in names]
    if unknown:
        listed = ", ".join(_shown(name) for name in unknown[:5])
        raise ListingError(f"{what} takes {', '.join(names)}, not {listed}")


def _key(what: str, key: Any) -> str:
    if not isinstance(key, str) or not key.strip():
        raise ListingError(f"{what}.key must name a key of the rows, e.g. ifName")
    if len(key) > KEY_CHARS:
        raise ListingError(f"{what}.key is {len(key)} characters; no key of a LibreNMS row is that long")
    return key.strip()


def _shown(value: Any) -> str:
    """*value*, from the model, quoted in a refusal: one line, clipped."""
    return repr(clip(one_line(value), 40)) if isinstance(value, str) else clip(one_line(repr(value)), 40)


def select(rows: List[Any], where: List[Condition], sort: Order | None) -> List[Any]:
    """The *rows* that pass every condition of *where*, in the order of *sort* when there is one (stable). A key that
    no row has is refused (:class:`UnknownKey`): a misspelt one would keep no row, or leave the order as read, and
    look like an answer."""
    for key in dict.fromkeys([condition.key for condition in where] + ([sort.key] if sort else [])):
        if rows and not any(isinstance(row, dict) and key in row for row in rows):
            raise _unknown(key, rows)
    kept = [row for row in rows if all(_holds(condition, row) for condition in where)] if where else list(rows)
    return _sorted(kept, sort) if sort else kept


def _unknown(key: str, rows: List[Any]) -> UnknownKey:
    seen: Dict[str, None] = {}
    for row in rows[:_KEYS_FROM]:
        if isinstance(row, dict):
            seen.update(dict.fromkeys(str(name) for name in row))
    names = list(seen)
    alike = [name for name in names if name.lower() == key.lower()]
    message = f"no row has the key {_shown(key)} (keys match as written)"
    if alike:
        return UnknownKey(f"{message}; did you mean {_shown(alike[0])}?", alike[0])
    listed = ", ".join(clip(one_line(name), 60) for name in names[:_KEYS_SHOWN])
    more = f" and {len(names) - _KEYS_SHOWN} more" if len(names) > _KEYS_SHOWN else ""
    return UnknownKey(f"{message}; the rows have {listed}{more}" if names else f"{message}; the rows are not objects")


def _field(row: Any, key: str) -> Any:
    """*row*'s value under *key* as the result shows it: a credential key's value masked when set."""
    if not isinstance(row, dict):
        return None
    value = row.get(key)
    return mask({key: value})[key] if key.lower() in SECRET_KEYS else value


def _classify(value: Any) -> Tuple[int, Any]:
    """*value*'s kind and the form it compares in: an int or a Decimal for a number (a float by its shortest text, so
    0.1 equals "0.1"), the natural key for a text (:func:`_natural`), None for the other kinds."""
    if value is None or value == "":
        return _EMPTY, None
    if isinstance(value, bool):
        return _NUMBER, int(value)
    if isinstance(value, int):
        return _NUMBER, value
    if isinstance(value, float):
        return (_EMPTY, None) if math.isnan(value) else (_NUMBER, Decimal(repr(value)))
    if isinstance(value, str):
        if len(value) <= _NUMBER_CHARS and _NUMBER_RE.fullmatch(value):
            return _NUMBER, Decimal(value)
        return _TEXT, _natural(value)
    return _OTHER, None


def _natural(text: str) -> Tuple[Tuple[Any, ...], str, str]:
    """The key a text sorts by: its case-folded runs of digits and of the rest, each run of digits as its length and
    digits without leading zeros (its value, without reading a number of any length), then the case-folded and the
    original text to break ties. Runs alternate from a text one (``re.split``), so two keys compare run by run."""
    folded = text.casefold()
    runs: List[Any] = _DIGITS_RE.split(folded)
    for index in range(1, len(runs), 2):
        digits = runs[index].lstrip("0")
        runs[index] = (len(digits), digits)
    return tuple(runs), folded, text


def natural_key(text: Any) -> Tuple[Tuple[Any, ...], str, str]:
    """The key *text* sorts by in natural order, ignoring case (``Gi1/0/2`` before ``Gi1/0/10``), as ``sort`` orders
    text; None and other values read as ``""``. For the report views' own orders."""
    return _natural(text if isinstance(text, str) else "")


def _text(value: Any) -> str:
    """A value as a ``contains`` reads it: a text as it is, a number as JSON writes it; "" for the other kinds."""
    if isinstance(value, str):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, float) and math.isfinite(value):
        return repr(value)
    return ""


def _holds(condition: Condition, row: Any) -> bool:
    raw = _field(row, condition.key)
    if condition.op == "contains":
        return condition.needle in _text(raw).casefold()
    kind, value = _classify(raw)
    if condition.op in ("eq", "ne"):
        same = kind == condition.kind and kind != _OTHER and _equal(kind, value, condition.value)
        return same if condition.op == "eq" else not same
    if kind == condition.kind == _NUMBER:
        wanted = condition.value
    elif kind == condition.kind == _TEXT:  # ignoring case, as eq does
        value, wanted = value[:2], condition.value[:2]
    elif kind in (_NUMBER, _TEXT) and condition.digits_first and _DIGITS_RE.match(_text(raw)):
        # a number and a text that both start with a digit: two texts, so a version "15.2(4)E" is lt 16
        value, wanted = _natural(_text(raw))[:2], condition.digits_first
    else:  # a number and other text, an object or a list, or an empty value
        return False
    return value > wanted if condition.op == "gt" else value < wanted


def _equal(kind: int, value: Any, wanted: Any) -> bool:
    if kind == _EMPTY:
        return True
    if kind == _TEXT:
        return value[1] == wanted[1]
    return value == wanted


def _sorted(rows: List[Any], sort: Order) -> List[Any]:
    """*rows* by *sort*'s key: numbers, then texts, each in *sort*'s direction, then other values and then empty ones
    as read. Python's sort is stable also in reverse, so equal values keep LibreNMS's order."""
    kinds: Tuple[List[Tuple[Any, Any]], ...] = ([], [], [], [])
    for row in rows:
        kind, value = _classify(_field(row, sort.key))
        kinds[kind].append((value, row))
    for kind in (_NUMBER, _TEXT):
        kinds[kind].sort(key=lambda pair: pair[0], reverse=sort.descending)
    return [row for pairs in kinds for _value, row in pairs]
