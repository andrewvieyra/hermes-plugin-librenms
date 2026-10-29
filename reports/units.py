"""Units for report rows: the number a question needs, under a key that names its unit (``speed_bps``, ``uptime_s``),
and beside it the same value as a person writes it (``speed`` "10G", ``uptime`` "3d 4h").

Network rates and speeds use decimal prefixes (1 kbit/s is 1,000 bit/s), as LibreNMS and interface speeds do.
LibreNMS stamps times two ways: the device API in ISO-8601 UTC (``2026-10-28T11:55:02.000000Z``) and unix seconds
(outages, port poll times), which are exact anywhere; the fault, alert-log, eventlog and syslog tables as the
server's local ``Y-m-d H:i:s`` with no zone, which no API v0 field names (``system``'s ``local_date`` is the date of
the LibreNMS commit). :func:`server_time` reads those in the operator's ``librenms_timezone`` and gives no time at
all without one.
"""

from __future__ import annotations

import math
import re
from datetime import datetime, timedelta, timezone, tzinfo
from typing import Any

_PREFIXES = (("T", 1e12), ("G", 1e9), ("M", 1e6), ("k", 1e3))
_SPEED_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([kmgt]?)(?:bit/s|bps|b)?\s*$", re.IGNORECASE)
_DURATION_RE = re.compile(r"^\s*(\d{1,6})\s*([smhdw])\s*$", re.IGNORECASE)
_DURATION_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
_SERVER_RE = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")
# Most seconds a duration argument may name (a year), and most a duration may show as a value (a century).
MAX_DURATION_S = 366 * 86400
PLAUSIBLE_S = 100 * 366 * 86400


def _number(value: Any) -> float | None:
    """*value* as a finite number: an int, a float, or text that reads as one; None for anything else."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        number = float(value)
    elif isinstance(value, str):
        try:
            number = float(value.strip())
        except ValueError:
            return None
    else:
        return None
    return number if math.isfinite(number) else None


def _scaled(value: float, unit: str, *, compact: bool = False) -> str:
    """*value* to three significant digits with the largest decimal prefix that keeps it at 1 or more (999.6 is
    rounded first, so it reads 1 k, not 1000)."""
    rounded = float(f"{value:.3g}")
    prefix, shown = "", rounded
    for name, size in _PREFIXES:
        if abs(rounded) >= size:
            prefix, shown = name, rounded / size
            break
    text = f"{shown:.3g}"
    if "e" in text:  # past 999 T only
        text = f"{shown:.0f}"
    return f"{text}{prefix}{unit}" if compact else f"{text} {prefix}{unit}"


def bits_per_second(value: Any) -> str | None:
    """``812 Mbit/s`` for 812000000; None when *value* is not a number."""
    number = _number(value)
    return None if number is None else _scaled(number, "bit/s")


def speed(value: Any) -> str | None:
    """An interface speed as it is written on the box: ``10G``, ``100M``, ``2.5G``; None for 0 or no number (LibreNMS
    stores 0 for a speed it does not know)."""
    number = _number(value)
    if not number or number < 0:
        return None
    return _scaled(number, "", compact=True)


def parse_speed(text: Any) -> int | None:
    """``10G``, ``100M``, ``2.5 Gbit/s``, ``1000000`` as bit/s; None when *text* is not a speed."""
    if isinstance(text, (int, float)) and not isinstance(text, bool):
        return int(text) if math.isfinite(text) and text >= 0 else None
    found = _SPEED_RE.match(text) if isinstance(text, str) else None
    if found is None:
        return None
    size = {"": 1, "k": 1e3, "m": 1e6, "g": 1e9, "t": 1e12}[found.group(2).lower()]
    return int(float(found.group(1)) * size)


def percent(part: Any, whole: Any) -> float | None:
    """*part* of *whole* in percent, one decimal; None when either is not a number or *whole* is 0 or less."""
    numerator, denominator = _number(part), _number(whole)
    if numerator is None or denominator is None or denominator <= 0:
        return None
    return round(numerator * 100 / denominator, 1)


def duration(seconds: Any) -> str | None:
    """``3d 4h``, ``2h 5m``, ``4m 58s``, ``12s``: the two largest units, rounded down; None for no number, a negative
    one, or one past a century (a counter that wrapped or was never set)."""
    number = _number(seconds)
    if number is None or number < 0 or number > PLAUSIBLE_S:
        return None
    total = int(number)
    days, rest = divmod(total, 86400)
    hours, rest = divmod(rest, 3600)
    minutes, secs = divmod(rest, 60)
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def parse_duration(text: Any) -> int | None:
    """A duration argument as seconds: ``30m``, ``24h``, ``7d``, ``2w`` (or ``90s``), at least a second and at most
    :data:`MAX_DURATION_S`; None for anything else."""
    found = _DURATION_RE.match(text) if isinstance(text, str) else None
    if found is None:
        return None
    seconds = int(found.group(1)) * _DURATION_UNITS[found.group(2).lower()]
    return seconds if 0 < seconds <= MAX_DURATION_S else None


def iso(moment: datetime | None) -> str | None:
    """ISO-8601 to the second: ``2026-10-28T11:55:02Z`` for UTC, with its offset for another zone."""
    if moment is None:
        return None
    if moment.utcoffset() == timedelta(0):
        return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return moment.isoformat(timespec="seconds")


def utc_time(value: Any) -> datetime | None:
    """A zone-safe LibreNMS time as an aware datetime: ISO-8601 with ``Z`` or an offset (the device API), or unix
    seconds (outages, poll times; 0 is none). A text without a zone is server-local: see :func:`server_time`."""
    if isinstance(value, str) and value.strip():
        text = value.strip()
        if text.isdigit():
            value = int(text)
        else:
            try:
                parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            except ValueError:
                return None
            return parsed if parsed.tzinfo is not None else None
    number = _number(value)
    if number is None or number <= 0 or number > 4102444800:  # 2100-01-01
        return None
    return datetime.fromtimestamp(number, tz=timezone.utc)


def server_time(value: Any, zone: tzinfo | None) -> datetime | None:
    """A server-local ``Y-m-d H:i:s`` from LibreNMS as an aware datetime in *zone* (``librenms_timezone``); None
    without a zone, which nothing in the API names, or for any other text. A zone-safe value is read as
    :func:`utc_time` reads it."""
    if isinstance(value, str) and _SERVER_RE.match(value.strip()):
        if zone is None:
            return None
        try:
            return datetime.strptime(value.strip(), "%Y-%m-%d %H:%M:%S").replace(tzinfo=zone)
        except ValueError:
            return None
    return utc_time(value)


def age(moment: datetime | None, now: datetime) -> int | None:
    """Whole seconds from *moment* to *now*; None without a moment. A moment after *now* (clocks apart) is 0."""
    if moment is None:
        return None
    return max(0, int((now - moment).total_seconds()))
