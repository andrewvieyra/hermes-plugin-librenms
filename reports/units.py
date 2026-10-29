"""Units for report rows: the number a question needs, under a key that names its unit (``speed_bps``, ``uptime_s``),
and beside it the same value as a person writes it (``speed`` "10G", ``uptime`` "3d 4h").

Network rates and speeds use decimal prefixes (1 kbit/s is 1,000 bit/s), as LibreNMS and interface speeds do. What a
port row holds, and what it means: ``ifInOctets_rate`` and ``ifOutOctets_rate`` are bytes per second averaged over the
last poll (``poll_period``, about 300 s), so eight times that is the bit rate; ``ifSpeed`` is bit/s (``ifHighSpeed``,
which older LibreNMS releases also kept, is Mbit/s); ``port_descr_speed`` is the circuit speed parsed from the port's
description, ``egress/ingress`` when it differs by direction (:func:`circuit_speeds`); ``ifLastChange`` is the
device's sysUpTime, in hundredths of a second, when the port last went up or down. A sensor's ``sensor_current`` and
its four limits are in the unit of its class (:data:`SENSOR_UNITS`: °C, dBm, V, ...); memory and storage sizes are
bytes, shown with binary prefixes (:func:`size`); bytes a bill counts, with decimal ones as LibreNMS's billing shows
them (:func:`volume`).

LibreNMS stamps times two ways: the device API in ISO-8601 UTC (``2026-10-28T11:55:02.000000Z``) and unix seconds
(outages, port poll times), which are exact anywhere; the fault, alert-log, eventlog, syslog, authlog and bills tables
as the server's local ``Y-m-d H:i:s`` with no zone, which no API v0 field names (``system``'s ``local_date`` is the
date of the LibreNMS commit). :func:`server_time` reads those in the operator's ``librenms_timezone`` and gives no
time at all without one; :func:`server_order` orders them either way.
"""

from __future__ import annotations

import math
import re
from datetime import datetime, timedelta, timezone, tzinfo
from typing import Any, Tuple

_PREFIXES = (("T", 1e12), ("G", 1e9), ("M", 1e6), ("k", 1e3))
_SPEED_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([kmgt]?)(?:bit/s|bps|b)?\s*$", re.IGNORECASE)
_DURATION_RE = re.compile(r"^\s*(\d{1,6})\s*([smhdw])\s*$", re.IGNORECASE)
_DURATION_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
_SERVER_RE = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")
_ORDER_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})")
# LibreNMS's Number::toBytes: a number, an SI prefix and any unit after it, whose first letter "i" means powers of 1024
_CIRCUIT_RE = re.compile(r"^([\d.]+)([KMGTPEZY]?)(\w?)\w*$", re.IGNORECASE | re.ASCII)
_SI_POWERS = {"": 0, "K": 1, "M": 2, "G": 3, "T": 4, "P": 5, "E": 6, "Z": 7, "Y": 8}
# Most seconds a duration argument may name (a year), and most a duration may show as a value (a century).
MAX_DURATION_S = 366 * 86400
PLAUSIBLE_S = 100 * 366 * 86400
_IEC = (("TiB", 2**40), ("GiB", 2**30), ("MiB", 2**20), ("KiB", 2**10))
# The unit of each of LibreNMS's sensor classes (its sensors translations), as it stores the reading: temperature in
# degrees Celsius whatever a user's display preference, runtime in minutes, power_consumed in kWh; "" for a ratio or
# a count, and none for a class LibreNMS has added since.
SENSOR_UNITS = {
    "airflow": "cfm", "ber": "", "bitrate": "bit/s", "charge": "%", "chromatic_dispersion": "ps/nm", "cooling": "W",
    "count": "", "current": "A", "dbm": "dBm", "delay": "s", "eer": "", "fanspeed": "RPM", "frequency": "Hz",
    "humidity": "%", "load": "%", "loss": "%", "percent": "%", "power": "W", "power_consumed": "kWh",
    "power_factor": "", "pressure": "kPa", "quality_factor": "dB", "runtime": "min", "signal": "dBm",
    "signal_loss": "dB", "snr": "dB", "state": "", "temperature": "°C", "tv_signal": "dBmV", "voltage": "V",
    "waterflow": "l/min",
}  # fmt: skip
_SI_CLASSES = frozenset({"current", "power", "frequency", "bitrate"})  # shown with a prefix, as LibreNMS does


def number(value: Any) -> float | None:
    """*value* as a finite number: an int, a float, or text that reads as one (LibreNMS writes some counters as
    text); None for anything else."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        found = float(value)
    elif isinstance(value, str):
        try:
            found = float(value.strip())
        except ValueError:
            return None
    else:
        return None
    return found if math.isfinite(found) else None


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
    found = number(value)
    return None if found is None else _scaled(found, "bit/s")


def speed(value: Any) -> str | None:
    """An interface speed as it is written on the box: ``10G``, ``100M``, ``2.5G``; None for 0 or no number (LibreNMS
    stores 0 for a speed it does not know)."""
    found = number(value)
    if not found or found < 0:
        return None
    return _scaled(found, "", compact=True)


def sensor_reading(value: Any, sensor_class: Any) -> str | None:
    """A sensor's reading as LibreNMS shows it: ``41 °C``, ``-3.2 dBm``, ``2.4 kW`` (current, power, frequency and
    bit rates with a prefix), ``1h 30m`` for a runtime (minutes); a state or a class without a unit as the bare
    number. None when *value* is not a number."""
    found = number(value)
    if found is None:
        return None
    unit = SENSOR_UNITS.get(sensor_class, "") if isinstance(sensor_class, str) else ""
    if sensor_class == "runtime":
        return duration(found * 60)
    if sensor_class in _SI_CLASSES and abs(found) >= 1000:
        return _scaled(found, unit)
    text = f"{round(found, 3):g}" if abs(found) < 1e6 else f"{found:.0f}"
    return f"{text} {unit}" if unit else text


def size(value: Any) -> str | None:
    """A size in bytes with a binary prefix, as LibreNMS shows memory and storage: ``7.45 GiB``; None for no number
    or a negative one."""
    found = number(value)
    if found is None or found < 0:
        return None
    for name, factor in _IEC:
        if found >= factor:
            shown = found / factor
            return f"{shown:.3g} {name}" if shown < 1000 else f"{shown:.0f} {name}"  # 1023.9 MiB, never 1.02e+03
    return f"{found:.0f} B"


def volume(value: Any) -> str | None:
    """Bytes transferred with a decimal prefix, as LibreNMS's billing shows them (its default ``billing.base``,
    1000): ``300 TB``; None for no number or a negative one."""
    found = number(value)
    return None if found is None or found < 0 else _scaled(found, "B")


def parse_speed(text: Any) -> int | None:
    """``10G``, ``100M``, ``2.5 Gbit/s``, ``1000000`` as bit/s; None when *text* is not a speed."""
    if isinstance(text, (int, float)) and not isinstance(text, bool):
        return int(text) if math.isfinite(text) and text >= 0 else None
    found = _SPEED_RE.match(text) if isinstance(text, str) else None
    if found is None:
        return None
    size = {"": 1, "k": 1e3, "m": 1e6, "g": 1e9, "t": 1e12}[found.group(2).lower()]
    return int(float(found.group(1)) * size)


def circuit_speeds(text: Any) -> Tuple[int, int] | None:
    """A port's circuit speed (``port_descr_speed``) as ``(egress, ingress)`` bit/s, read as LibreNMS's
    ``Port::circuitSpeeds`` reads it: ``100M/20M`` is 100 Mbit/s out and 20 Mbit/s in, ``1G`` and ``10Mbit`` the same
    both ways; each side a number, an SI prefix (``Mi``: powers of 1024) and any unit, with no space. None when there
    is none, or either side is not above 0: LibreNMS then measures the port against ``ifSpeed``."""
    if not isinstance(text, str) or not text or text == "0":  # PHP's empty()
        return None
    sides = [_si_bits(side) for side in text.split("/", 1)]
    egress, ingress = sides[0], sides[-1]
    if egress is None or ingress is None or egress <= 0 or ingress <= 0:
        return None
    return int(egress), int(ingress)


def _si_bits(text: str) -> float | None:
    found = _CIRCUIT_RE.match(text)
    if found is None:
        return None
    try:
        value = float(found.group(1))
    except ValueError:  # "1.2.3", which PHP reads as 1.2 and nobody writes
        return None
    base = 1024 if found.group(3) == "i" else 1000
    return value * base ** _SI_POWERS[found.group(2).upper()]


def seconds(value: Any) -> int | None:
    """A count of seconds LibreNMS holds (a device's ``uptime``): a positive whole number, else None (0 is not
    known). Past :data:`PLAUSIBLE_S` (a century, as :func:`duration` reads it) it is a counter that wrapped or was
    never set, also None: ``devices.uptime`` is a bigint, and a boot that far back may not be a date at all."""
    try:
        whole = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return whole if 0 < whole <= PLAUSIBLE_S else None


def percent(part: Any, whole: Any) -> float | None:
    """*part* of *whole* in percent, one decimal; None when either is not a number or *whole* is 0 or less."""
    numerator, denominator = number(part), number(whole)
    if numerator is None or denominator is None or denominator <= 0:
        return None
    return round(numerator * 100 / denominator, 1)


def duration(value: Any) -> str | None:
    """``3d 4h``, ``2h 5m``, ``4m 58s``, ``12s``: the two largest units, rounded down; None for no number, a negative
    one, or one past a century (a counter that wrapped or was never set)."""
    found = number(value)
    if found is None or found < 0 or found > PLAUSIBLE_S:
        return None
    total = int(found)
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
    total = int(found.group(1)) * _DURATION_UNITS[found.group(2).lower()]
    return total if 0 < total <= MAX_DURATION_S else None


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
    found = number(value)
    if found is None or found <= 0 or found > 4102444800:  # 2100-01-01
        return None
    return datetime.fromtimestamp(found, tz=timezone.utc)


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


def server_order(value: Any) -> int:
    """A fault or log time as an order key: a server-local ``Y-m-d H:i:s`` as the number its digits make (the times
    of one LibreNMS share its zone, so they order as they read, zone known or not); 0, first, for none."""
    found = _ORDER_RE.match(value) if isinstance(value, str) else None
    return int("".join(found.groups())) if found else 0


def age(moment: datetime | None, now: datetime) -> int | None:
    """Whole seconds from *moment* to *now*; None without a moment. A moment after *now* (clocks apart) is 0."""
    if moment is None:
        return None
    return max(0, int((now - moment).total_seconds()))
