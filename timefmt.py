"""Human-facing time rendering. Storage is always UTC; reports show the operator's zone.

The zone is the one Hermes uses, found as Hermes finds it but through its public modules only: ``HERMES_TIMEZONE``,
then the profile's ``timezone`` setting, else the host's local zone. Nothing here is used for comparisons or
persistence.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone, tzinfo
from typing import Any
from zoneinfo import ZoneInfo


def _zone_name() -> str:
    """The configured IANA zone name, or ``""``. ``HERMES_TIMEZONE`` speaks for the active profile except while one
    process serves several profiles (``agent.secret_scope.is_multiplex_active``): it then holds the default
    profile's zone, so the profile's own ``timezone`` setting is read instead. The config is Hermes' cached read
    with the managed overlay applied (``hermes_cli.config.load_config_readonly``), which is shared, so it is never
    modified. Outside Hermes only the variable is read."""
    try:
        from agent.secret_scope import is_multiplex_active  # type: ignore

        multiplexed = bool(is_multiplex_active())
    except Exception:
        multiplexed = False
    if not multiplexed:
        name = os.environ.get("HERMES_TIMEZONE", "").strip()
        if name:
            return name
    try:
        from hermes_cli.config import load_config_readonly  # type: ignore

        value = load_config_readonly().get("timezone")
    except Exception:
        return ""
    return value.strip() if isinstance(value, str) else ""


def get_zone() -> tzinfo | None:
    """Configured display zone, or ``None`` meaning the host's local zone (also for a name that is no zone, as
    Hermes falls back)."""
    name = _zone_name()
    if not name:
        return None
    try:
        return ZoneInfo(name)
    except Exception:
        return None


def parse_utc(stamp: Any) -> datetime | None:
    """A stored stamp as an aware datetime (UTC when it names no zone); None for anything else, an edited plan's
    number included."""
    if not isinstance(stamp, str) or not stamp:
        return None
    try:
        parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def local(stamp: Any, zone: tzinfo | None = None) -> str:
    """``2026-09-08 12:35:50 PDT`` for a stored UTC stamp; the input as text when it does not parse."""
    parsed = parse_utc(stamp)
    if parsed is None:
        return "" if stamp is None else str(stamp)
    zone = zone if zone is not None else get_zone()
    shown = parsed.astimezone(zone) if zone is not None else parsed.astimezone()
    name = shown.tzname() or ""
    return shown.strftime("%Y-%m-%d %H:%M:%S") + (f" {name}" if name else "")
