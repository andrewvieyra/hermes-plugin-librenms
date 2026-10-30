"""Audit trail: who asked for what, from where, and what happened.

Two outputs, both machine-facing and always UTC:

* **Actor records** embedded in the plan file (``requested_by``, ``apply.actor``, ``rollback.actor``).
* **An append-only event stream**, one JSON object per line, at ``<plugin-data>/librenms/audit.jsonl``
  (or ``audit_log_path``). Plan files are mutable state; the stream is what a SIEM tails. It is rotated at a size
  and daily, and rotated files are removed by count and age (``audit_max_mb``, ``audit_keep_files``,
  ``audit_retention_days``), because each event can carry the user's message.

Actor capture reads Hermes' per-session context (``gateway.session_context.get_session_env``), which the gateway
binds per turn and which falls back to process environment for the CLI, plus what the plugin context offers
(``session_surface()``, ``profile_name``, ``current_cron_execution()``), which also works under host isolation.
Hermes does not pass the user's message to a tool, so the ``pre_llm_call`` hook remembers it per session
(:func:`remember_request`) and :func:`capture_actor` looks it up. Every field is best-effort and never raises: an
audit failure must not block or fail a LibreNMS operation.
"""

from __future__ import annotations

import contextlib
import getpass
import itertools
import json
import logging
import os
import platform
import re
import socket
import stat
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Tuple

from .redact import MASK, clip, mask, scrub_text
from .settings import get_settings
from .store import data_dir, now_iso, private_dir
from .version import __version__

logger = logging.getLogger(__name__)

SCHEMA = 1
PLUGIN = "librenms"
REQUEST_TEXT_LIMIT = 500
REQUEST_CACHE_SIZE = 256
# Every string of an event is clipped to TEXT_LIMIT characters, saying so; a refusal's reason or first error to
# REASON_LIMIT where it is emitted. The model can pad what it sends (a description, a query path): an event that a
# collector truncates is broken JSON, and one too large for a UDP datagram is not sent at all.
TEXT_LIMIT = 2000
REASON_LIMIT = 500

# Hermes session variables -> actor field names, in the actor's key order. Missing values are recorded as null so
# every event carries the same keys (stable field mapping for SIEM ingestion).
_SESSION_FIELDS = (
    ("HERMES_SESSION_PLATFORM", "platform"),
    ("HERMES_SESSION_SOURCE", "source"),
    ("HERMES_SESSION_PROFILE", "profile"),
    ("HERMES_SESSION_CHAT_ID", "chat_id"),
    ("HERMES_SESSION_CHAT_NAME", "chat_name"),
    ("HERMES_SESSION_CHAT_TYPE", "chat_type"),
    ("HERMES_SESSION_PARENT_CHAT_ID", "parent_chat_id"),
    ("HERMES_SESSION_THREAD_ID", "thread_id"),
    ("HERMES_SESSION_SCOPE_ID", "scope_id"),
    ("HERMES_SESSION_USER_ID", "user_id"),
    ("HERMES_SESSION_USER_ID_ALT", "user_id_alt"),
    ("HERMES_SESSION_USER_NAME", "user_name"),
    ("HERMES_SESSION_MESSAGE_ID", "message_id"),
    ("HERMES_SESSION_KEY", "session_key"),
    ("HERMES_SESSION_ID", "session_id"),
    ("HERMES_UI_SESSION_ID", "ui_session_id"),
)
# What a slash command's ``source`` keyword (Hermes' SessionSource) says about the sender, as the gateway saw it.
_SOURCE_FIELDS = (
    "platform",
    "chat_id",
    "chat_name",
    "chat_type",
    "parent_chat_id",
    "thread_id",
    "scope_id",
    "user_id",
    "user_id_alt",
    "user_name",
    "message_id",
)

VIA_MODEL = "tool"
VIA_SLASH = "slash"
VIA_CLI = "cli"
# The actor fields public_actor keeps for tool results.
PUBLIC_ACTOR_FIELDS = ("kind", "via", "surface", "platform", "source", "profile", "chat_type", "cron", "cron_job_id")
# The actor's ids: kept in the plan file and the audit stream, never in describe_actor's phrase.
_ID_FIELDS = (
    "user_id",
    "user_id_alt",
    "sender_id",
    "chat_id",
    "parent_chat_id",
    "thread_id",
    "scope_id",
    "message_id",
    "session_key",
    "session_id",
    "ui_session_id",
    "task_id",
    "cron_execution_id",
)

_ctx: Any = None


def set_ctx(ctx: Any) -> None:
    """Remember the plugin context (``register``) for the actor fields only it knows; ``None`` forgets it (tests)."""
    global _ctx
    _ctx = ctx


def _from_ctx(name: str) -> Any:
    """A plugin-context attribute or the result of calling it; ``None`` without a context or when it fails
    (an older Hermes, or a context that has no session)."""
    ctx = _ctx
    if ctx is None:
        return None
    try:
        value = getattr(ctx, name)
        return value() if callable(value) else value
    except Exception:
        return None


def _session_env(name: str) -> str:
    try:  # a private Hermes module: nothing public gives the user and chat fields (see CONTRIBUTING.md)
        from gateway.session_context import get_session_env  # type: ignore

        return get_session_env(name, "") or ""
    except Exception:
        return os.getenv(name, "") or ""


def _named(value: Any) -> str | None:
    """A value as text (an enum by its value), or ``None`` when it is empty."""
    if value is None:
        return None
    text = str(getattr(value, "value", value)).strip()
    return text or None


def _truthy(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _hermes_version() -> str | None:
    try:  # private, but the package metadata's version is stale on a git install (see CONTRIBUTING.md)
        from hermes_cli import __version__ as hv  # type: ignore

        return str(hv)
    except Exception:
        return None


def _hermes_home() -> str | None:
    """The active profile's home: Hermes' resolver follows a multiplexed gateway's per-turn profile, which
    ``$HERMES_HOME`` (the launch profile) does not; the variable is only the fallback outside Hermes."""
    try:
        from hermes_constants import get_hermes_home  # type: ignore

        return str(get_hermes_home())
    except Exception:
        return os.environ.get("HERMES_HOME") or None


def _hostname() -> str | None:
    try:
        return socket.gethostname()
    except Exception:
        return None


def _os_user() -> str | None:
    try:
        return getpass.getuser()
    except Exception:
        return None


def environment() -> Dict[str, Any]:
    """Process-level facts recorded once per plan: where the plugin ran and which versions. ``os_user`` is the
    account the Hermes gateway or CLI runs as, not the person who asked."""
    return {
        "host": _hostname(),
        "os_user": _os_user(),
        "pid": os.getpid(),
        "python": platform.python_version(),
        "plugin_version": __version__,
        "hermes_version": _hermes_version(),
        "hermes_home": _hermes_home(),
    }


# -- request cache --------------------------------------------------------------------------------

# Credential shapes masked in the user's message before redact.scrub_text (the configured token, bearer values and
# `key: value` pairs of exact credential keys): a token pasted into chat must not land in audit.jsonl or a SIEM.
# Repeats are bounded so a long pasted message cannot make a pattern backtrack for seconds in the pre_llm_call hook.
_TOKEN_PATTERNS = (
    (re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)", re.S), MASK),
    # the whole header value, scheme and credential (scrub_text would mask only the scheme word)
    (re.compile(r"\b(authorization\s*[:=]\s*(?:(?:bearer|basic|token)\s+)?)[^\s\"',;]+", re.I), rf"\1{MASK}"),
    # keys that end in a credential word: LIBRENMS_TOKEN=, hec_token:, snmp_community=
    (
        re.compile(
            r"((?:token|password|passwd|secret|community|authpass|cryptopass|psk)[\"']?\s*[:=]\s*[\"']?)[^\s\"',;&]+",
            re.I,
        ),
        rf"\1{MASK}",
    ),
    (re.compile(r"\b([a-z][a-z0-9+.-]{0,30}://)[^/\s:@]{1,256}:[^/\s@]{1,256}@", re.I), rf"\1{MASK}@"),
    (re.compile(r"\b\d{1,20}\|[A-Za-z0-9_]{40,}"), MASK),  # Sanctum API token: <id>|<secret>
    (re.compile(r"\b[0-9a-fA-F]{32}\b"), MASK),  # pre-Sanctum LibreNMS API token
)

# (session_id, task_id) -> (message, sender_id, when remembered), least recently used first
_requests: OrderedDict[Tuple[str, str], Tuple[str | None, str | None, int]] = OrderedDict()
_requests_lock = threading.Lock()
_remembered = itertools.count()


def _token() -> str | None:
    try:
        from .client import secret

        return secret("LIBRENMS_TOKEN")
    except Exception:  # no secret scope bound: the patterns below still apply
        return None


def _message_text(message: Any) -> str:
    """The text of a user message: a string, or the text parts of a multimodal list (images are skipped)."""
    if isinstance(message, str):
        return message
    if isinstance(message, dict):
        message = [message]
    if not isinstance(message, (list, tuple)):
        return ""
    parts = []
    for part in message:
        if isinstance(part, str):
            parts.append(part)
        elif isinstance(part, dict) and isinstance(part.get("text"), str):
            parts.append(part["text"])
    return "\n".join(parts)


def _clean_request(message: Any) -> str | None:
    """The user's message as the audit records it: text only, credentials masked, at most 500 characters."""
    text = _message_text(message).strip()
    if not text:
        return None
    for pattern, replacement in _TOKEN_PATTERNS:
        text = pattern.sub(replacement, text)
    text = scrub_text(text, _token())
    return text if len(text) <= REQUEST_TEXT_LIMIT else text[: REQUEST_TEXT_LIMIT - 1] + "…"


def remember_request(session_id: Any, task_id: Any, message: Any, sender_id: Any = None) -> None:
    """``pre_llm_call``: remember the user's message (only with ``audit_include_request``) and the gateway's sender
    id for the turn, so a tool call of that session can name what it was asked to do. Never raises."""
    try:
        key = (str(session_id or ""), str(task_id or ""))
        if key == ("", ""):
            return
        text = _clean_request(message) if get_settings().audit_include_request else None
        sender = _named(sender_id)
        with _requests_lock:
            _requests[key] = (text, sender, next(_remembered))
            _requests.move_to_end(key)
            while len(_requests) > REQUEST_CACHE_SIZE:
                _requests.popitem(last=False)
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("librenms audit: could not remember the request: %s", exc)


def recall_request(session_id: Any, task_id: Any) -> Tuple[str | None, str | None]:
    """``(message, sender_id)`` remembered for this session and task; else the latest of the session (a delegated
    task has its own task id); else ``(None, None)``."""
    key = (str(session_id or ""), str(task_id or ""))
    with _requests_lock:
        if key not in _requests and key[0]:
            same = [k for k in _requests if k[0] == key[0]]
            key = max(same, key=lambda k: _requests[k][2], default=key)
        if key not in _requests:
            return None, None
        _requests.move_to_end(key)
        text, sender, _when = _requests[key]
        return text, sender


def clear_requests() -> None:
    """Forget every remembered request (tests)."""
    with _requests_lock:
        _requests.clear()


# -- actor ----------------------------------------------------------------------------------------


def capture_actor(kwargs: Dict[str, Any] | None = None, *, via: str = VIA_MODEL) -> Dict[str, Any]:
    """Who is acting and through which path. ``kwargs`` are what Hermes passed: a tool handler's ``task_id`` and
    ``session_id``, or a slash command's ``session_id``, ``source`` and ``platform``. ``via`` is ``tool`` (the model
    called a tool), ``slash`` (a human typed ``/librenms``) or ``cli`` (a human ran ``hermes librenms``)."""
    kwargs = kwargs or {}
    actor: Dict[str, Any] = {
        "kind": "model" if via == VIA_MODEL else "operator",
        "via": via,
        "surface": _named(_from_ctx("session_surface")),
    }
    for env_name, field in _SESSION_FIELDS:
        actor[field] = _session_env(env_name) or None
    source = kwargs.get("source")
    if isinstance(source, str):
        actor["source"] = source or actor["source"]
    elif source is not None:  # the gateway's record of who sent the command beats the bound session variables
        for field in _SOURCE_FIELDS:
            actor[field] = _named(getattr(source, field, None)) or actor[field]
    actor["platform"] = _named(kwargs.get("platform")) or actor["platform"]
    actor["profile"] = _named(_from_ctx("profile_name")) or actor["profile"]
    # Hermes passes session_id/task_id explicitly on tool dispatch; prefer those over context.
    if kwargs.get("session_id"):
        actor["session_id"] = str(kwargs["session_id"])
    actor["task_id"] = str(kwargs["task_id"]) if kwargs.get("task_id") else None
    cron = _from_ctx("current_cron_execution")
    actor["cron"] = cron is not None or _truthy(_session_env("HERMES_CRON_SESSION"))
    actor["cron_job_id"] = _named(getattr(cron, "job_id", None))
    actor["cron_execution_id"] = _named(getattr(cron, "execution_id", None))
    actor["os_user"] = _os_user()
    request, sender = None, None
    if isinstance(kwargs.get("user_task"), str):
        request = _clean_request(kwargs["user_task"])
    elif via == VIA_MODEL:  # an operator's command is not the message the model was last asked
        request, sender = recall_request(actor["session_id"], actor["task_id"])
    actor["sender_id"] = sender
    actor["request"] = request if get_settings().audit_include_request else None
    return actor


def _display_name(actor: Dict[str, Any], field: str) -> str | None:
    """The actor's user or chat name for :func:`describe_actor`, or ``None`` where it would show an id. Hermes fills
    a name in with the id when the platform has none (an SMS number, a Signal user without a profile name, an IRC
    nick), and some adapters build one around an id (``a2a:<peer>``, a BlueBubbles chat identifier that is part of
    its chat guid), so a name that is one of the actor's ids, or holds or is part of one (4 characters or more), is
    left out."""
    name = actor.get(field)
    if not isinstance(name, str) or not name:
        return None
    for key in _ID_FIELDS:
        ident = actor.get(key)
        if not isinstance(ident, str) or not ident:
            continue
        if name == ident or (min(len(name), len(ident)) >= 4 and (ident in name or name in ident)):
            return None
    return name


def describe_actor(actor: Dict[str, Any] | None) -> str:
    """One human-readable phrase for reports: ``model via tool on signal for Andrew in dm Andrew``,
    ``operator via slash on tui (quartermaster)`` or ``operator via cli (quartermaster)``. The diff and the journal
    that carry it reach the model of any session of the profile (:func:`public_actor`), so it names a user and a chat
    by display name only (:func:`_display_name`): a user known only by an id is ``an unnamed user``, a chat only by
    its type. The ids stay in the actor record."""
    if not actor:
        return "unknown"
    where = actor.get("platform") or actor.get("surface") or actor.get("source")
    text = f"{actor.get('kind', 'unknown')} via {actor.get('via') or where or 'unknown'}"
    if where and actor.get("via") in {VIA_MODEL, VIA_SLASH} and where != actor.get("via"):
        text += f" on {where}"
    who = _display_name(actor, "user_name")
    if who:
        text += f" for {who}"
    elif any(actor.get(key) for key in ("user_name", "user_id", "user_id_alt", "sender_id")):
        text += " for an unnamed user"
    elif actor.get("os_user"):
        text += f" ({actor['os_user']})"
    if actor.get("chat_type"):
        chat = _display_name(actor, "chat_name")
        text += f" in {actor['chat_type']}" + (f" {chat}" if chat else "")
    if actor.get("cron"):
        text += f" [cron {actor['cron_job_id']}]" if actor.get("cron_job_id") else " [cron]"
    return text


def public_actor(actor: Any) -> Any:
    """What a tool result shows of an actor record: how and where it acted, and :func:`describe_actor`'s phrase, which
    names no id, as ``by``. Plans belong to the profile, not to a session, so the model of any session of the profile (another
    user of a shared gateway) can read them; the user's message, the sender, user and chat ids and the session ids
    stay in the plan file and the audit stream. Anything but a record is returned as it is."""
    if not isinstance(actor, dict):
        return actor
    shown = {key: actor.get(key) for key in PUBLIC_ACTOR_FIELDS}
    shown["by"] = describe_actor(actor)
    return shown


# -- event stream ---------------------------------------------------------------------------------

_SURROGATE = re.compile("[\ud800-\udfff]")
# One lock for every AuditLog in the process: lines stay whole and in the order the sinks get them.
_write_lock = threading.Lock()
# Never through a symlink: in a directory another account can write to (a log shipper's), one planted at the log's
# name would have users' messages appended to whatever file it points at (no open flag sees a hard link; that is
# _check_owned's to refuse). Non-blocking, so a FIFO planted there fails the open instead of holding every audited
# operation until something reads it.
_OPEN_FLAGS = os.O_WRONLY | os.O_APPEND | os.O_CREAT
_OPEN_FLAGS |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)


class _Moved(OSError):
    """The log's name no longer leads to the file just opened: rotated or removed, or swapped by another account."""


def _check_owned(fd: int, path: Path) -> None:
    """Refuse to write to anything but a regular file this account owns whose only name is the log's: a FIFO or a
    device would take the events elsewhere, a file another account created in a shared directory is a file that
    account reads, and a hard link planted there (any account may link a file it can reach) is another of this
    account's files, a shell's rc file say, under a second name. The name is looked up again after the open, so a
    link planted for the open and removed before this check is caught as well."""
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        raise OSError("not a regular file; events are not written to it")
    if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
        raise OSError("owned by another account; events are not written to it")
    if info.st_nlink > 1:
        raise OSError("has other hard links; events are not written to it")
    if info.st_nlink == 0:
        raise _Moved("removed as it was opened; events are not written to it")
    if os.name != "posix":  # like the owner check; Windows' stat and fstat need not fill st_dev and st_ino alike
        return
    try:
        named = os.lstat(path)
    except FileNotFoundError:
        raise _Moved("moved away as it was opened; events are not written to it") from None
    if (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino):
        raise _Moved("replaced as it was opened; events are not written to it")
    if named.st_nlink != 1:
        raise OSError("has other hard links; events are not written to it")


def _write(path: Path, data: bytes) -> None:
    """Write *data* to the log with one ``write``, if :func:`_check_owned` passes. A name that moved between the
    open and the check (a rotation by something other than this plugin, logrotate say) is opened once more, so the
    event lands in the new one."""
    for attempt in (1, 2):
        fd = os.open(path, _OPEN_FLAGS, 0o600)
        try:
            try:
                _check_owned(fd, path)
            except _Moved:
                if attempt == 2:
                    raise
                continue
            if os.write(fd, data) != len(data):
                raise OSError("short write (disk full?)")
            return
        finally:
            os.close(fd)


# -- rotation and retention -----------------------------------------------------------------------

MIB = 1024 * 1024
# Seconds a writer waits for the rotation lock that another process holds before it writes without it (and does
# not rotate): a rotation takes milliseconds, and a stuck process must not hold up every audited operation.
LOCK_WAIT = 2.0
# A rotated file is <log name>.<UTC time of its newest event>, -<n> after the first for a second rotation within
# that second: sortable, and its age is in its name.
_STAMP = "%Y%m%dT%H%M%SZ"
_LOCK_FLAGS = os.O_RDWR | os.O_CREAT
_LOCK_FLAGS |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
# The rotated log's successor: never through a symlink, and never a file someone else made at the name meanwhile.
_NEW_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
# What has been logged once per process: a lock file that cannot be used stays so, and saying it per event is noise.
_warned: set[Tuple[str, ...]] = set()


class RetentionError(Exception):
    """The audit log's retention could not run (its rotation lock could not be had) or ran only in part (the live
    file could not be rotated, a rotated file could not be removed): :meth:`AuditLog.prune`'s message says why, in
    words that name no directory, and ``removed`` names the rotated files it removed all the same."""

    def __init__(self, reason: str, removed: List[str] | None = None):
        super().__init__(reason)
        self.removed = list(removed or [])


class _NoLock(Exception):
    """Why the rotation lock cannot be used at all (:func:`_open_lock`), in words that name no directory; *key* says
    it once per process in Hermes' log."""

    def __init__(self, reason: str, key: Tuple[str, ...]):
        super().__init__(reason)
        self.key = key


@dataclass(frozen=True)
class Retention:
    """How the event stream is rotated and how long rotated files stay: ``audit_max_mb`` (as bytes),
    ``audit_keep_files`` and ``audit_retention_days``. 0 turns that limit off."""

    max_bytes: int = 0
    keep_files: int = 0
    max_age_days: int = 0

    @classmethod
    def from_settings(cls, settings: Any = None) -> Retention:
        s = settings if settings is not None else get_settings()
        return cls(s.audit_max_mb * MIB, s.audit_keep_files, s.audit_retention_days)

    @property
    def rotates(self) -> bool:
        """Whether the live file is ever rotated: at a size, or daily while rotated files age out."""
        return bool(self.max_bytes or self.max_age_days)

    def due(self, info: os.stat_result, incoming: int, now: float) -> bool:
        """Whether the live file (its *info*) is rotated before *incoming* more bytes are written to it: they would
        take it past ``max_bytes``, or (with ``max_age_days``) it holds an earlier UTC day's events, so each file
        holds one day and a day's events age out together. Its last write is its newest event, and every event of
        the file is of that day. An empty file never is."""
        if info.st_size <= 0:
            return False
        if self.max_bytes and info.st_size + incoming > self.max_bytes:
            return True
        return bool(self.max_age_days) and _day(info.st_mtime) < _day(now)

    def expired(self, rotated: List[Tuple[datetime, str]], now: float) -> List[str]:
        """Which of the *rotated* files (newest first, :func:`rotated_files`) retention removes: those past the
        newest ``keep_files``, and those whose newest event is more than ``max_age_days`` old."""
        cutoff = datetime.fromtimestamp(now, timezone.utc) - timedelta(days=self.max_age_days)
        return [
            name
            for index, (newest, name) in enumerate(rotated)
            if (self.keep_files and index >= self.keep_files) or (self.max_age_days and newest < cutoff)
        ]


def _day(when: float) -> date:
    return datetime.fromtimestamp(when, timezone.utc).date()


def _warn_once(key: Tuple[str, ...], message: str, *args: Any) -> None:
    if key not in _warned:
        _warned.add(key)
        logger.warning(message, *args)


def _why(exc: OSError) -> str:
    """An ``OSError``'s reason without the path it names (``Permission denied``)."""
    return exc.strerror or str(exc)


def _own_file(path: Path) -> os.stat_result | None:
    """*path*'s ``lstat`` when it names a regular file this account owns and that has no other name, else ``None``
    (also when it is gone). Rotation renames and retention removes only such a file, as :func:`_check_owned` writes
    only to one: a link, or a file another account planted at the log's or a rotated file's name, is left alone."""
    try:
        info = os.lstat(path)
    except OSError:
        return None
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        return None
    if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
        return None
    return info


def _rotated_name(path: Path) -> re.Pattern:
    return re.compile(re.escape(path.name) + r"\.(\d{8}T\d{6}Z)(?:-([1-9]\d{0,8}))?", re.ASCII)


def rotated_files(path: Path) -> List[Tuple[datetime, str]]:
    """``(time of its newest event, name)`` of each rotated file of the log at *path*, newest first: the names
    ``<name>.<UTC stamp>`` and ``<name>.<UTC stamp>-<n>`` that are regular files this account owns with no other
    name (:func:`_own_file`). Anything else, logrotate's ``audit.jsonl.1`` say, is neither counted nor removed."""
    return _newest_first(_rotated(path))


def _rotated(path: Path) -> List[Tuple[datetime, int, str]]:
    """:func:`rotated_files` as ``(time of its newest event, n, name)``, in no order."""
    pattern = _rotated_name(path)
    try:
        names = os.listdir(path.parent)
    except OSError:
        return []
    found = []
    for name in names:
        match = pattern.fullmatch(name)
        if match is None or _own_file(path.parent / name) is None:
            continue
        try:
            newest = datetime.strptime(match.group(1), _STAMP).replace(tzinfo=timezone.utc)
        except ValueError:  # 20261399T…: not a time, so not one of the plugin's
            continue
        found.append((newest, int(match.group(2) or 1), name))
    return found


def _newest_first(found: List[Tuple[datetime, int, str]]) -> List[Tuple[datetime, str]]:
    return [(newest, name) for newest, _n, name in sorted(found, reverse=True)]


def _lock_path(path: Path) -> Path:
    return path.with_name(path.name + ".lock")


def _open_lock(lock_path: Path) -> Tuple[Any, int]:
    """The ``fcntl`` module and a descriptor of the rotation lock file at *lock_path*, created ``0600`` when it is
    missing and never through a symlink. Raises :class:`_NoLock` when it cannot be used: the platform has no
    ``flock`` (Windows), the file cannot be opened there (a directory this account cannot create files in), or it
    is not a regular file this account owns (it is never written to)."""
    try:
        import fcntl
    except ImportError:
        raise _NoLock("this platform has no flock", ("flock",)) from None
    try:
        fd = os.open(lock_path, _LOCK_FLAGS, 0o600)
    except OSError as exc:
        raise _NoLock(f"cannot open the lock file ({_why(exc)})", ("open", str(lock_path))) from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or (hasattr(os, "geteuid") and info.st_uid != os.geteuid()):
            raise _NoLock("the lock file is not a regular file this account owns", ("owner", str(lock_path)))
    except BaseException:
        os.close(fd)
        raise
    return fcntl, fd


@contextlib.contextmanager
def _rotation_lock(path: Path) -> Iterator[str | None]:
    """Hold an exclusive ``flock`` on ``<log>.lock`` for a write or a retention sweep. Every writer of this plugin,
    in every process (the gateway, ``hermes librenms``, a cron run), takes it before it opens the log and keeps it
    until it has written, and a rotation happens only under it, so no rotation falls between a writer's open and
    its write: no event is written to a file after it was rotated, where retention could remove it with the event.
    Yields ``None`` once it holds the lock, else why it cannot be had, in words that name no directory: the lock
    file cannot be used (:func:`_open_lock`) or locked (a file system without locks), or another process held it
    past :data:`LOCK_WAIT`. The event is then written without the lock and nothing is rotated or removed; Hermes'
    log says why, with the lock file's path (once per process for a cause that lasts)."""
    lock_path = _lock_path(path)
    try:
        fcntl, fd = _open_lock(lock_path)
    except _NoLock as exc:
        _warn_once(exc.key, "librenms audit log not rotated or pruned: %s (%s)", exc, lock_path)
        unusable = str(exc)
    else:
        try:
            yield _lock(fcntl, fd, lock_path)
        finally:
            os.close(fd)  # and with it the lock
        return
    yield unusable  # outside the handler, so an error raised under the with is not chained to this one


def _lock(fcntl: Any, fd: int, lock_path: Path) -> str | None:
    deadline = time.monotonic() + LOCK_WAIT
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return None
        except BlockingIOError:
            if time.monotonic() >= deadline:
                logger.warning(
                    "librenms audit log: another process held the rotation lock for %ss; the event is written without "
                    "it and the log is not rotated now",
                    LOCK_WAIT,
                )
                return f"another process held the rotation lock for {LOCK_WAIT:g}s"
            time.sleep(0.01)
        except OSError as exc:  # a file system without locks
            reason = f"the lock file cannot be locked ({_why(exc)})"
            _warn_once(
                ("flock", str(lock_path)), "librenms audit log not rotated or pruned: %s (%s)", reason, lock_path
            )
            return reason


def retention_problem(path: Path, retention: Retention) -> str | None:
    """Why the audit log at *path* can be neither rotated nor pruned, in words that name no directory, for status:
    its rotation lock file cannot be used (:func:`_open_lock`) or locked, or its directory is not one this account
    can write to (a rotation renames the log there). ``None`` when it can be, when every limit is 0, and before
    there is a log; a lock another process holds right now is no problem. Opens the lock file as the next event
    would. Never raises."""
    try:
        if not (retention.rotates or retention.keep_files):
            return None
        if not os.path.lexists(path) and not rotated_files(path):
            return None
        try:
            fcntl, fd = _open_lock(_lock_path(path))
        except _NoLock as exc:
            return str(exc)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:  # a writer or a sweep at work
            pass
        except OSError as exc:
            return f"the lock file cannot be locked ({_why(exc)})"
        finally:
            os.close(fd)
        if not os.access(path.parent, os.W_OK | os.X_OK):
            return "this account cannot write to the log's directory"
        return None
    except Exception:  # pragma: no cover - defensive
        return None


def _rotation_target(path: Path, info: os.stat_result) -> Tuple[datetime, int, str]:
    """``(time of its newest event, n, name)`` the live log (its *info*) is rotated to: ``<name>.<UTC time of its
    newest event>``, with ``-<n>`` past every file of that second, so names keep the order of rotations even after
    retention removed one."""
    stamp = datetime.fromtimestamp(info.st_mtime, timezone.utc).strftime(_STAMP)
    pattern, taken = _rotated_name(path), 0
    for name in os.listdir(path.parent):
        match = pattern.fullmatch(name)
        if match is not None and match.group(1) == stamp:
            taken = max(taken, int(match.group(2) or 1))
    newest = datetime.strptime(stamp, _STAMP).replace(tzinfo=timezone.utc)
    return newest, taken + 1, f"{path.name}.{stamp}" + (f"-{taken + 1}" if taken else "")


def _rotate(path: Path, info: os.stat_result) -> str:
    """Rename the live log (its *info*) to its :func:`_rotation_target` and create its successor with the same
    mode and group, as logrotate's ``create`` does: ``0600`` for a file the plugin made, and a shipper that reads a
    file the operator made by group keeps reading. A group this account is not in cannot be given (only root
    can), so the successor then gives its own group, the directory's or this account's, no more access than
    others: what the old file let only its group read is not passed to another group, and Hermes' log says the
    group lost it (once per process).
    Returns the rotated file's name. Called under the rotation lock, so no writer of this plugin has the file
    open."""
    target = path.with_name(_rotation_target(path, info)[2])
    os.rename(path, target)
    try:
        fd = os.open(path, _NEW_FLAGS, 0o600)
    except FileExistsError:  # a writer that could not wait for the lock made it first
        return target.name
    try:
        if hasattr(os, "fchown"):
            with contextlib.suppress(OSError):  # a group this account is not in: checked below
                os.fchown(fd, -1, info.st_gid)
        mode = stat.S_IMODE(info.st_mode) & 0o666 | 0o600
        if os.fstat(fd).st_gid != info.st_gid:  # the directory's group or this account's, which was never granted
            kept = mode & (0o707 | ((mode & 0o007) << 3))
            if kept != mode:
                _warn_once(
                    ("group", str(path)),
                    "librenms audit log %s rotated, but this account could not give the new file group %s, so it is "
                    "%o rather than %o and that group (a log shipper's, say) can no longer read it: make this account "
                    "a member of the group, or give the directory that group (and on Linux the setgid bit)",
                    path,
                    info.st_gid,
                    kept,
                    mode,
                )
            mode = kept
        if hasattr(os, "fchmod"):
            with contextlib.suppress(OSError):  # it stays 0600 or narrower
                os.fchmod(fd, mode)
    finally:
        os.close(fd)
    return target.name


def _remove(path: Path, names: List[str]) -> Tuple[List[str], List[str]]:
    """Unlink the rotated files *names* (in the log's directory) that are still regular files this account owns with
    one name; returns those removed, and why each that could not be was kept (logged; the next sweep tries again)."""
    removed, kept = [], []
    for name in names:
        rotated = path.with_name(name)
        if _own_file(rotated) is None:
            continue
        try:
            rotated.unlink()
        except FileNotFoundError:  # another process's sweep was first
            continue
        except OSError as exc:  # a directory this account cannot write to, say
            logger.warning("librenms audit log retention could not remove %s: %s", rotated, exc)
            kept.append(f"{name} could not be removed ({_why(exc)})")
            continue
        removed.append(name)
    return removed, kept


def _append(path: Path, data: bytes, retention: Retention, *, rotate: bool = True) -> List[str]:
    """Write *data* to the log (:func:`_write`). With rotation on, do it under :func:`_rotation_lock`: rotate the
    file first when it is due (unless not *rotate*), and after a rotation remove the rotated files retention no
    longer keeps. Returns the names of those removed. A rotation or removal that fails is logged; the event is
    written all the same."""
    if not retention.rotates or (_own_file(path) is None and os.path.lexists(path)):
        _write(path, data)  # nothing to rotate, or nothing this account may write to: _write refuses it and says why
        return []
    with _rotation_lock(path) as unavailable:
        now, rotated = time.time(), False
        info = _own_file(path) if rotate and not unavailable else None
        if info is not None and retention.due(info, len(data), now):
            try:
                _rotate(path, info)
                rotated = True
            except OSError as exc:  # a directory this account cannot write to: the file grows on
                logger.warning("librenms audit log rotation failed (%s): %s", path, exc)
        _write(path, data)
        return _remove(path, retention.expired(rotated_files(path), now))[0] if rotated else []


def _encodable(value: Any) -> Any:
    """``value`` with lone surrogates replaced (U+FFFD): one would fail the UTF-8 write and every sink's send."""
    if isinstance(value, str):
        return _SURROGATE.sub("�", value)
    if isinstance(value, dict):
        return {k: _encodable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_encodable(v) for v in value]
    return value


def _config_digest() -> str | None:
    try:
        return get_settings().digest()
    except Exception:
        return None


def _forward(record: Dict[str, Any]) -> None:
    try:
        from . import sinks

        sinks.dispatch(record)
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("librenms audit sinks unavailable: %s", exc)


class AuditLog:
    """Append-only JSON Lines writer. Each event is one ``open`` with ``O_APPEND`` and one ``write`` of the whole
    line, so several processes (gateway, ``hermes librenms``) can append to the same file: POSIX places each write
    whole at the end of the file. Every event opens the file by name, so rotating it by renaming loses no line;
    ``copytruncate`` can lose the lines written between its copy and its truncate. The file is never opened through
    a symlink and must be a regular file this account owns, with no other hard link; otherwise the event is not
    written there (the sinks still get it) and Hermes' log says why.

    *retention* (else ``audit_max_mb``, ``audit_keep_files`` and ``audit_retention_days`` as they are at each event)
    rotates the file by renaming it, under a ``flock`` every writer holds from its open to its write (see
    :func:`_rotation_lock`), and removes rotated files; each removal is recorded as ``audit_pruned``."""

    def __init__(self, path: Path | None = None, enabled: bool = True, retention: Retention | None = None):
        self._path = Path(path) if path else None
        self.enabled = enabled
        self._retention = retention

    @property
    def path(self) -> Path:
        """The configured file, or ``audit.jsonl`` in the active profile's plugin data directory (resolved on every
        use, so a profile switch moves it)."""
        return self._path if self._path is not None else data_dir() / "audit.jsonl"

    @property
    def retention(self) -> Retention:
        return self._retention if self._retention is not None else Retention.from_settings()

    def emit(
        self,
        event: str,
        *,
        plan_id: str | None = None,
        actor: Dict[str, Any] | None = None,
        librenms_url: str | None = None,
        **details: Any,
    ) -> Dict[str, Any] | None:
        """Append one event and hand it to the sinks; returns the record as written. Credential-bearing keys are
        masked whatever the caller passed (defence in depth), and every string is clipped to :data:`TEXT_LIMIT`
        characters, saying so. Never raises."""
        if not self.enabled:
            return None
        path: Any = self._path
        removed: List[str] = []
        try:
            with _write_lock:
                record: Dict[str, Any] = {
                    "ts": now_iso(),
                    "schema": SCHEMA,
                    "plugin": PLUGIN,
                    "event": event,
                    "plan_id": plan_id,
                    "librenms_url": librenms_url,
                    "config_digest": _config_digest(),
                    "actor": actor,
                    "host": _hostname(),
                    "pid": os.getpid(),
                }
                record.update(details)
                record = _encodable(clip(mask(record), TEXT_LIMIT))
                try:
                    line = json.dumps(record, ensure_ascii=False, default=str, separators=(",", ":")) + "\n"
                    data = line.encode("utf-8", "replace")
                    retention = self.retention
                    path = self.path
                    private_dir(path.parent)  # 0700 when it creates it; an existing one is the operator's
                    # the record of a removal never rotates, so it never removes a file it does not name
                    removed = _append(path, data, retention, rotate=event != "audit_pruned")
                except Exception as exc:  # never let auditing break the operation it describes
                    logger.warning("librenms audit log write failed (%s): %s", path, exc)
                _forward(record)  # under the lock, so the sinks see the file's order
            if removed:
                self._pruned(removed, retention, actor)
            return record
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("librenms audit event %s could not be recorded: %s", event, exc)
            return None

    def prune(self, *, actor: Dict[str, Any] | None = None, dry_run: bool = False) -> List[str]:
        """Retention sweep, for a log nobody writes to for a while: rotate the live file when it is due (it holds an
        earlier UTC day's events, or is past ``audit_max_mb``), then remove the rotated files retention no longer
        keeps; audited as ``audit_pruned``. Returns their names. With *dry_run* nothing changes, and it returns what
        the sweep would remove now: the rotated files, and a live file that is due and would go as soon as it is
        rotated, as ``<name> (would be rotated to <rotated name> and removed)``; the rotation it would do counts
        toward ``audit_keep_files`` as well. Runs whether or not ``audit_log`` is on: files already written still
        age out. Creates nothing when there is no log.

        Raises :class:`RetentionError` when it could not run (the rotation lock could not be had) or ran only in
        part (the live file could not be rotated, a rotated file could not be removed, the sweep failed), once what
        it did remove is recorded; Hermes' log has the details. Nothing else raises."""
        removed: List[str] = []
        problems: List[str] = []
        retention = Retention()
        try:
            retention, path = self.retention, self.path
            if not (retention.rotates or retention.keep_files):
                return []
            with _write_lock:
                if not os.path.lexists(path) and not rotated_files(path):
                    return []
                with _rotation_lock(path) as unavailable:
                    if unavailable:
                        raise RetentionError(f"retention could not run: {unavailable}")
                    now, live = time.time(), None
                    info = _own_file(path)
                    if info is not None and retention.due(info, 0, now):
                        if dry_run:  # what the real sweep would rotate counts and ages like any rotated file
                            live = _rotation_target(path, info)
                        else:
                            try:
                                _rotate(path, info)
                            except OSError as exc:  # the rotated files still age out
                                logger.warning("librenms audit log rotation failed (%s): %s", path, exc)
                                problems.append(f"{path.name} could not be rotated ({_why(exc)})")
                    found = _rotated(path) + ([live] if live else [])
                    expired = retention.expired(_newest_first(found), now)
                    if dry_run:
                        removed = [
                            f"{path.name} (would be rotated to {name} and removed)"
                            if live and name == live[2]
                            else name
                            for name in expired
                        ]
                    else:
                        removed, kept = _remove(path, expired)
                        problems += kept
        except RetentionError:
            raise
        except Exception as exc:  # retention is housekeeping and must not affect the call that ran it
            logger.warning("librenms audit log retention sweep failed: %s", exc)
            problems.append(f"the sweep failed ({type(exc).__name__})")
        if removed and not dry_run:
            self._pruned(removed, retention, actor)
        if problems:
            raise RetentionError("retention ran only in part: " + "; ".join(problems), removed)
        return removed

    def _pruned(self, removed: List[str], retention: Retention, actor: Dict[str, Any] | None) -> None:
        self.emit(
            "audit_pruned",
            plan_id=None,
            actor=actor,
            librenms_url=None,
            max_age_days=retention.max_age_days,
            keep_files=retention.keep_files,
            count=len(removed),
            files=removed,
        )


_log: AuditLog | None = None
_log_lock = threading.Lock()


def get_audit_log() -> AuditLog:
    """The log set with :func:`set_audit_log`, else one configured from the current settings (``audit_log``,
    ``audit_log_path`` and the retention settings), so a settings change or a profile switch applies to the next
    event."""
    with _log_lock:
        if _log is not None:
            return _log
    s = get_settings()
    path = Path(s.audit_log_path).expanduser() if s.audit_log_path else None
    return AuditLog(path, enabled=s.audit_log, retention=Retention.from_settings(s))


def set_audit_log(log: AuditLog | None) -> None:
    """Test seam: pin a log; ``None`` returns to the settings-driven one."""
    global _log
    with _log_lock:
        _log = log


def emit(event: str, **fields: Any) -> Dict[str, Any] | None:
    """Record one event (``plan_id``, ``actor``, ``librenms_url`` and event details as keywords). Never raises."""
    try:
        log = get_audit_log()
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("librenms audit log unavailable: %s", exc)
        return None
    return log.emit(event, **fields)
