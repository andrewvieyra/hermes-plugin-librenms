"""Audit trail: who asked for what, from where, and what happened.

Two outputs, both machine-facing and always UTC:

* **Actor records** embedded in the plan file (``requested_by``, ``apply.actor``, ``rollback.actor``).
* **An append-only event stream**, one JSON object per line, at ``<plugin-data>/librenms/audit.jsonl``
  (or ``audit_log_path``). Plan files are mutable state; the stream is what a SIEM tails.

Actor capture reads Hermes' per-session context (``gateway.session_context.get_session_env``), which the gateway
binds per turn and which falls back to process environment for the CLI, plus what the plugin context offers
(``session_surface()``, ``profile_name``, ``current_cron_execution()``), which also works under host isolation.
Hermes does not pass the user's message to a tool, so the ``pre_llm_call`` hook remembers it per session
(:func:`remember_request`) and :func:`capture_actor` looks it up. Every field is best-effort and never raises: an
audit failure must not block or fail a LibreNMS operation.
"""

from __future__ import annotations

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
from collections import OrderedDict
from pathlib import Path
from typing import Any, Dict, Tuple

from .redact import MASK, mask, scrub_text
from .settings import get_settings
from .store import data_dir, now_iso, private_dir
from .version import __version__

logger = logging.getLogger(__name__)

SCHEMA = 1
PLUGIN = "librenms"
REQUEST_TEXT_LIMIT = 500
REQUEST_CACHE_SIZE = 256

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
    try:
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
    try:
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


def describe_actor(actor: Dict[str, Any] | None) -> str:
    """One human-readable phrase for reports: ``model via tool on signal for Andrew in dm Andrew``,
    ``operator via slash on tui (quartermaster)`` or ``operator via cli (quartermaster)``."""
    if not actor:
        return "unknown"
    where = actor.get("platform") or actor.get("surface") or actor.get("source")
    text = f"{actor.get('kind', 'unknown')} via {actor.get('via') or where or 'unknown'}"
    if where and actor.get("via") in {VIA_MODEL, VIA_SLASH} and where != actor.get("via"):
        text += f" on {where}"
    who = actor.get("user_name") or actor.get("user_id") or actor.get("sender_id")
    if who:
        text += f" for {who}"
    elif actor.get("os_user"):
        text += f" ({actor['os_user']})"
    chat = actor.get("chat_name") or actor.get("chat_id")
    if chat and actor.get("chat_type"):
        text += f" in {actor['chat_type']} {chat}"
    if actor.get("cron"):
        text += f" [cron {actor['cron_job_id']}]" if actor.get("cron_job_id") else " [cron]"
    return text


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


def _append(path: Path, data: bytes) -> None:
    """Write *data* to the log with one ``write``, if :func:`_check_owned` passes. A name that moved between the
    open and the check (a rotation that renames the file) is opened once more, so the event lands in the new one."""
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
    line, so the file is safe to rotate with ``copytruncate`` and several processes (gateway, ``hermes librenms``)
    can append without coordination: POSIX places each write whole at the end of the file. The file is never
    opened through a symlink and must be a regular file this account owns, with no other hard link; otherwise the
    event is not written there (the sinks still get it) and Hermes' log says why."""

    def __init__(self, path: Path | None = None, enabled: bool = True):
        self._path = Path(path) if path else None
        self.enabled = enabled

    @property
    def path(self) -> Path:
        """The configured file, or ``audit.jsonl`` in the active profile's plugin data directory (resolved on every
        use, so a profile switch moves it)."""
        return self._path if self._path is not None else data_dir() / "audit.jsonl"

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
        masked whatever the caller passed (defence in depth). Never raises."""
        if not self.enabled:
            return None
        path: Any = self._path
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
                record = _encodable(mask(record))
                try:
                    line = json.dumps(record, ensure_ascii=False, default=str, separators=(",", ":")) + "\n"
                    data = line.encode("utf-8", "replace")
                    path = self.path
                    private_dir(path.parent)  # 0700 when it creates it; an existing one is the operator's
                    _append(path, data)
                except Exception as exc:  # never let auditing break the operation it describes
                    logger.warning("librenms audit log write failed (%s): %s", path, exc)
                _forward(record)  # under the lock, so the sinks see the file's order
            return record
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("librenms audit event %s could not be recorded: %s", event, exc)
            return None


_log: AuditLog | None = None
_log_lock = threading.Lock()


def get_audit_log() -> AuditLog:
    """The log set with :func:`set_audit_log`, else one configured from the current settings (``audit_log``,
    ``audit_log_path``), so a settings change or a profile switch applies to the next event."""
    with _log_lock:
        if _log is not None:
            return _log
    s = get_settings()
    return AuditLog(Path(s.audit_log_path).expanduser() if s.audit_log_path else None, enabled=s.audit_log)


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
