"""Optional audit sinks: forward every audit event to syslog and/or an HTTP collector.

The JSON Lines file written by :mod:`audit` stays the source of truth. Sinks are a convenience for
installs without a log shipper (a homelab syslog server, Graylog, Wazuh) or with an HTTPS-only
collector (Splunk HEC and similar). Delivery rules:

* Events are queued and sent from one daemon thread. Emitting never blocks a LibreNMS operation.
* A sink failure is retried a few times with a short backoff, then the event is dropped for that
  sink and the failure is logged once per sink per few minutes, not per event.
* The queue is bounded; when it is full, events are dropped for the sinks (never for the file).

Standard library only. Configuration lives in ``plugins.entries.librenms.settings.audit_sinks``::

    audit_sinks:
      - type: syslog
        host: siem.example.com
        port: 6514
        protocol: tls          # udp | tcp | tls
        format: json           # json | cef
        facility: local0
        verify_ssl: /etc/ssl/siem-ca.pem   # true (default) | false | a CA bundle file or directory
      - type: http
        url: https://splunk.example.com:8088/services/collector/event
        headers: {Authorization: "Splunk ${SPLUNK_HEC_TOKEN}"}   # ${VAR} is read from Hermes' secrets
        format: hec            # json | hec

Secrets belong in the profile's ``.env`` (``<HERMES_HOME>/.env``), so the token never sits in ``config.yaml``.
Hermes' config loader replaces each ``${VAR}`` in the settings (headers and url alike) with the active profile's
secret when the settings are read, on the thread of the call that emits the event. A placeholder still there
afterwards is a variable this profile does not set: that sink is not built (and the log says which variable), and
nothing here ever reads one later, on the sink thread, where no profile is bound and the environment holds another
profile's values. Status warns about a credential header written into ``config.yaml`` as a literal value. No
redirect is followed. Events hold users' messages, so clear text (``udp``/``tcp`` syslog, an ``http://`` url) is
accepted only to a loopback host, which is dialed directly, never through a proxy, and an unverified TLS collector
(``verify_ssl: false``) not at all, unless ``allow_insecure_transport`` is on. A change to that setting or to
``audit_sinks`` applies from the next event, without a restart. Each Hermes profile gets its own worker. Log lines
name a sink by its place in ``audit_sinks`` and its kind, never by its host, url, headers or file paths.
"""

from __future__ import annotations

import atexit
import contextlib
import hashlib
import ipaddress
import json
import logging
import os
import queue
import re
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List
from urllib.parse import urlsplit

from .client import env_file
from .settings import Settings, flag, get_settings
from .store import PLUGIN_NAME, profile_key
from .version import __version__

logger = logging.getLogger(__name__)

QUEUE_SIZE = 1000
RETRIES = 3
RETRY_BACKOFF = 0.25
ERROR_LOG_INTERVAL = 300.0
# Seconds a sink may wait to connect and send: 0 would make a socket non-blocking.
TIMEOUT_RANGE = (0.1, 600.0)
USER_AGENT = f"hermes-plugin-librenms/{__version__}"
CEF_VENDOR = "andrewvieyra"
CEF_PRODUCT = "hermes-plugin-librenms"
APP_NAME = "hermes-librenms"
SOURCETYPE = "hermes:librenms:audit"

FACILITIES = {
    "kern": 0,
    "user": 1,
    "mail": 2,
    "daemon": 3,
    "auth": 4,
    "syslog": 5,
    "lpr": 6,
    "news": 7,
    "uucp": 8,
    "cron": 9,
    "authpriv": 10,
    "ftp": 11,
    "local0": 16,
    "local1": 17,
    "local2": 18,
    "local3": 19,
    "local4": 20,
    "local5": 21,
    "local6": 22,
    "local7": 23,
}
SEV_WARNING, SEV_NOTICE, SEV_INFO = 4, 5, 6

_WARNING_EVENTS = {
    "plan_rejected",
    "apply_refused",
    "rollback_refused",
    "query_refused",
    "step_failed",
    "step_conflict",
    "revert_failed",
    "revert_conflict",
    "revert_irreversible",
    "run_recovered",
}
_NOTICE_EVENTS = {"apply_started", "rollback_started", "plans_pruned", "approval_requested", "approval_decided"}


def severity_of(record: Dict[str, Any]) -> int:
    """Syslog severity for an audit record: warning for anything that stopped, was refused or left work undone."""
    event = str(record.get("event", ""))
    if event in _WARNING_EVENTS:
        return SEV_WARNING
    if event == "apply_finished" and record.get("outcome") == "failed":
        return SEV_WARNING
    if event == "rollback_finished" and record.get("status") != "rolled_back":
        return SEV_WARNING
    if event == "eventlog_linked" and record.get("linked") is False:
        return SEV_WARNING
    if event in _NOTICE_EVENTS:
        return SEV_NOTICE
    return SEV_INFO


class SinkError(Exception):
    """A sink that cannot be built, or a send that failed, with a reason that quotes nothing from the entry (its
    url, headers and paths may carry a credential or name the OS account), so it is safe to log."""


# A ``${VAR}`` or ``${env:VAR}`` placeholder, as Hermes' config loader writes them and leaves them when unset
_PLACEHOLDER = re.compile(r"\$\{([^}]*)\}")
_VARIABLE = re.compile(r"(?:env:)?\s*([A-Za-z_][A-Za-z0-9_]{0,99})\s*")


def _unresolved(where: str, value: str) -> None:
    """Refuse *value* when Hermes left a placeholder in it: the variable is not set for this profile, and reading it
    any later (on the sink thread) would get the environment's, which is another profile's. The reason names the
    variable, never the value."""
    found = _PLACEHOLDER.search(value)
    if found is None:
        return
    name = _VARIABLE.fullmatch(found.group(1))
    shown = f"${{{name.group(1)}}}" if name else "a ${...} placeholder"
    raise SinkError(
        f"{where} holds {shown}, which is not set for this Hermes profile; set it in {env_file()}"
        if name
        else f"{where} holds {shown} that Hermes could not read; reference an environment variable as ${{NAME}}"
    )


def _reason(exc: BaseException) -> str:
    """Why a send failed, for the log: an HTTP status or the error's class, never its text, which can name the
    collector (a TLS hostname mismatch) or quote a header value (an invalid header)."""
    if isinstance(exc, SinkError):
        return str(exc)
    if isinstance(exc, urllib.error.HTTPError):
        return f"HTTP {exc.code}"
    if isinstance(exc, urllib.error.URLError) and isinstance(exc.reason, BaseException):
        exc = exc.reason
    return type(exc).__name__


def _loopback(host: str | None) -> bool:
    """Whether *host* names this machine (by name or address, no lookup): clear text to it never crosses a network."""
    name = (host or "").strip("[]").lower()
    if name == "localhost" or name.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(name).is_loopback
    except ValueError:
        return False


# -- CEF ------------------------------------------------------------------------------------------


def _cef_header(value: Any) -> str:
    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _cef_ext(value: Any) -> str:
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
    return text.replace("\\", "\\\\").replace("=", "\\=").replace("\r", " ").replace("\n", "\\n")


def to_cef(record: Dict[str, Any]) -> str:
    """ArcSight Common Event Format line. Standard keys where they fit, labelled ``csN``/``cnN`` pairs for the rest;
    a label is written only with its value, so no field is left dangling."""
    actor = record.get("actor") or {}
    sev = {SEV_WARNING: 7, SEV_NOTICE: 4, SEV_INFO: 2}[severity_of(record)]
    stamp = record.get("ts")
    try:
        rt = int(datetime.fromisoformat(str(stamp).replace("Z", "+00:00")).timestamp() * 1000)
    except Exception:
        rt = int(time.time() * 1000)
    ext: List[tuple] = [
        ("rt", rt),
        ("dvchost", record.get("host")),
        ("dvcpid", record.get("pid")),
        ("request", record.get("librenms_url")),
        ("suser", actor.get("user_name") or actor.get("user_id") or actor.get("sender_id")),
    ]
    labelled = [
        ("cs1", "plan_id", record.get("plan_id")),
        ("cs2", "actor_kind", actor.get("kind")),
        ("cs3", "via", actor.get("via")),
        ("cs4", "platform", actor.get("platform") or actor.get("surface") or actor.get("source")),
        ("cs5", "chat", actor.get("chat_name") or actor.get("chat_id")),
        ("cs6", "resource", record.get("resource")),
        ("cn1", "http_status", record.get("http_status")),
        ("cs7", "request_text", actor.get("request")),
        ("cs8", "config_digest", record.get("config_digest")),
    ]
    for key, label, value in labelled:
        if value not in (None, ""):
            ext += [(f"{key}Label", label), (key, value)]
    ext += [
        ("act", record.get("action")),
        ("externalId", record.get("object_id")),
        ("outcome", record.get("outcome") or record.get("status")),
        ("msg", record.get("error") or record.get("reason") or record.get("description")),
    ]
    extension = " ".join(f"{k}={_cef_ext(v)}" for k, v in ext if v not in (None, ""))
    name = str(record.get("event", "")).replace("_", " ")
    return "|".join(
        [
            "CEF:0",
            CEF_VENDOR,
            CEF_PRODUCT,
            _cef_header(__version__),
            _cef_header(record.get("event", "")),
            _cef_header(name),
            str(sev),
            extension,
        ]
    )


# -- sinks ----------------------------------------------------------------------------------------

_CLEAR_SYSLOG = (
    "syslog over udp or tcp sends events, which hold users' messages, in clear text to a host other than this one; "
    "use protocol tls, or turn on allow_insecure_transport"
)
_CLEAR_HTTP = (
    "an http:// url sends events, which hold users' messages, and the headers in clear text to a host other than "
    "this one; use https://, or turn on allow_insecure_transport"
)
_UNVERIFIED = (
    "verify_ssl: false leaves the collector unverified, so anyone on the path can read and forge events; give a CA "
    "bundle path in verify_ssl, or turn on allow_insecure_transport"
)


def _tls_context(verify: bool | str) -> ssl.SSLContext:
    """The system trust store, a CA bundle (file or directory), or no checks at all for ``verify_ssl: false``."""
    if isinstance(verify, str):
        if os.path.isdir(verify):
            return ssl.create_default_context(capath=verify)
        return ssl.create_default_context(cafile=verify)
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


class Sink:
    """One destination. ``name`` is its kind; ``number`` its index in ``audit_sinks``, which logs name it by."""

    name = "sink"
    number: int | None = None

    def label(self) -> str:
        return f"audit_sinks[{'?' if self.number is None else self.number}] ({self.name})"

    def send(self, record: Dict[str, Any]) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def close(self) -> None:
        return None


class SyslogSink(Sink):
    """RFC 5424 over UDP (IPv4 or IPv6), TCP (newline or octet-counted framing) or TLS (octet-counted, RFC 5425)."""

    def __init__(
        self,
        host: str,
        port: int = 514,
        *,
        protocol: str = "udp",
        fmt: str = "json",
        facility: Any = "local0",
        app_name: str = APP_NAME,
        framing: str | None = None,
        verify_ssl: bool | str = True,
        timeout: float = 5.0,
        allow_insecure: bool = False,
    ):
        self.host, self.port = host.strip().strip("[]"), int(port)
        self.protocol = protocol.lower()
        if self.protocol not in {"udp", "tcp", "tls"}:
            raise SinkError("syslog protocol must be udp, tcp or tls")
        if self.protocol != "tls" and not allow_insecure and not _loopback(self.host):
            raise SinkError(_CLEAR_SYSLOG)
        if self.protocol == "tls" and verify_ssl is False and not allow_insecure:
            raise SinkError(_UNVERIFIED)
        self.fmt = fmt.lower()
        if self.fmt not in {"json", "cef"}:
            raise SinkError("syslog format must be json or cef")
        self.facility = _facility(facility)
        if not re.fullmatch(r"[!-~]{1,48}", app_name):  # RFC 5424 APP-NAME
            raise SinkError("syslog app_name must be 1 to 48 printable ASCII characters without spaces")
        self.app_name = app_name
        self.framing = framing or ("octet-counting" if self.protocol == "tls" else "newline")
        if self.framing not in {"newline", "octet-counting"}:
            raise SinkError("syslog framing must be newline or octet-counting")
        self.verify_ssl, self.timeout = verify_ssl, timeout
        self.name = f"syslog {self.protocol}"
        self._sock: socket.socket | None = None
        self._address: Any = None
        try:
            self.hostname = socket.gethostname() or "-"
        except Exception:
            self.hostname = "-"

    def message(self, record: Dict[str, Any]) -> str:
        pri = self.facility * 8 + severity_of(record)
        stamp = record.get("ts") or datetime.now(timezone.utc).isoformat()
        body = (
            to_cef(record)
            if self.fmt == "cef"
            else json.dumps(record, ensure_ascii=False, default=str, separators=(",", ":"))
        )
        msgid = str(record.get("event") or "-")[:32] or "-"
        return f"<{pri}>1 {stamp} {self.hostname} {self.app_name} {record.get('pid') or '-'} {msgid} - {body}"

    def _connect(self) -> socket.socket:
        if self._sock is not None:
            return self._sock
        if self.protocol == "udp":
            # the resolver picks the family, so an IPv6 collector (or a name with only AAAA records) works too
            family, kind, proto, _name, address = socket.getaddrinfo(self.host, self.port, type=socket.SOCK_DGRAM)[0]
            sock = socket.socket(family, kind, proto)
            self._address = address
        else:
            context = _tls_context(self.verify_ssl) if self.protocol == "tls" else None
            sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
            if context is not None:
                try:
                    sock = context.wrap_socket(sock, server_hostname=self.host)
                except Exception:
                    sock.close()
                    raise
        self._sock = sock
        return sock

    def send(self, record: Dict[str, Any]) -> None:
        payload = self.message(record).encode("utf-8")
        try:
            sock = self._connect()
            if self.protocol == "udp":
                sock.sendto(payload, self._address)
            else:
                frame = f"{len(payload)} ".encode() + payload if self.framing == "octet-counting" else payload + b"\n"
                sock.sendall(frame)
        except Exception:
            self.close()  # reconnect (and resolve again) on the next attempt
            raise

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """Refuses every redirect: urllib's default follows a 301, 302 or 303 for a POST and keeps the headers (the HEC
    token among them) on the new request, to whatever host ``Location`` names."""

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        with contextlib.suppress(Exception):
            fp.close()
        raise SinkError(f"the collector answered with a redirect (HTTP {code}); events are never sent on")


class HttpSink(Sink):
    """POST each record as JSON (``format: json``) or wrapped for Splunk HEC (``format: hec``)."""

    def __init__(
        self,
        url: str,
        *,
        headers: Dict[str, Any] | None = None,
        fmt: str = "json",
        timeout: float = 5.0,
        verify_ssl: bool | str = True,
        sourcetype: str = SOURCETYPE,
        allow_insecure: bool = False,
    ):
        _unresolved("url", url)
        if not url.startswith(("http://", "https://")):
            raise SinkError("http sink url must start with http:// or https://")
        try:
            parts = urlsplit(url)
            host = parts.hostname
        except ValueError:
            raise SinkError("http sink url is not a valid URL") from None
        if not host:
            raise SinkError("http sink url must name a host")
        if "@" in parts.netloc:
            raise SinkError("http sink url must not carry a user name or password; put credentials in headers")
        loopback = _loopback(host)
        if parts.scheme == "http" and not allow_insecure and not loopback:
            raise SinkError(_CLEAR_HTTP)
        if parts.scheme == "https" and verify_ssl is False and not allow_insecure:
            raise SinkError(_UNVERIFIED)
        self.headers = _headers(headers or {})
        self.fmt = fmt.lower()
        if self.fmt not in {"json", "hec"}:
            raise SinkError("http format must be json or hec")
        self.url, self.timeout, self.verify_ssl, self.sourcetype = url, timeout, verify_ssl, sourcetype
        self.name, self.loopback = parts.scheme, loopback

    def body(self, record: Dict[str, Any]) -> bytes:
        if self.fmt == "hec":
            try:
                epoch = datetime.fromisoformat(str(record.get("ts")).replace("Z", "+00:00")).timestamp()
            except Exception:
                epoch = time.time()
            payload: Any = {"time": epoch, "sourcetype": self.sourcetype, "host": record.get("host"), "event": record}
        else:
            payload = record
        return json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")

    def send(self, record: Dict[str, Any]) -> None:
        headers = {"Content-Type": "application/json", "User-Agent": USER_AGENT, **self.headers}
        req = urllib.request.Request(self.url, data=self.body(record), headers=headers, method="POST")
        context = _tls_context(self.verify_ssl) if self.name == "https" else None
        # a loopback collector is dialed directly: through a proxy from the environment, its clear text (events and
        # headers) would cross the network after all. Any other collector honours the proxy, as urllib does.
        proxies = urllib.request.ProxyHandler({} if self.loopback else None)
        opener = urllib.request.build_opener(_NoRedirects(), urllib.request.HTTPSHandler(context=context), proxies)
        try:
            with opener.open(req, timeout=self.timeout):  # anything but a 2xx answer raises
                pass
        except urllib.error.HTTPError as exc:
            exc.close()  # it holds the response open
            raise


# -- entry parsing --------------------------------------------------------------------------------

_HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")


def _headers(raw: Any) -> Dict[str, str]:
    if not isinstance(raw, dict):
        raise SinkError("http sink headers must be a mapping")
    headers: Dict[str, str] = {}
    for name, value in raw.items():
        text = str(value) if isinstance(value, (str, int, float)) and not isinstance(value, bool) else None
        if not (isinstance(name, str) and _HEADER_NAME.fullmatch(name)) or text is None or re.search(r"[\r\n]", text):
            raise SinkError("http sink headers must map header names to single-line text values")
        _unresolved(f"header {name}", text)
        headers[name] = text
    return headers


def _facility(value: Any) -> int:
    """A syslog facility by name (``local0``) or number (0 to 23)."""
    if isinstance(value, str) and value.lower() in FACILITIES:
        return FACILITIES[value.lower()]
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 23:
        return value
    raise SinkError("syslog facility must be a name such as local0, or a number from 0 to 23")


def _number(spec: Dict[str, Any], key: str, kind: Any, default: Any, low: float, high: float) -> Any:
    """A numeric option, or its default when absent. ``true``/``false`` (which ``int()`` reads as 1/0), a fraction
    for a whole number, NaN and values out of range make the entry unusable rather than send somewhere nobody set."""
    raw = spec.get(key, default)
    value = None
    if not isinstance(raw, bool):
        with contextlib.suppress(TypeError, ValueError, OverflowError):
            value = kind(raw)
    if value is None or (kind is int and isinstance(raw, float) and value != raw):
        raise SinkError(f"{key} must be a whole number" if kind is int else f"{key} must be a number")
    if not low <= value <= high:
        raise SinkError(f"{key} must be a number from {low} to {high}")
    return value


def _ca_path(value: Any) -> str | None:
    """*value* as a readable CA bundle file or a directory, ``~`` expanded; ``None`` when it is neither."""
    path = os.path.expanduser(value) if isinstance(value, str) else ""
    if path and (os.path.isdir(path) or (os.path.isfile(path) and os.access(path, os.R_OK))):
        return path
    return None


def _verify(spec: Dict[str, Any]) -> bool | str:
    """``verify_ssl``: true (the default), false, or a CA bundle path (file or directory) that exists; ``ca_file``
    is the other spelling of the path. Anything else makes the entry unusable: ``bool()`` read an empty value or
    ``0`` as false, turning certificate checks off, and the text ``false`` as true. Paths are never quoted: they
    can name the OS account."""
    raw = spec.get("verify_ssl", True)
    value = flag(raw)
    if value is None:
        path = _ca_path(raw)
        if path is None:
            raise SinkError("verify_ssl must be true, false or the path of an existing CA bundle file or directory")
        value = path
    if spec.get("ca_file") is not None:
        if value is not True:
            raise SinkError("give the CA bundle either in verify_ssl or in ca_file, not both")
        value = _ca_path(spec["ca_file"])
        if value is None:
            raise SinkError("ca_file must be an existing CA bundle file or directory")
    return value


def _build(spec: Any, allow_insecure: bool) -> Sink:
    if not isinstance(spec, dict):
        raise SinkError("the entry is not a mapping")
    kind = str(spec.get("type") or "").lower()
    if kind == "syslog":
        host = spec.get("host")
        if not isinstance(host, str) or not host.strip():
            raise SinkError("syslog sink needs a host")
        _unresolved("host", host)
        framing = spec.get("framing")
        return SyslogSink(
            host,
            _number(spec, "port", int, 514, 1, 65535),
            protocol=str(spec.get("protocol", "udp")),
            fmt=str(spec.get("format", "json")),
            facility=spec.get("facility", "local0"),
            app_name=str(spec.get("app_name", APP_NAME)),
            framing=None if framing is None else str(framing),
            verify_ssl=_verify(spec),
            timeout=_number(spec, "timeout", float, 5.0, *TIMEOUT_RANGE),
            allow_insecure=allow_insecure,
        )
    if kind == "http":
        return HttpSink(
            str(spec.get("url") or ""),
            headers=spec.get("headers") or {},
            fmt=str(spec.get("format", "json")),
            timeout=_number(spec, "timeout", float, 5.0, *TIMEOUT_RANGE),
            verify_ssl=_verify(spec),
            sourcetype=str(spec.get("sourcetype", SOURCETYPE)),
            allow_insecure=allow_insecure,
        )
    raise SinkError("type must be syslog or http")


def build_sink(spec: Any, allow_insecure: bool = False, index: int | None = None) -> Sink | None:
    """One sink from its ``audit_sinks`` entry; ``None`` for an unusable one, with a warning that names the entry by
    its index and type and gives a reason that quotes nothing from it."""
    try:
        sink = _build(spec, allow_insecure)
    except SinkError as exc:
        reason = str(exc)
    except Exception:  # a value of a shape no check foresaw: its error text could quote the entry
        reason = "the entry is not usable"
    else:
        sink.number = index
        return sink
    kind = spec.get("type") if isinstance(spec, dict) else None
    kind = kind.lower() if isinstance(kind, str) and kind.lower() in {"syslog", "http"} else "unknown type"
    logger.warning("librenms audit_sinks[%s] (%s) ignored: %s", "?" if index is None else index, kind, reason)
    return None


# -- credentials written into config.yaml ---------------------------------------------------------

# A header that carries a credential: Authorization, Proxy-Authorization, X-Splunk-Token, X-API-Key, ...
_CREDENTIAL_HEADER = re.compile(r"auth|token|key|secret|pass", re.IGNORECASE)
SECRET_FIELD, SECRET_ENV = "audit_sink_secret", "LIBRENMS_AUDIT_SINK_SECRET"


def written_specs() -> Any:
    """``audit_sinks`` as config.yaml writes them, before Hermes' loader replaces the ``${VAR}`` placeholders (the
    settings hold the values, so a literal token cannot be told from a resolved one there): Hermes' raw read of the
    active profile's config.yaml, else (outside Hermes) the settings' own entries."""
    try:
        from hermes_cli.config import read_raw_config_readonly  # type: ignore
    except Exception:
        return get_settings().audit_sinks
    try:
        raw = read_raw_config_readonly()
        entry = ((raw.get("plugins") or {}).get("entries") or {}).get(PLUGIN_NAME) or {}
        for subtree in ("settings", "config"):  # where ctx.get_config looks, in its order
            values = entry.get(subtree)
            if isinstance(values, dict) and "audit_sinks" in values:
                return values["audit_sinks"]
    except Exception:  # an unreadable config.yaml: Hermes reports that itself
        pass
    return []


def literal_credentials(specs: Any) -> List[str]:
    """Where an http sink's credential header holds a value written into config.yaml rather than a ``${VAR}``
    placeholder, as ``audit_sinks[N] header NAME`` (N its place in config.yaml). Names no value."""
    found: List[str] = []
    for index, spec in enumerate(specs if isinstance(specs, list) else []):
        if not isinstance(spec, dict) or str(spec.get("type") or "").strip().lower() != "http":
            continue
        headers = spec.get("headers")
        for name, value in headers.items() if isinstance(headers, dict) else ():
            if not (isinstance(name, str) and _HEADER_NAME.fullmatch(name) and _CREDENTIAL_HEADER.search(name)):
                continue
            if isinstance(value, (str, int, float)) and str(value).strip() and not _PLACEHOLDER.search(str(value)):
                found.append(f"audit_sinks[{index}] header {name[:64]}")
    return found


def literal_credential_warnings() -> List[str]:
    """One warning per credential header written into config.yaml (see :func:`literal_credentials`), saying where
    the credential belongs instead, and that the placeholder is written in config.yaml: Hermes fills the Desktop's
    settings form from the expanded settings, so that form would save the credential back. For status and the log
    at registration. Never raises."""
    try:
        places = literal_credentials(written_specs())
    except Exception:
        return []
    return [
        f"{place} holds a credential written into config.yaml; put it in {env_file()} (the Desktop's "
        f"{SECRET_FIELD} setting stores one there as {SECRET_ENV}) and write ${{{SECRET_ENV}}} in its place, in "
        "config.yaml itself: the Desktop's form shows audit_sinks with each ${...} replaced by its value, and "
        "saving it there writes the credential back"
        for place in places
    ]


# -- worker ---------------------------------------------------------------------------------------


class SinkWorker:
    """Single background thread draining a bounded queue into every sink."""

    # what get_worker built it from (see _settings_key); None for a worker installed with set_worker
    settings_key: str | None = None

    def __init__(
        self, sinks: List[Sink], *, queue_size: int = QUEUE_SIZE, retries: int = RETRIES, backoff: float = RETRY_BACKOFF
    ):
        self.sinks = list(sinks)
        self.retries, self.backoff = retries, backoff
        self._queue: queue.Queue = queue.Queue(maxsize=queue_size)
        self.stats = {"queued": 0, "sent": 0, "failed": 0, "dropped": 0}
        self._last_error_log: Dict[str, float] = {}
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="librenms-audit-sinks", daemon=True)
        if self.sinks:
            self._thread.start()

    def enqueue(self, record: Dict[str, Any]) -> bool:
        if not self.sinks:
            return False
        try:
            self._queue.put_nowait(record)
        except queue.Full:
            self.stats["dropped"] += 1
            self._log_once("queue", "audit sink queue is full; dropping events for sinks (file is unaffected)")
            return False
        self.stats["queued"] += 1
        return True

    def _deliver(self, sink: Sink, record: Dict[str, Any]) -> None:
        for attempt in range(1, self.retries + 1):
            try:
                sink.send(record)
                self.stats["sent"] += 1
                return
            except Exception as exc:
                if attempt == self.retries:
                    self.stats["failed"] += 1
                    self._log_once(sink.label(), f"{sink.label()} failed after {attempt} attempts: {_reason(exc)}")
                    return
                time.sleep(self.backoff * attempt)

    def _log_once(self, key: str, message: str) -> None:
        now = time.monotonic()
        if now - self._last_error_log.get(key, -ERROR_LOG_INTERVAL) >= ERROR_LOG_INTERVAL:
            self._last_error_log[key] = now
            logger.warning("librenms %s", message)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                record = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                for sink in self.sinks:
                    self._deliver(sink, record)
            finally:
                self._queue.task_done()

    def flush(self, timeout: float = 5.0) -> bool:
        """Wait until queued events are delivered (or the timeout passes). Returns True when drained."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._queue.unfinished_tasks == 0:
                return True
            time.sleep(0.02)
        return self._queue.unfinished_tasks == 0

    def close(self, timeout: float = 2.0) -> None:
        self.flush(timeout)
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout)
        for sink in self.sinks:
            with contextlib.suppress(Exception):
                sink.close()


_pinned: SinkWorker | None = None  # set_worker's, which wins over the settings
_workers: Dict[str, SinkWorker] = {}  # built from the settings, one per Hermes profile (store.profile_key)
_worker_lock = threading.Lock()
_exit_hooked = False


def configure(specs: Any, allow_insecure: bool = False, numbers: List[int] | None = None) -> SinkWorker:
    """A worker for the ``audit_sinks`` entries; unusable ones are skipped (and logged), the rest still load.
    *numbers* give each entry its place in config.yaml, where settings may have dropped some before it."""
    specs = list(specs or [])
    if numbers is None or len(numbers) != len(specs):
        numbers = list(range(len(specs)))
    sinks: List[Sink] = []
    for index, spec in zip(numbers, specs):
        sink = build_sink(spec, allow_insecure, index)
        if sink is not None:
            sinks.append(sink)
    return SinkWorker(sinks)


def _settings_key(settings: Settings) -> str:
    """Digest of what a worker is built from: the full ``audit_sinks`` entries (``Settings.digest`` keeps only their
    count and types), their places in config.yaml and ``allow_insecure_transport``. ``ascii`` rather than JSON,
    which cannot write every key YAML gives (a date) or sort mixed ones (an int beside a str)."""
    built_from = (settings.audit_sinks, settings.audit_sink_numbers, settings.allow_insecure_transport)
    return hashlib.sha256(ascii(built_from).encode("ascii")).hexdigest()


def get_worker() -> SinkWorker:
    """The worker installed with :func:`set_worker`, else the active profile's, built from its settings (on the
    emitting thread, under that profile's secrets) and rebuilt when its ``audit_sinks`` or
    ``allow_insecure_transport`` changes, so turning the opt-in off stops a clear-text sink without a restart. A
    gateway serving several profiles keeps one worker each, rather than one rebuilt at every switch."""
    global _exit_hooked
    with _worker_lock:
        if _pinned is not None:
            return _pinned
    settings = get_settings()
    key, profile = _settings_key(settings), profile_key()
    with _worker_lock:
        if _pinned is not None:
            return _pinned
        old = _workers.get(profile)
        if old is not None and old.settings_key == key:
            return old
        _workers[profile] = worker = configure(
            settings.audit_sinks, settings.allow_insecure_transport, settings.audit_sink_numbers
        )
        worker.settings_key = key
        if not _exit_hooked:  # once per process, however many workers it builds
            atexit.register(_close_all, 2.0)
            _exit_hooked = True
    if old is not None:
        # closing waits for the old queue to drain, and emitting never blocks, so it closes on a thread of its own
        threading.Thread(target=old.close, name="librenms-audit-sinks-close", daemon=True).start()
    return worker


def _close_all(timeout: float) -> None:
    """At exit: let the workers' queues drain for up to *timeout* seconds in all, then stop them."""
    deadline = time.monotonic() + timeout
    with _worker_lock:
        workers = [*_workers.values(), *([_pinned] if _pinned is not None else [])]
    for worker in workers:
        with contextlib.suppress(Exception):
            worker.close(max(0.0, deadline - time.monotonic()))


def set_worker(worker: SinkWorker | None) -> None:
    """Replace (and close) the workers. One given here (the test seam) is kept whatever the settings and the
    profile say; ``None`` (``register``) has the next event build one from them."""
    global _pinned
    with _worker_lock:
        old = [*_workers.values(), *([_pinned] if _pinned is not None else [])]
        _workers.clear()
        _pinned = worker
    for each in old:
        if each is not worker:
            each.close(1.0)


def dispatch(record: Dict[str, Any]) -> None:
    """Hand a record to the sinks; never raises."""
    try:
        get_worker().enqueue(record)
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("librenms audit sink dispatch failed: %s", exc)
