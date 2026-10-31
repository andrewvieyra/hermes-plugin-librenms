"""LibreNMS REST client used by the planner, the executor and ``librenms_query``.

Deliberately small: ``X-Auth-Token`` auth, JSON in/out, LibreNMS's ``{"status": "ok", <key>: ...}`` envelope and
typed errors. Paths are relative to ``/api/v0`` and built by callers from encoded segments (:func:`path`); no
object-model knowledge lives here.

The transport is hardened like the GitLab plugin's: redirects are never followed (``requests`` would carry the
``X-Auth-Token`` header to whatever host ``Location`` names), ``~/.netrc`` and cookies are ignored, bodies are read
to a byte cap, only GETs are retried, and errors carry neither the token nor, for a transport failure, anything
but its kind and an id (the detail goes to the log under that id), or the variable that holds a proxy URL no parser
reads as written.
"""

from __future__ import annotations

import json as jsonlib
import logging
import math
import os
import re
import secrets
import socket
import ssl
import time
import urllib.request
from http.cookiejar import DefaultCookiePolicy
from typing import Any, Callable, Dict, List, Tuple
from urllib.parse import quote, unquote, urljoin, urlsplit

from .redact import clip, cut, scrub_token, scrub_values
from .version import __version__

logger = logging.getLogger(__name__)

API_PREFIX = "api/v0"
# Sent with every request, so LibreNMS's web server logs attribute the traffic to the plugin
USER_AGENT = f"hermes-plugin-librenms/{__version__}"
DEFAULT_TIMEOUT = 30.0
# LIBRENMS_TIMEOUT bounds, in seconds: 0 would make the socket non-blocking, a huge value hangs a tool call
TIMEOUT_RANGE = (0.1, 600.0)
MAX_BYTES = 16 * 2**20
STREAM_CHUNK = 64 * 1024
# An error's body is read to this many bytes: enough for LibreNMS's message, never a whole proxy error page
ERROR_BODY_BYTES = 64 * 1024
GET_RETRIES = 2
_RETRY_STATUSES = frozenset({502, 503, 504})
_BACKOFF_BASE = 0.5
_BACKOFF_CAP = 4.0
_MAX_RETRY_AFTER = 5.0
MAX_CALLS = 200
ROUTE_MISSING = "This API route doesn't exist."
_ENVELOPE_KEYS = frozenset({"status", "message", "count", "total"})
# A 500 from LibreNMS with APP_DEBUG on carries the exception, file paths and SQL with bound values
_DEBUG_KEYS = frozenset({"exception", "file", "line", "trace"})
_WITHHELD = "LibreNMS server error (details withheld; see the LibreNMS log)"
# Laravel reads _method as an HTTP method override; api_token would put a token in a URL
_DROPPED_KEYS = ("_method", "api_token")
# What seg() produces and LibreNMS's literal segments hold: nothing a URL parser or a proxy treats specially
_PATH_RE = re.compile(r"^[A-Za-z0-9_.~%-]+(?:/[A-Za-z0-9_.~%-]+)*$")
_CONTROL_RE = re.compile("[\x00-\x1f\x7f-\x9f\ud800-\udfff]")
_SURROGATE_RE = re.compile("[\ud800-\udfff]")
_KIND_LABELS = {"timeout": "timeout", "tls": "TLS", "dns": "DNS", "refused": "refused", "connection": "connection"}
_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"0", "false", "no", "off"})
# What a LibreNMS API token looks like (a Sanctum <id>|<secret>, or the older 32 hex digits): such a LIBRENMS_URL is
# a token in the wrong variable, and is never quoted back.
_TOKEN_SHAPE = re.compile(r"[0-9A-Fa-f]{32}|\d{1,20}\|[A-Za-z0-9_]{40,}")
# RFC 3986 userinfo: unreserved, percent-encoded and sub-delims characters, and ":" between user and password.
# Anything else in a proxy's user name or password ("@", "/", "?", "#", a space) must be percent-encoded, or the URL
# parser ends the user info, or the whole authority, early and reads part of the password as the host or port.
_USERINFO = re.compile(r"(?:[A-Za-z0-9._~!$&'()*+,;=:-]|%[0-9A-Fa-f]{2})*")
# A proxy's host (a name, an IPv4 address or a bracketed IPv6 one) and port, and at most a closing "/"
_HOSTPORT = re.compile(r"[A-Za-z0-9._\[\]:-]+/?")
_PROXY_FORM = "LIBRENMS_PROXY must be none or an http:// or https:// proxy URL: scheme, host and port only"
_PROXY_USERINFO = (
    "LIBRENMS_PROXY's user name or password holds a character that must be percent-encoded (such as @ / ? # % or "
    "a space: %40 for @, %2F for /, %3F for ?, %23 for #, %25 for %, %20 for a space)"
)
# What ends a URL's authority for urllib3 (a backslash too) or breaks urlsplit's reading of it (a bracket outside an
# IPv6 address). Unencoded in a proxy's user info, the parser takes part of the password for the host or port.
_AUTHORITY_ENDS = re.compile(r"[/?#\\\[\]]")
# Where a parser may split a user info or stop reading it (the delimiters above, ":", "@" and blanks): it quotes the
# piece it read, as urllib3 2.8 quotes "svc:Pr0xy" of "svc:Pr0xy#Pass", and each such piece of a proxy URL no parser
# reads as written is scrubbed too
_USERINFO_SPLITS = re.compile(r"[:@/?#\\\[\]\s]")
_BLANK = re.compile(r"\s")
# Said, to the model and to the log, instead of the parser's error about a proxy URL no parser reads as written
# (that error quotes the piece it could not read, part of the password among it), with what to fix in the part of
# the URL it could not read (:func:`unreadable_part`)
_PROXY_UNREADABLE = "the proxy URL in {name} could not be parsed; {advice}"
_PROXY_ADVICE = {
    "user info": (
        "percent-encode reserved characters in its user name and password (%23 for #, %2F for /, %3F for ?, %5C for "
        "\\, %5B and %5D for [ and ], %40 for @, %25 for %)"
    ),
    "host or port": (
        "its host or port could not be read: give a host (an IPv6 address within [ and ]) and a port that is a number "
        "up to 65535, with no blanks"
    ),
}

Timeout = Tuple[float, float]


def new_error_id() -> str:
    """``err-`` and 12 hex digits: what a result carries, and what the log line with the detail starts with."""
    return f"err-{secrets.token_hex(6)}"


class LibreNMSError(Exception):
    """Any failed LibreNMS request. ``status`` is the HTTP status (0 for transport errors). ``kind`` is ``api``,
    ``auth`` (401), ``forbidden`` (403), ``not_found``, ``route`` (404: this LibreNMS has no such route, or not for
    that method), ``validation`` (422), ``server`` (5xx), ``transport``, ``redirect``, ``too_large``, ``config`` or
    ``invalid`` (a request that could not be built, or an answer that is not LibreNMS's JSON)."""

    KIND = "api"

    def __init__(
        self, message: str, status: int = 0, body: Any = None, method: str = "", path: str = "", kind: str = ""
    ):
        super().__init__(message)
        self.status = status
        self.body = body
        self.method = method
        self.path = path
        self.kind = kind or self.KIND

    def to_dict(self) -> Dict[str, Any]:
        """Structured form for tool results and journals; the body was scrubbed when the error was made. Its text is
        kept as LibreNMS wrote it, cut to 500 characters as escaped (:func:`redact.clip`, :func:`redact.cut`), which
        bounds what the model reads of it."""
        body = self.body
        if isinstance(body, (dict, list)):
            body = clip(body, 500)
        elif body is not None:
            body = cut(str(body), 500) or None
        return {
            "message": str(self),
            "status": self.status,
            "kind": self.kind,
            "method": self.method,
            "path": self.path,
            "body": body,
        }


class ConfigError(LibreNMSError):
    """Missing or unusable LIBRENMS_* settings, or a secret that cannot be read for this profile."""

    KIND = "config"


class TransportError(LibreNMSError):
    """LibreNMS could not be reached, or the request could not be made at all. The message names the kind of
    failure and ``error_id`` only: the URL, the exception text, proxy details and CA paths (which name the OS
    account) go to the log under that id, never to the model. ``failure`` is ``timeout``, ``tls``, ``dns``,
    ``refused``, ``connection``, ``internal`` (a request that could not be made) or ``proxy``: a proxy URL no parser
    reads as written, whose message names the variable that holds it and what to fix, never its value."""

    KIND = "transport"

    def __init__(self, message: str, *, method: str = "", path: str = "", error_id: str = "", failure: str = ""):
        super().__init__(message, method=method, path=path)
        self.error_id = error_id
        self.failure = failure


# -- configuration ------------------------------------------------------------------------------------------------


def secret(name: str) -> str | None:
    """A credential by environment variable name, scoped to the active Hermes profile. Hermes' ``get_secret``
    raises when a multiplexing gateway has no profile bound; falling back to ``os.environ`` then would read another
    profile's LibreNMS URL and token, so that becomes a ConfigError (which never holds a value). Outside Hermes
    (tests, a bare shell) the environment is read."""
    try:
        from agent.secret_scope import get_secret
    except ImportError:
        return os.environ.get(name)
    try:
        return get_secret(name, default=None)
    except Exception as exc:
        raise ConfigError(f"no secret scope is bound for this Hermes profile; cannot read {name}") from exc


def env_file() -> str:
    """Where the active profile's secrets go, as a message may name it: Hermes' own spelling of the profile's home
    (``~/.hermes/.env``, ``~/.hermes/profiles/netops/.env``). A home outside the user's home directory is not
    spelled out, since its path names the OS account and messages reach the model."""
    try:
        from hermes_constants import display_hermes_home  # type: ignore

        shown = str(display_hermes_home())
    except Exception:
        return "<HERMES_HOME>/.env (~/.hermes/.env for the default profile)"
    return f"{shown}/.env" if shown.startswith("~/") else "the .env file in this profile's HERMES_HOME"


def normalise_url(url: str) -> str:
    """``url`` without surrounding blanks, trailing ``/`` or a trailing ``/api/v0``."""
    url = (url or "").strip().rstrip("/")
    if url.endswith(f"/{API_PREFIX}"):
        url = url[: -len(API_PREFIX) - 1].rstrip("/")
    return url


def verify_from_env(value: str | None) -> Any:
    """``LIBRENMS_VERIFY_SSL``: unset or true -> verify; false -> do not; anything else must be the path of a CA
    bundle file or directory that exists. The path is never quoted: messages reach the model, and paths name the OS
    account."""
    text = (value or "").strip()
    if not text or text.lower() in _TRUE:
        return True
    if text.lower() in _FALSE:
        return False
    bundle = os.path.expanduser(text)
    if not os.path.exists(bundle):
        raise ConfigError(
            "LIBRENMS_VERIFY_SSL must be true, false or the path of a CA bundle file or directory that exists"
        )
    return bundle


def timeout_from_env(value: str | None) -> Timeout:
    """``LIBRENMS_TIMEOUT``: seconds to connect and to wait for each read (``30``), or the two apart (``5,60``).
    Anything else, a number outside :data:`TIMEOUT_RANGE` included, is the default: a timeout only bounds a wait,
    so a typo should cost nothing."""
    default = (DEFAULT_TIMEOUT, DEFAULT_TIMEOUT)
    parts = [part.strip() for part in (value or "").split(",")]
    if not (value or "").strip() or len(parts) > 2:
        return default
    try:
        numbers = [float(part) for part in parts]
    except ValueError:
        return default
    low, high = TIMEOUT_RANGE
    if not all(low <= number <= high for number in numbers):  # NaN fails the comparison too
        return default
    return numbers[0], numbers[-1]


def proxy_from_env(value: str | None) -> str | None:
    """``LIBRENMS_PROXY``: unset is ``None`` (the environment's proxy variables apply), ``none`` ignores them, and
    an ``http://`` or ``https://`` URL of a host and port, with a percent-encoded user name and password if any, is
    the proxy for LibreNMS alone (Hermes' model traffic reads the same ``HTTPS_PROXY``; this is how the two part
    ways). Anything else is refused without quoting it: it may hold a proxy password. An unencoded ``#``, ``/`` or
    ``?`` in the password would otherwise pass for the end of the host, and ``requests`` would fail on every call
    with an error that quotes the whole URL, password included, into the log."""
    text = (value or "").strip()
    if not text:
        return None
    if text.lower() == "none":
        return "none"
    scheme, sep, rest = text.partition("://")
    if not sep or scheme.lower() not in ("http", "https"):
        raise ConfigError(_PROXY_FORM)
    userinfo, at, hostport = rest.rpartition("@")
    if at and not _USERINFO.fullmatch(userinfo):
        raise ConfigError(_PROXY_USERINFO)
    if not _HOSTPORT.fullmatch(hostport):
        raise ConfigError(_PROXY_FORM)
    try:
        parts = urlsplit(f"{scheme}://{hostport}")
        host, _port = parts.hostname, parts.port  # .port raises for a port that is not a number up to 65535
    except ValueError:
        host = None
    if not host:
        raise ConfigError(_PROXY_FORM)
    return text


def proxy_secrets(proxy: str | None) -> List[str]:
    """What of a proxy URL (``LIBRENMS_PROXY``, or one from the environment, which may have no scheme) must never
    reach a log line or an error: its user info, and the password (or a user name standing alone, which may be a
    token) as written and percent-decoded. Also, for a proxy URL no parser reads as written (:func:`proxy_unreadable`),
    as a parser that stops at an unencoded delimiter in the password quotes what it read up to there or after it, the
    user info up to each delimiter in the password and each piece of the password between delimiters (``svc:Pr0xy``,
    ``Pr0xy`` and ``Pass`` of ``svc:Pr0xy#Pass``). A proxy URL that reads is never split: no parser stops inside its
    user info, and the pieces of a password such as ``Spring:2026`` would mask every ``2026`` in an error LibreNMS
    sends. The user name beside a password is no secret."""
    if not proxy or proxy == "none":
        return []
    _scheme, sep, rest = proxy.partition("://")
    userinfo, at, _hostport = (rest if sep else proxy).rpartition("@")
    if not at or not userinfo:
        return []
    user, colon, password = userinfo.partition(":")
    credential = password if colon else user
    values = {userinfo, credential, unquote(credential)}
    if proxy_unreadable(proxy):  # every request through it fails, so masking more there hides no answer
        start = len(userinfo) - len(credential)
        values.update(userinfo[: start + found.start()] for found in _USERINFO_SPLITS.finditer(credential))
        values.update(_USERINFO_SPLITS.split(credential))
    return [value for value in values if value]


def unreadable_part(proxy: str) -> str | None:
    """Which part of *proxy* (``LIBRENMS_PROXY``, or one from the environment, which may have no scheme) a URL parser
    reads otherwise than written: ``user info`` when an unencoded ``/``, ``?``, ``#``, backslash or bracket in it ends
    the authority early, so part of the password is read as the host or port (``http://svc:12#34@proxy:3128`` is
    host ``svc``, port 12); ``host or port`` when the authority names no host, holds a blank, or has a port that is
    no number up to 65535. ``None`` when it reads as written."""
    _scheme, sep, rest = proxy.partition("://")
    userinfo, at, hostport = (rest if sep else proxy).rpartition("@")
    if at and _AUTHORITY_ENDS.search(userinfo):
        return "user info"
    authority = re.split(r"[/?#\\]", hostport, maxsplit=1)[0]
    try:
        parts = urlsplit(f"http://{authority}")
        host, _port = parts.hostname, parts.port  # .port raises for a port that is not a number up to 65535
    except ValueError:
        return "host or port"
    # urlsplit drops a tab or a line break and keeps a space in the host; urllib3 refuses all three
    return None if host and not _BLANK.search(authority) else "host or port"


def proxy_unreadable(proxy: str) -> bool:
    """Whether a URL parser reads *proxy* otherwise than written (:func:`unreadable_part`)."""
    return unreadable_part(proxy) is not None


def proxy_bypassed(url: str) -> bool:
    """Whether ``requests`` reaches *url* directly, past the environment's (or the system's) proxy: by ``requests``'
    own reading of ``NO_PROXY``, which also takes a CIDR range (``10.0.0.0/8``) and a ``host:port``, when it can be
    imported (always, once a request has been sent); by ``urllib``'s, which takes neither, otherwise. On macOS it may
    look *url*'s host up."""
    try:
        from requests.utils import should_bypass_proxies
    except ImportError:
        return bool(urllib.request.proxy_bypass(urlsplit(url).hostname or ""))
    return bool(should_bypass_proxies(url, no_proxy=None))


def unreadable_proxy(proxy: str | None, url: str) -> Tuple[str, str] | None:
    """Where the proxy for a request to *url* is set, and that proxy, when no URL parser reads it as written
    (:func:`proxy_unreadable`): ``LIBRENMS_PROXY`` when *proxy* (the client's) is a URL, else the environment's
    variable for the URL's scheme or ``ALL_PROXY``, as ``requests`` picks one (the system proxy settings when no
    variable holds it). ``None`` when the proxy reads, or ``requests`` takes none for *url* (:func:`proxy_bypassed`)."""
    if proxy == "none":
        return None
    if proxy:
        return ("LIBRENMS_PROXY", proxy) if proxy_unreadable(proxy) else None
    try:
        found = urllib.request.getproxies()
        key = next((key for key in (urlsplit(url).scheme, "all") if found.get(key)), None)
        # the bypass check last: on macOS it may look LibreNMS's host up
        if key is None or not proxy_unreadable(found[key]) or proxy_bypassed(url):
            return None
    except Exception:  # pragma: no cover - the system's proxy settings could not be read
        return None
    value = found[key]
    # urllib reads https_proxy over HTTPS_PROXY, and the lower-case name sorts last
    names = sorted(name for name in os.environ if name.lower() == f"{key}_proxy" and os.environ[name] == value)
    return (names[-1] if names else "the system proxy settings"), value


def environment_proxy_secrets(url: str) -> List[str]:
    """:func:`proxy_secrets` of the proxies ``requests`` may take from the environment for *url* when
    ``LIBRENMS_PROXY`` is unset: the one for its scheme (``HTTPS_PROXY`` or ``HTTP_PROXY``) and ``ALL_PROXY``.
    Nothing validates those (Hermes' model traffic reads them too), and a malformed one fails every request with
    an error that quotes it whole, password included."""
    try:
        found = urllib.request.getproxies()
    except Exception:  # pragma: no cover - the system's proxy settings could not be read
        return []
    return [secret for key in (urlsplit(url).scheme, "all") for secret in proxy_secrets(found.get(key))]


def insecure_transport(url: str, verify: Any) -> List[str]:
    """What makes a connection to *url* with *verify* readable or forgeable on the network, one clause each;
    empty for ``https://`` with the certificate checked."""
    problems = []
    if urlsplit(url).scheme == "http":
        problems.append("LIBRENMS_URL is http://, so the token and every answer cross the network in clear text")
    if verify is False:
        problems.append(
            "LIBRENMS_VERIFY_SSL is false, so LibreNMS's certificate is not checked and anyone on the path can "
            "read the token"
        )
    return problems


def settings_from_env(env: Dict[str, str] | None = None, *, allow_insecure: bool = False) -> Dict[str, Any]:
    """Connection settings from *env*, or through :func:`secret` when it is ``None``. Raises ConfigError when they
    are incomplete or unusable, and for clear-text or unverified transport unless *allow_insecure* (the
    ``allow_insecure_transport`` setting, which lives in config.yaml so one line in ``.env`` cannot turn it on)."""
    read = secret if env is None else env.get
    url = normalise_url(read("LIBRENMS_URL") or "")
    token = (read("LIBRENMS_TOKEN") or "").strip()
    if not url or not token:
        raise ConfigError(f"LIBRENMS_URL and LIBRENMS_TOKEN must both be set (put them in {env_file()})")
    # No message below quotes the value: it reaches the model, and a URL in the wrong shape may be the token itself
    # (the two variables swapped) or carry one in a query string.
    if _TOKEN_SHAPE.fullmatch(url):
        raise ConfigError(
            "LIBRENMS_URL looks like an API token, not a URL; are LIBRENMS_URL and LIBRENMS_TOKEN swapped?"
        )
    if "@" in url:
        # what precedes the @ is a user name and password
        raise ConfigError(
            "LIBRENMS_URL holds an @, as a user name and password before the host do; they are never needed "
            "(the token authenticates), so take them out of LIBRENMS_URL"
        )
    try:
        parts = urlsplit(url)
        host = parts.hostname
    except ValueError:
        raise ConfigError("LIBRENMS_URL cannot be read as a URL, e.g. https://librenms.example.com") from None
    if parts.scheme not in ("http", "https"):
        raise ConfigError("LIBRENMS_URL must start with http:// or https://, e.g. https://librenms.example.com")
    if not host:
        raise ConfigError("LIBRENMS_URL must name a host after http:// or https://, e.g. https://librenms.example.com")
    if "?" in url or "#" in url:
        raise ConfigError("LIBRENMS_URL must not hold a query string or a fragment")
    verify = verify_from_env(read("LIBRENMS_VERIFY_SSL"))
    problems = insecure_transport(url, verify)
    if problems and not allow_insecure:
        raise ConfigError(
            f"{'; '.join(problems)}. Refused: use https:// with certificate checks (LIBRENMS_VERIFY_SSL may name a "
            "CA bundle), or set allow_insecure_transport: true in config.yaml to permit it"
        )
    return {
        "url": url,
        "token": token,
        "verify": verify,
        "timeout": timeout_from_env(read("LIBRENMS_TIMEOUT")),
        "proxy": proxy_from_env(read("LIBRENMS_PROXY")),
    }


def is_configured(env: Dict[str, str] | None = None) -> bool:
    """Whether LIBRENMS_URL and LIBRENMS_TOKEN are both set (the tools' ``check_fn``). Transport problems leave the
    tools visible, so each call fails naming the setting to fix."""
    read = secret if env is None else env.get
    try:
        return bool((read("LIBRENMS_URL") or "").strip() and (read("LIBRENMS_TOKEN") or "").strip())
    except LibreNMSError:
        return False


# -- paths --------------------------------------------------------------------------------------------------------


def seg(value: Any) -> str:
    """One path segment, percent-encoded with nothing left as is (``/`` becomes ``%2F``). Refuses ``None``, booleans,
    empty, ``.`` and ``..`` segments and control characters, which no LibreNMS name holds and which would let a
    value from the model change which route is called."""
    text = "" if value is None or isinstance(value, bool) else str(value)
    if text in ("", ".", "..") or _CONTROL_RE.search(text):
        raise LibreNMSError(
            f"invalid path segment {str(value)[:100]!r}: it must not be empty, '.' or '..', nor hold control "
            "characters",
            kind="invalid",
        )
    return quote(text, safe="")


def is_digits(value: Any) -> bool:
    """Whether *value* is a non-negative int or one or more ASCII digits: the only spelling of an id. ``str.isdigit``
    also takes superscript digits, which ``int`` rejects, and other scripts' digits, which ``int`` reads."""
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return value >= 0
    return isinstance(value, str) and value.isascii() and value.isdigit()


def json_object(value: Any) -> Dict[str, Any] | None:
    """A JSON object column as LibreNMS may return it (decoded, or still a JSON string, as an alert rule's ``extra``
    and ``builder``), else None."""
    if isinstance(value, str):
        try:
            value = jsonlib.loads(value)
        except ValueError:
            return None
    return dict(value) if isinstance(value, dict) else None


def path(*segments: Any) -> str:
    """``devices/sw%201/ports`` from ``("devices", "sw 1", "ports")``, each segment through :func:`seg`."""
    return "/".join(seg(segment) for segment in segments)


def _checked_path(method: str, value: Any) -> str:
    """*value* when it is a path :meth:`LibreNMSClient.request` may send: empty (the index) or encoded segments, with
    no scheme, host, query, fragment, empty or dot segment, also once a proxy has decoded it (up to three times).
    Nor may a segment hold an encoded ``/``: Laravel decodes the path before it matches routes, so
    ``devices/1%2Fdiscover`` would reach the GET that schedules a rediscovery."""
    text = value.strip() if isinstance(value, str) else None
    if text is None or (text and not _PATH_RE.match(text)):
        raise LibreNMSError(
            f"invalid API path {str(value)[:200]!r}: build it from encoded segments relative to /{API_PREFIX}",
            method=method,
            kind="invalid",
        )
    for segment in text.split("/") if text else ():
        decoded = segment
        for _ in range(3):
            decoded = unquote(decoded)
        if "/" in decoded:
            raise LibreNMSError(
                f"invalid API path {text[:200]!r}: a segment holds an encoded '/', which LibreNMS would read as "
                "another route",
                method=method,
                path=text,
                kind="invalid",
            )
        if decoded in (".", "..") or any(char in decoded for char in "?#\\"):
            raise LibreNMSError(f"invalid API path {text[:200]!r}", method=method, path=text, kind="invalid")
    return text


def _shown(path_: str) -> str:
    return f"/{API_PREFIX}/{path_}" if path_ else f"/{API_PREFIX}"


def _without_dropped(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: item for key, item in value.items() if key not in _DROPPED_KEYS}
    return value


def _check_params(method: str, path_: str, params: Dict[str, Any] | None) -> None:
    """Refuse a query ``requests`` cannot encode (a lone surrogate, which JSON can carry) before anything is sent,
    so the failure is not mistaken for a request that may have reached LibreNMS."""
    for key, value in (params or {}).items():
        for item in [key, *(value if isinstance(value, (list, tuple)) else [value])]:
            if isinstance(item, str) and _SURROGATE_RE.search(item):
                raise LibreNMSError(
                    f"params.{str(key)[:100]!r} holds a lone surrogate, which cannot be URL-encoded",
                    method=method,
                    path=path_,
                    kind="invalid",
                )


# -- transport failures -------------------------------------------------------------------------------------------


def _causes(exc: BaseException) -> List[BaseException]:
    """*exc* and every exception it wraps: ``requests`` wraps urllib3's, which name the socket error as their cause,
    context or ``reason``, or hold it in their arguments."""
    found: List[BaseException] = []
    stack = [exc]
    while stack:
        error = stack.pop()
        if any(error is seen for seen in found):
            continue
        found.append(error)
        linked = (error.__cause__, error.__context__, getattr(error, "reason", None), *getattr(error, "args", ()))
        stack.extend(item for item in linked if isinstance(item, BaseException))
    return found


def _names(chain: List[BaseException]) -> set:
    return {cls.__name__ for error in chain for cls in type(error).__mro__}


def transport_kind(exc: BaseException) -> str:
    """``tls``, ``dns``, ``refused``, ``timeout`` or ``connection`` (anything else), from the socket and TLS errors at
    the root and the class names ``requests`` uses, without importing it. ``TimeoutError`` alone is not enough:
    urllib3 derives a refused connection from its connect-timeout class."""
    chain = _causes(exc)
    names = _names(chain)
    if "SSLError" in names or any(isinstance(error, ssl.SSLError) for error in chain):
        return "tls"
    if "NameResolutionError" in names or any(isinstance(error, socket.gaierror) for error in chain):
        return "dns"
    if any(isinstance(error, ConnectionRefusedError) for error in chain):
        return "refused"
    if "Timeout" in names or any(isinstance(error, TimeoutError) for error in chain):
        return "timeout"
    return "connection"


# What requests raises when LibreNMS could not be reached or its answer broke off on the way; its other errors
# (an invalid URL or header, a body that is not JSON) derive from OSError too but are about the request itself.
_UNREACHABLE = frozenset({"ConnectionError", "Timeout", "ChunkedEncodingError", "ContentDecodingError"})


def _unreachable(exc: BaseException) -> bool:
    """Whether *exc* means LibreNMS could not be reached, as opposed to a request that could not be made."""
    chain = _causes(exc)
    names = _names(chain)
    if "RequestException" in names:
        return bool(names & _UNREACHABLE)
    return any(isinstance(error, OSError) for error in chain)


def _retryable(exc: BaseException) -> bool:
    """Whether a GET that failed with *exc* may be tried again: the connection failed (refused, no address, a reset,
    a connect timeout). A certificate that failed stays failed, and a read that timed out may be a slow query that
    another try would only load LibreNMS with again."""
    if not _unreachable(exc):
        return False
    kind = transport_kind(exc)
    if kind in ("refused", "dns"):
        return True
    return "ConnectTimeout" in _names(_causes(exc)) or kind == "connection"


# -- answers ------------------------------------------------------------------------------------------------------


class _NoNetrc:
    """``Session.auth`` that adds nothing. With no auth on the session, ``requests`` reads ``~/.netrc`` and sends the
    password it finds for LibreNMS's host as ``Authorization: Basic`` next to the token; with any auth set it never
    looks. ``trust_env`` stays on, so ``REQUESTS_CA_BUNDLE`` and the proxy variables still apply."""

    def __call__(self, request: Any) -> Any:
        return request


def _request_proxies(proxy: str | None) -> Dict[str, Any] | None:
    """The ``proxies`` for one request (a fresh mapping: ``requests`` adds to it). They go with each request
    because ``requests`` lets the environment's proxies override a session's. ``None`` for a key drops the
    environment's proxy for it."""
    if proxy is None:
        return None
    if proxy == "none":
        return {"http": None, "https": None, "all": None}
    return {"http": proxy, "https": proxy}


def _headers(resp: Any) -> Dict[str, str]:
    items = getattr(getattr(resp, "headers", None) or {}, "items", None)
    return {str(key).lower(): str(value) for key, value in (items() if items else ())}


def _seconds(value: str | None) -> float | None:
    """A header's number of seconds; ``None`` when absent or not a finite number (an HTTP date)."""
    try:
        number = float(value) if value is not None else None
    except ValueError:
        return None
    return number if number is not None and math.isfinite(number) else None


def _capped_wait(seconds: float) -> float:
    return max(0.0, min(seconds, _MAX_RETRY_AFTER))


def _backoff(retry: int) -> float:
    return min(_BACKOFF_CAP, _BACKOFF_BASE * 2**retry)


def _read_capped(resp: Any, limit: int) -> Tuple[bytes, bool]:
    """At most *limit* bytes of a streamed body and whether more followed, reading no further than the chunk that
    holds the byte after *limit*: however large the answer, no more than that is read or held."""
    chunks: List[bytes] = []
    size = 0
    for chunk in resp.iter_content(chunk_size=min(STREAM_CHUNK, limit + 1)):
        chunks.append(chunk)
        size += len(chunk)
        if size > limit:
            break
    return b"".join(chunks)[:limit], size > limit


def _location(raw: str | None, url: str) -> str:
    """Where a redirect points, fit to quote: absolute, without user info, query or fragment (which may hold
    credentials or a token), and cut before ``/api/v0`` so it reads as the value for LIBRENMS_URL."""
    if not raw:
        return "an address it did not name"
    try:
        target = urlsplit(urljoin(url, raw.strip()))
        host = target.hostname or ""
        port = f":{target.port}" if target.port else ""
    except ValueError:
        return "an address that could not be parsed"
    if target.scheme not in ("http", "https") or not host:
        return "an address that is not an http:// or https:// URL"
    where = target.path.find(f"/{API_PREFIX}")
    base_path = (target.path[:where] if where >= 0 else target.path).rstrip("/")
    host = f"[{host}]" if ":" in host else host
    return f"{target.scheme}://{host}{port}{base_path}"[:300]


def _summary(body: Any) -> str:
    """One line from LibreNMS's error shapes: ``{"message": "..."}``, a 422 ``{"message": {field: [...]}}``, or text;
    at most 400 characters as escaped (:func:`redact.cut`), and raw still, so a step's secrets can be scrubbed from
    it."""
    if isinstance(body, dict):
        message = body.get("message")
        if isinstance(message, dict):
            text = "; ".join(
                f"{key}: {', '.join(map(str, value)) if isinstance(value, list) else value}"
                for key, value in message.items()
            )
        elif message is not None:
            text = str(message)
        else:
            text = jsonlib.dumps(body, ensure_ascii=False, default=str)
    elif isinstance(body, list):
        text = "; ".join(map(str, body))
    else:
        text = " ".join(str(body or "").split())
    return cut(text, 400)


def _withheld(body: Any) -> bool:
    """Whether a 5xx says more than it should: anything but LibreNMS's own ``{status: error, message}`` envelope (a
    framework error, a debug trace, a proxy page), or one that quotes SQL anywhere, which carries bound values."""
    if not (isinstance(body, dict) and body.get("status") == "error" and "message" in body):
        return True
    text = jsonlib.dumps({key: value for key, value in body.items() if key not in _DEBUG_KEYS}, default=str)
    return "SQLSTATE" in text or "SQL:" in text


def _pair(timeout: Any) -> Timeout:
    if isinstance(timeout, (tuple, list)):
        return float(timeout[0]), float(timeout[-1])
    return float(timeout), float(timeout)


class LibreNMSClient:
    """``session`` is anything with ``request(method, url, params=, data=, headers=, timeout=, verify=,
    allow_redirects=, stream=, proxies=)`` returning a response with ``status_code``, ``headers``,
    ``iter_content(chunk_size)`` and ``close()``: a ``requests.Session`` made on first use in production, a fake in
    tests. ``retry_sleep`` waits between tries of a GET (tests make it a no-op).

    ``last_call`` is the last try made (``method``, ``path`` as ``/api/v0/<path>``, ``status``, ``duration_ms``) and
    ``calls`` every try since :meth:`reset_calls`, the latest :data:`MAX_CALLS`; neither holds params or bodies.
    ``last_date`` is the ``Date`` header of the last answer that had one: LibreNMS's clock, which a report states its
    data as of."""

    def __init__(
        self,
        url: str,
        token: str,
        *,
        verify: Any = True,
        timeout: Any = (10.0, 60.0),
        proxy: str | None = None,
        session: Any = None,
    ):
        self.base_url = normalise_url(url)
        self.verify = verify
        self.timeout = _pair(timeout)
        self.proxy = proxy
        self._token = (token or "").strip()
        # made per call, so the environment's proxy is read as requests will read it for this client's requests
        self._proxy_secrets = proxy_secrets(proxy) if proxy is not None else environment_proxy_secrets(self.base_url)
        self._session = session
        self.retry_sleep: Callable[[float], None] = time.sleep
        self.last_call: Dict[str, Any] = {}
        self.calls: List[Dict[str, Any]] = []
        self.last_date: str | None = None

    @classmethod
    def from_env(
        cls, env: Dict[str, str] | None = None, session: Any = None, *, allow_insecure: bool = False
    ) -> LibreNMSClient:
        """A client from LIBRENMS_URL, LIBRENMS_TOKEN, LIBRENMS_VERIFY_SSL, LIBRENMS_TIMEOUT and LIBRENMS_PROXY; see
        :func:`settings_from_env` for *allow_insecure*."""
        s = settings_from_env(env, allow_insecure=allow_insecure)
        return cls(s["url"], s["token"], verify=s["verify"], timeout=s["timeout"], proxy=s["proxy"], session=session)

    def posture(self) -> Dict[str, str]:
        """How this client reaches LibreNMS, for status: ``scheme``; ``verify`` (``on``, ``off`` or ``custom CA``);
        ``proxy`` (``LIBRENMS_PROXY``, ``ignored``, ``environment`` or ``none``). It names no host, path or proxy
        address: the model reads it, and a CA path names the OS account."""
        if self.verify is False:
            verify = "off"
        elif isinstance(self.verify, str) or os.environ.get("REQUESTS_CA_BUNDLE") or os.environ.get("CURL_CA_BUNDLE"):
            verify = "custom CA"
        else:
            verify = "on"
        target = urlsplit(self.base_url)
        if self.proxy == "none":
            via = "ignored"
        elif self.proxy:
            via = "LIBRENMS_PROXY"
        else:
            found = urllib.request.getproxies()
            applies = target.scheme in found or "all" in found
            via = "environment" if applies and not proxy_bypassed(self.base_url) else "none"
        return {"scheme": target.scheme, "verify": verify, "proxy": via}

    def scrub(self, text: Any) -> str:
        """*text* without the token or the proxy's credentials (``LIBRENMS_PROXY``'s, or with it unset the
        environment's proxy for LibreNMS): defence in depth for error messages, bodies and log lines (Hermes' log
        redaction does not recognise either)."""
        return scrub_values(scrub_token(text, self._token), self._proxy_secrets)

    def _scrub_obj(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.scrub(value)
        if isinstance(value, dict):
            return {key: self._scrub_obj(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self._scrub_obj(item) for item in value]
        return value

    def reset_calls(self) -> List[Dict[str, Any]]:
        """The tries recorded since the last reset, oldest first; the record starts empty again."""
        calls, self.calls = self.calls, []
        return calls

    # -- low level --------------------------------------------------------------------------------------------------
    def _url(self, path_: str) -> str:
        return f"{self.base_url}{_shown(path_)}"

    def _session_for(self) -> Any:
        if self._session is None:
            import requests  # imported lazily so plugin registration never needs network libs

            session = requests.Session()
            session.auth = _NoNetrc()
            session.cookies.set_policy(DefaultCookiePolicy(allowed_domains=[]))
            self._session = session
        return self._session

    def request(
        self,
        method: str,
        path: str,
        *,
        params: Dict[str, Any] | None = None,
        json: Any = None,
        max_bytes: int = MAX_BYTES,
        timeout: Any = None,
    ) -> Any:
        """One HTTP call; returns the parsed JSON body (``None`` for an empty one) and raises LibreNMSError for
        anything else. A GET is tried again up to :data:`GET_RETRIES` times when the connection fails or LibreNMS
        (or its proxy) answers 502, 503 or 504, and once after a 429, waiting ``Retry-After`` (at most 5 s) or a
        back-off of 0.5 s doubling to 4 s. Nothing else is retried, so a write is never sent twice. *timeout*
        ``(connect, read)`` overrides the client's for this call (a device add probes for tens of seconds)."""
        method = str(method).upper()
        path = _checked_path(method, path)
        params = _without_dropped(params)
        _check_params(method, path, params)
        body = _without_dropped(json)
        data = None if body is None else jsonlib.dumps(body)
        retries, rate_limited = 0, False
        while True:
            started = time.monotonic()
            try:
                resp = self._send(method, path, params, data, timeout)
            except Exception as exc:  # transport failure (DNS, TLS, refused, timeout), or a request not made
                self._record(method, path, 0, started)
                # a proxy URL no parser reads as written fails every try alike (on parsing it, or on a host read
                # from its password); an exception of another class is a bug, not the proxy
                bad_proxy = None
                if isinstance(exc, (OSError, ValueError)):
                    bad_proxy = unreadable_proxy(self.proxy, self.base_url)
                if method == "GET" and retries < GET_RETRIES and not bad_proxy and _retryable(exc):
                    self.retry_sleep(_backoff(retries))
                    retries += 1
                    continue
                raise self._transport_error(method, path, exc, bad_proxy=bad_proxy) from exc
            try:
                status = int(getattr(resp, "status_code", 0) or 0)
                headers = _headers(resp)
                self._record(method, path, status, started)
                self.last_date = headers.get("date") or self.last_date
                wait = _seconds(headers.get("retry-after"))
                if method == "GET" and status == 429 and not rate_limited:
                    rate_limited = True
                    self.retry_sleep(_capped_wait(1.0 if wait is None else wait))
                    continue
                if method == "GET" and status in _RETRY_STATUSES and retries < GET_RETRIES:
                    self.retry_sleep(_backoff(retries) if wait is None else _capped_wait(wait))
                    retries += 1
                    continue
                return self._answer(resp, status, headers, method, path, max_bytes)
            finally:
                resp.close()  # a streamed answer holds its connection until it is closed

    def _send(self, method: str, path_: str, params: Dict[str, Any] | None, data: str | None, timeout: Any) -> Any:
        headers = {
            "X-Auth-Token": self._token,
            "Accept": "application/json",
            # always: edit_location reads its body only when the request says it is JSON
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
            # urllib3 1.x decompresses each streamed chunk whole, so a small compressed chunk could pass any cap
            "Accept-Encoding": "identity",
        }
        return self._session_for().request(
            method,
            self._url(path_),
            params=params or None,
            data=data,
            headers=headers,
            timeout=self.timeout if timeout is None else _pair(timeout),
            verify=self.verify,
            allow_redirects=False,  # never carry X-Auth-Token to another host
            stream=True,
            proxies=_request_proxies(self.proxy),
        )

    def _record(self, method: str, path_: str, status: int, started: float) -> None:
        self.last_call = {
            "method": method,
            "path": _shown(path_),
            "status": status,
            "duration_ms": round((time.monotonic() - started) * 1000),
        }
        self.calls.append(dict(self.last_call))
        if len(self.calls) > MAX_CALLS:
            del self.calls[: len(self.calls) - MAX_CALLS]

    def _transport_error(
        self, method: str, path_: str, exc: BaseException, *, bad_proxy: Tuple[str, str] | None = None
    ) -> TransportError:
        """The error for a request that failed on its way (or while its body was read); the detail is logged under
        its id, never returned. *bad_proxy* is where a proxy URL no parser reads as written is set, and that URL
        (:func:`unreadable_proxy`): then the error and the log say so in fixed words, with what to fix in the part the
        parser could not read. The exception's text quotes that part: for a URL with a user name or password, which
        may be among it, it goes nowhere; for one without, it is logged too, as it says what is wrong."""
        error_id = new_error_id()
        if bad_proxy:
            name, proxy = bad_proxy
            advice = _PROXY_ADVICE[unreadable_part(proxy) or "user info"]
            failure, said = "proxy", _PROXY_UNREADABLE.format(name=name, advice=advice)
            message = f"the request to LibreNMS could not be made: {said} {error_id}"
            detail = f"{type(exc).__name__}: {said}"
            if not proxy_secrets(proxy):
                detail += f" ({self.scrub(str(exc))})"
        else:
            failure = transport_kind(exc) if _unreachable(exc) else "internal"
            if failure == "internal":
                message = f"the request to LibreNMS could not be made (internal error) {error_id}"
            else:
                message = f"could not reach LibreNMS ({_KIND_LABELS[failure]}) {error_id}"
            detail = self.scrub(f"{type(exc).__name__}: {exc}")
        logger.warning("librenms %s: %s %s failed (%s): %s", error_id, method, self._url(path_), failure, detail)
        return TransportError(message, method=method, path=path_, error_id=error_id, failure=failure)

    def _answer(self, resp: Any, status: int, headers: Dict[str, str], method: str, path_: str, max_bytes: int) -> Any:
        """The parsed body of a final answer, or the LibreNMSError it stands for."""
        if 300 <= status < 400:
            where = _location(headers.get("location"), self._url(path_))
            raise LibreNMSError(
                self.scrub(
                    f"LibreNMS answered with a redirect (HTTP {status}) to {where}; set LIBRENMS_URL to that address"
                ),
                status=status,
                method=method,
                path=path_,
                kind="redirect",
            )
        try:
            raw, more = _read_capped(resp, max_bytes if status < 300 else ERROR_BODY_BYTES)
        except Exception as exc:
            raise self._transport_error(method, path_, exc) from exc
        if more and status < 300:
            raise LibreNMSError(
                f"{method} {_shown(path_)} -> HTTP {status}: the answer is larger than {max_bytes} bytes and was not "
                "read; narrow the query",
                status=status,
                method=method,
                path=path_,
                kind="too_large",
            )
        text = raw.decode("utf-8", "replace")
        parsed = True
        body: Any = None
        if text.strip():
            try:
                body = jsonlib.loads(text)
            except ValueError:
                body, parsed = text, False
        if status >= 400 or (isinstance(body, dict) and body.get("status") == "error"):
            raise self._error(method, path_, status, body)
        if not parsed:  # graphs are never requested; an HTML page is a proxy or PHP answering instead of the API
            raise LibreNMSError(
                f"{method} {_shown(path_)} -> HTTP {status}: LibreNMS did not answer with JSON",
                status=status,
                method=method,
                path=path_,
                kind="invalid",
            )
        return body

    def _error(self, method: str, path_: str, status: int, body: Any) -> LibreNMSError:
        """The error for an answer that says the request failed, classified by status and LibreNMS's message."""
        if status == 401:
            return LibreNMSError(
                "LibreNMS rejected the token (HTTP 401); check LIBRENMS_TOKEN, that it has not expired and that "
                "its user is enabled",
                status=status,
                body=self._scrub_obj(body),
                method=method,
                path=path_,
                kind="auth",
            )
        if status == 404 and not (isinstance(body, dict) and "message" in body):
            # LibreNMS answers every 404 under /api/v0 with JSON (its catch-all route included); a page that is not
            # is a web server or proxy answering for a path LibreNMS never saw, so it says nothing about the object
            return LibreNMSError(
                f"{method} {_shown(path_)} -> HTTP 404 that did not come from LibreNMS (not its JSON); check "
                "LIBRENMS_URL, including any sub-path LibreNMS is served under",
                status=status,
                method=method,
                path=path_,
                kind="invalid",
            )
        summary = _summary(body)
        if status == 403:
            kind = "forbidden"
        elif status == 404:
            kind = "route" if summary.strip() == ROUTE_MISSING else "not_found"
        elif status == 422:
            kind = "validation"
        elif status >= 500:
            kind = "server"
            if _withheld(body):
                summary, body = _WITHHELD, None
            else:
                body = {key: value for key, value in body.items() if key not in _DEBUG_KEYS}
        else:
            kind = "api"
        return LibreNMSError(
            self.scrub(f"{method} {_shown(path_)} -> HTTP {status}: {summary}"),
            status=status,
            body=self._scrub_obj(body),
            method=method,
            path=path_,
            kind=kind,
        )

    # -- convenience ------------------------------------------------------------------------------------------------
    def get(self, path: str, params: Dict[str, Any] | None = None) -> Any:
        """``GET`` *path*: the envelope dict (or, for the few routes outside it, the bare list or map)."""
        return self.request("GET", path, params=params)

    def get_or_none(self, path: str, params: Dict[str, Any] | None = None) -> Any:
        """:meth:`get`, or ``None`` when LibreNMS says the object does not exist. A 404 for a route this LibreNMS
        does not have, or one that did not come from LibreNMS at all, is still an error: it is no answer about the
        object."""
        try:
            return self.get(path, params)
        except LibreNMSError as exc:
            if exc.kind == "not_found":
                return None
            raise

    def system(self) -> Dict[str, Any]:
        """``GET system``: ``local_ver``, ``local_sha``, ``db_schema`` and the other version fields, or ``{}``."""
        rows = self.result(self.get("system"), "system")
        return rows[0] if isinstance(rows, list) and rows and isinstance(rows[0], dict) else {}

    @staticmethod
    def result(body: Any, key: str | None = None) -> Any:
        """What an envelope carries: ``body[key]``, or without *key* the first entry that is not ``status``,
        ``message``, ``count`` or ``total``. A body that is no envelope (a bare list) is returned as it is."""
        if not isinstance(body, dict):
            return body
        if key is not None:
            return body.get(key)
        return next((value for name, value in body.items() if name not in _ENVELOPE_KEYS), None)
