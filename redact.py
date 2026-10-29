"""Keep secrets and terminal tricks out of what the model and the operator read.

LibreNMS hands credentials back in ordinary reads: an admin token gets SNMP communities and v3 passwords in clear
in every device object, and service objects carry Nagios check arguments (``-p <password>``). Free text comes from
devices, syslog senders and LLDP neighbours, so it is clipped for the model and escaped for terminals.

- :func:`mask` replaces every value under a credential key, at any depth.
- :func:`scrub_text` removes the token, given secret values and ``key: value`` pairs from free text (error messages);
  :func:`scrub_values` removes given secret values only, and :func:`holds_any` says whether it would.
- :func:`clip` bounds long strings; :func:`for_model` is ``clip(mask(obj))``, applied to everything from LibreNMS.
- :func:`printable` escapes what a terminal would act on instead of showing; :func:`one_line` also escapes newlines
  and tabs, for a value shown inside one line.
"""

from __future__ import annotations

import re
from typing import Any, Iterable
from urllib.parse import quote

SECRET_KEYS = frozenset(
    {
        "community",
        "authpass",
        "cryptopass",
        "authname",
        "password",
        "passwd",
        "secret",
        "token",
        "api_token",
        "x-auth-token",
        "authorization",
        "service_param",
        "param",
        "ospfifauthkey",
        "auth_key",
        "authkey",
        "psk",
        "key",
    }
)
MASK = "<redacted>"
TOKEN_MASK = "<token>"
# The API token is long; a shorter configured value is not one, and replacing it would garble ordinary text.
_MIN_TOKEN = 8
# Secret values passed to scrub_text (SNMP credentials, service params) shorter than this are replaced only where
# they stand alone: inside a longer word or number they would match all over a message (a community "pub" in
# "public"), but a short community is still a credential.
_MIN_EXTRA = 4
_WORD_CHAR = "A-Za-z0-9"

_KEY_ALTERNATION = "|".join(re.escape(key) for key in sorted(SECRET_KEYS, key=len, reverse=True))
# `"community": "public"`, `community=public`, `'authpass': 'x'`: the key (optionally quoted), then the value
# (a double- or single-quoted string with escapes, or a bare word) is masked; the key stays so the text still reads.
_PAIR_RE = re.compile(
    rf"""(?<![\w-])(?P<q>["']?)(?P<key>{_KEY_ALTERNATION})(?P=q)(?P<sep>\s*[:=]\s*)"""
    r"""(?P<value>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^\s,;&}\]"']+)""",
    re.IGNORECASE,
)
_BEARER_RE = re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=|-]+")
_EMPTY_VALUES = ('""', "''", "null")

# What a terminal acts on instead of showing: C0 controls but newline and tab, DEL and the C1 controls (ESC starts
# a colour or cursor sequence, CR returns to the start of the line), the line and paragraph separators, the
# bidirectional controls that reorder what is shown, and lone surrogates, which cannot be encoded at all.
_TERMINAL_RE = re.compile(
    "[\x00-\x08\x0b-\x1f\x7f-\x9f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069\ud800-\udfff]"
)


def _is_empty(value: Any) -> bool:
    return value is None or (isinstance(value, (str, list, tuple, dict)) and len(value) == 0)


def mask(obj: Any, *, keys: Iterable[str] = SECRET_KEYS) -> Any:
    """A deep copy of *obj* where every non-empty value under a credential key (compared lowercased) is
    :data:`MASK`. ``None`` and empty values stay, so the model can still tell "not set" from "set"."""
    return _mask(obj, frozenset(str(key).lower() for key in keys))


def _mask(obj: Any, keys: frozenset) -> Any:
    if isinstance(obj, dict):
        return {
            key: (MASK if str(key).lower() in keys and not _is_empty(value) else _mask(value, keys))
            for key, value in obj.items()
        }
    if isinstance(obj, list):
        return [_mask(item, keys) for item in obj]
    if isinstance(obj, tuple):
        return tuple(_mask(item, keys) for item in obj)
    return obj


def _masked_pair(match: re.Match[str]) -> str:
    value = match.group("value")
    if value.lower() in _EMPTY_VALUES:
        return match.group(0)
    shown = f'"{MASK}"' if value.startswith('"') else (f"'{MASK}'" if value.startswith("'") else MASK)
    return f"{match.group('q')}{match.group('key')}{match.group('q')}{match.group('sep')}{shown}"


def scrub_token(text: Any, token: str | None) -> str:
    """*text* with the API *token* (8+ characters), as it is and URL-encoded, replaced by ``<token>``."""
    text = "" if text is None else str(text)
    if token and len(token) >= _MIN_TOKEN:
        for form in {token, quote(token, safe="")}:
            text = text.replace(form, TOKEN_MASK)
    return text


def _value_re(value: str) -> re.Pattern[str]:
    """Where *value* stands in a text: anywhere for 4+ characters, else only where no letter or digit touches it."""
    if len(value) >= _MIN_EXTRA:
        return re.compile(re.escape(value))
    return re.compile(rf"(?<![{_WORD_CHAR}]){re.escape(value)}(?![{_WORD_CHAR}])")


def _values(extra: Iterable[Any]) -> list:
    """The non-empty strings of *extra*, longest first: a value that holds another is replaced first, whole."""
    return sorted({value for value in extra if isinstance(value, str) and value}, key=len, reverse=True)


def scrub_values(text: Any, extra: Iterable[Any]) -> str:
    """*text* with every string in *extra* replaced by :data:`MASK`; one shorter than 4 characters only where it
    stands alone (see :data:`_MIN_EXTRA`)."""
    text = "" if text is None else str(text)
    for value in _values(extra):
        text = _value_re(value).sub(MASK, text)
    return text


def holds_any(text: Any, extra: Iterable[Any]) -> bool:
    """Whether :func:`scrub_values` would replace anything of *extra* in *text*."""
    text = "" if text is None else str(text)
    return any(_value_re(value).search(text) for value in _values(extra))


def scrub_text(text: Any, token: str | None = None, extra: Iterable[Any] = ()) -> str:
    """:func:`scrub_token`, then every string in *extra* (a step's resolved SNMP credentials, old and new service
    params) replaced by :data:`MASK` as :func:`scrub_values` does, bearer credentials, and the values of
    ``key: value`` / ``"key": "value"`` pairs whose key is a credential key."""
    text = scrub_values(scrub_token(text, token), extra)
    text = _BEARER_RE.sub(rf"\g<1>{MASK}", text)
    return _PAIR_RE.sub(_masked_pair, text)


def clip(value: Any, limit: int = 2000) -> Any:
    """A copy of *value* with every string longer than *limit* cut, saying so (``… [truncated N chars]``) rather
    than silently. Dict keys are left whole."""
    if isinstance(value, str):
        return value if len(value) <= limit else value[:limit] + f"… [truncated {len(value) - limit} chars]"
    if isinstance(value, dict):
        return {key: clip(item, limit) for key, item in value.items()}
    if isinstance(value, list):
        return [clip(item, limit) for item in value]
    if isinstance(value, tuple):
        return tuple(clip(item, limit) for item in value)
    return value


def _escaped(match: re.Match[str]) -> str:
    return match.group(0).encode("unicode_escape").decode("ascii")


def printable(text: Any) -> str:
    """*text* with every character a terminal would act on written as its escape (``\\x1b``, ``\\r``, ``\\u202e``,
    ``\\ud800``); newlines and tabs stay. For operator output built from LibreNMS data (labels, notes, syslog),
    which must not be able to hide, overwrite or reorder what the operator reads, nor fail to print."""
    return _TERMINAL_RE.sub(_escaped, "" if text is None else str(text))


def one_line(text: Any) -> str:
    """:func:`printable` with newlines and tabs escaped too (``\\n``, ``\\t``). For a value shown inside one line of a
    plan, a journal or a listing (a description, a label, an error from LibreNMS): it must not be able to start a
    line of its own, which would let it pass for a step or a summary line of the text a human approves."""
    return printable(text).replace("\n", "\\n").replace("\t", "\\t")


def for_model(obj: Any, limit: int = 2000) -> Any:
    """What a tool returns of data that came from LibreNMS: credentials masked, long strings clipped."""
    return clip(mask(obj), limit)
