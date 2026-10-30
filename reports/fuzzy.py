"""Ranking what a person calls a device, a site, a group or a port against what LibreNMS holds.

People name devices by short name (``core-sw1`` for ``core-sw1.example.net``), sysName, display name, IP, or a
phrase of role and site words ("the core switch in Amsterdam"); LibreNMS resolves only an id or the exact hostname.
:func:`device_match` scores one device for a :class:`Term`, deterministically, and says why:

- the whole term against hostname, sysName and display name, and the first DNS label of each, compared as words
  (case and punctuation aside: ``core sw1`` is ``core-sw1``): equal 100, the leading words 92, a prefix 88, whole
  words inside 85, the start of a word inside 80, any other part of three or more characters 70;
- an IP against the device's address (100); a MAC or an interface address is the caller's lookup;
- else each word of the term (stop words aside) against the name words (a whole word 3, the start of one or a role
  word's abbreviation 2: ``switch`` for ``sw1``), the location, purpose, type and os (2) and the hardware or serial
  (1, a whole serial 3). The score is 60 times the share of words that matched plus 20 times their weight against
  the most there could be, so at most 80, below any whole-term match of a name.

A match is ``full`` when the whole term matched at a word boundary or every word did. Locations, groups and port
groups are scored the same way by name; ports by their interface name (and the other words against their device and
description).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Tuple

from ..redact import clip, one_line
from ..routes import mac_hex

STOP_WORDS = frozenset(
    {"the", "a", "an", "in", "at", "on", "of", "for", "to", "from", "with", "and", "or", "device", "devices", "port"}
)
# What hostnames abbreviate role words to: "core switch" finds core-sw1, "edge router" edge-rtr1.
ROLE_WORDS: Dict[str, Tuple[str, ...]] = {
    "switch": ("sw",),
    "switches": ("sw",),
    "router": ("rtr", "rt", "gw"),
    "routers": ("rtr", "rt", "gw"),
    "firewall": ("fw",),
    "firewalls": ("fw",),
    "server": ("srv",),
    "servers": ("srv",),
    "gateway": ("gw",),
    "accesspoint": ("ap",),
}
_WORD_RE = re.compile(r"[^\W_]+")
# An interface name as people write it: Gi1/0/48, xe-0/0/1, Ethernet1/1, ge-0/0/0.100, eth0, Po10, vlan20.
_IFACE_RE = re.compile(
    r"^[a-z][a-z-]*\d+(?:[/:.]\d+)+$"
    r"|^(?:gi|te|fa|fo|hu|tw|xe|ge|et|eth|ens|eno|enp\d+s|ae|po|lo|vlan|bond|mgmt|port-channel|ethernet)\d+$",
    re.IGNORECASE,
)
_EDGE_PUNCT = "\"'`()[]{}<>,;!?"  # not ":", which an IPv6 address may start or end with
WHY_CHARS = 60  # a matched value quoted in a why
TERM_CHARS = 200
FULL_WEIGHT = 3


def norm(text: Any) -> str:
    """*text* as the words it is made of, lower case, one space apart: ``Core-SW1.example.net`` -> ``core sw1 example
    net``. Every comparison here is between such forms."""
    return " ".join(_WORD_RE.findall(str(text or "").casefold()))


def label(value: Any) -> str:
    """The first DNS label of a hostname (``core-sw1`` of ``core-sw1.example.net``); an IP address whole."""
    text = str(value or "").strip()
    if not text or _ip(text) is not None:
        return text
    return text.split(".", 1)[0]


def _ip(text: str) -> Any:
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def shown(value: Any) -> str:
    """*value* quoted in a why: one line, clipped."""
    return repr(clip(one_line(str(value)), WHY_CHARS))


@dataclass(frozen=True)
class Term:
    """What a person typed, taken apart: the whole of it in word form, its words (stop words aside), and the first
    interface name, IP address or MAC address in it."""

    text: str
    whole: str
    words: Tuple[str, ...]
    iface: str | None = None
    ip: str | None = None
    mac: str | None = None

    @classmethod
    def parse(cls, text: str) -> Term:
        words: List[str] = []
        iface = ip = mac = None
        for raw in text.split():
            token = raw.strip(_EDGE_PUNCT)
            if not token:
                continue
            if iface is None and _IFACE_RE.match(token):
                iface = token.casefold()
                continue
            address = _ip(token)
            if ip is None and address is not None:
                ip = str(address)
                continue
            # with its separators only: twelve bare hex digits may as well be a serial number
            digits = mac_hex(token) if any(sep in token for sep in ":-.") else None
            if mac is None and digits is not None:
                mac = digits
                continue
            words += [word for word in norm(token).split() if word not in STOP_WORDS]
        return cls(text, norm(text), tuple(dict.fromkeys(words)), iface, ip, mac)

    @property
    def parts(self) -> int:
        """How many things the term names: its words, and the interface, IP or MAC in it."""
        return len(self.words) + sum(item is not None for item in (self.iface, self.ip, self.mac))


@dataclass(frozen=True)
class Match:
    """How well a candidate matched (0-100), why, and whether the whole term or every word of it did."""

    score: int
    why: str
    full: bool


@dataclass
class _Tally:
    """Per-word matches of one candidate: the best weight each word reached and why."""

    weights: Dict[str, int] = field(default_factory=dict)
    whys: Dict[str, str] = field(default_factory=dict)

    def offer(self, word: str, weight: int, why: str) -> None:
        if weight > self.weights.get(word, 0):
            self.weights[word], self.whys[word] = weight, why

    def match(self, term: Term, whole: Tuple[int, str]) -> Match | None:
        parts = max(term.parts, 1)
        matched = sum(1 for weight in self.weights.values() if weight)
        score = round(60 * matched / parts + 20 * sum(self.weights.values()) / (FULL_WEIGHT * parts))
        if whole[0] >= score and whole[0]:
            return Match(whole[0], whole[1], whole[0] >= 80)  # inside a word only: not a name the person gave
        if not matched:
            return None
        return Match(score, "; ".join(self.whys[word] for word in self.weights if self.weights[word]), matched == parts)


_VERBS = {100: "equals", 92: "starts with", 88: "starts with", 85: "contains", 80: "contains", 70: "contains"}


def level(term: str, value: str) -> int:
    """How the whole *term* matches *value*, both in word form (:func:`norm`): 100, 92, 88, 85, 80, 70 or 0."""
    if not term or not value:
        return 0
    if value == term:
        return 100
    if value.startswith(term + " "):
        return 92
    if value.startswith(term):
        return 88
    padded = f" {value} "
    if f" {term} " in padded:
        return 85
    if f" {term}" in padded:
        return 80
    return 70 if len(term) >= 3 and term in value else 0


def _whole(term: Term, fields: Iterable[Tuple[str, Any]]) -> Tuple[int, str]:
    """The best whole-term match over *fields* (name, value) and its why, which quotes both the value and what the
    person typed (``hostname 'core-sw1.example.net' starts with 'core'``), or the value alone when they are the same
    (``sysName equals 'core-sw1'``), so the why shows what matched."""
    best: Tuple[int, str] = (0, "")
    for name, value in fields:
        found = level(term.whole, norm(value)) if value else 0
        if found > best[0]:
            if found == 100:
                best = (found, f"{name} {_VERBS[found]} {shown(value)}")
            else:
                best = (found, f"{name} {shown(value)} {_VERBS[found]} {shown(term.text.strip())}")
    return best


def _words_of(value: Any) -> List[str]:
    return norm(value).split()


def _offer_names(tally: _Tally, term: Term, fields: List[Tuple[str, Any]]) -> None:
    """Each word of the term against the words of the name *fields*: whole word 3, start of a word or a role word's
    abbreviation 2."""
    for word in term.words:
        for name, value in fields:
            for part in _words_of(value):
                if part == word:
                    tally.offer(word, 3, f"{shown(word)} in {name} {shown(value)}")
                elif len(word) >= 2 and part.startswith(word):
                    tally.offer(word, 2, f"{name} {shown(value)} has a word starting {shown(word)}")
                for short in ROLE_WORDS.get(word, ()):
                    if part.startswith(short) and (part == short or part[len(short) :].isdigit()):
                        tally.offer(word, 2, f"{shown(word)} as {shown(part)} in {name} {shown(value)}")


def _offer_attribute(tally: _Tally, term: Term, name: str, value: Any, weight: int, prefix: bool = True) -> None:
    """Each word of the term against the words of an attribute (location, purpose, ...). A number matches names
    only: the 1 of "core 1" is not the 1 of a location "SFO-1"."""
    parts = _words_of(value)
    for word in term.words:
        if word.isdigit():
            continue
        if word in parts or (prefix and len(word) >= 3 and any(part.startswith(word) for part in parts)):
            tally.offer(word, weight, f"{shown(word)} in {name} {shown(value)}")


def device_names(device: Dict[str, Any]) -> List[Tuple[str, Any]]:
    """A device's names as a person may give them: hostname, sysName, display name, and their first DNS labels."""
    names: List[Tuple[str, Any]] = []
    for key, what in (("hostname", "hostname"), ("sysName", "sysName"), ("display", "display name")):
        value = device.get(key)
        if isinstance(value, str) and value.strip() and all(value != seen for _n, seen in names):
            names.append((what, value))
    for key, what in (("hostname", "hostname's first label"), ("sysName", "sysName's first label")):
        first = label(device.get(key))
        if first and all(first != seen for _n, seen in names):
            names.append((what, first))
    return names


def device_match(term: Term, device: Dict[str, Any]) -> Match | None:
    """How *device* (a ``devices`` row) matches *term*, or None. A term that is an IP address matches only a device
    that has it as its address or hostname: ``192.0.2.1`` is not part of ``192.0.2.12``."""
    if term.ip is not None and term.parts == 1:
        for key, what in (("hostname", "hostname"), ("ip", "IP"), ("overwrite_ip", "overwrite_ip")):
            value = str(device.get(key) or "").strip()
            if _ip(value) is not None and str(_ip(value)) == term.ip:
                return Match(100, f"{what} equals {shown(term.ip)}", True)
        return None
    names = device_names(device)
    whole = _whole(term, names)
    tally = _Tally()
    _offer_names(tally, term, names)
    _offer_attribute(tally, term, "location", device.get("location"), 2)
    _offer_attribute(tally, term, "purpose", device.get("purpose"), 2)
    for key in ("type", "os"):
        _offer_attribute(tally, term, key, device.get(key), 2, prefix=False)
    _offer_attribute(tally, term, "hardware", device.get("hardware"), 1, prefix=False)
    serial = str(device.get("serial") or "").casefold()
    for word in term.words:
        if serial and word == serial:
            tally.offer(word, 3, f"serial equals {shown(device.get('serial'))}")
    return tally.match(term, whole)


def name_match(term: Term, what: str, name: Any, description: Any = None) -> Match | None:
    """How a location, group or port group called *name* (with an optional *description*) matches *term*."""
    whole = _whole(term, [(what, name)])
    tally = _Tally()
    _offer_names(tally, term, [(what, name)])
    if description:
        _offer_attribute(tally, term, "description", description, 1)
    return tally.match(term, whole)


def port_match(term: Term, port: Dict[str, Any], device: Dict[str, Any] | None) -> Match | None:
    """How a port (``ifName``, ``ifDescr``, ``ifAlias``) on *device* matches *term*: its interface name against the
    port's names, the other words against the device and the port's description."""
    tally = _Tally()
    if term.iface is not None:
        wanted = norm(term.iface)
        for key in ("ifName", "ifDescr"):
            value = port.get(key)
            found = level(wanted, norm(value)) if value else 0
            if found == 100:
                tally.offer(term.iface, 3, f"{key} equals {shown(value)}")
            elif found >= 88:
                tally.offer(term.iface, 2, f"{key} starts with {shown(term.iface)}")
    if device is not None:
        _offer_names(tally, term, device_names(device))
    _offer_attribute(tally, term, "description", port.get("ifAlias"), 2)
    whole = (0, "")
    if term.parts == 1 and term.iface is not None and tally.weights.get(term.iface) == FULL_WEIGHT:
        whole = (100, tally.whys[term.iface])
    return tally.match(term, whole)
