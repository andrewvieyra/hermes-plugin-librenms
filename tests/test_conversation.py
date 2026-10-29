"""The question skill, librenms:ask, against the fake LibreNMS: every question of the conversational audit (1 to 57)
is in its table with a call that runs as written, and its follow-ups put ids only where an argument takes them; the
example conversations in examples/conversations/ run turn by turn, every id a follow-up uses taken from an earlier
answer, every fact an answer states a value the tools returned, and every count, percentage and state it gives the
one under the key that holds it; and a conversation driven the way the skill says (find first, ask when it is
ambiguous, reuse ids, read on with next_offset, call again for "now", a window for "yesterday") gets its answers.
Read-only throughout: every request a GET on the allow-list, nothing written."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterator, List, NamedTuple, Tuple

from .helpers import REPO_ROOT, submodule
from .test_report_ports import POLLED, PortCase, ticks
from .test_reports import NOON
from .test_version import section

reports = submodule("reports")

ASK = REPO_ROOT / "skills" / "ask" / "SKILL.md"
CONVERSATIONS = REPO_ROOT / "examples" / "conversations"
QUESTIONS = list(range(1, 58))  # the conversational audit's questions, as the skill's table numbers them
NOT_IN_THE_API = {12, 20}  # a port's traffic history; what speed a port could run at
READ_TOOLS = ("librenms_report", "librenms_query")
DOWN = {"state": ["down", "lowerLayerDown", "notPresent"]}

# core-sw1 Gi1/0/2, the trunk to access-sw2: a five-minute drop yesterday evening and a one-minute drop today
FLAPS = (
    ("2026-10-27 18:00:00", "ifOperStatus: up -> down"),
    ("2026-10-27 18:05:00", "ifOperStatus: down -> up"),
    ("2026-10-28 11:30:00", "ifOperStatus: up -> down"),
    ("2026-10-28 11:31:00", "ifOperStatus: down -> up"),
)
# Where a follow-up's id comes from: an argument holding an id, and the result keys that give one.
ID_SOURCES = {"device": ("device_id",), "port": ("port_id", "remote_port_id"), "rule": ("rule_id", "top_rule_id")}
# The numbers and bare words each example answer gives (counts, percentages, states), in the order it gives them, each
# pinned to the key that holds it: a path into what the turn's calls returned, or for a turn without calls into what
# the conversation returned before it. A short number or word is found in almost any result, so finding it somewhere
# is no check that it is right; every one an answer gives must be pinned here.
PINNED = {
    ("alerts.json", 1): [("4", "0.count"), ("3", "0.summary.unacknowledged")],
    ("alerts.json", 3): [("75.0", "0.rows.0.limit_warn"), ("warning", "0.rows.0.status")],
    ("alerts.json", 4): [("recovered", "0.rows.3.state")],
    ("alerts.json", 6): [("alice", "0.rows.3.note")],
    ("busiest-port.json", 2): [("80.0", "0.rows.0.util_pct")],
    ("busiest-port.json", 3): [("0", "0.summary.bills")],
    ("busiest-port.json", 4): [("1.0", "0.rows.0.util_pct")],
    ("busiest-port.json", 5): [("6", "0.count")],
    ("wan-port-down.json", 4): [("down", "0.rows.0.last_status")],
    ("wan-port-down.json", 6): [("81.2", "0.rows.0.used_pct")],
    ("where-is.json", 1): [("10", "0.summary.edge.0.vlans.0")],
    ("where-is.json", 2): [("full", "0.rows.0.duplex"), ("up", "0.rows.0.state")],
    ("where-is.json", 3): [("1500", "0.rows.0.mtu")],
    ("where-is.json", 4): [("up", "0.rows.0.state")],
}
_CALL = re.compile(r"`(librenms_query )?(\{.*?\})`")
_FACT = re.compile(r"`([^`]+)`")
_NUMBER = re.compile(r"[-+]?\d+(?:\.\d+)?")
_WORD = re.compile(r"[A-Za-z]+")


class Row(NamedTuple):
    number: int
    question: str
    calls: List[Tuple[str, Dict[str, Any]]]
    answer: str


def question_table(text: str) -> List[Row]:
    """The skill's question tables as rows (number, question, calls as (tool, arguments), where the answer is). A
    call is a backticked JSON object, ``librenms_query`` when it says so and ``librenms_report`` otherwise."""
    rows = []
    for line in text.splitlines():
        if not re.match(r"\| \d+ \| ", line):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split(" | ")]
        assert len(cells) == 4, line
        calls = [
            (READ_TOOLS[1] if query else READ_TOOLS[0], json.loads(body)) for query, body in _CALL.findall(cells[2])
        ]
        rows.append(Row(int(cells[0]), cells[1], calls, cells[3]))
    return rows


def leaves(value: Any) -> Iterator[Any]:
    """Every value of *value* that is neither an object nor a list, at any depth: no key."""
    if isinstance(value, dict):
        for item in value.values():
            yield from leaves(item)
    elif isinstance(value, list):
        for item in value:
            yield from leaves(item)
    else:
        yield value


def holds(value: Any, fact: str) -> bool:
    """Whether *value*, a value a tool returned, says *fact*: a number that equals it (or the same digits as text), or
    for a text, that text or one holding it (``alice`` in an acknowledgement's note)."""
    if _NUMBER.fullmatch(fact):
        number = isinstance(value, (int, float)) and not isinstance(value, bool)
        return (number and value == float(fact)) or value == fact
    return isinstance(value, str) and fact in value


def at(value: Any, path: str) -> Any:
    """What *value* holds at *path*: keys and list indexes joined by dots (``0.rows.3.note``)."""
    for step in path.split("."):
        value = value[int(step)] if isinstance(value, list) else value[step]
    return value


def ids(value: Any, keys: Tuple[str, ...]) -> Iterator[Any]:
    """Every value of one of *keys*, at any depth of *value*."""
    if isinstance(value, dict):
        for key, item in value.items():
            if key in keys:
                yield item
            yield from ids(item, keys)
    elif isinstance(value, list):
        for item in value:
            yield from ids(item, keys)


class DemoCase(PortCase):
    """The demo network the skill's calls and the example conversations name, at noon UTC on 2026-10-28 with
    librenms_timezone UTC: PortCase's polled ports and traffic, core-sw1's trunk to access-sw2 up again after two
    drops, transit-a's drop this morning in the eventlog, and a desk on access-sw2 Gi1/0/5 where the MAC of
    192.0.2.50 is learned."""

    def setUp(self):
        super().setUp()
        self.settings_with(librenms_timezone="UTC")
        self.fake.touch("ports", 2, ifOperStatus="up", ifLastChange=ticks(8_640_000, 24 * 60))
        for when, change in FLAPS:
            self.fake.seed("eventlog", {"device_id": 1, "datetime": when, "message": change, "type": "interface",
                                        "reference": 2, "severity": 3})  # fmt: skip
        self.fake.seed("eventlog", {"device_id": 2, "datetime": "2026-10-28 09:55:00", "type": "interface",
                                    "reference": 5, "severity": 3, "message": "ifOperStatus: up -> down"})  # fmt: skip
        desk = self.seed_port(device_id=3, ifIndex=5, ifName="Gi1/0/5", ifDescr="GigabitEthernet1/0/5", ifAlias="desk 5",
                              ifVlan="10", ifInOctets_rate=150_000, ifOutOctets_rate=1_250_000, ifInErrors_delta=0,
                              ifOutErrors_delta=0)  # fmt: skip
        self.fake.touch("ports_fdb", 1, port_id=desk["port_id"])
        self.fake.now = NOON

    def ask(self, tool, arguments):
        out = self.call(tool, **arguments)
        self.assertTrue(out.get("success"), f"{tool} {json.dumps(arguments)}: {out.get('error')}")
        return out


class SkillTable(DemoCase):
    def setUp(self):
        super().setUp()
        self.text = ASK.read_text(encoding="utf-8")
        self.rows = question_table(section(self.text, "Questions and the call that answers them"))

    def test_every_question_of_the_audit_is_in_the_table_once(self):
        self.assertEqual([row.number for row in self.rows], QUESTIONS)

    def test_every_row_has_a_call_and_says_where_the_answer_is(self):
        for row in self.rows:
            with self.subTest(question=row.number):
                self.assertTrue(row.question.endswith("?"), row.question)
                self.assertTrue(row.calls, "no call")
                self.assertTrue(row.answer)

    def test_what_the_api_cannot_answer_is_marked_with_what_to_say_instead(self):
        marked = {row.number for row in self.rows if row.answer.startswith("**Not in the API.**")}
        self.assertEqual(marked, NOT_IN_THE_API)
        for row in self.rows:
            if row.number in marked:
                self.assertRegex(row.answer, r"say so|Offer", row.number)
        # and the questions it answers only in part say how
        answers = {row.number: row.answer for row in self.rows}
        self.assertTrue(answers[7].startswith("**Only from syslog.**"))
        self.assertIn("one port at a time", answers[4])

    def test_every_call_in_the_table_runs_as_written(self):
        for row in self.rows:
            for tool, arguments in row.calls:
                with self.subTest(question=row.number, call=arguments):
                    out = self.ask(tool, arguments)
                    self.assertFalse(out.get("ambiguous"), "a call the skill shows must not need a question back")
                    self.assertNotIn("refused", out)
        self.assert_reads_only_allowed_gets()

    def test_every_view_answers_a_question_and_find_comes_first(self):
        views = {arguments["view"] for row in self.rows for tool, arguments in row.calls if tool == READ_TOOLS[0]}
        self.assertEqual(views | {"find"}, set(reports.VIEWS))
        self.assertIn("view `find` first", section(self.text, "How to answer"))

    def test_follow_ups_say_how_to_carry_ids_scope_and_window(self):
        text = " ".join(section(self.text, "Follow-up questions").split())
        for phrase in ("Reuse ids, not names", '"That device", "that port", "it"', '"The other end"',
                       '"What about yesterday"', '"The same for edge-rtr1"', '"More", "the rest"',
                       '"Is it still down?"', "librenms:workflow"):  # fmt: skip
            self.assertIn(phrase, text)
        for key in ("scope.device", "scope.port", "filter.port_id", "remote_port_id", "next_offset", "`48h`",
                    "data_as_of"):  # fmt: skip
            self.assertIn(key, text)

    def test_follow_ups_put_ids_only_where_an_argument_takes_them(self):
        text = " ".join(section(self.text, "Follow-up questions").split())
        named = re.findall(r"`(scope|filter)\.(\w+)`", text)
        self.assertGreater(len(named), 5)
        takes = {"scope": {key for view in reports.VIEWS.values() for key in view.scope_keys},
                 "filter": {key for view in reports.VIEWS.values() for key in view.filters}}  # fmt: skip
        for kind, key in named:
            self.assertIn(key, takes[kind], f"no view takes {kind}.{key}")
        # a port_id is exact in filter.port_id of the views the skill names; filter.port reads a number as a name first
        for view in ("neighbours", "events"):
            self.assertEqual(reports.VIEWS[view].filters.get("port_id"), "id", view)
        self.assertIn("Never put a `port_id` in `filter.port`", text)
        self.assertNotIn("never ambiguous", text)
        self.assertIn("No argument takes `sensor_id`, `session_id` or `bill_id`", text)
        for key in ("sensor", "sensor_id", "session", "session_id", "bill", "bill_id", "alert_id"):
            self.assertNotIn(key, takes["scope"] | takes["filter"], key)

    def test_honesty_rules_name_every_flag_a_report_raises(self):
        text = section(self.text, "Being honest about the data")
        for flag in ("data_as_of", "stale: true", "truncated: true", "partial: true", "timezone", "exact: false"):
            self.assertIn(flag, text)


class ExampleConversations(DemoCase):
    """Every example conversation, turn by turn: a read tool for every call, each id a follow-up passes taken from an
    earlier answer of the conversation (and an offset from its next_offset), a question back whenever an answer was
    ambiguous, and every backticked fact of an answer a value that turn's calls returned (or, for a turn that makes
    none, the conversation before it): a number one that equals it, a text one that is it or holds it, never a key,
    and each number or bare word the one its key in :data:`PINNED` holds."""

    def conversations(self):
        files = sorted(CONVERSATIONS.glob("*.json"))
        self.assertGreaterEqual(len(files), 4)
        for path in files:
            yield path.name, json.loads(path.read_text(encoding="utf-8"))

    def assert_derived(self, arguments, earlier, where) -> int:
        """Every id in *arguments* is one an *earlier* answer gave, and an offset one's next_offset; how many."""
        scope, filters = arguments.get("scope") or {}, arguments.get("filter") or {}
        self.assertNotIsInstance(filters.get("port"), int, f"{where}: a port_id goes in filter.port_id")
        refs = [("device", scope.get("device")), ("port", scope.get("port")), ("port", filters.get("port_id")),
                ("rule", filters.get("rule"))]  # fmt: skip
        refs += [("device", ref) for ref in scope.get("devices") or []]
        refs = [(kind, ref) for kind, ref in refs if isinstance(ref, int) and not isinstance(ref, bool)]
        for kind, ref in refs:
            given = set(ids(earlier, ID_SOURCES[kind]))
            self.assertIn(ref, given, f"{where}: {kind} {ref} is no id an earlier answer gave")
        if arguments.get("offset"):
            offsets = [out.get("next_offset") for out in earlier]
            self.assertIn(arguments["offset"], offsets, f"{where}: offset is no next_offset an answer gave")
        return len(refs) + bool(arguments.get("offset"))

    def test_every_example_conversation_is_answered_from_what_the_tools_return(self):
        for name, conversation in self.conversations():
            with self.subTest(conversation=name):
                self.assertEqual(sorted(conversation), ["title", "turns"])
                self.assertGreaterEqual(len(conversation["turns"]), 4)
                earlier: List[Dict[str, Any]] = []
                derived = 0
                for number, turn in enumerate(conversation["turns"], 1):
                    where = f"{name} turn {number}"
                    self.assertEqual(sorted(turn), ["answer", "calls", "user"], where)
                    results = []
                    for call in turn["calls"]:
                        self.assertEqual(sorted(call), ["arguments", "tool"], where)
                        self.assertIn(call["tool"], READ_TOOLS, where)
                        derived += self.assert_derived(call["arguments"], earlier, where)
                        results.append(self.ask(call["tool"], call["arguments"]))
                    if any(out.get("ambiguous") for out in results):
                        self.assertTrue(turn["answer"].rstrip().endswith("?"), f"{where}: ambiguous, so ask")
                    facts = _FACT.findall(turn["answer"])
                    self.assertTrue(facts or not results, f"{where}: an answer states what the calls returned")
                    returned = results or earlier
                    values = list(leaves(returned))
                    for fact in facts:
                        self.assertTrue(any(holds(value, fact) for value in values),
                                        f"{where}: {fact!r} is no value the tools returned")  # fmt: skip
                    pinned = PINNED.get((name, number), [])
                    bare = [fact for fact in facts if _NUMBER.fullmatch(fact) or _WORD.fullmatch(fact)]
                    self.assertEqual(bare, [fact for fact, _ in pinned], f"{where}: pin each number and word in PINNED")
                    for fact, path in pinned:
                        value = at(returned, path)
                        self.assertTrue(holds(value, fact), f"{where}: {fact!r} is not what {path} holds: {value!r}")
                    earlier.extend(results)
                self.assertGreater(derived, 0, f"{name}: no follow-up built on an earlier answer")
        self.assertLessEqual({name for name, _ in PINNED}, {path.name for path in CONVERSATIONS.glob("*.json")})
        self.assert_reads_only_allowed_gets()

    def test_the_examples_cover_the_follow_ups_the_skill_names(self):
        users = " ".join(turn["user"] for _, c in self.conversations() for turn in c["turns"]).lower()
        for phrase in ("that port", "the other end", "what about yesterday", "next", "and the access switch"):
            self.assertIn(phrase, users)


class FollowingTheSkill(DemoCase):
    """One conversation driven as the skill says, every call built from what the answers before it returned."""

    def test_a_conversation_reuses_ids_asks_reads_on_and_calls_again(self):
        # "Which ports are down on the edge router?": a role, not a hostname, so view find first
        found = self.ask("librenms_report", {"view": "find", "term": "edge router"})
        self.assertFalse(found["ambiguous"])
        [router] = [row for row in found["rows"] if row["kind"] == "device"]
        down = self.ask("librenms_report", {"view": "ports", "scope": {"device": router["device_id"]}, "filter": DOWN})
        self.assertEqual((down["summary"]["not_up"], down["data_as_of"]), (2, "2026-10-28T12:00:00Z"))
        transit = next(row for row in down["rows"] if "transit-a" in row["port"])

        # "what is on the other end of transit-a?": its device and port_id, not their names
        far = self.ask("librenms_report", {"view": "neighbours", "scope": {"device": transit["device_id"]},
                                           "filter": {"port_id": transit["port_id"]}})  # fmt: skip
        [link] = far["rows"]
        # LibreNMS does not monitor that end: what the neighbour advertises is all there is, so no further call
        self.assertEqual((link["remote_hostname"], link["remote_monitored"], link["remote_port_id"]),
                         ("transit-a-pe1", False, None))  # fmt: skip

        # "is it still down?" ten minutes later it came back: call again, never answer from the earlier result
        self.fake.touch("ports", transit["port_id"], ifOperStatus="up", poll_time=POLLED + 600)
        self.fake.now = NOON.replace(minute=10)
        again = self.ask("librenms_report", {"view": "ports", "scope": {"device": router["device_id"]}, "filter": DOWN})
        self.assertEqual(([row["port"] for row in again["rows"]], again["data_as_of"]),
                         (["Gi0/0/1 (WAN: transit-b)"], "2026-10-28T12:10:00Z"))  # fmt: skip

        # "and on the switches?": two devices fit, so find says ambiguous and the user is asked; they say both
        switches = self.ask("librenms_report", {"view": "find", "term": "switch"})
        self.assertTrue(switches["ambiguous"])
        both = sorted(row["device_id"] for row in switches["rows"] if row["kind"] == "device")
        same = self.ask("librenms_report", {"view": "ports", "scope": {"devices": both}, "filter": DOWN})
        self.assertEqual((same["count"], same["summary"]["in_scope"]), (0, 4))

        # "list their ports, two at a time": read on with next_offset until nothing follows
        listed, offset = [], 0
        while True:
            page = self.ask("librenms_report", {"view": "ports", "scope": {"devices": both}, "sort": "name",
                                                "limit": 2, "offset": offset})  # fmt: skip
            listed += [row["port"] for row in page["rows"]]
            if not page["truncated"]:
                break
            offset = page["next_offset"]
        self.assertEqual(listed, ["Gi1/0/5 (desk 5)", "Gi1/0/48 (to core-sw1)", "Gi1/0/1 (uplink to edge-rtr1)",
                                  "Gi1/0/2"])  # fmt: skip

        # "did any of them flap? and yesterday?": the same scope over a window reaching past yesterday's midnight,
        # then that port's entries, the ones dated yesterday
        flapped = self.ask("librenms_report", {"view": "events", "scope": {"devices": both}, "window": "48h",
                                               "filter": {"type": "interface", "by": "port"}, "sort": "most"})  # fmt: skip
        [port] = flapped["rows"]
        self.assertEqual((port["port"], port["went_down"], port["flaps"]), ("Gi1/0/2", 2, 2))
        entries = self.ask("librenms_report", {"view": "events", "scope": {"device": port["device_id"]}, "window": "48h",
                                               "filter": {"port_id": port["port_id"], "by": "event"}})  # fmt: skip
        yesterday = [(row["time"], row["message"]) for row in entries["rows"] if row["time"].startswith("2026-10-27")]
        self.assertEqual(yesterday, [("2026-10-27T18:05:00Z", "ifOperStatus: down -> up"),
                                     ("2026-10-27T18:00:00Z", "ifOperStatus: up -> down")])  # fmt: skip
        self.assert_reads_only_allowed_gets()
