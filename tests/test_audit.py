"""Audit trail: actor capture (session context, plugin context, slash-command sender), the request cache filled by
``pre_llm_call`` and its redaction, the environment record, and the event stream's file discipline (0600 file in a
0700 directory, one append per line, masking, order shared with the sinks)."""

import json
import os
import stat
import tempfile
import threading
import time
import unittest
from enum import Enum
from pathlib import Path
from types import SimpleNamespace

from .base import PluginTestCase
from .fake_librenms import TOKEN
from .helpers import submodule

audit = submodule("audit")
sinks = submodule("sinks")
settings_mod = submodule("settings")
version = submodule("version")
Settings = settings_mod.Settings

_SESSION = {
    "HERMES_SESSION_PLATFORM": "signal",
    "HERMES_SESSION_SOURCE": "gateway",
    "HERMES_SESSION_CHAT_ID": "+15550001111",
    "HERMES_SESSION_CHAT_NAME": "Andrew",
    "HERMES_SESSION_CHAT_TYPE": "dm",
    "HERMES_SESSION_USER_ID": "+15550001111",
    "HERMES_SESSION_USER_ID_ALT": "uuid-1234",
    "HERMES_SESSION_USER_NAME": "Andrew",
    "HERMES_SESSION_KEY": "signal:dm:+15550001111",
    "HERMES_SESSION_ID": "sess-abc",
    "HERMES_SESSION_MESSAGE_ID": "m-77",
}
_ENV_NAMES = [env for env, _field in audit._SESSION_FIELDS] + ["HERMES_CRON_SESSION", "HERMES_HOME", "LIBRENMS_TOKEN"]
ACTOR_KEYS = [
    "kind",
    "via",
    "surface",
    "platform",
    "source",
    "profile",
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
    "session_key",
    "session_id",
    "ui_session_id",
    "task_id",
    "cron",
    "cron_job_id",
    "cron_execution_id",
    "os_user",
    "sender_id",
    "request",
]
BASE_KEYS = ["ts", "schema", "plugin", "event", "plan_id", "librenms_url", "config_digest", "actor", "host", "pid"]


def _restore_env(saved):
    """Put back the variables *saved* maps to their values (``None``: unset)."""
    for name, value in saved.items():
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value


class Ctx:
    """The plugin-context members the actor reads."""

    profile_name = "work"

    def __init__(self, surface="telegram", cron=None):
        self.surface, self.cron = surface, cron

    def session_surface(self):
        return self.surface

    def current_cron_execution(self):
        return self.cron


class BrokenCtx:
    """A context from an older Hermes, or one with no session: every member raises."""

    @property
    def profile_name(self):
        raise RuntimeError("no profile")

    def session_surface(self):
        raise RuntimeError("no session")

    def current_cron_execution(self):
        raise RuntimeError("no cron")


class Platform(Enum):
    SIGNAL = "signal"


class Recorder(sinks.Sink):
    """A sink that keeps what it was sent."""

    name = "recorder"

    def __init__(self):
        self.records = []

    def send(self, record):
        self.records.append(record)


class AuditCase(unittest.TestCase):
    """Default settings pinned, no session variables, no plugin context, an audit log in a temp dir, no sinks."""

    def setUp(self):
        self._env = {name: os.environ.pop(name, None) for name in _ENV_NAMES}
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.settings = Settings()
        settings_mod.set_settings(self.settings)
        self.audit_path = self.tmp / "audit.jsonl"
        audit.set_audit_log(audit.AuditLog(self.audit_path))
        audit.set_ctx(None)
        audit.clear_requests()
        sinks.set_worker(sinks.SinkWorker([]))

    def tearDown(self):
        sinks.set_worker(None)
        audit.clear_requests()
        audit.set_ctx(None)
        audit.set_audit_log(None)
        settings_mod.set_settings(None)
        _restore_env(self._env)
        self._tmp.cleanup()

    def set_settings(self, **values):
        self.settings = Settings(**values)
        settings_mod.set_settings(self.settings)

    def events(self):
        if not self.audit_path.exists():
            return []
        return [json.loads(line) for line in self.audit_path.read_text(encoding="utf-8").splitlines() if line]


class ActorCapture(AuditCase):
    def test_model_actor_from_session_context_and_kwargs(self):
        os.environ.update(_SESSION)
        actor = audit.capture_actor(
            {"task_id": "t-1", "session_id": "sess-override", "user_task": "Move sw1 to SFO please"},
            via=audit.VIA_MODEL,
        )
        self.assertEqual(list(actor), ACTOR_KEYS)
        self.assertEqual((actor["kind"], actor["via"]), ("model", "tool"))
        self.assertEqual(actor["platform"], "signal")
        self.assertEqual(actor["user_id"], "+15550001111")
        self.assertEqual(actor["user_name"], "Andrew")
        self.assertEqual(actor["chat_type"], "dm")
        self.assertEqual(actor["session_id"], "sess-override")  # explicit kwarg wins over context
        self.assertEqual(actor["task_id"], "t-1")
        self.assertEqual(actor["message_id"], "m-77")
        self.assertFalse(actor["cron"])
        self.assertEqual(actor["request"], "Move sw1 to SFO please")
        self.assertTrue(actor["os_user"])

    def test_operator_actor_and_missing_context_is_null_not_absent(self):
        actor = audit.capture_actor({}, via=audit.VIA_CLI)
        self.assertEqual(list(actor), ACTOR_KEYS)
        self.assertEqual((actor["kind"], actor["via"]), ("operator", "cli"))
        for key in ACTOR_KEYS:
            if key not in {"kind", "via", "cron", "os_user"}:
                self.assertIsNone(actor[key], key)
        self.assertIs(actor["cron"], False)
        self.assertEqual(audit.capture_actor(None)["kind"], "model")  # the default path is the model's

    def test_new_session_variables(self):
        os.environ.update(HERMES_SESSION_PARENT_CHAT_ID="chan-9", HERMES_UI_SESSION_ID="tab-3")
        actor = audit.capture_actor({})
        self.assertEqual((actor["parent_chat_id"], actor["ui_session_id"]), ("chan-9", "tab-3"))

    def test_request_text_truncated_and_optional(self):
        actor = audit.capture_actor({"user_task": "x" * 900})
        self.assertEqual(len(actor["request"]), 500)
        self.assertTrue(actor["request"].endswith("…"))
        self.set_settings(audit_include_request=False)
        self.assertIsNone(audit.capture_actor({"user_task": "secret ask"})["request"])

    def test_cron_flag_from_the_environment(self):
        os.environ["HERMES_CRON_SESSION"] = "1"
        actor = audit.capture_actor({})
        self.assertTrue(actor["cron"])
        self.assertIsNone(actor["cron_job_id"])

    def test_plugin_context_fields(self):
        os.environ["HERMES_SESSION_PROFILE"] = "launch-profile"
        cron = SimpleNamespace(job_id="job-7", execution_id="exec-42", job_name="nightly")
        audit.set_ctx(Ctx(surface="telegram", cron=cron))
        actor = audit.capture_actor({})
        self.assertEqual(actor["surface"], "telegram")
        self.assertEqual(actor["profile"], "work")  # the context's profile beats the session variable
        self.assertEqual((actor["cron"], actor["cron_job_id"], actor["cron_execution_id"]), (True, "job-7", "exec-42"))
        audit.set_ctx(Ctx(surface=""))
        self.assertIsNone(audit.capture_actor({})["surface"])

    def test_a_failing_plugin_context_leaves_nulls(self):
        os.environ["HERMES_SESSION_PROFILE"] = "launch-profile"
        audit.set_ctx(BrokenCtx())
        actor = audit.capture_actor({})
        self.assertEqual(list(actor), ACTOR_KEYS)
        self.assertIsNone(actor["surface"])
        self.assertEqual(actor["profile"], "launch-profile")
        self.assertEqual((actor["cron"], actor["cron_job_id"]), (False, None))

    def test_slash_command_sender_from_its_source_keyword(self):
        os.environ.update(_SESSION)
        source = SimpleNamespace(
            platform=Platform.SIGNAL,
            user_id="+15559990000",
            user_name="Dana",
            chat_id="group-1",
            chat_type="group",
            chat_name=None,
            thread_id="",
        )
        audit.remember_request("sess-abc", "t-1", "what the model was last asked", "+15550001111")
        actor = audit.capture_actor(
            {"session_id": "sess-abc", "source": source, "platform": Platform.SIGNAL}, via=audit.VIA_SLASH
        )
        self.assertEqual((actor["kind"], actor["via"]), ("operator", "slash"))
        self.assertEqual((actor["user_id"], actor["user_name"]), ("+15559990000", "Dana"))
        self.assertEqual((actor["chat_id"], actor["chat_type"]), ("group-1", "group"))
        self.assertEqual(actor["chat_name"], "Andrew")  # an empty source field keeps the session's value
        self.assertEqual(actor["platform"], "signal")
        self.assertEqual(actor["session_id"], "sess-abc")
        # the model's last message is not what the operator typed
        self.assertEqual((actor["request"], actor["sender_id"]), (None, None))
        self.assertEqual(audit.capture_actor({"source": "tui"}, via=audit.VIA_SLASH)["source"], "tui")

    def test_describe_actor(self):
        os.environ.update(_SESSION)
        self.assertEqual(
            audit.describe_actor(audit.capture_actor({})), "model via tool on signal for Andrew in dm Andrew"
        )
        for name in _SESSION:
            os.environ.pop(name)
        user = audit.capture_actor({}, via=audit.VIA_CLI)["os_user"]
        self.assertEqual(audit.describe_actor(audit.capture_actor({}, via=audit.VIA_CLI)), f"operator via cli ({user})")
        audit.set_ctx(Ctx(surface="tui", cron=SimpleNamespace(job_id="job-7", execution_id="e")))
        self.assertEqual(
            audit.describe_actor(audit.capture_actor({}, via=audit.VIA_SLASH)),
            f"operator via slash on tui ({user}) [cron job-7]",
        )
        self.assertEqual(audit.describe_actor(None), "unknown")


class RequestCache(AuditCase):
    def test_tool_call_recalls_the_turns_message_and_sender(self):
        audit.remember_request("sess-1", "task-1", "Put sw1 in maintenance for 2h", "+15550001111")
        actor = audit.capture_actor({"session_id": "sess-1", "task_id": "task-1"})
        self.assertEqual(actor["request"], "Put sw1 in maintenance for 2h")
        self.assertEqual(actor["sender_id"], "+15550001111")
        self.assertEqual(audit.describe_actor(actor), "model via tool for +15550001111")

    def test_lookup_falls_back_to_the_latest_message_of_the_session(self):
        audit.remember_request("sess-1", "task-1", "first", None)
        audit.remember_request("sess-1", "task-2", "second", None)
        audit.remember_request("sess-2", "task-9", "other session", None)
        self.assertEqual(audit.recall_request("sess-1", "task-1"), ("first", None))
        self.assertEqual(audit.recall_request("sess-1", "delegated-task"), ("second", None))
        self.assertEqual(audit.recall_request("sess-3", "task-1"), (None, None))
        self.assertEqual(audit.recall_request(None, None), (None, None))

    def test_multimodal_message_keeps_its_text_parts(self):
        parts = [
            {"type": "text", "text": "Which ports on sw1 are down?"},
            {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}},
            "and why",
        ]
        audit.remember_request("s", "t", parts, None)
        self.assertEqual(audit.recall_request("s", "t")[0], "Which ports on sw1 are down?\nand why")
        audit.remember_request("s", "t", {"type": "text", "text": "one part"}, None)
        self.assertEqual(audit.recall_request("s", "t")[0], "one part")
        audit.remember_request("s", "t", [{"type": "image_url", "image_url": {"url": "x"}}], "u-1")
        self.assertEqual(audit.recall_request("s", "t"), (None, "u-1"))

    def test_credentials_in_the_message_are_masked(self):
        token = "3f2a9c1e5b7d4f6a8c0e2b4d6f8a0c2e"
        os.environ["LIBRENMS_TOKEN"] = "configured-token-value-123"
        sanctum = "12|" + "A" * 40
        message = (
            f"my token is configured-token-value-123, the old one {token}, new {sanctum}. "
            "Send X-Auth-Token: abcdefgh12345678 and Authorization: Basic dXNlcjpwYXNz to "
            "https://admin:hunter2@nms.example.com/api; set community=public and LIBRENMS_TOKEN=zzz9 and "
            '"authpass": "sup3rs3cret" plus Bearer eyJhbGciOi.payload.sig9\n'
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----"
        )
        audit.remember_request("s", "t", message, None)
        text = audit.recall_request("s", "t")[0]
        for secret in (
            "configured-token-value-123",
            token,
            sanctum,
            "abcdefgh12345678",
            "dXNlcjpwYXNz",
            "hunter2",
            "public",
            "zzz9",
            "sup3rs3cret",
            "eyJhbGciOi",
            "MIIEow",
        ):
            self.assertNotIn(secret, text)
        self.assertIn("nms.example.com", text)  # the rest of the message stays readable
        self.assertIn("community=<redacted>", text)

    def test_masking_happens_before_the_500_character_cut(self):
        token = "f" * 32
        audit.remember_request("s", "t", "x" * 495 + " " + token, None)
        text = audit.recall_request("s", "t")[0]
        self.assertEqual(len(text), 500)
        self.assertNotIn("ffff", text)  # no partial token survives the cut

    def test_a_long_pasted_message_is_handled_quickly(self):
        for text in ("a-" * 200_000, "a." * 200_000 + "://", "token-" * 60_000):
            started = time.monotonic()
            audit.remember_request("s", "t", text, None)
            self.assertLess(time.monotonic() - started, 2.0)
            self.assertEqual(len(audit.recall_request("s", "t")[0]), 500)

    def test_include_request_off_keeps_only_the_sender(self):
        self.set_settings(audit_include_request=False)
        audit.remember_request("s", "t", "secret plans", "u-1")
        self.assertEqual(audit.recall_request("s", "t"), (None, "u-1"))
        self.set_settings(audit_include_request=True)
        audit.remember_request("s", "t", "now recorded", "u-1")
        self.set_settings(audit_include_request=False)
        self.assertIsNone(audit.capture_actor({"session_id": "s", "task_id": "t"})["request"])

    def test_cache_is_bounded_and_least_recently_used_goes_first(self):
        audit.remember_request("keep", "t", "kept", None)
        for n in range(audit.REQUEST_CACHE_SIZE + 50):
            if n % 50 == 0:
                audit.recall_request("keep", "t")  # recently used
            audit.remember_request(f"s{n}", "t", f"m{n}", None)
        self.assertEqual(len(audit._requests), audit.REQUEST_CACHE_SIZE)
        self.assertEqual(audit.recall_request("s0", "t"), (None, None))
        self.assertEqual(audit.recall_request("keep", "t")[0], "kept")
        audit.clear_requests()
        self.assertEqual(audit.recall_request("keep", "t"), (None, None))

    def test_remember_never_raises_and_ignores_unkeyed_turns(self):
        audit.remember_request(None, None, "no session", "u")
        audit.remember_request("s", "t", object(), object())
        self.assertEqual(len(audit._requests), 1)
        self.assertEqual(audit.recall_request("s", "t")[0], None)

    def test_concurrent_remember_and_recall(self):
        def worker(n):
            for i in range(200):
                audit.remember_request(f"s{n}-{i % 20}", "t", f"m{i}", None)
                audit.recall_request(f"s{n}-{i % 7}", "t")

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertLessEqual(len(audit._requests), audit.REQUEST_CACHE_SIZE)


class Environment(AuditCase):
    def test_keys_and_versions(self):
        os.environ["HERMES_HOME"] = str(self.tmp)
        env = audit.environment()
        self.assertEqual(
            list(env), ["host", "os_user", "pid", "python", "plugin_version", "hermes_version", "hermes_home"]
        )
        self.assertEqual(env["plugin_version"], version.__version__)
        self.assertEqual(env["pid"], os.getpid())
        self.assertRegex(env["python"], r"^3\.\d+\.\d+")
        self.assertEqual(env["hermes_home"], str(self.tmp))  # outside Hermes: the variable is the fallback


class EventStream(AuditCase):
    def test_record_shape_and_key_order(self):
        actor = audit.capture_actor({}, via=audit.VIA_CLI)
        record = audit.emit(
            "step_done",
            plan_id="lnp-1",
            actor=actor,
            librenms_url="https://nms.example.com",
            index=0,
            resource="device",
        )
        (event,) = self.events()
        self.assertEqual(event, record)
        self.assertEqual(list(event)[: len(BASE_KEYS)], BASE_KEYS)
        self.assertEqual(list(event)[len(BASE_KEYS) :], ["index", "resource"])
        self.assertTrue(event["ts"].endswith("Z"))
        self.assertEqual((event["schema"], event["plugin"], event["event"]), (1, "librenms", "step_done"))
        self.assertEqual(event["librenms_url"], "https://nms.example.com")
        self.assertEqual(event["config_digest"], self.settings.digest())
        self.assertEqual(event["actor"]["via"], "cli")
        self.assertEqual(event["pid"], os.getpid())
        self.set_settings(allow_delete=True)
        self.assertEqual(audit.emit("plans_pruned")["config_digest"], self.settings.digest())
        self.assertIsNone(self.events()[1]["plan_id"])

    def test_credential_keys_are_masked_at_any_depth(self):
        audit.emit(
            "step_failed",
            plan_id="lnp-1",
            snapshot={"hostname": "sw1", "community": "public", "ports": [{"authpass": "s3cret"}]},
            inverse={"data": {"service_param": "-p hunter2", "notes": ""}},
        )
        line = self.audit_path.read_text(encoding="utf-8")
        for secret in ("public", "s3cret", "hunter2"):
            self.assertNotIn(secret, line)
        (event,) = self.events()
        self.assertEqual(event["snapshot"]["community"], "<redacted>")
        self.assertEqual(event["snapshot"]["hostname"], "sw1")

    def test_file_is_0600_in_a_new_0700_directory(self):
        old = os.umask(0o022)
        try:
            path = self.tmp / "logs" / "nested" / "audit.jsonl"
            audit.set_audit_log(audit.AuditLog(path))
            audit.emit("plan_created", plan_id="lnp-1")
        finally:
            os.umask(old)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(path.parent.parent.stat().st_mode), 0o700)

    def test_one_write_per_line_even_for_a_large_event(self):
        writes = []
        real_write = os.write

        def counting_write(fd, data):
            writes.append(len(data))
            return real_write(fd, data)

        os.write = counting_write
        try:
            audit.emit("plan_created", plan_id="lnp-1", description="d" * 100_000)
        finally:
            os.write = real_write
        self.assertEqual(len(writes), 1)
        self.assertEqual(len(self.events()[0]["description"]), 100_000)

    def test_concurrent_writers_never_interleave_lines(self):
        other = audit.AuditLog(self.audit_path)  # a second writer on the same file, like another process

        def worker(n):
            log = other if n % 2 else audit.get_audit_log()
            for i in range(25):
                log.emit("step_done", plan_id=f"lnp-{n}", index=i, label=str(n) * 20_000)

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        events = self.events()
        self.assertEqual(len(events), 150)
        for event in events:
            self.assertEqual(event["label"], event["plan_id"][-1] * 20_000)

    def test_lone_surrogates_are_replaced(self):
        audit.emit("step_done", plan_id="lnp-1", label="sw\ud800-1", actor={"request": "a\udfffb"})
        raw = self.audit_path.read_bytes()
        raw.decode("utf-8")  # strict: the line is valid UTF-8
        (event,) = self.events()
        self.assertEqual((event["label"], event["actor"]["request"]), ("sw�-1", "a�b"))

    def test_values_json_cannot_hold_are_written_as_text(self):
        audit.emit("step_done", plan_id="lnp-1", path=Path("/x"), ids={3})
        (event,) = self.events()
        self.assertEqual((event["path"], event["ids"]), ("/x", "{3}"))

    def test_disabled_log_writes_nothing(self):
        recorder = Recorder()
        sinks.set_worker(sinks.SinkWorker([recorder]))
        audit.set_audit_log(audit.AuditLog(self.audit_path, enabled=False))
        self.assertIsNone(audit.emit("plan_created", plan_id="lnp-1"))
        self.assertTrue(sinks.get_worker().flush(2))
        self.assertFalse(self.audit_path.exists())
        self.assertEqual(recorder.records, [])

    def test_unwritable_log_never_raises(self):
        audit.set_audit_log(audit.AuditLog(self.tmp))  # a directory, not a file
        with self.assertLogs("hermes_plugins.librenms.audit", level="WARNING"):
            record = audit.emit("apply_started", plan_id="lnp-1")
        self.assertEqual(record["event"], "apply_started")

    def test_default_path_follows_the_profile_and_settings_override(self):
        audit.set_audit_log(None)
        os.environ["HERMES_HOME"] = str(self.tmp / "home")
        self.assertEqual(audit.get_audit_log().path, self.tmp / "home" / "plugin-data" / "librenms" / "audit.jsonl")
        audit.emit("plan_created", plan_id="lnp-1")
        self.assertTrue((self.tmp / "home" / "plugin-data" / "librenms" / "audit.jsonl").exists())
        os.environ["HERMES_HOME"] = str(self.tmp / "other")
        self.assertEqual(audit.get_audit_log().path.parent, self.tmp / "other" / "plugin-data" / "librenms")
        custom = self.tmp / "Logs" / "LibreNMS-Audit.jsonl"
        self.set_settings(audit_log_path=str(custom))
        self.assertEqual(audit.get_audit_log().path, custom)  # case kept
        self.set_settings(audit_log=False)
        self.assertFalse(audit.get_audit_log().enabled)

    def test_sinks_get_the_masked_record_in_file_order(self):
        recorder = Recorder()
        sinks.set_worker(sinks.SinkWorker([recorder]))
        names = [f"event_{n}" for n in range(30)]
        for name in names:
            audit.emit(name, plan_id="lnp-1", snapshot={"community": "public"})
        self.assertTrue(sinks.get_worker().flush(5))
        self.assertEqual([r["event"] for r in recorder.records], names)
        self.assertEqual([e["event"] for e in self.events()], names)
        self.assertEqual(recorder.records[0]["snapshot"]["community"], "<redacted>")


class Lifecycle(PluginTestCase):
    """A plan applied and rolled back through the tool handlers: the event sequence, the base keys on every event,
    the request remembered by ``pre_llm_call``, and no credential in any line (skipped until the handlers exist)."""

    def setUp(self):
        super().setUp()
        if self.handlers is None or self.executor is None:
            self.skipTest("handlers and executor are not written yet")
        self.addCleanup(
            _restore_env, {name: os.environ.pop(name, None) for name in _ENV_NAMES if name != "HERMES_HOME"}
        )
        os.environ.update(_SESSION)
        self.recorder = Recorder()
        sinks.set_worker(sinks.SinkWorker([self.recorder]))

    def call(self, name, args, **kwargs):
        return json.loads(self.handlers.HANDLERS[name](args, **kwargs))

    def test_plan_apply_rollback(self):
        audit.remember_request("sess-abc", "t-9", "make access-sw2 a distribution switch", "+15550001111")
        operations = [{"op": "update", "resource": "device", "id": 3, "data": {"purpose": "distribution"}}]
        out = self.call(
            "librenms_plan",
            {"description": "lifecycle", "operations": operations},
            task_id="t-9",
            session_id="sess-abc",
        )
        pid = out["plan_id"]
        self.call("librenms_apply", {"plan_id": pid, "dry_run": True})
        self.call("librenms_apply", {"plan_id": pid}, task_id="t-9", session_id="sess-abc")
        self.call("librenms_rollback", {"plan_id": pid})
        events = self.events()
        names = iter(e["event"] for e in events)
        for expected in ("plan_created", "plan_checked", "apply_started", "step_done", "apply_finished",
                         "rollback_started", "revert_reverted", "rollback_finished"):  # fmt: skip
            self.assertIn(expected, names, [e["event"] for e in events])  # in this order
        for event in events:
            self.assertEqual(list(event)[: len(BASE_KEYS)], BASE_KEYS)
            self.assertEqual((event["plan_id"], event["schema"], event["plugin"]), (pid, 1, "librenms"))
            self.assertEqual(event["librenms_url"], self.client.base_url)
            self.assertEqual(event["config_digest"], self.settings.digest())
            self.assertEqual(event["actor"]["platform"], "signal")
        created = self.events("plan_created")[0]["actor"]
        self.assertEqual(created["request"], "make access-sw2 a distribution switch")
        self.assertEqual((created["kind"], created["task_id"]), ("model", "t-9"))
        self.assertTrue(sinks.get_worker().flush(5))
        self.assertEqual([r["event"] for r in self.recorder.records], [e["event"] for e in events])
        text = self.audit_path.read_text(encoding="utf-8")
        for secret in (TOKEN, "acc3ss-Community", "Sup3rS3cret"):
            self.assertNotIn(secret, text)


if __name__ == "__main__":
    unittest.main()
