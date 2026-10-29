"""Audit sinks: severity, RFC 5424 and CEF formatting, strict entry parsing (insecure transport needs the opt-in,
nothing from an entry is quoted in logs), and delivery to real UDP (IPv4 and IPv6), TCP and HTTP servers on the
loopback interface, including refused redirects, retries and the bounded queue."""

import http.server
import json
import os
import socket
import socketserver
import tempfile
import threading
import time
import unittest
from pathlib import Path

from .helpers import submodule

sinks = submodule("sinks")
audit = submodule("audit")
client_mod = submodule("client")
settings_mod = submodule("settings")
version = submodule("version")
Settings = settings_mod.Settings


def _record(event="apply_started", **extra):
    rec = {
        "ts": "2026-09-08T19:35:50Z",
        "schema": 1,
        "plugin": "librenms",
        "event": event,
        "plan_id": "lnp-20260908T193512Z-4f1a",
        "librenms_url": "https://nms.example.com",
        "config_digest": "0123456789ab",
        "actor": {
            "kind": "model",
            "via": "tool",
            "platform": "signal",
            "user_name": "Andrew",
            "chat_type": "dm",
            "chat_name": "Andrew",
            "request": "Move sw1 | to SFO",
        },
        "host": "hermes-01",
        "pid": 4242,
    }
    rec.update(extra)
    return rec


class _UDP(socketserver.UDPServer):
    allow_reuse_address = True


class _UDP6(_UDP):
    address_family = socket.AF_INET6


class _UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.server.received.append(self.request[0])


class _TCP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _TCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        for line in self.rfile:
            self.server.received.append(line.rstrip(b"\n"))


class _HTTP(http.server.HTTPServer):
    status = 200
    location = None

    def server_bind(self):  # HTTPServer's looks up this host's FQDN, which can take seconds
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


class _HTTPHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        self.server.received.append({"path": self.path, "headers": dict(self.headers), "body": self.rfile.read(length)})
        self.send_response(self.server.status)
        if self.server.location:
            self.send_header("Location", self.server.location)
        self.send_header("Content-Length", "27")
        self.end_headers()
        self.wfile.write(b'{"text":"Success","code":0}')

    def log_message(self, *args):  # silence
        return None


def _serve(server):
    server.received = []
    t = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    t.start()
    return server


def _stop(server):
    server.shutdown()
    server.server_close()


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


class EnvCase(unittest.TestCase):
    """Restores the environment variables a test sets and the sink worker it installs."""

    def setUp(self):
        self._saved_env = dict(os.environ)

    def tearDown(self):
        sinks.set_worker(None)
        os.environ.clear()
        os.environ.update(self._saved_env)


class Formats(unittest.TestCase):
    def test_severity_mapping(self):
        self.assertEqual(sinks.severity_of(_record("step_done")), sinks.SEV_INFO)
        self.assertEqual(sinks.severity_of(_record("revert_skipped")), sinks.SEV_INFO)
        self.assertEqual(sinks.severity_of(_record("apply_started")), sinks.SEV_NOTICE)
        self.assertEqual(sinks.severity_of(_record("approval_decided", choice="deny")), sinks.SEV_NOTICE)
        self.assertEqual(sinks.severity_of(_record("approval_requested")), sinks.SEV_NOTICE)  # one never decided
        for event in ("apply_refused", "query_refused", "revert_irreversible", "run_recovered", "step_conflict"):
            self.assertEqual(sinks.severity_of(_record(event)), sinks.SEV_WARNING, event)
        self.assertEqual(sinks.severity_of(_record("apply_finished", outcome="failed")), sinks.SEV_WARNING)
        self.assertEqual(sinks.severity_of(_record("apply_finished", outcome="applied")), sinks.SEV_INFO)
        self.assertEqual(
            sinks.severity_of(_record("rollback_finished", status="partially_rolled_back")), sinks.SEV_WARNING
        )
        self.assertEqual(sinks.severity_of(_record("eventlog_linked", linked=False)), sinks.SEV_WARNING)
        self.assertEqual(sinks.severity_of(_record("eventlog_linked", linked=True)), sinks.SEV_INFO)

    def test_rfc5424_message_shape(self):
        sink = sinks.SyslogSink("127.0.0.1", 514, facility="local0")
        msg = sink.message(_record("step_done"))
        self.assertTrue(msg.startswith("<134>1 2026-09-08T19:35:50Z "), msg)  # local0(16)*8 + info(6)
        head, body = msg.split(" - ", 1)
        self.assertEqual(head.split(" ")[3:6], ["hermes-librenms", "4242", "step_done"])
        self.assertEqual(json.loads(body)["event"], "step_done")
        self.assertTrue(sink.message(_record("apply_refused")).startswith("<132>1 "))

    def test_cef_line(self):
        line = sinks.to_cef(
            _record(
                "apply_refused",
                reason="write_mode is read_only",
                resource="device",
                object_id=12,
                http_status=403,
                action="update",
            )
        )
        self.assertTrue(
            line.startswith(
                f"CEF:0|andrewvieyra|hermes-plugin-librenms|{version.__version__}|apply_refused|apply refused|7|"
            )
        )
        ext = line.split("|", 7)[7]
        for needle in (
            "rt=1788896150000",
            "dvchost=hermes-01",
            "request=https://nms.example.com",
            "suser=Andrew",
            "cs1Label=plan_id cs1=lnp-20260908T193512Z-4f1a",
            "cs2Label=actor_kind cs2=model",
            "cs4Label=platform cs4=signal",
            "cs6Label=resource cs6=device",
            "act=update",
            "externalId=12",
            "cn1Label=http_status cn1=403",
            "msg=write_mode is read_only",
            "cs7Label=request_text cs7=Move sw1 | to SFO",
            "cs8Label=config_digest cs8=0123456789ab",
        ):
            self.assertIn(needle, ext, needle)
        pipe = sinks.to_cef(_record("x|y"))
        self.assertIn("|x\\|y|", pipe)
        self.assertEqual(sinks._cef_ext("a=b\\c\nd"), "a\\=b\\\\c\\nd")

    def test_cef_writes_no_label_without_its_value(self):
        line = sinks.to_cef({"event": "plans_pruned", "ts": "bad", "actor": None, "count": 2})
        for label in ("cs1Label", "cs2Label", "cs6Label", "cn1Label", "cs7Label", "cs8Label"):
            self.assertNotIn(label, line)
        self.assertIn("rt=", line)


class HeaderSecrets(EnvCase):
    def test_placeholders_read_through_the_profile_secret_scope(self):
        os.environ["LN_TEST_TOKEN"] = "s3cret"
        os.environ.pop("LN_MISSING_VAR", None)
        self.assertEqual(sinks.expand_env("Splunk ${LN_TEST_TOKEN}"), "Splunk s3cret")
        self.assertEqual(sinks.expand_env("${LN_MISSING_VAR}"), "")
        self.assertEqual(sinks.expand_env("no placeholder $HOME"), "no placeholder $HOME")

    def test_an_unbound_secret_scope_fails_the_send_without_a_value(self):
        def unscoped(name):
            raise client_mod.ConfigError(f"no secret scope is bound for this Hermes profile; cannot read {name}")

        real = client_mod.secret
        client_mod.secret = unscoped
        try:
            with self.assertRaises(sinks.SinkError) as caught:
                sinks.expand_env("Splunk ${SPLUNK_HEC_TOKEN}")
        finally:
            client_mod.secret = real
        self.assertIn("${SPLUNK_HEC_TOKEN}", str(caught.exception))


class EntryParsing(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.ca_file = Path(self._tmp.name) / "ca.pem"
        self.ca_file.write_text("not used to connect here")

    def tearDown(self):
        self._tmp.cleanup()

    def build(self, spec, allow_insecure=False):
        with self.assertNoLogs("hermes_plugins.librenms.sinks", level="WARNING"):
            sink = sinks.build_sink(spec, allow_insecure, 0)
        self.assertIsNotNone(sink, spec)
        return sink

    def rejected(self, spec, allow_insecure=False):
        with self.assertLogs("hermes_plugins.librenms.sinks", level="WARNING") as logs:
            self.assertIsNone(sinks.build_sink(spec, allow_insecure, 3), spec)
        return logs.output[0]

    def test_unusable_entries_are_dropped(self):
        tls = {"type": "syslog", "host": "siem.example.com", "protocol": "tls"}
        for spec in (
            "not a mapping",
            {"type": "carrier-pigeon", "host": "x"},
            {"type": "syslog"},
            {"type": "syslog", "host": "  "},
            {**tls, "protocol": "smoke"},
            {**tls, "format": "xml"},
            {**tls, "facility": "bogus"},
            {**tls, "facility": 24},
            {**tls, "framing": "length"},
            {**tls, "app_name": "hermes librenms"},
            {**tls, "port": 0},
            {**tls, "port": "x"},
            {**tls, "port": True},
            {**tls, "port": 514.5},
            {**tls, "timeout": 0},
            {**tls, "timeout": float("nan")},
            {**tls, "verify_ssl": ""},
            {**tls, "verify_ssl": "maybe"},
            {**tls, "verify_ssl": 2},
            {**tls, "verify_ssl": "/nonexistent/ca.pem"},
            {**tls, "ca_file": "/nonexistent/ca.pem"},
            {**tls, "verify_ssl": str(self.ca_file), "ca_file": str(self.ca_file)},
            {"type": "http", "url": "ftp://x"},
            {"type": "http", "url": "https://"},
            {"type": "http", "url": "https://[::1"},
            {"type": "http", "url": "https://user:pw@collector.example.com/x"},
            {"type": "http", "url": "https://collector.example.com", "format": "xml"},
            {"type": "http", "url": "https://collector.example.com", "headers": ["Authorization"]},
            {"type": "http", "url": "https://collector.example.com", "headers": {"Bad Name": "x"}},
            {"type": "http", "url": "https://collector.example.com", "headers": {"X-Token": "a\r\nInjected: 1"}},
            {"type": "http", "url": "https://collector.example.com", "headers": {"X-Token": {"nested": 1}}},
        ):
            self.rejected(spec)

    def test_good_entries(self):
        tcp = self.build({"type": "syslog", "host": "127.0.0.1", "protocol": "tcp", "format": "cef", "facility": 19})
        self.assertEqual((tcp.protocol, tcp.fmt, tcp.facility, tcp.framing), ("tcp", "cef", 19, "newline"))
        tls = self.build({"type": "syslog", "host": "siem.example.com", "protocol": "TLS", "port": "6514"})
        self.assertEqual((tls.framing, tls.port, tls.verify_ssl), ("octet-counting", 6514, True))
        self.assertEqual(tls.label(), "audit_sinks[0] (syslog tls)")
        http_sink = self.build({"type": "http", "url": "https://collector.example.com", "timeout": "2.5"})
        self.assertEqual(
            (http_sink.name, http_sink.timeout, http_sink.sourcetype), ("https", 2.5, "hermes:librenms:audit")
        )
        self.assertEqual(http_sink.label(), "audit_sinks[0] (https)")

    def test_verify_ssl_values(self):
        tls = {"type": "syslog", "host": "siem.example.com", "protocol": "tls"}
        self.assertIs(self.build({**tls, "verify_ssl": "true"}).verify_ssl, True)
        self.assertIs(self.build({**tls, "verify_ssl": "False"}, allow_insecure=True).verify_ssl, False)
        self.assertEqual(self.build({**tls, "verify_ssl": str(self.ca_file)}).verify_ssl, str(self.ca_file))
        self.assertEqual(self.build({**tls, "verify_ssl": self._tmp.name}).verify_ssl, self._tmp.name)  # a CA dir
        self.assertEqual(self.build({**tls, "ca_file": str(self.ca_file)}).verify_ssl, str(self.ca_file))
        https = {"type": "http", "url": "https://collector.example.com", "verify_ssl": str(self.ca_file)}
        self.assertEqual(self.build(https).verify_ssl, str(self.ca_file))

    def test_clear_text_and_unverified_transport_need_the_opt_in(self):
        insecure = (
            {"type": "syslog", "host": "10.0.0.5"},
            {"type": "syslog", "host": "siem.example.com", "protocol": "tcp"},
            {"type": "syslog", "host": "siem.example.com", "protocol": "tls", "verify_ssl": False},
            {"type": "http", "url": "http://collector.example.com:8088/services/collector/event"},
            {"type": "http", "url": "https://collector.example.com", "verify_ssl": "false"},
        )
        for spec in insecure:
            self.assertIn("allow_insecure_transport", self.rejected(spec))
            self.build(spec, allow_insecure=True)
        for host in ("127.0.0.1", "127.0.0.53", "::1", "[::1]", "localhost", "LOCALHOST"):
            self.build({"type": "syslog", "host": host, "protocol": "udp"})
            self.build({"type": "syslog", "host": host, "protocol": "tcp"})
        self.build({"type": "http", "url": "http://127.0.0.1:8088/collector"})
        self.build({"type": "http", "url": "http://[::1]:8088/collector"})
        self.build({"type": "http", "url": "http://localhost/collector"})

    def test_warnings_name_the_entry_by_index_and_type_only(self):
        cases = (
            (
                {
                    "type": "http",
                    "url": "https://admin:hunter2@collector.example.com/x?token=s3cret",
                    "headers": {"Authorization": "Splunk literal-secret"},
                },
                "audit_sinks[3] (http)",
            ),
            (
                {
                    "type": "http",
                    "url": "http://collector.example.com/x?token=s3cret",
                    "headers": {"A": "literal-secret"},
                },
                "audit_sinks[3] (http)",
            ),
            ({"type": "syslog", "host": "collector.example.com", "port": "hunter2"}, "audit_sinks[3] (syslog)"),
            ({"type": "syslog", "host": "collector.example.com", "facility": "s3cret"}, "audit_sinks[3] (syslog)"),
            (
                {"type": "syslog", "host": "collector.example.com", "protocol": "tls", "ca_file": "/home/alice/ca.pem"},
                "audit_sinks[3] (syslog)",
            ),
            ({"type": "s3cret", "host": "collector.example.com"}, "audit_sinks[3] (unknown type)"),
        )
        for spec, prefix in cases:
            message = self.rejected(spec)
            self.assertIn(prefix, message)
            for leak in ("hunter2", "s3cret", "collector.example.com", "literal-secret", "alice"):
                self.assertNotIn(leak, message)

    def test_configure_skips_bad_entries_and_keeps_their_numbers(self):
        with self.assertLogs("hermes_plugins.librenms.sinks", level="WARNING"):
            worker = sinks.configure([{"type": "bogus"}, {"type": "syslog", "host": "127.0.0.1"}])
        try:
            self.assertEqual([s.label() for s in worker.sinks], ["audit_sinks[1] (syslog udp)"])
        finally:
            worker.close(0.5)

    def test_configure_numbers_entries_by_their_place_in_the_config(self):
        # settings dropped config.yaml's entries 0 and 2 (not mappings); warnings and labels use the config's numbers
        with self.assertLogs("hermes_plugins.librenms.sinks", level="WARNING") as logs:
            worker = sinks.configure([{"type": "bogus"}, {"type": "syslog", "host": "127.0.0.1"}], numbers=[1, 3])
        try:
            self.assertIn("audit_sinks[1] (unknown type) ignored", logs.output[0])
            self.assertEqual([s.label() for s in worker.sinks], ["audit_sinks[3] (syslog udp)"])
        finally:
            worker.close(0.5)


class Delivery(EnvCase):
    def test_udp_syslog(self):
        server = _serve(_UDP(("127.0.0.1", 0), _UDPHandler))
        try:
            worker = sinks.SinkWorker([sinks.SyslogSink("127.0.0.1", server.server_address[1])])
            worker.enqueue(_record("plan_created"))
            worker.enqueue(_record("apply_refused"))
            self.assertTrue(worker.flush(5))
            self.assertTrue(_wait(lambda: len(server.received) == 2))
            first = server.received[0].decode()
            self.assertTrue(first.startswith("<134>1 "))
            self.assertEqual(json.loads(first.split(" - ", 1)[1])["event"], "plan_created")
            self.assertTrue(server.received[1].decode().startswith("<132>1 "))
            self.assertEqual(worker.stats["sent"], 2)
            worker.close(1)
        finally:
            _stop(server)

    def test_udp_syslog_over_ipv6(self):
        try:
            server = _serve(_UDP6(("::1", 0), _UDPHandler))
        except OSError:
            self.skipTest("no IPv6 loopback on this host")
        try:
            worker = sinks.SinkWorker([sinks.SyslogSink("[::1]", server.server_address[1])])
            worker.enqueue(_record("plan_created"))
            self.assertTrue(worker.flush(5))
            self.assertTrue(_wait(lambda: len(server.received) == 1))
            self.assertEqual(worker.stats["sent"], 1)
            worker.close(1)
        finally:
            _stop(server)

    def test_tcp_syslog_newline_and_cef(self):
        server = _serve(_TCP(("127.0.0.1", 0), _TCPHandler))
        try:
            sink = sinks.SyslogSink("127.0.0.1", server.server_address[1], protocol="tcp", fmt="cef")
            worker = sinks.SinkWorker([sink])
            worker.enqueue(_record("step_done", resource="device", object_id=12, action="update", http_status=200))
            self.assertTrue(worker.flush(5))
            self.assertTrue(_wait(lambda: len(server.received) == 1))
            line = server.received[0].decode()
            self.assertTrue(line.startswith("<134>1 "))
            self.assertIn(" step_done - CEF:0|andrewvieyra|hermes-plugin-librenms|", line)
            worker.close(1)
        finally:
            _stop(server)

    def test_http_sink_json_and_hec_with_a_secret_header(self):
        server = _serve(_HTTP(("127.0.0.1", 0), _HTTPHandler))
        os.environ["LN_TEST_HEC"] = "tok-123"
        try:
            url = f"http://127.0.0.1:{server.server_address[1]}/services/collector/event"
            plain = sinks.HttpSink(url, headers={"Authorization": "Splunk ${LN_TEST_HEC}"})
            hec = sinks.HttpSink(url, headers={"Authorization": "Splunk ${LN_TEST_HEC}"}, fmt="hec")
            worker = sinks.SinkWorker([plain, hec])
            worker.enqueue(_record("apply_finished", outcome="applied"))
            self.assertTrue(worker.flush(5))
            self.assertTrue(_wait(lambda: len(server.received) == 2))
            a, b = server.received
            self.assertEqual(a["headers"]["Authorization"], "Splunk tok-123")
            self.assertEqual(json.loads(a["body"])["event"], "apply_finished")
            wrapped = json.loads(b["body"])
            self.assertEqual(
                (wrapped["sourcetype"], wrapped["event"]["event"], wrapped["host"]),
                ("hermes:librenms:audit", "apply_finished", "hermes-01"),
            )
            self.assertAlmostEqual(wrapped["time"], 1788896150.0, places=0)
            self.assertEqual(a["headers"]["User-Agent"], f"hermes-plugin-librenms/{version.__version__}")
            worker.close(1)
        finally:
            _stop(server)

    def test_a_redirect_is_never_followed(self):
        target = _serve(_HTTP(("127.0.0.1", 0), _HTTPHandler))
        redirector = _serve(_HTTP(("127.0.0.1", 0), _HTTPHandler))
        redirector.location = f"http://127.0.0.1:{target.server_address[1]}/elsewhere"
        os.environ["LN_TEST_HEC"] = "tok-123"
        try:
            for code in (301, 302, 303, 307, 308):
                redirector.status = code
                sink = sinks.HttpSink(
                    f"http://127.0.0.1:{redirector.server_address[1]}/c", headers={"Authorization": "${LN_TEST_HEC}"}
                )
                with self.assertRaises(Exception) as caught:  # Python 3.10 has no 308 handler: a plain HTTPError
                    sink.send(_record())
                reason = sinks._reason(caught.exception)
                self.assertIn(f"HTTP {code}", reason)
                self.assertNotIn("127.0.0.1", reason)
            self.assertEqual(len(redirector.received), 5)
            self.assertEqual(target.received, [])  # neither the event nor the token went on
        finally:
            _stop(target)
            _stop(redirector)

    def test_a_loopback_collector_is_never_reached_through_a_proxy(self):
        collector = _serve(_HTTP(("127.0.0.1", 0), _HTTPHandler))
        proxy = _serve(_HTTP(("127.0.0.1", 0), _HTTPHandler))  # stands in for a proxy across the network
        for name in [name for name in os.environ if name.lower().endswith("_proxy")]:
            del os.environ[name]  # no no_proxy either: nothing in the environment exempts loopback
        os.environ["http_proxy"] = f"http://127.0.0.1:{proxy.server_address[1]}"
        os.environ["LN_TEST_HEC"] = "tok-123"
        try:
            for host in ("127.0.0.1", "localhost"):
                url = f"http://{host}:{collector.server_address[1]}/c"
                sinks.HttpSink(url, headers={"Authorization": "Splunk ${LN_TEST_HEC}"}).send(_record())
            self.assertEqual(len(collector.received), 2)
            self.assertEqual(proxy.received, [])  # neither the event nor the token went to the proxy
            sinks.HttpSink("http://collector.example.com/c", allow_insecure=True).send(_record())
            self.assertEqual([r["path"] for r in proxy.received], ["http://collector.example.com/c"])
        finally:
            _stop(collector)
            _stop(proxy)

    def test_failures_are_logged_by_index_and_kind_without_the_url(self):
        server = _serve(_HTTP(("127.0.0.1", 0), _HTTPHandler))
        server.status = 503
        try:
            failing = sinks.HttpSink(f"http://127.0.0.1:{server.server_address[1]}/c?token=s3cret", timeout=2)
            failing.number = 2
            dead = sinks.HttpSink(f"http://127.0.0.1:{_free_port()}/collector", timeout=0.5)
            dead.number = 3
            worker = sinks.SinkWorker([failing, dead], retries=2, backoff=0.01)
            with self.assertLogs("hermes_plugins.librenms.sinks", level="WARNING") as logs:
                worker.enqueue(_record())
                self.assertTrue(worker.flush(10))
            output = "\n".join(logs.output)
            self.assertIn("audit_sinks[2] (http) failed after 2 attempts: HTTP 503", output)
            self.assertIn("audit_sinks[3] (http) failed after 2 attempts: ConnectionRefusedError", output)
            self.assertNotIn("127.0.0.1", output)
            self.assertNotIn("s3cret", output)
            self.assertEqual((worker.stats["sent"], worker.stats["failed"]), (0, 2))
            worker.close(1)
        finally:
            _stop(server)

    def test_unreachable_sink_is_retried_then_dropped_quickly(self):
        dead = sinks.HttpSink(f"http://127.0.0.1:{_free_port()}/collector", timeout=0.5)
        worker = sinks.SinkWorker([dead], retries=2, backoff=0.01)
        started = time.monotonic()
        with self.assertLogs("hermes_plugins.librenms.sinks", level="WARNING"):
            worker.enqueue(_record())
            self.assertTrue(worker.flush(10))
        self.assertLess(time.monotonic() - started, 8)
        self.assertEqual((worker.stats["sent"], worker.stats["failed"]), (0, 1))
        worker.close(1)

    def test_queue_overflow_drops_for_sinks_only(self):
        class Slow(sinks.Sink):
            name = "slow"

            def send(self, record):
                time.sleep(0.2)

        worker = sinks.SinkWorker([Slow()], queue_size=2)
        with self.assertLogs("hermes_plugins.librenms.sinks", level="WARNING"):
            results = [worker.enqueue(_record()) for _ in range(6)]
        self.assertIn(False, results)
        self.assertGreaterEqual(worker.stats["dropped"], 1)
        worker.close(3)

    def test_no_sinks_means_no_thread(self):
        worker = sinks.SinkWorker([])
        self.assertFalse(worker.enqueue(_record()))
        self.assertFalse(worker._thread.is_alive())


class ThroughAuditLog(EnvCase):
    def setUp(self):
        super().setUp()
        self._tmp = tempfile.TemporaryDirectory()
        self.audit_path = Path(self._tmp.name) / "audit.jsonl"
        settings_mod.set_settings(Settings())
        audit.set_audit_log(audit.AuditLog(self.audit_path))

    def tearDown(self):
        audit.set_audit_log(None)
        settings_mod.set_settings(None)
        self._tmp.cleanup()
        super().tearDown()

    def test_events_reach_syslog_and_the_file_in_the_same_order(self):
        server = _serve(_UDP(("127.0.0.1", 0), _UDPHandler))
        try:
            sinks.set_worker(sinks.SinkWorker([sinks.SyslogSink("127.0.0.1", server.server_address[1])]))
            for event in ("plan_created", "apply_started", "step_done", "eventlog_linked", "apply_finished"):
                audit.emit(event, plan_id="lnp-1", snapshot={"community": "public"})
            self.assertTrue(sinks.get_worker().flush(5))
            lines = self.audit_path.read_text(encoding="utf-8").splitlines()
            file_events = [json.loads(line)["event"] for line in lines]
            _wait(lambda: len(server.received) >= len(file_events))
            wire = [json.loads(d.decode().split(" - ", 1)[1]) for d in server.received]
            self.assertEqual([w["event"] for w in wire], file_events)
            self.assertEqual(wire[0]["snapshot"]["community"], "<redacted>")
        finally:
            _stop(server)

    def test_worker_built_from_settings(self):
        sinks.set_worker(None)
        entries = [{"type": "syslog", "host": "127.0.0.1", "port": 1}, {"type": "syslog", "host": "10.0.0.5"}]
        settings_mod.set_settings(Settings(audit_sinks=entries))
        with self.assertLogs("hermes_plugins.librenms.sinks", level="WARNING"):
            worker = sinks.get_worker()
        self.assertEqual([s.label() for s in worker.sinks], ["audit_sinks[0] (syslog udp)"])
        self.assertIs(sinks.get_worker(), worker)
        sinks.set_worker(None)
        settings_mod.set_settings(Settings(audit_sinks=entries, allow_insecure_transport=True))
        self.assertEqual(len(sinks.get_worker().sinks), 2)

    def test_turning_the_insecure_opt_in_off_stops_a_clear_text_sink_without_a_restart(self):
        sinks.set_worker(None)
        entries = [{"type": "syslog", "host": "127.0.0.1", "port": 1}, {"type": "syslog", "host": "10.0.0.5"}]
        settings_mod.set_settings(Settings(audit_sinks=entries, allow_insecure_transport=True))
        first = sinks.get_worker()
        self.assertEqual(len(first.sinks), 2)
        self.assertIs(sinks.get_worker(), first)  # unchanged settings keep the running worker
        settings_mod.set_settings(Settings(audit_sinks=entries))
        with self.assertLogs("hermes_plugins.librenms.sinks", level="WARNING"):
            second = sinks.get_worker()
        self.assertEqual([s.label() for s in second.sinks], ["audit_sinks[0] (syslog udp)"])
        self.assertTrue(_wait(lambda: not first._thread.is_alive()))  # the old worker is closed

    def test_an_edited_sink_entry_applies_without_a_restart(self):
        # the settings digest keeps only the entries' count and types, which this edit leaves alone
        sinks.set_worker(None)
        settings_mod.set_settings(Settings(audit_sinks=[{"type": "syslog", "host": "127.0.0.1", "port": 1}]))
        first = sinks.get_worker()
        settings_mod.set_settings(Settings(audit_sinks=[{"type": "syslog", "host": "127.0.0.1", "port": 2}]))
        second = sinks.get_worker()
        self.assertEqual([s.port for s in second.sinks], [2])
        self.assertIs(sinks.get_worker(), second)
        self.assertTrue(_wait(lambda: not first._thread.is_alive()))

    def test_settings_coercion_keeps_only_mappings(self):
        raw = {"audit_sinks": [{"type": "http", "url": "https://x"}, "junk", 3]}
        self.assertEqual(Settings.from_mapping(raw).audit_sinks, [{"type": "http", "url": "https://x"}])


if __name__ == "__main__":
    unittest.main()
