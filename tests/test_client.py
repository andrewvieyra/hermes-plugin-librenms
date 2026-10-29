import contextlib
import http.server
import json
import os
import socket
import socketserver
import ssl
import sys
import tempfile
import threading
import types
import unittest
from unittest import mock

from .helpers import submodule

try:
    import requests

    HAVE_REQUESTS = True
except ImportError:  # CI installs it; without it only the tests against a local server skip
    HAVE_REQUESTS = False

client_mod = submodule("client")

TOKEN = "7|hermesTestToken0123456789"
BASE = "https://nms.example.com"
LONE = chr(0xD800)  # a lone surrogate, as JSON can carry
OK = {"status": "ok", "devices": [], "count": 0}


class Resp:
    """A streamed answer as ``requests`` gives one; ``read`` counts the body bytes handed out."""

    def __init__(self, status=200, body=None, *, headers=None, raw=None, breaks=False):
        self.status_code = status
        self.headers = {"Content-Type": "application/json"} if headers is None else headers
        self.raw = raw if raw is not None else (b"" if body is None else json.dumps(body).encode())
        self.breaks = breaks
        self.read = 0
        self.closed = False

    def iter_content(self, chunk_size=1):
        for start in range(0, len(self.raw), chunk_size):
            if self.breaks and start:
                raise ConnectionResetError("connection broken: IncompleteRead")
            chunk = self.raw[start : start + chunk_size]
            self.read += len(chunk)
            yield chunk

    def close(self):
        self.closed = True


class Session:
    """Answers each request with the next of *answers* (a Resp, or an exception to raise); the last one repeats."""

    def __init__(self, *answers):
        self.answers = list(answers) or [Resp(200, OK)]
        self.sent = []

    def request(self, method, url, **kwargs):
        self.sent.append({"method": method, "url": url, **kwargs})
        answer = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        if isinstance(answer, BaseException):
            raise answer
        return answer


def make(*answers, url=BASE, **kwargs):
    session = Session(*answers)
    client = client_mod.LibreNMSClient(url, TOKEN, session=session, **kwargs)
    slept = []
    client.retry_sleep = slept.append
    return client, session, slept


def env(**extra):
    return {"LIBRENMS_URL": BASE, "LIBRENMS_TOKEN": TOKEN, **extra}


@contextlib.contextmanager
def env_proxies(**proxies):
    """The process environment with only *proxies* as its proxy variables (restored afterwards)."""
    with mock.patch.dict(os.environ):
        for name in [name for name in os.environ if name.lower().endswith("_proxy")]:
            del os.environ[name]
        os.environ.update(proxies)
        yield


def restore_module(name, module):
    if module is None:
        sys.modules.pop(name, None)
    else:
        sys.modules[name] = module


class Config(unittest.TestCase):
    def test_settings_from_env_normalises_the_url(self):
        s = client_mod.settings_from_env(env(LIBRENMS_URL=" https://nms.example.com/librenms/api/v0/ "))
        self.assertEqual(
            s,
            {
                "url": "https://nms.example.com/librenms",
                "token": TOKEN,
                "verify": True,
                "timeout": (30.0, 30.0),
                "proxy": None,
            },
        )
        self.assertEqual(client_mod.settings_from_env(env(LIBRENMS_URL="https://nms.example.com/"))["url"], BASE)

    def test_missing_settings_or_an_unusable_url_are_config_errors(self):
        for bad in (
            {},
            {"LIBRENMS_URL": BASE},
            {"LIBRENMS_TOKEN": TOKEN},
            env(LIBRENMS_TOKEN="  "),
            env(LIBRENMS_URL="nms.example.com"),
            env(LIBRENMS_URL="ftp://nms.example.com"),
            env(LIBRENMS_URL="https://"),
            env(LIBRENMS_URL="https://nms.example.com/?x=1"),
            env(LIBRENMS_URL="https://nms.example.com/#top"),
            env(LIBRENMS_URL="https://[::1"),
        ):
            with self.assertRaises(client_mod.ConfigError, msg=bad) as caught:
                client_mod.settings_from_env(bad)
            self.assertEqual((caught.exception.kind, caught.exception.status), ("config", 0))
            self.assertNotIn(TOKEN, str(caught.exception))

    def test_an_unusable_url_is_never_quoted(self):
        # the message reaches the model: a value in the wrong variable may be the token, or carry one
        hex_token = "9f86d081884c7d659a2feaa0c55ad015"
        sanctum = "12|" + "Ab3" * 16
        cases = (
            (
                hex_token,
                "LIBRENMS_URL looks like an API token, not a URL; are LIBRENMS_URL and LIBRENMS_TOKEN swapped?",
            ),
            (sanctum, "LIBRENMS_URL looks like an API token, not a URL; are LIBRENMS_URL and LIBRENMS_TOKEN swapped?"),
            (
                f"librenms.example.com/api/v0?api_token={hex_token}",
                "LIBRENMS_URL must start with http:// or https://, e.g. https://librenms.example.com",
            ),
            (
                f"ftp://{hex_token}",
                "LIBRENMS_URL must start with http:// or https://, e.g. https://librenms.example.com",
            ),
            ("https://", "LIBRENMS_URL must name a host after http:// or https://, e.g. https://librenms.example.com"),
            ("https://[::1", "LIBRENMS_URL cannot be read as a URL, e.g. https://librenms.example.com"),
        )
        for url, message in cases:
            with self.assertRaises(client_mod.ConfigError) as caught:
                client_mod.settings_from_env({"LIBRENMS_URL": url, "LIBRENMS_TOKEN": hex_token})
            self.assertEqual(str(caught.exception), message, url)
            self.assertNotIn(hex_token, str(caught.exception))
            self.assertNotIn("librenms.example.com/", str(caught.exception))

    def test_missing_settings_name_the_profiles_env_file(self):
        self.addCleanup(restore_module, "hermes_constants", sys.modules.get("hermes_constants"))
        for shown, expected in (
            ("~/.hermes/profiles/netops", "~/.hermes/profiles/netops/.env"),
            ("~/.hermes", "~/.hermes/.env"),
            ("/srv/alice/hermes", "the .env file in this profile's HERMES_HOME"),  # a path naming the OS account
        ):
            module = types.ModuleType("hermes_constants")
            module.display_hermes_home = lambda shown=shown: shown
            sys.modules["hermes_constants"] = module
            self.assertEqual(client_mod.env_file(), expected)
            with self.assertRaises(client_mod.ConfigError) as caught:
                client_mod.settings_from_env({"LIBRENMS_URL": BASE})
            self.assertEqual(
                str(caught.exception), f"LIBRENMS_URL and LIBRENMS_TOKEN must both be set (put them in {expected})"
            )
        sys.modules["hermes_constants"] = None  # outside Hermes
        self.assertEqual(client_mod.env_file(), "<HERMES_HOME>/.env (~/.hermes/.env for the default profile)")

    def test_a_user_or_password_in_the_url_is_refused_without_quoting_it(self):
        for url in (
            "https://admin:pa55word@nms.example.com",
            "https://pa55word@nms.example.com/librenms",
            "https://nms.example.com/@pa55word",
        ):
            with self.assertRaises(client_mod.ConfigError) as caught:
                client_mod.settings_from_env(env(LIBRENMS_URL=url))
            self.assertNotIn("pa55word", str(caught.exception))
            self.assertNotIn("nms.example.com", str(caught.exception))
            self.assertIn("@", str(caught.exception))

    def test_clear_text_or_unverified_transport_needs_allow_insecure_transport(self):
        cases = (
            (env(LIBRENMS_URL="http://nms.example.com"), ["LIBRENMS_URL is http://"]),
            (env(LIBRENMS_VERIFY_SSL="false"), ["LIBRENMS_VERIFY_SSL is false"]),
            (
                env(LIBRENMS_URL="http://nms.example.com", LIBRENMS_VERIFY_SSL="no"),
                ["LIBRENMS_URL is http://", "LIBRENMS_VERIFY_SSL is false"],
            ),
        )
        for settings, said in cases:
            with self.assertRaises(client_mod.ConfigError) as caught:
                client_mod.settings_from_env(settings)
            message = str(caught.exception)
            for clause in said:
                self.assertIn(clause, message)
            self.assertIn("allow_insecure_transport: true in config.yaml", message)
            allowed = client_mod.settings_from_env(settings, allow_insecure=True)
            self.assertEqual(allowed["url"], settings["LIBRENMS_URL"])
            with self.assertRaises(client_mod.ConfigError):
                client_mod.LibreNMSClient.from_env(settings, session=Session())
            self.assertIsInstance(
                client_mod.LibreNMSClient.from_env(settings, session=Session(), allow_insecure=True),
                client_mod.LibreNMSClient,
            )

    def test_verify_ssl_is_true_false_or_an_existing_ca_bundle(self):
        for value in (None, "", "true", "1", "YES", "on"):
            self.assertIs(client_mod.verify_from_env(value), True, value)
        for value in ("false", "0", "No", "off"):
            self.assertIs(client_mod.verify_from_env(value), False, value)
        with tempfile.TemporaryDirectory() as folder:
            bundle = os.path.join(folder, "ca.pem")
            with open(bundle, "w") as handle:
                handle.write("-----BEGIN CERTIFICATE-----\n")
            self.assertEqual(client_mod.settings_from_env(env(LIBRENMS_VERIFY_SSL=bundle))["verify"], bundle)
            self.assertEqual(client_mod.settings_from_env(env(LIBRENMS_VERIFY_SSL=folder))["verify"], folder)
            missing = os.path.join(folder, "secret-user", "nope.pem")
            with self.assertRaises(client_mod.ConfigError) as caught:
                client_mod.settings_from_env(env(LIBRENMS_VERIFY_SSL=missing))
            self.assertNotIn("secret-user", str(caught.exception))  # a path names the OS account

    def test_timeout_takes_one_number_or_connect_and_read_within_bounds(self):
        self.assertEqual(client_mod.timeout_from_env("5,60"), (5.0, 60.0))
        self.assertEqual(client_mod.timeout_from_env(" 12 "), (12.0, 12.0))
        self.assertEqual(client_mod.timeout_from_env("0.1,600"), (0.1, 600.0))
        for junk in (None, "", "soon", "0", "-1", "nan", "inf", "601", "1,2,3", "5,", "5,0"):
            self.assertEqual(client_mod.timeout_from_env(junk), (30.0, 30.0), junk)
        self.assertEqual(client_mod.settings_from_env(env(LIBRENMS_TIMEOUT="5,60"))["timeout"], (5.0, 60.0))

    def test_proxy_is_none_a_url_or_refused_without_quoting_it(self):
        self.assertIsNone(client_mod.proxy_from_env(None))
        self.assertEqual(client_mod.proxy_from_env(" NONE "), "none")
        for good in (
            "http://u:pw@proxy:3128",
            "https://proxy.example.com",
            "http://svc-proxy:Pr0xy%23Pa%2Fss%3F!$&'()*+,;=:x@127.0.0.1:3128/",
            "http://[::1]:3128",
            "http://token-as-user@proxy:8080",
        ):
            self.assertEqual(client_mod.proxy_from_env(good), good)
        form = "LIBRENMS_PROXY must be none or an http:// or https:// proxy URL: scheme, host and port only"
        for junk in (
            "socks5://u:topsecret@proxy:1080",
            "topsecret:3128",
            "http://",
            "http://proxy:topsecret",  # a port that is no number: requests would quote the URL into the log
            "http://proxy:99999",
            "http://proxy:3128/topsecret",
            "http://proxy:3128?topsecret",
            "http://proxy:3128#topsecret",
            "http://pro xy:3128",
        ):
            with self.assertRaises(client_mod.ConfigError) as caught:
                client_mod.settings_from_env(env(LIBRENMS_PROXY=junk))
            self.assertEqual(str(caught.exception), form, junk)
        for junk in (
            "http://svc-proxy:Pr0xy#topsecret@127.0.0.1:3128",  # what urlsplit read as host "svc-proxy"
            "http://svc-proxy:Pr0xy/topsecret@127.0.0.1:3128",
            "http://svc-proxy:Pr0xy?topsecret@127.0.0.1:3128",
            "http://svc-proxy:top@secret@127.0.0.1:3128",
            "http://svc-proxy:top secret@127.0.0.1:3128",
            "http://svc-proxy:topsecret%zz@127.0.0.1:3128",
        ):
            with self.assertRaises(client_mod.ConfigError) as caught:
                client_mod.settings_from_env(env(LIBRENMS_PROXY=junk))
            self.assertTrue(str(caught.exception).startswith("LIBRENMS_PROXY's user name or password holds"), junk)
            self.assertNotIn("topsecret", str(caught.exception))
            self.assertNotIn("Pr0xy", str(caught.exception))

    def test_proxy_credentials_never_reach_a_log_line_or_an_error(self):
        proxy = "http://svc-proxy:Pr0xy%23Pass@127.0.0.1:3128"
        self.assertEqual(
            sorted(client_mod.proxy_secrets(proxy)), ["Pr0xy#Pass", "Pr0xy%23Pass", "svc-proxy:Pr0xy%23Pass"]
        )
        self.assertEqual(client_mod.proxy_secrets("http://tok3n-as-user@proxy:3128"), ["tok3n-as-user"])
        for nothing in (None, "none", "http://proxy:3128"):
            self.assertEqual(client_mod.proxy_secrets(nothing), [])
        failure = OSError(f"Failed to parse: {proxy} (Pr0xy#Pass)")
        client, _, _ = make(failure, proxy=proxy)
        with (
            self.assertRaises(client_mod.TransportError) as caught,
            self.assertLogs(client_mod.logger, "WARNING") as logs,
        ):
            client.get("devices")
        self.assertNotIn("Pr0xy", logs.output[0] + str(caught.exception))
        self.assertIn("http://<redacted>@127.0.0.1:3128 (<redacted>)", logs.output[0])
        client, _, _ = make(Resp(400, {"status": "error", "message": "proxy said Pr0xy#Pass"}), proxy=proxy)
        with self.assertRaises(client_mod.LibreNMSError) as caught:
            client.get("devices")
        self.assertNotIn("Pr0xy", json.dumps(caught.exception.to_dict()))

    def test_the_environments_proxy_credentials_never_reach_a_log_line_either(self):
        # with LIBRENMS_PROXY unset requests takes HTTPS_PROXY, which nothing validates (Hermes' model traffic reads
        # it too): an unencoded "#" in its password fails every request with an error quoting the whole URL
        proxy = "http://svc:Pr0xy#Pass@127.0.0.1:9"
        with env_proxies(HTTPS_PROXY=proxy, http_proxy="http://web:W3bPass@127.0.0.1:9", NO_PROXY="localhost"):
            self.assertEqual(sorted(client_mod.environment_proxy_secrets(BASE)), ["Pr0xy#Pass", "svc:Pr0xy#Pass"])
            self.assertEqual(
                sorted(client_mod.environment_proxy_secrets("http://nms.example.com")), ["W3bPass", "web:W3bPass"]
            )
            client, _, _ = make(OSError(f"Failed to parse: {proxy}"))
            with (
                self.assertRaises(client_mod.TransportError) as caught,
                self.assertLogs(client_mod.logger, "WARNING") as logs,
            ):
                client.get("devices")
            self.assertNotIn("Pr0xy", logs.output[0] + str(caught.exception))
            self.assertIn("Failed to parse: http://<redacted>@127.0.0.1:9", logs.output[0])
            # LIBRENMS_PROXY replaces the environment's proxy, and none ignores it: then requests never reads it
            self.assertEqual(make(proxy="none")[0]._proxy_secrets, [])
            self.assertEqual(make(proxy="http://proxy:3128")[0]._proxy_secrets, [])
        with env_proxies(all_proxy="svc:Pr0xy%23Pass@127.0.0.1:9"):  # no scheme: requests assumes http://
            self.assertEqual(
                sorted(client_mod.environment_proxy_secrets(BASE)), ["Pr0xy#Pass", "Pr0xy%23Pass", "svc:Pr0xy%23Pass"]
            )
        with env_proxies(HTTPS_PROXY="http://proxy:3128"):
            self.assertEqual(client_mod.environment_proxy_secrets(BASE), [])

    @unittest.skipUnless(HAVE_REQUESTS, "requests is not installed")
    def test_requests_failing_on_the_environments_proxy_logs_no_password(self):
        with env_proxies(HTTPS_PROXY="http://svc:Pr0xy#Pass@127.0.0.1:9"):
            client = client_mod.LibreNMSClient("https://librenms.invalid", TOKEN)
            client.retry_sleep = lambda seconds: None
            with (
                self.assertRaises(client_mod.TransportError),
                self.assertLogs(client_mod.logger, "WARNING") as logs,
            ):
                client.get("system")
        self.assertIn("http://<redacted>@127.0.0.1:9", logs.output[0])  # requests did quote the proxy URL
        self.assertNotIn("Pr0xy", logs.output[0])

    def test_is_configured_needs_url_and_token_only(self):
        self.assertFalse(client_mod.is_configured({}))
        self.assertFalse(client_mod.is_configured({"LIBRENMS_URL": BASE, "LIBRENMS_TOKEN": " "}))
        self.assertTrue(client_mod.is_configured(env()))
        self.assertTrue(client_mod.is_configured(env(LIBRENMS_URL="http://nms.example.com")))


class Secrets(unittest.TestCase):
    """``secret()``: Hermes' profile-scoped ``get_secret`` when importable, the environment only when it is not."""

    NAMES = ("agent", "agent.secret_scope")

    def setUp(self):
        self.saved_modules = {name: sys.modules.get(name) for name in self.NAMES}
        self.saved_env = {name: os.environ.get(name) for name in ("LIBRENMS_URL", "LIBRENMS_TOKEN")}
        os.environ["LIBRENMS_URL"] = "https://launch-profile.example.com"
        os.environ["LIBRENMS_TOKEN"] = "launch-profile-token"

    def tearDown(self):
        for name, module in self.saved_modules.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module
        for name, value in self.saved_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value

    def install(self, get_secret):
        agent = types.ModuleType("agent")
        scope = types.ModuleType("agent.secret_scope")
        scope.get_secret = get_secret
        agent.secret_scope = scope
        sys.modules["agent"] = agent
        sys.modules["agent.secret_scope"] = scope

    def test_without_hermes_the_environment_is_read(self):
        sys.modules["agent"] = None  # importing it raises ImportError
        self.assertEqual(client_mod.secret("LIBRENMS_URL"), "https://launch-profile.example.com")
        self.assertEqual(client_mod.settings_from_env()["token"], "launch-profile-token")
        self.assertTrue(client_mod.is_configured())

    def test_the_profile_scope_is_read_and_the_environment_is_not(self):
        asked = []
        scoped = {"LIBRENMS_URL": "https://profile-b.example.com", "LIBRENMS_TOKEN": "profile-b-token"}

        def get_secret(name, default=None):
            asked.append((name, default))
            return scoped.get(name, default)

        self.install(get_secret)
        self.assertEqual(client_mod.secret("LIBRENMS_URL"), "https://profile-b.example.com")
        client = client_mod.LibreNMSClient.from_env(session=Session())
        self.assertEqual(client.base_url, "https://profile-b.example.com")
        self.assertIn(("LIBRENMS_TOKEN", None), asked)
        del scoped["LIBRENMS_TOKEN"]  # unset in this profile: never the launch profile's token
        self.assertIsNone(client_mod.secret("LIBRENMS_TOKEN"))
        self.assertFalse(client_mod.is_configured())

    def test_an_unscoped_read_is_a_config_error_never_the_environment(self):
        class UnscopedSecretError(RuntimeError):
            pass

        def get_secret(name, default=None):
            raise UnscopedSecretError(f"no scope for {name}")

        self.install(get_secret)
        with self.assertRaises(client_mod.ConfigError) as caught:
            client_mod.secret("LIBRENMS_TOKEN")
        self.assertEqual(
            str(caught.exception), "no secret scope is bound for this Hermes profile; cannot read LIBRENMS_TOKEN"
        )
        with self.assertRaises(client_mod.ConfigError) as caught:
            client_mod.LibreNMSClient.from_env(session=Session())
        self.assertNotIn("launch-profile", str(caught.exception))
        self.assertFalse(client_mod.is_configured())
        self.assertTrue(client_mod.is_configured(env()))  # an explicit mapping does not go through Hermes


class Paths(unittest.TestCase):
    def test_seg_encodes_every_reserved_character(self):
        self.assertEqual(client_mod.seg("sw 1/a?b#c%d"), "sw%201%2Fa%3Fb%23c%25d")
        self.assertEqual(client_mod.seg("fe80::1"), "fe80%3A%3A1")
        self.assertEqual(client_mod.seg(12), "12")
        self.assertEqual(client_mod.seg("Zürich"), "Z%C3%BCrich")
        for bad in ("", ".", "..", "a\nb", "a\x00", "\x1b[2K", None, True, "a" + LONE):
            with self.assertRaises(client_mod.LibreNMSError, msg=repr(bad)) as caught:
                client_mod.seg(bad)
            self.assertEqual(caught.exception.kind, "invalid")

    def test_is_digits_takes_ascii_digits_only(self):
        for value in ("12", "0012", 0, 12):
            self.assertTrue(client_mod.is_digits(value), value)
        for value in (chr(0xB2), chr(0x661), "-1", -1, "1.5", " 12", "", True, False, None, 1.0, "12a"):
            self.assertFalse(client_mod.is_digits(value), repr(value))

    def test_path_joins_encoded_segments(self):
        self.assertEqual(client_mod.path("devices", "sw 1", "ports"), "devices/sw%201/ports")
        self.assertEqual(client_mod.path("devices", 12, "rename", "new/name"), "devices/12/rename/new%2Fname")


class Requests(unittest.TestCase):
    def test_every_request_carries_the_token_header_and_the_hardened_options(self):
        client, session, _ = make(Resp(200, OK), verify="/etc/ssl/ca.pem", timeout=(5, 60), proxy="none")
        self.assertEqual(client.get("devices", {"type": "os", "query": "ios"}), OK)
        sent = session.sent[0]
        self.assertEqual((sent["method"], sent["url"]), ("GET", f"{BASE}/api/v0/devices"))
        self.assertEqual(
            sent["headers"],
            {
                "X-Auth-Token": TOKEN,
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": client_mod.USER_AGENT,
                "Accept-Encoding": "identity",
            },
        )
        self.assertTrue(client_mod.USER_AGENT.startswith("hermes-plugin-librenms/"))
        self.assertEqual(sent["params"], {"type": "os", "query": "ios"})
        self.assertIsNone(sent["data"])
        self.assertIs(sent["allow_redirects"], False)
        self.assertIs(sent["stream"], True)
        self.assertEqual((sent["verify"], sent["timeout"]), ("/etc/ssl/ca.pem", (5.0, 60.0)))
        self.assertEqual(sent["proxies"], {"http": None, "https": None, "all": None})
        self.assertNotIn(TOKEN, sent["url"])

    def test_proxies_go_with_each_request_as_a_fresh_mapping(self):
        client, session, _ = make(Resp(200, OK), proxy="http://proxy:3128")
        client.get("devices")
        client.get("devices")
        first, second = (sent["proxies"] for sent in session.sent)
        self.assertEqual(first, {"http": "http://proxy:3128", "https": "http://proxy:3128"})
        self.assertIsNot(first, second)
        client, session, _ = make(Resp(200, OK))
        client.get("devices")
        self.assertIsNone(session.sent[0]["proxies"])

    def test_the_base_url_is_normalised_and_the_index_has_no_trailing_slash(self):
        client, session, _ = make(Resp(200, {"ping": f"{BASE}/api/v0/ping"}), url=f"{BASE}/api/v0/")
        self.assertEqual(client.base_url, BASE)
        self.assertEqual(client.route_names(), ["ping"])
        self.assertEqual(session.sent[0]["url"], f"{BASE}/api/v0")

    def test_json_bodies_are_serialised_and_method_overrides_dropped(self):
        client, session, _ = make(Resp(201, {"status": "ok", "message": "Devices removed"}))
        client.request(
            "delete",
            "devicegroups/3/devices",
            json={"devices": [1, 2], "_method": "PUT", "api_token": "x"},
            params={"_method": "PUT", "api_token": "x", "full": "1"},
        )
        sent = session.sent[0]
        self.assertEqual(sent["method"], "DELETE")
        self.assertEqual(json.loads(sent["data"]), {"devices": [1, 2]})
        self.assertEqual(sent["params"], {"full": "1"})

    def test_a_per_call_timeout_overrides_the_clients(self):
        client, session, _ = make(Resp(200, OK), timeout=30)
        client.request("POST", "devices", json={"hostname": "sw9"}, timeout=(10, 120))
        client.get("devices")
        self.assertEqual([sent["timeout"] for sent in session.sent], [(10.0, 120.0), (30.0, 30.0)])

    def test_unsafe_paths_are_refused_before_anything_is_sent(self):
        client, session, _ = make()
        for bad in (
            "/devices",
            "devices/",
            "devices//x",
            "devices/../system",
            "devices/./x",
            "devices?x=1",
            "devices#x",
            "http://evil.example.com/x",
            "//evil.example.com",
            "devices/%2e%2e/system",
            "devices/%252e%252e",
            "devices/%25252e%25252e",
            "devices/a%3Fb",
            "devices/a b",
            "devices\\x",
            "devices/fe80::1",
            12,
            None,
        ):
            with self.assertRaises(client_mod.LibreNMSError, msg=repr(bad)) as caught:
                client.request("GET", bad)
            self.assertEqual(caught.exception.kind, "invalid", bad)
        self.assertEqual(session.sent, [])
        self.assertEqual(client.calls, [])

    def test_an_encoded_slash_is_refused_before_anything_is_sent(self):
        # Laravel decodes the path before it matches routes: devices/1%2Fdiscover is the GET that schedules a
        # rediscovery, not a lookup of a device named "1/discover"
        client, session, _ = make()
        for bad in ("devices/1%2Fdiscover", "devices/sw1%2fdiscover", "devices/1%252Fdiscover", "a%2F..%2Fsystem"):
            with self.assertRaises(client_mod.LibreNMSError, msg=bad) as caught:
                client.request("GET", bad)
            self.assertEqual((caught.exception.kind, caught.exception.path), ("invalid", bad))
            self.assertIn("encoded '/'", str(caught.exception))
        with self.assertRaises(client_mod.LibreNMSError):
            client.get(client_mod.path("devices", "core-sw1.example.net/discover"))
        self.assertEqual(session.sent, [])

    def test_a_query_that_cannot_be_encoded_is_refused_before_it_is_sent(self):
        client, session, _ = make()
        for params in ({"q": "a" + LONE}, {"q": ["a", LONE]}, {LONE: "x"}):
            with self.assertRaises(client_mod.LibreNMSError) as caught:
                client.get("devices", params)
            self.assertEqual(caught.exception.kind, "invalid")
        self.assertEqual(session.sent, [])


class Redirects(unittest.TestCase):
    def test_a_redirect_is_reported_not_followed_and_its_location_cleaned(self):
        location = "https://user:pw@other.example.com:8443/librenms/api/v0/devices?api_token=leak#frag"
        for method in ("GET", "POST"):
            answer = Resp(301, raw=b"moved", headers={"Location": location})
            client, session, slept = make(answer)
            with self.assertRaises(client_mod.LibreNMSError) as caught:
                client.request(method, "devices", json={} if method == "POST" else None)
            self.assertEqual((caught.exception.kind, caught.exception.status), ("redirect", 301))
            self.assertEqual(
                str(caught.exception),
                "LibreNMS answered with a redirect (HTTP 301) to https://other.example.com:8443/librenms; "
                "set LIBRENMS_URL to that address",
            )
            self.assertEqual((len(session.sent), slept, answer.read, answer.closed), (1, [], 0, True))

    def test_a_relative_or_missing_location(self):
        client, _, _ = make(Resp(302, headers={"location": "/librenms/api/v0/devices"}))
        with self.assertRaises(client_mod.LibreNMSError) as caught:
            client.get("devices")
        self.assertIn("to https://nms.example.com/librenms;", str(caught.exception))
        for headers, said in (({}, "an address it did not name"), ({"Location": "javascript:x"}, "not an http")):
            client, _, _ = make(Resp(307, headers=headers))
            with self.assertRaises(client_mod.LibreNMSError) as caught:
                client.get("devices")
            self.assertIn(said, str(caught.exception))


class Retries(unittest.TestCase):
    def test_a_get_is_retried_twice_on_502_503_504_and_a_failed_connection(self):
        for failures in (
            (Resp(502, raw=b"Bad Gateway"), Resp(503, raw=b"Service Unavailable")),
            (Resp(504, raw=b"Gateway Timeout"),),
            (ConnectionRefusedError(61, "refused"), ConnectionResetError("reset")),
            (socket.gaierror(8, "nodename nor servname provided"), Resp(503, raw=b"x")),
        ):
            client, session, slept = make(*failures, Resp(200, OK))
            self.assertEqual(client.get("devices"), OK, failures)
            self.assertEqual(len(session.sent), len(failures) + 1)
            self.assertEqual(slept, [0.5, 1.0][: len(failures)])
            self.assertEqual(client.last_call["status"], 200)
            self.assertEqual(len(client.calls), len(failures) + 1)  # every try is recorded
            for answer in failures:
                if isinstance(answer, Resp):
                    self.assertTrue(answer.closed)

    def test_after_three_tries_the_answer_stands(self):
        client, session, slept = make(*[Resp(503, {"status": "error", "message": "maintenance"}) for _ in range(3)])
        with self.assertRaises(client_mod.LibreNMSError) as caught:
            client.get("devices")
        self.assertEqual((caught.exception.status, caught.exception.kind), (503, "server"))
        self.assertEqual((len(session.sent), slept), (3, [0.5, 1.0]))

    def test_retry_after_is_honoured_and_capped(self):
        client, _, slept = make(
            Resp(503, headers={"Retry-After": "2"}), Resp(503, headers={"retry-after": "600"}), Resp(200, OK)
        )
        client.get("devices")
        self.assertEqual(slept, [2.0, 5.0])

    def test_a_429_is_retried_once_for_a_get(self):
        for headers, wait in (
            ({"Retry-After": "3"}, 3.0),
            ({"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"}, 1.0),
            ({"Retry-After": "-4"}, 0.0),
            ({}, 1.0),
        ):
            client, _, slept = make(Resp(429, {"message": "Too Many Attempts."}, headers=headers), Resp(200, OK))
            self.assertEqual(client.get("devices"), OK)
            self.assertEqual(slept, [wait], headers)
        client, session, slept = make(Resp(429, {"message": "Too Many Attempts."}))
        with self.assertRaises(client_mod.LibreNMSError) as caught:
            client.get("devices")
        self.assertEqual((caught.exception.status, caught.exception.kind), (429, "api"))
        self.assertEqual((len(session.sent), len(slept)), (2, 1))

    def test_writes_are_never_retried(self):
        # a write that failed may have reached LibreNMS: sending it again could apply it twice
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            for failure in (
                Resp(429, {"message": "Too Many Attempts."}),
                Resp(502, raw=b"x"),
                Resp(503, raw=b"x"),
                Resp(504, raw=b"x"),
                ConnectionRefusedError(61, "refused"),
                socket.gaierror(8, "nodename"),
            ):
                client, session, slept = make(failure, Resp(200, OK))
                logged = isinstance(failure, BaseException)  # a transport failure is logged, an answer is not
                with (
                    self.assertRaises(client_mod.LibreNMSError),
                    self.assertLogs(client_mod.logger, "WARNING") if logged else contextlib.nullcontext(),
                ):
                    client.request(method, "devices/1", json={"field": "notes", "data": "x"})
                self.assertEqual((len(session.sent), slept), (1, []), (method, failure))

    def test_a_certificate_failure_or_a_read_timeout_is_not_retried(self):
        for failure, kind in (
            (ssl.SSLCertVerificationError(1, "certificate verify failed"), "tls"),
            (TimeoutError("read timed out"), "timeout"),
        ):
            client, session, slept = make(failure, Resp(200, OK))
            with self.assertRaises(client_mod.TransportError) as caught, self.assertLogs(client_mod.logger, "WARNING"):
                client.get("devices")
            self.assertEqual((len(session.sent), slept, caught.exception.failure), (1, [], kind))


class TransportErrors(unittest.TestCase):
    def test_a_transport_error_names_its_kind_and_an_id_and_nothing_else(self):
        failure = ConnectionRefusedError(61, f"refused by nms.example.com for {TOKEN}")
        client, _, _ = make(failure)
        with (
            self.assertRaises(client_mod.TransportError) as caught,
            self.assertLogs(client_mod.logger, "WARNING") as logs,
        ):
            client.request("POST", "devices", json={"hostname": "sw9"})
        exc = caught.exception
        self.assertRegex(exc.error_id, r"^err-[0-9a-f]{12}$")
        self.assertEqual(str(exc), f"could not reach LibreNMS (refused) {exc.error_id}")
        self.assertEqual(
            (exc.status, exc.kind, exc.failure, exc.method, exc.path), (0, "transport", "refused", "POST", "devices")
        )
        self.assertEqual(exc.to_dict()["message"], str(exc))
        self.assertIsInstance(exc, client_mod.LibreNMSError)
        self.assertEqual(len(logs.output), 1)
        self.assertIn(f"{exc.error_id}: POST {BASE}/api/v0/devices failed (refused)", logs.output[0])
        self.assertNotIn(TOKEN, logs.output[0])
        self.assertEqual(client.last_call["status"], 0)

    def test_a_request_that_could_not_be_made_is_an_internal_error_and_not_retried(self):
        client, session, slept = make(RuntimeError("bug"))
        with self.assertRaises(client_mod.TransportError) as caught, self.assertLogs(client_mod.logger, "WARNING"):
            client.get("devices")
        exc = caught.exception
        self.assertEqual(str(exc), f"the request to LibreNMS could not be made (internal error) {exc.error_id}")
        self.assertEqual((exc.failure, len(session.sent), slept), ("internal", 1, []))

    def test_a_body_that_breaks_off_while_it_is_read_is_a_transport_error(self):
        answer = Resp(200, raw=b"x" * (3 * client_mod.STREAM_CHUNK), breaks=True)
        client, session, _ = make(answer)
        with self.assertRaises(client_mod.TransportError), self.assertLogs(client_mod.logger, "WARNING"):
            client.get("devices")
        self.assertEqual((len(session.sent), answer.closed), (1, True))

    def test_failures_are_classified_by_their_root_cause(self):
        refused = ConnectionRefusedError(61, "Connection refused")
        wrapped = OSError("Failed to establish a new connection")
        wrapped.__cause__ = refused
        for exc, kind, retried in (
            (ssl.SSLError(1, "wrong version number"), "tls", False),
            (socket.gaierror(8, "nodename nor servname"), "dns", True),
            (refused, "refused", True),
            (ConnectionError(wrapped), "refused", True),
            (TimeoutError("timed out"), "timeout", False),
            (ConnectionResetError("reset"), "connection", True),
            (RuntimeError("anything else"), "connection", False),
        ):
            self.assertEqual(client_mod.transport_kind(exc), kind, exc)
            self.assertEqual(client_mod._retryable(exc), retried, exc)
        loop = OSError("loop")
        loop.__context__ = loop  # a cycle ends the walk instead of hanging it
        self.assertEqual(client_mod.transport_kind(loop), "connection")

    @unittest.skipUnless(HAVE_REQUESTS, "requests is not installed")
    def test_the_exceptions_requests_raises_are_classified(self):
        import requests.exceptions as rex

        for exc, kind, retried in (
            (rex.ConnectionError("refused"), "connection", True),
            (rex.ConnectTimeout("connect timed out"), "timeout", True),
            (rex.ReadTimeout("read timed out"), "timeout", False),
            (rex.SSLError("bad certificate"), "tls", False),
            (rex.ChunkedEncodingError("IncompleteRead"), "connection", True),
        ):
            self.assertTrue(client_mod._unreachable(exc), exc)
            self.assertEqual(client_mod.transport_kind(exc), kind, exc)
            self.assertEqual(client_mod._retryable(exc), retried, exc)
        for exc in (rex.InvalidURL("bad"), rex.InvalidHeader("bad"), rex.MissingSchema("no scheme")):
            self.assertFalse(client_mod._unreachable(exc), exc)  # the request itself is wrong


class Errors(unittest.TestCase):
    def error(self, answer, method="GET", path="devices/sw1"):
        client, _, _ = make(answer)
        with self.assertRaises(client_mod.LibreNMSError) as caught:
            client.request(method, path, json={} if method != "GET" else None)
        return caught.exception

    def test_401_names_the_token(self):
        exc = self.error(Resp(401, {"message": "Unauthenticated."}))
        self.assertEqual((exc.kind, exc.status), ("auth", 401))
        self.assertEqual(
            str(exc), "LibreNMS rejected the token (HTTP 401); check LIBRENMS_TOKEN and that its user is enabled"
        )

    def test_403_from_the_handler_or_the_middleware(self):
        exc = self.error(Resp(403, {"status": "error", "message": "Insufficient permissions to access this device"}))
        self.assertEqual(exc.kind, "forbidden")
        self.assertEqual(
            str(exc), "GET /api/v0/devices/sw1 -> HTTP 403: Insufficient permissions to access this device"
        )
        exc = self.error(Resp(403, {"message": "This action is unauthorized."}), "PATCH", "devices/1")
        self.assertEqual(
            (exc.kind, str(exc)), ("forbidden", "PATCH /api/v0/devices/1 -> HTTP 403: This action is unauthorized.")
        )

    def test_a_missing_route_is_not_a_missing_object(self):
        missing_route = Resp(404, {"status": "error", "message": "This API route doesn't exist."})
        self.assertEqual(self.error(missing_route).kind, "route")
        missing_device = Resp(404, {"status": "error", "message": "Device sw1 does not exist"})
        exc = self.error(missing_device)
        self.assertEqual(
            (exc.kind, str(exc)), ("not_found", "GET /api/v0/devices/sw1 -> HTTP 404: Device sw1 does not exist")
        )
        client, _, _ = make(missing_device)
        self.assertIsNone(client.get_or_none("devices/sw1"))
        client, _, _ = make(missing_route)
        with self.assertRaises(client_mod.LibreNMSError):
            client.get_or_none("ping")
        # Laravel's model binding answers a 404 with a bare message: still LibreNMS saying the object is missing
        self.assertEqual(self.error(Resp(404, {"message": "No query results for model"})).kind, "not_found")

    def test_a_404_that_did_not_come_from_librenms_is_no_answer_about_the_object(self):
        # LibreNMS answers every 404 under /api/v0 with JSON; anything else is a web server or proxy that never
        # passed the request on (LIBRENMS_URL without LibreNMS's sub-path, say), and must not read as "no rows"
        nginx = b"<html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1>nginx</body></html>"
        for answer in (
            Resp(404, raw=nginx, headers={"Content-Type": "text/html"}),
            Resp(404, raw=b"404 page not found\n", headers={"Content-Type": "text/plain"}),
            Resp(404, raw=b"", headers={}),
            Resp(404, {"error": "not found"}),
            Resp(404, ["not found"]),
        ):
            exc = self.error(answer)
            self.assertEqual((exc.kind, exc.status, exc.body), ("invalid", 404, None), answer.raw)
            self.assertEqual(
                str(exc),
                "GET /api/v0/devices/sw1 -> HTTP 404 that did not come from LibreNMS (not its JSON); check "
                "LIBRENMS_URL, including any sub-path LibreNMS is served under",
            )
            client, _, _ = make(answer)
            with self.assertRaises(client_mod.LibreNMSError) as caught:
                client.get_or_none("devices/sw1")
            self.assertEqual(caught.exception.kind, "invalid")

    def test_422_flattens_a_field_message(self):
        body = {"status": "error", "message": {"name": ["The name has already been taken."], "type": ["bad", "worse"]}}
        exc = self.error(Resp(422, body), "PATCH", "devicegroups/3")
        self.assertEqual(exc.kind, "validation")
        self.assertEqual(
            str(exc),
            "PATCH /api/v0/devicegroups/3 -> HTTP 422: name: The name has already been taken.; type: bad, worse",
        )
        self.assertEqual(exc.body, body)
        # field names that are also credential key names read as LibreNMS wrote them: only the token is scrubbed
        exc = self.error(Resp(422, {"status": "error", "message": {"param": ["The param field is required."]}}))
        self.assertTrue(str(exc).endswith("HTTP 422: param: The param field is required."))

    def test_a_5xx_keeps_only_a_clean_message_of_librenms_own(self):
        trace = {"trace": [{"file": "/opt/librenms/app/x.php"}], "file": "/opt/librenms/x.php", "line": 3}
        exc = self.error(
            Resp(500, {"status": "error", "message": "Failed to update the service with id 4", **trace}), "PATCH"
        )
        self.assertEqual((exc.kind, exc.status), ("server", 500))
        self.assertEqual(str(exc), "PATCH /api/v0/devices/sw1 -> HTTP 500: Failed to update the service with id 4")
        self.assertEqual(exc.body, {"status": "error", "message": "Failed to update the service with id 4"})
        withheld = "LibreNMS server error (details withheld; see the LibreNMS log)"
        for answer in (
            Resp(500, {"status": "error", "message": "SQLSTATE[23000]: duplicate entry 'c0mmunity' for key"}),
            Resp(500, {"status": "error", "message": "m" * 450 + " (SQL: update ... 'hunter2')"}),  # past the summary
            Resp(500, {"status": "error", "message": "Failed", "detail": "(SQL: select 'hunter2')"}),
            Resp(500, {"status": "error", "message": "x (SQL: insert into services values ('-p hunter2'))"}),
            Resp(500, {"message": "Server Error", "exception": "QueryException", **trace}),
            Resp(502, raw=b"<html><body>Bad Gateway nginx/1.2 at /var/www</body></html>", headers={}),
            Resp(503, {"message": "Service Unavailable"}),
        ):
            exc = self.error(answer, "POST")
            self.assertEqual(
                (str(exc), exc.body, exc.kind),
                (f"POST /api/v0/devices/sw1 -> HTTP {answer.status_code}: {withheld}", None, "server"),
            )
            for leak in ("c0mmunity", "hunter2", "/opt/librenms", "/var/www"):
                self.assertNotIn(leak, json.dumps(exc.to_dict()))

    def test_other_errors_and_an_error_status_in_a_2xx(self):
        exc = self.error(Resp(400, {"status": "error", "message": "Invalid port ID."}), "PATCH", "ports/9/description")
        self.assertEqual(
            (exc.kind, exc.status, str(exc)),
            ("api", 400, "PATCH /api/v0/ports/9/description -> HTTP 400: Invalid port ID."),
        )
        exc = self.error(Resp(200, {"status": "error", "message": "Device field is not allowed to be updated"}))
        self.assertEqual((exc.kind, exc.status), ("api", 200))

    def test_the_token_is_scrubbed_from_messages_and_bodies(self):
        body = {"status": "error", "message": f"token {TOKEN} rejected", "echo": {"header": [TOKEN]}}
        for status in (400, 422, 500):
            exc = self.error(Resp(status, body), "POST")
            dumped = json.dumps(exc.to_dict())
            self.assertNotIn(TOKEN, str(exc))
            self.assertNotIn(TOKEN, dumped)
            self.assertIn("<token>", str(exc))

    def test_to_dict_has_the_contract_keys_and_clips_bodies(self):
        exc = self.error(Resp(400, raw=b"y" * 2000, headers={}))
        shown = exc.to_dict()
        self.assertEqual(set(shown), {"message", "status", "kind", "method", "path", "body"})
        self.assertEqual(
            (shown["status"], shown["method"], shown["path"], len(shown["body"])), (400, "GET", "devices/sw1", 500)
        )
        self.assertLessEqual(len(str(exc)), len("GET /api/v0/devices/sw1 -> HTTP 400: ") + 400)
        exc = self.error(Resp(400, {"status": "error", "message": "m" * 1000}))
        self.assertTrue(exc.to_dict()["body"]["message"].endswith("… [truncated 500 chars]"))
        self.assertEqual(client_mod.ConfigError("x").to_dict()["kind"], "config")

    def test_error_text_is_cut_by_what_it_takes_escaped_and_kept_raw(self):
        # 400 and 500 characters as the model reads them; raw still, so a step's secrets can be scrubbed from it
        tag = chr(0xE0078)  # ten characters escaped
        exc = self.error(Resp(400, {"status": "error", "message": tag * 1000}))
        self.assertEqual(str(exc), "GET /api/v0/devices/sw1 -> HTTP 400: " + tag * 40)
        self.assertEqual(exc.to_dict()["body"]["message"], tag * 50 + "… [truncated 9500 chars]")
        exc = self.error(Resp(400, raw=("\u200b" * 2000).encode(), headers={}))
        self.assertEqual(exc.to_dict()["body"], "\u200b" * 83)  # 498: an 84th would take 504


class Bodies(unittest.TestCase):
    def test_a_read_stops_at_the_byte_cap(self):
        answer = Resp(200, raw=b"[" + b"1," * 200_000 + b"1]")
        client, _, _ = make(answer)
        with self.assertRaises(client_mod.LibreNMSError) as caught:
            client.request("GET", "devices", max_bytes=1000)
        self.assertEqual((caught.exception.kind, caught.exception.status), ("too_large", 200))
        self.assertIn("larger than 1000 bytes", str(caught.exception))
        self.assertEqual((answer.read, answer.closed), (1001, True))  # one chunk past the cap, no more

    def test_a_body_up_to_the_cap_is_read_whole(self):
        raw = json.dumps({"status": "ok", "logs": ["x" * 500]}).encode()
        client, _, _ = make(Resp(200, raw=raw))
        self.assertEqual(client.request("GET", "logs/eventlog", max_bytes=len(raw))["logs"], ["x" * 500])

    def test_an_error_body_is_read_to_a_small_cap_without_failing_as_too_large(self):
        answer = Resp(404, raw=b"z" * (4 * client_mod.ERROR_BODY_BYTES), headers={})
        client, _, _ = make(answer)
        with self.assertRaises(client_mod.LibreNMSError) as caught:
            client.get("devices/sw1")
        self.assertEqual(caught.exception.kind, "invalid")  # a proxy's page: not LibreNMS, and not too large
        self.assertLessEqual(answer.read, 2 * client_mod.ERROR_BODY_BYTES)  # the cap and the chunk past it

    def test_an_empty_body_is_none(self):
        for raw in (b"", b"  \n"):
            client, _, _ = make(Resp(200, raw=raw, headers={"Content-Type": "text/html"}))
            self.assertIsNone(client.get("resources/ip/addresses/ipv5"))

    def test_an_answer_that_is_not_json_is_invalid(self):
        for raw, kind in ((b"<html>Login</html>", "text/html"), (b"\x89PNG\r\n\x1a\n", "image/png")):
            client, _, _ = make(Resp(200, raw=raw, headers={"Content-Type": kind}))
            with self.assertRaises(client_mod.LibreNMSError) as caught:
                client.get("devices/1/graphs")
            self.assertEqual(caught.exception.kind, "invalid")
            self.assertEqual(
                str(caught.exception), "GET /api/v0/devices/1/graphs -> HTTP 200: LibreNMS did not answer with JSON"
            )

    def test_a_bare_json_array_is_returned(self):
        client, _, _ = make(Resp(200, [{"hostname": "sw1", "os": "ios"}]))
        self.assertEqual(client.get("oxidized"), [{"hostname": "sw1", "os": "ios"}])


class CallLog(unittest.TestCase):
    def test_calls_record_method_path_status_and_duration_only(self):
        client, _, _ = make(Resp(404, {"status": "error", "message": "Device sw1 does not exist"}), Resp(200, OK))
        client.get_or_none("devices/sw1", {"secret_param": "hunter2"})
        client.request("PATCH", "devices/1", json={"field": "notes", "data": "hunter2"})
        calls = client.reset_calls()
        self.assertEqual(
            [{k: c[k] for k in ("method", "path", "status")} for c in calls],
            [
                {"method": "GET", "path": "/api/v0/devices/sw1", "status": 404},
                {"method": "PATCH", "path": "/api/v0/devices/1", "status": 200},
            ],
        )
        for call in calls:
            self.assertEqual(set(call), {"method", "path", "status", "duration_ms"})
            self.assertIsInstance(call["duration_ms"], int)
        self.assertNotIn("hunter2", json.dumps(calls))
        self.assertEqual(client.last_call, calls[-1])
        self.assertEqual((client.calls, client.reset_calls()), ([], []))
        self.assertEqual(client.last_call["path"], "/api/v0/devices/1")  # last_call survives a reset

    def test_the_call_log_keeps_the_latest_entries(self):
        client, _, _ = make(Resp(200, OK))
        for number in range(client_mod.MAX_CALLS + 5):
            client.get(f"devices/{number}")
        self.assertEqual(len(client.calls), client_mod.MAX_CALLS)
        self.assertEqual(client.calls[-1]["path"], f"/api/v0/devices/{client_mod.MAX_CALLS + 4}")
        self.assertEqual(client.calls[0]["path"], "/api/v0/devices/5")


class Convenience(unittest.TestCase):
    def test_result_unwraps_the_envelope(self):
        body = {"status": "ok", "message": "Found 2", "count": 2, "groups": [1, 2], "total": 2}
        self.assertEqual(client_mod.LibreNMSClient.result(body), [1, 2])
        self.assertEqual(client_mod.LibreNMSClient.result(body, "groups"), [1, 2])
        self.assertIsNone(client_mod.LibreNMSClient.result(body, "devices"))
        self.assertIsNone(client_mod.LibreNMSClient.result({"status": "ok"}))
        self.assertEqual(client_mod.LibreNMSClient.result([1]), [1])

    def test_system_and_route_names(self):
        info = {"local_ver": "26.10.0", "local_sha": "91b9a40", "db_schema": "x (412)"}
        client, session, _ = make(Resp(200, {"status": "ok", "system": [info], "count": 1}))
        self.assertEqual(client.system(), info)
        self.assertEqual(session.sent[0]["url"], f"{BASE}/api/v0/system")
        client, _, _ = make(Resp(200, {"status": "ok", "system": []}))
        self.assertEqual(client.system(), {})
        client, _, _ = make(Resp(200, {"ping": "u", "get_device": "u", "add_device": "u"}))
        self.assertEqual(client.route_names(), ["add_device", "get_device", "ping"])
        client, _, _ = make(Resp(401, {"message": "Unauthenticated."}))
        self.assertEqual(client.route_names(), [])

    def test_posture_names_no_host_path_or_proxy(self):
        saved = {name: os.environ.pop(name, None) for name in ("REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE")}
        try:
            cases = (
                ({}, {"scheme": "https", "verify": "on"}),
                ({"verify": False}, {"verify": "off"}),
                ({"verify": "/home/someone/ca.pem"}, {"verify": "custom CA"}),
                ({"proxy": "none"}, {"proxy": "ignored"}),
                ({"proxy": "http://u:pw@proxy.example.com:3128"}, {"proxy": "LIBRENMS_PROXY"}),
            )
            for options, expected in cases:
                client, _, _ = make(**options)
                shown = client.posture()
                self.assertEqual({k: shown[k] for k in expected}, expected, options)
                self.assertEqual(set(shown), {"scheme", "verify", "proxy"})
                self.assertNotRegex(json.dumps(shown), r"example\.com|someone|pw")
        finally:
            for name, value in saved.items():
                if value is not None:
                    os.environ[name] = value


class _LocalServer(http.server.ThreadingHTTPServer):
    def server_bind(self):
        # HTTPServer.server_bind looks up the fully qualified name of 127.0.0.1, which can take half a minute
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


@unittest.skipUnless(HAVE_REQUESTS, "requests is not installed")
class RealSession(unittest.TestCase):
    """The production ``requests.Session`` against a local server: what actually goes over the wire."""

    def setUp(self):
        seen = self.seen = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append({"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}})
                if self.path.startswith("/api/v0/moved"):
                    self.send_response(302)
                    self.send_header("Location", "/api/v0/system")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                body = json.dumps({"status": "ok", "system": [{"local_ver": "26.10.0"}], "count": 1}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", "laravel_session=abc123; Path=/")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = _LocalServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.folder = tempfile.TemporaryDirectory()
        netrc = os.path.join(self.folder.name, "netrc")
        with open(netrc, "w") as handle:
            handle.write("machine 127.0.0.1 login netrc-user password netrc-password\n")
        os.chmod(netrc, 0o600)
        self.saved_netrc = os.environ.get("NETRC")
        os.environ["NETRC"] = netrc

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.folder.cleanup()
        if self.saved_netrc is None:
            os.environ.pop("NETRC", None)
        else:
            os.environ["NETRC"] = self.saved_netrc

    def test_the_wire_carries_the_token_header_and_no_netrc_password_or_cookie(self):
        client = client_mod.LibreNMSClient(self.url, TOKEN, proxy="none")
        self.assertIsNone(client._session)  # made on first use
        self.assertEqual(client.system()["local_ver"], "26.10.0")
        self.assertEqual(client.system()["local_ver"], "26.10.0")
        first, second = (entry["headers"] for entry in self.seen)
        self.assertEqual(first["x-auth-token"], TOKEN)
        self.assertEqual(first["user-agent"], client_mod.USER_AGENT)
        self.assertEqual(first["accept-encoding"], "identity")
        self.assertEqual(first["content-type"], "application/json")
        self.assertNotIn("authorization", first)  # ~/.netrc is never read
        self.assertNotIn("cookie", second)  # the session cookie the server set is not sent back
        # the control: a plain session does read the netrc file this test points at
        requests.get(f"{self.url}/api/v0/system", proxies={"http": None, "https": None, "all": None}, timeout=5)
        self.assertTrue(self.seen[-1]["headers"]["authorization"].startswith("Basic "))

    def test_a_redirect_is_not_followed(self):
        client = client_mod.LibreNMSClient(self.url, TOKEN, proxy="none")
        with self.assertRaises(client_mod.LibreNMSError) as caught:
            client.get("moved")
        self.assertEqual(caught.exception.kind, "redirect")
        self.assertEqual([entry["path"] for entry in self.seen], ["/api/v0/moved"])
        self.assertIn(f"to {self.url};", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
