import json
import unittest

from .helpers import submodule

redact = submodule("redact")

RLO = chr(0x202E)  # right-to-left override
LONE = chr(0xD800)  # a lone surrogate, as JSON can carry


class Mask(unittest.TestCase):
    def test_credential_keys_are_masked_at_any_depth(self):
        device = {
            "device_id": 1,
            "hostname": "sw1",
            "community": "s3cret-comm",
            "AuthPass": "v3-auth",
            "cryptopass": "v3-priv",
            "authname": "snmpuser",
            "nested": {"services": [{"service_id": 4, "service_param": "-p hunter2"}], "Token": "abc"},
        }
        masked = redact.mask(device)
        self.assertEqual(masked["community"], redact.MASK)
        self.assertEqual(masked["AuthPass"], redact.MASK)  # compared lowercased
        self.assertEqual(masked["cryptopass"], redact.MASK)
        self.assertEqual(masked["authname"], redact.MASK)
        self.assertEqual(masked["nested"]["services"][0]["service_param"], redact.MASK)
        self.assertEqual(masked["nested"]["Token"], redact.MASK)
        self.assertEqual((masked["device_id"], masked["hostname"]), (1, "sw1"))
        for secret in ("s3cret-comm", "v3-auth", "v3-priv", "snmpuser", "hunter2", "abc"):
            self.assertNotIn(secret, json.dumps(masked))
        # a deep copy: the original keeps its values
        self.assertEqual(device["community"], "s3cret-comm")
        self.assertEqual(device["nested"]["services"][0]["service_param"], "-p hunter2")

    def test_unset_values_stay_so_not_set_reads_differently_from_set(self):
        masked = redact.mask({"community": None, "authpass": "", "param": [], "secret": {}, "psk": 0})
        self.assertEqual(masked, {"community": None, "authpass": "", "param": [], "secret": {}, "psk": redact.MASK})

    def test_a_whole_structure_under_a_credential_key_is_masked(self):
        self.assertEqual(redact.mask({"param": {"user": "u", "pass": "p"}}), {"param": redact.MASK})

    def test_keys_can_be_given(self):
        self.assertEqual(
            redact.mask({"Notes": "x", "community": "c"}, keys={"notes"}), {"Notes": redact.MASK, "community": "c"}
        )

    def test_non_container_values_pass_through(self):
        self.assertEqual(redact.mask("community"), "community")
        self.assertEqual(redact.mask(("a", {"key": "k"})), ("a", {"key": redact.MASK}))


class ScrubText(unittest.TestCase):
    def test_the_token_is_replaced_also_url_encoded(self):
        token = "12|abcdefghijklmnop"
        text = redact.scrub_text(f"token {token} and 12%7Cabcdefghijklmnop", token)
        self.assertNotIn("abcdefghijklmnop", text)
        self.assertEqual(text.count(redact.TOKEN_MASK), 2)

    def test_scrub_token_replaces_the_token_only(self):
        token = "12|abcdefghijklmnop"
        text = redact.scrub_token(f'{{"message": "bad {token}", "password": "x"}}', token)
        self.assertEqual(text, '{"message": "bad <token>", "password": "x"}')
        self.assertEqual(redact.scrub_token(None, token), "")

    def test_a_short_token_is_not_replaced(self):
        self.assertEqual(redact.scrub_text("abc in a sentence", "abc"), "abc in a sentence")

    def test_extra_secret_values_are_replaced_longest_first(self):
        text = redact.scrub_text(
            "check -H x -p topsecret1 then topsecret", None, extra=["topsecret", "topsecret1", "ab", None]
        )
        self.assertEqual(text, f"check -H x -p {redact.MASK} then {redact.MASK}")

    def test_a_short_secret_is_replaced_where_it_stands_alone(self):
        # a three-character community is still a credential; inside "public" or "pub1" it is not that community
        text = "community pub failed (pub), public pub1 _pub-pub"
        self.assertEqual(
            redact.scrub_values(text, ["pub", ""]),
            "community <redacted> failed (<redacted>), public pub1 _<redacted>-<redacted>",
        )
        self.assertTrue(redact.holds_any(text, ["pub"]))
        self.assertFalse(redact.holds_any("public pub1", ["pub"]))
        self.assertTrue(redact.holds_any("in publicity", ["publ"]))  # four characters and more: anywhere
        self.assertFalse(redact.holds_any("anything", ["", None]))
        self.assertEqual(redact.scrub_text('{"x": "ab"}', None, extra=["ab"]), f'{{"x": "{redact.MASK}"}}')

    def test_credential_pairs_are_masked_in_free_text(self):
        text = redact.scrub_text(
            "SQL: insert (\"community\":\"pub lic\", 'authpass': 'x y', password=hunter2; X-Auth-Token: tok123)"
        )
        for secret in ("pub lic", "x y", "hunter2", "tok123"):
            self.assertNotIn(secret, text)
        self.assertIn(f'"community":"{redact.MASK}"', text)
        self.assertIn(f"'authpass': '{redact.MASK}'", text)
        self.assertIn(f"password={redact.MASK}", text)

    def test_bearer_credentials_are_masked(self):
        self.assertNotIn("abc.def", redact.scrub_text("Authorization: Bearer abc.def"))

    def test_ordinary_words_are_left_alone(self):
        for text in ("Missing parameters: name", "keyboard: 1", "monkey=3", '"community": null', "token"):
            self.assertEqual(redact.scrub_text(text), text)

    def test_none_is_empty_text(self):
        self.assertEqual(redact.scrub_text(None, "x" * 10), "")


class Clip(unittest.TestCase):
    def test_long_strings_are_cut_saying_so(self):
        self.assertEqual(redact.clip("abcdef", 4), "abcd… [truncated 2 chars]")
        self.assertEqual(redact.clip("abcd", 4), "abcd")

    def test_clip_is_deep_and_leaves_keys_whole(self):
        long_key = "k" * 10
        clipped = redact.clip({long_key: ["x" * 10, {"y": "z" * 10}], "n": 5}, 3)
        self.assertEqual(clipped[long_key][0], "xxx… [truncated 7 chars]")
        self.assertEqual(clipped[long_key][1]["y"], "zzz… [truncated 7 chars]")
        self.assertEqual(clipped["n"], 5)

    def test_for_model_masks_then_clips(self):
        out = redact.for_model({"community": "c" * 5000, "notes": "n" * 3000})
        self.assertEqual(out["community"], redact.MASK)
        self.assertTrue(out["notes"].endswith("… [truncated 1000 chars]"))
        self.assertEqual(len(out["notes"].split("…")[0]), 2000)


class Printable(unittest.TestCase):
    def test_terminal_controls_are_escaped(self):
        label = "sw1\x1b[2K\rFAKE" + RLO + "gnp.exe" + LONE + "\x07\x7f\x85"
        shown = redact.printable(label)
        for char in ("\x1b", "\r", RLO, LONE, "\x07", "\x7f", "\x85"):
            self.assertNotIn(char, shown)
        self.assertEqual(shown, "sw1\\x1b[2K\\rFAKE\\u202egnp.exe\\ud800\\x07\\x7f\\x85")
        shown.encode("utf-8")  # printable once a lone surrogate is escaped

    def test_bidi_marks_and_separators_are_escaped(self):
        for code in (0x061C, 0x200E, 0x200F, 0x2028, 0x2029, 0x202A, 0x202B, 0x202C, 0x202D, 0x2066, 0x2069):
            self.assertEqual(redact.printable(chr(code)), f"\\u{code:04x}", hex(code))

    def test_newlines_tabs_and_ordinary_text_stay(self):
        text = 'Plan lnp-1\n\tdevice #12 "sw1" — Zürich 東京'
        self.assertEqual(redact.printable(text), text)
        self.assertEqual(redact.printable(None), "")
        self.assertEqual(redact.printable(42), "42")


class OneLine(unittest.TestCase):
    def test_line_breaks_and_tabs_are_escaped_too(self):
        forged = 'Move sw1\n[0] update      port #9 "Gi0/1"\r\n\tSummary: 0 delete\u2028\x85' + RLO
        shown = redact.one_line(forged)
        self.assertEqual(len(shown.splitlines()), 1)
        self.assertEqual(
            shown, 'Move sw1\\n[0] update      port #9 "Gi0/1"\\r\\n\\tSummary: 0 delete\\u2028\\x85\\u202e'
        )
        self.assertEqual(redact.one_line(shown), shown)  # escaping twice changes nothing
        self.assertEqual(redact.one_line(None), "")


if __name__ == "__main__":
    unittest.main()
