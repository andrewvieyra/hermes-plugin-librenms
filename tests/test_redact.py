import json
import unittest

from .helpers import submodule

redact = submodule("redact")

RLO = chr(0x202E)  # right-to-left override
LONE = chr(0xD800)  # a lone surrogate, as JSON can carry
TAG_I = chr(0xE0069)  # a tag character: nothing to a person, "i" to a tokenizer, ten characters escaped


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

    def test_the_limit_counts_a_character_as_long_as_its_escape(self):
        # an entity label or eventlog row is kept raw; what it shows as escaped stays within the limit
        self.assertEqual(redact.clip("ab" + TAG_I * 5, 25), "ab" + TAG_I * 2 + "… [truncated 30 chars]")
        self.assertEqual(redact.clip(TAG_I * 20, 200), TAG_I * 20)  # 200 as escaped: fits
        clipped = redact.clip({"ifAlias": "\u200b" * 300}, 200)["ifAlias"]
        self.assertEqual(len(redact.printable(clipped.split("…")[0])), 198)  # 33 of 6, a 34th would not fit
        self.assertTrue(clipped.endswith("… [truncated 1602 chars]"))

    def test_clipping_twice_changes_nothing(self):
        for text in ("x" * 50, "\u200b" * 50, "a" + TAG_I * 30 + "b"):
            once = redact.clip(text, 20)
            self.assertNotEqual(once, text)
            self.assertEqual(redact.clip(once, 20), once, text)
            self.assertLess(len(redact.clip(once, 5)), len(once))  # a smaller limit still cuts
        self.assertEqual(redact.clip("x" * 30 + "… [truncated 9 chars]", 20), "x" * 20 + "… [truncated 31 chars]")

    def test_cut_takes_what_fits_escaped_and_never_half_an_escape(self):
        self.assertEqual(redact.cut("x" * 10, 4), "xxxx")
        self.assertEqual(redact.cut("a" + "\u200b" * 3, 8), "a\u200b")  # 1 + 6; a second would make 13
        self.assertEqual(redact.cut("a" + "\u200b" + "bcdef", 9), "a\u200bbc")
        self.assertEqual(redact.cut(TAG_I * 3, 9), "")
        # a keycap's selector shows as itself; cut off from the keycap it is escaped, so it goes too
        self.assertEqual(redact.cut("ab1\ufe0f\u20e3", 5), "ab1\ufe0f\u20e3")
        self.assertEqual(redact.cut("ab1\ufe0f\u20e3", 4), "ab1")

    def test_for_model_masks_then_clips(self):
        out = redact.for_model({"community": "c" * 5000, "notes": "n" * 3000})
        self.assertEqual(out["community"], redact.MASK)
        self.assertTrue(out["notes"].endswith("… [truncated 1000 chars]"))
        self.assertEqual(len(out["notes"].split("…")[0]), 2000)

    def test_for_model_escapes_before_it_clips_so_the_limit_bounds_what_the_model_reads(self):
        out = redact.for_model({"ifAlias": "a" + RLO * 10, "password": RLO}, 13)
        self.assertEqual(out, {"ifAlias": "a\\u202e\\u202e… [truncated 48 chars]", "password": redact.MASK})


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

    def test_characters_that_show_as_nothing_are_escaped(self):
        # two labels that read the same, a word that hides another, ASCII spelled in tag characters
        for code in (
            0x00AD, 0x034F, 0x115F, 0x1160, 0x17B4, 0x180B, 0x180E, 0x200B, 0x200C, 0x200D, 0x2060, 0x2062, 0x2064,
            0x206A, 0x3164, 0xFE00, 0xFE0D, 0xFEFF, 0xFFA0, 0xFFF9, 0x1BCA0, 0x1D173, 0xE0001, 0xE0041, 0xE007F,
            0xE0100, 0xE01EF,
        ):  # fmt: skip
            shown = redact.printable("a" + chr(code) + "b")
            self.assertEqual(shown, "a" + chr(code).encode("unicode_escape").decode("ascii") + "b", hex(code))
            self.assertTrue(shown.isascii(), hex(code))
        self.assertEqual(redact.printable("sw1\U000e0069\U000e0067"), "sw1\\U000e0069\\U000e0067")

    def test_newlines_tabs_and_ordinary_text_stay(self):
        text = 'Plan lnp-1\n\tdevice #12 "sw1" — Zürich 東京 rack\u00a0B4'
        self.assertEqual(redact.printable(text), text)
        self.assertEqual(redact.printable(None), "")
        self.assertEqual(redact.printable(42), "42")

    def test_text_and_emoji_presentation_selectors_stay_after_what_they_change(self):
        # an emoji or symbol, the few emoji outside the symbol categories, a keycap
        text = (
            "\u26a0\ufe0f do not reboot \u2764\ufe0e \u00a9\ufe0f \u203c\ufe0f \u2139\ufe0e 1\ufe0f\u20e3 #\ufe0e\u20e3"
        )
        self.assertEqual(redact.printable(text), text)
        self.assertEqual(redact.visible({"note": text}), {"note": text})

    def test_presentation_selectors_that_show_as_nothing_are_escaped(self):
        # after a letter or a digit with no keycap, at the start, after another selector: two names that read the same
        for text, shown in (
            ("core-sw1\ufe0f.example.net", "core-sw1\\ufe0f.example.net"),
            ("core-sw\ufe0e1.example.net", "core-sw\\ufe0e1.example.net"),
            ("\ufe0fsw1", "\\ufe0fsw1"),
            ("c\ufe0f\ufe0e\ufe0f\ufe0eore", "c\\ufe0f\\ufe0e\\ufe0f\\ufe0eore"),  # a bit each, in a run
            ("\u2764\ufe0f\ufe0f\ufe0e", "\u2764\ufe0f\\ufe0f\\ufe0e"),  # the first is the emoji's own
            ("Z\u00fcrich\ufe0f", "Z\u00fcrich\\ufe0f"),
            ("\u200b\ufe0f", "\\u200b\\ufe0f"),
        ):
            self.assertEqual(redact.printable(text), shown, ascii(text))
            self.assertEqual(redact.one_line(shown), shown)  # escaping twice changes nothing
        self.assertEqual(redact.visible(["sw1\ufe0f"]), ["sw1\\ufe0f"])


class Visible(unittest.TestCase):
    def test_strings_and_keys_at_any_depth_are_escaped(self):
        value = {"ifAlias" + RLO: ["a\u200bb", ("c\x9b", {"d": "e\x1b[2K"})], "n": 5, 7: None, "ok": "plain"}
        self.assertEqual(
            redact.visible(value),
            {"ifAlias\\u202e": ["a\\u200bb", ("c\\x9b", {"d": "e\\x1b[2K"})], "n": 5, 7: None, "ok": "plain"},
        )

    def test_line_ends_and_tabs_keep_their_meaning_and_a_lone_cr_is_escaped(self):
        self.assertEqual(redact.visible("a\r\nb\tc\rd\n"), "a\nb\tc\\rd\n")

    def test_escaping_twice_changes_nothing_and_the_result_encodes(self):
        once = redact.visible("x" + RLO + LONE + "\U000e0041\r\n")
        self.assertEqual(redact.visible(once), once)
        once.encode("utf-8")
        text = "nothing to escape"
        self.assertIs(redact.visible(text), text)


class Untrusted(unittest.TestCase):
    def test_the_marker_names_the_fields_and_carries_the_notice(self):
        self.assertEqual(
            redact.untrusted("port", "ifAlias"),
            {"untrusted_fields": ["port", "ifAlias"], "untrusted_notice": redact.UNTRUSTED_NOTICE},
        )
        self.assertIn("not instructions", redact.UNTRUSTED_NOTICE)

    def test_mark_untrusted_names_the_keys_held_and_comes_before_the_first(self):
        payload = {"success": True, "count": 2, "result": None, "results": [1], "note": "", "extra": {"mac": "x"}}
        marked = redact.mark_untrusted(payload, "extra", "results", "result", "note")
        self.assertEqual(
            list(marked),
            ["success", "count", "result", "untrusted_fields", "untrusted_notice", "results", "note", "extra"],
        )
        self.assertEqual(marked["untrusted_fields"], ["results", "extra"])  # in the result's order, empty ones left out
        self.assertEqual({k: v for k, v in marked.items() if not k.startswith("untrusted_")}, payload)

    def test_a_result_holding_none_of_the_keys_is_left_as_it_is(self):
        payload = {"success": True, "results": []}
        self.assertIs(redact.mark_untrusted(payload, "results"), payload)


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
