import unittest

from .helpers import submodule

diff = submodule("diff")
base = submodule("resources.base")
Field = base.Field


class Normalise(unittest.TestCase):
    def norm(self, kind, value, **kwargs):
        return diff.normalise(Field("f", kind, **kwargs), value)

    def rejects(self, kind, value, **kwargs):
        with self.assertRaises(ValueError) as ctx:
            self.norm(kind, value, **kwargs)
        return str(ctx.exception)

    def test_bool_spellings(self):
        for value in (True, 1, "1", "true", "TRUE", " yes ", "Yes"):
            self.assertIs(self.norm("bool", value), True, value)
        for value in (False, 0, "0", "false", "False", "no"):
            self.assertIs(self.norm("bool", value), False, value)

    def test_bool_rejects_other_values(self):
        for value in (2, -1, "on", "off", "y", "", 1.0, [], {}):
            self.rejects("bool", value)
        self.assertEqual(self.rejects("bool", "maybe"), 'f: expected true or false, got "maybe"')

    def test_int(self):
        self.assertEqual(self.norm("int", 7), 7)
        self.assertEqual(self.norm("int", " 42 "), 42)
        self.assertEqual(self.norm("int", -3), -3)
        for value in (True, False, 1.5, 7.0, "7.0", "-3", "²", "١", "", "x", [1]):
            self.rejects("int", value)
        self.assertEqual(self.rejects("int", True), "f: expected an integer, got true")

    def test_text_maps_none_to_empty_and_str_keeps_none(self):
        self.assertEqual(self.norm("text", None), "")
        self.assertEqual(self.norm("text", "a b"), "a b")
        self.assertIsNone(self.norm("str", None))
        self.assertEqual(self.norm("str", ""), "")
        self.rejects("text", 5)
        self.rejects("str", ["x"])

    def test_none_passes_through_for_other_kinds(self):
        for kind in ("int", "bool", "float", "list_int", "json", "env"):
            self.assertIsNone(self.norm(kind, None), kind)
        self.assertIsNone(self.norm("enum", None, choices=("a",)))

    def test_float_rounds_and_rejects_non_finite(self):
        self.assertEqual(self.norm("float", "37.123456789123"), 37.12345679)
        self.assertEqual(self.norm("float", 3), 3.0)
        self.assertEqual(self.norm("float", " -122.4 "), -122.4)
        for value in (True, "nan", "inf", float("nan"), float("inf"), "x", "", [1.0]):
            self.rejects("float", value)

    def test_list_int_sorted_unique(self):
        self.assertEqual(self.norm("list_int", [3, "1", 3, 2]), [1, 2, 3])
        self.assertEqual(self.norm("list_int", []), [])
        self.assertEqual(self.norm("list_int", [-1]), [-1])
        for value in ([True], ["a"], [1.5], "1,2", (1, 2), {"a": 1}):
            self.rejects("list_int", value)

    def test_json_parses_strings_and_canonicalises(self):
        parsed = self.norm("json", '{"b": 1, "a": [1, {"d": 2, "c": 3}]}')
        self.assertEqual(parsed, {"a": [1, {"c": 3, "d": 2}], "b": 1})
        self.assertEqual(list(parsed), ["a", "b"])
        self.assertEqual(self.norm("json", [1, 2]), [1, 2])
        for value in ("1", '"x"', "not json", 5, {1, 2}, {"a": {1}}):
            self.rejects("json", value)

    def test_enum(self):
        self.assertEqual(self.norm("enum", "v2c", choices=("v1", "v2c", "v3")), "v2c")
        message = self.rejects("enum", "V2C", choices=("v1", "v2c", "v3"))
        self.assertEqual(message, 'f: expected one of v1, v2c, v3, got "V2C"')
        self.rejects("enum", 1, choices=("1",))

    def test_env_reference(self):
        self.assertEqual(self.norm("env", {"env": "LIBRENMS_SNMP_X"}), {"env": "LIBRENMS_SNMP_X"})
        for value in ({"env": ""}, {"env": 5}, {"env": "A", "x": 1}, "public", ["env"]):
            self.rejects("env", value)

    def test_error_names_only_the_type_of_long_or_multiline_values(self):
        self.assertEqual(self.rejects("int", "x" * 41), "f: expected an integer, got str")
        self.assertEqual(self.rejects("int", "a\nb"), "f: expected an integer, got str")
        self.assertEqual(self.rejects("int", {"a": 1}), "f: expected an integer, got dict")

    def test_unknown_kind_is_refused_by_field(self):
        with self.assertRaises(ValueError):
            Field("f", "string")


class ValuesEqual(unittest.TestCase):
    def test_equal_across_spellings(self):
        self.assertTrue(diff.values_equal(Field("b", "bool"), "1", True))
        self.assertTrue(diff.values_equal(Field("i", "int"), "7", 7))
        self.assertTrue(diff.values_equal(Field("t", "text"), None, ""))
        self.assertTrue(diff.values_equal(Field("f", "float"), "37.60", 37.6))
        self.assertTrue(diff.values_equal(Field("l", "list_int"), [2, 1], ["1", 2]))
        self.assertTrue(diff.values_equal(Field("j", "json"), '{"a":1,"b":2}', {"b": 2, "a": 1}))

    def test_different_values(self):
        self.assertFalse(diff.values_equal(Field("b", "bool"), True, 0))
        self.assertFalse(diff.values_equal(Field("i", "int"), None, 0))
        self.assertFalse(diff.values_equal(Field("s", "str"), None, ""))

    def test_unparseable_side_compared_as_is(self):
        field = Field("i", "int")
        self.assertFalse(diff.values_equal(field, "junk", 1))
        self.assertTrue(diff.values_equal(field, "junk", "junk"))


class ComputeChanges(unittest.TestCase):
    fields = {
        "purpose": Field("purpose", "text"),
        "disabled": Field("disabled", "bool"),
        "poller_group": Field("poller_group", "int"),
    }
    current = {"device_id": 12, "purpose": None, "disabled": 0, "poller_group": "0"}

    def test_only_real_differences_are_changes(self):
        changes = diff.compute_changes(
            {"purpose": "", "disabled": "false", "poller_group": 0}, self.current, self.fields
        )
        self.assertEqual(changes, {})

    def test_changes_hold_normalised_values(self):
        changes = diff.compute_changes({"purpose": "core", "disabled": "1"}, self.current, self.fields)
        self.assertEqual(changes, {"purpose": {"from": "", "to": "core"}, "disabled": {"from": False, "to": True}})

    def test_missing_key_counts_as_null_and_unknown_keys_compare_raw(self):
        changes = diff.compute_changes({"poller_group": 2, "extra": [1]}, {"device_id": 12}, self.fields)
        self.assertEqual(changes, {"poller_group": {"from": None, "to": 2}, "extra": {"from": None, "to": [1]}})
        self.assertEqual(diff.compute_changes({"extra": "x"}, {"extra": "x"}, self.fields), {})

    def test_invalid_desired_value_raises(self):
        with self.assertRaises(ValueError):
            diff.compute_changes({"disabled": "perhaps"}, self.current, self.fields)


class Formatting(unittest.TestCase):
    def test_format_value(self):
        self.assertEqual(diff.format_value(None), "null")
        self.assertEqual(diff.format_value(True), "true")
        self.assertEqual(diff.format_value(7), "7")
        self.assertEqual(diff.format_value(37.6), "37.6")
        self.assertEqual(diff.format_value("edge"), '"edge"')
        self.assertEqual(diff.format_value(""), '""')
        self.assertEqual(diff.format_value({"b": 1, "a": "é"}), '{"a": "é", "b": 1}')
        self.assertEqual(diff.format_value({"env": "LIBRENMS_SNMP_COMMUNITY"}), "$LIBRENMS_SNMP_COMMUNITY")

    def test_format_value_keeps_controls_visible_and_clips(self):
        self.assertEqual(diff.format_value("a\x1b[2K\nb"), '"a\\u001b[2K\\nb"')
        clipped = diff.format_value("x" * 100, limit=10)
        self.assertEqual(len(clipped), 10)
        self.assertTrue(clipped.endswith("…"))

    def test_format_value_stays_on_one_line(self):
        self.assertEqual(diff.format_value("a\u2028b\x85c"), '"a\\u2028b\\x85c"')  # JSON leaves these as they are
        self.assertEqual(diff.format_value({"env": "X\nSummary: 0 delete"}), "$X\\nSummary: 0 delete")
        self.assertEqual(diff.format_value({"note": "a\u202eb"}), '{"note": "a\\u202eb"}')

    def test_redacted_digest(self):
        shown = diff.redacted("-H host -p hunter2")
        self.assertRegex(shown, r"^<redacted sha256:[0-9a-f]{8}>$")
        self.assertNotIn("hunter2", shown)
        self.assertEqual(shown, diff.redacted("-H host -p hunter2"))
        self.assertNotEqual(shown, diff.redacted("-H host -p other"))
        self.assertEqual(diff.redacted(""), '""')
        self.assertEqual(diff.redacted(None), "null")

    def test_format_live_hides_only_sensitive_fields(self):
        self.assertEqual(diff.format_live(Field("desc", "text"), "x"), '"x"')
        self.assertEqual(diff.format_live(None, "x"), '"x"')
        self.assertEqual(diff.format_live(Field("param", "text", sensitive=True), "x"), diff.redacted("x"))

    def test_render_changes_sensitive_from_is_digest_to_is_verbatim(self):
        fields = {"param": Field("param", "text", sensitive=True), "desc": Field("desc", "text")}
        changes = {
            "param": {"from": "-p oldsecret", "to": "-p newvalue"},
            "desc": {"from": "a", "to": "b"},
        }
        lines = diff.render_changes(changes, fields)
        self.assertEqual(lines[0], 'desc: "a" -> "b"')
        self.assertEqual(lines[1], f'param: {diff.redacted("-p oldsecret")} -> "-p newvalue"')
        self.assertNotIn("oldsecret", "\n".join(lines))

    def test_render_changes_labels(self):
        fields = {"location_id": Field("location_id", "int", nullable=True)}
        changes = {"location_id": {"from": 3, "to": 7, "from_label": "NYC", "to_label": "SFO-1"}}
        self.assertEqual(diff.render_changes(changes, fields), ["location_id: 3 (NYC) -> 7 (SFO-1)"])
        changes = {"location_id": {"from": 3, "to": 7, "to_label": "SFO-1"}}
        self.assertEqual(diff.render_changes(changes, fields), ["location_id: 3 -> 7 (SFO-1)"])
        changes = {"location_id": {"from": 3, "to": 7, "from_label": "NYC\n[1] delete", "to_label": "SFO\t1\u2029"}}
        self.assertEqual(
            diff.render_changes(changes, fields), ["location_id: 3 (NYC\\n[1] delete) -> 7 (SFO\\t1\\u2029)"]
        )

    def test_env_name(self):
        self.assertEqual(diff.env_name({"env": "X"}), "X")
        self.assertIsNone(diff.env_name({"env": "X", "y": 1}))
        self.assertIsNone(diff.env_name("X"))


if __name__ == "__main__":
    unittest.main()
