"""The location resource against the fake LibreNMS: validation, planning, apply-time preconditions, verified writes,
PartialWrite settlement and rollback (design §8.3 location and §16.7; specs/ln-groups.md LO-1..LO-6)."""

from __future__ import annotations

import json
import unittest
from datetime import datetime

from .base import PluginTestCase, optional
from .fake_librenms import SECRETS, TOKEN, FakeResponse
from .helpers import submodule

PLAN_ID = "lnp-20261028T190000Z-ab12"
PDX = {"location": "PDX-4", "lat": 45.5898, "lng": -122.5951}
PDX_KEY = {"location": "PDX-4"}
SFO_STATE = {"location": "SFO-1", "lat": 37.6213, "lng": -122.379, "fixed_coordinates": True}
# Devices #1 and #2 are at SFO-1; #2 follows its SNMP sysLocation (override_sysLocation off).
SFO_SNAPSHOT = dict(SFO_STATE, device_ids=[1, 2], sysLocation_device_ids=[2])
TAKEN = "LibreNMS location names are unique, ignoring case and accents"
ANCHOR = "the location was never deleted"


class Died(BaseException):
    """The process dying during a request (Ctrl-C, OOM, a gateway restart): nothing in the plugin catches it."""


def resumable(context, entry):
    """*context* with the executor's ``checkpoint``: it merges progress into the entry's ``revert_progress``."""

    def checkpoint(progress):
        entry["revert_progress"] = {**(entry.get("revert_progress") or {}), **progress}

    return dict(context, checkpoint=checkpoint)


class DetachThenFail:
    """del_location failing between its two statements (devices detached, the row kept, a 500 answered), which the
    fake cannot do: its forced failures strike before a request or after it took full effect."""

    def __init__(self, fake, location_id):
        self.fake = fake
        self.location_id = location_id

    def request(self, method, url, **kwargs):
        if method == "DELETE" and url.endswith(f"/api/v0/locations/{self.location_id}"):
            for device in self.fake.tables["devices"].values():
                if device["location_id"] == self.location_id:
                    device["location_id"] = None
            body = {"status": "error", "message": "Failed to delete the location SFO-1"}
            return FakeResponse(500, {"Content-Type": "application/json"}, json.dumps(body).encode())
        return self.fake.request(method, url, **kwargs)


class LocationCase(PluginTestCase):
    def setUp(self):
        super().setUp()
        self.base = submodule("resources.base")
        self.diff = submodule("diff")
        self.res = submodule("resources.location").RESOURCE
        self.LibreNMSError = self.client_mod.LibreNMSError
        self.context = {"plan_id": PLAN_ID, "settings": self.settings, "actor": None}

    def plan(self, kind, data=None, id=None, match=None, client=None):
        data = data or {}
        self.assertEqual(self.res.validate(kind, data, self.settings), [])
        op = {"op": kind, "resource": "location", "id": id, "match": match, "data": data}
        return self.res.plan_step(client or self.client, 0, op, self.settings)

    def apply(self, step, client=None):
        return self.res.execute(client or self.client, step, self.context)

    def entry(self, step, result, status="done", **extra):
        """A journal entry as the executor writes it."""
        keys = ("index", "action", "resource", "object_id", "label", "parent_id", "inverse_kind")
        entry = {key: step.get(key) for key in keys}
        entry.update(status=status, at="2026-10-28T19:00:00Z", **result, **extra)
        return entry

    def applied(self, kind, data=None, id=None):
        step = self.plan(kind, data, id=id)
        return step, self.entry(step, self.apply(step))

    def revert(self, entry, step, force=False, client=None):
        return self.res.revert(client or self.client, entry, force, dict(self.context, step=step))

    def location(self, location_id):
        return self.fake.tables["locations"].get(location_id)

    def device_location(self, device_id):
        return self.fake.tables["devices"][device_id]["location_id"]

    def write_calls(self):
        return [(c["method"], c["path"], c["json"]) for c in self.fake.writes()]

    def assertNoSecrets(self, *values):
        text = json.dumps(values, default=str)
        for secret in SECRETS:
            self.assertNotIn(secret, text)


class Validation(LocationCase):
    def errors(self, op, data, settings=None):
        return self.res.validate(op, data, settings or self.settings)

    def test_create_requires_a_name_and_non_zero_coordinates(self):
        coordinates = "LibreNMS API v0 cannot create a location without coordinates"
        self.assertEqual(
            self.errors("create", {}),
            [
                "location is required to create a location",
                f"lat and lng are required to create a location and must not be 0: {coordinates}",
            ],
        )
        self.assertEqual(
            self.errors("create", {"location": "X", "lat": 0, "lng": "12.5"}),
            [f"lat is required to create a location and must not be 0: {coordinates}"],
        )
        self.assertEqual(
            self.errors("create", {"location": "X", "lat": "1", "lng": None}),
            [f"lng is required to create a location and must not be 0: {coordinates}"],
        )

    def test_coordinates_are_numbers_in_range(self):
        self.assertEqual(
            self.errors("create", {"location": "X", "lat": "north", "lng": 200}),
            ['lat: expected a number, got "north"', "lng: must be between -180 and 180, got 200.0"],
        )
        self.assertEqual(
            self.errors("update", {"lat": True, "lng": "-180.5"}),
            ["lat: expected a number, got true", "lng: must be between -180 and 180, got -180.5"],
        )
        self.assertEqual(self.errors("update", {"lat": -90, "lng": 180}), [])
        self.assertEqual(self.errors("update", {"lat": None}), [])  # an edit may clear the coordinates

    def test_unknown_fields_and_value_types(self):
        self.assertEqual(
            self.errors("create", dict(PDX, description="hq", fixed_coordinates="maybe")),
            [
                "cannot create location field(s) description; allowed: fixed_coordinates, lat, lng, location",
                'fixed_coordinates: expected true or false, got "maybe"',
            ],
        )
        self.assertEqual(self.errors("create", dict(PDX, fixed_coordinates="yes")), [])
        self.assertEqual(
            self.errors("update", {"location": 5, "timestamp": "now"}),
            [
                "cannot update location field(s) timestamp; allowed: lat, lng, location",
                "location: expected a string, got 5",
            ],
        )

    def test_fixed_coordinates_cannot_be_edited(self):
        self.assertEqual(
            self.errors("update", {"fixed_coordinates": True, "lat": 10}),
            ["fixed_coordinates can only be set when a location is created; LibreNMS API v0 ignores it on an edit"],
        )

    def test_names(self):
        self.assertEqual(self.errors("update", {"location": ""}), ["location: a location name cannot be empty"])
        self.assertEqual(self.errors("update", {"location": None}), ["location: null is not allowed"])
        self.assertEqual(
            self.errors("create", dict(PDX, location=" PDX-4")),
            ["location: leading or trailing spaces are not allowed (LibreNMS trims them on an edit only)"],
        )
        self.assertEqual(self.errors("update", {"location": "x" * 256}), ["location: at most 255 characters"])
        self.assertEqual(self.errors("update", {"location": "Bldg 7/Floor 2 ü"}), [])

    def test_maintenance_data(self):
        self.assertEqual(self.errors("maintenance", {"duration": "2:00"}), [])
        full = {"duration": "0:30", "start": "2026-10-29 01:00:00", "title": "fibre", "notes": "n", "behavior": 3}
        self.assertEqual(self.errors("maintenance", full), [])
        self.assertEqual(self.errors("maintenance", {"duration": "1:00", "behavior": "mute_alerts"}), [])
        no_colon = "LibreNMS turns a value without a colon into a schedule that has already ended"
        cases = {
            'duration is required: hours:minutes, such as "2:00"': {},
            f'duration: expected hours:minutes such as "2:00", got "2"; {no_colon}': {"duration": "2"},
            f'duration: expected hours:minutes such as "2:00", got 120; {no_colon}': {"duration": 120},
            f'duration: expected hours:minutes such as "2:00", got "2:60"; {no_colon}': {"duration": "2:60"},
            "duration must be longer than 0:00": {"duration": "0:00"},
            "duration 72:01 is longer than max_maintenance_hours (72); raise "
            "plugins.entries.librenms.settings.max_maintenance_hours to allow it": {"duration": "72:01"},
        }
        for message, data in cases.items():
            self.assertEqual(self.errors("maintenance", data), [message], data)
        self.assertEqual(self.errors("maintenance", {"duration": "72:00"}), [])
        roomy = self.settings_mod.Settings(max_maintenance_hours=100)
        self.assertEqual(self.errors("maintenance", {"duration": "99:59"}, roomy), [])

    def test_maintenance_value_errors(self):
        start = 'start: expected "YYYY-MM-DD HH:MM:SS" in the LibreNMS server\'s time zone, got '
        behavior = "behavior: expected one of skip_alerts, mute_alerts, run_alerts (or 1, 2, 3), got "
        cases = [
            ({"start": "2026-10-29T01:00:00"}, start + '"2026-10-29T01:00:00"'),
            ({"start": "2026-02-30 01:00:00"}, start + '"2026-02-30 01:00:00"'),
            ({"start": "2026-10-29 01:00:00\n"}, start + '"2026-10-29 01:00:00\\n"'),
            ({"behavior": "pause"}, behavior + '"pause"'),
            ({"behavior": 4}, behavior + "4"),
            ({"behavior": True}, behavior + "true"),
            ({"title": 5}, "title: expected a string of at most 200 characters"),
            ({"title": "t" * 201}, "title: expected a string of at most 200 characters"),
            ({"notes": ["a"]}, "notes: expected a string"),
            (
                {"reason": "x", "end": "y"},
                "cannot schedule maintenance with field(s) end, reason; allowed: behavior, duration, notes, start, "
                "title",
            ),
        ]
        for extra, message in cases:
            self.assertEqual(self.errors("maintenance", {"duration": "2:00", **extra}), [message], extra)

    def test_delete_takes_no_field_checks(self):
        self.assertEqual(self.errors("delete", {}), [])

    @unittest.skipIf(optional("planner") is None, "planner.py is not written yet")
    def test_delete_needs_allow_delete(self):
        planner = submodule("planner")
        settings = self.settings_mod.Settings(allow_delete=False)
        operations = [{"op": "delete", "resource": "location", "id": 3}]
        with self.assertRaises(planner.PlanError) as ctx:
            planner.build_plan(self.client, operations, "test", settings, self.client.base_url)
        self.assertIn("allow_delete", json.dumps(ctx.exception.errors))
        self.assertEqual(self.fake.writes(), [])


class Reads(LocationCase):
    def test_state_from_get_location(self):
        obj = self.res.get(self.client, 1)
        state = self.res.state(self.client, obj)
        self.assertEqual({k: v for k, v in state.items() if k != "timestamp"}, dict(SFO_STATE, id=1))
        self.assertEqual(state["timestamp"], "2026-10-28T12:00:01.000000Z")
        self.assertEqual(self.fake.calls[-1]["path"], "location/1")
        self.assertIsNone(self.res.get(self.client, 99))
        self.assertEqual(self.res.volatile_fields(state), {"timestamp"})

    def test_find_is_case_insensitive_and_reads_by_id(self):
        count, obj = self.res.find(self.client, {"location": "sfo-1 "})
        self.assertEqual((count, obj["id"]), (1, 1))
        self.assertEqual([c["path"] for c in self.fake.calls], ["resources/locations", "location/1"])
        self.assertEqual(self.res.find(self.client, {"location": "SFO"}), (0, None))
        with self.assertRaisesRegex(self.base.StepError, r"matched by its name"):
            self.res.find(self.client, {"location": 1})

    def test_find_when_librenms_has_no_location(self):
        self.fake.tables["locations"].clear()  # resources/locations answers 404 "Locations do not exist"
        self.assertEqual(self.res.find(self.client, {"location": "SFO-1"}), (0, None))

    def test_names_that_are_digits_or_hold_slashes_are_addressed_by_id(self):
        self.fake.seed("locations", {"id": 7, "location": "42", "lat": 1.5, "lng": 2.5})
        self.fake.seed("locations", {"id": 8, "location": "Bldg 7/Floor 2", "lat": 1.5, "lng": 2.5})
        self.assertEqual(self.res.find(self.client, {"location": "42"})[1]["id"], 7)
        step = self.plan("update", {"lat": 3.5}, match={"location": "bldg 7/floor 2"})
        self.apply(step)
        paths = {c["path"] for c in self.fake.calls}
        self.assertTrue({"location/7", "location/8", "locations/8"} <= paths)
        self.assertFalse({"location/42", "location/Bldg 7/Floor 2"} & paths)
        self.assertEqual(self.location(8)["lat"], 3.5)

    def test_docs_shape_and_odd_values(self):
        legacy = {"status": "ok", "get_location": [{"id": 3, "location": "LON-3", "lat": "51.5074", "lng": "-0.1278",
                                                    "fixed_coordinates": 1, "timestamp": "x"}], "count": 1}  # fmt: skip
        self.fake.fail_on("GET", "location/3", 200, legacy, times=1)
        state = self.res.state(self.client, self.res.get(self.client, 3))
        self.assertEqual((state["lat"], state["lng"], state["fixed_coordinates"]), (51.5074, -0.1278, True))
        self.fake.touch("locations", 3, lat="n/a")
        self.assertEqual(self.res.state(self.client, self.res.get(self.client, 3))["lat"], "n/a")


class Planning(LocationCase):
    def test_create(self):
        step = self.plan("create", {"location": "PDX-4", "lat": "45.5898", "lng": -122.5951, "fixed_coordinates": 0})
        self.assertEqual(step["action"], "create")
        self.assertEqual(step["data"], dict(PDX, fixed_coordinates=False))
        self.assertEqual(step["exists_check"], {"location": "PDX-4"})
        self.assertEqual((step["label"], step["object_id"], step["resolved_by"]), ("PDX-4", None, None))
        self.assertEqual(
            (step["inverse_kind"], step["inverse_note"]),
            ("exact", "deletes the location; refused while a device uses it unless forced"),
        )
        self.assertEqual(step["notes"], [])
        self.assertEqual(
            self.res.describe(step),
            [
                'location="PDX-4", lat=45.5898, lng=-122.5951, fixed_coordinates=false',
                'precondition: no location matches {"location": "PDX-4"}',
            ],
        )

    def test_create_of_a_taken_name_warns(self):
        step = self.plan("create", dict(PDX, location="sfo-1"))
        self.assertEqual(step["action"], "create")
        self.assertEqual(
            step["notes"],
            [
                f'a location named "SFO-1" already exists (#1); {TAKEN}; this create is refused at apply unless an '
                "earlier step frees the name"
            ],
        )

    def test_names_compare_as_the_unique_index_does(self):
        self.fake.seed("locations", {"id": 7, "location": "Zürich HQ", "lat": 47.3769, "lng": 8.5417})
        self.assertEqual(self.res.find(self.client, {"location": "ZURICH hq "})[1]["id"], 7)
        step = self.plan("create", {"location": "Zurich HQ", "lat": 47.0, "lng": 8.0})
        self.assertEqual(step["notes"][0].split(";")[0], 'a location named "Zürich HQ" already exists (#7)')
        self.assertEqual(
            self.res.check(self.client, step), '1 location(s) now match {"location": "Zurich HQ"}; expected none'
        )

    def test_upsert_of_an_existing_location_becomes_an_update(self):
        data = {"location": "SFO-1", "lat": 37.7, "lng": -122.379, "fixed_coordinates": False}
        step = self.plan("create", data, match={"location": "sfo-1"})
        self.assertEqual((step["action"], step["upsert"], step["object_id"]), ("update", True, 1))
        self.assertEqual(step["changes"], {"lat": {"from": 37.6213, "to": 37.7}})
        self.assertEqual(step["payload"], {"lat": 37.7})
        self.assertEqual(
            step["notes"],
            ["fixed_coordinates cannot be changed on an existing location; the matched one keeps its own value"],
        )
        self.assertEqual(step["inverse_kind"], "exact")

    def test_upsert_noop_and_absent(self):
        data = {"location": "SFO-1", "lat": "37.6213", "lng": -122.379}
        self.assertEqual(self.plan("create", data, match={"location": "SFO-1"})["action"], "noop")
        step = self.plan("create", PDX, match={"location": "PDX-4"})
        self.assertEqual((step["action"], step["resolved_by"], step["exists_check"]), ("create", "match", PDX_KEY))

    def test_update_of_a_geocoded_location(self):
        step = self.plan("update", {"lat": "40.75", "location": "NYC-2b"}, id=2)
        self.assertEqual(
            step["changes"],
            {"lat": {"from": 40.7128, "to": 40.75}, "location": {"from": "NYC-2", "to": "NYC-2b"}},
        )
        self.assertEqual(step["payload"], {"lat": 40.75, "location": "NYC-2b"})
        state = step["precondition"]["state"]
        self.assertEqual((state["id"], state["fixed_coordinates"]), (2, False))
        self.assertIn("timestamp", state)
        # access-sw2, the only device here, overrides sysLocation: no polling caveat for the rename
        self.assertEqual(
            step["notes"],
            ["fixed_coordinates is false: LibreNMS may re-geocode lat/lng; a later rollback may report a conflict"],
        )
        self.assertEqual(self.res.describe(step), ["lat: 40.7128 -> 40.75", 'location: "NYC-2" -> "NYC-2b"'])

    def test_rename_warns_about_devices_that_follow_sysLocation(self):
        step = self.plan("update", {"location": "SFO-1 HQ"}, id=1)
        self.assertEqual(
            step["notes"],
            [
                "device(s) #2 here follow SNMP sysLocation (override_sysLocation is off): while their sysLocation "
                'reads "SFO-1", polling re-creates a location of that name and moves them to it'
            ],
        )
        self.assertEqual(self.plan("update", {"lat": 37.5}, id=1)["notes"], [])
        self.assertNoSecrets(step)

    def test_rename_onto_a_taken_name_is_refused(self):
        with self.assertRaises(self.base.StepError) as ctx:
            self.plan("update", {"location": "nyc-2"}, id=1)
        self.assertEqual(str(ctx.exception), f'a location named "NYC-2" already exists (#2); {TAKEN}')
        step = self.plan("update", {"location": "sfo-1"}, id=1)  # a change of case only
        self.assertEqual(step["changes"], {"location": {"from": "SFO-1", "to": "sfo-1"}})

    def test_targets(self):
        self.assertEqual(self.plan("update", {"lat": 51.5074}, match={"location": "LON-3"})["action"], "noop")
        with self.assertRaisesRegex(self.base.StepError, r'^no location matches \{"location": "MIA-9"\}$'):
            self.plan("update", {"lat": 1}, match={"location": "MIA-9"})
        with self.assertRaisesRegex(self.base.StepError, r"^location #99 does not exist$"):
            self.plan("update", {"lat": 1}, id=99)

    def test_delete_records_the_devices_it_detaches(self):
        step = self.plan("delete", id=1)
        self.assertEqual(step["snapshot"], SFO_SNAPSHOT)
        self.assertEqual(
            (step["inverse_kind"], step["inverse_note"]),
            ("lossy", "re-created with a new id; alert-rule scoping and maintenance links to the old id are lost"),
        )
        self.assertEqual(
            step["notes"],
            [
                "LibreNMS detaches device(s) #1, #2 from this location (their location_id becomes null); rollback "
                "re-creates the location and attaches them again",
                "device(s) #2 here follow SNMP sysLocation (override_sysLocation is off): while their sysLocation "
                'reads "SFO-1", polling re-creates a location of that name and moves them to it, under a new id; a '
                "rollback then reports a conflict",
            ],
        )
        self.assertIn({"type": "location_id", "query": "1"}, [c["params"] for c in self.fake.calls])
        self.assertNoSecrets(step)
        self.assertEqual(self.plan("delete", id=3)["notes"], [])

    def test_delete_of_a_location_without_coordinates_is_irreversible(self):
        self.fake.seed("locations", {"id": 9, "location": "Closet"})  # as update_device's firstOrCreate makes one
        self.fake.touch("devices", 4, location_id=9)
        step = self.plan("delete", id=9)
        self.assertEqual(step["inverse_kind"], "none")
        self.assertIn("cannot create a location without them", step["inverse_note"])
        self.assertEqual(
            step["notes"],
            [
                "LibreNMS detaches device(s) #4 from this location (their location_id becomes null)",
                "device(s) #4 here follow SNMP sysLocation (override_sysLocation is off): while their sysLocation "
                'reads "Closet", polling re-creates a location of that name and moves them to it, under a new id',
            ],
        )

    def test_maintenance(self):
        step = self.plan("maintenance", {"duration": "2:00", "behavior": 2}, id=1)
        self.assertEqual(step["action"], "maintenance")
        self.assertEqual(
            step["params"],
            {"duration": "2:00", "start": None, "title": None, "notes": "", "behavior": "mute_alerts"},
        )
        self.assertEqual(step["device_ids"], [1, 2])
        self.assertEqual(step["inverse_kind"], "none")
        self.assertTrue(
            step["inverse_note"].startswith("LibreNMS API v0 cannot end or delete maintenance; it expires ")
        )
        self.assertIn("after 2:00", step["inverse_note"])
        self.assertEqual(
            self.res.describe(step),
            [
                'duration 2:00, behavior mute_alerts, title "SFO-1", starts now',
                "covers device(s) #1, #2 at this location",
            ],
        )
        data = {"duration": "1:30", "start": "2026-10-29 01:00:00", "title": "fibre", "notes": "splice"}
        step = self.plan("maintenance", data, id=3)
        self.assertEqual(
            self.res.describe(step),
            [
                'duration 1:30, behavior skip_alerts, title "fibre", start 2026-10-29 01:00:00 (LibreNMS server time), '
                'notes "splice"',
                "no device is at this location now",
            ],
        )


class Check(LocationCase):
    def test_update_conflicts_on_coordinates_but_not_on_the_timestamp(self):
        step = self.plan("update", {"location": "NYC-3"}, id=2)
        self.fake.touch("locations", 2, timestamp=datetime(2026, 10, 28, 13, 0, 0))  # the geocoder saved it
        self.assertIsNone(self.res.check(self.client, step))
        self.fake.touch("locations", 2, lat=40.8)
        self.assertEqual(self.res.check(self.client, step), "location #2 changed since planning (lat: 40.7128 -> 40.8)")

    def test_location_gone(self):
        step = self.plan("maintenance", {"duration": "1:00"}, id=3)
        self.fake.touch("locations", 3, lat=50.0)  # maintenance needs only the location
        self.assertIsNone(self.res.check(self.client, step))
        del self.fake.tables["locations"][3]
        self.assertEqual(self.res.check(self.client, step), "location #3 no longer exists")

    def test_create_refused_once_the_name_exists(self):
        step = self.plan("create", PDX)
        self.assertIsNone(self.res.check(self.client, step))
        self.fake.seed("locations", {"location": "pdx-4", "lat": 1.0, "lng": 1.0})
        self.assertEqual(
            self.res.check(self.client, step), '1 location(s) now match {"location": "PDX-4"}; expected none'
        )

    def test_ambiguous_names(self):
        rows = [{"id": 1, "location": "SFO-1"}, {"id": 5, "location": "sfo-1"}]  # a collation LibreNMS does not use
        self.fake.fail_on("GET", "resources/locations", 200, {"status": "ok", "locations": rows, "count": 2})
        step = {"action": "update", "object_id": 3, "changes": {"location": {"from": "LON-3", "to": "SFO-1"}}}
        self.assertEqual(self.res._extra_check(self.client, step, None, None), '2 locations are named "SFO-1"')

    def test_rename_refused_once_the_new_name_is_taken(self):
        step = self.plan("update", {"location": "PDX-4"}, id=3)
        self.assertIsNone(self.res.check(self.client, step))
        self.fake.seed("locations", {"id": 5, "location": "PDX-4", "lat": 1.0, "lng": 1.0})
        self.assertEqual(self.res.check(self.client, step), f'a location named "PDX-4" already exists (#5); {TAKEN}')

    def test_delete_refused_when_the_devices_at_the_location_changed(self):
        step = self.plan("delete", id=3)
        self.assertIsNone(self.res.check(self.client, step))
        self.fake.touch("devices", 4, location_id=3)
        self.assertEqual(
            self.res.check(self.client, step), "the devices at location #3 changed since planning (none -> #4)"
        )
        step = self.plan("delete", id=1)
        self.fake.touch("devices", 2, location_id=None)
        self.assertEqual(
            self.res.check(self.client, step), "the devices at location #1 changed since planning (#1, #2 -> #1)"
        )


class Execute(LocationCase):
    def test_create_posts_parses_the_id_and_verifies(self):
        result = self.apply(self.plan("create", PDX))
        self.assertEqual(set(result), {"object_id", "inverse", "after_state", "notes"})
        self.assertEqual(result["object_id"], 4)
        self.assertEqual(result["inverse"], {"action": "delete", "object_id": 4})
        # without fixed_coordinates LibreNMS fixes valid coordinates (coordinatesValid())
        after = {k: v for k, v in result["after_state"].items() if k != "timestamp"}
        self.assertEqual(after, dict(PDX, id=4, fixed_coordinates=True))
        self.assertEqual(self.write_calls(), [("POST", "locations", PDX)])
        post = self.fake.writes()[0]
        self.assertEqual(post["headers"]["Content-Type"], "application/json")
        self.assertEqual(post["status"], 201)

    def test_create_id_found_by_name_when_the_message_lacks_it(self):
        self.fake.fail_on("POST", "locations", 201, {"status": "ok", "message": "Location added"}, commit=True)
        result = self.apply(self.plan("create", dict(PDX, fixed_coordinates=False)))
        self.assertEqual(result["object_id"], 4)
        self.assertFalse(result["after_state"]["fixed_coordinates"])

    def test_update_sends_changed_keys_as_json_and_verifies(self):
        step = self.plan("update", {"lat": 40.75, "lng": -74.006}, id=2)
        result = self.apply(step)
        self.assertEqual(self.write_calls(), [("PATCH", "locations/2", {"lat": 40.75})])
        # edit_location reads its body only when the request says it is JSON
        self.assertEqual(self.fake.writes()[0]["headers"]["Content-Type"], "application/json")
        self.assertEqual(result["inverse"], {"action": "update", "object_id": 2, "data": {"lat": 40.7128}})
        self.assertEqual(result["after_state"]["lat"], 40.75)
        self.assertEqual(self.location(2)["lat"], 40.75)

    def test_rename_and_clearing_coordinates(self):
        self.apply(self.plan("update", {"location": "LON-3b", "lat": None, "lng": None}, id=3))
        self.assertEqual(
            (self.location(3)["location"], self.location(3)["lat"], self.location(3)["lng"]), ("LON-3b", None, None)
        )

    def test_201_without_effect_is_a_partial_write(self):
        answer = {"status": "ok", "message": "Location updated successfully"}
        self.fake.fail_on("PATCH", "locations/2", 201, answer)  # answered, not applied
        with self.assertRaises(self.base.PartialWrite) as ctx:
            self.apply(self.plan("update", {"lat": 40.75}, id=2))
        self.assertEqual(str(ctx.exception), "LibreNMS accepted the write but lat is 40.7128, expected 40.75")
        self.assertEqual(ctx.exception.entry["inverse"]["data"], {"lat": 40.7128})

    def test_update_of_a_location_deleted_since_is_a_plain_failure(self):
        step = self.plan("update", {"lat": 40.75}, id=2)
        del self.fake.tables["locations"][2]
        with self.assertRaises(self.LibreNMSError) as ctx:
            self.apply(step)  # edit_location: 400 "Failed to update location"
        self.assertEqual((ctx.exception.status, ctx.exception.kind), (400, "api"))

    def test_delete_detaches_devices(self):
        step = self.plan("delete", id=1)
        result = self.apply(step)
        self.assertIsNone(self.location(1))
        self.assertEqual((self.device_location(1), self.device_location(2)), (None, None))
        self.assertEqual(result["inverse"], {"action": "create", "snapshot": SFO_SNAPSHOT})
        self.assertIsNone(result["after_state"])
        self.assertEqual(self.write_calls(), [("DELETE", "locations/1", None)])

    def test_maintenance_posts_a_tagged_title(self):
        result = self.apply(self.plan("maintenance", {"duration": "2:00", "notes": "fibre works"}, id=1))
        title = f"[hermes:{PLAN_ID}] SFO-1"
        body = {"duration": "2:00", "title": title, "notes": "fibre works", "behavior": 1}
        self.assertEqual(self.write_calls(), [("POST", "locations/1/maintenance", body)])
        schedule = self.fake.schedules[-1]
        self.assertEqual((schedule["title"], schedule["locations"], schedule["behavior"]), (title, [1], 1))
        self.assertEqual(
            result,
            {
                "object_id": 1,
                "inverse": None,
                "after_state": None,
                "notes": [f'maintenance "{title}" scheduled for 2:00'],
            },
        )

    def test_maintenance_with_start_title_and_behavior(self):
        data = {"duration": "1:30", "start": "2026-10-29 01:00:00", "title": "fibre", "behavior": "run_alerts"}
        self.apply(self.plan("maintenance", data, id=3))
        body = {"duration": "1:30", "title": f"[hermes:{PLAN_ID}] fibre", "notes": "", "behavior": 3,
                "start": "2026-10-29 01:00:00"}  # fmt: skip
        self.assertEqual(self.write_calls(), [("POST", "locations/3/maintenance", body)])
        self.assertEqual(self.fake.schedules[-1]["start"], "2026-10-29 01:00:00")


class PartialWrites(LocationCase):
    def test_create_failing_after_the_insert(self):
        self.fake.fail_on("POST", "locations", 500, commit=True)
        with self.assertRaises(self.base.PartialWrite) as ctx:
            self.apply(self.plan("create", PDX))
        entry = ctx.exception.entry
        self.assertEqual((entry["object_id"], entry["inverse"]), (4, {"action": "delete", "object_id": 4}))
        self.assertEqual(entry["after_state"]["location"], "PDX-4")
        self.assertIn("HTTP 500", str(ctx.exception))

    def test_create_failing_before_the_insert_raises_the_original(self):
        self.fake.fail_on("POST", "locations", 500)
        with self.assertRaises(self.LibreNMSError) as ctx:
            self.apply(self.plan("create", PDX))
        self.assertEqual(ctx.exception.kind, "server")
        self.assertEqual(len(self.fake.tables["locations"]), 3)
        self.assertEqual(self.fake.calls[-1]["path"], "resources/locations")  # the re-read proved nothing was made

    def test_create_rejected_raises_without_a_reread(self):
        self.fake.fail_on(
            "POST",
            "locations",
            400,
            {"status": "error", "message": "Required fields missing (location, lat and lng needed)"},
        )
        with self.assertRaises(self.LibreNMSError) as ctx:
            self.apply(self.plan("create", PDX))
        self.assertEqual(ctx.exception.status, 400)
        self.assertEqual(self.fake.calls[-1]["method"], "POST")

    def test_create_with_an_unknown_id_is_found_again_by_rollback(self):
        step = self.plan("create", PDX)
        self.fake.fail_on("POST", "locations", 201, {"status": "ok", "message": "Location added"}, commit=True)
        self.fake.fail_on("GET", "resources/locations", 404, {"status": "error", "message": "x"}, times=1)
        with self.assertRaises(self.base.PartialWrite) as ctx:
            self.apply(step)
        entry = ctx.exception.entry
        self.assertEqual(entry["inverse"], {"action": "delete", "object_id": None, "find": PDX_KEY})
        entry = self.entry(step, entry, "failed", wrote=True)
        self.assertEqual(self.revert(entry, step), ("reverted", {"object_id": 4}))
        self.assertIsNone(self.location(4))

    def test_update_failing_after_the_write(self):
        self.fake.fail_on("PATCH", "locations/2", 500, commit=True)
        with self.assertRaises(self.base.PartialWrite) as ctx:
            self.apply(self.plan("update", {"lat": 40.75}, id=2))
        entry = ctx.exception.entry
        self.assertEqual(entry["after_state"]["lat"], 40.75)
        self.assertEqual(entry["inverse"], {"action": "update", "object_id": 2, "data": {"lat": 40.7128}})

    def test_update_transport_error_with_nothing_changed_raises_the_original(self):
        step = self.plan("update", {"lat": 40.75}, id=2)
        self.fake.fail_on("PATCH", "locations/2", exc=ConnectionRefusedError("connection refused"))
        with self.assertRaises(self.LibreNMSError) as ctx, self.assertLogs(level="WARNING"):
            self.apply(step)
        self.assertEqual(ctx.exception.kind, "transport")
        self.assertEqual(self.fake.calls[-1]["path"], "location/2")

    def test_delete_failing_after_the_delete_is_rolled_back_by_re_creating(self):
        self.fake.fail_on("DELETE", "locations/1", 500, commit=True)
        step = self.plan("delete", id=1)
        with self.assertRaises(self.base.PartialWrite) as ctx:
            self.apply(step)
        entry = self.entry(step, ctx.exception.entry, "failed", wrote=True)
        self.assertIsNone(entry["after_state"])
        status, details = self.revert(entry, step)
        self.assertEqual(status, "reverted")
        self.assertEqual(details, {"new_object_id": 4, "repointed_devices": [1, 2], "skipped_devices": []})

    def test_delete_failing_after_detaching_the_devices(self):
        client = self.client_mod.LibreNMSClient(self.fake.base_url, TOKEN, session=DetachThenFail(self.fake, 1))
        client.retry_sleep = lambda _seconds: None
        step = self.plan("delete", id=1, client=client)
        with self.assertRaises(self.base.PartialWrite) as ctx:
            self.apply(step, client)
        self.assertEqual(
            str(ctx.exception),
            "DELETE /api/v0/locations/1 -> HTTP 500: Failed to delete the location SFO-1 (LibreNMS detached device(s) "
            "#1, #2 but kept the location; rollback attaches them again)",
        )
        partial = ctx.exception.entry
        self.assertEqual((partial["object_id"], partial["after_state"]["location"]), (1, "SFO-1"))
        self.assertEqual(partial["inverse"]["action"], "create")
        self.assertEqual((self.device_location(1), self.device_location(2)), (None, None))
        entry = self.entry(step, partial, "failed", wrote=True)
        self.assertEqual(
            self.revert(entry, step, client=client),
            ("reverted", {"object_id": 1, "note": ANCHOR, "repointed_devices": [1, 2], "skipped_devices": []}),
        )
        self.assertEqual((self.device_location(1), self.device_location(2)), (1, 1))
        self.assertEqual(len(self.fake.tables["locations"]), 3)

    def test_a_delete_whose_answer_was_lost_waits_until_it_can_no_longer_land(self):
        step = self.plan("delete", id=1)
        self.fake.fail_on("DELETE", "locations/1", 504, times=1)  # a gateway gave up while LibreNMS was working
        with self.assertRaises(self.base.PartialWrite) as ctx:
            self.apply(step)
        entry = self.entry(step, ctx.exception.entry, "failed", wrote=True)
        self.fake.calls.clear()
        status, details = self.revert(entry, step)
        self.assertEqual(status, "failed")
        self.assertTrue(details["error"].startswith("nothing was deleted so far, but LibreNMS may still be carrying"))
        self.assertEqual([c for c in self.fake.calls if c["method"] != "GET"], [])
        entry["settles_at"] = "2026-10-28T19:10:00Z"
        self.assertEqual(
            self.revert(entry, step),
            ("reverted", {"object_id": 1, "note": ANCHOR, "repointed_devices": [1, 2], "skipped_devices": []}),
        )
        self.assertEqual([c for c in self.fake.calls if c["method"] != "GET"], [])  # both never left it

        self.fake.fail_on("DELETE", "locations/1", 504, times=1)
        self.fake.fail_on("GET", "location/1", 500, times=1)  # and the re-read cannot tell either
        with self.assertRaises(self.base.PartialWrite) as ctx:
            self.apply(step)
        self.assertIn("settles_at", ctx.exception.entry)

    def test_reattaching_after_a_half_done_delete_can_fail(self):
        client = self.client_mod.LibreNMSClient(self.fake.base_url, TOKEN, session=DetachThenFail(self.fake, 1))
        client.retry_sleep = lambda _seconds: None
        step = self.plan("delete", id=1, client=client)
        with self.assertRaises(self.base.PartialWrite) as ctx:
            self.apply(step, client)
        entry = self.entry(step, ctx.exception.entry, "failed", wrote=True)
        answer = {"status": "ok", "message": "Device location_id field has been updated"}
        self.fake.fail_on("PATCH", "devices/2", 200, answer)  # answered, not applied
        self.assertEqual(
            self.revert(entry, step, client=client),
            (
                "failed",
                {"error": "could not attach device #2 (its location_id is null) to location #1; set their location "
                          "by hand",
                 "object_id": 1, "note": "the location was never deleted", "repointed_devices": [1],
                 "skipped_devices": []},
            ),
        )  # fmt: skip

    def test_delete_failing_when_even_the_reread_fails(self):
        client = self.client_mod.LibreNMSClient(self.fake.base_url, TOKEN, session=DetachThenFail(self.fake, 1))
        client.retry_sleep = lambda _seconds: None
        step = self.plan("delete", id=1, client=client)
        self.fake.fail_on("GET", "location/1", 500, times=1)  # LibreNMS cannot tell what the delete did
        with self.assertRaises(self.base.PartialWrite) as ctx:
            self.apply(step, client)
        self.assertTrue(str(ctx.exception).endswith("(LibreNMS may have applied the write)"))
        partial = ctx.exception.entry
        self.assertEqual((partial["after_state"], partial["inverse"]["action"]), (None, "create"))
        self.assertTrue(partial["notes"][0].startswith("outcome unknown: re-reading location #1 and its devices"))
        entry = self.entry(step, partial, "failed", wrote=True)
        status, details = self.revert(entry, step, client=client)
        self.assertEqual((status, details["note"], details["repointed_devices"]), ("reverted", ANCHOR, [1, 2]))

    def test_devices_detached_from_a_location_without_coordinates(self):
        self.fake.seed("locations", {"id": 9, "location": "Closet"})
        self.fake.touch("devices", 4, location_id=9)
        client = self.client_mod.LibreNMSClient(self.fake.base_url, TOKEN, session=DetachThenFail(self.fake, 9))
        client.retry_sleep = lambda _seconds: None
        step = self.plan("delete", id=9, client=client)
        with self.assertRaises(self.base.PartialWrite) as ctx:
            self.apply(step, client)
        self.assertTrue(str(ctx.exception).endswith("(LibreNMS detached device(s) #4 but kept the location; set "
                                                    "their location again by hand)"))  # fmt: skip
        self.assertIsNone(ctx.exception.entry["inverse"])

    def test_delete_failing_with_no_device_detached_raises_the_original(self):
        self.fake.fail_on("DELETE", "locations/1", 500)
        with self.assertRaises(self.LibreNMSError):
            self.apply(self.plan("delete", id=1))
        self.assertEqual((self.device_location(1), self.device_location(2)), (1, 1))

    def test_delete_rejected_raises_without_a_reread(self):
        self.fake.fail_on(
            "DELETE", "locations/1", 400, {"status": "error", "message": "Failed to delete  (Does not exists)"}
        )
        with self.assertRaises(self.LibreNMSError) as ctx:
            self.apply(self.plan("delete", id=1))
        self.assertEqual(ctx.exception.status, 400)
        self.assertEqual(self.fake.calls[-1]["method"], "DELETE")

    def test_delete_with_an_unknown_outcome(self):
        step = self.plan("delete", id=1)
        self.fake.fail_on("DELETE", "locations/1", 500)
        self.fake.fail_on("GET", "location/1", 500)  # and LibreNMS cannot be read to tell
        with self.assertRaises(self.base.PartialWrite) as ctx:
            self.apply(step)
        self.assertIn("(LibreNMS may have applied the write)", str(ctx.exception))
        self.assertTrue(ctx.exception.entry["notes"][0].startswith("outcome unknown"))

    def test_maintenance_with_an_unknown_outcome(self):
        step = self.plan("maintenance", {"duration": "2:00"}, id=1)
        self.fake.fail_on("POST", "locations/1/maintenance", exc=OSError("read timed out"))
        with self.assertRaises(self.base.PartialWrite) as ctx, self.assertLogs(level="WARNING"):
            self.apply(step)
        self.assertIn("(LibreNMS may have created the schedule)", str(ctx.exception))
        entry = ctx.exception.entry
        self.assertEqual((entry["object_id"], entry["inverse"], entry["after_state"]), (1, None, None))
        self.assertEqual(
            entry["notes"],
            [f'look for a schedule titled "[hermes:{PLAN_ID}] SFO-1" under Alerts → Scheduled Maintenance before '
             "trying again"],
        )  # fmt: skip

    def test_maintenance_rejected_is_a_plain_failure(self):
        self.fake.fail_on(
            "POST", "locations/1/maintenance", 400, {"status": "error", "message": "Duration not provided"}
        )
        with self.assertRaises(self.LibreNMSError):
            self.apply(self.plan("maintenance", {"duration": "2:00"}, id=1))


class Revert(LocationCase):
    def test_create_is_deleted(self):
        step, entry = self.applied("create", PDX)
        self.assertEqual(self.revert(entry, step), ("reverted", {"object_id": 4}))
        self.assertIsNone(self.location(4))
        self.assertEqual(self.revert(entry, step), ("reverted", {"note": "object already gone"}))

    def test_create_rollback_whose_delete_fails(self):
        step, entry = self.applied("create", PDX)
        self.fake.fail_on("DELETE", "locations/4", 500)
        with self.assertRaises(self.LibreNMSError):
            self.revert(entry, step)
        self.assertIsNotNone(self.location(4))

    def test_create_kept_while_a_device_uses_it_unless_forced(self):
        step, entry = self.applied("create", PDX)
        self.fake.touch("devices", 4, location_id=4)
        self.assertEqual(
            self.revert(entry, step),
            ("conflict", {"error": "device(s) #4 now use location #4; deleting it would detach them (use force to "
                                   "delete anyway)"}),
        )  # fmt: skip
        self.assertIsNotNone(self.location(4))
        self.assertEqual(self.revert(entry, step, force=True), ("reverted", {"object_id": 4}))
        self.assertIsNone(self.device_location(4))

    def test_create_modified_after_apply(self):
        step, entry = self.applied("create", PDX)
        self.fake.touch("locations", 4, timestamp=datetime(2026, 10, 29))  # not a modification
        self.fake.touch("locations", 4, lng=-122.6)
        self.assertEqual(
            self.revert(entry, step),
            ("conflict", {"error": "location #4 was modified after apply (lng: -122.5951 -> -122.6); use force to "
                                   "delete anyway"}),
        )  # fmt: skip

    def test_unknown_create_outcome(self):
        step = self.plan("create", PDX)
        entry = self.entry(step, {}, "unknown", wrote=True)  # the process died during the POST
        self.assertEqual(self.revert(entry, step), ("reverted", {"note": "nothing was written"}))

    def test_update_is_restored(self):
        step, entry = self.applied("update", {"location": "NYC-2b", "lat": 40.75}, id=2)
        self.fake.touch("locations", 2, timestamp=datetime(2026, 10, 29))
        self.fake.calls.clear()
        self.assertEqual(self.revert(entry, step), ("reverted", {"restored_fields": ["lat", "location"]}))
        self.assertEqual(self.write_calls(), [("PATCH", "locations/2", {"location": "NYC-2", "lat": 40.7128})])
        self.assertEqual((self.location(2)["location"], self.location(2)["lat"]), ("NYC-2", 40.7128))

    def test_update_re_geocoded_since_conflicts_unless_forced(self):
        step, entry = self.applied("update", {"location": "NYC-2b"}, id=2)
        self.fake.touch("locations", 2, lng=-73.9)
        self.assertEqual(
            self.revert(entry, step),
            ("conflict", {"error": "location #2 was modified after apply (lng: -74.006 -> -73.9); use force to "
                                   "overwrite"}),
        )  # fmt: skip
        self.assertEqual(self.revert(entry, step, force=True), ("reverted", {"restored_fields": ["location"]}))
        self.assertEqual((self.location(2)["location"], self.location(2)["lng"]), ("NYC-2", -73.9))

    def test_delete_is_re_created_and_its_devices_attached(self):
        step, entry = self.applied("delete", id=1)
        self.fake.touch("devices", 1, location_id=3)  # moved elsewhere since: left there
        self.fake.calls.clear()
        status, details = self.revert(entry, step)
        self.assertEqual(status, "reverted")
        self.assertEqual(
            details,
            {"new_object_id": 4, "repointed_devices": [2], "skipped_devices": [1],
             "note": "not attached again: #1 (now at #3)"},
        )  # fmt: skip
        self.assertEqual(
            {k: v for k, v in self.location(4).items() if k in SFO_STATE},
            {"location": "SFO-1", "lat": 37.6213, "lng": -122.379, "fixed_coordinates": 1},
        )
        self.assertEqual((self.device_location(1), self.device_location(2)), (3, 4))
        self.assertEqual(
            self.write_calls(),
            [
                ("POST", "locations", dict(SFO_STATE)),
                ("PATCH", "devices/2", {"field": "location_id", "data": 4}),
            ],
        )
        self.assertNoSecrets(details)

    def test_delete_of_a_device_gone_since(self):
        step, entry = self.applied("delete", id=2)
        self.client.request("DELETE", "devices/3")  # someone removed the device in LibreNMS since the apply
        status, details = self.revert(entry, step)
        self.assertEqual(status, "reverted")
        self.assertEqual(details["skipped_devices"], [3])
        self.assertEqual(details["note"], "not attached again: #3 (gone)")

    def test_delete_refused_when_the_name_exists_again(self):
        step, entry = self.applied("delete", id=1)
        self.fake.seed("locations", {"location": "sfo-1", "lat": 1.0, "lng": 1.0})
        self.assertEqual(
            self.revert(entry, step),
            ("conflict", {"error": 'a location matching {"location": "SFO-1"} exists again; remove or rename it '
                                   "before rolling back"}),
        )  # fmt: skip

    def test_delete_rollback_reports_a_device_it_could_not_attach_and_can_be_tried_again(self):
        step, entry = self.applied("delete", id=1)
        self.fake.fail_on("PATCH", "devices/2", 500, times=1)
        status, details = self.revert(entry, step)
        self.assertEqual(status, "failed")
        self.assertEqual(
            details,
            {
                "error": "could not attach device #2 (PATCH /api/v0/devices/2 -> HTTP 500: LibreNMS server error "
                "(details withheld; see the LibreNMS log)) to location #4; set their location by hand",
                "new_object_id": 4,
                "repointed_devices": [1],
                "skipped_devices": [],
            },
        )
        self.assertEqual((self.device_location(1), self.device_location(2)), (4, None))
        entry.update(revert_status=status, revert=details)  # as the executor journals it
        self.fake.calls.clear()
        self.assertEqual(
            self.revert(entry, step),
            ("reverted", {"new_object_id": 4, "note": "re-created by an earlier rollback", "repointed_devices": [1, 2],
                          "skipped_devices": []}),
        )  # fmt: skip
        self.assertEqual(self.write_calls(), [("PATCH", "devices/2", {"field": "location_id", "data": 4})])
        self.assertEqual(len(self.fake.tables["locations"]), 3)

    def test_delete_rollback_that_died_after_its_post_adopts_that_location(self):
        step, entry = self.applied("delete", id=1)
        self.fake.fail_on("POST", "locations", exc=Died(), commit=True, times=1)
        with self.assertRaises(Died):
            self.res.revert(self.client, entry, False, resumable(dict(self.context, step=step), entry))
        self.assertEqual((entry["revert_progress"], self.location(4)["location"]), ({"recreating": True}, "SFO-1"))
        self.fake.calls.clear()
        self.assertEqual(
            self.res.revert(self.client, entry, False, resumable(dict(self.context, step=step), entry)),
            ("reverted", {"new_object_id": 4, "note": "re-created by an earlier rollback", "repointed_devices": [1, 2],
                          "skipped_devices": []}),
        )  # fmt: skip
        self.assertEqual(
            self.write_calls(),
            [("PATCH", "devices/1", {"field": "location_id", "data": 4}),
             ("PATCH", "devices/2", {"field": "location_id", "data": 4})],
        )  # fmt: skip
        self.assertEqual(len(self.fake.tables["locations"]), 3)

    def test_a_resumed_rollback_does_not_adopt_a_location_it_did_not_create(self):
        step, entry = self.applied("delete", id=1)
        entry["revert_progress"] = {"recreating": True}  # the earlier run died before its POST landed
        self.fake.seed("locations", {"location": "SFO-1", "lat": 1.0, "lng": 2.0})  # polling made one from sysLocation
        self.fake.calls.clear()
        self.assertEqual(
            self.revert(entry, step),
            ("failed", {"error": "location #4 has the deleted one's name but lat is 1.0, expected 37.6213; lng is 2.0, "
                                 "expected -122.379; fixed_coordinates is false, expected true, so it may not be the "
                                 "one an interrupted rollback re-created; check it, then remove or rename it before "
                                 "rolling back"}),
        )  # fmt: skip
        self.assertEqual(self.fake.writes(), [])

    def test_delete_rollback_whose_post_fails_after_the_insert(self):
        step, entry = self.applied("delete", id=2)
        self.fake.fail_on("POST", "locations", 500, commit=True)
        self.assertEqual(
            self.revert(entry, step),
            ("reverted", {"new_object_id": 4, "repointed_devices": [3], "skipped_devices": []}),
        )
        self.fake.failures.clear()
        step, entry = self.applied("delete", id=3)
        self.fake.fail_on("POST", "locations", 500)  # failed before the insert: the original error stands
        with self.assertRaises(self.LibreNMSError) as ctx:
            self.revert(entry, step)
        self.assertEqual(ctx.exception.kind, "server")

    def test_rename_rollback_onto_a_name_taken_since(self):
        step, entry = self.applied("update", {"location": "NYC-2b"}, id=2)
        self.fake.seed("locations", {"location": "nyc-2", "lat": 1.0, "lng": 1.0})
        self.fake.calls.clear()
        self.assertEqual(
            self.revert(entry, step), ("failed", {"error": f'a location named "nyc-2" already exists (#4); {TAKEN}'})
        )
        self.assertEqual(self.fake.writes(), [])

    def test_delete_rollback_finds_the_new_id_by_name(self):
        step, entry = self.applied("delete", id=2)
        self.fake.fail_on("POST", "locations", 201, {"status": "ok", "message": "Location added"}, commit=True)
        self.assertEqual(
            self.revert(entry, step),
            ("reverted", {"new_object_id": 4, "repointed_devices": [3], "skipped_devices": []}),
        )
        self.assertEqual(self.device_location(3), 4)

    def test_delete_rollback_that_cannot_find_what_it_re_created(self):
        step, entry = self.applied("delete", id=1)
        self.fake.fail_on("POST", "locations", 201, {"status": "ok", "message": "Location added"})  # nothing created
        self.assertEqual(
            self.revert(entry, step),
            ("failed", {"error": 'LibreNMS accepted re-creating location "SFO-1" but it cannot be found; set the '
                                 "location of device(s) #1, #2 by hand"}),
        )  # fmt: skip

    def test_irreversible_steps(self):
        step, entry = self.applied("maintenance", {"duration": "4:00"}, id=1)
        status, details = self.revert(entry, step)
        self.assertEqual(status, "irreversible")
        self.assertIn("it expires after 4:00", details["note"])
        self.fake.seed("locations", {"id": 9, "location": "Closet"})
        step, entry = self.applied("delete", id=9)
        self.assertEqual(self.revert(entry, step)[0], "irreversible")
        self.assertEqual(len(self.fake.tables["locations"]), 3)


if __name__ == "__main__":
    unittest.main()
