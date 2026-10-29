import json
import re
import unittest

from .fake_librenms import SECRETS, TOKEN, FakeResponse, seeded

CATCH_ALL = {"status": "error", "message": "This API route doesn't exist."}


class _FakeCase(unittest.TestCase):
    def setUp(self) -> None:
        self.fake = seeded()

    def send(self, method, path, params=None, body=None, *, token=TOKEN, content_type="application/json", raw=None):
        headers = {"X-Auth-Token": token, "Accept": "application/json"}
        if content_type:
            headers["Content-Type"] = content_type
        data = raw if raw is not None else None if body is None else json.dumps(body)
        url = f"{self.fake.base_url}/api/v0" + (f"/{path}" if path else "")
        return self.fake.request(method, url, params=params, data=data, headers=headers, stream=True)

    def call(self, method, path, params=None, body=None, **kwargs):
        """(status, decoded body) of one request."""
        response = self.send(method, path, params, body, **kwargs)
        return response.status_code, response.json()


class Transport(_FakeCase):
    def test_wrong_or_missing_token_is_a_bare_401(self):
        self.assertEqual(self.call("GET", "system", token="7|nope"), (401, {"message": "Unauthenticated."}))
        response = self.fake.request("GET", f"{self.fake.base_url}/api/v0/system", headers={})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.fake.calls[-1]["status"], 401)  # refused requests are logged too

    def test_unknown_path_wrong_method_and_encoded_slash_hit_the_catch_all(self):
        self.assertEqual(self.call("GET", "nope"), (404, CATCH_ALL))
        self.assertEqual(self.call("PUT", "devices/1", body={}), (404, CATCH_ALL))  # never a 405
        self.assertEqual(self.call("GET", "devicegroups/a%2Fb"), (404, CATCH_ALL))  # decoded before matching

    def test_trailing_slash_and_redirect_all_answer_301(self):
        response = self.send("GET", "devices/")
        self.assertEqual(
            (response.status_code, response.headers["location"]), (301, f"{self.fake.base_url}/api/v0/devices")
        )
        self.fake.redirect_all("https://elsewhere.test/api/v0/system")
        self.assertEqual(self.send("GET", "system").headers["Location"], "https://elsewhere.test/api/v0/system")
        self.fake.redirect_all(None)
        self.assertEqual(self.send("GET", "system").status_code, 200)

    def test_response_reads_like_a_streamed_requests_response(self):
        response = self.send("GET", "system")
        self.assertEqual(response.headers["CONTENT-TYPE"], "application/json")
        self.assertEqual(response.headers["content-length"], str(len(response.content)))
        self.assertEqual(b"".join(response.iter_content(7)), response.content)
        self.assertEqual(response.streamed, len(response.content))
        self.assertEqual(json.loads(response.text), response.json())
        response.close()
        self.assertTrue(response.closed)
        with self.assertRaises(ValueError):
            FakeResponse(200, {}, b"").json()

    def test_index_system_ping_and_missing_routes(self):
        status, index = self.call("GET", "")
        self.assertEqual(status, 200)
        self.assertNotIn("status", index)  # a flat map, not the envelope
        self.assertEqual(list(index), sorted(index))
        self.assertEqual(index["get_device"], f"{self.fake.base_url}/api/v0/devices/{{hostname}}")
        status, body = self.call("GET", "system")
        self.assertEqual((body["system"][0]["local_ver"], body["count"]), ("26.10.0", 1))
        self.assertEqual(self.call("GET", "ping"), (200, {"message": "pong"}))
        self.fake.missing_routes.add("ping")  # LibreNMS 24.x
        self.assertEqual(self.call("GET", "ping"), (404, CATCH_ALL))
        self.assertNotIn("ping", self.call("GET", "")[1])


class Hooks(_FakeCase):
    def test_fail_on_replaces_the_answer_before_or_after_the_write(self):
        self.fake.fail_on("PATCH", r"devices/\d+", 500)
        body = {"field": "purpose", "data": "spine"}
        self.assertEqual(self.call("PATCH", "devices/1", body=body), (500, {"message": "Server Error"}))
        self.assertEqual(self.fake.tables["devices"][1]["purpose"], "core")
        self.fake.failures.clear()
        self.fake.fail_on("PATCH", r"devices/1", 502, "<html>Bad Gateway</html>", commit=True, times=1)
        response = self.send("PATCH", "devices/1", body=body)
        self.assertEqual((response.status_code, response.headers["Content-Type"]), (502, "text/html"))
        self.assertEqual(self.fake.tables["devices"][1]["purpose"], "spine")  # it took effect all the same
        self.assertEqual(self.send("PATCH", "devices/1", body=body).status_code, 200)

    def test_fail_on_can_raise_like_a_transport_error(self):
        self.fake.fail_on("*", "system", exc=ConnectionError("refused"))
        with self.assertRaises(ConnectionError):
            self.send("GET", "system")
        self.assertIsNone(self.fake.calls[-1]["status"])

    def test_calls_record_requests_and_writes_lists_the_non_gets(self):
        self.send("GET", "devices", params={"type": "os", "query": "ios", "skip": None})
        self.send("PATCH", "ports/2/description", body={"description": "x"})
        first = self.fake.calls[0]
        self.assertEqual(
            (first["method"], first["path"], first["params"]), ("GET", "devices", {"type": "os", "query": "ios"})
        )
        self.assertEqual(first["headers"]["x-auth-token"], TOKEN)
        self.assertTrue(first["stream"])
        self.assertEqual([(c["method"], c["json"]) for c in self.fake.writes()], [("PATCH", {"description": "x"})])

    def test_ids_are_never_handed_out_twice(self):
        self.assertEqual(self.call("DELETE", "services/3")[0], 201)
        self.assertEqual(self.fake.seed("services", {"device_id": 1, "service_type": "icmp"})["service_id"], 4)

    def test_touch_edits_a_row_out_of_band(self):
        self.fake.touch("devices", 1, purpose="changed elsewhere")
        self.assertEqual(self.call("GET", "devices/1")[1]["devices"][0]["purpose"], "changed elsewhere")

    def test_seeded_secrets_are_the_ones_listed(self):
        stored = json.dumps([self.fake.tables["devices"], self.fake.tables["services"]])
        for secret in SECRETS:
            self.assertIn(secret, stored)


class Devices(_FakeCase):
    def test_get_by_id_or_hostname_and_404(self):
        status, body = self.call("GET", "devices/1")
        self.assertEqual((status, body["count"], body["devices"][0]["hostname"]), (200, 1, "core-sw1.example.net"))
        self.assertEqual(self.call("GET", "devices/CORE-SW1.example.net")[1]["devices"][0]["device_id"], 1)
        self.assertEqual(
            self.call("GET", "devices/nope.example.net"),
            (404, {"status": "error", "message": "Device nope.example.net does not exist"}),
        )

    def test_secrets_are_clear_for_an_admin_token_and_null_otherwise(self):
        device = self.call("GET", "devices/2")[1]["devices"][0]
        self.assertEqual((device["authpass"], device["cryptopass"], device["authname"]), SECRETS[1:3] + ("nms-v3",))
        self.fake.admin_secrets = False
        device = self.call("GET", "devices/2")[1]["devices"][0]
        self.assertEqual((device["authpass"], device["cryptopass"], device["authname"]), (None, None, "nms-v3"))
        self.assertIsNone(self.call("GET", "devices/1")[1]["devices"][0]["community"])

    def test_list_filters_orders_and_carries_parents(self):
        body = self.call("GET", "devices", {"type": "location_id", "query": "1"})[1]
        self.assertEqual(([d["device_id"] for d in body["devices"]], body["count"]), ([1, 2], 2))
        self.assertIn("dependency_parent_id", body["devices"][0])
        hosts = self.call("GET", "devices", {"type": "hostname", "query": "sw"})[1]["devices"]
        self.assertEqual([d["hostname"] for d in hosts], ["access-sw2.example.net", "core-sw1.example.net"])
        newest = self.call("GET", "devices", {"order": "device_id desc"})[1]["devices"]
        self.assertEqual([d["device_id"] for d in newest], [4, 3, 2, 1])
        self.assertEqual(self.call("GET", "devices", {"order": "nosuchcolumn"}), (500, {"message": "Server Error"}))

    def test_patch_ignores_unknown_fields_and_refuses_hostname(self):
        body = {"field": ["purpose", "community", "bogus"], "data": ["spine", "x", "y"]}
        self.assertEqual(
            self.call("PATCH", "devices/1", body=body),
            (200, {"status": "ok", "message": "Device fields have been updated"}),
        )
        device = self.fake.tables["devices"][1]
        self.assertEqual((device["purpose"], device["community"]), ("spine", SECRETS[0]))
        status, body = self.call("PATCH", "devices/1", body={"field": "hostname", "data": "x"})
        self.assertEqual((status, body["message"]), (500, "Device field is not allowed to be updated"))
        status, body = self.call("PATCH", "devices/1", body={"field": ["notes", "purpose"], "data": ["x"]})
        self.assertEqual(status, 500)
        self.assertIn("number of fields (2) does not match the supplied data (1)", body["message"])

    def test_boolean_strings_never_change_a_flag(self):
        self.assertEqual(self.call("PATCH", "devices/1", body={"field": "disabled", "data": "true"})[0], 200)
        self.assertEqual(self.fake.tables["devices"][1]["disabled"], 0)
        self.assertEqual(self.call("PATCH", "devices/4", body={"field": "disabled", "data": "false"})[0], 200)
        self.assertEqual(self.fake.tables["devices"][4]["disabled"], 1)
        self.call("PATCH", "devices/4", body={"field": "disabled", "data": False})
        self.assertEqual(self.fake.tables["devices"][4]["disabled"], 0)

    def test_location_writes_log_and_the_location_pseudo_field_creates_one(self):
        self.call("PATCH", "devices/3", body={"field": "location_id", "data": 1})
        self.assertEqual(
            self.fake.tables["eventlog"][max(self.fake.tables["eventlog"])]["message"], "Location: NYC-2 -> SFO-1"
        )
        self.call("PATCH", "devices/3", body={"field": ["location"], "data": ["New Site"]})
        created = [loc for loc in self.fake.tables["locations"].values() if loc["location"] == "New Site"]
        self.assertEqual(self.fake.tables["devices"][3]["location_id"], created[0]["id"])

    def test_rename(self):
        self.assertEqual(self.call("PATCH", "devices/1/rename/core-sw1b.example.net")[0], 200)
        device = self.fake.tables["devices"][1]
        self.assertEqual((device["hostname"], device["ip"]), ("core-sw1b.example.net", None))
        log = self.fake.tables["eventlog"][max(self.fake.tables["eventlog"])]
        self.assertEqual(log["message"], "Hostname changed -> core-sw1b.example.net (hermes)")
        status, body = self.call("PATCH", "devices/3/rename/edge-rtr1.example.net")
        self.assertEqual(status, 500)
        self.assertTrue(
            body["message"].startswith("Renaming of access-sw2.example.net failed because there is already")
        )
        self.assertEqual(self.call("PATCH", "devices/3/rename/Access-SW2.example.net")[0], 200)  # itself: a case change
        self.assertEqual(self.fake.tables["devices"][3]["hostname"], "Access-SW2.example.net")
        self.assertEqual(self.call("PATCH", "devices/99/rename/x")[1]["message"], "Existing device not found")

    def test_create_answers_200_with_the_device_and_logs_it(self):
        data = {"hostname": "new-sw9.example.net", "community": "c", "location_id": 3, "override_sysLocation": True}
        status, body = self.call("POST", "devices", body=data)
        self.assertEqual((status, body["count"]), (200, 1))
        self.assertEqual(body["message"], "Device new-sw9.example.net (5) has been added successfully")
        self.assertEqual((body["devices"][0]["community"], body["devices"][0]["location"]), ("c", "LON-3"))
        logs = [e["message"] for e in self.fake.tables["eventlog"].values() if e["device_id"] == 5]
        self.assertEqual(logs, ["Device new-sw9.example.net has been created"])
        self.assertEqual(
            self.call("POST", "devices", body=data),
            (400, {"status": "error", "message": "Device new-sw9.example.net already exists"}),
        )
        status, body = self.call("POST", "devices", body={"hostname": "x.example.net", "transport": "sctp"})
        self.assertEqual((status, list(body["message"])), (422, ["transport"]))

    def test_create_puts_poller_group_0_in_the_default_group(self):
        self.fake.default_poller_group = 1
        for hostname, group in (("a.example.net", 0), ("b.example.net", None), ("c.example.net", 2)):
            body = {"hostname": hostname, "community": "c", **({} if group is None else {"poller_group": group})}
            self.assertEqual(self.call("POST", "devices", body=body)[0], 200)
        groups = {d["hostname"]: d["poller_group"] for d in self.fake.tables["devices"].values()}
        self.assertEqual((groups["a.example.net"], groups["b.example.net"], groups["c.example.net"]), (1, 1, 2))

    def test_delete_returns_the_snapshot_and_cascades(self):
        status, body = self.call("DELETE", "devices/3")
        self.assertEqual(
            (status, body["message"], body["devices"][0]["device_id"]),
            (200, "Removed device access-sw2.example.net\n", 3),
        )
        self.assertEqual(self.call("GET", "services/3")[1]["services"], [[]])
        self.assertNotIn(3, {f["device_id"] for f in self.fake.tables["faults"].values()})
        logs = [
            (e["device_id"], e["message"]) for e in self.fake.tables["eventlog"].values() if e["device_id"] in (0, 3)
        ]
        self.assertEqual(logs, [(0, "Device access-sw2.example.net has been removed")])
        self.assertEqual(self.call("GET", "devices/3")[0], 404)

    def test_maintenance(self):
        status, body = self.call("POST", "devices/1/maintenance", body={"duration": "2:00", "notes": "IOS upgrade"})
        self.assertEqual(
            (status, body["message"]), (201, "Device core-sw1.example.net (1) moved into maintenance mode for 2:00h")
        )
        self.assertEqual(
            self.call("GET", "devices/1/maintenance"), (200, {"status": "ok", "is_under_maintenance": True})
        )
        self.assertEqual((self.fake.schedules[0]["title"], self.fake.tables["devices"][1]["notes"]), ("core-sw1", ""))
        self.fake.add_schedule_note_to_device = True
        self.call("POST", "devices/3/maintenance", body={"duration": "0:30", "notes": "swap PSU"})
        self.assertRegex(
            self.fake.tables["devices"][3]["notes"], r"^rack B4\n\d{4}-\d\d-\d\d \d\d:\d\d Alerts delayed: swap PSU$"
        )
        self.assertEqual(self.call("POST", "devices/2/maintenance", body={"duration": "120"})[0], 201)
        self.assertFalse(self.call("GET", "devices/2/maintenance")[1]["is_under_maintenance"])  # no colon: lapsed
        self.assertEqual(
            self.call("POST", "devices/2/maintenance", body={"duration": "1:00", "start": "2026-10-28T13:00"})[0], 500
        )
        self.assertEqual(self.call("POST", "devices/2/maintenance", body={})[0], 400)
        self.assertFalse(self.call("GET", "devices/99/maintenance")[1]["is_under_maintenance"])

    def test_discover_ports_and_poller_groups(self):
        self.assertEqual(
            self.call("GET", "devices/1/discover"),
            (200, {"status": "ok", "result": {"status": 1, "message": "Device will be rediscovered"}, "count": 2}),
        )
        self.assertEqual(self.call("GET", "devices/1/discover")[1]["result"]["status"], 0)
        status, body = self.call("GET", "devices/1/ports", {"columns": "port_id,ifName,ifAlias"})
        self.assertEqual(body, {"status": "ok", "ports": [
            {"port_id": 1, "ifName": "Gi1/0/1", "ifAlias": "uplink to edge-rtr1"},
            {"port_id": 2, "ifName": "Gi1/0/2", "ifAlias": ""},
        ]})  # fmt: skip
        self.assertEqual(
            self.call("GET", "devices/1/ports", {"columns": "port_id,bogus"})[1]["message"], "Invalid columns: bogus"
        )
        self.assertEqual(self.call("GET", "devices/4/ports"), (404, {"status": "error", "message": "No ports found"}))
        self.assertEqual(self.call("GET", "poller_group/1")[1], {"status": "ok", "get_poller_group": {
            "id": 1, "group_name": "core-pollers", "descr": "Pollers in the core sites"}})  # fmt: skip
        self.assertIsInstance(self.call("GET", "poller_group/0")[1]["get_poller_group"], list)


class Locations(_FakeCase):
    def test_list_has_decimal_strings_and_get_has_floats(self):
        body = self.call("GET", "resources/locations")[1]
        self.assertEqual(
            (body["locations"][0]["lat"], body["locations"][0]["fixed_coordinates"], body["count"]),
            ("37.62130000", 1, 3),
        )
        self.assertRegex(body["locations"][0]["timestamp"], r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$")
        status, body = self.call("GET", "location/sfo-1")
        self.assertEqual(
            (status, body["get_location"]["lat"], body["get_location"]["fixed_coordinates"]), (200, 37.6213, True)
        )
        self.assertTrue(body["get_location"]["timestamp"].endswith(".000000Z"))
        self.assertNotIn("count", body)
        self.assertEqual(self.call("GET", "location/99")[1]["message"], "Location does not exist")
        self.fake.tables["locations"].clear()
        self.assertEqual(
            self.call("GET", "resources/locations"), (404, {"status": "error", "message": "Locations do not exist"})
        )

    def test_add(self):
        body = {"location": "BER-4", "lat": 52.52, "lng": 13.405}
        self.assertEqual(
            self.call("POST", "locations", body=body), (201, {"status": "ok", "message": "Location added with id #4"})
        )
        self.assertEqual(self.fake.tables["locations"][4]["fixed_coordinates"], 1)
        self.assertEqual(self.call("POST", "locations", body=dict(body, location="ZERO", lat=0))[0], 400)
        self.assertEqual(
            self.call("POST", "locations", body=dict(body, location="ber-4")), (500, {"message": "Server Error"})
        )

    def test_edit(self):
        before = self.fake.tables["locations"][2]["timestamp"]
        self.assertEqual(self.call("PATCH", "locations/2", body={"lat": 40.5, "fixed_coordinates": 1})[0], 201)
        loc = self.fake.tables["locations"][2]
        self.assertEqual((loc["lat"], loc["fixed_coordinates"]), (40.5, 0))  # fixed_coordinates is not fillable
        self.assertGreater(loc["timestamp"], before)
        self.assertEqual(self.call("PATCH", "locations/2", body={"lat": 1.0}, content_type="")[0], 201)
        self.assertEqual(loc["lat"], 40.5)  # without a JSON content type the body is never read
        self.assertEqual(
            self.call("PATCH", "locations/99", body={"lat": 1.0})[1]["message"], "Failed to update location"
        )

    def test_delete_detaches_devices(self):
        status, body = self.call("DELETE", "locations/2")
        self.assertEqual(status, 201)
        self.assertRegex(body["message"], r'^Location \{"id":2,"location":"NYC-2",.*\} has been deleted successfully$')
        self.assertIsNone(self.fake.tables["devices"][3]["location_id"])
        self.assertEqual(self.call("DELETE", "locations/2")[1]["message"], "Failed to delete  (Does not exists)")


class DeviceGroups(_FakeCase):
    def test_list_and_members(self):
        body = self.call("GET", "devicegroups")[1]
        self.assertEqual(
            ([g["name"] for g in body["groups"]], body["message"]),
            (["core-switches", "edge-routers"], "Found 2 device groups"),
        )
        self.assertIn("joins", body["groups"][1]["rules"])
        self.assertEqual(
            self.call("GET", "devicegroups/1")[1], {"status": "ok", "devices": [{"device_id": 1}], "count": 1}
        )
        self.call("POST", "devicegroups", body={"name": "empty", "type": "static", "devices": []})
        self.assertEqual(self.call("GET", "devicegroups/empty")[1]["message"], "No devices found in group empty")
        self.fake.tables["device_groups"].clear()
        self.assertEqual(
            self.call("GET", "devicegroups"), (404, {"status": "error", "message": "No device groups found"})
        )

    def test_create_wants_rules_as_a_json_string(self):
        rules = {"condition": "AND", "rules": [{"field": "devices.os", "operator": "equal", "value": "ios"}]}
        body = {"name": "ios", "type": "dynamic", "rules": rules}
        self.assertEqual(
            self.call("POST", "devicegroups", body=body)[1]["message"],
            {"rules": ["The rules field must be a valid JSON string."]},
        )
        self.assertEqual(
            self.call("POST", "devicegroups", body=dict(body, rules=json.dumps(rules))),
            (201, {"status": "ok", "id": 3, "message": "Device group ios created"}),
        )
        self.assertEqual(
            self.call("POST", "devicegroups", body=dict(body, name="IOS", rules="{}"))[1]["message"],
            {"name": ["The name has already been taken."]},
        )
        status, body = self.call("POST", "devicegroups", body={"name": "s", "type": "static", "devices": [1, 99]})
        self.assertEqual(status, 500)  # created, then sync() failed on device 99
        self.assertEqual(self.fake.tables["device_groups"][4]["devices"], [1])

    def test_patch_rejects_an_unchanged_name_and_replaces_static_members(self):
        self.assertEqual(self.call("PATCH", "devicegroups/1", body={"name": "CORE-switches"})[0], 422)
        self.assertEqual(
            self.call("PATCH", "devicegroups/1", body={"desc": None})[1]["message"],
            {"desc": ["The desc field must be a string."]},
        )
        self.assertEqual(
            self.call("PATCH", "devicegroups/1", body={"devices": [3, 1]}),
            (200, {"status": "ok", "message": "Device group 1 updated"}),
        )
        self.assertEqual(self.fake.tables["device_groups"][1]["devices"], [1, 3])

    def test_delete_leaves_alert_rule_mappings(self):
        self.assertEqual(self.call("DELETE", "devicegroups/1")[1]["message"], "Device group 1 deleted")
        self.assertEqual(self.fake.tables["rules"][2]["groups"], [1])
        self.assertEqual(self.call("GET", "devicegroups/1")[1]["message"], "Device group not found")


class Services(_FakeCase):
    def test_lists_are_double_wrapped(self):
        body = self.call("GET", "services")[1]
        self.assertEqual((len(body["services"]), len(body["services"][0]), body["count"]), (1, 3, 1))
        row = self.call("GET", "services/3")[1]["services"][0][0]
        self.assertEqual(list(row)[:2], ["service_id", "device_id"])
        self.assertIn(SECRETS[5], row["service_param"])
        self.assertEqual(
            self.call("GET", "services/nope.example.net")[1]["message"], "No valid hostname or device id provided"
        )
        self.assertEqual(self.call("GET", "services/99")[1]["services"], [[]])

    def test_add_embeds_the_new_row_as_json_in_the_message(self):
        data = {"type": "http", "ip": "", "desc": "", "param": "-u /x", "ignore": False, "disable": False, "name": "n"}
        status, body = self.call("POST", "services/2", body=data)
        self.assertEqual(status, 201)
        self.assertIn('"service_param":"-u \\/x"', body["message"])  # json_encode escapes slashes
        model = json.loads(re.search(r"\(#(.*)\)$", body["message"]).group(1))
        self.assertEqual((model["service_id"], model["service_ip"]), (4, "198.51.100.2"))  # "" means the poll target
        self.assertEqual(self.call("POST", "services/2", body={"type": "http"}), (500, {"message": "Server Error"}))
        # desc and param are read with PHP's ?: so a "0" is stored as ""
        self.call("POST", "services/2", body=dict(data, desc="0", param=0))
        self.assertEqual(
            (self.fake.tables["services"][5]["service_desc"], self.fake.tables["services"][5]["service_param"]),
            ("", ""),
        )
        self.assertTrue(
            self.call("POST", "services/2", body=dict(data, type="nrpe"))[1]["message"].startswith(
                "The service nrpe does not exist."
            )
        )

    def test_after_runs_a_hook_once_the_route_has_handled_the_request(self):
        seen = []
        self.fake.after("add_service_for_host", lambda: seen.append(sorted(self.fake.tables["services"])))
        self.assertEqual(self.call("POST", "services/2", body={"type": "icmp", "ip": ""})[0], 201)
        self.call("GET", "services")
        self.assertEqual(seen, [[1, 2, 3, 4]])

    def test_an_edit_that_changes_nothing_and_an_unknown_delete_are_500s(self):
        failed = (500, {"status": "error", "message": "Failed to update the service with id 1"})
        self.assertEqual(self.call("PATCH", "services/1", body={"service_desc": "Web UI"}), failed)
        self.assertEqual(self.call("PATCH", "services/1", body={"service_desc": "new"})[0], 201)
        self.assertEqual(self.call("PATCH", "services/1", body={"desc": "x"}), (500, {"message": "Server Error"}))
        self.assertEqual(
            self.call("DELETE", "services/99"), (500, {"status": "error", "message": "Failed to delete the service"})
        )
        self.assertEqual(self.call("DELETE", "services/1")[0], 201)


class Rules(_FakeCase):
    BUILDER = {"condition": "AND", "rules": [{"field": "devices.status", "operator": "equal", "value": "0"}]}

    def test_shape_and_an_unknown_id(self):
        rule = self.call("GET", "rules/2")[1]["rules"][0]
        self.assertEqual((rule["devices"], rule["groups"], rule["locations"]), ([1], [1], []))
        self.assertEqual((rule["alert_operation_id"], rule["default_operation_step_duration_seconds"]), (1, 300))
        self.assertIsInstance(rule["extra"], dict)
        self.assertIsInstance(rule["operations"], list)
        self.assertEqual(self.call("GET", "rules/99")[1], {"status": "ok", "rules": [], "count": 0})

    def test_create_returns_no_id(self):
        body = {
            "name": "Device down",
            "severity": "critical",
            "builder": self.BUILDER,
            "devices": [-1],
            "alert_operation_id": 1,
        }
        self.assertEqual(self.call("POST", "rules", body=body), (200, {"status": "ok"}))
        created = [r for r in self.fake.tables["rules"].values() if r["name"] == "Device down"]
        self.assertEqual((created[0]["devices"], created[0]["alert_operation_id"]), ([], 1))
        self.assertEqual(
            self.call("POST", "rules", body=body)[1]["message"], "Addition failed : Name has already been used"
        )
        self.assertEqual(
            self.call("POST", "rules", body=dict(body, name="x", devices=[]))[1]["message"],
            "Missing the devices or global device (-1)",
        )
        self.assertEqual(self.call("POST", "rules", body=dict(body, name="x", builder={"rules": []}))[0], 500)
        self.assertEqual(
            self.call("POST", "rules", body=dict(body, name="x", severity="Critical"))[1]["message"],
            "Missing the severity",
        )

    def test_put_rebuilds_everything_the_body_omits(self):
        self.fake.touch("rules", 2, disabled=1)
        body = {"rule_id": 2, "name": "High CPU", "severity": "critical", "builder": self.BUILDER}
        self.assertEqual(self.call("PUT", "rules", body=body), (200, {"status": "ok"}))
        rule = self.fake.tables["rules"][2]
        self.assertEqual((rule["devices"], rule["groups"], rule["disabled"]), ([], [], 0))  # now global and enabled
        self.assertEqual((rule["extra"], rule["notify_per_entity"]), ({"options": {"override_query": False}}, True))
        self.assertEqual(
            self.call("PUT", "rules", body=dict(body, rule_id=99))[1]["message"], "Update failed : Invalid rule id"
        )
        missing = self.call("PUT", "rules", body=dict(body, rule_id=99, name="Fresh"))
        self.assertEqual(missing[1]["message"], "Failed to update existing alert rule")
        self.call("PUT", "rules", body=dict(body, rule_id="abc", name="Other"))  # not numeric: a create
        self.assertIn("Other", [r["name"] for r in self.fake.tables["rules"].values()])

    def test_delete_messages(self):
        self.assertEqual(self.call("DELETE", "rules/1")[1]["message"], "Alert rule has been removed")
        self.assertNotIn(1, {f["rule_id"] for f in self.fake.tables["faults"].values()})
        self.assertEqual(self.call("DELETE", "rules/1"), (200, {"status": "ok", "message": "No alert rule by that ID"}))
        self.assertEqual(self.call("DELETE", "rules/x")[0], 400)


class Faults(_FakeCase):
    ALL = {"state": "0,1,2,3,4,5"}

    def test_the_default_state_filter_hides_all_but_active(self):
        self.assertEqual(self.call("GET", "faults/2")[1], {"status": "ok", "alerts": [], "count": 0})
        row = self.call("GET", "faults/2", self.ALL)[1]["alerts"][0]
        self.assertEqual(
            (row["hostname"], row["info"], row["severity"], row["name"]),
            ("edge-rtr1.example.net", '{"until_clear":false}', "warning", "Port down"),
        )
        self.assertEqual(self.call("GET", "faults", dict(self.ALL, alert_rule="1"))[1]["count"], 3)

    def test_ack_on_a_rule_without_per_entity_changes_every_open_sibling(self):
        self.assertEqual(
            self.call("PUT", "faults/1", body={"note": "looking", "until_clear": True})[1]["message"],
            "Alert has been acknowledged",
        )
        faults = self.fake.tables["faults"]
        self.assertEqual((faults[1]["state"], faults[2]["state"], faults[3]["state"]), (2, 2, 1))  # 3 is another device
        self.assertTrue(faults[1]["note"].endswith(" - Ack (hermes) looking"))
        self.assertEqual(faults[1]["info"], {"until_clear": True})
        self.assertEqual(faults[2]["note"].count("\n"), 1)  # appended to the earlier ack

    def test_a_per_entity_rule_changes_only_the_fault(self):
        self.call("PUT", "faults/4", body={"note": "x", "until_clear": False})
        self.assertEqual((self.fake.tables["faults"][4]["state"], self.fake.tables["faults"][5]["state"]), (2, 0))

    def opened(self, fault_id, state=1):
        """A fault of rule 2 ("High CPU", per entity, no max_entities) on core-sw1."""
        row = {"id": fault_id, "rule_id": 2, "device_id": 1, "state": state, "timestamp": "2026-10-28 11:45:00"}
        self.fake.seed("faults", row)

    def acked(self, fault_id):
        """Acknowledge *fault_id*; the ids of rule 2's faults that are acknowledged afterwards."""
        self.call("PUT", f"faults/{fault_id}", body={"note": "x", "until_clear": False})
        return sorted(f["id"] for f in self.fake.tables["faults"].values() if f["rule_id"] == 2 and f["state"] == 2)

    def test_a_per_entity_rule_stops_at_its_limit_of_faults_that_are_not_clear(self):
        for fault_id in range(10, 29):  # with #4: 20 open faults, the default limit of a rule without max_entities
            self.opened(fault_id)
        self.opened(29, state=0)  # recovered but still open: not counted, yet reached once the limit is passed
        self.assertEqual(self.acked(4), [4])
        self.opened(30)  # the 21st
        self.assertEqual(self.acked(10), [4, *range(10, 31)])

    def test_the_limit_is_at_least_one_and_the_default_is_a_setting(self):
        self.opened(6)
        self.fake.touch("rules", 2, max_entities=0)  # LibreNMS takes at least 1: two open faults are beyond it
        self.assertEqual(self.acked(4), [4, 6])
        self.fake.touch("rules", 2, max_entities=None)
        for fault_id in (7, 8):
            self.opened(fault_id)
        self.assertEqual(self.acked(7), [4, 6, 7])  # four open faults: within the default of 20
        self.fake.default_max_entities = 3
        self.opened(9)
        self.assertEqual(self.acked(9), [4, 6, 7, 8, 9])  # five, beyond a default of 3: #8 is reached too

    def test_unmute_and_the_not_found_messages(self):
        self.assertEqual(
            self.call("PUT", "faults/unmute/2", body={"note": "y"})[1]["message"], "Alert has been unmuted"
        )
        faults = self.fake.tables["faults"]
        self.assertEqual((faults[1]["state"], faults[2]["state"], faults[2]["info"]), (1, 1, {"until_clear": False}))
        self.assertEqual(
            self.call("PUT", "faults/99", body={"note": "x", "until_clear": False})[1]["message"], "No Alert by that ID"
        )
        self.assertEqual(self.call("PUT", "faults/unmute/99", body={"note": "x"})[1]["message"], "No alert by that ID")
        self.fake.touch("faults", 3, open=0, state=0)  # cleared, and its rule does not notify per entity
        self.assertEqual(
            self.call("PUT", "faults/3", body={"note": "x", "until_clear": False})[1]["message"], "No Alert by that ID"
        )
        self.assertEqual(self.call("PUT", "faults/x", body={})[1]["message"], "Invalid fault has been provided")


class Eventlog(_FakeCase):
    def test_sortorder_must_be_exactly_DESC(self):
        newest = self.call("GET", "logs/eventlog/2", {"sortorder": "DESC", "limit": 1})[1]
        self.assertEqual((newest["logs"][0]["event_id"], newest["count"], newest["total"]), (6, 1, 3))
        self.assertEqual(list(newest["logs"][0])[:4], ["hostname", "sysName", "host", "event_id"])
        self.assertEqual(
            self.call("GET", "logs/eventlog/2", {"sortorder": "desc", "limit": 1})[1]["logs"][0]["event_id"], 3
        )

    def test_a_numeric_from_bounds_event_ids(self):
        body = self.call("GET", "logs/eventlog/2", {"from": 5, "sortorder": "DESC"})[1]
        self.assertEqual([e["event_id"] for e in body["logs"]], [6, 5])

    def test_an_unknown_hostname_returns_every_device_and_limits_follow_php(self):
        self.assertEqual(
            self.call("GET", "logs/eventlog/nope.example.net")[1]["total"], len(self.fake.tables["eventlog"])
        )
        self.assertEqual(self.call("GET", "logs/eventlog", {"limit": -1})[1]["count"], 6)
        self.assertEqual(self.call("GET", "logs/eventlog", {"limit": 0})[1]["count"], 0)


class Ports(_FakeCase):
    def test_port_info_includes_deleted_ports_and_an_unknown_id_is_empty(self):
        body = self.call("GET", "ports/3")[1]
        self.assertEqual((body["port"][0]["deleted"], "count" in body), (1, False))
        self.assertEqual(self.call("GET", "ports/99")[1], {"status": "ok", "port": []})

    def test_a_null_description_leaves_the_key_out(self):
        self.assertEqual(self.call("GET", "ports/3/description")[1], {"status": "ok"})
        self.assertEqual(self.call("GET", "ports/1/description")[1]["port_description"], "uplink to edge-rtr1")
        self.assertEqual(
            self.call("GET", "ports/99/description"), (400, {"status": "error", "message": "Invalid port ID."})
        )

    def test_a_clear_stores_repoll_until_the_next_poll(self):
        for body in ({"description": ""}, {}, {"descr": "typo"}):
            self.assertEqual(
                self.call("PATCH", "ports/2/description", body=body)[1]["message"], "Port description cleared."
            )
            self.assertEqual(self.call("GET", "ports/2/description")[1]["port_description"], "repoll")
        self.fake.poll(2, "from SNMP")
        self.assertEqual(self.fake.tables["ports"][2]["ifAlias"], "from SNMP")
        log = self.fake.tables["eventlog"][max(self.fake.tables["eventlog"])]
        self.assertEqual(
            (log["message"], log["type"], log["reference"]), ("Gi1/0/2 Port ifAlias cleared via API", "interface", 2)
        )

    def test_a_set_description_is_pinned_against_the_poller_and_truncated(self):
        self.assertEqual(
            self.call("PATCH", "ports/2/description", body={"description": "new"})[1]["message"],
            "Port description updated.",
        )
        self.fake.poll(2, "from SNMP")
        self.assertEqual(self.fake.tables["ports"][2]["ifAlias"], "new")
        self.call("PATCH", "ports/2/description", body={"description": "x" * 300})
        self.assertEqual(len(self.fake.tables["ports"][2]["ifAlias"]), 255)


if __name__ == "__main__":
    unittest.main()
