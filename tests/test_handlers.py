"""The five tool handlers against the fake LibreNMS: query (routes, hostname resolution, listings, refusals, masking,
status), plan / apply / rollback / plans end to end, argument coercion, plan id resolution, error shapes, and the
invariants that the token and existing service parameters never reach a tool result or an audit line."""

import json
import os
import unittest

from .base import PluginTestCase
from .fake_librenms import TOKEN
from .helpers import submodule

SERVICE_SECRET = "Sup3rS3cret!"  # in service 2's parameters in the seeded fake
SNMP_SECRETS = ("c0re-Community!", "Auth-S3cret-v3", "Priv-S3cret-v3", "acc3ss-Community")


class HandlerCase(PluginTestCase):
    def setUp(self):
        super().setUp()
        self.outputs = []

    def call(self, name, _kwargs=None, **args):
        raw = self.handlers.HANDLERS[name](args, **(_kwargs or {}))
        self.assertIsInstance(raw, str)
        self.outputs.append(raw)
        return json.loads(raw)

    def update_purpose(self, purpose="spine", device_id=1):
        return {"op": "update", "resource": "device", "id": device_id, "data": {"purpose": purpose}}

    def gets(self):
        return [c for c in self.fake.calls if c["method"] == "GET"]


class Query(HandlerCase):
    def test_status(self):
        out = self.call("librenms_query", action="status")
        self.assertTrue(out["success"])
        self.assertEqual(out["librenms"]["local_ver"], "26.10.0")
        self.assertEqual(out["librenms_url"], "https://librenms.test")
        self.assertEqual(out["transport"]["scheme"], "https")
        self.assertEqual(out["plugin_version"], submodule("version").__version__)
        self.assertEqual((out["write_mode"], out["apply_available"]), ("full", True))
        self.assertEqual(out["settings"]["audit_sinks"], {"count": 0, "types": []})
        self.assertEqual((out["settings_errors"], out["warnings"]), ([], []))

    def test_status_warns_about_unapproved_writes_and_insecure_transport(self):
        self.settings_mod.set_settings(
            self.settings_mod.Settings(require_approval=False, allow_insecure_transport=True)
        )
        warnings = self.call("librenms_query", action="status")["warnings"]
        self.assertTrue(any("require_approval is false" in w for w in warnings), warnings)
        self.assertTrue(any(w.startswith("allow_insecure_transport is on") for w in warnings), warnings)

    def test_status_warns_about_a_sink_credential_written_into_config_yaml_without_quoting_it(self):
        sink = {"type": "http", "url": "https://hec.example.com", "headers": {"Authorization": "Splunk 3f2a9c1e-77"}}
        self.settings_mod.set_settings(self.settings_mod.Settings(audit_sinks=[sink]))
        # what Hermes' raw read finds, where it is importable (JSON is YAML)
        config = {"plugins": {"entries": {"librenms": {"settings": {"audit_sinks": [sink]}}}}}
        (self.home / "config.yaml").write_text(json.dumps(config), encoding="utf-8")
        out = self.call("librenms_query", action="status")
        (warning,) = out["warnings"]
        self.assertTrue(warning.startswith("audit_sinks[0] header Authorization holds a credential written into "))
        self.assertNotIn("3f2a9c1e", json.dumps(out))

    def test_status_says_only_whether_a_custom_audit_log_path_is_set(self):
        self.settings_mod.set_settings(self.settings_mod.Settings(audit_log_path="/home/alice/logs/audit.jsonl"))
        out = self.call("librenms_query", action="status")
        self.assertEqual(out["settings"]["audit_log_path"], "custom")
        self.assertNotIn("alice", json.dumps(out))

    def test_list_with_params_fields_and_limit(self):
        out = self.call("librenms_query", path="devices", params={"type": "all"}, fields=["hostname"], limit=2)
        self.assertEqual((out["path"], out["route"]), ("devices", "list_devices"))
        self.assertEqual((out["count"], out["returned"], out["truncated"]), (4, 2, True))
        self.assertEqual(out["results"], [{"hostname": "access-sw2.example.net"}, {"hostname": "core-sw1.example.net"}])
        self.assertEqual(self.gets()[-1]["params"], {"type": "all"})

    def test_limit_capped_by_settings(self):
        self.settings_mod.set_settings(self.settings_mod.Settings(max_query_results=1))
        self.assertEqual(self.call("librenms_query", path="devices", limit=500)["returned"], 1)

    def test_hostname_is_resolved_to_an_id_before_the_query(self):
        out = self.call("librenms_query", path="devices/core-sw1.example.net/ports", params={"columns": "ifName"})
        self.assertEqual(out["path"], "devices/core-sw1.example.net/ports")
        self.assertEqual(out["results"], [{"ifName": "Gi1/0/1"}, {"ifName": "Gi1/0/2"}])
        self.assertEqual([c["path"] for c in self.gets()], ["devices/core-sw1.example.net", "devices/1/ports"])

    def test_empty_list_404_is_a_note_not_an_error(self):
        out = self.call("librenms_query", path="devices/4/ports")
        self.assertTrue(out["success"])
        self.assertEqual((out["count"], out["results"], out["note"]), (0, [], "No ports found"))

    def test_object_result_and_projection(self):
        out = self.call("librenms_query", path="location/1", fields=["location", "lat"])
        self.assertEqual(out["route"], "get_location")
        self.assertEqual(out["result"], {"location": "SFO-1", "lat": 37.6213})

    def test_service_rows_are_unwrapped_and_parameters_masked(self):
        out = self.call("librenms_query", path="services")
        self.assertEqual(out["count"], 3)
        self.assertEqual({row["service_id"] for row in out["results"]}, {1, 2, 3})
        self.assertNotIn(SERVICE_SECRET, self.outputs[-1])

    def test_device_credentials_are_masked(self):
        out = self.call("librenms_query", path="devices/2")
        device = out["results"][0]
        self.assertEqual((device["authpass"], device["cryptopass"], device["authname"]), ("<redacted>",) * 3)
        for secret in SNMP_SECRETS:
            self.assertNotIn(secret, self.outputs[-1])

    def test_logs_routes_send_the_exact_sortorder_and_report_the_total(self):
        out = self.call("librenms_query", path="logs/eventlog/edge-rtr1.example.net", limit=2)
        self.assertEqual((out["count"], out["total"], out["truncated"]), (2, 3, True))
        sent = self.gets()[-1]
        self.assertEqual(sent["path"], "logs/eventlog/2")
        self.assertEqual((sent["params"]["sortorder"], sent["params"]["limit"]), ("DESC", "2"))

    def test_logs_paging_is_truncated_only_while_rows_remain_past_this_page(self):
        total = len(self.fake.tables["eventlog"])
        for start, returned, truncated in (
            (0, 2, True),
            (total - 3, 2, True),
            (total - 2, 2, False),
            (total - 1, 1, False),
            (total, 0, False),
            (total + 50, 0, False),
        ):
            out = self.call("librenms_query", path="logs/eventlog", params={"start": start}, limit=2)
            self.assertEqual(
                (out["total"], out["returned"], out["truncated"]), (total, returned, truncated), f"start {start}"
            )

    def test_a_404_page_that_is_not_librenms_is_an_error_not_an_empty_inventory(self):
        # LIBRENMS_URL without LibreNMS's sub-path: the web server answers every request with its own 404 page
        nginx = "<html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1>nginx</body></html>"
        self.fake.fail_on("*", ".*", 404, nginx)
        for path in ("devices", "devices/core-sw1.example.net/ports"):
            out = self.call("librenms_query", path=path)
            self.assertFalse(out["success"], path)
            self.assertNotIn("results", out)
            self.assertEqual(out["librenms"]["kind"], "invalid", path)
            self.assertIn("did not come from LibreNMS", out["error"])
            self.assertIn("LIBRENMS_URL", out["error"])
        location = {"op": "create", "resource": "location", "data": {"location": "SFO-1", "lat": 1.5, "lng": 2.5}}
        planned = self.call("librenms_plan", description="x", operations=[location])
        self.assertFalse(planned["success"])  # SFO-1 exists: the page must not read as "no such location"
        self.assertIn("LIBRENMS_URL", self.outputs[-1])
        self.assertEqual(self.store.list(), [])

    def test_a_device_reference_with_a_slash_never_reaches_librenms(self):
        # devices/<id>%2Fdiscover is decoded by Laravel before routing and schedules a rediscovery
        discovered = self.fake.tables["devices"][1]["last_discovered"]
        for path, value in (("bgp", "1/discover"), ("routing/vrf", "core-sw1.example.net/discover")):
            out = self.call("librenms_query", path=path, params={"hostname": value})
            self.assertTrue(out["refused"], path)
            self.assertIn("no hostname holds a '/'", out["error"])
        port = {
            "op": "update",
            "resource": "port",
            "match": {"device": "core-sw1.example.net/discover", "ifName": "Gi1/0/1"},
            "data": {"description": "x"},
        }
        self.assertFalse(self.call("librenms_plan", description="x", operations=[port])["success"])
        self.assertEqual([c["path"] for c in self.fake.calls if "discover" in c["path"]], [])
        self.assertEqual(self.fake.tables["devices"][1]["last_discovered"], discovered)

    def test_a_hostname_param_a_route_ignores_is_refused_before_anything_is_sent(self):
        for path, form in (("logs/eventlog", "'logs/eventlog/<hostname>'"), ("services", "'services/<hostname>'")):
            out = self.call("librenms_query", path=path, params={"hostname": "no-such-device.example.net"})
            self.assertTrue(out["refused"], path)
            self.assertIn("every device's rows", out["error"])
            self.assertIn(f"query the path {form}", out["error"])
        out = self.call("librenms_query", path="faults", params={"hostname": "core-sw1.example.net"})
        self.assertEqual(
            out["error"], "LibreNMS's list_alerts does not read params.hostname, so it would return every device's rows"
        )
        self.assertEqual(len(self.events("query_refused")), 3)
        self.assertEqual(self.fake.calls, [])

    def test_an_unknown_device_id_is_refused(self):
        out = self.call("librenms_query", path="devices/999/ports")
        self.assertEqual((out["refused"], out["error"]), (True, "no LibreNMS device has id 999"))
        self.assertEqual([c["path"] for c in self.gets()], ["devices/999"])

    def test_refused_and_malformed_paths_are_audited(self):
        for path, phrase in (
            ("devices/1/discover", "refused"),
            ("../etc", ". or .."),
            ("devices?type=all", "params"),
            ("oxidized/config/sw1", "refused"),
            ("devices/no-such-host.example.net/ports", "no LibreNMS device has hostname"),
        ):
            out = self.call("librenms_query", path=path)
            self.assertFalse(out["success"], path)
            self.assertTrue(out["refused"], path)
            self.assertIn(phrase, out["error"], path)
        refused = self.events("query_refused")
        self.assertEqual(len(refused), 5)
        self.assertEqual((refused[0]["path"], refused[0]["actor"]["kind"]), ("devices/1/discover", "model"))
        self.assertIn("discover", refused[0]["reason"])
        self.assertEqual([c for c in self.fake.calls if c["method"] != "GET"], [])

    def test_bad_arguments_are_structured_errors(self):
        self.assertIn("action must be", self.call("librenms_query", action="delete")["error"])
        self.assertIn("fields must be", self.call("librenms_query", path="devices", fields="hostname")["error"])
        self.assertIn("limit must be an integer", self.call("librenms_query", path="devices", limit="lots")["error"])

    def test_librenms_errors_carry_the_structured_error(self):
        self.fake.fail_on("GET", "devices", 500, {"status": "error", "message": "boom"})
        out = self.call("librenms_query", path="devices")
        self.assertFalse(out["success"])
        self.assertEqual((out["librenms"]["status"], out["librenms"]["kind"]), (500, "server"))

    def test_unconfigured_client_reports_config_error(self):
        client_mod = submodule("client")
        self.handlers.set_client_factory(lambda: client_mod.LibreNMSClient.from_env({}))
        out = self.call("librenms_query", action="status")
        self.assertFalse(out["success"])
        self.assertIn("LIBRENMS_URL and LIBRENMS_TOKEN", out["error"])
        self.assertEqual(out["librenms"]["kind"], "config")

    def test_handlers_never_raise_and_hide_unexpected_detail(self):
        self.handlers.set_client_factory(lambda: (_ for _ in ()).throw(RuntimeError("kaboom at /home/x")))
        with self.assertLogs(self.handlers.logger, "ERROR"):
            out = self.call("librenms_query", path="devices")
        self.assertEqual(set(out), {"success", "error"})
        self.assertRegex(out["error"], r"^unexpected error err-[0-9a-f]{12} \(RuntimeError\); see the Hermes log$")
        self.assertNotIn("kaboom", self.outputs[-1])
        with self.assertLogs(self.handlers.logger, "ERROR"):
            self.assertFalse(json.loads(self.handlers.librenms_plans("not a mapping"))["success"])


class PlanApplyRollback(HandlerCase):
    def test_end_to_end_through_handlers(self):
        planned = self.call("librenms_plan", description="repurpose", operations=[self.update_purpose()])
        self.assertTrue(planned["success"])
        self.assertIn('purpose: "core" -> "spine"', planned["diff"])
        self.assertIn("explicitly say yes", planned["next_step"])
        self.assertEqual((planned["summary"]["update"], planned["irreversible"]), (1, []))
        pid = planned["plan_id"]
        created = self.events("plan_created")[-1]
        self.assertEqual((created["plan_id"], created["actor"]["kind"], created["steps"]), (pid, "model", 1))

        listed = self.call("librenms_plans")
        self.assertEqual(listed["plans"][0]["plan_id"], pid)
        self.assertEqual(self.call("librenms_plans", plan_id=pid)["status"], "planned")

        dry = self.call("librenms_apply", plan_id=pid, dry_run=True)
        self.assertEqual((dry["dry_run"], dry["applicable"], dry["conflicts"]), (True, True, []))
        applied = self.call("librenms_apply", plan_id=pid)
        self.assertTrue(applied["success"])
        self.assertEqual(applied["outcome"], "applied")
        self.assertEqual(self.fake.tables["devices"][1]["purpose"], "spine")
        entry = applied["journal"][0]
        self.assertEqual((entry["status"], entry["resource"], entry["inverse_kind"]), ("done", "device", "exact"))
        self.assertTrue(applied["eventlog"]["linked"])

        again = self.call("librenms_apply", plan_id=pid)
        self.assertFalse(again["success"])
        self.assertTrue(again["refused"])
        self.assertEqual(self.events("apply_refused")[-1]["plan_id"], pid)

        rolled = self.call("librenms_rollback", plan_id=pid)
        self.assertTrue(rolled["success"])
        self.assertEqual(self.fake.tables["devices"][1]["purpose"], "core")
        self.assertIn("Rollback: 1 reverted", rolled["report"])
        self.assertEqual(rolled["journal"][0]["revert_status"], "reverted")
        self.assertEqual(rolled["rollback"]["reverted"], 1)

    def test_failed_apply_reports_the_journal_without_an_error_key(self):
        pid = self.plan([self.update_purpose()])["id"]
        self.fake.fail_on("PATCH", "devices/1", 422, {"status": "error", "message": "nope"})
        out = self.call("librenms_apply", plan_id=pid)
        self.assertEqual((out["success"], out["outcome"]), (False, "failed"))
        self.assertNotIn("error", out)
        self.assertEqual(out["failure"]["index"], 0)
        self.assertEqual(out["journal"][0]["status"], "failed")
        self.assertIn("FAILED at step 0", out["report"])

    def test_plan_errors_are_returned_not_raised(self):
        out = self.call(
            "librenms_plan", description="bad", operations=[{"op": "update", "resource": "device", "data": {}}]
        )
        self.assertFalse(out["success"])
        self.assertEqual(out["errors"][0]["index"], 0)
        self.assertEqual(self.call("librenms_plans")["count"], 0)
        rejected = self.events("plan_rejected")[-1]
        self.assertEqual((rejected["operations"], rejected["errors"]), (1, len(out["errors"])))
        self.assertIn("plan not created", self.call("librenms_plan", description="x", operations=[])["error"])

    def test_noop_plan_says_nothing_to_apply(self):
        out = self.call("librenms_plan", description="same", operations=[self.update_purpose("core")])
        self.assertIn("Nothing to apply", out["next_step"])

    def test_action_only_plan_is_not_nothing_and_names_irreversible_steps(self):
        op = {"op": "maintenance", "resource": "device", "id": 1, "data": {"duration": "1:00"}}
        out = self.call("librenms_plan", description="window", operations=[op])
        self.assertEqual(out["irreversible"], [0])
        self.assertNotIn("Nothing to apply", out["next_step"])
        self.assertIn("steps [0] cannot be rolled back", out["next_step"])

    def test_string_booleans_are_coerced(self):
        pid = self.plan([self.update_purpose()])["id"]
        dry = self.call("librenms_apply", plan_id=pid, dry_run="true")
        self.assertTrue(dry.get("dry_run"))
        self.assertEqual(self.fake.writes(), [])
        applied = self.call("librenms_apply", plan_id=pid, dry_run="false", rollback_on_failure="no")
        self.assertEqual(applied["outcome"], "applied")
        self.assertFalse(self.store.load(pid)["apply"]["rollback_on_failure"])

    def test_junk_booleans_take_the_default(self):
        pid = self.plan([self.update_purpose()])["id"]
        applied = self.call("librenms_apply", plan_id=pid, dry_run="maybe", rollback_on_failure=0)
        self.assertEqual(applied["outcome"], "applied")
        self.assertTrue(self.store.load(pid)["apply"]["rollback_on_failure"])
        parse = self.handlers.parse_bool
        self.assertEqual(
            [parse(v, True) for v in (False, " Off ", "NO", "0", 0, None, [], "x")], [False] * 4 + [True] * 4
        )
        self.assertEqual([parse(v, False) for v in (True, "On", "yes", "1", 1, "", {})], [True] * 4 + [False] * 3)

    def test_unknown_and_ambiguous_plan_ids(self):
        for name in ("librenms_apply", "librenms_rollback", "librenms_plans"):
            for bad in ("lnp-nope", "../x", " "):
                out = self.call(name, plan_id=bad)
                if name == "librenms_plans" and not bad.strip():
                    self.assertTrue(out["success"])  # no plan_id: the listing
                    continue
                self.assertFalse(out["success"], (name, bad))
                self.assertIn("unknown plan_id", out["error"])
        self.assertEqual(self.events("apply_refused")[0]["reason"], "unknown plan_id 'lnp-nope'")
        self.assertIn("unknown plan_id", self.events("rollback_refused")[0]["reason"])
        self.plan([self.update_purpose()])
        self.plan([self.update_purpose("edge", 2)])
        out = self.call("librenms_apply", plan_id="lnp-")
        self.assertIn("matches 2 plans", out["error"])
        self.assertEqual(self.fake.writes(), [])

    def test_a_unique_fragment_resolves_to_its_plan(self):
        pid = self.plan([self.update_purpose()])["id"]
        out = self.call("librenms_plans", plan_id=pid.rsplit("-", 1)[1])
        self.assertEqual(out["plan_id"], pid)
        for short in (pid[-3:], "1", "Z"):  # shorter than the random suffix: never a guess at "the" plan
            self.assertIn("unknown plan_id", self.call("librenms_apply", plan_id=short)["error"])
            directive = self.handlers.pre_tool_call("librenms_apply", {"plan_id": short})
            self.assertIn(":unresolved:", directive["rule_key"])
        self.assertTrue(self.call("librenms_apply", plan_id=f"  {pid}  ")["success"])

    def test_plans_show_has_the_full_journal_and_the_listing_filters(self):
        pid = self.plan([self.update_purpose()])["id"]
        self.call("librenms_apply", plan_id=pid)
        shown = self.call("librenms_plans", plan_id=pid)
        self.assertEqual(shown["journal"][0]["inverse"]["data"], {"purpose": "core"})
        self.assertIn("after_state", shown["journal"][0])
        self.assertEqual(shown["apply"]["outcome"], "applied")
        self.assertEqual(self.call("librenms_plans", status="planned")["count"], 0)
        self.assertEqual(self.call("librenms_plans", status="applied", limit="junk")["count"], 1)

    def test_secrets_never_reach_a_tool_result_or_an_audit_line(self):
        op = {"op": "update", "resource": "service", "id": 2, "data": {"desc": "Intranet SSO"}}
        planned = self.call("librenms_plan", description="svc", operations=[op])
        pid = planned["plan_id"]
        self.assertIn(SERVICE_SECRET, json.dumps(self.store.load(pid)))  # the plan file keeps it for rollback
        self.call("librenms_plans", plan_id=pid)
        self.call("librenms_apply", plan_id=pid)
        self.call("librenms_plans", plan_id=pid)
        self.call("librenms_rollback", plan_id=pid)
        self.call("librenms_plans", plan_id=pid)
        self.call("librenms_query", path="devices")
        self.call("librenms_query", path="services/access-sw2.example.net")
        self.call("librenms_query", action="status")
        self.assertEqual(self.fake.tables["services"][2]["service_desc"], "Intranet login")
        audit_text = self.audit_path.read_text(encoding="utf-8")
        for text in [*self.outputs, audit_text]:
            for secret in (TOKEN, SERVICE_SECRET, *SNMP_SECRETS):
                self.assertNotIn(secret, text)


class Prune(HandlerCase):
    def age(self, plan_id, days):
        from datetime import datetime, timedelta, timezone

        path = self.store.directory / f"{plan_id}.json"
        doc = json.loads(path.read_text())
        doc["updated_at"] = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat().replace("+00:00", "Z")
        path.write_text(json.dumps(doc))

    def test_prune_plans_is_audited(self):
        pid = self.plan([self.update_purpose()])["id"]
        self.age(pid, 5)
        preview = self.handlers.prune_plans(days=3, dry_run=True)
        self.assertEqual([r["id"] for r in preview["removed"]], [pid])
        self.assertIsNotNone(self.store.load(pid))
        self.assertEqual(self.events("plans_pruned"), [])
        actor = self.audit.capture_actor({}, via=self.audit.VIA_CLI)
        result = self.handlers.prune_plans(days=3, actor=actor)
        self.assertEqual((result["max_age_days"], len(result["removed"])), (3, 1))
        self.assertIsNone(self.store.load(pid))
        pruned = self.events("plans_pruned")[-1]
        self.assertEqual((pruned["plan_ids"], pruned["actor"]["via"]), ([pid], "cli"))

    def test_opportunistic_prune_runs_on_plan_once_per_interval(self):
        self.settings_mod.set_settings(self.settings_mod.Settings(plan_retention_days=1))
        stale = self.plan([self.update_purpose()])["id"]
        self.age(stale, 2)
        self.call("librenms_plan", description="x", operations=[self.update_purpose("edge", 2)])
        self.assertIsNone(self.store.load(stale))
        again = self.plan([self.update_purpose()])["id"]
        self.age(again, 2)
        self.call("librenms_plan", description="y", operations=[self.update_purpose("edge", 3)])
        self.assertIsNotNone(self.store.load(again))  # within the hour: no second sweep
        self.handlers.reset_state()
        self.call("librenms_plan", description="z", operations=[self.update_purpose("edge", 4)])
        self.assertIsNone(self.store.load(again))

    def test_retention_zero_never_prunes(self):
        self.settings_mod.set_settings(self.settings_mod.Settings(plan_retention_days=0))
        stale = self.plan([self.update_purpose()])["id"]
        self.age(stale, 4000)
        self.call("librenms_plan", description="x", operations=[self.update_purpose("edge", 2)])
        self.assertIsNotNone(self.store.load(stale))

    def test_listing_plans_and_status_sweep_too_so_a_profile_that_stops_planning_is_still_pruned(self):
        self.settings_mod.set_settings(self.settings_mod.Settings(plan_retention_days=1))
        for name, args in (
            ("librenms_plans", {}),
            ("librenms_plans", {"plan_id": "x"}),
            ("librenms_query", {"action": "status"}),
        ):
            self.handlers.reset_state()
            stale = self.plan([self.update_purpose()])["id"]
            self.age(stale, 2)
            self.call(name, {"task_id": "t1"}, **args)
            self.assertIsNone(self.store.load(stale), name)
            pruned = self.events("plans_pruned")[-1]
            self.assertEqual((pruned["plan_ids"], pruned["actor"]["kind"]), ([stale], "model"))

    def test_the_hourly_throttle_is_kept_per_profile(self):
        # a gateway serving two profiles: one profile's sweep must not hold off the other's for an hour
        self.settings_mod.set_settings(self.settings_mod.Settings(plan_retention_days=1))
        os.environ["HERMES_HOME"] = str(self.home / "profiles" / "a")
        self.call("librenms_plans")  # profile a swept, nothing to remove yet
        stale = self.plan([self.update_purpose()])["id"]
        self.age(stale, 2)
        self.call("librenms_plans")
        self.assertIsNotNone(self.store.load(stale))  # profile a: within its hour
        os.environ["HERMES_HOME"] = str(self.home / "profiles" / "b")
        self.call("librenms_plans")
        self.assertIsNone(self.store.load(stale))  # profile b: its own first sweep

    def test_a_failing_sweep_never_fails_the_call(self):
        self.settings_mod.set_settings(self.settings_mod.Settings(plan_retention_days=1))

        def broken(*args, **kwargs):
            raise OSError("disk gone")

        self.store.prune = broken
        self.assertTrue(self.call("librenms_plans")["success"])


if __name__ == "__main__":
    unittest.main()
