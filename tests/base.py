"""Fixture shared by the suite: a fresh fake LibreNMS and a client on it, a temp HERMES_HOME holding the plan store,
pinned settings and a temp audit log for every test, and every module-level seam reset afterwards (design §16.9).
Modules are fetched per test (the loader test re-imports the package), and one not written yet is skipped, so the
earlier test waves share this base."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List

from .fake_librenms import TOKEN, FakeLibreNMS, seeded
from .helpers import submodule

# What tearDown calls, in the order design §16.9 gives: (module, function, arguments).
_RESETS = (
    ("settings", "set_settings", (None,)),
    ("settings", "set_context", (None,)),
    ("audit", "set_ctx", (None,)),
    ("audit", "clear_requests", ()),
    ("handlers", "reset_state", ()),
    ("audit", "set_audit_log", (None,)),
    ("sinks", "set_worker", (None,)),
    ("store", "set_store", (None,)),
    ("handlers", "set_client_factory", (None,)),
)


def optional(name: str) -> Any:
    """The plugin module *name*, or None while it does not exist yet."""
    try:
        return submodule(name)
    except ImportError:
        return None


class PluginTestCase(unittest.TestCase):
    """Fresh fake LibreNMS, client, temp HERMES_HOME and plan store, pinned settings and audit log for every test."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name) / "hermes-home"
        self.home.mkdir()
        self.addCleanup(_restore_env, "HERMES_HOME", os.environ.get("HERMES_HOME"))
        os.environ["HERMES_HOME"] = str(self.home)  # anything resolving a default path lands in the temp home
        self.client_mod = submodule("client")
        self.store_mod = submodule("store")
        self.settings_mod = submodule("settings")
        self.audit = optional("audit")
        self.planner = optional("planner")
        self.executor = optional("executor")
        self.handlers = optional("handlers")
        self.fake: FakeLibreNMS = seeded()
        self.client = self.client_mod.LibreNMSClient(self.fake.base_url, TOKEN, session=self.fake)
        self.client.retry_sleep = lambda _seconds: None
        self.store = self.store_mod.PlanStore(self.home / "plugin-data" / "librenms" / "plans")
        self.store_mod.set_store(self.store)
        self.settings = self.settings_mod.Settings(allow_delete=True, allow_device_add=True, allow_services=True)
        self.settings_mod.set_settings(self.settings)
        self.audit_path = Path(tmp.name) / "audit.jsonl"
        if self.audit is not None:
            self.audit.set_audit_log(self.audit.AuditLog(self.audit_path))
        if self.handlers is not None:
            self.handlers.set_client_factory(lambda *_args, **_kwargs: self.client)

    def tearDown(self) -> None:
        for name, function, args in _RESETS:
            module = optional(name)
            if module is not None:
                getattr(module, function)(*args)

    def plan(
        self, operations: List[Dict[str, Any]], description: str = "test", plan_id: str | None = None
    ) -> Dict[str, Any]:
        """Build and save a plan as librenms_plan does, minus the handler (no actor, no plan_created event); under
        *plan_id* when one is given (two plans that end alike)."""
        plan = submodule("planner").build_plan(
            self.client, operations, description, self.settings, self.client.base_url
        )
        if plan_id is not None:
            plan["id"] = plan_id
        self.store.create(plan)
        return plan

    def events(self, event: str | None = None) -> List[Dict[str, Any]]:
        """Parsed audit records written so far, oldest first; only those named *event* when one is given."""
        if not self.audit_path.exists():
            return []
        rows = [json.loads(line) for line in self.audit_path.read_text(encoding="utf-8").splitlines() if line]
        return [row for row in rows if event is None or row.get("event") == event]


def _restore_env(name: str, value: str | None) -> None:
    if value is None:
        os.environ.pop(name, None)
    else:
        os.environ[name] = value
