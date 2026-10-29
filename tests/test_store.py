"""Plan persistence: ids, where plans live, private and durable files, listing and fragment resolution,
retention, and the per-plan run lock within a process and across processes."""

import contextlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .helpers import REPO_ROOT, submodule

store_mod = submodule("store")
PlanStore = store_mod.PlanStore
RunLockBusy = store_mod.RunLockBusy

# Hermes absent: importing any of these raises ImportError.
NO_HERMES = {"plugins": None, "plugins.plugin_storage": None, "hermes_constants": None}
_MISSING = object()

# A second process that holds a plan's run lock until its stdin closes, or reports whether it can take it.
CHILD = """
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1])
from tests.helpers import submodule

store_mod = submodule("store")
store = store_mod.PlanStore(Path(sys.argv[2]))
mode, plan_id = sys.argv[3], sys.argv[4]
if mode == "hold":
    with store.run_lock(plan_id):
        print("locked", flush=True)
        sys.stdin.read()
else:
    print("free" if store.run_lock_free(plan_id) else "busy", flush=True)
    try:
        with store.run_lock(plan_id):
            print("acquired", flush=True)
    except store_mod.RunLockBusy:
        print("refused", flush=True)
"""


def _plan(plan_id, status="planned", **extra):
    plan = {"id": plan_id, "status": status, "created_at": store_mod.now_iso(), "steps": [], "journal": []}
    plan.update(extra)
    return plan


def _stamp(days_ago):
    moment = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return moment.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _mode(path):
    return stat.S_IMODE(Path(path).stat().st_mode)


@contextlib.contextmanager
def replaced(target, name, value):
    """Swap one attribute for the duration of a block (a hand-written stand-in for mock.patch)."""
    original = getattr(target, name)
    setattr(target, name, value)
    try:
        yield
    finally:
        setattr(target, name, original)


@contextlib.contextmanager
def modules(entries):
    """Install or hide (``None``) entries of ``sys.modules`` for the duration of a block."""
    saved = {name: sys.modules.get(name, _MISSING) for name in entries}
    sys.modules.update(entries)
    try:
        yield
    finally:
        for name, module in saved.items():
            if module is _MISSING:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module


@contextlib.contextmanager
def environ(**values):
    """Set (or, with ``None``, remove) environment variables for the duration of a block."""
    saved = {name: os.environ.get(name) for name in values}
    for name, value in values.items():
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value
    try:
        yield
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


@contextlib.contextmanager
def umask(mask):
    previous = os.umask(mask)
    try:
        yield
    finally:
        os.umask(previous)


class Child:
    """A second Python process running :data:`CHILD` against the same plans directory."""

    def __init__(self, directory, mode, plan_id):
        self.proc = subprocess.Popen(
            [sys.executable, "-c", CHILD, str(REPO_ROOT), str(directory), mode, plan_id],
            cwd=REPO_ROOT,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def line(self):
        line = self.proc.stdout.readline().strip()
        if not line:
            self.proc.kill()
            raise AssertionError(f"child said nothing: {self.proc.communicate(timeout=10)[1]}")
        return line

    def finish(self):
        """Close its stdin (a holder then releases) and return the rest of what it printed."""
        out, err = self.proc.communicate(timeout=30)
        if self.proc.returncode:
            raise AssertionError(f"child failed: {err}")
        return out.split()

    def kill(self):
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.communicate(timeout=10)


class StoreTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.dir = self.root / "plans"
        self.store = PlanStore(self.dir)

    def tearDown(self):
        self._tmp.cleanup()

    def write_raw(self, plan, name=None):
        """Put a plan file on disk as-is (no ``updated_at`` stamping), as an old or hand-edited plan would be."""
        store_mod.private_dir(self.dir)
        (self.dir / f"{name or plan['id']}.json").write_text(json.dumps(plan), encoding="utf-8")

    def hold_in_child(self, plan_id):
        child = Child(self.dir, "hold", plan_id)
        self.addCleanup(child.kill)
        self.assertEqual(child.line(), "locked")
        return child


class Ids(unittest.TestCase):
    def test_plan_ids_and_timestamps(self):
        self.assertRegex(store_mod.new_plan_id(), r"^lnp-\d{8}T\d{6}Z-[0-9a-f]{4}$")
        self.assertRegex(store_mod.now_iso(), r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        self.assertEqual(store_mod.PLUGIN_NAME, "librenms")


class DataDir(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.home = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_hermes_helper_decides_when_importable(self):
        asked = []

        def plugin_data_dir(name):
            asked.append(name)
            return self.home / "managed" / name

        plugins, storage = types.ModuleType("plugins"), types.ModuleType("plugins.plugin_storage")
        storage.plugin_data_dir = plugin_data_dir
        plugins.plugin_storage = storage
        with modules({"plugins": plugins, "plugins.plugin_storage": storage}):
            self.assertEqual(store_mod.data_dir(), self.home / "managed" / "librenms")
            self.assertEqual(store_mod.default_plans_dir(), self.home / "managed" / "librenms" / "plans")
        self.assertEqual(asked, ["librenms", "librenms"])  # resolved on every use, never cached

    def test_hermes_home_resolver_when_the_helper_is_missing_or_fails(self):
        constants = types.ModuleType("hermes_constants")
        constants.get_hermes_home = lambda: self.home / "profile"
        expected = self.home / "profile" / "plugin-data" / "librenms"
        with modules({**NO_HERMES, "hermes_constants": constants}):
            self.assertEqual(store_mod.data_dir(), expected)

        def refuses(name):
            raise PermissionError("read-only home")

        plugins, storage = types.ModuleType("plugins"), types.ModuleType("plugins.plugin_storage")
        storage.plugin_data_dir = refuses
        plugins.plugin_storage = storage
        with modules({"plugins": plugins, "plugins.plugin_storage": storage, "hermes_constants": constants}):
            self.assertEqual(store_mod.data_dir(), expected)

    def test_environment_fallback_is_read_on_every_call(self):
        with modules(NO_HERMES), environ(HERMES_HOME=str(self.home / "a")):
            self.assertEqual(store_mod.data_dir(), self.home / "a" / "plugin-data" / "librenms")
            os.environ["HERMES_HOME"] = str(self.home / "b")
            self.assertEqual(store_mod.data_dir(), self.home / "b" / "plugin-data" / "librenms")
        with modules(NO_HERMES), environ(HERMES_HOME=None, HOME=str(self.home)):
            self.assertEqual(store_mod.data_dir(), self.home / ".hermes" / "plugin-data" / "librenms")

    def test_the_data_directory_hermes_creates_under_the_umask_is_narrowed_to_0700(self):
        # Hermes' helper mkdirs it under the umask (0755 with 022), so other accounts could list plans and audit.jsonl
        def plugin_data_dir(name):
            root = self.home / "plugin-data" / name
            root.mkdir(parents=True, exist_ok=True)
            return root

        plugins, storage = types.ModuleType("plugins"), types.ModuleType("plugins.plugin_storage")
        storage.plugin_data_dir = plugin_data_dir
        plugins.plugin_storage = storage
        with modules({"plugins": plugins, "plugins.plugin_storage": storage}), umask(0o022):
            path = store_mod.data_dir()
            self.assertEqual(_mode(path), 0o700)
            self.assertEqual(_mode(path.parent), 0o755)  # Hermes' own directory, shared by every plugin, stays
            os.chmod(path, 0o750)  # an earlier release's directory, or one widened by hand
            self.assertEqual(_mode(store_mod.data_dir()), 0o700)

    def test_a_linked_data_directory_is_left_as_it_is(self):
        target = self.home / "relocated"
        target.mkdir(mode=0o755)
        os.chmod(target, 0o755)
        (self.home / "plugin-data").mkdir()
        os.symlink(target, self.home / "plugin-data" / "librenms")
        with modules(NO_HERMES), environ(HERMES_HOME=str(self.home)):
            self.assertEqual(store_mod.data_dir(), self.home / "plugin-data" / "librenms")
        self.assertEqual(_mode(target), 0o755)

    def test_profile_key_is_hermes_own_else_the_home(self):
        constants = types.ModuleType("hermes_constants")
        constants.hermes_home_key = lambda: "/resolved/profiles/netops"
        with modules({"hermes_constants": constants}):
            self.assertEqual(store_mod.profile_key(), "/resolved/profiles/netops")
        with modules(NO_HERMES), environ(HERMES_HOME=str(self.home / "b")):
            self.assertEqual(store_mod.profile_key(), str(self.home / "b"))

    def test_a_store_without_a_directory_follows_the_active_profile(self):
        with modules(NO_HERMES), environ(HERMES_HOME=str(self.home / "a")), umask(0o022):
            store = PlanStore()
            a = self.home / "a" / "plugin-data" / "librenms" / "plans"
            self.assertFalse(a.exists())  # nothing is created until first use
            store.create(_plan("lnp-20261028T190000Z-aaaa"))
            self.assertTrue((a / "lnp-20261028T190000Z-aaaa.json").exists())
            for directory in (a, a.parent, a.parent.parent, a.parent.parent.parent):
                self.assertEqual(_mode(directory), 0o700, directory)
            os.environ["HERMES_HOME"] = str(self.home / "b")
            self.assertEqual(store.list(), [])
            self.assertEqual(store.directory, self.home / "b" / "plugin-data" / "librenms" / "plans")


class Files(StoreTestCase):
    def test_create_never_overwrites_an_existing_plan(self):
        first = _plan("lnp-20261028T190000Z-aaaa", marker="first")
        self.store.create(first)
        second = _plan("lnp-20261028T190000Z-aaaa", marker="second")  # as if the random suffix repeated
        self.store.create(second)
        self.assertNotEqual(second["id"], first["id"])
        self.assertEqual(self.store.load(first["id"])["marker"], "first")
        self.assertEqual(self.store.load(second["id"])["marker"], "second")
        self.assertEqual(len(self.store.list()), 2)

    def test_create_gives_up_after_attempts(self):
        with replaced(store_mod, "new_plan_id", lambda: "lnp-20261028T190000Z-bbbb"):
            self.store.create(_plan("lnp-20261028T190000Z-bbbb"))
            with self.assertRaises(RuntimeError):
                self.store.create(_plan("lnp-20261028T190000Z-bbbb"), attempts=3)

    def test_files_are_0600_after_create_and_after_every_save(self):
        # NetBox's save wrote the temporary file with the umask, so a plan became 0644 after its first save
        for mask in (0o022, 0o000, 0o277):
            with umask(mask):
                plan = _plan(f"lnp-20261028T190000Z-{mask:04o}")
                self.store.create(plan)
                path = self.dir / f"{plan['id']}.json"
                self.assertEqual(_mode(path), 0o600, oct(mask))
                stale = path.with_suffix(".json.tmp")
                stale.write_text("{}")
                os.chmod(stale, 0o644)  # left by a crash; os.open would keep its mode
                plan["status"] = "applying"
                self.store.save(plan)
                self.assertEqual(_mode(path), 0o600, oct(mask))
                self.assertFalse(stale.exists())
                on_disk = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual((on_disk["status"], on_disk["updated_at"]), ("applying", plan["updated_at"]))

    def test_every_write_is_fsynced_with_its_directory(self):
        kinds = []
        real_fsync = os.fsync

        def recording(fd):
            kinds.append("dir" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file")
            return real_fsync(fd)

        plan = _plan("lnp-20261028T190000Z-f5f5")
        with replaced(os, "fsync", recording):
            self.store.create(plan)
            self.assertEqual(kinds, ["file", "dir"])
            self.store.save(plan)
        self.assertEqual(kinds, ["file", "dir", "file", "dir"])

    def test_a_failed_save_keeps_the_old_file_and_leaves_no_temporary_one(self):
        plan = _plan("lnp-20261028T190000Z-6b6b")
        self.store.create(plan)
        path = self.dir / f"{plan['id']}.json"
        before = path.read_text(encoding="utf-8")

        def disk_full(*_args):
            raise OSError(28, "No space left on device")

        with replaced(os, "replace", disk_full), self.assertRaises(OSError):
            self.store.save(dict(plan, status="applying"))
        self.assertEqual(path.read_text(encoding="utf-8"), before)
        self.assertEqual([p.name for p in self.dir.iterdir()], [path.name])

    def test_a_failed_create_leaves_no_truncated_plan(self):
        def fails(_fd):
            raise OSError(5, "I/O error")

        with replaced(os, "fsync", fails), self.assertRaises(OSError):
            self.store.create(_plan("lnp-20261028T190000Z-7c7c"))
        self.assertEqual(list(self.dir.iterdir()), [])

    def test_directories_it_creates_are_0700_whatever_the_umask(self):
        (self.root / "existing").mkdir()
        os.chmod(self.root / "existing", 0o755)
        for mask in (0o022, 0o000):
            plans = self.root / "existing" / f"home-{mask:o}" / "plugin-data" / "librenms" / "plans"
            with umask(mask):
                PlanStore(plans).create(_plan("lnp-20261028T190000Z-0700"))
            for directory in (plans, plans.parent, plans.parent.parent, plans.parent.parent.parent):
                self.assertEqual(_mode(directory), 0o700, (oct(mask), directory))
        self.assertEqual(_mode(self.root / "existing"), 0o755)  # the operator's own, left alone
        self.assertEqual(store_mod.private_dir(plans), plans)

    def test_a_directory_another_process_creates_first_is_not_an_error(self):
        target = self.root / "raced" / "plans"
        real_mkdir = os.mkdir

        def racing(path, mode=0o777):
            real_mkdir(path, 0o755)  # the other process wins
            raise FileExistsError(path)

        with replaced(os, "mkdir", racing):
            self.assertEqual(store_mod.private_dir(target), target)
        self.assertTrue(target.is_dir())

    def test_the_directory_fsync_is_best_effort(self):
        # Windows cannot open a directory, and some file systems refuse to fsync one
        store_mod._fsync_dir(self.root / "missing")

        def refuses(_fd):
            raise OSError(22, "Invalid argument")

        with replaced(os, "fsync", refuses):
            store_mod._fsync_dir(self.root)

    def test_a_lone_surrogate_is_saved_as_its_escape_and_read_back_the_same(self):
        # a JSON tool argument can carry "\ud800", which UTF-8 cannot encode
        plan = _plan("lnp-20261028T190000Z-5a5a", description="x\ud800", steps=[{"t\udfff": "\ud83d"}])
        self.store.create(plan)
        path = self.dir / f"{plan['id']}.json"
        self.assertIn('"x\\ud800"', path.read_text(encoding="utf-8"))
        self.assertEqual(self.store.load(plan["id"]), plan)
        plan["status"] = "applied"
        self.store.save(plan)
        self.assertEqual(self.store.load(plan["id"]), plan)

    def test_ids_that_could_escape_the_directory_are_refused(self):
        for bad in ("", "../etc/passwd", "a/b", "a\\b", "lnp-..-x"):
            with self.assertRaises(ValueError):
                self.store.load(bad)
            with self.assertRaises(ValueError):
                self.store.run_lock_free(bad)
        self.assertIsNone(self.store.load("lnp-20261028T190000Z-none"))


class Listing(StoreTestCase):
    def test_list_filters_sorts_limits_and_skips_what_does_not_parse(self):
        for i, status in enumerate(("planned", "applied", "planned")):
            self.write_raw(_plan(f"lnp-20261028T19000{i}Z-000{i}", status, created_at=f"2026-10-28T19:00:0{i}Z"))
        self.write_raw(_plan("lnp-20261028T190009Z-0009", created_at=5))  # edited stamp: sorts, never crashes
        (self.dir / "lnp-20261028T190010Z-trnc.json").write_text('{"id": "lnp-')  # truncated
        (self.dir / "lnp-20261028T190011Z-list.json").write_text("[]")
        (self.dir / "lnp-20261028T190002Z-0002.json.tmp").write_text("{}")
        (self.dir / "lnp-20261028T190002Z-0002.run").write_text("")
        (self.dir / "other.json").write_text("{}")
        ids = [p["id"] for p in self.store.list(limit=50)]
        self.assertEqual(
            ids,
            [
                "lnp-20261028T190009Z-0009",
                "lnp-20261028T190002Z-0002",
                "lnp-20261028T190001Z-0001",
                "lnp-20261028T190000Z-0000",
            ],
        )
        self.assertEqual(
            [p["id"] for p in self.store.list(status="planned", limit=50)],
            ["lnp-20261028T190009Z-0009", "lnp-20261028T190002Z-0002", "lnp-20261028T190000Z-0000"],
        )
        self.assertEqual(len(self.store.list(limit=2)), 2)
        self.assertEqual(len(self.store.list(limit=0)), 1)

    def test_resolve_exact_suffix_substring_and_case(self):
        for plan_id in ("lnp-20261028T190000Z-4f1a", "lnp-20261028T190100Z-9c2e", "lnp-20261028T190200Z-9c2f"):
            self.store.create(_plan(plan_id))
        resolve = self.store.resolve
        self.assertEqual(
            resolve("lnp-20261028T190000Z-4f1a"), ("lnp-20261028T190000Z-4f1a", ["lnp-20261028T190000Z-4f1a"])
        )
        self.assertEqual(resolve(" 4f1a ")[0], "lnp-20261028T190000Z-4f1a")
        self.assertEqual(resolve("4F1A")[0], "lnp-20261028T190000Z-4f1a")
        self.assertEqual(resolve("T190000Z-4f1a")[0], "lnp-20261028T190000Z-4f1a")
        self.assertEqual(resolve("190100")[0], "lnp-20261028T190100Z-9c2e")
        self.assertEqual(resolve("9c2"), (None, ["lnp-20261028T190100Z-9c2e", "lnp-20261028T190200Z-9c2f"]))
        for missing in ("zzzz", "", None, "../etc"):
            self.assertEqual(resolve(missing), (None, []), missing)


class Prune(StoreTestCase):
    def old(self, suffix, status, days=100, **changes):
        """An old plan file named ``...-<suffix>``; *changes* edit its content (even its id) after the fact."""
        plan_id = f"lnp-20260101T000000Z-{suffix}"
        plan = _plan(plan_id, status, updated_at=_stamp(days))
        plan.update(changes)
        self.write_raw(plan, name=plan_id)
        return plan_id

    def test_old_finished_plans_go_and_in_flight_ones_stay(self):
        for i, status in enumerate(("applied", "rolled_back", "planned", "applying", "rolling_back", "failed")):
            self.old(f"s{i:03d}", status)
        fresh = self.old("frsh", "applied", days=1)
        expected = ["applied", "failed", "planned", "rolled_back"]
        preview = self.store.prune(90, dry_run=True)
        self.assertEqual(sorted(r["status"] for r in preview), expected)
        self.assertEqual(len(self.store.list(limit=50)), 7)
        self.assertEqual({r["age_days"] for r in preview}, {100.0})
        removed = self.store.prune(90)
        self.assertEqual(sorted(r["status"] for r in removed), expected)
        self.assertEqual(
            sorted(p["status"] for p in self.store.list(limit=50)), ["applied", "applying", "rolling_back"]
        )
        self.assertIsNotNone(self.store.load(fresh))
        self.assertEqual(self.store.prune(0), [])
        self.assertEqual(self.store.prune(-1), [])
        later = datetime.now(timezone.utc) + timedelta(days=90)
        self.assertEqual([r["id"] for r in self.store.prune(90, now=later)], [fresh])

    def test_unreadable_stamps_are_kept_and_the_file_read_is_the_one_removed(self):
        keep = self.old("keep", "applied", days=1)
        for suffix, changes in (
            ("int0", {"updated_at": 5, "created_at": 5}),
            ("junk", {"updated_at": "yesterday", "created_at": None}),
            ("naiv", {"updated_at": "2020-01-01T00:00:00"}),  # no zone: read as UTC
            ("imps", {"id": keep, "updated_at": "2020-01-01T00:00:00Z"}),  # claims another plan's id
        ):
            self.old(suffix, "applied", **changes)
        removed = sorted(r["id"][-4:] for r in self.store.prune(30))
        self.assertEqual(removed, ["imps", "naiv"])
        self.assertIsNotNone(self.store.load(keep))

    def test_run_files_go_with_their_plan_and_held_plans_stay(self):
        ran = self.old("ran0", "applied")
        with self.store.run_lock(ran):
            pass
        self.assertTrue((self.dir / f"{ran}.run").exists())
        mine = self.old("mine", "failed")
        theirs = self.old("thrs", "failed")
        never = self.old("nevr", "planned")
        other = PlanStore(self.dir)  # another open file description: what another process would hold
        with self.store.run_lock(mine), other.run_lock(theirs):
            self.assertEqual(sorted(r["id"] for r in self.store.prune(90, dry_run=True)), sorted([ran, never]))
            self.assertFalse((self.dir / f"{never}.run").exists())  # a dry run creates nothing
            self.assertEqual(sorted(r["id"] for r in self.store.prune(90)), sorted([ran, never]))
        self.assertFalse((self.dir / f"{ran}.run").exists())
        self.assertEqual(sorted(p["id"] for p in self.store.list(limit=50)), sorted([mine, theirs]))
        self.assertEqual(sorted(r["id"] for r in self.store.prune(90)), sorted([mine, theirs]))
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()), [".lock"])

    def test_a_plan_another_process_is_running_is_kept(self):
        plan_id = self.old("proc", "failed")
        child = self.hold_in_child(plan_id)
        self.assertEqual(self.store.prune(90), [])
        self.assertIsNotNone(self.store.load(plan_id))
        child.finish()
        self.assertEqual([r["id"] for r in self.store.prune(90)], [plan_id])

    def test_prune_and_delete_wait_for_the_store_lock(self):
        plan_id = self.old("lckd", "applied")
        held, release = threading.Event(), threading.Event()

        def holder():
            with PlanStore(self.dir).exclusive(5.0):
                held.set()
                release.wait(10)

        thread = threading.Thread(target=holder, daemon=True)
        thread.start()
        self.assertTrue(held.wait(10))
        self.store.claim_timeout = 0.2
        try:
            with self.assertRaises(TimeoutError):
                self.store.prune(90)
            with self.assertRaises(TimeoutError):
                self.store.delete(plan_id)
        finally:
            release.set()
            thread.join(10)
        self.assertEqual([r["id"] for r in self.store.prune(90)], [plan_id])

    def test_delete_removes_the_plan_and_its_run_file_unless_a_run_holds_it(self):
        plan_id = self.old("del0", "applied")
        with self.store.run_lock(plan_id):
            self.assertFalse(self.store.delete(plan_id))
        self.assertTrue(self.store.delete(plan_id))
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()), [".lock"])
        self.assertFalse(self.store.delete(plan_id))
        self.store.create(_plan("lnp-20261028T190000Z-del1"))
        self.assertTrue(self.store.delete("lnp-20261028T190000Z-del1"))


class RunLock(StoreTestCase):
    PLAN = "lnp-20261028T190000Z-run0"

    def test_re_entrant_in_the_holding_thread(self):
        # the automatic rollback runs inside its apply; a second flock on a new descriptor would refuse it
        other = PlanStore(self.dir)
        self.assertTrue(self.store.run_lock_free(self.PLAN))
        with self.store.run_lock(self.PLAN):
            with self.store.run_lock(self.PLAN):
                self.assertFalse(self.store.run_lock_free(self.PLAN))
                with self.assertRaises(RunLockBusy), other.run_lock(self.PLAN):
                    pass
            self.assertFalse(self.store.run_lock_free(self.PLAN))  # the outer hold continues
            self.assertFalse(other.run_lock_free(self.PLAN))
            with self.assertRaises(RunLockBusy), other.run_lock(self.PLAN):
                pass
        self.assertTrue(self.store.run_lock_free(self.PLAN))
        with other.run_lock(self.PLAN):
            self.assertFalse(self.store.run_lock_free(self.PLAN))
        self.assertEqual(_mode(self.dir / f"{self.PLAN}.run"), 0o600)
        self.assertTrue(issubclass(RunLockBusy, RuntimeError))

    def test_another_thread_of_the_same_process_is_refused(self):
        outcome = []

        def contender():
            try:
                with self.store.run_lock(self.PLAN):
                    outcome.append("acquired")
            except RunLockBusy:
                outcome.append("refused")

        with self.store.run_lock(self.PLAN):
            thread = threading.Thread(target=contender)
            thread.start()
            thread.join(10)
        self.assertEqual(outcome, ["refused"])
        thread = threading.Thread(target=contender)
        thread.start()
        thread.join(10)
        self.assertEqual(outcome, ["refused", "acquired"])

    def test_an_exception_inside_releases_the_lock(self):
        with self.assertRaises(KeyError), self.store.run_lock(self.PLAN), self.store.run_lock(self.PLAN):
            raise KeyError("boom")
        self.assertTrue(PlanStore(self.dir).run_lock_free(self.PLAN))

    def test_checking_a_plan_that_never_ran_creates_nothing(self):
        self.assertTrue(self.store.run_lock_free(self.PLAN))
        self.assertEqual(list(self.dir.iterdir()), [])

    def test_running_lists_every_held_run_whatever_its_status(self):
        held_here, held_there, finished = (f"lnp-20261028T190000Z-run{n}" for n in (1, 2, 3))
        for plan_id, status in ((held_here, "failed"), (held_there, "applied"), (finished, "rolled_back")):
            self.store.create(_plan(plan_id, status))
        self.assertEqual(self.store.running(), [])
        with self.store.run_lock(finished):
            pass  # a run that ended leaves its .run file behind
        child = self.hold_in_child(held_there)
        with self.store.run_lock(held_here):
            self.assertEqual(self.store.running(), [held_here, held_there])
            self.assertEqual(PlanStore(self.dir).running(), [held_here, held_there])
        child.finish()
        self.assertEqual(self.store.running(), [])
        self.assertEqual(
            sorted(path.name for path in self.dir.glob("*.run")),
            [f"{p}.run" for p in (held_here, held_there, finished)],
        )

    def test_exclusive_across_processes(self):
        child = self.hold_in_child(self.PLAN)
        self.assertFalse(self.store.run_lock_free(self.PLAN))
        with self.assertRaises(RunLockBusy), self.store.run_lock(self.PLAN):
            pass
        child.finish()
        self.assertTrue(self.store.run_lock_free(self.PLAN))
        with self.store.run_lock(self.PLAN):
            child = Child(self.dir, "probe", self.PLAN)
            self.addCleanup(child.kill)
            self.assertEqual(child.finish(), ["busy", "refused"])
        self.assertEqual(Child(self.dir, "probe", self.PLAN).finish(), ["free", "acquired"])


class Exclusive(StoreTestCase):
    def test_the_store_lock_times_out_then_works(self):
        held, release = threading.Event(), threading.Event()

        def holder():
            with PlanStore(self.dir).exclusive(1.0):
                held.set()
                release.wait(10)

        thread = threading.Thread(target=holder, daemon=True)
        thread.start()
        self.assertTrue(held.wait(10))
        with self.assertRaises(TimeoutError) as caught, self.store.exclusive(0.2):
            pass
        self.assertEqual(str(caught.exception), "plan store is locked by another process")
        release.set()
        thread.join(10)
        with self.store.exclusive(1.0):
            pass
        self.assertEqual(_mode(self.dir / ".lock"), 0o600)

    def test_it_holds_the_in_process_lock_too(self):
        free = []
        with self.store.exclusive(1.0):
            thread = threading.Thread(target=lambda: free.append(self.store.lock.acquire(blocking=False)))
            thread.start()
            thread.join(10)
        self.assertEqual(free, [False])


class _Msvcrt:
    """``msvcrt.locking`` for the Windows branch: one byte-range lock per file, held by one descriptor."""

    LK_NBLCK, LK_UNLCK = 2, 0

    def __init__(self):
        self.holders = {}
        self.unlock_fails = False

    def locking(self, fd, mode, _nbytes):
        key = os.fstat(fd).st_ino
        if mode == self.LK_UNLCK:
            if self.unlock_fails:
                raise OSError("unlock failed")
            self.holders.pop(key, None)
        elif self.holders.get(key, fd) != fd:
            raise OSError("locked")
        else:
            self.holders[key] = fd


class WindowsLocking(StoreTestCase):
    """The msvcrt branch of both locks, run here with fcntl hidden and a stand-in msvcrt."""

    def setUp(self):
        super().setUp()
        self.msvcrt = _Msvcrt()
        hidden = modules({"fcntl": None, "msvcrt": self.msvcrt})
        hidden.__enter__()
        self.addCleanup(hidden.__exit__, None, None, None)

    def test_store_lock_and_run_lock(self):
        with self.store.exclusive(1.0):
            other = os.open(self.dir / ".lock", os.O_RDWR)
            try:
                with self.assertRaises(TimeoutError):
                    store_mod._acquire(other, 0.1)
            finally:
                os.close(other)
        self.assertEqual(self.msvcrt.holders, {})
        plan_id = "lnp-20261028T190000Z-win0"
        with self.store.run_lock(plan_id), self.store.run_lock(plan_id):
            self.assertFalse(PlanStore(self.dir).run_lock_free(plan_id))
            with self.assertRaises(RunLockBusy), PlanStore(self.dir).run_lock(plan_id):
                pass
        self.assertTrue(PlanStore(self.dir).run_lock_free(plan_id))

    def test_a_failed_unlock_is_ignored(self):
        self.msvcrt.unlock_fails = True
        with self.store.exclusive(1.0):
            pass


class Singleton(unittest.TestCase):
    def test_the_process_wide_store_is_created_once_and_replaceable(self):
        store_mod.set_store(None)
        try:
            first = store_mod.get_store()
            self.assertIs(store_mod.get_store(), first)
            mine = PlanStore(Path(tempfile.gettempdir()))
            store_mod.set_store(mine)
            self.assertIs(store_mod.get_store(), mine)
        finally:
            store_mod.set_store(None)


if __name__ == "__main__":
    unittest.main()
