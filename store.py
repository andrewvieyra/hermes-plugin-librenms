"""Plan persistence: one JSON file per plan under the plugin's data directory.

The plan file is the source of truth during apply: the journal is flushed after every step so an interrupted
apply leaves a file that ``librenms_rollback`` can act on. Files are ``0600`` in ``0700`` directories and every
write is fsynced, because a plan holds what rollback needs (service parameters included).
"""

from __future__ import annotations

import contextlib
import itertools
import json
import os
import secrets
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Tuple

PLUGIN_NAME = "librenms"
PREFIX = "lnp"
IN_FLIGHT = ("applying", "rolling_back")
# A plan can carry a lone surrogate (a JSON tool argument may hold "\ud800"), which UTF-8 cannot encode.
# json.dumps only leaves one inside a JSON string, where backslashreplace writes it as that escape again, so the
# plan is saved whole and reads back the same.
_ENCODE_ERRORS = "backslashreplace"
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


class RunLockBusy(RuntimeError):
    """Another process (or another thread of this one) holds the plan's run lock: an apply or rollback is
    running."""


def data_dir() -> Path:
    """``<HERMES_HOME>/plugin-data/librenms``, resolved on every call so it follows the active Hermes profile:
    Hermes' own helper when importable, else its home resolver, else ``$HERMES_HOME`` or ``~/.hermes``."""
    try:
        from plugins.plugin_storage import plugin_data_dir  # type: ignore

        return Path(plugin_data_dir(PLUGIN_NAME))
    except Exception:
        pass
    try:
        from hermes_constants import get_hermes_home  # type: ignore

        return Path(get_hermes_home()) / "plugin-data" / PLUGIN_NAME
    except Exception:
        pass
    home = os.environ.get("HERMES_HOME") or os.path.join(os.path.expanduser("~"), ".hermes")
    return Path(home) / "plugin-data" / PLUGIN_NAME


def default_plans_dir() -> Path:
    return data_dir() / "plans"


def private_dir(path: Path) -> Path:
    """Create *path* and any missing parent as ``0700`` directories, whatever the umask, and return it.
    ``mkdir(parents=True)`` would leave every parent it creates readable by other accounts. Directories that
    already exist keep their mode: they are the operator's."""
    path = Path(path)
    missing = list(itertools.takewhile(lambda directory: not directory.is_dir(), (path, *path.parents)))
    for directory in reversed(missing):
        try:
            os.mkdir(directory, 0o700)
        except FileExistsError:  # another process made it first
            continue
        os.chmod(directory, 0o700)
    return path


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def new_plan_id() -> str:
    """``lnp-<ISO 8601 basic UTC timestamp>-<4 hex>``, e.g. ``lnp-20261028T190000Z-ab12``: filename-safe (no
    colons), sorts chronologically, and the ``Z`` makes the zone explicit."""
    return f"{PREFIX}-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{secrets.token_hex(2)}"


class PlanStore:
    claim_timeout: float = 30.0  # seconds to wait for the cross-process lock when claiming a plan

    def __init__(self, directory: Path | None = None):
        self._dir = Path(directory) if directory else None
        self._lock = threading.RLock()
        # run-lock file path -> [fd, depth, owning thread]; see run_lock
        self._held: Dict[str, List[int]] = {}

    @property
    def lock(self) -> threading.RLock:
        """In-process lock; see :meth:`exclusive` for the cross-process one."""
        return self._lock

    @contextlib.contextmanager
    def exclusive(self, timeout: float = 30.0) -> Iterator[None]:
        """Serialise plan claims across processes (gateway and ``hermes librenms`` run separately) with an
        advisory lock on ``<plans>/.lock``. Holds the in-process lock too. Raises ``TimeoutError`` when another
        holder does not release within *timeout* seconds."""
        with self._lock:
            fd = os.open(self.directory / ".lock", os.O_RDWR | os.O_CREAT, 0o600)
            try:
                _acquire(fd, timeout)
                try:
                    yield
                finally:
                    _release(fd)
            finally:
                os.close(fd)

    @contextlib.contextmanager
    def run_lock(self, plan_id: str) -> Iterator[None]:
        """Hold an exclusive, non-blocking advisory lock on ``<plans>/<id>.run`` for a whole apply or rollback,
        so a plan left ``applying`` with its run lock free is known to be a run that died. Re-entrant in the
        thread that holds it (the automatic rollback runs inside its apply): a nested enter only counts, because
        a second ``flock`` on a new descriptor would conflict with the first. Raises :class:`RunLockBusy` when
        another process or another thread holds it."""
        key = str(self._run_path(plan_id))
        me = threading.get_ident()
        with self._lock:
            held = self._held.get(key)
            if held is not None and held[2] != me:
                raise RunLockBusy(f"plan {plan_id} is being run by another thread")
            if held is not None:
                held[1] += 1
            else:
                fd = os.open(key, os.O_RDWR | os.O_CREAT | _NOFOLLOW, 0o600)
                if not _try_lock(fd):
                    os.close(fd)
                    raise RunLockBusy(f"plan {plan_id} is being run by another process")
                self._held[key] = [fd, 1, me]
        try:
            yield
        finally:
            with self._lock:
                held = self._held[key]
                held[1] -= 1
                if held[1] == 0:
                    del self._held[key]
                    try:
                        _release(held[0])
                    finally:
                        os.close(held[0])

    def run_lock_free(self, plan_id: str) -> bool:
        """Whether nobody holds the plan's run lock; ``False`` while this process holds it. Takes and drops the
        lock to find out, so call it under :meth:`exclusive`, where no run can be starting. Creates nothing."""
        path = self._run_path(plan_id)
        with self._lock:
            if str(path) in self._held:
                return False
            return self._probe(path)

    def running(self) -> List[str]:
        """The ids of the plans whose run lock is held, by this process or another, whatever their status says (an
        apply saves ``failed`` while it still holds the lock for its automatic rollback). Probes every ``.run`` file
        like :meth:`run_lock_free`, so call it under :meth:`exclusive`. Creates nothing."""
        with self._lock:
            return sorted(
                path.stem
                for path in self.directory.glob(f"{PREFIX}-*.run")
                if str(path) in self._held or not self._probe(path)
            )

    @property
    def directory(self) -> Path:
        """The plans directory, created ``0700`` on first use. Without an explicit directory it is resolved on
        every access, so a process serving several Hermes profiles writes each one's plans to its own home."""
        return private_dir(self._dir if self._dir is not None else default_plans_dir())

    def _path(self, plan_id: str) -> Path:
        if not plan_id or "/" in plan_id or "\\" in plan_id or ".." in plan_id:
            raise ValueError(f"invalid plan id {plan_id!r}")
        return self.directory / f"{plan_id}.json"

    def _run_path(self, plan_id: str) -> Path:
        return self._path(plan_id).with_suffix(".run")

    def create(self, plan: Dict[str, Any], *, attempts: int = 5) -> None:
        """First save of a new plan. The file is created exclusively (``O_EXCL``), so an id that already exists on
        disk can never be overwritten; on a collision the plan gets a fresh id and we retry."""
        with self._lock:
            for _ in range(attempts):
                path = self._path(plan["id"])
                plan["updated_at"] = now_iso()
                payload = _dumps(plan)
                try:
                    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW, 0o600)
                except FileExistsError:
                    plan["id"] = new_plan_id()
                    continue
                try:
                    _write(fd, payload)
                except BaseException:
                    path.unlink(missing_ok=True)  # a truncated plan would fail every later load
                    raise
                _fsync_dir(path.parent)
                return
            raise RuntimeError(f"could not allocate a unique plan id after {attempts} attempts")

    def save(self, plan: Dict[str, Any]) -> None:
        """Persist an existing plan (atomic, durable replace). Use :meth:`create` for a brand-new plan. A save that
        fails leaves the old file as it was and no temporary file behind."""
        with self._lock:
            path = self._path(plan["id"])
            tmp = path.with_suffix(".json.tmp")
            plan["updated_at"] = now_iso()
            payload = _dumps(plan)
            try:
                _write(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | _NOFOLLOW, 0o600), payload)
                os.replace(tmp, path)
            except BaseException:
                tmp.unlink(missing_ok=True)
                raise
            _fsync_dir(path.parent)

    def load(self, plan_id: str) -> Dict[str, Any] | None:
        with self._lock:
            path = self._path(plan_id)
            if not path.exists():
                return None
            return json.loads(path.read_text(encoding="utf-8"))

    def _documents(self) -> List[Tuple[Path, Dict[str, Any]]]:
        """Every plan file that parses to an object, with its path; the rest (a truncated or hand-edited file) are
        left out."""
        found: List[Tuple[Path, Dict[str, Any]]] = []
        for path in self.directory.glob(f"{PREFIX}-*.json"):
            try:
                plan = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            if isinstance(plan, dict):
                found.append((path, plan))
        return found

    def list(self, status: str | None = None, limit: int = 20) -> List[Dict[str, Any]]:
        with self._lock:
            plans = [plan for _path, plan in self._documents() if not status or plan.get("status") == status]
        plans.sort(key=lambda p: str(p.get("created_at") or ""), reverse=True)  # an edited stamp never crashes
        return plans[: max(1, limit)]

    def resolve(self, fragment: str) -> Tuple[str | None, List[str]]:
        """Map what a human typed to a plan id. An exact id wins; otherwise an unambiguous suffix or substring
        match (``ab12`` or ``T190000Z-ab12``) resolves. Returns ``(plan_id, candidates)``: ``plan_id`` is None when
        nothing or more than one plan matches, and ``candidates`` lists the matches so the caller can show them."""
        fragment = (fragment or "").strip()
        if not fragment:
            return None, []
        with self._lock:
            try:
                if self._path(fragment).exists():
                    return fragment, [fragment]
            except ValueError:
                return None, []
            ids = sorted(p.stem for p in self.directory.glob(f"{PREFIX}-*.json"))
        needle = fragment.lower()
        candidates = [i for i in ids if i.lower().endswith(needle)]
        if not candidates:
            candidates = [i for i in ids if needle in i.lower()]
        return (candidates[0], candidates) if len(candidates) == 1 else (None, candidates)

    def prune(self, max_age_days: int, *, now: datetime | None = None, dry_run: bool = False) -> List[Dict[str, Any]]:
        """Remove plans whose last update is older than *max_age_days*, with their run-lock files. In-flight plans
        (``applying``, ``rolling_back``) and plans whose run lock is held are never removed; the whole sweep runs
        under :meth:`exclusive` so no run can start on a plan being removed. Returns ``[{"id", "status",
        "age_days"}]`` for each plan removed (or that would be, with *dry_run*). ``max_age_days <= 0`` disables
        pruning."""
        if max_age_days <= 0:
            return []
        now = now or datetime.now(timezone.utc)
        removed: List[Dict[str, Any]] = []
        with self.exclusive(self.claim_timeout):
            for path, plan in self._documents():
                if plan.get("status") in IN_FLIGHT:
                    continue
                updated = _parse_stamp(plan.get("updated_at") or plan.get("created_at"))
                if updated is None:
                    continue
                age_days = (now - updated).total_seconds() / 86400
                if age_days < max_age_days:
                    continue
                # the file that was read, whatever id an edited plan claims
                if self._remove(path, dry_run=dry_run):
                    removed.append({"id": path.stem, "status": plan.get("status"), "age_days": round(age_days, 1)})
        return removed

    def delete(self, plan_id: str) -> bool:
        """Remove a plan and its run-lock file, under :meth:`exclusive` like :meth:`prune`; ``False`` when there is
        no such plan or a run holds it."""
        path = self._path(plan_id)
        with self.exclusive(self.claim_timeout):
            return path.exists() and self._remove(path, dry_run=False)

    def _remove(self, path: Path, *, dry_run: bool) -> bool:
        """Unlink a plan file and its ``.run`` file while holding the run lock, so no run can hold a lock on a file
        that no longer exists; ``False`` when a run holds it. Callers hold :meth:`exclusive`, under which no run
        can be opening the file."""
        run_path = path.with_suffix(".run")
        if str(run_path) in self._held:
            return False
        try:
            fd = os.open(run_path, os.O_RDWR | _NOFOLLOW)
        except FileNotFoundError:  # never run: nothing to hold
            if not dry_run:
                path.unlink(missing_ok=True)
            return True
        try:
            if not _try_lock(fd):
                return False
            try:
                if not dry_run:
                    path.unlink(missing_ok=True)
                    run_path.unlink(missing_ok=True)
            finally:
                _release(fd)
        finally:
            os.close(fd)
        return True

    @staticmethod
    def _probe(path: Path) -> bool:
        try:
            fd = os.open(path, os.O_RDWR | _NOFOLLOW)
        except FileNotFoundError:
            return True
        try:
            if not _try_lock(fd):
                return False
            _release(fd)
            return True
        finally:
            os.close(fd)


def _dumps(plan: Dict[str, Any]) -> bytes:
    text = json.dumps(plan, indent=2, ensure_ascii=False, sort_keys=False, default=str)
    return text.encode("utf-8", _ENCODE_ERRORS)


def _write(fd: int, payload: bytes) -> None:
    """Write *payload* to *fd* as a ``0600`` file and fsync it; closes *fd*. The mode is set again because
    ``os.open`` only applies its mode to a file it creates, and the umask could narrow it."""
    with os.fdopen(fd, "wb") as fh:
        if hasattr(os, "fchmod"):
            os.fchmod(fh.fileno(), 0o600)
        fh.write(payload)
        fh.flush()
        os.fsync(fh.fileno())


def _fsync_dir(directory: Path) -> None:
    """Make a create or rename durable. Windows cannot open a directory, so there it is skipped."""
    try:
        fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _parse_stamp(stamp: Any) -> datetime | None:
    if not isinstance(stamp, str):
        return None
    try:
        parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _try_lock(fd: int) -> bool:
    """One non-blocking attempt at an exclusive advisory lock: ``fcntl.flock``, or ``msvcrt.locking`` on
    Windows."""
    try:
        import fcntl
    except ImportError:  # Windows: msvcrt byte-range lock
        import msvcrt

        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        except OSError:
            return False
        return True
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return False
    return True


def _acquire(fd: int, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while not _try_lock(fd):
        if time.monotonic() >= deadline:
            raise TimeoutError("plan store is locked by another process")
        time.sleep(0.05)


def _release(fd: int) -> None:
    try:
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_UN)
    except ImportError:
        import msvcrt

        with contextlib.suppress(OSError):
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)


_store: PlanStore | None = None
_store_lock = threading.Lock()


def get_store() -> PlanStore:
    global _store
    with _store_lock:
        if _store is None:
            _store = PlanStore()
        return _store


def set_store(store: PlanStore | None) -> None:
    """Test seam / profile switch: replace the process-wide store."""
    global _store
    with _store_lock:
        _store = store
