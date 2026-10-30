"""Plan persistence: one JSON file per plan under the plugin's data directory.

The plan file is the source of truth during apply: the journal is flushed after every step so an interrupted
apply leaves a file that ``librenms_rollback`` can act on. Files are ``0600`` in ``0700`` directories (the data
directory itself included, which Hermes' helper creates under the umask) and every write is fsynced, because a plan
holds what rollback needs (service parameters included).
"""

from __future__ import annotations

import contextlib
import hashlib
import itertools
import json
import os
import re
import secrets
import stat
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Tuple

PLUGIN_NAME = "librenms"
PREFIX = "lnp"
IN_FLIGHT = ("applying", "rolling_back")
UNKNOWN_STATUS = "unknown"  # what a plan file without a usable status (hand-edited, damaged) is listed and found as
MIN_FRAGMENT = 4  # hex digits in a plan id's random suffix
# What a plan id (and so a plan file's name) may hold: the planner's own ids (new_plan_id) and nothing that leaves
# the plans directory or that the approval rule key could not be read back from.
PLAN_ID_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*")
# A plan can carry a lone surrogate (a JSON tool argument may hold "\ud800"), which UTF-8 cannot encode.
# json.dumps only leaves one inside a JSON string, where backslashreplace writes it as that escape again, so the
# plan is saved whole and reads back the same.
_ENCODE_ERRORS = "backslashreplace"
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
# The keys of a plan that decide what an apply or a rollback does and what the approval prompt shows of it: what it
# changes and how (steps, with their snapshots and inverses), what it says about that (summary, irreversible steps,
# warnings, the description), where and since when (LibreNMS, created_at), and how far it has run (status, journal,
# and the apply and rollback records a rollback prompt shows: who ran it, how it failed, what was recovered). Left
# out: who planned it and from where (requested_by, audit), the dry-run checks, and updated_at, which a dry run
# changes without changing what runs or what a prompt shows.
CONTENT_KEYS = (
    "id",
    "version",
    "status",
    "created_at",
    "librenms_url",
    "description",
    "summary",
    "warnings",
    "irreversible",
    "steps",
    "journal",
    "apply",
    "rollback",
)
CONTENT_DIGEST_CHARS = 32  # hex: 128 bits, too many to make two plan files that share one


def plan_status(plan: Dict[str, Any]) -> str:
    """A plan's status as the listings show it and ``status`` filters it: :data:`UNKNOWN_STATUS` when the file
    leaves it out or holds something other than text, so the label an operator reads is one they can filter on."""
    status = plan.get("status")
    return status if isinstance(status, str) and status else UNKNOWN_STATUS


def content_digest(plan: Dict[str, Any]) -> str:
    """A sha256 of the canonical JSON of *plan*'s :data:`CONTENT_KEYS`, cut to :data:`CONTENT_DIGEST_CHARS` hex
    digits. The approval hook keys a person's answer to it and the executor compares it again under the claim, so
    an approval covers the plan as it was shown: a file edited after the prompt, or another plan saved under the
    same id, has another digest (an identical one, the same). Two loads of one file always give the same digest."""
    content = {key: plan.get(key) for key in CONTENT_KEYS}
    text = json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    return hashlib.sha256(text.encode("ascii")).hexdigest()[:CONTENT_DIGEST_CHARS]


class RunLockBusy(RuntimeError):
    """Another process (or another thread of this one) holds the plan's run lock: an apply or rollback is
    running."""


def _hermes_home() -> Path:
    """The active profile's home: Hermes' resolver, else ``$HERMES_HOME`` or ``~/.hermes``."""
    try:
        from hermes_constants import get_hermes_home  # type: ignore

        return Path(get_hermes_home())
    except Exception:
        pass
    return Path(os.environ.get("HERMES_HOME") or os.path.join(os.path.expanduser("~"), ".hermes"))


def profile_key() -> str:
    """Which Hermes profile is active, as a key: Hermes' ``hermes_home_key`` when importable, else the home's path.
    Per-profile state in this process (the retention throttle, the audit sink workers) is kept under it."""
    try:
        from hermes_constants import hermes_home_key  # type: ignore

        return str(hermes_home_key())
    except Exception:
        return str(_hermes_home())


def data_dir() -> Path:
    """``<HERMES_HOME>/plugin-data/librenms``, resolved on every call so it follows the active Hermes profile:
    Hermes' own helper when importable (it creates the directory), else the home resolver. Kept ``0700``: Hermes
    creates it under the process umask, usually ``0755``, which lets other accounts list the plans and watch the
    audit log grow, so a directory this account owns is narrowed when found wider (it is the plugin's own; a log
    shipper should read a copy at ``audit_log_path`` instead)."""
    try:
        from plugins.plugin_storage import plugin_data_dir  # type: ignore

        path = Path(plugin_data_dir(PLUGIN_NAME))
    except Exception:
        path = _hermes_home() / "plugin-data" / PLUGIN_NAME
    _narrow(path)
    return path


def _narrow(path: Path) -> None:
    """``chmod 0700`` *path* when it is a directory (not a link to one) owned by this account and open to anyone
    else; nothing when it does not exist yet (:func:`private_dir` will create it ``0700``), cannot be changed, or
    the platform has no POSIX owners and modes (Windows)."""
    if not hasattr(os, "geteuid"):
        return
    try:
        info = os.lstat(path)
        if stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and info.st_mode & 0o077:
            os.chmod(path, 0o700)
    except OSError:
        pass


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


def valid_plan_id(plan_id: Any) -> bool:
    """Whether *plan_id* can name a plan file: :data:`PLAN_ID_RE` (letters, digits, ``_``, ``.`` and ``-``) without
    ``..``. So nothing outside the plans directory, and no ``:``, which separates the parts of the approval rule key
    (``librenms:<tool>:<id>:<variant>:<digest>``) and which Windows reads as a stream name. A file whose name is not
    one (made by hand) is listed but never loaded, resolved or run."""
    return isinstance(plan_id, str) and PLAN_ID_RE.fullmatch(plan_id) is not None and ".." not in plan_id


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
        """``<plans>/<plan_id>.json``; ``ValueError`` for an id that is not :func:`valid_plan_id`."""
        if not valid_plan_id(plan_id):
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
        """The newest *limit* plans, those whose :func:`plan_status` is *status* only when it is given. Each carries
        as ``id`` the name of its file, which :meth:`load` and :meth:`resolve` go by, whatever an edited file says or
        leaves out."""
        with self._lock:
            plans = [
                {**plan, "id": path.stem}
                for path, plan in self._documents()
                if not status or plan_status(plan) == status
            ]
        plans.sort(key=lambda p: str(p.get("created_at") or ""), reverse=True)  # an edited stamp never crashes
        return plans[: max(1, limit)]

    def resolve(self, fragment: str) -> Tuple[str | None, List[str]]:
        """Map what a human typed to a plan id. An exact id wins; otherwise the end of an id, at least
        :data:`MIN_FRAGMENT` characters in any case (``ab12`` or ``T190000Z-ab12``), resolves when exactly one plan
        ends with it. Shorter text and text from the middle of an id resolve nothing: every id holds ``2026``,
        ``T``, ``Z`` and ``-``, so ``2`` would pick whichever single plan is saved, and the apply or rollback it
        names runs at once. Only files named by a :func:`valid_plan_id` count. Returns ``(plan_id, candidates)``:
        ``plan_id`` is None when nothing or more than one plan matches, and ``candidates`` lists the matches so the
        caller can show them."""
        fragment = (fragment or "").strip()
        if not fragment:
            return None, []
        with self._lock:
            if valid_plan_id(fragment) and self._path(fragment).exists():
                return fragment, [fragment]
            if len(fragment) < MIN_FRAGMENT:
                return None, []
            ids = sorted(p.stem for p in self.directory.glob(f"{PREFIX}-*.json") if valid_plan_id(p.stem))
        needle = fragment.lower()
        candidates = [i for i in ids if i.lower().endswith(needle)]
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
