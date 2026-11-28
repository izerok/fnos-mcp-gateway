"""Two per-profile locks (需求文档 §9.5).

- Network probe lock: only for /probe and probe-all, 5s deadline.
- Session lock: for /test, login start/finish, /logout, 5 min TTL,
  shared with the MCP entry points.

Implemented as flock() on per-profile files under <data>/locks/ so the
lock survives (and is released on) process death. A lock file whose
recorded acquisition time is older than the TTL is treated as stale and
replaced. Two different operation kinds never block each other; the
same kind on the same profile returns 409.
"""

from __future__ import annotations

import fcntl
import json
import os
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from .errors import LockedError

PROBE_LOCK_TTL = 5
SESSION_LOCK_TTL = 300


class _FileLock:
    def __init__(self, path: Path, ttl: int, kind: str):
        self.path = path
        self.ttl = ttl
        self.kind = kind
        self._fd = None

    def acquire(self) -> bool:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Stale-lock recovery: a record older than TTL is replaced.
        try:
            record = json.loads(self.path.read_text(encoding="utf-8"))
            if time.time() - float(record.get("acquired_at", 0)) > self.ttl:
                self.path.unlink(missing_ok=True)
        except (ValueError, OSError, KeyError, TypeError):
            pass
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            return False
        os.ftruncate(fd, 0)
        os.write(fd, json.dumps(
            {"owner": os.getpid(), "acquired_at": time.time(), "kind": self.kind}
        ).encode("utf-8"))
        os.fsync(fd)
        self._fd = fd
        return True

    def release(self) -> None:
        if self._fd is not None:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None


@contextmanager
def probe_lock(data_dir: str | Path, profile_name: str):
    lock = _FileLock(Path(data_dir) / "locks" / f"probe-{profile_name}.lock",
                     PROBE_LOCK_TTL, "probe")
    if not lock.acquire():
        raise LockedError("probe")
    try:
        yield
    finally:
        lock.release()


@contextmanager
def session_lock(data_dir: str | Path, profile_name: str):
    lock = _FileLock(Path(data_dir) / "locks" / f"session-{profile_name}.lock",
                     SESSION_LOCK_TTL, "session")
    if not lock.acquire():
        raise LockedError("session")
    try:
        yield
    finally:
        lock.release()


# Serializes lease read/remove/create within this process (the supported
# deployment is one worker/replica). Without this, an expired lease being
# removed by two concurrent login_start calls could delete the winner.
_LEASE_MUTEX = threading.Lock()


def acquire_login_lease(data_dir: str | Path, profile_name: str) -> bool:
    """A 5-minute lease created by login_start; a second login_start
    while the lease is fresh must return 409 and never overwrite the
    CLI's pending verifier. Released by login_finish / logout / expiry."""
    path = Path(data_dir) / "locks" / f"pending-{profile_name}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    now = time.time()
    with _LEASE_MUTEX:
        record = None
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, OSError, KeyError, TypeError):
            record = None
        if isinstance(record, dict):
            try:
                expires_at = float(record.get("expires_at", 0))
            except (TypeError, ValueError):
                expires_at = 0
            if now < expires_at:
                return False
        # The lease is expired, missing, or corrupt. Remove it before
        # O_EXCL, otherwise an expired file would block every retry.
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            # If it cannot be removed, O_EXCL below will fail safely.
            pass
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return False
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump({"owner": os.getpid(), "acquired_at": now,
                       "expires_at": now + SESSION_LOCK_TTL}, fh)
        return True


def release_login_lease(data_dir: str | Path, profile_name: str) -> None:
    with _LEASE_MUTEX:
        try:
            Path(data_dir).joinpath("locks", f"pending-{profile_name}.json").unlink(missing_ok=True)
        except OSError:
            pass
