"""Audit log: append-only JSONL (需求文档 FR-32).

Fields are whitelisted: time, event, token_id, profile, result,
client_ip, plus optional latency_ms / http_status / sub_reason /
retry_after / key_id. Never token / sha256 / code / authorization URL /
headers / response bodies / passwords. File 0600.

Retention (P1, FR-32 enhancement): over MAX_BYTES the current file is
renamed to a numbered archive audit.jsonl.N (N = 1 newest) and archives
above AUDIT_KEEP - 1 are DELETED, so the audit directory is bounded at
AUDIT_KEEP files regardless of how often rotation fires. Rotation never
blocks or fails the caller: every OSError is swallowed and the line is
still appended.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

MAX_BYTES = 50 * 1024 * 1024
AUDIT_KEEP = 7  # current file + up to six numbered archives, bounded
_ALLOWED_EXTRA = ("latency_ms", "http_status", "sub_reason", "retry_after", "key_id")


class AuditLog:
    def __init__(self, path: str | Path, keep: int = AUDIT_KEEP):
        self.path = Path(path)
        # keep counts the current file, so the archive cap is keep-1;
        # keep>=2 keeps that invariant true for the final rename to .1.
        self._keep = max(2, int(keep))
        self._lock = threading.Lock()

    def _rotate(self) -> None:
        """audit.jsonl -> audit.jsonl.1 -> audit.jsonl.2 ... keeping at
        most keep-1 numeric archives so the audit directory is bounded.
        Archives that would overflow the cap (or leftovers from an older
        overflow) are deleted instead of renamed. Raises nothing."""
        parent = self.path.parent
        try:
            nums = []
            for p in parent.glob(self.path.name + ".*"):
                suffix = p.name.rsplit(".", 1)[1]
                if suffix.isdigit():
                    nums.append(int(suffix))
        except (OSError, ValueError):
            nums = []
        # Highest first: .3 -> .4 before .2 -> .3, so nothing is clobbered.
        for n in sorted(nums, reverse=True):
            src = self.path.with_name(f"{self.path.name}.{n}")
            dst_n = n + 1
            try:
                if dst_n > self._keep - 1:
                    src.unlink()
                else:
                    src.rename(self.path.with_name(f"{self.path.name}.{dst_n}"))
            except OSError:
                pass
        try:
            if self.path.exists():
                self.path.rename(self.path.with_name(f"{self.path.name}.1"))
        except OSError:
            pass

    def record(self, event: str, token_id: str | None = None,
               profile: str | None = None, result: str = "ok",
               client_ip: str | None = None, **extra) -> None:
        entry = {
            "time": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "token_id": token_id,
            "profile": profile,
            "result": result,
            "client_ip": client_ip,
        }
        for key in _ALLOWED_EXTRA:
            if key in extra:
                entry[key] = extra[key]
        line = json.dumps(entry, ensure_ascii=False) + "\n"
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            try:
                if self.path.exists() and self.path.stat().st_size > MAX_BYTES:
                    self._rotate()
            except OSError:
                pass
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()
                os.fsync(fh.fileno())
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
