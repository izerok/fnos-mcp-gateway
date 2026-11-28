"""Panel state store: /data/panel-state.json (需求文档 FR-30/FR-31, §9).

- schema_version 1; per profile: target fingerprint + network layer +
  auth layer, stored separately and never overwriting each other
  (probe writes network only, test writes auth only).
- Atomic write: temp file in the same directory + fsync + os.replace.
  File mode 0600. Process-wide lock for writers.
- Corrupt file: renamed to .corrupt-<timestamp>, empty state continues,
  page shows "历史检查结果不可用".
- Target fingerprint (scheme/host/port): on read, entries whose target
  no longer matches the current config are dropped (FR-31).
- Merge order (§9.3): config error > network failure > auth ok (fresh
  24h) > logged out > expired > permission > no/stale auth > untested.
  Auth older than 24h is treated as "no auth result".
"""

from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

AUTH_FRESH_SECONDS = 24 * 3600

# badge key -> (label, bucket, css class)
BADGES = {
    "connected": ("已连接", "connected", "ok"),
    "unverified": ("地址可达 · 未验证登录", "pending", "warn"),
    "loggedout": ("地址可达 · 未登录", "pending", "warn"),
    "expired": ("登录失效", "error", "bad"),
    "permission": ("权限不足", "error", "bad"),
    "unreachable": ("网络不可达", "error", "bad"),
    "tls": ("TLS / 协议错误", "error", "bad"),
    "config": ("配置错误", "error", "bad"),
    "untested": ("未测试", "pending", "idle"),
}

SUB_LABELS = {
    "connected": "身份 {identity}",
    "unverified": "未做认证测试",
    "loggedout": "还没有登录",
    "expired": "需要重新登录",
    "permission": "账号权限不足",
    "unreachable": "检查网络与端口",
    "tls": "证书校验失败",
    "config": "profile 被跳过",
    "untested": "还没有检查",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_time(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value).timestamp()
    except ValueError:
        return None


def merge_status(network: dict | None, auth: dict | None,
                 config_error: bool = False, now: float | None = None) -> str:
    """Fixed merge order (§9.3). Returns a badge key."""
    if config_error:
        return "config"
    if not network:
        return "untested"
    net_status = network.get("status")
    if net_status in ("dns_failed", "refused", "timeout"):
        return "unreachable"
    if net_status in ("tls_failed", "http_failed"):
        return "tls"
    if net_status != "ok":
        return "untested"
    now = now if now is not None else time.time()
    if auth:
        auth_at = _parse_time(auth.get("at"))
        fresh = auth_at is not None and (now - auth_at) < AUTH_FRESH_SECONDS
        if fresh:
            status = auth.get("status")
            if status == "ok":
                return "connected"
            if status == "logged_out":
                return "loggedout"
            if status == "expired":
                return "expired"
            if status == "permission":
                return "permission"
    return "unverified"


class PanelStateStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self.corrupt = False

    def load(self) -> dict:
        if not self.path.exists():
            return {"schema_version": 1, "profiles": {}}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(data, dict) or data.get("schema_version") != 1:
                raise ValueError("bad schema")
            if not isinstance(data.get("profiles"), dict):
                raise ValueError("bad profiles")
            self.corrupt = False
            return data
        except (ValueError, OSError, UnicodeDecodeError):
            stamp = time.strftime("%Y%m%dT%H%M%S")
            try:
                self.path.rename(self.path.with_name(f"{self.path.name}.corrupt-{stamp}"))
            except OSError:
                pass
            self.corrupt = True
            return {"schema_version": 1, "profiles": {}}

    def _save(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(f".{self.path.name}.tmp-{os.getpid()}")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.path)
        os.chmod(self.path, 0o600)

    def update(self, name: str, target: str, network: dict | None = None,
               auth: dict | None = None) -> dict:
        """Merge one layer; the other layer is preserved (FR-17)."""
        with self._lock:
            data = self.load()
            entry = data["profiles"].setdefault(name, {"target": target})
            entry["target"] = target
            if network is not None:
                entry["network"] = network
            if auth is not None:
                entry["auth"] = auth
            self._save(data)
            return entry

    def remove(self, name: str) -> None:
        """Drop one profile's stored layers (used by profile delete)."""
        with self._lock:
            data = self.load()
            if name in data["profiles"]:
                del data["profiles"][name]
                self._save(data)

    def drop_stale(self, current_targets: dict[str, str]) -> list[str]:
        """Drop entries whose target fingerprint changed (FR-31)."""
        with self._lock:
            data = self.load()
            dropped = [n for n, e in data["profiles"].items()
                       if current_targets.get(n) != e.get("target")]
            for name in dropped:
                data["profiles"].pop(name, None)
            if dropped:
                self._save(data)
            return dropped

    def summarize(self, names: list[str], config_errors: set[str],
                  targets: dict[str, str] | None = None) -> dict:
        """Summary badges; when `targets` is given, a stored entry whose
        target fingerprint no longer matches the current config is ignored
        (FR-31), even if the caller has not run drop_stale yet."""
        data = self.load()
        counts = {"total": len(names), "connected": 0, "pending": 0, "error": 0, "untested": 0}
        badges: dict[str, str] = {}
        for name in names:
            entry = data["profiles"].get(name)
            if entry and targets is not None and entry.get("target") != targets.get(name):
                entry = None
            badge = merge_status(
                entry.get("network") if entry else None,
                entry.get("auth") if entry else None,
                config_error=name in config_errors,
            )
            badges[name] = badge
            if badge == "untested":
                counts["untested"] += 1
            counts[BADGES[badge][1]] += 1
        return {"counts": counts, "badges": badges}
