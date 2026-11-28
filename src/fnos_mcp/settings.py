"""Runtime-adjustable panel settings (/data/settings.json).

The panel's 「设置」 dialog writes here; changes take effect immediately
(no restart). Every knob falls back to its built-in default, and env
vars — where they exist (FNOS_RATE_LIMIT_*) — seed the *startup* value
but the panel store then overrides them at runtime.

Design rules:
- Stored file is a flat dict, validated field by field; an invalid or
  missing field falls back to the default (never fails startup).
- Values are conservative bounds, not free-form: limits that are wrong
  by a typo must not brick the panel (e.g. a 1-second panel-session TTL
  would log the admin out in a loop).
- The file is 0600, atomic write, single lock — same pattern as
  panel-state / panel-auth.
- Audit events record THAT settings changed (event `settings_updated`),
  never the old/new values (they are not secrets, but keep the audit
  line uniform).

What is here (and therefore panel-editable):
- rate limits: the same 9 kinds as auth.RATE_LIMITS, None = off
- probe.timeout_s / probe.concurrency / probe.wait_s (probe-all gather)
- panel.session_hours (cookie + signed payload TTL)
- audit.max_mb / audit.keep (rotation)
- cli timeouts: read_s / logs_s / action_s / build_s (seconds)

Not panel-editable (startup-only): everything else in docs/configuration.md
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path

from .auth import RATE_LIMITS, parse_rate_limit
from .fsutil import atomic_write

# ---- defaults (mirrors of the constants in the respective modules) ----
DEFAULTS: dict[str, object] = {
    "probe_timeout_s": 5.0,     # probe.py PROBE_DEADLINE
    "probe_concurrency": 4,     # routes.py probe-all Semaphore
    "probe_wait_s": 10,         # routes.py probe-all gather timeout
    "panel_session_hours": 12,  # auth.create_panel_session ttl_hours
    "audit_max_mb": 50,         # audit.py MAX_BYTES
    "audit_keep": 7,            # audit.py AUDIT_KEEP
    "cli_read_s": 60,           # cli_adapter read-only timeout
    "cli_logs_s": 120,          # compose logs / file chown
    "cli_action_s": 180,        # compose lifecycle / container create
    "cli_build_s": 600,         # compose build/clear/delete, uploads, request
}

# Field -> (type, minimum, maximum). Booleans are not tunable.
_BOUNDS: dict[str, tuple[type, int | float, int | float]] = {
    "probe_timeout_s": (float, 1.0, 30.0),
    "probe_concurrency": (int, 1, 16),
    "probe_wait_s": (int, 5, 120),
    "panel_session_hours": (int, 1, 168),
    "audit_max_mb": (int, 1, 1024),
    "audit_keep": (int, 2, 50),
    "cli_read_s": (int, 10, 900),
    "cli_logs_s": (int, 10, 900),
    "cli_action_s": (int, 10, 900),
    "cli_build_s": (int, 30, 1800),
}

_RATE_KINDS = tuple(RATE_LIMITS)
_RATE_LIMIT_BOUNDS = (1, 10_000)     # per window
_RATE_WINDOW_BOUNDS = (1, 3600)      # seconds


def _clean_number(raw: object, kind: type, lo: int | float,
                  hi: int | float) -> int | float | None:
    """Accept int or float inside bounds; reject bools and anything else."""
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        return None
    if kind is int:
        value = int(raw)
    else:
        value = float(raw)
    if value < lo or value > hi:
        return None
    return value


class SettingsStore:
    """Panel-editable runtime settings, persisted to a 0600 JSON file."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._rate_limits: dict[str, tuple[int, int] | None] = dict(RATE_LIMITS)
        self._values: dict[str, int | float] = {
            k: v for k, v in DEFAULTS.items()}
        self._load()

    # -- loading ---------------------------------------------------------
    def _load(self) -> None:
        """Read the file; any invalid field falls back to its default.

        Startup never fails on a bad settings file: worst case the panel
        shows defaults again, which is always a safe configuration.
        """
        try:
            raw = self.path.read_text(encoding="utf-8-sig")
            data = json.loads(raw)
        except (FileNotFoundError, OSError, UnicodeError, ValueError):
            return
        if not isinstance(data, dict):
            return
        for field, (kind, lo, hi) in _BOUNDS.items():
            if field in data:
                value = _clean_number(data[field], kind, lo, hi)
                if value is not None:
                    self._values[field] = value
        rates = data.get("rate_limits")
        if isinstance(rates, dict):
            for kind in _RATE_KINDS:
                if kind not in rates:
                    continue
                value = _clean_rate(rates[kind])
                if value != "invalid":
                    self._rate_limits[kind] = value

    # -- reads -------------------------------------------------------------
    def get(self, field: str) -> int | float:
        return self._values.get(field, DEFAULTS.get(field))  # type: ignore[arg-type]

    @property
    def rate_limits(self) -> dict[str, tuple[int, int] | None]:
        return dict(self._rate_limits)

    def snapshot(self) -> dict:
        """Everything the settings form needs, in display shape."""
        return {
            "values": dict(self._values),
            "rate_limits": {k: (None if v is None else list(v))
                            for k, v in self._rate_limits.items()},
            "defaults": dict(DEFAULTS),
            "default_rate_limits": {k: (None if v is None else list(v))
                                    for k, v in RATE_LIMITS.items()},
        }

    # -- writes ------------------------------------------------------------
    def update(self, fields: dict[str, object],
               rate_limits: dict[str, tuple[int, int] | None] | None = None
               ) -> dict[str, str]:
        """Validate + persist + apply. Returns field errors (empty = ok).

        Validation is all-or-nothing: nothing is written or applied when
        any field is bad, so the panel never shows a half-saved form.
        """
        errors: dict[str, str] = {}
        clean_values: dict[str, int | float] = {}
        for field, raw in (fields or {}).items():
            if field not in _BOUNDS:
                continue
            kind, lo, hi = _BOUNDS[field]
            value = _clean_number(raw, kind, lo, hi)
            if value is None:
                errors[field] = f"取值需在 {lo}–{hi} 之间。"
            else:
                clean_values[field] = value
        clean_rates: dict[str, tuple[int, int] | None] | None = None
        if rate_limits is not None:
            clean_rates = {}
            for kind, value in rate_limits.items():
                if kind not in _RATE_KINDS:
                    continue
                if value is None:
                    clean_rates[kind] = None
                    continue
                (limit, window) = value
                ok = (isinstance(limit, int) and not isinstance(limit, bool)
                      and isinstance(window, int) and not isinstance(window, bool)
                      and _RATE_LIMIT_BOUNDS[0] <= limit <= _RATE_LIMIT_BOUNDS[1]
                      and _RATE_WINDOW_BOUNDS[0] <= window <= _RATE_WINDOW_BOUNDS[1])
                if not ok:
                    errors[f"rate_{kind}"] = (
                        f"次数需在 {_RATE_LIMIT_BOUNDS[0]}–{_RATE_LIMIT_BOUNDS[1]}、"
                        f"窗口需在 {_RATE_WINDOW_BOUNDS[0]}–{_RATE_WINDOW_BOUNDS[1]} 秒之间。")
                else:
                    clean_rates[kind] = (limit, window)
        if errors:
            return errors
        with self._lock:
            if clean_values:
                self._values.update(clean_values)
            if clean_rates is not None:
                self._rate_limits.update(clean_rates)
            try:
                self._persist()
            except OSError:
                # Apply in memory anyway; the file write failed (disk full,
                # read-only volume). Restarting falls back to previous file.
                return {}
        return {}

    def _persist(self) -> None:
        data: dict[str, object] = dict(self._values)
        data["rate_limits"] = {k: (None if v is None else [v[0], v[1]])
                               for k, v in self._rate_limits.items()}
        atomic_write(self.path, json.dumps(data, ensure_ascii=False, indent=2) + "\n")
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass


def _clean_rate(raw: object):
    """File read-back: (limit, window) pair, None, or "invalid" sentinel."""
    if raw is None:
        return None
    if isinstance(raw, list) and len(raw) == 2:
        limit = _clean_number(raw[0], int, *_RATE_LIMIT_BOUNDS)
        window = _clean_number(raw[1], int, *_RATE_WINDOW_BOUNDS)
        if limit is not None and window is not None:
            return (int(limit), int(window))
    return "invalid"


def parse_rate_limit_form(raw: object):
    """Parse one rate-limit form field into a tri-state action.

    Returns (action, value, error):
      ("keep", None, None)  field absent, or empty ("empty = keep current")
      ("off", None, None)   user typed "off" (or "0/60")
      ("set", (n, w), None) user typed "120/60"
      ("error", None, msg)  unparseable input

    The three-way split is load-bearing: "absent" and "empty" must never
    be confused with "off", or a partial submit would silently switch
    every limit it did not mention to unlimited (F2).
    """
    if raw is None:
        return "keep", None, None
    text = str(raw).strip()
    if not text:
        return "keep", None, None  # empty = keep current
    try:
        value = parse_rate_limit(text)
    except ValueError as exc:
        return "error", None, str(exc)
    if value is None:
        return "off", None, None
    return "set", value, None
