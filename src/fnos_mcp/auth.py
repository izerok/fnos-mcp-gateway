"""Authentication: MCP Bearer tokens + panel signed cookies + CSRF + limits.

- Bearer: SHA-256 of the presented token, constant-time comparison against
  the token store (which stores hashes only). Never log or echo the token.
- Panel cookie: HMAC-SHA256 signed, payload is only the subject, expiry
  and the current password-hash fingerprint, so changing the panel
  password invalidates old cookies immediately (FR-03).
- CSRF: double-submit cookie (``fnos_csrf``) + ``X-CSRF-Token`` header.
- Rate limits: frozen M0 values from FR-35 (see DECISIONS.md).
  Panel login is keyed by real client IP; probe/test/login keyed by
  token id + profile. Only trust X-Forwarded-For when the direct peer is
  inside TRUSTED_PROXY_CIDRS (default: trust nobody).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import secrets
import time
from collections import deque
from dataclasses import dataclass

from .config import TokenRecord

# M0-frozen panel rate limits (FR-35 suggested values, frozen per
# DECISIONS.md). (limit, window_seconds); None = unlimited.
#
# Every entry can be overridden at startup with an env var
# FNOS_RATE_LIMIT_<KIND> (kind upper-cased, e.g. FNOS_RATE_LIMIT_PANEL_LOGIN)
# taking "N/WINDOW" ("120/60") or "off"/"0"/"none" for unlimited. Anything
# else fails startup. The MCP endpoint is unlimited by default: operators
# decide whether to throttle agents, and a local gateway usually should
# not.
RATE_LIMITS: dict[str, tuple[int, int] | None] = {
    "panel_login": (10, 300),    # per client IP
    "probe": (30, 60),           # per token id + profile
    "test": (10, 60),            # per token id + profile
    "login_start": (5, 60),      # per token id + profile
    "login_finish": (10, 300),   # per token id + profile
    "profile_write": (20, 60),   # per token id (create + edit)
    "token_write": (10, 60),     # per panel session (agent key CRUD)
    "token_secret": (30, 60),    # per panel session (reveal for copy)
    "mcp_call": None,            # per token id: all /mcp requests (off)
    "mcp_write": (20, 60),       # per token id: write-gated tool calls
}

_RATE_LIMIT_ENV_PREFIX = "FNOS_RATE_LIMIT_"
_OFF_VALUES = {"off", "none", "unlimited", "false", "no", "0"}


def parse_rate_limit(value: str) -> tuple[int, int] | None:
    """Parse "N/WINDOW" (calls per window seconds) or an off switch.

    Raises ValueError for anything malformed so a typo fails startup
    loudly instead of silently disabling a guard.
    """
    text = value.strip().lower()
    if text in _OFF_VALUES:
        return None
    if text in ("", "default"):
        raise ValueError("rate limit value is empty")
    parts = text.split("/")
    if len(parts) != 2:
        raise ValueError(f"rate limit must be N/WINDOW or off, got {value!r}")
    try:
        limit, window = int(parts[0]), int(parts[1])
    except ValueError:
        raise ValueError(f"rate limit must be N/WINDOW or off, got {value!r}")
    if limit < 0 or window <= 0:
        raise ValueError(f"rate limit must be N>=0 and WINDOW>0, got {value!r}")
    return None if limit == 0 else (limit, window)


def load_rate_limits(env=None) -> dict[str, tuple[int, int] | None]:
    """Built-in limits overlaid with FNOS_RATE_LIMIT_<KIND> env overrides."""
    import os
    env = os.environ if env is None else env
    limits = dict(RATE_LIMITS)
    known = {kind.upper(): kind for kind in RATE_LIMITS}
    for key, value in env.items():
        if not key.startswith(_RATE_LIMIT_ENV_PREFIX):
            continue
        kind = known.get(key[len(_RATE_LIMIT_ENV_PREFIX):])
        if kind is None:
            continue  # unknown kind: ignore, don't fail other knobs
        limits[kind] = parse_rate_limit(value)
    return limits


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def verify_bearer(token: str, tokens: list[TokenRecord]) -> TokenRecord | None:
    digest = hash_token(token)
    for rec in tokens:
        if hmac.compare_digest(digest, rec.sha256):
            return rec
    return None


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def create_panel_session(secret: bytes, fingerprint: str, ttl_hours: int = 12) -> str:
    """Signed panel session cookie: subject, expiry and the current
    password-hash fingerprint (a password change invalidates it)."""
    payload = {
        "sub": "admin",
        "exp": int(time.time()) + ttl_hours * 3600,
        "fp": fingerprint,
    }
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sig = hmac.new(secret, raw, hashlib.sha256).digest()
    return f"{_b64(raw)}.{_b64(sig)}"


def verify_panel_session(value: str, secret: bytes, fingerprint: str) -> bool:
    try:
        raw_b64, sig_b64 = value.split(".", 1)
        raw = _unb64(raw_b64)
        sig = _unb64(sig_b64)
    except (ValueError, binascii.Error):
        return False
    if not hmac.compare_digest(sig, hmac.new(secret, raw, hashlib.sha256).digest()):
        return False
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return False
    if payload.get("sub") != "admin":
        return False
    if int(payload.get("exp", 0)) < int(time.time()):
        return False
    return hmac.compare_digest(str(payload.get("fp", "")), fingerprint)


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def csrf_valid(header_value: str | None, cookie_value: str | None) -> bool:
    if not header_value or not cookie_value:
        return False
    return hmac.compare_digest(header_value, cookie_value)


@dataclass
class RateLimiter:
    """In-memory sliding-window limiter (single worker, single process).

    ``limits`` maps kind -> (limit, window) or None for unlimited; default
    is the built-in RATE_LIMITS table (MCP off)."""

    _hits: dict[str, deque] = None  # type: ignore[assignment]
    limits: dict[str, tuple[int, int] | None] = None  # type: ignore[assignment]

    def __post_init__(self):
        self._hits = {}
        self.limits = dict(RATE_LIMITS if self.limits is None else self.limits)

    def check(self, kind: str, key: str) -> tuple[bool, int]:
        """Return (allowed, retry_after_seconds)."""
        limit, window = self.limits.get(kind) or (None, None)
        if limit is None:
            return True, 0
        now = time.monotonic()
        bucket = self._hits.setdefault(f"{kind}:{key}", deque())
        while bucket and bucket[0] <= now - window:
            bucket.popleft()
        if len(bucket) >= limit:
            return False, max(1, int(bucket[0] + window - now))
        bucket.append(now)
        return True, 0


def real_client_ip(client_host: str | None, x_forwarded_for: str | None,
                   trusted_proxy_cidrs: list[str]) -> str:
    """Only trust X-Forwarded-For when the direct peer is a trusted proxy.

    Default: trust nobody (empty list) — a forged XFF must never change
    the rate-limit key (FR-35).
    """
    if not x_forwarded_for or not client_host:
        return client_host or "unknown"
    try:
        peer = ipaddress.ip_address(client_host)
    except ValueError:
        return client_host
    for cidr in trusted_proxy_cidrs:
        try:
            if peer in ipaddress.ip_network(cidr, strict=False):
                first = x_forwarded_for.split(",")[0].strip()
                return first or client_host
        except ValueError:
            continue
    return client_host


def validate_authorization_url(url: str, profile) -> str | None:
    """FR-21: treat the CLI-returned authorization URL as untrusted data.

    Returns None when the URL is safe to show, else a Chinese reason.
    Rules: https only (http only when profile.allow_insecure_http), no
    userinfo, no control characters, no javascript:/data: schemes, origin
    must equal the profile target origin or be an exact entry of
    profile.authorization_hosts (no wildcards, no suffix matching).
    """
    from urllib.parse import urlparse

    if not isinstance(url, str) or not url:
        return "授权链接为空。"
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in url):
        return "授权链接含有控制字符。"
    try:
        parsed = urlparse(url)
    except ValueError:
        return "授权链接格式不正确。"
    if parsed.scheme not in ("https", "http"):
        return "授权链接必须是 https 链接。"
    if parsed.scheme == "http" and not profile.allow_insecure_http:
        return "授权链接必须是 https 链接。"
    if parsed.username or parsed.password:
        return "授权链接不得包含用户信息。"
    if not parsed.hostname:
        return "授权链接缺少主机名。"
    try:
        port = parsed.port
    except ValueError:
        return "授权链接的端口不正确。"
    origin = _origin_of(parsed.scheme, parsed.hostname, port)
    target_origin = _origin_of(profile.scheme, profile.host, profile.port)
    # Normalise default ports for comparison.
    if origin == target_origin:
        return None
    for allowed in profile.authorization_hosts:
        try:
            ap = urlparse(allowed)
            if _origin_of(ap.scheme, ap.hostname or "", ap.port) == origin:
                return None
        except ValueError:
            continue
    return f"授权链接的来源与这台机器不一致：{origin}。"


def _origin_of(scheme: str, host: str, port: int | None) -> str:
    origin = f"{scheme}://{host}"
    if port:
        origin += f":{port}"
    elif scheme == "https":
        origin += ":443"
    elif scheme == "http":
        origin += ":80"
    return origin
