"""First-run panel password (no default credential).

The panel starts with **no** credential: the first visitor sets the
administrator password. Only a salted scrypt hash is stored (0600,
atomic write); the signed session cookie is bound to the hash's
fingerprint, so changing the password invalidates every old session
immediately. The plaintext password is never written to disk, logged
or echoed.

File format (version 1)::

    {"version": 1, "alg": "scrypt", "n": 16384, "r": 8, "p": 1,
     "salt": "<hex>", "hash": "<hex>", "updated_at": "<iso>"}
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
from datetime import datetime, timezone
from pathlib import Path

from .fsutil import atomic_write

SCRYPT_N = 16384
SCRYPT_R = 8
SCRYPT_P = 1
SALT_BYTES = 16
KEY_BYTES = 32
MIN_LEN = 8
MAX_LEN = 128

# Bounds for values read back from the file: a tampered file must not
# turn verification into a memory/time bomb.
_MAX_N = 1 << 20
_MAX_R = 16
_MAX_P = 4


class PanelAuthError(Exception):
    """Password setup/change failed with a code the panel can render."""

    def __init__(self, code: str, message: str, fields: dict[str, str] | None = None):
        self.code = code
        self.message = message
        self.fields = fields or {}
        super().__init__(f"{code}: {message}")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def validate_password(password: object, confirm: object | None = None) -> dict[str, str]:
    """Return field errors for a new password (empty dict = valid)."""
    errors: dict[str, str] = {}
    if not isinstance(password, str) or not password:
        errors["password"] = "请设置管理员密码。"
        return errors
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in password):
        errors["password"] = "密码不能包含控制字符。"
    elif len(password) < MIN_LEN:
        errors["password"] = f"密码至少 {MIN_LEN} 个字符。"
    elif len(password) > MAX_LEN:
        errors["password"] = f"密码最多 {MAX_LEN} 个字符。"
    if confirm is not None and password != confirm:
        errors["confirm"] = "两次输入的密码不一致。"
    return errors


class PanelAuthStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.Lock()

    def configured(self) -> bool:
        return self.path.is_file()

    def _read(self) -> dict | None:
        try:
            raw = self.path.read_text(encoding="utf-8-sig")
        except FileNotFoundError:
            return None
        except (OSError, UnicodeError):
            return None
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return None
        if not isinstance(data, dict) or data.get("alg") != "scrypt":
            return None
        return data

    def fingerprint(self) -> str | None:
        """Stable id of the current credential; sessions bind to it.

        Derived from the stored hash only, so it changes exactly when
        the password changes (a fresh salt also changes the hash).
        """
        data = self._read()
        if not data:
            return None
        stored = data.get("hash")
        if not isinstance(stored, str) or not stored:
            return None
        return hashlib.sha256(stored.encode("ascii", "ignore")).hexdigest()

    def verify(self, password: object) -> bool:
        if not isinstance(password, str) or not password:
            return False
        data = self._read()
        if not data:
            return False
        try:
            n = int(data["n"])
            r = int(data["r"])
            p = int(data["p"])
            salt = bytes.fromhex(str(data["salt"]))
            expected = bytes.fromhex(str(data["hash"]))
        except (KeyError, TypeError, ValueError):
            return False
        if not (2 <= n <= _MAX_N and 1 <= r <= _MAX_R and 1 <= p <= _MAX_P):
            return False
        if not salt or len(expected) < 16:
            return False
        try:
            digest = hashlib.scrypt(password.encode("utf-8"), salt=salt,
                                    n=n, r=r, p=p, dklen=len(expected),
                                    maxmem=64 * 1024 * 1024)
        except (ValueError, MemoryError):
            return False
        return hmac.compare_digest(digest, expected)

    def set_password(self, password: str, *, replace: bool = True) -> str:
        """Hash and store a validated password; returns the fingerprint.

        ``replace=False`` is the first-run path: if a password appeared
        in the meantime (concurrent first visits), it must not be
        overwritten — the caller maps the error onto a "setup done"
        answer.
        """
        errors = validate_password(password)
        if errors:
            raise PanelAuthError("password.invalid", errors["password"], errors)
        salt = secrets.token_bytes(SALT_BYTES)
        digest = hashlib.scrypt(password.encode("utf-8"), salt=salt,
                                n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
                                dklen=KEY_BYTES, maxmem=64 * 1024 * 1024)
        data = {
            "version": 1,
            "alg": "scrypt",
            "n": SCRYPT_N,
            "r": SCRYPT_R,
            "p": SCRYPT_P,
            "salt": salt.hex(),
            "hash": digest.hex(),
            "updated_at": _now_iso(),
        }
        with self._lock:
            if not replace and self.path.exists():
                raise PanelAuthError("setup.done", "管理员密码已设置，请直接登录。")
            try:
                atomic_write(self.path,
                             json.dumps(data, ensure_ascii=False, indent=2) + "\n")
            except OSError as exc:
                raise PanelAuthError("internal", f"密码保存失败：{exc}")
        return self.fingerprint() or ""
