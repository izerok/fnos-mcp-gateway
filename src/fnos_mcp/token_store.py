"""Writable agent-token store for the ACL panel.

The panel manages MCP access keys ("agent keys") here: each entry maps a
key name to a SHA-256 hash plus its ACL (profile names or ``"*"``), role
and delegated capabilities. MCP verification always uses the hash.

The plaintext is encrypted at rest (AES-GCM, key derived from the panel
session secret) so an authenticated admin can copy an existing key from
the list instead of rotating it. Entries seeded from an older
``tokens.json`` have no ciphertext and are reported as not copyable until
they are rotated. Losing/changing the panel session secret makes stored
ciphertext unreadable; the keys still authenticate MCP until rotated.

``FNOS_TOKENS_STORE`` (normally ``/data/tokens.json``) is a writable
copy seeded once from the read-only ``tokens.json`` secret. Without the
env var the store is the tokens file itself (tests / single-file
deployments). Writes are atomic (0600) and serialized by one lock.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import secrets
import threading
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .config import PROFILE_NAME_RE, load_tokens, validate_tokens_data
from .errors import ConfigError
from .fsutil import atomic_write

MAX_TOKENS = 50
MAX_PROFILES = 32
MAX_NAME_LEN = 64
CAPABILITIES = ("manage_login", "manage_profiles")
ROLES = ("operator", "admin")

_KDF_SALT = b"fnos-mcp/token-store/v1"
_KDF_INFO = b"agent-key"
_NONCE_BYTES = 12


class TokenStoreError(Exception):
    """A token write failed with a code the panel can render."""

    def __init__(self, code: str, message: str,
                 fields: dict[str, str] | None = None):
        self.code = code
        self.message = message
        self.fields = fields or {}
        super().__init__(f"{code}: {message}")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class SecretBox:
    """Encrypt/decrypt token plaintext with a key derived from the panel
    session secret. The key id is authenticated as AAD so a ciphertext
    cannot be moved onto another entry."""

    def __init__(self, secret: bytes):
        if not secret:
            raise ValueError("token store secret is empty")
        self._aead = AESGCM(HKDF(
            algorithm=hashes.SHA256(), length=32,
            salt=_KDF_SALT, info=_KDF_INFO).derive(secret))

    def seal(self, key_id: str, plaintext: str) -> str:
        nonce = os.urandom(_NONCE_BYTES)
        ciphertext = self._aead.encrypt(nonce, plaintext.encode("utf-8"),
                                        key_id.encode("utf-8"))
        return base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")

    def open(self, key_id: str, blob: object) -> str | None:
        if not isinstance(blob, str) or not blob:
            return None
        try:
            raw = base64.urlsafe_b64decode(blob.encode("ascii"))
            if len(raw) <= _NONCE_BYTES:
                return None
            return self._aead.decrypt(raw[:_NONCE_BYTES], raw[_NONCE_BYTES:],
                                      key_id.encode("utf-8")).decode("utf-8")
        except (InvalidTag, ValueError, UnicodeError, binascii.Error):
            return None


def _clean_name(raw: object) -> str:
    name = raw.strip() if isinstance(raw, str) else ""
    if not name:
        raise TokenStoreError("token.invalid", "请填写密钥名称。",
                              {"name": "请填写密钥名称。"})
    if len(name) > MAX_NAME_LEN:
        raise TokenStoreError("token.invalid", "密钥名称过长。",
                              {"name": f"名称最多 {MAX_NAME_LEN} 个字符。"})
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in name):
        raise TokenStoreError("token.invalid", "密钥名称包含控制字符。",
                              {"name": "名称不能包含控制字符。"})
    return name


def _clean_profiles(raw: object) -> list[str]:
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, (list, tuple)):
        raise TokenStoreError("token.invalid", "ACL 格式不正确。",
                              {"profiles": "ACL 必须是机器名列表。"})
    values = [p.strip() for p in raw if isinstance(p, str) and p.strip()]
    if "*" in values:
        return ["*"]
    seen: list[str] = []
    for value in values:
        if not PROFILE_NAME_RE.match(value):
            raise TokenStoreError("token.invalid", "ACL 含非法机器名。",
                                  {"profiles": f"机器名不合法：{value}"})
        if value not in seen:
            seen.append(value)
    if len(seen) > MAX_PROFILES:
        raise TokenStoreError("token.invalid", "ACL 过长。",
                              {"profiles": f"最多授权 {MAX_PROFILES} 台机器。"})
    return seen


def _clean_role(raw: object) -> str:
    role = raw.strip() if isinstance(raw, str) else ""
    if role not in ROLES:
        raise TokenStoreError("token.invalid", "角色不正确。",
                              {"role": "角色只能是 operator 或 admin。"})
    return role


def _clean_capabilities(raw: object) -> list[str]:
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, (list, tuple)):
        raise TokenStoreError("token.invalid", "能力格式不正确。",
                              {"capabilities": "能力必须是列表。"})
    caps: list[str] = []
    for value in raw:
        if not isinstance(value, str):
            continue
        if value not in CAPABILITIES:
            raise TokenStoreError("token.invalid", "含未知能力。",
                                  {"capabilities": f"未知能力：{value}"})
        if value not in caps:
            caps.append(value)
    return caps


def _sanitize(entry: dict, *, copyable: bool | None = None) -> dict:
    """Panel/API view of an entry: prefix only, never the full hash or
    ciphertext. ``copyable`` says whether the plaintext can be decrypted
    with the current session secret."""
    sha = entry.get("sha256") or ""
    profiles = list(entry.get("profiles") or [])
    if copyable is None:
        copyable = isinstance(entry.get("key_enc"), str) and bool(entry.get("key_enc"))
    return {
        "id": str(entry.get("id", "")),
        "name": str(entry.get("name", "")),
        "role": str(entry.get("role", "operator")),
        "capabilities": list(entry.get("capabilities") or []),
        "profiles": profiles,
        "all_machines": "*" in profiles,
        "profile_count": len(profiles),
        "created_at": entry.get("created_at"),
        "fingerprint": sha[:8],
        "copyable": copyable,
    }


def ensure_token_store(seed_path: str | Path, store_path: str | Path) -> Path:
    """Create the writable store from the seed on first start.

    Existing stores are never overwritten: after the first boot the
    store is the source of truth for the panel. To reseed, remove the
    store file (or the persistent volume) and restart.
    """
    seed = Path(seed_path)
    store = Path(store_path)
    try:
        same = seed.resolve() == store.resolve()
    except OSError:
        same = False
    if same:
        return store
    if store.exists():
        if not store.is_file():
            raise ConfigError(f"tokens store is not a file: {store}")
        return store
    load_tokens(seed)  # validates the seed before copying it
    try:
        raw = seed.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise ConfigError(f"tokens seed unreadable: {seed}: {exc}")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"tokens seed is not valid JSON: {seed}: {exc}")
    try:
        atomic_write(store, json.dumps(data, ensure_ascii=False, indent=2) + "\n")
    except OSError as exc:
        raise ConfigError(f"cannot create tokens store: {store}: {exc}")
    return store


class TokenStore:
    def __init__(self, path: str | Path, secret: bytes):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._box = SecretBox(secret)

    def _read(self) -> dict:
        try:
            raw = self.path.read_text(encoding="utf-8-sig")
        except FileNotFoundError:
            raise TokenStoreError("internal", "密钥库不存在。")
        except (OSError, UnicodeError) as exc:
            raise TokenStoreError("internal", f"密钥库读取失败：{exc}")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise TokenStoreError("internal", f"密钥库不是有效 JSON：{exc}")
        if not isinstance(data, dict) or not isinstance(data.get("tokens"), list):
            raise TokenStoreError("internal", "密钥库缺少 tokens 列表。")
        return data

    def _write_checked(self, data: dict) -> None:
        try:
            validate_tokens_data(data)
        except ConfigError as exc:
            raise TokenStoreError("internal", f"密钥库校验失败：{exc}")
        try:
            atomic_write(self.path,
                         json.dumps(data, ensure_ascii=False, indent=2) + "\n")
        except OSError as exc:
            raise TokenStoreError("internal", f"密钥库写入失败：{exc}")

    def _can_copy(self, entry: dict) -> bool:
        return self._box.open(str(entry.get("id", "")),
                              entry.get("key_enc")) is not None

    def list_entries(self) -> list[dict]:
        data = self._read()
        return [_sanitize(e, copyable=self._can_copy(e))
                for e in data["tokens"] if isinstance(e, dict)]

    def get(self, key_id: str) -> dict | None:
        data = self._read()
        for entry in data["tokens"]:
            if isinstance(entry, dict) and entry.get("id") == key_id:
                return _sanitize(entry, copyable=self._can_copy(entry))
        return None

    def _find(self, data: dict, key_id: str) -> dict:
        for entry in data["tokens"]:
            if isinstance(entry, dict) and entry.get("id") == key_id:
                return entry
        raise TokenStoreError("token.not_found", "找不到这个密钥。")

    def _unique_name(self, data: dict, name: str, *, exclude: str | None = None) -> str:
        for entry in data["tokens"]:
            if not isinstance(entry, dict):
                continue
            if entry.get("id") == exclude:
                continue
            if str(entry.get("name", "")).strip() == name:
                raise TokenStoreError("token.invalid", "密钥名称已存在。",
                                      {"name": "名称已存在，换一个。"})
        return name

    def create(self, name: object, profiles: object, role: object,
               capabilities: object) -> tuple[dict, str]:
        clean_name = _clean_name(name)
        clean_profiles = _clean_profiles(profiles)
        clean_role = _clean_role(role)
        clean_caps = _clean_capabilities(capabilities)
        with self._lock:
            data = self._read()
            if len(data["tokens"]) >= MAX_TOKENS:
                raise TokenStoreError("token.limit", "密钥数量已达上限。")
            self._unique_name(data, clean_name)
            key_id = self._new_id(data)
            plaintext = secrets.token_urlsafe(32)
            entry = {
                "id": key_id,
                "name": clean_name,
                "sha256": _hash_token(plaintext),
                "key_enc": self._box.seal(key_id, plaintext),
                "profiles": clean_profiles,
                "role": clean_role,
                "capabilities": clean_caps,
                "created_at": _now_iso(),
            }
            data["tokens"].append(entry)
            self._write_checked(data)
            return _sanitize(entry), plaintext

    def update(self, key_id: str, name: object, profiles: object, role: object,
               capabilities: object) -> dict:
        clean_name = _clean_name(name)
        clean_profiles = _clean_profiles(profiles)
        clean_role = _clean_role(role)
        clean_caps = _clean_capabilities(capabilities)
        with self._lock:
            data = self._read()
            entry = self._find(data, key_id)
            self._unique_name(data, clean_name, exclude=key_id)
            entry["name"] = clean_name
            entry["profiles"] = clean_profiles
            entry["role"] = clean_role
            entry["capabilities"] = clean_caps
            self._write_checked(data)
            return _sanitize(entry, copyable=self._can_copy(entry))

    def rotate(self, key_id: str) -> tuple[dict, str]:
        with self._lock:
            data = self._read()
            entry = self._find(data, key_id)
            plaintext = secrets.token_urlsafe(32)
            entry["sha256"] = _hash_token(plaintext)
            entry["key_enc"] = self._box.seal(key_id, plaintext)
            self._write_checked(data)
            return _sanitize(entry), plaintext

    def secret_for(self, key_id: str) -> tuple[dict, str | None]:
        """Return (entry, plaintext), or (entry, None) when this key has
        no recoverable ciphertext (seeded legacy key or changed secret)."""
        data = self._read()
        entry = self._find(data, key_id)
        plaintext = self._box.open(key_id, entry.get("key_enc"))
        return _sanitize(entry, copyable=plaintext is not None), plaintext

    def delete(self, key_id: str) -> dict:
        with self._lock:
            data = self._read()
            entry = self._find(data, key_id)
            data["tokens"] = [e for e in data["tokens"] if e is not entry]
            self._write_checked(data)
            return _sanitize(entry, copyable=self._can_copy(entry))

    @staticmethod
    def _new_id(data: dict) -> str:
        used = {str(e.get("id")) for e in data["tokens"] if isinstance(e, dict)}
        while True:
            candidate = "key-" + secrets.token_hex(4)
            if candidate not in used:
                return candidate
