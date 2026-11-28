"""Writable profile store for the admin panel.

The store is deliberately separate from ``config.load_profiles``:

* reads keep the same validation rules as startup;
* writes are atomic (temp file in the same directory, fsync, replace) and
  always 0600;
* a single process-wide lock serializes read-modify-write cycles;
* only the fields exposed by the panel form are changed, so advanced
  fields such as ``authorization_hosts`` and ``allow_dangerous`` survive
  an edit.

``FNOS_PROFILES_STORE`` points at the writable copy (normally
``/data/profiles.json``). On first start the read-only seed
(``/etc/fnos-mcp/profiles.json``) is copied there. Without the env var,
the store is the same file passed as ``FNOS_PROFILES_PATH`` (useful for
tests and simple single-file deployments).
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

from .config import (
    PROFILE_NAME_RE,
    Profile,
    ProfilesConfig,
    validate_host,
    validate_profiles_data,
)
from .errors import ConfigError
from .fsutil import atomic_write

_atomic_write = atomic_write  # kept as the module-local name used below


class ProfileStoreError(Exception):
    """A profile write failed with a code the panel can render."""

    def __init__(self, code: str, message: str,
                 fields: dict[str, str] | None = None):
        self.code = code
        self.message = message
        self.fields = fields or {}
        super().__init__(f"{code}: {message}")


def _field(raw: dict, key: str) -> str:
    value = raw.get(key)
    if isinstance(value, str):
        return value.strip()
    return ""


def _checked(raw: dict, key: str) -> bool:
    return _field(raw, key).lower() in ("on", "true", "1", "yes")


def parse_profile_form(raw: dict, *, name: str | None = None
                       ) -> tuple[str, dict, dict[str, str]]:
    """Parse and validate the panel form.

    ``name`` is the path name for an edit; for a create it is read from
    the form. The name is immutable on edit so a stale/malicious form
    cannot silently rename a profile and orphan its session directory.

    Returns ``(name, entry, errors)``. ``entry`` contains only the
    fields the panel owns; the caller merges it into the existing JSON
    object, preserving advanced fields.
    """
    errors: dict[str, str] = {}
    if name is None:
        target_name = _field(raw, "name")
        if not target_name:
            errors["name"] = "请填写机器名。"
        elif not PROFILE_NAME_RE.match(target_name):
            errors["name"] = ("机器名只能包含字母、数字、- 和 _，"
                              "以字母或数字开头，最长 64 个字符。")
    else:
        target_name = name
        submitted = _field(raw, "name")
        if submitted and submitted != name:
            errors["name"] = "机器名保存后不可修改。"
        elif not PROFILE_NAME_RE.match(name):
            errors["name"] = "机器名格式不正确，不能通过面板编辑。"

    host_raw = _field(raw, "host")
    try:
        host = validate_host(host_raw)
    except ValueError as exc:
        host = host_raw
        message = str(exc)
        if "required" in message:
            errors["host"] = "请填写地址。"
        elif "IPv6" in message:
            errors["host"] = "暂不支持 IPv6，请填写域名或 IPv4 地址。"
        else:
            errors["host"] = ("地址格式不正确：只填域名或 IPv4，"
                              "不要带协议、端口、路径或空格。")

    port_raw = _field(raw, "port")
    try:
        port = int(port_raw)
        if not 1 <= port <= 65535:
            raise ValueError
    except (TypeError, ValueError):
        port = port_raw
        errors["port"] = "端口必须是 1-65535 的整数。"

    scheme = _field(raw, "scheme") or "https"
    if scheme not in ("http", "https"):
        scheme = "https"
        errors["scheme"] = "连接方式只能是 HTTPS 或 HTTP。"

    description = _field(raw, "description")
    if len(description) > 200:
        errors["description"] = "备注不能超过 200 个字符。"
    elif any(ord(c) < 0x20 or ord(c) == 0x7f for c in description):
        errors["description"] = "备注不能包含控制字符。"

    allow_insecure_http = _checked(raw, "allow_insecure_http")
    if scheme == "http" and not allow_insecure_http:
        errors["allow_insecure_http"] = "HTTP 明文连接需要勾选允许；建议改用 HTTPS。"

    entry: dict = {
        "host": host,
        "port": port,
        "scheme": scheme,
        "description": description,
    }
    if allow_insecure_http:
        entry["allow_insecure_http"] = True
    if _checked(raw, "tls_insecure"):
        entry["tls_insecure"] = True
    return target_name, entry, errors


def ensure_profile_store(seed_path: str | Path, store_path: str | Path) -> Path:
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
            raise ConfigError(f"profiles store is not a file: {store}")
        return store
    try:
        raw = seed.read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        raise ConfigError(f"profiles seed not found: {seed}")
    except OSError as exc:
        raise ConfigError(f"profiles seed unreadable: {seed}: {exc}")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"profiles seed is not valid JSON: {seed}: {exc}")
    validate_profiles_data(data)
    try:
        _atomic_write(store, json.dumps(data, ensure_ascii=False, indent=2) + "\n")
    except OSError as exc:
        raise ConfigError(f"cannot create profiles store: {store}: {exc}")
    return store


class ProfileStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.Lock()

    def _read(self) -> dict:
        try:
            raw = self.path.read_text(encoding="utf-8-sig")
        except FileNotFoundError:
            raise ProfileStoreError("internal", "机器配置文件不存在。")
        except (OSError, UnicodeError) as exc:
            raise ProfileStoreError("internal", f"机器配置文件读取失败：{exc}")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ProfileStoreError("internal", f"机器配置不是有效 JSON：{exc}")
        if not isinstance(data, dict):
            raise ProfileStoreError("internal", "机器配置顶层必须是对象。")
        return data

    def load(self):
        """Current validated ProfilesConfig, for callers that need the
        same view the tools see (used by tests and MCP wiring)."""
        from .config import load_profiles
        return load_profiles(str(self.path))

    def get_raw(self, name: str) -> object | None:
        data = self._read()
        profiles = data.get("profiles")
        if not isinstance(profiles, dict):
            raise ProfileStoreError("internal", "机器配置缺少 profiles 对象。")
        return profiles.get(name)

    def create(self, name: str, entry: dict) -> Profile:
        return self._write(name, entry, create=True)

    def update(self, name: str, entry: dict) -> Profile:
        return self._write(name, entry, create=False)

    def delete(self, name: str) -> None:
        """Remove a profile from the store.

        If it was the default, the default pointer is cleared (None is a
        valid default_profile; the next create fills it again). Advanced
        fields of the other profiles are untouched.
        """
        with self._lock:
            data = self._read()
            profiles = data.get("profiles")
            if not isinstance(profiles, dict):
                raise ProfileStoreError("internal", "机器配置缺少 profiles 对象。")
            if name not in profiles:
                raise ProfileStoreError("profile.not_found", "找不到这台机器。")
            del profiles[name]
            if data.get("default_profile") == name:
                data["default_profile"] = None
            try:
                validate_profiles_data(data)
            except ConfigError as exc:
                raise ProfileStoreError("internal", str(exc))
            try:
                _atomic_write(self.path,
                              json.dumps(data, ensure_ascii=False, indent=2) + "\n")
            except OSError as exc:
                raise ProfileStoreError("internal", f"机器配置写入失败：{exc}")

    def _write(self, name: str, entry: dict, *, create: bool) -> Profile:
        with self._lock:
            data = self._read()
            profiles = data.get("profiles")
            if not isinstance(profiles, dict):
                raise ProfileStoreError("internal", "机器配置缺少 profiles 对象。")

            if create:
                if name in profiles:
                    raise ProfileStoreError("profile.exists", "机器名已存在。",
                                            {"name": "机器名已存在，换一个名字。"})
                existing: dict = {}
            else:
                if name not in profiles:
                    raise ProfileStoreError("profile.not_found", "找不到这台机器。")
                raw_existing = profiles[name]
                existing = dict(raw_existing) if isinstance(raw_existing, dict) else {}

            merged = dict(existing)
            merged.update(entry)
            if "allow_insecure_http" not in entry:
                merged.pop("allow_insecure_http", None)
            if "tls_insecure" not in entry:
                merged.pop("tls_insecure", None)
            profiles[name] = merged

            if create:
                default = data.get("default_profile")
                if not isinstance(default, str) or default not in profiles:
                    data["default_profile"] = name

            try:
                parsed: ProfilesConfig = validate_profiles_data(data)
            except ConfigError as exc:
                raise ProfileStoreError("internal", str(exc))
            if name in parsed.config_errors:
                raise ProfileStoreError("profile.invalid",
                                        "机器配置不合法：" + parsed.config_errors[name],
                                        {"host": "配置校验失败，请检查地址、端口和连接方式。"})
            if name not in parsed.profiles:
                raise ProfileStoreError("profile.invalid", "机器配置不合法。")
            try:
                _atomic_write(self.path,
                              json.dumps(data, ensure_ascii=False, indent=2) + "\n")
            except OSError as exc:
                raise ProfileStoreError("internal", f"机器配置写入失败：{exc}")
            return parsed.profiles[name]
