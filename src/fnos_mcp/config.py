"""Load and validate profiles.json / tokens.json (需求文档 §10.1–§10.2).

Rules:
- File-level errors (missing file, bad JSON, wrong top-level shape,
  tokens.json unreadable) -> ConfigError, startup must fail.
- A single bad profile is skipped, recorded in ``config_errors``, and the
  panel shows it as 配置错误; it never takes the whole service down.
- Profile names: ^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$ (no '.', '..', leading
  dot, slash or control characters) — the name is used as a URL path
  segment and a session directory name.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .errors import ConfigError

PROFILE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$")


def validate_host(value: object) -> str:
    """Validate a profile host without accepting a URL or path.

    The host is passed to the CLI as ``--host`` and later used by the
    network probe. It must be a bare DNS name or IPv4 address: no scheme,
    port, path, userinfo, whitespace, or control characters. IPv6 is not
    supported (the CLI/URL construction would need brackets and the
    current profile model does not carry them).
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError("host is required")
    host = value.strip()
    if len(host) > 253:
        raise ValueError("host is too long")
    if any(ord(c) < 0x20 or ord(c) == 0x7f for c in host):
        raise ValueError("host contains control characters")
    if any(c.isspace() for c in host):
        raise ValueError("host contains whitespace")
    if any(c in host for c in ("/", "\\", "?", "#", "@")):
        raise ValueError("host must not include a scheme, path, or userinfo")
    if "://" in host:
        raise ValueError("host must not include a scheme")
    if ":" in host:
        raise ValueError("host must be a domain or IPv4 address (IPv6 is not supported)")
    labels = host.split(".")
    if any(not label or len(label) > 63 or not _HOST_LABEL_RE.match(label)
           for label in labels):
        raise ValueError("host is not a valid domain or IPv4 address")
    if host.startswith(".") or host.endswith(".") or ".." in host:
        raise ValueError("host is not a valid domain or IPv4 address")
    return host


@dataclass
class Profile:
    name: str
    host: str
    port: int
    scheme: str = "https"
    allow_insecure_http: bool = False
    tls_insecure: bool = False
    allow_dangerous: bool = False
    description: str = ""
    authorization_hosts: list[str] = field(default_factory=list)

    @property
    def target(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"

    @property
    def origin(self) -> str:
        return self.target


@dataclass
class TokenRecord:
    id: str
    name: str
    sha256: str
    profiles: list[str]
    role: str  # "operator" | "admin"
    capabilities: list[str] = field(default_factory=list)

    @property
    def can_manage_login(self) -> bool:
        return self.role == "admin" or "manage_login" in self.capabilities

    @property
    def can_manage_profiles(self) -> bool:
        """Admin-only profile add/edit (a delegated capability is allowed)."""
        return self.role == "admin" or "manage_profiles" in self.capabilities

    def allows(self, name: str) -> bool:
        """ACL check; ``"*"`` is the explicit all-profiles grant."""
        return name in self.profiles or "*" in self.profiles


@dataclass
class ProfilesConfig:
    default_profile: str | None
    profiles: dict[str, Profile]
    config_errors: dict[str, str]  # name -> reason (skipped profiles)


def _load_json(path: str | Path) -> dict:
    p = Path(path)
    try:
        # utf-8-sig accepts both plain UTF-8 and files written by Windows
        # PowerShell 5.1's default Out-File -Encoding utf8 (BOM).
        raw = p.read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        raise ConfigError(f"config file not found: {p}")
    except OSError as exc:
        raise ConfigError(f"config file unreadable: {p}: {exc}")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"config file is not valid JSON: {p}: {exc}")
    if not isinstance(data, dict):
        raise ConfigError(f"config file top level must be an object: {p}")
    return data


def _validate_profile(name: str, raw: object) -> Profile:
    if not PROFILE_NAME_RE.match(name):
        raise ValueError(f"invalid profile name {name!r}")
    if not isinstance(raw, dict):
        raise ValueError("profile entry must be an object")
    host = validate_host(raw.get("host"))
    port = raw.get("port")
    scheme = raw.get("scheme", "https")
    if not isinstance(port, int) or isinstance(port, bool) or not (1 <= port <= 65535):
        raise ValueError("port must be an integer 1..65535")
    if scheme not in ("http", "https"):
        raise ValueError("scheme must be http or https")
    if scheme == "http" and not raw.get("allow_insecure_http", False):
        raise ValueError("http scheme requires allow_insecure_http=true")
    auth_hosts = raw.get("authorization_hosts", [])
    if not isinstance(auth_hosts, list) or not all(isinstance(h, str) for h in auth_hosts):
        raise ValueError("authorization_hosts must be a list of origins")
    description_raw = raw.get("description", "")
    if description_raw is None:
        description_raw = ""
    if not isinstance(description_raw, str):
        raise ValueError("description must be a string")
    description = description_raw.strip()
    if len(description) > 200:
        raise ValueError("description must be at most 200 characters")
    if any(ord(c) < 0x20 or ord(c) == 0x7f for c in description):
        raise ValueError("description contains control characters")
    return Profile(
        name=name,
        host=host,
        port=port,
        scheme=scheme,
        allow_insecure_http=bool(raw.get("allow_insecure_http", False)),
        tls_insecure=bool(raw.get("tls_insecure", False)),
        allow_dangerous=bool(raw.get("allow_dangerous", False)),
        description=description,
        authorization_hosts=list(auth_hosts),
    )


def validate_profiles_data(data: object) -> ProfilesConfig:
    """Validate an already-parsed profiles document.

    File-level shape errors raise ConfigError. Individual bad profiles are
    collected in ``config_errors`` so the panel can show them and an admin
    can repair them through the editor.
    """
    if not isinstance(data, dict):
        raise ConfigError("profiles.json: top level must be an object")
    raw_profiles = data.get("profiles")
    if not isinstance(raw_profiles, dict):
        raise ConfigError("profiles.json: 'profiles' must be an object")
    default_profile = data.get("default_profile")
    if default_profile is not None and not isinstance(default_profile, str):
        raise ConfigError("profiles.json: 'default_profile' must be a string")
    profiles: dict[str, Profile] = {}
    errors: dict[str, str] = {}
    for name, raw in raw_profiles.items():
        try:
            profiles[name] = _validate_profile(name, raw)
        except ValueError as exc:
            errors[name] = str(exc)
    return ProfilesConfig(default_profile=default_profile, profiles=profiles,
                          config_errors=errors)


def load_profiles(path: str | Path) -> ProfilesConfig:
    return validate_profiles_data(_load_json(path))


def load_tokens(path: str | Path) -> list[TokenRecord]:
    return validate_tokens_data(_load_json(path))


def validate_tokens_data(data: object) -> list[TokenRecord]:
    """Validate an already-parsed tokens document (startup and writes)."""
    if not isinstance(data, dict):
        raise ConfigError("tokens.json: top level must be an object")
    raw_tokens = data.get("tokens")
    if not isinstance(raw_tokens, list):
        raise ConfigError("tokens.json: 'tokens' must be a list")
    tokens: list[TokenRecord] = []
    seen_ids: set[str] = set()
    for raw in raw_tokens:
        if not isinstance(raw, dict):
            raise ConfigError("tokens.json: each token must be an object")
        tid = raw.get("id")
        sha = raw.get("sha256")
        role = raw.get("role")
        profs = raw.get("profiles")
        if not isinstance(tid, str) or not tid:
            raise ConfigError("tokens.json: token 'id' is required")
        if tid in seen_ids:
            raise ConfigError(f"tokens.json: duplicate token id {tid!r}")
        seen_ids.add(tid)
        if not isinstance(sha, str) or len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha.lower()):
            raise ConfigError(f"tokens.json: token {tid!r} 'sha256' must be 64 hex chars")
        if role not in ("operator", "admin"):
            raise ConfigError(f"tokens.json: token {tid!r} 'role' must be operator or admin")
        if not isinstance(profs, list) or not all(isinstance(p, str) for p in profs):
            raise ConfigError(f"tokens.json: token {tid!r} 'profiles' must be a list of names")
        caps = raw.get("capabilities", [])
        if not isinstance(caps, list) or not all(isinstance(c, str) for c in caps):
            raise ConfigError(f"tokens.json: token {tid!r} 'capabilities' must be a list")
        tokens.append(TokenRecord(
            id=tid, name=str(raw.get("name", tid)), sha256=sha.lower(),
            profiles=list(profs), role=role, capabilities=list(caps),
        ))
    return tokens
