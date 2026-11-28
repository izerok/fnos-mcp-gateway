"""CLI adapter — the ONLY module that talks to fnos-cli (PLAN §4).

Boundary rules enforced here, nowhere else:
- Pinned to fnos-cli 0.6.2 (SUPPORTED_CLI_VERSIONS). --version must match
  or startup fails.
- Narrow interface only: version / login_start / login_finish / user_info /
  system_info / storage_* / file_ls / docker_ps / monitor_cpu / logout.
- Never construct the authorization URL ourselves: login_start returns
  the CLI's URL verbatim; the caller validates it (FR-21).
- Never judge login with `system info` (it does not require a session).
- Never parse human-readable CLI error text for business decisions; only
  the structured signals below are recognised:
    * token_persisted / refresh_token_persisted (bool, JSON or key=value)
    * authorization_url (string)
    * "saved proxy session is required" (the documented user-info signal
      for "no saved session", per reference/sysinfo.md)
    * structured error codes, when the CLI returns them as JSON
      (session_expired / token_expired / unauthorized / permission_denied)
- login_finish: if the CLI exits non-zero but token_persisted=true, the
  code was already consumed — check the existing session instead of
  re-exchanging the code (实施计划 §2.5).
- The exact read-only subcommand spellings (storage/file/docker/monitor)
  follow the Skill reference docs, CONFIRMED BY CAPABILITY PROBE against
  the real --help and re-verified against the 0.6.2 --help tree on
  2026-11-24 (identical command surface; only login gained
  --agent-name/--device-name). The fake CLI implements the same
  spellings, so a spelling change is caught by test_cli_adapter, not by
  users.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from .config import Profile
from .errors import CliError, CliVersionError
from .runner import CliRunner, RunResult

SUPPORTED_CLI_VERSIONS = ("0.6.2",)
CLI_VERSION = "0.6.2"

_VERSION_RE = re.compile(r"(\d+\.\d+\.\d+)")
_BOOL_RE = re.compile(r"(token_persisted|refresh_token_persisted)\s*[:=]\s*(true|false)",
                      re.IGNORECASE)
_URL_RE = re.compile(r"authorization_url\s*[:=]\s*(\S+)", re.IGNORECASE)
_NO_SESSION_SIGNAL = "saved proxy session is required"

# Structured error codes the adapter recognises (JSON only).
_EXPIRED_CODES = {"session_expired", "token_expired", "unauthorized", "invalid_token"}
_PERMISSION_CODES = {"permission_denied", "forbidden", "insufficient_permission"}

# Compose lifecycle endpoints, recovered from the fnOS Docker app bundle
# (apps/docker/assets/index-*.js, 2026-11-25) and verified against a live
# NAS for list/containers/log/existing-file. Every action takes only
# {"project_name": <name>}; composeCreate additionally takes folder/file.
# The fnOS UI enforces this same project-name rule.
COMPOSE_ACTIONS = {
    "build": "appcgi.dockermgr.composeBuild",
    "start": "appcgi.dockermgr.composeStart",
    "stop": "appcgi.dockermgr.composeStop",
    "restart": "appcgi.dockermgr.composeRestart",
    "clear": "appcgi.dockermgr.composeClear",
    "delete": "appcgi.dockermgr.composeDelete",
    "cancel": "appcgi.dockermgr.composeCancel",
}
COMPOSE_ENDPOINTS = {
    "list": "appcgi.dockermgr.composeList",
    "containers": "appcgi.dockermgr.composeContainers",
    "logs": "appcgi.dockermgr.composeLog",
    "existing_file": "appcgi.dockermgr.composeExistingFile",
    "create": "appcgi.dockermgr.composeCreate",
    **COMPOSE_ACTIONS,
}
_COMPOSE_NAME_RE = re.compile(r"^(?![_-])[a-z0-9_-]{1,63}$")
_COMPOSE_FILE_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}\.(?:ya?ml)$")


def normalize_compose_folder(folder: str) -> str:
    """fnOS compose APIs take share paths WITHOUT a leading slash
    ("vol1/1000/docker/app"); the CLI file API takes them WITH one.
    Reject traversal and anything that is not under a volume."""
    if not isinstance(folder, str):
        raise ValueError("folder must be a string")
    raw = folder.strip()
    if not raw or len(raw) > 512:
        raise ValueError("folder is empty or too long")
    if any(ord(c) < 0x20 or ord(c) == 0x7f for c in raw):
        raise ValueError("folder contains control characters")
    if "\\" in raw:
        raise ValueError("folder must use forward slashes")
    if ".." in raw.split("/"):
        raise ValueError("folder must not contain '..'")
    norm = raw.lstrip("/").rstrip("/")
    if not re.match(r"^vol[0-9]+(?:/|$)", norm):
        raise ValueError("folder must be a path under a volume (vol1/...)")
    return norm


@dataclass
class LoginResult:
    token_persisted: bool
    refresh_token_persisted: bool
    # True when the code was consumed but the CLI exited non-zero; the
    # caller must verify the session with user_info instead of retrying.
    consumed_but_unverified: bool = False


@dataclass
class AuthResult:
    status: str  # "ok" | "logged_out" | "expired" | "permission"
    identity: str | None = None
    # Whitelisted identity facts from user info (FR-37): uid / gid /
    # admin / groups. Built by _identity_detail; never contains tokens
    # or anything beyond what the NAS itself reports for the account.
    detail: dict | None = None


def _identity_detail(info: dict) -> dict | None:
    """Pick the safe, displayable identity fields out of a user info
    payload (FR-37). Unknown shapes yield None; lists are capped so a
    hostile NAS cannot bloat the panel-state file."""
    detail: dict = {}
    uid = info.get("uid")
    if isinstance(uid, int) and not isinstance(uid, bool):
        detail["uid"] = uid
    gid = info.get("gid")
    if isinstance(gid, int) and not isinstance(gid, bool):
        detail["gid"] = gid
    admin = info.get("admin")
    if isinstance(admin, bool):
        detail["admin"] = admin
    groups = info.get("groups")
    if isinstance(groups, list):
        clean = [str(g) for g in groups[:20]
                 if isinstance(g, (str, int)) and not isinstance(g, bool)
                 and str(g)]
        if clean:
            detail["groups"] = clean
    return detail or None


class FnosCli:
    def __init__(self, runner: CliRunner, timeouts: "dict[str, int] | None" = None):
        self._runner = runner
        # Timeout buckets (seconds), editable live via the panel settings;
        # a None member falls back to the built-in default below.
        self._timeouts = dict(timeouts or {})

    def _t(self, bucket: str, default: int) -> int:
        value = self._timeouts.get(bucket)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
            return default
        return int(value)

    def set_timeouts(self, buckets: dict[str, int]) -> None:
        """Live-update timeout buckets (panel settings). Values already
        validated by SettingsStore bounds; unknown buckets are ignored."""
        for key, value in (buckets or {}).items():
            if key in ("read", "logs", "action", "build"):
                self._timeouts[key] = int(value)

    # -- version / capability -------------------------------------------
    def version(self) -> str:
        result = self._runner.run(["--version"], timeout=15)
        text = (result.stdout or "") + "\n" + (result.stderr or "")
        match = _VERSION_RE.search(text)
        if not match:
            raise CliError("could not determine CLI version from --version output")
        return match.group(1)

    def check_version(self) -> str:
        found = self.version()
        if found not in SUPPORTED_CLI_VERSIONS:
            raise CliVersionError(
                f"unsupported fnos-cli version {found!r}; supported: {SUPPORTED_CLI_VERSIONS}"
            )
        return found

    # -- internals --------------------------------------------------------
    def _global_args(self, profile: Profile) -> list[str]:
        args = [
            "--profile", profile.name,
            "--host", profile.host,
            "--port", str(profile.port),
            "--scheme", profile.scheme,
        ]
        if profile.allow_insecure_http:
            args.append("--allow-insecure-http")
        if profile.tls_insecure:
            args.append("--tls-insecure")
        return args

    @staticmethod
    def _parse_json(text: str) -> dict | None:
        text = text.strip()
        if not text:
            return None
        try:
            data = json.loads(text)
        except ValueError:
            return None
        return data if isinstance(data, dict) else None

    def _run(self, profile: Profile, args: list[str], timeout: float) -> RunResult:
        return self._runner.run([*self._global_args(profile), *args], timeout=timeout)

    @staticmethod
    def _persisted_flags(data: dict | None, raw: str) -> tuple[bool, bool]:
        if data:
            return bool(data.get("token_persisted")), bool(data.get("refresh_token_persisted"))
        found = dict((k.lower(), v.lower() == "true") for k, v in _BOOL_RE.findall(raw))
        return found.get("token_persisted", False), found.get("refresh_token_persisted", False)

    @staticmethod
    def _error_code(data: dict | None) -> str | None:
        if not data:
            return None
        for key in ("error_code", "code", "errno"):
            value = data.get(key)
            if isinstance(value, str):
                return value
        return None

    # -- login ------------------------------------------------------------
    def login_start(self, profile: Profile) -> str:
        """Return the CLI's authorization URL verbatim (never constructed)."""
        result = self._run(profile, ["login", "--authorize-only"], timeout=30)
        data = self._parse_json(result.stdout)
        url = (data or {}).get("authorization_url")
        if not url:
            match = _URL_RE.search(result.stdout)
            url = match.group(1) if match else None
        if not url:
            raise CliError("login --authorize-only did not return an authorization_url")
        return str(url)

    def login_finish(self, profile: Profile, code: str) -> LoginResult:
        result = self._run(profile, ["login", "--code", code], timeout=30)
        data = self._parse_json(result.stdout)
        token_ok, refresh_ok = self._persisted_flags(data, result.stdout)
        if result.timed_out:
            # A timeout is not evidence that the code is invalid. If the
            # CLI already persisted a token, let the caller verify it;
            # otherwise surface a CLI failure instead of a code error.
            if token_ok:
                return LoginResult(token_ok, refresh_ok, consumed_but_unverified=True)
            raise CliError("login --code timed out")
        if result.returncode != 0 and not token_ok:
            err = self._error_code(data)
            if err == "code_expired":
                raise LoginCodeExpired()
            raise LoginCodeInvalid()
        if result.returncode != 0 and token_ok:
            return LoginResult(token_ok, refresh_ok, consumed_but_unverified=True)
        return LoginResult(token_ok, refresh_ok)

    # -- auth probe ---------------------------------------------------------
    def user_info(self, profile: Profile) -> AuthResult:
        """The ONLY login check. `system info` must never be used for this."""
        result = self._run(profile, ["user", "info"], timeout=30)
        combined = (result.stdout or "") + "\n" + (result.stderr or "")
        if _NO_SESSION_SIGNAL in combined:
            return AuthResult(status="logged_out")
        data = self._parse_json(result.stdout)
        if data:
            # Real fnOS returns {"result": "succ", "userInfo": {...}}; the
            # fake CLI (and older builds) may return a flat identity/user.
            info = data.get("userInfo")
            if isinstance(info, dict):
                data = info
            identity = data.get("identity") or data.get("user") or data.get("username")
            if isinstance(identity, dict):
                identity = identity.get("name") or identity.get("username")
            if identity:
                return AuthResult(status="ok", identity=str(identity),
                                  detail=_identity_detail(data))
            err = self._error_code(data)
            if err in _PERMISSION_CODES:
                return AuthResult(status="permission")
            if err in _EXPIRED_CODES:
                return AuthResult(status="expired")
            if result.returncode == 0:
                return AuthResult(status="ok", identity=None,
                                  detail=_identity_detail(data))
        if result.returncode != 0:
            raise CliError("user info failed without a recognised auth signal")
        return AuthResult(status="ok", identity=None)

    # -- read-only tools ------------------------------------------------------
    def system_info(self, profile: Profile) -> dict:
        return self._read_only(profile, ["system", "info"])

    def storage_overview(self, profile: Profile) -> dict:
        return self._read_only(profile, ["storage", "overview"])

    def storage_pools(self, profile: Profile) -> dict:
        return self._read_only(profile, ["storage", "pools"])

    def storage_disks(self, profile: Profile) -> dict:
        return self._read_only(profile, ["storage", "disks"])

    def file_ls(self, profile: Profile, path: str = "/") -> dict:
        if not path.startswith("/") or ".." in path.split("/"):
            raise ValueError("file path must be absolute and must not contain '..'")
        return self._read_only(profile, ["file", "ls", path])

    def docker_ps(self, profile: Profile) -> dict:
        # fnos-cli 0.5.1+ has no `docker ps`; the container list lives at
        # `docker container ls` (verified against both --help trees). The
        # real CLI answers with a Docker-style ARRAY, so this read parses
        # any JSON value and wraps arrays as {"containers": [...]}.
        result = self._run(profile, ["docker", "container", "ls"], timeout=self._t("read", 60))
        if result.timed_out:
            raise CliError("docker container ls timed out")
        raw = _parse_json_any(result.stdout)
        if isinstance(raw, list):
            return {"containers": raw}
        if isinstance(raw, dict):
            return raw
        if result.returncode != 0:
            raise CliError(f"docker container ls failed (exit {result.returncode})")
        return {"output": result.stdout[:4000]}

    def monitor_cpu(self, profile: Profile) -> dict:
        return self._read_only(profile, ["monitor", "cpu"])

    # -- deploy/write operations ------------------------------------------
    # Narrow, individually-audited wrappers (M3-deploy). Each returns the
    # CLI's JSON envelope verbatim; nothing is retried automatically.

    def file_mkdir(self, profile: Profile, path: str) -> dict:
        if not path.startswith("/") or ".." in path.split("/"):
            raise ValueError("file path must be absolute and must not contain '..'")
        result = self._run(profile, ["file", "mkdir", path, "--yes"], timeout=self._t("read", 60))
        return self._mutate_result(profile, ["file", "mkdir"], result)

    def file_upload(self, profile: Profile, remote_dir: str, local_file: str,
                    overwrite: str = "rename") -> dict:
        if not remote_dir.startswith("/") or ".." in remote_dir.split("/"):
            raise ValueError("remote dir must be absolute and must not contain '..'")
        if overwrite not in ("skip", "replace", "rename"):
            raise ValueError("overwrite must be one of skip/replace/rename")
        result = self._run(profile, ["file", "upload", remote_dir, local_file,
                                     "--overwrite", overwrite, "--yes"], timeout=self._t("build", 600))
        return self._mutate_result(profile, ["file", "upload"], result)

    def file_chown(self, profile: Profile, path: str, uid: int,
                   recursive: bool = False) -> dict:
        if not path.startswith("/") or ".." in path.split("/"):
            raise ValueError("file path must be absolute and must not contain '..'")
        if not isinstance(uid, int) or isinstance(uid, bool) or not (0 <= uid <= 65535):
            raise ValueError("uid must be an integer 0..65535")
        args = ["file", "chown", "--uid", str(uid), path]
        if recursive:
            args.append("--sub")
        args.append("--yes")
        result = self._run(profile, args, timeout=self._t("logs", 120))
        return self._mutate_result(profile, ["file", "chown"], result)

    def docker_container_create(self, profile: Profile, image: str, *, name: str | None = None,
                                start: bool = False, restart: bool = False,
                                memory_mb: int | None = None, cpu_shares: int | None = None,
                                env: list[str] | None = None, cmd: list[str] | None = None,
                                ports: list[str] | None = None,
                                mounts: list[str] | None = None) -> dict:
        if not image or any(c in image for c in "\r\n\x00"):
            raise ValueError("invalid image reference")
        args = ["docker", "container", "create", "--image", image]
        if name:
            args += ["--name", name]
        if start:
            args.append("--start")
        if restart:
            args.append("--restart")
        if memory_mb is not None:
            args += ["--memory", str(int(memory_mb))]
        if cpu_shares is not None:
            args += ["--cpu", str(int(cpu_shares))]
        for e in env or []:
            if "=" not in e:
                raise ValueError("env entries must be key=value")
            args += ["--env", e]
        for c in cmd or []:
            # fnos-cli splits each --cmd value on whitespace; a caller who
            # needs a multi-word argument must use docker_request instead.
            if not c or any(ch.isspace() for ch in c):
                raise ValueError("cmd entries must be single words (no whitespace)")
            args += ["--cmd", c]
        for p in ports or []:
            args += ["--port", p]
        for m in mounts or []:
            args += ["--mount", m]
        args.append("--yes")
        result = self._run(profile, args, timeout=self._t("action", 300))
        return self._mutate_result(profile, ["docker", "container", "create"], result)

    def docker_container_remove(self, profile: Profile, container: str,
                                force: bool = False) -> dict:
        if not container or any(c in container for c in "\r\n\x00"):
            raise ValueError("invalid container id or name")
        args = ["docker", "container", "rm", container]
        if force:
            args.append("--force")
        args.append("--yes")
        result = self._run(profile, args, timeout=self._t("logs", 120))
        return self._mutate_result(profile, ["docker", "container", "rm"], result)

    _DOCKER_REQUEST_ENDPOINT_RE = re.compile(r"appcgi\.dockermgr\.[A-Za-z0-9]+")

    def docker_request(self, profile: Profile, endpoint: str, body: dict | None = None) -> dict:
        """Escape hatch to unfixed appcgi.dockermgr.* endpoints (compose
        create/build/start/stop, network*, image save/load, ...). The
        endpoint must be a bare dockermgr name or full appcgi.dockermgr.*
        path; anything else is refused before touching the CLI."""
        ep = endpoint.strip()
        if not ep.startswith("appcgi.dockermgr."):
            ep = "appcgi.dockermgr." + ep
        if not self._DOCKER_REQUEST_ENDPOINT_RE.fullmatch(ep) or ep.endswith("."):
            raise ValueError("endpoint must be an appcgi.dockermgr.* name")
        if body is not None and not isinstance(body, dict):
            raise ValueError("body must be a JSON object")
        if body and ("req" in body or "reqid" in body):
            raise ValueError("body must not contain req/reqid (CLI generates them)")
        args = ["docker", "request", ep]
        if body:
            args += ["--json", json.dumps(body, ensure_ascii=False)]
        args.append("--yes")
        result = self._run(profile, args, timeout=self._t("build", 600))
        return self._mutate_result(profile, ["docker", "request", ep], result)

    # -- compose ---------------------------------------------------------
    # Read calls and typed lifecycle calls over the same CLI `docker request`
    # bridge. composeList/containers/log answers are bare JSON arrays; the
    # lifecycle calls (build/start/...) answer with an errno envelope or a
    # streamed result, so they are returned as-is under {"result": ...}
    # when the shape is not an object.

    def _docker_endpoint_call(self, profile: Profile, endpoint: str,
                              body: dict | None = None, timeout: float = 120):
        ep = endpoint if endpoint.startswith("appcgi.") else "appcgi.dockermgr." + endpoint
        args = ["docker", "request", ep]
        if body:
            args += ["--json", json.dumps(body, ensure_ascii=False)]
        args.append("--yes")
        result = self._run(profile, args, timeout=timeout)
        if result.timed_out:
            raise CliError(f"{ep} timed out")
        raw = _parse_json_any(result.stdout)
        if raw is not None:
            return raw
        if result.returncode != 0:
            raise CliError(f"{ep} failed (exit {result.returncode})")
        return {"output": result.stdout[:4000]}

    @staticmethod
    def _compose_name(project_name: str) -> str:
        if not isinstance(project_name, str) or not _COMPOSE_NAME_RE.match(project_name):
            raise ValueError(
                "project_name must match ^(?![_-])[a-z0-9_-]{1,63}$ (fnOS compose rule)")
        return project_name

    def docker_compose_list(self, profile: Profile) -> dict:
        raw = self._docker_endpoint_call(profile, COMPOSE_ENDPOINTS["list"], timeout=self._t("read", 60))
        if isinstance(raw, list):
            return {"projects": raw}
        return raw if isinstance(raw, dict) else {"result": raw}

    def docker_compose_containers(self, profile: Profile, project_name: str) -> dict:
        self._compose_name(project_name)
        raw = self._docker_endpoint_call(
            profile, COMPOSE_ENDPOINTS["containers"], {"project_name": project_name}, timeout=self._t("read", 60))
        if isinstance(raw, list):
            return {"project": project_name, "containers": raw}
        return raw if isinstance(raw, dict) else {"result": raw}

    def docker_compose_logs(self, profile: Profile, project_name: str) -> dict:
        self._compose_name(project_name)
        raw = self._docker_endpoint_call(
            profile, COMPOSE_ENDPOINTS["logs"], {"project_name": project_name}, timeout=self._t("logs", 120))
        if isinstance(raw, list):
            return {"project": project_name, "logs": raw}
        return raw if isinstance(raw, dict) else {"result": raw}

    def docker_compose_existing_file(self, profile: Profile, folder: str) -> dict:
        norm = normalize_compose_folder(folder)
        raw = self._docker_endpoint_call(
            profile, COMPOSE_ENDPOINTS["existing_file"], {"folder": norm}, timeout=self._t("read", 60))
        if isinstance(raw, dict):
            return {"folder": norm, "config_files": raw.get("ConfigFiles"), "result": raw}
        return {"folder": norm, "result": raw}

    def docker_compose_create(self, profile: Profile, folder: str, project_name: str,
                              file: str = "docker-compose.yaml",
                              auto_build: bool = False) -> dict:
        norm = normalize_compose_folder(folder)
        self._compose_name(project_name)
        if not isinstance(file, str) or not _COMPOSE_FILE_RE.match(file):
            raise ValueError("file must be a .yml/.yaml file name without a path")
        body = {"auto_build": bool(auto_build), "file": file,
                "folder": norm, "project_name": project_name}
        raw = self._docker_endpoint_call(
            profile, COMPOSE_ENDPOINTS["create"], body, timeout=self._t("action", 300))
        return raw if isinstance(raw, dict) else {"result": raw}

    def docker_compose_action(self, profile: Profile, action: str,
                              project_name: str) -> dict:
        endpoint = COMPOSE_ACTIONS.get(action)
        if endpoint is None:
            raise ValueError(f"action must be one of {sorted(COMPOSE_ACTIONS)}")
        self._compose_name(project_name)
        timeout = self._t("build", 600) if action in ("build", "clear", "delete") else self._t("action", 180)
        raw = self._docker_endpoint_call(
            profile, endpoint, {"project_name": project_name}, timeout=timeout)
        return raw if isinstance(raw, dict) else {"result": raw}

    def _mutate_result(self, profile: Profile, args: list[str], result: RunResult) -> dict:
        """Unpack a write command. Writes often answer with a bare success
        string ("succeed") or an array, so a non-dict JSON body is kept
        as {"result": ...}; stdout text goes into {"output": ...}."""
        if result.timed_out:
            raise CliError(f"{' '.join(args)} timed out")
        data = self._parse_json(result.stdout)
        if data is not None:
            return data
        raw = _parse_json_any(result.stdout)
        if raw is not None:
            return {"result": raw}
        if result.returncode != 0:
            raise CliError(f"{' '.join(args)} failed (exit {result.returncode})")
        return {"output": result.stdout[:4000]}

    def _read_only(self, profile: Profile, args: list[str]) -> dict:
        result = self._run(profile, args, timeout=self._t("read", 60))
        if result.timed_out:
            raise CliError(f"{' '.join(args)} timed out")
        data = self._parse_json(result.stdout)
        if data is not None:
            return data
        if result.returncode != 0:
            raise CliError(f"{' '.join(args)} failed (exit {result.returncode})")
        return {"output": result.stdout[:4000]}

    # -- logout ---------------------------------------------------------------
    def logout(self, profile: Profile) -> None:
        """Clear the local session + pending only; never revokes NAS-side auth."""
        result = self._run(profile, ["logout"], timeout=30)
        if result.timed_out:
            # Never report success when the local session state is unknown.
            raise CliError("logout timed out")
        if result.returncode != 0:
            raise CliError(f"logout failed (exit {result.returncode})")


class LoginCodeInvalid(CliError):
    pass


class LoginCodeExpired(CliError):
    pass


def _parse_json_any(text: str):
    """Parse any JSON value; None when the text is not JSON."""
    text = text.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except ValueError:
        return None
