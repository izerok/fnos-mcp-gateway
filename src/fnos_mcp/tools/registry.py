"""MCP tool registry: the 12 P0 tools (需求文档 §16.1).

Tools are plain functions over a ToolContext — no framework types leak
in, so the same registry can be served by the minimal JSON-RPC transport
in server.py today and by FastMCP 2 later without touching tool logic.

Rules enforced here:
- profile is resolved ONLY from the registry + token ACL (+ the
  X-FNOS-Profile pin, which the transport puts into ctx.pinned_profile).
  host/port/scheme arguments are rejected outright.
- Login state is judged only by user_info, never system_info.
- Every tool call re-checks the ACL (the caller supplies a fresh token
  record); the panel and MCP share this code path.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..cli_adapter import LoginCodeExpired, LoginCodeInvalid
from ..config import Profile, ProfilesConfig, TokenRecord
from ..errors import CliError, LockedError
from ..state_store import now_iso


class ToolError(Exception):
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


@dataclass
class ToolContext:
    token: TokenRecord
    profiles: ProfilesConfig
    cli: object  # FnosCli
    state: object  # PanelStateStore
    audit: object  # AuditLog
    client_ip: str | None = None
    pinned_profile: str | None = None
    limiter: object = None  # RateLimiter; None in unit tests skips the gate

    def visible_profiles(self) -> list[Profile]:
        if "*" in self.token.profiles:
            return list(self.profiles.profiles.values())
        return [self.profiles.profiles[n] for n in self.token.profiles
                if n in self.profiles.profiles]


def resolve_profile(ctx: ToolContext, params: dict) -> Profile:
    for forbidden in ("host", "port", "scheme"):
        if forbidden in params:
            raise ToolError("invalid_params", f"不接受 {forbidden} 参数，目标只来自服务端配置。")
    name = params.get("profile") or ctx.pinned_profile
    if (name is None and ctx.profiles.default_profile
            and ctx.token.allows(ctx.profiles.default_profile)):
        name = ctx.profiles.default_profile
    if name is None:
        visible = ctx.visible_profiles()
        if len(visible) == 1:
            return visible[0]
        raise ToolError("profile.required", "请指定一台机器。")
    if ctx.pinned_profile is not None and name != ctx.pinned_profile:
        raise ToolError("profile.not_found", "找不到这台机器，或当前 token 无权访问。")
    if name not in ctx.profiles.profiles or not ctx.token.allows(name):
        raise ToolError("profile.not_found", "找不到这台机器，或当前 token 无权访问。")
    return ctx.profiles.profiles[name]


def _sync_targets(ctx: ToolContext) -> None:
    """Drop state whose target fingerprint no longer matches config (FR-31)."""
    ctx.state.drop_stale({n: p.target for n, p in ctx.profiles.profiles.items()})


def _profile_summary(ctx: ToolContext, profile: Profile) -> dict:
    entry = ctx.state.load()["profiles"].get(profile.name, {})
    if entry and entry.get("target") != profile.target:
        entry = {}
    from ..state_store import merge_status
    badge = merge_status(entry.get("network"), entry.get("auth"),
                         config_error=profile.name in ctx.profiles.config_errors)
    auth = entry.get("auth") or {}
    return {
        "name": profile.name,
        "description": profile.description,
        "target": profile.target,
        "status": badge,
        "identity": auth.get("identity"),
        "network": entry.get("network"),
        "auth": auth or None,
    }


def fnos_profiles(ctx: ToolContext, params: dict) -> dict:
    _sync_targets(ctx)
    return {"profiles": [_profile_summary(ctx, p) for p in ctx.visible_profiles()]}


def fnos_login_start(ctx: ToolContext, params: dict) -> dict:
    profile = resolve_profile(ctx, params)
    if not ctx.token.can_manage_login:
        raise ToolError("auth.forbidden", "当前 token 没有这个操作权限。")
    from ..locks import acquire_login_lease, release_login_lease, session_lock
    # The lease lives in the caller's data dir; the registry gets it via state path.
    data_dir = ctx.state.path.parent
    # Same session lock the panel uses (5 min TTL): a concurrent panel
    # login on this profile must 409 instead of overwriting the pending
    # verifier the CLI just created.
    try:
        with session_lock(data_dir, profile.name):
            if not acquire_login_lease(data_dir, profile.name):
                raise ToolError("session.locked", "这台机器正在执行登录，请稍后再试。")
            try:
                url = ctx.cli.login_start(profile)
                # FR-21 applies to the MCP path too: never hand an
                # unchecked authorization URL to an agent.
                from ..auth import validate_authorization_url
                reason = validate_authorization_url(url, profile)
                if reason:
                    raise ToolError("login.failed", f"授权链接被拒绝：{reason}")
            except Exception:
                # Any failure before a URL is handed out must release the
                # lease so the user can retry immediately.
                release_login_lease(data_dir, profile.name)
                raise
    except LockedError:
        # Map the shared lock + CLI failures onto stable tool errors so an
        # MCP client never sees a bare LockedError/CliError.
        raise ToolError("session.locked", "这台机器正在执行登录或连接测试，请稍后再试。")
    except CliError:
        ctx.audit.record("login_failed", token_id=ctx.token.id, profile=profile.name,
                         result="failed", client_ip=ctx.client_ip)
        raise ToolError("login.failed", "登录没有完成，NAS 端可能拒绝或网络中断。")
    ctx.audit.record("login_started", token_id=ctx.token.id, profile=profile.name,
                     client_ip=ctx.client_ip)
    return {"profile": profile.name, "authorization_url": url,
            "target_host": profile.host}


def fnos_login_finish(ctx: ToolContext, params: dict) -> dict:
    profile = resolve_profile(ctx, params)
    if not ctx.token.can_manage_login:
        raise ToolError("auth.forbidden", "当前 token 没有这个操作权限。")
    code = params.get("code")
    if not code or not isinstance(code, str):
        raise ToolError("login.code_invalid", "授权码无效，请重新发起授权。")
    from ..locks import release_login_lease, session_lock
    data_dir = ctx.state.path.parent
    # Same session lock the panel uses: a concurrent panel login/test on
    # this profile must 409 instead of racing the CLI's pending verifier.
    try:
        with session_lock(data_dir, profile.name):
            try:
                try:
                    ctx.cli.login_finish(profile, code)
                except LoginCodeExpired:
                    raise ToolError("login.code_expired", "授权码已过期，请重新发起授权。")
                except LoginCodeInvalid:
                    raise ToolError("login.code_invalid", "授权码无效，请重新发起授权。")
                # token_persisted (even with a non-zero exit) -> verify the
                # existing session; never re-exchange a consumed code.
                auth = ctx.cli.user_info(profile)
                if auth.status != "ok":
                    ctx.audit.record("login_failed", token_id=ctx.token.id, profile=profile.name,
                                     result="failed", client_ip=ctx.client_ip)
                    raise ToolError("login.failed", "登录没有完成，NAS 端可能拒绝或网络中断。")
                ctx.state.update(profile.name, profile.target,
                                 network={"at": now_iso(), "status": "ok", "latency_ms": 0,
                                          "looks_like_fnos": True},
                                 auth={"at": now_iso(), "status": "ok", "latency_ms": 0,
                                       "identity": auth.identity})
                ctx.audit.record("login_finished", token_id=ctx.token.id, profile=profile.name,
                                 client_ip=ctx.client_ip)
                return {"profile": profile.name, "status": "connected",
                        "identity": auth.identity}
            finally:
                release_login_lease(data_dir, profile.name)
    except LockedError:
        raise ToolError("session.locked", "这台机器正在执行登录或连接测试，请稍后再试。")
    except CliError:
        ctx.audit.record("login_failed", token_id=ctx.token.id, profile=profile.name,
                         result="failed", client_ip=ctx.client_ip)
        raise ToolError("login.failed", "登录没有完成，NAS 端可能拒绝或网络中断。")


def fnos_logout(ctx: ToolContext, params: dict) -> dict:
    profile = resolve_profile(ctx, params)
    if not ctx.token.can_manage_login:
        raise ToolError("auth.forbidden", "当前 token 没有这个操作权限。")
    from ..locks import release_login_lease, session_lock
    data_dir = ctx.state.path.parent
    try:
        with session_lock(data_dir, profile.name):
            try:
                ctx.cli.logout(profile)
            finally:
                # Even a failed logout must not leave a stale login lease
                # blocking the next login_start for five minutes.
                release_login_lease(data_dir, profile.name)
            ctx.state.update(profile.name, profile.target,
                             auth={"at": now_iso(), "status": "logged_out", "latency_ms": 0,
                                   "identity": None})
    except LockedError:
        raise ToolError("session.locked", "这台机器正在执行登录或连接测试，请稍后再试。")
    except CliError:
        ctx.audit.record("logout", token_id=ctx.token.id, profile=profile.name,
                         result="failed", client_ip=ctx.client_ip)
        raise ToolError("logout.failed", "本机 session 清理失败，请重试；NAS 端授权未改变。")
    ctx.audit.record("logout", token_id=ctx.token.id, profile=profile.name,
                     client_ip=ctx.client_ip)
    return {"profile": profile.name, "status": "logged_out"}


def fnos_status(ctx: ToolContext, params: dict) -> dict:
    _sync_targets(ctx)
    if params.get("profile"):
        profile = resolve_profile(ctx, params)
        return {"profiles": [_profile_summary(ctx, profile)]}
    return {"profiles": [_profile_summary(ctx, p) for p in ctx.visible_profiles()]}


def _read_only(ctx: ToolContext, params: dict, method: str):
    profile = resolve_profile(ctx, params)
    func = getattr(ctx.cli, method)
    if method == "file_ls":
        return func(profile, params.get("path", "/"))
    return func(profile)


def fnos_system_info(ctx: ToolContext, params: dict) -> dict:
    return _read_only(ctx, params, "system_info")


def fnos_storage_overview(ctx: ToolContext, params: dict) -> dict:
    return _read_only(ctx, params, "storage_overview")


def fnos_storage_pools(ctx: ToolContext, params: dict) -> dict:
    return _read_only(ctx, params, "storage_pools")


def fnos_storage_disks(ctx: ToolContext, params: dict) -> dict:
    return _read_only(ctx, params, "storage_disks")


def fnos_file_ls(ctx: ToolContext, params: dict) -> dict:
    return _read_only(ctx, params, "file_ls")


def fnos_docker_ps(ctx: ToolContext, params: dict) -> dict:
    return _read_only(ctx, params, "docker_ps")


def fnos_monitor_cpu(ctx: ToolContext, params: dict) -> dict:
    return _read_only(ctx, params, "monitor_cpu")


# --- deploy/write tools (M3-deploy) -----------------------------------------
# Every write tool: (1) admin role or the manage_deploy capability,
# (2) an explicit confirm=true in the same call, (3) the target profile
# must have allow_dangerous=true (the operator deliberately opted this
# machine in), (4) an audit record with the tool name and params digest.
#
# The CLI adapter validates inputs and raises ValueError before spawning;
# the registry maps that onto the stable invalid_params tool error so a
# bad request never surfaces as a bare exception to an MCP client.

def _write_allowed(ctx: ToolContext, profile: Profile) -> None:
    def _deny(result: str) -> None:
        # A refused write is exactly what the audit log exists for: record
        # it like the panel-side ACL denials (no params, no digest).
        ctx.audit.record("deploy_denied", token_id=ctx.token.id,
                         profile=profile.name, result=result,
                         client_ip=ctx.client_ip)

    if not (ctx.token.role == "admin" or "manage_deploy" in ctx.token.capabilities):
        _deny("forbidden")
        raise ToolError("auth.forbidden", "当前 token 没有部署写权限。")
    if not profile.allow_dangerous:
        _deny("not_allowed")
        raise ToolError("deploy.not_allowed",
                        f"机器 {profile.name} 未开启 allow_dangerous，拒绝写操作。")


def _require_confirm(ctx: ToolContext, params: dict, action: str) -> None:
    if params.get("confirm") is not True:
        raw = params.get("profile") or ctx.pinned_profile
        # Audit metadata only: never trust the caller's string beyond a
        # short label (a full profile name is < 64 chars).
        label = raw[:64] if isinstance(raw, str) else None
        ctx.audit.record("deploy_denied", token_id=ctx.token.id,
                         profile=label,
                         result="confirm_missing", client_ip=ctx.client_ip)
        raise ToolError("deploy.confirm_required",
                        f"{action} 是写操作，必须在同一请求里带 confirm=true。")


def _check_write_rate(ctx: ToolContext, params: dict) -> None:
    """Per-token write gate (mcp_write: 20/60s). Runs only after the
    permission and confirm gates pass, so refused calls don't consume
    quota. The outer mcp_call limit (120/60s) still applies to every
    /mcp request at the HTTP layer; this is the tighter inner gate for
    calls that actually mutate a NAS."""
    if ctx.limiter is None:
        return
    allowed, retry_after = ctx.limiter.check("mcp_write", ctx.token.id)
    if not allowed:
        raw = params.get("profile") or ctx.pinned_profile
        label = raw[:64] if isinstance(raw, str) else None
        ctx.audit.record("deploy_denied", token_id=ctx.token.id,
                         profile=label, result="rate_limited",
                         client_ip=ctx.client_ip)
        raise ToolError("rate_limited",
                        f"写操作过于频繁，请 {retry_after} 秒后再试。")


def _audit_write(ctx: ToolContext, profile: Profile, action: str,
                 params_digest: str, outcome: str) -> None:
    # sub_reason is a whitelisted audit field; the digest carries only a
    # SHA-256 of the confirm-stripped params — no raw values.
    ctx.audit.record(action, token_id=ctx.token.id, profile=profile.name,
                     result=outcome, client_ip=ctx.client_ip,
                     sub_reason=params_digest)


def _params_digest(params: dict) -> str:
    import hashlib
    import json as _json
    cleaned = {k: v for k, v in params.items() if k != "confirm"}
    raw = _json.dumps(cleaned, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()


def _local_upload_dir(ctx: ToolContext):
    """The only directory agents may upload FROM. Everything else in the
    gateway container is either gateway state (tokens.json, panel-auth.json,
    fnos-cli sessions = live NAS credentials) or the app itself; letting a
    write-capable token read-and-exfiltrate those as "upload" is exactly the
    path we must not open. The panel writes files here (uploads/), and
    compose_create stages its YAML here too."""
    d = ctx.state.path.parent / "uploads"
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    return d


def _resolve_local_upload(ctx: ToolContext, local_file: str) -> str:
    """Constrain `local_file` to the gateway upload dir. Accepts either a
    bare name ("app.tar") or an absolute path INSIDE the dir; rejects
    traversal, control characters, symlinks, and non-regular files."""
    from pathlib import Path
    if not isinstance(local_file, str) or not local_file.strip():
        raise ToolError("invalid_params", "local_file 不能为空。")
    raw = local_file.strip()
    if any(ord(c) < 0x20 or ord(c) == 0x7f for c in raw):
        raise ToolError("invalid_params", "local_file 含非法控制字符。")
    if "\\" in raw or "\x00" in raw:
        raise ToolError("invalid_params", "local_file 必须用正斜杠。")
    base = _local_upload_dir(ctx).resolve()
    # Absolute paths are taken as-is (then checked); bare names are joined
    # to the upload dir.
    candidate = Path(raw).resolve() if raw.startswith("/") else (base / raw).resolve()
    if base not in candidate.parents and candidate != base:
        raise ToolError("invalid_params",
                        "local_file 必须是网关上传目录里的文件（不能有 '..'，"
                        "也不能指向目录外）。")
    if not candidate.is_file():
        raise ToolError("invalid_params",
                        f"上传目录里没有这个文件：{candidate.name}（先用面板把"
                        "文件放到 /data/uploads/，或改用 compose_create 的 "
                        "content 参数直接传文本）。")
    if candidate.is_symlink():
        raise ToolError("invalid_params", "local_file 不能是符号链接。")
    return str(candidate)


class _WriteCli:
    """Shared try/except for one adapter write call."""

    def __init__(self, ctx: ToolContext, profile: Profile, action: str,
                 params: dict):
        self.ctx = ctx
        self.profile = profile
        self.action = action
        self.params = params

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is CliError:
            _audit_write(self.ctx, self.profile, self.action,
                         _params_digest(self.params), "failed")
            raise ToolError("cli.failed", str(exc))
        if exc_type is ValueError:
            raise ToolError("invalid_params", str(exc))
        return False


def fnos_file_mkdir(ctx: ToolContext, params: dict) -> dict:
    profile = resolve_profile(ctx, params)
    _write_allowed(ctx, profile)
    _require_confirm(ctx, params, "file mkdir")
    _check_write_rate(ctx, params)
    path = params.get("path", "")
    with _WriteCli(ctx, profile, "file_mkdir", params):
        out = ctx.cli.file_mkdir(profile, path)
    _audit_write(ctx, profile, "file_mkdir", _params_digest(params), "ok")
    return {"profile": profile.name, "path": path, "result": out}


def fnos_file_upload(ctx: ToolContext, params: dict) -> dict:
    profile = resolve_profile(ctx, params)
    _write_allowed(ctx, profile)
    _require_confirm(ctx, params, "file upload")
    _check_write_rate(ctx, params)
    remote_dir = params.get("remote_dir", "")
    local_file = params.get("local_file", "")
    overwrite = params.get("overwrite", "rename")
    checked = _resolve_local_upload(ctx, local_file)
    with _WriteCli(ctx, profile, "file_upload", params):
        out = ctx.cli.file_upload(profile, remote_dir, checked, overwrite)
    _audit_write(ctx, profile, "file_upload", _params_digest(params), "ok")
    return {"profile": profile.name, "remote_dir": remote_dir,
            "local_file": checked, "result": out}


def fnos_file_chown(ctx: ToolContext, params: dict) -> dict:
    profile = resolve_profile(ctx, params)
    _write_allowed(ctx, profile)
    _require_confirm(ctx, params, "file chown")
    _check_write_rate(ctx, params)
    path = params.get("path", "")
    uid = params.get("uid")
    recursive = bool(params.get("recursive", False))
    if not isinstance(uid, int) or isinstance(uid, bool):
        raise ToolError("invalid_params", "uid 必须是整数。")
    with _WriteCli(ctx, profile, "file_chown", params):
        out = ctx.cli.file_chown(profile, path, uid, recursive)
    _audit_write(ctx, profile, "file_chown", _params_digest(params), "ok")
    return {"profile": profile.name, "path": path, "uid": uid, "result": out}


def fnos_docker_container_create(ctx: ToolContext, params: dict) -> dict:
    profile = resolve_profile(ctx, params)
    _write_allowed(ctx, profile)
    _require_confirm(ctx, params, "container create")
    _check_write_rate(ctx, params)
    image = params.get("image", "")
    if not image:
        raise ToolError("invalid_params", "image 必填。")
    with _WriteCli(ctx, profile, "container_create", params):
        out = ctx.cli.docker_container_create(
            profile, image,
            name=params.get("name"),
            start=bool(params.get("start", False)),
            restart=bool(params.get("restart", False)),
            memory_mb=params.get("memory_mb"),
            cpu_shares=params.get("cpu_shares"),
            env=params.get("env"),
            cmd=params.get("cmd"),
            ports=params.get("ports"),
            mounts=params.get("mounts"),
        )
    _audit_write(ctx, profile, "container_create", _params_digest(params), "ok")
    return {"profile": profile.name, "image": image, "result": out}


def fnos_docker_container_remove(ctx: ToolContext, params: dict) -> dict:
    profile = resolve_profile(ctx, params)
    _write_allowed(ctx, profile)
    _require_confirm(ctx, params, "container remove")
    _check_write_rate(ctx, params)
    container = params.get("container", "")
    if not container:
        raise ToolError("invalid_params", "container 必填。")
    with _WriteCli(ctx, profile, "container_remove", params):
        out = ctx.cli.docker_container_remove(
            profile, container, force=bool(params.get("force", False)))
    _audit_write(ctx, profile, "container_remove", _params_digest(params), "ok")
    return {"profile": profile.name, "container": container, "result": out}


def fnos_docker_request(ctx: ToolContext, params: dict) -> dict:
    profile = resolve_profile(ctx, params)
    _write_allowed(ctx, profile)
    _require_confirm(ctx, params, "docker request")
    _check_write_rate(ctx, params)
    endpoint = params.get("endpoint", "")
    body = params.get("body")
    if body is not None and not isinstance(body, dict):
        raise ToolError("invalid_params", "body 必须是 JSON object。")
    with _WriteCli(ctx, profile, "docker_request", params):
        out = ctx.cli.docker_request(profile, endpoint, body)
    _audit_write(ctx, profile, "docker_request", _params_digest(params), "ok")
    return {"profile": profile.name, "endpoint": endpoint, "result": out}


# --- docker compose ------------------------------------------------
# Endpoints recovered from the fnOS Docker app and verified against a
# live NAS (see docs/compose.md). Reads need only a session; lifecycle
# calls are write-gated exactly like the other deploy tools.

def _compose_read(ctx: ToolContext, params: dict, method: str) -> dict:
    profile = resolve_profile(ctx, params)
    project = params.get("project_name")
    try:
        if method == "list":
            return ctx.cli.docker_compose_list(profile)
        if method == "containers":
            return ctx.cli.docker_compose_containers(profile, project or "")
        if method == "logs":
            return ctx.cli.docker_compose_logs(profile, project or "")
        if method == "existing_file":
            return ctx.cli.docker_compose_existing_file(profile, params.get("folder", ""))
    except CliError as exc:
        raise ToolError("cli.failed", str(exc))
    except ValueError as exc:
        raise ToolError("invalid_params", str(exc))
    raise ToolError("invalid_params", f"unknown compose read {method}")


def fnos_docker_compose_list(ctx: ToolContext, params: dict) -> dict:
    return _compose_read(ctx, params, "list")


def fnos_docker_compose_containers(ctx: ToolContext, params: dict) -> dict:
    return _compose_read(ctx, params, "containers")


def fnos_docker_compose_logs(ctx: ToolContext, params: dict) -> dict:
    return _compose_read(ctx, params, "logs")


def fnos_docker_compose_existing_file(ctx: ToolContext, params: dict) -> dict:
    return _compose_read(ctx, params, "existing_file")


def fnos_docker_compose_create(ctx: ToolContext, params: dict) -> dict:
    profile = resolve_profile(ctx, params)
    _write_allowed(ctx, profile)
    _require_confirm(ctx, params, "compose create")
    _check_write_rate(ctx, params)
    folder = params.get("folder", "")
    project_name = params.get("project_name", "")
    file = params.get("file", "docker-compose.yaml")
    auto_build = bool(params.get("auto_build", False))
    content = params.get("content")
    if content is not None:
        if not isinstance(content, str):
            raise ToolError("invalid_params", "content 必须是 YAML 文本。")
        if len(content.encode("utf-8")) > 256 * 1024:
            raise ToolError("invalid_params", "content 不能超过 256KB。")
        if "\x00" in content:
            raise ToolError("invalid_params", "content 不能包含 NUL 字符。")
    digest = _params_digest(params)
    tmp_path = None
    stage_dir = None
    try:
        uploaded = False
        if content is not None:
            import os
            import tempfile
            from ..cli_adapter import _COMPOSE_FILE_RE, normalize_compose_folder
            norm = normalize_compose_folder(folder)
            # The remote name is the LOCAL basename (verified on a real
            # NAS: `file upload` keeps it), and composeCreate references
            # `file` inside `folder`. Stage the YAML under that exact
            # name in a throw-away subdir so nothing else is clobbered.
            if not _COMPOSE_FILE_RE.match(file):
                raise ToolError("invalid_params",
                                "file 必须是 .yml/.yaml 文件名，不能带路径。")
            stage_dir = tempfile.mkdtemp(prefix="compose-",
                                         dir=str(_local_upload_dir(ctx)))
            os.chmod(stage_dir, 0o700)
            tmp_path = os.path.join(stage_dir, file)
            with open(tmp_path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(content if content.endswith("\n") else content + "\n")
            os.chmod(tmp_path, 0o600)
            ctx.cli.file_upload(profile, "/" + norm, tmp_path, "replace")
            uploaded = True
        out = ctx.cli.docker_compose_create(profile, folder, project_name, file, auto_build)
    except CliError as exc:
        _audit_write(ctx, profile, "compose_create", digest, "failed")
        raise ToolError("cli.failed", str(exc))
    except ValueError as exc:
        raise ToolError("invalid_params", str(exc))
    finally:
        if tmp_path is not None:
            import os
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            if stage_dir is not None:
                try:
                    os.rmdir(stage_dir)
                except OSError:
                    pass
    _audit_write(ctx, profile, "compose_create", digest, "ok")
    return {"profile": profile.name, "project": project_name, "folder": folder,
            "file": file, "uploaded": uploaded, "result": out}


def _compose_action(ctx: ToolContext, params: dict, action: str) -> dict:
    profile = resolve_profile(ctx, params)
    _write_allowed(ctx, profile)
    _require_confirm(ctx, params, f"compose {action}")
    _check_write_rate(ctx, params)
    project_name = params.get("project_name", "")
    with _WriteCli(ctx, profile, f"compose_{action}", params):
        out = ctx.cli.docker_compose_action(profile, action, project_name)
    _audit_write(ctx, profile, f"compose_{action}", _params_digest(params), "ok")
    return {"profile": profile.name, "project": project_name,
            "action": action, "result": out}


def fnos_docker_compose_build(ctx: ToolContext, params: dict) -> dict:
    return _compose_action(ctx, params, "build")


def fnos_docker_compose_start(ctx: ToolContext, params: dict) -> dict:
    return _compose_action(ctx, params, "start")


def fnos_docker_compose_stop(ctx: ToolContext, params: dict) -> dict:
    return _compose_action(ctx, params, "stop")


def fnos_docker_compose_restart(ctx: ToolContext, params: dict) -> dict:
    return _compose_action(ctx, params, "restart")


def fnos_docker_compose_clear(ctx: ToolContext, params: dict) -> dict:
    return _compose_action(ctx, params, "clear")


def fnos_docker_compose_delete(ctx: ToolContext, params: dict) -> dict:
    return _compose_action(ctx, params, "delete")


def fnos_docker_compose_cancel(ctx: ToolContext, params: dict) -> dict:
    return _compose_action(ctx, params, "cancel")


def tool_group(name: str) -> str:
    """Coarse capability grouping used by the panel's capability page."""
    if name.startswith("fnos_docker_compose"):
        return "Docker Compose"
    if name in ("fnos_docker_ps", "fnos_docker_container_create",
                "fnos_docker_container_remove", "fnos_docker_request"):
        return "Docker 容器"
    if name.startswith("fnos_file_"):
        return "文件"
    if name.startswith("fnos_monitor_"):
        return "监控"
    if name.startswith("fnos_system_") or name.startswith("fnos_storage_"):
        return "系统与存储"
    return "会话与状态"


def tool_kind(name: str) -> str:
    schema = TOOLS[name][2]
    return "write" if "confirm" in schema.get("properties", {}) else "read"


def tool_catalog() -> list[dict]:
    """Stable, UI-friendly view of every registered tool.

    Derived from TOOLS so the panel can never drift from what the MCP
    server actually exposes (tests compare tool_catalog() with the MCP
    tool list)."""
    from ..cli_adapter import COMPOSE_ACTIONS, COMPOSE_ENDPOINTS
    compose_by_tool = {
        "fnos_docker_compose_list": COMPOSE_ENDPOINTS["list"],
        "fnos_docker_compose_containers": COMPOSE_ENDPOINTS["containers"],
        "fnos_docker_compose_logs": COMPOSE_ENDPOINTS["logs"],
        "fnos_docker_compose_existing_file": COMPOSE_ENDPOINTS["existing_file"],
        "fnos_docker_compose_create": COMPOSE_ENDPOINTS["create"],
    }
    for action, endpoint in COMPOSE_ACTIONS.items():
        compose_by_tool[f"fnos_docker_compose_{action}"] = endpoint
    catalog = []
    for name, (_func, description, schema) in TOOLS.items():
        kind = tool_kind(name)
        catalog.append({
            "name": name,
            "description": description,
            "group": tool_group(name),
            "kind": kind,
            "required": list(schema.get("required", [])),
            "endpoint": compose_by_tool.get(name),
            "gates": (["admin 或 manage_deploy", "allow_dangerous", "confirm=true"]
                      if kind == "write" else []),
        })
    return catalog


TOOLS = {
    "fnos_profiles": (fnos_profiles, "列出当前 token 允许的 profile。", {"type": "object", "properties": {}}),
    "fnos_login_start": (fnos_login_start, "生成授权链接（两步登录第一步）。", {"type": "object", "properties": {"profile": {"type": "string"}}}),
    "fnos_login_finish": (fnos_login_finish, "提交一次性 code 完成登录。", {"type": "object", "properties": {"profile": {"type": "string"}, "code": {"type": "string"}}, "required": ["code"]}),
    "fnos_logout": (fnos_logout, "清理本机 session（不撤销 NAS 端授权）。", {"type": "object", "properties": {"profile": {"type": "string"}}}),
    "fnos_status": (fnos_status, "连接/登录状态概览。", {"type": "object", "properties": {"profile": {"type": "string"}}}),
    "fnos_system_info": (fnos_system_info, "机器类型、版本、硬件；不用于判断登录。", {"type": "object", "properties": {"profile": {"type": "string"}}}),
    "fnos_storage_overview": (fnos_storage_overview, "存储总览。", {"type": "object", "properties": {"profile": {"type": "string"}}}),
    "fnos_storage_pools": (fnos_storage_pools, "存储池。", {"type": "object", "properties": {"profile": {"type": "string"}}}),
    "fnos_storage_disks": (fnos_storage_disks, "磁盘。", {"type": "object", "properties": {"profile": {"type": "string"}}}),
    "fnos_file_ls": (fnos_file_ls, "列目录。", {"type": "object", "properties": {"profile": {"type": "string"}, "path": {"type": "string"}}}),
    "fnos_docker_ps": (fnos_docker_ps, "容器列表。", {"type": "object", "properties": {"profile": {"type": "string"}}}),
    "fnos_monitor_cpu": (fnos_monitor_cpu, "CPU；需要 session，可作认证探测。", {"type": "object", "properties": {"profile": {"type": "string"}}}),
    # --- deploy/write tools: admin or manage_deploy capability, target
    # profile must have allow_dangerous=true, confirm=true required.
    "fnos_file_mkdir": (fnos_file_mkdir, "在目标机器上创建目录（写操作）。", {
        "type": "object",
        "properties": {"profile": {"type": "string"}, "path": {"type": "string"},
                       "confirm": {"type": "boolean"}},
        "required": ["path", "confirm"]}),
    "fnos_file_upload": (fnos_file_upload, "把网关本地的文件上传到目标机器目录（写操作）。", {
        "type": "object",
        "properties": {"profile": {"type": "string"}, "remote_dir": {"type": "string"},
                       "local_file": {"type": "string"},
                       "overwrite": {"type": "string", "enum": ["skip", "replace", "rename"]},
                       "confirm": {"type": "boolean"}},
        "required": ["remote_dir", "local_file", "confirm"]}),
    "fnos_file_chown": (fnos_file_chown, "修改目标机器上文件/目录的属主 uid（写操作）。", {
        "type": "object",
        "properties": {"profile": {"type": "string"}, "path": {"type": "string"},
                       "uid": {"type": "integer"}, "recursive": {"type": "boolean"},
                       "confirm": {"type": "boolean"}},
        "required": ["path", "uid", "confirm"]}),
    "fnos_docker_container_create": (fnos_docker_container_create, "创建容器（写操作）；cmd 每项不能含空格，复杂命令走 fnos_docker_request(containerCreate)。", {
        "type": "object",
        "properties": {"profile": {"type": "string"}, "image": {"type": "string"},
                       "name": {"type": "string"}, "start": {"type": "boolean"},
                       "restart": {"type": "boolean"}, "memory_mb": {"type": "integer"},
                       "cpu_shares": {"type": "integer"},
                       "env": {"type": "array", "items": {"type": "string"}},
                       "cmd": {"type": "array", "items": {"type": "string"}},
                       "ports": {"type": "array", "items": {"type": "string"}},
                       "mounts": {"type": "array", "items": {"type": "string"}},
                       "confirm": {"type": "boolean"}},
        "required": ["image", "confirm"]}),
    "fnos_docker_container_remove": (fnos_docker_container_remove, "删除容器（写操作）。", {
        "type": "object",
        "properties": {"profile": {"type": "string"}, "container": {"type": "string"},
                       "force": {"type": "boolean"}, "confirm": {"type": "boolean"}},
        "required": ["container", "confirm"]}),
    "fnos_docker_request": (fnos_docker_request, "调用 appcgi.dockermgr.* 兜底端点（写操作）。endpoint 只写端点名，body 不能含 req/reqid。", {
        "type": "object",
        "properties": {"profile": {"type": "string"}, "endpoint": {"type": "string"},
                       "body": {"type": "object"}, "confirm": {"type": "boolean"}},
        "required": ["endpoint", "confirm"]}),
    # --- docker compose (reads need a session; lifecycle is write-gated).
    "fnos_docker_compose_list": (fnos_docker_compose_list, "列出 compose 项目及状态（只读）。", {
        "type": "object", "properties": {"profile": {"type": "string"}}}),
    "fnos_docker_compose_containers": (fnos_docker_compose_containers, "列出某个 compose 项目下的容器（只读）。", {
        "type": "object",
        "properties": {"profile": {"type": "string"}, "project_name": {"type": "string"}},
        "required": ["project_name"]}),
    "fnos_docker_compose_logs": (fnos_docker_compose_logs, "读取某个 compose 项目的日志（只读）。", {
        "type": "object",
        "properties": {"profile": {"type": "string"}, "project_name": {"type": "string"}},
        "required": ["project_name"]}),
    "fnos_docker_compose_existing_file": (fnos_docker_compose_existing_file, "查看目录里已有的 compose 文件（只读）。", {
        "type": "object",
        "properties": {"profile": {"type": "string"}, "folder": {"type": "string"}},
        "required": ["folder"]}),
    "fnos_docker_compose_create": (fnos_docker_compose_create, "在目标机目录创建 compose 项目（写操作）；可带 content 直接写入 YAML。", {
        "type": "object",
        "properties": {"profile": {"type": "string"}, "folder": {"type": "string"},
                       "project_name": {"type": "string"}, "file": {"type": "string"},
                       "content": {"type": "string"}, "auto_build": {"type": "boolean"},
                       "confirm": {"type": "boolean"}},
        "required": ["folder", "project_name", "confirm"]}),
    "fnos_docker_compose_build": (fnos_docker_compose_build, "构建 compose 项目镜像（写操作）。", {
        "type": "object",
        "properties": {"profile": {"type": "string"}, "project_name": {"type": "string"},
                       "confirm": {"type": "boolean"}},
        "required": ["project_name", "confirm"]}),
    "fnos_docker_compose_start": (fnos_docker_compose_start, "启动 compose 项目（写操作）。", {
        "type": "object",
        "properties": {"profile": {"type": "string"}, "project_name": {"type": "string"},
                       "confirm": {"type": "boolean"}},
        "required": ["project_name", "confirm"]}),
    "fnos_docker_compose_stop": (fnos_docker_compose_stop, "停止 compose 项目（写操作）。", {
        "type": "object",
        "properties": {"profile": {"type": "string"}, "project_name": {"type": "string"},
                       "confirm": {"type": "boolean"}},
        "required": ["project_name", "confirm"]}),
    "fnos_docker_compose_restart": (fnos_docker_compose_restart, "重启 compose 项目（写操作）。", {
        "type": "object",
        "properties": {"profile": {"type": "string"}, "project_name": {"type": "string"},
                       "confirm": {"type": "boolean"}},
        "required": ["project_name", "confirm"]}),
    "fnos_docker_compose_clear": (fnos_docker_compose_clear, "清理 compose 项目（保留项目，写操作）。", {
        "type": "object",
        "properties": {"profile": {"type": "string"}, "project_name": {"type": "string"},
                       "confirm": {"type": "boolean"}},
        "required": ["project_name", "confirm"]}),
    "fnos_docker_compose_delete": (fnos_docker_compose_delete, "删除 compose 项目（写操作）。", {
        "type": "object",
        "properties": {"profile": {"type": "string"}, "project_name": {"type": "string"},
                       "confirm": {"type": "boolean"}},
        "required": ["project_name", "confirm"]}),
    "fnos_docker_compose_cancel": (fnos_docker_compose_cancel, "取消正在进行的 compose 构建（写操作）。", {
        "type": "object",
        "properties": {"profile": {"type": "string"}, "project_name": {"type": "string"},
                       "confirm": {"type": "boolean"}},
        "required": ["project_name", "confirm"]}),
}


def call_tool(ctx: ToolContext, name: str, params: dict | None) -> dict:
    if name not in TOOLS:
        raise ToolError("invalid_params", f"未知工具 {name}。")
    func = TOOLS[name][0]
    return func(ctx, params or {})
