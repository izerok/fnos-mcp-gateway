"""FastMCP 2 transport for the P0 read tools + deploy write tools (M2/M3).

The tool LOGIC lives in tools/registry.py and is untouched here; this
module only adapts it to FastMCP 2 (Streamable HTTP, POST /mcp).

Authentication: the HTTP layer is wrapped by _McpAuthApp in server.py,
which verifies the Bearer token and puts the TokenRecord, the
X-FNOS-Profile pin and the client IP into contextvars before FastMCP
handles the request. Tool wrappers read them from there — FastMCP
itself never sees a raw token. The in-process Client used by tests
bypasses HTTP, so tests set the same contextvars explicitly.
"""

import contextvars
from typing import Optional

from fastmcp import FastMCP

from .config import TokenRecord
from .tools.registry import TOOLS, ToolContext, ToolError, call_tool

_TOKEN: contextvars.ContextVar[Optional[TokenRecord]] = contextvars.ContextVar(
    "fnos_mcp_token", default=None)
_PINNED: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "fnos_mcp_pinned_profile", default=None)
_CLIENT_IP: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "fnos_mcp_client_ip", default=None)


def _ctx(service) -> ToolContext:
    token = _TOKEN.get()
    if token is None:
        raise ToolError("auth.required", "未认证。")
    from .config import load_profiles
    return ToolContext(
        token=token,
        profiles=load_profiles(service.profiles_path),
        cli=service.cli,
        state=service.state,
        audit=service.audit,
        client_ip=_CLIENT_IP.get(),
        pinned_profile=_PINNED.get(),
        limiter=service.limiter,
    )


def _call(service, name: str, params: dict) -> dict:
    try:
        return call_tool(_ctx(service), name, params)
    except ToolError as exc:
        # FastMCP turns a raised exception into an isError tool result;
        # keep the stable code as a prefix so clients can match on it.
        raise RuntimeError(f"{exc.code}: {exc.message}") from exc


def build_fastmcp(service) -> FastMCP:
    """Register the 12 P0 tools on a FastMCP server bound to `service`."""
    mcp = FastMCP("fnos-mcp")

    @mcp.tool(description=TOOLS["fnos_profiles"][1])
    async def fnos_profiles(profile: Optional[str] = None) -> dict:
        return _call(service, "fnos_profiles", {"profile": profile} if profile else {})

    @mcp.tool(description=TOOLS["fnos_login_start"][1])
    async def fnos_login_start(profile: Optional[str] = None) -> dict:
        return _call(service, "fnos_login_start", {"profile": profile} if profile else {})

    @mcp.tool(description=TOOLS["fnos_login_finish"][1])
    async def fnos_login_finish(code: str, profile: Optional[str] = None) -> dict:
        params: dict = {"code": code}
        if profile:
            params["profile"] = profile
        return _call(service, "fnos_login_finish", params)

    @mcp.tool(description=TOOLS["fnos_logout"][1])
    async def fnos_logout(profile: Optional[str] = None) -> dict:
        return _call(service, "fnos_logout", {"profile": profile} if profile else {})

    @mcp.tool(description=TOOLS["fnos_status"][1])
    async def fnos_status(profile: Optional[str] = None) -> dict:
        return _call(service, "fnos_status", {"profile": profile} if profile else {})

    @mcp.tool(description=TOOLS["fnos_system_info"][1])
    async def fnos_system_info(profile: Optional[str] = None) -> dict:
        return _call(service, "fnos_system_info", {"profile": profile} if profile else {})

    @mcp.tool(description=TOOLS["fnos_storage_overview"][1])
    async def fnos_storage_overview(profile: Optional[str] = None) -> dict:
        return _call(service, "fnos_storage_overview", {"profile": profile} if profile else {})

    @mcp.tool(description=TOOLS["fnos_storage_pools"][1])
    async def fnos_storage_pools(profile: Optional[str] = None) -> dict:
        return _call(service, "fnos_storage_pools", {"profile": profile} if profile else {})

    @mcp.tool(description=TOOLS["fnos_storage_disks"][1])
    async def fnos_storage_disks(profile: Optional[str] = None) -> dict:
        return _call(service, "fnos_storage_disks", {"profile": profile} if profile else {})

    @mcp.tool(description=TOOLS["fnos_file_ls"][1])
    async def fnos_file_ls(profile: Optional[str] = None, path: str = "/") -> dict:
        params: dict = {"path": path}
        if profile:
            params["profile"] = profile
        return _call(service, "fnos_file_ls", params)

    @mcp.tool(description=TOOLS["fnos_docker_ps"][1])
    async def fnos_docker_ps(profile: Optional[str] = None) -> dict:
        return _call(service, "fnos_docker_ps", {"profile": profile} if profile else {})

    @mcp.tool(description=TOOLS["fnos_monitor_cpu"][1])
    async def fnos_monitor_cpu(profile: Optional[str] = None) -> dict:
        return _call(service, "fnos_monitor_cpu", {"profile": profile} if profile else {})

    # --- deploy/write tools (M3-deploy): each requires confirm=true and
    # is gated server-side (admin/manage_deploy + profile allow_dangerous).

    @mcp.tool(description=TOOLS["fnos_file_mkdir"][1])
    async def fnos_file_mkdir(profile: Optional[str] = None, path: str = "",
                              confirm: bool = False) -> dict:
        params: dict = {"path": path, "confirm": confirm}
        if profile:
            params["profile"] = profile
        return _call(service, "fnos_file_mkdir", params)

    @mcp.tool(description=TOOLS["fnos_file_upload"][1])
    async def fnos_file_upload(profile: Optional[str] = None, remote_dir: str = "",
                               local_file: str = "",
                               overwrite: Optional[str] = None,
                               confirm: bool = False) -> dict:
        params: dict = {"remote_dir": remote_dir, "local_file": local_file,
                        "confirm": confirm}
        if profile:
            params["profile"] = profile
        if overwrite:
            params["overwrite"] = overwrite
        return _call(service, "fnos_file_upload", params)

    @mcp.tool(description=TOOLS["fnos_file_chown"][1])
    async def fnos_file_chown(profile: Optional[str] = None, path: str = "",
                              uid: int = 0, recursive: bool = False,
                              confirm: bool = False) -> dict:
        params: dict = {"path": path, "uid": uid, "recursive": recursive,
                        "confirm": confirm}
        if profile:
            params["profile"] = profile
        return _call(service, "fnos_file_chown", params)

    @mcp.tool(description=TOOLS["fnos_docker_container_create"][1])
    async def fnos_docker_container_create(
            profile: Optional[str] = None, image: str = "",
            name: Optional[str] = None, start: bool = False,
            restart: bool = False, memory_mb: Optional[int] = None,
            cpu_shares: Optional[int] = None,
            env: Optional[list[str]] = None, cmd: Optional[list[str]] = None,
            ports: Optional[list[str]] = None, mounts: Optional[list[str]] = None,
            confirm: bool = False) -> dict:
        params: dict = {"image": image, "start": start, "restart": restart,
                        "confirm": confirm}
        if profile:
            params["profile"] = profile
        for key, value in (("name", name), ("memory_mb", memory_mb),
                           ("cpu_shares", cpu_shares), ("env", env),
                           ("cmd", cmd), ("ports", ports), ("mounts", mounts)):
            if value is not None:
                params[key] = value
        return _call(service, "fnos_docker_container_create", params)

    @mcp.tool(description=TOOLS["fnos_docker_container_remove"][1])
    async def fnos_docker_container_remove(profile: Optional[str] = None,
                                           container: str = "",
                                           force: bool = False,
                                           confirm: bool = False) -> dict:
        params: dict = {"container": container, "force": force,
                        "confirm": confirm}
        if profile:
            params["profile"] = profile
        return _call(service, "fnos_docker_container_remove", params)

    @mcp.tool(description=TOOLS["fnos_docker_request"][1])
    async def fnos_docker_request(profile: Optional[str] = None,
                                  endpoint: str = "",
                                  body: Optional[dict] = None,
                                  confirm: bool = False) -> dict:
        params: dict = {"endpoint": endpoint, "confirm": confirm}
        if profile:
            params["profile"] = profile
        if body is not None:
            params["body"] = body
        return _call(service, "fnos_docker_request", params)

    # --- docker compose (M6.1): reads + write-gated lifecycle.

    @mcp.tool(description=TOOLS["fnos_docker_compose_list"][1])
    async def fnos_docker_compose_list(profile: Optional[str] = None) -> dict:
        return _call(service, "fnos_docker_compose_list",
                     {"profile": profile} if profile else {})

    @mcp.tool(description=TOOLS["fnos_docker_compose_containers"][1])
    async def fnos_docker_compose_containers(project_name: str,
                                             profile: Optional[str] = None) -> dict:
        params: dict = {"project_name": project_name}
        if profile:
            params["profile"] = profile
        return _call(service, "fnos_docker_compose_containers", params)

    @mcp.tool(description=TOOLS["fnos_docker_compose_logs"][1])
    async def fnos_docker_compose_logs(project_name: str,
                                       profile: Optional[str] = None) -> dict:
        params: dict = {"project_name": project_name}
        if profile:
            params["profile"] = profile
        return _call(service, "fnos_docker_compose_logs", params)

    @mcp.tool(description=TOOLS["fnos_docker_compose_existing_file"][1])
    async def fnos_docker_compose_existing_file(folder: str,
                                                profile: Optional[str] = None) -> dict:
        params: dict = {"folder": folder}
        if profile:
            params["profile"] = profile
        return _call(service, "fnos_docker_compose_existing_file", params)

    @mcp.tool(description=TOOLS["fnos_docker_compose_create"][1])
    async def fnos_docker_compose_create(folder: str, project_name: str,
                                         file: Optional[str] = None,
                                         content: Optional[str] = None,
                                         auto_build: bool = False,
                                         confirm: bool = False,
                                         profile: Optional[str] = None) -> dict:
        params: dict = {"folder": folder, "project_name": project_name,
                        "auto_build": auto_build, "confirm": confirm}
        if profile:
            params["profile"] = profile
        if file:
            params["file"] = file
        if content is not None:
            params["content"] = content
        return _call(service, "fnos_docker_compose_create", params)

    @mcp.tool(description=TOOLS["fnos_docker_compose_build"][1])
    async def fnos_docker_compose_build(project_name: str, confirm: bool = False,
                                        profile: Optional[str] = None) -> dict:
        params: dict = {"project_name": project_name, "confirm": confirm}
        if profile:
            params["profile"] = profile
        return _call(service, "fnos_docker_compose_build", params)

    @mcp.tool(description=TOOLS["fnos_docker_compose_start"][1])
    async def fnos_docker_compose_start(project_name: str, confirm: bool = False,
                                        profile: Optional[str] = None) -> dict:
        params: dict = {"project_name": project_name, "confirm": confirm}
        if profile:
            params["profile"] = profile
        return _call(service, "fnos_docker_compose_start", params)

    @mcp.tool(description=TOOLS["fnos_docker_compose_stop"][1])
    async def fnos_docker_compose_stop(project_name: str, confirm: bool = False,
                                       profile: Optional[str] = None) -> dict:
        params: dict = {"project_name": project_name, "confirm": confirm}
        if profile:
            params["profile"] = profile
        return _call(service, "fnos_docker_compose_stop", params)

    @mcp.tool(description=TOOLS["fnos_docker_compose_restart"][1])
    async def fnos_docker_compose_restart(project_name: str, confirm: bool = False,
                                          profile: Optional[str] = None) -> dict:
        params: dict = {"project_name": project_name, "confirm": confirm}
        if profile:
            params["profile"] = profile
        return _call(service, "fnos_docker_compose_restart", params)

    @mcp.tool(description=TOOLS["fnos_docker_compose_clear"][1])
    async def fnos_docker_compose_clear(project_name: str, confirm: bool = False,
                                        profile: Optional[str] = None) -> dict:
        params: dict = {"project_name": project_name, "confirm": confirm}
        if profile:
            params["profile"] = profile
        return _call(service, "fnos_docker_compose_clear", params)

    @mcp.tool(description=TOOLS["fnos_docker_compose_delete"][1])
    async def fnos_docker_compose_delete(project_name: str, confirm: bool = False,
                                         profile: Optional[str] = None) -> dict:
        params: dict = {"project_name": project_name, "confirm": confirm}
        if profile:
            params["profile"] = profile
        return _call(service, "fnos_docker_compose_delete", params)

    @mcp.tool(description=TOOLS["fnos_docker_compose_cancel"][1])
    async def fnos_docker_compose_cancel(project_name: str, confirm: bool = False,
                                         profile: Optional[str] = None) -> dict:
        params: dict = {"project_name": project_name, "confirm": confirm}
        if profile:
            params["profile"] = profile
        return _call(service, "fnos_docker_compose_cancel", params)

    return mcp
