"""Docker compose tools (M6.1).

Endpoints and payload shapes were recovered from the fnOS Docker app
bundle and verified on a live NAS (composeList / composeContainers /
composeLog / composeExistingFile). These tests pin the tool surface,
the write gates and the argument validation.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from fnos_mcp.audit import AuditLog
from fnos_mcp.cli_adapter import FnosCli, normalize_compose_folder
from fnos_mcp.config import load_profiles, load_tokens
from fnos_mcp.runner import CliRunner
from fnos_mcp.state_store import PanelStateStore
from fnos_mcp.tools.registry import (TOOLS, ToolContext, ToolError, call_tool,
                                     tool_catalog, tool_group, tool_kind)

FAKE_CLI = str(Path(__file__).resolve().parent / "fake_cli.py")


@pytest.fixture()
def ctx(tmp_path, profiles_path, tokens_path, monkeypatch):
    monkeypatch.setenv("FNOS_FAKE_STATE_FILE", str(tmp_path / "state.json"))
    monkeypatch.setenv("FNOS_FAKE_ARGV_LOG", str(tmp_path / "fake-argv.log"))
    runner = CliRunner(FAKE_CLI, str(tmp_path), str(tmp_path))
    return ToolContext(
        token=load_tokens(tokens_path)[0], profiles=load_profiles(profiles_path),
        cli=FnosCli(runner), state=PanelStateStore(tmp_path / "panel-state.json"),
        audit=AuditLog(tmp_path / "audit.jsonl"), client_ip="127.0.0.1")


def _allow(ctx):
    for prof in ctx.profiles.profiles.values():
        prof.allow_dangerous = True


def test_compose_read_tools(ctx):
    out = call_tool(ctx, "fnos_docker_compose_list", {"profile": "home"})
    assert out["projects"][0]["Name"] == "demo"
    out = call_tool(ctx, "fnos_docker_compose_containers",
                    {"profile": "home", "project_name": "demo"})
    assert out["containers"][0]["Names"] == "demo"
    out = call_tool(ctx, "fnos_docker_compose_logs",
                    {"profile": "home", "project_name": "demo"})
    assert "Started" in out["logs"][0]
    out = call_tool(ctx, "fnos_docker_compose_existing_file",
                    {"profile": "home", "folder": "/vol1/1000/docker/demo"})
    assert out["config_files"] == "compose.yaml"


def test_compose_read_rejects_bad_project_name(ctx):
    with pytest.raises(ToolError) as exc:
        call_tool(ctx, "fnos_docker_compose_containers",
                  {"profile": "home", "project_name": "_bad"})
    assert exc.value.code == "invalid_params"


def test_compose_create_without_content(ctx):
    _allow(ctx)
    out = call_tool(ctx, "fnos_docker_compose_create",
                    {"profile": "home", "folder": "vol1/1000/docker/demo",
                     "project_name": "demo", "file": "compose.yaml",
                     "confirm": True})
    assert out["uploaded"] is False
    assert out["result"]["errno"] == 0


def test_compose_create_with_content_uploads_yaml(ctx):
    _allow(ctx)
    # The argv log records every fake-CLI invocation; use it to pin the
    # upload target and the composeCreate file argument to the same name.
    import os
    argv_log = Path(os.environ["FNOS_FAKE_ARGV_LOG"]) \
        if os.environ.get("FNOS_FAKE_ARGV_LOG") else None
    out = call_tool(ctx, "fnos_docker_compose_create",
                    {"profile": "home", "folder": "/vol1/1000/docker/demo",
                     "project_name": "demo", "content": "services: {}\n",
                     "confirm": True})
    assert out["uploaded"] is True
    # The staged YAML must not survive the call.
    uploads = Path(ctx.state.path.parent) / "uploads"
    assert not list(uploads.glob("compose-*"))
    if argv_log is not None and argv_log.exists():
        calls = [json.loads(line)["argv"] for line in
                 argv_log.read_text(encoding="utf-8").splitlines()]
        uploads_argv = [a for a in calls if "upload" in a]
        creates = [a for a in calls
                   if any("composeCreate" in item for item in a)]
        assert uploads_argv and creates
        # CLI upload keeps the local basename (verified on a real NAS):
        # the uploaded file name must equal composeCreate's `file` arg.
        uploaded_name = Path(uploads_argv[0][uploads_argv[0].index("upload") + 2]).name
        create_body = json.loads(creates[0][creates[0].index("--json") + 1])
        assert uploaded_name == create_body["file"] == "docker-compose.yaml"
    # An explicit `file` name is honored for both the upload and create.
    out = call_tool(ctx, "fnos_docker_compose_create",
                    {"profile": "home", "folder": "/vol1/1000/docker/demo",
                     "project_name": "demo", "file": "compose.yaml",
                     "content": "services: {}\n", "confirm": True})
    assert out["file"] == "compose.yaml"
    assert not list(uploads.glob("compose-*"))


def test_compose_create_content_limit(ctx):
    _allow(ctx)
    with pytest.raises(ToolError) as exc:
        call_tool(ctx, "fnos_docker_compose_create",
                  {"profile": "home", "folder": "vol1/1000/docker/demo",
                   "project_name": "demo", "content": "x" * (256 * 1024 + 1),
                   "confirm": True})
    assert exc.value.code == "invalid_params"


def test_compose_create_gates(ctx):
    # allow_dangerous off (fixture default)
    with pytest.raises(ToolError) as exc:
        call_tool(ctx, "fnos_docker_compose_create",
                  {"profile": "home", "folder": "vol1/1000/docker/demo",
                   "project_name": "demo", "confirm": True})
    assert exc.value.code == "deploy.not_allowed"
    _allow(ctx)
    with pytest.raises(ToolError) as exc:
        call_tool(ctx, "fnos_docker_compose_create",
                  {"profile": "home", "folder": "vol1/1000/docker/demo",
                   "project_name": "demo"})
    assert exc.value.code == "deploy.confirm_required"
    ctx.token.role = "operator"
    ctx.token.capabilities = []
    with pytest.raises(ToolError) as exc:
        call_tool(ctx, "fnos_docker_compose_create",
                  {"profile": "home", "folder": "vol1/1000/docker/demo",
                   "project_name": "demo", "confirm": True})
    assert exc.value.code == "auth.forbidden"


def test_compose_action_happy_path_and_audit(ctx):
    _allow(ctx)
    for action in ("build", "start", "stop", "restart", "clear", "delete", "cancel"):
        out = call_tool(ctx, f"fnos_docker_compose_{action}",
                        {"profile": "home", "project_name": "demo", "confirm": True})
        assert out["action"] == action
        assert out["result"]["errno"] == 0
    events = [json.loads(line) for line in
              ctx.audit.path.read_text(encoding="utf-8").splitlines()]
    actions = {e.get("event") for e in events}
    assert {"compose_build", "compose_start", "compose_delete"} <= actions
    ok = [e for e in events if e.get("event") == "compose_start"
          and e.get("result") == "ok"]
    assert ok and len(ok[0].get("sub_reason")) == 64


def test_compose_action_validation(ctx):
    _allow(ctx)
    for bad in ("Bad Name", "_demo", "-demo", "demo!", "a" * 64):
        with pytest.raises(ToolError) as exc:
            call_tool(ctx, "fnos_docker_compose_start",
                      {"profile": "home", "project_name": bad, "confirm": True})
        assert exc.value.code == "invalid_params"
    with pytest.raises(ValueError):
        normalize_compose_folder("/vol1/../etc")
    with pytest.raises(ValueError):
        normalize_compose_folder("etc/passwd")
    with pytest.raises(ValueError):
        ctx.cli.docker_compose_create(ctx.profiles.profiles["home"],
                                      "vol1/1000/docker/x", "demo",
                                      file="../../etc/passwd")


def test_compose_action_requires_confirm(ctx):
    _allow(ctx)
    with pytest.raises(ToolError) as exc:
        call_tool(ctx, "fnos_docker_compose_stop",
                  {"profile": "home", "project_name": "demo"})
    assert exc.value.code == "deploy.confirm_required"


def test_catalog_matches_registry(ctx):
    catalog = tool_catalog()
    assert len(catalog) == len(TOOLS) == 30
    names = {item["name"] for item in catalog}
    assert names == set(TOOLS)
    compose = [item for item in catalog if item["group"] == "Docker Compose"]
    assert len(compose) == 12
    by_name = {item["name"]: item for item in catalog}
    assert by_name["fnos_docker_compose_start"]["kind"] == "write"
    assert by_name["fnos_docker_compose_start"]["endpoint"] == \
        "appcgi.dockermgr.composeStart"
    assert by_name["fnos_docker_compose_list"]["kind"] == "read"
    assert by_name["fnos_docker_compose_list"]["gates"] == []
    assert tool_kind("fnos_docker_compose_list") == "read"
    assert tool_group("fnos_file_upload") == "文件"
    assert tool_group("fnos_profiles") == "会话与状态"
