"""Deploy/write tools (M3-deploy): fnos_file_mkdir/upload/chown,
fnos_docker_container_create/remove, fnos_docker_request.

Gates under test, per tool:
- admin or manage_deploy capability (operator denied)
- explicit confirm=true in the same call
- target profile must have allow_dangerous=true
- host/port/scheme rejected (same as read tools)
- audit record written on success and failure
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from fnos_mcp.audit import AuditLog
from fnos_mcp.cli_adapter import FnosCli
from fnos_mcp.config import load_profiles, load_tokens
from fnos_mcp.runner import CliRunner
from fnos_mcp.state_store import PanelStateStore
from fnos_mcp.tools.registry import ToolContext, ToolError, call_tool

FAKE_CLI = str(Path(__file__).resolve().parent / "fake_cli.py")


@pytest.fixture()
def ctx(tmp_path, profiles_path, tokens_path, monkeypatch):
    monkeypatch.setenv("FNOS_FAKE_STATE_FILE", str(tmp_path / "state.json"))
    monkeypatch.setenv("FNOS_FAKE_ARGV_LOG", str(tmp_path / "argv.log"))
    runner = CliRunner(FAKE_CLI, str(tmp_path), str(tmp_path))
    profiles = load_profiles(profiles_path)
    tokens = load_tokens(tokens_path)
    return ToolContext(
        token=tokens[0], profiles=profiles, cli=FnosCli(runner),
        state=PanelStateStore(tmp_path / "panel-state.json"),
        audit=AuditLog(tmp_path / "audit.jsonl"), client_ip="127.0.0.1")


def _allow(ctx):
    """Opt both fixture profiles into deploy writes."""
    for name, prof in ctx.profiles.profiles.items():
        prof.allow_dangerous = True


def test_write_requires_admin(ctx):
    _allow(ctx)
    ctx.token.capabilities = []
    ctx.token.role = "operator"
    with pytest.raises(ToolError) as exc:
        call_tool(ctx, "fnos_file_mkdir",
                  {"profile": "home", "path": "/vol1/x", "confirm": True})
    assert exc.value.code == "auth.forbidden"


def test_write_allows_manage_deploy_capability(ctx):
    _allow(ctx)
    ctx.token.role = "operator"
    ctx.token.capabilities = ["manage_deploy"]
    out = call_tool(ctx, "fnos_file_mkdir",
                    {"profile": "home", "path": "/vol1/deploy", "confirm": True})
    assert out["result"]["result"] == "succ"


def test_write_requires_confirm(ctx):
    _allow(ctx)
    with pytest.raises(ToolError) as exc:
        call_tool(ctx, "fnos_file_mkdir", {"profile": "home", "path": "/vol1/x"})
    assert exc.value.code == "deploy.confirm_required"
    with pytest.raises(ToolError) as exc:
        call_tool(ctx, "fnos_file_mkdir",
                  {"profile": "home", "path": "/vol1/x", "confirm": False})
    assert exc.value.code == "deploy.confirm_required"


def test_write_requires_allow_dangerous_profile(ctx):
    # profiles.json fixture has no allow_dangerous; the gate must fire
    # even for admin + confirm.
    with pytest.raises(ToolError) as exc:
        call_tool(ctx, "fnos_file_mkdir",
                  {"profile": "home", "path": "/vol1/x", "confirm": True})
    assert exc.value.code == "deploy.not_allowed"


def test_write_rejects_host_params(ctx):
    _allow(ctx)
    with pytest.raises(ToolError) as exc:
        call_tool(ctx, "fnos_file_mkdir",
                  {"profile": "home", "path": "/vol1/x", "confirm": True,
                   "host": "1.2.3.4"})
    assert exc.value.code == "invalid_params"


def test_file_mkdir_rejects_relative_and_traversal(ctx):
    _allow(ctx)
    for bad in ("vol1/x", "/vol1/../etc", "/vol1/a/../b"):
        with pytest.raises(ValueError):
            ctx.cli.file_mkdir(ctx.profiles.profiles["home"], bad)


def test_file_upload_validation(ctx):
    _allow(ctx)
    with pytest.raises(ValueError):
        ctx.cli.file_upload(ctx.profiles.profiles["home"], "/vol1", "f.txt",
                            "clobber")
    # local_file must point at a file inside the gateway upload dir;
    # the fixture file doesn't exist there yet.
    with pytest.raises(ToolError) as exc:
        call_tool(ctx, "fnos_file_upload",
                  {"profile": "home", "remote_dir": "/vol1/deploy",
                   "local_file": "/tmp/compose.yaml",
                   "overwrite": "replace", "confirm": True})
    assert exc.value.code == "invalid_params"
    # Stage a file in the upload dir, then upload by bare name.
    from fnos_mcp.tools.registry import _local_upload_dir
    up = _local_upload_dir(ctx)
    (up / "app.tar").write_bytes(b"fake")
    out = call_tool(ctx, "fnos_file_upload",
                    {"profile": "home", "remote_dir": "/vol1/deploy",
                     "local_file": "app.tar",
                     "overwrite": "replace", "confirm": True})
    assert out["result"]["result"] == "succ"
    assert out["local_file"].endswith("app.tar")


def test_file_chown_validation(ctx):
    _allow(ctx)
    out = call_tool(ctx, "fnos_file_chown",
                    {"profile": "home", "path": "/vol1/deploy", "uid": 1000,
                     "recursive": True, "confirm": True})
    assert out["result"]["result"] == "succ"
    with pytest.raises(ToolError) as exc:
        call_tool(ctx, "fnos_file_chown",
                  {"profile": "home", "path": "/vol1/deploy", "uid": "1000",
                   "confirm": True})
    assert exc.value.code == "invalid_params"


def test_container_create_happy_path_and_cmd_guard(ctx):
    _allow(ctx)
    out = call_tool(ctx, "fnos_docker_container_create",
                    {"profile": "home", "image": "localhost/app:1",
                     "name": "web", "start": True, "restart": True,
                     "env": ["A=1"], "cmd": ["sh"], "ports": ["8080:80"],
                     "mounts": ["/vol1/x:/x"], "confirm": True})
    assert out["result"]["Id"] == "newcontainer123"
    # fnos-cli splits --cmd values on whitespace: reject multi-word entries.
    with pytest.raises(ToolError) as exc:
        call_tool(ctx, "fnos_docker_container_create",
                  {"profile": "home", "image": "localhost/app:1",
                   "cmd": ["sh -c", "echo hi"], "confirm": True})
    assert exc.value.code == "invalid_params"


def test_container_create_requires_image(ctx):
    _allow(ctx)
    with pytest.raises(ToolError) as exc:
        call_tool(ctx, "fnos_docker_container_create", {"profile": "home",
                                                        "confirm": True})
    assert exc.value.code == "invalid_params"


def test_container_remove(ctx):
    _allow(ctx)
    out = call_tool(ctx, "fnos_docker_container_remove",
                    {"profile": "home", "container": "demo",
                     "force": True, "confirm": True})
    assert out["result"]["result"] == "succ"


def test_docker_request_endpoint_whitelist(ctx):
    _allow(ctx)
    out = call_tool(ctx, "fnos_docker_request",
                    {"profile": "home", "endpoint": "composeCreate",
                     "body": {"project_name": "demo"}, "confirm": True})
    assert out["result"]["result"] == "succ"
    # Non-dockermgr endpoints are refused before the CLI runs.
    with pytest.raises(ToolError) as exc:
        call_tool(ctx, "fnos_docker_request",
                  {"profile": "home", "endpoint": "appcgi.stor.format",
                   "confirm": True})
    assert exc.value.code == "invalid_params"
    # Adapter-level guards raise ValueError before any CLI spawn.
    with pytest.raises(ValueError):
        ctx.cli.docker_request(ctx.profiles.profiles["home"],
                               "appcgi.dockermgr.composeCreate;rm", {})
    with pytest.raises(ValueError):
        ctx.cli.docker_request(ctx.profiles.profiles["home"],
                               "composeCreate", {"req": "x"})
    with pytest.raises(ValueError):
        ctx.cli.docker_request(ctx.profiles.profiles["home"],
                               "composeCreate", ["not", "an", "object"])


def test_write_tools_audited(ctx):
    _allow(ctx)
    call_tool(ctx, "fnos_file_mkdir",
              {"profile": "home", "path": "/vol1/deploy", "confirm": True})
    with pytest.raises(ToolError):
        call_tool(ctx, "fnos_file_mkdir",
                  {"profile": "home", "path": "/vol1/x", "confirm": False})
    events = [json.loads(line) for line in
              (ctx.audit.path).read_text(encoding="utf-8").splitlines()]
    actions = [e.get("event") for e in events]
    assert "file_mkdir" in actions
    ok_events = [e for e in events if e.get("event") == "file_mkdir"
                 and e.get("result") == "ok"]
    assert ok_events and ok_events[0].get("sub_reason")
    failed = [e for e in events if e.get("event") == "file_mkdir"
              and e.get("result") == "failed"]
    assert failed == []  # confirm-gate rejects before the CLI/audit point


def test_write_tools_digest_excludes_confirm(ctx):
    from fnos_mcp.tools.registry import _params_digest
    a = _params_digest({"profile": "home", "path": "/x", "confirm": True})
    b = _params_digest({"profile": "home", "path": "/x"})
    assert a == b and len(a) == 64


def test_file_upload_local_path_confined(ctx):
    """The exfiltration guard: local_file must stay inside the gateway
    upload dir — tokens.json, fnos-cli sessions and panel-auth.json are
    all inside /data and must never be uploadable to a NAS."""
    _allow(ctx)
    data_parent = ctx.state.path.parent
    # A path that escapes the upload dir (even existing files) is refused.
    for bad in ("../tokens.json", "../fnos-cli/session", "../../etc/passwd",
                "/../tokens.json"):
        with pytest.raises(ToolError) as exc:
            call_tool(ctx, "fnos_file_upload",
                      {"profile": "home", "remote_dir": "/vol1/deploy",
                       "local_file": bad, "confirm": True})
        assert exc.value.code == "invalid_params"
    # Absolute path outside the upload dir: refused even though the file
    # exists on the gateway.
    outside = data_parent / "tokens.json"
    outside.write_text("{}", encoding="utf-8")
    with pytest.raises(ToolError) as exc:
        call_tool(ctx, "fnos_file_upload",
                  {"profile": "home", "remote_dir": "/vol1/deploy",
                   "local_file": str(outside), "confirm": True})
    assert exc.value.code == "invalid_params"
    # The CLI was never invoked with anything: argv log stays empty.
    import os
    argv_log = os.environ.get("FNOS_FAKE_ARGV_LOG", "")
    assert not argv_log or not Path(argv_log).exists()
    # An absolute path INSIDE the upload dir is legitimate.
    from fnos_mcp.tools.registry import _local_upload_dir
    up = _local_upload_dir(ctx)
    (up / "abs-path.tar").write_bytes(b"x")
    out = call_tool(ctx, "fnos_file_upload",
                    {"profile": "home", "remote_dir": "/vol1/deploy",
                     "local_file": str(up / "abs-path.tar"), "confirm": True})
    assert out["result"]["result"] == "succ"


def test_write_denials_are_audited(ctx):
    """Refused writes (role, allow_dangerous, confirm) each land an
    audit record — they used to be silent."""
    ctx.token.role = "operator"
    ctx.token.capabilities = []
    with pytest.raises(ToolError):
        call_tool(ctx, "fnos_file_mkdir",
                  {"profile": "home", "path": "/vol1/x", "confirm": True})
    ctx.token.role = "admin"
    with pytest.raises(ToolError):
        call_tool(ctx, "fnos_file_mkdir",
                  {"profile": "home", "path": "/vol1/x", "confirm": True})
    for p in ctx.profiles.profiles.values():
        p.allow_dangerous = True
    with pytest.raises(ToolError):
        call_tool(ctx, "fnos_file_mkdir",
                  {"profile": "home", "path": "/vol1/x", "confirm": False})
    events = [json.loads(line) for line in
              (ctx.audit.path).read_text(encoding="utf-8").splitlines()]
    denied = [e for e in events if e.get("event") == "deploy_denied"]
    results = sorted(e.get("result") for e in denied)
    assert results == ["confirm_missing", "forbidden", "not_allowed"]
    for e in denied:
        assert e.get("token_id") == ctx.token.id


def test_write_rate_limit_per_token(ctx):
    """mcp_write (20/60s per token) is enforced after the permission and
    confirm gates; the 21st write in a minute is refused and audited."""
    from fnos_mcp.auth import RateLimiter

    _allow(ctx)
    ctx.limiter = RateLimiter()
    params = {"profile": "home", "path": "/vol1/x", "confirm": True}
    for _ in range(20):
        call_tool(ctx, "fnos_file_mkdir", dict(params))
    with pytest.raises(ToolError) as exc:
        call_tool(ctx, "fnos_file_mkdir", dict(params))
    assert exc.value.code == "rate_limited"
    events = [json.loads(line) for line in
              (ctx.audit.path).read_text(encoding="utf-8").splitlines()]
    denied = [e for e in events if e.get("event") == "deploy_denied"
              and e.get("result") == "rate_limited"]
    assert len(denied) == 1
    assert denied[0].get("token_id") == ctx.token.id
