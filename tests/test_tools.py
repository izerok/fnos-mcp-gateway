import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

from conftest import ADMIN_TOKEN

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from fnos_mcp.audit import AuditLog
from fnos_mcp.cli_adapter import FnosCli
from fnos_mcp.config import load_profiles, load_tokens
from fnos_mcp.runner import CliRunner
from fnos_mcp.server import create_app
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


def test_profiles_lists_acl_only(ctx):
    out = call_tool(ctx, "fnos_profiles", {})
    assert [p["name"] for p in out["profiles"]] == ["home", "office"]


def test_profile_resolution_rejects_host_params(ctx):
    with pytest.raises(ToolError) as exc:
        call_tool(ctx, "fnos_system_info", {"profile": "home", "host": "evil.example"})
    assert exc.value.code == "invalid_params"


def test_profile_outside_acl_rejected(ctx):
    ctx.token.profiles = ["home"]
    with pytest.raises(ToolError) as exc:
        call_tool(ctx, "fnos_system_info", {"profile": "office"})
    assert exc.value.code == "profile.not_found"


def test_wildcard_acl_lists_all_profiles(ctx):
    ctx.token.profiles = ["*"]
    out = call_tool(ctx, "fnos_profiles", {})
    assert [p["name"] for p in out["profiles"]] == ["home", "office"]
    assert call_tool(ctx, "fnos_system_info", {"profile": "office"})["machine"] == "fnOS"


def test_default_profile_outside_acl_falls_back_to_single_visible(ctx):
    ctx.token.profiles = ["office"]
    # default is home, but this token only sees office; do not resolve to
    # a profile outside the ACL.
    out = call_tool(ctx, "fnos_status", {})
    assert [p["name"] for p in out["profiles"]] == ["office"]


def test_login_flow_via_tools(ctx):
    start = call_tool(ctx, "fnos_login_start", {"profile": "home"})
    assert start["authorization_url"].startswith("https://192.168.1.10:5667/oauth/authorize")
    done = call_tool(ctx, "fnos_login_finish", {"profile": "home", "code": "abc-123"})
    assert done["status"] == "connected" and done["identity"] == "admin"
    status = call_tool(ctx, "fnos_status", {"profile": "home"})
    assert status["profiles"][0]["status"] == "connected"
    out = call_tool(ctx, "fnos_logout", {"profile": "home"})
    assert out["status"] == "logged_out"


def test_login_finish_bad_code(ctx):
    call_tool(ctx, "fnos_login_start", {"profile": "home"})
    with pytest.raises(ToolError) as exc:
        call_tool(ctx, "fnos_login_finish", {"profile": "home", "code": "000000"})
    assert exc.value.code == "login.code_invalid"


def test_operator_cannot_login(ctx):
    from fnos_mcp.config import TokenRecord
    ctx.token = TokenRecord(id="t_operator", name="operator",
                            sha256=hashlib.sha256(b"x").hexdigest(),
                            profiles=["home"], role="operator")
    with pytest.raises(ToolError) as exc:
        call_tool(ctx, "fnos_login_start", {"profile": "home"})
    assert exc.value.code == "auth.forbidden"


def test_system_info_does_not_require_login(ctx):
    # Logged out, yet system_info still returns data — and tools must
    # never use it to judge login (that is user_info's job).
    out = call_tool(ctx, "fnos_system_info", {"profile": "home"})
    assert out["machine"] == "fnOS"
    status = call_tool(ctx, "fnos_status", {"profile": "home"})
    assert status["profiles"][0]["status"] == "untested"


def test_stale_target_not_reported_by_mcp(ctx):
    from fnos_mcp.state_store import now_iso
    ctx.state.update(
        "home", "https://192.168.1.99:5667",
        network={"at": now_iso(), "status": "ok", "latency_ms": 1,
                 "looks_like_fnos": True},
        auth={"at": now_iso(), "status": "ok", "latency_ms": 3,
              "identity": "admin"})
    status = call_tool(ctx, "fnos_status", {"profile": "home"})
    assert status["profiles"][0]["status"] == "untested"


def test_read_only_tools(ctx):
    call_tool(ctx, "fnos_login_start", {"profile": "home"})
    call_tool(ctx, "fnos_login_finish", {"profile": "home", "code": "abc-123"})
    assert call_tool(ctx, "fnos_storage_pools", {"profile": "home"})["pools"]
    assert call_tool(ctx, "fnos_docker_ps", {"profile": "home"})["containers"][0]["Names"] == ["/demo"]
    assert call_tool(ctx, "fnos_monitor_cpu", {"profile": "home"})["cpu_percent"] == 3.5
    assert call_tool(ctx, "fnos_file_ls", {"profile": "home", "path": "/vol1"})["path"] == "/vol1"


# --- wildcard ACL + panel-managed store (m2-admin follow-up) ----------------

WILDCARD_PROFILES = {"default_profile": "home", "profiles": {
    "home": {"host": "192.168.1.10", "port": 5667, "scheme": "https"},
    "office": {"host": "nas.office.example.com", "port": 443, "scheme": "https"},
}}


def _make_app(tmp_path, monkeypatch):
    data = tmp_path / "data-tools"
    data.mkdir(exist_ok=True)
    (data / "panel-session.key").write_bytes(os.urandom(32))
    p = tmp_path / "p-tools.json"
    p.write_text(json.dumps(WILDCARD_PROFILES), encoding="utf-8")
    t = tmp_path / "t-tools.json"
    t.write_text(json.dumps({"tokens": [
        {"id": "t_admin", "name": "admin",
         "sha256": hashlib.sha256(ADMIN_TOKEN.encode()).hexdigest(),
         "profiles": ["*"], "role": "admin"}]}), encoding="utf-8")
    monkeypatch.setenv("FNOS_CLI_BIN", FAKE_CLI)
    return create_app(profiles_path=str(p), tokens_path=str(t),
                      data_dir=str(data))


def _admin_token(app):
    svc = app.state.service
    return load_tokens(svc.tokens_path)[0]


def test_wildcard_acl_sees_panel_created_profile(tmp_path, monkeypatch):
    app = _make_app(tmp_path, monkeypatch)
    svc = app.state.service
    ctx = ToolContext(token=_admin_token(app), profiles=svc.profile_store.load(),
                      cli=svc.cli, state=svc.state, audit=svc.audit)
    assert [prof.name for prof in ctx.visible_profiles()] == ["home", "office"]

    # A profile created through the panel store becomes visible without
    # touching tokens.json — the point of the wildcard.
    svc.profile_store.create("lab", {"host": "10.0.0.7", "port": 5667,
                                     "scheme": "https", "description": ""})
    ctx = ToolContext(token=_admin_token(app), profiles=svc.profile_store.load(),
                      cli=svc.cli, state=svc.state, audit=svc.audit)
    assert [prof.name for prof in ctx.visible_profiles()] == ["home", "office", "lab"]


def test_mcp_rejects_host_port_scheme(tmp_path, monkeypatch):
    app = _make_app(tmp_path, monkeypatch)
    svc = app.state.service
    ctx = ToolContext(token=_admin_token(app), profiles=svc.profile_store.load(),
                      cli=svc.cli, state=svc.state, audit=svc.audit)
    for forbidden in ({"host": "1.2.3.4"}, {"port": 5667}, {"scheme": "http"}):
        params = {"profile": "home", **forbidden}
        with pytest.raises(ToolError) as exc:
            call_tool(ctx, "fnos_system_info", params)
        assert exc.value.code == "invalid_params"
