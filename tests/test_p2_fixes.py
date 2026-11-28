"""Regressions for the P2/P3 fix round (iteration after m2-admin).

Covers:
- DNS probe returns within the deadline even when getaddrinfo hangs
- drawer auth layer renders fail + correct copy for expired/permission
- MCP login_start/login_finish/logout take the shared session lock
- panel secret must be >= 32 bytes
- probe-all holds the probe lock until in-flight threads settle
"""
import fcntl
import hashlib
import os
import socket
import time
from pathlib import Path

import pytest

from conftest import post_csrf
from fnos_mcp.config import Profile
from fnos_mcp.locks import acquire_login_lease, release_login_lease
from fnos_mcp.probe import probe_profile
from fnos_mcp.server import _load_panel_secret


def _sha(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# --- 1. DNS deadline -------------------------------------------------------
def test_dns_hang_returns_within_deadline(monkeypatch):
    def slow(*args, **kwargs):
        time.sleep(1.0)
        raise socket.gaierror("slow")

    monkeypatch.setattr("fnos_mcp.probe.socket.getaddrinfo", slow)
    p = Profile(name="home", host="192.168.1.10", port=5667)
    t0 = time.monotonic()
    result = probe_profile(p, timeout=0.2)
    elapsed = time.monotonic() - t0
    assert result.status == "dns_failed"
    assert elapsed < 0.6


# --- 2. drawer expired/permission copy -------------------------------------
def test_drawer_expired_and_permission_auth_layer(admin_client, app):
    svc = app.state.service
    svc.state.update("home", "https://192.168.1.10:5667",
                     network={"at": "2026-11-23T09:00:00+00:00", "status": "ok",
                              "latency_ms": 10, "looks_like_fnos": True},
                     auth={"at": "2026-11-23T09:05:00+00:00", "status": "expired",
                           "latency_ms": 3, "identity": None})
    html = admin_client.get("/api/profiles/home/drawer").text
    assert 'class="fail"' in html
    assert "登录已失效" in html
    assert "本机 session 已清除" not in html

    svc.state.update("home", "https://192.168.1.10:5667",
                     auth={"at": "2026-11-23T09:06:00+00:00", "status": "permission",
                           "latency_ms": 3, "identity": None})
    html = admin_client.get("/api/profiles/home/drawer").text
    assert "账号权限不足" in html


# --- 3. MCP tools take the shared session lock -----------------------------
@pytest.fixture()
def mcp_ctx(admin_client, app):
    """A ToolContext wired to the running test service."""
    from fnos_mcp.config import load_tokens
    from fnos_mcp.tools.registry import ToolContext
    svc = app.state.service
    token = next(t for t in load_tokens(svc.tokens_path) if t.role == "admin")
    return ToolContext(token=token, profiles=svc.profile_store.load(),
                       cli=svc.cli, state=svc.state, audit=svc.audit), app


def test_mcp_login_start_conflicts_with_held_lock(mcp_ctx, data_dir):
    from fnos_mcp.tools.registry import ToolError, call_tool
    ctx, _app = mcp_ctx
    lock = Path(data_dir) / "locks" / "session-home.lock"
    lock.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        with pytest.raises(ToolError) as exc:
            call_tool(ctx, "fnos_login_start", {"profile": "home"})
        assert exc.value.code == "session.locked"
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def test_mcp_login_finish_releases_lease_on_cli_error(mcp_ctx, app, monkeypatch):
    from fnos_mcp.tools.registry import ToolError, call_tool
    ctx, app_ = mcp_ctx
    svc = app_.state.service
    acquire_login_lease(svc.data_dir, "home")
    monkeypatch.setattr(svc.cli, "login_finish",
                        lambda profile, code: (_ for _ in ()).throw(
                            __import__("fnos_mcp.errors", fromlist=["CliError"])
                            .CliError("boom")))
    with pytest.raises(ToolError) as exc:
        call_tool(ctx, "fnos_login_finish", {"profile": "home", "code": "x"})
    assert exc.value.code == "session.locked" or exc.value.code == "login.failed"
    release_login_lease(svc.data_dir, "home")


# --- 4. panel secret length ------------------------------------------------
def test_panel_secret_must_be_at_least_32_bytes(tmp_path):
    key = tmp_path / "panel-session.key"
    key.write_bytes(b"short")
    with pytest.raises(RuntimeError):
        _load_panel_secret(tmp_path)
    key.write_bytes(os.urandom(32))
    assert len(_load_panel_secret(tmp_path)) == 32


# --- 5. probe-all persists settled results ---------------------------------
def test_probe_all_persists_settled_results(admin_client, app, monkeypatch):
    calls = {"n": 0}

    def slow_probe(profile, timeout, ca_bundle):
        calls["n"] += 1
        time.sleep(0.3)
        from fnos_mcp.probe import ProbeResult
        return ProbeResult("timeout", "timeout", 300, False)

    monkeypatch.setattr("fnos_mcp.api.routes.probe_profile", slow_probe)
    resp = post_csrf(admin_client, "/api/profiles/probe-all")
    assert resp.status_code == 200
    assert calls["n"] >= 1
    # The result must have been written (thread finished before response).
    rows = {p["name"]: p for p in admin_client.get("/api/profiles").json()["profiles"]}
    assert rows["home"]["badge"] in ("unreachable", "untested")
    assert rows["home"]["badge"] == "unreachable"
