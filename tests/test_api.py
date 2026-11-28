
import pytest

from conftest import post_csrf
from fnos_mcp.errors import CliError


def test_unauth_redirects_to_login(client):
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code == 302 and resp.headers["location"] == "/login"
    resp = client.get("/api/profiles")
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "auth.required"


def test_login_wrong_password_401(admin_client):
    csrf = admin_client.cookies.get("fnos_csrf")
    resp = admin_client.post("/login", data={"password": "not-the-password"},
                             headers={"X-CSRF-Token": csrf},
                             follow_redirects=False)
    assert resp.status_code == 401
    assert "密码不正确" in resp.text


def test_panel_index_and_profiles(admin_client):
    resp = admin_client.get("/")
    assert resp.status_code == 200
    assert "fnOS 接入面板" in resp.text
    assert "home" in resp.text and "office" in resp.text
    assert "全部测试" in resp.text
    resp = admin_client.get("/api/profiles")
    assert resp.status_code == 200
    names = [p["name"] for p in resp.json()["profiles"]]
    assert names == ["home", "office"]
    assert resp.json()["summary"]["counts"]["total"] == 2


def test_panel_sees_all_machines(admin_client):
    """The panel is the human administrator: password login grants the
    wildcard ACL. Agent keys and their narrower ACLs only apply to MCP
    clients (see test_tokens_panel.py)."""
    resp = admin_client.get("/api/profiles")
    assert [p["name"] for p in resp.json()["profiles"]] == ["home", "office"]
    # Outside the store is still indistinguishable from outside the ACL.
    r1 = post_csrf(admin_client, "/api/profiles/nope/probe")
    assert r1.status_code == 404
    assert r1.json()["error"]["code"] == "profile.not_found"


def test_login_flow_end_to_end(admin_client):
    resp = post_csrf(admin_client, "/api/profiles/home/login/start",
                     headers={"HX-Request": "true"})
    assert resp.status_code == 200
    assert resp.headers["cache-control"] == "no-store"
    assert "oauth/authorize" in resp.text
    # Second start while the lease is fresh -> 409.
    resp2 = post_csrf(admin_client, "/api/profiles/home/login/start")
    assert resp2.status_code == 409
    assert resp2.json()["error"]["code"] == "session.locked"
    # Finish with a good code -> connected; the lease is released.
    resp = post_csrf(admin_client, "/api/profiles/home/login/finish",
                     data={"code": "abc-123"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "connected"
    assert resp.json()["identity"] == "admin"
    # Logout -> logged_out, network kept.
    resp = post_csrf(admin_client, "/api/profiles/home/logout")
    assert resp.status_code == 200
    assert resp.json()["status"] == "logged_out"


def test_login_finish_bad_code(admin_client):
    post_csrf(admin_client, "/api/profiles/home/login/start")
    resp = post_csrf(admin_client, "/api/profiles/home/login/finish",
                     data={"code": "000000"})
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "login.code_invalid"


def test_test_endpoint_uses_user_info(admin_client):
    # Logged out in the fake CLI -> "地址可达 · 未登录" (loggedout), not connected.
    resp = post_csrf(admin_client, "/api/profiles/home/test")
    assert resp.status_code == 200
    assert resp.json()["auth"]["status"] == "logged_out"


def test_test_endpoint_cli_error_uses_json_contract(admin_client, app, monkeypatch):
    def boom(profile):
        raise CliError("simulated user_info failure")

    monkeypatch.setattr(app.state.service.cli, "user_info", boom)
    resp = post_csrf(admin_client, "/api/profiles/home/test")
    assert resp.status_code == 500
    assert resp.json()["error"]["code"] == "internal"


def test_login_start_cli_error_releases_lease(admin_client, app, data_dir, monkeypatch):
    pending = data_dir / "locks" / "pending-home.json"

    def boom(profile):
        raise CliError("simulated login_start failure")

    monkeypatch.setattr(app.state.service.cli, "login_start", boom)
    resp = post_csrf(admin_client, "/api/profiles/home/login/start")
    assert resp.status_code == 502
    assert resp.json()["error"]["code"] == "login.failed"
    assert not pending.exists()


def test_login_finish_cli_error_releases_lease(admin_client, app, data_dir, monkeypatch):
    pending = data_dir / "locks" / "pending-home.json"
    started = post_csrf(admin_client, "/api/profiles/home/login/start")
    assert started.status_code == 200
    assert pending.exists()

    def boom(profile, code):
        raise CliError("simulated login_finish timeout")

    monkeypatch.setattr(app.state.service.cli, "login_finish", boom)
    resp = post_csrf(admin_client, "/api/profiles/home/login/finish",
                     data={"code": "abc-123"})
    assert resp.status_code == 502
    assert resp.json()["error"]["code"] == "login.failed"
    assert not pending.exists()


def test_logout_cli_error_uses_json_contract(admin_client, app, monkeypatch):
    def boom(profile):
        raise CliError("simulated logout failure")

    monkeypatch.setattr(app.state.service.cli, "logout", boom)
    resp = post_csrf(admin_client, "/api/profiles/home/logout")
    assert resp.status_code == 500
    assert resp.json()["error"]["code"] == "logout.failed"


def test_healthz(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["cli_version"] == "0.6.2"


def test_mcp_tools_list_and_call(admin_client, app):
    """FastMCP 2 transport: in-process client for tools, HTTP for auth."""
    import asyncio

    from fastmcp import Client

    from fnos_mcp.mcp_server import _TOKEN, build_fastmcp
    from fnos_mcp.config import load_tokens
    from conftest import ADMIN_TOKEN

    token = load_tokens(app.state.service.tokens_path)
    admin = [t for t in token if t.id == "t_admin"][0]

    async def _run():
        mcp = build_fastmcp(app.state.service)
        t = _TOKEN.set(admin)
        try:
            async with Client(mcp) as client:
                tools = await client.list_tools()
                names = [tool.name for tool in tools]
                assert len(names) == 30 and "fnos_profiles" in names
                assert "fnos_docker_compose_start" in names
                assert "fnos_docker_compose_logs" in names
                result = await client.call_tool("fnos_profiles", {})
                import json as _json
                payload = _json.loads(result.content[0].text)
                assert [p["name"] for p in payload["profiles"]] == ["home", "office"]
                # host/port/scheme are rejected: the client schema has
                # no such argument, so FastMCP raises before dispatch.
                from fastmcp.exceptions import ToolError as _FastToolError
                with pytest.raises(_FastToolError):
                    await client.call_tool(
                        "fnos_system_info", {"profile": "home", "host": "evil.example"})
        finally:
            _TOKEN.reset(t)

    asyncio.run(_run())
    # HTTP: no Bearer -> 401 before FastMCP sees the request.
    resp = admin_client.post("/mcp/", json={
        "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        headers={"Content-Type": "application/json"})
    assert resp.status_code == 401
    # HTTP: Bearer + a FastMCP initialize still needs the MCP handshake;
    # a bare JSON-RPC tools/list is not the FastMCP wire shape any more
    # (FastMCP answers 404 for a session-less request). Real HTTP MCP
    # coverage lives in tests/smoke_m2.py with the MCP SDK client.
    resp = admin_client.post("/mcp/", json={
        "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}",
                 "Content-Type": "application/json",
                 "Accept": "application/json, text/event-stream"})
    assert resp.status_code in (200, 400, 404, 405)


def test_mcp_unlimited_by_default(admin_client, app):
    """/mcp has no rate limit by default (FNOS_RATE_LIMIT_MCP_CALL decides)."""
    service = app.state.service
    assert service.limiter.limits["mcp_call"] is None
    service.limiter._hits.clear()
    for _ in range(500):
        assert service.limiter.check("mcp_call", "t_admin")[0] is True


def test_mcp_rate_limit_per_token_when_enabled(admin_client, app):
    """/mcp can be throttled per token via FNOS_RATE_LIMIT_MCP_CALL;
    429 carries Retry-After and other tokens are unaffected."""
    from conftest import ADMIN_TOKEN
    service = app.state.service
    service.limiter.limits["mcp_call"] = (3, 60)
    service.limiter._hits.clear()
    for _ in range(3):
        assert service.limiter.check("mcp_call", "t_admin")[0] is True
    resp = admin_client.post("/mcp/", json={
        "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}",
                 "Content-Type": "application/json"})
    assert resp.status_code == 429
    assert resp.json()["error"]["code"] == "rate_limited"
    assert "retry-after" in resp.headers
    assert service.limiter.check("mcp_call", "t_operator")[0] is True
    service.limiter._hits.clear()
    resp = admin_client.post("/mcp/", json={
        "jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {}},
        headers={"Content-Type": "application/json"})
    assert resp.status_code == 401
