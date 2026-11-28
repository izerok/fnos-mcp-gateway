def test_index_renders_tokens_and_cards(admin_client):
    resp = admin_client.get("/")
    assert resp.status_code == 200
    # Visual tokens are the v2 StyleKit Apple set (see docs/ui-mock/NOTES-v2.md).
    assert "#0071e3" in admin_client.get("/static/style.css").text
    assert "MCP 接入" in resp.text
    assert "Bearer &lt;token&gt;" in resp.text or "Bearer •" in resp.text
    assert 'hx-get="/api/profiles/home/drawer"' in resp.text  # drawer is server-rendered
    assert "/static/htmx.min.js" in resp.text
    assert "配置与连通性" in resp.text
    assert "添加机器" in resp.text
    assert 'hx-get="/api/profiles/new/form"' in resp.text


from conftest import PANEL_PASSWORD, panel_setup


def test_login_page_first_run(client):
    """No default credential: the first visitor sets the password."""
    resp = client.get("/login")
    assert resp.status_code == 200
    assert "设置管理员密码" in resp.text
    assert 'name="csrf-token"' in resp.text
    assert "CLI 0.6.2" in resp.text


def test_login_page_after_setup(client, app):
    panel_setup(client)
    client.cookies.delete("fnos_panel")
    resp = client.get("/login")
    assert resp.status_code == 200
    assert "登录面板" in resp.text
    assert "设置管理员密码" not in resp.text


def test_login_plain_form_no_header(client):
    """Regression (2026-11-23 visual check): a real browser submits /login
    as a plain <form> POST with NO X-CSRF-Token header. The hidden
    csrf_token field must satisfy the double-submit check, or panel login
    is unusable outside the smoke scripts (which always sent the header)."""
    csrf = client.get("/login").cookies.get("fnos_csrf")
    assert csrf
    resp = client.post("/login",
                       data={"password": PANEL_PASSWORD,
                             "password_confirm": PANEL_PASSWORD,
                             "csrf_token": csrf},
                       follow_redirects=False)
    assert resp.status_code == 302, resp.text
    assert "fnos_panel" in resp.headers.get("set-cookie", "")


def test_login_plain_form_without_csrf_field_rejected(client):
    client.get("/login")
    resp = client.post("/login",
                       data={"password": PANEL_PASSWORD,
                             "password_confirm": PANEL_PASSWORD},
                       follow_redirects=False)
    assert resp.status_code == 403


def test_static_assets(client):
    assert client.get("/static/style.css").status_code == 200
    assert client.get("/static/app.js").status_code == 200


def test_last_scan_shows_latest_probe_time(admin_client, app):
    """Task C: #lastScan is the max network.at across the token's visible
    profiles, not a hardcoded '—'."""
    html = admin_client.get("/").text
    assert "最后扫描 —" in html

    state = app.state.service.state
    state.update("home", "https://192.168.1.10:5667",
                 network={"at": "2026-11-24T10:30:00+00:00", "status": "ok",
                          "latency_ms": 6, "detail": "ok"})
    state.update("office", "https://nas.office.example.com:443",
                 network={"at": "2026-11-24T10:15:00+00:00", "status": "refused",
                          "latency_ms": None, "detail": "refused"})
    html = admin_client.get("/").text
    assert "最后扫描 10:30" in html
    assert "最后扫描 —" not in html
