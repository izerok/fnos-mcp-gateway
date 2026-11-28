"""M2 panel tests: load probe-all, nine states, layered times, 409s,
empty states, FR-21 rejection, Chinese copy, accessibility, HTMX.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from conftest import ADMIN_TOKEN, PANEL_PASSWORD, post_csrf
from fnos_mcp.server import create_app
from fnos_mcp.state_store import now_iso


def _sha(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _fake_state(data_dir, profile, **patch):
    """Write per-profile fake-CLI state (auth_mode / auth_url)."""
    path = Path(data_dir) / "fnos-cli" / "fake-state.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        state = {}
    state.setdefault(profile, {"logged_in": False}).update(patch)
    path.write_text(json.dumps(state), encoding="utf-8")


def _make_client(tmp_path, profiles, tokens, monkeypatch):
    data = tmp_path / "data2"
    data.mkdir(exist_ok=True)
    (data / "panel-session.key").write_bytes(os.urandom(32))
    p = tmp_path / "p2.json"
    p.write_text(json.dumps(profiles), encoding="utf-8")
    t = tmp_path / "t2.json"
    t.write_text(json.dumps(tokens), encoding="utf-8")
    monkeypatch.setenv("FNOS_CLI_BIN", str(Path(__file__).parent / "fake_cli.py"))
    app = create_app(profiles_path=str(p), tokens_path=str(t), data_dir=str(data))
    client = TestClient(app, raise_server_exceptions=False)
    csrf = client.get("/login").cookies.get("fnos_csrf")
    return client, csrf, data


def _login(client, csrf):
    """First-run panel setup (no default credential)."""
    resp = client.post("/login",
                       data={"password": PANEL_PASSWORD,
                             "password_confirm": PANEL_PASSWORD,
                             "csrf_token": csrf},
                       follow_redirects=False)
    assert resp.status_code == 302, resp.text
    return client


# --- 1. load probe-all -------------------------------------------------
def test_load_probe_all_once(admin_client):
    resp = admin_client.get("/")
    assert resp.status_code == 200
    assert 'hx-post="/api/profiles/probe-all"' in resp.text
    assert 'hx-trigger="load"' in resp.text
    assert resp.text.count('hx-trigger="load"') == 1
    # The probe-all response must NOT carry the trigger again.
    resp = post_csrf(admin_client, "/api/profiles/probe-all",
                     headers={"HX-Request": "true"})
    assert resp.status_code == 200
    assert 'hx-trigger="load"' not in resp.text
    assert 'id="roster"' in resp.text


# --- 2. nine states ------------------------------------------------------
def test_badge_matrix_via_state(admin_client, app):
    svc = app.state.service
    svc.state.update("home", "https://192.168.1.10:5667",
                     network={"at": "2026-11-23T09:00:00+00:00", "status": "ok",
                              "latency_ms": 10, "looks_like_fnos": True})
    svc.state.update("office", "https://nas.office.example.com:443",
                     network={"at": "2026-11-23T09:00:00+00:00", "status": "refused",
                              "latency_ms": 5, "looks_like_fnos": False})
    resp = admin_client.get("/api/profiles")
    rows = {p["name"]: p for p in resp.json()["profiles"]}
    assert rows["home"]["badge"] == "unverified"
    assert rows["home"]["badge_label"] == "地址可达 · 未验证登录"
    assert rows["office"]["badge"] == "unreachable"
    counts = resp.json()["summary"]["counts"]
    assert counts["pending"] == 1 and counts["error"] == 1


def test_row_shows_status_once_and_badge_next_to_name(admin_client, app):
    """Machine rows put the state badge beside the name, keep address and
    metadata on one line, and do not repeat the network reason."""
    svc = app.state.service
    svc.state.update("office", "https://nas.office.example.com:443",
                     network={"at": "2026-11-23T09:00:00+00:00",
                              "status": "timeout", "detail": "连接超时。",
                              "latency_ms": 5, "looks_like_fnos": False})
    html = admin_client.get("/").text
    start = html.index('id="row-office"')
    row = html[start:html.index("</article>", start)]
    assert "网络不可达" in row
    assert row.index("网络不可达") < row.index(
        "https://nas.office.example.com:443")
    # The reason appears once, as the meta sub; the duplicate .err is gone.
    assert row.count("连接超时") == 1
    assert "连接超时。" not in row
    assert "上次检查" in row and "5ms" in row


def test_expired_and_permission_via_fake_cli(admin_client, app, data_dir):
    svc = app.state.service
    # A badge needs a network layer first (no network -> untested).
    svc.state.update("home", "https://192.168.1.10:5667",
                     network={"at": "2026-11-23T09:00:00+00:00", "status": "ok",
                              "latency_ms": 10, "looks_like_fnos": True})
    _fake_state(data_dir, "home", auth_mode="expired")
    resp = post_csrf(admin_client, "/api/profiles/home/test")
    assert resp.status_code == 200
    assert resp.json()["auth"]["status"] == "expired"
    rows = {p["name"]: p for p in admin_client.get("/api/profiles").json()["profiles"]}
    assert rows["home"]["badge"] == "expired"
    assert rows["home"]["badge_label"] == "登录失效"
    _fake_state(data_dir, "home", auth_mode="permission")
    resp = post_csrf(admin_client, "/api/profiles/home/test")
    assert resp.json()["auth"]["status"] == "permission"
    rows = {p["name"]: p for p in admin_client.get("/api/profiles").json()["profiles"]}
    assert rows["home"]["badge"] == "permission"
    assert rows["home"]["badge_label"] == "权限不足"


def test_config_badge_row(tmp_path, monkeypatch):
    profiles = {"default_profile": "home", "profiles": {
        "home": {"host": "192.168.1.10", "port": 5667, "scheme": "https"},
        "vault": {"host": "", "port": 0, "scheme": "https"}}}
    tokens = {"tokens": [{"id": "t_admin", "name": "admin",
                          "sha256": _sha(ADMIN_TOKEN), "profiles": ["home", "vault"],
                          "role": "admin"}]}
    client, csrf, _ = _make_client(tmp_path, profiles, tokens, monkeypatch)
    _login(client, csrf)
    resp = client.get("/api/profiles")
    rows = {p["name"]: p for p in resp.json()["profiles"]}
    assert rows["vault"]["badge"] == "config"
    assert rows["vault"]["badge_label"] == "配置错误"
    assert resp.json()["summary"]["counts"]["total"] == 2
    assert resp.json()["summary"]["counts"]["error"] == 1
    html = client.get("/").text
    assert "配置错误" in html


def test_target_change_invalidates_api_without_index(admin_client, app, profiles_path):
    svc = app.state.service
    svc.state.update(
        "home", "https://192.168.1.10:5667",
        network={"at": now_iso(), "status": "ok", "latency_ms": 10,
                 "looks_like_fnos": True},
        auth={"at": now_iso(), "status": "ok", "latency_ms": 3,
              "identity": "admin"})
    data = json.loads(Path(profiles_path).read_text(encoding="utf-8"))
    data["profiles"]["home"]["host"] = "192.168.1.11"
    Path(profiles_path).write_text(json.dumps(data), encoding="utf-8")
    # Do NOT request GET / first; the API read itself must invalidate.
    resp = admin_client.get("/api/profiles")
    rows = {p["name"]: p for p in resp.json()["profiles"]}
    assert rows["home"]["badge"] == "untested"
    assert resp.json()["summary"]["badges"]["home"] == "untested"


def test_overlays_are_outside_inert_page(admin_client):
    html = admin_client.get("/").text
    page_end = html.index("</main>")
    for marker in ('id="drawer"', 'id="scrim"', 'id="loginModal"', 'id="confirmModal"'):
        assert html.index(marker) > page_end


def test_untested_and_loggedout_badges(admin_client, app):
    rows = {p["name"]: p for p in admin_client.get("/api/profiles").json()["profiles"]}
    assert rows["home"]["badge"] == "untested"
    assert rows["home"]["badge_label"] == "未测试"
    app.state.service.state.update(
        "home", "https://192.168.1.10:5667",
        network={"at": "2026-11-23T09:00:00+00:00", "status": "ok",
                 "latency_ms": 10, "looks_like_fnos": True})
    post_csrf(admin_client, "/api/profiles/home/test")
    rows = {p["name"]: p for p in admin_client.get("/api/profiles").json()["profiles"]}
    assert rows["home"]["badge"] == "loggedout"
    assert rows["home"]["badge_label"] == "地址可达 · 未登录"


def test_http_profile_tls_text(tmp_path, monkeypatch):
    profiles = {"default_profile": "home", "profiles": {
        "home": {"host": "127.0.0.1", "port": 5667, "scheme": "http",
                 "allow_insecure_http": True}}}
    tokens = {"tokens": [{"id": "t_admin", "name": "admin",
                          "sha256": _sha(ADMIN_TOKEN), "profiles": ["home"],
                          "role": "admin"}]}
    data = tmp_path / "data3"
    data.mkdir(exist_ok=True)
    (data / "panel-session.key").write_bytes(os.urandom(32))
    p = tmp_path / "p3.json"
    p.write_text(json.dumps(profiles), encoding="utf-8")
    t = tmp_path / "t3.json"
    t.write_text(json.dumps(tokens), encoding="utf-8")
    monkeypatch.setenv("FNOS_CLI_BIN", str(Path(__file__).parent / "fake_cli.py"))
    app = create_app(profiles_path=str(p), tokens_path=str(t), data_dir=str(data))
    client = TestClient(app, raise_server_exceptions=False)
    csrf = client.get("/login").cookies.get("fnos_csrf")
    _login(client, csrf)
    app.state.service.state.update(
        "home", "http://127.0.0.1:5667",
        network={"at": "2026-11-23T09:00:00+00:00", "status": "ok",
                 "latency_ms": 10, "looks_like_fnos": True,
                 "detail": "HTTP 200。"})
    rows = {p["name"]: p for p in client.get("/api/profiles").json()["profiles"]}
    assert rows["home"]["tls_text"] == "明文连接"
    html = client.get("/api/profiles/home/drawer").text
    assert "明文连接，不走 TLS" in html
    assert "证书有效" not in html


# --- 3. layered times ------------------------------------------------------
def test_drawer_layers_have_own_times(admin_client, app):
    svc = app.state.service
    svc.state.update("home", "https://192.168.1.10:5667",
                     network={"at": "2026-11-23T09:00:00+00:00", "status": "ok",
                              "latency_ms": 50, "looks_like_fnos": True,
                              "dns_ms": 5, "tcp_ms": 12, "tls_ms": 40,
                              "detail": "HTTP 200。"},
                     auth={"at": "2026-11-23T09:05:00+00:00", "status": "ok",
                           "latency_ms": 3, "identity": "admin"})
    resp = admin_client.get("/api/profiles/home/drawer")
    assert resp.status_code == 200
    html = resp.text
    assert "09:00" in html and "09:05" in html
    assert "12ms" in html  # network layer: TCP cumulative
    assert "28ms" in html  # TLS layer: handshake only (40-12)
    assert "3ms" in html   # auth layer: user_info call
    # Config layer has no time at all.
    assert html.count("—") >= 1
    # Auth identity comes from user info, not system info.
    assert "user info" in html and "system info" in html


# --- 4. real 409 fragments -------------------------------------------------
def test_probe_busy_409_fragment(admin_client, app, data_dir):
    lock = Path(data_dir) / "locks" / "probe-home.lock"
    lock.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        resp = post_csrf(admin_client, "/api/profiles/home/probe",
                         headers={"HX-Request": "true"})
        assert resp.status_code == 409
        assert 'data-error-code="probe.busy"' in resp.text
        assert 'role="alert"' in resp.text
        # probe-all marks the locked profile busy instead of dropping it.
        resp = post_csrf(admin_client, "/api/profiles/probe-all")
        assert resp.status_code == 200
        assert resp.json()["results"]["home"]["status"] == "busy"
        assert "home" in resp.json()["busy"]
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def test_session_locked_409_fragment(admin_client, app, data_dir):
    lock = Path(data_dir) / "locks" / "session-home.lock"
    lock.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        resp = post_csrf(admin_client, "/api/profiles/home/test",
                         headers={"HX-Request": "true"})
        assert resp.status_code == 409
        assert 'data-error-code="session.locked"' in resp.text
        assert 'role="alert"' in resp.text
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


# --- 5. empty states / operator / insecure tags ---------------------------
def test_zero_config_empty_state(tmp_path, monkeypatch):
    profiles = {"default_profile": None, "profiles": {}}
    tokens = {"tokens": [{"id": "t_admin", "name": "admin",
                          "sha256": _sha(ADMIN_TOKEN), "profiles": [],
                          "role": "admin"}]}
    client, csrf, _ = _make_client(tmp_path, profiles, tokens, monkeypatch)
    _login(client, csrf)
    assert "还没有配置机器" in client.get("/").text


def test_insecure_tags_rendered(admin_client, tmp_path, profiles_path):
    data = json.loads(Path(profiles_path).read_text(encoding="utf-8"))
    data["profiles"]["home"]["allow_insecure_http"] = True
    data["profiles"]["home"]["scheme"] = "http"
    data["profiles"]["home"]["tls_insecure"] = True
    Path(profiles_path).write_text(json.dumps(data), encoding="utf-8")
    html = admin_client.get("/").text
    assert "allow_insecure_http" in html
    assert "tls_insecure" in html


# --- 6. FR-21 rejection ------------------------------------------------------
@pytest.mark.parametrize("bad_url", [
    "javascript:alert(1)",
    "data:text/html,hi",
    "https://evil.example.com:443/oauth/authorize?client_id=x",
    "https://user:pass@192.168.1.10:5667/oauth/authorize",
    "https://192.168.1.10:5667/oauth/authorize?x=1\x01",
])
def test_fr21_rejection_fragment(admin_client, app, data_dir, bad_url):
    _fake_state(data_dir, "home", auth_url=bad_url)
    resp = post_csrf(admin_client, "/api/profiles/home/login/start",
                     headers={"HX-Request": "true"})
    assert resp.status_code == 400
    assert resp.headers.get("cache-control") == "no-store"
    assert "授权链接被拒绝" in resp.text
    assert 'role="alert"' in resp.text
    assert "<a " not in resp.text
    assert "oauth/authorize" not in resp.text
    assert "javascript:" not in resp.text
    assert "data:text/html" not in resp.text


# --- 7. Chinese copy ---------------------------------------------------------
def test_no_english_main_copy(admin_client):
    html = admin_client.get("/").text + admin_client.get("/login").text
    assert "saved proxy session is required" not in html
    assert "authorization_url" not in html
    # No English as visible copy (element ids like panelLogoutBtn are code).
    assert ">Login<" not in html and ">Logout<" not in html


# --- 8. accessibility + HTMX assets -------------------------------------------
def test_a11y_and_htmx_assets(admin_client):
    html = admin_client.get("/").text
    assert 'aria-pressed="true"' in html
    assert 'aria-pressed="false"' in html
    assert 'aria-live="polite"' in html
    assert 'role="dialog"' in html
    assert 'aria-modal="true"' in html
    css = admin_client.get("/static/style.css").text
    assert "min-height:44px" in css
    assert ".sr-only" in css
    js = admin_client.get("/static/htmx.min.js")
    assert js.status_code == 200
    assert len(js.content) > 40000
    assert b"2.0.7" in js.content
    app_js = admin_client.get("/static/app.js").text
    assert "htmx:configRequest" in app_js
    assert "inert" in app_js


def test_rows_filter(admin_client):
    resp = admin_client.get("/api/profiles/rows?bucket=connected")
    assert resp.status_code == 200
    assert "没有符合筛选的机器" in resp.text
    resp = admin_client.get("/api/profiles/rows?bucket=all")
    assert "home" in resp.text and "office" in resp.text
