"""M5 panel authentication: first-run password, scrypt store, session
binding, change-password, and the removal of token-based panel login."""
import json
import stat
from pathlib import Path

from fastapi.testclient import TestClient

from conftest import ADMIN_TOKEN, PANEL_PASSWORD, panel_setup


def _audit_events(data_dir):
    path = Path(data_dir) / "audit.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in
            path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _form(client, **data):
    if not client.cookies.get("fnos_csrf"):
        client.get("/login")
    data.setdefault("csrf_token", client.cookies.get("fnos_csrf", ""))
    return client.post("/login", data=data, follow_redirects=False)


def test_first_run_has_no_credential(client, data_dir):
    assert not (Path(data_dir) / "panel-auth.json").exists()
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code == 302 and resp.headers["location"] == "/login"
    page = client.get("/login")
    assert "设置管理员密码" in page.text


def test_setup_stores_only_scrypt_hash(client, data_dir):
    resp = _form(client, password=PANEL_PASSWORD,
                 password_confirm=PANEL_PASSWORD)
    assert resp.status_code == 302
    assert "fnos_panel" in resp.headers.get("set-cookie", "")
    path = Path(data_dir) / "panel-auth.json"
    assert path.is_file()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    raw = path.read_text(encoding="utf-8")
    data = json.loads(raw)
    assert data["alg"] == "scrypt" and data["version"] == 1
    assert data["n"] >= 16384 and data["r"] >= 8 and data["p"] >= 1
    assert len(data["salt"]) >= 32 and len(data["hash"]) == 64
    # The plaintext password never reaches disk.
    assert PANEL_PASSWORD not in raw
    # The panel is usable right away.
    assert client.get("/").status_code == 200
    events = [e["event"] for e in _audit_events(data_dir)]
    assert "panel_setup" in events


def test_setup_rejects_weak_or_mismatched(client, data_dir):
    resp = _form(client, password="short", password_confirm="short")
    assert resp.status_code == 400
    assert "至少 8 个字符" in resp.text
    resp = _form(client, password=PANEL_PASSWORD, password_confirm="different-pass")
    assert resp.status_code == 400
    assert "不一致" in resp.text
    resp = _form(client, password="has\x01control", password_confirm="has\x01control")
    assert resp.status_code == 400
    assert "控制字符" in resp.text
    assert not (Path(data_dir) / "panel-auth.json").exists()
    assert client.get("/", follow_redirects=False).status_code == 302


def test_wrong_password_is_401_and_audited(client, data_dir):
    panel_setup(client)
    # Fresh jar: no session, only the CSRF cookie.
    anon = TestClient(client.app, raise_server_exceptions=False)
    anon.get("/login")
    resp = anon.post("/login", data={"password": "definitely-wrong",
                                     "csrf_token": anon.cookies.get("fnos_csrf")},
                     follow_redirects=False)
    assert resp.status_code == 401
    assert "密码不正确" in resp.text
    assert anon.get("/", follow_redirects=False).status_code == 302
    failed = [e for e in _audit_events(data_dir)
              if e["event"] == "panel_login" and e["result"] == "failed"]
    assert failed
    assert all("password" not in json.dumps(e) for e in failed)


def test_agent_token_cannot_open_the_panel(client, app):
    """The old token login is gone: a valid MCP key is not a panel
    credential, and there is no default credential to fall back on."""
    panel_setup(client)
    anon = TestClient(app, raise_server_exceptions=False)
    anon.get("/login")
    resp = anon.post("/login",
                     data={"token": ADMIN_TOKEN,
                           "csrf_token": anon.cookies.get("fnos_csrf")},
                     follow_redirects=False)
    assert resp.status_code == 401
    assert anon.get("/", follow_redirects=False).status_code == 302


def test_logout_clears_session(client):
    panel_setup(client)
    resp = client.post("/api/panel/logout",
                       headers={"X-CSRF-Token": client.cookies.get("fnos_csrf")},
                       follow_redirects=False)
    assert resp.status_code == 302
    assert client.get("/", follow_redirects=False).status_code == 302


def test_change_password_invalidates_old_sessions(admin_client, app, data_dir):
    old_cookie = admin_client.cookies.get("fnos_panel")
    resp = admin_client.post(
        "/api/panel/password",
        data={"current_password": PANEL_PASSWORD,
              "password": "a-brand-new-panel-pass",
              "password_confirm": "a-brand-new-panel-pass"},
        headers={"X-CSRF-Token": admin_client.cookies.get("fnos_csrf")})
    assert resp.status_code == 200
    assert resp.json() == {"status": "changed"}
    assert admin_client.get("/").status_code == 200  # re-issued cookie works

    # The pre-change cookie is dead: the session is bound to the hash.
    stale = TestClient(app, raise_server_exceptions=False)
    stale.cookies.set("fnos_panel", old_cookie)
    assert stale.get("/", follow_redirects=False).status_code == 302

    # Old password no longer works; the new one does.
    stale.cookies.delete("fnos_panel")
    stale.get("/login")
    bad = stale.post("/login", data={"password": PANEL_PASSWORD,
                                     "csrf_token": stale.cookies.get("fnos_csrf")},
                     follow_redirects=False)
    assert bad.status_code == 401
    good = stale.post("/login", data={"password": "a-brand-new-panel-pass",
                                      "csrf_token": stale.cookies.get("fnos_csrf")},
                      follow_redirects=False)
    assert good.status_code == 302
    events = [e["event"] for e in _audit_events(data_dir)]
    assert "panel_password_changed" in events


def test_change_password_requires_current_password(admin_client, data_dir):
    raw_before = (Path(data_dir) / "panel-auth.json").read_bytes()
    resp = admin_client.post(
        "/api/panel/password",
        data={"current_password": "not-the-current-one",
              "password": "another-new-panel-pass",
              "password_confirm": "another-new-panel-pass"},
        headers={"X-CSRF-Token": admin_client.cookies.get("fnos_csrf")})
    assert resp.status_code == 400
    assert "当前密码不正确" in resp.text
    assert (Path(data_dir) / "panel-auth.json").read_bytes() == raw_before


def test_password_form_requires_session(client):
    resp = client.get("/api/panel/password/form")
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "auth.required"


def test_setup_race_never_overwrites(tmp_path):
    """Two first visits: the second setup must not replace the first
    password (PanelAuthStore.replace=False)."""
    from fnos_mcp.panel_auth import PanelAuthError, PanelAuthStore

    store = PanelAuthStore(tmp_path / "panel-auth.json")
    store.set_password(PANEL_PASSWORD, replace=False)
    try:
        store.set_password("second-setup-pass", replace=False)
    except PanelAuthError as exc:
        assert exc.code == "setup.done"
    else:  # pragma: no cover - a regression would land here
        raise AssertionError("second first-run setup overwrote the password")
    assert store.verify(PANEL_PASSWORD)
    assert not store.verify("second-setup-pass")


def test_validate_password_policy():
    from fnos_mcp.panel_auth import validate_password

    assert validate_password(PANEL_PASSWORD) == {}
    assert "password" in validate_password("")
    assert "password" in validate_password(None)
    assert "password" in validate_password("1234567")
    assert "password" in validate_password("x" * 129)
    assert "password" in validate_password("bad\x7fchar")
    assert "confirm" in validate_password(PANEL_PASSWORD, "other-pass")
