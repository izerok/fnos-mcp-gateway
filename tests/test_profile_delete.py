"""Manual profile delete through the panel (POST /api/profiles/{name}/delete).

Guards mirror add/edit: panel session + ACL (outside = 404) + Origin +
profile_write rate limit + CSRF + manage_profiles capability. Deleting
also drops the panel-state record and releases a pending login lease,
and the roster fragment renders the zero_config empty state when the
last machine is gone.
"""
import hashlib
import json
import os
from pathlib import Path

from fastapi.testclient import TestClient

from conftest import ADMIN_TOKEN, PANEL_PASSWORD, post_csrf
from fnos_mcp.locks import acquire_login_lease
from fnos_mcp.server import create_app


def _sha(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _audit_events(data_dir):
    path = Path(data_dir) / "audit.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in
            path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _wildcard_admin_client(tmp_path, monkeypatch):
    """Panel session, for the not-found case (a name absent from the
    store)."""
    data = tmp_path / "data-del-wild"
    data.mkdir(exist_ok=True)
    (data / "panel-session.key").write_bytes(os.urandom(32))
    p = tmp_path / "profiles-del-wild.json"
    p.write_text(json.dumps({"default_profile": "home", "profiles": {
        "home": {"host": "192.168.1.10", "port": 5667, "scheme": "https"}}}),
        encoding="utf-8")
    t = tmp_path / "tokens-del-wild.json"
    t.write_text(json.dumps({"tokens": [{
        "id": "t_admin", "name": "admin", "sha256": _sha(ADMIN_TOKEN),
        "profiles": ["*"], "role": "admin"}]}), encoding="utf-8")
    monkeypatch.setenv("FNOS_CLI_BIN", str(Path(__file__).parent / "fake_cli.py"))
    app = create_app(profiles_path=str(p), tokens_path=str(t), data_dir=str(data))
    client = TestClient(app, raise_server_exceptions=False)
    csrf = client.get("/login").cookies.get("fnos_csrf")
    resp = client.post("/login",
                       data={"password": PANEL_PASSWORD,
                             "password_confirm": PANEL_PASSWORD,
                             "csrf_token": csrf},
                       follow_redirects=False)
    assert resp.status_code == 302, resp.text
    return client


def test_admin_delete_removes_store_state_lease_and_audits(
        admin_client, profiles_path, app, data_dir):
    svc = app.state.service
    # Seed a panel-state record and a pending login lease for office.
    svc.state.update("office", "https://nas.office.example.com:443",
                     network={"at": "2026-11-24T10:20:00+00:00", "status": "ok",
                              "latency_ms": 3, "detail": "ok"})
    assert acquire_login_lease(data_dir, "office") is True
    assert (Path(data_dir) / "locks" / "pending-office.json").exists()

    resp = post_csrf(admin_client, "/api/profiles/office/delete",
                     headers={"HX-Request": "true"})
    assert resp.status_code == 200, resp.text
    assert 'data-deleted="office"' in resp.text
    assert 'id="row-office"' not in resp.text
    assert 'id="row-home"' in resp.text
    assert resp.headers["cache-control"] == "no-store"

    data = _read(profiles_path)
    assert "office" not in data["profiles"]
    assert "home" in data["profiles"]
    assert "office" not in svc.state.load()["profiles"]
    assert not (Path(data_dir) / "locks" / "pending-office.json").exists()
    events = [e for e in _audit_events(data_dir)
              if e["event"] == "profile_deleted"]
    assert events and events[-1]["profile"] == "office"
    assert events[-1]["token_id"] == "panel"
    assert events[-1]["result"] == "ok"

    # JSON clients get the same outcome without the fragment.
    resp = post_csrf(admin_client, "/api/profiles/home/delete")
    assert resp.status_code == 200
    assert resp.json() == {"profile": "home", "status": "deleted"}


def test_delete_without_csrf_is_forbidden(admin_client, profiles_path):
    before = Path(profiles_path).read_bytes()
    resp = admin_client.post("/api/profiles/office/delete")
    assert resp.status_code == 403
    assert Path(profiles_path).read_bytes() == before


def test_delete_default_profile_clears_default(admin_client, profiles_path):
    data = _read(profiles_path)
    assert data["default_profile"] == "home"
    resp = post_csrf(admin_client, "/api/profiles/home/delete")
    assert resp.status_code == 200
    data = _read(profiles_path)
    assert "home" not in data["profiles"]
    assert data["default_profile"] is None
    assert "office" in data["profiles"]


def test_delete_nonexistent_is_not_found(tmp_path, monkeypatch):
    client = _wildcard_admin_client(tmp_path, monkeypatch)
    resp = post_csrf(client, "/api/profiles/ghost/delete")
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "profile.not_found"


def test_delete_last_machine_lands_on_zero_config_empty_state(
        admin_client, profiles_path):
    post_csrf(admin_client, "/api/profiles/home/delete",
              headers={"HX-Request": "true"})
    resp = post_csrf(admin_client, "/api/profiles/office/delete",
                     headers={"HX-Request": "true"})
    assert resp.status_code == 200, resp.text
    # The roster fragment itself carries the zero_config empty state.
    assert "还没有配置机器" in resp.text
    assert _read(profiles_path)["profiles"] == {}
    html = admin_client.get("/").text
    assert "还没有配置机器" in html
    assert "添加机器" in html
