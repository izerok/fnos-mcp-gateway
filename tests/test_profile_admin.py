"""Admin-only profile add/edit through the panel.

The writable store is exercised with the same temporary config used by
the rest of the suite; no real token or NAS address is involved.
"""
import hashlib
import json
import os
import stat
from pathlib import Path

from fastapi.testclient import TestClient

from conftest import ADMIN_TOKEN, PANEL_PASSWORD, post_csrf
from fnos_mcp.profile_store import ensure_profile_store
from fnos_mcp.server import create_app


def _sha(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _custom_client(tmp_path, monkeypatch, profiles, tokens):
    data = tmp_path / "data-admin"
    data.mkdir(exist_ok=True)
    (data / "panel-session.key").write_bytes(os.urandom(32))
    p = tmp_path / "profiles-admin.json"
    p.write_text(json.dumps(profiles), encoding="utf-8")
    t = tmp_path / "tokens-admin.json"
    t.write_text(json.dumps(tokens), encoding="utf-8")
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
    return client, csrf, app, p


def _read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def test_admin_create_profile_writes_private_store(admin_client, profiles_path, app):
    form = admin_client.get("/api/profiles/new/form")
    assert form.status_code == 200
    assert "添加机器" in form.text
    assert 'hx-post="/api/profiles"' in form.text
    assert "allow_insecure_http" in form.text
    assert form.headers["cache-control"] == "no-store"

    resp = post_csrf(
        admin_client, "/api/profiles",
        data={"name": "lab", "host": "10.0.0.5", "port": "5667",
              "scheme": "https", "description": "lab NAS"},
        headers={"HX-Request": "true"})
    assert resp.status_code == 200, resp.text
    assert "已保存 lab" in resp.text
    assert 'hx-swap-oob="outerHTML"' in resp.text
    # The panel is the wildcard administrator: the new machine appears in
    # the OOB roster immediately.
    assert 'id="row-lab"' in resp.text

    data = _read(profiles_path)
    assert data["profiles"]["lab"] == {
        "host": "10.0.0.5", "port": 5667, "scheme": "https",
        "description": "lab NAS"}
    assert stat.S_IMODE(Path(profiles_path).stat().st_mode) == 0o600
    assert app.state.service.profiles_path == profiles_path


def test_profile_validation_keeps_store_unchanged(admin_client, profiles_path):
    before = Path(profiles_path).read_bytes()
    resp = post_csrf(
        admin_client, "/api/profiles",
        data={"name": "bad", "host": "https://evil.example/path",
              "port": "0", "scheme": "http"},
        headers={"HX-Request": "true"})
    assert resp.status_code == 400
    assert "地址格式不正确" in resp.text
    assert "端口必须是" in resp.text
    assert "HTTP 明文连接需要勾选" in resp.text
    assert Path(profiles_path).read_bytes() == before

    # Duplicate names are a field error, not a 500.
    resp = post_csrf(
        admin_client, "/api/profiles",
        data={"name": "home", "host": "10.0.0.6", "port": "5667",
              "scheme": "https"},
        headers={"HX-Request": "true"})
    assert resp.status_code == 400
    assert "机器名已存在" in resp.text
    assert Path(profiles_path).read_bytes() == before


def test_admin_edit_preserves_advanced_fields(admin_client, profiles_path):
    data = _read(profiles_path)
    data["profiles"]["home"]["authorization_hosts"] = ["https://sso.example.com"]
    data["profiles"]["home"]["allow_dangerous"] = True
    Path(profiles_path).write_text(json.dumps(data), encoding="utf-8")

    form = admin_client.get("/api/profiles/home/edit/form")
    assert form.status_code == 200
    assert "编辑 home" in form.text
    assert "192.168.1.10" in form.text

    resp = post_csrf(
        admin_client, "/api/profiles/home/edit",
        data={"name": "home", "host": "192.168.1.20", "port": "443",
              "scheme": "https", "description": "new home"},
        headers={"HX-Request": "true"})
    assert resp.status_code == 200, resp.text
    assert "机器配置已更新" in resp.text
    data = _read(profiles_path)
    home = data["profiles"]["home"]
    assert home["host"] == "192.168.1.20"
    assert home["port"] == 443
    assert home["description"] == "new home"
    assert home["authorization_hosts"] == ["https://sso.example.com"]
    assert home["allow_dangerous"] is True
    assert "allow_insecure_http" not in home
    assert stat.S_IMODE(Path(profiles_path).stat().st_mode) == 0o600

    # A stale/malicious form cannot rename and orphan the session directory.
    resp = post_csrf(
        admin_client, "/api/profiles/home/edit",
        data={"name": "office", "host": "192.168.1.20", "port": "443",
              "scheme": "https"},
        headers={"HX-Request": "true"})
    assert resp.status_code == 400
    assert "机器名保存后不可修改" in resp.text
    assert "home" in _read(profiles_path)["profiles"]


def test_admin_repairs_config_error_profile(tmp_path, monkeypatch):
    profiles = {"default_profile": "home", "profiles": {
        "home": {"host": "192.168.1.10", "port": 5667, "scheme": "https"},
        "vault": {"host": "", "port": 0, "scheme": "https"}}}
    tokens = {"tokens": [{"id": "t_admin", "name": "admin",
                          "sha256": _sha(ADMIN_TOKEN), "profiles": ["home", "vault"],
                          "role": "admin"}]}
    client, csrf, app, path = _custom_client(tmp_path, monkeypatch, profiles, tokens)
    form = client.get("/api/profiles/vault/edit/form")
    assert form.status_code == 200
    assert "现有配置不完整" in form.text
    resp = post_csrf(
        client, "/api/profiles/vault/edit",
        data={"name": "vault", "host": "10.0.0.9", "port": "5667",
              "scheme": "https"},
        headers={"HX-Request": "true"})
    assert resp.status_code == 200, resp.text
    data = _read(path)
    assert data["profiles"]["vault"]["host"] == "10.0.0.9"
    rows = {p["name"]: p for p in client.get("/api/profiles").json()["profiles"]}
    assert rows["vault"]["badge"] == "untested"
    assert client.get("/api/profiles").json()["config_errors"] == {}


def test_wildcard_acl_sees_panel_created_profile(tmp_path, monkeypatch):
    profiles = {"default_profile": "home", "profiles": {
        "home": {"host": "192.168.1.10", "port": 5667, "scheme": "https"}}}
    tokens = {"tokens": [{"id": "t_admin", "name": "admin",
                          "sha256": _sha(ADMIN_TOKEN), "profiles": ["*"],
                          "role": "admin"}]}
    client, csrf, app, path = _custom_client(tmp_path, monkeypatch, profiles, tokens)
    resp = post_csrf(
        client, "/api/profiles",
        data={"name": "lab", "host": "10.0.0.7", "port": "5667",
              "scheme": "https", "description": "wildcard lab"},
        headers={"HX-Request": "true"})
    assert resp.status_code == 200
    assert "ACL" not in resp.text
    rows = {p["name"]: p for p in client.get("/api/profiles").json()["profiles"]}
    assert set(rows) == {"home", "lab"}
    assert "lab" in client.get("/").text
    assert "lab" in _read(path)["profiles"]


def test_profile_store_seed_is_one_time_and_private(tmp_path):
    seed = tmp_path / "seed.json"
    seed.write_text(json.dumps({"profiles": {
        "home": {"host": "192.168.1.10", "port": 5667, "scheme": "https"}}}),
        encoding="utf-8")
    store = tmp_path / "data" / "profiles.json"
    result = ensure_profile_store(seed, store)
    assert result == store
    assert store.is_file()
    assert stat.S_IMODE(store.stat().st_mode) == 0o600
    first = store.read_text(encoding="utf-8")

    # A later seed change must not overwrite the writable store.
    seed.write_text(json.dumps({"profiles": {
        "other": {"host": "10.0.0.8", "port": 5667, "scheme": "https"}}}),
        encoding="utf-8")
    ensure_profile_store(seed, store)
    assert store.read_text(encoding="utf-8") == first


def test_store_env_makes_service_use_writable_copy(tmp_path, monkeypatch):
    seed = tmp_path / "seed-env.json"
    seed.write_text(json.dumps({"profiles": {
        "home": {"host": "192.168.1.10", "port": 5667, "scheme": "https"}}}),
        encoding="utf-8")
    store = tmp_path / "data-env" / "profiles.json"
    tokens = tmp_path / "tokens-env.json"
    tokens.write_text(json.dumps({"tokens": [{
        "id": "t_admin", "name": "admin", "sha256": _sha(ADMIN_TOKEN),
        "profiles": ["*"], "role": "admin"}]}), encoding="utf-8")
    data = tmp_path / "data-env"
    data.mkdir(exist_ok=True)
    (data / "panel-session.key").write_bytes(os.urandom(32))
    monkeypatch.setenv("FNOS_PROFILES_STORE", str(store))
    monkeypatch.setenv("FNOS_CLI_BIN", str(Path(__file__).parent / "fake_cli.py"))
    app = create_app(profiles_path=str(seed), tokens_path=str(tokens),
                     data_dir=str(data))
    assert app.state.service.profiles_path == str(store)
    assert store.is_file()
    assert json.loads(seed.read_text(encoding="utf-8"))["profiles"].keys() == {"home"}
    assert stat.S_IMODE(store.stat().st_mode) == 0o600
