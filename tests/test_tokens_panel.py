"""M5 agent-key (ACL) panel: create / rotate / edit / delete, one-time
plaintext, hashed storage, MCP ACL enforcement and route guards."""
import hashlib
import html as html_mod
import json
import os
import re
import stat
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from conftest import ADMIN_TOKEN, PANEL_PASSWORD, panel_setup, post_csrf
from fnos_mcp.auth import verify_bearer
from fnos_mcp.config import load_tokens
from fnos_mcp.server import create_app
from fnos_mcp.token_store import (SecretBox, TokenStore, TokenStoreError,
                                  ensure_token_store)
from fnos_mcp.tools.registry import ToolContext, ToolError, resolve_profile


def _create(client, name, profiles, role="operator", capabilities=None,
            scope_all=False):
    data = {"name": name, "role": role, "profiles": list(profiles)}
    if capabilities:
        data["capabilities"] = list(capabilities)
    if scope_all:
        data["scope_all"] = "on"
    return post_csrf(client, "/api/tokens", data=data)


def _stored(app):
    return load_tokens(app.state.service.tokens_path)


def test_create_stores_hash_and_recoverable_secret(admin_client, app, data_dir):
    resp = _create(admin_client, "agent-a", ["home"])
    assert resp.status_code == 200, resp.text
    body = resp.json()
    plaintext = body["plaintext"]
    entry = body["token"]
    assert entry["name"] == "agent-a"
    assert entry["profiles"] == ["home"] and entry["all_machines"] is False
    assert entry["role"] == "operator"
    assert entry["copyable"] is True
    assert len(entry["fingerprint"]) == 8
    assert "sha256" not in entry and "plaintext" not in entry
    assert "key_enc" not in entry
    # The ready-to-paste client config exists only in the one-time HTML
    # view, never in the JSON API shape.
    assert "mcpServers" not in resp.text and "client_config" not in body

    store_text = Path(app.state.service.tokens_path).read_text(encoding="utf-8")
    assert plaintext not in store_text
    assert hashlib.sha256(plaintext.encode()).hexdigest() in store_text
    stored = [t for t in json.loads(store_text)["tokens"]
              if t["id"] == entry["id"]][0]
    assert stored["key_enc"] and plaintext not in stored["key_enc"]

    # The list endpoint never returns the hash, ciphertext or plaintext.
    listed = admin_client.get("/api/tokens").json()
    keys = [t for t in listed["tokens"] if t["id"] == entry["id"]]
    assert keys and keys[0]["fingerprint"] == entry["fingerprint"]
    assert keys[0]["copyable"] is True
    assert "key_enc" not in keys[0]
    html = admin_client.get("/").text
    assert plaintext not in html
    assert hashlib.sha256(plaintext.encode()).hexdigest() not in html
    assert "访问密钥" in html and "agent-a" in html

    # The created key authenticates MCP and is held to its ACL.
    recs = _stored(app)
    key = [r for r in recs if r.name == "agent-a"][0]
    assert verify_bearer(plaintext, recs) is key
    svc = app.state.service
    ctx = ToolContext(token=key, profiles=svc.profile_store.load(),
                      cli=svc.cli, state=svc.state, audit=svc.audit)
    assert resolve_profile(ctx, {"profile": "home"}).name == "home"
    with pytest.raises(ToolError) as exc:
        resolve_profile(ctx, {"profile": "office"})
    assert exc.value.code == "profile.not_found"
    # The seeded admin key (mounted tokens.json) still works for MCP.
    assert verify_bearer(ADMIN_TOKEN, recs).name == "admin"


def test_created_fragment_has_copy_and_pasteable_config(admin_client, app):
    """The one-time HTMX view must offer copy controls and a config that
    can be pasted straight into an MCP client (key + public endpoint)."""
    resp = post_csrf(admin_client, "/api/tokens",
                     data={"name": "agent-copy", "role": "operator",
                           "profiles": ["home"]},
                     headers={"HX-Request": "true"})
    assert resp.status_code == 200, resp.text
    body = resp.text
    assert 'id="copyTokenBtn"' in body and "复制密钥" in body
    assert 'id="copyTokenConfigBtn"' in body and "复制客户端配置" in body
    assert 'id="tokenClientConfig" hidden' in body
    assert "no-store" in resp.headers.get("cache-control", "")

    plaintext = html_mod.unescape(
        re.search(r'id="tokenPlaintext"[^>]*>([^<]+)<', body).group(1))
    raw_config = html_mod.unescape(
        re.search(r'<pre id="tokenClientConfig" hidden>(.*?)</pre>',
                  body, re.S).group(1))
    config = json.loads(raw_config)["mcpServers"]["fnos"]
    expected_url = (app.state.service.mcp_public_url
                    or "http://testserver/mcp")
    assert config == {
        "type": "http",
        "url": expected_url,
        "headers": {"Authorization": f"Bearer {plaintext}"},
    }
    # Outside this one response the key is nowhere on the panel.
    assert plaintext not in admin_client.get("/").text


def test_index_puts_keys_before_integration_cards(admin_client):
    resp = admin_client.get("/")
    body = resp.text
    assert resp.headers.get("cache-control") == "no-store"
    assert body.index('class="paper keys"') < body.index(
        'class="paper topology-section"')
    assert "count-pill" in body


def test_list_secret_endpoint_returns_key_and_config(admin_client, app):
    created = _create(admin_client, "agent-secret", ["home"]).json()
    key_id = created["token"]["id"]
    plaintext = created["plaintext"]
    resp = admin_client.get(f"/api/tokens/{key_id}/secret")
    assert resp.status_code == 200, resp.text
    assert resp.headers.get("cache-control") == "no-store"
    data = resp.json()
    assert data["key"] == plaintext
    config = json.loads(data["config"])["mcpServers"]["fnos"]
    expected_url = app.state.service.mcp_public_url or "http://testserver/mcp"
    assert config == {
        "type": "http", "url": expected_url,
        "headers": {"Authorization": f"Bearer {plaintext}"},
    }
    # The row offers both copy actions but the page itself has no secret.
    html = admin_client.get("/").text
    assert f'data-id="{key_id}" data-mode="key"' in html
    assert f'data-id="{key_id}" data-mode="config"' in html
    assert plaintext not in html
    # Reveal is audited with the key id and never with the plaintext.
    audit_text = (Path(app.state.service.data_dir) / "audit.jsonl").read_text(
        encoding="utf-8")
    assert "token_secret_read" in audit_text
    assert key_id in audit_text
    assert plaintext not in audit_text


def test_seeded_key_is_not_copyable(admin_client):
    resp = admin_client.get("/api/tokens/t_admin/secret")
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "token.unavailable"
    html = admin_client.get("/").text
    assert "早期密钥" in html
    assert 'data-id="t_admin" data-mode="key"' not in html


def test_rotated_seed_key_becomes_copyable(admin_client):
    resp = post_csrf(admin_client, "/api/tokens/t_admin/rotate",
                     headers={"HX-Request": "true"})
    assert resp.status_code == 200, resp.text
    secret = admin_client.get("/api/tokens/t_admin/secret")
    assert secret.status_code == 200
    assert secret.json()["key"] in secret.json()["config"]


def test_secret_endpoint_requires_panel(client):
    resp = client.get("/api/tokens/t_admin/secret")
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "auth.required"


def test_secret_box_binds_key_id_and_secret():
    box = SecretBox(b"unit-test-secret-value-0123456789")
    blob = box.seal("key-1", "tok-abc")
    assert box.open("key-1", blob) == "tok-abc"
    assert box.open("key-2", blob) is None
    assert SecretBox(b"another-secret-value-0123456789").open("key-1", blob) is None
    assert box.open("key-1", "not-base64") is None
    assert box.open("key-1", None) is None


def test_changed_session_secret_marks_key_not_copyable(tmp_path):
    path = tmp_path / "tokens.json"
    path.write_text(json.dumps({"tokens": []}), encoding="utf-8")
    first = TokenStore(path, b"first-session-secret-0123456789")
    entry, _plaintext = first.create("k-secret", ["home"], "operator", [])
    second = TokenStore(path, b"other-session-secret-0123456789")
    listed = second.list_entries()[0]
    assert listed["id"] == entry["id"] and listed["copyable"] is False
    _entry, plaintext = second.secret_for(entry["id"])
    assert plaintext is None


def test_scope_all_and_delegated_capabilities(admin_client, app):
    resp = _create(admin_client, "agent-all", [], role="operator",
                   capabilities=["manage_login"], scope_all=True)
    assert resp.status_code == 200, resp.text
    key = [r for r in _stored(app) if r.name == "agent-all"][0]
    assert key.profiles == ["*"]
    assert key.can_manage_login
    assert key.allows("office") and key.allows("a-future-machine")


def test_rotate_invalidates_old_plaintext(admin_client, app):
    created = _create(admin_client, "agent-b", ["home"]).json()
    old = created["plaintext"]
    resp = post_csrf(admin_client, f"/api/tokens/{created['token']['id']}/rotate")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    new = body["plaintext"]
    assert body["token"]["id"] == created["token"]["id"]
    assert new != old
    recs = _stored(app)
    assert verify_bearer(old, recs) is None
    assert verify_bearer(new, recs).name == "agent-b"


def test_edit_acl_and_role(admin_client, app):
    created = _create(admin_client, "agent-c", ["home"])
    key_id = created.json()["token"]["id"]
    old_key = created.json()["plaintext"]
    form = admin_client.get(f"/api/tokens/{key_id}/edit/form")
    assert form.status_code == 200
    assert "编辑密钥 agent-c" in form.text
    assert 'name="profiles" value="home"' in form.text

    resp = post_csrf(admin_client, f"/api/tokens/{key_id}/edit",
                     data={"name": "agent-c2", "role": "admin",
                           "profiles": ["office"],
                           "capabilities": ["manage_login"]})
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "updated"
    key = [r for r in _stored(app) if r.id == key_id][0]
    assert key.name == "agent-c2" and key.role == "admin"
    assert key.profiles == ["office"]
    assert key.can_manage_login and key.can_manage_profiles
    # ACL edit does not touch the credential itself.
    assert verify_bearer(old_key, _stored(app)).id == key_id


def test_delete_removes_key(admin_client, app):
    created = _create(admin_client, "agent-d", ["home"])
    key_id = created.json()["token"]["id"]
    plaintext = created.json()["plaintext"]
    resp = post_csrf(admin_client, f"/api/tokens/{key_id}/delete")
    assert resp.status_code == 200
    assert resp.json() == {"token": key_id, "status": "deleted"}
    assert all(r.id != key_id for r in _stored(app))
    assert verify_bearer(plaintext, _stored(app)) is None
    listed = admin_client.get("/api/tokens").json()
    assert all(t["id"] != key_id for t in listed["tokens"])
    again = post_csrf(admin_client, f"/api/tokens/{key_id}/delete")
    assert again.status_code == 404
    assert again.json()["error"]["code"] == "token.not_found"


def test_validation_errors_keep_store_unchanged(admin_client, app):
    path = Path(app.state.service.tokens_path)
    before = path.read_bytes()
    resp = _create(admin_client, "", ["home"])
    assert resp.status_code == 400
    assert "请填写密钥名称" in resp.text
    resp = _create(admin_client, "agent-x", ["bad name!"])
    assert resp.status_code == 400
    assert "机器名不合法" in resp.text
    resp = _create(admin_client, "agent-x", ["home"], role="root")
    assert resp.status_code == 400
    assert "角色不正确" in resp.text
    resp = _create(admin_client, "agent-x", ["home"], capabilities=["wipe_disk"])
    assert resp.status_code == 400
    assert "未知能力" in resp.text
    # Duplicate names are rejected, case-sensitively exact.
    assert _create(admin_client, "dup-key", ["home"]).status_code == 200
    before = path.read_bytes()
    resp = _create(admin_client, "dup-key", ["office"])
    assert resp.status_code == 400
    assert "名称已存在" in resp.text
    assert path.read_bytes() == before


def test_route_guards(client, app):
    anon = TestClient(app, raise_server_exceptions=False)
    resp = anon.post("/api/tokens", data={"name": "x", "role": "operator"})
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "auth.required"

    panel_setup(client)
    csrf = client.cookies.get("fnos_csrf")
    resp = client.post("/api/tokens", data={"name": "x", "role": "operator"})
    assert resp.status_code == 403  # no CSRF
    resp = client.post("/api/tokens",
                       data={"name": "x", "role": "operator", "csrf_token": csrf},
                       headers={"Origin": "https://evil.example.com"})
    assert resp.status_code == 403
    resp = client.post("/api/tokens",
                       data={"name": "x", "role": "operator", "csrf_token": csrf})
    assert resp.status_code == 200
    resp = client.get("/api/tokens/new/form")
    assert resp.status_code == 200
    assert 'hx-post="/api/tokens"' in resp.text
    assert 'id="keyScopeAll"' in resp.text


def test_audit_records_key_id_only(admin_client, data_dir):
    created = _create(admin_client, "agent-e", ["home"]).json()
    key_id = created["token"]["id"]
    plaintext = created["plaintext"]
    post_csrf(admin_client, f"/api/tokens/{key_id}/rotate")
    post_csrf(admin_client, f"/api/tokens/{key_id}/delete")
    audit_path = Path(data_dir) / "audit.jsonl"
    text = audit_path.read_text(encoding="utf-8")
    events = [json.loads(line) for line in text.splitlines() if line.strip()]
    wanted = [e for e in events if e["event"].startswith("token_")]
    assert {e["event"] for e in wanted} >= {"token_created", "token_rotated",
                                            "token_deleted"}
    assert all(e.get("key_id") == key_id for e in wanted)
    assert plaintext not in text
    stored_hash = hashlib.sha256(plaintext.encode()).hexdigest()
    assert stored_hash not in text


def test_token_store_limit(tmp_path):
    path = tmp_path / "tokens.json"
    path.write_text(json.dumps({"tokens": []}), encoding="utf-8")
    store = TokenStore(path, b"unit-test-token-store-secret")
    for i in range(50):
        store.create(f"k{i}", ["home"], "operator", [])
    with pytest.raises(TokenStoreError) as exc:
        store.create("overflow", ["home"], "operator", [])
    assert exc.value.code == "token.limit"
    assert len(store.list_entries()) == 50


def test_ensure_token_store_copies_seed_once(tmp_path):
    seed = tmp_path / "seed.json"
    seed.write_text(json.dumps({"tokens": [{
        "id": "t_admin", "name": "admin",
        "sha256": hashlib.sha256(ADMIN_TOKEN.encode()).hexdigest(),
        "profiles": ["*"], "role": "admin"}]}), encoding="utf-8")
    store = tmp_path / "data" / "tokens.json"
    result = ensure_token_store(seed, store)
    assert result == store and store.is_file()
    assert stat.S_IMODE(store.stat().st_mode) == 0o600
    first = store.read_text(encoding="utf-8")
    assert json.loads(first) == json.loads(seed.read_text(encoding="utf-8"))

    # A later seed change must not overwrite the panel-owned store.
    seed.write_text(json.dumps({"tokens": []}), encoding="utf-8")
    ensure_token_store(seed, store)
    assert store.read_text(encoding="utf-8") == first


def test_store_env_makes_service_use_writable_copy(tmp_path, monkeypatch):
    seed = tmp_path / "seed-env.json"
    seed.write_text(json.dumps({"tokens": [{
        "id": "t_admin", "name": "admin",
        "sha256": hashlib.sha256(ADMIN_TOKEN.encode()).hexdigest(),
        "profiles": ["*"], "role": "admin"}]}), encoding="utf-8")
    profiles = tmp_path / "profiles-env.json"
    profiles.write_text(json.dumps({"profiles": {
        "home": {"host": "192.168.1.10", "port": 5667, "scheme": "https"}}}),
        encoding="utf-8")
    data = tmp_path / "data-env"
    data.mkdir()
    (data / "panel-session.key").write_bytes(os.urandom(32))
    store = data / "tokens.json"
    monkeypatch.setenv("FNOS_TOKENS_STORE", str(store))
    monkeypatch.setenv("FNOS_CLI_BIN", str(Path(__file__).parent / "fake_cli.py"))
    app = create_app(profiles_path=str(profiles), tokens_path=str(seed),
                     data_dir=str(data))
    assert app.state.service.tokens_path == str(store)
    assert app.state.service.tokens_seed_path == str(seed)
    assert store.is_file()
    assert stat.S_IMODE(store.stat().st_mode) == 0o600
    # The read-only seed is untouched.
    assert json.loads(seed.read_text(encoding="utf-8"))["tokens"][0]["id"] == "t_admin"
    # The MCP verifier reads the writable store.
    client = TestClient(app, raise_server_exceptions=False)
    csrf = client.get("/login").cookies.get("fnos_csrf")
    client.post("/login", data={"password": PANEL_PASSWORD,
                                "password_confirm": PANEL_PASSWORD,
                                "csrf_token": csrf}, follow_redirects=False)
    resp = _create(client, "agent-f", ["home"])
    assert resp.status_code == 200
    assert "agent-f" in store.read_text(encoding="utf-8")
    assert "agent-f" not in seed.read_text(encoding="utf-8")
