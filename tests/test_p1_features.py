"""P1 iteration tests (FR-37 identity detail / FR-36 topology /
audit retention), on top of the m2-iter3 baseline (121 tests).

Covers:
- _identity_detail: hostile shapes (bool uid, string uid, huge groups,
  nested junk) yield only whitelisted, capped fields; empty -> None
- /test: detail persisted only for auth ok, dropped on expired runs;
  drawer renders the dl only for auth ok
- /api/topology: JSON shape, HTMX fragment (Chinese-only labels, no raw
  badge keys), panel sees every machine, config-error node dashed,
  stale-target entries ignored
- audit rotation: bounded archive count, deletion of overflow archives,
  line always appended
"""
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from conftest import ADMIN_TOKEN, PANEL_PASSWORD, post_csrf
from fnos_mcp.audit import AuditLog
from fnos_mcp.cli_adapter import _identity_detail
from fnos_mcp.server import create_app


def _sha(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _login(client):
    # CSRF cookie is set on the first GET /login and survives the setup
    # POST; re-fetching /login after login redirects and would hand back
    # None, so read the jar first.
    csrf = client.cookies.get("fnos_csrf")
    if not csrf:
        csrf = client.get("/login").cookies.get("fnos_csrf")
    resp = client.post("/login",
                       data={"password": PANEL_PASSWORD,
                             "password_confirm": PANEL_PASSWORD,
                             "csrf_token": csrf},
                       follow_redirects=False)
    assert resp.status_code == 302, resp.text
    return client


def _make_client(tmp_path, profiles, tokens, monkeypatch):
    data = tmp_path / "data9"
    data.mkdir(exist_ok=True)
    (data / "panel-session.key").write_bytes(os.urandom(32))
    p = tmp_path / "p9.json"
    p.write_text(json.dumps(profiles), encoding="utf-8")
    t = tmp_path / "t9.json"
    t.write_text(json.dumps(tokens), encoding="utf-8")
    monkeypatch.setenv("FNOS_CLI_BIN", str(Path(__file__).parent / "fake_cli.py"))
    app = create_app(profiles_path=str(p), tokens_path=str(t),
                     data_dir=str(data), skip_cli_check=True)
    client = TestClient(app, raise_server_exceptions=False)
    return client, app, data


def _fake_state(data_dir: Path, profile: str, **patch) -> None:
    """Write per-profile fake-CLI state (auth_mode / user_info_flat...)."""
    path = Path(data_dir) / "fnos-cli" / "fake-state.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        state = {}
    state.setdefault(profile, {}).update(patch)
    path.write_text(json.dumps(state), encoding="utf-8")


# === FR-37: identity detail extraction =====================================
def test_identity_detail_whitelists_and_caps():
    d = _identity_detail({"uid": 1000, "gid": 1000, "admin": True,
                          "groups": ["administrators", "users", "", 5, None,
                                     ["nested"]],
                          "password": "x", "token": "y"})
    assert d == {"uid": 1000, "gid": 1000, "admin": True,
                 "groups": ["administrators", "users", "5"]}
    # Cap: a hostile NAS cannot bloat the panel-state file.
    d = _identity_detail({"groups": [f"g{i}" for i in range(50)]})
    assert len(d["groups"]) == 20
    assert d["groups"][0] == "g0"


def test_identity_detail_hostile_shapes():
    # bools are ints in Python — must NOT pass as uid/gid
    assert _identity_detail({"uid": True, "gid": False}) is None
    assert _identity_detail({"uid": "1000"}) is None
    assert _identity_detail({"uid": 1.5}) is None
    assert _identity_detail({"groups": [{"name": "x"}]}) is None
    assert _identity_detail({"groups": [None, ""]}) is None
    # bool group entries are junk, not "True" strings
    assert _identity_detail({"groups": [True]}) is None
    # nothing valid -> None (no empty dict stored)
    assert _identity_detail({"user": "admin", "password": "x"}) is None
    assert _identity_detail({}) is None
    # admin=False is still meaningful and kept
    assert _identity_detail({"admin": False}) == {"admin": False}


def test_test_persists_detail_only_on_ok(admin_client, app, data_dir):
    svc = app.state.service
    svc.state.update("home", "https://192.168.1.10:5667",
                     network={"at": "2026-11-24T09:00:00+00:00", "status": "ok",
                              "latency_ms": 10, "looks_like_fnos": True})
    _fake_state(data_dir, "home", logged_in=True)
    # fake_cli default shape: {"result":"succ","userInfo":{"user":"admin",
    # "admin":true,"uid":1000,"gid":1000,"groups":[...]}}
    resp = post_csrf(admin_client, "/api/profiles/home/test")
    assert resp.status_code == 200
    body = resp.json()
    assert body["auth"]["status"] == "ok"
    assert body["auth"]["detail"] == {"uid": 1000, "gid": 1000, "admin": True,
                                      "groups": ["administrators", "users"]}
    stored = svc.state.load()["profiles"]["home"]["auth"]
    assert stored["detail"]["uid"] == 1000
    assert "password" not in stored["detail"]

    # An expired run must NOT keep a stale detail.
    _fake_state(data_dir, "home", logged_in=True, auth_mode="expired")
    resp = post_csrf(admin_client, "/api/profiles/home/test")
    assert resp.status_code == 200
    assert resp.json()["auth"]["status"] == "expired"
    assert "detail" not in resp.json()["auth"]
    stored = svc.state.load()["profiles"]["home"]["auth"]
    assert stored["status"] == "expired"
    assert "detail" not in stored


def test_drawer_renders_identity_detail_only_when_ok(admin_client, app):
    svc = app.state.service
    svc.state.update("home", "https://192.168.1.10:5667",
                     network={"at": "2026-11-24T09:00:00+00:00", "status": "ok",
                              "latency_ms": 10, "looks_like_fnos": True},
                     auth={"at": "2026-11-24T09:05:00+00:00", "status": "ok",
                           "latency_ms": 3, "identity": "admin",
                           "detail": {"uid": 1000, "gid": 1000, "admin": True,
                                      "groups": ["administrators", "users"]}})
    html = admin_client.get("/api/profiles/home/drawer").text
    assert 'id="drawerIdentityDetail"' in html
    assert "管理员" in html and "UID" in html and "GID" in html and "所属组" in html
    assert "administrators、users" in html
    assert "最近验证" in html

    # Same layers but auth expired: the detail block must vanish.
    svc.state.update("home", "https://192.168.1.10:5667",
                     auth={"at": "2026-11-24T09:06:00+00:00", "status": "expired",
                           "latency_ms": 3, "identity": None,
                           "detail": {"uid": 1000}})
    html = admin_client.get("/api/profiles/home/drawer").text
    assert 'id="drawerIdentityDetail"' not in html
    assert "最近验证" not in html
    assert "未登录" in html

    # Auth ok but detail absent (legacy flat shape): no dl, no crash.
    svc.state.update("home", "https://192.168.1.10:5667",
                     auth={"at": "2026-11-24T09:07:00+00:00", "status": "ok",
                           "latency_ms": 3, "identity": "admin"})
    html = admin_client.get("/api/profiles/home/drawer").text
    assert 'id="drawerIdentityDetail"' not in html
    assert ">admin<" in html


# === FR-36: topology ========================================================
def _topo_setup(tmp_path, monkeypatch):
    profiles = {"default_profile": "home", "profiles": {
        "home": {"host": "192.168.1.10", "port": 5667, "scheme": "https"},
        "office": {"host": "nas.office.example.com", "port": 443, "scheme": "https"},
        "vault": {"host": "", "port": 0, "scheme": "https"}}}
    tokens = {"tokens": [
        {"id": "t_admin", "name": "admin", "sha256": _sha(ADMIN_TOKEN),
         "profiles": ["home", "office", "vault"], "role": "admin"}]}
    client, app, data = _make_client(tmp_path, profiles, tokens, monkeypatch)
    svc = app.state.service
    # The auth freshness window is 24h, so stamps must be relative to now
    # (fixed dates make this test rot once the clock rolls past them).
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    svc.state.update("home", "https://192.168.1.10:5667",
                     network={"at": now, "status": "ok",
                              "latency_ms": 10, "looks_like_fnos": True},
                     auth={"at": now, "status": "ok",
                           "latency_ms": 3, "identity": "admin"})
    svc.state.update("office", "https://nas.office.example.com:443",
                     network={"at": now, "status": "refused",
                              "latency_ms": 5, "looks_like_fnos": False})
    return _login(client), app, data


def test_topology_json_shape(tmp_path, monkeypatch):
    admin, app, _data = _topo_setup(tmp_path, monkeypatch)
    resp = admin.get("/api/topology")
    assert resp.status_code == 200
    data = resp.json()
    assert "endpoint" in data["gateway"]
    names = [n["name"] for n in data["nodes"]]
    assert names == ["home", "office", "vault"]  # admin sees all incl. config-error
    by_name = {n["name"]: n for n in data["nodes"]}
    assert by_name["home"]["badge"] == "connected"
    assert by_name["home"]["identity"] == "admin"
    assert by_name["home"]["latency_ms"] == 10
    assert by_name["office"]["badge"] == "unreachable"
    assert by_name["vault"]["badge"] == "config"
    assert by_name["vault"]["target"] is None
    # No token material anywhere.
    assert ADMIN_TOKEN not in resp.text

    # No panel session -> auth.required.
    anon = TestClient(app, raise_server_exceptions=False)
    resp = anon.get("/api/topology")
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "auth.required"


def test_topology_htmx_fragment_chinese_only(tmp_path, monkeypatch):
    admin, _app, _data = _topo_setup(tmp_path, monkeypatch)
    resp = admin.get("/api/topology", headers={"HX-Request": "true"})
    assert resp.status_code == 200
    assert resp.headers.get("cache-control") == "no-store"
    html = resp.text
    assert 'id="topologyView"' in html
    assert "MCP 网关" in html
    assert "topo-node gateway" in html
    # Colors: connected -> ok, refused -> bad, config-error -> dashed link
    assert "topo-line ok" in html
    assert "topo-line bad" in html
    assert "topo-link config" in html
    # Chinese labels; raw badge keys never appear as visible text.
    # (home shows 身份 admin instead of the 已连接 label.)
    assert "网络不可达" in html and "配置错误" in html
    for raw_key in (">unreachable<", ">untested<", ">loggedout<",
                    ">connected<", ">expired<", ">permission<"):
        assert raw_key not in html
    assert "身份 admin" in html
    assert ADMIN_TOKEN not in html


def test_topology_target_change_resets_entry(admin_client, app):
    svc = app.state.service
    # State written against a DIFFERENT target must not color the node.
    svc.state.update("office", "https://old-office.example.com:443",
                     network={"at": "2026-11-24T09:00:00+00:00", "status": "ok",
                              "latency_ms": 9, "looks_like_fnos": True})
    data = admin_client.get("/api/topology").json()
    by_name = {n["name"]: n for n in data["nodes"]}
    # The route ignores state whose target no longer matches config.
    assert by_name["office"]["badge"] == "untested"


# === audit retention (P1) ===================================================
def test_audit_rotation_bounded(tmp_path, monkeypatch):
    import fnos_mcp.audit as audit_mod
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, keep=4)
    monkeypatch.setattr(audit_mod, "MAX_BYTES", 10)
    for i in range(8):
        log.record("probe", token_id="t", profile="p", latency_ms=i)
    files = sorted(p.name for p in tmp_path.iterdir())
    archives = [f for f in files if f.startswith("audit.jsonl.")]
    # Bounded: at most keep-1 archives, no archive number beyond keep-1.
    assert len(archives) <= 3
    assert all(int(f.rsplit(".", 1)[1]) <= 3 for f in archives)
    assert "audit.jsonl" in files

    def _lat(name: str) -> int:
        line = (tmp_path / name).read_text(encoding="utf-8").splitlines()[-1]
        return json.loads(line)["latency_ms"]

    # Newest-first ordering: current = 7, .1 = 6, .2 = 5, .3 = 4.
    assert _lat("audit.jsonl") == 7
    assert _lat("audit.jsonl.1") == 6
    assert _lat("audit.jsonl.2") == 5
    assert _lat("audit.jsonl.3") == 4
    # Bounded retention: only keep files' worth of lines survive (4).
    total = sum(len((tmp_path / f).read_text(encoding="utf-8").splitlines())
                for f in files if f.startswith("audit.jsonl"))
    assert total == 4


def test_audit_rotation_converges_preexisting_overflow(tmp_path, monkeypatch):
    # Archives left behind by an older version that renamed without
    # deleting (.1 ... .9): the next rotation must converge to the
    # bounded set instead of preserving the overflow forever.
    import fnos_mcp.audit as audit_mod
    path = tmp_path / "audit.jsonl"
    path.write_text("y" * 64, encoding="utf-8")  # oversized -> rotate
    for n in range(1, 10):
        (tmp_path / f"audit.jsonl.{n}").write_text(
            json.dumps({"event": "old", "n": n}) + "\n", encoding="utf-8")
    log = AuditLog(path, keep=4)
    monkeypatch.setattr(audit_mod, "MAX_BYTES", 10)
    log.record("probe", token_id="t")
    names = sorted(p.name for p in tmp_path.iterdir())
    archives = [f for f in names if f.startswith("audit.jsonl.")]
    assert len(archives) <= 3
    assert all(int(f.rsplit(".", 1)[1]) <= 3 for f in archives)
    assert "audit.jsonl" in names


def test_audit_line_appended_even_when_rotation_fails(tmp_path, monkeypatch):
    # Force rotation (oversized file) AND make every rename/unlink fail:
    # the audit line must still land, with 0600 re-applied.
    import fnos_mcp.audit as audit_mod
    path = tmp_path / "audit.jsonl"
    path.write_text("x" * 64 + "\n", encoding="utf-8")
    log = AuditLog(path, keep=3)
    monkeypatch.setattr(audit_mod, "MAX_BYTES", 10)

    real_rename = Path.rename
    real_unlink = Path.unlink

    def rename_fail(self, target):
        if str(self).startswith(str(path)):
            raise OSError("nope")
        return real_rename(self, target)

    def unlink_fail(self):
        if str(self).startswith(str(path)):
            raise OSError("nope")
        return real_unlink(self)

    monkeypatch.setattr(Path, "rename", rename_fail)
    monkeypatch.setattr(Path, "unlink", unlink_fail)

    log.record("probe", token_id="t1")
    text = path.read_text(encoding="utf-8")
    assert text.endswith("\n")
    assert json.loads(text.splitlines()[-1])["token_id"] == "t1"
    assert oct(os.stat(path).st_mode & 0o777) == "0o600"
