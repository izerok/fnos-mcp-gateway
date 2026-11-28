from conftest import PANEL_PASSWORD


def test_csrf_missing_is_403(admin_client):
    resp = admin_client.post("/api/profiles/home/probe")
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "auth.forbidden"


def test_cross_site_origin_is_403(admin_client):
    csrf = admin_client.cookies.get("fnos_csrf")
    resp = admin_client.post(
        "/api/profiles/home/probe",
        headers={"X-CSRF-Token": csrf, "Origin": "https://evil.example.com"})
    assert resp.status_code == 403


def test_forged_xff_does_not_change_rate_limit_key(client):
    # 10 failed logins from one real IP, each with a different forged XFF,
    # must still trip the per-IP limit (limit is 10 per 5 min).
    csrf = client.get("/login").cookies.get("fnos_csrf")
    # First visit sets the password (the panel has no default credential).
    resp = client.post("/login",
                       data={"password": PANEL_PASSWORD,
                             "password_confirm": PANEL_PASSWORD,
                             "csrf_token": csrf},
                       follow_redirects=False)
    assert resp.status_code == 302
    csrf = client.cookies.get("fnos_csrf")
    for i in range(10):
        resp = client.post("/login", data={"password": "wrong-password"},
                           headers={"X-CSRF-Token": csrf,
                                    "X-Forwarded-For": f"9.9.9.{i}"},
                           follow_redirects=False)
    assert resp.status_code == 429
    assert resp.json()["error"]["code"] == "rate_limited"
    assert "retry-after" in resp.headers


def test_probe_all_updates_local_profiles(tmp_path, monkeypatch):
    """probe-all: one reachable host, one refused host, both updated."""
    import json
    import os
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from pathlib import Path
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
    from fastapi.testclient import TestClient
    from fnos_mcp.server import create_app

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"fnOS"
            self.send_response(200)
            self.send_header("Server", "fnOS")
            self.send_header("Content-Length", "4")
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *a):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    try:
        profiles = tmp_path / "profiles.json"
        profiles.write_text(json.dumps({"profiles": {
            "local": {"host": "127.0.0.1", "port": port, "scheme": "http",
                      "allow_insecure_http": True, "description": "local"},
            "dead": {"host": "127.0.0.1", "port": 59997, "scheme": "http",
                     "allow_insecure_http": True, "description": "dead"},
        }}), encoding="utf-8")
        import hashlib
        tokens = tmp_path / "tokens.json"
        tokens.write_text(json.dumps({"tokens": [
            {"id": "t1", "name": "a", "sha256": hashlib.sha256(b"tok").hexdigest(),
             "profiles": ["local", "dead"], "role": "admin"}]}), encoding="utf-8")
        data = tmp_path / "data"
        data.mkdir()
        (data / "panel-session.key").write_bytes(os.urandom(32))
        fake = Path(__file__).resolve().parent / "fake_cli.py"
        monkeypatch.setenv("FNOS_CLI_BIN", str(fake))
        monkeypatch.setenv("FNOS_FAKE_STATE_FILE", str(tmp_path / "state.json"))
        app = create_app(profiles_path=str(profiles), tokens_path=str(tokens),
                         data_dir=str(data))
        client = TestClient(app, raise_server_exceptions=False)
        csrf = client.get("/login").cookies.get("fnos_csrf")
        resp = client.post("/login",
                           data={"password": PANEL_PASSWORD,
                                 "password_confirm": PANEL_PASSWORD,
                                 "csrf_token": csrf},
                           follow_redirects=False)
        assert resp.status_code == 302
        resp = client.post("/api/profiles/probe-all",
                           headers={"X-CSRF-Token": client.cookies.get("fnos_csrf")})
        assert resp.status_code == 200
        body = resp.json()
        assert body["results"]["local"]["status"] == "ok"
        assert body["results"]["dead"]["status"] == "refused"
        assert body["summary"]["counts"]["total"] == 2
    finally:
        server.shutdown()
