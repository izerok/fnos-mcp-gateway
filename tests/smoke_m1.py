#!/usr/bin/env python3
"""M1 smoke test: real uvicorn + fake CLI, no real NAS, no real CLI binary.

Prints PASS/FAIL per step and exits non-zero on any failure.
Usage: .venv/bin/python /tmp/smoke-m1.py
"""
import asyncio
import hashlib
import http.server
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import urllib.error

BASE = "http://127.0.0.1:18081"
PANEL_PASSWORD = "{{SECRET_qm2v7r4c}}"
results = []


def check(name, cond, detail=""):
    results.append((name, bool(cond), detail))
    print(f"{'PASS' if cond else 'FAIL'}  {name}  {detail}")


async def _mcp_smoke(token):
    """Real MCP SDK client over Streamable HTTP (FastMCP 2)."""
    from mcp.client.streamable_http import streamablehttp_client
    from mcp import ClientSession

    def _factory(**kw):
        import httpx
        kw["trust_env"] = False  # sandbox egress proxy must not touch localhost
        return httpx.AsyncClient(**kw)

    async with streamablehttp_client(
            BASE + "/mcp", headers={"Authorization": f"Bearer {token}"},
            httpx_client_factory=_factory) as (read, write, _sid):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            check("MCP initialize", init.serverInfo.name == "fnos-mcp",
                  str(init.serverInfo))
            tools = await session.list_tools()
            names = [t.name for t in tools.tools]
            CORE_TOOLS = {"fnos_profiles", "fnos_login_start",
                          "fnos_login_finish", "fnos_logout", "fnos_status",
                          "fnos_system_info", "fnos_storage_overview",
                          "fnos_storage_pools", "fnos_storage_disks",
                          "fnos_file_ls", "fnos_docker_ps", "fnos_monitor_cpu"}
            check("POST /mcp tools/list -> core tools present", CORE_TOOLS <= set(names), str(names))
            result = await session.call_tool("fnos_profiles", {})
            payload = json.loads(result.content[0].text)
            check("POST /mcp fnos_profiles -> 2 profiles",
                  [p["name"] for p in payload["profiles"]] == ["home", "office"])


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"<html><head><title>fnOS</title></head><body>fnOS</body></html>"
        self.send_response(200)
        self.send_header("Server", "fnOS/1.2")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def req(method, path, data=None, headers=None, jar=None):
    h = dict(headers or {})
    body = None
    if data is not None:
        if isinstance(data, dict):
            body = urllib.parse.urlencode(data).encode()
            h["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            body = data if isinstance(data, bytes) else data.encode()
    r = urllib.request.Request(BASE + path, data=body, method=method, headers=h)
    if jar:
        r.add_header("Cookie", "; ".join(f"{k}={v}" for k, v in jar.items()))
    try:
        with _OPENER.open(r, timeout=30) as resp:
            return resp.status, resp.read(), resp.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read(), e.headers


def main():
    import urllib.parse  # noqa
    tmp = tempfile.mkdtemp(prefix="fnos-smoke-")
    data = os.path.join(tmp, "data")
    os.makedirs(data)
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]
    profiles = {"default_profile": "home", "profiles": {
        "home": {"host": "127.0.0.1", "port": port, "scheme": "http",
                 "allow_insecure_http": True, "description": "本地冒烟机"},
        "office": {"host": "127.0.0.1", "port": 59996, "scheme": "http",
                   "allow_insecure_http": True, "description": "断开的机器"}}}
    open(os.path.join(tmp, "profiles.json"), "w").write(json.dumps(profiles))
    token = "smoke-admin-token-001"
    open(os.path.join(tmp, "tokens.json"), "w").write(json.dumps({"tokens": [{
        "id": "t_admin", "name": "admin",
        "sha256": hashlib.sha256(token.encode()).hexdigest(),
        "profiles": ["home", "office"], "role": "admin"}]}))
    open(os.path.join(data, "panel-session.key"), "wb").write(os.urandom(32))
    env = dict(os.environ)
    env.update({
        "FNOS_PROFILES_PATH": os.path.join(tmp, "profiles.json"),
        "FNOS_TOKENS_PATH": os.path.join(tmp, "tokens.json"),
        "FNOS_DATA_DIR": data,
        "FNOS_CLI_BIN": os.path.abspath("tests/fake_cli.py"),
        "MCP_PORT": "18081",
    })
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "fnos_mcp.server:create_app",
         "--factory", "--host", "127.0.0.1", "--port", "18081", "--workers", "1"],
        env=env, cwd=os.getcwd(), stdout=open(os.path.join(tmp, "uvicorn.log"), "w"),
        stderr=subprocess.STDOUT)
    try:
        ok = False
        for _ in range(30):
            try:
                s, b, _ = req("GET", "/healthz")
                if s == 200:
                    ok = True
                    break
            except Exception:
                pass
            time.sleep(0.5)
        check("healthz 200 + cli 0.6.2", ok and json.loads(b)["cli_version"] == "0.6.2",
              b.decode()[:120] if ok else "server did not start")
        if not ok:
            print(open(os.path.join(tmp, "uvicorn.log")).read()[-2000:])
            return 1
        # Login page sets CSRF cookie; first visit is the password setup.
        s, b, h = req("GET", "/login")
        check("GET /login 200 (setup page)", s == 200 and "设置管理员密码" in b.decode(errors="replace"))
        jar = {}
        for morsel in (h.get_all("Set-Cookie") or []):
            k, _, v = morsel.partition("="); jar[k] = v.split(";")[0]
        csrf = jar.get("fnos_csrf", "")
        check("CSRF cookie issued", bool(csrf))
        # First run: set the admin password -> 302 + panel cookie.
        s, b, h = req("POST", "/login",
                      {"password": PANEL_PASSWORD,
                       "password_confirm": PANEL_PASSWORD},
                      {"X-CSRF-Token": csrf}, jar)
        check("POST /login first-run setup -> 302", s == 302, f"got {s}")
        for morsel in (h.get_all("Set-Cookie") or []):
            k, _, v = morsel.partition("="); jar[k] = v.split(";")[0]
        check("panel cookie set", "fnos_panel" in jar)
        csrf = jar.get("fnos_csrf", csrf)
        # Wrong password -> 401 (never accepted, never changes the stored one).
        s, b, _ = req("POST", "/login", {"password": "wrong-password"},
                      {"X-CSRF-Token": csrf}, jar)
        check("POST /login wrong password -> 401", s == 401, f"got {s}")
        # Unauthenticated (fresh jar) -> 401 on API.
        s, b, _ = req("GET", "/api/profiles")
        check("GET /api/profiles unauth -> 401", s == 401, f"got {s}")
        # Authenticated list.
        s, b, _ = req("GET", "/api/profiles", headers={}, jar=jar)
        body = json.loads(b) if s == 200 else {}
        check("GET /api/profiles -> home+office", s == 200 and
              [p["name"] for p in body.get("profiles", [])] == ["home", "office"], b.decode()[:200])
        # probe-all: home ok, office refused.
        s, b, _ = req("POST", "/api/profiles/probe-all",
                      headers={"X-CSRF-Token": csrf}, jar=jar)
        body = json.loads(b) if s == 200 else {}
        check("POST probe-all -> home ok / office refused", s == 200 and
              body.get("results", {}).get("home", {}).get("status") == "ok" and
              body.get("results", {}).get("office", {}).get("status") == "refused",
              b.decode()[:300])
        # test connection (fake CLI logged out) -> logged_out.
        s, b, _ = req("POST", "/api/profiles/home/test",
                      headers={"X-CSRF-Token": csrf}, jar=jar)
        body = json.loads(b) if s == 200 else {}
        check("POST home/test -> logged_out", s == 200 and
              body.get("auth", {}).get("status") == "logged_out", b.decode()[:200])
        # login start -> authorization_url + no-store.
        s, b, h = req("POST", "/api/profiles/home/login/start",
                      headers={"X-CSRF-Token": csrf, "HX-Request": "true"}, jar=jar)
        check("POST login/start 200 + no-store", s == 200 and
              h.get("Cache-Control") == "no-store" and b"oauth/authorize" in b, f"got {s}")
        # login finish with good code -> connected.
        s, b, _ = req("POST", "/api/profiles/home/login/finish",
                      {"code": "abc-123"}, {"X-CSRF-Token": csrf}, jar)
        body = json.loads(b) if s == 200 else {}
        check("POST login/finish abc-123 -> connected", s == 200 and
              body.get("status") == "connected", b.decode()[:200])
        # MCP over Streamable HTTP (FastMCP 2; raw JSON-RPC shape is gone).
        asyncio.run(_mcp_smoke(token))
        # Panel index renders.
        s, b, _ = req("GET", "/", headers={}, jar=jar)
        check("GET / renders panel", s == 200 and "fnOS" in b.decode(errors="replace"))
        # Audit file has events and no secrets.
        audit = open(os.path.join(data, "audit.jsonl")).read()
        check("audit.jsonl has login/probe events, no secrets",
              "login_started" in audit and "probe_all" in audit
              and token not in audit and PANEL_PASSWORD not in audit)
        print(f"\nSMOKE DIR: {tmp}")
        failed = [n for n, ok_, _ in results if not ok_]
        print(f"SMOKE: {len(results)-len(failed)}/{len(results)} passed")
        return 1 if failed else 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        httpd.shutdown()


if __name__ == "__main__":
    sys.exit(main())
