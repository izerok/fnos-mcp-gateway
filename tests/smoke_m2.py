#!/usr/bin/env python3
"""M2 smoke: real uvicorn + fake CLI + real MCP SDK client over HTTP.

Covers: load probe-all attrs, 9 badge samples, 409 fragments, FR-21
rejection, empty states, FastMCP initialize/tools/list/tools/call over
Streamable HTTP, plus the M1 regressions (healthz/login/probe-all).
Prints PASS/FAIL per step and exits non-zero on any failure.
Usage: .venv/bin/python tests/smoke_m2.py  (run from repo root)
"""
import asyncio
import fcntl
import hashlib
import http.server
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import urllib.error

BASE = "http://127.0.0.1:18082"
BASE2 = "http://127.0.0.1:18083"
PANEL_PASSWORD = "{{SECRET_8f3kxm2p}}"
results = []


def check(name, cond, detail=""):
    results.append((name, bool(cond), detail))
    print(f"{'PASS' if cond else 'FAIL'}  {name}  {detail}")


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


def req(base, method, path, data=None, headers=None, jar=None):
    h = dict(headers or {})
    body = None
    if data is not None:
        if isinstance(data, dict):
            body = urllib.parse.urlencode(data).encode()
            h["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            body = data if isinstance(data, bytes) else data.encode()
    r = urllib.request.Request(base + path, data=body, method=method, headers=h)
    if jar:
        r.add_header("Cookie", "; ".join(f"{k}={v}" for k, v in jar.items()))
    try:
        with _OPENER.open(r, timeout=30) as resp:
            return resp.status, resp.read(), resp.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read(), e.headers


def _jar_from(headers):
    jar = {}
    for morsel in (headers.get_all("Set-Cookie") or []):
        k, _, v = morsel.partition("=")
        jar[k] = v.split(";")[0]
    return jar


def _start_server(tmp, port, profiles, token):
    data = os.path.join(tmp, f"data{port}")
    os.makedirs(data)
    open(os.path.join(tmp, f"profiles{port}.json"), "w").write(json.dumps(profiles))
    open(os.path.join(tmp, f"tokens{port}.json"), "w").write(json.dumps({"tokens": [{
        "id": "t_admin", "name": "admin",
        "sha256": hashlib.sha256(token.encode()).hexdigest(),
        "profiles": list(profiles["profiles"].keys()), "role": "admin"}]}))
    open(os.path.join(data, "panel-session.key"), "wb").write(os.urandom(32))
    env = dict(os.environ)
    env.update({
        "FNOS_PROFILES_PATH": os.path.join(tmp, f"profiles{port}.json"),
        "FNOS_TOKENS_PATH": os.path.join(tmp, f"tokens{port}.json"),
        "FNOS_DATA_DIR": data,
        "FNOS_CLI_BIN": os.path.abspath("tests/fake_cli.py"),
        "MCP_PORT": str(port),
    })
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "fnos_mcp.server:create_app",
         "--factory", "--host", "127.0.0.1", "--port", str(port), "--workers", "1"],
        env=env, cwd=os.getcwd(), stdout=open(os.path.join(tmp, f"uvicorn{port}.log"), "w"),
        stderr=subprocess.STDOUT)
    return proc, data


def _wait_up(base):
    for _ in range(30):
        try:
            s, b, _ = req(base, "GET", "/healthz")
            if s == 200:
                return json.loads(b)
        except Exception:
            pass
        time.sleep(0.5)
    return None


def _login(base):
    """First visit sets the panel password (no default credential)."""
    s, b, h = req(base, "GET", "/login")
    jar = _jar_from(h)
    csrf = jar.get("fnos_csrf", "")
    s, b, h = req(base, "POST", "/login",
                  {"password": PANEL_PASSWORD,
                   "password_confirm": PANEL_PASSWORD},
                  {"X-CSRF-Token": csrf}, jar)
    jar.update(_jar_from(h))
    return jar, jar.get("fnos_csrf", csrf)


async def _mcp_smoke(token):
    """Real MCP SDK client over Streamable HTTP."""
    from mcp.client.streamable_http import streamablehttp_client
    from mcp import ClientSession

    url = BASE + "/mcp"
    headers = {"Authorization": f"Bearer {token}"}

    def _factory(**kw):
        import httpx
        # Sandbox egress proxy env vars must not touch localhost MCP.
        kw["trust_env"] = False
        return httpx.AsyncClient(**kw)

    async with streamablehttp_client(url, headers=headers,
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
            check("MCP tools/list -> core tools present", CORE_TOOLS <= set(names), str(names))
            result = await session.call_tool("fnos_profiles", {})
            payload = json.loads(result.content[0].text)
            check("MCP call fnos_profiles -> 2 profiles",
                  [p["name"] for p in payload["profiles"]] == ["home", "office"])
            bad = await session.call_tool("fnos_system_info",
                                          {"profile": "home", "host": "evil.example"})
            check("MCP call with host param -> isError", bad.isError)
    # No Bearer -> 401 (post to /mcp/ to skip Starlette's slash redirect).
    s, b, _ = req(BASE, "POST", "/mcp/", b"{}", {"Content-Type": "application/json"})
    check("MCP no Bearer -> 401", s == 401, f"got {s}")


def main():
    tmp = tempfile.mkdtemp(prefix="fnos-smoke-m2-")
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]
    profiles = {"default_profile": "home", "profiles": {
        "home": {"host": "127.0.0.1", "port": port, "scheme": "http",
                 "allow_insecure_http": True, "description": "本地冒烟机"},
        "office": {"host": "127.0.0.1", "port": 59996, "scheme": "http",
                   "allow_insecure_http": True, "description": "断开的机器"}}}
    token = "smoke-admin-token-002"
    proc, data = _start_server(tmp, 18082, profiles, token)
    proc2 = data2 = None
    try:
        health = _wait_up(BASE)
        check("healthz 200 + cli 0.6.2", health and health.get("cli_version") == "0.6.2",
              str(health))
        if not health:
            print(open(os.path.join(tmp, "uvicorn18082.log")).read()[-2000:])
            return 1
        jar, csrf = _login(BASE)
        check("panel login 302 + cookie", "fnos_panel" in jar)
        # 1. Load probe-all attributes.
        s, b, _ = req(BASE, "GET", "/", jar=jar)
        html = b.decode(errors="replace")
        check("GET / has load probe-all (once)", s == 200 and
              'hx-post="/api/profiles/probe-all"' in html and
              html.count('hx-trigger="load"') == 1)
        check("GET / has htmx + aria-pressed", "/static/htmx.min.js" in html and
              'aria-pressed="true"' in html)
        check("GET / insecure tags visible",
              "allow_insecure_http" in html and "tls_insecure" not in html)
        # 9 badges: untested before any probe.
        s, b, _ = req(BASE, "GET", "/api/profiles", jar=jar)
        rows = {p["name"]: p for p in json.loads(b)["profiles"]}
        check("badge untested (fresh)", rows["home"]["badge"] == "untested")
        # probe-all: home ok (unverified), office refused (unreachable).
        s, b, _ = req(BASE, "POST", "/api/profiles/probe-all",
                      headers={"X-CSRF-Token": csrf, "HX-Request": "true"}, jar=jar)
        html = b.decode(errors="replace")
        check("probe-all HX has no re-fire trigger", s == 200 and
              'hx-trigger="load"' not in html and 'id="roster"' in html)
        rows = {p["name"]: p for p in
                json.loads(req(BASE, "GET", "/api/profiles", jar=jar)[1])["profiles"]}
        check("badge unverified + unreachable",
              rows["home"]["badge"] == "unverified" and
              rows["office"]["badge"] == "unreachable",
              str({k: v["badge"] for k, v in rows.items()}))
        # Drawer: layered times (network 09:xx from probe, auth none yet).
        s, b, _ = req(BASE, "GET", "/api/profiles/home/drawer", jar=jar)
        check("drawer fragment renders layers", s == 200 and
              "网络" in b.decode(errors="replace") and "认证 / API" in b.decode(errors="replace"))
        # 409: hold the probe lock, then probe + probe-all.
        lock_path = os.path.join(data, "locks", "probe-home.lock")
        os.makedirs(os.path.dirname(lock_path), exist_ok=True)
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            s, b, _ = req(BASE, "POST", "/api/profiles/home/probe",
                          headers={"X-CSRF-Token": csrf, "HX-Request": "true"}, jar=jar)
            check("probe busy -> 409 fragment", s == 409 and
                  b'probe.busy' in b and b'role="alert"' in b, f"got {s}")
            s, b, _ = req(BASE, "POST", "/api/profiles/probe-all",
                          headers={"X-CSRF-Token": csrf}, jar=jar)
            body = json.loads(b)
            check("probe-all marks locked profile busy",
                  body["results"]["home"]["status"] == "busy")
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
        # test -> logged_out, then login -> connected.
        s, b, _ = req(BASE, "POST", "/api/profiles/home/test",
                      headers={"X-CSRF-Token": csrf}, jar=jar)
        check("test -> logged_out", json.loads(b)["auth"]["status"] == "logged_out")
        s, b, h = req(BASE, "POST", "/api/profiles/home/login/start",
                      headers={"X-CSRF-Token": csrf, "HX-Request": "true"}, jar=jar)
        check("login/start 200 + no-store", s == 200 and
              h.get("Cache-Control") == "no-store" and b"oauth/authorize" in b)
        s, b, _ = req(BASE, "POST", "/api/profiles/home/login/finish",
                      {"code": "abc-123"}, {"X-CSRF-Token": csrf}, jar)
        check("login/finish -> connected", json.loads(b)["status"] == "connected")
        # FR-21: inject a hostile auth URL, start must be rejected with
        # no link and no URL in the fragment.
        state_path = os.path.join(data, "fnos-cli", "fake-state.json")
        state = json.loads(open(state_path).read())
        state["home"]["auth_url"] = "javascript:alert(1)"
        open(state_path, "w").write(json.dumps(state))
        s, b, h = req(BASE, "POST", "/api/profiles/home/login/start",
                      headers={"X-CSRF-Token": csrf, "HX-Request": "true"}, jar=jar)
        check("FR-21 javascript: rejected, no link",
              s == 400 and h.get("Cache-Control") == "no-store" and
              "授权链接被拒绝" in b.decode(errors="replace") and
              b"<a " not in b and b"javascript:" not in b, f"got {s}")
        # Expired via fake state.
        state["home"]["auth_url"] = None
        state["home"].pop("auth_url", None)
        state["home"]["auth_mode"] = "expired"
        open(state_path, "w").write(json.dumps(state))
        s, b, _ = req(BASE, "POST", "/api/profiles/home/test",
                      headers={"X-CSRF-Token": csrf}, jar=jar)
        check("test -> expired (fake signal)",
              json.loads(b)["auth"]["status"] == "expired")
        # FastMCP over real HTTP.
        asyncio.run(_mcp_smoke(token))
        # Audit has no secrets.
        audit = open(os.path.join(data, "audit.jsonl")).read()
        check("audit has events, no token/code/password",
              "login_started" in audit and token not in audit and
              "abc-123" not in audit and PANEL_PASSWORD not in audit)
        # Empty state on a second server with zero profiles.
        proc2, data2 = _start_server(tmp, 18083,
                                      {"default_profile": None, "profiles": {}}, token)
        health2 = _wait_up(BASE2)
        check("empty server up", bool(health2))
        jar2, _ = _login(BASE2)
        s, b, _ = req(BASE2, "GET", "/", jar=jar2)
        check("zero-config empty state", s == 200 and
              "还没有配置机器" in b.decode(errors="replace"))
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
        if proc2:
            proc2.terminate()
            try:
                proc2.wait(timeout=5)
            except Exception:
                proc2.kill()
        httpd.shutdown()


if __name__ == "__main__":
    sys.exit(main())
