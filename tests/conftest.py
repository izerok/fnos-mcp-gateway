"""Shared fixtures: fake CLI, example configs, TestClient.

Test tokens are random-looking strings generated HERE; they are not
real secrets and never leave the tmp directory.
"""

import hashlib
import json
import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from fnos_mcp.server import create_app  # noqa: E402

ADMIN_TOKEN = "test-admin-token-001"
OPERATOR_TOKEN = "test-operator-token-001"
MANAGE_TOKEN = "test-manage-token-001"
PANEL_PASSWORD = "panel-test-pass-123"

FAKE_CLI = Path(__file__).resolve().parent / "fake_cli.py"


def _sha(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@pytest.fixture()
def data_dir(tmp_path):
    d = tmp_path / "data"
    d.mkdir()
    return d


@pytest.fixture()
def profiles_path(tmp_path):
    p = tmp_path / "profiles.json"
    p.write_text(json.dumps({
        "default_profile": "home",
        "profiles": {
            "home": {"host": "192.168.1.10", "port": 5667, "scheme": "https",
                     "description": "家里的 fnOS"},
            "office": {"host": "nas.office.example.com", "port": 443, "scheme": "https",
                       "description": "办公室 fnOS"},
        },
    }), encoding="utf-8")
    return str(p)


@pytest.fixture()
def tokens_path(tmp_path):
    p = tmp_path / "tokens.json"
    p.write_text(json.dumps({"tokens": [
        {"id": "t_admin", "name": "admin", "sha256": _sha(ADMIN_TOKEN),
         "profiles": ["home", "office"], "role": "admin"},
        {"id": "t_operator", "name": "operator", "sha256": _sha(OPERATOR_TOKEN),
         "profiles": ["home"], "role": "operator"},
        {"id": "t_manage", "name": "manager", "sha256": _sha(MANAGE_TOKEN),
         "profiles": ["home", "office"], "role": "operator",
         "capabilities": ["manage_login"]},
    ]}), encoding="utf-8")
    return str(p)


@pytest.fixture()
def app(tmp_path, data_dir, profiles_path, tokens_path, monkeypatch):
    (data_dir / "panel-session.key").write_bytes(os.urandom(32))
    os.chmod(FAKE_CLI, 0o755)
    monkeypatch.setenv("FNOS_CLI_BIN", str(FAKE_CLI))
    monkeypatch.setenv("FNOS_FAKE_STATE_FILE", str(tmp_path / "fake-state.json"))
    monkeypatch.setenv("FNOS_FAKE_ARGV_LOG", str(tmp_path / "fake-argv.log"))
    return create_app(profiles_path=profiles_path, tokens_path=tokens_path,
                      data_dir=str(data_dir))


@pytest.fixture()
def client(app):
    # Context manager runs the app lifespan, which FastMCP's
    # Streamable HTTP session manager requires.
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


def _csrf(client):
    resp = client.get("/login")
    assert resp.status_code == 200
    return client.cookies.get("fnos_csrf")


def panel_setup(client, password=PANEL_PASSWORD):
    """First-run setup: the panel has no credential until this POST."""
    csrf = client.cookies.get("fnos_csrf") or _csrf(client)
    resp = client.post("/login",
                       data={"password": password,
                             "password_confirm": password,
                             "csrf_token": csrf},
                       follow_redirects=False)
    assert resp.status_code == 302, resp.text
    assert "fnos_panel" in resp.headers.get("set-cookie", "")
    return client


def panel_login(client, password=PANEL_PASSWORD):
    csrf = client.cookies.get("fnos_csrf") or _csrf(client)
    resp = client.post("/login",
                       data={"password": password, "csrf_token": csrf},
                       follow_redirects=False)
    assert resp.status_code == 302, resp.text
    return client


@pytest.fixture()
def admin_client(client):
    return panel_setup(client)


def post_csrf(client, url, **kwargs):
    headers = dict(kwargs.pop("headers", {}))
    headers["X-CSRF-Token"] = client.cookies.get("fnos_csrf", "")
    return client.post(url, headers=headers, **kwargs)
