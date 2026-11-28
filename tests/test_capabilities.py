"""Capability page + machine-readable manifest (M6.1).

The page must be generated from the same registry the MCP server
exposes, so these tests compare the rendered counts with TOOLS.
"""

import json
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from fnos_mcp.tools.registry import TOOLS, tool_catalog


def test_capability_page_requires_panel_login(client):
    resp = client.get("/capabilities", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/login"


def test_capability_page_lists_every_tool(admin_client):
    resp = admin_client.get("/capabilities")
    assert resp.status_code == 200
    assert resp.headers["cache-control"] == "no-store"
    html = resp.text
    for name in TOOLS:
        assert name in html, name
    assert "Docker Compose" in html
    assert "只读" in html and "confirm=true" in html
    assert "allow_dangerous" in html
    # Visible profiles from the fixture, with their write state.
    assert "home" in html and "office" in html
    assert "未开启" in html


def test_capability_counts_match_registry(admin_client):
    resp = admin_client.get("/api/capabilities.json")
    assert resp.status_code == 200
    data = resp.json()
    catalog = tool_catalog()
    assert data["counts"]["total"] == len(TOOLS) == 30
    assert data["counts"]["compose"] == 12
    assert data["counts"]["read"] + data["counts"]["write"] == 30
    assert {t["name"] for t in data["tools"]} == set(TOOLS)
    compose = [g for g in data["groups"] if g["name"] == "Docker Compose"][0]
    assert "fnos_docker_compose_create" in compose["tools"]
    assert len(catalog) == 30


def test_capability_manifest_has_no_secrets(admin_client):
    body = admin_client.get("/api/capabilities.json").text
    # The manifest carries names, gates and endpoints only.
    assert "Bearer" not in body
    assert "sha256" not in body
    assert "authorization_url" not in body
    data = json.loads(body)
    assert data["gateway"]["mcp_url"].endswith("/mcp")
    assert data["token"]["role"] == "admin"


def test_nav_links_pages(admin_client):
    index = admin_client.get("/")
    assert 'href="/capabilities"' in index.text
    cap = admin_client.get("/capabilities")
    assert 'href="/"' in cap.text
    assert 'aria-current="page"' in cap.text
