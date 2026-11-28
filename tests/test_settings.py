"""Panel-editable runtime settings (settings.py + /api/panel/settings)."""

import json


from fnos_mcp.settings import SettingsStore, parse_rate_limit_form

from conftest import post_csrf


# -- unit: SettingsStore -------------------------------------------------

def test_settings_defaults_and_bounds(tmp_path):
    store = SettingsStore(tmp_path / "settings.json")
    assert store.get("probe_timeout_s") == 5.0
    assert store.get("panel_session_hours") == 12
    assert store.rate_limits["mcp_call"] is None  # MCP off by default
    # Out-of-bounds values are rejected with field errors, nothing applied.
    errors = store.update({"probe_timeout_s": 99, "audit_keep": 1})
    assert set(errors) == {"probe_timeout_s", "audit_keep"}
    assert store.get("probe_timeout_s") == 5.0
    assert store.get("audit_keep") == 7


def test_settings_update_persists_and_reloads(tmp_path):
    path = tmp_path / "settings.json"
    store = SettingsStore(path)
    errors = store.update({"panel_session_hours": 24,
                           "probe_timeout_s": 8},
                          rate_limits={"mcp_call": (120, 60),
                                       "panel_login": None})
    assert errors == {}
    assert store.get("panel_session_hours") == 24
    assert store.get("probe_timeout_s") == 8.0
    assert store.rate_limits["mcp_call"] == (120, 60)
    assert store.rate_limits["panel_login"] is None
    # A fresh instance reads the same values back.
    again = SettingsStore(path)
    assert again.get("panel_session_hours") == 24
    assert again.rate_limits["mcp_call"] == (120, 60)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["rate_limits"]["mcp_call"] == [120, 60]


def test_settings_corrupt_file_falls_back_to_defaults(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text("{not json", encoding="utf-8")
    store = SettingsStore(path)
    assert store.get("probe_timeout_s") == 5.0
    path.write_text(json.dumps({"panel_session_hours": 999,
                                "rate_limits": {"mcp_call": "garbage"}}),
                    encoding="utf-8")
    store = SettingsStore(path)
    assert store.get("panel_session_hours") == 12  # out of bounds -> default
    assert store.rate_limits["mcp_call"] is None   # invalid -> default


def test_parse_rate_limit_form_empty_keeps_current():
    # Tri-state: absent/empty ("keep") must never collapse into "off".
    assert parse_rate_limit_form(None) == ("keep", None, None)
    assert parse_rate_limit_form("") == ("keep", None, None)
    assert parse_rate_limit_form("   ") == ("keep", None, None)
    assert parse_rate_limit_form("off") == ("off", None, None)
    assert parse_rate_limit_form("0/60") == ("off", None, None)
    action, value, err = parse_rate_limit_form("120/60")
    assert (action, value, err) == ("set", (120, 60), None)
    action, value, err = parse_rate_limit_form("fast")
    assert action == "error" and value is None and err


# -- panel integration ----------------------------------------------------

def test_settings_form_get_and_save(admin_client):
    resp = admin_client.get("/api/panel/settings/form",
                            headers={"HX-Request": "true"})
    assert resp.status_code == 200
    assert "手动配置" in resp.text
    assert 'name="probe_timeout_s"' in resp.text
    assert 'name="rate_mcp_call"' in resp.text
    assert 'value="off"' in resp.text  # MCP shown as off by default

    resp = post_csrf(admin_client, "/api/panel/settings",
                     data={"panel_session_hours": "24",
                           "rate_mcp_call": "120/60"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "saved"

    # Live: limiter table and settings store reflect the change.
    # (TestClient exposes the app via .app only in some versions; query via request)
    # Read the persisted file through a second client on the same app is
    # complex — assert through the API instead: re-open the form.
    resp = admin_client.get("/api/panel/settings/form",
                            headers={"HX-Request": "true"})
    assert 'value="120/60"' in resp.text


def test_settings_partial_submit_keeps_other_limits(admin_client, app):
    """F2: a submit that mentions no rate field must not touch any limit."""
    service = app.state.service
    before = dict(service.limiter.limits)
    assert before["panel_login"] == (10, 300)  # on by default
    resp = post_csrf(admin_client, "/api/panel/settings",
                     data={"panel_session_hours": "24"})
    assert resp.status_code == 200
    assert service.limiter.limits == before
    assert service.settings.rate_limits == before
    assert service.settings.get("panel_session_hours") == 24


def test_settings_empty_rate_field_keeps_current(admin_client, app):
    """F2: clearing one rate field (per the form's own copy) keeps its value."""
    service = app.state.service
    resp = post_csrf(admin_client, "/api/panel/settings",
                     data={"rate_mcp_call": "120/60",
                           "rate_panel_login": "10/300"})
    assert resp.status_code == 200
    assert service.limiter.limits["mcp_call"] == (120, 60)
    resp = post_csrf(admin_client, "/api/panel/settings",
                     data={"rate_mcp_call": ""})
    assert resp.status_code == 200
    assert service.limiter.limits["mcp_call"] == (120, 60)
    assert service.limiter.limits["panel_login"] == (10, 300)


def test_settings_off_closes_only_that_limit(admin_client, app):
    """F2: "off" switches off exactly the limit it names, nothing else."""
    service = app.state.service
    resp = post_csrf(admin_client, "/api/panel/settings",
                     data={"rate_mcp_call": "120/60",
                           "rate_panel_login": "10/300"})
    assert resp.status_code == 200
    resp = post_csrf(admin_client, "/api/panel/settings",
                     data={"rate_mcp_call": "off"})
    assert resp.status_code == 200
    assert service.limiter.limits["mcp_call"] is None
    assert service.limiter.limits["panel_login"] == (10, 300)


def test_settings_bad_rate_format_is_rejected_not_saved(admin_client):
    resp = post_csrf(admin_client, "/api/panel/settings",
                     data={"rate_mcp_call": "fast"})
    assert resp.status_code == 400
    assert "次数/窗口秒数" in resp.text
    # Nothing was persisted: the form still shows off.
    resp = admin_client.get("/api/panel/settings/form",
                            headers={"HX-Request": "true"})
    assert 'value="off"' in resp.text


def test_settings_rate_limit_takes_effect_immediately(admin_client, app):
    """Saving a limit applies to the live limiter and /mcp honours it."""
    service = app.state.service
    service.limiter._hits.clear()
    resp = post_csrf(admin_client, "/api/panel/settings",
                     data={"rate_mcp_call": "3/60"})
    assert resp.status_code == 200
    assert service.limiter.limits["mcp_call"] == (3, 60)
    service.limiter._hits.clear()
    for _ in range(3):
        assert service.limiter.check("mcp_call", "t_admin")[0] is True
    from conftest import ADMIN_TOKEN
    resp = admin_client.post("/mcp/", json={
        "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}",
                 "Content-Type": "application/json"})
    assert resp.status_code == 429
    # Turning it back off is immediate, too.
    resp = post_csrf(admin_client, "/api/panel/settings",
                     data={"rate_mcp_call": "off"})
    assert resp.status_code == 200
    assert service.limiter.limits["mcp_call"] is None


def test_settings_probe_values_flow_into_probe_all(admin_client, app):
    service = app.state.service
    resp = post_csrf(admin_client, "/api/panel/settings",
                     data={"probe_timeout_s": "8.5", "probe_concurrency": "2"})
    assert resp.status_code == 200
    assert service.settings.get("probe_timeout_s") == 8.5
    assert service.settings.get("probe_concurrency") == 2


def test_settings_requires_panel_and_csrf(client):
    resp = client.get("/api/panel/settings/form")
    assert resp.status_code == 401
    resp = client.post("/api/panel/settings", data={"panel_session_hours": "24"})
    assert resp.status_code == 401


def test_settings_audit_recorded(admin_client, app):
    post_csrf(admin_client, "/api/panel/settings", data={"panel_session_hours": "24"})
    audit = app.state.service.audit
    events = [json.loads(line)["event"]
              for line in (audit.path.parent / "audit.jsonl").read_text().splitlines()
              if line.strip()]
    assert "settings_updated" in events
