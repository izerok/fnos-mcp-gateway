import os

from fnos_mcp.state_store import PanelStateStore, merge_status, now_iso


def test_layers_do_not_overwrite_each_other(tmp_path):
    store = PanelStateStore(tmp_path / "panel-state.json")
    store.update("home", "https://10.0.0.1:5667",
                 auth={"at": now_iso(), "status": "ok", "latency_ms": 10, "identity": "admin"})
    store.update("home", "https://10.0.0.1:5667",
                 network={"at": now_iso(), "status": "ok", "latency_ms": 80, "looks_like_fnos": True})
    entry = store.load()["profiles"]["home"]
    assert entry["auth"]["status"] == "ok"  # probe did not clobber auth
    assert entry["network"]["status"] == "ok"


def test_merge_order():
    ok_net = {"status": "ok"}
    assert merge_status(None, None) == "untested"
    assert merge_status({"status": "timeout"}, {"status": "ok"}) == "unreachable"
    assert merge_status({"status": "tls_failed"}, None) == "tls"
    assert merge_status(ok_net, {"at": now_iso(), "status": "ok"}) == "connected"
    assert merge_status(ok_net, {"at": now_iso(), "status": "logged_out"}) == "loggedout"
    assert merge_status(ok_net, {"at": now_iso(), "status": "expired"}) == "expired"
    assert merge_status(ok_net, {"at": now_iso(), "status": "permission"}) == "permission"
    assert merge_status(ok_net, None) == "unverified"
    assert merge_status(ok_net, {"status": "ok"}, config_error=True) == "config"


def test_auth_older_than_24h_is_stale():
    old = "2020-01-01T00:00:00+00:00"
    assert merge_status({"status": "ok"}, {"at": old, "status": "ok"}) == "unverified"


def test_atomic_write_mode_0600(tmp_path):
    path = tmp_path / "panel-state.json"
    store = PanelStateStore(path)
    store.update("home", "https://10.0.0.1:5667",
                 network={"at": now_iso(), "status": "ok", "latency_ms": 1, "looks_like_fnos": True})
    assert path.exists()
    assert oct(os.stat(path).st_mode & 0o777) == "0o600"
    assert not list(tmp_path.glob(".*.tmp-*"))


def test_corrupt_file_renamed_and_empty(tmp_path):
    path = tmp_path / "panel-state.json"
    path.write_text("{broken", encoding="utf-8")
    store = PanelStateStore(path)
    assert store.load() == {"schema_version": 1, "profiles": {}}
    assert store.corrupt is True
    assert len(list(tmp_path.glob("panel-state.json.corrupt-*"))) == 1


def test_drop_stale_target(tmp_path):
    store = PanelStateStore(tmp_path / "panel-state.json")
    store.update("home", "https://10.0.0.1:5667",
                 network={"at": now_iso(), "status": "ok", "latency_ms": 1, "looks_like_fnos": True})
    dropped = store.drop_stale({"home": "https://10.0.0.2:5667"})
    assert dropped == ["home"]
    assert store.load()["profiles"] == {}


def test_summarize_ignores_stale_target(tmp_path):
    store = PanelStateStore(tmp_path / "panel-state.json")
    store.update("home", "https://10.0.0.2:5667",
                 network={"at": now_iso(), "status": "ok", "latency_ms": 1,
                          "looks_like_fnos": True},
                 auth={"at": now_iso(), "status": "ok", "latency_ms": 3,
                       "identity": "admin"})
    result = store.summarize(["home"], set(),
                             targets={"home": "https://10.0.0.1:5667"})
    assert result["badges"]["home"] == "untested"
    assert result["counts"]["untested"] == 1
