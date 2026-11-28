import json
import os

from fnos_mcp.audit import AuditLog


def test_audit_appends_jsonl_and_mode(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.record("probe", token_id="t1", profile="home", sub_reason="ok", latency_ms=12)
    log.record("login_started", token_id="t1", profile="home")
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["event"] == "probe" and first["token_id"] == "t1"
    assert first["latency_ms"] == 12 and first["sub_reason"] == "ok"
    assert oct(os.stat(path).st_mode & 0o777) == "0o600"


def test_audit_drops_non_whitelisted_fields(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    # Even if a caller passes secrets, only whitelisted fields are stored.
    log.record("probe", token_id="t1", token="SECRET-TOKEN", code="123456",
               authorization_url="https://evil.example/x")
    entry = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    assert "SECRET-TOKEN" not in path.read_text()
    assert "123456" not in path.read_text()
    assert "authorization_url" not in entry
    assert set(entry) <= {"time", "event", "token_id", "profile", "result",
                          "client_ip", "latency_ms", "http_status",
                          "sub_reason", "retry_after"}
