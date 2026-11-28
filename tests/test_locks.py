import json
import time

from fnos_mcp.locks import acquire_login_lease, release_login_lease


def test_fresh_lease_blocks_second_login(tmp_path):
    assert acquire_login_lease(tmp_path, "home") is True
    try:
        assert acquire_login_lease(tmp_path, "home") is False
    finally:
        release_login_lease(tmp_path, "home")


def test_expired_lease_can_be_reacquired(tmp_path):
    locks = tmp_path / "locks"
    locks.mkdir()
    (locks / "pending-home.json").write_text(
        json.dumps({"expires_at": time.time() - 1}), encoding="utf-8")
    assert acquire_login_lease(tmp_path, "home") is True
    release_login_lease(tmp_path, "home")
    assert acquire_login_lease(tmp_path, "home") is True
    release_login_lease(tmp_path, "home")


def test_corrupt_lease_can_be_reacquired(tmp_path):
    locks = tmp_path / "locks"
    locks.mkdir()
    (locks / "pending-home.json").write_text("{not-json", encoding="utf-8")
    assert acquire_login_lease(tmp_path, "home") is True
    release_login_lease(tmp_path, "home")
