import time

from fnos_mcp import auth as auth_mod
from fnos_mcp.auth import RateLimiter, real_client_ip, validate_authorization_url
from fnos_mcp.config import Profile, TokenRecord


def _token(**kw):
    base = {"id": "t1", "name": "admin", "sha256": "a" * 64,
            "profiles": ["home"], "role": "admin"}
    base.update(kw)
    return TokenRecord(**base)


def test_bearer_verify():
    token = "some-token-value"
    rec = _token(sha256=auth_mod.hash_token(token))
    assert auth_mod.verify_bearer(token, [rec]) is rec
    assert auth_mod.verify_bearer("wrong", [rec]) is None


def test_panel_session_roundtrip_and_password_change():
    secret = b"test-secret-32-bytes-long-xxxxxx"
    fingerprint = "f" * 64
    value = auth_mod.create_panel_session(secret, fingerprint)
    assert auth_mod.verify_panel_session(value, secret, fingerprint)
    # Changing the password changes the fingerprint -> old cookies die.
    assert not auth_mod.verify_panel_session(value, secret, "e" * 64)
    # A different signing secret fails.
    assert not auth_mod.verify_panel_session(value, b"other-secret-32-bytes-long-xx", fingerprint)
    # Tampered payload fails.
    assert not auth_mod.verify_panel_session(value + "x", secret, fingerprint)
    assert not auth_mod.verify_panel_session("garbage", secret, fingerprint)


def test_panel_session_expiry():
    secret = b"test-secret-32-bytes-long-xxxxxx"
    fingerprint = "f" * 64
    value = auth_mod.create_panel_session(secret, fingerprint, ttl_hours=0)
    time.sleep(1.1)
    assert not auth_mod.verify_panel_session(value, secret, fingerprint)


def test_csrf():
    assert auth_mod.csrf_valid("abc", "abc")
    assert not auth_mod.csrf_valid("abc", "def")
    assert not auth_mod.csrf_valid(None, "abc")


def test_rate_limiter():
    limiter = RateLimiter()
    for _ in range(5):
        allowed, _ = limiter.check("login_start", "t:home")
        assert allowed
    allowed, retry = limiter.check("login_start", "t:home")
    assert not allowed and retry > 0
    # A different key is unaffected.
    allowed, _ = limiter.check("login_start", "t:office")
    assert allowed


def test_mcp_limiter_off_by_default():
    limiter = RateLimiter()
    assert limiter.limits["mcp_call"] is None
    for _ in range(1000):
        assert limiter.check("mcp_call", "t1")[0] is True


def test_parse_rate_limit_values():
    from fnos_mcp.auth import parse_rate_limit
    assert parse_rate_limit("120/60") == (120, 60)
    assert parse_rate_limit(" 5 / 300 ") == (5, 300)
    assert parse_rate_limit("off") is None
    assert parse_rate_limit("0/60") is None
    assert parse_rate_limit("NONE") is None
    for bad in ("", "default", "120", "a/b", "-1/60", "5/0", "5/60/2"):
        try:
            parse_rate_limit(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"{bad!r} should be rejected")


def test_load_rate_limits_env_overrides():
    from fnos_mcp.auth import load_rate_limits
    limits = load_rate_limits({})
    assert limits["panel_login"] == (10, 300) and limits["mcp_call"] is None
    limits = load_rate_limits({
        "FNOS_RATE_LIMIT_MCP_CALL": "120/60",
        "FNOS_RATE_LIMIT_PANEL_LOGIN": "off",
        "FNOS_RATE_LIMIT_UNKNOWN_KIND": "1/1",  # ignored
    })
    assert limits["mcp_call"] == (120, 60)
    assert limits["panel_login"] is None
    assert "unknown_kind" not in limits
    # A malformed value for a known kind fails loudly.
    try:
        load_rate_limits({"FNOS_RATE_LIMIT_MCP_CALL": "fast"})
    except ValueError:
        pass
    else:
        raise AssertionError("malformed env value must raise")


def test_real_client_ip_ignores_forged_xff_by_default():
    assert real_client_ip("10.0.0.5", "1.2.3.4", []) == "10.0.0.5"
    assert real_client_ip("10.0.0.5", "1.2.3.4", ["10.0.0.0/8"]) == "1.2.3.4"


def _profile(**kw):
    base = {"name": "home", "host": "192.168.1.10", "port": 5667}
    base.update(kw)
    return Profile(**base)


def test_authorization_url_validation():
    p = _profile()
    assert validate_authorization_url("https://192.168.1.10:5667/oauth/authorize?x=1", p) is None
    assert validate_authorization_url("javascript:alert(1)", p) is not None
    assert validate_authorization_url("data:text/html,hi", p) is not None
    assert validate_authorization_url("https://user:pass@192.168.1.10:5667/x", p) is not None
    assert validate_authorization_url("https://evil.example.com/oauth/authorize", p) is not None
    assert validate_authorization_url("https://192.168.1.10:5667.evil.com/x", p) is not None
    assert validate_authorization_url("https://192.168.1.10:5667/x\nbad", p) is not None
    # SSO allowlist: exact origin only.
    sso = _profile(authorization_hosts=["https://sso.example.com"])
    assert validate_authorization_url("https://sso.example.com/oauth/authorize", sso) is None
    assert validate_authorization_url("https://sso.example.com.evil.com/x", sso) is not None
    # http only with the explicit flag.
    http_p = _profile(scheme="http", port=80, allow_insecure_http=True)
    assert validate_authorization_url("http://192.168.1.10:80/oauth/authorize", http_p) is None
    assert validate_authorization_url("http://192.168.1.10:80/oauth/authorize", p) is not None
