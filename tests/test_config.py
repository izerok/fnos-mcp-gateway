import json

import pytest

from fnos_mcp.config import load_profiles, load_tokens
from fnos_mcp.errors import ConfigError


def test_load_profiles_ok(profiles_path):
    cfg = load_profiles(profiles_path)
    assert cfg.profiles["home"].target == "https://192.168.1.10:5667"
    assert cfg.default_profile == "home"
    assert cfg.config_errors == {}


def test_single_bad_profile_skipped(tmp_path):
    p = tmp_path / "profiles.json"
    p.write_text(json.dumps({"profiles": {
        "good": {"host": "10.0.0.1", "port": 5667, "scheme": "https"},
        "bad-port": {"host": "10.0.0.2", "port": 99999, "scheme": "https"},
        "bad.name": {"host": "10.0.0.3", "port": 5667, "scheme": "https"},
        "http-no-flag": {"host": "10.0.0.4", "port": 80, "scheme": "http"},
    }}), encoding="utf-8")
    cfg = load_profiles(str(p))
    assert list(cfg.profiles) == ["good"]
    assert set(cfg.config_errors) == {"bad-port", "bad.name", "http-no-flag"}


def test_file_level_errors(tmp_path):
    missing = tmp_path / "nope.json"
    with pytest.raises(ConfigError):
        load_profiles(str(missing))
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_profiles(str(bad))
    wrong_shape = tmp_path / "shape.json"
    wrong_shape.write_text(json.dumps({"profiles": ["home"]}), encoding="utf-8")
    with pytest.raises(ConfigError):
        load_profiles(str(wrong_shape))


def test_tokens_validation(tmp_path):
    p = tmp_path / "tokens.json"
    p.write_text(json.dumps({"tokens": [
        {"id": "a", "name": "a", "sha256": "x" * 64, "profiles": ["home"], "role": "admin"},
        {"id": "a", "name": "b", "sha256": "y" * 64, "profiles": [], "role": "admin"},
    ]}), encoding="utf-8")
    with pytest.raises(ConfigError):
        load_tokens(str(p))
    p.write_text(json.dumps({"tokens": [
        {"id": "a", "name": "a", "sha256": "not-hex", "profiles": [], "role": "admin"},
    ]}), encoding="utf-8")
    with pytest.raises(ConfigError):
        load_tokens(str(p))
    p.write_text(json.dumps({"tokens": [
        {"id": "a", "name": "a", "sha256": "0" * 64, "profiles": [], "role": "superuser"},
    ]}), encoding="utf-8")
    with pytest.raises(ConfigError):
        load_tokens(str(p))
