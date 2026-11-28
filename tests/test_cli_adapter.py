import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from fnos_mcp.cli_adapter import (FnosCli, LoginCodeExpired, LoginCodeInvalid)
from fnos_mcp.cli_capabilities import EXPECTED_COMMANDS_051, probe_capabilities
from fnos_mcp.config import Profile
from fnos_mcp.errors import CliError, CliVersionError
from fnos_mcp.runner import CliRunner, RunResult

FAKE_CLI = str(Path(__file__).resolve().parent / "fake_cli.py")


def _cli(tmp_path, monkeypatch):
    monkeypatch.setenv("FNOS_FAKE_STATE_FILE", str(tmp_path / "state.json"))
    monkeypatch.setenv("FNOS_FAKE_ARGV_LOG", str(tmp_path / "argv.log"))
    runner = CliRunner(FAKE_CLI, str(tmp_path), str(tmp_path))
    return FnosCli(runner), tmp_path


def _profile():
    return Profile(name="home", host="192.168.1.10", port=5667)


def test_version_is_pinned(tmp_path, monkeypatch):
    cli, _ = _cli(tmp_path, monkeypatch)
    assert cli.version() == "0.6.2"
    assert cli.check_version() == "0.6.2"


def test_version_mismatch_fails_startup(tmp_path, monkeypatch):
    script = tmp_path / "old-cli.py"
    script.write_text("#!/usr/bin/env python3\nimport sys; print('fnos-cli 0.6.1')\n")
    script.chmod(0o755)
    cli = FnosCli(CliRunner(str(script), str(tmp_path), str(tmp_path)))
    with pytest.raises(CliVersionError):
        cli.check_version()


def test_login_start_returns_cli_url_verbatim(tmp_path, monkeypatch):
    cli, _ = _cli(tmp_path, monkeypatch)
    url = cli.login_start(_profile())
    assert url.startswith("https://192.168.1.10:5667/oauth/authorize")
    assert "code_challenge_method=S256" in url


def test_login_finish_ok_and_consumed_code(tmp_path, monkeypatch):
    cli, _ = _cli(tmp_path, monkeypatch)
    result = cli.login_finish(_profile(), "abc-123")
    assert result.token_persisted and result.refresh_token_persisted
    assert cli.user_info(_profile()).status == "ok"
    # Non-zero exit but token_persisted=true: no re-exchange, verify instead.
    result = cli.login_finish(_profile(), "consumed-code")
    assert result.token_persisted and result.consumed_but_unverified
    assert cli.user_info(_profile()).status == "ok"


def test_login_finish_bad_codes(tmp_path, monkeypatch):
    cli, _ = _cli(tmp_path, monkeypatch)
    with pytest.raises(LoginCodeInvalid):
        cli.login_finish(_profile(), "000000")
    with pytest.raises(LoginCodeExpired):
        cli.login_finish(_profile(), "expired-code")


def test_login_finish_timeout_is_not_invalid_code(tmp_path, monkeypatch):
    cli, _ = _cli(tmp_path, monkeypatch)
    monkeypatch.setattr(cli._runner, "run",
                        lambda *args, **kwargs: RunResult(-1, "", "", True))
    with pytest.raises(CliError) as exc:
        cli.login_finish(_profile(), "abc-123")
    assert not isinstance(exc.value, LoginCodeInvalid)


def test_login_finish_timeout_with_persisted_token_is_unverified(tmp_path, monkeypatch):
    cli, _ = _cli(tmp_path, monkeypatch)
    output = '{"token_persisted": true, "refresh_token_persisted": true}'
    monkeypatch.setattr(cli._runner, "run",
                        lambda *args, **kwargs: RunResult(-1, output, "", True))
    result = cli.login_finish(_profile(), "abc-123")
    assert result.token_persisted and result.refresh_token_persisted
    assert result.consumed_but_unverified is True


def test_logout_timeout_is_cli_error(tmp_path, monkeypatch):
    cli, _ = _cli(tmp_path, monkeypatch)
    monkeypatch.setattr(cli._runner, "run",
                        lambda *args, **kwargs: RunResult(-1, "", "", True))
    with pytest.raises(CliError):
        cli.logout(_profile())


def test_user_info_mapping(tmp_path, monkeypatch):
    cli, _ = _cli(tmp_path, monkeypatch)
    assert cli.user_info(_profile()).status == "logged_out"
    cli.login_finish(_profile(), "abc-123")
    auth = cli.user_info(_profile())
    assert auth.status == "ok" and auth.identity == "admin"


def test_system_info_never_judges_login(tmp_path, monkeypatch):
    cli, _ = _cli(tmp_path, monkeypatch)
    # Logged out, yet system info still returns data (per reference/sysinfo.md).
    assert cli.user_info(_profile()).status == "logged_out"
    info = cli.system_info(_profile())
    assert info["machine"] == "fnOS"


def test_argv_uses_global_args(tmp_path, monkeypatch):
    cli, d = _cli(tmp_path, monkeypatch)
    cli.system_info(_profile())
    lines = (d / "fake-argv.log").read_text().splitlines()
    argv = json.loads(lines[-1])["argv"]
    assert argv[:8] == ["--profile", "home", "--host", "192.168.1.10",
                        "--port", "5667", "--scheme", "https"]
    assert "system" in argv and "info" in argv


def test_docker_ps_uses_container_ls(tmp_path, monkeypatch):
    # fnos-cli 0.5.1+ has no `docker ps`; the adapter must call
    # `docker container ls` (regression guard for the real-CLI spelling)
    # and wrap the Docker-style array as {"containers": [...]}.
    cli, d = _cli(tmp_path, monkeypatch)
    out = cli.docker_ps(_profile())
    assert out["containers"][0]["Names"] == ["/demo"]
    lines = (d / "fake-argv.log").read_text().splitlines()
    argv = json.loads(lines[-1])["argv"]
    assert argv[-3:] == ["docker", "container", "ls"]


def test_capabilities_probe(tmp_path, monkeypatch):
    cli_runner = CliRunner(FAKE_CLI, str(tmp_path), str(tmp_path))
    caps = probe_capabilities(cli_runner)
    assert caps.version == "0.6.2"
    assert {"login", "user", "system"}.issubset(caps.commands)
    diff = caps.diff({"login", "user", "nonexistent-cmd"})
    assert diff["missing"] == ["nonexistent-cmd"]
    assert caps.diff(EXPECTED_COMMANDS_051)["missing"] == []
