import sys

from fnos_mcp.runner import CliRunner, redact


def test_runner_runs_argv_list(tmp_path, monkeypatch):
    monkeypatch.setenv("FNOS_CLI_BIN", "unused")
    runner = CliRunner(sys.executable, str(tmp_path), str(tmp_path))
    result = runner.run(["-c", "print('hello')"], timeout=10)
    assert result.returncode == 0
    assert result.stdout.strip() == "hello"


def test_runner_timeout(tmp_path):
    runner = CliRunner(sys.executable, str(tmp_path), str(tmp_path))
    result = runner.run(["-c", "import time; time.sleep(5)"], timeout=0.5)
    assert result.timed_out


def test_runner_missing_binary(tmp_path):
    runner = CliRunner("/nonexistent/fnos-cli", str(tmp_path), str(tmp_path))
    result = runner.run(["--version"], timeout=5)
    assert result.returncode == -1


def test_redact_masks_secrets():
    text = "login --code abc123 --password hunter2 Bearer tok123 dlink=xyz"
    out = redact(text)
    assert "abc123" not in out and "hunter2" not in out
    assert "tok123" not in out and "xyz" not in out
    assert "<redacted>" in out
    assert "--code" in out  # the flag stays, the value goes


def test_runner_env_whitelist(tmp_path, monkeypatch):
    monkeypatch.setenv("MY_SECRET_TOKEN", "should-not-leak")
    monkeypatch.setenv("PANEL_SESSION_SECRET_FILE", "/tmp/secret")
    runner = CliRunner(sys.executable, str(tmp_path), str(tmp_path))
    result = runner.run(["-c", "import os, json; print(json.dumps(dict(os.environ)))"],
                        timeout=10)
    import json
    env = json.loads(result.stdout)
    assert "MY_SECRET_TOKEN" not in env
    assert "PANEL_SESSION_SECRET_FILE" not in env
    assert env["FNOS_CLI_SESSION_STORAGE"] == "file"
    assert env["TRIM_CLI_DISTRIBUTION"] == "fnos"
