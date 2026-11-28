"""Subprocess runner: the only place that spawns the CLI (via cli_adapter).

- argv is always a list, never a shell string.
- Timeouts are enforced per call; output is capped at 1 MiB per stream.
- The child environment is a whitelist only (no token paths, no panel
  secret, no proxy variables leak in).
- Secrets are redacted from anything that can reach a log, an audit
  record or an error message (FR-33).
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass

MAX_OUTPUT_BYTES = 1 * 1024 * 1024

# Anything matching these patterns is replaced before it can be logged.
_REDACT_PATTERNS = [
    re.compile(r"(--code\s+)([^\s]+)", re.IGNORECASE),
    re.compile(r"(--password\s+)([^\s]+)", re.IGNORECASE),
    re.compile(r"(Bearer\s+)([^\s]+)", re.IGNORECASE),
    re.compile(r"(access_token[\"'\s:=]+)([^\s\"',}]+)", re.IGNORECASE),
    re.compile(r"(refresh_token[\"'\s:=]+)([^\s\"',}]+)", re.IGNORECASE),
    re.compile(r"(authorization_url[\"'\s:=]+)([^\s\"',}]+)", re.IGNORECASE),
    re.compile(r"(dlink[\"'\s:=]+)([^\s\"',}]+)", re.IGNORECASE),
    re.compile(r"(code_verifier[\"'\s:=]+)([^\s\"',}]+)", re.IGNORECASE),
]


def redact(text: str) -> str:
    if not text:
        return text
    for pattern in _REDACT_PATTERNS:
        text = pattern.sub(lambda m: f"{m.group(1)}<redacted>", text)
    return text


@dataclass
class RunResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def stdout_redacted(self) -> str:
        return redact(self.stdout)

    @property
    def stderr_redacted(self) -> str:
        return redact(self.stderr)


def _truncate(data: bytes) -> str:
    if len(data) > MAX_OUTPUT_BYTES:
        return data[:MAX_OUTPUT_BYTES].decode("utf-8", "replace") + "\n<output truncated>"
    return data.decode("utf-8", "replace")


class CliRunner:
    """Runs the CLI binary with a whitelisted environment."""

    def __init__(self, bin_path: str, config_dir: str, data_dir: str):
        self.bin_path = bin_path
        self.config_dir = config_dir
        self.data_dir = data_dir

    def _env(self) -> dict[str, str]:
        env = {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "LANG": os.environ.get("LANG", "C.UTF-8"),
            "FNOS_CLI_CONFIG_DIR": self.config_dir,
            "FNOS_CLI_SESSION_STORAGE": "file",
            "TRIM_CLI_DISTRIBUTION": "fnos",
            "HOME": os.path.join(self.data_dir, "home"),
        }
        if "SSL_CERT_FILE" in os.environ:
            env["SSL_CERT_FILE"] = os.environ["SSL_CERT_FILE"]
        if "SSL_CERT_DIR" in os.environ:
            env["SSL_CERT_DIR"] = os.environ["SSL_CERT_DIR"]
        return env

    def run(self, argv: list[str], timeout: float) -> RunResult:
        try:
            proc = subprocess.run(
                [self.bin_path, *argv],
                capture_output=True,
                timeout=timeout,
                env=self._env(),
            )
            return RunResult(
                returncode=proc.returncode,
                stdout=_truncate(proc.stdout),
                stderr=_truncate(proc.stderr),
            )
        except subprocess.TimeoutExpired as exc:
            return RunResult(
                returncode=-1,
                stdout=_truncate(exc.stdout or b""),
                stderr=_truncate(exc.stderr or b""),
                timed_out=True,
            )
        except FileNotFoundError:
            return RunResult(returncode=-1, stdout="", stderr=f"CLI binary not found: {self.bin_path}")
        except OSError as exc:
            return RunResult(returncode=-1, stdout="", stderr=f"failed to run CLI: {exc}")
