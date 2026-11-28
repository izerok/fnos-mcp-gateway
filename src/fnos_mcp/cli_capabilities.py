"""Capability probe: what does this CLI binary actually support?

Run at startup (version only) and during an upgrade (full probe). The
probe never trusts Skill Markdown docs: it parses the real --help output
of the binary in front of it and diffs it against the commands this
codebase expects for the pinned version.

If a future CLI renames a subcommand, the diff — not a user — finds it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .runner import CliRunner

# Commands the 0.6.2 adapter expects to exist (P0 surface only). The
# 0.5.1 -> 0.6.2 --help diff (2026-11-24) showed an identical command
# tree; only login gained --agent-name/--device-name options.
EXPECTED_COMMANDS_051 = {
    "login", "logout", "user", "system", "storage", "file", "docker", "monitor",
}

_COMMAND_RE = re.compile(r"^\s{2,}([a-z][a-z0-9_-]+)\b", re.MULTILINE)


@dataclass
class Capabilities:
    version: str
    commands: set[str] = field(default_factory=set)
    help_text: str = ""

    def diff(self, expected: set[str] | None = None) -> dict[str, list[str]]:
        expected = expected if expected is not None else EXPECTED_COMMANDS_051
        return {
            "missing": sorted(expected - self.commands),
            "extra": sorted(self.commands - expected),
        }


def probe_capabilities(runner: CliRunner) -> Capabilities:
    version_result = runner.run(["--version"], timeout=15)
    version_text = (version_result.stdout or "") + (version_result.stderr or "")
    match = re.search(r"(\d+\.\d+\.\d+)", version_text)
    version = match.group(1) if match else "unknown"
    help_result = runner.run(["--help"], timeout=15)
    help_text = help_result.stdout or ""
    commands = set(_COMMAND_RE.findall(help_text))
    # Some CLIs list subcommands as "fnos-cli <command>"; catch those too.
    commands |= set(re.findall(r"fnos-cli\s+([a-z][a-z0-9_-]+)", help_text))
    return Capabilities(version=version, commands=commands, help_text=help_text)
