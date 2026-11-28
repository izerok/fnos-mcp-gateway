"""Capability-probe tests live in test_cli_adapter.py (they share the
fake-CLI fixture); this module covers the diff helper in isolation."""

from fnos_mcp.cli_capabilities import Capabilities


def test_diff_reports_missing_and_extra():
    caps = Capabilities(version="0.6.2", commands={"login", "user", "extra-cmd"})
    diff = caps.diff({"login", "user", "system"})
    assert diff["missing"] == ["system"]
    assert diff["extra"] == ["extra-cmd"]
    assert caps.diff({"login", "user", "extra-cmd"}) == {"missing": [], "extra": []}
