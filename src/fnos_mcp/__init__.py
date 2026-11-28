"""fnOS multi-machine MCP gateway.

One container, one HTTP MCP service + one configuration/connectivity
panel, managing multiple fnOS NAS via the official fnos-cli 0.6.2 (see
cli_adapter.py — the only module that talks to the CLI). Admins can add
and edit machine profiles in the panel; the writable store lives in
/data, seeded once from the read-only profiles.json.
"""

__version__ = "0.1.0"
__cli_version__ = "0.6.2"
