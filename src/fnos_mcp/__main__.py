"""Entry point: python -m fnos_mcp / `fnos-mcp` console script.

Single worker (uvicorn --workers 1 is enforced here by not forking).
Startup fails fast on: bad config files, missing panel secret, or a
CLI whose --version is not 0.6.2.
"""

from __future__ import annotations

import os

import uvicorn

from .server import create_app


def main() -> None:
    port = int(os.environ.get("MCP_PORT", "8000"))
    app = create_app()
    uvicorn.run(app, host="0.0.0.0", port=port, workers=1, log_level="info")


if __name__ == "__main__":
    main()
