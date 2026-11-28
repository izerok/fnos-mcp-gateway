"""FastAPI + MCP server (single process, single worker).

MCP transport (M2): FastMCP 2, Streamable HTTP, mounted at /mcp.
Bearer auth + X-FNOS-Profile pin are enforced by _McpAuthApp, a pure
ASGI wrapper around the FastMCP app — it verifies the token before
FastMCP sees the request and hands the TokenRecord to the tools via
contextvars (see mcp_server.py). Tool logic is unchanged
(tools/registry.py).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import auth as auth_mod
from . import __version__
from .audit import AuditLog
from .auth import RateLimiter, load_rate_limits
from .cli_adapter import FnosCli
from .config import load_profiles, load_tokens
from .errors import ApiError, CliVersionError
from .mcp_server import _CLIENT_IP, _PINNED, _TOKEN, build_fastmcp
from .panel_auth import PanelAuthStore
from .profile_store import ProfileStore, ensure_profile_store
from .runner import CliRunner
from .settings import SettingsStore
from .state_store import PanelStateStore
from .token_store import TokenStore, ensure_token_store


@dataclass
class Service:
    profiles_path: str
    tokens_path: str
    tokens_seed_path: str
    data_dir: Path
    cli: FnosCli
    cli_version: str
    state: PanelStateStore
    audit: AuditLog
    profile_store: ProfileStore
    token_store: TokenStore
    panel_auth: PanelAuthStore
    limiter: RateLimiter
    settings: SettingsStore
    secret: bytes
    trusted_proxies: list[str]
    allowed_origins: list[str]
    ca_bundle: str | None
    mcp_public_url: str | None


def _cli_timeout_buckets(settings) -> dict[str, int]:
    """Map SettingsStore fields onto FnosCli timeout buckets."""
    return {
        "read": int(settings.get("cli_read_s")),
        "logs": int(settings.get("cli_logs_s")),
        "action": int(settings.get("cli_action_s")),
        "build": int(settings.get("cli_build_s")),
    }


def _load_panel_secret(data_dir: Path) -> bytes:
    candidates = []
    env_path = os.environ.get("PANEL_SESSION_SECRET_FILE")
    if env_path:
        candidates.append(Path(env_path))
    candidates.append(Path("/run/secrets/panel_session_secret"))
    candidates.append(data_dir / "panel-session.key")
    for path in candidates:
        if path.is_file():
            # Raw bytes: never strip a binary key — random keys legitimately
            # contain leading/trailing whitespace bytes, and stripping them
            # would silently shorten an otherwise valid 32-byte secret.
            secret = path.read_bytes()
            if not secret.strip():
                raise RuntimeError(
                    f"panel session secret at {path} is blank; refusing to start"
                )
            if len(secret) < 32:
                raise RuntimeError(
                    f"panel session secret at {path} is too short "
                    f"({len(secret)} bytes; need >=32); refusing to start"
                )
            return secret
    raise RuntimeError(
        "panel session secret missing: set PANEL_SESSION_SECRET_FILE or "
        "place a key at /data/panel-session.key (0600); refusing to start"
    )


def build_service(profiles_path: str, tokens_path: str, data_dir: str,
                  skip_cli_check: bool = False) -> Service:
    data = Path(data_dir)
    data.mkdir(parents=True, exist_ok=True)
    (data / "locks").mkdir(parents=True, exist_ok=True)
    (data / "fnos-cli").mkdir(parents=True, exist_ok=True)
    (data / "home").mkdir(parents=True, exist_ok=True)
    # File-level config errors fail startup (FR: config.py).
    # The seed is read-only; when FNOS_PROFILES_STORE is set, copy it to
    # the writable volume once, then use the store as the source of truth.
    seed_path = str(profiles_path)
    load_profiles(seed_path)
    store_env = os.environ.get("FNOS_PROFILES_STORE")
    if store_env:
        ensure_profile_store(seed_path, store_env)
        profiles_path = str(Path(store_env))
        load_profiles(profiles_path)
    # Same pattern for agent tokens: the mounted seed is read-only, the
    # writable store is what the panel manages and what MCP verifies.
    tokens_seed_path = str(tokens_path)
    load_tokens(tokens_seed_path)
    tokens_store_env = os.environ.get("FNOS_TOKENS_STORE")
    if tokens_store_env:
        ensure_token_store(tokens_seed_path, tokens_store_env)
        tokens_path = str(Path(tokens_store_env))
        load_tokens(tokens_path)
    secret = _load_panel_secret(data)
    cli_bin = os.environ.get("FNOS_CLI_BIN", "fnos-cli")
    runner = CliRunner(cli_bin, str(data / "fnos-cli"), str(data))
    settings = SettingsStore(data / "settings.json")
    cli = FnosCli(runner, timeouts=_cli_timeout_buckets(settings))
    if skip_cli_check or os.environ.get("FNOS_SKIP_CLI_CHECK") == "1":
        cli_version = "unchecked"
    else:
        try:
            cli_version = cli.check_version()
        except CliVersionError:
            raise
        except Exception as exc:
            raise RuntimeError(f"CLI startup self-check failed: {exc}")
    return Service(
        profiles_path=profiles_path, tokens_path=tokens_path,
        tokens_seed_path=tokens_seed_path, data_dir=data,
        cli=cli, cli_version=cli_version,
        state=PanelStateStore(data / "panel-state.json"),
        audit=AuditLog(data / "audit.jsonl"),
        profile_store=ProfileStore(profiles_path),
        token_store=TokenStore(tokens_path, secret),
        panel_auth=PanelAuthStore(data / "panel-auth.json"),
        limiter=RateLimiter(load_rate_limits()),
        settings=settings,
        secret=secret,
        trusted_proxies=[c for c in os.environ.get("TRUSTED_PROXY_CIDRS", "").split(",") if c],
        allowed_origins=[o for o in os.environ.get("PANEL_ALLOWED_ORIGINS", "").split(",") if o],
        ca_bundle=os.environ.get("SSL_CERT_FILE"),
        mcp_public_url=os.environ.get("MCP_PUBLIC_URL") or None,
    )


def create_app(profiles_path: str | None = None, tokens_path: str | None = None,
               data_dir: str | None = None, skip_cli_check: bool = False) -> FastAPI:
    profiles_path = profiles_path or os.environ.get(
        "FNOS_PROFILES_PATH", "/etc/fnos-mcp/profiles.json")
    tokens_path = tokens_path or os.environ.get(
        "FNOS_TOKENS_PATH", "/run/secrets/mcp_tokens.json")
    data_dir = data_dir or os.environ.get("FNOS_DATA_DIR", "/data")
    service = build_service(profiles_path, tokens_path, data_dir, skip_cli_check)
    templates_dir = Path(__file__).resolve().parent.parent.parent / "web" / "templates"
    static_dir = Path(__file__).resolve().parent.parent.parent / "web" / "static"

    from .api.routes import build_router

    # FastMCP 2 (Streamable HTTP) behind a Bearer-checking ASGI wrapper.
    # Its lifespan must run under the parent app, or the session
    # manager's task group is never initialized (500 on first POST).
    mcp = build_fastmcp(service)
    fastmcp_app = mcp.http_app(path="/", transport="streamable-http")
    app = FastAPI(title="fnOS MCP gateway", version=__version__,
                  lifespan=fastmcp_app.lifespan)
    app.state.service = service
    app.state.templates = Jinja2Templates(directory=str(templates_dir))
    app.include_router(build_router())
    if static_dir.is_dir():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    @app.exception_handler(ApiError)
    async def api_error_handler(request: Request, exc: ApiError):
        status = exc.http_status or 400
        headers = {}
        if exc.code == "rate_limited" and exc.details.get("retry_after") is not None:
            headers["Retry-After"] = str(exc.details["retry_after"])
        if request.headers.get("hx-request") == "true":
            from .errors import ERRORS
            entry = ERRORS.get(exc.code)
            message = entry[1] if entry else exc.message
            retryable = entry[2] if entry else exc.retryable
            fragment = (f'<div class="inline-error" role="alert" data-error-code="{exc.code}" '
                        f'data-retryable="{str(retryable).lower()}"><p>{message}</p></div>')
            return HTMLResponse(fragment, status_code=status, headers=headers)
        return JSONResponse({"error": {"code": exc.code, "message": exc.message,
                                       "profile": None, "retryable": exc.retryable,
                                       "details": exc.details}},
                            status_code=status, headers=headers)

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok", "cli_version": service.cli_version}

    # Mounted at /mcp: inside the mount the app sees path "/", so
    # FastMCP must serve "/" here (path="/mcp" would 307 to /mcp/).
    app.mount("/mcp", _McpAuthApp(fastmcp_app, service))

    return app


class _McpAuthApp:
    """Pure-ASGI wrapper: Bearer auth before FastMCP, no body read.

    Every /mcp request (including initialize) needs a valid Bearer
    token — unlike M1, where initialize was unauthenticated. A missing
    or unknown token gets a plain 401 JSON response; a valid token is
    placed in contextvars for the tool wrappers (mcp_server.py).
    """

    def __init__(self, inner, service: Service):
        self._inner = inner
        self._service = service

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self._inner(scope, receive, send)
            return
        headers = {k.decode("latin-1").lower(): v.decode("latin-1")
                   for k, v in scope.get("headers", [])}
        auth_header = headers.get("authorization", "")
        token_value = auth_header[7:] if auth_header.lower().startswith("bearer ") else ""
        token = (auth_mod.verify_bearer(token_value, load_tokens(self._service.tokens_path))
                 if token_value else None)
        if token is None:
            body = json.dumps({"error": {"code": "auth.required",
                                         "message": "未认证。",
                                         "profile": None, "retryable": True,
                                         "details": {}}}, ensure_ascii=False).encode("utf-8")
            await send({"type": "http.response.start", "status": 401,
                        "headers": [(b"content-type", b"application/json"),
                                    (b"content-length", str(len(body)).encode())]})
            await send({"type": "http.response.body", "body": body})
            return
        # Per-token rate limit for every authenticated /mcp request. The
        # panel endpoints have their own limits; without this, a leaked
        # key could hammer tool calls (each spawns a CLI process) freely.
        # Off by default; adjustable live in the panel (settings) and at
        # startup via FNOS_RATE_LIMIT_MCP_CALL.
        allowed, retry_after = self._service.limiter.check(
            "mcp_call", token.id)
        if not allowed:
            body = json.dumps({"error": {"code": "rate_limited",
                                         "message": "请求过于频繁，请稍后再试。",
                                         "profile": None, "retryable": True,
                                         "details": {"retry_after": retry_after}}},
                              ensure_ascii=False).encode("utf-8")
            await send({"type": "http.response.start", "status": 429,
                        "headers": [(b"content-type", b"application/json"),
                                    (b"content-length", str(len(body)).encode()),
                                    (b"retry-after", str(retry_after).encode())]})
            await send({"type": "http.response.body", "body": body})
            return
        client = scope.get("client")
        client_ip = client[0] if client else None
        t_token = _TOKEN.set(token)
        t_pin = _PINNED.set(headers.get("x-fnos-profile") or None)
        t_ip = _CLIENT_IP.set(client_ip)
        try:
            await self._inner(scope, receive, send)
        finally:
            _TOKEN.reset(t_token)
            _PINNED.reset(t_pin)
            _CLIENT_IP.reset(t_ip)

