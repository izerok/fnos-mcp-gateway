"""Panel API routes (需求文档 §10.5 路由契约).

- GET /, /login, /api/profiles, /healthz are read-only GETs.
- Every state change is POST, requires a panel session + CSRF +
  same-origin Origin/Referer, and is rate-limited (FR-34/FR-35).
- Every /api/profiles/{p}/* entry does cookie -> token -> ACL at the
  route entry; outside the ACL the answer is 404, indistinguishable
  from an unknown profile (FR-35, NFR-06).
- HTMX requests (HX-Request: true) get HTML fragments; other clients
  get the §10.6 JSON shape. Errors always carry a stable error code.

M2 scope note:
- Page-load probe-all IS auto-triggered (FR-13): the roster wrapper
  posts probe-all once on load (hx-trigger="load", fragment rendered
  without the trigger so it cannot re-fire).
- Per-layer at/latency in the drawer (server-rendered fragment).
- 409 fragments carry data-error-code (probe.busy / session.locked).
- Config-error profiles render a 配置错误 row; zero-config and
  ACL-empty empty states are distinct.
- FR-21 rejection renders a no-URL fragment (login_rejected.html).
- HTMX is vendored (web/static/htmx.min.js); app.js is only the
  fallback/enhancement layer (focus trap, inert, live announcements).
"""

from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from .. import auth as auth_mod
from ..cli_adapter import LoginCodeExpired, LoginCodeInvalid
from ..config import Profile, TokenRecord, load_profiles
from ..errors import ERRORS, ApiError, CliError
from ..locks import LockedError, acquire_login_lease, probe_lock, release_login_lease, session_lock
from ..panel_auth import PanelAuthError, validate_password
from ..probe import probe_profile
from ..profile_store import ProfileStoreError, parse_profile_form
from ..settings import parse_rate_limit_form
from ..state_store import BADGES, SUB_LABELS, merge_status, now_iso
from ..token_store import TokenStoreError
from ..tools.registry import TOOLS, tool_catalog

CSRF_COOKIE = "fnos_csrf"
PANEL_COOKIE = "fnos_panel"


# ---------------------------------------------------------------- helpers
def _templates(request: Request):
    return request.app.state.templates


def _svc(request: Request):
    return request.app.state.service


def _public_mcp_url(request: Request) -> str:
    """Public MCP endpoint shown to the operator (never derived from input)."""
    svc = _svc(request)
    return svc.mcp_public_url or str(request.base_url).rstrip("/") + "/mcp"


def _fresh_profiles(request: Request):
    return load_profiles(_svc(request).profiles_path)


def _client_ip(request: Request) -> str:
    svc = _svc(request)
    host = request.client.host if request.client else None
    return auth_mod.real_client_ip(host, request.headers.get("x-forwarded-for"),
                                   svc.trusted_proxies)


PANEL_SUBJECT_ID = "panel"
PANEL_SUBJECT_NAME = "管理员"


def _panel_session(request: Request) -> bool:
    value = request.cookies.get(PANEL_COOKIE)
    fp = _svc(request).panel_auth.fingerprint()
    if not value or not fp:
        return False
    return auth_mod.verify_panel_session(value, _svc(request).secret, fp)


def _panel_token(request: Request) -> TokenRecord | None:
    """The panel is the human administrator: password login grants an
    explicit wildcard ACL. Agent keys (tokens.json) only authenticate
    MCP clients; they cannot open the panel."""
    if not _panel_session(request):
        return None
    fp = _svc(request).panel_auth.fingerprint() or ""
    return TokenRecord(id=PANEL_SUBJECT_ID, name=PANEL_SUBJECT_NAME,
                       sha256=fp, profiles=["*"], role="admin")


def _require_panel(request: Request) -> TokenRecord:
    token = _panel_token(request)
    if token is None:
        raise ApiError("auth.required")
    return token


def _require_csrf(request: Request, form_token: str | None = None) -> None:
    """Double-submit CSRF: header (HTMX/fetch) or hidden form field (plain
    form POST, e.g. /login — a plain <form> sends no X-CSRF-Token header).
    Either must match the cookie value."""
    header = request.headers.get("x-csrf-token")
    cookie = request.cookies.get(CSRF_COOKIE)
    if auth_mod.csrf_valid(header, cookie):
        return
    if form_token and auth_mod.csrf_valid(form_token, cookie):
        return
    raise ApiError("auth.forbidden")


def _check_origin(request: Request) -> None:
    svc = _svc(request)
    origin = request.headers.get("origin")
    referer = request.headers.get("referer")
    host = request.headers.get("host", "")
    allowed = {f"{request.url.scheme}://{host}", *svc.allowed_origins}
    for value in (origin, referer):
        if value:
            from urllib.parse import urlparse
            parsed = urlparse(value)
            cand = f"{parsed.scheme}://{parsed.netloc}"
            if cand not in allowed:
                raise ApiError("auth.forbidden")


def _rate_limit(request: Request, kind: str, key: str) -> None:
    allowed, retry_after = _svc(request).limiter.check(kind, key)
    if not allowed:
        raise ApiError("rate_limited", details={"retry_after": retry_after})


def _respond(request: Request, status: int, fragment: str, payload: dict,
             headers: dict | None = None):
    if request.headers.get("hx-request") == "true":
        return HTMLResponse(fragment, status_code=status, headers=headers)
    return JSONResponse(payload, status_code=status, headers=headers)


def _require_profile_manager(request: Request, token: TokenRecord,
                             *, action: str = "profile_write") -> None:
    if token.can_manage_profiles:
        return
    _audit(request, "acl_forbidden", token_id=token.id, result="failed")
    raise ApiError("auth.forbidden")


def _profile_form_values(raw: object, name: str | None) -> dict:
    if not hasattr(raw, "get"):
        raw = {}
    if name is None:
        submitted = raw.get("name", "")
        name = submitted if isinstance(submitted, str) else ""
    port = raw.get("port", 5667)
    if not isinstance(port, int) or isinstance(port, bool):
        port = raw.get("port", "")
    scheme = raw.get("scheme", "https")
    if scheme not in ("http", "https"):
        scheme = "https"
    description = raw.get("description", "")
    if not isinstance(description, str):
        description = str(description)
    host = raw.get("host", "")
    return {
        "name": name,
        "host": host if isinstance(host, str) else "",
        "port": port,
        "scheme": scheme,
        "allow_insecure_http": bool(raw.get("allow_insecure_http", False)),
        "tls_insecure": bool(raw.get("tls_insecure", False)),
        "description": description,
    }


def _render_profile_form(request: Request, *, name: str | None, values: dict,
                         errors: dict[str, str] | None = None,
                         error: str | None = None,
                         config_error: str | None = None,
                         status: int = 200):
    is_edit = name is not None
    action = f"/api/profiles/{name}/edit" if is_edit else "/api/profiles"
    html = _templates(request).get_template("fragments/profile_form.html").render(
        request=request, is_edit=is_edit, profile_name=name, action=action,
        values=values, errors=errors or {}, error=error,
        config_error=config_error,
        csrf_token=request.cookies.get(CSRF_COOKIE, ""))
    if request.headers.get("hx-request") == "true":
        return HTMLResponse(html, status_code=status,
                            headers={"Cache-Control": "no-store"})
    if status >= 400:
        return JSONResponse({
            "error": {"code": "profile.invalid", "message": "机器配置不合法，请检查输入。",
                      "profile": name, "retryable": False, "details": {}}},
            status_code=status, headers={"Cache-Control": "no-store"})
    return HTMLResponse(html, status_code=status,
                        headers={"Cache-Control": "no-store"})


def _profile_saved_response(request: Request, token: TokenRecord, profile: Profile,
                            *, created: bool):
    acl_visible = token.allows(profile.name)
    saved = _templates(request).get_template("fragments/profile_saved.html").render(
        profile=profile, created=created, acl_visible=acl_visible)
    if request.headers.get("hx-request") == "true":
        # The saved panel replaces the modal body; the OOB roster makes
        # the new/edited machine appear without a full page reload.
        roster = _roster_fragment(request, token, oob=True)
        return HTMLResponse(saved + roster,
                            headers={"Cache-Control": "no-store"})
    return JSONResponse({"profile": profile.name,
                         "status": "created" if created else "updated",
                         "visible_to_token": acl_visible},
                        headers={"Cache-Control": "no-store"})


def _visible_profile(request: Request, token: TokenRecord, name: str) -> Profile:
    profiles = _fresh_profiles(request)
    # ACL first: a name outside the token's ACL must be indistinguishable
    # from an unknown profile, even when that profile is also malformed.
    if not token.allows(name):
        _audit(request, "acl_forbidden", token_id=token.id, profile=name, result="failed")
        raise ApiError("profile.not_found")
    if name in profiles.config_errors:
        raise ApiError("profile.config_error")
    if name not in profiles.profiles:
        raise ApiError("profile.not_found")
    return profiles.profiles[name]


def _entry(request: Request, name: str) -> dict:
    return _svc(request).state.load()["profiles"].get(name, {})


def _drop_stale(request: Request, profiles=None) -> None:
    """Invalidate state whose target fingerprint no longer matches config.

    Called by every profile read entry, not only GET / (FR-31), so the
    API/MCP cannot keep showing a stale "connected" badge.
    """
    profiles = profiles or _fresh_profiles(request)
    _svc(request).state.drop_stale(
        {n: p.target for n, p in profiles.profiles.items()})


def _fmt_time(iso: str | None) -> str:
    if not iso:
        return "—"
    try:
        return datetime.fromisoformat(iso).strftime("%H:%M")
    except ValueError:
        return "—"


def _row_context(request: Request, token: TokenRecord, profile: Profile) -> dict:
    profiles = _fresh_profiles(request)
    entry = _entry(request, profile.name)
    # A stored layer belongs to the target it was measured against. If
    # profiles.json changed host/port/scheme, never reuse that result.
    if entry and entry.get("target") != profile.target:
        entry = {}
    network = entry.get("network") or {}
    auth = entry.get("auth") or {}
    badge = merge_status(entry.get("network"), entry.get("auth"),
                         config_error=profile.name in profiles.config_errors)
    label, bucket, cls = BADGES[badge]
    sub = SUB_LABELS[badge]
    if badge == "connected" and auth.get("identity"):
        sub = f"身份 {auth['identity']}"
    if badge == "unreachable":
        sub = {"dns_failed": "域名解析失败", "refused": "连接被拒绝",
               "timeout": "连接超时"}.get(network.get("status", ""), "网络不可达")
    tls_ok = network.get("status") == "ok"
    # Layer details for the drawer. Each layer carries its OWN at /
    # latency_ms — never a shared network.at. Config has no check time;
    # network is DNS+TCP (tcp_ms is cumulative to TCP connect); TLS is
    # the handshake slice of the same probe run (its at is the probe
    # run's time, its latency is handshake-only); auth is user_info's
    # own call (auth.at / auth.latency_ms, measured in the route).
    tls_handshake = None
    if network.get("tls_ms") is not None and network.get("tcp_ms") is not None:
        tls_handshake = max(0, network["tls_ms"] - network["tcp_ms"])
    layers = {
        "config": {"status": ("pass" if profile.name not in profiles.config_errors else "fail"),
                   "detail": ("profile 合法，ACL 允许访问" if profile.name not in profiles.config_errors
                              else "profile 被跳过"),
                   "at": None, "latency_ms": None},
        "network": {"status": ("pass" if tls_ok or network.get("status") == "ok" else
                               ("fail" if network.get("status") in ("dns_failed", "refused", "timeout") else "idle")),
                    "detail": network.get("detail") or ("未执行" if not network else ""),
                    "at": network.get("at"), "latency_ms": network.get("tcp_ms")},
        "tls": {"status": ("idle" if profile.scheme == "http" else
                          ("pass" if network.get("status") == "ok" else
                           ("fail" if network.get("status") in ("tls_failed", "http_failed") else "idle"))),
                "detail": ("明文连接，不走 TLS" if profile.scheme == "http"
                           else ("证书有效" if network.get("status") == "ok"
                                 else (network.get("detail") or "未执行"))),
                "at": (None if profile.scheme == "http" else network.get("at")),
                "latency_ms": (None if profile.scheme == "http" else tls_handshake)},
        "auth": {"status": ("pass" if auth.get("status") == "ok" else
                           ("fail" if auth.get("status") in ("expired", "permission") else "idle")),
                 "detail": (f"user info 返回 {auth['identity'] or '会话有效'}" if auth.get("status") == "ok"
                            else {"expired": "登录已失效，需要重新登录",
                                  "permission": "账号权限不足"
                                  }.get(auth.get("status"),
                                        "未登录" if not auth else "本机 session 已清除")),
                 "at": auth.get("at"), "latency_ms": auth.get("latency_ms")},
    }
    last_network = _fmt_time(network.get("at"))
    last_auth = _fmt_time(auth.get("at"))
    latest = max([t for t in (last_network, last_auth) if t != "—"], default="—")
    return {
        "name": profile.name, "desc": profile.description, "target": profile.target,
        "badge": badge, "badge_label": label, "badge_cls": cls, "bucket": bucket,
        "sub": sub, "tls_text": ("明文连接" if profile.scheme == "http"
                                 else ("TLS 有效" if network.get("status") == "ok"
                                       else "TLS 错误" if network.get("status") in ("tls_failed", "http_failed")
                                       else "TLS 未验证")),
        "last_check": latest, "latency": network.get("latency_ms"),
        "error": network.get("detail") if badge == "tls" else "",
        "can_login": network.get("status") == "ok",
        "can_manage_login": token.can_manage_login,
        "can_manage_profiles": token.can_manage_profiles,
        "layers": layers,
        "identity": auth.get("identity"),
        # FR-37: whitelisted identity facts (uid/gid/admin/groups) as
        # stored by /test or login_finish; only shown for auth.status ok.
        "identity_detail": (auth.get("detail") if auth.get("status") == "ok" else None),
        "insecure_tags": ([t for t in (
            ("allow_insecure_http", profile.allow_insecure_http),
            ("tls_insecure", profile.tls_insecure)) if t[1]]),
        "config_error": False,
    }


def _config_error_row_context(request: Request, token: TokenRecord, name: str,
                              reason: str) -> dict:
    """Row for a profile that failed validation: no Profile object
    exists, so the row is built from the error alone (badge: config)."""
    return {
        "name": name, "desc": "", "target": "—",
        "badge": "config", "badge_label": "配置错误", "badge_cls": "bad",
        "bucket": "error", "sub": "profile 被跳过", "tls_text": "TLS 未验证",
        "last_check": "—", "latency": None, "error": reason,
        "can_login": False, "can_manage_login": token.can_manage_login,
        "can_manage_profiles": token.can_manage_profiles,
        "layers": {
            "config": {"status": "fail", "detail": reason, "at": None, "latency_ms": None},
            "network": {"status": "idle", "detail": "未执行", "at": None, "latency_ms": None},
            "tls": {"status": "idle", "detail": "未执行", "at": None, "latency_ms": None},
            "auth": {"status": "idle", "detail": "未执行", "at": None, "latency_ms": None},
        },
        "identity": None, "identity_detail": None, "insecure_tags": [],
        "config_error": True,
    }


def _visible_names(request: Request, token: TokenRecord):
    """Token-visible profile names, valid ones first, then config-error
    ones (so a 配置错误 row is rendered instead of vanishing)."""
    profiles = _fresh_profiles(request)
    if "*" in token.profiles:
        return list(profiles.profiles), list(profiles.config_errors)
    valid = [n for n in token.profiles if n in profiles.profiles]
    broken = [n for n in token.profiles if n in profiles.config_errors]
    return valid, broken


def _all_row_contexts(request: Request, token: TokenRecord) -> list[dict]:
    profiles = _fresh_profiles(request)
    valid, broken = _visible_names(request, token)
    rows = [_row_context(request, token, profiles.profiles[n]) for n in valid]
    rows += [_config_error_row_context(request, token, n, profiles.config_errors[n])
             for n in broken]
    return rows


def _rows_fragment(request: Request, token: TokenRecord) -> str:
    return _templates(request).get_template("fragments/rows.html").render(
        rows=_all_row_contexts(request, token))


def _roster_fragment(request: Request, token: TokenRecord,
                     busy: list[str] | None = None, *, oob: bool = False,
                     deleted: str | None = None) -> str:
    """Summary + roster sections as one fragment (probe-all target).

    ``deleted`` marks a roster rendered as the answer to a profile
    delete, so the frontend can tell a delete swap apart from a scan
    (no "扫描完成" announcement) and the empty state renders when the
    last machine is gone."""
    return _templates(request).get_template("fragments/roster.html").render(
        summary=_summary_context(request, token),
        rows=_all_row_contexts(request, token),
        config_errors=_fresh_profiles(request).config_errors,
        can_manage_login=token.can_manage_login,
        can_manage_profiles=token.can_manage_profiles,
        empty_kind=_empty_kind(request, token),
        last_scan=_last_scan_text(request, token),
        busy=busy or [], auto_probe=False, oob=oob, deleted=deleted)


def _empty_kind(request: Request, token: TokenRecord) -> str | None:
    """Which empty state the roster is in (None = machines to show).

    Shared by GET / and the roster fragment so an HTMX roster swap
    (e.g. after deleting the last machine) lands on the same empty
    state a full page load would show."""
    profiles = _fresh_profiles(request)
    valid, broken = _visible_names(request, token)
    if not profiles.profiles and not profiles.config_errors:
        return "zero_config"
    if not valid and not broken:
        return "acl_empty"
    if not valid and broken:
        return "config_only"
    return None


def _last_scan_text(request: Request, token: TokenRecord) -> str:
    """Latest network-layer time across the token's visible profiles
    (max of panel-state network.at); "—" when nothing was ever probed.
    Stale entries (target fingerprint changed) are ignored, like the
    summary badges."""
    profiles = _fresh_profiles(request)
    valid, _broken = _visible_names(request, token)
    state = _svc(request).state.load()["profiles"]
    latest: str | None = None
    latest_ts = -1.0
    for name in valid:
        profile = profiles.profiles.get(name)
        if profile is None:
            continue
        entry = state.get(name) or {}
        if entry.get("target") != profile.target:
            continue
        at = (entry.get("network") or {}).get("at")
        if not at:
            continue
        try:
            ts = datetime.fromisoformat(at).timestamp()
        except ValueError:
            continue
        if ts > latest_ts:
            latest_ts = ts
            latest = at
    return _fmt_time(latest)


def _summary_context(request: Request, token: TokenRecord) -> dict:
    profiles = _fresh_profiles(request)
    valid, broken = _visible_names(request, token)
    names = valid + broken
    targets = {n: p.target for n, p in profiles.profiles.items()}
    summary = _svc(request).state.summarize(
        names, set(profiles.config_errors), targets=targets)
    return {"counts": summary["counts"], "badges": summary["badges"],
            "names": names, "config_errors": profiles.config_errors}


CAP_GROUP_ORDER = ["会话与状态", "系统与存储", "文件", "Docker 容器",
                   "Docker Compose", "监控"]


def _capability_context(request: Request, token: TokenRecord) -> dict:
    """Everything the capability page shows, derived from the tool
    registry and the live config so it cannot drift from MCP."""
    catalog = tool_catalog()
    for item in catalog:
        schema = TOOLS[item["name"]][2]
        required = set(schema.get("required", []))
        params = []
        for pname, pschema in (schema.get("properties") or {}).items():
            ptype = pschema.get("type") or "any"
            if ptype == "array":
                ptype = "array<" + str((pschema.get("items") or {}).get("type", "string")) + ">"
            params.append({"name": pname, "type": ptype,
                           "required": pname in required,
                           "enum": pschema.get("enum")})
        item["params"] = params
        item["schema_json"] = json.dumps(schema, ensure_ascii=False, indent=1)
    groups = []
    for gname in CAP_GROUP_ORDER:
        items = [i for i in catalog if i["group"] == gname]
        if items:
            groups.append({
                "name": gname, "tools": items,
                "read": sum(1 for i in items if i["kind"] == "read"),
                "write": sum(1 for i in items if i["kind"] == "write"),
            })
    profiles = _fresh_profiles(request)
    valid, broken = _visible_names(request, token)
    profile_rows = []
    for n in valid:
        row = _row_context(request, token, profiles.profiles[n])
        profile_rows.append({
            "name": n, "description": profiles.profiles[n].description,
            "status": row["badge_label"], "badge_cls": row["badge_cls"],
            "allow_dangerous": profiles.profiles[n].allow_dangerous,
            "tls_insecure": profiles.profiles[n].tls_insecure,
            "allow_insecure_http": profiles.profiles[n].allow_insecure_http,
        })
    for n in broken:
        profile_rows.append({
            "name": n, "description": "", "status": "配置错误", "badge_cls": "bad",
            "allow_dangerous": False, "tls_insecure": False,
            "allow_insecure_http": False, "config_error": profiles.config_errors[n],
        })
    svc = _svc(request)
    return {
        "tools": catalog,
        "groups": groups,
        "counts": {
            "total": len(catalog),
            "read": sum(1 for i in catalog if i["kind"] == "read"),
            "write": sum(1 for i in catalog if i["kind"] == "write"),
            "compose": sum(1 for i in catalog if i["group"] == "Docker Compose"),
        },
        "profiles": profile_rows,
        "hidden": max(0, len(profiles.profiles) - len(valid)),
        "runtime": {
            "cli_version": svc.cli_version,
            "mcp_url": _public_mcp_url(request),
            "data_dir": str(svc.data_dir),
            "writable": _dir_writable(svc.data_dir),
            "protocol": "Streamable HTTP（POST /mcp）",
        },
    }


def _dir_writable(path) -> bool:
    import os
    return os.access(str(path), os.W_OK)


def _capability_manifest(request: Request, token: TokenRecord) -> dict:
    cap = _capability_context(request, token)
    return {
        "gateway": cap["runtime"],
        "token": {"name": token.name, "role": token.role,
                  "capabilities": list(token.capabilities),
                  "profiles": list(token.profiles)},        "counts": cap["counts"],
        "groups": [{"name": g["name"], "read": g["read"], "write": g["write"],
                    "tools": [i["name"] for i in g["tools"]]} for g in cap["groups"]],
        "tools": [{k: v for k, v in i.items() if k not in ("schema_json", "params")}
                  for i in cap["tools"]],
        "profiles": cap["profiles"],
        "hidden": cap["hidden"],
    }


def _row_fragment(request: Request, token: TokenRecord, profile: Profile) -> str:
    return _templates(request).get_template("fragments/row.html").render(
        row=_row_context(request, token, profile))


def _audit(request: Request, event: str, token_id=None, profile=None,
           result="ok", **extra):
    _svc(request).audit.record(event, token_id=token_id, profile=profile,
                               result=result, client_ip=_client_ip(request), **extra)


# ------------------------------------------------- panel / key management
def _token_list_context(request: Request) -> dict:
    try:
        return {"tokens": _svc(request).token_store.list_entries(),
                "token_error": None}
    except TokenStoreError as exc:
        return {"tokens": [], "token_error": exc.message}


def _token_rows_fragment(request: Request, *, oob: bool = False) -> str:
    return _templates(request).get_template("fragments/token_rows.html").render(
        **_token_list_context(request), oob=oob)


def _token_values_from_form(form) -> dict:
    def _checked(key: str) -> bool:
        return str(form.get(key) or "").lower() in ("on", "true", "1", "yes")
    return {
        "name": str(form.get("name") or "").strip(),
        "role": str(form.get("role") or "operator"),
        "capabilities": [str(c) for c in form.getlist("capabilities")],
        "scope_all": _checked("scope_all"),
        "profiles": [str(p) for p in form.getlist("profiles")],
    }


def _token_values_from_entry(entry: dict) -> dict:
    profiles = list(entry.get("profiles") or [])
    return {
        "name": entry.get("name") or "",
        "role": entry.get("role") or "operator",
        "capabilities": list(entry.get("capabilities") or []),
        "scope_all": "*" in profiles,
        "profiles": [p for p in profiles if p != "*"],
    }


def _render_token_form(request: Request, *, key_id: str | None, values: dict,
                       errors: dict[str, str] | None = None,
                       error: str | None = None, status: int = 200):
    is_edit = key_id is not None
    action = f"/api/tokens/{key_id}/edit" if is_edit else "/api/tokens"
    profiles = _fresh_profiles(request)
    html = _templates(request).get_template("fragments/token_form.html").render(
        request=request, is_edit=is_edit, key_id=key_id, action=action,
        values=values, errors=errors or {}, error=error,
        profiles=profiles.profiles, config_errors=profiles.config_errors,
        csrf_token=request.cookies.get(CSRF_COOKIE, ""))
    if request.headers.get("hx-request") == "true":
        return HTMLResponse(html, status_code=status,
                            headers={"Cache-Control": "no-store"})
    if status >= 400:
        return JSONResponse({"error": {"code": "token.invalid",
                                       "message": error or "密钥配置不合法。",
                                       "profile": None, "retryable": False,
                                       "details": errors or {}}},
                            status_code=status,
                            headers={"Cache-Control": "no-store"})
    return HTMLResponse(html, status_code=status,
                        headers={"Cache-Control": "no-store"})


def _client_config(request: Request, plaintext: str) -> tuple[str, str]:
    """(mcp_url, ready-to-paste mcpServers JSON) for one plaintext key."""
    mcp_url = _public_mcp_url(request)
    config = json.dumps({"mcpServers": {"fnos": {
        "type": "http",
        "url": mcp_url,
        "headers": {"Authorization": f"Bearer {plaintext}"},
    }}}, ensure_ascii=False, indent=2)
    return mcp_url, config


def _token_secret_response(request: Request, entry: dict, plaintext: str,
                           *, rotated: bool):
    """Response that carries the new plaintext right after create/rotate.

    The HTML branch also embeds a ready-to-paste MCP client config. It is
    rendered server-side into a hidden <pre> so app.js only copies text
    and never interpolates a secret into JavaScript.
    """
    mcp_url, client_config = _client_config(request, plaintext)
    fragment = _templates(request).get_template(
        "fragments/token_created.html").render(
        entry=entry, plaintext=plaintext, rotated=rotated,
        mcp_url=mcp_url, client_config=client_config)
    if request.headers.get("hx-request") == "true":
        return HTMLResponse(fragment + _token_rows_fragment(request, oob=True),
                            headers={"Cache-Control": "no-store"})
    return JSONResponse({"token": entry, "plaintext": plaintext},
                        headers={"Cache-Control": "no-store"})


def _token_saved_response(request: Request, entry: dict):
    fragment = _templates(request).get_template(
        "fragments/token_saved.html").render(entry=entry)
    if request.headers.get("hx-request") == "true":
        return HTMLResponse(fragment + _token_rows_fragment(request, oob=True),
                            headers={"Cache-Control": "no-store"})
    return JSONResponse({"token": entry, "status": "updated"},
                        headers={"Cache-Control": "no-store"})


def _render_password_form(request: Request, *, values: dict | None = None,
                          errors: dict[str, str] | None = None,
                          error: str | None = None, status: int = 200):
    html = _templates(request).get_template("fragments/password_form.html").render(
        values=values or {"current": ""}, errors=errors or {}, error=error,
        csrf_token=request.cookies.get(CSRF_COOKIE, ""))
    if request.headers.get("hx-request") == "true":
        return HTMLResponse(html, status_code=status,
                            headers={"Cache-Control": "no-store"})
    if status >= 400:
        code = "password.wrong" if error == "当前密码不正确。" else "password.invalid"
        return JSONResponse({"error": {"code": code,
                                       "message": error or ERRORS[code][1],
                                       "profile": None, "retryable": False,
                                       "details": {}}},
                            status_code=status,
                            headers={"Cache-Control": "no-store"})
    return HTMLResponse(html, status_code=status,
                        headers={"Cache-Control": "no-store"})


# Settings form field metadata: (label, unit hint, min, max, step).
_SETTINGS_FIELDS = [
    ("probe_timeout_s", "探测超时", "秒（DNS+TCP+TLS+HTTP 总预算）", 1, 30, 0.5),
    ("probe_concurrency", "探测并发", "同时探测的机器数上限", 1, 16, 1),
    ("probe_wait_s", "全部探测等待", "整轮探测的最长等待", 5, 120, 1),
    ("panel_session_hours", "面板会话时长", "登录后多久需要重新登录", 1, 168, 1),
    ("audit_max_mb", "审计单文件上限", "超过后轮转成 .1/.2…", 1, 1024, 1),
    ("audit_keep", "审计保留份数", "当前文件 + 归档总数", 2, 50, 1),
    ("cli_read_s", "CLI 读取超时", "列表、info 类命令", 10, 900, 1),
    ("cli_logs_s", "CLI 日志/文件超时", "日志、chown、容器删除", 10, 900, 1),
    ("cli_action_s", "CLI 动作超时", "compose create、容器创建", 10, 900, 1),
    ("cli_build_s", "CLI 构建超时", "compose build/clear/delete、上传", 30, 1800, 1),
]

# Rate-limit kinds shown in the settings form, with human labels.
_RATE_LIMIT_FIELDS = [
    ("mcp_call", "MCP 调用（每把 key）", "off"),
    ("mcp_write", "MCP 写操作（每把 key）", None),
    ("panel_login", "面板登录（每 IP）", None),
    ("probe", "测试网络（每机器）", None),
    ("test", "测试连接（每机器）", None),
    ("login_start", "发起登录（每机器）", None),
    ("login_finish", "提交授权码（每机器）", None),
    ("profile_write", "保存机器（每会话）", None),
    ("token_write", "密钥管理（每会话）", None),
    ("token_secret", "读取密钥明文（每会话）", None),
]


def _rate_limit_text(value) -> str:
    return "off" if value is None else f"{value[0]}/{value[1]}"


def _render_settings_form(request: Request, *, values: dict | None = None,
                          rate_texts: dict | None = None,
                          errors: dict | None = None, error: str | None = None,
                          saved: bool = False, status: int = 200):
    svc = _svc(request)
    snap = svc.settings.snapshot()
    if values is None:
        values = {k: str(v) for k, v in snap["values"].items()}
    if rate_texts is None:
        rate_texts = {k: _rate_limit_text(v)
                      for k, v in snap["rate_limits"].items()}
    html = _templates(request).get_template("fragments/settings_form.html").render(
        fields=_SETTINGS_FIELDS, rate_fields=_RATE_LIMIT_FIELDS,
        values=values, rate_texts=rate_texts, errors=errors or {},
        error=error, saved=saved, csrf_token=request.cookies.get(CSRF_COOKIE, ""))
    if request.headers.get("hx-request") == "true":
        return HTMLResponse(html, status_code=status,
                            headers={"Cache-Control": "no-store"})
    return JSONResponse({"status": "saved" if saved else "error",
                         "errors": errors or {},
                         **({"error": error} if error else {})},
                        status_code=status if status >= 400 else 200,
                        headers={"Cache-Control": "no-store"})


def _login_failure(request: Request, message: str, *, setup: bool, status: int,
                   wants_json: bool):
    if wants_json:
        code = "password.invalid" if setup else "auth.invalid"
        return JSONResponse({"error": {"code": code, "message": message,
                                       "profile": None, "retryable": True,
                                       "details": {}}}, status_code=status)
    html = _templates(request).get_template("login.html").render(
        request=request, csrf_token=request.cookies.get(CSRF_COOKIE, ""),
        error=message, setup=setup, cli_version=_svc(request).cli_version)
    return HTMLResponse(html, status_code=status)


def _login_success(request: Request, fingerprint: str):
    resp = RedirectResponse("/", status_code=302)
    secure = request.url.scheme == "https"
    ttl_hours = _svc(request).settings.get("panel_session_hours")
    resp.set_cookie(PANEL_COOKIE,
                    auth_mod.create_panel_session(_svc(request).secret, fingerprint,
                                                  ttl_hours=int(ttl_hours)),
                    httponly=True, secure=secure, samesite="lax",
                    max_age=int(ttl_hours) * 3600, path="/")
    resp.set_cookie(CSRF_COOKIE, auth_mod.new_csrf_token(), samesite="lax", path="/")
    return resp


# ---------------------------------------------------------------- router
def build_router():
    router = APIRouter()

    @router.get("/")
    async def index(request: Request):
        token = _panel_token(request)
        if token is None:
            return RedirectResponse("/login", status_code=302)
        svc = _svc(request)
        profiles = _fresh_profiles(request)
        svc.state.drop_stale({n: p.target for n, p in profiles.profiles.items()})
        valid, broken = _visible_names(request, token)
        summary = _summary_context(request, token)
        rows = _all_row_contexts(request, token)
        empty_kind = _empty_kind(request, token)
        csrf = request.cookies.get(CSRF_COOKIE) or auth_mod.new_csrf_token()
        mcp_url = _public_mcp_url(request)
        html = _templates(request).get_template("index.html").render(
            request=request, token=token, rows=rows, summary=summary,
            config_errors=profiles.config_errors, csrf_token=csrf,
            cli_version=svc.cli_version, corrupt=svc.state.corrupt,
            mcp_url=mcp_url, can_manage_login=token.can_manage_login,
            can_manage_profiles=token.can_manage_profiles,
            empty_kind=empty_kind, auto_probe=True, oob=False,
            nav_active="machines", tool_count=len(TOOLS),
            last_scan=_last_scan_text(request, token),
            **_token_list_context(request),
        )
        resp = HTMLResponse(html, headers={"Cache-Control": "no-store"})
        if not request.cookies.get(CSRF_COOKIE):
            resp.set_cookie(CSRF_COOKIE, csrf, samesite="lax", path="/")
        return resp

    @router.get("/capabilities")
    async def capabilities_page(request: Request):
        token = _panel_token(request)
        if token is None:
            return RedirectResponse("/login", status_code=302)
        csrf = request.cookies.get(CSRF_COOKIE) or auth_mod.new_csrf_token()
        html = _templates(request).get_template("capabilities.html").render(
            request=request, token=token, csrf_token=csrf,
            nav_active="capabilities", tool_count=len(TOOLS),
            **_capability_context(request, token))
        resp = HTMLResponse(html, headers={"Cache-Control": "no-store"})
        if not request.cookies.get(CSRF_COOKIE):
            resp.set_cookie(CSRF_COOKIE, csrf, samesite="lax", path="/")
        return resp

    @router.get("/api/capabilities.json")
    async def capabilities_json(request: Request):
        token = _panel_token(request)
        if token is None:
            raise ApiError("auth.required")
        return JSONResponse(_capability_manifest(request, token),
                            headers={"Cache-Control": "no-store"})

    @router.get("/login")
    async def login_page(request: Request):
        if _panel_session(request):
            return RedirectResponse("/", status_code=302)
        setup = not _svc(request).panel_auth.configured()
        csrf = request.cookies.get(CSRF_COOKIE) or auth_mod.new_csrf_token()
        html = _templates(request).get_template("login.html").render(
            request=request, csrf_token=csrf, error=None, setup=setup,
            cli_version=_svc(request).cli_version)
        resp = HTMLResponse(html, headers={"Cache-Control": "no-store"})
        if not request.cookies.get(CSRF_COOKIE):
            resp.set_cookie(CSRF_COOKIE, csrf, samesite="lax", path="/")
        return resp

    @router.post("/login")
    async def login_post(request: Request):
        _check_origin(request)
        _rate_limit(request, "panel_login", _client_ip(request))
        # Plain form POST: parse the body first so the hidden csrf_token
        # field can satisfy the double-submit check (no header is sent).
        form = await request.form()
        try:
            _require_csrf(request, form_token=form.get("csrf_token"))
        except ApiError:
            _audit(request, "csrf_failed", result="failed")
            raise
        auth_store = _svc(request).panel_auth
        wants_json = "application/json" in (request.headers.get("accept") or "")
        if not auth_store.configured():
            password = form.get("password") or ""
            errors = validate_password(password, form.get("password_confirm"))
            if errors:
                _audit(request, "panel_setup", result="failed")
                message = (errors.get("password") or errors.get("confirm")
                           or "密码不符合要求。")
                return _login_failure(request, message, setup=True, status=400,
                                      wants_json=wants_json)
            try:
                fingerprint = auth_store.set_password(password, replace=False)
            except PanelAuthError:
                # Another request won the first-run race.
                _audit(request, "panel_setup", result="failed")
                return _login_failure(request, "管理员密码已设置，请直接登录。",
                                      setup=False, status=409,
                                      wants_json=wants_json)
            _audit(request, "panel_setup", token_id=PANEL_SUBJECT_ID)
            return _login_success(request, fingerprint)
        if not auth_store.verify(form.get("password")):
            _audit(request, "panel_login", result="failed")
            return _login_failure(request, "密码不正确。", setup=False,
                                  status=401, wants_json=wants_json)
        _audit(request, "panel_login", token_id=PANEL_SUBJECT_ID)
        return _login_success(request, auth_store.fingerprint() or "")

    @router.post("/api/panel/logout")
    async def panel_logout(request: Request):
        _check_origin(request)
        _require_csrf(request)
        token = _panel_token(request)
        _audit(request, "panel_logout", token_id=token.id if token else None)
        resp = RedirectResponse("/login", status_code=302)
        resp.delete_cookie(PANEL_COOKIE, path="/")
        return resp

    @router.get("/api/panel/password/form")
    async def password_form(request: Request):
        _require_panel(request)
        return _render_password_form(request)

    @router.post("/api/panel/password")
    async def password_change(request: Request):
        _require_panel(request)
        _check_origin(request)
        _rate_limit(request, "panel_login", _client_ip(request))
        form = await request.form()
        try:
            _require_csrf(request, form_token=form.get("csrf_token"))
        except ApiError:
            _audit(request, "csrf_failed", result="failed")
            raise
        auth_store = _svc(request).panel_auth
        if not auth_store.verify(form.get("current_password")):
            _audit(request, "panel_password_changed", token_id=PANEL_SUBJECT_ID,
                   result="failed")
            return _render_password_form(request, error="当前密码不正确。",
                                         status=400)
        errors = validate_password(form.get("password") or "",
                                   form.get("password_confirm"))
        if errors:
            _audit(request, "panel_password_changed", token_id=PANEL_SUBJECT_ID,
                   result="failed")
            return _render_password_form(request, errors=errors, status=400)
        try:
            fingerprint = auth_store.set_password(form.get("password"))
        except PanelAuthError:
            raise ApiError("internal")
        _audit(request, "panel_password_changed", token_id=PANEL_SUBJECT_ID)
        if request.headers.get("hx-request") == "true":
            html = _templates(request).get_template(
                "fragments/password_saved.html").render()
            resp = HTMLResponse(html, headers={"Cache-Control": "no-store"})
        else:
            resp = JSONResponse({"status": "changed"},
                                headers={"Cache-Control": "no-store"})
        resp.set_cookie(PANEL_COOKIE,
                        auth_mod.create_panel_session(_svc(request).secret, fingerprint,
                                                      ttl_hours=int(
                                                          _svc(request).settings.get(
                                                              "panel_session_hours"))),
                        httponly=True, secure=request.url.scheme == "https",
                        samesite="lax",
                        max_age=int(_svc(request).settings.get("panel_session_hours")) * 3600,
                        path="/")
        return resp

    @router.get("/api/panel/settings/form")
    async def settings_form(request: Request):
        _require_panel(request)
        return _render_settings_form(request)

    @router.post("/api/panel/settings")
    async def settings_save(request: Request):
        token = _require_panel(request)
        if token.role != "admin":
            raise ApiError("auth.forbidden")
        _check_origin(request)
        _rate_limit(request, "profile_write", PANEL_SUBJECT_ID)
        form = await request.form()
        try:
            _require_csrf(request, form_token=form.get("csrf_token"))
        except ApiError:
            _audit(request, "csrf_failed", result="failed")
            raise
        svc = _svc(request)
        fields: dict[str, object] = {}
        for name, _label, _hint, _lo, _hi, _step in _SETTINGS_FIELDS:
            raw = form.get(name)
            if raw is None or str(raw).strip() == "":
                continue
            text = str(raw).strip()
            fields[name] = float(text) if "." in text else int(text)
        rate_limits: dict[str, tuple[int, int] | None] | None = {}
        rate_texts: dict[str, str] = {}
        rate_errors: dict[str, str] = {}
        touched = False
        for kind, _label, _default in _RATE_LIMIT_FIELDS:
            action, value, err = parse_rate_limit_form(form.get(f"rate_{kind}"))
            if err:
                rate_errors[f"rate_{kind}"] = ("取值格式为「次数/窗口秒数」，"
                                               "例如 120/60；不限速填 off。")
                continue
            if action == "keep":
                # Field absent or left empty: leave this limit untouched.
                # Writing it would turn a partial submit into a silent
                # reset of every limit (F2).
                continue
            rate_texts[kind] = "off" if action == "off" else f"{value[0]}/{value[1]}"
            rate_limits[kind] = value
            touched = True
        if rate_errors:
            return _render_settings_form(
                request,
                values={k: form.get(k) or "" for k, *_ in _SETTINGS_FIELDS},
                rate_texts={**{k: _rate_limit_text(v)
                               for k, v in svc.settings.rate_limits.items()},
                            **rate_texts},
                errors=rate_errors, status=400)
        errors = svc.settings.update(
            fields if fields else {},
            rate_limits if touched else None)
        if errors:
            return _render_settings_form(
                request,
                values={k: form.get(k) or "" for k, *_ in _SETTINGS_FIELDS},
                errors=errors, status=400)
        # Apply live: limiter table + CLI timeout buckets. Both objects
        # read their dicts on every check/call, so this is instant.
        for kind, value in svc.settings.rate_limits.items():
            svc.limiter.limits[kind] = value
        svc.cli.set_timeouts({
            "read": int(svc.settings.get("cli_read_s")),
            "logs": int(svc.settings.get("cli_logs_s")),
            "action": int(svc.settings.get("cli_action_s")),
            "build": int(svc.settings.get("cli_build_s")),
        })
        _audit(request, "settings_updated", token_id=PANEL_SUBJECT_ID)
        return _render_settings_form(request, saved=True)

    @router.get("/api/profiles")
    async def list_profiles(request: Request):
        token = _require_panel(request)
        profiles = _fresh_profiles(request)
        _drop_stale(request, profiles)
        return {"profiles": _all_row_contexts(request, token),
                "summary": _summary_context(request, token),
                "config_errors": profiles.config_errors}

    @router.get("/api/profiles/rows")
    async def list_rows(request: Request):
        """Rows fragment for HTMX chip filtering (bucket=all|connected|
        pending|error). Server-side filter so the chip state is the
        server's, not a guess in JS."""
        token = _require_panel(request)
        _drop_stale(request)
        bucket = request.query_params.get("bucket", "all")
        rows = [r for r in _all_row_contexts(request, token)
                if bucket == "all" or r["bucket"] == bucket]
        return HTMLResponse(_templates(request).get_template("fragments/rows.html").render(
            rows=rows, empty_bucket=bucket))

    @router.get("/api/profiles/new/form")
    async def new_profile_form(request: Request):
        token = _require_panel(request)
        _require_profile_manager(request, token)
        values = _profile_form_values({}, None)
        return _render_profile_form(request, name=None, values=values)

    @router.get("/api/profiles/{name}/edit/form")
    async def edit_profile_form(request: Request, name: str):
        token = _require_panel(request)
        _require_profile_manager(request, token)
        if not token.allows(name):
            raise ApiError("profile.not_found")
        try:
            raw = _svc(request).profile_store.get_raw(name)
        except ProfileStoreError:
            _audit(request, "profile_edit_form", token_id=token.id, profile=name,
                   result="failed")
            raise ApiError("internal")
        if raw is None:
            raise ApiError("profile.not_found")
        config_error = _fresh_profiles(request).config_errors.get(name)
        values = _profile_form_values(raw, name)
        return _render_profile_form(request, name=name, values=values,
                                    config_error=config_error)

    @router.get("/api/profiles/{name}/drawer")
    async def drawer(request: Request, name: str):
        """Drawer body fragment: per-layer at/latency + identity, rendered
        server-side so the drawer never reads a shared timestamp."""
        token = _require_panel(request)
        # ACL before the config-error branch: an unauthorized caller must
        # not learn that a malformed profile exists or why it is malformed.
        if not token.allows(name):
            _audit(request, "acl_forbidden", token_id=token.id, profile=name, result="failed")
            raise ApiError("profile.not_found")
        profiles = _fresh_profiles(request)
        _drop_stale(request, profiles)
        if name in profiles.config_errors:
            row = _config_error_row_context(request, token, name, profiles.config_errors[name])
        else:
            profile = _visible_profile(request, token, name)
            row = _row_context(request, token, profile)
        return HTMLResponse(_templates(request).get_template("fragments/drawer.html").render(
            row=row, fmt_time=_fmt_time))

    @router.get("/api/topology")
    async def topology(request: Request):
        """FR-36: optional MCP-gateway -> NAS topology view. Read-only,
        ACL-scoped (only profiles the token can see), no editing. Plain
        server-rendered markup; no chart library. Returns a fragment for
        HTMX or JSON for API clients."""
        token = _require_panel(request)
        profiles = _fresh_profiles(request)
        _drop_stale(request, profiles)
        valid, broken = _visible_names(request, token)
        svc = _svc(request)
        nodes = []
        for n in valid:
            profile = profiles.profiles[n]
            entry = svc.state.load()["profiles"].get(n, {})
            if entry and entry.get("target") != profile.target:
                entry = {}
            badge = merge_status(entry.get("network"), entry.get("auth"),
                                 config_error=False)
            nodes.append({"name": n, "target": profile.target,
                          "scheme": profile.scheme, "badge": badge,
                          "identity": (entry.get("auth") or {}).get("identity"),
                          "latency_ms": (entry.get("network") or {}).get("latency_ms")})
        for n in broken:
            nodes.append({"name": n, "target": None, "scheme": None,
                          "badge": "config", "identity": None, "latency_ms": None})
        _audit(request, "topology_view", token_id=token.id)
        if request.headers.get("hx-request") == "true":
            html = _templates(request).get_template("fragments/topology.html").render(
                nodes=nodes, mcp_public_url=(svc.mcp_public_url or ""))
            return HTMLResponse(html, headers={"Cache-Control": "no-store"})
        return {"gateway": {"endpoint": svc.mcp_public_url or ""},
                "nodes": nodes}

    @router.post("/api/profiles/probe-all")
    async def probe_all(request: Request):
        token = _require_panel(request)
        _check_origin(request)
        _require_csrf(request)
        profiles = _fresh_profiles(request)
        visible, _broken = _visible_names(request, token)
        names = [n for n in visible if n in profiles.profiles]
        svc = _svc(request)
        sem = asyncio.Semaphore(int(svc.settings.get("probe_concurrency")))

        async def _one(name: str):
            async with sem:
                profile = profiles.profiles[name]
                try:
                    with probe_lock(svc.data_dir, name):
                        result = await asyncio.to_thread(
                            probe_profile, profile,
                            float(svc.settings.get("probe_timeout_s")), svc.ca_bundle)
                except LockedError:
                    return name, {"status": "busy", "at": now_iso(), "latency_ms": None,
                                  "detail": "这台机器正在测试网络，请稍后再试。"}
                entry = {"at": now_iso(), "status": result.status,
                         "latency_ms": result.latency_ms,
                         "looks_like_fnos": result.looks_like_fnos,
                         "detail": result.detail,
                         "dns_ms": result.dns_ms, "tcp_ms": result.tcp_ms,
                         "tls_ms": result.tls_ms, "http_status": result.http_status}
                svc.state.update(name, profile.target, network=entry)
                return name, entry

        # Own tasks, shielded from wait_for's cancellation: cancelling a
        # coroutine blocked on to_thread would release the probe lock
        # while its thread is still running, letting a second probe
        # overwrite the in-flight result. Shielded tasks keep the lock
        # until they settle (the probe self-deadlines at 5s); the request
        # returns after 10s without waiting for the stragglers.
        tasks = [asyncio.create_task(_one(n)) for n in names]
        for task in tasks:
            # Retrieve exceptions on tasks that outlive this request.
            task.add_done_callback(
                lambda t: None if t.cancelled() else t.exception())
        try:
            results = await asyncio.wait_for(
                asyncio.gather(*[asyncio.shield(t) for t in tasks]),
                timeout=float(svc.settings.get("probe_wait_s")))
        except asyncio.TimeoutError:
            results = [t.result() for t in tasks
                       if t.done() and not t.cancelled() and t.exception() is None]
        _audit(request, "probe_all", token_id=token.id)
        summary = _summary_context(request, token)
        busy = [n for n, r in results if r and r.get("status") == "busy"]
        fragment = _roster_fragment(request, token, busy=busy)
        return _respond(request, 200, fragment,
                        {"results": dict(results), "summary": summary, "busy": busy})

    @router.post("/api/profiles")
    async def create_profile(request: Request):
        token = _require_panel(request)
        _check_origin(request)
        _rate_limit(request, "profile_write", token.id)
        form = await request.form()
        try:
            _require_csrf(request, form_token=form.get("csrf_token"))
        except ApiError:
            _audit(request, "csrf_failed", token_id=token.id, result="failed")
            raise
        _require_profile_manager(request, token)
        name, entry, errors = parse_profile_form(form)
        if errors:
            _audit(request, "profile_created", token_id=token.id,
                   profile=name or None, result="failed")
            return _render_profile_form(
                request, name=None, values=_profile_form_values(form, None),
                errors=errors, status=400)
        try:
            profile = _svc(request).profile_store.create(name, entry)
        except ProfileStoreError as exc:
            _audit(request, "profile_created", token_id=token.id,
                   profile=name or None, result="failed")
            if exc.code in ("profile.exists", "profile.invalid"):
                return _render_profile_form(
                    request, name=None, values=_profile_form_values(form, None),
                    errors=exc.fields, error=exc.message, status=400)
            raise ApiError("internal")
        _drop_stale(request)
        _audit(request, "profile_created", token_id=token.id, profile=profile.name)
        return _profile_saved_response(request, token, profile, created=True)

    @router.post("/api/profiles/{name}/edit")
    async def update_profile(request: Request, name: str):
        token = _require_panel(request)
        if not token.allows(name):
            raise ApiError("profile.not_found")
        _check_origin(request)
        _rate_limit(request, "profile_write", token.id)
        form = await request.form()
        try:
            _require_csrf(request, form_token=form.get("csrf_token"))
        except ApiError:
            _audit(request, "csrf_failed", token_id=token.id, profile=name,
                   result="failed")
            raise
        _require_profile_manager(request, token)
        svc = _svc(request)
        try:
            raw = svc.profile_store.get_raw(name)
        except ProfileStoreError:
            _audit(request, "profile_updated", token_id=token.id, profile=name,
                   result="failed")
            raise ApiError("internal")
        if raw is None:
            raise ApiError("profile.not_found")
        _parsed_name, entry, errors = parse_profile_form(form, name=name)
        config_error = _fresh_profiles(request).config_errors.get(name)
        if errors:
            _audit(request, "profile_updated", token_id=token.id, profile=name,
                   result="failed")
            return _render_profile_form(
                request, name=name, values=_profile_form_values(form, name),
                errors=errors, config_error=config_error, status=400)
        try:
            profile = svc.profile_store.update(name, entry)
        except ProfileStoreError as exc:
            _audit(request, "profile_updated", token_id=token.id, profile=name,
                   result="failed")
            if exc.code == "profile.invalid":
                return _render_profile_form(
                    request, name=name, values=_profile_form_values(form, name),
                    errors=exc.fields, error=exc.message,
                    config_error=config_error, status=400)
            if exc.code == "profile.not_found":
                raise ApiError("profile.not_found")
            raise ApiError("internal")
        _drop_stale(request)
        _audit(request, "profile_updated", token_id=token.id, profile=name)
        return _profile_saved_response(request, token, profile, created=False)

    @router.post("/api/profiles/{name}/delete")
    async def delete_profile(request: Request, name: str):
        """Delete a machine from the panel config (admin only).

        Guards mirror the add/edit routes: panel session + ACL (outside
        the ACL the profile does not exist) + Origin + profile_write
        rate limit + CSRF + manage_profiles capability. Deleting also
        drops the profile's panel-state record and releases a pending
        login lease, so no stale badge or lease survives the removal.
        The HTMX answer is a fresh roster fragment, which renders the
        zero_config empty state when the last machine is gone."""
        token = _require_panel(request)
        if not token.allows(name):
            _audit(request, "acl_forbidden", token_id=token.id, profile=name, result="failed")
            raise ApiError("profile.not_found")
        _check_origin(request)
        _rate_limit(request, "profile_write", token.id)
        form = await request.form()
        try:
            _require_csrf(request, form_token=form.get("csrf_token"))
        except ApiError:
            _audit(request, "csrf_failed", token_id=token.id, profile=name, result="failed")
            raise
        _require_profile_manager(request, token)
        svc = _svc(request)
        try:
            raw = svc.profile_store.get_raw(name)
        except ProfileStoreError:
            _audit(request, "profile_deleted", token_id=token.id, profile=name,
                   result="failed")
            raise ApiError("internal")
        if raw is None:
            raise ApiError("profile.not_found")
        try:
            svc.profile_store.delete(name)
        except ProfileStoreError as exc:
            _audit(request, "profile_deleted", token_id=token.id, profile=name,
                   result="failed")
            if exc.code == "profile.not_found":
                raise ApiError("profile.not_found")
            raise ApiError("internal")
        svc.state.remove(name)
        release_login_lease(svc.data_dir, name)
        _audit(request, "profile_deleted", token_id=token.id, profile=name)
        if request.headers.get("hx-request") == "true":
            return HTMLResponse(_roster_fragment(request, token, deleted=name),
                                headers={"Cache-Control": "no-store"})
        return JSONResponse({"profile": name, "status": "deleted"},
                            headers={"Cache-Control": "no-store"})

    @router.post("/api/profiles/{name}/probe")
    async def probe_one(request: Request, name: str):
        token = _require_panel(request)
        _check_origin(request)
        _require_csrf(request)
        _rate_limit(request, "probe", f"{token.id}:{name}")
        profile = _visible_profile(request, token, name)
        svc = _svc(request)
        try:
            with probe_lock(svc.data_dir, name):
                result = await asyncio.to_thread(
                    probe_profile, profile,
                    float(svc.settings.get("probe_timeout_s")), svc.ca_bundle)
        except LockedError:
            raise ApiError("probe.busy")
        entry = {"at": now_iso(), "status": result.status,
                 "latency_ms": result.latency_ms,
                 "looks_like_fnos": result.looks_like_fnos, "detail": result.detail,
                 "dns_ms": result.dns_ms, "tcp_ms": result.tcp_ms,
                 "tls_ms": result.tls_ms, "http_status": result.http_status}
        svc.state.update(name, profile.target, network=entry)
        _audit(request, "probe", token_id=token.id, profile=name,
               sub_reason=result.sub_reason, latency_ms=result.latency_ms)
        return _respond(request, 200, _row_fragment(request, token, profile),
                        {"profile": name, "network": entry})

    @router.post("/api/profiles/{name}/test")
    async def test_one(request: Request, name: str):
        token = _require_panel(request)
        _check_origin(request)
        _require_csrf(request)
        _rate_limit(request, "test", f"{token.id}:{name}")
        profile = _visible_profile(request, token, name)
        svc = _svc(request)
        try:
            with session_lock(svc.data_dir, name):
                _t0 = time.monotonic()
                try:
                    auth = await asyncio.to_thread(svc.cli.user_info, profile)
                except CliError:
                    _audit(request, "test", token_id=token.id, profile=name, result="failed")
                    raise ApiError("internal")
                auth_ms = int((time.monotonic() - _t0) * 1000)
        except LockedError:
            raise ApiError("session.locked")
        entry = {"at": now_iso(), "status": auth.status, "latency_ms": auth_ms,
                 "identity": auth.identity}
        # FR-37: keep the whitelisted identity facts when the NAS reports
        # them; a stale/absent detail must not survive a new test run.
        detail = getattr(auth, "detail", None)
        if detail:
            entry["detail"] = detail
        svc.state.update(name, profile.target, auth=entry)
        _audit(request, "test", token_id=token.id, profile=name)
        return _respond(request, 200, _row_fragment(request, token, profile),
                        {"profile": name, "auth": entry})

    @router.post("/api/profiles/{name}/login/start")
    async def login_start(request: Request, name: str):
        token = _require_panel(request)
        _check_origin(request)
        _require_csrf(request)
        _rate_limit(request, "login_start", f"{token.id}:{name}")
        if not token.can_manage_login:
            _audit(request, "acl_forbidden", token_id=token.id, profile=name, result="failed")
            raise ApiError("auth.forbidden")
        profile = _visible_profile(request, token, name)
        svc = _svc(request)
        try:
            with session_lock(svc.data_dir, name):
                if not acquire_login_lease(svc.data_dir, name):
                    raise ApiError("session.locked")
                try:
                    url = await asyncio.to_thread(svc.cli.login_start, profile)
                except Exception:
                    # The CLI failed before returning a URL: release the
                    # lease so the user can retry immediately, and map the
                    # failure to the stable error contract.
                    release_login_lease(svc.data_dir, name)
                    _audit(request, "login_failed", token_id=token.id,
                           profile=name, result="failed")
                    raise ApiError("login.failed")
        except LockedError:
            raise ApiError("session.locked")
        headers = {"Cache-Control": "no-store"}
        try:
            reason = auth_mod.validate_authorization_url(url, profile)
            if reason:
                release_login_lease(svc.data_dir, name)
                _audit(request, "login_failed", token_id=token.id, profile=name, result="failed")
                # Rejected URL is NEVER rendered: no link, no URL text, only
                # the Chinese reason (FR-21). The fragment carries role=alert.
                fragment = _templates(request).get_template(
                    "fragments/login_rejected.html").render(reason=reason, profile=profile)
                return _respond(request, 400, fragment,
                                {"error": {"code": "login.failed",
                                           "message": f"授权链接被拒绝：{reason}",
                                           "profile": name, "retryable": True, "details": {}}},
                                headers=headers)
            _audit(request, "login_started", token_id=token.id, profile=name)
            fragment = _templates(request).get_template("fragments/login_step1.html").render(
                profile=profile, url=url, csrf_token=request.cookies.get(CSRF_COOKIE, ""))
            return _respond(request, 200, fragment,
                            {"profile": name, "authorization_url": url}, headers=headers)
        except Exception:
            # Never leave a lease behind if rendering the first step fails.
            release_login_lease(svc.data_dir, name)
            raise

    @router.post("/api/profiles/{name}/login/finish")
    async def login_finish(request: Request, name: str):
        token = _require_panel(request)
        _check_origin(request)
        _require_csrf(request)
        _rate_limit(request, "login_finish", f"{token.id}:{name}")
        if not token.can_manage_login:
            raise ApiError("auth.forbidden")
        profile = _visible_profile(request, token, name)
        svc = _svc(request)
        form = await request.form()
        code = (form.get("code") or "").strip()
        if not code:
            raise ApiError("login.code_invalid")
        acquired = False
        auth_ms = 0
        try:
            with session_lock(svc.data_dir, name):
                acquired = True
                try:
                    await asyncio.to_thread(svc.cli.login_finish, profile, code)
                except LoginCodeExpired:
                    _audit(request, "login_failed", token_id=token.id, profile=name, result="failed")
                    raise ApiError("login.code_expired")
                except LoginCodeInvalid:
                    _audit(request, "login_failed", token_id=token.id, profile=name, result="failed")
                    raise ApiError("login.code_invalid")
                except CliError:
                    # Timeout / CLI failure: not an invalid code.
                    _audit(request, "login_failed", token_id=token.id, profile=name, result="failed")
                    raise ApiError("login.failed")
                _t0 = time.monotonic()
                try:
                    auth = await asyncio.to_thread(svc.cli.user_info, profile)
                except CliError:
                    _audit(request, "login_failed", token_id=token.id, profile=name, result="failed")
                    raise ApiError("login.failed")
                auth_ms = int((time.monotonic() - _t0) * 1000)
                if auth.status != "ok":
                    _audit(request, "login_failed", token_id=token.id, profile=name, result="failed")
                    raise ApiError("login.failed")
                auth_entry = {"at": now_iso(), "status": "ok", "latency_ms": auth_ms,
                              "identity": auth.identity}
                detail = getattr(auth, "detail", None)
                if detail:
                    auth_entry["detail"] = detail
                svc.state.update(name, profile.target,
                                 network={"at": now_iso(), "status": "ok", "latency_ms": 0,
                                          "looks_like_fnos": True},
                                 auth=auth_entry)
        except LockedError:
            raise ApiError("session.locked")
        finally:
            # Only release the lease we (or an earlier start of this same
            # login) created when this request actually held the lock.
            if acquired:
                release_login_lease(svc.data_dir, name)
        _audit(request, "login_finished", token_id=token.id, profile=name)
        # HX: the form lives in the modal, so the swap target is the
        # whole rows list (hx-target="#rows"); JSON keeps the old shape.
        return _respond(request, 200, _rows_fragment(request, token),
                        {"profile": name, "status": "connected", "identity": auth.identity})

    @router.post("/api/profiles/{name}/logout")
    async def profile_logout(request: Request, name: str):
        token = _require_panel(request)
        _check_origin(request)
        _require_csrf(request)
        if not token.can_manage_login:
            raise ApiError("auth.forbidden")
        profile = _visible_profile(request, token, name)
        svc = _svc(request)
        try:
            with session_lock(svc.data_dir, name):
                try:
                    await asyncio.to_thread(svc.cli.logout, profile)
                except CliError:
                    _audit(request, "logout", token_id=token.id, profile=name, result="failed")
                    raise ApiError("logout.failed")
        except LockedError:
            raise ApiError("session.locked")
        svc.state.update(name, profile.target,
                         auth={"at": now_iso(), "status": "logged_out", "latency_ms": 0,
                               "identity": None})
        release_login_lease(svc.data_dir, name)
        _audit(request, "logout", token_id=token.id, profile=name)
        return _respond(request, 200, _rows_fragment(request, token),
                        {"profile": name, "status": "logged_out"})

    # -------------------------------------------------- agent keys (ACL)
    # The panel is password-admin only; every route below mirrors the
    # profile-write guards: session + Origin + rate limit + CSRF. The
    # plaintext key appears in exactly one response (create / rotate).
    @router.get("/api/tokens")
    async def list_tokens(request: Request):
        _require_panel(request)
        if request.headers.get("hx-request") == "true":
            return HTMLResponse(_token_rows_fragment(request),
                                headers={"Cache-Control": "no-store"})
        return JSONResponse(_token_list_context(request),
                            headers={"Cache-Control": "no-store"})

    @router.get("/api/tokens/new/form")
    async def new_token_form(request: Request):
        _require_panel(request)
        return _render_token_form(
            request, key_id=None,
            values={"name": "", "role": "operator", "capabilities": [],
                    "scope_all": False, "profiles": []})

    @router.post("/api/tokens")
    async def create_token(request: Request):
        _require_panel(request)
        _check_origin(request)
        _rate_limit(request, "token_write", PANEL_SUBJECT_ID)
        form = await request.form()
        try:
            _require_csrf(request, form_token=form.get("csrf_token"))
        except ApiError:
            _audit(request, "csrf_failed", result="failed")
            raise
        values = _token_values_from_form(form)
        profiles = ["*"] if values["scope_all"] else values["profiles"]
        try:
            entry, plaintext = _svc(request).token_store.create(
                values["name"], profiles, values["role"],
                values["capabilities"])
        except TokenStoreError as exc:
            _audit(request, "token_created", token_id=PANEL_SUBJECT_ID,
                   result="failed")
            if exc.code in ("token.invalid", "token.limit"):
                return _render_token_form(request, key_id=None, values=values,
                                          errors=exc.fields, error=exc.message,
                                          status=400)
            raise ApiError("internal")
        _audit(request, "token_created", token_id=PANEL_SUBJECT_ID,
               key_id=entry["id"])
        return _token_secret_response(request, entry, plaintext, rotated=False)

    @router.get("/api/tokens/{key_id}/edit/form")
    async def edit_token_form(request: Request, key_id: str):
        _require_panel(request)
        try:
            entry = _svc(request).token_store.get(key_id)
        except TokenStoreError:
            raise ApiError("internal")
        if entry is None:
            raise ApiError("token.not_found")
        return _render_token_form(request, key_id=key_id,
                                  values=_token_values_from_entry(entry))

    @router.post("/api/tokens/{key_id}/edit")
    async def update_token(request: Request, key_id: str):
        _require_panel(request)
        _check_origin(request)
        _rate_limit(request, "token_write", PANEL_SUBJECT_ID)
        form = await request.form()
        try:
            _require_csrf(request, form_token=form.get("csrf_token"))
        except ApiError:
            _audit(request, "csrf_failed", result="failed")
            raise
        values = _token_values_from_form(form)
        profiles = ["*"] if values["scope_all"] else values["profiles"]
        try:
            entry = _svc(request).token_store.update(
                key_id, values["name"], profiles, values["role"],
                values["capabilities"])
        except TokenStoreError as exc:
            _audit(request, "token_updated", token_id=PANEL_SUBJECT_ID,
                   key_id=key_id, result="failed")
            if exc.code == "token.not_found":
                raise ApiError("token.not_found")
            if exc.code == "token.invalid":
                return _render_token_form(request, key_id=key_id, values=values,
                                          errors=exc.fields, error=exc.message,
                                          status=400)
            raise ApiError("internal")
        _audit(request, "token_updated", token_id=PANEL_SUBJECT_ID, key_id=key_id)
        return _token_saved_response(request, entry)

    @router.post("/api/tokens/{key_id}/rotate")
    async def rotate_token(request: Request, key_id: str):
        _require_panel(request)
        _check_origin(request)
        _rate_limit(request, "token_write", PANEL_SUBJECT_ID)
        form = await request.form()
        try:
            _require_csrf(request, form_token=form.get("csrf_token"))
        except ApiError:
            _audit(request, "csrf_failed", result="failed")
            raise
        try:
            entry, plaintext = _svc(request).token_store.rotate(key_id)
        except TokenStoreError as exc:
            _audit(request, "token_rotated", token_id=PANEL_SUBJECT_ID,
                   key_id=key_id, result="failed")
            if exc.code == "token.not_found":
                raise ApiError("token.not_found")
            raise ApiError("internal")
        _audit(request, "token_rotated", token_id=PANEL_SUBJECT_ID, key_id=key_id)
        return _token_secret_response(request, entry, plaintext, rotated=True)

    @router.get("/api/tokens/{key_id}/secret")
    async def token_secret(request: Request, key_id: str):
        """Return the decrypted key and MCP JSON for the list-page copy
        buttons. Only an authenticated panel admin can read it; the
        response is never cached and never contains other entries."""
        _require_panel(request)
        _rate_limit(request, "token_secret", PANEL_SUBJECT_ID)
        try:
            _entry, plaintext = _svc(request).token_store.secret_for(key_id)
        except TokenStoreError as exc:
            if exc.code == "token.not_found":
                raise ApiError("token.not_found")
            raise ApiError("internal")
        if plaintext is None:
            raise ApiError("token.unavailable")
        mcp_url, config = _client_config(request, plaintext)
        _audit(request, "token_secret_read", token_id=PANEL_SUBJECT_ID,
               key_id=key_id)
        return JSONResponse({"key": plaintext, "config": config,
                             "mcp_url": mcp_url},
                            headers={"Cache-Control": "no-store"})

    @router.post("/api/tokens/{key_id}/delete")
    async def delete_token(request: Request, key_id: str):
        _require_panel(request)
        _check_origin(request)
        _rate_limit(request, "token_write", PANEL_SUBJECT_ID)
        form = await request.form()
        try:
            _require_csrf(request, form_token=form.get("csrf_token"))
        except ApiError:
            _audit(request, "csrf_failed", result="failed")
            raise
        try:
            entry = _svc(request).token_store.delete(key_id)
        except TokenStoreError as exc:
            _audit(request, "token_deleted", token_id=PANEL_SUBJECT_ID,
                   key_id=key_id, result="failed")
            if exc.code == "token.not_found":
                raise ApiError("token.not_found")
            raise ApiError("internal")
        _audit(request, "token_deleted", token_id=PANEL_SUBJECT_ID,
               key_id=entry["id"])
        if request.headers.get("hx-request") == "true":
            return HTMLResponse(_token_rows_fragment(request),
                                headers={"Cache-Control": "no-store"})
        return JSONResponse({"token": entry["id"], "status": "deleted"},
                            headers={"Cache-Control": "no-store"})

    return router
