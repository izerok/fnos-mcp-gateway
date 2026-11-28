"""Network probe: DNS / TCP / TLS / HTTP (需求文档 FR-14, 实施计划 §11.3).

Pure Python (socket/ssl/http.client). Never carries a token, never calls
the CLI, never follows redirects, never accepts a caller-supplied host:
the target always comes from profiles.json. Total deadline 5 seconds,
DNS included. 3xx counts as HTTP reachable; 4xx/5xx is http_failed.
fnOS fingerprint: only the Server header / page title, stored as a bool.
"""

from __future__ import annotations

import http.client
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

MAX_BODY_BYTES = 64 * 1024
PROBE_DEADLINE = 5.0


@dataclass
class ProbeResult:
    status: str  # ok | dns_failed | refused | timeout | tls_failed | http_failed
    sub_reason: str
    latency_ms: int
    looks_like_fnos: bool
    dns_ms: int | None = None
    tcp_ms: int | None = None
    tls_ms: int | None = None  # elapsed at end of the TLS handshake (https only)
    http_status: int | None = None
    detail: str = ""


def _remaining(deadline: float) -> float:
    return max(0.05, deadline - time.monotonic())


def _resolve_addrinfo(host: str, port: int, deadline: float):
    """getaddrinfo with a hard timeout so probe_profile returns on time even
    when resolution hangs. A running resolver thread cannot be cancelled;
    it is abandoned and exits on its own (the executor is shut down
    without waiting)."""
    executor = ThreadPoolExecutor(max_workers=1)
    try:
        future = executor.submit(socket.getaddrinfo, host, port,
                                 socket.AF_UNSPEC, socket.SOCK_STREAM)
        return future.result(timeout=_remaining(deadline))
    finally:
        # shutdown(wait=False) returns immediately; the worker thread is
        # killed at interpreter exit via the interpreter's atexit hook on
        # the executor's threads (they are non-daemon only while a future
        # is pending — cancel_futures drops it first).
        executor.shutdown(wait=False, cancel_futures=True)


def probe_profile(profile, timeout: float = PROBE_DEADLINE,
                  ca_bundle: str | None = None) -> ProbeResult:
    start = time.monotonic()
    deadline = start + timeout
    host, port, scheme = profile.host, profile.port, profile.scheme
    t0 = time.monotonic()
    try:
        addrinfo = _resolve_addrinfo(host, port, deadline)
        if not addrinfo:
            raise socket.gaierror("no address")
    except Exception:
        return ProbeResult("dns_failed", "dns", int((time.monotonic() - start) * 1000),
                           False, detail="域名解析失败。")
    dns_ms = int((time.monotonic() - t0) * 1000)

    family, socktype, proto, _, sockaddr = addrinfo[0]
    sock = socket.socket(family, socktype, proto)
    try:
        sock.settimeout(_remaining(deadline))
        sock.connect(sockaddr)
    except ConnectionRefusedError:
        sock.close()
        return ProbeResult("refused", "refused", int((time.monotonic() - start) * 1000),
                           False, dns_ms=dns_ms, detail="连接被拒绝。")
    except (socket.timeout, TimeoutError, OSError):
        sock.close()
        return ProbeResult("timeout", "timeout", int((time.monotonic() - start) * 1000),
                           False, dns_ms=dns_ms, detail="连接超时。")
    tcp_ms = int((time.monotonic() - t0) * 1000)

    conn: http.client.HTTPConnection | http.client.HTTPSConnection
    if scheme == "https":
        context = ssl._create_unverified_context() if profile.tls_insecure else ssl.create_default_context()
        if ca_bundle and not profile.tls_insecure:
            try:
                context.load_verify_locations(cafile=ca_bundle)
            except OSError:
                pass
        try:
            sock = context.wrap_socket(sock, server_hostname=host)
        except ssl.SSLError:
            sock.close()
            return ProbeResult("tls_failed", "tls", int((time.monotonic() - start) * 1000),
                               False, dns_ms=dns_ms, tcp_ms=tcp_ms,
                               tls_ms=int((time.monotonic() - t0) * 1000),
                               detail="证书校验或 TLS 握手失败。")
        except (socket.timeout, TimeoutError, OSError):
            sock.close()
            return ProbeResult("timeout", "timeout", int((time.monotonic() - start) * 1000),
                               False, dns_ms=dns_ms, tcp_ms=tcp_ms, detail="连接超时。")
        conn = http.client.HTTPSConnection(host, port, timeout=_remaining(deadline))
        conn.sock = sock  # type: ignore[attr-defined]
        tls_ms = int((time.monotonic() - t0) * 1000)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=_remaining(deadline))
        conn.sock = sock  # type: ignore[attr-defined]
        tls_ms = None
    try:
        conn.request("GET", "/", headers={"User-Agent": "fnos-mcp-probe/0.1"})
        resp = conn.getresponse()
        body = resp.read(MAX_BODY_BYTES + 1)[:MAX_BODY_BYTES]
        server = (resp.getheader("Server") or "")
        looks = "fnos" in server.lower() or b"fnos" in body.lower() or "fnOS" in body.decode("utf-8", "replace")
        latency = int((time.monotonic() - start) * 1000)
        if 200 <= resp.status < 400:
            return ProbeResult("ok", "ok", latency, bool(looks),
                               dns_ms=dns_ms, tcp_ms=tcp_ms, tls_ms=tls_ms,
                               http_status=resp.status,
                               detail=f"HTTP {resp.status}。")
        return ProbeResult("http_failed", "http", latency, bool(looks),
                           dns_ms=dns_ms, tcp_ms=tcp_ms, tls_ms=tls_ms,
                           http_status=resp.status,
                           detail=f"目标返回了异常 HTTP 状态 {resp.status}。")
    except (socket.timeout, TimeoutError):
        return ProbeResult("timeout", "timeout", int((time.monotonic() - start) * 1000),
                           False, dns_ms=dns_ms, tcp_ms=tcp_ms, detail="连接超时。")
    except ssl.SSLError:
        return ProbeResult("tls_failed", "tls", int((time.monotonic() - start) * 1000),
                           False, dns_ms=dns_ms, tcp_ms=tcp_ms, detail="证书校验或 TLS 握手失败。")
    except OSError:
        return ProbeResult("timeout", "timeout", int((time.monotonic() - start) * 1000),
                           False, dns_ms=dns_ms, tcp_ms=tcp_ms, detail="连接超时。")
    finally:
        try:
            conn.close()
        except Exception:
            pass
