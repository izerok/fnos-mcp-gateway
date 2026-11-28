import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


from fnos_mcp.config import Profile
from fnos_mcp.probe import probe_profile


def _serve(handler_cls):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


class FnosHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"<html><head><title>fnOS</title></head><body>fnOS</body></html>"
        self.send_response(200)
        self.send_header("Server", "fnOS/1.2")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class PlainHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"hello"
        self.send_response(200)
        self.send_header("Server", "nginx")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class NotFoundHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


def _profile(port, scheme="http", **kw):
    return Profile(name="t", host="127.0.0.1", port=port, scheme=scheme, **kw)


def test_probe_ok_fnos_fingerprint():
    server = _serve(FnosHandler)
    try:
        result = probe_profile(_profile(server.server_address[1]))
    finally:
        server.shutdown()
    assert result.status == "ok"
    assert result.looks_like_fnos is True
    assert result.http_status == 200
    assert result.latency_ms < 5000


def test_probe_ok_not_fnos():
    server = _serve(PlainHandler)
    try:
        result = probe_profile(_profile(server.server_address[1]))
    finally:
        server.shutdown()
    assert result.status == "ok"
    assert result.looks_like_fnos is False


def test_probe_http_failed_on_404():
    server = _serve(NotFoundHandler)
    try:
        result = probe_profile(_profile(server.server_address[1]))
    finally:
        server.shutdown()
    assert result.status == "http_failed"
    assert result.sub_reason == "http"


def test_probe_refused_closed_port():
    result = probe_profile(_profile(59998))
    assert result.status == "refused"
    assert result.sub_reason == "refused"


def test_probe_dns_failed(monkeypatch):
    # NOTE: this sandbox's resolver answers wildcard IPs for any name, so
    # a real NXDOMAIN cannot be reproduced here; force the resolver error.
    import socket as _socket
    def _fail(*args, **kwargs):
        raise _socket.gaierror("Name or service not known")

    monkeypatch.setattr(_socket, "getaddrinfo", _fail)
    profile = Profile(name="t", host="nonexistent.invalid", port=5667, scheme="https")
    result = probe_profile(profile)
    assert result.status == "dns_failed"
    assert result.sub_reason == "dns"


def test_probe_tls_failed_https_against_plain_http():
    server = _serve(PlainHandler)
    try:
        result = probe_profile(_profile(server.server_address[1], scheme="https"))
    finally:
        server.shutdown()
    assert result.status == "tls_failed"
