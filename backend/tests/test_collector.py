import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

import httpx
import pytest

from app.core.target_policy import TargetPolicyError
from app.scanner.client import SafeHttpCollector


def test_pins_ip_preserves_host_and_tls_sni():
    observed = []
    real_client = httpx.Client

    def handler(request):
        observed.append(request)
        return httpx.Response(200, headers={"Content-Type": "text/html"})

    def client_factory(**kwargs):
        assert kwargs["trust_env"] is False
        assert kwargs["follow_redirects"] is False
        assert kwargs["verify"] is True
        return real_client(transport=httpx.MockTransport(handler), **kwargs)

    answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.7", 443))]
    with (
        patch("socket.getaddrinfo", return_value=answers) as dns,
        patch("app.scanner.client.httpx.Client", side_effect=client_factory),
    ):
        response = SafeHttpCollector().fetch("https://clinic.test:8443/api?token=secret")
    assert dns.call_count == 1
    assert observed[0].url.host == "10.0.0.7"
    assert observed[0].headers["host"] == "clinic.test:8443"
    assert observed[0].extensions["sni_hostname"] == "clinic.test"
    assert "secret" not in response.endpoint


def test_collector_captures_tls_metadata_when_transport_exposes_it():
    class FakeSslObject:
        def version(self):
            return "TLSv1.3"

        def cipher(self):
            return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

    class FakeNetworkStream:
        def get_extra_info(self, name):
            return FakeSslObject() if name == "ssl_object" else None

    real_client = httpx.Client

    def handler(_request):
        return httpx.Response(
            200,
            extensions={"network_stream": FakeNetworkStream()},
        )

    def client_factory(**kwargs):
        return real_client(transport=httpx.MockTransport(handler), **kwargs)

    answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.7", 443))]
    with (
        patch("socket.getaddrinfo", return_value=answers),
        patch("app.scanner.client.httpx.Client", side_effect=client_factory),
    ):
        response = SafeHttpCollector().fetch("https://clinic.test/")
    assert response.tls_version == "TLSv1.3"
    assert response.tls_cipher == "TLS_AES_256_GCM_SHA384"


def test_revalidation_blocks_dns_rebinding_before_connection():
    with (
        patch(
            "socket.getaddrinfo",
            return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 80))],
        ),
        patch("app.scanner.client.httpx.Client") as client,
    ):
        with pytest.raises(TargetPolicyError):
            SafeHttpCollector().fetch("http://clinic.test")
        client.assert_not_called()


def test_collector_rejects_mutating_methods():
    collector = SafeHttpCollector()
    with patch.object(collector, "request", wraps=collector.request):
        with pytest.raises(ValueError):
            collector.request("http://127.0.0.1:8765", "POST")


def test_collector_allows_options_without_following_redirects():
    observed = []
    real_client = httpx.Client

    def handler(request):
        observed.append(request)
        return httpx.Response(204, headers={"Allow": "GET, OPTIONS"})

    def client_factory(**kwargs):
        return real_client(transport=httpx.MockTransport(handler), **kwargs)

    answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))]
    with (
        patch("socket.getaddrinfo", return_value=answers),
        patch("app.scanner.client.httpx.Client", side_effect=client_factory),
    ):
        response = SafeHttpCollector().request(
            "http://localhost/",
            "OPTIONS",
            extra_headers={"Authorization": "Bearer temporary", "Host": "attacker.invalid"},
        )

    assert response.status_code == 204
    assert observed[0].method == "OPTIONS"
    assert observed[0].headers["authorization"] == "Bearer temporary"
    assert observed[0].headers["host"] == "localhost"


def test_collector_keeps_bounded_error_body_in_memory_but_sanitizes_endpoint():
    real_client = httpx.Client

    def handler(_request):
        return httpx.Response(
            500,
            headers={"Content-Type": "text/html", "Content-Length": "16"},
            content=b"SQL syntax error",
        )

    def client_factory(**kwargs):
        return real_client(transport=httpx.MockTransport(handler), **kwargs)

    with patch("app.scanner.client.httpx.Client", side_effect=client_factory):
        response = SafeHttpCollector().fetch("http://127.0.0.1:8765/item?id=private-marker")

    assert response.status_code == 500
    assert response.body == b"SQL syntax error"
    assert response.endpoint == "http://127.0.0.1:8765/item"


def test_real_http_redirect_not_followed_and_body_not_consumed():
    paths = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            paths.append(self.path)
            self.send_response(302)
            self.send_header("Location", "http://8.8.8.8/private")
            self.send_header("Content-Length", "100000000")
            self.end_headers()
            # No body is sent: collector must return on headers rather than wait for it.

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        response = SafeHttpCollector().fetch(f"http://127.0.0.1:{server.server_port}/")
        assert response.status_code == 302
        assert paths == ["/"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
