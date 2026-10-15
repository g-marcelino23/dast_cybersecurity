"""Generic local fixture for end-to-end Safe Active demonstrations.

This server is deliberately vulnerable. Run it only on loopback and never expose it
to a network. It contains no real data and records request-method counters only.
"""

import json
import threading
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

LAB_HOST = "127.0.0.1"
LAB_PORT = 8775
REQUEST_COUNTS: Counter[str] = Counter()
REQUEST_LOCK = threading.Lock()


def record(method: str) -> None:
    with REQUEST_LOCK:
        REQUEST_COUNTS[method] += 1


class SafeActiveLabHandler(BaseHTTPRequestHandler):
    server_version = "DAST-Safe-Active-Lab/1.0"

    def _send(
        self,
        status: int,
        body: bytes = b"",
        *,
        content_type: str = "text/html; charset=utf-8",
        headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_OPTIONS(self) -> None:
        record("OPTIONS")
        self._send(204, headers={"Allow": "GET, HEAD, OPTIONS, PUT, DELETE"})

    def do_HEAD(self) -> None:
        record("HEAD")
        self._send(200)

    def do_GET(self) -> None:
        record("GET")
        parsed = urlsplit(self.path)
        values = parse_qs(parsed.query, keep_blank_values=True)
        if parsed.path == "/":
            body = b"""<!doctype html><html lang="pt-BR"><head>
              <meta charset="utf-8"><title>DAST Safe Active Lab</title></head><body>
              <h1>Laboratorio local Safe Active</h1>
              <p>Dados inteiramente sinteticos para validacao autorizada.</p>
              <a href="/search?q=hello">Busca</a>
              <a href="/redirect?next=/safe">Redirect</a>
              <a href="/item?id=1">Item</a>
              <a href="/download?file=guide.txt">Download</a>
              </body></html>"""
            self._send(200, body)
            return
        if parsed.path == "/search":
            query = values.get("q", [""])[0]
            self._send(200, f"<html><p>{query}</p></html>".encode())
            return
        if parsed.path == "/redirect":
            destination = values.get("next", ["/safe"])[0]
            self._send(302, headers={"Location": destination})
            return
        if parsed.path == "/safe":
            self._send(200, b"<html><p>Destino local seguro.</p></html>")
            return
        if parsed.path == "/item":
            item_id = values.get("id", [""])[0]
            if item_id.endswith("'"):
                self._send(500, b"<html>syntax error at or near user input</html>")
            else:
                self._send(200, b'<html>{"item":"synthetic"}</html>')
            return
        if parsed.path == "/download":
            filename = unquote(values.get("file", [""])[0])
            if "../" in filename:
                self._send(200, b"<html>root:x:0:0:root:/root:/bin/bash</html>")
            else:
                self._send(200, b"<html>synthetic guide</html>")
            return
        if parsed.path == "/__metrics":
            with REQUEST_LOCK:
                document = {"request_methods": dict(sorted(REQUEST_COUNTS.items()))}
            self._send(
                200,
                json.dumps(document).encode(),
                content_type="application/json",
            )
            return
        self._send(404, b"<html>not found</html>")

    def _reject_mutation(self) -> None:
        record(self.command)
        self._send(405, b"<html>mutating methods are disabled</html>")

    do_POST = _reject_mutation
    do_PUT = _reject_mutation
    do_PATCH = _reject_mutation
    do_DELETE = _reject_mutation

    def log_message(self, format: str, *args: object) -> None:
        print(f"[SAFE-ACTIVE-LAB] {format % args}")


def main() -> None:
    server = ThreadingHTTPServer((LAB_HOST, LAB_PORT), SafeActiveLabHandler)
    print(
        f"Deliberately vulnerable local lab: http://{LAB_HOST}:{LAB_PORT} "
        "(Ctrl+C to stop)"
    )
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
