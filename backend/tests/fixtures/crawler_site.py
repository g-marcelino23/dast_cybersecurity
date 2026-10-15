import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class FixtureState:
    submitted_forms = 0


@contextmanager
def crawler_site(static_resources: int = 0) -> Iterator[tuple[str, str, FixtureState]]:
    state = FixtureState()
    state.submitted_forms = 0
    allowed_origin = [""]

    class ApiHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if not self.path.startswith("/api/"):
                self.send_error(404)
                return
            body = json.dumps({"ok": True, "data": "synthetic"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", allowed_origin[0])
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:
            state.submitted_forms += 1
            self.send_error(405)

        def log_message(self, _format: str, *_args: object) -> None:
            pass

    api = ThreadingHTTPServer(("127.0.0.1", 0), ApiHandler)
    api_port = api.server_port

    class WebHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            path = self.path.split("?", maxsplit=1)[0]
            if path.startswith("/assets/module-") and path.endswith(".js"):
                body = b"export const fixture = true"
                self.send_response(200)
                self.send_header("Content-Type", "text/javascript")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            api_paths = {"/": "/api/root", "/one": "/api/one", "/two": "/api/two"}
            if path not in api_paths:
                self.send_error(404)
                return
            static_tags = "".join(
                f'<script type="module" src="/assets/module-{index}.js"></script>'
                for index in range(static_resources)
            )
            body = f"""<!doctype html><html><body>
              <a href="/">Root</a><a href="/one/#fragment">One</a>
              <a href="/two?record=42">Two</a><a href="https://8.8.8.8/external">External</a>
              <form action="http://127.0.0.1:{api_port}/auth/login" method="post">
                <input name="email" type="email" value="must-not-be-collected">
                <input name="senha" type="password" value="secret">
              </form>
              <script>fetch('http://127.0.0.1:{api_port}{api_paths[path]}?token=secret')</script>
              {static_tags}
            </body></html>""".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            pass

    web = ThreadingHTTPServer(("127.0.0.1", 0), WebHandler)
    allowed_origin[0] = f"http://127.0.0.1:{web.server_port}"
    api_thread = threading.Thread(target=api.serve_forever, daemon=True)
    web_thread = threading.Thread(target=web.serve_forever, daemon=True)
    api_thread.start()
    web_thread.start()
    try:
        yield (
            f"http://127.0.0.1:{web.server_port}",
            f"http://127.0.0.1:{api.server_port}",
            state,
        )
    finally:
        web.shutdown()
        api.shutdown()
        web.server_close()
        api.server_close()
        web_thread.join(timeout=2)
        api_thread.join(timeout=2)
