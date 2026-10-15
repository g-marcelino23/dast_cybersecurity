"""Synthetic multi-role web application for authorized local DAST demonstrations."""

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

WEB_PORT = 8765
API_PORT = 8766
USERS = {
    "viewer.a@fixture.invalid": ("FixtureViewerA!", "VIEWER", "user-a"),
    "viewer.b@fixture.invalid": ("FixtureViewerB!", "VIEWER", "user-b"),
    "manager.a@fixture.invalid": ("FixtureManagerA!", "MANAGER", "manager-a"),
    "support.a@fixture.invalid": ("FixtureSupportA!", "SUPPORT", "support-a"),
}


def page(title: str) -> bytes:
    return f"""<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><title>{title}</title></head>
<body>
  <nav><a href="/">Início</a><a href="/portal">Portal</a></nav>
  <h1>{title}</h1>
  <form action="http://localhost:{API_PORT}/auth/login" method="post">
    <input name="username" type="email"><input name="password" type="password">
    <button type="submit">Entrar</button>
  </form>
  <script>
    fetch('http://localhost:{API_PORT}/api/me').then(item => item.json()).then(me => {{
      const requests = [fetch('http://localhost:{API_PORT}/api/me')];
      if (me.profile.role === 'VIEWER') {{
        const id = me.profile.id.replace('user-', '');
        requests.push(fetch(`http://localhost:{API_PORT}/api/users/${{id}}/profile`));
        requests.push(fetch(`http://localhost:{API_PORT}/api/users/${{id}}/projects`));
        requests.push(fetch(`http://localhost:{API_PORT}/api/users/${{id}}/documents`));
        requests.push(fetch(`http://localhost:{API_PORT}/api/users/${{id}}/private-notes`));
      }}
      if (me.profile.role === 'MANAGER')
        requests.push(fetch('http://localhost:{API_PORT}/api/manager/dashboard'));
      return Promise.all(requests);
    }}).then(() => document.body.dataset.loaded = 'true');
  </script>
</body></html>""".encode()


class WebHandler(BaseHTTPRequestHandler):
    server_version = "DAST-Crawler-Lab/1.0"

    def do_GET(self) -> None:
        path = self.path.split("?", maxsplit=1)[0]
        if path not in {"/", "/portal"}:
            self.send_error(404)
            return
        body = page("Aplicação sintética multi-role")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if path == "/":
            self.send_header("Set-Cookie", "session=public-synthetic-marker; Path=/")
            self.send_header("X-Powered-By", "DAST-Fixture")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        print(f"[WEB] {format % args}")


class ApiHandler(BaseHTTPRequestHandler):
    server_version = "DAST-API-Lab/1.0"

    def _cors(self) -> None:
        self.send_header("Access-Control-Allow-Origin", f"http://localhost:{WEB_PORT}")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

    def _json(self, status: int, document: object) -> None:
        body = json.dumps(document, ensure_ascii=False).encode()
        self.send_response(status)
        self._cors()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_POST(self) -> None:
        if self.path != "/auth/login":
            self.send_error(404)
            return
        size = int(self.headers.get("Content-Length", "0"))
        try:
            payload = json.loads(self.rfile.read(size))
        except json.JSONDecodeError:
            payload = {}
        username = payload.get("username") if isinstance(payload, dict) else None
        password = payload.get("password") if isinstance(payload, dict) else None
        account = USERS.get(username) if isinstance(username, str) else None
        if account is None or password != account[0]:
            self._json(401, {"authenticated": False})
            return
        self._json(200, {"session": {"access_token": f"fixture-token-{account[2]}"}})

    def do_GET(self) -> None:
        authorization = self.headers.get("Authorization", "")
        subject = next(
            (
                (username, account)
                for username, account in USERS.items()
                if authorization == f"Bearer fixture-token-{account[2]}"
            ),
            None,
        )
        if subject is None:
            self._json(401, {"authenticated": False})
            return
        username, (_password, role, user_id) = subject
        path = self.path.split("?", maxsplit=1)[0]
        if path == "/api/me":
            self._json(200, {"profile": {"id": user_id, "role": role, "email": username}})
            return
        if path == "/api/manager/dashboard":
            if role != "MANAGER":
                self._json(403, {"authorized": False})
                return
            self._json(200, {"dashboard": {"projects": [], "role": "MANAGER"}})
            return
        match = re.fullmatch(
            r"/api/users/([ab])/(profile|projects|documents|private-notes)", path
        )
        if match is None:
            self.send_error(404)
            return
        account_id, resource = match.groups()
        owner_id = f"user-{account_id}"
        # private-notes is the single deliberate local authorization vulnerability.
        if resource != "private-notes" and role == "VIEWER" and user_id != owner_id:
            self._json(403, {"authorized": False})
            return
        documents = {
            "profile": {"user": {"name": f"Usuário Sintético {account_id.upper()}"}},
            "projects": {"user": {"projects": ["Projeto sintético"]}},
            "documents": {"user": {"documents": ["Documento sintético"]}},
            "private-notes": {"user": {"private_notes": "Nota sintética privada"}},
        }
        self._json(200, documents[resource])

    def log_message(self, format: str, *args: object) -> None:
        print(f"[API] {format % args}")


if __name__ == "__main__":
    web = ThreadingHTTPServer(("127.0.0.1", WEB_PORT), WebHandler)
    api = ThreadingHTTPServer(("127.0.0.1", API_PORT), ApiHandler)
    api_thread = threading.Thread(target=api.serve_forever, daemon=True)
    api_thread.start()
    print(
        f"Authenticated fixture: web http://127.0.0.1:{WEB_PORT}; "
        f"API http://127.0.0.1:{API_PORT} (Ctrl+C to stop)"
    )
    try:
        web.serve_forever()
    finally:
        web.server_close()
        api.shutdown()
        api.server_close()
        api_thread.join(timeout=2)
