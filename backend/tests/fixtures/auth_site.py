import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PATIENT_TOKEN = "synthetic-session-patient-a"
PATIENT_EMAIL = "paciente.a@fixture.invalid"
PATIENT_PASSWORD = "fixture-password-a"
PATIENT_MFA_CODE = "123456"


class AuthFixtureState:
    login_attempts = 0
    authenticated_requests = 0
    rejected_requests = 0
    mfa_attempts = 0


@contextmanager
def mfa_cookie_site() -> Iterator[tuple[str, AuthFixtureState]]:
    state = AuthFixtureState()
    state.login_attempts = 0
    state.authenticated_requests = 0
    state.rejected_requests = 0
    state.mfa_attempts = 0

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            size = int(self.headers.get("Content-Length", "0"))
            try:
                payload = json.loads(self.rfile.read(size))
            except json.JSONDecodeError:
                payload = {}
            if self.path == "/auth/login":
                state.login_attempts += 1
                if payload != {"email": PATIENT_EMAIL, "senha": PATIENT_PASSWORD}:
                    self.send_response(401)
                    self.end_headers()
                    return
                self._json(202, {"mfa_required": True, "challenge_id": "challenge-1"})
                return
            if self.path == "/auth/mfa/verify":
                state.mfa_attempts += 1
                if payload != {"challenge_id": "challenge-1", "codigo": PATIENT_MFA_CODE}:
                    self.send_response(401)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header(
                    "Set-Cookie",
                    f"clinicalmed_session={PATIENT_TOKEN}; HttpOnly; SameSite=Strict; Path=/",
                )
                body = json.dumps({"usuario": {"perfil": "PACIENTE"}}).encode()
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_error(404)

        def do_GET(self) -> None:
            if self.path != "/auth/me":
                self.send_error(404)
                return
            if f"clinicalmed_session={PATIENT_TOKEN}" not in self.headers.get("Cookie", ""):
                state.rejected_requests += 1
                self.send_response(401)
                self.end_headers()
                return
            state.authenticated_requests += 1
            self._json(200, {"usuario": {"perfil": "PACIENTE"}})

        def _json(self, status: int, payload: dict[str, object]) -> None:
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@contextmanager
def authenticated_site() -> Iterator[tuple[str, str, AuthFixtureState]]:
    state = AuthFixtureState()
    state.login_attempts = 0
    state.authenticated_requests = 0
    state.rejected_requests = 0
    web_origin = [""]

    class ApiHandler(BaseHTTPRequestHandler):
        def _cors(self) -> None:
            self.send_header("Access-Control-Allow-Origin", web_origin[0])
            self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

        def do_OPTIONS(self) -> None:
            self.send_response(204)
            self._cors()
            self.end_headers()

        def do_POST(self) -> None:
            if self.path != "/auth/login":
                self.send_error(404)
                return
            state.login_attempts += 1
            size = int(self.headers.get("Content-Length", "0"))
            try:
                payload = json.loads(self.rfile.read(size))
            except json.JSONDecodeError:
                payload = {}
            if payload != {"email": PATIENT_EMAIL, "senha": PATIENT_PASSWORD}:
                self.send_response(401)
                self._cors()
                self.end_headers()
                return
            body = json.dumps({"session": {"access_token": PATIENT_TOKEN}}).encode()
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if self.headers.get("Authorization") != f"Bearer {PATIENT_TOKEN}":
                state.rejected_requests += 1
                self.send_response(401)
                self._cors()
                self.end_headers()
                return
            state.authenticated_requests += 1
            documents = {
                "/api/me": {
                    "patient": {
                        "name": "Paciente Sintético A",
                        "email": PATIENT_EMAIL,
                        "cpf": "111.444.777-35",
                    }
                },
                "/api/patient/exams": {
                    "patient": {
                        "diagnosis": "Diagnóstico sintético",
                        "exam_result": "Resultado sintético normal",
                    }
                },
                "/api/patient/prescriptions": {
                    "patient": {
                        "prescription": "Prescrição sintética",
                        "medication": "Medicamento sintético Alpha",
                    }
                },
            }
            document = documents.get(self.path.split("?", maxsplit=1)[0])
            if document is None:
                self.send_error(404)
                return
            body = json.dumps(document, ensure_ascii=False).encode()
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            pass

    api = ThreadingHTTPServer(("127.0.0.1", 0), ApiHandler)
    api_port = api.server_port

    class WebHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path.split("?", maxsplit=1)[0] != "/":
                self.send_error(404)
                return
            body = f"""<!doctype html><html><body>
              <h1>Portal clínico sintético autenticado</h1>
              <script>
                Promise.all([
                  fetch('http://127.0.0.1:{api_port}/api/me'),
                  fetch('http://127.0.0.1:{api_port}/api/patient/exams'),
                  fetch('http://127.0.0.1:{api_port}/api/patient/prescriptions')
                ]).then(items => Promise.all(items.map(item => item.json())))
                  .then(() => document.body.dataset.loaded = 'true');
              </script>
            </body></html>""".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            pass

    web = ThreadingHTTPServer(("127.0.0.1", 0), WebHandler)
    web_origin[0] = f"http://127.0.0.1:{web.server_port}"
    api_thread = threading.Thread(target=api.serve_forever, daemon=True)
    web_thread = threading.Thread(target=web.serve_forever, daemon=True)
    api_thread.start()
    web_thread.start()
    try:
        yield web_origin[0], f"http://127.0.0.1:{api_port}", state
    finally:
        web.shutdown()
        api.shutdown()
        web.server_close()
        api.server_close()
        web_thread.join(timeout=2)
        api_thread.join(timeout=2)
