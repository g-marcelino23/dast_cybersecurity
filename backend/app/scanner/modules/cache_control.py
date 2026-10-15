from http.cookies import CookieError, SimpleCookie

from app.models.enums import Confidence, Severity
from app.scanner.base import BaseScannerModule, ResponseSnapshot
from app.scanner.modules.cookies import SESSION_NAMES
from app.schemas.entities import FindingDraft


class CacheControlModule(BaseScannerModule):
    name = "cache_control"
    description = "Identifica cache público em respostas que criam possível sessão."

    def scan(self, response: ResponseSnapshot) -> list[FindingDraft]:
        cache_control = response.headers.get("cache-control", "").casefold()
        if "public" not in {part.strip() for part in cache_control.split(",")}:
            return []
        session_cookie_names: list[str] = []
        for raw in response.headers.get_list("set-cookie"):
            cookies = SimpleCookie()
            try:
                cookies.load(raw)
            except CookieError:
                continue
            for name, cookie in cookies.items():
                normalized = name.removeprefix("__Host-").removeprefix("__Secure-")
                if cookie.value and SESSION_NAMES.fullmatch(normalized):
                    session_cookie_names.append(name[:80])
        if not session_cookie_names:
            return []
        return [
            self.generate_finding(
                response,
                title="Cache público em resposta de possível sessão",
                cwe="CWE-525",
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                description="A resposta define um cookie cujo nome sugere sessão e permite cache "
                "público. A sensibilidade do conteúdo precisa ser confirmada manualmente.",
                evidence="Cache-Control contém public; cookies observados: "
                + ", ".join(sorted(set(session_cookie_names)))
                + "=<redigido>.",
                recommendation="Para respostas autenticadas ou personalizadas, use Cache-Control: "
                "no-store ou uma política private adequada.",
            )
        ]
