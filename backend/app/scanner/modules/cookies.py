import re
from http.cookies import CookieError, SimpleCookie

from app.models.enums import Confidence, Severity
from app.scanner.base import BaseScannerModule, ResponseSnapshot
from app.schemas.entities import FindingDraft

# Names are contextual signals only; they never prove that a cookie contains sensitive data.
SESSION_NAMES = re.compile(
    r"^(?:session(?:id)?|session_id|sid|connect\.sid|jsessionid|phpsessid|"
    r"asp\.net_sessionid|auth_token|access_token|refresh_token|auth|jwt)$",
    re.I,
)


class CookiesModule(BaseScannerModule):
    name = "cookies"
    description = "Atributos de proteção de cookies com indícios de sessão."

    def scan(self, response: ResponseSnapshot) -> list[FindingDraft]:
        findings = []
        seen: set[tuple[str, str]] = set()
        for raw in response.headers.get_list("set-cookie"):
            cookies = SimpleCookie()
            try:
                cookies.load(raw)
            except CookieError:
                continue
            for name, cookie in cookies.items():
                if not cookie.value or cookie["max-age"] == "0":
                    continue
                session_name = re.sub(r"^__(?:Host|Secure)-", "", name, flags=re.I)
                if not SESSION_NAMES.fullmatch(session_name):
                    continue
                rules: list[tuple[str, str, str, Severity]] = []
                if response.endpoint.startswith("https://") and not cookie["secure"]:
                    rules.append(
                        (
                            "Secure",
                            "CWE-614",
                            "Use Secure para restringir o envio do cookie a HTTPS.",
                            Severity.LOW,
                        )
                    )
                if not cookie["httponly"]:
                    rules.append(
                        (
                            "HttpOnly",
                            "CWE-1004",
                            "Se o cookie autentica uma sessão, "
                            "defina HttpOnly e evite acesso por JavaScript.",
                            Severity.LOW,
                        )
                    )
                if not cookie["samesite"]:
                    rules.append(
                        (
                            "SameSite",
                            "CWE-1275",
                            "Defina SameSite=Lax ou Strict "
                            "conforme o fluxo. Navegadores modernos podem aplicar Lax "
                            "por padrão; a ausência não comprova CSRF.",
                            Severity.INFO,
                        )
                    )
                elif cookie["samesite"].lower() == "none" and not cookie["secure"]:
                    rules.append(
                        (
                            "SameSite=None sem Secure",
                            "CWE-1275",
                            "SameSite=None "
                            "requer Secure nos navegadores modernos. Confirme a "
                            "necessidade de envio entre sites.",
                            Severity.INFO,
                        )
                    )
                for attribute, cwe, recommendation, severity in rules:
                    if (name, attribute) in seen:
                        continue
                    seen.add((name, attribute))
                    findings.append(
                        self.generate_finding(
                            response,
                            title=f"Cookie de possível sessão: {attribute} inadequado",
                            cwe=cwe,
                            severity=severity,
                            confidence=Confidence.MEDIUM,
                            description="O nome do cookie sugere uso em sessão/autenticação, "
                            "mas sua finalidade precisa de confirmação manual. "
                            "Nenhum valor de cookie foi armazenado.",
                            evidence=f"Set-Cookie: {name}=<redigido>; atributo observado: "
                            f"{attribute} ausente ou inconsistente.",
                            recommendation=recommendation,
                        )
                    )
        return findings
