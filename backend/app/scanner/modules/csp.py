from app.models.enums import Confidence, Severity
from app.scanner.base import BaseScannerModule, ResponseSnapshot
from app.schemas.entities import FindingDraft


class ContentSecurityPolicyModule(BaseScannerModule):
    name = "csp"
    description = "Revisão de diretivas potencialmente permissivas em Content-Security-Policy."

    def scan(self, response: ResponseSnapshot) -> list[FindingDraft]:
        if not response.is_html or not 200 <= response.status_code < 300:
            return []
        policy = response.headers.get("content-security-policy", "").strip()
        if not policy:
            return []
        directives = policy.casefold()
        risky = [token for token in ("'unsafe-inline'", "'unsafe-eval'") if token in directives]
        if not risky:
            return []
        return [
            self.generate_finding(
                response,
                title="CSP contém diretivas permissivas",
                cwe="CWE-693",
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                description="A política CSP utiliza diretivas que reduzem sua proteção contra "
                "injeção de scripts. A presença isolada não comprova uma vulnerabilidade XSS.",
                evidence=f"Content-Security-Policy contém: {', '.join(risky)}.",
                recommendation="Remova unsafe-eval e substitua unsafe-inline por nonces ou hashes "
                "após validar a compatibilidade da aplicação.",
            )
        ]
