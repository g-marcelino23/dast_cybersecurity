from app.models.enums import Severity
from app.scanner.base import BaseScannerModule, ResponseSnapshot
from app.schemas.entities import FindingDraft


class SecurityHeadersModule(BaseScannerModule):
    name = "security_headers"
    description = "Presença de cabeçalhos de proteção em respostas HTTP."

    def scan(self, response: ResponseSnapshot) -> list[FindingDraft]:
        if not 200 <= response.status_code < 300:
            return []
        rules = [
            ("X-Content-Type-Options", "Defina X-Content-Type-Options: nosniff.", Severity.LOW),
        ]
        if response.is_html:
            rules.extend(
                [
                    (
                        "Content-Security-Policy",
                        "Defina uma CSP compatível com a aplicação, "
                        "preferindo nonces/hashes e restringindo as origens autorizadas.",
                        Severity.LOW,
                    ),
                    (
                        "Referrer-Policy",
                        "Defina Referrer-Policy: strict-origin-when-cross-origin "
                        "ou uma política mais restritiva adequada à aplicação.",
                        Severity.LOW,
                    ),
                    (
                        "Permissions-Policy",
                        "Restrinja recursos como câmera, microfone e "
                        "geolocalização aos estritamente necessários.",
                        Severity.INFO,
                    ),
                ]
            )
        if response.endpoint.startswith("https://"):
            rules.append(
                (
                    "Strict-Transport-Security",
                    "Após confirmar HTTPS em todo o escopo, configure HSTS com max-age apropriado.",
                    Severity.LOW,
                )
            )
        findings = []
        for header, recommendation, severity in rules:
            if not response.headers.get(header, "").strip():
                findings.append(
                    self.generate_finding(
                        response,
                        title=f"{header} ausente",
                        cwe="CWE-693",
                        severity=severity,
                        description="Cabeçalho de defesa em profundidade ausente nesta resposta. "
                        "A observação não comprova exploração nem exposição de dados. "
                        "Valide a necessidade no contexto do endpoint.",
                        evidence=f"HTTP {response.status_code}; {header}: ausente ou vazio.",
                        recommendation=recommendation,
                    )
                )
        return findings
