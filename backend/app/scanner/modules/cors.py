from app.models.enums import Confidence, Severity
from app.scanner.base import BaseScannerModule, ResponseSnapshot
from app.schemas.entities import FindingDraft


class CorsModule(BaseScannerModule):
    name = "cors"
    description = "Observação conservadora de CORS, sem Origin forjada ou preflight."

    def scan(self, response: ResponseSnapshot) -> list[FindingDraft]:
        origin = response.headers.get("access-control-allow-origin", "").strip()
        credentials = response.headers.get("access-control-allow-credentials", "").strip()
        if credentials != "true" or origin not in {"*", "null"}:
            return []
        wildcard = origin == "*"
        return [
            self.generate_finding(
                response,
                title="CORS: combinação de origem e credenciais requer revisão",
                cwe="CWE-942",
                severity=Severity.INFO if wildcard else Severity.LOW,
                confidence=Confidence.HIGH if wildcard else Confidence.MEDIUM,
                description=(
                    "Wildcard com credenciais é uma configuração inconsistente: navegadores "
                    "bloqueiam a leitura de respostas credentialed com essa combinação. "
                    "Isso não demonstra vazamento de dados."
                    if wildcard
                    else "A origem literal null é permitida com credenciais. "
                    "Pode incluir contextos "
                    "sandboxed; revise a necessidade. Não foram testados reflexão de origem, "
                    "sessões autenticadas ou acesso a dados."
                ),
                evidence=f"Access-Control-Allow-Origin: {origin}; "
                "Access-Control-Allow-Credentials: true.",
                recommendation="Use origens explícitas confiáveis quando credenciais forem "
                "necessárias e valide a política no contexto da API. Evite permitir null.",
            )
        ]
