import re

from app.models.enums import Confidence, Severity
from app.scanner.base import BaseScannerModule, ResponseSnapshot
from app.schemas.entities import FindingDraft

SIGNATURES = (
    (re.compile(rb"Traceback \(most recent call last\)", re.I), "traceback Python"),
    (re.compile(rb"\bat [\w.$]+\([^\r\n]+\.java:\d+\)", re.I), "stack trace Java"),
    (re.compile(rb"System\.[\w.]+Exception", re.I), "exceção .NET"),
    (re.compile(rb"(?:SQL syntax|mysql_fetch|PG::[A-Za-z]+Error|sqlite3?\.)", re.I), "erro SQL"),
    (re.compile(rb"node_modules[/\\].+?:\d+:\d+", re.I), "stack trace Node.js"),
)


class ErrorDisclosureModule(BaseScannerModule):
    name = "error_disclosure"
    description = "Detecta assinaturas de stack traces e erros técnicos sem persistir o corpo."

    def scan(self, response: ResponseSnapshot) -> list[FindingDraft]:
        if response.status_code < 500 or not response.body:
            return []
        matches = [label for pattern, label in SIGNATURES if pattern.search(response.body)]
        if not matches:
            return []
        return [
            self.generate_finding(
                response,
                title="Detalhes técnicos expostos em resposta de erro",
                cwe="CWE-209",
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                description="A resposta de erro contém assinatura de tecnologia ou stack trace. "
                "O corpo completo não foi armazenado pelo módulo.",
                evidence=f"HTTP {response.status_code}; assinaturas: {', '.join(matches)}.",
                recommendation="Retorne mensagens genéricas ao cliente e registre detalhes apenas "
                "em logs internos com acesso controlado.",
            )
        ]
