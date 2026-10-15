import re

from app.models.enums import Severity
from app.scanner.base import BaseScannerModule, ResponseSnapshot
from app.schemas.entities import FindingDraft


class ServerDisclosureModule(BaseScannerModule):
    name = "server_disclosure"
    description = "Identificação de tecnologia divulgada em cabeçalhos."

    def scan(self, response: ResponseSnapshot) -> list[FindingDraft]:
        findings = []
        for header in ("Server", "X-Powered-By"):
            value = response.headers.get(header, "").strip()
            if not value:
                continue
            # Keep evidence small and single-line. No cookies or body are retained.
            value = re.sub(r"[\x00-\x1f\x7f]", "", value)[:160]
            findings.append(
                self.generate_finding(
                    response,
                    title=f"Tecnologia divulgada em {header}",
                    cwe="CWE-200",
                    severity=Severity.INFO,
                    description="O servidor divulga um identificador de tecnologia. Isso pode "
                    "auxiliar reconhecimento, mas não demonstra versão vulnerável "
                    "ou dados expostos.",
                    evidence=f"{header}: {value}",
                    recommendation="Avalie remover ou reduzir identificadores desnecessários "
                    "no servidor/reverse proxy. Mantenha os componentes atualizados.",
                )
            )
        return findings
