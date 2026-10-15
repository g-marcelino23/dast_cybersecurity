from app.models.enums import Confidence, Severity
from app.scanner.base import BaseScannerModule, ResponseSnapshot
from app.schemas.entities import FindingDraft


class TlsModule(BaseScannerModule):
    name = "tls"
    description = "Revisão passiva da versão e cifra TLS observadas."

    def scan(self, response: ResponseSnapshot) -> list[FindingDraft]:
        if not response.endpoint.casefold().startswith("https://") or not response.tls_version:
            return []
        findings: list[FindingDraft] = []
        version = response.tls_version.upper().replace(" ", "")
        if version in {"SSLV2", "SSLV3", "TLSV1", "TLSV1.0", "TLSV1.1"}:
            findings.append(
                self.generate_finding(
                    response,
                    title="Versão TLS obsoleta observada",
                    cwe="CWE-326",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    description="A conexão negociou uma versão TLS obsoleta, com proteção "
                    "criptográfica inferior às versões atuais.",
                    evidence=f"Versão negociada: {response.tls_version}.",
                    recommendation="Desabilite SSL e TLS 1.0/1.1; permita TLS 1.2 ou superior.",
                )
            )
        cipher = (response.tls_cipher or "").upper()
        weak_tokens = ("_NULL_", "_RC4_", "_DES_", "3DES", "_EXPORT_", "_MD5")
        matched = [token.strip("_") for token in weak_tokens if token in cipher]
        if matched:
            findings.append(
                self.generate_finding(
                    response,
                    title="Cifra TLS fraca observada",
                    cwe="CWE-326",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    description="A conexão negociou uma cifra com algoritmo obsoleto ou "
                    "sem proteção criptográfica adequada.",
                    evidence=f"Indicadores fracos na cifra negociada: {', '.join(matched)}.",
                    recommendation="Restrinja as cifras a conjuntos modernos com AEAD e "
                    "forward secrecy.",
                )
            )
        return findings
