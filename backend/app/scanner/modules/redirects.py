from urllib.parse import urljoin, urlsplit

from app.models.enums import Confidence, Severity
from app.scanner.base import BaseScannerModule, ResponseSnapshot
from app.schemas.entities import FindingDraft


class RedirectsModule(BaseScannerModule):
    name = "redirects"
    description = "Revisão passiva de destinos de redirect sem seguir a resposta."

    def scan(self, response: ResponseSnapshot) -> list[FindingDraft]:
        if response.status_code not in {301, 302, 303, 307, 308}:
            return []
        location = response.headers.get("location", "").strip()
        if not location:
            return []
        source = urlsplit(response.endpoint)
        destination = urlsplit(urljoin(response.endpoint, location))
        if destination.scheme not in {"http", "https"}:
            return [
                self.generate_finding(
                    response,
                    title="Redirect usa esquema não HTTP",
                    cwe="CWE-601",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    description="A resposta direciona o navegador para um esquema não HTTP(S). "
                    "O destino não foi seguido nem persistido.",
                    evidence=f"HTTP {response.status_code}; esquema observado: "
                    f"{destination.scheme or 'ausente'}.",
                    recommendation="Permita apenas destinos HTTP(S) previamente validados e "
                    "prefira caminhos relativos.",
                )
            ]
        if source.scheme == "https" and destination.scheme == "http":
            host_changed = source.netloc.casefold() != destination.netloc.casefold()
            return [
                self.generate_finding(
                    response,
                    title="Redirect reduz HTTPS para HTTP",
                    cwe="CWE-319",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    description="A resposta HTTPS redireciona para transporte sem criptografia. "
                    "O scanner não seguiu o destino.",
                    evidence=f"HTTP {response.status_code}; HTTPS para HTTP; mudança de host: "
                    f"{'sim' if host_changed else 'não'}.",
                    recommendation="Mantenha toda a cadeia de redirects em HTTPS.",
                )
            ]
        if source.netloc.casefold() != destination.netloc.casefold():
            return [
                self.generate_finding(
                    response,
                    title="Redirect para host externo observado",
                    cwe="CWE-601",
                    severity=Severity.INFO,
                    confidence=Confidence.MEDIUM,
                    description="A resposta aponta para outro host. Isso pode ser intencional e "
                    "não comprova Open Redirect; revise a necessidade e a origem do destino.",
                    evidence=f"HTTP {response.status_code}; esquema: {destination.scheme}; "
                    "host alterado: sim. Destino não seguido.",
                    recommendation="Use uma allowlist de destinos confiáveis e caminhos relativos "
                    "quando o redirect externo não for necessário.",
                )
            ]
        return []
