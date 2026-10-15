from html.parser import HTMLParser

from app.models.enums import Confidence, Severity
from app.scanner.base import BaseScannerModule, ResponseSnapshot
from app.schemas.entities import FindingDraft

RESOURCE_ATTRIBUTES = {
    "audio": ("src",),
    "embed": ("src",),
    "form": ("action",),
    "iframe": ("src",),
    "img": ("src", "srcset"),
    "input": ("src",),
    "link": ("href",),
    "object": ("data",),
    "script": ("src",),
    "source": ("src", "srcset"),
    "track": ("src",),
    "video": ("poster", "src"),
}


class _MixedContentParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.categories: set[str] = set()
        self.occurrences = 0
        self._style_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.casefold() == "style":
            self._style_depth += 1
        relevant = RESOURCE_ATTRIBUTES.get(tag.casefold(), ())
        for name, value in attrs:
            if name.casefold() not in relevant or value is None:
                continue
            lowered = value.strip().casefold()
            if "http://" in lowered or "ws://" in lowered:
                self.categories.add(tag.casefold())
                self.occurrences += 1
        style = next((value for name, value in attrs if name.casefold() == "style"), None)
        if style and "http://" in style.casefold():
            self.categories.add("inline-style")
            self.occurrences += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() == "style" and self._style_depth:
            self._style_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self._style_depth:
            return
        lowered = data.casefold()
        if "url(http://" in lowered or "url('http://" in lowered or 'url("http://' in lowered:
            self.categories.add("style")
            self.occurrences += 1


class MixedContentModule(BaseScannerModule):
    name = "mixed_content"
    description = "Detecção passiva de sub-recursos inseguros em páginas HTTPS."

    def scan(self, response: ResponseSnapshot) -> list[FindingDraft]:
        if (
            not response.endpoint.casefold().startswith("https://")
            or not response.is_html
            or not 200 <= response.status_code < 300
            or not response.body
        ):
            return []
        parser = _MixedContentParser()
        try:
            parser.feed(response.body.decode("utf-8", errors="replace"))
        except (ValueError, AssertionError):
            return []
        if not parser.occurrences:
            return []
        categories = ", ".join(sorted(parser.categories))
        return [
            self.generate_finding(
                response,
                title="Conteúdo misto observado em página HTTPS",
                cwe="CWE-319",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                description="A página HTTPS referencia recursos por transporte não criptografado. "
                "Os destinos completos não foram persistidos.",
                evidence=f"{parser.occurrences} referência(s) insegura(s); tipos: {categories}.",
                recommendation="Sirva todos os sub-recursos por HTTPS/WSS e remova referências "
                "HTTP/WS dos templates e estilos.",
            )
        ]
