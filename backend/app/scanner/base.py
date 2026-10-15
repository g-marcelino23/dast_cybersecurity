from abc import ABC, abstractmethod
from dataclasses import dataclass

import httpx

from app.models.enums import Confidence, Severity
from app.schemas.entities import FindingDraft


@dataclass(frozen=True)
class ResponseSnapshot:
    endpoint: str
    status_code: int
    headers: httpx.Headers
    body: bytes | None = None
    method: str = "GET"
    tls_version: str | None = None
    tls_cipher: str | None = None

    @property
    def is_html(self) -> bool:
        content_type = self.headers.get("content-type", "").lower().split(";")[0].strip()
        return content_type in {"text/html", "application/xhtml+xml"}


class BaseScannerModule(ABC):
    name: str
    description: str

    @abstractmethod
    def scan(self, response: ResponseSnapshot) -> list[FindingDraft]:
        """Analyze a snapshot; modules have no network or database access."""
        raise NotImplementedError

    def generate_finding(
        self,
        response: ResponseSnapshot,
        *,
        title: str,
        description: str,
        evidence: str,
        recommendation: str,
        cwe: str,
        severity: Severity = Severity.LOW,
        confidence: Confidence = Confidence.HIGH,
    ) -> FindingDraft:
        return FindingDraft(
            title=title,
            description=description,
            endpoint=response.endpoint,
            evidence=evidence,
            recommendation=recommendation,
            cwe=cwe,
            severity=severity,
            confidence=confidence,
        )
