from collections.abc import Collection
from dataclasses import dataclass

from app.crawler.browser import AuthContext
from app.scanner.base import BaseScannerModule, ResponseSnapshot
from app.scanner.client import SafeHttpCollector
from app.scanner.modules.cache_control import CacheControlModule
from app.scanner.modules.cookies import CookiesModule
from app.scanner.modules.cors import CorsModule
from app.scanner.modules.csp import ContentSecurityPolicyModule
from app.scanner.modules.error_disclosure import ErrorDisclosureModule
from app.scanner.modules.security_headers import SecurityHeadersModule
from app.scanner.modules.server_disclosure import ServerDisclosureModule
from app.schemas.entities import FindingDraft


@dataclass
class ScanResult:
    findings: list[FindingDraft]
    observations: list[dict[str, str | int]]
    responses: list[ResponseSnapshot]


class ScannerEngine:
    def __init__(self, collector: SafeHttpCollector | None = None) -> None:
        self.collector = collector or SafeHttpCollector()
        self.modules: tuple[BaseScannerModule, ...] = (
            SecurityHeadersModule(),
            ServerDisclosureModule(),
            CookiesModule(),
            CorsModule(),
            ContentSecurityPolicyModule(),
            CacheControlModule(),
            ErrorDisclosureModule(),
        )

    def run(
        self,
        urls: list[str],
        auth: AuthContext | None = None,
        enabled_modules: list[str] | None = None,
        allowed_public_hosts: Collection[str] = (),
    ) -> ScanResult:
        observations: list[dict[str, str | int]] = []
        responses: list[ResponseSnapshot] = []
        for url in dict.fromkeys(urls):
            response = (
                self.collector.fetch(url, auth, allowed_public_hosts)
                if allowed_public_hosts
                else self.collector.fetch(url, auth)
            )
            responses.append(response)
            observations.append(
                {"endpoint": response.endpoint, "status_code": response.status_code}
            )
        return ScanResult(
            findings=self.analyze(responses, enabled_modules),
            observations=observations,
            responses=responses,
        )

    def analyze(
        self, responses: list[ResponseSnapshot], enabled_modules: list[str] | None = None
    ) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        selected = set(enabled_modules) if enabled_modules is not None else None
        for response in responses:
            for module in self.modules:
                if selected is not None and module.name not in selected:
                    continue
                findings.extend(module.scan(response))
        return findings
