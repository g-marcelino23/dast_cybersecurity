import ipaddress
import socket
from collections.abc import Collection
from dataclasses import dataclass

from app.core.target_policy import TargetPolicyError, validate_target
from app.crawler.normalizer import URLNormalizationError, normalize_url


@dataclass(frozen=True)
class CrawlerScope:
    base_url: str
    trusted_hosts: dict[str, str]
    navigable_origins: frozenset[str]

    @classmethod
    def from_target(
        cls,
        base_url: str,
        api_url: str | None = None,
        allowed_public_hosts: Collection[str] = (),
        additional_urls: Collection[str] = (),
        additional_navigation_urls: Collection[str] = (),
    ) -> "CrawlerScope":
        trusted_hosts: dict[str, str] = {}
        all_urls = [base_url] + ([api_url] if api_url else []) + list(additional_urls)
        for raw_url in all_urls:
            assert raw_url is not None
            validated = validate_target(raw_url, allowed_public_hosts)
            normalized = normalize_url(str(validated.url))
            if normalized.hostname not in trusted_hosts:
                trusted_hosts[normalized.hostname] = _reachable_address(
                    validated.addresses,
                    validated.url.port or (443 if validated.url.scheme == "https" else 80),
                )
        navigable_origins = frozenset(
            normalize_url(url).origin for url in [base_url, *additional_navigation_urls]
        )
        return cls(
            base_url=normalize_url(base_url).url,
            trusted_hosts=trusted_hosts,
            navigable_origins=navigable_origins,
        )

    def allows_request(self, raw_url: str, browser_type: str) -> bool:
        try:
            normalized = normalize_url(raw_url)
            validated = validate_target(normalized.url, self.trusted_hosts)
        except (TargetPolicyError, URLNormalizationError):
            return False
        try:
            ipaddress.ip_address(normalized.hostname)
            known_or_literal = True
        except ValueError:
            pinned_address = self.trusted_hosts.get(normalized.hostname)
            known_or_literal = pinned_address is not None and pinned_address in validated.addresses
        if not known_or_literal:
            return False
        return browser_type != "document" or normalized.origin in self.navigable_origins

    def can_navigate(self, raw_url: str) -> bool:
        try:
            return normalize_url(raw_url).origin in self.navigable_origins and self.allows_request(
                raw_url, "document"
            )
        except URLNormalizationError:
            return False

    def chromium_resolver_rules(self) -> str:
        rules = []
        for host, address in sorted(self.trusted_hosts.items()):
            try:
                ipaddress.ip_address(host)
            except ValueError:
                resolver_address = f"[{address}]" if ":" in address else address
                rules.append(f"MAP {host} {resolver_address}")
        return ", ".join(rules)


def _reachable_address(addresses: tuple[str, ...], port: int) -> str:
    """Select only among policy-validated addresses, preserving DNS pinning."""
    for address in addresses:
        try:
            connection = socket.create_connection((address, port), timeout=0.25)
        except OSError:
            continue
        connection.close()
        return address
    return addresses[0]
