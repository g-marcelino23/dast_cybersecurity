from urllib.parse import parse_qs, unquote, urlsplit

import httpx

from app.core.config import Settings
from app.crawler.models import EndpointObservation
from app.models.enums import DiscoverySource, ResourceType
from app.scanner.active import SafeActiveEngine
from app.scanner.base import ResponseSnapshot


class ActiveCollector:
    def __init__(self) -> None:
        self.requests: list[tuple[str, str]] = []

    def request(
        self,
        url: str,
        method: str,
        _auth=None,
        *,
        timeout_seconds: float | None = None,
    ) -> ResponseSnapshot:
        self.requests.append((method, url))
        parts = urlsplit(url)
        endpoint = f"{parts.scheme}://{parts.netloc}{parts.path}"
        if method == "OPTIONS":
            return ResponseSnapshot(endpoint, 204, httpx.Headers({"Allow": "GET, PUT, DELETE"}))
        values = parse_qs(parts.query)
        if values.get("next", [""])[0].startswith("https://dast.invalid/"):
            return ResponseSnapshot(
                endpoint,
                302,
                httpx.Headers({"Location": values["next"][0]}),
            )
        reflected = next(
            (value for rows in values.values() for value in rows if value.startswith("<dast-xss-")),
            "",
        )
        return ResponseSnapshot(
            endpoint,
            200,
            httpx.Headers({"Content-Type": "text/html"}),
            f"<html>{reflected}</html>".encode(),
        )


def active_settings(*, max_requests: int = 30) -> Settings:
    return Settings(
        database_url="sqlite://",
        active_max_requests=max_requests,
        active_max_endpoints=10,
        active_max_parameters=10,
        active_request_timeout=2,
        active_request_delay_ms=0,
    )


def query_endpoint() -> EndpointObservation:
    return EndpointObservation(
        url="http://127.0.0.1:8765/search?q={value}&next={value}",
        path="/search",
        method="GET",
        source=DiscoverySource.CRAWLER,
        resource_type=ResourceType.PAGE,
        parameters={
            "query": [
                {"name": "q", "location": "query"},
                {"name": "next", "location": "query"},
            ]
        },
    )


def injection_endpoint() -> EndpointObservation:
    return EndpointObservation(
        url="http://127.0.0.1:8765/item?id={value}&file={value}",
        path="/item",
        method="GET",
        source=DiscoverySource.CRAWLER,
        resource_type=ResourceType.API,
        parameters={
            "query": [
                {"name": "id", "location": "query"},
                {"name": "file", "location": "query"},
            ]
        },
    )


class InjectionCollector:
    def __init__(self, *, error_on_baseline: bool = False) -> None:
        self.requests: list[tuple[str, str]] = []
        self.error_on_baseline = error_on_baseline

    def request(
        self,
        url: str,
        method: str,
        _auth=None,
        *,
        timeout_seconds: float | None = None,
    ) -> ResponseSnapshot:
        self.requests.append((method, url))
        parts = urlsplit(url)
        endpoint = f"{parts.scheme}://{parts.netloc}{parts.path}"
        values = parse_qs(parts.query)
        if unquote(values.get("file", [""])[0]).startswith("../../"):
            body = b"root:x:0:0:root:/root:/bin/bash"
        elif self.error_on_baseline or any(
            value.endswith("'") for rows in values.values() for value in rows
        ):
            body = b"syntax error at or near user input"
        else:
            body = b'{"ok": true}'
        return ResponseSnapshot(
            endpoint,
            200,
            httpx.Headers({"Content-Type": "application/json"}),
            body,
        )


def test_safe_active_modules_use_only_non_mutating_requests() -> None:
    collector = ActiveCollector()
    phases: list[str] = []
    result = SafeActiveEngine(collector, active_settings()).run(  # type: ignore[arg-type]
        [query_endpoint()],
        ["http://127.0.0.1:8765"],
        None,
        ["http_methods", "open_redirect", "reflected_xss"],
        before_request=phases.append,
    )

    assert {finding.cwe for finding in result.findings} == {"CWE-79", "CWE-601", "CWE-749"}
    assert {finding.finding_type for finding in result.findings} == {
        "CONFIRMED_VULNERABILITY",
        "POTENTIAL_VULNERABILITY",
    }
    assert result.requests_sent == len(collector.requests) == 5
    assert result.tested_parameters == 3
    assert result.truncated is False
    assert {method for method, _url in collector.requests} <= {"GET", "HEAD", "OPTIONS"}
    assert not any(method in {"POST", "PUT", "PATCH", "DELETE"} for method, _ in collector.requests)
    assert phases == [
        "http_methods",
        "http_methods",
        "open_redirect",
        "reflected_xss",
        "reflected_xss",
    ]
    assert all("?" not in finding.endpoint for finding in result.findings)
    assert all("dast-xss-" not in finding.evidence for finding in result.findings)


def test_safe_active_budget_stops_additional_requests() -> None:
    collector = ActiveCollector()
    result = SafeActiveEngine(collector, active_settings(max_requests=2)).run(  # type: ignore[arg-type]
        [query_endpoint()],
        ["http://127.0.0.1:8765"],
        None,
        ["http_methods", "open_redirect", "reflected_xss"],
    )

    assert result.requests_sent == 2
    assert result.truncated is True
    assert len(collector.requests) == 2


def test_active_parameter_modules_skip_endpoints_without_query_parameters() -> None:
    collector = ActiveCollector()
    endpoint = query_endpoint()
    endpoint.parameters = None
    result = SafeActiveEngine(collector, active_settings()).run(  # type: ignore[arg-type]
        [endpoint],
        [],
        None,
        ["open_redirect", "reflected_xss"],
    )

    assert result.requests_sent == 0
    assert result.findings == []


def test_sql_injection_and_path_traversal_use_sanitized_differential_evidence() -> None:
    collector = InjectionCollector()
    result = SafeActiveEngine(collector, active_settings()).run(  # type: ignore[arg-type]
        [injection_endpoint()],
        [],
        None,
        ["path_traversal", "sql_injection"],
    )

    assert {finding.cwe for finding in result.findings} == {"CWE-22", "CWE-89"}
    assert result.requests_sent == len(collector.requests) == 5
    assert result.tested_parameters == 3
    assert result.truncated is False
    assert {method for method, _url in collector.requests} == {"GET"}
    assert all("?" not in finding.endpoint for finding in result.findings)
    evidence = " ".join(finding.evidence for finding in result.findings)
    assert "../../" not in evidence
    assert "root:x:0:0" not in evidence
    assert "dast-" not in evidence


def test_sql_injection_ignores_error_already_present_in_control_response() -> None:
    collector = InjectionCollector(error_on_baseline=True)
    result = SafeActiveEngine(collector, active_settings()).run(  # type: ignore[arg-type]
        [injection_endpoint()],
        [],
        None,
        ["sql_injection"],
    )

    assert result.requests_sent == 4
    assert result.tested_parameters == 2
    assert result.findings == []
