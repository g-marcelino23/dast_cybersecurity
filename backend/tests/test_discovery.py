import json
import socket
from unittest.mock import Mock, patch

import httpx

from app.core.config import Settings
from app.crawler.crawler import DiscoveryCrawler
from app.crawler.discovery import DiscoveryInventory, DiscoveryQueue, classify_resource
from app.crawler.models import DiscoveryResult, EndpointObservation
from app.crawler.normalizer import normalize_url
from app.crawler.scope import CrawlerScope
from app.models.enums import DiscoverySource, ResourceType
from app.scanner.base import ResponseSnapshot
from tests.fixtures.crawler_site import crawler_site


def test_url_normalization_redacts_values_and_deduplicates_page_variants():
    first = normalize_url("HTTP://LOCALHOST:80/records/../patients/?token=secret&b=2&a=1&a=2#first")
    second = normalize_url("http://localhost/patients?a=other&token=changed&b=9#second")
    assert first.url == second.url
    assert first.url == "http://localhost/patients?a={value}&b={value}&token={value}"
    assert first.path == "/patients"
    assert "secret" not in json.dumps(first.parameters)
    assert first.parameters == {
        "query": [
            {"name": "a", "location": "query", "repeated": True},
            {"name": "b", "location": "query", "repeated": False},
            {"name": "token", "location": "query", "repeated": False},
        ]
    }


def test_inventory_deduplicates_requests_and_sanitizes_persisted_shape():
    inventory = DiscoveryInventory(max_requests=3)
    assert inventory.observe_request("http://localhost/api?a=secret", "get", "fetch")
    assert inventory.observe_request("http://localhost/api?a=other", "GET", "fetch")
    inventory.observe_response(
        "http://localhost/api?a=secret",
        "GET",
        "fetch",
        401,
        {"content-type": "application/json", "authorization": "Bearer must-not-persist"},
    )
    result = inventory.result()
    assert len(result.endpoints) == 1
    assert result.requests_observed == 2
    endpoint = result.endpoints[0]
    assert endpoint.resource_type == ResourceType.API
    assert endpoint.requires_auth is True
    assert "secret" not in json.dumps(endpoint.__dict__)
    assert "must-not-persist" not in json.dumps(endpoint.__dict__)
    assert inventory.observe_request("http://localhost/last", "GET", "document")
    assert not inventory.observe_request("http://localhost/blocked", "GET", "document")


def test_static_budget_does_not_consume_page_or_api_budget_and_preserves_hard_limit():
    inventory = DiscoveryInventory(max_requests=2, max_static_requests=2)
    assert inventory.observe_request("http://localhost/app.js", "GET", "script")
    assert inventory.observe_request("http://localhost/app.css", "GET", "stylesheet")
    assert not inventory.observe_request("http://localhost/app.js.map", "GET", "other")
    assert inventory.observe_request("http://localhost/page", "GET", "document")
    assert inventory.observe_request("http://localhost/api/data", "GET", "fetch")
    assert not inventory.observe_request("http://localhost/another", "GET", "document")
    result = inventory.result()
    assert result.requests_observed == 4
    assert result.useful_requests_observed == 2
    assert result.static_requests_observed == 2
    assert result.useful_limit_reached is True
    assert result.static_limit_reached is True
    assert result.hard_limit_reached is True


def test_queue_enforces_depth_page_limit_and_cycles():
    queue = DiscoveryQueue(max_depth=1, max_pages=3)
    assert queue.add("http://localhost/", 0)
    assert not queue.add("http://localhost/#again", 0)
    assert queue.add("http://localhost/one", 1)
    assert not queue.add("http://localhost/deep", 2)
    assert queue.add("http://localhost/two", 1)
    assert not queue.add("http://localhost/three", 1)
    assert [queue.next(), queue.next(), queue.next()] == [
        ("http://localhost/", 0),
        ("http://localhost/one", 1),
        ("http://localhost/two", 1),
    ]
    assert queue.next() is None


def test_queue_uses_query_values_only_for_navigation_and_deduplicates_template():
    queue = DiscoveryQueue(max_depth=1, max_pages=2)
    assert queue.add("http://localhost/search?q=first-secret#fragment", 0)
    assert not queue.add("http://localhost/search?q=second-secret", 0)

    assert queue.next() == ("http://localhost/search?q=first-secret", 0)


def test_scope_blocks_external_navigation_and_revalidates_dns():
    scope = CrawlerScope.from_target("http://localhost:5173", "http://127.0.0.1:3001")
    assert scope.can_navigate("http://localhost:5173/internal")
    assert scope.allows_request("http://127.0.0.1:3001/api/data", "fetch")
    assert not scope.can_navigate("http://127.0.0.1:3001/admin")
    assert not scope.allows_request("https://8.8.8.8/external", "fetch")
    answer = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.8", 80))
    with patch("socket.getaddrinfo", return_value=[answer]):
        named = CrawlerScope.from_target("http://clinic.internal")
    rebound = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.9", 80))
    with patch("socket.getaddrinfo", return_value=[rebound]):
        assert not named.allows_request("http://clinic.internal/page", "document")


def test_scope_pins_reachable_ipv6_for_localhost_without_api_overwrite():
    connection = Mock()

    def connect(address: tuple[str, int], timeout: float):
        assert timeout == 0.25
        if address == ("127.0.0.1", 5173):
            raise ConnectionRefusedError
        if address == ("::1", 5173):
            return connection
        raise AssertionError(f"unexpected connection attempt: {address}")

    with patch("app.crawler.scope.socket.create_connection", side_effect=connect):
        scope = CrawlerScope.from_target("http://localhost:5173", "http://localhost:3001")

    connection.close.assert_called_once_with()
    assert scope.trusted_hosts == {"localhost": "::1"}
    assert scope.chromium_resolver_rules() == "MAP localhost [::1]"


def test_resource_classification():
    assert classify_resource("document", "GET") == ResourceType.PAGE
    assert classify_resource("fetch", "GET") == ResourceType.API
    assert classify_resource("other", "GET", "application/fhir+json") == ResourceType.API
    assert classify_resource("script", "GET") == ResourceType.SCRIPT
    assert classify_resource("other", "DELETE") == ResourceType.API


def test_real_chromium_crawler_discovers_pages_api_and_form_without_submission():
    settings = Settings(
        database_url="sqlite://",
        crawler_max_depth=2,
        crawler_max_pages=10,
        crawler_max_requests=50,
        crawler_timeout_seconds=5,
        crawler_wait_after_load_ms=100,
    )
    with crawler_site() as (web_url, api_url, state):
        result = DiscoveryCrawler(settings=settings).crawl(web_url, api_url)
    pages = [item for item in result.endpoints if item.resource_type == ResourceType.PAGE]
    apis = [item for item in result.endpoints if item.resource_type == ResourceType.API]
    forms = [item for item in result.endpoints if item.resource_type == ResourceType.FORM]
    assert {item.path for item in pages} == {"/", "/one", "/two"}
    assert {item.path for item in apis} == {"/api/root", "/api/one", "/api/two"}
    assert len(forms) == 1 and forms[0].method == "POST"
    assert forms[0].parameters == {
        "fields": [{"name": "email", "type": "email"}, {"name": "senha", "type": "password"}]
    }
    assert "must-not-be-collected" not in json.dumps(forms[0].__dict__)
    assert state.submitted_forms == 0
    assert result.blocked_requests == 0
    assert result.requests_observed >= 6
    assert all("secret" not in item.url for item in result.endpoints)
    assert any(isinstance(response, ResponseSnapshot) for response in result.responses)


def test_many_scripts_do_not_prevent_page_and_api_discovery():
    settings = Settings(
        database_url="sqlite://",
        crawler_max_depth=2,
        crawler_max_pages=10,
        crawler_max_requests=20,
        crawler_max_static_requests=3,
        crawler_timeout_seconds=5,
        crawler_wait_after_load_ms=100,
    )
    with crawler_site(static_resources=12) as (web_url, api_url, state):
        result = DiscoveryCrawler(settings=settings).crawl(web_url, api_url)
    pages = {item.path for item in result.endpoints if item.resource_type == ResourceType.PAGE}
    apis = {item.path for item in result.endpoints if item.resource_type == ResourceType.API}
    scripts = [item for item in result.endpoints if item.resource_type == ResourceType.SCRIPT]
    assert pages == {"/", "/one", "/two"}
    assert apis == {"/api/root", "/api/one", "/api/two"}
    assert len(scripts) == 3
    assert result.static_limit_reached is True
    assert result.hard_limit_reached is False
    assert result.useful_limit_reached is False
    assert result.requests_observed <= 23
    assert state.submitted_forms == 0
    assert all(item.method == "GET" for item in result.responses)


def discovery_result_for_api() -> DiscoveryResult:
    return DiscoveryResult(
        endpoints=[
            EndpointObservation(
                url="http://localhost:5173/",
                path="/",
                method="GET",
                source=DiscoverySource.CRAWLER,
                resource_type=ResourceType.PAGE,
                status_code=200,
                content_type="text/html",
            ),
            EndpointObservation(
                url="http://127.0.0.1:3001/api/exams?patient_id={value}",
                path="/api/exams",
                method="GET",
                source=DiscoverySource.NETWORK,
                resource_type=ResourceType.API,
                status_code=200,
                content_type="application/json",
                parameters={
                    "query": [{"name": "patient_id", "location": "query", "repeated": False}]
                },
            ),
            EndpointObservation(
                url="http://127.0.0.1:3001/auth/login",
                path="/auth/login",
                method="POST",
                source=DiscoverySource.FORM,
                resource_type=ResourceType.FORM,
                parameters={
                    "fields": [
                        {"name": "email", "type": "email"},
                        {"name": "password", "type": "password"},
                    ]
                },
            ),
        ],
        requests_observed=5,
        useful_requests_observed=4,
        static_requests_observed=1,
    )


def test_endpoint_persistence_api_filters_and_summary(client):
    target = client.post(
        "/targets", json={"name": "Discovery", "base_url": "http://localhost:5173"}
    ).json()
    scan_id = client.post("/scans", json={"target_id": target["id"]}).json()["id"]
    response = ResponseSnapshot(
        "http://localhost:5173/", 200, httpx.Headers({"Content-Type": "text/html"})
    )
    with (
        patch("app.services.scans.DiscoveryCrawler.crawl", return_value=discovery_result_for_api()),
        patch("app.scanner.client.SafeHttpCollector.fetch", return_value=response),
    ):
        scan = client.post(f"/scans/{scan_id}/run").json()
    assert scan["status"] == "COMPLETED"
    assert scan["discovery_requests_observed"] == 5
    assert scan["configuration_snapshot"]["discovery_budget"] == {
        "total_requests": 5,
        "useful_requests": 4,
        "static_requests": 1,
        "useful_limit_reached": False,
        "static_limit_reached": False,
        "hard_limit_reached": False,
    }
    endpoints = client.get(f"/scans/{scan_id}/endpoints?limit=100").json()
    assert len(endpoints) == 3
    assert "metadata" in endpoints[0]
    api = client.get(f"/scans/{scan_id}/endpoints?resource_type=API").json()
    assert len(api) == 1 and api[0]["path"] == "/api/exams"
    assert client.get(f"/scans/{scan_id}/endpoints?method=post").json()[0]["method"] == "POST"
    assert client.get(f"/scans/{scan_id}/endpoints/{api[0]['id']}").status_code == 200
    summary = client.get(f"/scans/{scan_id}/discovery-summary").json()
    assert summary == {
        "scan_id": scan_id,
        "pages": 1,
        "api_endpoints": 1,
        "forms": 1,
        "requests_observed": 5,
        "unique_endpoints": 3,
        "methods": ["GET", "POST"],
    }
    another_scan = client.post("/scans", json={"target_id": target["id"]}).json()["id"]
    assert client.get(f"/scans/{another_scan}/endpoints/{api[0]['id']}").status_code == 404
