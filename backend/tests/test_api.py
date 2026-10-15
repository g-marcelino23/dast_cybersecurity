import json
from unittest.mock import patch

import httpx

from app.crawler.models import DiscoveryResult, EndpointObservation
from app.models.enums import (
    Confidence,
    DiscoverySource,
    PrivacyImpact,
    ResourceType,
    ScanStatus,
    Severity,
)
from app.scanner.active import ActiveScanResult
from app.scanner.base import ResponseSnapshot
from app.scanner.engine import ScannerEngine
from app.schemas.entities import FindingDraft


def new_scan(client):
    target = client.post(
        "/targets",
        json={
            "name": "Portal de teste",
            "base_url": "http://localhost:5173",
            "api_url": "http://127.0.0.1:3001",
        },
    )
    assert target.status_code == 201
    result = client.post("/scans", json={"target_id": target.json()["id"]})
    assert result.status_code == 201
    return result.json()["id"]


def test_basic_api_and_complete_scan(client):
    assert client.get("/health").json()["status"] == "ok"
    assert client.get("/targets").json() == []
    scan_id = new_scan(client)
    assert client.get(f"/scans/{scan_id}").json()["status"] == "PENDING"
    response = ResponseSnapshot(
        "http://localhost:5173/", 200, httpx.Headers({"Content-Type": "text/html"})
    )
    with (
        patch("app.scanner.client.SafeHttpCollector.fetch", return_value=response) as collect,
        patch("app.services.scans.DiscoveryCrawler.crawl", return_value=DiscoveryResult.empty()),
    ):
        result = client.post(f"/scans/{scan_id}/run")
    assert collect.call_count == 2
    assert result.status_code == 200
    scan = result.json()
    assert scan["status"] == ScanStatus.COMPLETED
    assert scan["started_at"] and scan["finished_at"]
    findings = client.get(f"/scans/{scan_id}/findings").json()
    assert scan["total_findings"] == len(findings) == 8
    assert all(f["owasp_category"] is None for f in findings)
    assert all(f["finding_type"] in {"MISCONFIGURATION", "INFORMATION"} for f in findings)
    assert all(f["status"] == "OPEN" for f in findings)
    updated = client.patch(f"/findings/{findings[0]['id']}/status", json={"status": "IN_REVIEW"})
    assert updated.status_code == 200
    assert updated.json()["status"] == "IN_REVIEW"
    assert len(scan["observations"]) == 2
    assert client.get(f"/findings/{findings[0]['id']}").status_code == 200
    assert client.get("/targets/1").status_code == 200
    assert len(client.get("/scans").json()) == 1
    assert len(client.get("/findings?limit=2&offset=1").json()) == 2
    assert client.post(f"/scans/{scan_id}/run").status_code == 409
    assert len(client.get(f"/scans/{scan_id}/findings").json()) == 8


def test_scan_failure_persists_without_partial_findings(client):
    scan_id = new_scan(client)
    response = ResponseSnapshot("http://localhost:5173/", 200, httpx.Headers({"Server": "demo"}))
    with (
        patch(
            "app.scanner.client.SafeHttpCollector.fetch",
            side_effect=[response, httpx.ConnectError("sensitive diagnostic")],
        ),
        patch("app.services.scans.DiscoveryCrawler.crawl", return_value=DiscoveryResult.empty()),
    ):
        scan = client.post(f"/scans/{scan_id}/run").json()
    assert scan["status"] == "FAILED"
    assert scan["finished_at"]
    assert scan["total_findings"] == 0
    assert "sensitive diagnostic" not in scan["error_message"]
    assert client.get(f"/scans/{scan_id}/findings").json() == []


def test_bad_targets_missing_entities_and_origin_protection(client):
    assert (
        client.post("/targets", json={"name": "external", "base_url": "http://8.8.8.8"}).status_code
        == 422
    )
    assert (
        client.post("/targets", json={"name": "   ", "base_url": "http://localhost"}).status_code
        == 422
    )
    assert (
        client.post(
            "/targets",
            json={"name": "x", "base_url": "http://localhost", "api_url": "http://169.254.169.254"},
        ).status_code
        == 422
    )
    assert client.post("/scans", json={"target_id": 999}).status_code == 404
    for path in ["/targets/999", "/scans/999", "/scans/999/findings", "/findings/999"]:
        assert client.get(path).status_code == 404
    assert client.post("/scans/999/run").status_code == 404
    assert client.get("/targets?limit=0").status_code == 422
    assert (
        client.post(
            "/scans", headers={"Origin": "https://untrusted.test"}, json={"target_id": 1}
        ).status_code
        == 403
    )
    assert client.get("/targets", headers={"Host": "evil.test"}).status_code == 400
    allowed = client.get("/targets", headers={"Origin": "http://localhost:5174"})
    assert allowed.headers["access-control-allow-origin"] == "http://localhost:5174"


def test_public_target_requires_and_completes_ownership_verification(client):
    from app.core.target_policy import TargetPolicyError, ValidatedTarget

    def public_target(raw_url, allowed_public_hosts=()):
        if not allowed_public_hosts:
            raise TargetPolicyError("Alvo público bloqueado: domínio fora do escopo.")
        return ValidatedTarget(httpx.URL(raw_url), ("93.184.216.34",))

    with patch("app.services.ownership.validate_target", side_effect=public_target):
        created = client.post(
            "/targets",
            json={
                "name": "Public app",
                "base_url": "https://app.example.test",
                "components": [
                    {
                        "name": "Admin",
                        "kind": "WEB",
                        "url": "https://admin.example.test",
                    }
                ],
            },
        )
    assert created.status_code == 201
    target = created.json()
    assert target["ownership_verification_status"] == "PENDING"
    assert target["allowed_hosts"] == ["app.example.test", "admin.example.test"]
    assert target["components"] == [
        {"name": "Admin", "kind": "WEB", "url": "https://admin.example.test"}
    ]
    assert client.post("/scans", json={"target_id": target["id"]}).status_code == 422

    token = target["ownership_verification_token"]
    real_client = httpx.Client

    def client_factory(**kwargs):
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path == "/.well-known/dast-verification.txt"
            return httpx.Response(200, text=token)

        return real_client(transport=httpx.MockTransport(handler), **kwargs)

    with (
        patch("app.services.ownership.validate_target", side_effect=public_target),
        patch("app.services.ownership.httpx.Client", side_effect=client_factory),
    ):
        verified = client.post(f"/targets/{target['id']}/ownership-verification")
    assert verified.status_code == 200
    assert verified.json()["status"] == "VERIFIED"
    assert client.post("/scans", json={"target_id": target["id"]}).status_code == 201


def test_scan_collects_all_registered_components(client):
    created = client.post(
        "/targets",
        json={
            "name": "Multi component",
            "base_url": "http://localhost:5173",
            "api_url": "http://127.0.0.1:3001",
            "components": [
                {"name": "Admin", "kind": "WEB", "url": "http://localhost:8080"},
                {
                    "name": "Worker",
                    "kind": "SERVICE",
                    "url": "http://127.0.0.1:9090",
                },
            ],
        },
    )
    assert created.status_code == 201
    target = created.json()
    scan = client.post("/scans", json={"target_id": target["id"]}).json()

    def collected(url, *_args, **_kwargs):
        return ResponseSnapshot(url, 200, httpx.Headers({"content-type": "text/html"}), b"")

    with (
        patch("app.scanner.client.SafeHttpCollector.fetch", side_effect=collected) as fetch,
        patch(
            "app.services.scans.DiscoveryCrawler.crawl",
            return_value=DiscoveryResult.empty(),
        ) as crawl,
    ):
        completed = client.post(f"/scans/{scan['id']}/run")

    assert completed.status_code == 200
    assert [call.args[0] for call in fetch.call_args_list] == [
        "http://localhost:5173",
        "http://127.0.0.1:3001",
        "http://localhost:8080",
        "http://127.0.0.1:9090",
    ]
    assert crawl.call_args.kwargs["additional_navigation_urls"] == ["http://localhost:8080"]


def test_target_rejects_duplicate_component_urls(client):
    response = client.post(
        "/targets",
        json={
            "name": "Duplicate",
            "base_url": "http://localhost:5173",
            "components": [{"name": "Same", "kind": "WEB", "url": "http://localhost:5173"}],
        },
    )

    assert response.status_code == 422
    assert "URL única" in response.text


def test_duplicate_url_is_collected_once():
    response = ResponseSnapshot("http://localhost/", 200, httpx.Headers())
    with patch("app.scanner.client.SafeHttpCollector.fetch", return_value=response) as collect:
        result = ScannerEngine().run(["http://localhost/", "http://localhost/"])
    assert collect.call_count == 1
    assert len(result.observations) == 1


def test_scan_presets_module_catalog_and_pending_cancellation(client):
    target = client.post(
        "/targets",
        json={"name": "App genérica", "base_url": "http://localhost:5173"},
    ).json()

    catalog = client.get("/scanner/modules")
    assert catalog.status_code == 200
    assert {module["id"] for module in catalog.json()} >= {
        "discovery",
        "security_headers",
        "cookies",
        "cors",
    }
    active_modules = [module for module in catalog.json() if module["kind"] == "ACTIVE"]
    assert {module["id"] for module in active_modules} == {
        "http_methods",
        "open_redirect",
        "reflected_xss",
        "sql_injection",
        "path_traversal",
    }
    assert all(module["sends_additional_requests"] is True for module in active_modules)

    discovery = client.post("/scans", json={"target_id": target["id"], "preset": "DISCOVERY"})
    assert discovery.status_code == 201
    assert discovery.json()["preset"] == "DISCOVERY"
    assert discovery.json()["modules_enabled"] == ["discovery"]
    assert discovery.json()["phase"] == "PENDING"
    assert discovery.json()["progress_percent"] == 0

    custom = client.post(
        "/scans",
        json={
            "target_id": target["id"],
            "preset": "CUSTOM",
            "modules": ["cors", "security_headers"],
        },
    )
    assert custom.status_code == 201
    assert custom.json()["modules_enabled"] == ["discovery", "cors", "security_headers"]
    with patch("app.api.routes._run_scan_background") as background_run:
        started = client.post(f"/scans/{custom.json()['id']}/start")
    assert started.status_code == 202
    background_run.assert_called_once_with(custom.json()["id"], {})

    invalid = client.post(
        "/scans",
        json={"target_id": target["id"], "preset": "CUSTOM", "modules": ["unknown"]},
    )
    assert invalid.status_code == 422

    unconfirmed_active = client.post(
        "/scans", json={"target_id": target["id"], "preset": "SAFE_ACTIVE"}
    )
    assert unconfirmed_active.status_code == 422
    confirmed_active = client.post(
        "/scans",
        json={
            "target_id": target["id"],
            "preset": "SAFE_ACTIVE",
            "active_confirmation": True,
        },
    )
    assert confirmed_active.status_code == 201
    assert {
        "http_methods",
        "open_redirect",
        "path_traversal",
        "reflected_xss",
        "sql_injection",
    }.issubset(confirmed_active.json()["modules_enabled"])
    assert confirmed_active.json()["configuration_snapshot"]["active_confirmation"] is True

    cancelled = client.post(f"/scans/{discovery.json()['id']}/cancel")
    assert cancelled.status_code == 200
    assert cancelled.json()["status"] == "CANCELLED"
    assert cancelled.json()["phase"] == "CANCELLED"
    assert client.post(f"/scans/{discovery.json()['id']}/start").status_code == 409


def test_safe_active_findings_and_budget_are_persisted(client):
    target = client.post(
        "/targets",
        json={"name": "Safe Active", "base_url": "http://localhost:5173"},
    ).json()
    scan = client.post(
        "/scans",
        json={
            "target_id": target["id"],
            "preset": "SAFE_ACTIVE",
            "active_confirmation": True,
        },
    ).json()
    response = ResponseSnapshot(
        "http://localhost:5173/", 200, httpx.Headers({"Content-Type": "text/html"})
    )
    active_finding = FindingDraft(
        title="Redirecionamento externo controlado por parâmetro",
        description="O endpoint aceitou o destino-canário.",
        endpoint="http://localhost:5173/redirect",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        cwe="CWE-601",
        privacy_impact=PrivacyImpact.NONE,
        evidence="O parâmetro next redirecionou para o domínio reservado.",
        recommendation="Use uma allowlist de destinos.",
        issue_key="active:open-redirect:next",
        finding_type="CONFIRMED_VULNERABILITY",
    )
    with (
        patch("app.scanner.client.SafeHttpCollector.fetch", return_value=response),
        patch("app.services.scans.DiscoveryCrawler.crawl", return_value=DiscoveryResult.empty()),
        patch(
            "app.services.scans.SafeActiveEngine.run",
            return_value=ActiveScanResult([active_finding], 3, 1, False),
        ) as active_run,
    ):
        completed = client.post(f"/scans/{scan['id']}/run")

    assert completed.status_code == 200
    assert completed.json()["status"] == "COMPLETED"
    assert completed.json()["configuration_snapshot"]["active_scan"] == {
        "requests_sent": 3,
        "tested_parameters": 1,
        "request_budget": 50,
        "parameters_per_module": 5,
        "budget_truncated": False,
        "allowed_methods": ["GET", "HEAD", "OPTIONS"],
        "follow_redirects": False,
        "forms_submitted": False,
    }
    findings = client.get(f"/scans/{scan['id']}/findings").json()
    assert any(
        finding["cwe"] == "CWE-601" and finding["finding_type"] == "CONFIRMED_VULNERABILITY"
        for finding in findings
    )
    active_run.assert_called_once()


def test_openapi_import_is_added_to_scan_inventory(client):
    target = client.post(
        "/targets",
        json={
            "name": "API documentada",
            "base_url": "http://localhost:5173",
            "api_url": "http://127.0.0.1:3001/api",
        },
    ).json()
    document = {
        "openapi": "3.0.3",
        "info": {"title": "Example API", "version": "1"},
        "servers": [{"url": "http://127.0.0.1:3001/api"}],
        "paths": {
            "/users/{id}": {
                "post": {
                    "operationId": "updateUser",
                    "parameters": [{"name": "id", "in": "path"}],
                }
            }
        },
    }
    imported = client.put(
        f"/targets/{target['id']}/openapi",
        json={"filename": "openapi.json", "content": json.dumps(document)},
    )
    assert imported.status_code == 200
    assert imported.json()["operation_count"] == 1
    refreshed_target = client.get(f"/targets/{target['id']}").json()
    assert refreshed_target["openapi_title"] == "Example API"

    scan = client.post("/scans", json={"target_id": target["id"], "preset": "DISCOVERY"}).json()
    response = ResponseSnapshot("http://localhost:5173/", 200, httpx.Headers())
    with (
        patch("app.scanner.client.SafeHttpCollector.fetch", return_value=response),
        patch("app.services.scans.DiscoveryCrawler.crawl", return_value=DiscoveryResult.empty()),
    ):
        completed = client.post(f"/scans/{scan['id']}/run")
    assert completed.status_code == 200
    endpoints = client.get(f"/scans/{scan['id']}/endpoints").json()
    assert len(endpoints) == 1
    assert endpoints[0]["source"] == "OPENAPI"
    assert endpoints[0]["method"] == "POST"
    assert endpoints[0]["metadata"]["openapi_operation_id"] == "updateUser"
    assert completed.json()["configuration_snapshot"]["openapi_operations_imported"] == 1

    assert client.delete(f"/targets/{target['id']}/openapi").status_code == 204
    assert client.get(f"/targets/{target['id']}").json()["openapi_operation_count"] == 0


def test_postman_import_is_added_to_scan_inventory(client):
    target = client.post(
        "/targets",
        json={
            "name": "API Postman",
            "base_url": "http://localhost:5173",
            "api_url": "http://127.0.0.1:3001/api",
        },
    ).json()
    collection = {
        "info": {
            "name": "Users collection",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        "variable": [{"key": "baseUrl", "value": "http://127.0.0.1:3001/api"}],
        "item": [
            {
                "name": "Update user",
                "request": {
                    "method": "PUT",
                    "url": "{{baseUrl}}/users/{{id}}?notify=true",
                    "header": [{"key": "Authorization", "value": "Bearer discard-me"}],
                },
            }
        ],
    }
    imported = client.put(
        f"/targets/{target['id']}/postman",
        json={"filename": "users.json", "content": json.dumps(collection)},
    )
    assert imported.status_code == 200
    assert imported.json()["request_count"] == 1
    refreshed_target = client.get(f"/targets/{target['id']}").json()
    assert refreshed_target["postman_name"] == "Users collection"

    scan = client.post("/scans", json={"target_id": target["id"], "preset": "DISCOVERY"}).json()
    response = ResponseSnapshot("http://localhost:5173/", 200, httpx.Headers())
    with (
        patch("app.scanner.client.SafeHttpCollector.fetch", return_value=response),
        patch("app.services.scans.DiscoveryCrawler.crawl", return_value=DiscoveryResult.empty()),
    ):
        completed = client.post(f"/scans/{scan['id']}/run")
    assert completed.status_code == 200
    endpoints = client.get(f"/scans/{scan['id']}/endpoints").json()
    assert len(endpoints) == 1
    assert endpoints[0]["source"] == "POSTMAN"
    assert endpoints[0]["method"] == "PUT"
    assert endpoints[0]["path"] == "/api/users/{id}"
    assert endpoints[0]["metadata"]["postman_name"] == "Update user"
    assert completed.json()["configuration_snapshot"]["postman_requests_imported"] == 1

    assert client.delete(f"/targets/{target['id']}/postman").status_code == 204
    assert client.get(f"/targets/{target['id']}").json()["postman_request_count"] == 0


def test_manual_api_request_is_added_to_scan_inventory(client):
    target = client.post(
        "/targets",
        json={
            "name": "API manual",
            "base_url": "http://localhost:5173",
            "api_url": "http://127.0.0.1:3001/api",
        },
    ).json()
    invalid = client.post(
        f"/targets/{target['id']}/api-requests",
        json={"name": "External", "method": "GET", "path": "https://example.com/users"},
    )
    assert invalid.status_code == 422

    created = client.post(
        f"/targets/{target['id']}/api-requests",
        json={
            "name": "Update user",
            "method": "PATCH",
            "path": "/users/{id}",
            "query_parameters": ["notify"],
            "header_names": ["X-Tenant-ID", "Authorization"],
            "body_mode": "JSON",
            "content_type": "application/json; charset=utf-8",
            "requires_auth": True,
        },
    )
    assert created.status_code == 201
    template = created.json()
    assert template["content_type"] == "application/json"
    assert "value" not in json.dumps(template).lower()
    assert len(client.get(f"/targets/{target['id']}/api-requests").json()) == 1

    scan = client.post("/scans", json={"target_id": target["id"], "preset": "DISCOVERY"}).json()
    response = ResponseSnapshot("http://localhost:5173/", 200, httpx.Headers())
    with (
        patch("app.scanner.client.SafeHttpCollector.fetch", return_value=response),
        patch("app.services.scans.DiscoveryCrawler.crawl", return_value=DiscoveryResult.empty()),
    ):
        completed = client.post(f"/scans/{scan['id']}/run")
    assert completed.status_code == 200
    endpoints = client.get(f"/scans/{scan['id']}/endpoints").json()
    assert len(endpoints) == 1
    assert endpoints[0]["source"] == "MANUAL_API"
    assert endpoints[0]["method"] == "PATCH"
    assert endpoints[0]["path"] == "/users/{id}"
    assert endpoints[0]["metadata"]["manual_api_name"] == "Update user"
    assert completed.json()["configuration_snapshot"]["manual_api_requests_imported"] == 1

    removed = client.delete(f"/targets/{target['id']}/api-requests/{template['id']}")
    assert removed.status_code == 204
    assert client.get(f"/targets/{target['id']}/api-requests").json() == []


def test_manual_safe_api_requests_are_collected_and_analyzed(client):
    target = client.post(
        "/targets",
        json={
            "name": "API manual safe",
            "base_url": "http://localhost:5173",
            "api_url": "http://127.0.0.1:3001/api",
        },
    ).json()
    templates = [
        {
            "name": "Health",
            "method": "GET",
            "path": "/health",
            "query_parameters": ["verbose"],
            "header_names": ["Accept-Language"],
        },
        {"name": "Delete user", "method": "DELETE", "path": "/users/7"},
        {"name": "User by id", "method": "GET", "path": "/users/{id}"},
        {
            "name": "Private profile",
            "method": "GET",
            "path": "/me",
            "requires_auth": True,
        },
    ]
    for template in templates:
        created = client.post(f"/targets/{target['id']}/api-requests", json=template)
        assert created.status_code == 201

    scan = client.post("/scans", json={"target_id": target["id"], "preset": "PASSIVE"}).json()
    configured_response = ResponseSnapshot(
        "http://localhost:5173/", 200, httpx.Headers({"Content-Type": "text/html"})
    )
    manual_response = ResponseSnapshot(
        "http://127.0.0.1:3001/api/health",
        200,
        httpx.Headers({"Content-Type": "application/json", "Server": "manual-api/1.0"}),
        b'{"status":"ok","email":"person@example.test"}',
        "GET",
    )
    discovered_duplicate = EndpointObservation(
        url="http://127.0.0.1:3001/api/health?verbose={value}",
        path="/api/health",
        method="GET",
        source=DiscoverySource.NETWORK,
        resource_type=ResourceType.API,
    )
    discovery = DiscoveryResult.empty()
    discovery.endpoints.append(discovered_duplicate)
    with (
        patch("app.scanner.client.SafeHttpCollector.fetch", return_value=configured_response),
        patch(
            "app.services.scans.SafeHttpCollector.request", return_value=manual_response
        ) as collect_manual,
        patch("app.services.scans.DiscoveryCrawler.crawl", return_value=discovery),
    ):
        completed = client.post(f"/scans/{scan['id']}/run")

    assert completed.status_code == 200
    collect_manual.assert_called_once_with(
        "http://127.0.0.1:3001/api/health?verbose=dast",
        "GET",
        None,
        timeout_seconds=10.0,
        extra_headers={},
    )
    endpoints = client.get(f"/scans/{scan['id']}/endpoints").json()
    endpoint_by_path = {endpoint["path"]: endpoint for endpoint in endpoints}
    assert endpoint_by_path["/api/health"]["status_code"] == 200
    assert endpoint_by_path["/api/health"]["content_type"] == "application/json"
    signature = endpoint_by_path["/api/health"]["metadata"]["response_signature"]
    assert signature["approximate_size"] == len(manual_response.body or b"")
    assert len(signature["structural_fingerprint"]) == 64
    assert "person@example.test" not in str(signature)
    assert endpoint_by_path["/users/7"]["status_code"] is None
    assert endpoint_by_path["/users/{id}"]["status_code"] is None
    assert endpoint_by_path["/me"]["status_code"] is None

    snapshot = completed.json()["configuration_snapshot"]["manual_api_collection"]
    assert snapshot == {
        "eligible": 1,
        "requests_sent": 1,
        "responses_collected": 1,
        "skipped_path_templates": 1,
        "skipped_without_auth": 1,
        "skipped_unsafe_methods": 1,
        "runtime_values_supplied": 0,
        "budget_truncated": False,
        "request_budget": 20,
        "allowed_methods": ["GET", "HEAD", "OPTIONS"],
        "follow_redirects": False,
        "values_persisted": False,
        "runtime_inputs_used": [
            {
                "template_id": 1,
                "path_parameters": [],
                "query_parameters": [],
                "header_names": [],
            }
        ],
    }
    assert completed.json()["discovery_requests_observed"] == 1
    sensitive_data = client.get(f"/scans/{scan['id']}/sensitive-data").json()
    assert len(sensitive_data) == 2
    assert {item["field_path"] for item in sensitive_data} == {"email"}
    assert {item["endpoint_id"] for item in sensitive_data} == {
        endpoint_by_path["/api/health"]["id"]
    }
    findings = client.get(f"/scans/{scan['id']}/findings").json()
    assert any(
        finding["title"] == "Tecnologia divulgada em Server"
        and finding["endpoint"] == "http://127.0.0.1:3001/api/health"
        for finding in findings
    )


def test_manual_api_runtime_values_are_ephemeral_and_sanitized(client):
    target = client.post(
        "/targets",
        json={
            "name": "Parameterized API",
            "base_url": "http://localhost:5173",
            "api_url": "http://127.0.0.1:3001/api",
        },
    ).json()
    template = client.post(
        f"/targets/{target['id']}/api-requests",
        json={
            "name": "Customer detail",
            "method": "GET",
            "path": "/customers/{customer_id}",
            "query_parameters": ["expand"],
            "header_names": ["Authorization", "X-Tenant-ID"],
        },
    ).json()
    scan = client.post("/scans", json={"target_id": target["id"], "preset": "PASSIVE"}).json()
    configured_response = ResponseSnapshot(
        "http://localhost:5173/", 200, httpx.Headers({"Content-Type": "text/html"})
    )
    collected_response = ResponseSnapshot(
        "http://127.0.0.1:3001/api/customers/customer-secret?expand=private-secret",
        200,
        httpx.Headers({"Content-Type": "application/json", "Server": "runtime-api/1.0"}),
        b'{"status":"ok"}',
        "GET",
    )
    runtime_payload = {
        "manual_api_values": [
            {
                "template_id": template["id"],
                "path_parameters": {"customer_id": "customer-secret"},
                "query_parameters": {"expand": "private-secret"},
                "header_values": {
                    "Authorization": "Bearer token-secret",
                    "X-Tenant-ID": "tenant-secret",
                },
            }
        ]
    }
    with (
        patch("app.scanner.client.SafeHttpCollector.fetch", return_value=configured_response),
        patch("app.services.scans.DiscoveryCrawler.crawl", return_value=DiscoveryResult.empty()),
        patch(
            "app.services.scans.SafeHttpCollector.request", return_value=collected_response
        ) as collect_manual,
        patch("app.api.routes._run_scan_background") as background_run,
    ):
        started = client.post(f"/scans/{scan['id']}/start", json=runtime_payload)
        scheduled_values = background_run.call_args.args[1]
        assert scheduled_values[template["id"]].path_parameters == {
            "customer_id": "customer-secret"
        }
        completed = client.post(f"/scans/{scan['id']}/run", json=runtime_payload)

    assert started.status_code == 202
    assert completed.json()["status"] == "COMPLETED"
    collect_manual.assert_called_once_with(
        "http://127.0.0.1:3001/api/customers/customer-secret?expand=private-secret",
        "GET",
        None,
        timeout_seconds=10.0,
        extra_headers={
            "Authorization": "Bearer token-secret",
            "X-Tenant-ID": "tenant-secret",
        },
    )
    endpoints = client.get(f"/scans/{scan['id']}/endpoints").json()
    assert endpoints[0]["path"] == "/customers/{customer_id}"
    assert endpoints[0]["status_code"] == 200
    findings = client.get(f"/scans/{scan['id']}/findings").json()
    persisted = json.dumps({"scan": completed.json(), "endpoints": endpoints, "findings": findings})
    for secret in (
        "customer-secret",
        "private-secret",
        "token-secret",
        "tenant-secret",
    ):
        assert secret not in persisted
    collection = completed.json()["configuration_snapshot"]["manual_api_collection"]
    assert collection["runtime_values_supplied"] == 1
    assert collection["runtime_inputs_used"] == [
        {
            "template_id": template["id"],
            "path_parameters": ["customer_id"],
            "query_parameters": ["expand"],
            "header_names": ["Authorization", "X-Tenant-ID"],
        }
    ]
    assert collection["values_persisted"] is False

    invalid_scan = client.post(
        "/scans", json={"target_id": target["id"], "preset": "PASSIVE"}
    ).json()
    invalid = client.post(
        f"/scans/{invalid_scan['id']}/run",
        json={
            "manual_api_values": [
                {
                    "template_id": template["id"],
                    "query_parameters": {"undeclared": "do-not-use"},
                }
            ]
        },
    )
    assert invalid.status_code == 422
    assert client.get(f"/scans/{invalid_scan['id']}").json()["status"] == "PENDING"
