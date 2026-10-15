import json

import pytest

from app.models import Target
from app.models.enums import DiscoverySource
from app.services.postman import (
    PostmanImportError,
    parse_postman_collection,
    postman_endpoints,
)


@pytest.fixture
def target() -> Target:
    return Target(
        name="API",
        base_url="http://localhost:5173",
        api_url="http://127.0.0.1:3001/api",
    )


def test_postman_collection_is_normalized_without_secret_values(target):
    content = json.dumps(
        {
            "info": {
                "name": "Orders",
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
            },
            "variable": [
                {"key": "baseUrl", "value": "http://127.0.0.1:3001/api"},
                {"key": "token", "value": "super-secret-token"},
                {"key": "orderId", "value": "sensitive-order-42"},
            ],
            "auth": {"type": "bearer", "bearer": [{"key": "token", "value": "{{token}}"}]},
            "item": [
                {
                    "name": "Orders folder",
                    "item": [
                        {
                            "name": "Update order",
                            "request": {
                                "method": "PATCH",
                                "header": [
                                    {"key": "Authorization", "value": "Bearer super-secret-token"},
                                    {"key": "Content-Type", "value": "application/json"},
                                ],
                                "body": {"mode": "raw", "raw": '{"password":"dont-store"}'},
                                "url": "{{baseUrl}}/orders/{{orderId}}?expand=customer",
                            },
                            "event": [{"listen": "test", "script": {"exec": ["secret script"]}}],
                            "response": [{"body": "secret response"}],
                        }
                    ],
                }
            ],
        }
    )

    document = parse_postman_collection(content, target, "orders.postman_collection.json")
    serialized = json.dumps(document)
    assert document["name"] == "Orders"
    assert document["version"] == "v2.1.0"
    assert len(document["operations"]) == 1
    operation = document["operations"][0]
    assert operation["path"] == "/api/orders/{orderId}"
    assert operation["method"] == "PATCH"
    assert operation["parameters"] == {
        "path": ["orderId"],
        "query": ["expand"],
        "header": ["Authorization", "Content-Type"],
    }
    assert operation["body_mode"] == "raw"
    assert operation["content_type"] == "application/json"
    assert operation["requires_auth"] is True
    assert operation["folder_path"] == ["Orders folder"]
    for secret in (
        "super-secret-token",
        "sensitive-order-42",
        "dont-store",
        "secret script",
        "secret response",
    ):
        assert secret not in serialized

    endpoints = postman_endpoints(dict(document))
    assert endpoints[0].source == DiscoverySource.POSTMAN
    assert endpoints[0].method == "PATCH"
    assert endpoints[0].path == "/api/orders/{orderId}"
    assert endpoints[0].metadata["postman_path_template"] == "/api/orders/{orderId}"


def test_postman_rejects_external_origin_and_unsupported_schema(target):
    external = {
        "info": {
            "name": "External",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        "item": [
            {"name": "Bad", "request": {"method": "GET", "url": "https://example.com/users"}}
        ],
    }
    with pytest.raises(PostmanImportError, match="URL inválida|origem"):
        parse_postman_collection(json.dumps(external), target)

    external["info"]["schema"] = "https://example.com/v1/collection.json"
    with pytest.raises(PostmanImportError, match="v2.0 ou v2.1"):
        parse_postman_collection(json.dumps(external), target)
