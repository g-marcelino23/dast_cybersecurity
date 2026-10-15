import json

import pytest

from app.models import Target
from app.models.enums import DiscoverySource
from app.services.openapi import OpenApiImportError, openapi_endpoints, parse_openapi


@pytest.fixture
def target() -> Target:
    return Target(
        name="API",
        base_url="http://localhost:5173",
        api_url="http://127.0.0.1:3001/api",
    )


def test_openapi_json_is_normalized_without_examples_or_secrets(target):
    content = json.dumps(
        {
            "openapi": "3.1.0",
            "info": {"title": "Orders", "version": "1.0"},
            "servers": [{"url": "http://127.0.0.1:3001/api"}],
            "security": [{"bearer": []}],
            "paths": {
                "/orders/{id}": {
                    "parameters": [{"name": "id", "in": "path", "required": True}],
                    "get": {
                        "operationId": "getOrder",
                        "tags": ["orders"],
                        "parameters": [{"name": "include", "in": "query"}],
                        "x-secret-example": "must-not-be-stored",
                    },
                    "delete": {"operationId": "deleteOrder", "security": []},
                }
            },
        }
    )
    document = parse_openapi(content, target, "orders.json")
    assert document["title"] == "Orders"
    assert len(document["operations"]) == 2
    assert "must-not-be-stored" not in json.dumps(document)
    get_operation = next(item for item in document["operations"] if item["method"] == "GET")
    assert get_operation["requires_auth"] is True
    assert get_operation["parameters"] == {"path": ["id"], "query": ["include"]}
    endpoints = openapi_endpoints(dict(document))
    assert endpoints[0].source == DiscoverySource.OPENAPI
    assert all(endpoint.status_code is None for endpoint in endpoints)


def test_swagger_yaml_and_scope_validation(target):
    document = parse_openapi(
        """
swagger: '2.0'
info:
  title: Legacy API
  version: '1'
host: 127.0.0.1:3001
basePath: /v1
schemes: [http]
paths:
  /users:
    get:
      operationId: listUsers
""",
        target,
    )
    assert document["format"] == "swagger"
    assert document["base_url"] == "http://127.0.0.1:3001/v1"

    public_server = json.dumps(
        {
            "openapi": "3.0.0",
            "info": {"title": "Bad", "version": "1"},
            "servers": [{"url": "https://example.com"}],
            "paths": {"/": {"get": {}}},
        }
    )
    with pytest.raises(OpenApiImportError):
        parse_openapi(public_server, target)
