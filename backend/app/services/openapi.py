import json
from typing import NotRequired, TypedDict, cast
from urllib.parse import urljoin

import yaml

from app.core.target_policy import TargetPolicyError, validate_target
from app.crawler.models import EndpointObservation
from app.crawler.normalizer import normalize_url
from app.models import Target
from app.models.enums import DiscoverySource, ResourceType
from app.services.ownership import verified_public_hosts
from app.services.target_components import target_urls

MAX_SPEC_BYTES = 2_000_000
MAX_PATHS = 500
MAX_OPERATIONS = 2_000
HTTP_METHODS = ("get", "post", "put", "patch", "delete", "options", "head", "trace")


class OpenApiImportError(ValueError):
    pass


class OpenApiOperation(TypedDict):
    path: str
    method: str
    operation_id: str | None
    tags: list[str]
    parameters: dict[str, list[str]]
    requires_auth: bool
    deprecated: bool


class NormalizedOpenApiDocument(TypedDict):
    format: str
    version: str
    title: str
    base_url: str
    operations: list[OpenApiOperation]
    source_filename: NotRequired[str | None]


def _mapping(value: object) -> dict[str, object]:
    return cast(dict[str, object], value) if isinstance(value, dict) else {}


def _sequence(value: object) -> list[object]:
    return cast(list[object], value) if isinstance(value, list) else []


def _read_document(content: str) -> dict[str, object]:
    if not content.strip():
        raise OpenApiImportError("O documento OpenAPI está vazio.")
    if len(content.encode("utf-8")) > MAX_SPEC_BYTES:
        raise OpenApiImportError("O documento OpenAPI excede o limite de 2 MB.")
    try:
        parsed = (
            json.loads(content)
            if content.lstrip().startswith(("{", "["))
            else yaml.safe_load(content)
        )
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise OpenApiImportError("O arquivo não contém JSON ou YAML válido.") from exc
    if not isinstance(parsed, dict):
        raise OpenApiImportError("A raiz do documento OpenAPI deve ser um objeto.")
    return cast(dict[str, object], parsed)


def _server_url(document: dict[str, object], target: Target, is_swagger: bool) -> str:
    fallback = target.api_url or target.base_url
    raw_server = fallback
    if is_swagger:
        host = document.get("host")
        base_path = str(document.get("basePath") or "/")
        schemes = _sequence(document.get("schemes"))
        if isinstance(host, str) and host:
            scheme = str(schemes[0]) if schemes else normalize_url(fallback).url.split(":", 1)[0]
            raw_server = f"{scheme}://{host}{base_path}"
    else:
        servers = _sequence(document.get("servers"))
        first = _mapping(servers[0]) if servers else {}
        candidate = first.get("url")
        if isinstance(candidate, str) and candidate:
            variables = _mapping(first.get("variables"))
            for name, definition in variables.items():
                default = _mapping(definition).get("default")
                if default is not None:
                    candidate = candidate.replace(f"{{{name}}}", str(default))
            raw_server = urljoin(fallback.rstrip("/") + "/", candidate)
    try:
        validate_target(raw_server, verified_public_hosts(target))
        normalized = normalize_url(raw_server)
    except (TargetPolicyError, ValueError) as exc:
        raise OpenApiImportError(
            "O servidor declarado no OpenAPI não é um alvo permitido."
        ) from exc
    allowed_origins = {normalize_url(url).origin for url in target_urls(target)}
    if normalized.origin not in allowed_origins:
        raise OpenApiImportError(
            "O servidor declarado no OpenAPI precisa usar a origem do frontend "
            "ou de um componente cadastrado."
        )
    return normalized.url


def _parameters(*groups: object) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for group in groups:
        for parameter in _sequence(group):
            item = _mapping(parameter)
            name = item.get("name")
            location = item.get("in")
            if isinstance(name, str) and isinstance(location, str):
                clean_name = name.strip()[:128]
                clean_location = location.strip().lower()[:32]
                if clean_name and clean_location in {"path", "query", "header", "cookie"}:
                    result.setdefault(clean_location, [])
                    if clean_name not in result[clean_location]:
                        result[clean_location].append(clean_name)
    return result


def parse_openapi(
    content: str, target: Target, filename: str | None = None
) -> NormalizedOpenApiDocument:
    document = _read_document(content)
    openapi_version = document.get("openapi")
    swagger_version = document.get("swagger")
    is_swagger = str(swagger_version) == "2.0"
    valid_openapi = isinstance(openapi_version, str) and openapi_version.startswith("3.")
    if not valid_openapi and not is_swagger:
        raise OpenApiImportError("Use OpenAPI 3.x ou Swagger 2.0.")
    version = str(swagger_version if is_swagger else openapi_version)[:40]
    info = _mapping(document.get("info"))
    title = str(info.get("title") or "API sem título").strip()[:240]
    paths = _mapping(document.get("paths"))
    if not paths:
        raise OpenApiImportError("O documento não possui operações em paths.")
    if len(paths) > MAX_PATHS:
        raise OpenApiImportError(f"O documento excede o limite de {MAX_PATHS} paths.")
    base_url = _server_url(document, target, is_swagger)
    global_security = document.get("security")
    operations: list[OpenApiOperation] = []
    for raw_path, raw_path_item in paths.items():
        if not isinstance(raw_path, str) or not raw_path.startswith("/"):
            continue
        path_item = _mapping(raw_path_item)
        for method in HTTP_METHODS:
            operation = _mapping(path_item.get(method))
            if not operation:
                continue
            tags = [
                str(tag)[:80] for tag in _sequence(operation.get("tags")) if isinstance(tag, str)
            ]
            security = operation.get("security", global_security)
            operations.append(
                {
                    "path": raw_path[:2048],
                    "method": method.upper(),
                    "operation_id": (
                        str(operation["operationId"])[:240]
                        if operation.get("operationId") is not None
                        else None
                    ),
                    "tags": tags[:20],
                    "parameters": _parameters(
                        path_item.get("parameters"), operation.get("parameters")
                    ),
                    "requires_auth": bool(_sequence(security)),
                    "deprecated": operation.get("deprecated") is True,
                }
            )
            if len(operations) > MAX_OPERATIONS:
                raise OpenApiImportError(
                    f"O documento excede o limite de {MAX_OPERATIONS} operações."
                )
    if not operations:
        raise OpenApiImportError("Nenhuma operação HTTP válida foi encontrada.")
    return {
        "format": "swagger" if is_swagger else "openapi",
        "version": version,
        "title": title,
        "base_url": base_url,
        "operations": operations,
        "source_filename": filename[:255] if filename else None,
    }


def openapi_endpoints(document: dict[str, object]) -> list[EndpointObservation]:
    base_url = str(document.get("base_url") or "")
    endpoints: list[EndpointObservation] = []
    for raw in _sequence(document.get("operations")):
        operation = _mapping(raw)
        path = operation.get("path")
        method = operation.get("method")
        if not isinstance(path, str) or not isinstance(method, str):
            continue
        normalized = normalize_url(path.lstrip("/"), base_url.rstrip("/") + "/")
        endpoints.append(
            EndpointObservation(
                url=normalized.url,
                path=normalized.path,
                method=method,
                source=DiscoverySource.OPENAPI,
                resource_type=ResourceType.API,
                requires_auth=operation.get("requires_auth") is True,
                parameters={
                    location: [
                        {"name": name, "location": location}
                        for name in names
                        if isinstance(name, str)
                    ]
                    for location, names in _mapping(operation.get("parameters")).items()
                    if isinstance(names, list)
                }
                or None,
                metadata={
                    "openapi_operation_id": operation.get("operation_id"),
                    "openapi_tags": operation.get("tags") or [],
                    "openapi_deprecated": operation.get("deprecated") is True,
                    "openapi_path_template": path,
                },
            )
        )
    return endpoints
