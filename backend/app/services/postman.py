import json
import re
from typing import NotRequired, TypedDict, cast
from urllib.parse import parse_qsl, urljoin, urlsplit

from app.core.target_policy import TargetPolicyError, validate_target
from app.crawler.models import EndpointObservation
from app.crawler.normalizer import URLNormalizationError, normalize_method, normalize_url
from app.models import Target
from app.models.enums import DiscoverySource, ResourceType
from app.services.ownership import verified_public_hosts

MAX_COLLECTION_BYTES = 2_000_000
MAX_REQUESTS = 2_000
MAX_FOLDER_DEPTH = 20
POSTMAN_SCHEMAS = ("v2.0.0", "v2.1.0")
VARIABLE_PATTERN = re.compile(r"{{\s*([A-Za-z0-9_.-]{1,128})\s*}}")
PATH_VARIABLE_PATTERN = re.compile(r"(?<=/):([A-Za-z0-9_.-]{1,128})(?=/|$)")
MEDIA_TYPE_PATTERN = re.compile(r"^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+$")


class PostmanImportError(ValueError):
    pass


class PostmanOperation(TypedDict):
    name: str
    method: str
    path: str
    parameters: dict[str, list[str]]
    body_mode: str
    content_type: str | None
    requires_auth: bool
    folder_path: list[str]


class NormalizedPostmanDocument(TypedDict):
    format: str
    version: str
    name: str
    base_url: str
    operations: list[PostmanOperation]
    source_filename: NotRequired[str | None]


def _mapping(value: object) -> dict[str, object]:
    return cast(dict[str, object], value) if isinstance(value, dict) else {}


def _sequence(value: object) -> list[object]:
    return cast(list[object], value) if isinstance(value, list) else []


def _clean_name(value: object, fallback: str, maximum: int = 240) -> str:
    if not isinstance(value, str):
        return fallback
    clean = re.sub(r"[\x00-\x1f\x7f]", "", value).strip()
    return clean[:maximum] or fallback


def _collection_version(schema: object) -> str:
    if not isinstance(schema, str):
        raise PostmanImportError("A coleção precisa declarar o schema Postman v2.0 ou v2.1.")
    version = next((item for item in POSTMAN_SCHEMAS if item in schema), None)
    if version is None:
        raise PostmanImportError("Use uma coleção Postman v2.0 ou v2.1.")
    return version


def _variables(document: dict[str, object]) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in _sequence(document.get("variable")):
        item = _mapping(raw)
        key, value = item.get("key"), item.get("value")
        if isinstance(key, str) and isinstance(value, (str, int, float, bool)):
            values[key.strip()] = str(value)
    return values


def _raw_url(value: object) -> str:
    if isinstance(value, str):
        return value
    url = _mapping(value)
    if isinstance(url.get("raw"), str):
        return str(url["raw"])
    protocol = str(url.get("protocol") or "http")
    host_value = url.get("host")
    host = (
        ".".join(str(part) for part in host_value)
        if isinstance(host_value, list)
        else str(host_value or "")
    )
    path_value = url.get("path")
    path = (
        "/".join(str(part) for part in path_value)
        if isinstance(path_value, list)
        else str(path_value or "")
    )
    port = f":{url['port']}" if url.get("port") else ""
    query = [
        str(_mapping(item).get("key"))
        for item in _sequence(url.get("query"))
        if _mapping(item).get("disabled") is not True and _mapping(item).get("key")
    ]
    suffix = "?" + "&".join(f"{name}=" for name in query) if query else ""
    return f"{protocol}://{host}{port}/{path.lstrip('/')}{suffix}"


def _resolve_url(raw_url: str, values: dict[str, str], fallback: str) -> tuple[str, str]:
    common_base_names = {"baseurl", "base_url", "url", "host", "apiurl", "api_url"}

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name.casefold() in common_base_names:
            return values.get(name, fallback.rstrip("/"))
        return f"__DAST_PARAM_{name}__"

    resolved_with_markers = VARIABLE_PATTERN.sub(replace, raw_url.strip())
    absolute_with_markers = urljoin(fallback.rstrip("/") + "/", resolved_with_markers)
    parts = urlsplit(absolute_with_markers)
    template_path = PATH_VARIABLE_PATTERN.sub(r"{\1}", parts.path or "/")
    template_path = re.sub(r"__DAST_PARAM_([A-Za-z0-9_.-]+)__", r"{\1}", template_path)
    safe_url = re.sub(r"__DAST_PARAM_[A-Za-z0-9_.-]+__", "dast", absolute_with_markers)
    return safe_url, template_path[:2048]


def _auth_required(auth_value: object, inherited: bool) -> bool:
    if auth_value is None:
        return inherited
    auth = _mapping(auth_value)
    auth_type = auth.get("type")
    return isinstance(auth_type, str) and auth_type.casefold() != "noauth"


def _parameter_names(request: dict[str, object], raw_url: str, path: str) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    path_names = re.findall(r"{([A-Za-z0-9_.-]{1,128})}", path)
    if path_names:
        result["path"] = list(dict.fromkeys(path_names))
    query_names = [
        name[:128] for name, _ in parse_qsl(urlsplit(raw_url).query, keep_blank_values=True) if name
    ]
    url_object = _mapping(request.get("url"))
    query_names.extend(
        str(_mapping(item).get("key"))[:128]
        for item in _sequence(url_object.get("query"))
        if _mapping(item).get("disabled") is not True and _mapping(item).get("key")
    )
    if query_names:
        result["query"] = list(dict.fromkeys(query_names))
    header_names = [
        str(_mapping(item).get("key"))[:128]
        for item in _sequence(request.get("header"))
        if _mapping(item).get("disabled") is not True and _mapping(item).get("key")
    ]
    if header_names:
        result["header"] = list(dict.fromkeys(header_names))
    return result


def _content_type(request: dict[str, object]) -> str | None:
    for raw in _sequence(request.get("header")):
        header = _mapping(raw)
        if str(header.get("key") or "").casefold() != "content-type":
            continue
        value = str(header.get("value") or "").split(";", 1)[0].strip().lower()
        return value[:128] if MEDIA_TYPE_PATTERN.fullmatch(value) else None
    return None


def parse_postman_collection(
    content: str, target: Target, filename: str | None = None
) -> NormalizedPostmanDocument:
    if not content.strip():
        raise PostmanImportError("A coleção Postman está vazia.")
    if len(content.encode("utf-8")) > MAX_COLLECTION_BYTES:
        raise PostmanImportError("A coleção Postman excede o limite de 2 MB.")
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError as exc:
        raise PostmanImportError("O arquivo não contém JSON válido.") from exc
    if not isinstance(parsed, dict):
        raise PostmanImportError("A raiz da coleção Postman deve ser um objeto.")
    document = cast(dict[str, object], parsed)
    info = _mapping(document.get("info"))
    version = _collection_version(info.get("schema"))
    name = _clean_name(info.get("name"), "Coleção sem nome")
    fallback = target.api_url or target.base_url
    allowed_origins = {normalize_url(target.base_url).origin}
    if target.api_url:
        allowed_origins.add(normalize_url(target.api_url).origin)
    values = _variables(document)
    operations: list[PostmanOperation] = []

    def visit(items: object, folders: list[str], inherited_auth: bool, depth: int) -> None:
        if depth > MAX_FOLDER_DEPTH:
            raise PostmanImportError(f"A coleção excede {MAX_FOLDER_DEPTH} níveis de pastas.")
        for raw_item in _sequence(items):
            item = _mapping(raw_item)
            item_auth = _auth_required(item.get("auth"), inherited_auth)
            if "request" not in item and isinstance(item.get("item"), list):
                folder = _clean_name(item.get("name"), "Pasta", 120)
                visit(item.get("item"), [*folders, folder], item_auth, depth + 1)
                continue
            request = _mapping(item.get("request"))
            if not request:
                continue
            raw_url = _raw_url(request.get("url"))
            if not raw_url:
                continue
            safe_url, path_template = _resolve_url(raw_url, values, fallback)
            try:
                validate_target(safe_url, verified_public_hosts(target))
                normalized = normalize_url(safe_url)
            except (TargetPolicyError, URLNormalizationError, ValueError) as exc:
                raise PostmanImportError(
                    "Uma requisição da coleção possui URL inválida ou não permitida."
                ) from exc
            if normalized.origin not in allowed_origins:
                raise PostmanImportError(
                    "Todas as requisições Postman precisam usar a origem do frontend "
                    "ou da API cadastrada."
                )
            method = normalize_method(str(request.get("method") or "GET"))
            body_mode = str(_mapping(request.get("body")).get("mode") or "none").lower()
            if body_mode not in {"raw", "urlencoded", "formdata", "graphql", "file", "none"}:
                body_mode = "other"
            operations.append(
                {
                    "name": _clean_name(item.get("name"), f"{method} {path_template}"),
                    "method": method,
                    "path": path_template,
                    "parameters": _parameter_names(request, raw_url, path_template),
                    "body_mode": body_mode,
                    "content_type": _content_type(request),
                    "requires_auth": _auth_required(request.get("auth"), item_auth),
                    "folder_path": folders[:MAX_FOLDER_DEPTH],
                }
            )
            if len(operations) > MAX_REQUESTS:
                raise PostmanImportError(
                    f"A coleção excede o limite de {MAX_REQUESTS} requisições."
                )

    visit(document.get("item"), [], _auth_required(document.get("auth"), False), 1)
    if not operations:
        raise PostmanImportError("Nenhuma requisição HTTP válida foi encontrada na coleção.")
    return {
        "format": "postman_collection",
        "version": version,
        "name": name,
        "base_url": normalize_url(fallback).url,
        "operations": operations,
        "source_filename": filename[:255] if filename else None,
    }


def postman_endpoints(document: dict[str, object]) -> list[EndpointObservation]:
    base_url = str(document.get("base_url") or "")
    endpoints: list[EndpointObservation] = []
    for raw in _sequence(document.get("operations")):
        operation = _mapping(raw)
        path, method = operation.get("path"), operation.get("method")
        if not isinstance(path, str) or not isinstance(method, str):
            continue
        raw_content_type = operation.get("content_type")
        content_type = raw_content_type if isinstance(raw_content_type, str) else None
        executable_path = re.sub(r"{[A-Za-z0-9_.-]+}", "dast", path)
        normalized = normalize_url(executable_path.lstrip("/"), base_url.rstrip("/") + "/")
        endpoints.append(
            EndpointObservation(
                url=normalized.url,
                path=path,
                method=method,
                source=DiscoverySource.POSTMAN,
                resource_type=ResourceType.API,
                content_type=content_type,
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
                    "postman_name": operation.get("name"),
                    "postman_folder_path": operation.get("folder_path") or [],
                    "postman_body_mode": operation.get("body_mode"),
                    "postman_path_template": path,
                },
            )
        )
    return endpoints
