import re
from dataclasses import dataclass, field
from urllib.parse import quote, urlencode, urljoin, urlsplit, urlunsplit

from app.crawler.models import EndpointObservation
from app.crawler.normalizer import normalize_url
from app.models import ApiRequestTemplate, Target
from app.models.enums import DiscoverySource, ResourceType

FORBIDDEN_RUNTIME_HEADERS = {
    "connection",
    "content-length",
    "host",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


class ManualApiRuntimeError(ValueError):
    pass


@dataclass(frozen=True)
class ManualApiRuntimeValues:
    path_parameters: dict[str, str] = field(default_factory=dict)
    query_parameters: dict[str, str] = field(default_factory=dict)
    header_values: dict[str, str] = field(default_factory=dict)

    @property
    def supplied(self) -> bool:
        return bool(self.path_parameters or self.query_parameters or self.header_values)


def validate_manual_api_runtime_values(
    templates: list[ApiRequestTemplate],
    values: dict[int, ManualApiRuntimeValues],
) -> dict[int, ManualApiRuntimeValues]:
    templates_by_id = {template.id: template for template in templates}
    for template_id, runtime in values.items():
        template = templates_by_id.get(template_id)
        if template is None:
            raise ManualApiRuntimeError("Template de API temporário não pertence ao alvo do scan.")
        if template.method not in {"GET", "HEAD", "OPTIONS"}:
            raise ManualApiRuntimeError(
                "Valores temporários são aceitos somente para GET, HEAD e OPTIONS."
            )
        path_names = set(re.findall(r"{([A-Za-z_][A-Za-z0-9_.-]{0,127})}", template.path))
        _require_declared_names("caminho", set(runtime.path_parameters), path_names)
        _require_declared_names(
            "query", set(runtime.query_parameters), set(template.query_parameters)
        )
        _require_declared_names("header", set(runtime.header_values), set(template.header_names))
        forbidden = {
            name for name in runtime.header_values if name.casefold() in FORBIDDEN_RUNTIME_HEADERS
        }
        if forbidden:
            raise ManualApiRuntimeError("Um header temporário reservado foi informado.")
        if any(
            value in {".", ".."} or "/" in value or "\\" in value
            for value in runtime.path_parameters.values()
        ):
            raise ManualApiRuntimeError(
                "Valores temporários de path não podem alterar segmentos da rota."
            )
    return values


def materialize_manual_api_request(
    target: Target,
    template: ApiRequestTemplate,
    runtime: ManualApiRuntimeValues,
) -> tuple[str, dict[str, str]] | None:
    path_names = re.findall(r"{([A-Za-z_][A-Za-z0-9_.-]{0,127})}", template.path)
    if any(name not in runtime.path_parameters for name in path_names):
        return None
    path = template.path
    for name in path_names:
        path = path.replace(f"{{{name}}}", quote(runtime.path_parameters[name], safe=""))
    base_url = (target.api_url or target.base_url).rstrip("/") + "/"
    url = urljoin(base_url, path.lstrip("/"))
    query = urlencode(
        [(name, runtime.query_parameters.get(name, "dast")) for name in template.query_parameters]
    )
    if query:
        parts = urlsplit(url)
        url = urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))
    return url, dict(runtime.header_values)


def manual_api_report_endpoint(target: Target, template: ApiRequestTemplate) -> str:
    base_url = (target.api_url or target.base_url).rstrip("/") + "/"
    return urljoin(base_url, template.path.lstrip("/"))


def _require_declared_names(label: str, provided: set[str], declared: set[str]) -> None:
    if not provided <= declared:
        raise ManualApiRuntimeError(f"Parâmetro temporário de {label} não declarado no template.")


def manual_api_endpoints(
    target: Target, templates: list[ApiRequestTemplate]
) -> list[EndpointObservation]:
    base_url = target.api_url or target.base_url
    endpoints: list[EndpointObservation] = []
    for template in templates:
        executable_path = re.sub(r"{[A-Za-z_][A-Za-z0-9_.-]{0,127}}", "dast", template.path)
        query = urlencode([(name, "") for name in template.query_parameters])
        relative_url = executable_path.lstrip("/") + (f"?{query}" if query else "")
        normalized = normalize_url(relative_url, base_url.rstrip("/") + "/")
        path_parameters = re.findall(r"{([A-Za-z_][A-Za-z0-9_.-]{0,127})}", template.path)
        parameters: dict[str, object] = {}
        if path_parameters:
            parameters["path"] = [{"name": name, "location": "path"} for name in path_parameters]
        if template.query_parameters:
            parameters["query"] = [
                {"name": name, "location": "query"} for name in template.query_parameters
            ]
        if template.header_names:
            parameters["header"] = [
                {"name": name, "location": "header"} for name in template.header_names
            ]
        endpoints.append(
            EndpointObservation(
                url=normalized.url,
                path=template.path,
                method=template.method,
                source=DiscoverySource.MANUAL_API,
                resource_type=ResourceType.API,
                content_type=template.content_type,
                requires_auth=template.requires_auth,
                parameters=parameters or None,
                metadata={
                    "manual_api_template_id": template.id,
                    "manual_api_name": template.name,
                    "manual_api_body_mode": template.body_mode,
                    "path_template": template.path,
                },
            )
        )
    return endpoints
