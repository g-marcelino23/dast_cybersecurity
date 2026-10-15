from collections.abc import Callable, Collection
from dataclasses import dataclass
from hashlib import sha256
from time import sleep
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from app.core.config import Settings, get_settings
from app.crawler.browser import AuthContext
from app.crawler.models import EndpointObservation
from app.models.enums import Confidence, PrivacyImpact, ResourceType, Severity
from app.scanner.base import ResponseSnapshot
from app.scanner.client import SafeHttpCollector
from app.schemas.entities import FindingDraft

ACTIVE_MODULE_IDS = frozenset(
    {
        "http_methods",
        "open_redirect",
        "path_traversal",
        "reflected_xss",
        "sql_injection",
    }
)
REDIRECT_PARAMETER_NAMES = frozenset(
    {
        "callback",
        "continue",
        "dest",
        "destination",
        "next",
        "redirect",
        "redirect_to",
        "redirect_uri",
        "return",
        "return_to",
        "url",
        "uri",
    }
)
DANGEROUS_METHODS = frozenset({"CONNECT", "DELETE", "PATCH", "PUT", "TRACE"})
PATH_PARAMETER_NAMES = frozenset(
    {
        "directory",
        "document",
        "download",
        "file",
        "filename",
        "filepath",
        "folder",
        "include",
        "page",
        "path",
        "resource",
        "template",
    }
)
SQL_ERROR_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"sql syntax", "erro de sintaxe SQL"),
    (b"syntax error at or near", "erro de sintaxe PostgreSQL"),
    (b"unterminated quoted string", "string SQL não terminada"),
    (b"unclosed quotation mark", "aspas SQL não fechadas"),
    (b"sqlite_error", "erro SQLite"),
    (b"sqlite3.operationalerror", "erro SQLite"),
    (b"mysql_fetch", "erro MySQL"),
    (b"sqlstate[", "erro SQLSTATE"),
    (b"ora-01756", "erro Oracle"),
    (b"ora-00933", "erro Oracle"),
    (b"microsoft ole db provider for sql server", "erro SQL Server"),
)


@dataclass(frozen=True)
class ActiveScanResult:
    findings: list[FindingDraft]
    requests_sent: int
    tested_parameters: int
    truncated: bool


class SafeActiveEngine:
    """Bounded, non-destructive probes for explicitly confirmed local targets."""

    def __init__(
        self,
        collector: SafeHttpCollector | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.collector = collector or SafeHttpCollector()
        self.settings = settings or get_settings()

    def run(
        self,
        endpoints: list[EndpointObservation],
        roots: list[str],
        auth: AuthContext | None,
        enabled_modules: list[str],
        before_request: Callable[[str], None] | None = None,
        allowed_public_hosts: Collection[str] = (),
    ) -> ActiveScanResult:
        selected = set(enabled_modules) & ACTIVE_MODULE_IDS
        if not selected:
            return ActiveScanResult([], 0, 0, False)
        findings: list[FindingDraft] = []
        requests_sent = 0
        tested_parameters = 0
        truncated = False
        budget = self.settings.active_max_requests

        def request(url: str, method: str, module_id: str) -> ResponseSnapshot | None:
            nonlocal requests_sent, truncated
            if requests_sent >= budget:
                truncated = True
                return None
            if before_request:
                before_request(module_id)
            if requests_sent and self.settings.active_request_delay_ms:
                sleep(self.settings.active_request_delay_ms / 1000)
            requests_sent += 1
            try:
                if not allowed_public_hosts:
                    return self.collector.request(
                        url,
                        method,
                        auth,
                        timeout_seconds=self.settings.active_request_timeout,
                    )
                return self.collector.request(
                    url,
                    method,
                    auth,
                    timeout_seconds=self.settings.active_request_timeout,
                    allowed_public_hosts=allowed_public_hosts,
                )
            except httpx.HTTPError:
                return None

        if "http_methods" in selected:
            endpoint_urls = [
                item.url
                for item in endpoints
                if item.resource_type in {ResourceType.PAGE, ResourceType.API}
                and not self._has_path_template(item)
            ]
            candidates = list(dict.fromkeys([*roots, *endpoint_urls]))
            for url in candidates[: self.settings.active_max_endpoints]:
                response = request(self._without_template_query(url), "OPTIONS", "http_methods")
                if response is None:
                    if truncated:
                        break
                    continue
                advertised = self._advertised_methods(response.headers)
                dangerous = sorted(advertised & DANGEROUS_METHODS)
                if dangerous:
                    findings.append(self._http_methods_finding(response.endpoint, dangerous))

        parameter_candidates = self._parameter_candidates(endpoints)
        per_module_candidates = parameter_candidates[
            : self.settings.active_max_parameters_per_module
        ]
        if "open_redirect" in selected:
            for url, parameter in per_module_candidates:
                if parameter.casefold() not in REDIRECT_PARAMETER_NAMES:
                    continue
                marker = self._marker("redirect", url, parameter)
                probe = f"https://dast.invalid/{marker}"
                response = request(
                    self._with_parameter(url, parameter, probe), "GET", "open_redirect"
                )
                if response is None:
                    if truncated:
                        break
                    continue
                tested_parameters += 1
                location = response.headers.get("location", "")
                if 300 <= response.status_code < 400 and self._is_canary_redirect(location, marker):
                    findings.append(self._open_redirect_finding(response.endpoint, parameter))

        if "path_traversal" in selected:
            for url, parameter in per_module_candidates:
                if parameter.casefold() not in PATH_PARAMETER_NAMES:
                    continue
                matched_family: str | None = None
                parameter_tested = False
                response_endpoint = self._without_template_query(url)
                probes = (
                    (
                        "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                        "arquivo de contas Unix",
                    ),
                    (
                        "%2e%2e%5c%2e%2e%5c%2e%2e%5cWindows%5cwin.ini",
                        "arquivo de configuração Windows",
                    ),
                )
                for payload, family in probes:
                    response = request(
                        self._with_parameter(url, parameter, payload),
                        "GET",
                        "path_traversal",
                    )
                    if response is None:
                        if truncated:
                            break
                        continue
                    parameter_tested = True
                    response_endpoint = response.endpoint
                    if self._has_system_file_signature(response.body, family):
                        matched_family = family
                        break
                if parameter_tested:
                    tested_parameters += 1
                if matched_family:
                    findings.append(
                        self._path_traversal_finding(response_endpoint, parameter, matched_family)
                    )
                if truncated:
                    break

        if "sql_injection" in selected:
            for url, parameter in per_module_candidates:
                baseline_marker = self._marker("sql-baseline", url, parameter)
                baseline = request(
                    self._with_parameter(url, parameter, baseline_marker),
                    "GET",
                    "sql_injection",
                )
                if baseline is None:
                    if truncated:
                        break
                    continue
                probe_response = request(
                    self._with_parameter(url, parameter, f"{baseline_marker}'"),
                    "GET",
                    "sql_injection",
                )
                if probe_response is None:
                    if truncated:
                        break
                    continue
                tested_parameters += 1
                baseline_errors = self._sql_error_families(baseline.body)
                probe_errors = self._sql_error_families(probe_response.body)
                new_errors = sorted(probe_errors - baseline_errors)
                if new_errors:
                    findings.append(
                        self._sql_injection_finding(
                            probe_response.endpoint, parameter, new_errors[0]
                        )
                    )

        if "reflected_xss" in selected:
            for url, parameter in per_module_candidates:
                marker = self._marker("xss", url, parameter)
                payload = f"<dast-xss-{marker}>"
                response = request(
                    self._with_parameter(url, parameter, payload), "GET", "reflected_xss"
                )
                if response is None:
                    if truncated:
                        break
                    continue
                tested_parameters += 1
                if (
                    200 <= response.status_code < 300
                    and response.is_html
                    and response.body is not None
                    and payload.encode() in response.body
                ):
                    findings.append(self._reflected_xss_finding(response.endpoint, parameter))

        return ActiveScanResult(findings, requests_sent, tested_parameters, truncated)

    def _parameter_candidates(self, endpoints: list[EndpointObservation]) -> list[tuple[str, str]]:
        candidates: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for endpoint in endpoints:
            if endpoint.method != "GET" or endpoint.resource_type not in {
                ResourceType.PAGE,
                ResourceType.API,
            }:
                continue
            if self._has_path_template(endpoint):
                continue
            parameters = endpoint.parameters or {}
            raw_query = parameters.get("query")
            if not isinstance(raw_query, list):
                continue
            for raw_parameter in raw_query:
                if not isinstance(raw_parameter, dict):
                    continue
                name = raw_parameter.get("name")
                if not isinstance(name, str) or not name or len(name) > 128:
                    continue
                key = (endpoint.url, name)
                if key not in seen:
                    seen.add(key)
                    candidates.append(key)
                    if len(candidates) >= self.settings.active_max_parameters:
                        return candidates
        return candidates

    @staticmethod
    def _has_path_template(endpoint: EndpointObservation) -> bool:
        metadata = endpoint.metadata or {}
        templates = (
            metadata.get("path_template"),
            metadata.get("openapi_path_template"),
            metadata.get("postman_path_template"),
        )
        return any(isinstance(template, str) and "{" in template for template in templates)

    @staticmethod
    def _with_parameter(url: str, parameter: str, value: str) -> str:
        parts = urlsplit(url)
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        filtered = [
            (name, "dast" if current == "{value}" else current)
            for name, current in pairs
            if name != parameter
        ]
        filtered.append((parameter, value))
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(filtered), ""))

    @staticmethod
    def _without_template_query(url: str) -> str:
        parts = urlsplit(url)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))

    @staticmethod
    def _marker(kind: str, url: str, parameter: str) -> str:
        digest = sha256(f"{kind}:{url}:{parameter}".encode()).hexdigest()[:12]
        return f"dast-{digest}"

    @staticmethod
    def _advertised_methods(headers: httpx.Headers) -> set[str]:
        values = [headers.get("allow", ""), headers.get("access-control-allow-methods", "")]
        return {
            method.strip().upper()
            for value in values
            for method in value.split(",")
            if method.strip()
        }

    @staticmethod
    def _is_canary_redirect(location: str, marker: str) -> bool:
        try:
            parsed = urlsplit(location)
        except ValueError:
            return False
        return (
            parsed.scheme == "https" and parsed.hostname == "dast.invalid" and marker in parsed.path
        )

    @staticmethod
    def _sql_error_families(body: bytes | None) -> set[str]:
        if body is None:
            return set()
        lowered = body.lower()
        return {family for signature, family in SQL_ERROR_SIGNATURES if signature in lowered}

    @staticmethod
    def _has_system_file_signature(body: bytes | None, family: str) -> bool:
        if body is None:
            return False
        lowered = body.lower()
        if family == "arquivo de contas Unix":
            return b"root:x:0:0:" in lowered or b"root:*:0:0:" in lowered
        return b"[fonts]" in lowered and b"[extensions]" in lowered

    @staticmethod
    def _http_methods_finding(endpoint: str, methods: list[str]) -> FindingDraft:
        return FindingDraft(
            title="Métodos HTTP potencialmente perigosos anunciados",
            description=(
                "O servidor anunciou métodos que podem alterar estado ou ampliar a superfície "
                "de ataque. O scanner não executou esses métodos; confirme a necessidade e "
                "as regras de autorização antes de classificar o impacto."
            ),
            endpoint=endpoint,
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
            cwe="CWE-749",
            owasp_category="A05:2021 Security Misconfiguration",
            privacy_impact=PrivacyImpact.NONE,
            evidence=(
                f"OPTIONS anunciou: {', '.join(methods)}. Nenhum método mutável foi executado."
            ),
            recommendation=(
                "Permita somente os métodos necessários e aplique autenticação, autorização e "
                "proteção CSRF aos métodos que alteram estado."
            ),
            issue_key="active:http-methods",
            finding_type="POTENTIAL_VULNERABILITY",
        )

    @staticmethod
    def _open_redirect_finding(endpoint: str, parameter: str) -> FindingDraft:
        return FindingDraft(
            title="Redirecionamento externo controlado por parâmetro",
            description=(
                "O endpoint redirecionou para o domínio-canário fornecido pelo scanner sem "
                "seguir o redirect. Isso pode facilitar phishing e encadeamento de ataques."
            ),
            endpoint=endpoint,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            cwe="CWE-601",
            owasp_category="A01:2021 Broken Access Control",
            privacy_impact=PrivacyImpact.NONE,
            evidence=(
                f"O parâmetro {parameter!r} produziu Location para o domínio reservado "
                "dast.invalid; o destino não foi acessado."
            ),
            recommendation=(
                "Aceite apenas destinos relativos ou use uma allowlist estrita de origens e "
                "caminhos de redirecionamento."
            ),
            issue_key=f"active:open-redirect:{parameter.casefold()}",
            finding_type="CONFIRMED_VULNERABILITY",
        )

    @staticmethod
    def _reflected_xss_finding(endpoint: str, parameter: str) -> FindingDraft:
        return FindingDraft(
            title="Entrada refletida sem escaping em resposta HTML",
            description=(
                "Um marcador HTML inofensivo enviado no parâmetro foi refletido literalmente. "
                "Isso indica contexto compatível com XSS refletido, mas o scanner não executou "
                "JavaScript; valide o contexto do DOM antes de confirmar exploração."
            ),
            endpoint=endpoint,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            cwe="CWE-79",
            owasp_category="A03:2021 Injection",
            privacy_impact=PrivacyImpact.NONE,
            evidence=(
                f"O parâmetro {parameter!r} refletiu um elemento-canário DAST sem escaping "
                "observável na resposta HTML."
            ),
            recommendation=(
                "Aplique encoding contextual na saída, valide entradas e mantenha uma CSP "
                "restritiva como defesa adicional."
            ),
            issue_key=f"active:reflected-xss:{parameter.casefold()}",
            finding_type="POTENTIAL_VULNERABILITY",
        )

    @staticmethod
    def _sql_injection_finding(endpoint: str, parameter: str, error_family: str) -> FindingDraft:
        return FindingDraft(
            title="Possível SQL Injection indicada por erro diferencial",
            description=(
                "Uma alteração mínima e não destrutiva no parâmetro provocou uma assinatura "
                "de erro de banco de dados ausente na resposta de controle. Nenhuma consulta "
                "de extração, alteração ou bypass foi executada."
            ),
            endpoint=endpoint,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            cwe="CWE-89",
            owasp_category="A03:2021 Injection",
            privacy_impact=PrivacyImpact.NONE,
            evidence=(
                f"O parâmetro {parameter!r} apresentou {error_family} somente após o probe "
                "controlado; corpo e valor enviado não foram persistidos."
            ),
            recommendation=(
                "Use consultas parametrizadas, evite concatenar entradas em SQL e retorne "
                "mensagens de erro genéricas ao cliente."
            ),
            issue_key=f"active:sql-injection:{parameter.casefold()}",
            finding_type="POTENTIAL_VULNERABILITY",
        )

    @staticmethod
    def _path_traversal_finding(
        endpoint: str, parameter: str, signature_family: str
    ) -> FindingDraft:
        return FindingDraft(
            title="Leitura de arquivo por Path Traversal",
            description=(
                "O endpoint retornou uma assinatura reconhecível de arquivo do sistema após "
                "um probe de travessia de diretório. O scanner interrompeu o teste sem tentar "
                "ler outros arquivos."
            ),
            endpoint=endpoint,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            cwe="CWE-22",
            owasp_category="A01:2021 Broken Access Control",
            privacy_impact=PrivacyImpact.NONE,
            evidence=(
                f"O parâmetro {parameter!r} retornou assinatura compatível com "
                f"{signature_family}; o conteúdo observado e o probe não foram persistidos."
            ),
            recommendation=(
                "Resolva caminhos a partir de uma raiz fixa, rejeite segmentos de travessia "
                "e autorize arquivos por identificadores ou allowlist."
            ),
            issue_key=f"active:path-traversal:{parameter.casefold()}",
            finding_type="CONFIRMED_VULNERABILITY",
        )
