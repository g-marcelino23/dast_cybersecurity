from dataclasses import asdict, dataclass
from typing import Literal


@dataclass(frozen=True)
class ScanModuleDefinition:
    id: str
    name: str
    description: str
    kind: Literal["DISCOVERY", "PASSIVE", "ACTIVE"]
    sends_additional_requests: bool
    default_enabled: bool
    cwes: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["cwes"] = list(self.cwes)
        return value


MODULE_CATALOG: tuple[ScanModuleDefinition, ...] = (
    ScanModuleDefinition(
        "discovery",
        "Discovery",
        "Navega na aplicação e inventaria páginas, APIs, formulários e scripts.",
        "DISCOVERY",
        False,
        True,
    ),
    ScanModuleDefinition(
        "security_headers",
        "Security Headers",
        "Analisa cabeçalhos HTTP de defesa em profundidade.",
        "PASSIVE",
        False,
        True,
        ("CWE-693",),
    ),
    ScanModuleDefinition(
        "server_disclosure",
        "Server Disclosure",
        "Identifica divulgação desnecessária de tecnologia.",
        "PASSIVE",
        False,
        True,
        ("CWE-200",),
    ),
    ScanModuleDefinition(
        "cookies",
        "Cookie Security",
        "Analisa atributos de proteção de cookies de possível sessão.",
        "PASSIVE",
        False,
        True,
        ("CWE-614", "CWE-1004", "CWE-1275"),
    ),
    ScanModuleDefinition(
        "cors",
        "CORS",
        "Analisa configurações CORS observadas sem forjar origens.",
        "PASSIVE",
        False,
        True,
        ("CWE-942",),
    ),
    ScanModuleDefinition(
        "sensitive_data",
        "Sensitive Data",
        "Classifica metadados sensíveis em memória sem persistir corpos completos.",
        "PASSIVE",
        False,
        True,
    ),
    ScanModuleDefinition(
        "csp",
        "Content Security Policy",
        "Revisa diretivas potencialmente permissivas na política CSP.",
        "PASSIVE",
        False,
        True,
        ("CWE-693",),
    ),
    ScanModuleDefinition(
        "cache_control",
        "Cache Control",
        "Identifica cache público em respostas que criam possível sessão.",
        "PASSIVE",
        False,
        True,
        ("CWE-525",),
    ),
    ScanModuleDefinition(
        "error_disclosure",
        "Error Disclosure",
        "Detecta assinaturas de stack traces e erros técnicos sem persistir o corpo.",
        "PASSIVE",
        False,
        True,
        ("CWE-209",),
    ),
    ScanModuleDefinition(
        "tls",
        "TLS",
        "Revisa versão e cifra TLS observadas na conexão validada.",
        "PASSIVE",
        False,
        True,
        ("CWE-326",),
    ),
    ScanModuleDefinition(
        "mixed_content",
        "Mixed Content",
        "Detecta sub-recursos HTTP e WebSocket inseguro em páginas HTTPS.",
        "PASSIVE",
        False,
        True,
        ("CWE-319",),
    ),
    ScanModuleDefinition(
        "redirects",
        "Redirects",
        "Revisa redirects observados sem seguir ou persistir o destino completo.",
        "PASSIVE",
        False,
        True,
        ("CWE-319", "CWE-601"),
    ),
    ScanModuleDefinition(
        "http_methods",
        "HTTP Methods",
        "Usa OPTIONS sem executar métodos mutáveis e sinaliza métodos perigosos anunciados.",
        "ACTIVE",
        True,
        False,
        ("CWE-749",),
    ),
    ScanModuleDefinition(
        "open_redirect",
        "Open Redirect",
        "Testa parâmetros de redirecionamento com domínio-canário sem seguir o destino.",
        "ACTIVE",
        True,
        False,
        ("CWE-601",),
    ),
    ScanModuleDefinition(
        "path_traversal",
        "Path Traversal",
        "Testa parâmetros de arquivo com assinaturas conhecidas e interrompe após confirmação.",
        "ACTIVE",
        True,
        False,
        ("CWE-22",),
    ),
    ScanModuleDefinition(
        "sql_injection",
        "SQL Injection",
        "Compara resposta de controle com probe de erro, sem extrair ou alterar dados.",
        "ACTIVE",
        True,
        False,
        ("CWE-89",),
    ),
    ScanModuleDefinition(
        "reflected_xss",
        "Reflected XSS",
        "Reflete um marcador HTML inofensivo sem executar JavaScript.",
        "ACTIVE",
        True,
        False,
        ("CWE-79",),
    ),
)

MODULE_IDS = frozenset(module.id for module in MODULE_CATALOG)
PASSIVE_MODULE_IDS = tuple(
    module.id
    for module in MODULE_CATALOG
    if module.default_enabled and module.kind in {"DISCOVERY", "PASSIVE"}
)
ACTIVE_MODULE_IDS = tuple(module.id for module in MODULE_CATALOG if module.kind == "ACTIVE")


def modules_for_preset(preset: str, requested: list[str] | None = None) -> list[str]:
    if preset == "DISCOVERY":
        return ["discovery"]
    if preset == "PASSIVE":
        return list(PASSIVE_MODULE_IDS)
    if preset == "SAFE_ACTIVE":
        return [*PASSIVE_MODULE_IDS, *ACTIVE_MODULE_IDS]
    if preset != "CUSTOM":
        raise ValueError("Preset de scan inválido.")
    selected = list(dict.fromkeys(requested or []))
    unknown = sorted(set(selected) - MODULE_IDS)
    if unknown:
        raise ValueError(f"Módulos desconhecidos: {', '.join(unknown)}.")
    if "discovery" not in selected:
        selected.insert(0, "discovery")
    return selected
