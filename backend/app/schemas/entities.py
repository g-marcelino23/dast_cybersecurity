import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

from app.models.enums import (
    AuthorizationProbeResult,
    AuthorizationRuleStatus,
    AuthorizationScenarioExecutionStatus,
    AuthType,
    Confidence,
    DetectorType,
    DiscoverySource,
    ExpectedAccess,
    PrivacyImpact,
    ResourceType,
    ScanMode,
    ScanStatus,
    SensitiveDataCategory,
    Severity,
    TargetEnvironment,
)


class TargetComponent(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    name: str = Field(min_length=1, max_length=80)
    kind: Literal["WEB", "API", "SERVICE"]
    url: str = Field(min_length=1, max_length=2048)


class TargetCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    name: str = Field(min_length=1, max_length=120)
    base_url: str = Field(min_length=1, max_length=2048)
    api_url: str | None = Field(default=None, max_length=2048)
    components: list[TargetComponent] = Field(default_factory=list, max_length=20)
    description: str | None = Field(default=None, max_length=4000)
    environment: TargetEnvironment = TargetEnvironment.LOCAL
    is_protected_target: bool = False
    safe_scan_mode: bool = True

    @model_validator(mode="after")
    def require_safe_mode_for_protected_target(self) -> "TargetCreate":
        if self.is_protected_target and not self.safe_scan_mode:
            raise ValueError("Safe Scan Mode é obrigatório para alvos protegidos.")
        if self.is_protected_target and self.environment == TargetEnvironment.FIXTURE:
            raise ValueError("Alvos de laboratório e alvos protegidos devem permanecer separados.")
        return self


class TargetRead(TargetCreate):
    model_config = ConfigDict(from_attributes=True)
    id: int
    allowed_hosts: list[str]
    requires_ownership_verification: bool
    ownership_verification_token: str | None
    ownership_verified_at: datetime | None
    ownership_verification_expires_at: datetime | None
    ownership_verification_status: Literal["NOT_REQUIRED", "PENDING", "VERIFIED", "EXPIRED"]
    openapi_title: str | None
    openapi_version: str | None
    openapi_operation_count: int
    openapi_imported_at: datetime | None
    postman_name: str | None
    postman_version: str | None
    postman_request_count: int
    postman_imported_at: datetime | None
    created_at: datetime


class OwnershipVerificationRead(BaseModel):
    target_id: int
    status: Literal["NOT_REQUIRED", "PENDING", "VERIFIED", "EXPIRED"]
    challenge_path: str
    challenge_urls: list[str]
    token: str | None
    allowed_hosts: list[str]
    verified_at: datetime | None
    expires_at: datetime | None


class OpenApiImportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    content: str = Field(min_length=1, max_length=2_000_000)
    filename: str | None = Field(default=None, max_length=255)


class OpenApiImportRead(BaseModel):
    target_id: int
    title: str
    version: str
    operation_count: int
    path_count: int
    methods: list[str]
    imported_at: datetime


class PostmanImportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    content: str = Field(min_length=1, max_length=2_000_000)
    filename: str | None = Field(default=None, max_length=255)


class PostmanImportRead(BaseModel):
    target_id: int
    name: str
    version: str
    request_count: int
    methods: list[str]
    imported_at: datetime


class ApiRequestTemplateCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    name: str = Field(min_length=1, max_length=160)
    method: Literal["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"] = "GET"
    path: str = Field(min_length=1, max_length=2048)
    query_parameters: list[str] = Field(default_factory=list, max_length=50)
    header_names: list[str] = Field(default_factory=list, max_length=50)
    body_mode: Literal["NONE", "JSON", "FORM", "MULTIPART", "GRAPHQL", "RAW"] = "NONE"
    content_type: str | None = Field(default=None, max_length=128)
    requires_auth: bool = False

    @field_validator("path")
    @classmethod
    def validate_relative_path(cls, value: str) -> str:
        if not value.startswith("/") or "://" in value or "?" in value or "#" in value:
            raise ValueError(
                "Informe somente um caminho relativo iniciado por /, sem query string."
            )
        if "\\" in value or any(ord(character) < 32 for character in value):
            raise ValueError("O caminho contém caracteres inválidos.")
        if ".." in value.split("/"):
            raise ValueError("O caminho não pode conter segmentos de navegação.")
        without_placeholders = re.sub(r"{[A-Za-z_][A-Za-z0-9_.-]{0,127}}", "", value)
        if "{" in without_placeholders or "}" in without_placeholders:
            raise ValueError("Use placeholders no formato {nome}.")
        return value

    @field_validator("query_parameters", "header_names")
    @classmethod
    def validate_parameter_names(cls, values: list[str]) -> list[str]:
        result: list[str] = []
        for value in values:
            clean = value.strip()
            if not re.fullmatch(r"[A-Za-z0-9_.\-\[\]]{1,128}", clean):
                raise ValueError("Nome de parâmetro inválido.")
            if clean not in result:
                result.append(clean)
        return result

    @field_validator("content_type")
    @classmethod
    def validate_content_type(cls, value: str | None) -> str | None:
        if value is None or not value:
            return None
        clean = value.split(";", 1)[0].strip().lower()
        if not re.fullmatch(r"[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+", clean):
            raise ValueError("Content-Type inválido.")
        return clean


class ApiRequestTemplateRead(ApiRequestTemplateCreate):
    model_config = ConfigDict(from_attributes=True)
    id: int
    target_id: int
    created_at: datetime


class ScanCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_id: int = Field(gt=0)
    auth_profile_id: int | None = Field(default=None, gt=0)
    mode: ScanMode = ScanMode.DISCOVERY_PASSIVE
    experiment_label: str | None = Field(default=None, max_length=160, pattern=r"^[A-Za-z0-9._-]+$")
    preset: Literal["DISCOVERY", "PASSIVE", "SAFE_ACTIVE", "CUSTOM"] = "PASSIVE"
    modules: list[str] | None = Field(default=None, max_length=20)
    active_confirmation: bool = False


class ApiRequestRuntimeValues(BaseModel):
    model_config = ConfigDict(extra="forbid")
    template_id: int = Field(gt=0)
    path_parameters: dict[str, SecretStr] = Field(default_factory=dict, max_length=50)
    query_parameters: dict[str, SecretStr] = Field(default_factory=dict, max_length=50)
    header_values: dict[str, SecretStr] = Field(default_factory=dict, max_length=50)

    @field_validator("path_parameters", "query_parameters", "header_values")
    @classmethod
    def validate_runtime_values(cls, values: dict[str, SecretStr]) -> dict[str, SecretStr]:
        for name, secret in values.items():
            if not re.fullmatch(r"[A-Za-z0-9_.\-\[\]]{1,128}", name):
                raise ValueError("Nome de parâmetro temporário inválido.")
            value = secret.get_secret_value()
            if not value or len(value) > 2048 or any(ord(character) < 32 for character in value):
                raise ValueError("Valor temporário inválido.")
        return values


class ScanRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    manual_api_values: list[ApiRequestRuntimeValues] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def reject_duplicate_templates(self) -> "ScanRunRequest":
        template_ids = [item.template_id for item in self.manual_api_values]
        if len(template_ids) != len(set(template_ids)):
            raise ValueError("Cada template pode receber somente um conjunto de valores.")
        return self


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    target_id: int
    auth_profile_id: int | None
    status: ScanStatus
    mode: ScanMode
    experiment_label: str | None
    dast_version: str
    modules_enabled: list[str]
    configuration_snapshot: dict[str, object]
    preset: str
    phase: str
    progress_percent: int
    cancellation_requested: bool
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    total_findings: int
    error_message: str | None
    observations: list[dict[str, str | int]]
    discovery_requests_observed: int


class ScanModuleRead(BaseModel):
    id: str
    name: str
    description: str
    kind: Literal["DISCOVERY", "PASSIVE", "ACTIVE"]
    sends_additional_requests: bool
    default_enabled: bool
    cwes: list[str]


class FindingDraft(BaseModel):
    title: str = Field(min_length=1, max_length=240)
    description: str = Field(min_length=1)
    endpoint: str = Field(min_length=1, max_length=2048)
    severity: Severity = Severity.LOW
    confidence: Confidence = Confidence.HIGH
    cwe: str = Field(pattern=r"^CWE-\d+$")
    owasp_category: str | None = None
    privacy_impact: PrivacyImpact = PrivacyImpact.NONE
    evidence: str = Field(min_length=1)
    recommendation: str = Field(min_length=1)
    privacy_reason: str | None = None
    issue_key: str | None = Field(default=None, max_length=255)
    finding_type: Literal[
        "CONFIRMED_VULNERABILITY",
        "POTENTIAL_VULNERABILITY",
        "MISCONFIGURATION",
        "INFORMATION",
        "INCONCLUSIVE",
    ] = "MISCONFIGURATION"


class FindingRead(FindingDraft):
    model_config = ConfigDict(from_attributes=True)
    id: int
    scan_id: int
    status: Literal[
        "OPEN",
        "CONFIRMED",
        "IN_REVIEW",
        "IN_PROGRESS",
        "RESOLVED",
        "ACCEPTED_RISK",
        "FALSE_POSITIVE",
        "REOPENED",
    ] = "OPEN"
    created_at: datetime


class FindingStatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal[
        "OPEN",
        "CONFIRMED",
        "IN_REVIEW",
        "IN_PROGRESS",
        "RESOLVED",
        "ACCEPTED_RISK",
        "FALSE_POSITIVE",
        "REOPENED",
    ]


class DiscoveredEndpointRead(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)
    id: int
    scan_id: int
    url: str
    path: str
    method: str
    source: DiscoverySource
    resource_type: ResourceType
    status_code: int | None
    content_type: str | None
    discovered_at: datetime
    requires_auth: bool | None
    parameters: dict[str, object] | None
    metadata: dict[str, object] | None = Field(validation_alias="metadata_json")


class DiscoverySummary(BaseModel):
    scan_id: int
    pages: int
    api_endpoints: int
    forms: int
    requests_observed: int
    unique_endpoints: int
    methods: list[str]


class AuthProfileBase(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    name: str = Field(min_length=1, max_length=120)
    role_name: str = Field(min_length=1, max_length=120)
    auth_type: AuthType
    login_url: str | None = Field(default=None, max_length=2048)
    validation_url: str | None = Field(default=None, max_length=2048)
    http_method: Literal["POST"] = "POST"
    body_encoding: Literal["JSON", "FORM"] = "JSON"
    body_template: dict[str, object] | None = None
    header_template: dict[str, str] | None = None
    username_field: str | None = Field(default=None, max_length=128)
    password_field: str | None = Field(default=None, max_length=128)
    token_json_path: str | None = Field(default=None, max_length=255)
    token_header_name: str | None = Field(default="Authorization", max_length=128)
    token_prefix: str | None = Field(default="Bearer", max_length=64)
    mfa_url: str | None = Field(default=None, max_length=2048)
    mfa_challenge_json_path: str | None = Field(default=None, max_length=255)
    mfa_challenge_field: str | None = Field(default=None, max_length=128)
    mfa_code_field: str | None = Field(default=None, max_length=128)
    role_json_path: str | None = Field(default=None, max_length=255)
    oidc_discovery_url: str | None = Field(default=None, max_length=2048)
    oauth_scopes: list[str] = Field(default_factory=list, max_length=50)
    oauth_audience: str | None = Field(default=None, max_length=255)

    @field_validator("oauth_scopes")
    @classmethod
    def validate_oauth_scopes(cls, values: list[str]) -> list[str]:
        result: list[str] = []
        for value in values:
            clean = value.strip()
            if not re.fullmatch(r"[A-Za-z0-9:._/-]{1,128}", clean):
                raise ValueError("Escopo OAuth inválido.")
            if clean not in result:
                result.append(clean)
        return result


class AuthProfileCreate(AuthProfileBase):
    username: SecretStr | None = Field(default=None, min_length=1, max_length=1024)
    password: SecretStr | None = Field(default=None, min_length=1, max_length=4096)


class AuthProfileUpdate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    name: str | None = Field(default=None, min_length=1, max_length=120)
    role_name: str | None = Field(default=None, min_length=1, max_length=120)
    auth_type: AuthType | None = None
    login_url: str | None = Field(default=None, max_length=2048)
    validation_url: str | None = Field(default=None, max_length=2048)
    http_method: Literal["POST"] | None = None
    body_encoding: Literal["JSON", "FORM"] | None = None
    body_template: dict[str, object] | None = None
    header_template: dict[str, str] | None = None
    username_field: str | None = Field(default=None, max_length=128)
    password_field: str | None = Field(default=None, max_length=128)
    token_json_path: str | None = Field(default=None, max_length=255)
    token_header_name: str | None = Field(default=None, max_length=128)
    token_prefix: str | None = Field(default=None, max_length=64)
    mfa_url: str | None = Field(default=None, max_length=2048)
    mfa_challenge_json_path: str | None = Field(default=None, max_length=255)
    mfa_challenge_field: str | None = Field(default=None, max_length=128)
    mfa_code_field: str | None = Field(default=None, max_length=128)
    role_json_path: str | None = Field(default=None, max_length=255)
    oidc_discovery_url: str | None = Field(default=None, max_length=2048)
    oauth_scopes: list[str] | None = Field(default=None, max_length=50)
    oauth_audience: str | None = Field(default=None, max_length=255)
    username: SecretStr | None = Field(default=None, min_length=1, max_length=1024)
    password: SecretStr | None = Field(default=None, min_length=1, max_length=4096)

    @field_validator("oauth_scopes")
    @classmethod
    def validate_oauth_scopes(cls, values: list[str] | None) -> list[str] | None:
        if values is None:
            return None
        result: list[str] = []
        for value in values:
            clean = value.strip()
            if not re.fullmatch(r"[A-Za-z0-9:._/-]{1,128}", clean):
                raise ValueError("Escopo OAuth inválido.")
            if clean not in result:
                result.append(clean)
        return result


class AuthProfileRead(AuthProfileBase):
    model_config = ConfigDict(from_attributes=True)
    id: int
    target_id: int
    credentials_configured: bool
    last_auth_success: bool | None
    last_auth_status_code: int | None
    last_auth_tested_at: datetime | None
    last_authenticated_scan_id: int | None
    last_authenticated_scan_at: datetime | None
    created_at: datetime
    updated_at: datetime


class AuthenticationTestResult(BaseModel):
    success: bool
    status_code: int | None
    message: str
    requires_mfa: bool = False


class AuthenticationValidationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: SecretStr | None = Field(default=None, min_length=1, max_length=1024)
    password: SecretStr | None = Field(default=None, min_length=1, max_length=4096)
    secret: SecretStr | None = Field(default=None, min_length=1, max_length=16384)
    mfa_code: SecretStr | None = Field(default=None, min_length=1, max_length=64)
    retain_session: bool = True


class AuthenticationValidationResult(BaseModel):
    success: bool
    status_code: int | None
    role_name: str
    session_initialized: bool
    requires_mfa: bool = False
    message: str


class TargetComponentHealth(BaseModel):
    url: str
    status: Literal["ONLINE", "OFFLINE"]
    status_code: int | None = None


class TargetHealthRead(BaseModel):
    target_id: int
    available: bool
    frontend: TargetComponentHealth
    api: TargetComponentHealth | None
    components: list[TargetComponentHealth]
    message: str
    code: Literal["AVAILABLE", "TARGET_UNAVAILABLE"]


class LoginConfigurationSuggestion(BaseModel):
    login_url: str
    method: Literal["POST"]
    username_field: str | None
    password_field: str | None
    confidence: Confidence
    status: Literal["SUGGESTED"] = "SUGGESTED"
    requires_confirmation: Literal[True] = True


class SensitiveDataObservationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    scan_id: int
    endpoint_id: int
    category: SensitiveDataCategory
    field_path: str
    detector_type: DetectorType
    confidence: Confidence
    count: int
    detected_at: datetime


class SensitiveCategoryCount(BaseModel):
    category: SensitiveDataCategory
    count: int


class SensitiveDataSummary(BaseModel):
    scan_id: int
    observations: int
    endpoints_with_sensitive_data: int
    categories_detected: int
    health_endpoints: int
    authenticated_endpoints: int
    categories: list[SensitiveCategoryCount]


class AuthorizationRuleCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    name: str = Field(min_length=1, max_length=160)
    source_role: str = Field(min_length=1, max_length=120)
    resource_pattern: str = Field(min_length=1, max_length=2048)
    http_method: str = Field(min_length=1, max_length=16)
    expected_access: ExpectedAccess
    description: str | None = Field(default=None, max_length=4000)
    enabled: bool = True
    status: AuthorizationRuleStatus = AuthorizationRuleStatus.APPROVED
    suggestion_reason: str | None = Field(default=None, max_length=4000)
    suggestion_confidence: Confidence | None = None


class AuthorizationRuleRead(AuthorizationRuleCreate):
    model_config = ConfigDict(from_attributes=True)
    id: int
    target_id: int
    created_at: datetime
    updated_at: datetime


class AuthorizationScenarioCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    name: str = Field(min_length=1, max_length=160)
    owner_profile_id: int = Field(gt=0)
    test_profile_id: int = Field(gt=0)
    authorization_rule_id: int = Field(gt=0)
    enabled: bool = True


class AuthorizationScenarioRead(AuthorizationScenarioCreate):
    model_config = ConfigDict(from_attributes=True)
    id: int
    target_id: int
    execution_status: AuthorizationScenarioExecutionStatus
    execution_started_at: datetime | None
    execution_finished_at: datetime | None
    execution_error_code: str | None
    execution_attempt: int
    created_at: datetime


class ResourceCandidate(BaseModel):
    endpoint: str
    method: str
    resource_pattern: str
    identifier_location: Literal["path", "query", "configured"]
    identifier_name: str
    discovered_by_profile: int
    confidence: Confidence


class AuthorizationTestPlan(BaseModel):
    scenario_id: int
    scenarios: int
    get_requests: int
    head_requests: int
    mutating_requests: int
    total_requests: int
    owner_profile: str
    test_profile: str
    candidates: list[ResourceCandidate]
    target_name: str
    rules_approved: int
    methods: list[str]
    sensitive_endpoints: int
    target_scope: Literal["LOCAL_PRIVATE", "VERIFIED_PUBLIC"]
    request_urls: list[str]


class AuthorizationRunConfirmation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirmed: Literal[True]
    rerun: bool = False


class AuthorizationRuleStatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: AuthorizationRuleStatus


class AccessSurfaceProfile(BaseModel):
    profile_id: int
    profile_name: str
    role_name: str


class AccessSurfaceRow(BaseModel):
    endpoint: str
    method: str
    access: dict[str, Literal["OBSERVED", "NOT_OBSERVED", "UNKNOWN"]]


class AccessSurfaceMatrix(BaseModel):
    target_id: int
    profiles: list[AccessSurfaceProfile]
    rows: list[AccessSurfaceRow]


class SensitiveSurfaceRow(BaseModel):
    endpoint: str
    method: str
    categories: list[SensitiveDataCategory]
    observed_by: list[str]
    confidence: Confidence


class SensitiveSurfaceMatrix(BaseModel):
    target_id: int
    rows: list[SensitiveSurfaceRow]


class CweCoverageRow(BaseModel):
    cwe: str
    occurrences: int
    severity: Severity
    owasp_mappings: list[str]
    privacy_impact: PrivacyImpact
    affected_endpoints: int


class CweCoverage(BaseModel):
    target_id: int
    rows: list[CweCoverageRow]
    mapped_to_owasp: int
    without_direct_owasp_mapping: int
    total_cwes: int


class AccessProfileSurface(BaseModel):
    target_id: int
    profile_id: int
    profile_name: str
    role_name: str
    authentication_status: Literal["VALIDATED", "FAILED", "NOT_TESTED"]
    last_scan_id: int | None
    last_scan_at: datetime | None
    pages_discovered: int
    api_endpoints: int
    forms: int
    methods: list[str]
    sensitive_endpoints: int
    sensitive_categories: list[SensitiveDataCategory]
    cwes: list[str]
    passive_findings: int
    unique_issues: int
    authorization_candidates: int
    authorization_rules_related: int
    authorization_probes: int
    confirmed_failures: int
    inconclusive: int
    message: str | None


class RoleSurfaceSnapshotRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    target_id: int
    scan_id: int
    auth_profile_id: int
    role_name: str
    pages_discovered: int
    api_endpoints: int
    forms: int
    methods: list[str]
    sensitive_categories: list[str]
    cwes: list[str]
    passive_findings: int
    unique_issues: int
    authorization_rules_related: int
    created_at: datetime


class RoleComparisonRow(BaseModel):
    endpoint: str
    method: str
    resource_type: ResourceType
    sensitive_categories: list[SensitiveDataCategory]
    state: Literal["ONLY_PROFILE_A", "ONLY_PROFILE_B", "COMMON", "UNKNOWN"]


class RoleComparison(BaseModel):
    target_id: int
    profile_a: AccessSurfaceProfile
    profile_b: AccessSurfaceProfile
    profile_a_scan_id: int | None
    profile_b_scan_id: int | None
    methods_profile_a: list[str]
    methods_profile_b: list[str]
    sensitive_categories_profile_a: list[SensitiveDataCategory]
    sensitive_categories_profile_b: list[SensitiveDataCategory]
    rows: list[RoleComparisonRow]
    message: str


class AuthorizationCandidateRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    target_id: int
    owner_profile_id: int
    test_profile_id: int
    owner_scan_id: int
    test_scan_id: int | None
    method: str
    resource_pattern: str
    expected_access: ExpectedAccess
    reason: str
    confidence: Confidence
    sensitive_categories: list[str]
    status: AuthorizationRuleStatus
    created_at: datetime


class CandidateGenerationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    profile_a_id: int = Field(gt=0)
    profile_b_id: int = Field(gt=0)


class AuthorizationPreviewItem(BaseModel):
    scenario_id: int
    rule_name: str
    owner_profile: str
    test_profile: str
    method: str
    resource: str
    expected_access: ExpectedAccess
    sensitive_categories: list[SensitiveDataCategory]
    rationale: str
    confidence: Confidence
    executable: bool


class AuthorizationPreview(BaseModel):
    target_id: int
    profile_id: int
    items: list[AuthorizationPreviewItem]
    mutating_requests: Literal[0] = 0
    requires_explicit_confirmation: Literal[True] = True


class ScanSummary(BaseModel):
    scan_id: int
    target_name: str
    environment: str
    scan_date: datetime
    scan_profile: str
    role_name: str | None
    authenticated: bool
    experiment_label: str | None
    dast_version: str
    modules_enabled: list[str]
    configuration_snapshot: dict[str, object]
    pages_discovered: int
    api_endpoints: int
    forms: int
    passive_findings: int
    unique_findings: int
    finding_occurrences: int
    cwes: list[str]
    owasp_mapped_findings: int
    findings_without_direct_owasp_mapping: int
    sensitive_endpoints: int
    sensitive_categories: list[SensitiveDataCategory]
    authorization_candidates: int
    authorization_probes: int
    confirmed_authorization_failures: int
    inconclusive_authorization_probes: int
    safe_scan_mode: bool


class ScanComparisonFinding(BaseModel):
    title: str
    cwe: str
    severity: Severity
    endpoint: str


class ScanComparisonEndpoint(BaseModel):
    method: str
    path: str
    resource_type: ResourceType


class ScanComparisonResponseChange(BaseModel):
    method: str
    path: str
    baseline_status: int | None
    current_status: int | None
    baseline_size: int | None
    current_size: int | None
    reasons: list[Literal["STATUS", "CONTENT_TYPE", "STRUCTURE", "SIZE", "SIGNATURE_UNAVAILABLE"]]


class ScanComparison(BaseModel):
    target_id: int
    baseline_scan_id: int
    current_scan_id: int
    new_findings: list[ScanComparisonFinding]
    resolved_findings: list[ScanComparisonFinding]
    persistent_findings: list[ScanComparisonFinding]
    added_endpoints: list[ScanComparisonEndpoint]
    removed_endpoints: list[ScanComparisonEndpoint]
    response_size_tolerance_percent: float
    compared_responses: int
    unchanged_responses: int
    response_changes: list[ScanComparisonResponseChange]


class PrivacyAnalysis(BaseModel):
    target_id: int
    sensitive_endpoints: int
    sensitive_categories: list[SensitiveDataCategory]
    authorization_findings_affecting_sensitive_data: int
    privacy_impact_distribution: dict[str, int]


class AuthorizationProbeRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    scan_id: int
    scenario_id: int
    owner_profile_id: int
    test_profile_id: int
    endpoint: str
    method: str
    expected_access: ExpectedAccess
    result: AuthorizationProbeResult
    status_code: int | None
    confidence: Confidence
    baseline_fingerprint: str | None
    tested_fingerprint: str | None
    sensitive_categories: list[str]
    baseline_metadata: dict[str, object] | None
    tested_metadata: dict[str, object] | None
    created_at: datetime


class AuthorizationSummary(BaseModel):
    total_probes: int
    denied_correctly: int
    allowed_correctly: int
    confirmed_bypass: int
    possible_bypass: int
    inconclusive: int
    skipped: int
    errors: int
    privacy_impacting_authorization_failures: int


class FindingCorrelationSummary(BaseModel):
    unique_issues: int
    occurrences: int
    affected_endpoints: int
