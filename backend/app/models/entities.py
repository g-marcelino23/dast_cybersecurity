from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database.session import Base
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

JsonDocument = JSON().with_variant(JSONB(), "postgresql")


def utcnow() -> datetime:
    return datetime.now(UTC)


class Target(Base):
    __tablename__ = "targets"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    base_url: Mapped[str] = mapped_column(String(2048))
    api_url: Mapped[str | None] = mapped_column(String(2048))
    description: Mapped[str | None] = mapped_column(Text)
    environment: Mapped[TargetEnvironment] = mapped_column(
        Enum(TargetEnvironment), default=TargetEnvironment.LOCAL
    )
    is_protected_target: Mapped[bool] = mapped_column(Boolean, default=False)
    safe_scan_mode: Mapped[bool] = mapped_column(Boolean, default=True)
    allowed_hosts: Mapped[list[str]] = mapped_column(JsonDocument, default=list)
    requires_ownership_verification: Mapped[bool] = mapped_column(Boolean, default=False)
    ownership_verification_token: Mapped[str | None] = mapped_column(String(160))
    ownership_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ownership_verification_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    openapi_document: Mapped[dict[str, object] | None] = mapped_column(JsonDocument)
    openapi_title: Mapped[str | None] = mapped_column(String(240))
    openapi_version: Mapped[str | None] = mapped_column(String(40))
    openapi_operation_count: Mapped[int] = mapped_column(Integer, default=0)
    openapi_imported_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    postman_document: Mapped[dict[str, object] | None] = mapped_column(JsonDocument)
    postman_name: Mapped[str | None] = mapped_column(String(240))
    postman_version: Mapped[str | None] = mapped_column(String(40))
    postman_request_count: Mapped[int] = mapped_column(Integer, default=0)
    postman_imported_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    @property
    def ownership_verification_status(self) -> str:
        if not self.requires_ownership_verification:
            return "NOT_REQUIRED"
        if self.ownership_verified_at is None or self.ownership_verification_expires_at is None:
            return "PENDING"
        expires = self.ownership_verification_expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
        return "VERIFIED" if expires > datetime.now(UTC) else "EXPIRED"


class ApiRequestTemplate(Base):
    __tablename__ = "api_request_templates"
    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(160))
    method: Mapped[str] = mapped_column(String(16))
    path: Mapped[str] = mapped_column(String(2048))
    query_parameters: Mapped[list[str]] = mapped_column(JsonDocument, default=list)
    header_names: Mapped[list[str]] = mapped_column(JsonDocument, default=list)
    body_mode: Mapped[str] = mapped_column(String(24), default="NONE")
    content_type: Mapped[str | None] = mapped_column(String(128))
    requires_auth: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), index=True)
    auth_profile_id: Mapped[int | None] = mapped_column(
        ForeignKey("auth_profiles.id", ondelete="SET NULL"), index=True
    )
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), default=ScanStatus.PENDING)
    mode: Mapped[ScanMode] = mapped_column(Enum(ScanMode), default=ScanMode.DISCOVERY_PASSIVE)
    experiment_label: Mapped[str | None] = mapped_column(String(160), index=True)
    dast_version: Mapped[str] = mapped_column(String(32), default="0.23.0")
    modules_enabled: Mapped[list[str]] = mapped_column(JsonDocument, default=list)
    configuration_snapshot: Mapped[dict[str, object]] = mapped_column(JsonDocument, default=dict)
    preset: Mapped[str] = mapped_column(String(32), default="PASSIVE")
    phase: Mapped[str] = mapped_column(String(40), default="PENDING")
    progress_percent: Mapped[int] = mapped_column(Integer, default=0)
    cancellation_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    total_findings: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str | None] = mapped_column(Text)
    observations: Mapped[list[dict[str, str | int]]] = mapped_column(JSON, default=list)
    discovery_requests_observed: Mapped[int] = mapped_column(Integer, default=0)


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    title: Mapped[str] = mapped_column(String(240))
    description: Mapped[str] = mapped_column(Text)
    endpoint: Mapped[str] = mapped_column(String(2048))
    severity: Mapped[Severity] = mapped_column(Enum(Severity))
    confidence: Mapped[Confidence] = mapped_column(Enum(Confidence))
    cwe: Mapped[str] = mapped_column(String(24))
    owasp_category: Mapped[str | None] = mapped_column(String(160))
    privacy_impact: Mapped[PrivacyImpact] = mapped_column(Enum(PrivacyImpact))
    evidence: Mapped[str] = mapped_column(Text)
    recommendation: Mapped[str] = mapped_column(Text)
    privacy_reason: Mapped[str | None] = mapped_column(Text)
    issue_key: Mapped[str | None] = mapped_column(String(255), index=True)
    finding_type: Mapped[str] = mapped_column(String(40), default="MISCONFIGURATION")
    status: Mapped[str] = mapped_column(String(32), default="OPEN", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DiscoveredEndpoint(Base):
    __tablename__ = "discovered_endpoints"
    __table_args__ = (
        UniqueConstraint(
            "scan_id", "method", "url", "resource_type", name="uq_discovered_endpoint_logical"
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    url: Mapped[str] = mapped_column(String(2048))
    path: Mapped[str] = mapped_column(String(2048))
    method: Mapped[str] = mapped_column(String(16))
    source: Mapped[DiscoverySource] = mapped_column(Enum(DiscoverySource))
    resource_type: Mapped[ResourceType] = mapped_column(Enum(ResourceType))
    status_code: Mapped[int | None] = mapped_column(Integer)
    content_type: Mapped[str | None] = mapped_column(String(255))
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    requires_auth: Mapped[bool | None] = mapped_column(Boolean)
    parameters: Mapped[dict[str, object] | None] = mapped_column(JsonDocument)
    metadata_json: Mapped[dict[str, object] | None] = mapped_column("metadata", JsonDocument)


class AuthProfile(Base):
    __tablename__ = "auth_profiles"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    role_name: Mapped[str] = mapped_column(String(120))
    auth_type: Mapped[AuthType] = mapped_column(Enum(AuthType))
    login_url: Mapped[str | None] = mapped_column(String(2048))
    validation_url: Mapped[str | None] = mapped_column(String(2048))
    http_method: Mapped[str] = mapped_column(String(16), default="POST")
    body_encoding: Mapped[str] = mapped_column(String(16), default="JSON")
    body_template: Mapped[dict[str, object] | None] = mapped_column(JsonDocument)
    header_template: Mapped[dict[str, object] | None] = mapped_column(JsonDocument)
    username_field: Mapped[str | None] = mapped_column(String(128))
    password_field: Mapped[str | None] = mapped_column(String(128))
    token_json_path: Mapped[str | None] = mapped_column(String(255))
    token_header_name: Mapped[str | None] = mapped_column(String(128))
    token_prefix: Mapped[str | None] = mapped_column(String(64))
    mfa_url: Mapped[str | None] = mapped_column(String(2048))
    mfa_challenge_json_path: Mapped[str | None] = mapped_column(String(255))
    mfa_challenge_field: Mapped[str | None] = mapped_column(String(128))
    mfa_code_field: Mapped[str | None] = mapped_column(String(128))
    role_json_path: Mapped[str | None] = mapped_column(String(255))
    encrypted_username: Mapped[str | None] = mapped_column(Text)
    encrypted_password: Mapped[str | None] = mapped_column(Text)
    last_auth_success: Mapped[bool | None] = mapped_column(Boolean)
    last_auth_status_code: Mapped[int | None] = mapped_column(Integer)
    last_auth_tested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_authenticated_scan_id: Mapped[int | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), index=True
    )
    last_authenticated_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    @property
    def credentials_configured(self) -> bool:
        if self.auth_type == AuthType.NONE:
            return True
        if self.auth_type in {AuthType.BEARER_TOKEN, AuthType.API_KEY}:
            return bool(self.header_template)
        if self.auth_type == AuthType.CUSTOM_HEADERS:
            return bool(self.header_template)
        return bool(self.encrypted_username)


class SensitiveDataObservation(Base):
    __tablename__ = "sensitive_data_observations"
    __table_args__ = (
        UniqueConstraint(
            "scan_id",
            "endpoint_id",
            "category",
            "field_path",
            "detector_type",
            name="uq_sensitive_observation_logical",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    endpoint_id: Mapped[int] = mapped_column(
        ForeignKey("discovered_endpoints.id", ondelete="CASCADE"), index=True
    )
    category: Mapped[SensitiveDataCategory] = mapped_column(Enum(SensitiveDataCategory))
    field_path: Mapped[str] = mapped_column(String(1024))
    detector_type: Mapped[DetectorType] = mapped_column(Enum(DetectorType))
    confidence: Mapped[Confidence] = mapped_column(Enum(Confidence))
    count: Mapped[int] = mapped_column(Integer, default=1)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuthorizationRule(Base):
    __tablename__ = "authorization_rules"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(160))
    source_role: Mapped[str] = mapped_column(String(120))
    resource_pattern: Mapped[str] = mapped_column(String(2048))
    http_method: Mapped[str] = mapped_column(String(16))
    expected_access: Mapped[ExpectedAccess] = mapped_column(Enum(ExpectedAccess))
    description: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    status: Mapped[AuthorizationRuleStatus] = mapped_column(
        Enum(AuthorizationRuleStatus), default=AuthorizationRuleStatus.APPROVED
    )
    suggestion_reason: Mapped[str | None] = mapped_column(Text)
    suggestion_confidence: Mapped[Confidence | None] = mapped_column(Enum(Confidence))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class AuthorizationTestScenario(Base):
    __tablename__ = "authorization_test_scenarios"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(160))
    owner_profile_id: Mapped[int] = mapped_column(
        ForeignKey("auth_profiles.id", ondelete="CASCADE"), index=True
    )
    test_profile_id: Mapped[int] = mapped_column(
        ForeignKey("auth_profiles.id", ondelete="CASCADE"), index=True
    )
    authorization_rule_id: Mapped[int] = mapped_column(
        ForeignKey("authorization_rules.id", ondelete="CASCADE"), index=True
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    execution_status: Mapped[AuthorizationScenarioExecutionStatus] = mapped_column(
        Enum(AuthorizationScenarioExecutionStatus),
        default=AuthorizationScenarioExecutionStatus.READY,
        index=True,
    )
    execution_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    execution_finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    execution_error_code: Mapped[str | None] = mapped_column(String(80))
    execution_attempt: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuthorizationProbe(Base):
    __tablename__ = "authorization_probes"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    scenario_id: Mapped[int] = mapped_column(
        ForeignKey("authorization_test_scenarios.id", ondelete="CASCADE"), index=True
    )
    owner_profile_id: Mapped[int] = mapped_column(ForeignKey("auth_profiles.id"))
    test_profile_id: Mapped[int] = mapped_column(ForeignKey("auth_profiles.id"))
    endpoint: Mapped[str] = mapped_column(String(2048))
    method: Mapped[str] = mapped_column(String(16))
    expected_access: Mapped[ExpectedAccess] = mapped_column(Enum(ExpectedAccess))
    result: Mapped[AuthorizationProbeResult] = mapped_column(Enum(AuthorizationProbeResult))
    status_code: Mapped[int | None] = mapped_column(Integer)
    confidence: Mapped[Confidence] = mapped_column(Enum(Confidence))
    baseline_fingerprint: Mapped[str | None] = mapped_column(String(64))
    tested_fingerprint: Mapped[str | None] = mapped_column(String(64))
    sensitive_categories: Mapped[list[str]] = mapped_column(JsonDocument, default=list)
    baseline_metadata: Mapped[dict[str, object] | None] = mapped_column(JsonDocument)
    tested_metadata: Mapped[dict[str, object] | None] = mapped_column(JsonDocument)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RoleSurfaceSnapshot(Base):
    __tablename__ = "role_surface_snapshots"
    __table_args__ = (UniqueConstraint("scan_id", name="uq_role_surface_snapshot_scan"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    auth_profile_id: Mapped[int] = mapped_column(
        ForeignKey("auth_profiles.id", ondelete="CASCADE"), index=True
    )
    role_name: Mapped[str] = mapped_column(String(120))
    pages_discovered: Mapped[int] = mapped_column(Integer, default=0)
    api_endpoints: Mapped[int] = mapped_column(Integer, default=0)
    forms: Mapped[int] = mapped_column(Integer, default=0)
    methods: Mapped[list[str]] = mapped_column(JsonDocument, default=list)
    sensitive_categories: Mapped[list[str]] = mapped_column(JsonDocument, default=list)
    cwes: Mapped[list[str]] = mapped_column(JsonDocument, default=list)
    passive_findings: Mapped[int] = mapped_column(Integer, default=0)
    unique_issues: Mapped[int] = mapped_column(Integer, default=0)
    authorization_rules_related: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuthorizationCandidate(Base):
    __tablename__ = "authorization_candidates"
    __table_args__ = (
        UniqueConstraint(
            "target_id",
            "owner_profile_id",
            "test_profile_id",
            "owner_scan_id",
            "method",
            "resource_pattern",
            name="uq_authorization_candidate_observation",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    owner_profile_id: Mapped[int] = mapped_column(
        ForeignKey("auth_profiles.id", ondelete="CASCADE"), index=True
    )
    test_profile_id: Mapped[int] = mapped_column(
        ForeignKey("auth_profiles.id", ondelete="CASCADE"), index=True
    )
    owner_scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    test_scan_id: Mapped[int | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), index=True
    )
    method: Mapped[str] = mapped_column(String(16))
    resource_pattern: Mapped[str] = mapped_column(String(2048))
    expected_access: Mapped[ExpectedAccess] = mapped_column(Enum(ExpectedAccess))
    reason: Mapped[str] = mapped_column(Text)
    confidence: Mapped[Confidence] = mapped_column(Enum(Confidence))
    sensitive_categories: Mapped[list[str]] = mapped_column(JsonDocument, default=list)
    status: Mapped[AuthorizationRuleStatus] = mapped_column(
        Enum(AuthorizationRuleStatus), default=AuthorizationRuleStatus.SUGGESTED
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
