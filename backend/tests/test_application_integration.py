from collections.abc import Iterator
from unittest.mock import patch

import httpx
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.database.session import Base
from app.models import (
    AuthorizationRule,
    AuthorizationTestScenario,
    AuthProfile,
    DiscoveredEndpoint,
    Finding,
    Scan,
    SensitiveDataObservation,
    Target,
)
from app.models.enums import (
    AuthorizationRuleStatus,
    AuthType,
    Confidence,
    DetectorType,
    DiscoverySource,
    ExpectedAccess,
    PrivacyImpact,
    ResourceType,
    ScanStatus,
    SensitiveDataCategory,
    Severity,
)
from app.scanner.base import ResponseSnapshot
from app.services.authorization import AuthorizationService, AuthorizationValidationError
from app.services.insights import (
    TargetHealthService,
    access_surface,
    cwe_coverage,
    login_suggestions,
    privacy_analysis,
    sanitize_resource,
    scan_comparison,
    sensitive_surface,
    suggest_rules,
)


@pytest.fixture
def db() -> Iterator[Session]:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    engine.dispose()


class Collector:
    def __init__(self, response: ResponseSnapshot | Exception) -> None:
        self.response = response
        self.methods: list[str] = []

    def fetch(self, url: str) -> ResponseSnapshot:
        self.methods.append("GET")
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def seed_surface(db: Session) -> tuple[Target, AuthProfile, AuthProfile, Scan]:
    target = Target(
        name="Clinical fixture",
        base_url="http://localhost:5173",
        api_url="http://localhost:3001",
        is_protected_target=True,
        safe_scan_mode=True,
    )
    db.add(target)
    db.flush()
    owner = AuthProfile(
        target_id=target.id, name="Paciente A", role_name="PACIENTE", auth_type=AuthType.NONE
    )
    tested = AuthProfile(
        target_id=target.id, name="Paciente B", role_name="PACIENTE", auth_type=AuthType.NONE
    )
    db.add_all([owner, tested])
    db.flush()
    scan = Scan(target_id=target.id, auth_profile_id=owner.id, status=ScanStatus.COMPLETED)
    db.add(scan)
    db.flush()
    endpoint = DiscoveredEndpoint(
        scan_id=scan.id,
        url="http://localhost:3001/api/patients/123/medical-record",
        path="/api/patients/123/medical-record",
        method="GET",
        source=DiscoverySource.NETWORK,
        resource_type=ResourceType.API,
        status_code=200,
        content_type="application/json",
    )
    db.add(endpoint)
    db.flush()
    db.add(
        SensitiveDataObservation(
            scan_id=scan.id,
            endpoint_id=endpoint.id,
            category=SensitiveDataCategory.MEDICAL_RECORD,
            field_path="record.diagnosis",
            detector_type=DetectorType.FIELD_NAME,
            confidence=Confidence.HIGH,
        )
    )
    db.commit()
    return target, owner, tested, scan


def test_health_check_online_uses_read_only_get() -> None:
    collector = Collector(ResponseSnapshot("http://localhost/", 404, httpx.Headers()))
    target = Target(id=1, name="x", base_url="http://localhost:5173", api_url=None)
    result = TargetHealthService(collector=collector).check(target)  # type: ignore[arg-type]
    assert result.available is True
    assert result.frontend.status == "ONLINE"
    assert collector.methods == ["GET"]


def test_health_check_offline() -> None:
    collector = Collector(httpx.ConnectError("offline"))
    target = Target(id=1, name="x", base_url="http://localhost:5173", api_url=None)
    result = TargetHealthService(collector=collector).check(target)  # type: ignore[arg-type]
    assert result.available is False
    assert result.message == "Target unavailable"


def test_tcc_target_offline_prevents_scan(client) -> None:
    target = client.post(
        "/targets",
        json={
            "name": "Clinical Med",
            "base_url": "http://localhost:5173",
            "api_url": "http://localhost:3001",
            "is_protected_target": True,
        },
    ).json()
    scan = client.post("/scans", json={"target_id": target["id"]}).json()
    with patch(
        "app.scanner.client.SafeHttpCollector.fetch", side_effect=httpx.ConnectError("offline")
    ):
        response = client.post(f"/scans/{scan['id']}/run")
    assert response.status_code == 503
    assert response.json()["detail"] == "Target unavailable"
    assert client.get(f"/scans/{scan['id']}").json()["status"] == "PENDING"


def test_target_defaults_to_safe_discovery_passive(client) -> None:
    target = client.post(
        "/targets", json={"name": "Local", "base_url": "http://localhost:5173"}
    ).json()
    assert target["safe_scan_mode"] is True
    assert target["environment"] == "LOCAL"
    scan = client.post("/scans", json={"target_id": target["id"]}).json()
    assert scan["mode"] == "DISCOVERY_PASSIVE"


def test_access_and_sensitive_surface_are_observations_not_policy(db: Session) -> None:
    target, owner, tested, _scan = seed_surface(db)
    matrix = access_surface(db, target.id)
    row = matrix.rows[0]
    assert row.access[str(owner.id)] == "OBSERVED"
    assert row.access[str(tested.id)] == "UNKNOWN"
    assert "{id}" in row.endpoint
    sensitive = sensitive_surface(db, target.id)
    assert sensitive.rows[0].categories == [SensitiveDataCategory.MEDICAL_RECORD]
    assert sensitive.rows[0].observed_by == ["Paciente A"]


def test_rule_assistant_creates_only_disabled_suggestions(db: Session) -> None:
    target, _owner, tested, _scan = seed_surface(db)
    tested_scan = Scan(target_id=target.id, auth_profile_id=tested.id, status=ScanStatus.COMPLETED)
    db.add(tested_scan)
    db.commit()
    rules = suggest_rules(db, target.id)
    assert rules
    assert all(rule.status == AuthorizationRuleStatus.SUGGESTED for rule in rules)
    assert all(rule.enabled is False for rule in rules)
    assert all(rule.suggestion_confidence == Confidence.LOW for rule in rules)


@pytest.mark.parametrize(
    ("status", "allowed"),
    [
        (AuthorizationRuleStatus.SUGGESTED, False),
        (AuthorizationRuleStatus.REJECTED, False),
        (AuthorizationRuleStatus.APPROVED, True),
    ],
)
def test_only_approved_rule_can_produce_preview(
    db: Session, status: AuthorizationRuleStatus, allowed: bool
) -> None:
    target, owner, tested, _scan = seed_surface(db)
    rule = AuthorizationRule(
        target_id=target.id,
        name="Horizontal",
        source_role=tested.role_name,
        resource_pattern="/api/patients/{id}/medical-record",
        http_method="GET",
        expected_access=ExpectedAccess.DENY,
        enabled=status == AuthorizationRuleStatus.APPROVED,
        status=status,
    )
    db.add(rule)
    db.flush()
    scenario = AuthorizationTestScenario(
        target_id=target.id,
        name="A para B",
        owner_profile_id=owner.id,
        test_profile_id=tested.id,
        authorization_rule_id=rule.id,
        enabled=True,
    )
    db.add(scenario)
    db.commit()
    if not allowed:
        with pytest.raises(AuthorizationValidationError, match="APPROVED"):
            AuthorizationService(db).plan(scenario.id)
        return
    plan = AuthorizationService(db).plan(scenario.id)
    assert plan.methods == ["GET"]
    assert plan.mutating_requests == 0
    assert plan.target_scope == "LOCAL_PRIVATE"
    assert plan.request_urls == ["http://localhost:3001/api/patients/{id}/medical-record"]


def test_login_detection_is_passive_and_requires_confirmation(db: Session) -> None:
    target, _owner, _tested, scan = seed_surface(db)
    db.add(
        DiscoveredEndpoint(
            scan_id=scan.id,
            url="http://localhost:5173/login",
            path="/login",
            method="POST",
            source=DiscoverySource.FORM,
            resource_type=ResourceType.FORM,
            parameters={"fields": ["email", "senha"]},
        )
    )
    db.commit()
    result = login_suggestions(db, target.id)
    assert result[0].username_field == "email"
    assert result[0].password_field == "senha"
    assert result[0].requires_confirmation is True


def test_cwe_coverage_keeps_owasp_optional_and_privacy_is_technical(db: Session) -> None:
    target, _owner, _tested, scan = seed_surface(db)
    db.add_all(
        [
            Finding(
                scan_id=scan.id,
                title="No direct map",
                description="fixture",
                endpoint="/fixture",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                cwe="CWE-1004",
                owasp_category=None,
                privacy_impact=PrivacyImpact.HIGH,
                evidence="sanitized",
                recommendation="fix",
            ),
            Finding(
                scan_id=scan.id,
                title="BOLA",
                description="fixture",
                endpoint="/api/patients/{id}",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                cwe="CWE-639",
                owasp_category="A01:2021 - Broken Access Control",
                privacy_impact=PrivacyImpact.CRITICAL,
                privacy_reason="technical privacy risk",
                issue_key="authz:CWE-639:GET:/api/patients/{id}",
                evidence="sanitized",
                recommendation="fix",
            ),
        ]
    )
    db.commit()
    coverage = cwe_coverage(db, target.id)
    assert coverage.mapped_to_owasp == 1
    assert coverage.without_direct_owasp_mapping == 1
    privacy = privacy_analysis(db, target.id)
    assert privacy.authorization_findings_affecting_sensitive_data == 1
    assert privacy.privacy_impact_distribution["CRITICAL"] == 1


def test_urls_are_sanitized_without_query_or_identifiers() -> None:
    value = sanitize_resource(
        "http://localhost:3001/api/patients/123/records/550e8400-e29b-41d4-a716-446655440000?token=secret"
    )
    assert value == "/api/patients/{id}/records/{id}"
    assert "secret" not in value


def test_scan_comparison_classifies_findings_and_endpoints(db: Session) -> None:
    target, owner, _tested, baseline = seed_surface(db)
    baseline_endpoint = (
        db.query(DiscoveredEndpoint).filter(DiscoveredEndpoint.scan_id == baseline.id).one()
    )
    baseline_endpoint.metadata_json = {
        "response_signature": {
            "content_type": "application/json",
            "approximate_size": 100,
            "structural_fingerprint": "stable-shape",
        }
    }
    current = Scan(
        target_id=target.id,
        auth_profile_id=owner.id,
        status=ScanStatus.COMPLETED,
    )
    db.add(current)
    db.flush()
    db.add_all(
        [
            Finding(
                scan_id=baseline.id,
                title="Persistente",
                description="fixture",
                endpoint="/shared/123?token=secret",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                cwe="CWE-1004",
                privacy_impact=PrivacyImpact.NONE,
                evidence="sanitized",
                recommendation="fix",
                issue_key="headers:CWE-1004:/shared/{id}",
            ),
            Finding(
                scan_id=current.id,
                title="Persistente",
                description="fixture",
                endpoint="/shared/456?token=other",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                cwe="CWE-1004",
                privacy_impact=PrivacyImpact.NONE,
                evidence="sanitized",
                recommendation="fix",
                issue_key="headers:CWE-1004:/shared/{id}",
            ),
            Finding(
                scan_id=baseline.id,
                title="Resolvido",
                description="fixture",
                endpoint="/old",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                cwe="CWE-16",
                privacy_impact=PrivacyImpact.NONE,
                evidence="sanitized",
                recommendation="fix",
            ),
            Finding(
                scan_id=current.id,
                title="Novo",
                description="fixture",
                endpoint="/new",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                cwe="CWE-319",
                privacy_impact=PrivacyImpact.NONE,
                evidence="sanitized",
                recommendation="fix",
            ),
            DiscoveredEndpoint(
                scan_id=current.id,
                url="http://localhost:3001/api/patients/456/medical-record",
                path="/api/patients/456/medical-record",
                method="GET",
                source=DiscoverySource.NETWORK,
                resource_type=ResourceType.API,
                status_code=201,
                metadata_json={
                    "response_signature": {
                        "content_type": "application/json",
                        "approximate_size": 105,
                        "structural_fingerprint": "stable-shape",
                    }
                },
            ),
            DiscoveredEndpoint(
                scan_id=current.id,
                url="http://localhost:3001/api/new",
                path="/api/new",
                method="POST",
                source=DiscoverySource.OPENAPI,
                resource_type=ResourceType.API,
            ),
            DiscoveredEndpoint(
                scan_id=baseline.id,
                url="http://localhost:3001/old",
                path="/old",
                method="GET",
                source=DiscoverySource.CRAWLER,
                resource_type=ResourceType.PAGE,
            ),
        ]
    )
    db.commit()

    result = scan_comparison(db, target.id, baseline.id, current.id)

    assert [item.title for item in result.new_findings] == ["Novo"]
    assert [item.title for item in result.resolved_findings] == ["Resolvido"]
    assert [item.title for item in result.persistent_findings] == ["Persistente"]
    assert result.persistent_findings[0].endpoint == "/shared/{id}"
    assert [(item.method, item.path) for item in result.added_endpoints] == [("POST", "/api/new")]
    assert [(item.method, item.path) for item in result.removed_endpoints] == [("GET", "/old")]
    assert result.compared_responses == 1
    assert result.unchanged_responses == 0
    assert result.response_changes[0].reasons == ["STATUS"]

    strict_result = scan_comparison(
        db, target.id, baseline.id, current.id, response_size_tolerance_percent=2
    )
    assert strict_result.response_changes[0].reasons == ["STATUS", "SIZE"]


def test_scan_comparison_rejects_invalid_pairs(db: Session) -> None:
    target, _owner, _tested, completed = seed_surface(db)
    pending = Scan(target_id=target.id, status=ScanStatus.PENDING)
    other_target = Target(name="Other", base_url="http://localhost:8080")
    db.add_all([pending, other_target])
    db.flush()
    other_scan = Scan(target_id=other_target.id, status=ScanStatus.COMPLETED)
    db.add(other_scan)
    db.commit()

    with pytest.raises(ValueError, match="dois scans diferentes"):
        scan_comparison(db, target.id, completed.id, completed.id)
    with pytest.raises(ValueError, match="dois scans concluídos"):
        scan_comparison(db, target.id, completed.id, pending.id)
    with pytest.raises(ValueError, match="alvo informado"):
        scan_comparison(db, target.id, completed.id, other_scan.id)


def test_authorization_run_requires_explicit_confirmation(client) -> None:
    response = client.post("/authorization/scenarios/1/run", json={})
    assert response.status_code == 422
    assert "confirmed" in response.text
