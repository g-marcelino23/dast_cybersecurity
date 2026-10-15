import json
from collections.abc import Iterator

import httpx
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.crawler.browser import AuthContext
from app.crawler.models import DiscoveryResult, EndpointObservation
from app.database.session import Base
from app.models import (
    AuthorizationCandidate,
    AuthProfile,
    RoleSurfaceSnapshot,
    Scan,
    Target,
)
from app.models.enums import (
    AuthorizationRuleStatus,
    AuthType,
    DiscoverySource,
    ResourceType,
    ScanStatus,
)
from app.scanner.base import ResponseSnapshot
from app.scanner.engine import ScanResult
from app.services.authorization import structural_snapshot
from app.services.insights import (
    access_profile_surface,
    generate_authorization_candidates,
    role_comparison,
    scan_summary,
)
from app.services.scans import ScanService


@pytest.fixture
def db() -> Iterator[Session]:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    engine.dispose()


class FakeAuthenticator:
    def authenticate(self, profile: AuthProfile, _target: Target) -> AuthContext:
        return AuthContext(
            headers={"Authorization": f"Bearer ephemeral-{profile.id}"},
            profile_id=profile.id,
            profile_name=profile.name,
            role_name=profile.role_name,
        )


class FakeHealth:
    def ensure_available(self, _target: Target) -> None:
        return None


class FakeEngine:
    def run(
        self,
        _urls: list[str],
        _auth: AuthContext | None = None,
        _enabled_modules: list[str] | None = None,
    ) -> ScanResult:
        return ScanResult(findings=[], observations=[], responses=[])

    def analyze(
        self,
        _responses: list[ResponseSnapshot],
        _enabled_modules: list[str] | None = None,
    ):
        return []


class ProfileCrawler:
    def crawl(
        self, _base_url: str, api_url: str | None = None, auth: AuthContext | None = None
    ) -> DiscoveryResult:
        assert auth is not None and auth.profile_id is not None
        origin = api_url or "http://127.0.0.1:8765"
        unique = "doctor/dashboard" if auth.role_name == "MEDICO" else "patient/profile"
        definitions = [
            ("common", "GET", ResourceType.API),
            (unique, "GET", ResourceType.API),
            ("search", "POST", ResourceType.FORM),
        ]
        endpoints = [
            EndpointObservation(
                url=f"{origin}/api/{path}",
                path=f"/api/{path}",
                method=method,
                source=DiscoverySource.NETWORK,
                resource_type=resource_type,
                status_code=200,
                content_type="application/json",
                requires_auth=True,
            )
            for path, method, resource_type in definitions
        ]
        body = b'{"record":{"diagnosis":"never-persist-this-clinical-value"}}'
        return DiscoveryResult(
            endpoints=endpoints,
            responses=[
                ResponseSnapshot(
                    endpoint=endpoints[1].url,
                    status_code=200,
                    headers=httpx.Headers({"Content-Type": "application/json"}),
                    body=body,
                    method="GET",
                )
            ],
            requests_observed=3,
        )


def seed(db: Session) -> tuple[Target, AuthProfile, AuthProfile]:
    target = Target(
        name="Local authorized fixture",
        base_url="http://127.0.0.1:8765",
        api_url="http://127.0.0.1:8766",
        safe_scan_mode=True,
    )
    db.add(target)
    db.flush()
    doctor = AuthProfile(
        target_id=target.id,
        name="Médico A",
        role_name="MEDICO",
        auth_type=AuthType.NONE,
        last_auth_success=True,
    )
    patient = AuthProfile(
        target_id=target.id,
        name="Paciente A",
        role_name="PACIENTE",
        auth_type=AuthType.NONE,
        last_auth_success=True,
    )
    db.add_all([doctor, patient])
    db.commit()
    return target, doctor, patient


def run_profile_scan(db: Session, target: Target, profile: AuthProfile, label: str) -> Scan:
    scan = Scan(
        target_id=target.id,
        auth_profile_id=profile.id,
        experiment_label=label,
        dast_version="0.20.0",
        modules_enabled=["discovery", "sensitive_data"],
        configuration_snapshot={"safe_scan_mode": True},
    )
    db.add(scan)
    db.commit()
    return ScanService(
        db,
        engine=FakeEngine(),  # type: ignore[arg-type]
        crawler=ProfileCrawler(),  # type: ignore[arg-type]
        authenticator=FakeAuthenticator(),  # type: ignore[arg-type]
        health_service=FakeHealth(),  # type: ignore[arg-type]
    ).run(scan.id)


def test_authenticated_discovery_creates_sanitized_role_snapshot(db: Session) -> None:
    target, doctor, _patient = seed(db)
    scan = run_profile_scan(db, target, doctor, "MEDICO_A_DISCOVERY_001")
    snapshot = db.scalar(
        select(RoleSurfaceSnapshot).where(RoleSurfaceSnapshot.scan_id == scan.id)
    )
    assert scan.status == ScanStatus.COMPLETED
    assert snapshot is not None
    assert snapshot.auth_profile_id == doctor.id
    assert snapshot.api_endpoints == 2
    assert snapshot.forms == 1
    assert snapshot.methods == ["GET", "POST"]
    assert doctor.last_authenticated_scan_id == scan.id
    serialized = json.dumps(snapshot.__dict__, default=str)
    assert "never-persist-this-clinical-value" not in serialized
    assert "Bearer" not in serialized


def test_role_surface_reports_snapshot_metadata(db: Session) -> None:
    target, doctor, _patient = seed(db)
    scan = run_profile_scan(db, target, doctor, "MEDICO_A_DISCOVERY_002")
    surface = access_profile_surface(db, doctor.id)
    assert surface.last_scan_id == scan.id
    assert surface.api_endpoints == 2
    assert surface.forms == 1
    assert "HEALTH_INFORMATION" in {item.value for item in surface.sensitive_categories}
    assert surface.message is None


def test_role_surface_without_scan_is_explicit(db: Session) -> None:
    _target, _doctor, patient = seed(db)
    surface = access_profile_surface(db, patient.id)
    assert surface.last_scan_id is None
    assert surface.message == "No authenticated scan has been executed for this profile."


def test_role_comparison_uses_neutral_observation_states(db: Session) -> None:
    target, doctor, patient = seed(db)
    run_profile_scan(db, target, doctor, "DOCTOR_001")
    run_profile_scan(db, target, patient, "PATIENT_001")
    comparison = role_comparison(db, target.id, doctor.id, patient.id)
    states = {row.endpoint: row.state for row in comparison.rows}
    assert states["/api/common"] == "COMMON"
    assert states["/api/doctor/dashboard"] == "ONLY_PROFILE_A"
    assert states["/api/patient/profile"] == "ONLY_PROFILE_B"
    assert "not proof" in comparison.message


def test_role_comparison_is_unknown_until_both_scans_exist(db: Session) -> None:
    target, doctor, patient = seed(db)
    run_profile_scan(db, target, doctor, "DOCTOR_ONLY")
    comparison = role_comparison(db, target.id, doctor.id, patient.id)
    assert comparison.rows
    assert all(row.state == "UNKNOWN" for row in comparison.rows)
    assert comparison.profile_b_scan_id is None


def test_candidate_generation_is_read_only_suggested_and_idempotent(db: Session) -> None:
    target, doctor, patient = seed(db)
    run_profile_scan(db, target, doctor, "DOCTOR_CANDIDATE")
    run_profile_scan(db, target, patient, "PATIENT_CANDIDATE")
    created = generate_authorization_candidates(db, target.id, doctor.id, patient.id)
    assert len(created) == 2
    assert all(item.method in {"GET", "HEAD"} for item in created)
    assert all(item.status == AuthorizationRuleStatus.SUGGESTED for item in created)
    assert all(item.confidence.value == "LOW" for item in created)
    assert generate_authorization_candidates(db, target.id, doctor.id, patient.id) == []
    assert (
        db.scalar(
            select(AuthorizationCandidate).where(AuthorizationCandidate.method == "POST")
        )
        is None
    )


def test_structural_baseline_persists_only_allowlisted_headers() -> None:
    response = ResponseSnapshot(
        endpoint="http://localhost/api/patients/123?token=secret",
        status_code=200,
        headers=httpx.Headers(
            {
                "Content-Type": "application/json",
                "Content-Length": "42",
                "Authorization": "Bearer must-not-persist",
                "Set-Cookie": "session=must-not-persist",
                "Location": "/patients/123?token=must-not-persist",
            }
        ),
        body=b'{"patient":{"diagnosis":"private"}}',
    )
    baseline = structural_snapshot(response)
    assert baseline.fingerprint is not None and len(baseline.fingerprint) == 64
    assert baseline.metadata["status_code"] == 200
    assert baseline.metadata["approximate_size"] == len(response.body or b"")
    serialized = json.dumps(baseline.metadata)
    assert "Authorization" not in serialized
    assert "Set-Cookie" not in serialized
    assert "must-not-persist" not in serialized
    assert "private" not in serialized


def test_tcc_summary_includes_authenticated_methodology_metadata(db: Session) -> None:
    target, doctor, _patient = seed(db)
    scan = run_profile_scan(db, target, doctor, "MEDICO_A_DISCOVERY_003")
    summary = scan_summary(db, scan.id)
    assert summary.experiment_label == "MEDICO_A_DISCOVERY_003"
    assert summary.authenticated is True
    assert summary.scan_profile == "Médico A"
    assert summary.role_name == "MEDICO"
    assert summary.forms == 1
    assert summary.authorization_probes == 0
    assert "never-persist-this-clinical-value" not in summary.model_dump_json()
