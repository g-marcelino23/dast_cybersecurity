import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

import httpx
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.core.config import Settings
from app.crawler.browser import AuthContext
from app.database.session import Base
from app.models import (
    AuthorizationProbe,
    AuthorizationRule,
    AuthorizationTestScenario,
    AuthProfile,
    DiscoveredEndpoint,
    Finding,
    Scan,
    Target,
)
from app.models.enums import (
    AuthorizationProbeResult,
    AuthorizationScenarioExecutionStatus,
    AuthType,
    Confidence,
    DiscoverySource,
    ExpectedAccess,
    PrivacyImpact,
    ResourceType,
    ScanStatus,
)
from app.scanner.base import ResponseSnapshot
from app.services.authentication import ephemeral_auth_sessions
from app.services.authorization import (
    AuthorizationExecutionConflict,
    AuthorizationService,
    AuthorizationValidationError,
    pattern_matches,
    structural_snapshot,
)


class FakeAuthenticator:
    def authenticate(self, profile, _target):
        return AuthContext(
            headers={"Authorization": f"Bearer synthetic-{profile.id}"},
            profile_id=profile.id,
            profile_name=profile.name,
            role_name=profile.role_name,
        )


class FakeCollector:
    def __init__(self, owner_id: int, tested_status: int = 200, tested_body: bytes | None = None):
        self.owner_id = owner_id
        self.tested_status = tested_status
        self.tested_body = tested_body
        self.calls: list[tuple[str, int | None]] = []

    def request(self, url, method, auth):
        self.calls.append((method, auth.profile_id))
        owner_body = b'{"patient":{"medical_record":"synthetic","diagnosis":"synthetic"}}'
        body = owner_body if auth.profile_id == self.owner_id else self.tested_body
        status = 200 if auth.profile_id == self.owner_id else self.tested_status
        return ResponseSnapshot(
            url,
            status,
            httpx.Headers({"Content-Type": "application/json"}),
            body=body,
            method=method,
        )


class RedirectCollector(FakeCollector):
    def request(self, url, method, auth):
        if auth.profile_id == self.owner_id:
            return super().request(url, method, auth)
        self.calls.append((method, auth.profile_id))
        return ResponseSnapshot(
            url,
            302,
            httpx.Headers({"Location": "https://8.8.8.8/login"}),
            method=method,
        )


class InvalidBaselineCollector(FakeCollector):
    def request(self, url, method, auth):
        response = super().request(url, method, auth)
        if auth.profile_id == self.owner_id:
            return ResponseSnapshot(
                url,
                403,
                httpx.Headers({"Content-Type": "application/json"}),
                b'{"authorized":false}',
                method,
            )
        return response


@pytest.fixture
def authz_db():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        target = Target(
            name="Fixture", base_url="http://127.0.0.1:8765", api_url="http://127.0.0.1:8766"
        )
        owner = AuthProfile(
            target_id=1, name="Paciente A", role_name="PACIENTE", auth_type=AuthType.NONE
        )
        tested = AuthProfile(
            target_id=1, name="Paciente B", role_name="PACIENTE", auth_type=AuthType.NONE
        )
        db.add_all([target, owner, tested])
        db.flush()
        scan = Scan(
            target_id=target.id,
            auth_profile_id=owner.id,
            status=ScanStatus.COMPLETED,
            total_findings=0,
        )
        db.add(scan)
        db.flush()
        endpoint = DiscoveredEndpoint(
            scan_id=scan.id,
            url="http://127.0.0.1:8766/api/patients/a/medical-record",
            path="/api/patients/a/medical-record",
            method="GET",
            source=DiscoverySource.NETWORK,
            resource_type=ResourceType.API,
            status_code=200,
            content_type="application/json",
        )
        rule = AuthorizationRule(
            target_id=target.id,
            name="Paciente não acessa prontuário de outro paciente",
            source_role="PACIENTE",
            resource_pattern="/api/patients/{patient_id}/medical-record",
            http_method="GET",
            expected_access=ExpectedAccess.DENY,
            enabled=True,
        )
        db.add_all([endpoint, rule])
        db.flush()
        scenario = AuthorizationTestScenario(
            target_id=target.id,
            name="Paciente A para Paciente B",
            owner_profile_id=owner.id,
            test_profile_id=tested.id,
            authorization_rule_id=rule.id,
            enabled=True,
        )
        db.add(scenario)
        db.commit()
        yield db, target, owner, tested, scan, endpoint, rule, scenario
    engine.dispose()


def service(db, collector, delays=None, *, max_requests=100):
    settings = Settings(
        database_url="sqlite://",
        authz_request_delay_ms=125 if delays is not None else 0,
        authz_max_requests=max_requests,
    )
    return AuthorizationService(
        db,
        collector=collector,
        authenticator=FakeAuthenticator(),
        settings=settings,
        sleeper=(lambda seconds: delays.append(seconds))
        if delays is not None
        else (lambda _: None),
    )


def test_authorization_rule_and_resource_pattern(authz_db):
    _db, _target, _owner, _tested, _scan, endpoint, rule, _scenario = authz_db
    assert rule.expected_access == ExpectedAccess.DENY
    assert pattern_matches(rule.resource_pattern, endpoint.path)
    assert not pattern_matches(rule.resource_pattern, "/api/patients/a/exams")


def test_scenario_rejects_same_profile(authz_db):
    db, target, owner, _tested, _scan, _endpoint, rule, _scenario = authz_db
    with pytest.raises(AuthorizationValidationError):
        service(db, FakeCollector(owner.id)).validate_scenario(target, owner, owner, rule)


def test_plan_uses_only_observed_endpoint(authz_db):
    db, _target, owner, _tested, _scan, _endpoint, _rule, scenario = authz_db
    plan = service(db, FakeCollector(owner.id)).plan(scenario.id)
    assert plan.total_requests == 2
    assert plan.candidates[0].endpoint == "/api/patients/{patient_id}/medical-record"
    assert "patients/a" not in plan.model_dump_json()


@pytest.mark.parametrize("status", [401, 403])
def test_expected_denial(status, authz_db):
    db, _target, owner, _tested, _scan, _endpoint, _rule, scenario = authz_db
    rows = service(db, FakeCollector(owner.id, status)).run(scenario.id)
    assert rows[0].result == AuthorizationProbeResult.DENIED_AS_EXPECTED
    assert db.scalars(__import__("sqlalchemy").select(Finding)).all() == []


def test_200_generic_is_inconclusive(authz_db):
    db, _target, owner, _tested, _scan, _endpoint, _rule, scenario = authz_db
    collector = FakeCollector(owner.id, 200, b'{"message":"generic"}')
    row = service(db, collector).run(scenario.id)[0]
    assert row.result == AuthorizationProbeResult.INCONCLUSIVE
    assert db.query(Finding).count() == 0


def test_404_is_conservative_expected_denial(authz_db):
    db, _target, owner, _tested, _scan, _endpoint, _rule, scenario = authz_db
    row = service(db, FakeCollector(owner.id, 404)).run(scenario.id)[0]
    assert row.result == AuthorizationProbeResult.DENIED_AS_EXPECTED
    assert row.confidence == Confidence.MEDIUM


def test_failed_owner_baseline_is_inconclusive(authz_db):
    db, _target, owner, _tested, _scan, _endpoint, _rule, scenario = authz_db
    row = service(db, InvalidBaselineCollector(owner.id, 403)).run(scenario.id)[0]
    assert row.result == AuthorizationProbeResult.INCONCLUSIVE
    assert db.query(Finding).count() == 0


def test_allow_rule_and_head_are_supported(authz_db):
    db, _target, owner, _tested, _scan, endpoint, rule, scenario = authz_db
    endpoint.method = rule.http_method = "HEAD"
    rule.expected_access = ExpectedAccess.ALLOW
    db.commit()
    collector = FakeCollector(owner.id, 200)
    row = service(db, collector).run(scenario.id)[0]
    assert row.result == AuthorizationProbeResult.ALLOWED_AS_EXPECTED
    assert collector.calls == [("HEAD", owner.id), ("HEAD", scenario.test_profile_id)]


def test_confirmed_idor_generates_sanitized_finding(authz_db):
    db, _target, owner, _tested, _scan, _endpoint, _rule, scenario = authz_db
    body = b'{"patient":{"medical_record":"do-not-persist","diagnosis":"secret"}}'
    row = service(db, FakeCollector(owner.id, 200, body)).run(scenario.id)[0]
    finding = db.query(Finding).one()
    assert row.result == AuthorizationProbeResult.CONFIRMED_BYPASS
    assert finding.cwe == "CWE-639"
    assert finding.privacy_impact == PrivacyImpact.CRITICAL
    assert set(row.sensitive_categories) == {"MEDICAL_RECORD", "HEALTH_INFORMATION"}
    serialized = json.dumps(
        {key: value for key, value in row.__dict__.items() if not key.startswith("_")}, default=str
    )
    assert "do-not-persist" not in serialized and "secret" not in serialized


def test_structural_fingerprint_uses_types_not_values():
    first = ResponseSnapshot(
        "http://localhost/a",
        200,
        httpx.Headers({"content-type": "application/json"}),
        b'{"patient":{"name":"A","exams":[]}}',
    )
    second = ResponseSnapshot(
        "http://localhost/b",
        200,
        httpx.Headers({"content-type": "application/json"}),
        b'{"patient":{"name":"B","exams":[]}}',
    )
    one, two = structural_snapshot(first), structural_snapshot(second)
    assert one.fingerprint == two.fingerprint
    assert "A" not in json.dumps(one.metadata)


def test_empty_json_has_deterministic_structural_fingerprint():
    empty_list = ResponseSnapshot(
        "http://localhost/empty-list",
        200,
        httpx.Headers({"content-type": "application/json"}),
        b"[]",
    )
    same_empty_list = ResponseSnapshot(
        "http://localhost/another-empty-list",
        200,
        httpx.Headers({"content-type": "application/json"}),
        b"[]",
    )
    empty_object = ResponseSnapshot(
        "http://localhost/empty-object",
        200,
        httpx.Headers({"content-type": "application/json"}),
        b"{}",
    )

    list_shape = structural_snapshot(empty_list)
    assert list_shape.fingerprint is not None
    assert list_shape.fingerprint == structural_snapshot(same_empty_list).fingerprint
    assert list_shape.fingerprint != structural_snapshot(empty_object).fingerprint
    assert list_shape.metadata["field_paths"] == ["$:array(empty)"]


def test_html_fingerprint_uses_structure_without_values():
    first = ResponseSnapshot(
        "http://localhost/a",
        200,
        httpx.Headers({"content-type": "text/html"}),
        b'<main data-patient="Alice"><h1>Private value</h1></main>',
    )
    second = ResponseSnapshot(
        "http://localhost/b",
        200,
        httpx.Headers({"content-type": "text/html"}),
        b'<main data-patient="Bob"><h1>Another value</h1></main>',
    )

    one, two = structural_snapshot(first), structural_snapshot(second)

    assert one.fingerprint == two.fingerprint
    assert "Alice" not in json.dumps(one.metadata)
    assert "Private value" not in json.dumps(one.metadata)


def test_mutating_method_is_skipped_without_requests(authz_db):
    db, _target, owner, _tested, _scan, endpoint, rule, scenario = authz_db
    endpoint.method = rule.http_method = "POST"
    db.commit()
    collector = FakeCollector(owner.id)
    row = service(db, collector).run(scenario.id)[0]
    assert row.result == AuthorizationProbeResult.SKIPPED
    assert row.baseline_metadata == {"reason": "NOT_TESTED_MUTATING_METHOD"}
    assert collector.calls == []


def test_auth_contexts_are_isolated_and_only_get(authz_db):
    db, _target, owner, tested, _scan, _endpoint, _rule, scenario = authz_db
    collector = FakeCollector(owner.id, 403)
    service(db, collector).run(scenario.id)
    assert collector.calls == [("GET", owner.id), ("GET", tested.id)]


def test_probe_reuses_and_discards_isolated_ephemeral_sessions(authz_db):
    db, target, owner, tested, _scan, _endpoint, _rule, scenario = authz_db

    class UnexpectedAuthenticator:
        def authenticate(self, _profile, _target):
            raise AssertionError("ephemeral AuthContext should have been reused")

    ephemeral_auth_sessions.put(
        owner,
        AuthContext(headers={"X-Synthetic": "owner"}, profile_id=owner.id),
    )
    ephemeral_auth_sessions.put(
        tested,
        AuthContext(headers={"X-Synthetic": "tested"}, profile_id=tested.id),
    )
    collector = FakeCollector(owner.id, 403)
    rows = AuthorizationService(
        db,
        collector=collector,
        authenticator=UnexpectedAuthenticator(),
        settings=Settings(database_url="sqlite://", authz_request_delay_ms=0),
    ).run(scenario.id)

    assert rows[0].result == AuthorizationProbeResult.DENIED_AS_EXPECTED
    assert collector.calls == [("GET", owner.id), ("GET", tested.id)]
    assert not ephemeral_auth_sessions.contains(owner.id)
    assert not ephemeral_auth_sessions.contains(tested.id)


def test_request_limit_prevents_network(authz_db):
    db, _target, owner, _tested, _scan, _endpoint, _rule, scenario = authz_db
    collector = FakeCollector(owner.id)
    with pytest.raises(AuthorizationValidationError, match="AUTHZ_MAX_REQUESTS"):
        service(db, collector, max_requests=1).run(scenario.id)
    assert collector.calls == []


def test_rate_limit_is_configurable(authz_db):
    db, _target, owner, _tested, _scan, _endpoint, _rule, scenario = authz_db
    delays = []
    service(db, FakeCollector(owner.id, 403), delays).run(scenario.id)
    assert delays == [0.125, 0.125]


def test_ssrf_endpoint_is_blocked(authz_db):
    db, _target, owner, _tested, _scan, endpoint, _rule, scenario = authz_db
    endpoint.url = "http://8.8.8.8/api/patients/a/medical-record"
    db.commit()
    real_service = AuthorizationService(
        db,
        authenticator=FakeAuthenticator(),
        settings=Settings(database_url="sqlite://", authz_request_delay_ms=0),
    )
    assert real_service.run(scenario.id)[0].result == AuthorizationProbeResult.ERROR


def test_external_redirect_is_not_followed_and_is_error(authz_db):
    db, _target, owner, _tested, _scan, _endpoint, _rule, scenario = authz_db
    collector = RedirectCollector(owner.id)
    row = service(db, collector).run(scenario.id)[0]
    assert row.result == AuthorizationProbeResult.ERROR
    assert len(collector.calls) == 2


def test_sanitized_query_candidate_is_not_replayed(authz_db):
    db, _target, owner, _tested, _scan, endpoint, rule, scenario = authz_db
    endpoint.url = "http://127.0.0.1:8766/api/patients?id={value}"
    endpoint.path = rule.resource_pattern = "/api/patients"
    db.commit()
    with pytest.raises(AuthorizationValidationError, match="Nenhum endpoint"):
        service(db, FakeCollector(owner.id)).run(scenario.id)


def test_api_rule_scenario_validation_and_probe_summary(client):
    target = client.post(
        "/targets", json={"name": "Local", "base_url": "http://127.0.0.1:8765"}
    ).json()
    base = {"role_name": "PACIENTE", "auth_type": "NONE", "http_method": "POST"}
    owner = client.post(
        f"/targets/{target['id']}/auth-profiles", json={**base, "name": "Paciente A"}
    ).json()
    tested = client.post(
        f"/targets/{target['id']}/auth-profiles", json={**base, "name": "Paciente B"}
    ).json()
    rule = client.post(
        f"/targets/{target['id']}/authorization-rules",
        json={
            "name": "IDOR",
            "source_role": "PACIENTE",
            "resource_pattern": "/api/patients/{id}/medical-record",
            "http_method": "GET",
            "expected_access": "DENY",
        },
    ).json()
    invalid = client.post(
        f"/targets/{target['id']}/authorization-scenarios",
        json={
            "name": "Inválido",
            "owner_profile_id": owner["id"],
            "test_profile_id": owner["id"],
            "authorization_rule_id": rule["id"],
        },
    )
    assert invalid.status_code == 422
    valid = client.post(
        f"/targets/{target['id']}/authorization-scenarios",
        json={
            "name": "Horizontal",
            "owner_profile_id": owner["id"],
            "test_profile_id": tested["id"],
            "authorization_rule_id": rule["id"],
        },
    )
    assert valid.status_code == 201
    scan = client.post(
        "/scans", json={"target_id": target["id"], "auth_profile_id": owner["id"]}
    ).json()
    summary = client.get(f"/scans/{scan['id']}/authorization-summary").json()
    assert summary["total_probes"] == 0
    assert client.get(f"/scans/{scan['id']}/authorization-probes").json() == []


def test_api_returns_safe_conflict_for_running_scenario(client, monkeypatch):
    def reject_running(_service, _scenario_id, *, rerun=False):
        assert rerun is False
        raise AuthorizationExecutionConflict(
            "SCENARIO_ALREADY_RUNNING", "Este cenário de autorização já está em execução."
        )

    monkeypatch.setattr(AuthorizationService, "run", reject_running)
    response = client.post(
        "/authorization/scenarios/11/run", json={"confirmed": True, "rerun": False}
    )

    assert response.status_code == 409
    assert response.json() == {
        "detail": {
            "code": "SCENARIO_ALREADY_RUNNING",
            "message": "Este cenário de autorização já está em execução.",
        }
    }


@pytest.fixture
def concurrent_authz_engine(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'authorization-concurrency.db'}",
        connect_args={"check_same_thread": False, "timeout": 5},
    )
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        target = Target(
            name="Concurrent Fixture",
            base_url="http://127.0.0.1:8765",
            api_url="http://127.0.0.1:8766",
        )
        db.add(target)
        db.flush()
        owner = AuthProfile(
            target_id=target.id,
            name="Owner",
            role_name="OWNER",
            auth_type=AuthType.NONE,
        )
        tested = AuthProfile(
            target_id=target.id,
            name="Tested",
            role_name="TESTED",
            auth_type=AuthType.NONE,
        )
        db.add_all([owner, tested])
        db.flush()
        scan = Scan(
            target_id=target.id,
            auth_profile_id=owner.id,
            status=ScanStatus.COMPLETED,
        )
        db.add(scan)
        db.flush()
        endpoint = DiscoveredEndpoint(
            scan_id=scan.id,
            url="http://127.0.0.1:8766/api/admin",
            path="/api/admin",
            method="GET",
            source=DiscoverySource.NETWORK,
            resource_type=ResourceType.API,
            status_code=200,
            content_type="application/json",
        )
        rule = AuthorizationRule(
            target_id=target.id,
            name="Admin denied",
            source_role=tested.role_name,
            resource_pattern="/api/admin",
            http_method="GET",
            expected_access=ExpectedAccess.DENY,
            enabled=True,
        )
        db.add_all([endpoint, rule])
        db.flush()
        scenario = AuthorizationTestScenario(
            target_id=target.id,
            name="Concurrent scenario",
            owner_profile_id=owner.id,
            test_profile_id=tested.id,
            authorization_rule_id=rule.id,
            enabled=True,
        )
        db.add(scenario)
        db.commit()
        yield engine, scenario.id, owner.id, tested.id, target.id, rule.id
    engine.dispose()


class BlockingCollector(FakeCollector):
    def __init__(self, owner_id: int):
        super().__init__(owner_id, 403)
        self.entered = threading.Event()
        self.release = threading.Event()

    def request(self, url, method, auth):
        if not self.calls:
            self.entered.set()
            assert self.release.wait(timeout=5)
        return super().request(url, method, auth)


def concurrent_service(db, collector):
    return AuthorizationService(
        db,
        collector=collector,
        authenticator=FakeAuthenticator(),
        settings=Settings(database_url="sqlite://", authz_request_delay_ms=0),
        sleeper=lambda _: None,
    )


def test_simultaneous_same_scenario_executes_only_one_probe(concurrent_authz_engine):
    engine, scenario_id, owner_id, _tested_id, _target_id, _rule_id = concurrent_authz_engine
    collector = BlockingCollector(owner_id)

    def first_run():
        with Session(engine) as db:
            return concurrent_service(db, collector).run(scenario_id)

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(first_run)
        assert collector.entered.wait(timeout=5)
        with Session(engine) as second_db:
            with pytest.raises(AuthorizationExecutionConflict) as caught:
                concurrent_service(second_db, collector).run(scenario_id)
            assert caught.value.code == "SCENARIO_ALREADY_RUNNING"
        collector.release.set()
        assert future.result()[0].result == AuthorizationProbeResult.DENIED_AS_EXPECTED

    with Session(engine) as audit_db:
        assert len(collector.calls) == 2
        assert len(audit_db.scalars(select(AuthorizationProbe)).all()) == 1


def test_running_scenario_is_rejected_without_external_requests(concurrent_authz_engine):
    engine, scenario_id, owner_id, _tested_id, _target_id, _rule_id = concurrent_authz_engine
    with Session(engine) as db:
        scenario = db.get(AuthorizationTestScenario, scenario_id)
        assert scenario is not None
        scenario.execution_status = AuthorizationScenarioExecutionStatus.RUNNING
        scenario.execution_started_at = datetime.now(UTC)
        db.commit()
        collector = FakeCollector(owner_id, 403)
        with pytest.raises(AuthorizationExecutionConflict) as caught:
            concurrent_service(db, collector).run(scenario_id)
        assert caught.value.code == "SCENARIO_ALREADY_RUNNING"
        assert collector.calls == []


def test_double_click_requires_explicit_rerun(concurrent_authz_engine):
    engine, scenario_id, owner_id, _tested_id, _target_id, _rule_id = concurrent_authz_engine
    collector = FakeCollector(owner_id, 403)
    with Session(engine) as db:
        runner = concurrent_service(db, collector)
        runner.run(scenario_id)
        with pytest.raises(AuthorizationExecutionConflict) as caught:
            runner.run(scenario_id)
        assert caught.value.code == "SCENARIO_RERUN_REQUIRED"
        assert len(collector.calls) == 2
        runner.run(scenario_id, rerun=True)
        assert len(collector.calls) == 4
        assert db.query(AuthorizationProbe).count() == 2


def test_different_scenario_can_execute_normally(concurrent_authz_engine):
    engine, scenario_id, owner_id, tested_id, target_id, rule_id = concurrent_authz_engine
    collector = FakeCollector(owner_id, 403)
    with Session(engine) as db:
        another = AuthorizationTestScenario(
            target_id=target_id,
            name="Different scenario",
            owner_profile_id=owner_id,
            test_profile_id=tested_id,
            authorization_rule_id=rule_id,
            enabled=True,
        )
        db.add(another)
        db.commit()
        concurrent_service(db, collector).run(scenario_id)
        concurrent_service(db, collector).run(another.id)
        assert len(collector.calls) == 4
        assert db.query(AuthorizationProbe).count() == 2


def test_failure_releases_running_state_and_allows_explicit_rerun(concurrent_authz_engine):
    engine, scenario_id, owner_id, _tested_id, _target_id, _rule_id = concurrent_authz_engine

    class FailingCollector(FakeCollector):
        def request(self, url, method, auth):
            raise RuntimeError("synthetic collector failure")

    with Session(engine) as db:
        with pytest.raises(RuntimeError, match="synthetic collector failure"):
            concurrent_service(db, FailingCollector(owner_id)).run(scenario_id)
        db.expire_all()
        scenario = db.get(AuthorizationTestScenario, scenario_id)
        assert scenario is not None
        assert scenario.execution_status == AuthorizationScenarioExecutionStatus.FAILED
        healthy = FakeCollector(owner_id, 403)
        concurrent_service(db, healthy).run(scenario_id, rerun=True)
        assert len(healthy.calls) == 2
        db.refresh(scenario)
        assert scenario.execution_status == AuthorizationScenarioExecutionStatus.COMPLETED
