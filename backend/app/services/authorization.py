import logging
import re
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Protocol, cast
from urllib.parse import urljoin

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.target_policy import TargetPolicyError, validate_target
from app.crawler.normalizer import normalize_url
from app.models import (
    AuthorizationProbe,
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
    AuthorizationProbeResult,
    AuthorizationRuleStatus,
    AuthorizationScenarioExecutionStatus,
    Confidence,
    ExpectedAccess,
    PrivacyImpact,
    ScanStatus,
    SensitiveDataCategory,
    Severity,
)
from app.privacy import SensitiveDataDetector
from app.scanner.base import ResponseSnapshot
from app.scanner.client import SafeHttpCollector
from app.schemas.entities import AuthorizationSummary, AuthorizationTestPlan, ResourceCandidate
from app.services.analysis import sanitize_resource
from app.services.authentication import Authenticator, ephemeral_auth_sessions
from app.services.ownership import verified_public_hosts
from app.services.response_signatures import StructuralSnapshot, structural_snapshot

logger = logging.getLogger(__name__)
PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
HIGH_SENSITIVITY_CATEGORIES = {
    SensitiveDataCategory.HEALTH_INFORMATION,
    SensitiveDataCategory.MEDICAL_RECORD,
    SensitiveDataCategory.PRESCRIPTION,
    SensitiveDataCategory.MEDICATION,
    SensitiveDataCategory.EXAM_RESULT,
    SensitiveDataCategory.DIAGNOSIS,
}


class AuthorizationValidationError(ValueError):
    pass


class AuthorizationExecutionConflict(AuthorizationValidationError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class RowCountResult(Protocol):
    rowcount: int


def pattern_matches(pattern: str, path: str) -> bool:
    normalized_pattern = pattern if pattern.startswith("/") else f"/{pattern}"
    cursor = 0
    fragments: list[str] = []
    for match in PLACEHOLDER.finditer(normalized_pattern):
        fragments.append(re.escape(normalized_pattern[cursor : match.start()]))
        fragments.append(r"[^/?#]+")
        cursor = match.end()
    fragments.append(re.escape(normalized_pattern[cursor:]))
    return re.fullmatch("".join(fragments), path) is not None


def privacy_impact(categories: set[SensitiveDataCategory]) -> PrivacyImpact:
    if categories & HIGH_SENSITIVITY_CATEGORIES:
        return PrivacyImpact.CRITICAL
    if SensitiveDataCategory.PERSONAL_IDENTIFIER in categories:
        return PrivacyImpact.HIGH
    return PrivacyImpact.MEDIUM


class AuthorizationService:
    def __init__(
        self,
        db: Session,
        *,
        collector: SafeHttpCollector | None = None,
        authenticator: Authenticator | None = None,
        detector: SensitiveDataDetector | None = None,
        settings: Settings | None = None,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self.db = db
        self.collector = collector or SafeHttpCollector()
        self.authenticator = authenticator or Authenticator()
        self.detector = detector or SensitiveDataDetector()
        self.settings = settings or get_settings()
        self.sleeper = sleeper

    def validate_scenario(
        self, target: Target, owner: AuthProfile, tested: AuthProfile, rule: AuthorizationRule
    ) -> None:
        if target.is_protected_target and not target.safe_scan_mode:
            raise AuthorizationValidationError(
                "Safe Scan Mode é obrigatório para testes no alvo protegido."
            )
        if owner.id == tested.id:
            raise AuthorizationValidationError(
                "Os perfis proprietário e de teste devem ser diferentes."
            )
        if any(item.target_id != target.id for item in (owner, tested, rule)):
            raise AuthorizationValidationError("Perfis e regra devem pertencer ao mesmo alvo.")
        if tested.role_name.casefold() != rule.source_role.casefold():
            raise AuthorizationValidationError(
                "O papel da regra deve corresponder ao perfil de teste."
            )
        if not rule.resource_pattern.startswith("/"):
            raise AuthorizationValidationError("Resource Pattern deve iniciar com '/'.")

    def _load(
        self, scenario_id: int
    ) -> tuple[AuthorizationTestScenario, Target, AuthProfile, AuthProfile, AuthorizationRule]:
        scenario = self.db.get(AuthorizationTestScenario, scenario_id)
        if scenario is None:
            raise AuthorizationValidationError("Cenário não encontrado.")
        target = self.db.get(Target, scenario.target_id)
        owner = self.db.get(AuthProfile, scenario.owner_profile_id)
        tested = self.db.get(AuthProfile, scenario.test_profile_id)
        rule = self.db.get(AuthorizationRule, scenario.authorization_rule_id)
        if not all((target, owner, tested, rule)):
            raise AuthorizationValidationError("Cenário possui referência inválida.")
        assert target and owner and tested and rule
        self.validate_scenario(target, owner, tested, rule)
        return scenario, target, owner, tested, rule

    def _owner_scan(self, target_id: int, profile_id: int) -> Scan:
        scan = self.db.scalar(
            select(Scan)
            .where(
                Scan.target_id == target_id,
                Scan.auth_profile_id == profile_id,
                Scan.status == ScanStatus.COMPLETED,
            )
            .order_by(Scan.id.desc())
        )
        if scan is None:
            raise AuthorizationValidationError(
                "Execute primeiro um scan autenticado concluído com o perfil proprietário."
            )
        return scan

    def _candidates(
        self, scan: Scan, rule: AuthorizationRule
    ) -> list[tuple[DiscoveredEndpoint, ResourceCandidate]]:
        rows = list(
            self.db.scalars(
                select(DiscoveredEndpoint)
                .where(DiscoveredEndpoint.scan_id == scan.id)
                .order_by(DiscoveredEndpoint.id)
            )
        )
        placeholders = PLACEHOLDER.findall(rule.resource_pattern)
        candidates: list[tuple[DiscoveredEndpoint, ResourceCandidate]] = []
        seen: set[tuple[str, str]] = set()
        for endpoint in rows:
            if endpoint.method != rule.http_method or not pattern_matches(
                rule.resource_pattern, endpoint.path
            ):
                continue
            # Normalized query URLs intentionally discard values, so they cannot be replayed.
            if "?" in endpoint.url:
                continue
            key = (endpoint.method, endpoint.url)
            if key in seen:
                continue
            seen.add(key)
            candidates.append(
                (
                    endpoint,
                    ResourceCandidate(
                        endpoint=rule.resource_pattern,
                        method=endpoint.method,
                        resource_pattern=rule.resource_pattern,
                        identifier_location="path" if placeholders else "configured",
                        identifier_name=",".join(placeholders) or "none",
                        discovered_by_profile=scan.auth_profile_id or 0,
                        confidence=Confidence.HIGH if placeholders else Confidence.MEDIUM,
                    ),
                )
            )
        return candidates

    def plan(self, scenario_id: int) -> AuthorizationTestPlan:
        scenario, target, owner, tested, rule = self._load(scenario_id)
        if rule.status != AuthorizationRuleStatus.APPROVED:
            raise AuthorizationValidationError("Somente regras APPROVED podem gerar um plano.")
        scan = self._owner_scan(scenario.target_id, owner.id)
        candidates = [candidate for _endpoint, candidate in self._candidates(scan, rule)]
        safe = rule.http_method in {"GET", "HEAD"}
        request_count = len(candidates) * 2 if safe else 0
        return AuthorizationTestPlan(
            scenario_id=scenario.id,
            scenarios=1,
            get_requests=request_count if rule.http_method == "GET" else 0,
            head_requests=request_count if rule.http_method == "HEAD" else 0,
            mutating_requests=0,
            total_requests=request_count,
            owner_profile=owner.name,
            test_profile=tested.name,
            candidates=candidates,
            target_name=target.name,
            rules_approved=1,
            methods=[rule.http_method] if safe else [],
            sensitive_endpoints=len(
                {
                    item.endpoint_id
                    for item in self.db.scalars(
                        select(SensitiveDataObservation).where(
                            SensitiveDataObservation.scan_id == scan.id
                        )
                    )
                }
            ),
            target_scope=(
                "VERIFIED_PUBLIC" if target.requires_ownership_verification else "LOCAL_PRIVATE"
            ),
            request_urls=[
                f"{normalize_url(target.api_url or target.base_url).origin}"
                f"{sanitize_resource(rule.resource_pattern)}"
                for _endpoint, _candidate in self._candidates(scan, rule)
            ],
        )

    def _claim_execution(self, scenario_id: int, *, rerun: bool) -> AuthorizationTestScenario:
        now = datetime.now(UTC)
        stale_before = now - timedelta(seconds=self.settings.authz_execution_stale_seconds)
        self.db.execute(
            update(AuthorizationTestScenario)
            .execution_options(synchronize_session=False)
            .where(
                AuthorizationTestScenario.id == scenario_id,
                AuthorizationTestScenario.execution_status
                == AuthorizationScenarioExecutionStatus.RUNNING,
                AuthorizationTestScenario.execution_started_at < stale_before,
            )
            .values(
                execution_status=AuthorizationScenarioExecutionStatus.INTERRUPTED,
                execution_finished_at=now,
                execution_error_code="SCENARIO_EXECUTION_INTERRUPTED",
            )
        )
        self.db.commit()

        allowed = [AuthorizationScenarioExecutionStatus.READY]
        if rerun:
            allowed.extend(
                [
                    AuthorizationScenarioExecutionStatus.COMPLETED,
                    AuthorizationScenarioExecutionStatus.FAILED,
                    AuthorizationScenarioExecutionStatus.INTERRUPTED,
                ]
            )
        claimed = cast(
            RowCountResult,
            self.db.execute(
                update(AuthorizationTestScenario)
                .execution_options(synchronize_session=False)
                .where(
                    AuthorizationTestScenario.id == scenario_id,
                    AuthorizationTestScenario.execution_status.in_(allowed),
                )
                .values(
                    execution_status=AuthorizationScenarioExecutionStatus.RUNNING,
                    execution_started_at=now,
                    execution_finished_at=None,
                    execution_error_code=None,
                    execution_attempt=AuthorizationTestScenario.execution_attempt + 1,
                )
            ),
        )
        self.db.commit()
        self.db.expire_all()
        scenario = self.db.get(AuthorizationTestScenario, scenario_id)
        if scenario is None:
            raise AuthorizationValidationError("Cenário não encontrado.")
        if claimed.rowcount == 1:
            return scenario
        if scenario.execution_status == AuthorizationScenarioExecutionStatus.RUNNING:
            raise AuthorizationExecutionConflict(
                "SCENARIO_ALREADY_RUNNING",
                "Este cenário de autorização já está em execução.",
            )
        raise AuthorizationExecutionConflict(
            "SCENARIO_RERUN_REQUIRED",
            "O cenário já foi executado. Use a ação explícita de nova execução.",
        )

    def _finish_execution(
        self,
        scenario_id: int,
        status: AuthorizationScenarioExecutionStatus,
        error_code: str | None = None,
    ) -> None:
        self.db.rollback()
        self.db.execute(
            update(AuthorizationTestScenario)
            .execution_options(synchronize_session=False)
            .where(
                AuthorizationTestScenario.id == scenario_id,
                AuthorizationTestScenario.execution_status
                == AuthorizationScenarioExecutionStatus.RUNNING,
            )
            .values(
                execution_status=status,
                execution_finished_at=datetime.now(UTC),
                execution_error_code=error_code,
            )
        )
        self.db.commit()

    def run(self, scenario_id: int, *, rerun: bool = False) -> list[AuthorizationProbe]:
        scenario, target, owner, tested, rule = self._load(scenario_id)
        if rule.status != AuthorizationRuleStatus.APPROVED:
            raise AuthorizationValidationError("Somente regras APPROVED podem executar probes.")
        if not scenario.enabled or not rule.enabled:
            raise AuthorizationValidationError("Cenário e regra devem estar habilitados.")
        scan = self._owner_scan(target.id, owner.id)
        candidates = self._candidates(scan, rule)
        if len(candidates) * 2 > self.settings.authz_max_requests:
            raise AuthorizationValidationError("Plano excede AUTHZ_MAX_REQUESTS.")
        if not candidates:
            raise AuthorizationValidationError(
                "Nenhum endpoint legitimamente observado corresponde à regra."
            )
        scenario = self._claim_execution(scenario_id, rerun=rerun)

        try:
            if rule.http_method not in {"GET", "HEAD"}:
                skipped_rows = [
                    self._skipped(scan, scenario, rule) for _endpoint, _candidate in candidates
                ]
                self.db.add_all(skipped_rows)
                self.db.commit()
                self._finish_execution(scenario.id, AuthorizationScenarioExecutionStatus.COMPLETED)
                for row in skipped_rows:
                    self.db.refresh(row)
                return skipped_rows

            owner_auth = ephemeral_auth_sessions.get(owner) or self.authenticator.authenticate(
                owner, target
            )
            test_auth = ephemeral_auth_sessions.get(tested) or self.authenticator.authenticate(
                tested, target
            )
            if owner_auth.profile_id != owner.id or test_auth.profile_id != tested.id:
                raise AuthorizationValidationError(
                    "AuthContext não corresponde ao perfil solicitado."
                )
            if owner_auth is test_auth:
                raise AuthorizationValidationError(
                    "Os contextos de autenticação não estão isolados."
                )

            rows: list[AuthorizationProbe] = []
            allowed_public_hosts = verified_public_hosts(target)
            for endpoint, _candidate in candidates:
                logger.info("[AUTHZ] Scenario %s -> %s", owner.name, tested.name)
                logger.info("[AUTHZ] %s %s", rule.http_method, rule.resource_pattern)
                try:
                    baseline = (
                        self.collector.request(
                            endpoint.url,
                            rule.http_method,
                            owner_auth,
                            allowed_public_hosts=allowed_public_hosts,
                        )
                        if allowed_public_hosts
                        else self.collector.request(endpoint.url, rule.http_method, owner_auth)
                    )
                    self._delay()
                    tested_response = (
                        self.collector.request(
                            endpoint.url,
                            rule.http_method,
                            test_auth,
                            allowed_public_hosts=allowed_public_hosts,
                        )
                        if allowed_public_hosts
                        else self.collector.request(endpoint.url, rule.http_method, test_auth)
                    )
                    self._delay()
                    result, confidence, baseline_shape, tested_shape, categories = self._compare(
                        baseline, tested_response, rule.expected_access, target
                    )
                    row = AuthorizationProbe(
                        scan_id=scan.id,
                        scenario_id=scenario.id,
                        owner_profile_id=owner.id,
                        test_profile_id=tested.id,
                        endpoint=rule.resource_pattern,
                        method=rule.http_method,
                        expected_access=rule.expected_access,
                        result=result,
                        status_code=tested_response.status_code,
                        confidence=confidence,
                        baseline_fingerprint=baseline_shape.fingerprint,
                        tested_fingerprint=tested_shape.fingerprint,
                        sensitive_categories=sorted(category.value for category in categories),
                        baseline_metadata=baseline_shape.metadata,
                        tested_metadata=tested_shape.metadata,
                    )
                    rows.append(row)
                    self.db.add(row)
                    if result == AuthorizationProbeResult.CONFIRMED_BYPASS:
                        self.db.add(self._finding(scan, scenario, rule, categories))
                        scan.total_findings += 1
                    logger.info("[AUTHZ] Result %s", result.value)
                except (TargetPolicyError, ValueError):
                    logger.warning("[AUTHZ] Probe blocked by target policy or validation")
                    rows.append(self._error(scan, scenario, rule))
                    self.db.add(rows[-1])
            self.db.commit()
            for row in rows:
                self.db.refresh(row)
            final_status = (
                AuthorizationScenarioExecutionStatus.FAILED
                if any(row.result == AuthorizationProbeResult.ERROR for row in rows)
                else AuthorizationScenarioExecutionStatus.COMPLETED
            )
            self._finish_execution(
                scenario.id,
                final_status,
                "PROBE_EXECUTION_ERROR"
                if final_status == AuthorizationScenarioExecutionStatus.FAILED
                else None,
            )
            for row in rows:
                self.db.refresh(row)
            return rows
        except Exception:
            self._finish_execution(
                scenario.id,
                AuthorizationScenarioExecutionStatus.FAILED,
                "SCENARIO_EXECUTION_FAILED",
            )
            raise
        finally:
            ephemeral_auth_sessions.discard(owner.id)
            ephemeral_auth_sessions.discard(tested.id)

    def _delay(self) -> None:
        if self.settings.authz_request_delay_ms:
            self.sleeper(self.settings.authz_request_delay_ms / 1000)

    def _compare(
        self,
        baseline: ResponseSnapshot,
        tested: ResponseSnapshot,
        expected: ExpectedAccess,
        target: Target,
    ) -> tuple[
        AuthorizationProbeResult,
        Confidence,
        StructuralSnapshot,
        StructuralSnapshot,
        set[SensitiveDataCategory],
    ]:
        baseline_shape = structural_snapshot(baseline)
        tested_shape = structural_snapshot(tested)
        categories = {item.category for item in self.detector.analyze(tested)}
        if not 200 <= baseline.status_code < 300:
            return (
                AuthorizationProbeResult.INCONCLUSIVE,
                Confidence.LOW,
                baseline_shape,
                tested_shape,
                categories,
            )
        if 300 <= tested.status_code < 400:
            location = tested.headers.get("location")
            if location:
                absolute = urljoin(tested.endpoint, location)
                validated = validate_target(absolute, verified_public_hosts(target))
                allowed_origins = {normalize_url(target.base_url).origin}
                if target.api_url:
                    allowed_origins.add(normalize_url(target.api_url).origin)
                if normalize_url(str(validated.url)).origin not in allowed_origins:
                    return (
                        AuthorizationProbeResult.ERROR,
                        Confidence.HIGH,
                        baseline_shape,
                        tested_shape,
                        categories,
                    )
        if expected == ExpectedAccess.DENY:
            if tested.status_code in {401, 403}:
                return (
                    AuthorizationProbeResult.DENIED_AS_EXPECTED,
                    Confidence.HIGH,
                    baseline_shape,
                    tested_shape,
                    categories,
                )
            if tested.status_code == 404:
                return (
                    AuthorizationProbeResult.DENIED_AS_EXPECTED,
                    Confidence.MEDIUM,
                    baseline_shape,
                    tested_shape,
                    categories,
                )
            if 300 <= tested.status_code < 400:
                return (
                    AuthorizationProbeResult.DENIED_AS_EXPECTED,
                    Confidence.MEDIUM,
                    baseline_shape,
                    tested_shape,
                    categories,
                )
            equivalent = bool(
                baseline_shape.fingerprint
                and baseline_shape.fingerprint == tested_shape.fingerprint
            )
            if 200 <= tested.status_code < 300 and equivalent and categories:
                return (
                    AuthorizationProbeResult.CONFIRMED_BYPASS,
                    Confidence.HIGH,
                    baseline_shape,
                    tested_shape,
                    categories,
                )
            if 200 <= tested.status_code < 300 and equivalent:
                return (
                    AuthorizationProbeResult.POSSIBLE_BYPASS,
                    Confidence.MEDIUM,
                    baseline_shape,
                    tested_shape,
                    categories,
                )
            return (
                AuthorizationProbeResult.INCONCLUSIVE,
                Confidence.LOW,
                baseline_shape,
                tested_shape,
                categories,
            )
        if expected == ExpectedAccess.ALLOW and 200 <= tested.status_code < 300:
            equivalent = baseline_shape.fingerprint == tested_shape.fingerprint
            if equivalent or ruleless_head(baseline, tested):
                return (
                    AuthorizationProbeResult.ALLOWED_AS_EXPECTED,
                    Confidence.HIGH,
                    baseline_shape,
                    tested_shape,
                    categories,
                )
        return (
            AuthorizationProbeResult.INCONCLUSIVE,
            Confidence.LOW,
            baseline_shape,
            tested_shape,
            categories,
        )

    def _finding(
        self,
        scan: Scan,
        scenario: AuthorizationTestScenario,
        rule: AuthorizationRule,
        categories: set[SensitiveDataCategory],
    ) -> Finding:
        object_level = bool(PLACEHOLDER.search(rule.resource_pattern))
        cwe = "CWE-639" if object_level else "CWE-863"
        ordered = sorted(category.value for category in categories)
        return Finding(
            scan_id=scan.id,
            title="Broken Object Level Authorization" if object_level else "Broken Access Control",
            description=(
                "Um perfil para o qual a política esperava negação recebeu uma "
                "representação estruturalmente equivalente ao recurso legítimo."
            ),
            endpoint=rule.resource_pattern,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            cwe=cwe,
            owasp_category="A01:2021 - Broken Access Control",
            privacy_impact=privacy_impact(categories),
            privacy_reason=(
                "Perfil não autorizado obteve acesso a uma resposta contendo "
                "categorias de dados altamente sensíveis."
            )
            if categories & HIGH_SENSITIVITY_CATEGORIES
            else "Perfil não autorizado obteve acesso a uma resposta protegida.",
            evidence=(
                "expected=DENY; unauthorized_status=2xx; structural_match=true; "
                f"sensitive_categories={len(categories)} ({', '.join(ordered)})"
            ),
            recommendation=(
                "Valide autorização por objeto e papel no servidor para cada requisição, "
                "sem confiar apenas na interface."
            ),
            issue_key=f"authz:{cwe}:{rule.http_method}:{rule.resource_pattern}"[:255],
            finding_type="CONFIRMED_VULNERABILITY",
        )

    @staticmethod
    def _skipped(
        scan: Scan, scenario: AuthorizationTestScenario, rule: AuthorizationRule
    ) -> AuthorizationProbe:
        return AuthorizationProbe(
            scan_id=scan.id,
            scenario_id=scenario.id,
            owner_profile_id=scenario.owner_profile_id,
            test_profile_id=scenario.test_profile_id,
            endpoint=rule.resource_pattern,
            method=rule.http_method,
            expected_access=rule.expected_access,
            result=AuthorizationProbeResult.SKIPPED,
            status_code=None,
            confidence=Confidence.HIGH,
            baseline_fingerprint=None,
            tested_fingerprint=None,
            sensitive_categories=[],
            baseline_metadata={"reason": "NOT_TESTED_MUTATING_METHOD"},
            tested_metadata={"reason": "NOT_TESTED_MUTATING_METHOD"},
        )

    @staticmethod
    def _error(
        scan: Scan, scenario: AuthorizationTestScenario, rule: AuthorizationRule
    ) -> AuthorizationProbe:
        return AuthorizationProbe(
            scan_id=scan.id,
            scenario_id=scenario.id,
            owner_profile_id=scenario.owner_profile_id,
            test_profile_id=scenario.test_profile_id,
            endpoint=rule.resource_pattern,
            method=rule.http_method,
            expected_access=rule.expected_access,
            result=AuthorizationProbeResult.ERROR,
            status_code=None,
            confidence=Confidence.HIGH,
            baseline_fingerprint=None,
            tested_fingerprint=None,
            sensitive_categories=[],
            baseline_metadata=None,
            tested_metadata=None,
        )


def ruleless_head(baseline: ResponseSnapshot, tested: ResponseSnapshot) -> bool:
    return baseline.method == tested.method == "HEAD" and baseline.status_code == tested.status_code


def summarize(probes: list[AuthorizationProbe]) -> AuthorizationSummary:
    def count(result: AuthorizationProbeResult) -> int:
        return sum(item.result == result for item in probes)

    return AuthorizationSummary(
        total_probes=len(probes),
        denied_correctly=count(AuthorizationProbeResult.DENIED_AS_EXPECTED),
        allowed_correctly=count(AuthorizationProbeResult.ALLOWED_AS_EXPECTED),
        confirmed_bypass=count(AuthorizationProbeResult.CONFIRMED_BYPASS),
        possible_bypass=count(AuthorizationProbeResult.POSSIBLE_BYPASS),
        inconclusive=count(AuthorizationProbeResult.INCONCLUSIVE),
        skipped=count(AuthorizationProbeResult.SKIPPED),
        errors=count(AuthorizationProbeResult.ERROR),
        privacy_impacting_authorization_failures=sum(
            item.result == AuthorizationProbeResult.CONFIRMED_BYPASS
            and bool(item.sensitive_categories)
            for item in probes
        ),
    )
