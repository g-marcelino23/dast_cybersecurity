import re
from collections import defaultdict
from typing import Literal
from urllib.parse import urlsplit, urlunsplit

import httpx
from sqlalchemy import func as sa_func
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import (
    AuthorizationCandidate,
    AuthorizationProbe,
    AuthorizationRule,
    AuthorizationTestScenario,
    AuthProfile,
    DiscoveredEndpoint,
    Finding,
    RoleSurfaceSnapshot,
    Scan,
    SensitiveDataObservation,
    Target,
)
from app.models.entities import utcnow
from app.models.enums import (
    AuthorizationProbeResult,
    AuthorizationRuleStatus,
    Confidence,
    ExpectedAccess,
    PrivacyImpact,
    ResourceType,
    ScanStatus,
    SensitiveDataCategory,
    Severity,
)
from app.scanner.client import SafeHttpCollector
from app.schemas.entities import (
    AccessProfileSurface,
    AccessSurfaceMatrix,
    AccessSurfaceProfile,
    AccessSurfaceRow,
    AuthorizationPreview,
    AuthorizationPreviewItem,
    CweCoverage,
    CweCoverageRow,
    LoginConfigurationSuggestion,
    PrivacyAnalysis,
    RoleComparison,
    RoleComparisonRow,
    ScanSummary,
    SensitiveSurfaceMatrix,
    SensitiveSurfaceRow,
    TargetComponentHealth,
    TargetHealthRead,
)
from app.services.ownership import verified_public_hosts

IDENTIFIER_SEGMENT = re.compile(
    r"^(?:\d+|[0-9a-f]{8}-[0-9a-f-]{27,}|[0-9a-f]{16,})$", re.IGNORECASE
)
USERNAME_HINTS = ("email", "username", "user", "login")
PASSWORD_HINTS = ("password", "senha", "pass")
SEVERITY_ORDER = {item: index for index, item in enumerate(Severity)}
PRIVACY_ORDER = {item: index for index, item in enumerate(PrivacyImpact)}
CONFIDENCE_ORDER = {item: index for index, item in enumerate(Confidence)}


class TargetUnavailableError(RuntimeError):
    pass


def sanitize_resource(raw_url: str) -> str:
    parsed = urlsplit(raw_url)
    path = "/".join(
        "{id}" if IDENTIFIER_SEGMENT.fullmatch(segment) else segment
        for segment in parsed.path.split("/")
    )
    return urlunsplit(("", "", path or "/", "", ""))


class TargetHealthService:
    def __init__(self, collector: SafeHttpCollector | None = None) -> None:
        self.collector = collector or SafeHttpCollector()

    def check(self, target: Target) -> TargetHealthRead:
        allowed_hosts = verified_public_hosts(target)
        frontend = self._component(target.base_url, allowed_hosts)
        api = self._component(target.api_url, allowed_hosts) if target.api_url else None
        available = frontend.status == "ONLINE" and (api is None or api.status == "ONLINE")
        return TargetHealthRead(
            target_id=target.id,
            available=available,
            frontend=frontend,
            api=api,
            message="Target available" if available else "Target unavailable",
            code="AVAILABLE" if available else "TARGET_UNAVAILABLE",
        )

    def ensure_available(self, target: Target) -> None:
        if not self.check(target).available:
            raise TargetUnavailableError("Target unavailable")

    def _component(self, url: str, allowed_public_hosts: tuple[str, ...]) -> TargetComponentHealth:
        try:
            response = (
                self.collector.fetch(url, allowed_public_hosts=allowed_public_hosts)
                if allowed_public_hosts
                else self.collector.fetch(url)
            )
            return TargetComponentHealth(url=url, status="ONLINE", status_code=response.status_code)
        except (httpx.HTTPError, ValueError):
            return TargetComponentHealth(url=url, status="OFFLINE", status_code=None)


def latest_profile_scans(db: Session, target_id: int) -> tuple[list[AuthProfile], dict[int, Scan]]:
    profiles = list(
        db.scalars(
            select(AuthProfile).where(AuthProfile.target_id == target_id).order_by(AuthProfile.id)
        )
    )
    scans: dict[int, Scan] = {}
    for profile in profiles:
        scan = db.scalar(
            select(Scan)
            .where(
                Scan.target_id == target_id,
                Scan.auth_profile_id == profile.id,
                Scan.status == ScanStatus.COMPLETED,
            )
            .order_by(Scan.id.desc())
        )
        if scan:
            scans[profile.id] = scan
    return profiles, scans


def access_surface(db: Session, target_id: int) -> AccessSurfaceMatrix:
    profiles, scans = latest_profile_scans(db, target_id)
    observed: dict[int, set[tuple[str, str]]] = {}
    universe: set[tuple[str, str]] = set()
    for profile_id, scan in scans.items():
        values = {
            (item.method, sanitize_resource(item.url))
            for item in db.scalars(
                select(DiscoveredEndpoint).where(DiscoveredEndpoint.scan_id == scan.id)
            )
        }
        observed[profile_id] = values
        universe.update(values)
    rows = []
    for method, endpoint in sorted(universe):
        states: dict[str, Literal["OBSERVED", "NOT_OBSERVED", "UNKNOWN"]] = {
            str(profile.id): (
                "UNKNOWN"
                if profile.id not in scans
                else "OBSERVED"
                if (method, endpoint) in observed[profile.id]
                else "NOT_OBSERVED"
            )
            for profile in profiles
        }
        rows.append(AccessSurfaceRow(endpoint=endpoint, method=method, access=states))
    return AccessSurfaceMatrix(
        target_id=target_id,
        profiles=[
            AccessSurfaceProfile(
                profile_id=item.id, profile_name=item.name, role_name=item.role_name
            )
            for item in profiles
        ],
        rows=rows,
    )


def sensitive_surface(db: Session, target_id: int) -> SensitiveSurfaceMatrix:
    profiles, scans = latest_profile_scans(db, target_id)
    profile_names = {item.id: item.name for item in profiles}
    grouped: dict[
        tuple[str, str], tuple[set[SensitiveDataCategory], set[str], set[Confidence]]
    ] = {}
    for profile_id, scan in scans.items():
        statement = (
            select(SensitiveDataObservation, DiscoveredEndpoint)
            .join(DiscoveredEndpoint, SensitiveDataObservation.endpoint_id == DiscoveredEndpoint.id)
            .where(SensitiveDataObservation.scan_id == scan.id)
        )
        for observation, endpoint in db.execute(statement):
            key = (endpoint.method, sanitize_resource(endpoint.url))
            categories, names, confidences = grouped.setdefault(key, (set(), set(), set()))
            categories.add(observation.category)
            names.add(profile_names[profile_id])
            confidences.add(observation.confidence)
    return SensitiveSurfaceMatrix(
        target_id=target_id,
        rows=[
            SensitiveSurfaceRow(
                endpoint=endpoint,
                method=method,
                categories=sorted(categories, key=lambda item: item.value),
                observed_by=sorted(names),
                confidence=max(confidences, key=lambda item: CONFIDENCE_ORDER[item]),
            )
            for (method, endpoint), (categories, names, confidences) in sorted(grouped.items())
        ],
    )


def login_suggestions(db: Session, target_id: int) -> list[LoginConfigurationSuggestion]:
    scan_ids = list(db.scalars(select(Scan.id).where(Scan.target_id == target_id)))
    if not scan_ids:
        return []
    rows = list(
        db.scalars(
            select(DiscoveredEndpoint).where(
                DiscoveredEndpoint.scan_id.in_(scan_ids),
                DiscoveredEndpoint.resource_type == "FORM",
            )
        )
    )
    suggestions: list[LoginConfigurationSuggestion] = []
    seen: set[str] = set()
    for endpoint in rows:
        fields = endpoint.parameters or {}
        raw_names = fields.get("fields", []) if isinstance(fields, dict) else []
        names = [str(item) for item in raw_names] if isinstance(raw_names, list) else []
        username = next(
            (name for name in names if any(hint in name.casefold() for hint in USERNAME_HINTS)),
            None,
        )
        password = next(
            (name for name in names if any(hint in name.casefold() for hint in PASSWORD_HINTS)),
            None,
        )
        if not password or endpoint.url in seen:
            continue
        seen.add(endpoint.url)
        suggestions.append(
            LoginConfigurationSuggestion(
                login_url=endpoint.url,
                method="POST",
                username_field=username,
                password_field=password,
                confidence=Confidence.MEDIUM if username else Confidence.LOW,
            )
        )
    return suggestions


def suggest_rules(db: Session, target_id: int) -> list[AuthorizationRule]:
    matrix = access_surface(db, target_id)
    sensitive = {(row.method, row.endpoint) for row in sensitive_surface(db, target_id).rows}
    created: list[AuthorizationRule] = []
    for row in matrix.rows:
        observed_profiles = [
            profile
            for profile in matrix.profiles
            if row.access[str(profile.profile_id)] == "OBSERVED"
        ]
        missing_profiles = [
            profile
            for profile in matrix.profiles
            if row.access[str(profile.profile_id)] == "NOT_OBSERVED"
        ]
        if not observed_profiles or not missing_profiles:
            continue
        for profile in missing_profiles:
            exists = db.scalar(
                select(AuthorizationRule.id).where(
                    AuthorizationRule.target_id == target_id,
                    AuthorizationRule.source_role == profile.role_name,
                    AuthorizationRule.resource_pattern == row.endpoint,
                    AuthorizationRule.http_method == row.method,
                )
            )
            if exists:
                continue
            reason = "Endpoint observado somente por outros perfis; ausência não comprova negação."
            if (row.method, row.endpoint) in sensitive:
                reason += " A superfície contém categorias sensíveis."
            rule = AuthorizationRule(
                target_id=target_id,
                name=f"Revisar acesso de {profile.role_name} a {row.endpoint}"[:160],
                source_role=profile.role_name,
                resource_pattern=row.endpoint,
                http_method=row.method,
                expected_access=ExpectedAccess.DENY,
                description="Sugestão conservadora para revisão humana.",
                enabled=False,
                status=AuthorizationRuleStatus.SUGGESTED,
                suggestion_reason=reason,
                suggestion_confidence=Confidence.LOW,
            )
            db.add(rule)
            created.append(rule)
    db.commit()
    for rule in created:
        db.refresh(rule)
    return created


def cwe_coverage(db: Session, target_id: int) -> CweCoverage:
    findings = list(
        db.scalars(
            select(Finding)
            .join(Scan, Finding.scan_id == Scan.id)
            .where(Scan.target_id == target_id)
        )
    )
    grouped: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        grouped[finding.cwe].append(finding)
    rows = []
    for cwe, items in sorted(grouped.items()):
        mappings = sorted({item.owasp_category for item in items if item.owasp_category})
        rows.append(
            CweCoverageRow(
                cwe=cwe,
                occurrences=len(items),
                severity=max(
                    (item.severity for item in items), key=lambda value: SEVERITY_ORDER[value]
                ),
                owasp_mappings=mappings,
                privacy_impact=max(
                    (item.privacy_impact for item in items),
                    key=lambda value: PRIVACY_ORDER[value],
                ),
                affected_endpoints=len({item.endpoint for item in items}),
            )
        )
    return CweCoverage(
        target_id=target_id,
        rows=rows,
        mapped_to_owasp=sum(bool(item.owasp_mappings) for item in rows),
        without_direct_owasp_mapping=sum(not item.owasp_mappings for item in rows),
        total_cwes=len(rows),
    )


def access_profile_surface(db: Session, profile_id: int) -> AccessProfileSurface:
    profile = db.get(AuthProfile, profile_id)
    if profile is None:
        raise ValueError("Perfil de autenticação não encontrado.")
    scan = db.scalar(
        select(Scan)
        .where(
            Scan.target_id == profile.target_id,
            Scan.auth_profile_id == profile.id,
            Scan.status == ScanStatus.COMPLETED,
        )
        .order_by(Scan.id.desc())
    )
    endpoints = (
        list(
            db.scalars(
                select(DiscoveredEndpoint).where(DiscoveredEndpoint.scan_id == scan.id)
            )
        )
        if scan
        else []
    )
    observations = (
        list(
            db.scalars(
                select(SensitiveDataObservation).where(
                    SensitiveDataObservation.scan_id == scan.id
                )
            )
        )
        if scan
        else []
    )
    sensitive_endpoint_ids = {item.endpoint_id for item in observations}
    findings = (
        list(db.scalars(select(Finding).where(Finding.scan_id == scan.id))) if scan else []
    )
    rules = (
        db.scalar(
            select(sa_func.count())
            .select_from(AuthorizationRule)
            .where(
                AuthorizationRule.target_id == profile.target_id,
                AuthorizationRule.source_role == profile.role_name,
            )
        )
        or 0
    )
    probes = list(
        db.scalars(
            select(AuthorizationProbe).where(
                (AuthorizationProbe.owner_profile_id == profile.id)
                | (AuthorizationProbe.test_profile_id == profile.id)
            )
        )
    )
    candidates = (
        db.scalar(
            select(sa_func.count())
            .select_from(AuthorizationCandidate)
            .where(
                (AuthorizationCandidate.owner_profile_id == profile.id)
                | (AuthorizationCandidate.test_profile_id == profile.id)
            )
        )
        or 0
    )
    auth_status: Literal["VALIDATED", "FAILED", "NOT_TESTED"] = (
        "VALIDATED"
        if profile.last_auth_success is True
        else "FAILED"
        if profile.last_auth_success is False
        else "NOT_TESTED"
    )
    return AccessProfileSurface(
        target_id=profile.target_id,
        profile_id=profile.id,
        profile_name=profile.name,
        role_name=profile.role_name,
        authentication_status=auth_status,
        last_scan_id=scan.id if scan else None,
        last_scan_at=scan.finished_at if scan else None,
        pages_discovered=sum(item.resource_type.value == "PAGE" for item in endpoints),
        api_endpoints=sum(item.resource_type.value == "API" for item in endpoints),
        forms=sum(item.resource_type.value == "FORM" for item in endpoints),
        methods=sorted({item.method for item in endpoints}),
        sensitive_endpoints=len(sensitive_endpoint_ids),
        sensitive_categories=sorted(
            {item.category for item in observations}, key=lambda item: item.value
        ),
        cwes=sorted({item.cwe for item in findings}),
        passive_findings=sum(
            not (item.issue_key or "").startswith("authz:") for item in findings
        ),
        unique_issues=len(
            {item.issue_key or f"{item.title}:{item.cwe}" for item in findings}
        ),
        authorization_candidates=candidates,
        authorization_rules_related=rules,
        authorization_probes=len(probes),
        confirmed_failures=sum(
            item.result == AuthorizationProbeResult.CONFIRMED_BYPASS for item in probes
        ),
        inconclusive=sum(item.result == AuthorizationProbeResult.INCONCLUSIVE for item in probes),
        message=None
        if scan
        else "No authenticated scan has been executed for this profile.",
    )


def create_role_surface_snapshot(
    db: Session, scan: Scan, profile: AuthProfile
) -> RoleSurfaceSnapshot:
    existing = db.scalar(
        select(RoleSurfaceSnapshot).where(RoleSurfaceSnapshot.scan_id == scan.id)
    )
    if existing is not None:
        return existing
    endpoints = list(
        db.scalars(select(DiscoveredEndpoint).where(DiscoveredEndpoint.scan_id == scan.id))
    )
    observations = list(
        db.scalars(
            select(SensitiveDataObservation).where(SensitiveDataObservation.scan_id == scan.id)
        )
    )
    findings = list(db.scalars(select(Finding).where(Finding.scan_id == scan.id)))
    rules = (
        db.scalar(
            select(sa_func.count())
            .select_from(AuthorizationRule)
            .where(
                AuthorizationRule.target_id == scan.target_id,
                AuthorizationRule.source_role == profile.role_name,
            )
        )
        or 0
    )
    passive = [item for item in findings if not (item.issue_key or "").startswith("authz:")]
    snapshot = RoleSurfaceSnapshot(
        target_id=scan.target_id,
        scan_id=scan.id,
        auth_profile_id=profile.id,
        role_name=profile.role_name,
        pages_discovered=sum(item.resource_type == ResourceType.PAGE for item in endpoints),
        api_endpoints=sum(item.resource_type == ResourceType.API for item in endpoints),
        forms=sum(item.resource_type == ResourceType.FORM for item in endpoints),
        methods=sorted({item.method for item in endpoints}),
        sensitive_categories=sorted({item.category.value for item in observations}),
        cwes=sorted({item.cwe for item in passive}),
        passive_findings=len(passive),
        unique_issues=len(
            {item.issue_key or f"{item.title}:{item.cwe}" for item in passive}
        ),
        authorization_rules_related=rules,
    )
    db.add(snapshot)
    profile.last_authenticated_scan_id = scan.id
    profile.last_authenticated_scan_at = scan.finished_at or utcnow()
    return snapshot


def _endpoint_categories(db: Session, scan_id: int) -> dict[int, set[SensitiveDataCategory]]:
    grouped: dict[int, set[SensitiveDataCategory]] = defaultdict(set)
    for item in db.scalars(
        select(SensitiveDataObservation).where(SensitiveDataObservation.scan_id == scan_id)
    ):
        grouped[item.endpoint_id].add(item.category)
    return grouped


def role_comparison(
    db: Session, target_id: int, profile_a_id: int, profile_b_id: int
) -> RoleComparison:
    if profile_a_id == profile_b_id:
        raise ValueError("Selecione dois perfis diferentes.")
    profile_a = db.get(AuthProfile, profile_a_id)
    profile_b = db.get(AuthProfile, profile_b_id)
    if (
        profile_a is None
        or profile_b is None
        or profile_a.target_id != target_id
        or profile_b.target_id != target_id
    ):
        raise ValueError("Os perfis devem pertencer ao alvo selecionado.")
    _profiles, scans = latest_profile_scans(db, target_id)
    scan_a = scans.get(profile_a_id)
    scan_b = scans.get(profile_b_id)
    endpoints_a = (
        list(db.scalars(select(DiscoveredEndpoint).where(DiscoveredEndpoint.scan_id == scan_a.id)))
        if scan_a
        else []
    )
    endpoints_b = (
        list(db.scalars(select(DiscoveredEndpoint).where(DiscoveredEndpoint.scan_id == scan_b.id)))
        if scan_b
        else []
    )
    categories_a = _endpoint_categories(db, scan_a.id) if scan_a else {}
    categories_b = _endpoint_categories(db, scan_b.id) if scan_b else {}

    def indexed(
        rows: list[DiscoveredEndpoint], categories: dict[int, set[SensitiveDataCategory]]
    ) -> dict[tuple[str, str, ResourceType], set[SensitiveDataCategory]]:
        values: dict[tuple[str, str, ResourceType], set[SensitiveDataCategory]] = {}
        for endpoint in rows:
            key = (endpoint.method, sanitize_resource(endpoint.url), endpoint.resource_type)
            values.setdefault(key, set()).update(categories.get(endpoint.id, set()))
        return values

    indexed_a = indexed(endpoints_a, categories_a)
    indexed_b = indexed(endpoints_b, categories_b)
    rows: list[RoleComparisonRow] = []
    for method, endpoint, resource_type in sorted(
        set(indexed_a) | set(indexed_b), key=lambda item: (item[1], item[0], item[2].value)
    ):
        key = (method, endpoint, resource_type)
        state: Literal[
            "ONLY_PROFILE_A", "ONLY_PROFILE_B", "COMMON", "UNKNOWN"
        ] = (
            "UNKNOWN"
            if scan_a is None or scan_b is None
            else "COMMON"
            if key in indexed_a and key in indexed_b
            else "ONLY_PROFILE_A"
            if key in indexed_a
            else "ONLY_PROFILE_B"
        )
        rows.append(
            RoleComparisonRow(
                endpoint=endpoint,
                method=method,
                resource_type=resource_type,
                sensitive_categories=sorted(
                    indexed_a.get(key, set()) | indexed_b.get(key, set()),
                    key=lambda item: item.value,
                ),
                state=state,
            )
        )
    all_categories_a = sorted(
        {category for values in categories_a.values() for category in values},
        key=lambda item: item.value,
    )
    all_categories_b = sorted(
        {category for values in categories_b.values() for category in values},
        key=lambda item: item.value,
    )
    return RoleComparison(
        target_id=target_id,
        profile_a=AccessSurfaceProfile(
            profile_id=profile_a.id,
            profile_name=profile_a.name,
            role_name=profile_a.role_name,
        ),
        profile_b=AccessSurfaceProfile(
            profile_id=profile_b.id,
            profile_name=profile_b.name,
            role_name=profile_b.role_name,
        ),
        profile_a_scan_id=scan_a.id if scan_a else None,
        profile_b_scan_id=scan_b.id if scan_b else None,
        methods_profile_a=sorted({item.method for item in endpoints_a}),
        methods_profile_b=sorted({item.method for item in endpoints_b}),
        sensitive_categories_profile_a=all_categories_a,
        sensitive_categories_profile_b=all_categories_b,
        rows=rows,
        message=(
            "Observed surface differences are not proof of an authorization vulnerability."
            if scan_a and scan_b
            else "UNKNOWN: both profiles require a completed authenticated scan."
        ),
    )


def generate_authorization_candidates(
    db: Session, target_id: int, profile_a_id: int, profile_b_id: int
) -> list[AuthorizationCandidate]:
    comparison = role_comparison(db, target_id, profile_a_id, profile_b_id)
    if comparison.profile_a_scan_id is None or comparison.profile_b_scan_id is None:
        raise ValueError("Ambos os perfis precisam de scans autenticados concluídos.")
    created: list[AuthorizationCandidate] = []
    for row in comparison.rows:
        if row.state not in {"ONLY_PROFILE_A", "ONLY_PROFILE_B"}:
            continue
        if row.method not in {"GET", "HEAD"}:
            continue
        owner_id, tested_id, owner_scan_id, test_scan_id = (
            (
                profile_a_id,
                profile_b_id,
                comparison.profile_a_scan_id,
                comparison.profile_b_scan_id,
            )
            if row.state == "ONLY_PROFILE_A"
            else (
                profile_b_id,
                profile_a_id,
                comparison.profile_b_scan_id,
                comparison.profile_a_scan_id,
            )
        )
        exists = db.scalar(
            select(AuthorizationCandidate.id).where(
                AuthorizationCandidate.target_id == target_id,
                AuthorizationCandidate.owner_profile_id == owner_id,
                AuthorizationCandidate.test_profile_id == tested_id,
                AuthorizationCandidate.owner_scan_id == owner_scan_id,
                AuthorizationCandidate.method == row.method,
                AuthorizationCandidate.resource_pattern == row.endpoint,
            )
        )
        if exists:
            continue
        reason = (
            "Recurso observado somente no perfil proprietário. A diferença não comprova "
            "negação e exige revisão humana."
        )
        candidate = AuthorizationCandidate(
            target_id=target_id,
            owner_profile_id=owner_id,
            test_profile_id=tested_id,
            owner_scan_id=owner_scan_id,
            test_scan_id=test_scan_id,
            method=row.method,
            resource_pattern=row.endpoint,
            expected_access=ExpectedAccess.DENY,
            reason=reason,
            confidence=Confidence.LOW,
            sensitive_categories=[item.value for item in row.sensitive_categories],
            status=AuthorizationRuleStatus.SUGGESTED,
        )
        db.add(candidate)
        created.append(candidate)
    db.commit()
    for candidate in created:
        db.refresh(candidate)
    return created


def authorization_preview(
    db: Session, target_id: int, profile_id: int
) -> AuthorizationPreview:
    profile = db.get(AuthProfile, profile_id)
    if profile is None or profile.target_id != target_id:
        raise ValueError("Perfil de autenticação não pertence ao alvo.")
    scenarios = list(
        db.scalars(
            select(AuthorizationTestScenario).where(
                AuthorizationTestScenario.target_id == target_id,
                (
                    (AuthorizationTestScenario.owner_profile_id == profile_id)
                    | (AuthorizationTestScenario.test_profile_id == profile_id)
                ),
            )
        )
    )
    surface = {
        (row.method, row.endpoint): row.categories for row in sensitive_surface(db, target_id).rows
    }
    items: list[AuthorizationPreviewItem] = []
    for scenario in scenarios:
        rule = db.get(AuthorizationRule, scenario.authorization_rule_id)
        owner = db.get(AuthProfile, scenario.owner_profile_id)
        tested = db.get(AuthProfile, scenario.test_profile_id)
        if rule is None or owner is None or tested is None:
            continue
        executable = (
            scenario.enabled
            and rule.enabled
            and rule.status == AuthorizationRuleStatus.APPROVED
            and rule.http_method in {"GET", "HEAD"}
        )
        items.append(
            AuthorizationPreviewItem(
                scenario_id=scenario.id,
                rule_name=rule.name,
                owner_profile=owner.name,
                test_profile=tested.name,
                method=rule.http_method,
                resource=sanitize_resource(rule.resource_pattern),
                expected_access=rule.expected_access,
                sensitive_categories=surface.get(
                    (rule.http_method, sanitize_resource(rule.resource_pattern)), []
                ),
                rationale=rule.suggestion_reason
                or rule.description
                or "Regra configurada para revisão humana.",
                confidence=rule.suggestion_confidence or Confidence.MEDIUM,
                executable=executable,
            )
        )
    return AuthorizationPreview(target_id=target_id, profile_id=profile_id, items=items)


def scan_summary(db: Session, scan_id: int) -> ScanSummary:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise ValueError("Scan não encontrado.")
    target = db.get(Target, scan.target_id)
    if target is None:
        raise ValueError("Alvo não encontrado.")
    profile = db.get(AuthProfile, scan.auth_profile_id) if scan.auth_profile_id else None
    endpoints = list(
        db.scalars(select(DiscoveredEndpoint).where(DiscoveredEndpoint.scan_id == scan_id))
    )
    observations = list(
        db.scalars(
            select(SensitiveDataObservation).where(SensitiveDataObservation.scan_id == scan_id)
        )
    )
    findings = list(db.scalars(select(Finding).where(Finding.scan_id == scan_id)))
    probes = list(
        db.scalars(select(AuthorizationProbe).where(AuthorizationProbe.scan_id == scan_id))
    )
    issue_keys = {item.issue_key or f"{item.title}:{item.cwe}" for item in findings}
    passive_findings = [
        item for item in findings if not (item.issue_key or "").startswith("authz:")
    ]
    authorization_candidates = (
        db.scalar(
            select(sa_func.count())
            .select_from(AuthorizationCandidate)
            .where(AuthorizationCandidate.owner_scan_id == scan.id)
        )
        or 0
    )
    environment = (
        "FIXTURE"
        if target.environment.value == "FIXTURE"
        else "LOCAL / PROTECTED TARGET"
        if target.is_protected_target
        else "LOCAL"
    )
    return ScanSummary(
        scan_id=scan.id,
        target_name=target.name,
        environment=environment,
        scan_date=scan.finished_at or scan.started_at or scan.created_at,
        scan_profile=profile.name if profile else "ANONYMOUS",
        role_name=profile.role_name if profile else None,
        authenticated=profile is not None,
        experiment_label=scan.experiment_label,
        dast_version=scan.dast_version,
        modules_enabled=scan.modules_enabled,
        configuration_snapshot=scan.configuration_snapshot,
        pages_discovered=sum(item.resource_type.value == "PAGE" for item in endpoints),
        api_endpoints=sum(item.resource_type.value == "API" for item in endpoints),
        forms=sum(item.resource_type.value == "FORM" for item in endpoints),
        passive_findings=len(passive_findings),
        unique_findings=len(issue_keys),
        finding_occurrences=len(findings),
        cwes=sorted({item.cwe for item in findings}),
        owasp_mapped_findings=sum(item.owasp_category is not None for item in findings),
        findings_without_direct_owasp_mapping=sum(
            item.owasp_category is None for item in findings
        ),
        sensitive_endpoints=len({item.endpoint_id for item in observations}),
        sensitive_categories=sorted(
            {item.category for item in observations}, key=lambda item: item.value
        ),
        authorization_candidates=authorization_candidates,
        authorization_probes=len(probes),
        confirmed_authorization_failures=sum(
            item.result == AuthorizationProbeResult.CONFIRMED_BYPASS for item in probes
        ),
        inconclusive_authorization_probes=sum(
            item.result == AuthorizationProbeResult.INCONCLUSIVE for item in probes
        ),
        safe_scan_mode=target.safe_scan_mode,
    )


def privacy_analysis(db: Session, target_id: int) -> PrivacyAnalysis:
    surface = sensitive_surface(db, target_id)
    findings = list(
        db.scalars(
            select(Finding)
            .join(Scan, Finding.scan_id == Scan.id)
            .where(Scan.target_id == target_id)
        )
    )
    distribution = {item.value: 0 for item in PrivacyImpact}
    for finding in findings:
        distribution[finding.privacy_impact.value] += 1
    return PrivacyAnalysis(
        target_id=target_id,
        sensitive_endpoints=len(surface.rows),
        sensitive_categories=sorted(
            {category for row in surface.rows for category in row.categories},
            key=lambda item: item.value,
        ),
        authorization_findings_affecting_sensitive_data=sum(
            item.issue_key is not None
            and item.issue_key.startswith("authz:")
            and item.privacy_impact in {PrivacyImpact.HIGH, PrivacyImpact.CRITICAL}
            for item in findings
        ),
        privacy_impact_distribution=distribution,
    )
