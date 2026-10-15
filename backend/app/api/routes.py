from typing import Annotated

import httpx
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Response
from sqlalchemy import func, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app import __version__
from app.core.config import get_settings
from app.core.secrets import SecretStoreError
from app.core.target_policy import TargetPolicyError
from app.database.session import get_db, get_engine
from app.models import (
    ApiRequestTemplate,
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
    AuthorizationRuleStatus,
    DiscoverySource,
    ResourceType,
    ScanStatus,
    SensitiveDataCategory,
)
from app.scanner.registry import ACTIVE_MODULE_IDS, MODULE_CATALOG, modules_for_preset
from app.schemas.entities import (
    AccessProfileSurface,
    AccessSurfaceMatrix,
    ApiRequestTemplateCreate,
    ApiRequestTemplateRead,
    AuthenticationTestResult,
    AuthenticationValidationRequest,
    AuthenticationValidationResult,
    AuthorizationCandidateRead,
    AuthorizationPreview,
    AuthorizationProbeRead,
    AuthorizationRuleCreate,
    AuthorizationRuleRead,
    AuthorizationRuleStatusUpdate,
    AuthorizationRunConfirmation,
    AuthorizationScenarioCreate,
    AuthorizationScenarioRead,
    AuthorizationSummary,
    AuthorizationTestPlan,
    AuthProfileCreate,
    AuthProfileRead,
    AuthProfileUpdate,
    CandidateGenerationRequest,
    CweCoverage,
    DiscoveredEndpointRead,
    DiscoverySummary,
    FindingCorrelationSummary,
    FindingRead,
    FindingStatusUpdate,
    LoginConfigurationSuggestion,
    OpenApiImportRead,
    OpenApiImportRequest,
    OwnershipVerificationRead,
    PostmanImportRead,
    PostmanImportRequest,
    PrivacyAnalysis,
    RoleComparison,
    RoleSurfaceSnapshotRead,
    ScanComparison,
    ScanCreate,
    ScanModuleRead,
    ScanRead,
    ScanRunRequest,
    ScanSummary,
    SensitiveCategoryCount,
    SensitiveDataObservationRead,
    SensitiveDataSummary,
    SensitiveSurfaceMatrix,
    TargetCreate,
    TargetHealthRead,
    TargetRead,
)
from app.services.analysis import (
    TargetHealthService,
    TargetUnavailableError,
    access_profile_surface,
    access_surface,
    authorization_preview,
    cwe_coverage,
    generate_authorization_candidates,
    login_suggestions,
    privacy_analysis,
    role_comparison,
    scan_comparison,
    scan_summary,
    sensitive_surface,
    suggest_rules,
)
from app.services.auth_profiles import AuthProfileError, AuthProfileService
from app.services.authentication import (
    AuthenticationError,
    Authenticator,
    ephemeral_auth_sessions,
)
from app.services.authorization import (
    AuthorizationExecutionConflict,
    AuthorizationService,
    AuthorizationValidationError,
    summarize,
)
from app.services.manual_api import (
    ManualApiRuntimeError,
    ManualApiRuntimeValues,
    validate_manual_api_runtime_values,
)
from app.services.openapi import OpenApiImportError, parse_openapi
from app.services.ownership import (
    CHALLENGE_PATH,
    challenge_urls,
    new_verification_token,
    registration_scope,
    verification_status,
    verify_target_ownership,
)
from app.services.postman import PostmanImportError, parse_postman_collection
from app.services.scans import ScanConflictError, ScanService

router = APIRouter()
Db = Annotated[Session, Depends(get_db)]
Limit = Annotated[int, Query(ge=1, le=1000)]
Offset = Annotated[int, Query(ge=0)]


def require_target(db: Session, target_id: int) -> Target:
    target = db.get(Target, target_id)
    if target is None:
        raise HTTPException(404, "Alvo não encontrado.")
    return target


def require_scan(db: Session, scan_id: int) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(404, "Scan não encontrado.")
    return scan


def require_auth_profile(db: Session, profile_id: int) -> AuthProfile:
    profile = db.get(AuthProfile, profile_id)
    if profile is None:
        raise HTTPException(404, "Perfil de autenticação não encontrado.")
    return profile


def require_authorization_rule(db: Session, rule_id: int) -> AuthorizationRule:
    rule = db.get(AuthorizationRule, rule_id)
    if rule is None:
        raise HTTPException(404, "Regra de autorização não encontrada.")
    return rule


@router.get("/health")
def health(db: Db) -> dict[str, str]:
    try:
        db.execute(text("SELECT 1"))
    except SQLAlchemyError as exc:
        raise HTTPException(503, "Banco de dados indisponível.") from exc
    return {"status": "ok", "service": "DAST", "version": __version__}


@router.get("/targets", response_model=list[TargetRead])
def list_targets(db: Db, limit: Limit = 100, offset: Offset = 0) -> list[Target]:
    return list(db.scalars(select(Target).order_by(Target.id.desc()).offset(offset).limit(limit)))


@router.post("/targets", response_model=TargetRead, status_code=201)
def create_target(payload: TargetCreate, db: Db) -> Target:
    try:
        base_url, api_url, allowed_hosts, public = registration_scope(
            payload.base_url, payload.api_url
        )
    except TargetPolicyError as exc:
        raise HTTPException(422, str(exc)) from exc
    values = payload.model_dump() | {
        "base_url": base_url,
        "api_url": api_url,
        "allowed_hosts": allowed_hosts,
        "requires_ownership_verification": public,
        "ownership_verification_token": new_verification_token() if public else None,
        "safe_scan_mode": True if public else payload.safe_scan_mode,
    }
    target = Target(**values)
    db.add(target)
    db.commit()
    db.refresh(target)
    return target


@router.get("/targets/{target_id}", response_model=TargetRead)
def get_target(target_id: int, db: Db) -> Target:
    return require_target(db, target_id)


def _ownership_read(target: Target) -> OwnershipVerificationRead:
    return OwnershipVerificationRead(
        target_id=target.id,
        status=verification_status(target),
        challenge_path=CHALLENGE_PATH,
        challenge_urls=challenge_urls(target),
        token=target.ownership_verification_token,
        allowed_hosts=target.allowed_hosts,
        verified_at=target.ownership_verified_at,
        expires_at=target.ownership_verification_expires_at,
    )


@router.get("/targets/{target_id}/ownership-verification", response_model=OwnershipVerificationRead)
def get_ownership_verification(target_id: int, db: Db) -> OwnershipVerificationRead:
    return _ownership_read(require_target(db, target_id))


@router.post(
    "/targets/{target_id}/ownership-verification", response_model=OwnershipVerificationRead
)
def verify_ownership(target_id: int, db: Db) -> OwnershipVerificationRead:
    target = require_target(db, target_id)
    try:
        verify_target_ownership(target)
    except (TargetPolicyError, httpx.HTTPError) as exc:
        raise HTTPException(422, str(exc)) from exc
    db.commit()
    db.refresh(target)
    return _ownership_read(target)


@router.put("/targets/{target_id}/openapi", response_model=OpenApiImportRead)
def import_target_openapi(
    target_id: int, payload: OpenApiImportRequest, db: Db
) -> OpenApiImportRead:
    target = require_target(db, target_id)
    try:
        document = parse_openapi(payload.content, target, payload.filename)
    except OpenApiImportError as exc:
        raise HTTPException(422, str(exc)) from exc
    imported_at = utcnow()
    target.openapi_document = dict(document)
    target.openapi_title = document["title"]
    target.openapi_version = document["version"]
    target.openapi_operation_count = len(document["operations"])
    target.openapi_imported_at = imported_at
    db.commit()
    methods = sorted({operation["method"] for operation in document["operations"]})
    paths = {operation["path"] for operation in document["operations"]}
    return OpenApiImportRead(
        target_id=target.id,
        title=document["title"],
        version=document["version"],
        operation_count=len(document["operations"]),
        path_count=len(paths),
        methods=methods,
        imported_at=imported_at,
    )


@router.delete("/targets/{target_id}/openapi", status_code=204)
def delete_target_openapi(target_id: int, db: Db) -> Response:
    target = require_target(db, target_id)
    target.openapi_document = None
    target.openapi_title = None
    target.openapi_version = None
    target.openapi_operation_count = 0
    target.openapi_imported_at = None
    db.commit()
    return Response(status_code=204)


@router.put("/targets/{target_id}/postman", response_model=PostmanImportRead)
def import_target_postman(
    target_id: int, payload: PostmanImportRequest, db: Db
) -> PostmanImportRead:
    target = require_target(db, target_id)
    try:
        document = parse_postman_collection(payload.content, target, payload.filename)
    except PostmanImportError as exc:
        raise HTTPException(422, str(exc)) from exc
    imported_at = utcnow()
    target.postman_document = dict(document)
    target.postman_name = document["name"]
    target.postman_version = document["version"]
    target.postman_request_count = len(document["operations"])
    target.postman_imported_at = imported_at
    db.commit()
    return PostmanImportRead(
        target_id=target.id,
        name=document["name"],
        version=document["version"],
        request_count=len(document["operations"]),
        methods=sorted({operation["method"] for operation in document["operations"]}),
        imported_at=imported_at,
    )


@router.delete("/targets/{target_id}/postman", status_code=204)
def delete_target_postman(target_id: int, db: Db) -> Response:
    target = require_target(db, target_id)
    target.postman_document = None
    target.postman_name = None
    target.postman_version = None
    target.postman_request_count = 0
    target.postman_imported_at = None
    db.commit()
    return Response(status_code=204)


@router.get("/targets/{target_id}/api-requests", response_model=list[ApiRequestTemplateRead])
def list_target_api_requests(target_id: int, db: Db) -> list[ApiRequestTemplate]:
    require_target(db, target_id)
    return list(
        db.scalars(
            select(ApiRequestTemplate)
            .where(ApiRequestTemplate.target_id == target_id)
            .order_by(ApiRequestTemplate.id)
        )
    )


@router.post(
    "/targets/{target_id}/api-requests",
    response_model=ApiRequestTemplateRead,
    status_code=201,
)
def create_target_api_request(
    target_id: int, payload: ApiRequestTemplateCreate, db: Db
) -> ApiRequestTemplate:
    require_target(db, target_id)
    template = ApiRequestTemplate(target_id=target_id, **payload.model_dump())
    db.add(template)
    db.commit()
    db.refresh(template)
    return template


@router.delete("/targets/{target_id}/api-requests/{request_id}", status_code=204)
def delete_target_api_request(target_id: int, request_id: int, db: Db) -> Response:
    require_target(db, target_id)
    template = db.scalar(
        select(ApiRequestTemplate).where(
            ApiRequestTemplate.id == request_id,
            ApiRequestTemplate.target_id == target_id,
        )
    )
    if template is None:
        raise HTTPException(404, "Template de requisição não encontrado neste alvo.")
    db.delete(template)
    db.commit()
    return Response(status_code=204)


@router.get("/targets/{target_id}/health", response_model=TargetHealthRead)
def target_health(target_id: int, db: Db) -> TargetHealthRead:
    return TargetHealthService().check(require_target(db, target_id))


@router.get(
    "/targets/{target_id}/login-suggestions",
    response_model=list[LoginConfigurationSuggestion],
)
def detect_login_configuration(target_id: int, db: Db) -> list[LoginConfigurationSuggestion]:
    require_target(db, target_id)
    return login_suggestions(db, target_id)


@router.get("/targets/{target_id}/access-surface", response_model=AccessSurfaceMatrix)
def get_access_surface(target_id: int, db: Db) -> AccessSurfaceMatrix:
    require_target(db, target_id)
    return access_surface(db, target_id)


@router.get("/targets/{target_id}/role-comparison", response_model=RoleComparison)
def get_role_comparison(
    target_id: int,
    db: Db,
    profile_a_id: Annotated[int, Query(gt=0)],
    profile_b_id: Annotated[int, Query(gt=0)],
) -> RoleComparison:
    require_target(db, target_id)
    try:
        return role_comparison(db, target_id, profile_a_id, profile_b_id)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@router.get(
    "/targets/{target_id}/authorization-candidates",
    response_model=list[AuthorizationCandidateRead],
)
def list_authorization_candidates(target_id: int, db: Db) -> list[AuthorizationCandidate]:
    require_target(db, target_id)
    return list(
        db.scalars(
            select(AuthorizationCandidate)
            .where(AuthorizationCandidate.target_id == target_id)
            .order_by(AuthorizationCandidate.id)
        )
    )


@router.post(
    "/targets/{target_id}/authorization-candidates/generate",
    response_model=list[AuthorizationCandidateRead],
)
def create_authorization_candidates(
    target_id: int, payload: CandidateGenerationRequest, db: Db
) -> list[AuthorizationCandidate]:
    require_target(db, target_id)
    try:
        return generate_authorization_candidates(
            db, target_id, payload.profile_a_id, payload.profile_b_id
        )
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@router.get("/targets/{target_id}/sensitive-surface", response_model=SensitiveSurfaceMatrix)
def get_sensitive_surface(target_id: int, db: Db) -> SensitiveSurfaceMatrix:
    require_target(db, target_id)
    return sensitive_surface(db, target_id)


@router.get("/targets/{target_id}/cwe-coverage", response_model=CweCoverage)
def get_cwe_coverage(target_id: int, db: Db) -> CweCoverage:
    require_target(db, target_id)
    return cwe_coverage(db, target_id)


@router.get("/targets/{target_id}/privacy-analysis", response_model=PrivacyAnalysis)
def get_privacy_analysis(target_id: int, db: Db) -> PrivacyAnalysis:
    require_target(db, target_id)
    return privacy_analysis(db, target_id)


@router.get("/targets/{target_id}/findings", response_model=list[FindingRead])
def list_target_findings(target_id: int, db: Db) -> list[Finding]:
    require_target(db, target_id)
    return list(
        db.scalars(
            select(Finding)
            .join(Scan, Finding.scan_id == Scan.id)
            .where(Scan.target_id == target_id)
            .order_by(Finding.id.desc())
        )
    )


@router.post("/scans", response_model=ScanRead, status_code=201)
def create_scan(payload: ScanCreate, db: Db) -> Scan:
    target = require_target(db, payload.target_id)
    if verification_status(target) != "VERIFIED" and target.requires_ownership_verification:
        raise HTTPException(
            422,
            "Verifique a propriedade de todos os domínios públicos antes de criar o scan.",
        )
    if payload.auth_profile_id is not None:
        profile = require_auth_profile(db, payload.auth_profile_id)
        if profile.target_id != payload.target_id:
            raise HTTPException(422, "O perfil de autenticação não pertence ao alvo.")
        if target.is_protected_target and profile.last_auth_success is not True:
            raise HTTPException(
                422,
                "Valide a autenticação do perfil antes do scan neste alvo protegido.",
            )
    settings = get_settings()
    try:
        modules_enabled = modules_for_preset(payload.preset, payload.modules)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    active_modules = sorted(set(modules_enabled) & set(ACTIVE_MODULE_IDS))
    if active_modules and not payload.active_confirmation:
        raise HTTPException(
            422,
            "Confirme explicitamente a execução dos módulos Safe Active.",
        )
    scan = Scan(
        target_id=payload.target_id,
        auth_profile_id=payload.auth_profile_id,
        mode=payload.mode,
        experiment_label=payload.experiment_label,
        dast_version=__version__,
        preset=payload.preset,
        modules_enabled=modules_enabled,
        configuration_snapshot={
            "scan_mode": payload.mode.value,
            "preset": payload.preset,
            "modules_enabled": modules_enabled,
            "active_confirmation": payload.active_confirmation,
            "active_modules": active_modules,
            "active_allowed_methods": ["GET", "HEAD", "OPTIONS"],
            "safe_scan_mode": target.safe_scan_mode,
            "ownership_verification_status": verification_status(target),
            "allowed_hosts": target.allowed_hosts,
            "crawler_max_depth": settings.crawler_max_depth,
            "crawler_max_pages": settings.crawler_max_pages,
            "crawler_max_requests": settings.crawler_max_requests,
            "crawler_max_static_requests": settings.crawler_max_static_requests,
            "crawler_hard_max_requests": (
                settings.crawler_max_requests + settings.crawler_max_static_requests
            ),
            "crawler_timeout_seconds": settings.crawler_timeout_seconds,
            "manual_api_max_requests": settings.manual_api_max_requests,
            "manual_api_request_delay_ms": settings.manual_api_request_delay_ms,
            "sensitive_body_max_bytes": settings.sensitive_body_max_bytes,
        },
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


@router.get("/scanner/modules", response_model=list[ScanModuleRead])
def list_scan_modules() -> list[dict[str, object]]:
    return [module.as_dict() for module in MODULE_CATALOG]


@router.get("/scans", response_model=list[ScanRead])
def list_scans(db: Db, limit: Limit = 100, offset: Offset = 0) -> list[Scan]:
    return list(db.scalars(select(Scan).order_by(Scan.id.desc()).offset(offset).limit(limit)))


@router.get("/scans/{scan_id}", response_model=ScanRead)
def get_scan(scan_id: int, db: Db) -> Scan:
    return require_scan(db, scan_id)


@router.get("/scans/{scan_id}/findings", response_model=list[FindingRead])
def list_scan_findings(scan_id: int, db: Db) -> list[Finding]:
    require_scan(db, scan_id)
    return list(db.scalars(select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.id)))


@router.get("/scans/{scan_id}/endpoints", response_model=list[DiscoveredEndpointRead])
def list_scan_endpoints(
    scan_id: int,
    db: Db,
    limit: Limit = 100,
    offset: Offset = 0,
    method: Annotated[str | None, Query(min_length=1, max_length=16)] = None,
    resource_type: ResourceType | None = None,
    source: DiscoverySource | None = None,
) -> list[DiscoveredEndpoint]:
    require_scan(db, scan_id)
    statement = select(DiscoveredEndpoint).where(DiscoveredEndpoint.scan_id == scan_id)
    if method:
        statement = statement.where(DiscoveredEndpoint.method == method.upper())
    if resource_type:
        statement = statement.where(DiscoveredEndpoint.resource_type == resource_type)
    if source:
        statement = statement.where(DiscoveredEndpoint.source == source)
    return list(db.scalars(statement.order_by(DiscoveredEndpoint.id).offset(offset).limit(limit)))


@router.get("/scans/{scan_id}/endpoints/{endpoint_id}", response_model=DiscoveredEndpointRead)
def get_scan_endpoint(scan_id: int, endpoint_id: int, db: Db) -> DiscoveredEndpoint:
    require_scan(db, scan_id)
    endpoint = db.scalar(
        select(DiscoveredEndpoint).where(
            DiscoveredEndpoint.id == endpoint_id, DiscoveredEndpoint.scan_id == scan_id
        )
    )
    if endpoint is None:
        raise HTTPException(404, "Endpoint descoberto não encontrado neste scan.")
    return endpoint


@router.get("/scans/{scan_id}/discovery-summary", response_model=DiscoverySummary)
def get_discovery_summary(scan_id: int, db: Db) -> DiscoverySummary:
    scan = require_scan(db, scan_id)
    endpoints = list(
        db.scalars(select(DiscoveredEndpoint).where(DiscoveredEndpoint.scan_id == scan_id))
    )
    return DiscoverySummary(
        scan_id=scan_id,
        pages=sum(item.resource_type == ResourceType.PAGE for item in endpoints),
        api_endpoints=sum(item.resource_type == ResourceType.API for item in endpoints),
        forms=sum(item.resource_type == ResourceType.FORM for item in endpoints),
        requests_observed=scan.discovery_requests_observed,
        unique_endpoints=len({(item.method, item.url) for item in endpoints}),
        methods=sorted({item.method for item in endpoints}),
    )


@router.get("/targets/{target_id}/auth-profiles", response_model=list[AuthProfileRead])
def list_auth_profiles(target_id: int, db: Db) -> list[AuthProfile]:
    require_target(db, target_id)
    return list(
        db.scalars(
            select(AuthProfile).where(AuthProfile.target_id == target_id).order_by(AuthProfile.id)
        )
    )


@router.post("/targets/{target_id}/auth-profiles", response_model=AuthProfileRead, status_code=201)
def create_auth_profile(target_id: int, payload: AuthProfileCreate, db: Db) -> AuthProfile:
    target = require_target(db, target_id)
    try:
        return AuthProfileService(db).create(target, payload)
    except AuthProfileError as exc:
        db.rollback()
        raise HTTPException(422, str(exc)) from exc
    except SecretStoreError as exc:
        db.rollback()
        raise HTTPException(503, str(exc)) from exc


@router.get("/auth-profiles/{profile_id}", response_model=AuthProfileRead)
def get_auth_profile(profile_id: int, db: Db) -> AuthProfile:
    return require_auth_profile(db, profile_id)


@router.put("/auth-profiles/{profile_id}", response_model=AuthProfileRead)
def update_auth_profile(profile_id: int, payload: AuthProfileUpdate, db: Db) -> AuthProfile:
    profile = require_auth_profile(db, profile_id)
    target = require_target(db, profile.target_id)
    try:
        return AuthProfileService(db).update(profile, target, payload)
    except AuthProfileError as exc:
        db.rollback()
        raise HTTPException(422, str(exc)) from exc
    except SecretStoreError as exc:
        db.rollback()
        raise HTTPException(503, str(exc)) from exc


@router.delete("/auth-profiles/{profile_id}", status_code=204)
def delete_auth_profile(profile_id: int, db: Db) -> Response:
    profile = require_auth_profile(db, profile_id)
    ephemeral_auth_sessions.discard(profile.id)
    db.delete(profile)
    db.commit()
    return Response(status_code=204)


@router.post("/auth-profiles/{profile_id}/test", response_model=AuthenticationTestResult)
def test_auth_profile(
    profile_id: int,
    db: Db,
    payload: AuthenticationValidationRequest | None = None,
) -> AuthenticationTestResult:
    profile = require_auth_profile(db, profile_id)
    target = require_target(db, profile.target_id)
    retain_session = payload.retain_session if payload is not None else True
    if not retain_session:
        # A validation-only attempt must also remove a context retained by an
        # earlier operation before handling any new transient credentials.
        ephemeral_auth_sessions.discard(profile.id)
    try:
        context = Authenticator().authenticate(
            profile,
            target,
            username=(
                payload.username.get_secret_value()
                if payload is not None and payload.username is not None
                else None
            ),
            password=(
                payload.password.get_secret_value()
                if payload is not None and payload.password is not None
                else None
            ),
            mfa_code=(
                payload.mfa_code.get_secret_value()
                if payload is not None and payload.mfa_code is not None
                else None
            ),
            secret=(
                payload.secret.get_secret_value()
                if payload is not None and payload.secret is not None
                else None
            ),
        )
    except (AuthenticationError, SecretStoreError) as exc:
        error_code = exc.code if isinstance(exc, AuthenticationError) else "SECRET_STORE_ERROR"
        awaiting_mfa = error_code == "MFA_REQUIRED"
        if not awaiting_mfa:
            profile.last_auth_success = False
        if not awaiting_mfa or not retain_session:
            ephemeral_auth_sessions.discard(profile.id)
        profile.last_auth_status_code = (
            exc.status_code if isinstance(exc, AuthenticationError) else None
        )
        profile.last_auth_tested_at = utcnow()
        db.commit()
        return AuthenticationTestResult(
            success=False,
            status_code=exc.status_code if isinstance(exc, AuthenticationError) else None,
            message=(
                "MFA code required"
                if awaiting_mfa
                else "MFA enrollment required"
                if error_code == "MFA_ENROLLMENT_REQUIRED"
                else "Authentication failed"
            ),
            requires_mfa=awaiting_mfa,
        )
    profile.last_auth_success = True
    profile.last_auth_status_code = 200
    profile.last_auth_tested_at = utcnow()
    db.commit()
    db.refresh(profile)
    if retain_session:
        ephemeral_auth_sessions.put(profile, context)
    else:
        ephemeral_auth_sessions.discard(profile.id)
    return AuthenticationTestResult(
        success=True, status_code=200, message="Authentication successful"
    )


@router.post(
    "/auth-profiles/{profile_id}/validation",
    response_model=AuthenticationValidationResult,
)
def validate_auth_profile(
    profile_id: int,
    db: Db,
    payload: AuthenticationValidationRequest | None = None,
) -> AuthenticationValidationResult:
    result = test_auth_profile(profile_id, db, payload)
    profile = require_auth_profile(db, profile_id)
    retain_session = payload.retain_session if payload is not None else True
    return AuthenticationValidationResult(
        success=result.success,
        status_code=result.status_code,
        role_name=profile.role_name,
        session_initialized=result.success and retain_session,
        requires_mfa=result.requires_mfa,
        message=result.message,
    )


@router.get(
    "/auth-profiles/{profile_id}/access-profile-surface",
    response_model=AccessProfileSurface,
)
def get_access_profile_surface(profile_id: int, db: Db) -> AccessProfileSurface:
    require_auth_profile(db, profile_id)
    try:
        return access_profile_surface(db, profile_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc


@router.get(
    "/auth-profiles/{profile_id}/role-surface-snapshots",
    response_model=list[RoleSurfaceSnapshotRead],
)
def list_role_surface_snapshots(profile_id: int, db: Db) -> list[RoleSurfaceSnapshot]:
    require_auth_profile(db, profile_id)
    return list(
        db.scalars(
            select(RoleSurfaceSnapshot)
            .where(RoleSurfaceSnapshot.auth_profile_id == profile_id)
            .order_by(RoleSurfaceSnapshot.id.desc())
        )
    )


@router.get(
    "/targets/{target_id}/authorization-preview/{profile_id}",
    response_model=AuthorizationPreview,
)
def get_authorization_preview(target_id: int, profile_id: int, db: Db) -> AuthorizationPreview:
    require_target(db, target_id)
    try:
        return authorization_preview(db, target_id, profile_id)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@router.get("/scans/{scan_id}/summary", response_model=ScanSummary)
def get_scan_summary(scan_id: int, db: Db) -> ScanSummary:
    require_scan(db, scan_id)
    try:
        return scan_summary(db, scan_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc


@router.get(
    "/targets/{target_id}/scan-comparison",
    response_model=ScanComparison,
)
def get_scan_comparison(
    target_id: int,
    baseline_scan_id: int,
    current_scan_id: int,
    db: Db,
    response_size_tolerance_percent: Annotated[float, Query(ge=0, le=100)] = 10.0,
) -> ScanComparison:
    require_target(db, target_id)
    try:
        return scan_comparison(
            db,
            target_id,
            baseline_scan_id,
            current_scan_id,
            response_size_tolerance_percent,
        )
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@router.get(
    "/scans/{scan_id}/sensitive-data",
    response_model=list[SensitiveDataObservationRead],
)
def list_sensitive_data(scan_id: int, db: Db) -> list[SensitiveDataObservation]:
    require_scan(db, scan_id)
    return list(
        db.scalars(
            select(SensitiveDataObservation)
            .where(SensitiveDataObservation.scan_id == scan_id)
            .order_by(SensitiveDataObservation.id)
        )
    )


@router.get("/scans/{scan_id}/sensitive-data-summary", response_model=SensitiveDataSummary)
def get_sensitive_data_summary(scan_id: int, db: Db) -> SensitiveDataSummary:
    require_scan(db, scan_id)
    observations = list(
        db.scalars(
            select(SensitiveDataObservation).where(SensitiveDataObservation.scan_id == scan_id)
        )
    )
    endpoints = list(
        db.scalars(select(DiscoveredEndpoint).where(DiscoveredEndpoint.scan_id == scan_id))
    )
    category_counts: dict[SensitiveDataCategory, int] = {}
    for item in observations:
        category_counts[item.category] = category_counts.get(item.category, 0) + item.count
    health_categories = {
        SensitiveDataCategory.HEALTH_INFORMATION,
        SensitiveDataCategory.MEDICAL_RECORD,
        SensitiveDataCategory.PRESCRIPTION,
        SensitiveDataCategory.MEDICATION,
        SensitiveDataCategory.EXAM_RESULT,
        SensitiveDataCategory.DIAGNOSIS,
    }
    health_endpoint_ids = {
        item.endpoint_id for item in observations if item.category in health_categories
    }
    return SensitiveDataSummary(
        scan_id=scan_id,
        observations=sum(item.count for item in observations),
        endpoints_with_sensitive_data=len({item.endpoint_id for item in observations}),
        categories_detected=len(category_counts),
        health_endpoints=len(health_endpoint_ids),
        authenticated_endpoints=sum(item.requires_auth is True for item in endpoints),
        categories=[
            SensitiveCategoryCount(category=category, count=count)
            for category, count in sorted(category_counts.items(), key=lambda pair: pair[0].value)
        ],
    )


@router.get("/targets/{target_id}/authorization-rules", response_model=list[AuthorizationRuleRead])
def list_authorization_rules(target_id: int, db: Db) -> list[AuthorizationRule]:
    require_target(db, target_id)
    return list(
        db.scalars(
            select(AuthorizationRule)
            .where(AuthorizationRule.target_id == target_id)
            .order_by(AuthorizationRule.id)
        )
    )


@router.post(
    "/targets/{target_id}/authorization-rules",
    response_model=AuthorizationRuleRead,
    status_code=201,
)
def create_authorization_rule(
    target_id: int, payload: AuthorizationRuleCreate, db: Db
) -> AuthorizationRule:
    require_target(db, target_id)
    method = payload.http_method.upper()
    if method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}:
        raise HTTPException(422, "Método HTTP inválido.")
    if not payload.resource_pattern.startswith("/"):
        raise HTTPException(422, "Resource Pattern deve iniciar com '/'.")
    rule = AuthorizationRule(
        target_id=target_id, **(payload.model_dump() | {"http_method": method})
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule


@router.post(
    "/targets/{target_id}/authorization-rule-suggestions",
    response_model=list[AuthorizationRuleRead],
)
def create_authorization_rule_suggestions(target_id: int, db: Db) -> list[AuthorizationRule]:
    require_target(db, target_id)
    return suggest_rules(db, target_id)


@router.put("/authorization-rules/{rule_id}/status", response_model=AuthorizationRuleRead)
def update_authorization_rule_status(
    rule_id: int, payload: AuthorizationRuleStatusUpdate, db: Db
) -> AuthorizationRule:
    rule = require_authorization_rule(db, rule_id)
    rule.status = payload.status
    rule.enabled = payload.status == AuthorizationRuleStatus.APPROVED
    db.commit()
    db.refresh(rule)
    return rule


@router.get(
    "/targets/{target_id}/authorization-scenarios", response_model=list[AuthorizationScenarioRead]
)
def list_authorization_scenarios(target_id: int, db: Db) -> list[AuthorizationTestScenario]:
    require_target(db, target_id)
    return list(
        db.scalars(
            select(AuthorizationTestScenario)
            .where(AuthorizationTestScenario.target_id == target_id)
            .order_by(AuthorizationTestScenario.id)
        )
    )


@router.post(
    "/targets/{target_id}/authorization-scenarios",
    response_model=AuthorizationScenarioRead,
    status_code=201,
)
def create_authorization_scenario(
    target_id: int, payload: AuthorizationScenarioCreate, db: Db
) -> AuthorizationTestScenario:
    target = require_target(db, target_id)
    owner = require_auth_profile(db, payload.owner_profile_id)
    tested = require_auth_profile(db, payload.test_profile_id)
    rule = require_authorization_rule(db, payload.authorization_rule_id)
    count = (
        db.scalar(
            select(func.count())
            .select_from(AuthorizationTestScenario)
            .where(AuthorizationTestScenario.target_id == target_id)
        )
        or 0
    )
    if count >= get_settings().authz_max_scenarios:
        raise HTTPException(422, "Limite AUTHZ_MAX_SCENARIOS atingido.")
    try:
        AuthorizationService(db).validate_scenario(target, owner, tested, rule)
    except AuthorizationValidationError as exc:
        raise HTTPException(422, str(exc)) from exc
    scenario = AuthorizationTestScenario(target_id=target_id, **payload.model_dump())
    db.add(scenario)
    db.commit()
    db.refresh(scenario)
    return scenario


@router.get("/authorization/scenarios/{scenario_id}/plan", response_model=AuthorizationTestPlan)
def authorization_plan(scenario_id: int, db: Db) -> AuthorizationTestPlan:
    try:
        return AuthorizationService(db).plan(scenario_id)
    except AuthorizationValidationError as exc:
        raise HTTPException(422, str(exc)) from exc


@router.post(
    "/authorization/scenarios/{scenario_id}/run", response_model=list[AuthorizationProbeRead]
)
def run_authorization_scenario(
    scenario_id: int, payload: AuthorizationRunConfirmation, db: Db
) -> list[AuthorizationProbe]:
    try:
        return AuthorizationService(db).run(scenario_id, rerun=payload.rerun)
    except AuthorizationExecutionConflict as exc:
        db.rollback()
        raise HTTPException(
            409,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc
    except (AuthorizationValidationError, AuthenticationError, SecretStoreError) as exc:
        db.rollback()
        raise HTTPException(422, str(exc)) from exc


@router.get("/scans/{scan_id}/authorization-probes", response_model=list[AuthorizationProbeRead])
def list_authorization_probes(scan_id: int, db: Db) -> list[AuthorizationProbe]:
    require_scan(db, scan_id)
    return list(
        db.scalars(
            select(AuthorizationProbe)
            .where(AuthorizationProbe.scan_id == scan_id)
            .order_by(AuthorizationProbe.id)
        )
    )


@router.get("/scans/{scan_id}/authorization-summary", response_model=AuthorizationSummary)
def authorization_summary(scan_id: int, db: Db) -> AuthorizationSummary:
    require_scan(db, scan_id)
    probes = list(
        db.scalars(select(AuthorizationProbe).where(AuthorizationProbe.scan_id == scan_id))
    )
    return summarize(probes)


@router.get("/scans/{scan_id}/finding-correlation", response_model=FindingCorrelationSummary)
def finding_correlation(scan_id: int, db: Db) -> FindingCorrelationSummary:
    require_scan(db, scan_id)
    findings = list(db.scalars(select(Finding).where(Finding.scan_id == scan_id)))
    keys = {item.issue_key or f"{item.title}:{item.cwe}" for item in findings}
    return FindingCorrelationSummary(
        unique_issues=len(keys),
        occurrences=len(findings),
        affected_endpoints=len({item.endpoint for item in findings}),
    )


@router.get("/findings", response_model=list[FindingRead])
def list_findings(db: Db, limit: Limit = 100, offset: Offset = 0) -> list[Finding]:
    return list(db.scalars(select(Finding).order_by(Finding.id.desc()).offset(offset).limit(limit)))


@router.get("/findings/{finding_id}", response_model=FindingRead)
def get_finding(finding_id: int, db: Db) -> Finding:
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(404, "Achado não encontrado.")
    return finding


@router.patch("/findings/{finding_id}/status", response_model=FindingRead)
def update_finding_status(finding_id: int, payload: FindingStatusUpdate, db: Db) -> Finding:
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(404, "Achado não encontrado.")
    occurrences = [finding]
    if finding.issue_key:
        occurrences = list(
            db.scalars(
                select(Finding).where(
                    Finding.scan_id == finding.scan_id,
                    Finding.issue_key == finding.issue_key,
                )
            )
        )
    for occurrence in occurrences:
        occurrence.status = payload.status
    db.commit()
    db.refresh(finding)
    return finding


def _manual_runtime_values(
    db: Session, scan: Scan, payload: ScanRunRequest | None
) -> dict[int, ManualApiRuntimeValues]:
    values = {
        item.template_id: ManualApiRuntimeValues(
            path_parameters={
                name: value.get_secret_value() for name, value in item.path_parameters.items()
            },
            query_parameters={
                name: value.get_secret_value() for name, value in item.query_parameters.items()
            },
            header_values={
                name: value.get_secret_value() for name, value in item.header_values.items()
            },
        )
        for item in (payload.manual_api_values if payload else [])
    }
    templates = list(
        db.scalars(
            select(ApiRequestTemplate)
            .where(ApiRequestTemplate.target_id == scan.target_id)
            .order_by(ApiRequestTemplate.id)
        )
    )
    try:
        return validate_manual_api_runtime_values(templates, values)
    except ManualApiRuntimeError as exc:
        raise HTTPException(422, str(exc)) from exc


@router.post("/scans/{scan_id}/run", response_model=ScanRead)
def run_scan(scan_id: int, db: Db, payload: ScanRunRequest | None = None) -> Scan:
    scan = require_scan(db, scan_id)
    manual_values = _manual_runtime_values(db, scan, payload)
    try:
        return ScanService(db).run(scan_id, manual_values)
    except ScanConflictError as exc:
        raise HTTPException(409, str(exc)) from exc
    except TargetUnavailableError as exc:
        raise HTTPException(503, str(exc)) from exc
    finally:
        manual_values.clear()


def _run_scan_background(scan_id: int, manual_values: dict[int, ManualApiRuntimeValues]) -> None:
    try:
        with Session(get_engine()) as session:
            ScanService(session).run(scan_id, manual_values)
    finally:
        manual_values.clear()


@router.post("/scans/{scan_id}/start", response_model=ScanRead, status_code=202)
def start_scan(
    scan_id: int,
    background_tasks: BackgroundTasks,
    db: Db,
    payload: ScanRunRequest | None = None,
) -> Scan:
    scan = require_scan(db, scan_id)
    if scan.status != ScanStatus.PENDING:
        raise HTTPException(409, "Somente scans PENDING podem ser iniciados.")
    manual_values = _manual_runtime_values(db, scan, payload)
    background_tasks.add_task(_run_scan_background, scan_id, manual_values)
    return scan


@router.post("/scans/{scan_id}/cancel", response_model=ScanRead)
def cancel_scan(scan_id: int, db: Db) -> Scan:
    scan = require_scan(db, scan_id)
    if scan.status == ScanStatus.PENDING:
        scan.status = ScanStatus.CANCELLED
        scan.phase = "CANCELLED"
        scan.finished_at = utcnow()
    elif scan.status == ScanStatus.RUNNING:
        scan.cancellation_requested = True
        scan.phase = "CANCELLING"
    else:
        raise HTTPException(409, "Somente scans PENDING ou RUNNING podem ser cancelados.")
    db.commit()
    db.refresh(scan)
    return scan
