import logging
from time import sleep
from typing import TypedDict

import httpx
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.target_policy import TargetPolicyError, validate_target
from app.crawler import DiscoveryCrawler
from app.crawler.crawler import CrawlerUnavailableError
from app.crawler.normalizer import normalize_url
from app.models import (
    ApiRequestTemplate,
    AuthProfile,
    DiscoveredEndpoint,
    Finding,
    Scan,
    SensitiveDataObservation,
    Target,
)
from app.models.entities import utcnow
from app.models.enums import ScanStatus, Severity
from app.privacy import SensitiveDataDetector
from app.scanner.active import ActiveScanResult, SafeActiveEngine
from app.scanner.base import ResponseSnapshot
from app.scanner.client import SafeHttpCollector
from app.scanner.engine import ScannerEngine
from app.scanner.registry import ACTIVE_MODULE_IDS
from app.services.analysis import (
    TargetHealthService,
    create_role_surface_snapshot,
    sanitize_resource,
)
from app.services.authentication import (
    AuthenticationError,
    Authenticator,
    ephemeral_auth_sessions,
)
from app.services.manual_api import (
    ManualApiRuntimeValues,
    manual_api_endpoints,
    manual_api_report_endpoint,
    materialize_manual_api_request,
    validate_manual_api_runtime_values,
)
from app.services.openapi import openapi_endpoints
from app.services.ownership import verification_status, verified_public_hosts
from app.services.postman import postman_endpoints
from app.services.response_signatures import persisted_response_signature

logger = logging.getLogger(__name__)


class ScanConflictError(ValueError):
    pass


class ScanCancelled(RuntimeError):
    pass


class ManualApiCollectionMetrics(TypedDict):
    eligible: int
    requests_sent: int
    responses_collected: int
    skipped_path_templates: int
    skipped_without_auth: int
    skipped_unsafe_methods: int
    runtime_values_supplied: int
    budget_truncated: bool


class ScanService:
    """Transaction boundary ready for invocation by a future job worker."""

    def __init__(
        self,
        db: Session,
        engine: ScannerEngine | None = None,
        crawler: DiscoveryCrawler | None = None,
        authenticator: Authenticator | None = None,
        sensitive_detector: SensitiveDataDetector | None = None,
        health_service: TargetHealthService | None = None,
        active_engine: SafeActiveEngine | None = None,
        manual_collector: SafeHttpCollector | None = None,
    ) -> None:
        self.db = db
        self.engine = engine or ScannerEngine()
        self.crawler = crawler or DiscoveryCrawler()
        self.authenticator = authenticator
        self.sensitive_detector = sensitive_detector or SensitiveDataDetector()
        self.health_service = health_service or TargetHealthService()
        self.active_engine = active_engine or SafeActiveEngine()
        self.manual_collector = manual_collector or SafeHttpCollector()

    def run(
        self,
        scan_id: int,
        manual_api_values: dict[int, ManualApiRuntimeValues] | None = None,
    ) -> Scan:
        pending = self.db.get(Scan, scan_id)
        if pending is None:
            raise ScanConflictError("Scan não encontrado.")
        target_for_health = self.db.get(Target, pending.target_id)
        if target_for_health is None:
            raise ScanConflictError("Alvo não encontrado.")
        if (
            target_for_health.requires_ownership_verification
            and verification_status(target_for_health) != "VERIFIED"
        ):
            raise ScanConflictError(
                "A verificação de propriedade do domínio público está pendente ou expirada."
            )
        manual_templates = list(
            self.db.scalars(
                select(ApiRequestTemplate)
                .where(ApiRequestTemplate.target_id == target_for_health.id)
                .order_by(ApiRequestTemplate.id)
            )
        )
        runtime_values = validate_manual_api_runtime_values(
            manual_templates, manual_api_values or {}
        )
        if target_for_health.is_protected_target:
            if not target_for_health.safe_scan_mode:
                raise ScanConflictError("Safe Scan Mode é obrigatório para alvos protegidos.")
            self.health_service.ensure_available(target_for_health)
        # Compare-and-swap prevents two HTTP requests from running the same scan.
        claimed = self.db.execute(
            update(Scan)
            .where(Scan.id == scan_id, Scan.status == ScanStatus.PENDING)
            .values(
                status=ScanStatus.RUNNING,
                started_at=utcnow(),
                error_message=None,
                phase="PREPARING",
                progress_percent=5,
                cancellation_requested=False,
            )
            .returning(Scan.id)
        ).scalar_one_or_none()
        if claimed is None:
            self.db.rollback()
            raise ScanConflictError(
                "Somente scans PENDING podem ser executados. Crie um novo scan."
            )
        self.db.commit()
        scan = self.db.get(Scan, scan_id)
        assert scan is not None
        logger.info("scan_started scan_id=%s target_id=%s", scan.id, scan.target_id)
        try:
            target = self.db.get(Target, scan.target_id)
            if target is None:
                raise ValueError("Missing target")
            urls = [target.base_url] + ([target.api_url] if target.api_url else [])
            allowed_public_hosts = verified_public_hosts(target)
            # Validate the entire scope before making any requests; collector revalidates.
            for url in urls:
                validate_target(url, allowed_public_hosts)
            auth = None
            profile = None
            self._checkpoint(scan, "AUTHENTICATING", 10)
            if scan.auth_profile_id is not None:
                profile = self.db.get(AuthProfile, scan.auth_profile_id)
                if profile is None or profile.target_id != target.id:
                    raise AuthenticationError("Perfil de autenticação inválido para este alvo.")
                if target.is_protected_target and profile.last_auth_success is not True:
                    raise AuthenticationError(
                        "O perfil de acesso precisa estar VALIDATED para este alvo protegido."
                    )
                authenticator = self.authenticator or Authenticator()
                auth = ephemeral_auth_sessions.get(profile)
                if auth is None:
                    auth = authenticator.authenticate(profile, target)
                self._checkpoint(scan, "DISCOVERING", 20)
                discovery = (
                    self.crawler.crawl(target.base_url, target.api_url, auth, allowed_public_hosts)
                    if allowed_public_hosts
                    else self.crawler.crawl(target.base_url, target.api_url, auth)
                )
            else:
                self._checkpoint(scan, "DISCOVERING", 20)
                discovery = (
                    self.crawler.crawl(
                        target.base_url,
                        target.api_url,
                        allowed_public_hosts=allowed_public_hosts,
                    )
                    if allowed_public_hosts
                    else self.crawler.crawl(target.base_url, target.api_url)
                )
            if target.openapi_document:
                self._checkpoint(scan, "IMPORTING_API_SPEC", 45)
                observed_keys = {
                    (item.method, normalize_url(item.url).url) for item in discovery.endpoints
                }
                for imported_endpoint in openapi_endpoints(target.openapi_document):
                    key = (
                        imported_endpoint.method,
                        normalize_url(imported_endpoint.url).url,
                    )
                    if key not in observed_keys:
                        observed_keys.add(key)
                        discovery.endpoints.append(imported_endpoint)
            if target.postman_document:
                self._checkpoint(scan, "IMPORTING_API_COLLECTION", 48)
                observed_keys = {
                    (item.method, normalize_url(item.url).url) for item in discovery.endpoints
                }
                for imported_endpoint in postman_endpoints(target.postman_document):
                    key = (
                        imported_endpoint.method,
                        normalize_url(imported_endpoint.url).url,
                    )
                    if key not in observed_keys:
                        observed_keys.add(key)
                        discovery.endpoints.append(imported_endpoint)
            settings = get_settings()
            manual_collection: ManualApiCollectionMetrics = {
                "eligible": 0,
                "requests_sent": 0,
                "responses_collected": 0,
                "skipped_path_templates": 0,
                "skipped_without_auth": 0,
                "skipped_unsafe_methods": 0,
                "runtime_values_supplied": 0,
                "budget_truncated": False,
            }
            manual_response_endpoint_keys: dict[tuple[str, str], tuple[str, str]] = {}
            runtime_inputs_used: list[dict[str, object]] = []
            if manual_templates:
                self._checkpoint(scan, "IMPORTING_MANUAL_API", 50)
                observed_endpoints = {
                    (item.method, normalize_url(item.url).url): item for item in discovery.endpoints
                }
                manual_collection_candidates = []
                imported_manual_endpoints = manual_api_endpoints(target, manual_templates)
                for template, imported_endpoint in zip(
                    manual_templates, imported_manual_endpoints, strict=True
                ):
                    key = (
                        imported_endpoint.method,
                        normalize_url(imported_endpoint.url).url,
                    )
                    inventory_endpoint = observed_endpoints.get(key)
                    if inventory_endpoint is None:
                        discovery.endpoints.append(imported_endpoint)
                        observed_endpoints[key] = imported_endpoint
                        inventory_endpoint = imported_endpoint
                    manual_collection_candidates.append(
                        (template, imported_endpoint, inventory_endpoint)
                    )
                self._checkpoint(scan, "COLLECTING_MANUAL_API", 52)
                for template, template_endpoint, inventory_endpoint in manual_collection_candidates:
                    if template_endpoint.method not in {"GET", "HEAD", "OPTIONS"}:
                        manual_collection["skipped_unsafe_methods"] += 1
                        continue
                    runtime = runtime_values.get(template.id, ManualApiRuntimeValues())
                    materialized = materialize_manual_api_request(target, template, runtime)
                    if materialized is None:
                        manual_collection["skipped_path_templates"] += 1
                        continue
                    runtime_auth_values = bool(runtime.header_values or runtime.query_parameters)
                    if template_endpoint.requires_auth and auth is None and not runtime_auth_values:
                        manual_collection["skipped_without_auth"] += 1
                        continue
                    manual_collection["eligible"] += 1
                    if manual_collection["requests_sent"] >= settings.manual_api_max_requests:
                        manual_collection["budget_truncated"] = True
                        continue
                    if manual_collection["requests_sent"] and settings.manual_api_request_delay_ms:
                        sleep(settings.manual_api_request_delay_ms / 1000)
                    manual_collection["requests_sent"] += 1
                    request_url, extra_headers = materialized
                    try:
                        if allowed_public_hosts:
                            collected_response = self.manual_collector.request(
                                request_url,
                                template_endpoint.method,
                                auth,
                                timeout_seconds=settings.scan_timeout_seconds,
                                extra_headers=extra_headers,
                                allowed_public_hosts=allowed_public_hosts,
                            )
                        else:
                            collected_response = self.manual_collector.request(
                                request_url,
                                template_endpoint.method,
                                auth,
                                timeout_seconds=settings.scan_timeout_seconds,
                                extra_headers=extra_headers,
                            )
                    except httpx.HTTPError:
                        continue
                    response = ResponseSnapshot(
                        endpoint=manual_api_report_endpoint(target, template),
                        status_code=collected_response.status_code,
                        headers=collected_response.headers,
                        body=collected_response.body,
                        method=collected_response.method,
                    )
                    if runtime.supplied:
                        manual_collection["runtime_values_supplied"] += 1
                    runtime_inputs_used.append(
                        {
                            "template_id": template.id,
                            "path_parameters": sorted(runtime.path_parameters),
                            "query_parameters": sorted(runtime.query_parameters),
                            "header_names": sorted(runtime.header_values),
                        }
                    )
                    inventory_endpoint.status_code = response.status_code
                    inventory_endpoint.content_type = response.headers.get("content-type")
                    discovery.responses.append(response)
                    manual_response_endpoint_keys[
                        (response.method, normalize_url(response.endpoint).url)
                    ] = (
                        inventory_endpoint.method,
                        normalize_url(inventory_endpoint.url).url,
                    )
                    discovery.requests_observed += 1
                    discovery.useful_requests_observed += 1
                    manual_collection["responses_collected"] += 1
            self._checkpoint(scan, "ANALYZING", 55)
            configured_result = (
                self.engine.run(urls, auth, scan.modules_enabled, allowed_public_hosts)
                if allowed_public_hosts
                else self.engine.run(urls, auth, scan.modules_enabled)
            )
            active_result = ActiveScanResult([], 0, 0, False)
            if set(scan.modules_enabled) & set(ACTIVE_MODULE_IDS):
                self._checkpoint(scan, "ACTIVE_TESTING", 65)
                active_scan = scan

                def checkpoint(module_id: str) -> None:
                    self._active_checkpoint(active_scan, module_id)

                if allowed_public_hosts:
                    active_result = self.active_engine.run(
                        discovery.endpoints,
                        urls,
                        auth,
                        scan.modules_enabled,
                        before_request=checkpoint,
                        allowed_public_hosts=allowed_public_hosts,
                    )
                else:
                    active_result = self.active_engine.run(
                        discovery.endpoints,
                        urls,
                        auth,
                        scan.modules_enabled,
                        before_request=checkpoint,
                    )
            self._checkpoint(scan, "PERSISTING", 82)
            response_signatures: dict[tuple[str, str], dict[str, object]] = {}
            for response in [*discovery.responses, *configured_result.responses]:
                response_key = (response.method, normalize_url(response.endpoint).url)
                endpoint_key = manual_response_endpoint_keys.get(response_key, response_key)
                response_signatures[endpoint_key] = persisted_response_signature(response)
            for endpoint_observation in discovery.endpoints:
                endpoint_key = (
                    endpoint_observation.method,
                    normalize_url(endpoint_observation.url).url,
                )
                signature = response_signatures.get(endpoint_key)
                if signature is not None:
                    endpoint_observation.metadata = {
                        **(endpoint_observation.metadata or {}),
                        "response_signature": signature,
                    }
            endpoint_models = [
                DiscoveredEndpoint(
                    scan_id=scan.id,
                    url=item.url,
                    path=item.path,
                    method=item.method,
                    source=item.source,
                    resource_type=item.resource_type,
                    status_code=item.status_code,
                    content_type=item.content_type,
                    requires_auth=item.requires_auth,
                    parameters=item.parameters,
                    metadata_json=item.metadata,
                )
                for item in discovery.endpoints
            ]
            self.db.add_all(endpoint_models)
            self.db.flush()
            endpoint_index = {
                (item.method, normalize_url(item.url).url): item.id for item in endpoint_models
            }
            sensitive_rows: dict[tuple[int, object, str, object], SensitiveDataObservation] = {}
            if "sensitive_data" in scan.modules_enabled:
                for response in discovery.responses:
                    response_key = (response.method, normalize_url(response.endpoint).url)
                    endpoint_id = endpoint_index.get(response_key)
                    if endpoint_id is None:
                        endpoint_id = endpoint_index.get(
                            manual_response_endpoint_keys.get(response_key, response_key)
                        )
                    if endpoint_id is None:
                        continue
                    for item in self.sensitive_detector.analyze(response):
                        sensitive_key = (
                            endpoint_id,
                            item.category,
                            item.field_path,
                            item.detector_type,
                        )
                        current = sensitive_rows.get(sensitive_key)
                        if current:
                            current.count += item.count
                        else:
                            sensitive_rows[sensitive_key] = SensitiveDataObservation(
                                scan_id=scan.id,
                                endpoint_id=endpoint_id,
                                category=item.category,
                                field_path=item.field_path,
                                detector_type=item.detector_type,
                                confidence=item.confidence,
                                count=item.count,
                            )
            self.db.add_all(sensitive_rows.values())
            discovered_findings = self.engine.analyze(discovery.responses, scan.modules_enabled)
            # Preserve the configured URL behavior; only suppress browser-observed duplicates.
            findings = list(configured_result.findings)
            finding_keys = {
                (finding.title, normalize_url(finding.endpoint).url) for finding in findings
            }
            for finding in discovered_findings:
                finding_key = (finding.title, normalize_url(finding.endpoint).url)
                if finding_key not in finding_keys:
                    finding_keys.add(finding_key)
                    findings.append(finding)
            for finding in active_result.findings:
                finding_key = (finding.issue_key or finding.title, finding.endpoint)
                if finding_key not in finding_keys:
                    finding_keys.add(finding_key)
                    findings.append(finding)
            finding_models = []
            for finding_draft in findings:
                values = finding_draft.model_dump()
                if finding_draft.severity == Severity.INFO:
                    values["finding_type"] = "INFORMATION"
                if target.is_protected_target:
                    values["endpoint"] = sanitize_resource(finding_draft.endpoint)
                finding_models.append(Finding(scan_id=scan.id, **values))
            self.db.add_all(finding_models)
            scan.total_findings = len(findings)
            scan.observations = configured_result.observations
            scan.discovery_requests_observed = discovery.requests_observed
            scan.configuration_snapshot = {
                **scan.configuration_snapshot,
                "discovery_budget": {
                    "total_requests": discovery.requests_observed,
                    "useful_requests": discovery.useful_requests_observed,
                    "static_requests": discovery.static_requests_observed,
                    "useful_limit_reached": discovery.useful_limit_reached,
                    "static_limit_reached": discovery.static_limit_reached,
                    "hard_limit_reached": discovery.hard_limit_reached,
                },
                "openapi_operations_imported": (
                    target.openapi_operation_count if target.openapi_document else 0
                ),
                "postman_requests_imported": (
                    target.postman_request_count if target.postman_document else 0
                ),
                "manual_api_requests_imported": len(manual_templates),
                "manual_api_collection": {
                    **manual_collection,
                    "request_budget": settings.manual_api_max_requests,
                    "allowed_methods": ["GET", "HEAD", "OPTIONS"],
                    "follow_redirects": False,
                    "values_persisted": False,
                    "runtime_inputs_used": runtime_inputs_used,
                },
                "active_scan": {
                    "requests_sent": active_result.requests_sent,
                    "tested_parameters": active_result.tested_parameters,
                    "request_budget": self.active_engine.settings.active_max_requests,
                    "parameters_per_module": (
                        self.active_engine.settings.active_max_parameters_per_module
                    ),
                    "budget_truncated": active_result.truncated,
                    "allowed_methods": ["GET", "HEAD", "OPTIONS"],
                    "follow_redirects": False,
                    "forms_submitted": False,
                },
            }
            scan.status = ScanStatus.COMPLETED
            scan.phase = "COMPLETED"
            scan.progress_percent = 100
            scan.finished_at = utcnow()
            self.db.flush()
            if profile is not None:
                create_role_surface_snapshot(self.db, scan, profile)
            auth = None
            self.db.commit()
            logger.info("scan_completed scan_id=%s findings=%s", scan.id, scan.total_findings)
        except ScanCancelled:
            self.db.rollback()
            scan = self.db.get(Scan, scan_id)
            assert scan is not None
            scan.status = ScanStatus.CANCELLED
            scan.phase = "CANCELLED"
            scan.finished_at = utcnow()
            scan.error_message = None
            self.db.commit()
            logger.info("scan_cancelled scan_id=%s", scan_id)
        except Exception as exc:
            self.db.rollback()
            scan = self.db.get(Scan, scan_id)
            assert scan is not None
            scan.status = ScanStatus.FAILED
            scan.phase = "FAILED"
            scan.finished_at = utcnow()
            scan.total_findings = 0
            scan.discovery_requests_observed = 0
            if isinstance(exc, TargetPolicyError):
                scan.error_message = str(exc)
            elif isinstance(exc, CrawlerUnavailableError):
                scan.error_message = str(exc)
            elif isinstance(exc, AuthenticationError):
                scan.error_message = str(exc)
            elif isinstance(exc, httpx.TimeoutException):
                scan.error_message = "Tempo limite ao aguardar o alvo. Verifique se está acessível."
            elif isinstance(exc, httpx.HTTPError):
                scan.error_message = (
                    "Falha HTTP/conexão/TLS. Verifique endereço, porta e certificado."
                )
            else:
                scan.error_message = "Falha interna durante a varredura. Consulte o log do backend."
            self.db.commit()
            # Exception messages may contain sensitive URLs. Log class and identifiers only.
            logger.error("scan_failed scan_id=%s error_type=%s", scan_id, type(exc).__name__)
        if scan.auth_profile_id is not None:
            ephemeral_auth_sessions.discard(scan.auth_profile_id)
        self.db.refresh(scan)
        return scan

    def _checkpoint(self, scan: Scan, phase: str, progress_percent: int) -> None:
        self.db.refresh(scan)
        if scan.cancellation_requested:
            raise ScanCancelled
        scan.phase = phase
        scan.progress_percent = progress_percent
        self.db.commit()
        self.db.refresh(scan)

    def _active_checkpoint(self, scan: Scan, module_id: str) -> None:
        self.db.refresh(scan)
        if scan.cancellation_requested:
            raise ScanCancelled
        phase = f"ACTIVE_{module_id.upper()}"
        progress = {
            "http_methods": 67,
            "open_redirect": 69,
            "path_traversal": 72,
            "sql_injection": 75,
            "reflected_xss": 77,
        }.get(module_id, 65)
        if scan.phase != phase:
            scan.phase = phase
            scan.progress_percent = progress
            self.db.commit()
            self.db.refresh(scan)
