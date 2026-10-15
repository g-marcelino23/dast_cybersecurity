import logging
from collections.abc import Callable, Collection
from typing import cast

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import Request, Response, Route
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError

from app.core.config import Settings, get_settings
from app.crawler.browser import AuthContext, BrowserSession
from app.crawler.discovery import DiscoveryInventory, DiscoveryQueue
from app.crawler.models import DiscoveryResult, EndpointObservation
from app.crawler.normalizer import URLNormalizationError, normalize_method, normalize_url
from app.crawler.scope import CrawlerScope
from app.models.enums import DiscoverySource, ResourceType

logger = logging.getLogger(__name__)


class CrawlerUnavailableError(RuntimeError):
    pass


class DiscoveryCrawler:
    def __init__(
        self,
        settings: Settings | None = None,
        session_factory: Callable[
            [CrawlerScope, AuthContext | None], BrowserSession
        ] = BrowserSession,
    ) -> None:
        self.settings = settings or get_settings()
        self.session_factory = session_factory

    def crawl(
        self,
        base_url: str,
        api_url: str | None = None,
        auth: AuthContext | None = None,
        allowed_public_hosts: Collection[str] = (),
        additional_urls: Collection[str] = (),
        additional_navigation_urls: Collection[str] = (),
    ) -> DiscoveryResult:
        scope = CrawlerScope.from_target(
            base_url,
            api_url,
            allowed_public_hosts,
            additional_urls,
            additional_navigation_urls,
        )
        inventory = DiscoveryInventory(
            self.settings.crawler_max_requests,
            max_static_requests=self.settings.crawler_max_static_requests,
            authenticated=bool(auth and auth.authenticated),
        )
        queue = DiscoveryQueue(self.settings.crawler_max_depth, self.settings.crawler_max_pages)
        queue.add(scope.base_url, 0)
        for url in additional_navigation_urls:
            queue.add(normalize_url(url).url, 0)
        timeout_ms = int(self.settings.crawler_timeout_seconds * 1000)
        logger.info("[DISCOVERY] Opening %s", normalize_url(base_url).url)
        try:
            with self.session_factory(scope, auth).open() as (context, page):
                if auth and auth.authenticated:
                    logger.info("[DISCOVERY] Authenticated browser context created")

                def handle_route(route: Route, request: Request) -> None:
                    if not scope.allows_request(request.url, request.resource_type):
                        inventory.blocked_requests += 1
                        route.abort("blockedbyclient")
                        return
                    if not inventory.observe_request(
                        request.url, request.method, request.resource_type
                    ):
                        route.abort("blockedbyclient")
                        return
                    route.continue_()

                def handle_response(response: Response) -> None:
                    request = response.request
                    if not scope.allows_request(request.url, request.resource_type):
                        return
                    try:
                        headers = response.all_headers()
                    except PlaywrightError:
                        headers = {}
                    body: bytes | None = None
                    content_type = headers.get("content-type", "").lower()
                    content_length = headers.get("content-length")
                    declared_size = (
                        int(content_length) if content_length and content_length.isdigit() else 0
                    )
                    if (
                        "json" in content_type or "html" in content_type
                    ) and declared_size <= self.settings.sensitive_body_max_bytes:
                        try:
                            candidate = response.body()
                            if len(candidate) <= self.settings.sensitive_body_max_bytes:
                                body = candidate
                        except PlaywrightError:
                            body = None
                    inventory.observe_response(
                        request.url,
                        request.method,
                        request.resource_type,
                        response.status,
                        headers,
                        body,
                    )

                context.route("**/*", handle_route)
                context.on("response", handle_response)
                while not inventory.limit_reached:
                    queued = queue.next()
                    if queued is None:
                        break
                    url, depth = queued
                    if not scope.can_navigate(url):
                        continue
                    logger.info("[DISCOVERY] PAGE %s depth=%s", normalize_url(url).path, depth)
                    try:
                        navigation = page.goto(
                            url, wait_until="domcontentloaded", timeout=timeout_ms
                        )
                        if self.settings.crawler_wait_after_load_ms:
                            page.wait_for_timeout(self.settings.crawler_wait_after_load_ms)
                    except PlaywrightTimeoutError:
                        logger.warning("[DISCOVERY] Page timeout path=%s", normalize_url(url).path)
                        continue
                    except PlaywrightError:
                        logger.warning("[DISCOVERY] Broken page path=%s", normalize_url(url).path)
                        continue
                    if not scope.can_navigate(page.url):
                        continue
                    final_url = normalize_url(page.url)
                    headers = navigation.all_headers() if navigation is not None else {}
                    inventory.add(
                        EndpointObservation(
                            url=final_url.url,
                            path=final_url.path,
                            method="GET",
                            source=DiscoverySource.CRAWLER,
                            resource_type=ResourceType.PAGE,
                            status_code=navigation.status if navigation is not None else None,
                            content_type=headers.get("content-type", "")[:255] or None,
                            parameters=final_url.parameters,
                            metadata={"depth": depth},
                        )
                    )
                    links = self._extract_links(
                        page.locator("a[href]").evaluate_all(
                            "elements => elements.map(element => element.href).filter(Boolean)"
                        )
                    )
                    for link in links:
                        if scope.can_navigate(link):
                            queue.add(link, depth + 1)
                    forms = cast(
                        list[object],
                        page.locator("form").evaluate_all(
                            """forms => forms.map(form => ({
                              action: form.action || location.href,
                              method: (form.method || 'GET').toUpperCase(),
                              fields: Array.from(form.elements)
                                .filter(field => field.name)
                                .map(field => ({
                                  name: field.name,
                                  type: field.type || field.tagName.toLowerCase()
                                }))
                            }))"""
                        ),
                    )
                    self._record_forms(forms, page.url, scope, inventory)
        except PlaywrightError as exc:
            if "Executable doesn't exist" in str(exc):
                raise CrawlerUnavailableError(
                    "Chromium do Playwright não está instalado. Execute: "
                    "python -m playwright install chromium"
                ) from exc
            raise
        result = inventory.result()
        logger.info(
            "[DISCOVERY] Completed: endpoints=%s requests=%s blocked=%s",
            len(result.endpoints),
            result.requests_observed,
            result.blocked_requests,
        )
        return result

    @staticmethod
    def _extract_links(raw_links: object) -> list[str]:
        if not isinstance(raw_links, list):
            return []
        return [link for link in raw_links if isinstance(link, str) and len(link) <= 2048]

    @staticmethod
    def _record_forms(
        raw_forms: list[object],
        page_url: str,
        scope: CrawlerScope,
        inventory: DiscoveryInventory,
    ) -> None:
        for raw_form in raw_forms:
            if not isinstance(raw_form, dict):
                continue
            action = raw_form.get("action")
            method = raw_form.get("method")
            fields = raw_form.get("fields")
            if not isinstance(action, str) or not isinstance(method, str):
                continue
            try:
                normalized = normalize_url(action, page_url)
            except URLNormalizationError:
                continue
            if not scope.allows_request(normalized.url, "xhr"):
                continue
            safe_fields = []
            if isinstance(fields, list):
                for field in fields[:100]:
                    if not isinstance(field, dict):
                        continue
                    name = field.get("name")
                    field_type = field.get("type")
                    if isinstance(name, str) and name:
                        safe_fields.append(
                            {
                                "name": name[:128],
                                "type": field_type[:64]
                                if isinstance(field_type, str)
                                else "unknown",
                            }
                        )
            inventory.add(
                EndpointObservation(
                    url=normalized.url,
                    path=normalized.path,
                    method=normalize_method(method),
                    source=DiscoverySource.FORM,
                    resource_type=ResourceType.FORM,
                    parameters={"fields": safe_fields},
                    metadata={"detected_on": normalize_url(page_url).path},
                )
            )
