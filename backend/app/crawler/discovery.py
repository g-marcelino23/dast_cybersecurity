from collections import deque
from collections.abc import Iterable
from urllib.parse import urlsplit, urlunsplit

import httpx

from app.crawler.models import DiscoveryResult, EndpointObservation
from app.crawler.normalizer import URLNormalizationError, normalize_method, normalize_url
from app.models.enums import DiscoverySource, ResourceType
from app.scanner.base import ResponseSnapshot

RESOURCE_PRIORITY = {
    ResourceType.OTHER: 0,
    ResourceType.SCRIPT: 1,
    ResourceType.PAGE: 2,
    ResourceType.API: 3,
    ResourceType.FORM: 4,
}
SOURCE_PRIORITY = {
    DiscoverySource.OPENAPI: -1,
    DiscoverySource.NETWORK: 0,
    DiscoverySource.JAVASCRIPT: 1,
    DiscoverySource.HTML: 2,
    DiscoverySource.CRAWLER: 3,
    DiscoverySource.FORM: 4,
}
STATIC_BROWSER_TYPES = {"script", "stylesheet", "image", "font", "media", "manifest"}
DEVELOPMENT_RESOURCE_MARKERS = (
    "/@vite/",
    "/@react-refresh",
    "/__vite",
    "/sockjs-node",
    "webpack-hmr",
    ".hot-update.",
)


def classify_resource(
    browser_type: str, method: str, content_type: str | None = None
) -> ResourceType:
    kind = browser_type.lower()
    media_type = (content_type or "").lower().split(";", maxsplit=1)[0].strip()
    if kind == "document":
        return ResourceType.PAGE
    if kind in {"xhr", "fetch", "eventsource", "websocket"}:
        return ResourceType.API
    if media_type == "application/json" or media_type.endswith("+json"):
        return ResourceType.API
    if normalize_method(method) not in {"GET", "HEAD", "OPTIONS"}:
        return ResourceType.API
    if kind == "script":
        return ResourceType.SCRIPT
    return ResourceType.OTHER


def is_static_or_development_resource(url: str, browser_type: str) -> bool:
    kind = browser_type.lower()
    if kind in STATIC_BROWSER_TYPES:
        return True
    try:
        path = normalize_url(url).path.casefold()
    except URLNormalizationError:
        path = url.casefold()
    return path.endswith(".map") or any(marker in path for marker in DEVELOPMENT_RESOURCE_MARKERS)


class DiscoveryInventory:
    def __init__(
        self,
        max_requests: int,
        *,
        max_static_requests: int | None = None,
        authenticated: bool = False,
    ) -> None:
        self.max_requests = max_requests
        self.max_static_requests = (
            max_requests if max_static_requests is None else max_static_requests
        )
        self.hard_max_requests = self.max_requests + self.max_static_requests
        self.authenticated = authenticated
        self.requests_observed = 0
        self.useful_requests_observed = 0
        self.static_requests_observed = 0
        self.blocked_requests = 0
        self._items: dict[tuple[str, str, ResourceType], EndpointObservation] = {}
        self._responses: dict[tuple[str, int], ResponseSnapshot] = {}

    @property
    def limit_reached(self) -> bool:
        return self.hard_limit_reached or self.useful_limit_reached

    @property
    def useful_limit_reached(self) -> bool:
        return self.useful_requests_observed >= self.max_requests

    @property
    def static_limit_reached(self) -> bool:
        return self.static_requests_observed >= self.max_static_requests

    @property
    def hard_limit_reached(self) -> bool:
        return self.requests_observed >= self.hard_max_requests

    def observe_request(self, url: str, method: str, browser_type: str) -> bool:
        is_static = is_static_or_development_resource(url, browser_type)
        if self.hard_limit_reached or (
            self.static_limit_reached if is_static else self.useful_limit_reached
        ):
            self.blocked_requests += 1
            return False
        self.requests_observed += 1
        if is_static:
            self.static_requests_observed += 1
        else:
            self.useful_requests_observed += 1
        try:
            normalized = normalize_url(url)
        except URLNormalizationError:
            return True
        resource_type = classify_resource(browser_type, method)
        self.add(
            EndpointObservation(
                url=normalized.url,
                path=normalized.path,
                method=normalize_method(method),
                source=DiscoverySource.NETWORK,
                resource_type=resource_type,
                parameters=normalized.parameters,
                metadata={"browser_resource_type": browser_type[:32]},
            )
        )
        return True

    def observe_response(
        self,
        url: str,
        method: str,
        browser_type: str,
        status_code: int,
        headers: dict[str, str],
        body: bytes | None = None,
    ) -> None:
        try:
            normalized = normalize_url(url)
        except URLNormalizationError:
            return
        content_type = headers.get("content-type", "").strip()[:255] or None
        resource_type = classify_resource(browser_type, method, content_type)
        observation = EndpointObservation(
            url=normalized.url,
            path=normalized.path,
            method=normalize_method(method),
            source=DiscoverySource.NETWORK,
            resource_type=resource_type,
            status_code=status_code,
            content_type=content_type,
            requires_auth=True if self.authenticated or status_code in {401, 403} else None,
            parameters=normalized.parameters,
            metadata={"browser_resource_type": browser_type[:32]},
        )
        self.add(observation)
        if resource_type in {ResourceType.PAGE, ResourceType.API}:
            snapshot_key = (normalized.url, status_code)
            self._responses[snapshot_key] = ResponseSnapshot(
                endpoint=normalized.url,
                status_code=status_code,
                # Sensitive values live only in this in-memory snapshot and are never persisted.
                headers=httpx.Headers(headers),
                body=body,
                method=normalize_method(method),
            )

    def add(self, observation: EndpointObservation) -> None:
        current = self._items.get(observation.key)
        if current is None:
            self._items[observation.key] = observation
            return
        if observation.status_code is not None:
            current.status_code = observation.status_code
            current.requires_auth = observation.requires_auth
        if observation.content_type:
            current.content_type = observation.content_type
        if SOURCE_PRIORITY[observation.source] > SOURCE_PRIORITY[current.source]:
            current.source = observation.source
        if observation.parameters:
            current.parameters = observation.parameters
        if observation.metadata:
            current.metadata = {**(current.metadata or {}), **observation.metadata}

    def result(self) -> DiscoveryResult:
        endpoints = sorted(
            self._items.values(), key=lambda item: (item.url, item.method, item.resource_type)
        )
        return DiscoveryResult(
            endpoints=endpoints,
            responses=list(self._responses.values()),
            requests_observed=self.requests_observed,
            blocked_requests=self.blocked_requests,
            useful_requests_observed=self.useful_requests_observed,
            static_requests_observed=self.static_requests_observed,
            useful_limit_reached=self.useful_limit_reached,
            static_limit_reached=self.static_limit_reached,
            hard_limit_reached=self.hard_limit_reached,
        )


class DiscoveryQueue:
    def __init__(self, max_depth: int, max_pages: int) -> None:
        self.max_depth = max_depth
        self.max_pages = max_pages
        self._queue: deque[tuple[str, int]] = deque()
        self._scheduled: set[str] = set()
        self.visited: set[str] = set()

    def add(self, url: str, depth: int) -> bool:
        if depth > self.max_depth or len(self._scheduled) >= self.max_pages:
            return False
        normalized = normalize_url(url).url
        if normalized in self._scheduled:
            return False
        normalized_parts = urlsplit(normalized)
        original_query = urlsplit(url).query
        # Query values are needed for navigation but remain in this in-memory queue only.
        # The deduplication key and every persisted observation stay value-free.
        navigation_url = urlunsplit(
            (
                normalized_parts.scheme,
                normalized_parts.netloc,
                normalized_parts.path,
                original_query,
                "",
            )
        )
        self._scheduled.add(normalized)
        self._queue.append((navigation_url, depth))
        return True

    def next(self) -> tuple[str, int] | None:
        if not self._queue or len(self.visited) >= self.max_pages:
            return None
        url, depth = self._queue.popleft()
        self.visited.add(url)
        return url, depth

    def extend(self, urls: Iterable[str], depth: int) -> None:
        for url in urls:
            self.add(url, depth)
