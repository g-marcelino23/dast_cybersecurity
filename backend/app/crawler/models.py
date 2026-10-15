from dataclasses import dataclass, field

from app.models.enums import DiscoverySource, ResourceType
from app.scanner.base import ResponseSnapshot


@dataclass
class EndpointObservation:
    url: str
    path: str
    method: str
    source: DiscoverySource
    resource_type: ResourceType
    status_code: int | None = None
    content_type: str | None = None
    requires_auth: bool | None = None
    parameters: dict[str, object] | None = None
    metadata: dict[str, object] | None = None

    @property
    def key(self) -> tuple[str, str, ResourceType]:
        return self.method, self.url, self.resource_type


@dataclass
class DiscoveryResult:
    endpoints: list[EndpointObservation] = field(default_factory=list)
    responses: list[ResponseSnapshot] = field(default_factory=list)
    requests_observed: int = 0
    blocked_requests: int = 0
    useful_requests_observed: int = 0
    static_requests_observed: int = 0
    useful_limit_reached: bool = False
    static_limit_reached: bool = False
    hard_limit_reached: bool = False

    @classmethod
    def empty(cls) -> "DiscoveryResult":
        return cls()
