from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, cast

from playwright.sync_api import BrowserContext, Page, sync_playwright

from app import __version__
from app.crawler.scope import CrawlerScope


@dataclass(frozen=True)
class AuthContext:
    """Ephemeral authentication material for one isolated browser context."""

    headers: dict[str, str] = field(default_factory=dict)
    cookies: tuple[dict[str, object], ...] = ()
    profile_id: int | None = None
    profile_name: str | None = None
    role_name: str | None = None
    session_metadata: dict[str, str] = field(default_factory=dict)
    storage_state_path: str | None = None

    @property
    def authenticated(self) -> bool:
        return bool(self.headers or self.cookies)


class BrowserSession:
    def __init__(self, scope: CrawlerScope, auth: AuthContext | None = None) -> None:
        self.scope = scope
        self.auth = auth or AuthContext()

    @contextmanager
    def open(self) -> Iterator[tuple[BrowserContext, Page]]:
        with sync_playwright() as playwright:
            resolver_rules = self.scope.chromium_resolver_rules()
            launch_args = ["--no-proxy-server", "--disable-background-networking"]
            if resolver_rules:
                launch_args.append(f"--host-resolver-rules={resolver_rules}")
            browser = playwright.chromium.launch(headless=True, args=launch_args)
            try:
                context = browser.new_context(
                    accept_downloads=False,
                    ignore_https_errors=False,
                    java_script_enabled=True,
                    service_workers="block",
                    storage_state=self.auth.storage_state_path,
                    extra_http_headers=self.auth.headers,
                    user_agent=f"DAST/{__version__} (authorized security scanner)",
                )
                if self.auth.cookies:
                    context.add_cookies(cast(Any, list(self.auth.cookies)))
                try:
                    yield context, context.new_page()
                finally:
                    context.close()
            finally:
                browser.close()
