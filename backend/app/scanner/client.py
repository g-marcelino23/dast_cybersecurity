from collections.abc import Collection, Mapping

import httpx

from app import __version__
from app.core.config import get_settings
from app.core.target_policy import validate_target
from app.crawler.browser import AuthContext
from app.scanner.base import ResponseSnapshot


def _tls_metadata(response: httpx.Response) -> tuple[str | None, str | None]:
    stream = response.extensions.get("network_stream")
    extra_info = getattr(stream, "get_extra_info", None)
    if not callable(extra_info):
        return None, None
    ssl_object = extra_info("ssl_object")
    if ssl_object is None:
        return None, None
    version = ssl_object.version()
    cipher_details = ssl_object.cipher()
    cipher = cipher_details[0] if cipher_details else None
    return version, cipher


class SafeHttpCollector:
    """Pinned, no-proxy HTTP collection with no redirect following."""

    def fetch(
        self,
        raw_url: str,
        auth: AuthContext | None = None,
        allowed_public_hosts: Collection[str] = (),
    ) -> ResponseSnapshot:
        return self.request(
            raw_url,
            "GET",
            auth,
            timeout_seconds=get_settings().scan_timeout_seconds,
            allowed_public_hosts=allowed_public_hosts,
        )

    def request(
        self,
        raw_url: str,
        method: str,
        auth: AuthContext | None = None,
        *,
        timeout_seconds: float | None = None,
        extra_headers: Mapping[str, str] | None = None,
        allowed_public_hosts: Collection[str] = (),
    ) -> ResponseSnapshot:
        normalized_method = method.upper()
        if normalized_method not in {"GET", "HEAD", "OPTIONS"}:
            raise ValueError("Safe collection permits only GET, HEAD and OPTIONS.")
        validated = validate_target(raw_url, allowed_public_hosts)
        url = validated.url
        safe_extra_headers = {
            name: value
            for name, value in (extra_headers or {}).items()
            if name.casefold()
            not in {
                "connection",
                "content-length",
                "host",
                "proxy-authorization",
                "proxy-connection",
                "te",
                "trailer",
                "transfer-encoding",
                "upgrade",
            }
        }
        # Connect to the vetted IP, preventing a second DNS lookup (DNS rebinding).
        # Host and TLS SNI/certificate validation still use the original hostname.
        last_error: httpx.ConnectError | None = None
        for address in validated.addresses:
            try:
                with httpx.Client(
                    timeout=timeout_seconds or get_settings().authz_request_timeout,
                    follow_redirects=False,
                    trust_env=False,
                    verify=True,
                    limits=httpx.Limits(max_connections=1, max_keepalive_connections=0),
                ) as client:
                    auth_headers = auth.headers if auth else {}
                    auth_cookies = (
                        {str(item["name"]): str(item["value"]) for item in auth.cookies}
                        if auth
                        else None
                    )
                    with client.stream(
                        normalized_method,
                        url.copy_with(host=address),
                        headers={
                            "Host": url.netloc.decode("ascii"),
                            "User-Agent": f"DAST/{__version__} (authorized security scanner)",
                            "Accept": "text/html, application/json;q=0.9, */*;q=0.5",
                            **auth_headers,
                            **safe_extra_headers,
                        },
                        cookies=auth_cookies,
                        extensions={"sni_hostname": url.host},
                    ) as response:
                        tls_version, tls_cipher = _tls_metadata(response)
                        chunks: list[bytes] = []
                        content_type = response.headers.get("content-type", "").lower()
                        declared = response.headers.get("content-length", "")
                        declared_size = int(declared) if declared.isdigit() else 0
                        if (
                            "json" in content_type or "html" in content_type
                        ) and declared_size <= get_settings().sensitive_body_max_bytes:
                            size = 0
                            for chunk in response.iter_bytes():
                                size += len(chunk)
                                if size > get_settings().sensitive_body_max_bytes:
                                    chunks = []
                                    break
                                chunks.append(chunk)
                        return ResponseSnapshot(
                            # Query strings can contain identifiers or tokens. Never store them.
                            endpoint=str(url.copy_with(query=None, fragment=None)),
                            status_code=response.status_code,
                            headers=httpx.Headers(response.headers),
                            body=b"".join(chunks) or None,
                            method=normalized_method,
                            tls_version=tls_version,
                            tls_cipher=tls_cipher,
                        )
            except httpx.ConnectError as exc:
                last_error = exc
        assert last_error is not None
        raise last_error
