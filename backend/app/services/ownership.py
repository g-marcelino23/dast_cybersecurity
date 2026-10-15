import ipaddress
import secrets
from datetime import UTC, datetime, timedelta
from typing import Literal
from urllib.parse import urlsplit, urlunsplit

import httpx

from app import __version__
from app.core.target_policy import (
    TargetPolicyError,
    normalize_target_url,
    target_hostname,
    validate_target,
)
from app.models import Target

CHALLENGE_PATH = "/.well-known/dast-verification.txt"
VERIFICATION_TTL = timedelta(days=30)
MAX_CHALLENGE_BYTES = 4096
OwnershipVerificationStatus = Literal["NOT_REQUIRED", "PENDING", "VERIFIED", "EXPIRED"]


def new_verification_token() -> str:
    return secrets.token_urlsafe(32)


def configured_hosts(base_url: str, api_url: str | None) -> list[str]:
    return list(dict.fromkeys(target_hostname(url) for url in [base_url, api_url] if url))


def registration_scope(
    base_url: str, api_url: str | None
) -> tuple[str, str | None, list[str], bool]:
    normalized = [str(normalize_target_url(url)) for url in [base_url, api_url] if url]
    hosts = configured_hosts(normalized[0], normalized[1] if len(normalized) > 1 else None)
    public = False
    private = False
    for url in normalized:
        host = target_hostname(url)
        try:
            ipaddress.ip_address(host)
        except ValueError:
            try:
                validate_target(url)
                private = True
            except TargetPolicyError as exc:
                if "não foi possível resolver" in str(exc).casefold():
                    public = True
                elif (
                    "somente loopback" in str(exc).casefold()
                    or "fora do escopo" in str(exc).casefold()
                ):
                    public = True
                else:
                    raise
        else:
            try:
                validate_target(url)
                private = True
            except TargetPolicyError as exc:
                raise TargetPolicyError(
                    "IPs públicos não podem ser cadastrados; use um domínio que você controla."
                ) from exc
    if public and private:
        raise TargetPolicyError("Não combine hosts públicos e privados no mesmo alvo.")
    if public and any(normalize_target_url(url).scheme != "https" for url in normalized):
        raise TargetPolicyError("Alvos públicos exigem HTTPS.")
    return normalized[0], normalized[1] if len(normalized) > 1 else None, hosts, public


def verification_status(
    target: Target, now: datetime | None = None
) -> OwnershipVerificationStatus:
    if not target.requires_ownership_verification:
        return "NOT_REQUIRED"
    if target.ownership_verified_at is None or target.ownership_verification_expires_at is None:
        return "PENDING"
    moment = now or datetime.now(UTC)
    expires = target.ownership_verification_expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=UTC)
    return "VERIFIED" if expires > moment else "EXPIRED"


def verified_public_hosts(target: Target) -> tuple[str, ...]:
    return tuple(target.allowed_hosts) if verification_status(target) == "VERIFIED" else ()


def challenge_urls(target: Target) -> list[str]:
    result: list[str] = []
    for raw_url in [target.base_url, target.api_url]:
        if not raw_url:
            continue
        parts = urlsplit(raw_url)
        value = urlunsplit((parts.scheme, parts.netloc, CHALLENGE_PATH, "", ""))
        if value not in result:
            result.append(value)
    return result


def verify_target_ownership(target: Target) -> None:
    if not target.requires_ownership_verification:
        return
    token = target.ownership_verification_token
    if not token:
        raise TargetPolicyError("Desafio de verificação ausente.")
    for raw_url in challenge_urls(target):
        validated = validate_target(raw_url, target.allowed_hosts)
        last_error: Exception | None = None
        for address in validated.addresses:
            try:
                with httpx.Client(
                    timeout=10,
                    follow_redirects=False,
                    trust_env=False,
                    verify=True,
                    limits=httpx.Limits(max_connections=1, max_keepalive_connections=0),
                ) as client:
                    response = client.request(
                        "GET",
                        validated.url.copy_with(host=address),
                        headers={
                            "Host": validated.url.netloc.decode("ascii"),
                            "User-Agent": f"DAST/{__version__} (ownership verification)",
                            "Accept": "text/plain",
                        },
                        extensions={"sni_hostname": validated.url.host},
                    )
                if response.status_code != 200 or len(response.content) > MAX_CHALLENGE_BYTES:
                    raise TargetPolicyError("Arquivo de verificação ausente ou inválido.")
                if not secrets.compare_digest(response.text.strip(), token):
                    raise TargetPolicyError("O conteúdo do arquivo de verificação não confere.")
                break
            except httpx.ConnectError as exc:
                last_error = exc
        else:
            raise TargetPolicyError(
                "Não foi possível acessar o arquivo de verificação."
            ) from last_error
    now = datetime.now(UTC)
    target.ownership_verified_at = now
    target.ownership_verification_expires_at = now + VERIFICATION_TTL
