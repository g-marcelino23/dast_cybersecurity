"""URL and network policy shared by registration and every outbound connection."""

import ipaddress
import socket
from collections.abc import Collection
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(network) for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


class TargetPolicyError(ValueError):
    pass


@dataclass(frozen=True)
class ValidatedTarget:
    url: httpx.URL
    addresses: tuple[str, ...]


def address_allowed(value: str) -> bool:
    address = ipaddress.ip_address(value)
    # Reject mapped IPv6, scoped addresses, link-local, unspecified and reserved ranges.
    if isinstance(address, ipaddress.IPv6Address):
        return address == ipaddress.ip_address("::1")
    return address.is_loopback or any(address in network for network in PRIVATE_NETWORKS)


def normalize_target_url(raw_url: str) -> httpx.URL:
    if not raw_url or len(raw_url) > 2048 or any(ord(c) <= 32 for c in raw_url):
        raise TargetPolicyError("URL vazia, extensa demais ou com espaços/caracteres de controle.")
    if "\\" in raw_url:
        raise TargetPolicyError("Barras invertidas não são permitidas na URL.")
    try:
        parts = urlsplit(raw_url)
        url = httpx.URL(raw_url)
        port = parts.port if parts.port is not None else (443 if parts.scheme == "https" else 80)
    except (ValueError, httpx.InvalidURL) as exc:
        raise TargetPolicyError("URL inválida.") from exc
    if parts.scheme not in {"http", "https"} or not parts.hostname or not url.host:
        raise TargetPolicyError("Use uma URL HTTP ou HTTPS absoluta.")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise TargetPolicyError("Credenciais na URL não são permitidas.")
    if parts.fragment or "%" in parts.netloc or port < 1:
        raise TargetPolicyError("Fragmentos, hosts codificados e escopos IPv6 não são permitidos.")
    return url


def target_hostname(raw_url: str) -> str:
    return normalize_target_url(raw_url).host.rstrip(".").casefold()


def validate_target(
    raw_url: str, allowed_public_hosts: Collection[str] = ()
) -> ValidatedTarget:
    url = normalize_target_url(raw_url)
    port = url.port or (443 if url.scheme == "https" else 80)
    host = url.host
    addresses: tuple[str, ...]
    try:
        addresses = (str(ipaddress.ip_address(host)),)
    except ValueError:
        if host.rstrip(".").lower() == "localhost":
            addresses = ("127.0.0.1", "::1")
        else:
            try:
                addresses = tuple(
                    dict.fromkeys(
                        str(entry[4][0])
                        for entry in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
                    )
                )
            except OSError as exc:
                raise TargetPolicyError("Não foi possível resolver o hostname do alvo.") from exc
    if not addresses:
        raise TargetPolicyError("Não foi possível resolver o hostname do alvo.")
    private = [address_allowed(address) for address in addresses]
    if all(private):
        return ValidatedTarget(url=url, addresses=addresses)
    allowed_hosts = {value.rstrip(".").casefold() for value in allowed_public_hosts}
    hostname = host.rstrip(".").casefold()
    globally_routable = all(ipaddress.ip_address(address).is_global for address in addresses)
    if any(private) or not globally_routable:
        raise TargetPolicyError("Alvo bloqueado: resolução DNS insegura ou fora do escopo.")
    if hostname not in allowed_hosts:
        raise TargetPolicyError("Alvo público bloqueado: domínio não verificado ou fora do escopo.")
    return ValidatedTarget(url=url, addresses=addresses)
