import posixpath
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, quote, urljoin, urlsplit, urlunsplit

HTTP_METHOD = re.compile(r"^[A-Z][A-Z0-9_-]{0,15}$")


class URLNormalizationError(ValueError):
    pass


@dataclass(frozen=True)
class NormalizedURL:
    url: str
    path: str
    origin: str
    hostname: str
    parameters: dict[str, object] | None


def normalize_method(method: str) -> str:
    normalized = method.strip().upper()
    return normalized if HTTP_METHOD.fullmatch(normalized) else "OTHER"


def normalize_url(raw_url: str, base_url: str | None = None) -> NormalizedURL:
    try:
        absolute = urljoin(base_url, raw_url) if base_url else raw_url
        parts = urlsplit(absolute)
        port = parts.port
    except ValueError as exc:
        raise URLNormalizationError("URL inválida durante discovery.") from exc
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        raise URLNormalizationError("Discovery aceita somente URLs HTTP(S) absolutas.")
    if parts.username is not None or parts.password is not None:
        raise URLNormalizationError("Credenciais na URL não são permitidas.")
    scheme = parts.scheme.lower()
    hostname = parts.hostname.rstrip(".").lower()
    try:
        hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise URLNormalizationError("Hostname inválido.") from exc
    display_host = f"[{hostname}]" if ":" in hostname else hostname
    default_port = 443 if scheme == "https" else 80
    authority = display_host if port in {None, default_port} else f"{display_host}:{port}"

    path = parts.path or "/"
    if any(ord(character) < 32 for character in path):
        raise URLNormalizationError("Caminho contém caracteres de controle.")
    # Normalize dot segments without decoding percent-encoded path separators.
    path = posixpath.normpath(path)
    if not path.startswith("/"):
        path = f"/{path}"
    if path != "/":
        path = path.rstrip("/")
    path = quote(path, safe="/%:@!$&'()*+,;=-._~")

    query_pairs = parse_qsl(parts.query, keep_blank_values=True, strict_parsing=False)
    counts: dict[str, int] = {}
    for name, _value in query_pairs:
        clean_name = re.sub(r"[\x00-\x1f\x7f]", "", name).strip()[:128]
        if clean_name:
            counts[clean_name] = counts.get(clean_name, 0) + 1
    names = sorted(counts, key=str.casefold)
    query_template = "&".join(f"{quote(name, safe='-._~')}={{value}}" for name in names)
    parameters: dict[str, object] | None = None
    if names:
        parameters = {
            "query": [
                {"name": name, "location": "query", "repeated": counts[name] > 1} for name in names
            ]
        }
    origin = f"{scheme}://{authority}"
    return NormalizedURL(
        url=urlunsplit((scheme, authority, path, query_template, "")),
        path=path,
        origin=origin,
        hostname=hostname,
        parameters=parameters,
    )


def same_origin(first: str, second: str) -> bool:
    return normalize_url(first).origin == normalize_url(second).origin
