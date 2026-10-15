import json
import logging
import re
from base64 import b64encode
from dataclasses import dataclass
from http.cookies import SimpleCookie
from threading import Lock
from time import monotonic
from typing import Any
from urllib.parse import quote

import httpx

from app import __version__
from app.core.config import Settings, get_settings
from app.core.secrets import CredentialVault
from app.core.target_policy import validate_target
from app.crawler.browser import AuthContext
from app.crawler.normalizer import normalize_url
from app.models import AuthProfile, Target
from app.models.enums import AuthType
from app.services.ownership import verified_public_hosts
from app.services.target_components import target_urls

logger = logging.getLogger(__name__)
DIRECT_AUTH_TYPES = {
    AuthType.BASIC,
    AuthType.BEARER_TOKEN,
    AuthType.API_KEY,
    AuthType.CUSTOM_HEADERS,
}


class AuthenticationError(RuntimeError):
    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        code: str = "AUTHENTICATION_FAILED",
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code


@dataclass(frozen=True)
class SafeResponse:
    status_code: int
    headers: httpx.Headers
    body: bytes
    cookies: dict[str, str]
    browser_cookies: tuple[dict[str, object], ...] = ()


class EphemeralAuthSessions:
    """Process-local authenticated contexts; secrets never reach the database."""

    def __init__(self, ttl_seconds: float = 600) -> None:
        self.ttl_seconds = ttl_seconds
        self._entries: dict[int, tuple[float, str, AuthContext]] = {}
        self._lock = Lock()

    @staticmethod
    def _marker(profile: AuthProfile) -> str:
        return f"{profile.target_id}:{profile.created_at}:{profile.updated_at}"

    def put(self, profile: AuthProfile, context: AuthContext) -> None:
        with self._lock:
            self._entries[profile.id] = (
                monotonic() + self.ttl_seconds,
                self._marker(profile),
                context,
            )

    def get(self, profile: AuthProfile) -> AuthContext | None:
        with self._lock:
            entry = self._entries.get(profile.id)
            if entry is None:
                return None
            expires_at, marker, context = entry
            if expires_at <= monotonic() or marker != self._marker(profile):
                self._entries.pop(profile.id, None)
                return None
            return context

    def discard(self, profile_id: int) -> None:
        with self._lock:
            self._entries.pop(profile_id, None)

    def contains(self, profile_id: int) -> bool:
        """Return only whether process-local authentication material is retained."""
        with self._lock:
            return profile_id in self._entries


ephemeral_auth_sessions = EphemeralAuthSessions()


def ensure_auth_url_in_target_scope(raw_url: str, target: Target) -> str:
    validated = validate_target(raw_url, verified_public_hosts(target))
    normalized = normalize_url(str(validated.url))
    configured_origins = {normalize_url(url).origin for url in target_urls(target)}
    if normalized.origin not in configured_origins:
        raise AuthenticationError("A URL de autenticação deve pertencer ao alvo configurado.")
    return str(validated.url)


class Authenticator:
    def __init__(
        self,
        vault: CredentialVault | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.vault = vault or CredentialVault.from_settings()
        self.settings = settings or get_settings()
        self.allowed_public_hosts: tuple[str, ...] = ()

    def authenticate(
        self,
        profile: AuthProfile,
        target: Target,
        *,
        username: str | None = None,
        password: str | None = None,
        mfa_code: str | None = None,
        secret: str | None = None,
    ) -> AuthContext:
        self.allowed_public_hosts = verified_public_hosts(target)
        if profile.auth_type == AuthType.NONE:
            return AuthContext(
                profile_id=profile.id,
                profile_name=profile.name,
                role_name=profile.role_name,
                session_metadata={"auth_type": AuthType.NONE},
            )
        if profile.auth_type == AuthType.OAUTH2_CLIENT_CREDENTIALS:
            return self._authenticate_oauth_client_credentials(
                profile, target, username, password, secret
            )
        if profile.auth_type in DIRECT_AUTH_TYPES:
            return self._authenticate_direct(profile, target, username, password, secret)
        if not profile.login_url:
            raise AuthenticationError("Perfil sem URL de login.")
        if not username and not profile.encrypted_username:
            raise AuthenticationError("Username is required for this authentication attempt.")
        if not password and not profile.encrypted_password:
            raise AuthenticationError("Password is required for this authentication attempt.")

        login_url = ensure_auth_url_in_target_scope(profile.login_url, target)
        resolved_username = username or self.vault.decrypt(profile.encrypted_username or "")
        resolved_password = password or self.vault.decrypt(profile.encrypted_password or "")
        body = self._render_body(profile, resolved_username, resolved_password)
        logger.info("[AUTH] Authenticating profile %s", profile.name)
        response = self._request(
            login_url,
            "POST",
            json_body=body if profile.body_encoding != "FORM" else None,
            form_body=self._form_body(body) if profile.body_encoding == "FORM" else None,
        )
        if not 200 <= response.status_code < 300:
            raise AuthenticationError("Authentication failed", response.status_code)

        if response.status_code == 202:
            response = self._complete_mfa(profile, target, response, mfa_code)

        headers: dict[str, str] = {}
        cookies: tuple[dict[str, object], ...] = ()
        if profile.auth_type == AuthType.BEARER_LOGIN:
            token = self._extract_token(response.body, profile.token_json_path or "token")
            header_name = profile.token_header_name or "Authorization"
            prefix = (profile.token_prefix or "Bearer").strip()
            headers[header_name] = f"{prefix} {token}".strip()
        elif profile.auth_type in {AuthType.COOKIE_LOGIN, AuthType.FORM_LOGIN}:
            if not response.cookies:
                raise AuthenticationError("Login não retornou cookie de sessão.")
            cookies = response.browser_cookies
        else:
            raise AuthenticationError("Tipo de autenticação ainda não suportado.")

        validation_url = ensure_auth_url_in_target_scope(
            profile.validation_url or target.api_url or target.base_url, target
        )
        validation = self._request(
            validation_url,
            "GET",
            headers=headers,
            cookies=(
                response.cookies
                if profile.auth_type in {AuthType.COOKIE_LOGIN, AuthType.FORM_LOGIN}
                else None
            ),
        )
        if not 200 <= validation.status_code < 400:
            raise AuthenticationError("Authentication validation failed", validation.status_code)
        if profile.role_json_path:
            observed_role = self._extract_json_value(validation.body, profile.role_json_path)
            if observed_role != profile.role_name:
                raise AuthenticationError(
                    "Authenticated role does not match the configured role.",
                    validation.status_code,
                    "ROLE_MISMATCH",
                )
        logger.info("[AUTH] Authentication successful profile_id=%s", profile.id)
        return AuthContext(
            headers=headers,
            cookies=cookies,
            profile_id=profile.id,
            profile_name=profile.name,
            role_name=profile.role_name,
            session_metadata={"auth_type": profile.auth_type.value},
        )

    def _authenticate_direct(
        self,
        profile: AuthProfile,
        target: Target,
        username: str | None,
        password: str | None,
        secret: str | None,
    ) -> AuthContext:
        resolved_username = username
        if resolved_username is None and profile.encrypted_username:
            resolved_username = self.vault.decrypt(profile.encrypted_username)
        headers: dict[str, str]
        if profile.auth_type == AuthType.BASIC:
            if not resolved_username or not password:
                raise AuthenticationError("Username and password are required for Basic Auth.")
            encoded = b64encode(f"{resolved_username}:{password}".encode()).decode("ascii")
            headers = {"Authorization": f"Basic {encoded}"}
        else:
            template = profile.header_template or {}
            requires_secret = any(
                isinstance(value, str) and "{{secret}}" in value for value in template.values()
            )
            if requires_secret and not secret:
                raise AuthenticationError("Secret is required for this authentication attempt.")
            headers = self._render_headers(
                template,
                username=resolved_username or "",
                password=password or "",
                secret=secret or "",
            )
        validation_url = ensure_auth_url_in_target_scope(
            profile.validation_url or target.api_url or target.base_url, target
        )
        validation = self._request(validation_url, "GET", headers=headers)
        if not 200 <= validation.status_code < 400:
            raise AuthenticationError("Authentication validation failed", validation.status_code)
        if profile.role_json_path:
            observed_role = self._extract_json_value(validation.body, profile.role_json_path)
            if observed_role != profile.role_name:
                raise AuthenticationError(
                    "Authenticated role does not match the configured role.",
                    validation.status_code,
                    "ROLE_MISMATCH",
                )
        return AuthContext(
            headers=headers,
            profile_id=profile.id,
            profile_name=profile.name,
            role_name=profile.role_name,
            session_metadata={"auth_type": profile.auth_type.value},
        )

    def _authenticate_oauth_client_credentials(
        self,
        profile: AuthProfile,
        target: Target,
        client_id: str | None,
        password: str | None,
        secret: str | None,
    ) -> AuthContext:
        resolved_client_id = client_id
        if resolved_client_id is None and profile.encrypted_username:
            resolved_client_id = self.vault.decrypt(profile.encrypted_username)
        client_secret = secret or password
        if not resolved_client_id or not client_secret:
            raise AuthenticationError("Client ID and client secret are required for OAuth.")

        token_url = profile.login_url
        if profile.oidc_discovery_url:
            discovery_url = ensure_auth_url_in_target_scope(profile.oidc_discovery_url, target)
            discovery = self._request(discovery_url, "GET")
            if not 200 <= discovery.status_code < 300:
                raise AuthenticationError(
                    "OIDC discovery failed.", discovery.status_code, "OIDC_DISCOVERY_FAILED"
                )
            discovered = self._extract_json_value(discovery.body, "token_endpoint")
            if not isinstance(discovered, str) or not discovered:
                raise AuthenticationError(
                    "OIDC discovery did not provide a token endpoint.",
                    discovery.status_code,
                    "OIDC_CONFIGURATION_ERROR",
                )
            token_url = ensure_auth_url_in_target_scope(discovered, target)
        if not token_url:
            raise AuthenticationError("OAuth token endpoint is not configured.")
        token_url = ensure_auth_url_in_target_scope(token_url, target)

        form_body = {"grant_type": "client_credentials"}
        if profile.oauth_scopes:
            form_body["scope"] = " ".join(profile.oauth_scopes)
        if profile.oauth_audience:
            form_body["audience"] = profile.oauth_audience
        encoded_client_id = quote(resolved_client_id, safe="")
        encoded_client_secret = quote(client_secret, safe="")
        encoded = b64encode(f"{encoded_client_id}:{encoded_client_secret}".encode()).decode("ascii")
        token_response = self._request(
            token_url,
            "POST",
            headers={"Authorization": f"Basic {encoded}"},
            form_body=form_body,
        )
        if not 200 <= token_response.status_code < 300:
            raise AuthenticationError("OAuth token request failed.", token_response.status_code)
        token = self._extract_token(token_response.body, profile.token_json_path or "access_token")
        try:
            token_type = self._extract_json_value(token_response.body, "token_type")
        except AuthenticationError:
            token_type = None
        prefix = (
            token_type
            if isinstance(token_type, str) and token_type.strip()
            else profile.token_prefix or "Bearer"
        )
        if not isinstance(prefix, str) or not re.fullmatch(
            r"[A-Za-z][A-Za-z0-9._-]{0,63}", prefix.strip()
        ):
            raise AuthenticationError("OAuth token type is invalid.")
        header_name = profile.token_header_name or "Authorization"
        headers = {header_name: f"{prefix.strip()} {token}"}

        validation_url = ensure_auth_url_in_target_scope(
            profile.validation_url or target.api_url or target.base_url, target
        )
        validation = self._request(validation_url, "GET", headers=headers)
        if not 200 <= validation.status_code < 400:
            raise AuthenticationError("Authentication validation failed", validation.status_code)
        if profile.role_json_path:
            observed_role = self._extract_json_value(validation.body, profile.role_json_path)
            if observed_role != profile.role_name:
                raise AuthenticationError(
                    "Authenticated role does not match the configured role.",
                    validation.status_code,
                    "ROLE_MISMATCH",
                )
        return AuthContext(
            headers=headers,
            profile_id=profile.id,
            profile_name=profile.name,
            role_name=profile.role_name,
            session_metadata={"auth_type": profile.auth_type.value},
        )

    def _complete_mfa(
        self,
        profile: AuthProfile,
        target: Target,
        response: SafeResponse,
        mfa_code: str | None,
    ) -> SafeResponse:
        try:
            payload = json.loads(response.body)
        except json.JSONDecodeError as exc:
            raise AuthenticationError(
                "Additional authentication step could not be interpreted.",
                response.status_code,
                "MFA_CONFIGURATION_ERROR",
            ) from exc
        if isinstance(payload, dict) and payload.get("mfa_enrollment_required") is True:
            raise AuthenticationError(
                "MFA enrollment must be completed manually in the target application.",
                response.status_code,
                "MFA_ENROLLMENT_REQUIRED",
            )
        if not profile.mfa_url or not all(
            (
                profile.mfa_challenge_json_path,
                profile.mfa_challenge_field,
                profile.mfa_code_field,
            )
        ):
            raise AuthenticationError(
                "Auth Profile requires an MFA step configuration.",
                response.status_code,
                "MFA_CONFIGURATION_REQUIRED",
            )
        if not mfa_code:
            raise AuthenticationError(
                "MFA code required for this authentication attempt.",
                response.status_code,
                "MFA_REQUIRED",
            )
        challenge_path = profile.mfa_challenge_json_path
        challenge_field = profile.mfa_challenge_field
        code_field = profile.mfa_code_field
        assert challenge_path is not None
        assert challenge_field is not None
        assert code_field is not None
        challenge = self._extract_json_value(response.body, challenge_path)
        if not isinstance(challenge, str) or not challenge:
            raise AuthenticationError(
                "MFA challenge was not found.",
                response.status_code,
                "MFA_CONFIGURATION_ERROR",
            )
        mfa_url = ensure_auth_url_in_target_scope(profile.mfa_url, target)
        verified = self._request(
            mfa_url,
            "POST",
            json_body={
                challenge_field: challenge,
                code_field: mfa_code,
            },
            cookies=response.cookies or None,
        )
        if not 200 <= verified.status_code < 300:
            raise AuthenticationError(
                "MFA verification failed.", verified.status_code, "MFA_FAILED"
            )
        return verified

    @staticmethod
    def _render_body(profile: AuthProfile, username: str, password: str) -> dict[str, object]:
        template = profile.body_template
        if template is None:
            if not profile.username_field or not profile.password_field:
                raise AuthenticationError("Configure o template ou os campos de credencial.")
            template = {
                profile.username_field: "{{username}}",
                profile.password_field: "{{password}}",
            }

        def replace(value: object) -> object:
            if isinstance(value, str):
                return value.replace("{{username}}", username).replace("{{password}}", password)
            if isinstance(value, dict):
                return {str(key): replace(item) for key, item in value.items()}
            if isinstance(value, list):
                return [replace(item) for item in value]
            return value

        rendered = replace(template)
        if not isinstance(rendered, dict):
            raise AuthenticationError("O body template deve ser um objeto JSON.")
        return rendered

    @staticmethod
    def _form_body(body: dict[str, object]) -> dict[str, str]:
        if not all(isinstance(value, (str, int, float, bool)) for value in body.values()):
            raise AuthenticationError("Login por formulário aceita somente campos simples.")
        return {name: str(value) for name, value in body.items()}

    @staticmethod
    def _render_headers(
        template: dict[str, object], *, username: str, password: str, secret: str
    ) -> dict[str, str]:
        headers: dict[str, str] = {}
        for raw_name, raw_value in template.items():
            name = str(raw_name).strip()
            if not isinstance(raw_value, str):
                raise AuthenticationError("Valores de headers personalizados devem ser texto.")
            value = (
                raw_value.replace("{{username}}", username)
                .replace("{{password}}", password)
                .replace("{{secret}}", secret)
            )
            if not name or any(character in name for character in "\r\n:"):
                raise AuthenticationError("Nome de header personalizado inválido.")
            if any(character in value for character in "\r\n") or len(value) > 16384:
                raise AuthenticationError("Valor de header personalizado inválido.")
            headers[name] = value
        return headers

    @staticmethod
    def _extract_token(body: bytes, path: str) -> str:
        current = Authenticator._extract_json_value(body, path)
        if not isinstance(current, str) or not current or len(current) > 16384:
            raise AuthenticationError("Token de autenticação inválido.")
        return current

    @staticmethod
    def _extract_json_value(body: bytes, path: str) -> object:
        try:
            current: Any = json.loads(body)
            for segment in path.split("."):
                current = current[int(segment)] if isinstance(current, list) else current[segment]
        except (json.JSONDecodeError, KeyError, IndexError, TypeError, ValueError) as exc:
            raise AuthenticationError("Configured JSON path was not found.") from exc
        return current

    def _request(
        self,
        raw_url: str,
        method: str,
        *,
        json_body: dict[str, object] | None = None,
        form_body: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
    ) -> SafeResponse:
        validated = validate_target(raw_url, self.allowed_public_hosts)
        last_error: httpx.ConnectError | None = None
        for address in validated.addresses:
            try:
                with httpx.Client(
                    timeout=self.settings.scan_timeout_seconds,
                    follow_redirects=False,
                    trust_env=False,
                    verify=True,
                    limits=httpx.Limits(max_connections=1, max_keepalive_connections=0),
                ) as client:
                    request_headers = {
                        "Host": validated.url.netloc.decode("ascii"),
                        "User-Agent": f"DAST/{__version__} (controlled authentication)",
                        "Accept": "application/json, text/html;q=0.8",
                        **(headers or {}),
                    }
                    with client.stream(
                        method,
                        validated.url.copy_with(host=address),
                        headers=request_headers,
                        json=json_body,
                        data=form_body,
                        cookies=cookies,
                        extensions={"sni_hostname": validated.url.host},
                    ) as response:
                        chunks: list[bytes] = []
                        size = 0
                        for chunk in response.iter_bytes():
                            size += len(chunk)
                            if size > self.settings.sensitive_body_max_bytes:
                                raise AuthenticationError(
                                    "Resposta de autenticação excedeu o limite."
                                )
                            chunks.append(chunk)
                        return SafeResponse(
                            status_code=response.status_code,
                            headers=httpx.Headers(response.headers),
                            body=b"".join(chunks),
                            cookies=dict(response.cookies),
                            browser_cookies=self._browser_cookies(response.headers, validated.url),
                        )
            except httpx.ConnectError as exc:
                last_error = exc
        if last_error:
            raise AuthenticationError(
                "Não foi possível conectar ao serviço de autenticação."
            ) from last_error
        raise AuthenticationError("Falha ao autenticar.")

    @staticmethod
    def _browser_cookies(
        headers: httpx.Headers, logical_url: httpx.URL
    ) -> tuple[dict[str, object], ...]:
        """Preserve non-secret cookie scope for the isolated Playwright context."""
        parsed: list[dict[str, object]] = []
        for raw_header in headers.get_list("set-cookie"):
            jar = SimpleCookie()
            jar.load(raw_header)
            for name, morsel in jar.items():
                same_site = morsel["samesite"].capitalize() or "Lax"
                if same_site not in {"Strict", "Lax", "None"}:
                    same_site = "Lax"
                parsed.append(
                    {
                        "name": name,
                        "value": morsel.value,
                        "domain": morsel["domain"] or logical_url.host,
                        "path": morsel["path"] or "/",
                        "httpOnly": bool(morsel["httponly"]),
                        "secure": bool(morsel["secure"]),
                        "sameSite": same_site,
                    }
                )
        return tuple(parsed)
