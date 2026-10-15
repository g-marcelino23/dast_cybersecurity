import json

from pydantic import SecretStr
from sqlalchemy.orm import Session

from app.core.secrets import CredentialVault
from app.core.target_policy import TargetPolicyError
from app.crawler.normalizer import normalize_url
from app.models import AuthProfile, Target
from app.models.entities import utcnow
from app.models.enums import AuthType
from app.schemas.entities import AuthProfileCreate, AuthProfileUpdate
from app.services.authentication import (
    AuthenticationError,
    ensure_auth_url_in_target_scope,
    ephemeral_auth_sessions,
)


class AuthProfileError(ValueError):
    pass


LOGIN_AUTH_TYPES = {AuthType.BEARER_LOGIN, AuthType.COOKIE_LOGIN, AuthType.FORM_LOGIN}
DIRECT_AUTH_TYPES = {
    AuthType.BASIC,
    AuthType.BEARER_TOKEN,
    AuthType.API_KEY,
    AuthType.CUSTOM_HEADERS,
}
RESERVED_HEADERS = {"host", "content-length", "transfer-encoding", "connection"}
SENSITIVE_HEADER_NAMES = {"authorization", "cookie", "x-api-key", "api-key"}


def _secret_value(value: SecretStr | None) -> str | None:
    return value.get_secret_value() if value else None


class AuthProfileService:
    def __init__(self, db: Session, vault: CredentialVault | None = None) -> None:
        self.db = db
        self.vault = vault or CredentialVault.from_settings()

    def create(self, target: Target, payload: AuthProfileCreate) -> AuthProfile:
        data = payload.model_dump(exclude={"username", "password"})
        username = _secret_value(payload.username)
        profile = AuthProfile(target_id=target.id, **data)
        if username:
            profile.encrypted_username = self.vault.encrypt(username)
        # Passwords are accepted only for backward-compatible clients and discarded.
        profile.encrypted_password = None
        self._normalize_and_validate(profile, target)
        self.db.add(profile)
        self.db.commit()
        self.db.refresh(profile)
        return profile

    def update(
        self, profile: AuthProfile, target: Target, payload: AuthProfileUpdate
    ) -> AuthProfile:
        ephemeral_auth_sessions.discard(profile.id)
        changes = payload.model_dump(exclude_unset=True, exclude={"username", "password"})
        for name, value in changes.items():
            setattr(profile, name, value)
        username = (
            _secret_value(payload.username) if "username" in payload.model_fields_set else None
        )
        if username:
            profile.encrypted_username = self.vault.encrypt(username)
        profile.encrypted_password = None
        profile.updated_at = utcnow()
        self._normalize_and_validate(profile, target)
        self.db.commit()
        self.db.refresh(profile)
        return profile

    @staticmethod
    def _normalize_and_validate(profile: AuthProfile, target: Target) -> None:
        if profile.auth_type == AuthType.NONE:
            profile.login_url = None
            profile.validation_url = None
            profile.mfa_url = None
            profile.mfa_challenge_json_path = None
            profile.mfa_challenge_field = None
            profile.mfa_code_field = None
            profile.role_json_path = None
            profile.encrypted_username = None
            profile.encrypted_password = None
            profile.body_template = None
            profile.header_template = None
            return
        if profile.auth_type in DIRECT_AUTH_TYPES:
            AuthProfileService._normalize_direct(profile, target)
            return
        if profile.auth_type not in LOGIN_AUTH_TYPES or not profile.login_url:
            raise AuthProfileError("Informe a URL de login.")
        try:
            profile.login_url = ensure_auth_url_in_target_scope(profile.login_url, target)
            if profile.validation_url:
                profile.validation_url = ensure_auth_url_in_target_scope(
                    profile.validation_url, target
                )
            if profile.mfa_url:
                profile.mfa_url = ensure_auth_url_in_target_scope(profile.mfa_url, target)
        except (AuthenticationError, TargetPolicyError) as exc:
            raise AuthProfileError(str(exc)) from exc
        if not profile.credentials_configured:
            raise AuthProfileError("Informe o username da conta sintética.")
        if profile.http_method != "POST":
            raise AuthProfileError("Esta versão permite somente login por POST.")
        profile.body_encoding = "FORM" if profile.auth_type == AuthType.FORM_LOGIN else "JSON"
        profile.header_template = None
        if profile.body_template is not None:
            template = json.dumps(profile.body_template, ensure_ascii=False)
            if "{{username}}" not in template or "{{password}}" not in template:
                raise AuthProfileError(
                    "O template deve usar {{username}} e {{password}}; não grave credenciais nele."
                )
        elif not profile.username_field or not profile.password_field:
            raise AuthProfileError("Configure o template ou os campos de username e password.")
        if profile.auth_type == AuthType.BEARER_LOGIN:
            if not profile.token_json_path or not profile.token_header_name:
                raise AuthProfileError("Configure o caminho do token e o header.")
            if any(character in profile.token_header_name for character in "\r\n:"):
                raise AuthProfileError("Nome de header inválido.")
        if profile.mfa_url and not all(
            (
                profile.mfa_challenge_json_path,
                profile.mfa_challenge_field,
                profile.mfa_code_field,
            )
        ):
            raise AuthProfileError("Configure todos os campos do segundo passo MFA.")
        normalize_url(profile.login_url)

    @staticmethod
    def _normalize_direct(profile: AuthProfile, target: Target) -> None:
        profile.login_url = None
        profile.body_template = None
        profile.body_encoding = "JSON"
        profile.mfa_url = None
        profile.mfa_challenge_json_path = None
        profile.mfa_challenge_field = None
        profile.mfa_code_field = None
        profile.token_json_path = None
        profile.username_field = None
        profile.password_field = None
        profile.token_header_name = None
        profile.token_prefix = None
        if profile.validation_url:
            try:
                profile.validation_url = ensure_auth_url_in_target_scope(
                    profile.validation_url, target
                )
            except (AuthenticationError, TargetPolicyError) as exc:
                raise AuthProfileError(str(exc)) from exc
        if profile.auth_type == AuthType.BASIC:
            if not profile.encrypted_username:
                raise AuthProfileError("Informe o username para Basic Auth.")
            profile.header_template = None
            return
        profile.encrypted_username = None
        if profile.auth_type == AuthType.BEARER_TOKEN and not profile.header_template:
            profile.header_template = {"Authorization": "Bearer {{secret}}"}
        if not profile.header_template:
            raise AuthProfileError("Configure ao menos um header.")
        for name, value in profile.header_template.items():
            clean_name = name.strip()
            if (
                not clean_name
                or len(clean_name) > 128
                or any(character in clean_name for character in "\r\n:")
                or clean_name.casefold() in RESERVED_HEADERS
            ):
                raise AuthProfileError("Nome de header personalizado inválido ou reservado.")
            if not isinstance(value, str) or len(value) > 16384 or any(
                character in value for character in "\r\n"
            ):
                raise AuthProfileError("Valor de header personalizado inválido.")
            if (
                clean_name.casefold() in SENSITIVE_HEADER_NAMES
                and "{{secret}}" not in value
                and "{{password}}" not in value
            ):
                raise AuthProfileError(
                    "Headers sensíveis devem usar {{secret}} ou {{password}}; "
                    "não grave credenciais no template."
                )
