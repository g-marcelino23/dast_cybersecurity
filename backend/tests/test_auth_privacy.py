import json
from base64 import b64encode
from dataclasses import asdict

import httpx
import pytest
from cryptography.fernet import Fernet

from app.core.config import Settings
from app.core.secrets import CredentialVault, SecretStoreError
from app.crawler.browser import AuthContext, BrowserSession
from app.crawler.crawler import DiscoveryCrawler
from app.crawler.scope import CrawlerScope
from app.models import AuthProfile, Target
from app.models.enums import (
    AuthType,
    Confidence,
    DetectorType,
    ResourceType,
    SensitiveDataCategory,
)
from app.privacy import SensitiveDataDetector
from app.scanner.base import ResponseSnapshot
from app.services.authentication import (
    AuthenticationError,
    Authenticator,
    SafeResponse,
    ephemeral_auth_sessions,
)
from tests.fixtures.auth_site import (
    PATIENT_EMAIL,
    PATIENT_MFA_CODE,
    PATIENT_PASSWORD,
    PATIENT_TOKEN,
    authenticated_site,
    mfa_cookie_site,
)


def settings(key: str) -> Settings:
    return Settings(
        database_url="sqlite://",
        dast_secret_key=key,
        crawler_max_depth=1,
        crawler_max_pages=5,
        crawler_max_requests=30,
        crawler_timeout_seconds=5,
        crawler_wait_after_load_ms=150,
    )


def profile_for(
    api_url: str,
    vault: CredentialVault,
    *,
    password: str = PATIENT_PASSWORD,
    profile_id: int = 1,
) -> AuthProfile:
    return AuthProfile(
        id=profile_id,
        target_id=1,
        name=f"Paciente {profile_id}",
        role_name="PACIENTE",
        auth_type=AuthType.BEARER_LOGIN,
        login_url=f"{api_url}/auth/login",
        validation_url=f"{api_url}/api/me",
        http_method="POST",
        body_template={"email": "{{username}}", "senha": "{{password}}"},
        token_json_path="session.access_token",
        token_header_name="Authorization",
        token_prefix="Bearer",
        encrypted_username=vault.encrypt(PATIENT_EMAIL),
        encrypted_password=vault.encrypt(password),
    )


def profile_payload(api_url: str, password: str = PATIENT_PASSWORD) -> dict[str, object]:
    return {
        "name": "Paciente A",
        "role_name": "PACIENTE",
        "auth_type": "BEARER_LOGIN",
        "login_url": f"{api_url}/auth/login",
        "validation_url": f"{api_url}/api/me",
        "http_method": "POST",
        "body_template": {"email": "{{username}}", "senha": "{{password}}"},
        "username_field": "email",
        "password_field": "senha",
        "token_json_path": "session.access_token",
        "token_header_name": "Authorization",
        "token_prefix": "Bearer",
        "username": PATIENT_EMAIL,
        "password": password,
    }


def mfa_cookie_profile(api_url: str, vault: CredentialVault) -> AuthProfile:
    return AuthProfile(
        id=41,
        target_id=1,
        name="Paciente MFA",
        role_name="PACIENTE",
        auth_type=AuthType.COOKIE_LOGIN,
        login_url=f"{api_url}/auth/login",
        validation_url=f"{api_url}/auth/me",
        http_method="POST",
        body_template={"email": "{{username}}", "senha": "{{password}}"},
        mfa_url=f"{api_url}/auth/mfa/verify",
        mfa_challenge_json_path="challenge_id",
        mfa_challenge_field="challenge_id",
        mfa_code_field="codigo",
        role_json_path="usuario.perfil",
        encrypted_username=vault.encrypt(PATIENT_EMAIL),
        encrypted_password=vault.encrypt(PATIENT_PASSWORD),
    )


def create_mfa_cookie_profile(
    client, api_url: str, *, role_name: str = "PACIENTE"
) -> dict[str, object]:
    target = client.post(
        "/targets", json={"name": "MFA", "base_url": api_url, "api_url": api_url}
    ).json()
    response = client.post(
        f"/targets/{target['id']}/auth-profiles",
        json={
            "name": f"{role_name} MFA",
            "role_name": role_name,
            "auth_type": "COOKIE_LOGIN",
            "login_url": f"{api_url}/auth/login",
            "validation_url": f"{api_url}/auth/me",
            "http_method": "POST",
            "body_template": {"email": "{{username}}", "senha": "{{password}}"},
            "username_field": "email",
            "password_field": "senha",
            "mfa_url": f"{api_url}/auth/mfa/verify",
            "mfa_challenge_json_path": "challenge_id",
            "mfa_challenge_field": "challenge_id",
            "mfa_code_field": "codigo",
            "role_json_path": "usuario.perfil",
            "username": PATIENT_EMAIL,
        },
    )
    assert response.status_code == 201
    profile = response.json()
    ephemeral_auth_sessions.discard(int(profile["id"]))
    return profile


def test_credential_vault_encrypts_and_decrypts_without_plaintext() -> None:
    vault = CredentialVault(Fernet.generate_key().decode("ascii"))
    ciphertext = vault.encrypt("never-store-this-password")
    assert ciphertext != "never-store-this-password"
    assert "never-store-this-password" not in ciphertext
    assert vault.decrypt(ciphertext) == "never-store-this-password"
    with pytest.raises(SecretStoreError):
        CredentialVault(Fernet.generate_key().decode("ascii")).decrypt(ciphertext)


def test_auth_profile_api_never_returns_password_or_ciphertext(client) -> None:
    with authenticated_site() as (web_url, api_url, _state):
        target = client.post(
            "/targets", json={"name": "Auth", "base_url": web_url, "api_url": api_url}
        ).json()
        created = client.post(
            f"/targets/{target['id']}/auth-profiles", json=profile_payload(api_url)
        )
        assert created.status_code == 201
        profile = created.json()
        assert profile["credentials_configured"] is True
        for response in (
            created,
            client.get(f"/auth-profiles/{profile['id']}"),
            client.get(f"/targets/{target['id']}/auth-profiles"),
        ):
            serialized = response.text
            assert PATIENT_PASSWORD not in serialized
            assert PATIENT_EMAIL not in serialized
            assert "encrypted_password" not in serialized
            assert "ciphertext" not in serialized


def test_bearer_authentication_and_token_extraction() -> None:
    key = Fernet.generate_key().decode("ascii")
    vault = CredentialVault(key)
    with authenticated_site() as (web_url, api_url, state):
        target = Target(id=1, name="Auth", base_url=web_url, api_url=api_url)
        context = Authenticator(vault, settings(key)).authenticate(
            profile_for(api_url, vault), target
        )
        assert context.headers == {"Authorization": f"Bearer {PATIENT_TOKEN}"}
        assert context.profile_name == "Paciente 1"
        assert context.role_name == "PACIENTE"
        assert context.authenticated is True
        assert state.login_attempts == 1
        assert state.authenticated_requests == 1


@pytest.mark.parametrize(
    ("auth_type", "header_template", "secret", "expected_headers"),
    [
        (
            AuthType.BEARER_TOKEN,
            {"Authorization": "Bearer {{secret}}"},
            "temporary-token",
            {"Authorization": "Bearer temporary-token"},
        ),
        (
            AuthType.API_KEY,
            {"X-API-Key": "{{secret}}"},
            "temporary-api-key",
            {"X-API-Key": "temporary-api-key"},
        ),
        (
            AuthType.CUSTOM_HEADERS,
            {"Authorization": "Token {{secret}}", "X-Tenant": "laboratorio"},
            "temporary-custom-secret",
            {
                "Authorization": "Token temporary-custom-secret",
                "X-Tenant": "laboratorio",
            },
        ),
    ],
)
def test_direct_secret_authentication_builds_ephemeral_headers(
    monkeypatch: pytest.MonkeyPatch,
    auth_type: AuthType,
    header_template: dict[str, str],
    secret: str,
    expected_headers: dict[str, str],
) -> None:
    key = Fernet.generate_key().decode("ascii")
    authenticator = Authenticator(CredentialVault(key), settings(key))
    requests: list[tuple[str, str, dict[str, object]]] = []

    def fake_request(raw_url: str, method: str, **kwargs: object) -> SafeResponse:
        requests.append((raw_url, method, kwargs))
        return SafeResponse(200, httpx.Headers(), b"{}", {})

    monkeypatch.setattr(authenticator, "_request", fake_request)
    profile = AuthProfile(
        id=70,
        target_id=1,
        name="Acesso direto",
        role_name="TESTER",
        auth_type=auth_type,
        validation_url="http://127.0.0.1:8765/api/me",
        header_template=header_template,
    )
    target = Target(
        id=1,
        name="Aplicação",
        base_url="http://127.0.0.1:8765",
        api_url="http://127.0.0.1:8765",
    )

    context = authenticator.authenticate(profile, target, secret=secret)

    assert context.headers == expected_headers
    assert requests == [
        (
            "http://127.0.0.1:8765/api/me",
            "GET",
            {"headers": expected_headers},
        )
    ]
    assert secret not in json.dumps(context.session_metadata)


def test_basic_authentication_uses_ephemeral_password(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = Fernet.generate_key().decode("ascii")
    vault = CredentialVault(key)
    authenticator = Authenticator(vault, settings(key))
    observed_headers: dict[str, str] = {}

    def fake_request(_raw_url: str, _method: str, **kwargs: object) -> SafeResponse:
        observed_headers.update(kwargs["headers"])  # type: ignore[arg-type]
        return SafeResponse(204, httpx.Headers(), b"", {})

    monkeypatch.setattr(authenticator, "_request", fake_request)
    profile = AuthProfile(
        id=71,
        target_id=1,
        name="Basic",
        role_name="ADMIN",
        auth_type=AuthType.BASIC,
        encrypted_username=vault.encrypt("synthetic-user"),
    )
    target = Target(id=1, name="App", base_url="http://127.0.0.1:8765")

    context = authenticator.authenticate(profile, target, password="one-use-password")

    encoded = b64encode(b"synthetic-user:one-use-password").decode("ascii")
    assert observed_headers == {"Authorization": f"Basic {encoded}"}
    assert context.headers == observed_headers
    assert "one-use-password" not in json.dumps(context.session_metadata)


def test_form_login_sends_urlencoded_fields_and_keeps_cookie_ephemeral(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = Fernet.generate_key().decode("ascii")
    vault = CredentialVault(key)
    authenticator = Authenticator(vault, settings(key))
    requests: list[tuple[str, str, dict[str, object]]] = []

    def fake_request(raw_url: str, method: str, **kwargs: object) -> SafeResponse:
        requests.append((raw_url, method, kwargs))
        if method == "POST":
            return SafeResponse(
                200,
                httpx.Headers(),
                b"{}",
                {"session": "temporary-cookie"},
                ({"name": "session", "value": "temporary-cookie", "path": "/"},),
            )
        return SafeResponse(200, httpx.Headers(), b"{}", {})

    monkeypatch.setattr(authenticator, "_request", fake_request)
    profile = AuthProfile(
        id=72,
        target_id=1,
        name="Form login",
        role_name="USER",
        auth_type=AuthType.FORM_LOGIN,
        login_url="http://127.0.0.1:8765/login",
        validation_url="http://127.0.0.1:8765/me",
        body_encoding="FORM",
        body_template={"email": "{{username}}", "password": "{{password}}"},
        encrypted_username=vault.encrypt("user@example.invalid"),
    )
    target = Target(id=1, name="App", base_url="http://127.0.0.1:8765")

    context = authenticator.authenticate(profile, target, password="temporary-password")

    assert requests[0][2]["json_body"] is None
    assert requests[0][2]["form_body"] == {
        "email": "user@example.invalid",
        "password": "temporary-password",
    }
    assert requests[1][2]["cookies"] == {"session": "temporary-cookie"}
    assert context.cookies[0]["value"] == "temporary-cookie"
    assert "temporary-password" not in json.dumps(context.session_metadata)


def test_direct_auth_profile_api_stores_only_secret_placeholder(client) -> None:
    target = client.post(
        "/targets",
        json={"name": "API", "base_url": "http://127.0.0.1:8765"},
    ).json()
    created = client.post(
        f"/targets/{target['id']}/auth-profiles",
        json={
            "name": "Token externo",
            "role_name": "SERVICE",
            "auth_type": "BEARER_TOKEN",
        },
    )

    assert created.status_code == 201
    assert created.json()["header_template"] == {"Authorization": "Bearer {{secret}}"}
    assert "temporary-token" not in created.text
    rejected = client.post(
        f"/targets/{target['id']}/auth-profiles",
        json={
            "name": "Token inválido",
            "role_name": "SERVICE",
            "auth_type": "BEARER_TOKEN",
            "secret": "temporary-token",
        },
    )
    assert rejected.status_code == 422
    assert "temporary-token" not in rejected.text


@pytest.mark.parametrize(
    "header_template",
    [
        {"Authorization": "literal-secret"},
        {"Host": "127.0.0.1"},
    ],
)
def test_custom_header_profile_rejects_persisted_secrets_and_reserved_headers(
    client, header_template: dict[str, str]
) -> None:
    target = client.post(
        "/targets",
        json={"name": "Headers", "base_url": "http://127.0.0.1:8765"},
    ).json()
    response = client.post(
        f"/targets/{target['id']}/auth-profiles",
        json={
            "name": "Headers inválidos",
            "role_name": "SERVICE",
            "auth_type": "CUSTOM_HEADERS",
            "header_template": header_template,
        },
    )

    assert response.status_code == 422


def test_failed_authentication_does_not_expose_reason_or_token(client) -> None:
    with authenticated_site() as (web_url, api_url, _state):
        target = client.post(
            "/targets", json={"name": "Auth", "base_url": web_url, "api_url": api_url}
        ).json()
        profile = client.post(
            f"/targets/{target['id']}/auth-profiles",
            json=profile_payload(api_url, "wrong-password"),
        ).json()
        result = client.post(
            f"/auth-profiles/{profile['id']}/test", json={"password": "wrong-password"}
        )
        assert result.json() == {
            "success": False,
            "status_code": 401,
            "message": "Authentication failed",
            "requires_mfa": False,
        }
        assert PATIENT_TOKEN not in result.text


def test_token_extraction_rejects_missing_path() -> None:
    body = json.dumps({"session": {"access_token": "temporary"}}).encode()
    assert Authenticator._extract_token(body, "session.access_token") == "temporary"
    with pytest.raises(AuthenticationError):
        Authenticator._extract_token(body, "token")


def test_cookie_authentication_requires_ephemeral_mfa_code() -> None:
    key = Fernet.generate_key().decode("ascii")
    vault = CredentialVault(key)
    with mfa_cookie_site() as (api_url, _state):
        target = Target(id=1, name="MFA", base_url=api_url, api_url=api_url)
        with pytest.raises(AuthenticationError) as caught:
            Authenticator(vault, settings(key)).authenticate(
                mfa_cookie_profile(api_url, vault), target
            )
    assert caught.value.code == "MFA_REQUIRED"
    assert caught.value.status_code == 202


def test_cookie_mfa_authentication_validates_role_and_keeps_session_ephemeral() -> None:
    key = Fernet.generate_key().decode("ascii")
    vault = CredentialVault(key)
    with mfa_cookie_site() as (api_url, state):
        target = Target(id=1, name="MFA", base_url=api_url, api_url=api_url)
        context = Authenticator(vault, settings(key)).authenticate(
            mfa_cookie_profile(api_url, vault), target, mfa_code=PATIENT_MFA_CODE
        )
    assert context.headers == {}
    assert context.cookies[0]["name"] == "clinicalmed_session"
    assert context.cookies[0]["path"] == "/"
    assert context.cookies[0]["httpOnly"] is True
    assert context.cookies[0]["sameSite"] == "Strict"
    assert context.cookies[0]["secure"] is False
    assert context.role_name == "PACIENTE"
    assert state.login_attempts == 1
    assert state.mfa_attempts == 1
    assert state.authenticated_requests == 1
    serialized_metadata = json.dumps(context.session_metadata)
    assert PATIENT_MFA_CODE not in serialized_metadata
    assert PATIENT_TOKEN not in serialized_metadata


def test_cookie_mfa_authentication_rejects_role_mismatch() -> None:
    key = Fernet.generate_key().decode("ascii")
    vault = CredentialVault(key)
    with mfa_cookie_site() as (api_url, _state):
        target = Target(id=1, name="MFA", base_url=api_url, api_url=api_url)
        profile = mfa_cookie_profile(api_url, vault)
        profile.role_name = "MEDICO"
        with pytest.raises(AuthenticationError) as caught:
            Authenticator(vault, settings(key)).authenticate(
                profile, target, mfa_code=PATIENT_MFA_CODE
            )
    assert caught.value.code == "ROLE_MISMATCH"


def test_auth_profile_api_uses_mfa_code_only_for_current_validation(client) -> None:
    with mfa_cookie_site() as (api_url, _state):
        target = client.post(
            "/targets", json={"name": "MFA", "base_url": api_url, "api_url": api_url}
        ).json()
        profile = client.post(
            f"/targets/{target['id']}/auth-profiles",
            json={
                "name": "Paciente MFA",
                "role_name": "PACIENTE",
                "auth_type": "COOKIE_LOGIN",
                "login_url": f"{api_url}/auth/login",
                "validation_url": f"{api_url}/auth/me",
                "http_method": "POST",
                "body_template": {"email": "{{username}}", "senha": "{{password}}"},
                "username_field": "email",
                "password_field": "senha",
                "mfa_url": f"{api_url}/auth/mfa/verify",
                "mfa_challenge_json_path": "challenge_id",
                "mfa_challenge_field": "challenge_id",
                "mfa_code_field": "codigo",
                "role_json_path": "usuario.perfil",
                "username": PATIENT_EMAIL,
                "password": PATIENT_PASSWORD,
            },
        ).json()
        pending = client.post(
            f"/auth-profiles/{profile['id']}/validation",
            json={"password": PATIENT_PASSWORD},
        )
        assert pending.json()["requires_mfa"] is True
        validated = client.post(
            f"/auth-profiles/{profile['id']}/validation",
            json={"password": PATIENT_PASSWORD, "mfa_code": PATIENT_MFA_CODE},
        )
        stored = client.get(f"/auth-profiles/{profile['id']}")
    assert validated.json()["session_initialized"] is True
    assert validated.json()["role_name"] == "PACIENTE"
    assert PATIENT_MFA_CODE not in validated.text
    assert PATIENT_MFA_CODE not in stored.text
    assert PATIENT_TOKEN not in validated.text
    assert PATIENT_TOKEN not in stored.text


def test_validation_without_retention_records_success_and_discards_session(client) -> None:
    with mfa_cookie_site() as (api_url, _state):
        profile = create_mfa_cookie_profile(client, api_url)
        response = client.post(
            f"/auth-profiles/{profile['id']}/validation",
            json={
                "password": PATIENT_PASSWORD,
                "mfa_code": PATIENT_MFA_CODE,
                "retain_session": False,
            },
        )
        stored = client.get(f"/auth-profiles/{profile['id']}").json()

    assert response.status_code == 200
    assert response.json()["success"] is True
    assert response.json()["session_initialized"] is False
    assert stored["last_auth_success"] is True
    assert stored["last_auth_status_code"] == 200
    assert not ephemeral_auth_sessions.contains(int(profile["id"]))
    assert PATIENT_PASSWORD not in response.text
    assert PATIENT_MFA_CODE not in response.text
    assert PATIENT_TOKEN not in response.text


def test_validation_with_retention_preserves_existing_ephemeral_behavior(client) -> None:
    with mfa_cookie_site() as (api_url, _state):
        profile = create_mfa_cookie_profile(client, api_url)
        response = client.post(
            f"/auth-profiles/{profile['id']}/validation",
            json={
                "password": PATIENT_PASSWORD,
                "mfa_code": PATIENT_MFA_CODE,
                "retain_session": True,
            },
        )

    try:
        assert response.status_code == 200
        assert response.json()["success"] is True
        assert ephemeral_auth_sessions.contains(int(profile["id"]))
    finally:
        ephemeral_auth_sessions.discard(int(profile["id"]))


def test_login_failure_without_retention_leaves_no_ephemeral_session(client) -> None:
    with mfa_cookie_site() as (api_url, _state):
        profile = create_mfa_cookie_profile(client, api_url)
        response = client.post(
            f"/auth-profiles/{profile['id']}/validation",
            json={"password": "invalid-synthetic-password", "retain_session": False},
        )

    assert response.json()["success"] is False
    assert not ephemeral_auth_sessions.contains(int(profile["id"]))


def test_mfa_failure_without_retention_leaves_no_ephemeral_session(client) -> None:
    with mfa_cookie_site() as (api_url, _state):
        profile = create_mfa_cookie_profile(client, api_url)
        response = client.post(
            f"/auth-profiles/{profile['id']}/validation",
            json={
                "password": PATIENT_PASSWORD,
                "mfa_code": "000000",
                "retain_session": False,
            },
        )

    assert response.json()["success"] is False
    assert not ephemeral_auth_sessions.contains(int(profile["id"]))


def test_role_mismatch_without_retention_leaves_no_ephemeral_session(client) -> None:
    with mfa_cookie_site() as (api_url, _state):
        profile = create_mfa_cookie_profile(client, api_url, role_name="MEDICO")
        response = client.post(
            f"/auth-profiles/{profile['id']}/validation",
            json={
                "password": PATIENT_PASSWORD,
                "mfa_code": PATIENT_MFA_CODE,
                "retain_session": False,
            },
        )

    assert response.json()["success"] is False
    assert not ephemeral_auth_sessions.contains(int(profile["id"]))


def test_auth_contexts_and_browser_sessions_are_isolated() -> None:
    scope = CrawlerScope.from_target("http://127.0.0.1:8765")
    first = AuthContext(headers={"Authorization": "Bearer first"}, profile_id=1)
    second = AuthContext(headers={"Authorization": "Bearer second"}, profile_id=2)
    with BrowserSession(scope, first).open() as (first_browser, _first_page):
        first_context_id = id(first_browser)
    with BrowserSession(scope, second).open() as (second_browser, _second_page):
        assert first_context_id != id(second_browser)
    assert first.headers != second.headers


def test_authenticated_crawler_discovers_protected_endpoints() -> None:
    key = Fernet.generate_key().decode("ascii")
    vault = CredentialVault(key)
    with authenticated_site() as (web_url, api_url, state):
        target = Target(id=1, name="Auth", base_url=web_url, api_url=api_url)
        auth = Authenticator(vault, settings(key)).authenticate(profile_for(api_url, vault), target)
        result = DiscoveryCrawler(settings(key)).crawl(web_url, api_url, auth)
    api_endpoints = {
        item.path: item for item in result.endpoints if item.resource_type == ResourceType.API
    }
    assert {
        "/api/me",
        "/api/patient/exams",
        "/api/patient/prescriptions",
    }.issubset(api_endpoints)
    assert all(api_endpoints[path].requires_auth is True for path in api_endpoints)
    assert state.authenticated_requests >= 4
    assert PATIENT_TOKEN not in json.dumps([item.__dict__ for item in result.endpoints])


def test_sensitive_detector_classifies_json_fields_and_patterns_without_values() -> None:
    body = json.dumps(
        {
            "patient": {
                "cpf": "111.444.777-35",
                "email": "synthetic@fixture.invalid",
                "diagnosis": "diagnóstico que não pode ser persistido",
                "exam_result": "resultado que não pode ser persistido",
            }
        }
    ).encode()
    response = ResponseSnapshot(
        "http://localhost/api/me",
        200,
        httpx.Headers({"Content-Type": "application/json"}),
        body=body,
    )
    observations = SensitiveDataDetector().analyze(response)
    categories = {item.category for item in observations}
    detectors = {item.detector_type for item in observations}
    assert SensitiveDataCategory.HEALTH_INFORMATION in categories
    assert SensitiveDataCategory.EXAM_RESULT in categories
    assert SensitiveDataCategory.PERSONAL_IDENTIFIER in categories
    assert DetectorType.CPF_PATTERN in detectors
    assert DetectorType.EMAIL_PATTERN in detectors
    assert any(
        item.field_path == "patient.diagnosis" and item.confidence == Confidence.HIGH
        for item in observations
    )
    serialized = json.dumps([asdict(item) for item in observations], default=str)
    assert "não pode ser persistido" not in serialized
    assert "111.444.777-35" not in serialized
    assert "synthetic@fixture.invalid" not in serialized


def test_invalid_cpf_does_not_create_pattern_observation() -> None:
    response = ResponseSnapshot(
        "http://localhost/api",
        200,
        httpx.Headers({"Content-Type": "application/json"}),
        body=b'{"reference": "111.111.111-11"}',
    )
    observations = SensitiveDataDetector().analyze(response)
    assert all(item.detector_type != DetectorType.CPF_PATTERN for item in observations)


def test_html_text_is_not_treated_as_structured_health_data() -> None:
    response = ResponseSnapshot(
        "http://localhost/",
        200,
        httpx.Headers({"Content-Type": "text/html"}),
        body=b"<p>Saiba mais sobre diagnosticos</p>",
    )
    assert SensitiveDataDetector().analyze(response) == []


def test_external_login_url_is_blocked(client) -> None:
    target = client.post(
        "/targets",
        json={
            "name": "Local",
            "base_url": "http://127.0.0.1:5173",
            "api_url": "http://127.0.0.1:3001",
        },
    ).json()
    payload = profile_payload("http://127.0.0.1:3001")
    payload["login_url"] = "https://8.8.8.8/auth/login"
    response = client.post(f"/targets/{target['id']}/auth-profiles", json=payload)
    assert response.status_code == 422


def test_authenticated_scan_persists_only_sanitized_observations_and_summary(client) -> None:
    with authenticated_site() as (web_url, api_url, _state):
        target = client.post(
            "/targets", json={"name": "Auth", "base_url": web_url, "api_url": api_url}
        ).json()
        profile = client.post(
            f"/targets/{target['id']}/auth-profiles", json=profile_payload(api_url)
        ).json()
        validation = client.post(
            f"/auth-profiles/{profile['id']}/validation",
            json={"password": PATIENT_PASSWORD},
        ).json()
        assert validation["session_initialized"] is True
        scan = client.post(
            "/scans",
            json={"target_id": target["id"], "auth_profile_id": profile["id"]},
        ).json()
        completed = client.post(f"/scans/{scan['id']}/run").json()
        assert completed["status"] == "COMPLETED"
        assert completed["auth_profile_id"] == profile["id"]
        assert not ephemeral_auth_sessions.contains(int(profile["id"]))
        observations = client.get(f"/scans/{scan['id']}/sensitive-data")
        summary = client.get(f"/scans/{scan['id']}/sensitive-data-summary").json()
    assert observations.status_code == 200
    assert summary["endpoints_with_sensitive_data"] == 3
    assert summary["health_endpoints"] == 2
    assert summary["authenticated_endpoints"] >= 3
    assert summary["categories_detected"] >= 5
    serialized = observations.text
    for forbidden in (
        PATIENT_EMAIL,
        PATIENT_TOKEN,
        "111.444.777-35",
        "Diagnóstico sintético",
        "Medicamento sintético Alpha",
    ):
        assert forbidden not in serialized
