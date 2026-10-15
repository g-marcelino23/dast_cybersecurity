from unittest.mock import patch

import httpx

from app.crawler.browser import AuthContext


def create_target(client, *, fixture: bool = False, tcc: bool = False) -> dict[str, object]:
    response = client.post(
        "/targets",
        json={
            "name": "Synthetic fixture" if fixture else "Clinical Med",
            "base_url": "http://localhost:5173",
            "api_url": "http://localhost:3001",
            "environment": "FIXTURE" if fixture else "LOCAL",
            "is_protected_target": tcc,
            "safe_scan_mode": True,
        },
    )
    assert response.status_code == 201
    return response.json()


def create_profile(client, target_id: int, name: str, role: str) -> dict[str, object]:
    response = client.post(
        f"/targets/{target_id}/auth-profiles",
        json={"name": name, "role_name": role, "auth_type": "NONE"},
    )
    assert response.status_code == 201
    return response.json()


def test_protected_target_cannot_disable_safe_scan_mode(client) -> None:
    response = client.post(
        "/targets",
        json={
            "name": "Clinical Med",
            "base_url": "http://localhost:5173",
            "is_protected_target": True,
            "safe_scan_mode": False,
        },
    )
    assert response.status_code == 422
    assert "Safe Scan Mode" in response.text


def test_health_response_exposes_machine_readable_unavailable_code(client) -> None:
    target = create_target(client, tcc=True)
    with patch(
        "app.scanner.client.SafeHttpCollector.fetch",
        side_effect=httpx.ConnectError("offline"),
    ):
        response = client.get(f"/targets/{target['id']}/health")
    assert response.status_code == 200
    assert response.json()["code"] == "TARGET_UNAVAILABLE"


def test_fixture_and_real_tcc_target_are_explicitly_separate(client) -> None:
    response = client.post(
        "/targets",
        json={
            "name": "Not allowed",
            "base_url": "http://localhost:5173",
            "environment": "FIXTURE",
            "is_protected_target": True,
        },
    )
    assert response.status_code == 422
    fixture = create_target(client, fixture=True)
    assert fixture["environment"] == "FIXTURE"
    assert fixture["is_protected_target"] is False


def test_tcc_authenticated_scan_requires_validated_profile(client) -> None:
    target = create_target(client, tcc=True)
    profile = create_profile(client, int(target["id"]), "Médico A", "MEDICO")
    denied = client.post(
        "/scans",
        json={"target_id": target["id"], "auth_profile_id": profile["id"]},
    )
    assert denied.status_code == 422
    assert "Valide a autenticação" in denied.text


def test_authentication_validation_records_safe_status_only(client) -> None:
    target = create_target(client)
    profile = create_profile(client, int(target["id"]), "Médico A", "MEDICO")
    response = client.post(f"/auth-profiles/{profile['id']}/validation")
    assert response.status_code == 200
    assert response.json() == {
        "success": True,
        "status_code": 200,
        "role_name": "MEDICO",
        "session_initialized": True,
        "requires_mfa": False,
        "message": "Authentication successful",
    }
    stored = client.get(f"/auth-profiles/{profile['id']}").json()
    assert stored["last_auth_success"] is True
    assert stored["last_auth_status_code"] == 200
    assert "token" not in response.text.casefold()


def test_four_profiles_receive_distinct_auth_contexts(client) -> None:
    target = create_target(client)
    definitions = [
        ("Paciente A", "PACIENTE"),
        ("Paciente B", "PACIENTE"),
        ("Médico A", "MEDICO"),
        ("Secretário A", "SECRETARIO"),
    ]
    profile_ids = []
    contexts = []
    for name, role in definitions:
        profile = create_profile(client, int(target["id"]), name, role)
        profile_ids.append(profile["id"])
        contexts.append(
            AuthContext(
                profile_id=int(profile["id"]),
                profile_name=name,
                role_name=role,
            )
        )
    assert len({id(context) for context in contexts}) == 4
    assert [context.profile_id for context in contexts] == profile_ids
    assert all(context.headers == {} and context.cookies == () for context in contexts)


def test_role_comparison_api_is_unknown_without_authenticated_scans(client) -> None:
    target = create_target(client)
    first = create_profile(client, int(target["id"]), "Médico A", "MEDICO")
    second = create_profile(client, int(target["id"]), "Paciente A", "PACIENTE")
    response = client.get(
        f"/targets/{target['id']}/role-comparison",
        params={"profile_a_id": first["id"], "profile_b_id": second["id"]},
    )
    assert response.status_code == 200
    assert response.json()["profile_a_scan_id"] is None
    assert response.json()["profile_b_scan_id"] is None
    assert response.json()["rows"] == []
    generated = client.post(
        f"/targets/{target['id']}/authorization-candidates/generate",
        json={"profile_a_id": first["id"], "profile_b_id": second["id"]},
    )
    assert generated.status_code == 422


def test_role_snapshot_api_is_empty_before_first_authenticated_scan(client) -> None:
    target = create_target(client)
    profile = create_profile(client, int(target["id"]), "Médico A", "MEDICO")
    response = client.get(f"/auth-profiles/{profile['id']}/role-surface-snapshots")
    assert response.status_code == 200
    assert response.json() == []
    stored = client.get(f"/auth-profiles/{profile['id']}").json()
    assert stored["last_authenticated_scan_id"] is None
    assert stored["last_authenticated_scan_at"] is None


def test_scan_stores_reproducibility_metadata_without_secrets(client) -> None:
    target = create_target(client, fixture=True)
    response = client.post(
        "/scans",
        json={
            "target_id": target["id"],
            "experiment_label": "doctor-baseline-01",
        },
    )
    assert response.status_code == 201
    scan = response.json()
    assert scan["experiment_label"] == "doctor-baseline-01"
    assert scan["dast_version"] == "0.24.0"
    assert "discovery" in scan["modules_enabled"]
    serialized = str(scan["configuration_snapshot"]).casefold()
    assert "password" not in serialized
    assert "token" not in serialized


def test_experiment_label_rejects_unsafe_text(client) -> None:
    target = create_target(client, fixture=True)
    response = client.post(
        "/scans",
        json={"target_id": target["id"], "experiment_label": "patient A / secret"},
    )
    assert response.status_code == 422


def test_access_profile_surface_is_profile_driven_not_role_hardcoded(client) -> None:
    target = create_target(client)
    profile = create_profile(client, int(target["id"]), "Research Role", "CUSTOM_ROLE")
    surface = client.get(f"/auth-profiles/{profile['id']}/access-profile-surface").json()
    assert surface["profile_name"] == "Research Role"
    assert surface["role_name"] == "CUSTOM_ROLE"
    assert surface["authentication_status"] == "NOT_TESTED"
    assert surface["api_endpoints"] == 0


def test_tcc_summary_is_sanitized_and_marks_fixture(client) -> None:
    target = create_target(client, fixture=True)
    scan = client.post(
        "/scans",
        json={"target_id": target["id"], "experiment_label": "fixture-control"},
    ).json()
    summary = client.get(f"/scans/{scan['id']}/summary")
    assert summary.status_code == 200
    document = summary.json()
    assert document["environment"] == "FIXTURE"
    assert document["scan_profile"] == "ANONYMOUS"
    assert document["authorization_probes"] == 0
    serialized = summary.text.casefold()
    assert "password" not in serialized
    assert "authorization" not in document["modules_enabled"]


def test_real_tcc_scan_does_not_start_when_health_is_offline(client) -> None:
    target = create_target(client, tcc=True)
    scan = client.post("/scans", json={"target_id": target["id"]}).json()
    with patch(
        "app.scanner.client.SafeHttpCollector.fetch",
        side_effect=httpx.ConnectError("offline"),
    ):
        response = client.post(f"/scans/{scan['id']}/run")
    assert response.status_code == 503
    assert response.json()["detail"] == "Target unavailable"
