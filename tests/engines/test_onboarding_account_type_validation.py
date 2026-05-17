"""
Unit tests for onboarding-C5: account_type / tenant_type validation.

Covers:
  - validate_account_type_for_tenant() (AC7, AC3)
  - create_account endpoint happy-path and rejection (AC1, AC2, AC4)
  - DB timeout returns HTTP 503 (AC6)
  - tenant_id from auth context, not body (AC5)
"""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient
from fastapi import FastAPI

# ── Pure unit tests for the validator module ──────────────────────────────────

from engines.onboarding.validators.account_type import (  # type: ignore[import]
    validate_account_type_for_tenant,
    ACCOUNT_TYPE_TENANT_TYPE_MAP,
)


class TestValidateAccountTypeForTenant:
    """Tests for engines/onboarding/validators/account_type.py."""

    # AC3 — valid combinations
    def test_cloud_csp_cloud_tenant_is_valid(self) -> None:
        assert validate_account_type_for_tenant("cloud_csp", "cloud") is True

    def test_vulnerability_vulnerability_tenant_is_valid(self) -> None:
        assert validate_account_type_for_tenant("vulnerability", "vulnerability") is True

    def test_secops_secops_tenant_is_valid(self) -> None:
        assert validate_account_type_for_tenant("secops", "secops") is True

    # AC1 — cloud_csp rejected under non-cloud tenant
    def test_cloud_csp_under_vulnerability_tenant_is_invalid(self) -> None:
        assert validate_account_type_for_tenant("cloud_csp", "vulnerability") is False

    def test_cloud_csp_under_secops_tenant_is_invalid(self) -> None:
        assert validate_account_type_for_tenant("cloud_csp", "secops") is False

    # AC2 — vulnerability rejected under non-vulnerability tenant
    def test_vulnerability_under_cloud_tenant_is_invalid(self) -> None:
        assert validate_account_type_for_tenant("vulnerability", "cloud") is False

    def test_vulnerability_under_secops_tenant_is_invalid(self) -> None:
        assert validate_account_type_for_tenant("vulnerability", "secops") is False

    # secops rejected under non-secops tenant
    def test_secops_under_cloud_tenant_is_invalid(self) -> None:
        assert validate_account_type_for_tenant("secops", "cloud") is False

    def test_secops_under_vulnerability_tenant_is_invalid(self) -> None:
        assert validate_account_type_for_tenant("secops", "vulnerability") is False

    # Types not in the governed map are always compatible
    def test_database_type_is_not_governed(self) -> None:
        assert validate_account_type_for_tenant("database", "cloud") is True
        assert validate_account_type_for_tenant("database", "vulnerability") is True

    def test_code_security_type_is_not_governed(self) -> None:
        assert validate_account_type_for_tenant("code_security", "cloud") is True

    def test_middleware_type_is_not_governed(self) -> None:
        assert validate_account_type_for_tenant("middleware", "secops") is True

    def test_unknown_account_type_is_not_governed(self) -> None:
        # Unknown types not in the map fall through as compatible (broader
        # VALID_ACCOUNT_TYPES check handles rejection of truly unknown types).
        assert validate_account_type_for_tenant("unknown_type", "cloud") is True

    # Verify map constant completeness
    def test_map_covers_required_account_types(self) -> None:
        required = {"cloud_csp", "vulnerability", "secops"}
        assert required.issubset(set(ACCOUNT_TYPE_TENANT_TYPE_MAP.keys()))

    def test_map_values_are_correct(self) -> None:
        assert ACCOUNT_TYPE_TENANT_TYPE_MAP["cloud_csp"] == "cloud"
        assert ACCOUNT_TYPE_TENANT_TYPE_MAP["vulnerability"] == "vulnerability"
        assert ACCOUNT_TYPE_TENANT_TYPE_MAP["secops"] == "secops"


# ── Endpoint-level tests ──────────────────────────────────────────────────────

_TENANT_ID = "tenant-abc-123"
_CUSTOMER_ID = "cust-001"


def _make_app():
    """Build a minimal FastAPI app with the cloud-accounts router wired up."""
    from engines.onboarding.api.cloud_accounts import router  # type: ignore[import]
    app = FastAPI()
    app.include_router(router)
    return app


def _base_payload(**overrides) -> dict:
    payload = {
        "customer_id": _CUSTOMER_ID,
        "tenant_id": _TENANT_ID,
        "account_name": "Test Account",
        "provider": "aws",
    }
    payload.update(overrides)
    return payload


@pytest.fixture()
def client():
    return TestClient(_make_app())


class TestCreateAccountEndpoint:
    """Integration-style tests for POST /api/v1/cloud-accounts."""

    def _mock_happy_path(self, mocker, tenant_type: str = "cloud") -> None:
        """Patch all external calls so the endpoint succeeds."""
        mocker.patch(
            "engines.onboarding.api.cloud_accounts.get_tenant_type",
            return_value=tenant_type,
        )
        mocker.patch(
            "engines.onboarding.api.cloud_accounts.get_tenant",
            return_value={
                "tenant_id": _TENANT_ID,
                "customer_id": _CUSTOMER_ID,
                "tenant_type": tenant_type,
            },
        )
        mocker.patch(
            "engines.onboarding.api.cloud_accounts.create_cloud_account",
            return_value={
                "account_id": "acct-001",
                "tenant_id": _TENANT_ID,
                "account_type": "cloud_csp",
                "provider": "aws",
                "account_name": "Test Account",
                "account_status": "pending",
            },
        )

    # AC1: cloud_csp under vulnerability tenant → 422
    def test_cloud_csp_rejected_under_vulnerability_tenant(self, client, mocker) -> None:
        mocker.patch(
            "engines.onboarding.api.cloud_accounts.get_tenant_type",
            return_value="vulnerability",
        )
        mocker.patch(
            "engines.onboarding.api.cloud_accounts.get_tenant",
            return_value={"tenant_id": _TENANT_ID, "tenant_type": "vulnerability"},
        )
        resp = client.post(
            "/api/v1/cloud-accounts",
            json=_base_payload(provider="aws", account_type="cloud_csp"),
        )
        assert resp.status_code == 422
        assert "cloud_csp" in resp.json()["detail"]
        assert "vulnerability" in resp.json()["detail"]

    # AC2: vulnerability account under cloud tenant → 422
    def test_vulnerability_rejected_under_cloud_tenant(self, client, mocker) -> None:
        mocker.patch(
            "engines.onboarding.api.cloud_accounts.get_tenant_type",
            return_value="cloud",
        )
        mocker.patch(
            "engines.onboarding.api.cloud_accounts.get_tenant",
            return_value={"tenant_id": _TENANT_ID, "tenant_type": "cloud"},
        )
        resp = client.post(
            "/api/v1/cloud-accounts",
            json=_base_payload(provider="aws", account_type="vulnerability"),
        )
        assert resp.status_code == 422
        assert "vulnerability" in resp.json()["detail"]

    # AC3: secops account under cloud tenant → 422
    def test_secops_rejected_under_cloud_tenant(self, client, mocker) -> None:
        mocker.patch(
            "engines.onboarding.api.cloud_accounts.get_tenant_type",
            return_value="cloud",
        )
        mocker.patch(
            "engines.onboarding.api.cloud_accounts.get_tenant",
            return_value={"tenant_id": _TENANT_ID, "tenant_type": "cloud"},
        )
        resp = client.post(
            "/api/v1/cloud-accounts",
            json=_base_payload(provider="aws", account_type="secops"),
        )
        assert resp.status_code == 422

    # Valid combinations pass
    def test_cloud_csp_accepted_under_cloud_tenant(self, client, mocker) -> None:
        self._mock_happy_path(mocker, tenant_type="cloud")
        resp = client.post(
            "/api/v1/cloud-accounts",
            json=_base_payload(provider="aws", account_type="cloud_csp"),
        )
        assert resp.status_code == 201

    def test_vulnerability_accepted_under_vulnerability_tenant(
        self, client, mocker
    ) -> None:
        mocker.patch(
            "engines.onboarding.api.cloud_accounts.get_tenant_type",
            return_value="vulnerability",
        )
        mocker.patch(
            "engines.onboarding.api.cloud_accounts.get_tenant",
            return_value={"tenant_id": _TENANT_ID, "tenant_type": "vulnerability"},
        )
        mocker.patch(
            "engines.onboarding.api.cloud_accounts.create_cloud_account",
            return_value={
                "account_id": "acct-002",
                "tenant_id": _TENANT_ID,
                "account_type": "vulnerability",
                "provider": "agent",
                "account_name": "Vuln Scanner",
                "account_status": "pending",
            },
        )
        resp = client.post(
            "/api/v1/cloud-accounts",
            json=_base_payload(
                provider="agent",
                account_type="vulnerability",
                account_name="Vuln Scanner",
            ),
        )
        assert resp.status_code == 201

    # AC6: DB OperationalError → 503
    def test_db_timeout_returns_503(self, client, mocker) -> None:
        import psycopg2

        mocker.patch(
            "engines.onboarding.api.cloud_accounts.get_tenant_type",
            side_effect=psycopg2.OperationalError("connection refused"),
        )
        resp = client.post(
            "/api/v1/cloud-accounts",
            json=_base_payload(provider="aws"),
        )
        assert resp.status_code == 503
        assert "Tenant service unavailable" in resp.json()["detail"]

    # AC4: validation fires BEFORE DB write (create_cloud_account never called on mismatch)
    def test_db_write_not_called_on_type_mismatch(self, client, mocker) -> None:
        mocker.patch(
            "engines.onboarding.api.cloud_accounts.get_tenant_type",
            return_value="vulnerability",
        )
        mocker.patch(
            "engines.onboarding.api.cloud_accounts.get_tenant",
            return_value={"tenant_id": _TENANT_ID, "tenant_type": "vulnerability"},
        )
        mock_create = mocker.patch(
            "engines.onboarding.api.cloud_accounts.create_cloud_account"
        )
        client.post(
            "/api/v1/cloud-accounts",
            json=_base_payload(provider="aws", account_type="cloud_csp"),
        )
        mock_create.assert_not_called()

    # AC5: auth context tenant_id takes precedence over body tenant_id
    def test_auth_tenant_id_used_not_body(self, client, mocker) -> None:
        """Ensures get_tenant_type is called with auth tenant_id when auth is present."""
        mocker.patch(
            "engines.onboarding.api.cloud_accounts.get_tenant_type",
            return_value="cloud",
        ) as mock_gtt
        mocker.patch(
            "engines.onboarding.api.cloud_accounts.get_tenant",
            return_value={"tenant_id": _TENANT_ID, "tenant_type": "cloud"},
        )
        mocker.patch(
            "engines.onboarding.api.cloud_accounts.create_cloud_account",
            return_value={
                "account_id": "acct-003",
                "tenant_id": _TENANT_ID,
                "account_type": "cloud_csp",
                "provider": "aws",
                "account_name": "Test Account",
                "account_status": "pending",
            },
        )
        # Inject auth context with a different tenant_id than the body
        auth_tenant_id = "auth-tenant-from-header"
        body_tenant_id = "body-tenant-different"

        mock_auth = MagicMock()
        mock_auth.tenant_id = auth_tenant_id

        # Override get_auth_context dependency to return mock auth
        from engines.onboarding.api.cloud_accounts import router  # type: ignore[import]
        app = FastAPI()

        async def _mock_get_auth_context():
            return mock_auth

        async def _mock_require_perm():
            return None

        import engines.onboarding.api.cloud_accounts as ca_module  # type: ignore[import]

        app.include_router(router)
        app.dependency_overrides[ca_module.get_auth_context] = _mock_get_auth_context
        app.dependency_overrides[ca_module.require_permission("cloud_accounts:write")] = _mock_require_perm  # type: ignore[index]

        test_client = TestClient(app)
        test_client.post(
            "/api/v1/cloud-accounts",
            json=_base_payload(tenant_id=body_tenant_id, provider="aws"),
        )
        # get_tenant_type must have been called with the auth tenant_id, not the body one
        mock_gtt.assert_called_once_with(auth_tenant_id)
