"""
Unit tests for onboarding-C7: POST /api/v1/scans/run-now.

Covers AC10 test cases:
  - valid account → 202 + scan_run_id
  - wrong tenant (account belongs to different tenant) → 404
  - inactive / unvalidated account → 409
  - vulnerability agent account → sets run_now flag (no Argo call)
"""
from __future__ import annotations

from typing import Any, Optional
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Stub out heavy imports before the module is loaded
# ---------------------------------------------------------------------------

import sys

# Provide minimal engine_auth stubs so the router can be imported in tests
_fake_auth_module = MagicMock()
_fake_auth_module.require_permission = lambda perm: (lambda: None)
_fake_auth_module.get_auth_context = lambda: None
sys.modules.setdefault("engine_auth", MagicMock())
sys.modules.setdefault("engine_auth.fastapi", MagicMock())
sys.modules.setdefault("engine_auth.fastapi.dependencies", _fake_auth_module)
sys.modules.setdefault("engine_auth.core", MagicMock())
sys.modules.setdefault("engine_auth.core.models", MagicMock())
sys.modules.setdefault("engine_common", MagicMock())
sys.modules.setdefault("engine_common.logger", MagicMock())
sys.modules.setdefault("engine_onboarding", MagicMock())
sys.modules.setdefault("engine_onboarding.database", MagicMock())
sys.modules.setdefault("engine_onboarding.database.cloud_accounts_operations", MagicMock())
sys.modules.setdefault("engine_onboarding.database.scan_run_operations", MagicMock())
sys.modules.setdefault("engine_onboarding.scheduler", MagicMock())
sys.modules.setdefault("engine_onboarding.scheduler.argo_client", MagicMock())

from engines.onboarding.api.scans_adhoc import router  # type: ignore[import]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TENANT_A = "tenant-aaaa-0000"
_TENANT_B = "tenant-bbbb-1111"
_ACCOUNT_ID = "acct-1234-5678"

_VALID_ACCOUNT: dict[str, Any] = {
    "account_id": _ACCOUNT_ID,
    "tenant_id": _TENANT_A,
    "customer_id": "cust-001",
    "account_name": "Test Account",
    "provider": "aws",
    "credential_type": "access_key",
    "credential_ref": "threat-engine/account/some-uuid",
    "credential_validation_status": "pass",
    "account_status": "ACTIVE",
    "account_type": "cloud_csp",
    "exclude_regions": None,
}


def _make_auth(tenant_id: str = _TENANT_A) -> MagicMock:
    auth = MagicMock()
    auth.tenant_id = tenant_id
    auth.engine_tenant_id = tenant_id
    return auth


def _build_app(
    account: Optional[dict] = None,
    auth: Optional[MagicMock] = None,
    create_scan_run_raises: bool = False,
    agent_run_now_returns: bool = True,
    argo_raises: bool = False,
) -> TestClient:
    """Construct a TestClient with all external calls mocked."""
    from engines.onboarding.api import scans_adhoc as module  # type: ignore[import]

    # Patch get_cloud_account
    module.get_cloud_account = MagicMock(return_value=account)  # type: ignore[attr-defined]

    # Patch set_agent_run_now
    module.set_agent_run_now = MagicMock(return_value=agent_run_now_returns)  # type: ignore[attr-defined]

    # Patch create_scan_run
    if create_scan_run_raises:
        module.create_scan_run = MagicMock(side_effect=RuntimeError("DB error"))  # type: ignore[attr-defined]
    else:
        module.create_scan_run = MagicMock(return_value={"scan_run_id": "mocked"})  # type: ignore[attr-defined]

    # Patch auth dependencies
    resolved_auth = auth if auth is not None else _make_auth()
    module.get_auth_context = lambda: resolved_auth  # type: ignore[attr-defined]
    module.require_permission = lambda perm: (lambda: None)  # type: ignore[attr-defined]

    app = FastAPI()
    app.include_router(router)

    # Override FastAPI dependency injection
    from engines.onboarding.api.scans_adhoc import get_auth_context as _gac, require_permission as _rp  # type: ignore[import]
    app.dependency_overrides[_gac] = lambda: resolved_auth
    app.dependency_overrides[_rp("scans:create")] = lambda: None

    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------


class TestRunNowEndpoint:
    """AC10 test matrix for POST /api/v1/scans/run-now."""

    # ── AC10 case 1: valid account → 202 + scan_run_id ───────────────────────

    @patch("engines.onboarding.api.scans_adhoc.trigger_scan", return_value="wf-abc")
    @patch("engines.onboarding.api.scans_adhoc.create_scan_run", return_value={"scan_run_id": "x"})
    @patch("engines.onboarding.api.scans_adhoc.get_cloud_account", return_value=_VALID_ACCOUNT)
    def test_valid_account_returns_202(
        self,
        mock_get: MagicMock,
        mock_create: MagicMock,
        mock_trigger: MagicMock,
    ) -> None:
        """AC10 case 1: 202 + scan_run_id returned for a valid active account."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from engines.onboarding.api.scans_adhoc import router, get_auth_context, require_permission  # type: ignore[import]

        app = FastAPI()
        app.include_router(router)
        app.dependency_overrides[get_auth_context] = lambda: _make_auth()
        app.dependency_overrides[require_permission("scans:create")] = lambda: None

        client = TestClient(app, raise_server_exceptions=True)
        resp = client.post("/api/v1/scans/run-now", json={"account_id": _ACCOUNT_ID})

        assert resp.status_code == 202
        data = resp.json()
        assert "scan_run_id" in data
        assert data["status"] == "queued"
        mock_create.assert_called_once()
        mock_trigger.assert_called_once()

    # ── AC10 case 2: wrong tenant → 404 ──────────────────────────────────────

    @patch("engines.onboarding.api.scans_adhoc.get_cloud_account", return_value=_VALID_ACCOUNT)
    def test_wrong_tenant_returns_404(self, mock_get: MagicMock) -> None:
        """AC10 case 2: account belongs to tenant-A but caller is tenant-B → 404."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from engines.onboarding.api.scans_adhoc import router, get_auth_context, require_permission  # type: ignore[import]

        app = FastAPI()
        app.include_router(router)
        # Auth claims tenant-B, but the account is under tenant-A
        app.dependency_overrides[get_auth_context] = lambda: _make_auth(tenant_id=_TENANT_B)
        app.dependency_overrides[require_permission("scans:create")] = lambda: None

        client = TestClient(app, raise_server_exceptions=True)
        resp = client.post("/api/v1/scans/run-now", json={"account_id": _ACCOUNT_ID})

        assert resp.status_code == 404

    # ── AC10 case 3: inactive account → 409 ──────────────────────────────────

    @patch(
        "engines.onboarding.api.scans_adhoc.get_cloud_account",
        return_value={**_VALID_ACCOUNT, "account_status": "INACTIVE"},
    )
    def test_inactive_account_returns_409(self, mock_get: MagicMock) -> None:
        """AC10 case 3: INACTIVE account_status → 409 Conflict."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from engines.onboarding.api.scans_adhoc import router, get_auth_context, require_permission  # type: ignore[import]

        app = FastAPI()
        app.include_router(router)
        app.dependency_overrides[get_auth_context] = lambda: _make_auth()
        app.dependency_overrides[require_permission("scans:create")] = lambda: None

        client = TestClient(app, raise_server_exceptions=True)
        resp = client.post("/api/v1/scans/run-now", json={"account_id": _ACCOUNT_ID})

        assert resp.status_code == 409
        assert "inactive" in resp.json()["detail"].lower()

    @patch(
        "engines.onboarding.api.scans_adhoc.get_cloud_account",
        return_value={**_VALID_ACCOUNT, "credential_validation_status": "fail"},
    )
    def test_failed_validation_returns_409(self, mock_get: MagicMock) -> None:
        """AC10 case 3 (variant): credential_validation_status != 'pass' → 409."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from engines.onboarding.api.scans_adhoc import router, get_auth_context, require_permission  # type: ignore[import]

        app = FastAPI()
        app.include_router(router)
        app.dependency_overrides[get_auth_context] = lambda: _make_auth()
        app.dependency_overrides[require_permission("scans:create")] = lambda: None

        client = TestClient(app, raise_server_exceptions=True)
        resp = client.post("/api/v1/scans/run-now", json={"account_id": _ACCOUNT_ID})

        assert resp.status_code == 409

    # ── AC10 case 4: vulnerability agent account → run_now flag set ───────────

    @patch("engines.onboarding.api.scans_adhoc.set_agent_run_now", return_value=True)
    @patch("engines.onboarding.api.scans_adhoc.create_scan_run", return_value={"scan_run_id": "x"})
    @patch(
        "engines.onboarding.api.scans_adhoc.get_cloud_account",
        return_value={**_VALID_ACCOUNT, "account_type": "vulnerability"},
    )
    def test_agent_account_sets_run_now_flag(
        self,
        mock_get: MagicMock,
        mock_create: MagicMock,
        mock_set_flag: MagicMock,
    ) -> None:
        """AC10 case 4: vulnerability account → sets run_now flag, no Argo call."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from engines.onboarding.api.scans_adhoc import router, get_auth_context, require_permission  # type: ignore[import]

        app = FastAPI()
        app.include_router(router)
        app.dependency_overrides[get_auth_context] = lambda: _make_auth()
        app.dependency_overrides[require_permission("scans:create")] = lambda: None

        client = TestClient(app, raise_server_exceptions=True)
        resp = client.post("/api/v1/scans/run-now", json={"account_id": _ACCOUNT_ID})

        assert resp.status_code == 202
        data = resp.json()
        assert data["status"] == "queued"
        assert "scan_run_id" in data
        # run_now flag must be set
        mock_set_flag.assert_called_once_with(_ACCOUNT_ID)
        # scan_orchestration row still created
        mock_create.assert_called_once()

    # ── Missing account → 404 ─────────────────────────────────────────────────

    @patch("engines.onboarding.api.scans_adhoc.get_cloud_account", return_value=None)
    def test_missing_account_returns_404(self, mock_get: MagicMock) -> None:
        """Non-existent account_id returns 404."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from engines.onboarding.api.scans_adhoc import router, get_auth_context, require_permission  # type: ignore[import]

        app = FastAPI()
        app.include_router(router)
        app.dependency_overrides[get_auth_context] = lambda: _make_auth()
        app.dependency_overrides[require_permission("scans:create")] = lambda: None

        client = TestClient(app, raise_server_exceptions=True)
        resp = client.post("/api/v1/scans/run-now", json={"account_id": "does-not-exist"})

        assert resp.status_code == 404
