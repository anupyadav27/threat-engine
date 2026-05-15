"""
Unit tests for onboarding-C9: POST /api/v1/scans/run-all

Covers AC10 (4 required test cases + extras):
  1. org_admin triggers all valid accounts — scan_orchestration row created per account.
  2. tenant_admin calling the endpoint gets HTTP 403.
  3. INACTIVE account is skipped with reason "INACTIVE credential".
  4. Mixed scenario: one valid, one INACTIVE, one bad credentials — correct split.

Additional coverage:
  5. org_admin cross-tenant attempt blocked (AC3).
  6. Zero active accounts returns 202 with empty triggered list (AC8).
  7. create_scan_run failure adds account to skipped without aborting loop (AC9).
"""
import hashlib
import sys
import types
import uuid
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# ── Stub sys.modules so the router can be imported in an isolated test env ────

_engine_auth = types.ModuleType("engine_auth")
_engine_auth_fastapi = types.ModuleType("engine_auth.fastapi")
_engine_auth_fastapi_deps = types.ModuleType("engine_auth.fastapi.dependencies")
_engine_auth_core = types.ModuleType("engine_auth.core")
_engine_auth_core_models = types.ModuleType("engine_auth.core.models")


class _AuthContext:
    """Minimal AuthContext stand-in for tests."""

    def __init__(self, role: str, tenant_id: str) -> None:
        self.role = role
        self.tenant_id = tenant_id
        self.engine_tenant_id = tenant_id


# Stub require_permission and get_auth_context — overridden per test below.
_engine_auth_fastapi_deps.require_permission = lambda perm: (lambda: None)
_engine_auth_fastapi_deps.get_auth_context = lambda: None
_engine_auth_core_models.AuthContext = _AuthContext

_engine_auth.fastapi = _engine_auth_fastapi
_engine_auth_fastapi.dependencies = _engine_auth_fastapi_deps
_engine_auth.core = _engine_auth_core
_engine_auth_core.models = _engine_auth_core_models

for _name, _mod in [
    ("engine_auth", _engine_auth),
    ("engine_auth.fastapi", _engine_auth_fastapi),
    ("engine_auth.fastapi.dependencies", _engine_auth_fastapi_deps),
    ("engine_auth.core", _engine_auth_core),
    ("engine_auth.core.models", _engine_auth_core_models),
]:
    sys.modules.setdefault(_name, _mod)

# Stub engine_onboarding sub-packages referenced by bulk_scans.py
_engine_onboarding = types.ModuleType("engine_onboarding")
_engine_onboarding_db = types.ModuleType("engine_onboarding.database")
_engine_onboarding_db_ca = types.ModuleType("engine_onboarding.database.cloud_accounts_operations")
_engine_onboarding_db_sr = types.ModuleType("engine_onboarding.database.scan_run_operations")
_engine_onboarding_sched = types.ModuleType("engine_onboarding.scheduler")
_engine_onboarding_argo = types.ModuleType("engine_onboarding.scheduler.argo_client")

_engine_onboarding_db_ca.get_active_accounts_for_tenant = lambda tenant_id: []
_engine_onboarding_db_sr.create_scan_run = lambda data: data


class _FakeArgoClient:
    def submit_pipeline(self, **kwargs: Any) -> None:
        pass


_engine_onboarding_argo.ArgoClient = _FakeArgoClient

for _name, _mod in [
    ("engine_onboarding", _engine_onboarding),
    ("engine_onboarding.database", _engine_onboarding_db),
    ("engine_onboarding.database.cloud_accounts_operations", _engine_onboarding_db_ca),
    ("engine_onboarding.database.scan_run_operations", _engine_onboarding_db_sr),
    ("engine_onboarding.scheduler", _engine_onboarding_sched),
    ("engine_onboarding.scheduler.argo_client", _engine_onboarding_argo),
]:
    sys.modules.setdefault(_name, _mod)

# Import the module under test AFTER stubs are in place.
import engines.onboarding.routers.bulk_scans as _bulk_scans_module  # type: ignore[import]
from engines.onboarding.routers.bulk_scans import router  # type: ignore[import]


# ── Helpers ───────────────────────────────────────────────────────────────────

TENANT_A = "tenant-aaaa-0000"
TENANT_B = "tenant-bbbb-1111"


def _make_account(
    account_id: str,
    account_status: str = "active",
    credential_validation_status: str = "pass",
    tenant_id: str = TENANT_A,
) -> Dict[str, Any]:
    return {
        "account_id": account_id,
        "account_name": f"Account {account_id}",
        "provider": "aws",
        "credential_type": "access_key",
        "credential_ref": f"threat-engine/account/{account_id}",
        "account_status": account_status,
        "credential_validation_status": credential_validation_status,
        "customer_id": "customer-1",
        "tenant_id": tenant_id,
    }


def _build_app(auth_context: Any) -> TestClient:
    """Build a fresh TestClient with the auth context injected via dependency override."""
    app = FastAPI()
    app.include_router(router)

    async def _override_auth() -> Any:
        return auth_context

    # require_permission returns a callable; override the factory itself.
    def _override_perm(perm: str):
        async def _noop() -> None:
            return None
        return _noop

    # Override using the actual dependency callables from the module.
    app.dependency_overrides[_bulk_scans_module.get_auth_context] = _override_auth
    app.dependency_overrides[_bulk_scans_module.require_permission] = _override_perm

    return TestClient(app, raise_server_exceptions=True)


# ── AC10-1: org_admin triggers all valid accounts ─────────────────────────────

class TestRunAllOrgAdmin:
    """AC10-1: org_admin triggers all valid accounts."""

    def test_org_admin_triggers_valid_accounts(self) -> None:
        accounts = [
            _make_account("acct-001"),
            _make_account("acct-002"),
        ]
        auth = _AuthContext(role="org_admin", tenant_id=TENANT_A)
        client = _build_app(auth)

        created_runs: List[str] = []

        def _fake_create_scan_run(data: Dict[str, Any]) -> Dict[str, Any]:
            created_runs.append(data["scan_run_id"])
            return data

        with (
            patch(
                "engines.onboarding.routers.bulk_scans.get_active_accounts_for_tenant",
                return_value=accounts,
            ),
            patch(
                "engines.onboarding.routers.bulk_scans.create_scan_run",
                side_effect=_fake_create_scan_run,
            ),
        ):
            resp = client.post("/api/v1/scans/run-all", json={"tenant_id": TENANT_A})

        assert resp.status_code == 202, resp.text
        body = resp.json()
        assert len(body["triggered"]) == 2
        assert len(body["skipped"]) == 0
        triggered_ids = {t["account_id"] for t in body["triggered"]}
        assert triggered_ids == {"acct-001", "acct-002"}
        assert len(created_runs) == 2


# ── AC10-2: tenant_admin must receive HTTP 403 ────────────────────────────────

class TestRunAllTenantAdminForbidden:
    """AC10-2: tenant_admin calling the endpoint gets HTTP 403."""

    def test_tenant_admin_gets_403(self) -> None:
        auth = _AuthContext(role="tenant_admin", tenant_id=TENANT_A)
        client = _build_app(auth)

        resp = client.post("/api/v1/scans/run-all", json={"tenant_id": TENANT_A})

        assert resp.status_code == 403
        assert "org_admin" in resp.json()["detail"]


# ── AC10-3: INACTIVE account is skipped ──────────────────────────────────────

class TestRunAllInactiveSkipped:
    """AC10-3: INACTIVE account is skipped with reason 'INACTIVE credential'."""

    def test_inactive_account_skipped(self) -> None:
        accounts = [_make_account("acct-inactive", account_status="INACTIVE")]
        auth = _AuthContext(role="org_admin", tenant_id=TENANT_A)
        client = _build_app(auth)

        with (
            patch(
                "engines.onboarding.routers.bulk_scans.get_active_accounts_for_tenant",
                return_value=accounts,
            ),
            patch("engines.onboarding.routers.bulk_scans.create_scan_run", return_value={}),
        ):
            resp = client.post("/api/v1/scans/run-all", json={"tenant_id": TENANT_A})

        assert resp.status_code == 202
        body = resp.json()
        assert len(body["triggered"]) == 0
        assert len(body["skipped"]) == 1
        assert body["skipped"][0]["account_id"] == "acct-inactive"
        assert "INACTIVE" in body["skipped"][0]["reason"]


# ── AC10-4: Mixed scenario ────────────────────────────────────────────────────

class TestRunAllMixedScenario:
    """AC10-4: mixed scenario returns correct triggered/skipped split."""

    def test_mixed_scenario(self) -> None:
        accounts = [
            _make_account("acct-valid", account_status="active", credential_validation_status="pass"),
            _make_account("acct-inactive", account_status="INACTIVE", credential_validation_status="pass"),
            _make_account("acct-bad-creds", account_status="active", credential_validation_status="fail"),
        ]
        auth = _AuthContext(role="org_admin", tenant_id=TENANT_A)
        client = _build_app(auth)

        with (
            patch(
                "engines.onboarding.routers.bulk_scans.get_active_accounts_for_tenant",
                return_value=accounts,
            ),
            patch("engines.onboarding.routers.bulk_scans.create_scan_run", return_value={}),
        ):
            resp = client.post("/api/v1/scans/run-all", json={"tenant_id": TENANT_A})

        assert resp.status_code == 202
        body = resp.json()
        triggered_ids = {t["account_id"] for t in body["triggered"]}
        skipped_ids = {s["account_id"] for s in body["skipped"]}
        assert triggered_ids == {"acct-valid"}
        assert skipped_ids == {"acct-inactive", "acct-bad-creds"}
        skipped_map = {s["account_id"]: s["reason"] for s in body["skipped"]}
        assert "INACTIVE" in skipped_map["acct-inactive"]
        assert "fail" in skipped_map["acct-bad-creds"]


# ── AC3: org_admin cross-tenant attempt blocked ───────────────────────────────

class TestRunAllOrgAdminCrossTenantBlocked:
    """AC3: org_admin cannot target a different tenant."""

    def test_org_admin_cross_tenant_blocked(self) -> None:
        auth = _AuthContext(role="org_admin", tenant_id=TENANT_A)
        client = _build_app(auth)

        resp = client.post(
            "/api/v1/scans/run-all",
            json={"tenant_id": TENANT_B},  # different tenant
        )

        assert resp.status_code == 403
        assert "own tenant" in resp.json()["detail"]


# ── AC8: zero active accounts returns 202 ────────────────────────────────────

class TestRunAllEmptyTenant:
    """AC8: zero accounts returns 202 with empty triggered list — not an error."""

    def test_empty_triggered_is_not_error(self) -> None:
        auth = _AuthContext(role="org_admin", tenant_id=TENANT_A)
        client = _build_app(auth)

        with patch(
            "engines.onboarding.routers.bulk_scans.get_active_accounts_for_tenant",
            return_value=[],
        ):
            resp = client.post("/api/v1/scans/run-all", json={"tenant_id": TENANT_A})

        assert resp.status_code == 202
        body = resp.json()
        assert body["triggered"] == []
        assert body["skipped"] == []


# ── AC9: submission error does not abort the loop ────────────────────────────

class TestRunAllSubmissionError:
    """AC9: create_scan_run failure adds account to skipped without aborting the loop."""

    def test_submission_error_does_not_abort(self) -> None:
        accounts = [
            _make_account("acct-fail"),
            _make_account("acct-ok"),
        ]
        auth = _AuthContext(role="org_admin", tenant_id=TENANT_A)
        client = _build_app(auth)

        call_count = {"n": 0}

        def _sometimes_fail(data: Dict[str, Any]) -> Dict[str, Any]:
            call_count["n"] += 1
            if data["account_id"] == "acct-fail":
                raise RuntimeError("DB error")
            return data

        with (
            patch(
                "engines.onboarding.routers.bulk_scans.get_active_accounts_for_tenant",
                return_value=accounts,
            ),
            patch(
                "engines.onboarding.routers.bulk_scans.create_scan_run",
                side_effect=_sometimes_fail,
            ),
        ):
            resp = client.post("/api/v1/scans/run-all", json={"tenant_id": TENANT_A})

        assert resp.status_code == 202
        body = resp.json()
        assert len(body["triggered"]) == 1
        assert body["triggered"][0]["account_id"] == "acct-ok"
        assert len(body["skipped"]) == 1
        assert body["skipped"][0]["account_id"] == "acct-fail"
        assert body["skipped"][0]["reason"] == "submission_error"
        # Both accounts were attempted (loop was not aborted)
        assert call_count["n"] == 2
