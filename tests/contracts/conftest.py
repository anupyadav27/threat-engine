"""Shared fixtures for BFF offline contract tests (Phase 0 — ADR-004).

These tests import handler functions directly and mock all engine HTTP calls,
so they run in CI with no running gateway, no DB, and no session cookie.

Design constraints:
  - No live network calls.
  - No environment variables required.
  - Must run in < 5 seconds total for all 24 views.
  - Auth is mocked via a fixture that patches ``require_permission`` to return
    a predictable AuthContext.  Tests that need to verify 403 behaviour should
    override the mock explicitly.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Ensure repo root is importable.
REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))


# ── AuthContext stub ──────────────────────────────────────────────────────────


def make_auth_context(
    tenant_id: str = "tenant-test-001",
    user_id: str = "user-test-001",
    role: str = "analyst",
    permissions: Optional[List[str]] = None,
) -> MagicMock:
    """Return a MagicMock that behaves like an AuthContext for all tests.

    Permissions default to the analyst role set (all :read permissions).
    Override for role-specific tests.
    """
    if permissions is None:
        permissions = [
            "dashboard:read",
            "discoveries:read",
            "inventory:read",
            "threats:read",
            "compliance:read",
            "iam:read",
            "network_security:read",
            "risk:read",
            "datasec:read",
            "encryption:read",
            "vulnerability:read",
            "secops:read",
            "ciem:read",
            "scans:read",
            "rules:read",
            "reports:read",
            "billing:read",
            "platform_admin:read",
            "container_security:read",
            "ai_security:read",
            "database_security:read",
        ]
    ctx = MagicMock()
    ctx.tenant_id = tenant_id
    ctx.user_id = user_id
    ctx.role = role
    ctx.permissions = permissions
    ctx.has_permission = lambda p: p in permissions
    return ctx


# ── Engine response factories ─────────────────────────────────────────────────

#: Fields that appear on every finding row from any engine (14 standard columns)
_STANDARD_FINDING: Dict[str, Any] = {
    "finding_id": "abc123",
    "scan_run_id": "run-001",
    "tenant_id": "tenant-test-001",
    "account_id": "123456789012",
    "credential_ref": "should-be-excluded",   # must NOT appear in serialized output
    "credential_type": "access_key",           # must NOT appear in serialized output
    "provider": "aws",
    "region": "us-east-1",
    "resource_uid": "arn:aws:ec2:us-east-1:123456789012:instance/i-abc",
    "resource_type": "aws.ec2.instance",
    "severity": "high",
    "status": "OPEN",
    "first_seen_at": "2026-01-01T00:00:00Z",
    "last_seen_at": "2026-05-07T00:00:00Z",
}


def make_finding(overrides: Optional[Dict[str, Any]] = None, **kwargs: Any) -> Dict[str, Any]:
    """Return a complete finding dict ready to feed into any Pydantic model."""
    row = {**_STANDARD_FINDING}
    if overrides:
        row.update(overrides)
    row.update(kwargs)
    return row


def make_finding_azure(**kwargs: Any) -> Dict[str, Any]:
    """Azure-flavoured finding for multi-CSP fixture tests."""
    return make_finding(
        provider="azure",
        account_id="sub-12345678-abcd-ef01-2345-678901234567",
        region="eastus",
        resource_uid="/subscriptions/sub-12345678/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-prod",
        resource_type="azure.compute.virtual_machine",
        **kwargs,
    )


def make_finding_gcp(**kwargs: Any) -> Dict[str, Any]:
    """GCP-flavoured finding for multi-CSP fixture tests."""
    return make_finding(
        provider="gcp",
        account_id="my-gcp-project",
        region="us-central1",
        resource_uid="//compute.googleapis.com/projects/my-gcp-project/zones/us-central1-a/instances/vm-001",
        resource_type="gcp.compute.instance",
        **kwargs,
    )


def make_engine_list_response(
    items: Optional[List[Dict[str, Any]]] = None,
    total: Optional[int] = None,
    **extras: Any,
) -> Dict[str, Any]:
    """Return a generic paginated engine response envelope."""
    rows = items if items is not None else [make_finding()]
    return {
        "items": rows,
        "total": total if total is not None else len(rows),
        "page": 1,
        "page_size": 50,
        "has_more": False,
        **extras,
    }


# ── Pytest fixtures ────────────────────────────────────────────────────────────


@pytest.fixture()
def mock_auth() -> MagicMock:
    """Standard analyst AuthContext mock."""
    return make_auth_context()


@pytest.fixture()
def mock_auth_admin() -> MagicMock:
    """Platform admin AuthContext mock (all permissions)."""
    return make_auth_context(role="platform_admin")


@pytest.fixture()
def mock_auth_viewer() -> MagicMock:
    """Viewer AuthContext mock (read-only, restricted engines return 403)."""
    return make_auth_context(
        role="viewer",
        permissions=[
            "dashboard:read",
            "inventory:read",
            "compliance:read",
            "scans:read",
            "rules:read",
        ],
    )


@pytest.fixture()
def aws_finding() -> Dict[str, Any]:
    """Single AWS finding row."""
    return make_finding()


@pytest.fixture()
def azure_finding() -> Dict[str, Any]:
    """Single Azure finding row."""
    return make_finding_azure()


@pytest.fixture()
def gcp_finding() -> Dict[str, Any]:
    """Single GCP finding row."""
    return make_finding_gcp()


@pytest.fixture()
def multi_csp_findings() -> List[Dict[str, Any]]:
    """Three-item list covering AWS, Azure, GCP."""
    return [make_finding(), make_finding_azure(), make_finding_gcp()]


@pytest.fixture()
def engine_list_response() -> Dict[str, Any]:
    """Generic paginated engine response with one AWS finding."""
    return make_engine_list_response()


@pytest.fixture()
def engine_list_response_multi_csp(multi_csp_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Paginated engine response containing findings from 3 CSPs."""
    return make_engine_list_response(items=multi_csp_findings)


# ── HTTP mock helper ──────────────────────────────────────────────────────────


class MockHTTPResponse:
    """Minimal stand-in for an httpx.Response used in BFF engine calls."""

    def __init__(self, json_data: Any, status_code: int = 200) -> None:
        self._json = json_data
        self.status_code = status_code

    def json(self) -> Any:
        return self._json

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


def make_mock_client(responses: Dict[str, Any]) -> MagicMock:
    """Return an AsyncMock httpx client that returns ``responses[url]``.

    ``responses`` is a dict mapping URL substrings to the JSON body to return.
    The first match wins, so keep more specific URLs first.
    """
    client = MagicMock()

    async def _get(url: str, **kw: Any) -> MockHTTPResponse:
        for key, body in responses.items():
            if key in url:
                return MockHTTPResponse(body)
        return MockHTTPResponse({}, status_code=404)

    client.get = _get
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    return client


@pytest.fixture()
def mock_http_client_factory():
    """Factory fixture: returns a function that builds a mock HTTP client.

    Usage in a test:
        def test_foo(mock_http_client_factory):
            client = mock_http_client_factory({"/threat/": {"items": [...]}})
    """
    return make_mock_client
