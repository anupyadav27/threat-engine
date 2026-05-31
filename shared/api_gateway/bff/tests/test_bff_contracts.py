"""BFF Contract Tests — DI-08.

Live integration tests that verify each BFF view endpoint returns the
expected top-level keys. Requires a running gateway with a valid session.

Usage:
    TEST_SESSION_COOKIE="access_token=<token>" pytest \
        shared/api_gateway/bff/tests/test_bff_contracts.py -v -m contract

Environment variables:
    TEST_SESSION_COOKIE   Cookie header value (required — skip if absent)
    GATEWAY_URL           Base URL of the API gateway (default: http://localhost:8000)
"""

from __future__ import annotations

import os
from typing import Any, Dict, Optional

import pytest

# ── Optional httpx import (not available in all environments) ─────────────────
try:
    import httpx
    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False

# ── Skip guard — module-level ─────────────────────────────────────────────────

SESSION_COOKIE = os.environ.get("TEST_SESSION_COOKIE", "")
GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://localhost:8000")

_SKIP_REASON = (
    "TEST_SESSION_COOKIE not set — skipping live integration tests"
    if not SESSION_COOKIE
    else ("httpx not installed — skipping live integration tests" if not _HTTPX_AVAILABLE else "")
)
_SKIP = bool(_SKIP_REASON)

pytestmark = pytest.mark.contract


# ── HTTP helper ───────────────────────────────────────────────────────────────

def _get_view(path: str, params: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """GET /api/v1/views/{path} using the session cookie.

    Args:
        path: BFF view path, e.g. "dashboard" or "threats/attack-paths".
        params: Optional query parameters dict.

    Returns:
        Parsed JSON response dict. Empty dict on non-200 or parse error.
    """
    if not _HTTPX_AVAILABLE:
        return {}
    url = f"{GATEWAY_URL}/api/v1/views/{path}"
    # Parse cookie string into a dict for httpx
    cookies: Dict[str, str] = {}
    for part in SESSION_COOKIE.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            cookies[k.strip()] = v.strip()

    try:
        resp = httpx.get(url, params=params or {}, cookies=cookies, timeout=30.0)
        if resp.status_code == 200:
            return resp.json()
        return {"_status_code": resp.status_code}
    except Exception as exc:  # noqa: BLE001
        return {"_error": str(exc)}


# ── Contract test classes ─────────────────────────────────────────────────────


@pytest.mark.skipif(_SKIP, reason=_SKIP_REASON)
class TestDashboardContract:
    """Verify /views/dashboard returns expected top-level keys."""

    def test_top_level_keys(self) -> None:
        data = _get_view("dashboard")
        assert isinstance(data, dict), f"Expected dict, got {type(data)}"
        # Core keys the UI reads
        assert "kpi" in data or "kpiGroups" in data, (
            "dashboard must return 'kpi' or 'kpiGroups'"
        )
        assert "criticalActions" in data or "criticalAlerts" in data, (
            "dashboard must return criticalActions or criticalAlerts"
        )

    def test_kpi_has_total_assets(self) -> None:
        data = _get_view("dashboard")
        kpi = data.get("kpi", {})
        assert isinstance(kpi, dict)
        assert "totalAssets" in kpi or "openFindings" in kpi

    def test_chart_categories_present(self) -> None:
        data = _get_view("dashboard")
        assert "chartCategories" in data or "recentThreats" in data


@pytest.mark.skipif(_SKIP, reason=_SKIP_REASON)
class TestThreatsContract:
    """Verify /views/threats returns expected top-level keys."""

    def test_top_level_keys(self) -> None:
        data = _get_view("threats")
        assert "findings" in data or "threats" in data or "total" in data, (
            "threats must return 'findings', 'threats', or 'total'"
        )

    def test_kpi_groups_present(self) -> None:
        data = _get_view("threats")
        assert "kpiGroups" in data or "kpi" in data

    def test_scan_meta_present(self) -> None:
        data = _get_view("threats")
        assert "scanMeta" in data

    def test_mitre_matrix_present(self) -> None:
        data = _get_view("threats")
        assert "mitreMatrix" in data


@pytest.mark.skipif(_SKIP, reason=_SKIP_REASON)
class TestComplianceContract:
    """Verify /views/compliance returns expected top-level keys."""

    def test_top_level_keys(self) -> None:
        data = _get_view("compliance")
        assert "frameworks" in data or "total" in data, (
            "compliance must return 'frameworks' or 'total'"
        )

    def test_kpi_groups_present(self) -> None:
        data = _get_view("compliance")
        assert "kpiGroups" in data

    def test_frameworks_is_list(self) -> None:
        data = _get_view("compliance")
        frameworks = data.get("frameworks", [])
        assert isinstance(frameworks, list)

    def test_account_matrix_present(self) -> None:
        data = _get_view("compliance")
        assert "accountMatrix" in data


@pytest.mark.skipif(_SKIP, reason=_SKIP_REASON)
class TestInventoryContract:
    """Verify /views/inventory returns expected top-level keys."""

    def test_top_level_keys(self) -> None:
        data = _get_view("inventory")
        assert "assets" in data or "total" in data or "findings" in data, (
            "inventory must return 'assets', 'total', or 'findings'"
        )

    def test_kpi_groups_present(self) -> None:
        data = _get_view("inventory")
        assert "kpiGroups" in data or "kpi" in data

    def test_scan_meta_present(self) -> None:
        data = _get_view("inventory")
        assert "scanMeta" in data or "pageContext" in data


@pytest.mark.skipif(_SKIP, reason=_SKIP_REASON)
class TestIamContract:
    """Verify /views/iam returns expected top-level keys."""

    def test_top_level_keys(self) -> None:
        data = _get_view("iam")
        assert "findings" in data or "total" in data or "kpiGroups" in data, (
            "iam must return 'findings', 'total', or 'kpiGroups'"
        )

    def test_kpi_groups_present(self) -> None:
        data = _get_view("iam")
        assert "kpiGroups" in data or "kpi" in data


@pytest.mark.skipif(_SKIP, reason=_SKIP_REASON)
class TestRiskContract:
    """Verify /views/risk returns expected top-level keys."""

    def test_top_level_keys(self) -> None:
        data = _get_view("risk")
        assert "scenarios" in data or "kpiGroups" in data or "total" in data, (
            "risk must return 'scenarios', 'kpiGroups', or 'total'"
        )

    def test_risk_categories_present(self) -> None:
        data = _get_view("risk")
        assert "riskCategories" in data or "kpiGroups" in data

    def test_trend_data_present(self) -> None:
        data = _get_view("risk")
        assert "trendData" in data


@pytest.mark.skipif(_SKIP, reason=_SKIP_REASON)
class TestMisconfigContract:
    """Verify /views/misconfig returns expected top-level keys."""

    def test_top_level_keys(self) -> None:
        data = _get_view("misconfig")
        assert "findings" in data or "total" in data or "kpiGroups" in data

    def test_kpi_groups_present(self) -> None:
        data = _get_view("misconfig")
        assert "kpiGroups" in data or "kpi" in data


@pytest.mark.skipif(_SKIP, reason=_SKIP_REASON)
class TestNetworkSecurityContract:
    """Verify /views/network-security returns expected top-level keys."""

    def test_top_level_keys(self) -> None:
        data = _get_view("network-security")
        assert "findings" in data or "total" in data or "kpiGroups" in data

    def test_kpi_groups_present(self) -> None:
        data = _get_view("network-security")
        assert "kpiGroups" in data or "kpi" in data


@pytest.mark.skipif(_SKIP, reason=_SKIP_REASON)
class TestCiemContract:
    """Verify /views/cdr returns expected top-level keys."""

    def test_top_level_keys(self) -> None:
        data = _get_view("cdr")
        assert "findings" in data or "total" in data or "kpiGroups" in data

    def test_kpi_groups_present(self) -> None:
        data = _get_view("cdr")
        assert "kpiGroups" in data or "kpi" in data


@pytest.mark.skipif(_SKIP, reason=_SKIP_REASON)
class TestVulnerabilityContract:
    """Verify /views/vulnerability returns expected top-level keys."""

    def test_top_level_keys(self) -> None:
        data = _get_view("vulnerability")
        assert "findings" in data or "total" in data or "kpiGroups" in data

    def test_kpi_groups_present(self) -> None:
        data = _get_view("vulnerability")
        assert "kpiGroups" in data or "kpi" in data


# ── Unauthenticated 401 tests ─────────────────────────────────────────────────

_ALL_VIEWS = [
    "dashboard",
    "threats",
    "compliance",
    "inventory",
    "iam",
    "risk",
    "misconfig",
    "network-security",
    "cdr",
    "vulnerability",
    "datasec",
    "encryption",
    "container-security",
    "ai-security",
    "database-security",
    "cwpp",
    "cnapp",
]


@pytest.mark.skipif(not _HTTPX_AVAILABLE, reason="httpx not installed")
class TestUnauthenticatedReturns401:
    """All BFF views must return 401 when called without a session cookie."""

    @pytest.mark.parametrize("view", _ALL_VIEWS)
    def test_no_cookie_returns_401(self, view: str) -> None:
        if not _HTTPX_AVAILABLE:
            pytest.skip("httpx not installed")
        url = f"{GATEWAY_URL}/api/v1/views/{view}"
        try:
            resp = httpx.get(url, timeout=10.0)
            assert resp.status_code == 401, (
                f"Expected 401 for unauthenticated request to {view}, "
                f"got {resp.status_code}"
            )
        except httpx.ConnectError:
            pytest.skip(f"Gateway not reachable at {GATEWAY_URL}")
