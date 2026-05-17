"""BFF Contract Tests — onboarding-D6: scan history, scan detail, scan re-run.

Verifies the response shape of:
  GET  /api/v1/views/scan_history
  GET  /api/v1/views/scan_detail
  POST /api/v1/views/scan_rerun

Unit tests use pytest-mock to stub the fetch_many / httpx calls so they run
without a live gateway.  Live integration tests are gated by TEST_SESSION_COOKIE.

Usage (unit — no gateway needed):
    pytest shared/api_gateway/bff/tests/test_scan_history.py -v

Usage (integration — requires running gateway):
    TEST_SESSION_COOKIE="access_token=<token>" pytest \
        shared/api_gateway/bff/tests/test_scan_history.py -v -m contract
"""

from __future__ import annotations

import os
from typing import Any, Dict, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ── Optional httpx import ─────────────────────────────────────────────────────
try:
    import httpx
    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False

SESSION_COOKIE = os.environ.get("TEST_SESSION_COOKIE", "")
GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://localhost:8000")

_SKIP_REASON = (
    "TEST_SESSION_COOKIE not set — skipping live integration tests"
    if not SESSION_COOKIE
    else ("httpx not installed — skipping live integration tests" if not _HTTPX_AVAILABLE else "")
)
_SKIP = bool(_SKIP_REASON)

pytestmark = pytest.mark.contract


# ── Fixtures ──────────────────────────────────────────────────────────────────

SAMPLE_SCAN_ROW: Dict[str, Any] = {
    "scan_run_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "account_id": "11111111-2222-3333-4444-555555555555",
    "overall_status": "completed",
    "engines_requested": ["discovery", "check", "inventory", "threat"],
    "engines_completed": ["discovery", "check", "inventory", "threat"],
    "created_at": "2026-05-10T10:00:00+00:00",
    "started_at": "2026-05-10T10:00:00+00:00",
    "completed_at": "2026-05-10T10:05:30+00:00",
    "updated_at": "2026-05-10T10:05:30+00:00",
    "provider": "aws",
    "scan_type": "full",
    "trigger_type": "manual",
    "engine_statuses": {
        "discovery": {"status": "completed", "findings": 120},
        "check": {"status": "completed", "findings": 45},
    },
    "results_summary": {"total_findings": 45, "critical": 3, "high": 10},
    "error_details": {},
}

SAMPLE_RUNNING_ROW: Dict[str, Any] = {
    **SAMPLE_SCAN_ROW,
    "scan_run_id": "ffffffff-0000-1111-2222-333333333333",
    "overall_status": "running",
    "completed_at": None,
    "updated_at": None,
    "engines_completed": ["discovery"],
}


# ── Unit tests (no live gateway) ─────────────────────────────────────────────

class TestShapeScanRow:
    """Unit tests for the _shape_scan_row helper."""

    def _import_helper(self):
        """Import the helper from the BFF module."""
        import importlib
        import sys

        # Stub engine_auth if not available
        if "engine_auth" not in sys.modules:
            import types
            stub = types.ModuleType("engine_auth")
            stub.fastapi = types.ModuleType("engine_auth.fastapi")  # type: ignore[attr-defined]
            stub.fastapi.dependencies = types.ModuleType("engine_auth.fastapi.dependencies")  # type: ignore[attr-defined]
            stub.fastapi.dependencies.require_permission = lambda _: lambda: None  # type: ignore[attr-defined]
            sys.modules["engine_auth"] = stub
            sys.modules["engine_auth.fastapi"] = stub.fastapi
            sys.modules["engine_auth.fastapi.dependencies"] = stub.fastapi.dependencies

        try:
            from bff.onboarding_cloud_accounts import _shape_scan_row, _compute_duration
            return _shape_scan_row, _compute_duration
        except ImportError:
            pytest.skip("bff package not importable in this environment")

    def test_shape_completed_scan(self) -> None:
        """Completed scan must include duration_seconds."""
        _shape_scan_row, _ = self._import_helper()
        shaped = _shape_scan_row(SAMPLE_SCAN_ROW)

        assert shaped["scan_run_id"] == SAMPLE_SCAN_ROW["scan_run_id"]
        assert shaped["status"] == "completed"
        assert shaped["duration_seconds"] == 330  # 5m30s = 330s
        assert shaped["created_at"] is not None
        assert shaped["updated_at"] is not None

    def test_engines_completed_is_list_not_string(self) -> None:
        """AC7: engines_completed must be a list, never a JSON string."""
        _shape_scan_row, _ = self._import_helper()
        # Simulate a row where engines_completed came back as a JSON string
        row_with_string = {
            **SAMPLE_SCAN_ROW,
            "engines_completed": '["discovery", "check"]',
        }
        shaped = _shape_scan_row(row_with_string)
        assert isinstance(shaped["engines_completed"], list), (
            "engines_completed must be a list — never a raw JSON string (AC7)"
        )
        assert "discovery" in shaped["engines_completed"]

    def test_engines_requested_is_list_not_string(self) -> None:
        """AC7: engines_requested must be a list, never a JSON string."""
        _shape_scan_row, _ = self._import_helper()
        row_with_string = {
            **SAMPLE_SCAN_ROW,
            "engines_requested": '["discovery", "check", "inventory"]',
        }
        shaped = _shape_scan_row(row_with_string)
        assert isinstance(shaped["engines_requested"], list), (
            "engines_requested must be a list — never a raw JSON string (AC7)"
        )

    def test_running_scan_duration_is_none(self) -> None:
        """AC6: duration_seconds is None for non-terminal status."""
        _shape_scan_row, _ = self._import_helper()
        shaped = _shape_scan_row(SAMPLE_RUNNING_ROW)
        assert shaped["duration_seconds"] is None, (
            "duration_seconds must be null for running scans (AC6)"
        )

    def test_shape_has_all_ac2_fields(self) -> None:
        """AC2: shaped row must contain all required fields."""
        _shape_scan_row, _ = self._import_helper()
        shaped = _shape_scan_row(SAMPLE_SCAN_ROW)
        required = {
            "scan_run_id", "account_id", "status",
            "engines_requested", "engines_completed",
            "created_at", "updated_at", "duration_seconds",
        }
        missing = required - set(shaped.keys())
        assert not missing, f"Missing required AC2 fields: {missing}"


class TestComputeDuration:
    """Unit tests for the _compute_duration helper."""

    def _import(self):
        import sys, types
        if "engine_auth" not in sys.modules:
            stub = types.ModuleType("engine_auth")
            sys.modules["engine_auth"] = stub
        try:
            from bff.onboarding_cloud_accounts import _compute_duration
            return _compute_duration
        except ImportError:
            pytest.skip("bff package not importable in this environment")

    def test_completed_returns_seconds(self) -> None:
        fn = self._import()
        result = fn("2026-05-10T10:00:00+00:00", "2026-05-10T10:05:30+00:00", "completed")
        assert result == 330

    def test_failed_returns_seconds(self) -> None:
        fn = self._import()
        result = fn("2026-05-10T10:00:00+00:00", "2026-05-10T10:01:00+00:00", "failed")
        assert result == 60

    def test_running_returns_none(self) -> None:
        fn = self._import()
        result = fn("2026-05-10T10:00:00+00:00", "2026-05-10T10:01:00+00:00", "running")
        assert result is None

    def test_missing_updated_at_returns_none(self) -> None:
        fn = self._import()
        result = fn("2026-05-10T10:00:00+00:00", None, "completed")
        assert result is None

    def test_missing_created_at_returns_none(self) -> None:
        fn = self._import()
        result = fn(None, "2026-05-10T10:01:00+00:00", "completed")
        assert result is None


# ── Live integration tests (require TEST_SESSION_COOKIE) ─────────────────────

def _get_view(path: str, params: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """GET /api/v1/views/{path} using the test session cookie."""
    if not _HTTPX_AVAILABLE:
        return {}
    url = f"{GATEWAY_URL}/api/v1/views/{path}"
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
    except Exception as exc:
        return {"_error": str(exc)}


def _post_view(path: str, body: Dict[str, Any]) -> Dict[str, Any]:
    """POST /api/v1/views/{path} using the test session cookie."""
    if not _HTTPX_AVAILABLE:
        return {}
    url = f"{GATEWAY_URL}/api/v1/views/{path}"
    cookies: Dict[str, str] = {}
    for part in SESSION_COOKIE.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            cookies[k.strip()] = v.strip()
    try:
        resp = httpx.post(url, json=body, cookies=cookies, timeout=30.0)
        return {"_status_code": resp.status_code, **(resp.json() if resp.content else {})}
    except Exception as exc:
        return {"_error": str(exc)}


@pytest.mark.skipif(_SKIP, reason=_SKIP_REASON)
class TestScanHistoryContract:
    """AC1 + AC2: GET /views/scan_history returns correct envelope and item shape."""

    def test_top_level_envelope(self) -> None:
        data = _get_view("scan_history")
        assert isinstance(data, dict), f"Expected dict, got {type(data)}"
        assert "scans" in data, "scan_history must return 'scans'"
        assert "total" in data, "scan_history must return 'total'"
        assert "page" in data, "scan_history must return 'page'"
        assert "page_size" in data, "scan_history must return 'page_size'"

    def test_scans_is_list(self) -> None:
        data = _get_view("scan_history")
        assert isinstance(data.get("scans"), list), "'scans' must be a list"

    def test_empty_returns_valid_envelope(self) -> None:
        """AC5: engine returning empty list must yield valid envelope, not fallback data."""
        data = _get_view("scan_history")
        scans = data.get("scans", [])
        assert isinstance(scans, list)
        assert data.get("total", 0) >= 0

    def test_scan_item_has_required_fields(self) -> None:
        """AC2: each scan item must have the contract fields."""
        data = _get_view("scan_history")
        scans = data.get("scans", [])
        if not scans:
            pytest.skip("No scan history items to validate")
        item = scans[0]
        required = {
            "scan_run_id", "account_id", "status",
            "engines_requested", "engines_completed",
            "created_at", "updated_at", "duration_seconds",
        }
        missing = required - set(item.keys())
        assert not missing, f"Missing fields in scan history item: {missing}"

    def test_engines_completed_is_list_not_string(self) -> None:
        """AC7 + AC8: engines_completed must be a list, not a JSON string."""
        data = _get_view("scan_history")
        scans = data.get("scans", [])
        if not scans:
            pytest.skip("No scan history items to validate")
        for item in scans:
            ec = item.get("engines_completed")
            assert isinstance(ec, list), (
                f"engines_completed must be a list (AC7), got {type(ec).__name__}: {ec!r}"
            )

    def test_engines_requested_is_list_not_string(self) -> None:
        """AC7: engines_requested must be a list, not a JSON string."""
        data = _get_view("scan_history")
        scans = data.get("scans", [])
        if not scans:
            pytest.skip("No scan history items to validate")
        for item in scans:
            er = item.get("engines_requested")
            assert isinstance(er, list), (
                f"engines_requested must be a list (AC7), got {type(er).__name__}: {er!r}"
            )

    def test_duration_seconds_null_for_running(self) -> None:
        """AC6: running scans must have null duration_seconds."""
        data = _get_view("scan_history")
        for item in data.get("scans", []):
            if item.get("status") == "running":
                assert item.get("duration_seconds") is None, (
                    f"running scan {item['scan_run_id']} must have null duration_seconds (AC6)"
                )

    def test_account_id_filter(self) -> None:
        """AC1: account_id query param is forwarded to onboarding engine."""
        # Use a clearly non-existent account to verify the filter param is accepted
        data = _get_view("scan_history", {"account_id": "00000000-0000-0000-0000-000000000000"})
        assert "scans" in data
        assert isinstance(data["scans"], list)
        # With a non-existent account_id, scans should be empty (AC5: no fallback)
        assert data["scans"] == [], "Non-existent account_id must return empty scans, not fallback"


@pytest.mark.skipif(_SKIP, reason=_SKIP_REASON)
class TestScanDetailContract:
    """AC3: GET /views/scan_detail?scan_run_id={id} returns per-engine breakdown."""

    def test_known_scan_returns_detail(self) -> None:
        # First get a real scan_run_id from history
        history = _get_view("scan_history")
        scans = history.get("scans", [])
        if not scans:
            pytest.skip("No scan history available to test detail view")

        scan_run_id = scans[0]["scan_run_id"]
        data = _get_view("scan_detail", {"scan_run_id": scan_run_id})

        assert isinstance(data, dict)
        assert data.get("scan_run_id") == scan_run_id
        assert "status" in data
        assert "engines_completed" in data
        assert isinstance(data["engines_completed"], list), (
            "engines_completed in scan_detail must be a list (AC7)"
        )
        assert "per_engine" in data, "scan_detail must return per_engine breakdown (AC3)"
        assert isinstance(data["per_engine"], dict)

    def test_unknown_scan_returns_404(self) -> None:
        data = _get_view("scan_detail", {"scan_run_id": "00000000-0000-0000-0000-000000000000"})
        assert data.get("_status_code") == 404 or "not found" in str(data).lower()


@pytest.mark.skipif(_SKIP, reason=_SKIP_REASON)
class TestScanRerunContract:
    """AC4: POST /views/scan_rerun returns 202 with a new scan_run_id."""

    def test_rerun_returns_new_scan_run_id(self) -> None:
        history = _get_view("scan_history")
        completed = [s for s in history.get("scans", []) if s.get("status") in ("completed", "failed")]
        if not completed:
            pytest.skip("No completed/failed scans available to test re-run")

        original_scan_run_id = completed[0]["scan_run_id"]
        resp = _post_view("scan_rerun", {"scan_run_id": original_scan_run_id})

        assert resp.get("_status_code") == 202, (
            f"scan_rerun must return 202, got {resp.get('_status_code')}"
        )
        assert "scan_run_id" in resp or "new_scan_run_id" in resp, (
            "scan_rerun response must contain a new scan_run_id"
        )
        new_id = resp.get("scan_run_id") or resp.get("new_scan_run_id")
        assert new_id != original_scan_run_id, (
            "Re-run must produce a DIFFERENT scan_run_id than the original (DoD)"
        )

    def test_rerun_unknown_id_returns_404(self) -> None:
        resp = _post_view("scan_rerun", {"scan_run_id": "00000000-0000-0000-0000-000000000000"})
        status = resp.get("_status_code")
        assert status == 404, f"Unknown scan_run_id must return 404, got {status}"
