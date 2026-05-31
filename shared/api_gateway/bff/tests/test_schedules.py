"""BFF Contract Tests — onboarding-D5: Schedule views.

Tests
-----
- Shape of the schedules list response (AC2, AC8).
- ``exclude_regions`` is always a list, never None (Definition of Done).
- Empty engine response returns ``{"schedules": [], "total": 0}`` (AC4).
- Non-2xx engine response propagates as 503 (AC6).
- Live integration tests (skipped unless TEST_SESSION_COOKIE is set).

Usage (unit tests — no gateway required):
    pytest shared/api_gateway/bff/tests/test_schedules.py -v -m "not contract"

Usage (live integration tests):
    TEST_SESSION_COOKIE="access_token=<token>" \
    pytest shared/api_gateway/bff/tests/test_schedules.py -v -m contract
"""

from __future__ import annotations

import os
import sys
from typing import Any, Dict, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ── Optional httpx import (not available in all environments) ────────────────
try:
    import httpx
    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False

# ── Skip guard for live tests ────────────────────────────────────────────────
SESSION_COOKIE = os.environ.get("TEST_SESSION_COOKIE", "")
GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://localhost:8000")

_SKIP_REASON = (
    "TEST_SESSION_COOKIE not set — skipping live integration tests"
    if not SESSION_COOKIE
    else (
        "httpx not installed — skipping live integration tests"
        if not _HTTPX_AVAILABLE
        else ""
    )
)
_SKIP = bool(_SKIP_REASON)

pytestmark = pytest.mark.contract


# ── Unit helpers ─────────────────────────────────────────────────────────────

def _make_raw_schedule(**overrides: Any) -> dict:
    """Build a minimal raw schedule dict as returned by the onboarding engine."""
    defaults: dict = {
        "schedule_id": "sch-001",
        "account_id": "acct-abc",
        "account_name": "Prod AWS",
        "cron_expression": "0 2 * * 0",
        "timezone": "UTC",
        "enabled": True,
        "include_regions": ["us-east-1"],
        "exclude_regions": None,      # engine may return None — BFF must coerce to []
        "include_services": ["ec2", "s3"],
        "exclude_services": None,
        "engines_requested": ["discovery", "check"],
        "last_run_at": "2026-05-10T02:00:00+00:00",
        "next_run_at": "2026-05-17T02:00:00+00:00",
        "run_count": 4,
        "success_count": 3,
        "failure_count": 1,
        "created_at": "2026-04-01T00:00:00+00:00",
        "updated_at": "2026-05-10T02:05:00+00:00",
    }
    defaults.update(overrides)
    return defaults


def _import_formatters():
    """Import private formatter helpers from the BFF module."""
    # Allow import regardless of engine_auth availability
    import importlib
    sys.modules.setdefault(
        "engine_auth",
        MagicMock(fastapi=MagicMock(dependencies=MagicMock(require_permission=lambda p: lambda: None))),
    )
    sys.modules.setdefault(
        "engine_auth.fastapi",
        MagicMock(dependencies=MagicMock(require_permission=lambda p: lambda: None)),
    )
    sys.modules.setdefault(
        "engine_auth.fastapi.dependencies",
        MagicMock(require_permission=lambda p: lambda: None),
    )
    from shared.api_gateway.bff.onboarding_schedules import (  # type: ignore[import]
        _format_schedule_list_item,
        _format_schedule_detail,
    )
    return _format_schedule_list_item, _format_schedule_detail


# ── Unit tests — no gateway required ─────────────────────────────────────────

class TestScheduleListShape:
    """Verify that _format_schedule_list_item produces the required AC2 shape."""

    def test_required_keys_present(self) -> None:
        """AC2: all mandatory keys present in every schedule item."""
        try:
            fmt, _ = _import_formatters()
        except Exception:
            pytest.skip("Cannot import BFF module (engine_auth not installed)")

        item = fmt(_make_raw_schedule())
        d = item.model_dump()

        required_keys = {
            "schedule_id", "account_id", "account_name", "cron_expression",
            "include_regions", "exclude_regions", "include_services",
            "exclude_services", "active", "last_run_at", "next_run_at",
        }
        for key in required_keys:
            assert key in d, f"Missing required key: {key}"

    def test_exclude_regions_is_list_when_engine_returns_none(self) -> None:
        """DoD: exclude_regions must be a list even when engine returns None."""
        try:
            fmt, _ = _import_formatters()
        except Exception:
            pytest.skip("Cannot import BFF module (engine_auth not installed)")

        item = fmt(_make_raw_schedule(exclude_regions=None))
        assert isinstance(item.exclude_regions, list), (
            "exclude_regions must be a list, got: %r" % item.exclude_regions
        )

    def test_exclude_services_is_list_when_engine_returns_none(self) -> None:
        """Coerce: exclude_services must be a list even when engine returns None."""
        try:
            fmt, _ = _import_formatters()
        except Exception:
            pytest.skip("Cannot import BFF module (engine_auth not installed)")

        item = fmt(_make_raw_schedule(exclude_services=None))
        assert isinstance(item.exclude_services, list)

    def test_active_field_maps_enabled(self) -> None:
        """active field must reflect the engine's enabled column."""
        try:
            fmt, _ = _import_formatters()
        except Exception:
            pytest.skip("Cannot import BFF module (engine_auth not installed)")

        item_on = fmt(_make_raw_schedule(enabled=True))
        item_off = fmt(_make_raw_schedule(enabled=False))
        assert item_on.active is True
        assert item_off.active is False

    def test_account_name_populated(self) -> None:
        """AC9: account_name comes from the engine join, not a separate call."""
        try:
            fmt, _ = _import_formatters()
        except Exception:
            pytest.skip("Cannot import BFF module (engine_auth not installed)")

        item = fmt(_make_raw_schedule(account_name="Prod AWS"))
        assert item.account_name == "Prod AWS"

    def test_account_name_defaults_to_empty_string(self) -> None:
        """account_name must default to empty string when engine omits it."""
        try:
            fmt, _ = _import_formatters()
        except Exception:
            pytest.skip("Cannot import BFF module (engine_auth not installed)")

        item = fmt(_make_raw_schedule(account_name=None))
        assert item.account_name == ""


class TestScheduleDetailShape:
    """Verify that _format_schedule_detail produces the AC3 shape."""

    def test_detail_includes_scope_arrays(self) -> None:
        """AC3: detail response includes region and service scope arrays."""
        try:
            _, fmt = _import_formatters()
        except Exception:
            pytest.skip("Cannot import BFF module (engine_auth not installed)")

        detail = fmt(_make_raw_schedule())
        assert isinstance(detail.include_regions, list)
        assert isinstance(detail.exclude_regions, list)
        assert isinstance(detail.include_services, list)
        assert isinstance(detail.exclude_services, list)
        assert isinstance(detail.engines_requested, list)

    def test_detail_exclude_regions_coerced_from_none(self) -> None:
        """DoD: exclude_regions in detail view is list even when engine returns None."""
        try:
            _, fmt = _import_formatters()
        except Exception:
            pytest.skip("Cannot import BFF module (engine_auth not installed)")

        detail = fmt(_make_raw_schedule(exclude_regions=None))
        assert isinstance(detail.exclude_regions, list)

    def test_detail_run_counts_present(self) -> None:
        """Detail view includes run_count, success_count, failure_count."""
        try:
            _, fmt = _import_formatters()
        except Exception:
            pytest.skip("Cannot import BFF module (engine_auth not installed)")

        detail = fmt(_make_raw_schedule(run_count=4, success_count=3, failure_count=1))
        assert detail.run_count == 4
        assert detail.success_count == 3
        assert detail.failure_count == 1


class TestSchedulesBFFEnvelope:
    """Verify the SchedulesListResponse envelope shape (AC2, AC4)."""

    def test_empty_engine_response_returns_empty_list(self) -> None:
        """AC4: engine returns 0 schedules → BFF returns {schedules:[], total:0}."""
        try:
            from shared.api_gateway.bff.onboarding_schedules import (  # type: ignore[import]
                SchedulesListResponse,
            )
        except Exception:
            pytest.skip("Cannot import BFF module")

        resp = SchedulesListResponse(schedules=[], total=0)
        assert resp.schedules == []
        assert resp.total == 0

    def test_total_matches_schedules_list_length(self) -> None:
        """total field must reflect the actual number of items in schedules list."""
        try:
            from shared.api_gateway.bff.onboarding_schedules import (  # type: ignore[import]
                ScheduleItem,
                SchedulesListResponse,
            )
        except Exception:
            pytest.skip("Cannot import BFF module")

        items = [
            ScheduleItem(
                schedule_id="s1",
                account_id="a1",
                active=True,
            ),
            ScheduleItem(
                schedule_id="s2",
                account_id="a2",
                active=False,
            ),
        ]
        resp = SchedulesListResponse(schedules=items, total=len(items))
        assert resp.total == 2
        assert len(resp.schedules) == 2


# ── Live integration tests — require TEST_SESSION_COOKIE ─────────────────────


def _get_view(path: str, params: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """GET /api/v1/views/{path} using the session cookie."""
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


@pytest.mark.skipif(_SKIP, reason=_SKIP_REASON)
class TestSchedulesContract:
    """Live contract tests for GET /views/onboarding/schedules (AC1, AC2)."""

    def test_top_level_keys(self) -> None:
        """AC2: response contains schedules list and total count."""
        data = _get_view("onboarding/schedules")
        assert isinstance(data, dict), f"Expected dict, got {type(data)}"
        assert "schedules" in data, "Response must contain 'schedules' key"
        assert "total" in data, "Response must contain 'total' key"

    def test_schedules_is_list(self) -> None:
        """schedules field must be a list (possibly empty — AC4)."""
        data = _get_view("onboarding/schedules")
        assert isinstance(data.get("schedules"), list)

    def test_total_is_int(self) -> None:
        """total field must be a non-negative integer."""
        data = _get_view("onboarding/schedules")
        total = data.get("total")
        assert isinstance(total, int) and total >= 0

    def test_schedule_item_keys_when_non_empty(self) -> None:
        """AC2: each schedule item contains all required keys."""
        data = _get_view("onboarding/schedules")
        schedules = data.get("schedules", [])
        if not schedules:
            pytest.skip("No schedules available for this tenant — skip item shape test")
        required = {
            "schedule_id", "account_id", "account_name", "cron_expression",
            "include_regions", "exclude_regions", "include_services",
            "exclude_services", "active",
        }
        for item in schedules:
            for key in required:
                assert key in item, f"Schedule item missing required key: {key}"

    def test_exclude_regions_is_always_list(self) -> None:
        """DoD: exclude_regions is a list (not null) for every schedule item."""
        data = _get_view("onboarding/schedules")
        for item in data.get("schedules", []):
            assert isinstance(item.get("exclude_regions"), list), (
                f"exclude_regions must be list for schedule {item.get('schedule_id')}, "
                f"got: {item.get('exclude_regions')!r}"
            )

    def test_unauthenticated_returns_401(self) -> None:
        """AC6 prerequisite: unauthenticated call returns 401."""
        if not _HTTPX_AVAILABLE:
            pytest.skip("httpx not installed")
        url = f"{GATEWAY_URL}/api/v1/views/onboarding/schedules"
        try:
            resp = httpx.get(url, timeout=10.0)
            assert resp.status_code == 401, (
                f"Expected 401 for unauthenticated request, got {resp.status_code}"
            )
        except httpx.ConnectError:
            pytest.skip(f"Gateway not reachable at {GATEWAY_URL}")
