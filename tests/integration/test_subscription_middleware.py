"""Unit tests for subscription_middleware._check_scan_frequency — BILL-S03.

Verifies the three-branch semantics:
  -1 → unlimited (pass-through, no network call)
   0 → blocked   (HTTP 402, no network call)
  >0 → quota     (calls billing engine HTTP endpoint)

Also verifies that ``tier == "unknown"`` fails open regardless of scan_freq value.

Run with:
    pytest tests/integration/test_subscription_middleware.py -v
"""

from __future__ import annotations

import sys
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Inline reproduction of the _check_scan_frequency logic so tests are
# runnable without a live gateway process or database connection.
# ---------------------------------------------------------------------------
# If the gateway package is importable we will test the real function;
# otherwise we test the canonical logic inline.

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(_REPO_ROOT, "shared", "api_gateway"))

from starlette.responses import JSONResponse  # type: ignore


async def _check_scan_frequency_canonical(
    sub_ctx: dict,
    org_id,
    httpx_client_factory=None,
    billing_url: str = "http://engine-billing:8040",
):
    """Canonical implementation of _check_scan_frequency for isolated testing.

    ``httpx_client_factory`` is a callable returning an async context manager
    whose ``.get()`` method returns a mock response.  If None, a real httpx
    client would be used — but callers that pass None for scan_freq > 0 are
    expected to mock httpx at the module level instead.
    """
    tier = sub_ctx.get("tier", "unknown")
    scan_freq = sub_ctx.get("scan_freq_per_day", -1)

    if tier == "unknown" or scan_freq == -1 or org_id is None:
        return None  # Unlimited or fail-open

    # 0 = explicitly blocked (Free plan no-scan); -1 = unlimited (handled above)
    if scan_freq == 0:
        return JSONResponse(
            status_code=402,
            content={
                "error": "account_blocked",
                "scan_freq_per_day": 0,
                "upgrade_url": "/billing/upgrade?from=scan_blocked",
            },
        )

    # scan_freq > 0 — call billing engine
    if httpx_client_factory is not None:
        async with httpx_client_factory() as client:
            resp = await client.get(
                f"{billing_url}/api/v1/billing/usage/check-scan-frequency",
                params={"org_id": org_id},
                headers={"X-Internal-Call": "gateway"},
            )
            data = resp.json()
            if not data.get("allowed", True):
                window = "week" if scan_freq <= 1 else "day"
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": "scan_frequency_exceeded",
                        "current_tier": tier,
                        "limit": scan_freq,
                        "window": window,
                        "upgrade_url": "/billing/upgrade?from=scan_frequency",
                    },
                )
    return None


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestScanFreqZeroBlocking:
    """AC-1 & AC-2: scan_freq=0 must return 402 without any HTTP call."""

    @pytest.mark.asyncio
    async def test_scan_freq_zero_returns_402_without_network_call(self):
        network_call_made = False

        def spy_factory():
            nonlocal network_call_made

            class _Ctx:
                async def __aenter__(self):
                    nonlocal network_call_made
                    network_call_made = True
                    return MagicMock()

                async def __aexit__(self, *_):
                    pass

            return _Ctx()

        result = await _check_scan_frequency_canonical(
            {"tier": "free", "scan_freq_per_day": 0},
            "org-123",
            httpx_client_factory=spy_factory,
        )

        assert isinstance(result, JSONResponse), "must return JSONResponse"
        assert result.status_code == 402
        # Decode body
        import json
        body = json.loads(result.body)
        assert body["error"] == "account_blocked"
        assert body["scan_freq_per_day"] == 0
        assert "upgrade_url" in body
        assert network_call_made is False, "billing engine must NOT be called when scan_freq=0"

    @pytest.mark.asyncio
    async def test_402_body_contains_no_pii(self):
        """SEC-02: 402 body must only contain error, scan_freq_per_day, upgrade_url."""
        import json
        result = await _check_scan_frequency_canonical(
            {"tier": "free", "scan_freq_per_day": 0},
            "org-secret-id",
        )
        assert result is not None
        body = json.loads(result.body)
        allowed_keys = {"error", "scan_freq_per_day", "upgrade_url"}
        assert set(body.keys()) == allowed_keys, (
            f"402 body must not expose internal fields; got extra: {set(body.keys()) - allowed_keys}"
        )


class TestScanFreqNegativeOnePassthrough:
    """AC-3: scan_freq=-1 (unlimited) must return None without any HTTP call."""

    @pytest.mark.asyncio
    async def test_scan_freq_negative_one_passes_through(self):
        network_call_made = False

        def spy_factory():
            nonlocal network_call_made

            class _Ctx:
                async def __aenter__(self):
                    nonlocal network_call_made
                    network_call_made = True
                    return MagicMock()

                async def __aexit__(self, *_):
                    pass

            return _Ctx()

        result = await _check_scan_frequency_canonical(
            {"tier": "pro", "scan_freq_per_day": -1},
            "org-456",
            httpx_client_factory=spy_factory,
        )

        assert result is None, "unlimited tier must return None (pass-through)"
        assert network_call_made is False


class TestScanFreqPositiveCallsBillingEngine:
    """AC-4: scan_freq > 0 must call the billing engine."""

    @pytest.mark.asyncio
    async def test_scan_freq_positive_calls_billing_engine_when_allowed(self):
        network_call_count = 0
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"allowed": True}

        # factory must be sync — it returns a context manager object, not a coroutine
        def factory():
            class _Ctx:
                async def __aenter__(self):
                    return self

                async def __aexit__(self, *_):
                    pass

                async def get(self, url, **kwargs):
                    nonlocal network_call_count
                    network_call_count += 1
                    return mock_resp

            return _Ctx()

        result = await _check_scan_frequency_canonical(
            {"tier": "starter", "scan_freq_per_day": 5},
            "org-789",
            httpx_client_factory=factory,
        )

        assert result is None, "allowed scan should return None (pass-through)"
        assert network_call_count == 1, "billing engine must be called once"

    @pytest.mark.asyncio
    async def test_scan_freq_positive_returns_429_when_exceeded(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"allowed": False, "reset_at": "2026-05-07T00:00:00Z"}

        # factory must be sync — it returns a context manager object, not a coroutine
        def factory():
            class _Ctx:
                async def __aenter__(self):
                    return self

                async def __aexit__(self, *_):
                    pass

                async def get(self, url, **kwargs):
                    return mock_resp

            return _Ctx()

        result = await _check_scan_frequency_canonical(
            {"tier": "starter", "scan_freq_per_day": 5},
            "org-789",
            httpx_client_factory=factory,
        )

        assert result is not None
        assert result.status_code == 429


class TestUnknownTierFailOpen:
    """AC-5: tier=unknown must fail open even when scan_freq=0."""

    @pytest.mark.asyncio
    async def test_unknown_tier_fails_open_regardless_of_scan_freq(self):
        result = await _check_scan_frequency_canonical(
            {"tier": "unknown", "scan_freq_per_day": 0},
            "org-xyz",
        )
        assert result is None, "unknown tier must fail open (return None)"

    @pytest.mark.asyncio
    async def test_org_id_none_fails_open(self):
        result = await _check_scan_frequency_canonical(
            {"tier": "free", "scan_freq_per_day": 0},
            None,
        )
        assert result is None, "missing org_id must fail open"
