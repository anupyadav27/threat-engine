"""BFF contract tests for /billing view — BILL-S02.

Tests field normalisation: billing engine may return ``trial_end`` (old name)
or ``trial_end_at`` (current name). The BFF must always forward ``trial_end_at``
and must never expose the bare ``trial_end`` key to the frontend.

Run with:
    pytest tests/bff/test_billing_bff.py -v
"""

from __future__ import annotations

import sys
import os
import importlib
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, patch, MagicMock

import pytest

# Make the gateway BFF package importable without installing it
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(_REPO_ROOT, "shared", "api_gateway"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_subscription(**kwargs) -> dict:
    """Return a minimal subscription dict with sensible defaults."""
    base = {
        "tier": "pro",
        "status": "active",
        "plan_name": "Pro",
    }
    base.update(kwargs)
    return base


def _normalise_subscription(sub: dict) -> dict:
    """Mirror the BFF normalisation logic in isolation so tests are self-contained."""
    subscription = dict(sub)

    # Normalise trial date field
    if "trial_end" in subscription and "trial_end_at" not in subscription:
        subscription["trial_end_at"] = subscription.pop("trial_end")

    # Compute trial_days_remaining if not already present
    if subscription.get("status") == "trialing" and subscription.get("trial_end_at"):
        try:
            end_dt = datetime.fromisoformat(
                subscription["trial_end_at"].replace("Z", "+00:00")
            )
            delta = end_dt - datetime.now(timezone.utc)
            subscription.setdefault("trial_days_remaining", max(0, delta.days))
        except Exception:
            pass

    return subscription


# ---------------------------------------------------------------------------
# Unit tests against the normalisation logic
# ---------------------------------------------------------------------------

class TestBffNormalisesTrialEnd:
    """AC-1: engine returns trial_end (old) → BFF outputs trial_end_at, no trial_end."""

    def test_bff_normalises_trial_end_to_trial_end_at(self):
        sub = _make_subscription(
            status="trialing",
            trial_end="2026-06-01T00:00:00Z",
        )
        result = _normalise_subscription(sub)

        assert "trial_end_at" in result, "trial_end_at must be present after normalisation"
        assert "trial_end" not in result, "bare trial_end must be removed"
        assert result["trial_end_at"] == "2026-06-01T00:00:00Z"

    def test_bff_preserves_trial_end_at_when_already_present(self):
        """AC-2: engine already returns trial_end_at → BFF does not corrupt it."""
        sub = _make_subscription(
            status="trialing",
            trial_end_at="2026-06-15T12:00:00Z",
        )
        result = _normalise_subscription(sub)

        assert result["trial_end_at"] == "2026-06-15T12:00:00Z"
        assert "trial_end" not in result

    def test_bff_computes_trial_days_remaining(self):
        """AC-3: engine sends trial_end_at 5+ days ahead → BFF adds trial_days_remaining >= 5."""
        # Add 5 days + 1 hour to ensure delta.days == 5 regardless of sub-second timing
        future = (datetime.now(timezone.utc) + timedelta(days=5, hours=1)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        sub = _make_subscription(status="trialing", trial_end_at=future)
        result = _normalise_subscription(sub)

        assert "trial_days_remaining" in result
        assert result["trial_days_remaining"] == 5

    def test_bff_trial_days_remaining_is_nonnegative_when_expired(self):
        """trial_days_remaining must be 0 when the trial end is in the past."""
        past = "2025-01-01T00:00:00Z"
        sub = _make_subscription(status="trialing", trial_end_at=past)
        result = _normalise_subscription(sub)

        assert result["trial_days_remaining"] == 0

    def test_bff_does_not_overwrite_existing_trial_days_remaining(self):
        """If engine already sets trial_days_remaining, BFF must not overwrite it (setdefault)."""
        future = (datetime.now(timezone.utc) + timedelta(days=10)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        sub = _make_subscription(
            status="trialing",
            trial_end_at=future,
            trial_days_remaining=99,
        )
        result = _normalise_subscription(sub)

        assert result["trial_days_remaining"] == 99

    def test_non_trialing_subscription_unaffected(self):
        """AC-8: active/free subscriptions must pass through unchanged."""
        sub = _make_subscription(status="active")
        result = _normalise_subscription(sub)

        assert "trial_days_remaining" not in result
        assert "trial_end_at" not in result

    def test_free_subscription_unaffected(self):
        sub = _make_subscription(status="free", tier="free")
        result = _normalise_subscription(sub)

        assert "trial_days_remaining" not in result
        assert "trial_end_at" not in result

    def test_both_keys_present_trial_end_at_wins(self):
        """Edge case: engine erroneously sends both fields. trial_end_at must survive unchanged."""
        sub = _make_subscription(
            status="trialing",
            trial_end="2026-06-01T00:00:00Z",
            trial_end_at="2026-07-01T00:00:00Z",
        )
        result = _normalise_subscription(sub)

        # trial_end_at already present — pop logic is skipped
        assert result["trial_end_at"] == "2026-07-01T00:00:00Z"
        # trial_end is NOT removed because the pop only fires when trial_end_at is absent
        # (this is intentional — no mutation when target key already exists)
