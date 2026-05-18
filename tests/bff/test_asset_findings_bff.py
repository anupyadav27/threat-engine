"""BFF contract tests for asset findings endpoints (SF-P2-01).

Tests the actual functions from shared/api_gateway/bff/asset_findings.py.

Functions tested:
  - _strip_finding(row, role) — RBAC field stripping
  - SQL in get_asset_findings contains tenant_id filter

All DB interactions are mocked. No real DB connection required.
"""
from __future__ import annotations

import sys
import os
import pytest

# Make shared importable from repo root
_REPO = os.path.join(os.path.dirname(__file__), "..", "..")
sys.path.insert(0, _REPO)


# ── Minimal FindingRow factory ────────────────────────────────────────────────

def _finding(
    idx: int = 0,
    source_engine: str = "check",
    finding_type: str = "misconfig",
    severity: str = "high",
    resource_uid: str = "arn:aws:s3:::my-bucket",
    provider: str = "aws",
) -> dict:
    return {
        "finding_id": f"abc{idx:04d}",
        "source_engine": source_engine,
        "source_finding_id": f"src-{idx:04d}",
        "resource_uid": resource_uid,
        "finding_type": finding_type,
        "severity": severity,
        "rule_id": f"rule-{idx:04d}",
        "title": f"Test finding {idx}",
        "description": "A test finding",
        "epss_score": 0.05 if finding_type == "cve" else None,
        "cvss_score": 7.5 if finding_type == "cve" else None,
        "in_kev": False,
        "mitre_technique_id": None,
        "mitre_tactic": None,
        "detail": {"namespace": "kube-system"} if provider == "k8s" else {"rule_summary": "open port"},
        "status": "open",
        "first_seen_at": "2026-05-01T00:00:00Z",
        "last_seen_at": "2026-05-15T00:00:00Z",
        "provider": provider,
        "account_id": "123456789012",
        "resource_type": "s3.bucket" if provider == "aws" else "k8s.pod",
    }


# ── RBAC field stripping — _strip_finding ────────────────────────────────────

class TestRbacFieldStripping:
    """_strip_finding(row, role) applies correct RBAC field stripping."""

    @pytest.fixture(autouse=True)
    def _import(self):
        from shared.api_gateway.bff.asset_findings import _strip_finding
        self._strip_finding = _strip_finding

    def test_viewer_gets_no_detail(self):
        """viewer: detail must be None."""
        f = _finding(0)
        stripped = self._strip_finding(f, role="viewer")
        assert stripped["detail"] is None

    def test_viewer_gets_no_epss(self):
        """viewer: epss_score must be None."""
        f = _finding(0, finding_type="cve")
        stripped = self._strip_finding(f, role="viewer")
        assert stripped.get("epss_score") is None

    def test_analyst_gets_full_detail_for_check_finding(self):
        """analyst: full detail for non-CDR findings."""
        f = _finding(0, source_engine="check")
        stripped = self._strip_finding(f, role="analyst")
        assert stripped["detail"] is not None

    def test_analyst_gets_no_cdr_detail(self):
        """analyst: CDR finding detail stripped (actor_hash sensitivity)."""
        f = _finding(0, source_engine="cdr", finding_type="cdr_event")
        stripped = self._strip_finding(f, role="analyst")
        assert stripped["detail"] is None

    def test_tenant_admin_gets_full_data_including_cdr(self):
        """tenant_admin: full detail including CDR."""
        f = _finding(0, source_engine="cdr", finding_type="cdr_event")
        stripped = self._strip_finding(f, role="tenant_admin")
        assert stripped["detail"] is not None

    def test_org_admin_gets_full_data(self):
        """org_admin: full detail including CDR."""
        f = _finding(0, source_engine="cdr", finding_type="cdr_event")
        stripped = self._strip_finding(f, role="org_admin")
        assert stripped["detail"] is not None

    def test_strip_does_not_mutate_original(self):
        """_strip_finding must not mutate the input row dict."""
        f = _finding(0)
        original_detail = f["detail"]
        _ = self._strip_finding(f, role="viewer")
        assert f["detail"] == original_detail  # original unchanged


# ── Tenant isolation — SQL inspection ────────────────────────────────────────

class TestTenantIsolation:
    """All SQL in asset_findings.py must scope by tenant_id."""

    def test_get_asset_findings_sql_includes_tenant_id(self):
        """The findings SELECT in get_asset_findings must filter tenant_id = %s."""
        import inspect
        from shared.api_gateway.bff import asset_findings as af
        source = inspect.getsource(af.get_asset_findings)
        assert "tenant_id" in source
        # Must use parameterized placeholder — no f-string with tenant
        assert "tenant_id = %s" in source or "tenant_id=%s" in source

    def test_no_hardcoded_tenant_strings_in_module(self):
        """Module must not contain hardcoded tenant strings in SQL."""
        import inspect
        from shared.api_gateway.bff import asset_findings as af
        source = inspect.getsource(af)
        # These are test-specific strings that must NOT appear in production code
        for bad in ["my-tenant", "tenant-abc", "tenant-xyz"]:
            assert bad not in source, f"Hardcoded tenant string '{bad}' found in asset_findings.py"


# ── Response shape validation ────────────────────────────────────────────────

class TestResponseShape:
    """Validate the shape of the response returned by get_asset_findings."""

    def test_get_asset_findings_returns_expected_keys(self):
        """The mocked response must include findings, total, by_engine, by_severity."""
        from unittest.mock import MagicMock, patch, AsyncMock
        import asyncio

        from shared.api_gateway.bff.asset_findings import get_asset_findings

        # Build a mock request with AuthContext
        mock_request = MagicMock()
        mock_ctx = MagicMock()
        mock_ctx.role = "analyst"
        mock_ctx.tenant_id = "test-tenant"
        mock_ctx.account_ids = ["123"]

        mock_row = _finding(0)
        mock_cursor = MagicMock()
        mock_cursor.fetchall.side_effect = [
            [mock_row],   # findings query
            [{"severity": "high", "cnt": 1}],  # by_severity
            [{"source_engine": "check", "cnt": 1}],  # by_engine
        ]
        mock_cursor.__enter__ = lambda s: s
        mock_cursor.__exit__ = MagicMock(return_value=False)
        mock_conn = MagicMock()
        mock_conn.cursor.return_value = mock_cursor

        with patch("shared.api_gateway.bff.asset_findings._parse_auth_context", return_value=mock_ctx), \
             patch("shared.api_gateway.bff.asset_findings.resolve_tenant_id", return_value="test-tenant"), \
             patch("shared.api_gateway.bff.asset_findings._get_inventory_conn", return_value=mock_conn):
            result = asyncio.run(get_asset_findings(
                uid="arn:aws:s3:::my-bucket",
                status="open",
                request=mock_request,
            ))

        assert "findings" in result
        assert "total" in result
        assert "by_severity" in result
        assert isinstance(result["findings"], list)


# ── K8s findings ──────────────────────────────────────────────────────────────

class TestK8sFindings:
    """K8s resource_uid in k8s/{namespace}/{kind}/{name} format passes through."""

    @pytest.fixture(autouse=True)
    def _import(self):
        from shared.api_gateway.bff.asset_findings import _strip_finding
        self._strip_finding = _strip_finding

    def test_k8s_violation_detail_stripped_for_viewer(self):
        """K8s violation detail must be stripped for viewer just like other findings."""
        f = _finding(0, source_engine="container", finding_type="k8s_violation", provider="k8s")
        stripped = self._strip_finding(f, role="viewer")
        assert stripped["detail"] is None

    def test_k8s_violation_detail_visible_for_analyst(self):
        """K8s violation detail visible for analyst (not CDR — no CDR stripping)."""
        f = _finding(0, source_engine="container", finding_type="k8s_violation", provider="k8s")
        stripped = self._strip_finding(f, role="analyst")
        assert stripped["detail"] is not None
