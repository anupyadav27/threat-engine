"""Tests for shared/common/security_findings_writer.py — SF-P0-02.

All DB interactions are mocked — no real DB connection required.
"""
from __future__ import annotations

import sys
import os
from unittest.mock import MagicMock, call

import pytest

# Make shared/common importable without package installation
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared", "common"))
from security_findings_writer import upsert_findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_conn() -> tuple[MagicMock, MagicMock]:
    """Return a (conn, cursor) mock pair wired for security_findings_writer usage."""
    mock_cursor = MagicMock()
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    return mock_conn, mock_cursor


def _make_finding(idx: int) -> dict:
    """Build a minimal valid FindingRow dict."""
    return {
        "source_finding_id": f"sha256-finding-{idx:04d}",
        "resource_uid": f"arn:aws:ec2:us-east-1:123456789012:instance/i-{idx:04d}",
        "finding_type": "misconfig",
        "severity": "high",
        "title": f"Test finding {idx}",
        "status": "open",
    }


# ---------------------------------------------------------------------------
# Test 1: Batching behaviour
# ---------------------------------------------------------------------------

class TestBatching:
    def test_upsert_findings_batches_correctly(self):
        """1100 rows must be flushed in exactly 3 batches: 500 + 500 + 100."""
        conn, cursor = _make_conn()
        findings = [_make_finding(i) for i in range(1100)]

        total = upsert_findings(
            conn,
            findings=findings,
            source_engine="check",
            tenant_id="tenant-abc",
            scan_run_id="550e8400-e29b-41d4-a716-446655440000",
            batch_size=500,
        )

        # Total returned must equal input count
        assert total == 1100

        # executemany must have been called exactly 3 times
        assert cursor.executemany.call_count == 3

        # Verify each batch size via the rows argument (second positional arg)
        batch_sizes = [len(c.args[1]) for c in cursor.executemany.call_args_list]
        assert batch_sizes == [500, 500, 100]

        # conn.commit must be called once per batch
        assert conn.commit.call_count == 3

    def test_upsert_findings_empty_list_returns_zero(self):
        """Empty findings list must return 0 without touching the DB."""
        conn, cursor = _make_conn()

        total = upsert_findings(
            conn,
            findings=[],
            source_engine="iam",
            tenant_id="tenant-abc",
            scan_run_id="550e8400-e29b-41d4-a716-446655440000",
        )

        assert total == 0
        cursor.executemany.assert_not_called()
        conn.commit.assert_not_called()


# ---------------------------------------------------------------------------
# Test 2: first_seen_at is never touched on conflict
# ---------------------------------------------------------------------------

class TestFirstSeenAtImmutability:
    def test_upsert_findings_never_updates_first_seen_at(self):
        """ON CONFLICT clause must update last_seen_at/updated_at, not first_seen_at."""
        conn, cursor = _make_conn()

        upsert_findings(
            conn,
            findings=[_make_finding(0)],
            source_engine="vuln",
            tenant_id="tenant-xyz",
            scan_run_id="660e8400-e29b-41d4-a716-446655440001",
        )

        # Retrieve the SQL string passed to executemany
        assert cursor.executemany.call_count == 1
        sql: str = cursor.executemany.call_args[0][0]

        # ON CONFLICT must update last_seen_at and updated_at
        conflict_section = sql.split("ON CONFLICT")[1]
        assert "last_seen_at" in conflict_section
        assert "updated_at" in conflict_section

        # first_seen_at must NOT appear anywhere in the DO UPDATE SET section
        do_update_section = sql.split("DO UPDATE SET")[1]
        assert "first_seen_at" not in do_update_section

    def test_first_seen_at_present_in_insert_columns(self):
        """first_seen_at must appear in the INSERT column list (set on first write)."""
        conn, cursor = _make_conn()

        upsert_findings(
            conn,
            findings=[_make_finding(0)],
            source_engine="cdr",
            tenant_id="tenant-xyz",
            scan_run_id="660e8400-e29b-41d4-a716-446655440001",
        )

        sql: str = cursor.executemany.call_args[0][0]
        insert_section = sql.split("VALUES")[0]
        assert "first_seen_at" in insert_section


# ---------------------------------------------------------------------------
# Test 3: Unknown engine raises ValueError
# ---------------------------------------------------------------------------

class TestEngineValidation:
    def test_upsert_findings_rejects_unknown_engine(self):
        """Passing an unknown source_engine must raise ValueError immediately."""
        conn, _ = _make_conn()

        with pytest.raises(ValueError, match="unknown source_engine"):
            upsert_findings(
                conn,
                findings=[_make_finding(0)],
                source_engine="threat",  # not in _ALLOWED_ENGINES
                tenant_id="tenant-abc",
                scan_run_id="550e8400-e29b-41d4-a716-446655440000",
            )

    def test_upsert_findings_accepts_all_allowed_engines(self):
        """Every engine in the allowed set must succeed without raising."""
        allowed = ["check", "iam", "network", "datasec", "vuln", "cdr", "container"]
        for engine in allowed:
            conn, _ = _make_conn()
            # Should not raise
            upsert_findings(
                conn,
                findings=[_make_finding(0)],
                source_engine=engine,
                tenant_id="tenant-abc",
                scan_run_id="550e8400-e29b-41d4-a716-446655440000",
            )

    def test_upsert_findings_rejects_empty_tenant_id(self):
        """Empty tenant_id must raise ValueError — never silently write cross-tenant."""
        conn, _ = _make_conn()

        with pytest.raises(ValueError, match="tenant_id"):
            upsert_findings(
                conn,
                findings=[_make_finding(0)],
                source_engine="check",
                tenant_id="",
                scan_run_id="550e8400-e29b-41d4-a716-446655440000",
            )

    def test_upsert_findings_rejects_none_tenant_id(self):
        """None tenant_id must raise ValueError."""
        conn, _ = _make_conn()

        with pytest.raises(ValueError, match="tenant_id"):
            upsert_findings(
                conn,
                findings=[_make_finding(0)],
                source_engine="check",
                tenant_id=None,  # type: ignore
                scan_run_id="550e8400-e29b-41d4-a716-446655440000",
            )
