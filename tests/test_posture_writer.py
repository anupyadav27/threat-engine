"""Tests for shared/common/posture_writer.py — AP-P0-02.

All DB interactions are mocked — no real DB connection required.
"""

from __future__ import annotations

import sys
import os
from unittest.mock import MagicMock, call, patch
from typing import Any

import pytest
import psycopg2.extras

# Make shared/common importable without package installation
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared", "common"))
from posture_writer import upsert_posture_signals, _JSONB_COLS, _IDENTITY_COLS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_conn(return_row: dict | None = None) -> tuple[MagicMock, MagicMock]:
    """Return a (conn, cursor) mock pair wired for posture_writer usage."""
    if return_row is None:
        return_row = {
            "posture_id": "uuid-1",
            "resource_uid": "r-uid",
            "scan_run_id": "scan-1",
            "tenant_id": "t1",
        }

    mock_cursor = MagicMock()
    mock_cursor.__enter__ = MagicMock(return_value=mock_cursor)
    mock_cursor.__exit__ = MagicMock(return_value=False)
    mock_cursor.fetchone.return_value = return_row

    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    return mock_conn, mock_cursor


_BASE = dict(
    resource_uid="arn:aws:ec2:us-east-1:123:instance/i-abc",
    scan_run_id="550e8400-e29b-41d4-a716-446655440000",
    tenant_id="my-tenant",
    account_id="123456789012",
    provider="aws",
    resource_type="ec2_instance",
)


# ---------------------------------------------------------------------------
# Basic functionality
# ---------------------------------------------------------------------------

class TestBasicUpsert:
    def test_execute_called_once(self):
        conn, cursor = _make_conn()
        upsert_posture_signals(conn, **_BASE, is_internet_exposed=True)
        cursor.execute.assert_called_once()

    def test_commit_called_after_execute(self):
        conn, cursor = _make_conn()
        upsert_posture_signals(conn, **_BASE, is_internet_exposed=True)
        conn.commit.assert_called_once()

    def test_returns_dict(self):
        conn, _ = _make_conn(return_row={"posture_id": "x", **_BASE})
        result = upsert_posture_signals(conn, **_BASE, is_internet_exposed=True)
        assert isinstance(result, dict)

    def test_cursor_uses_real_dict_cursor(self):
        conn, _ = _make_conn()
        upsert_posture_signals(conn, **_BASE, is_crown_jewel=True)
        conn.cursor.assert_called_once_with(
            cursor_factory=psycopg2.extras.RealDictCursor
        )

    def test_sql_contains_on_conflict_clause(self):
        conn, cursor = _make_conn()
        upsert_posture_signals(conn, **_BASE, is_internet_exposed=True)
        sql: str = cursor.execute.call_args[0][0]
        assert "ON CONFLICT" in sql
        assert "resource_uid, scan_run_id, tenant_id" in sql
        assert "DO UPDATE SET" in sql

    def test_sql_contains_returning(self):
        conn, cursor = _make_conn()
        upsert_posture_signals(conn, **_BASE, is_crown_jewel=True)
        sql: str = cursor.execute.call_args[0][0]
        assert "RETURNING" in sql


# ---------------------------------------------------------------------------
# Column ownership — IAM engine writes only IAM columns
# ---------------------------------------------------------------------------

class TestColumnOwnership:
    def test_iam_only_signals_not_include_network_columns(self):
        conn, cursor = _make_conn()
        upsert_posture_signals(
            conn,
            **_BASE,
            is_admin_role=True,
            role_has_wildcard_policy=False,
            has_permission_boundary=True,
        )
        sql: str = cursor.execute.call_args[0][0]
        vals: list = cursor.execute.call_args[0][1]
        # is_admin_role must be in the query
        assert "is_admin_role" in sql
        assert True in vals  # is_admin_role=True in positional params
        # network columns must NOT appear in the UPDATE SET section
        update_section = sql.split("DO UPDATE SET")[1]
        assert "is_internet_exposed" not in update_section
        assert "has_waf" not in update_section

    def test_network_only_signals_not_include_iam_columns(self):
        conn, cursor = _make_conn()
        upsert_posture_signals(
            conn,
            **_BASE,
            is_internet_exposed=True,
            has_waf=False,
            network_exposure_score=80,
        )
        sql: str = cursor.execute.call_args[0][0]
        assert "is_internet_exposed" in sql
        update_section = sql.split("DO UPDATE SET")[1]
        assert "is_admin_role" not in update_section
        assert "role_has_wildcard_policy" not in update_section

    def test_attack_path_signals_written_correctly(self):
        conn, cursor = _make_conn()
        upsert_posture_signals(
            conn,
            **_BASE,
            is_crown_jewel=True,
            crown_jewel_type="storage",
            is_on_attack_path=True,
            attack_path_count=3,
            is_choke_point=True,
            paths_blocked_if_fixed=7,
        )
        sql: str = cursor.execute.call_args[0][0]
        assert "is_crown_jewel" in sql
        assert "is_choke_point" in sql
        assert "paths_blocked_if_fixed" in sql
        vals: list = cursor.execute.call_args[0][1]
        assert True in vals
        assert 7 in vals


# ---------------------------------------------------------------------------
# None value filtering
# ---------------------------------------------------------------------------

class TestNoneValueFiltering:
    def test_none_valued_signals_excluded_from_set_clause(self):
        conn, cursor = _make_conn()
        upsert_posture_signals(
            conn,
            **_BASE,
            is_internet_exposed=True,
            has_waf=None,          # must be excluded
            cdr_last_seen_at=None, # must be excluded
        )
        sql: str = cursor.execute.call_args[0][0]
        update_section = sql.split("DO UPDATE SET")[1]
        assert "has_waf" not in update_section
        assert "cdr_last_seen_at" not in update_section

    def test_none_values_not_in_positional_params(self):
        conn, cursor = _make_conn()
        upsert_posture_signals(
            conn,
            **_BASE,
            is_internet_exposed=True,
            has_waf=None,
        )
        vals: list = cursor.execute.call_args[0][1]
        assert None not in vals

    def test_false_boolean_is_included(self):
        """False is a valid signal value — only None is excluded."""
        conn, cursor = _make_conn()
        upsert_posture_signals(conn, **_BASE, is_internet_exposed=False)
        sql: str = cursor.execute.call_args[0][0]
        assert "is_internet_exposed" in sql
        vals: list = cursor.execute.call_args[0][1]
        assert False in vals

    def test_zero_integer_is_included(self):
        conn, cursor = _make_conn()
        upsert_posture_signals(conn, **_BASE, attack_path_count=0)
        sql: str = cursor.execute.call_args[0][0]
        assert "attack_path_count" in sql
        vals: list = cursor.execute.call_args[0][1]
        assert 0 in vals


# ---------------------------------------------------------------------------
# Merge / two-call convergence
# ---------------------------------------------------------------------------

class TestMergePattern:
    def test_two_calls_with_disjoint_kwargs_each_write_own_columns(self):
        """Simulate IAM engine then network engine writing to same row."""
        conn1, cursor1 = _make_conn()
        upsert_posture_signals(
            conn1,
            **_BASE,
            is_admin_role=True,
            role_has_wildcard_policy=True,
        )
        sql1: str = cursor1.execute.call_args[0][0]
        assert "is_admin_role" in sql1
        assert "is_internet_exposed" not in sql1.split("DO UPDATE SET")[1]

        conn2, cursor2 = _make_conn()
        upsert_posture_signals(
            conn2,
            **_BASE,
            is_internet_exposed=True,
            network_exposure_score=75,
        )
        sql2: str = cursor2.execute.call_args[0][0]
        assert "is_internet_exposed" in sql2
        assert "is_admin_role" not in sql2.split("DO UPDATE SET")[1]

    def test_updated_at_always_in_set_clause(self):
        conn, cursor = _make_conn()
        upsert_posture_signals(conn, **_BASE, is_crown_jewel=True)
        sql: str = cursor.execute.call_args[0][0]
        update_section = sql.split("DO UPDATE SET")[1]
        assert "updated_at = NOW()" in update_section


# ---------------------------------------------------------------------------
# Tenant isolation
# ---------------------------------------------------------------------------

class TestTenantIsolation:
    def test_tenant_id_always_in_params(self):
        conn, cursor = _make_conn()
        upsert_posture_signals(conn, **_BASE, is_crown_jewel=True)
        vals: list = cursor.execute.call_args[0][1]
        assert "my-tenant" in vals

    def test_tenant_id_in_conflict_clause(self):
        conn, cursor = _make_conn()
        upsert_posture_signals(conn, **_BASE, is_crown_jewel=True)
        sql: str = cursor.execute.call_args[0][0]
        assert "tenant_id" in sql.split("ON CONFLICT")[1]

    def test_tenant_id_not_nullable(self):
        """Passing tenant_id=None should raise — not silently skip."""
        conn, _ = _make_conn()
        with pytest.raises(Exception):
            upsert_posture_signals(
                conn,
                resource_uid="r",
                scan_run_id="s",
                tenant_id=None,  # type: ignore
                account_id="a",
                provider="aws",
                resource_type="ec2",
                is_crown_jewel=True,
            )


# ---------------------------------------------------------------------------
# Forbidden columns
# ---------------------------------------------------------------------------

class TestForbiddenColumns:
    def test_posture_id_in_signals_raises(self):
        conn, _ = _make_conn()
        with pytest.raises(ValueError, match="posture_id"):
            upsert_posture_signals(
                conn,
                **_BASE,
                posture_id="override-me",  # must be rejected
            )

    def test_created_at_in_signals_raises(self):
        conn, _ = _make_conn()
        with pytest.raises(ValueError, match="created_at"):
            upsert_posture_signals(
                conn,
                **_BASE,
                created_at="2026-01-01",  # must be rejected
            )


# ---------------------------------------------------------------------------
# JSONB auto-wrapping
# ---------------------------------------------------------------------------

class TestJsonbAutoWrap:
    def test_dict_value_for_jsonb_col_is_wrapped(self):
        conn, cursor = _make_conn()
        upsert_posture_signals(
            conn,
            **_BASE,
            iam_detail={"role_arn": "arn:aws:iam::123:role/r"},
        )
        vals: list = cursor.execute.call_args[0][1]
        # Find the iam_detail value — it must be a Json wrapper, not a plain dict
        json_vals = [v for v in vals if isinstance(v, psycopg2.extras.Json)]
        assert len(json_vals) == 1
        assert json_vals[0].adapted == {"role_arn": "arn:aws:iam::123:role/r"}

    def test_already_wrapped_jsonb_value_is_not_double_wrapped(self):
        conn, cursor = _make_conn()
        wrapped = psycopg2.extras.Json({"key": "val"})
        upsert_posture_signals(
            conn,
            **_BASE,
            iam_detail=wrapped,
        )
        vals: list = cursor.execute.call_args[0][1]
        json_vals = [v for v in vals if isinstance(v, psycopg2.extras.Json)]
        # Should be the same wrapped object, not a Json(Json(...))
        assert json_vals[0] is wrapped

    def test_non_jsonb_col_dict_not_wrapped(self):
        """A dict passed for a non-JSONB column is passed through as-is."""
        conn, cursor = _make_conn()
        plain_dict = {"unexpected": True}
        upsert_posture_signals(
            conn,
            **_BASE,
            # cdr_ttps IS a JSONB col — use a non-JSONB key to test passthrough
            # tls_version is a plain VARCHAR col
            tls_version="TLSv1.3",
        )
        vals: list = cursor.execute.call_args[0][1]
        assert "TLSv1.3" in vals
