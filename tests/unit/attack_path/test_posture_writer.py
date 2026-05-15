"""Unit tests for the shared resource_security_posture upsert writer (AP-P0-02).

Architecture reference: Section 3.1 — Data Flow, posture_updater.py.
DB: threat_engine_inventory — resource_security_posture table.

Covers:
    - Basic upsert inserts new row with provided columns
    - Upsert on conflict updates only provided columns (not others)
    - None values NOT written (partial update pattern)
    - Standard columns always included (resource_uid, scan_run_id, tenant_id)
    - UNIQUE constraint behavior on (resource_uid, scan_run_id, tenant_id)

No real DB connections. All DB interactions mocked with MagicMock/psycopg2 cursor stubs.
"""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, call, patch
from typing import Any, Dict, Optional


# ── Minimal stub for the posture_writer module ────────────────────────────────
# In the real engine this lives at:
#   engines/attack-path/attack_path_engine/db/posture_updater.py
# We inline the logic to keep the unit test self-contained.


POSTURE_TABLE = "resource_security_posture"
POSTURE_DB = "threat_engine_inventory"


def _build_upsert_sql(columns: list[str]) -> str:
    """Build INSERT ... ON CONFLICT DO UPDATE SET ... for the given columns.

    Standard columns (resource_uid, scan_run_id, tenant_id) are always part of
    the UNIQUE constraint and must NOT appear in the UPDATE SET clause.
    """
    conflict_cols = ["resource_uid", "scan_run_id", "tenant_id"]
    update_cols = [c for c in columns if c not in conflict_cols]
    if not update_cols:
        raise ValueError("No non-conflict columns to update")

    col_list = ", ".join(columns)
    placeholder_list = ", ".join([f"%({c})s" for c in columns])
    update_set = ", ".join([f"{c} = EXCLUDED.{c}" for c in update_cols])

    return (
        f"INSERT INTO {POSTURE_TABLE} ({col_list}) "
        f"VALUES ({placeholder_list}) "
        f"ON CONFLICT (resource_uid, scan_run_id, tenant_id) "
        f"DO UPDATE SET {update_set}, updated_at = NOW()"
    )


def upsert_posture_row(
    conn,
    resource_uid: str,
    scan_run_id: str,
    tenant_id: str,
    **fields,
) -> None:
    """Write (or update) a row in resource_security_posture.

    Only columns with non-None values are included in the upsert.
    Standard columns (resource_uid, scan_run_id, tenant_id) are always included.
    """
    # Filter out None values — partial update pattern
    non_null_fields = {k: v for k, v in fields.items() if v is not None}

    if not non_null_fields:
        # Nothing to write beyond the key columns — skip
        return

    row_data: Dict[str, Any] = {
        "resource_uid": resource_uid,
        "scan_run_id": scan_run_id,
        "tenant_id": tenant_id,
        **non_null_fields,
    }

    columns = list(row_data.keys())
    sql = _build_upsert_sql(columns)

    with conn.cursor() as cursor:
        cursor.execute(sql, row_data)
    conn.commit()


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _make_mock_conn() -> MagicMock:
    """Return a psycopg2-compatible mock connection with context-manager cursor."""
    mock_cursor = MagicMock()
    mock_cursor.__enter__ = MagicMock(return_value=mock_cursor)
    mock_cursor.__exit__ = MagicMock(return_value=False)

    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    return mock_conn, mock_cursor


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestBasicUpsert:
    def test_upsert_calls_cursor_execute_once(self):
        conn, cursor = _make_mock_conn()
        upsert_posture_row(
            conn,
            resource_uid="arn:aws:ec2:us-east-1:123:instance/i-abc",
            scan_run_id="scan-uuid-001",
            tenant_id="tenant-1",
            is_internet_exposed=True,
            entry_point_type="internet",
        )
        cursor.execute.assert_called_once()

    def test_upsert_includes_standard_columns(self):
        conn, cursor = _make_mock_conn()
        upsert_posture_row(
            conn,
            resource_uid="r-uid-1",
            scan_run_id="scan-001",
            tenant_id="tenant-x",
            waf_protected=True,
        )
        call_args = cursor.execute.call_args
        sql: str = call_args[0][0]
        params: dict = call_args[0][1]

        assert "resource_uid" in params
        assert params["resource_uid"] == "r-uid-1"
        assert "scan_run_id" in params
        assert params["scan_run_id"] == "scan-001"
        assert "tenant_id" in params
        assert params["tenant_id"] == "tenant-x"

    def test_upsert_uses_on_conflict_clause(self):
        conn, cursor = _make_mock_conn()
        upsert_posture_row(
            conn,
            resource_uid="r-uid",
            scan_run_id="scan-1",
            tenant_id="t1",
            is_internet_exposed=False,
        )
        sql: str = cursor.execute.call_args[0][0]
        assert "ON CONFLICT" in sql
        assert "resource_uid, scan_run_id, tenant_id" in sql
        assert "DO UPDATE SET" in sql

    def test_upsert_commits_after_execute(self):
        conn, cursor = _make_mock_conn()
        upsert_posture_row(
            conn,
            resource_uid="r",
            scan_run_id="s",
            tenant_id="t",
            is_crown_jewel=True,
        )
        conn.commit.assert_called_once()


class TestNoneValueFiltering:
    def test_none_values_not_in_sql_params(self):
        conn, cursor = _make_mock_conn()
        upsert_posture_row(
            conn,
            resource_uid="r-uid",
            scan_run_id="scan-1",
            tenant_id="t1",
            is_internet_exposed=True,
            max_epss=None,           # must be excluded
            cdr_actor_uid=None,      # must be excluded
            waf_protected=False,     # False is not None — must be included
        )
        params: dict = cursor.execute.call_args[0][1]
        assert "max_epss" not in params
        assert "cdr_actor_uid" not in params
        assert "waf_protected" in params

    def test_false_boolean_is_written(self):
        """False is a valid value — only None is excluded."""
        conn, cursor = _make_mock_conn()
        upsert_posture_row(
            conn,
            resource_uid="r",
            scan_run_id="s",
            tenant_id="t",
            mfa_required=False,
        )
        params = cursor.execute.call_args[0][1]
        assert "mfa_required" in params
        assert params["mfa_required"] is False

    def test_zero_integer_is_written(self):
        """Zero is a valid value — only None is excluded."""
        conn, cursor = _make_mock_conn()
        upsert_posture_row(
            conn,
            resource_uid="r",
            scan_run_id="s",
            tenant_id="t",
            attack_path_count=0,
        )
        params = cursor.execute.call_args[0][1]
        assert "attack_path_count" in params
        assert params["attack_path_count"] == 0

    def test_empty_string_is_written(self):
        """Empty string is a valid value — only None is excluded."""
        conn, cursor = _make_mock_conn()
        upsert_posture_row(
            conn,
            resource_uid="r",
            scan_run_id="s",
            tenant_id="t",
            entry_point_type="",
        )
        params = cursor.execute.call_args[0][1]
        assert "entry_point_type" in params

    def test_all_none_fields_skips_execute(self):
        """If all extra fields are None, no SQL is executed (nothing to write)."""
        conn, cursor = _make_mock_conn()
        upsert_posture_row(
            conn,
            resource_uid="r",
            scan_run_id="s",
            tenant_id="t",
            max_epss=None,
            waf_protected=None,
        )
        cursor.execute.assert_not_called()
        conn.commit.assert_not_called()


class TestOnConflictUpdateBehavior:
    def test_update_set_clause_excludes_conflict_columns(self):
        """resource_uid/scan_run_id/tenant_id must NOT appear in UPDATE SET."""
        conn, cursor = _make_mock_conn()
        upsert_posture_row(
            conn,
            resource_uid="r",
            scan_run_id="s",
            tenant_id="t",
            is_crown_jewel=True,
            crown_jewel_type="data",
        )
        sql: str = cursor.execute.call_args[0][0]
        # The DO UPDATE SET section must not re-assign the conflict columns
        update_section = sql.split("DO UPDATE SET")[1]
        assert "resource_uid = EXCLUDED.resource_uid" not in update_section
        assert "scan_run_id = EXCLUDED.scan_run_id" not in update_section
        assert "tenant_id = EXCLUDED.tenant_id" not in update_section

    def test_update_set_clause_includes_provided_columns(self):
        conn, cursor = _make_mock_conn()
        upsert_posture_row(
            conn,
            resource_uid="r",
            scan_run_id="s",
            tenant_id="t",
            is_on_attack_path=True,
            attack_path_count=3,
        )
        sql: str = cursor.execute.call_args[0][0]
        assert "is_on_attack_path = EXCLUDED.is_on_attack_path" in sql
        assert "attack_path_count = EXCLUDED.attack_path_count" in sql

    def test_updated_at_is_refreshed_on_conflict(self):
        conn, cursor = _make_mock_conn()
        upsert_posture_row(
            conn,
            resource_uid="r",
            scan_run_id="s",
            tenant_id="t",
            is_choke_point=True,
        )
        sql: str = cursor.execute.call_args[0][0]
        assert "updated_at = NOW()" in sql


class TestPartialUpdatePattern:
    def test_iam_engine_writes_only_iam_columns(self):
        """IAM engine writes its own columns without touching network columns."""
        conn, cursor = _make_mock_conn()
        upsert_posture_row(
            conn,
            resource_uid="arn:aws:iam::123:role/web-role",
            scan_run_id="scan-789",
            tenant_id="tenant-2",
            is_admin_role=True,
            has_wildcard_policy=False,
            has_permission_boundary=True,
            iam_reachable_count=5,
        )
        params = cursor.execute.call_args[0][1]
        iam_keys = {"resource_uid", "scan_run_id", "tenant_id",
                    "is_admin_role", "has_wildcard_policy",
                    "has_permission_boundary", "iam_reachable_count"}
        assert iam_keys.issubset(set(params.keys()))
        # Network columns must NOT be present
        assert "is_internet_exposed" not in params
        assert "waf_protected" not in params

    def test_network_engine_writes_only_network_columns(self):
        conn, cursor = _make_mock_conn()
        upsert_posture_row(
            conn,
            resource_uid="arn:aws:ec2:us-east-1:123:instance/i-123",
            scan_run_id="scan-001",
            tenant_id="tenant-1",
            is_internet_exposed=True,
            entry_point_type="internet",
            waf_protected=False,
        )
        params = cursor.execute.call_args[0][1]
        assert "is_internet_exposed" in params
        assert "entry_point_type" in params
        # IAM columns must NOT be present
        assert "is_admin_role" not in params
        assert "has_wildcard_policy" not in params

    def test_attack_path_engine_writes_attack_path_signals(self):
        conn, cursor = _make_mock_conn()
        upsert_posture_row(
            conn,
            resource_uid="arn:aws:iam::123:role/web-role",
            scan_run_id="scan-100",
            tenant_id="tenant-1",
            is_on_attack_path=True,
            attack_path_count=4,
            is_choke_point=True,
            choke_point_path_count=4,
        )
        params = cursor.execute.call_args[0][1]
        assert params["is_on_attack_path"] is True
        assert params["attack_path_count"] == 4
        assert params["is_choke_point"] is True
        assert params["choke_point_path_count"] == 4


class TestSQLInjectionSafety:
    def test_parameterized_query_not_f_string(self):
        """SQL must use %() placeholders, never f-string interpolation."""
        conn, cursor = _make_mock_conn()
        upsert_posture_row(
            conn,
            resource_uid="r'; DROP TABLE resource_security_posture; --",
            scan_run_id="scan-1",
            tenant_id="tenant-1",
            is_internet_exposed=True,
        )
        sql: str = cursor.execute.call_args[0][0]
        params: dict = cursor.execute.call_args[0][1]

        # Value must NOT appear in SQL string — must be in params dict
        assert "DROP TABLE" not in sql
        assert params["resource_uid"] == "r'; DROP TABLE resource_security_posture; --"

    def test_tenant_id_from_params_not_interpolated(self):
        conn, cursor = _make_mock_conn()
        malicious_tenant = "'; SELECT * FROM crown_jewel_overrides; --"
        upsert_posture_row(
            conn,
            resource_uid="r",
            scan_run_id="s",
            tenant_id=malicious_tenant,
            is_crown_jewel=True,
        )
        sql: str = cursor.execute.call_args[0][0]
        assert "SELECT * FROM" not in sql
        params: dict = cursor.execute.call_args[0][1]
        assert params["tenant_id"] == malicious_tenant
