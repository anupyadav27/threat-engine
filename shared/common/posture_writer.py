"""
posture_writer — shared utility for writing per-engine security signals to
resource_security_posture (threat_engine_inventory DB).

Each engine writes only the columns it owns.  The INSERT...ON CONFLICT pattern
ensures one row per (resource_uid, scan_run_id, tenant_id) and never overwrites
a different engine's columns.

Usage:
    from engine_common.posture_writer import upsert_posture_signals
    import psycopg2.extras

    with get_inventory_conn() as conn:
        row = upsert_posture_signals(
            conn,
            resource_uid="arn:aws:ec2:us-east-1:123456789012:instance/i-abc",
            scan_run_id="550e8400-e29b-41d4-a716-446655440000",
            tenant_id="my-tenant",
            account_id="123456789012",
            provider="aws",
            resource_type="ec2_instance",
            # IAM engine signals
            is_admin_role=True,
            role_has_wildcard_policy=True,
            iam_detail=psycopg2.extras.Json({"role_arn": "arn:aws:iam::..."}),
        )
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import psycopg2.extras

logger = logging.getLogger(__name__)

# Columns that callers must never pass as signals — they are identity fields or
# DB-managed.  Enforced at call time so mis-wired callers fail fast.
_IDENTITY_COLS = frozenset({
    "posture_id",
    "created_at",
})

# JSONB columns whose dict/list values must be wrapped in psycopg2.extras.Json.
# If a caller passes a plain dict/list we wrap it automatically.
_JSONB_COLS = frozenset({
    "network_detail",
    "iam_detail",
    "connected_db_uids",
    "cdr_ttps",
})

# Columns that are mandatory on every INSERT (not optional signals).
_REQUIRED_INSERT_COLS = (
    "resource_uid",
    "scan_run_id",
    "tenant_id",
    "account_id",
    "provider",
    "resource_type",
)


def upsert_posture_signals(
    conn: Any,
    resource_uid: str,
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
    resource_type: str,
    region: Optional[str] = None,
    resource_name: Optional[str] = None,
    **signals: Any,
) -> dict:
    """Upsert one engine's security signals into resource_security_posture.

    Only the columns present in ``signals`` (with non-None values) are written;
    all other columns remain unchanged.  Calling this function twice with
    disjoint kwargs merges both engines' data without data loss.

    Args:
        conn: psycopg2 connection owned by the caller.
        resource_uid: Canonical resource identifier (e.g. ARN or OCI OCID).
        scan_run_id: UUID of the current pipeline run.
        tenant_id: Tenant identifier — never NULL, enforces multi-tenant scope.
        account_id: Cloud account / subscription / project ID.
        provider: CSP identifier: aws / azure / gcp / oci / alicloud / k8s.
        resource_type: Normalised resource type (e.g. ec2_instance, s3_bucket).
        region: Cloud region; may be None for global resources.
        resource_name: Human-readable name; may be None.
        **signals: Per-engine columns to write.  None-valued entries are
            silently dropped.  Dict/list values for JSONB columns are
            auto-wrapped in psycopg2.extras.Json.

    Returns:
        The full row after upsert as a Python dict (via RETURNING *).

    Raises:
        ValueError: If a protected identity column is passed in signals.
        psycopg2.Error: Propagates DB errors to the caller for transaction
            handling.
    """
    if tenant_id is None:
        raise ValueError("upsert_posture_signals: tenant_id must not be None")
    _validate_signals(signals)

    # Filter out None-valued signals — these must not appear in the SET clause
    non_null: dict[str, Any] = {
        k: _coerce_jsonb(k, v)
        for k, v in signals.items()
        if v is not None
    }

    # Build base INSERT columns (always present)
    insert_cols = list(_REQUIRED_INSERT_COLS)
    insert_vals: list[Any] = [
        resource_uid,
        scan_run_id,
        tenant_id,
        account_id,
        provider,
        resource_type,
    ]

    if region is not None:
        insert_cols.append("region")
        insert_vals.append(region)
    if resource_name is not None:
        insert_cols.append("resource_name")
        insert_vals.append(resource_name)

    # Append signal columns to INSERT
    for col, val in non_null.items():
        insert_cols.append(col)
        insert_vals.append(val)

    col_list = ", ".join(insert_cols)
    placeholder_list = ", ".join(["%s"] * len(insert_cols))

    # ON CONFLICT: update only the signal columns that were passed
    if non_null:
        set_clauses = [f"{col} = EXCLUDED.{col}" for col in non_null]
    else:
        set_clauses = []

    # Always refresh updated_at; include optional identity fields if present
    if region is not None:
        set_clauses.append("region = EXCLUDED.region")
    if resource_name is not None:
        set_clauses.append("resource_name = EXCLUDED.resource_name")
    set_clauses.append("updated_at = NOW()")

    # ON CONFLICT targets (resource_uid, tenant_id) — the real unique constraint
    # (uq_rsp_resource_tenant). scan_run_id is updated on every conflict so the
    # row always reflects the latest scan.
    set_clauses.insert(0, "scan_run_id = EXCLUDED.scan_run_id")

    sql = f"""
        INSERT INTO resource_security_posture ({col_list})
        VALUES ({placeholder_list})
        ON CONFLICT (resource_uid, tenant_id)
        DO UPDATE SET {", ".join(set_clauses)}
        RETURNING *
    """

    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(sql, insert_vals)
        row = cur.fetchone()
        conn.commit()

    logger.debug(
        "upsert_posture_signals: upserted posture row",
        extra={
            "posture_id": str(row["posture_id"]) if row else None,
            "resource_uid": resource_uid,
            "tenant_id": tenant_id,
            "scan_run_id": str(scan_run_id),
            "signals_written": list(non_null.keys()),
        },
    )
    return dict(row) if row else {}


def _validate_signals(signals: dict[str, Any]) -> None:
    """Raise ValueError if caller passes a protected identity column."""
    forbidden = _IDENTITY_COLS & signals.keys()
    if forbidden:
        raise ValueError(
            f"upsert_posture_signals: forbidden signal columns: {sorted(forbidden)}. "
            "posture_id and created_at are DB-managed and must not be passed."
        )


def _coerce_jsonb(col: str, value: Any) -> Any:
    """Auto-wrap dict/list values for JSONB columns."""
    if col in _JSONB_COLS and isinstance(value, (dict, list)):
        return psycopg2.extras.Json(value)
    return value
