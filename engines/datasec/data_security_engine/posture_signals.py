"""
Write datasec engine posture signals to resource_security_posture after scan.

Called at the end of run_scan.py after datasec_findings are persisted.
Queries datasec_data_catalog and datasec_findings to extract data-owned columns:
    data_classification, reachable_pii_store_count, has_exfil_path,
    secrets_in_env_vars, can_access_pii

Column ownership: datasec engine writes ONLY these columns.
"""

from __future__ import annotations

import logging
from typing import Any

import psycopg2.extras

from engine_common.db_connections import get_datasec_conn, get_di_conn
from engine_common.posture_writer import upsert_posture_signals

logger = logging.getLogger(__name__)

_BATCH_SIZE = 500

# Classification values that indicate PII/sensitive data
_PII_CLASSIFICATIONS = {"pii", "phi", "pci", "restricted", "confidential"}


def write_datasec_posture_signals(
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
) -> int:
    """Aggregate datasec signals from datasec_data_catalog and upsert to posture table.

    Returns number of posture rows written.
    """
    try:
        signals_by_uid = _aggregate_datasec_signals(scan_run_id, tenant_id)
        if not signals_by_uid:
            logger.info("DataSec posture signals: no datasec findings for scan %s", scan_run_id)
            return 0

        inv_conn = get_di_conn()
        try:
            written = _batch_upsert(
                inv_conn, signals_by_uid,
                scan_run_id, tenant_id, account_id, provider,
            )
            logger.info("DataSec posture signals: wrote %d rows for scan %s", written, scan_run_id)
            return written
        finally:
            inv_conn.close()

    except Exception as exc:
        logger.warning("DataSec posture signal write failed (non-fatal): %s", exc, exc_info=True)
        return 0


def _aggregate_datasec_signals(scan_run_id: str, tenant_id: str) -> dict[str, dict[str, Any]]:
    """Query datasec tables and aggregate per resource_uid."""
    ds_conn = get_datasec_conn()
    signals: dict[str, dict[str, Any]] = {}

    try:
        # Primary: datasec_data_catalog has classification per resource
        with ds_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            try:
                cur.execute("""
                    SELECT
                        resource_uid,
                        resource_type,
                        data_classification
                    FROM datasec_data_catalog
                    WHERE scan_run_id = %s AND tenant_id = %s AND resource_uid IS NOT NULL
                """, (scan_run_id, tenant_id))

                for row in cur.fetchall():
                    uid = row["resource_uid"]
                    raw_cls = row.get("data_classification") or []
                    # data_classification is a JSONB/text[] — already a list in psycopg2
                    if isinstance(raw_cls, str):
                        raw_cls = [raw_cls]
                    classifications = [c.lower() for c in raw_cls if c]

                    # Pick the highest classification
                    top_cls = _pick_top_classification(classifications)
                    has_pii = any(c in _PII_CLASSIFICATIONS for c in classifications)

                    signals[uid] = {
                        "resource_type": row.get("resource_type", "storage"),
                        "data_classification": top_cls,
                        "can_access_pii": has_pii,
                    }

            except Exception as cat_exc:
                logger.debug("datasec_data_catalog query failed: %s — trying datasec_findings", cat_exc)

        # Fallback: datasec_findings if catalog is empty
        if not signals:
            with ds_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT
                        resource_uid,
                        resource_type,
                        data_classification
                    FROM datasec_findings
                    WHERE scan_run_id = %s AND tenant_id = %s AND resource_uid IS NOT NULL
                """, (scan_run_id, tenant_id))

                for row in cur.fetchall():
                    uid = row["resource_uid"]
                    if uid in signals:
                        continue
                    raw_cls = row.get("data_classification") or []
                    if isinstance(raw_cls, str):
                        raw_cls = [raw_cls]
                    classifications = [c.lower() for c in raw_cls if c]
                    top_cls = _pick_top_classification(classifications)
                    has_pii = any(c in _PII_CLASSIFICATIONS for c in classifications)

                    signals[uid] = {
                        "resource_type": row.get("resource_type", "storage"),
                        "data_classification": top_cls,
                        "can_access_pii": has_pii,
                    }

        # Check for exfil-path and secrets-in-env rules from datasec_findings
        with ds_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT resource_uid, rule_id, status
                FROM datasec_findings
                WHERE scan_run_id = %s AND tenant_id = %s
                  AND resource_uid IS NOT NULL
                  AND (rule_id ILIKE '%%exfil%%' OR rule_id ILIKE '%%secret%%'
                       OR rule_id ILIKE '%%env_var%%' OR rule_id ILIKE '%%env%%')
            """, (scan_run_id, tenant_id))
            for row in cur.fetchall():
                uid = row["resource_uid"]
                rule_id = (row.get("rule_id") or "").lower()
                if uid in signals and row.get("status") == "FAIL":
                    if "exfil" in rule_id:
                        signals[uid]["has_exfil_path"] = True
                    if "secret" in rule_id or "env" in rule_id:
                        signals[uid]["secrets_in_env_vars"] = True

    finally:
        ds_conn.close()

    return signals


def _pick_top_classification(classifications: list[str]) -> str:
    """Return the highest sensitivity classification from a list."""
    _ORDER = ["restricted", "pii", "phi", "pci", "confidential", "internal", "public", "unknown"]
    for cls in _ORDER:
        if cls in classifications:
            return cls
    return "unknown"


def _batch_upsert(
    inv_conn: Any,
    signals_by_uid: dict[str, dict[str, Any]],
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
) -> int:
    """Upsert signals in batches. Returns total rows written."""
    uids = list(signals_by_uid.keys())
    written = 0

    for i in range(0, len(uids), _BATCH_SIZE):
        batch = uids[i : i + _BATCH_SIZE]
        for uid in batch:
            sig = signals_by_uid[uid]
            resource_type = sig.pop("resource_type", "storage")
            upsert_posture_signals(
                inv_conn,
                resource_uid=uid,
                scan_run_id=scan_run_id,
                tenant_id=tenant_id,
                account_id=account_id,
                provider=provider,
                resource_type=resource_type,
                **sig,
            )
            written += 1

    return written
