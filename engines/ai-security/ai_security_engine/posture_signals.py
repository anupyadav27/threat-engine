"""
AI Security Engine — Write posture signals to resource_security_posture.

Called at the end of run_scan.py after findings are persisted.

AI-owned columns (per PC-P0-01):
    ai_model_publicly_accessible  — from ai_security_findings FAIL on public_access rules
    ai_training_data_has_pii      — cross-engine: datasec posture row for training bucket
    has_shadow_ai_service         — cross-engine: CDR calls to AI APIs not in inventory

All writes are non-fatal: a posture write failure never aborts the main scan.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import psycopg2
import psycopg2.extras

logger = logging.getLogger(__name__)

_PUBLIC_ACCESS_RULE_KEYWORDS = (
    "public_access",
    "public_endpoint",
    "no_vpc",
    "without_vpc",
    "vpc_config",
)

_AI_RESOURCE_TYPES = frozenset({
    "sagemaker_endpoint",
    "sagemaker_notebook",
    "sagemaker_training_job",
    "bedrock_model",
    "bedrock_agent",
    "azure_ml_workspace",
    "vertex_ai_endpoint",
    "ibm_watson_service",
})


def write_ai_posture_signals(
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
) -> int:
    """Write AI security posture signals to resource_security_posture.

    Returns number of posture rows written/updated.
    """
    written = 0
    try:
        from engine_common.db_connections import get_ai_security_conn, get_di_conn
        ai_conn = get_ai_security_conn()
        inv_conn = get_di_conn()
        try:
            written += _write_public_access_signals(ai_conn, inv_conn, scan_run_id, tenant_id, account_id, provider)
            written += _write_shadow_ai_signals(ai_conn, inv_conn, scan_run_id, tenant_id, account_id, provider)
            # ai_training_data_has_pii cross-engine join (uses datasec posture rows)
            written += _write_training_pii_signals(ai_conn, inv_conn, scan_run_id, tenant_id, account_id, provider)
        finally:
            ai_conn.close()
            inv_conn.close()

        logger.info(
            "AI security posture signals: wrote %d rows (scan=%s tenant=%s)",
            written, scan_run_id, tenant_id,
        )
    except Exception as exc:
        logger.warning("AI security posture signal write failed (non-fatal): %s", exc, exc_info=True)

    return written


def _write_public_access_signals(
    ai_conn: Any,
    inv_conn: Any,
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
) -> int:
    """Mark ai_model_publicly_accessible=TRUE for AI resources with FAIL public-access findings."""
    from engine_common.posture_writer import upsert_posture_signals

    public_uids: list[tuple[str, str]] = []  # (resource_uid, resource_type)
    try:
        with ai_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """SELECT DISTINCT resource_uid, resource_type
                   FROM ai_security_findings
                   WHERE scan_run_id = %s AND tenant_id = %s AND status = 'FAIL'
                     AND (
                         rule_id ILIKE %s OR rule_id ILIKE %s OR rule_id ILIKE %s
                         OR rule_id ILIKE %s OR rule_id ILIKE %s
                     )""",
                (
                    scan_run_id, tenant_id,
                    "%public_access%", "%public_endpoint%", "%no_vpc%",
                    "%without_vpc%", "%vpc_config%",
                ),
            )
            public_uids = [(r["resource_uid"], r["resource_type"]) for r in cur.fetchall() if r["resource_uid"]]
    except Exception as exc:
        logger.debug("AI posture: could not query ai_security_findings: %s", exc)
        return 0

    for uid, rtype in public_uids:
        try:
            upsert_posture_signals(
                inv_conn,
                resource_uid=uid,
                scan_run_id=scan_run_id,
                tenant_id=tenant_id,
                account_id=account_id,
                provider=provider,
                resource_type=rtype or "ai_resource",
                ai_model_publicly_accessible=True,
            )
        except Exception as exc:
            logger.debug("AI posture: upsert failed for %s: %s", uid, exc)

    return len(public_uids)


def _write_shadow_ai_signals(
    ai_conn: Any,
    inv_conn: Any,
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
) -> int:
    """Mark has_shadow_ai_service=TRUE for CDR-observed AI API calls not in AI inventory."""
    from engine_common.posture_writer import upsert_posture_signals

    # Collect AI resource_uids already in inventory for this scan
    try:
        with ai_conn.cursor() as cur:
            cur.execute(
                "SELECT DISTINCT resource_uid FROM ai_security_findings WHERE scan_run_id = %s AND tenant_id = %s",
                (scan_run_id, tenant_id),
            )
            known_uids: set[str] = {row[0] for row in cur.fetchall() if row[0]}
    except Exception:
        known_uids = set()

    # Query CDR findings for AI service resource types not in known_uids
    shadow_uids: list[str] = []
    try:
        from engine_common.db_connections import get_cdr_conn
        cdr_conn = get_cdr_conn()
        try:
            with cdr_conn.cursor() as cur:
                cur.execute(
                    """SELECT DISTINCT resource_uid
                       FROM cdr_findings
                       WHERE tenant_id = %s
                         AND resource_type = ANY(%s)
                         AND resource_uid IS NOT NULL""",
                    (tenant_id, list(_AI_RESOURCE_TYPES)),
                )
                for (uid,) in cur.fetchall():
                    if uid and uid not in known_uids:
                        shadow_uids.append(uid)
        finally:
            cdr_conn.close()
    except Exception as exc:
        logger.info("AI posture: CDR DB unavailable for shadow AI detection (non-fatal): %s", exc)
        return 0

    for uid in shadow_uids:
        try:
            upsert_posture_signals(
                inv_conn,
                resource_uid=uid,
                scan_run_id=scan_run_id,
                tenant_id=tenant_id,
                account_id=account_id,
                provider=provider,
                resource_type="ai_shadow_resource",
                has_shadow_ai_service=True,
            )
        except Exception as exc:
            logger.debug("AI posture: shadow upsert failed for %s: %s", uid, exc)

    return len(shadow_uids)


def _write_training_pii_signals(
    ai_conn: Any,
    inv_conn: Any,
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
) -> int:
    """Mark ai_training_data_has_pii=TRUE when training data bucket has PII classification."""
    from engine_common.posture_writer import upsert_posture_signals

    # Find training jobs with a training_data_bucket in their finding_data
    training_resources: list[tuple[str, str, str]] = []  # (resource_uid, resource_type, bucket_arn)
    try:
        with ai_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """SELECT DISTINCT resource_uid, resource_type,
                          finding_data->>'training_data_bucket' AS bucket_arn
                   FROM ai_security_findings
                   WHERE scan_run_id = %s AND tenant_id = %s
                     AND finding_data->>'training_data_bucket' IS NOT NULL""",
                (scan_run_id, tenant_id),
            )
            for row in cur.fetchall():
                if row["resource_uid"] and row["bucket_arn"]:
                    training_resources.append((
                        row["resource_uid"],
                        row["resource_type"] or "sagemaker_training_job",
                        row["bucket_arn"],
                    ))
    except Exception as exc:
        logger.debug("AI posture: training PII query failed: %s", exc)
        return 0

    if not training_resources:
        return 0

    # For each training resource, check if the bucket has PII in posture table
    pii_classifications = ("pii", "phi", "pci")
    updated = 0
    for uid, rtype, bucket_arn in training_resources:
        try:
            with inv_conn.cursor() as cur:
                cur.execute(
                    """SELECT 1 FROM resource_security_posture
                       WHERE tenant_id = %s
                         AND resource_uid = %s
                         AND data_classification = ANY(%s)
                       LIMIT 1""",
                    (tenant_id, bucket_arn, list(pii_classifications)),
                )
                has_pii = cur.fetchone() is not None

            if has_pii:
                upsert_posture_signals(
                    inv_conn,
                    resource_uid=uid,
                    scan_run_id=scan_run_id,
                    tenant_id=tenant_id,
                    account_id=account_id,
                    provider=provider,
                    resource_type=rtype,
                    ai_training_data_has_pii=True,
                )
                updated += 1
        except Exception as exc:
            logger.debug("AI posture: training PII upsert failed for %s: %s", uid, exc)

    return updated
