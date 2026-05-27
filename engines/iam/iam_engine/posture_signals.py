"""
Write IAM engine posture signals to resource_security_posture after scan.

Called at the end of run_scan.py after iam_findings are persisted.
Queries iam_policy_statements and iam_findings, aggregates per resource_uid,
then batch-upserts IAM-owned columns to resource_security_posture.

Column ownership (IAM engine writes ONLY these columns):
    has_attached_role, role_has_wildcard_policy, role_allows_cross_account,
    mfa_enforced, has_permission_boundary, is_admin_role, can_access_pii, iam_detail,
    has_priv_escalation_path, priv_escalation_hop_count, priv_escalation_cdr_confirmed
"""

from __future__ import annotations

import logging
from typing import Any

import psycopg2.extras

from engine_common.db_connections import get_iam_conn, get_di_conn
from engine_common.posture_writer import upsert_posture_signals

logger = logging.getLogger(__name__)

_BATCH_SIZE = 500


def write_iam_posture_signals(
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
) -> int:
    """Aggregate IAM signals from iam_findings/iam_policy_statements and upsert.

    Returns number of posture rows written.
    """
    try:
        signals_by_uid = _aggregate_iam_signals(scan_run_id, tenant_id)
        if not signals_by_uid:
            logger.info("IAM posture signals: no IAM findings for scan %s", scan_run_id)
            return 0

        inv_conn = get_di_conn()
        try:
            written = _batch_upsert(
                inv_conn, signals_by_uid,
                scan_run_id, tenant_id, account_id, provider,
            )
            logger.info("IAM posture signals: wrote %d rows for scan %s", written, scan_run_id)
            return written
        finally:
            inv_conn.close()

    except Exception as exc:
        logger.warning("IAM posture signal write failed (non-fatal): %s", exc, exc_info=True)
        return 0


def _aggregate_iam_signals(scan_run_id: str, tenant_id: str) -> dict[str, dict[str, Any]]:
    """Query iam_findings + iam_policy_statements for the scan and aggregate per resource."""
    iam_conn = get_iam_conn()
    signals: dict[str, dict[str, Any]] = {}

    try:
        with iam_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            # Pull per-resource summary from iam_findings
            cur.execute("""
                SELECT
                    resource_uid,
                    resource_type,
                    MAX(CASE WHEN rule_id ILIKE '%%admin%%' OR rule_id ILIKE '%%privilege%%' THEN 1 ELSE 0 END) = 1
                        AS is_admin_role,
                    MAX(CASE WHEN rule_id ILIKE '%%wildcard%%' AND status = 'FAIL' THEN 1 ELSE 0 END) = 1
                        AS role_has_wildcard_policy,
                    MAX(CASE WHEN rule_id ILIKE '%%cross_account%%' OR rule_id ILIKE '%%trust%%' THEN 1 ELSE 0 END) = 1
                        AS role_allows_cross_account,
                    MAX(CASE WHEN rule_id ILIKE '%%mfa%%' AND status = 'PASS' THEN 1 ELSE 0 END) = 1
                        AS mfa_enforced,
                    MAX(CASE WHEN rule_id ILIKE '%%permission_boundary%%' AND status = 'PASS' THEN 1 ELSE 0 END) = 1
                        AS has_permission_boundary,
                    MAX(CASE WHEN (rule_id ILIKE '%%s3%%' OR rule_id ILIKE '%%data%%' OR rule_id ILIKE '%%pii%%')
                             AND status = 'FAIL' THEN 1 ELSE 0 END) = 1
                        AS can_access_pii,
                    bool_or(TRUE) AS has_attached_role
                FROM iam_findings
                WHERE scan_run_id = %s AND tenant_id = %s AND resource_uid IS NOT NULL
                GROUP BY resource_uid, resource_type
            """, (scan_run_id, tenant_id))

            for row in cur.fetchall():
                uid = row["resource_uid"]
                signals[uid] = {
                    "resource_type": row.get("resource_type", "iam_resource"),
                    "has_attached_role": True,
                    "is_admin_role": bool(row["is_admin_role"]),
                    "role_has_wildcard_policy": bool(row["role_has_wildcard_policy"]),
                    "role_allows_cross_account": bool(row["role_allows_cross_account"]),
                    "mfa_enforced": bool(row["mfa_enforced"]),
                    "has_permission_boundary": bool(row["has_permission_boundary"]),
                    "can_access_pii": bool(row["can_access_pii"]),
                    "has_priv_escalation_path": False,
                    "priv_escalation_hop_count": 0,
                    "priv_escalation_cdr_confirmed": False,
                }

        # Detect privilege escalation paths from escalation_detector rule IDs.
        # Reads finding_data JSONB directly for precise hop_count and CDR confirmation.
        # Falls back to ILIKE pattern if the new rule IDs are not present.
        _ESCALATION_RULE_PREFIX = "aws.iam.role.privilege_escalation"
        try:
            with iam_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as _esc_cur:
                _esc_cur.execute("""
                    SELECT
                        resource_uid,
                        COUNT(*) AS escalation_count,
                        MIN((finding_data->>'hop_count')::int) AS min_hop_count,
                        bool_or(
                            (finding_data->>'cdr_active')::boolean IS TRUE
                            OR rule_id = 'aws.iam.role.privilege_escalation_cdr_confirmed'
                        ) AS cdr_confirmed
                    FROM iam_findings
                    WHERE scan_run_id = %s
                      AND tenant_id = %s
                      AND resource_uid IS NOT NULL
                      AND status = 'FAIL'
                      AND rule_id LIKE %s
                    GROUP BY resource_uid
                """, (scan_run_id, tenant_id, _ESCALATION_RULE_PREFIX + "%"))
                _esc_rows = _esc_cur.fetchall()

            if _esc_rows:
                for _row in _esc_rows:
                    _uid = _row["resource_uid"]
                    if _uid in signals:
                        signals[_uid]["has_priv_escalation_path"] = True
                        _hop = int(_row["min_hop_count"] or 1)
                        signals[_uid]["priv_escalation_hop_count"] = max(_hop, 1)
                        signals[_uid]["priv_escalation_cdr_confirmed"] = bool(
                            _row["cdr_confirmed"]
                )
            else:
                # Fallback: ILIKE scan for older/non-standard escalation rule IDs
                with iam_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as _fb_cur:
                    _fb_cur.execute("""
                        SELECT
                            resource_uid,
                            COUNT(*) FILTER (WHERE rule_id ILIKE '%%escalat%%' AND status = 'FAIL')
                                AS escalation_count,
                            COUNT(*) FILTER (WHERE (rule_id ILIKE '%%passrole%%'
                                OR rule_id ILIKE '%%pass_role%%'
                                OR rule_id ILIKE '%%assume%%')
                                AND status = 'FAIL')
                                AS hop_count
                        FROM iam_findings
                        WHERE scan_run_id = %s AND tenant_id = %s AND resource_uid IS NOT NULL
                        GROUP BY resource_uid
                        HAVING COUNT(*) FILTER (WHERE rule_id ILIKE '%%escalat%%'
                            OR rule_id ILIKE '%%passrole%%'
                            OR rule_id ILIKE '%%pass_role%%') > 0
                    """, (scan_run_id, tenant_id))
                    for _row in _fb_cur.fetchall():
                        _uid = _row["resource_uid"]
                        if _uid in signals:
                            _esc = int(_row["escalation_count"] or 0)
                            _hops = int(_row["hop_count"] or 0)
                            if _esc > 0:
                                signals[_uid]["has_priv_escalation_path"] = True
                                signals[_uid]["priv_escalation_hop_count"] = max(_hops, 1)
        except Exception as _esc_exc:
            logger.debug("Privilege escalation detection skipped: %s", _esc_exc)

        # Enrich from iam_policy_statements (more precise admin/wildcard signals + iam_detail)
        try:
            with iam_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT
                        resource_uid,
                        bool_or(is_admin) AS is_admin,
                        bool_or(is_wildcard_principal) AS is_wildcard_principal,
                        bool_or(is_cross_account) AS is_cross_account,
                        COUNT(*) AS policy_statement_count,
                        array_agg(DISTINCT policy_arn) FILTER (WHERE policy_arn IS NOT NULL)
                            AS policy_arns,
                        array_agg(DISTINCT attached_to_arn) FILTER (WHERE attached_to_arn IS NOT NULL)
                            AS role_arns
                    FROM iam_policy_statements
                    WHERE scan_run_id = %s AND tenant_id = %s AND resource_uid IS NOT NULL
                    GROUP BY resource_uid
                """, (scan_run_id, tenant_id))
                for row in cur.fetchall():
                    uid = row["resource_uid"]
                    if uid in signals:
                        signals[uid]["is_admin_role"] = signals[uid]["is_admin_role"] or bool(row["is_admin"])
                        signals[uid]["role_has_wildcard_policy"] = (
                            signals[uid]["role_has_wildcard_policy"] or bool(row["is_wildcard_principal"])
                        )
                        signals[uid]["role_allows_cross_account"] = (
                            signals[uid]["role_allows_cross_account"] or bool(row["is_cross_account"])
                        )
                        _role_arns = row["role_arns"] or []
                        _policy_arns = row["policy_arns"] or []
                        signals[uid]["iam_detail"] = {
                            "role_arns": _role_arns[:5],
                            "policy_arns": _policy_arns[:10],
                            "policy_statement_count": int(row["policy_statement_count"] or 0),
                            "is_admin": bool(row["is_admin"]),
                            "is_wildcard_principal": bool(row["is_wildcard_principal"]),
                            "is_cross_account": bool(row["is_cross_account"]),
                        }
        except Exception as stmt_exc:
            logger.debug("iam_policy_statements enrichment skipped: %s", stmt_exc)

    finally:
        iam_conn.close()

    # Ensure every uid has at least a minimal iam_detail from collected boolean signals.
    # This runs when iam_policy_statements is empty or has no overlapping UIDs.
    for uid, sig in signals.items():
        if "iam_detail" not in sig:
            sig["iam_detail"] = {
                "is_admin": sig.get("is_admin_role", False),
                "is_wildcard_principal": sig.get("role_has_wildcard_policy", False),
                "is_cross_account": sig.get("role_allows_cross_account", False),
                "policy_statement_count": 0,
                "role_arns": [],
                "policy_arns": [],
            }

    return signals


def _batch_upsert(
    inv_conn: Any,
    signals_by_uid: dict[str, dict[str, Any]],
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
) -> int:
    """Upsert signals in batches of _BATCH_SIZE. Returns total rows written."""
    uids = list(signals_by_uid.keys())
    written = 0

    for i in range(0, len(uids), _BATCH_SIZE):
        batch = uids[i : i + _BATCH_SIZE]
        for uid in batch:
            sig = signals_by_uid[uid]
            resource_type = sig.pop("resource_type", "iam_resource")
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
