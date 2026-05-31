"""
Validator: Assume Role (AWS-ID-004..005, VAL-ASSUME-*)

Creates: Principal → CAN_ASSUME → Role

IAM engine already validated trust policy + sts:AssumeRole when writing
ASSUMES / CAN_ASSUME edges. We mark those rows as is_attack_edge=TRUE
and also write a normalised CAN_ASSUME derived edge.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

import psycopg2.extras

from .base import _upsert_attack_edges

logger = logging.getLogger("attack-path.validators.assume_role")

_ASSUME_TYPES = ["assumes", "can_assume"]

# Source types that are AWS service/federation principals — not real traversable resources.
# Attacker can't "be" lambda.amazonaws.com; filter these from attack edges.
_NON_TRAVERSABLE_SOURCE_TYPES = {"service", "federated", "account"}


def validate_assume_role(
    di_conn: Any,
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
) -> int:
    """Write CAN_ASSUME edges and mark existing ASSUMES rows as attack edges."""
    placeholders = ",".join(["%s"] * len(_ASSUME_TYPES))

    rows = []
    try:
        with di_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                f"""
                SELECT DISTINCT
                    source_uid, source_type,
                    target_uid, target_type,
                    LOWER(relation_type) AS rel_type,
                    relation_metadata
                FROM asset_relationships
                WHERE tenant_id = %s
                  AND scan_run_id = %s
                  AND LOWER(relation_type) IN ({placeholders})
                  AND source_uid IS NOT NULL
                  AND target_uid IS NOT NULL
                """,
                (tenant_id, scan_run_id, *_ASSUME_TYPES),
            )
            rows = cur.fetchall()
    except Exception as exc:
        logger.warning("assume_role: query failed: %s", exc)
        try:
            di_conn.rollback()
        except Exception:
            pass
        return 0

    if not rows:
        logger.info("assume_role: 0 assume edges found tenant=%s scan=%s", tenant_id, scan_run_id)
        return 0

    # Mark existing rows as attack edges — only for real resource sources (not AWS principals)
    try:
        with di_conn.cursor() as cur:
            cur.execute(
                f"""
                UPDATE asset_relationships
                SET is_attack_edge     = TRUE,
                    attack_edge_type   = 'CAN_ASSUME',
                    validation_status  = 'validated',
                    validation_rule_id = 'AWS-ID-005',
                    last_seen_at       = NOW()
                WHERE tenant_id = %s
                  AND scan_run_id = %s
                  AND LOWER(relation_type) IN ({placeholders})
                  AND LOWER(COALESCE(source_type,'')) NOT IN ('service', 'federated', 'account')
                  AND target_uid NOT LIKE '%%:root'
                """,
                (tenant_id, scan_run_id, *_ASSUME_TYPES),
            )
        di_conn.commit()
    except Exception as exc:
        logger.warning("assume_role: UPDATE failed (non-fatal): %s", exc)
        try:
            di_conn.rollback()
        except Exception:
            pass

    # Build normalised CAN_ASSUME edges — skip service/account principals and :root targets
    edges: List[Dict[str, Any]] = []
    for row in rows:
        src_type = (row.get("source_type") or "").lower()
        tgt_uid = row.get("target_uid") or ""

        # Skip AWS-managed principals (can't be an attacker's entry point)
        if src_type in _NON_TRAVERSABLE_SOURCE_TYPES:
            continue
        # Skip account-root ARNs (e.g. arn:aws:iam::123456789012:root) — not a traversable role
        if tgt_uid.endswith(":root"):
            continue

        meta = row.get("relation_metadata") or {}
        is_cross_account = False
        if isinstance(meta, dict):
            principal = str(meta.get("principal", ""))
            if account_id and principal and account_id not in principal:
                is_cross_account = True

        rule_id = "AWS-XACC-001" if is_cross_account else "AWS-ID-005"

        edges.append({
            "source_uid":           row["source_uid"],
            "source_type":          row["source_type"] or "",
            "target_uid":           tgt_uid,
            "target_type":          row["target_type"] or "",
            "relation_type":        "CAN_ASSUME",
            "attack_edge_type":     "CAN_ASSUME",
            "validation_rule_id":   rule_id,
            "attack_path_category": "privilege_escalation",
            "confidence":           "high",
            "attack_evidence":      {
                "raw_relation_type": row["rel_type"],
                "cross_account":     is_cross_account,
                "derived_from":      "assume_role_validator",
            },
        })

    written = _upsert_attack_edges(di_conn, edges, scan_run_id, tenant_id, account_id, provider)
    logger.info(
        "assume_role: %d CAN_ASSUME edges → tenant=%s scan=%s",
        written, tenant_id, scan_run_id,
    )
    return written
