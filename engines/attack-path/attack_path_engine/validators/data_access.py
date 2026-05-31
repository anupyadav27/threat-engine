"""
Validator: Data Access (AWS-DATA-001..005, AWS-SEC-001..002, AWS-KMS-001..002)

Creates:
  Principal → CAN_READ   → data asset (S3, RDS, DynamoDB, EFS, Secrets Manager, SSM)
  Principal → CAN_WRITE  → data asset
  Principal → CAN_DECRYPT → KMS key

Reads GRANTS_ACCESS_TO, reads_from, stores_data_in, encrypted_by edges.
GRANTS_ACCESS_TO = IAM engine confirmed the permission when writing the edge.
encrypted_by = KMS relationship; role owning key CAN_DECRYPT the associated resource.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

import psycopg2.extras

from .base import _upsert_attack_edges

logger = logging.getLogger("attack-path.validators.data_access")

# relation_type → (attack_edge_type, rule_id, attack_path_category)
_DATA_RULES: Dict[str, tuple] = {
    "grants_access_to": ("CAN_READ",    "AWS-DATA-001", "data_access"),
    "reads_from":       ("CAN_READ",    "AWS-DATA-001", "data_access"),
    "stores_data_in":   ("CAN_WRITE",   "AWS-DATA-002", "data_access"),
    "encrypted_by":     ("CAN_DECRYPT", "AWS-KMS-001",  "data_exfil"),
}

_DATA_RELATION_TYPES = list(_DATA_RULES.keys())

# Resource types that classify as secrets / KMS for rule ID refinement
_SECRET_TYPES = frozenset({"secretsmanager_secret", "ssm_parameter", "secretsmanager.secret"})
_KMS_TYPES    = frozenset({"kms_key", "kms.key", "kms_alias"})
_S3_TYPES     = frozenset({"s3_bucket", "s3.bucket"})


def _refine_rule(
    base_edge_type: str,
    base_rule_id: str,
    target_type: str,
) -> tuple:
    """Refine rule ID and edge type based on target resource type."""
    tt = (target_type or "").lower()

    if base_edge_type == "CAN_DECRYPT":
        return "CAN_DECRYPT", "AWS-KMS-001"

    if any(s in tt for s in ("secret", "ssm", "parameter_store")):
        return "CAN_READ", "AWS-SEC-001"

    if any(s in tt for s in ("kms", "key_management")):
        return "CAN_DECRYPT", "AWS-KMS-001"

    if "s3" in tt or "bucket" in tt or "blob" in tt or "oss" in tt:
        return base_edge_type, "AWS-DATA-001" if base_edge_type == "CAN_READ" else "AWS-DATA-002"

    if any(s in tt for s in ("rds", "database", "dynamodb", "redshift", "postgres", "mysql")):
        return base_edge_type, "AWS-DATA-004"

    if "efs" in tt or "filesystem" in tt or "nfs" in tt:
        return base_edge_type, "AWS-DATA-005"

    return base_edge_type, base_rule_id


def validate_data_access(
    di_conn: Any,
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
) -> int:
    """Write CAN_READ / CAN_WRITE / CAN_DECRYPT edges for data access relationships."""
    placeholders = ",".join(["%s"] * len(_DATA_RELATION_TYPES))

    rows = []
    try:
        with di_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                f"""
                SELECT DISTINCT
                    source_uid, source_type,
                    target_uid, target_type,
                    LOWER(relation_type) AS rel_type
                FROM asset_relationships
                WHERE tenant_id = %s
                  AND scan_run_id = %s
                  AND LOWER(relation_type) IN ({placeholders})
                  AND source_uid IS NOT NULL
                  AND target_uid IS NOT NULL
                """,
                (tenant_id, scan_run_id, *_DATA_RELATION_TYPES),
            )
            rows = cur.fetchall()
    except Exception as exc:
        logger.warning("data_access: query failed: %s", exc)
        try:
            di_conn.rollback()
        except Exception:
            pass
        return 0

    if not rows:
        logger.info("data_access: 0 data access edges found tenant=%s scan=%s", tenant_id, scan_run_id)
        return 0

    edges: List[Dict[str, Any]] = []
    for row in rows:
        rel = row["rel_type"]
        base_edge_type, base_rule_id, ap_cat = _DATA_RULES.get(
            rel, ("CAN_READ", "AWS-DATA-001", "data_access")
        )
        edge_type, rule_id = _refine_rule(base_edge_type, base_rule_id, row["target_type"] or "")

        edges.append({
            "source_uid":           row["source_uid"],
            "source_type":          row["source_type"] or "",
            "target_uid":           row["target_uid"],
            "target_type":          row["target_type"] or "",
            "relation_type":        edge_type,
            "attack_edge_type":     edge_type,
            "validation_rule_id":   rule_id,
            "attack_path_category": ap_cat,
            "confidence":           "high",
            "attack_evidence":      {
                "raw_relation_type": rel,
                "derived_from":      "data_access_validator",
                "target_type":       row["target_type"] or "",
            },
        })

    written = _upsert_attack_edges(di_conn, edges, scan_run_id, tenant_id, account_id, provider)
    logger.info(
        "data_access: %d CAN_READ/CAN_WRITE/CAN_DECRYPT edges → tenant=%s scan=%s",
        written, tenant_id, scan_run_id,
    )
    return written
