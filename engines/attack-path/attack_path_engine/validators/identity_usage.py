"""
Validator: Identity Usage (AWS-ID-001..003, VAL-ID-*)

Creates: Compute → CAN_USE_IDENTITY → IAM Role / Service Account

Chain resolution (2-hop):
  EC2 → HAS_PROFILE → instance_profile (from DI catalog writer)
  instance_profile → LINKED_TO → iam_role (from IAM relationship writer)
  → Derived: EC2 → CAN_USE_IDENTITY → iam_role

Single-hop (direct role attachment):
  Lambda/ECS/Pod → has_role / USES_IDENTITY / has_sa / has_identity → role
  → Derived: Compute → CAN_USE_IDENTITY → role

The IAM engine already validated that the profile/role attachment is real.
We just chain the multi-hop structural edges into a single attack-capable edge.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

import psycopg2.extras

from .base import _upsert_attack_edges

logger = logging.getLogger("attack-path.validators.identity_usage")

# Single-hop: compute directly attached to role/SA
_DIRECT_IDENTITY_RELS = ["has_role", "uses_identity", "has_sa", "has_identity"]

# 2-hop chain: compute → HAS_PROFILE → instance_profile → LINKED_TO → role
_PROFILE_REL = "has_profile"
_LINKED_TO_REL = "linked_to"


def validate_identity_usage(
    di_conn: Any,
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
) -> int:
    """Write CAN_USE_IDENTITY edges for compute → role attachments."""
    edges: List[Dict[str, Any]] = []

    # ── 1. Single-hop: compute → has_role / USES_IDENTITY / has_sa ──────────
    direct_rels = _DIRECT_IDENTITY_RELS
    placeholders = ",".join(["%s"] * len(direct_rels))
    try:
        with di_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                f"""
                SELECT DISTINCT source_uid, source_type, target_uid, target_type
                FROM asset_relationships
                WHERE tenant_id = %s AND scan_run_id = %s
                  AND LOWER(relation_type) IN ({placeholders})
                  AND source_uid IS NOT NULL AND target_uid IS NOT NULL
                """,
                (tenant_id, scan_run_id, *direct_rels),
            )
            for row in cur.fetchall():
                edges.append({
                    "source_uid":           row["source_uid"],
                    "source_type":          row["source_type"] or "",
                    "target_uid":           row["target_uid"],
                    "target_type":          row["target_type"] or "",
                    "relation_type":        "CAN_USE_IDENTITY",
                    "attack_edge_type":     "CAN_USE_IDENTITY",
                    "validation_rule_id":   "AWS-ID-002",
                    "attack_path_category": "privilege_escalation",
                    "confidence":           "high",
                    "attack_evidence": {
                        "derived_from": "identity_usage_validator_direct",
                    },
                })
    except Exception as exc:
        logger.warning("identity_usage direct query failed: %s", exc)
        try:
            di_conn.rollback()
        except Exception:
            pass

    # ── 2. Two-hop: EC2 → HAS_PROFILE → instance_profile → LINKED_TO → role ─
    # Build: profile_uid → [role_uids] from LINKED_TO edges
    profile_to_roles: Dict[str, list] = {}
    try:
        with di_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT DISTINCT source_uid AS profile_uid, target_uid AS role_uid, target_type
                FROM asset_relationships
                WHERE tenant_id = %s AND scan_run_id = %s
                  AND LOWER(relation_type) = %s
                  AND source_uid IS NOT NULL AND target_uid IS NOT NULL
                """,
                (tenant_id, scan_run_id, _LINKED_TO_REL),
            )
            for row in cur.fetchall():
                profile_to_roles.setdefault(row["profile_uid"], []).append(
                    (row["role_uid"], row["target_type"] or "iam_role")
                )
    except Exception as exc:
        logger.warning("identity_usage LINKED_TO query failed: %s", exc)
        try:
            di_conn.rollback()
        except Exception:
            pass

    if profile_to_roles:
        # Find compute → HAS_PROFILE → instance_profile
        try:
            with di_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT DISTINCT source_uid AS compute_uid, source_type, target_uid AS profile_uid
                    FROM asset_relationships
                    WHERE tenant_id = %s AND scan_run_id = %s
                      AND LOWER(relation_type) = %s
                      AND source_uid IS NOT NULL AND target_uid IS NOT NULL
                    """,
                    (tenant_id, scan_run_id, _PROFILE_REL),
                )
                for row in cur.fetchall():
                    profile_uid = row["profile_uid"]
                    for role_uid, role_type in profile_to_roles.get(profile_uid, []):
                        edges.append({
                            "source_uid":           row["compute_uid"],
                            "source_type":          row["source_type"] or "",
                            "target_uid":           role_uid,
                            "target_type":          role_type,
                            "relation_type":        "CAN_USE_IDENTITY",
                            "attack_edge_type":     "CAN_USE_IDENTITY",
                            "validation_rule_id":   "AWS-ID-001",
                            "attack_path_category": "privilege_escalation",
                            "confidence":           "high",
                            "attack_evidence": {
                                "via_profile":  profile_uid,
                                "derived_from": "identity_usage_validator_chain",
                            },
                        })
        except Exception as exc:
            logger.warning("identity_usage HAS_PROFILE chain query failed: %s", exc)
            try:
                di_conn.rollback()
            except Exception:
                pass

    if not edges:
        logger.info("identity_usage: 0 edges for tenant=%s scan=%s", tenant_id, scan_run_id)
        return 0

    written = _upsert_attack_edges(di_conn, edges, scan_run_id, tenant_id, account_id, provider)
    logger.info(
        "identity_usage: %d CAN_USE_IDENTITY edges (direct=%d chain=via_profile) tenant=%s scan=%s",
        written, len([e for e in edges if "direct" in str(e.get("attack_evidence", ""))]),
        tenant_id, scan_run_id,
    )
    return written
