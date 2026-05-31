"""
Validator: Internet Reachability (AWS-INET-001..005, VAL-INET-*)

Creates: pseudo:internet:global → CAN_REACH → asset

Sources:
  1. resource_security_posture WHERE is_attack_entry_point=true OR is_internet_exposed=true
  2. asset_relationships WHERE relation_type = 'INTERNET_ACCESSIBLE'
     (written by network engine for all CSPs via IEDS)
  3. Always-internet resources: cloudfront_distribution, internet-facing elbv2_load_balancer,
     apigatewayv2_api — these are always public by design; RSP/network-engine coverage varies.
  4. SSM-managed EC2 instances (MANAGED_BY_AGENT edges) → ENDPOINT_AGENT_ENTRY
     An attacker with compromised AWS credentials can reach these via SSM StartSession.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

import psycopg2.extras

from .base import INTERNET_NODE, _upsert_attack_edges

logger = logging.getLogger("attack-path.validators.internet_reachability")

# Resource types that are always internet-accessible by design.
# These are promoted as INTERNET_ENTRY even if RSP/network-engine did not mark them.
_ALWAYS_INTERNET_TYPES = (
    "cloudfront_distribution",
    "elbv2_load_balancer",       # filtered to Scheme=internet-facing below
    "apigatewayv2_api",
    "apigatewayv2.api",
    "apigateway_api",
    "apigateway.restapi",
    "apigateway.httpapi",
    "apigateway.v2api",
)


def _rule_id_for_type(resource_type: str) -> str:
    """Map resource_type to best-fit AWS-INET rule ID."""
    rt = (resource_type or "").lower()
    if "rds" in rt or "database" in rt:
        return "AWS-INET-005"
    if "alb" in rt or "elbv2" in rt or "load_balancer" in rt or "slb" in rt:
        return "AWS-INET-002"
    if "api" in rt or "gateway" in rt:
        return "AWS-INET-003"
    if "ingress" in rt or "eks" in rt:
        return "AWS-INET-004"
    if "cloudfront" in rt:
        return "AWS-INET-002"
    return "AWS-INET-001"


def validate_internet_reachability(
    di_conn: Any,
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
) -> int:
    """Write CAN_REACH edges from pseudo:internet:global to all internet entry points.

    Returns count of edges written.
    """
    entry_uids: Dict[str, str] = {}  # uid → resource_type

    # Source 1: resource_security_posture entry points (from ONTO sprint Phase 3)
    try:
        with di_conn.cursor() as cur:
            cur.execute(
                """
                SELECT resource_uid, resource_type
                FROM resource_security_posture
                WHERE tenant_id = %s
                  AND scan_run_id = %s
                  AND (is_attack_entry_point = TRUE OR is_internet_exposed = TRUE)
                  AND resource_uid IS NOT NULL
                """,
                (tenant_id, scan_run_id),
            )
            for row in cur.fetchall():
                entry_uids[row[0]] = row[1] or ""
    except Exception as exc:
        logger.warning("Could not read posture entry points: %s", exc)
        try:
            di_conn.rollback()
        except Exception:
            pass

    # Source 2: INTERNET_ACCESSIBLE edges from network engine
    # Also promote these structural edges to is_attack_edge=TRUE so BFS can traverse them
    # for multi-hop paths: internet-facing LB → EC2 → IAM role → S3
    try:
        with di_conn.cursor() as cur:
            cur.execute(
                """
                SELECT DISTINCT source_uid, source_type
                FROM asset_relationships
                WHERE tenant_id = %s
                  AND scan_run_id = %s
                  AND UPPER(relation_type) = 'INTERNET_ACCESSIBLE'
                  AND source_uid IS NOT NULL
                  AND source_uid NOT LIKE 'pseudo:%%'
                """,
                (tenant_id, scan_run_id),
            )
            for row in cur.fetchall():
                if row[0] not in entry_uids:
                    entry_uids[row[0]] = row[1] or ""
        # NOTE: INTERNET_ACCESSIBLE edges are intentionally kept is_attack_edge=FALSE.
        # They mark entry points (resource → internet) but are NOT BFS traversal edges.
        # Only CAN_REACH edges (pseudo:internet:global → resource, written below) are
        # traversal edges. Promoting INTERNET_ACCESSIBLE would cause every entry point
        # to pivot through the internet node and explode the path count.
    except Exception as exc:
        logger.warning("Could not read INTERNET_ACCESSIBLE edges: %s", exc)
        try:
            di_conn.rollback()
        except Exception:
            pass

    # Source 3: Always-internet resource types (CloudFront, internet-facing ELB, API GW variants)
    # RSP and network engine don't always mark these; query asset_inventory directly.
    try:
        type_placeholders = ",".join(["%s"] * len(_ALWAYS_INTERNET_TYPES))
        with di_conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT resource_uid, resource_type, emitted_fields
                FROM asset_inventory
                WHERE tenant_id = %s
                  AND resource_type IN ({type_placeholders})
                  AND resource_uid IS NOT NULL
                  AND resource_uid NOT LIKE 'pseudo:%%'
                ORDER BY last_seen_at DESC
                """,
                (tenant_id, *_ALWAYS_INTERNET_TYPES),
            )
            for row in cur.fetchall():
                uid, rtype, fields = row[0], row[1] or "", row[2] or {}
                if uid in entry_uids:
                    continue
                # ELBv2: only internet-facing scheme qualifies
                if "elbv2_load_balancer" in rtype:
                    scheme = (fields.get("Scheme") or "") if isinstance(fields, dict) else ""
                    if scheme != "internet-facing":
                        continue
                entry_uids[uid] = rtype
    except Exception as exc:
        logger.warning("internet_reachability source3 (always-internet) failed: %s", exc)
        try:
            di_conn.rollback()
        except Exception:
            pass

    # Source 4: SSM-managed EC2 instances → ENDPOINT_AGENT_ENTRY
    # An attacker with stolen AWS credentials can use SSM StartSession to reach these instances.
    # MANAGED_BY_AGENT edges: ssm_describe_instance_information → ec2_instance
    ssm_entry_uids: List[Tuple[str, str]] = []  # (ec2_uid, resource_type)
    try:
        with di_conn.cursor() as cur:
            cur.execute(
                """
                SELECT DISTINCT target_uid, target_type
                FROM asset_relationships
                WHERE tenant_id = %s
                  AND UPPER(relation_type) = 'MANAGED_BY_AGENT'
                  AND target_uid IS NOT NULL
                  AND target_uid NOT LIKE 'pseudo:%%'
                """,
                (tenant_id,),
            )
            for row in cur.fetchall():
                if row[0] not in entry_uids:
                    ssm_entry_uids.append((row[0], row[1] or "ec2_instance"))
    except Exception as exc:
        logger.warning("internet_reachability source4 (SSM) failed: %s", exc)
        try:
            di_conn.rollback()
        except Exception:
            pass

    if not entry_uids and not ssm_entry_uids:
        logger.info("internet_reachability: 0 entry points for tenant=%s scan=%s", tenant_id, scan_run_id)
        return 0

    edges: List[Dict[str, Any]] = []
    for uid, rtype in entry_uids.items():
        edges.append({
            "source_uid":           INTERNET_NODE,
            "source_type":          "internet",
            "target_uid":           uid,
            "target_type":          rtype,
            "relation_type":        "CAN_REACH",
            "attack_edge_type":     "CAN_REACH",
            "validation_rule_id":   _rule_id_for_type(rtype),
            "attack_path_category": "internet_exposure",
            "confidence":           "high",
            "attack_evidence":      {"source": "posture_entry_point", "resource_type": rtype},
        })

    # Source 4 SSM edges: use ENDPOINT_AGENT_ENTRY category (credential-based, not internet pivot)
    for uid, rtype in ssm_entry_uids:
        edges.append({
            "source_uid":           INTERNET_NODE,
            "source_type":          "internet",
            "target_uid":           uid,
            "target_type":          rtype,
            "relation_type":        "CAN_REACH",
            "attack_edge_type":     "CAN_REACH",
            "validation_rule_id":   "AWS-SSM-001",
            "attack_path_category": "lateral_movement",
            "confidence":           "medium",
            "attack_evidence":      {
                "source":               "ssm_managed_by_agent",
                "entry_point_category": "ENDPOINT_AGENT_ENTRY",
                "resource_type":        rtype,
            },
        })

    written = _upsert_attack_edges(di_conn, edges, scan_run_id, tenant_id, account_id, provider)
    logger.info(
        "internet_reachability: %d CAN_REACH edges (%d ssm) → tenant=%s scan=%s",
        written, len(ssm_entry_uids), tenant_id, scan_run_id,
    )
    return written
