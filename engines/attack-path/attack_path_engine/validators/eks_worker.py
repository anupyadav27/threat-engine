"""
Validator: EKS Worker Node (AWS-EKS-001)

Replaces the in-memory _build_eks_worker_node_edges() in run_scan.py.
Finds EC2 instances with EKS nodegroup instance profiles and writes
EC2 → EKS cluster worker_node_of edges to asset_relationships with
is_attack_edge=TRUE.

This makes the EC2 → EKS topology bridge a first-class validated edge so:
  - It appears in asset_relationships (relationship quality endpoint, BFS).
  - The pg BFS can traverse it without needing synthetic extra_edges.
  - It survives the VAL-01 filter (is_attack_edge=TRUE) in pg_graph.

Attack path enabled:
  Internet → EC2 (EKS worker) → worker_node_of → EKS cluster (crown jewel)
"""
from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any, Dict, List

import psycopg2.extras

from .base import _upsert_attack_edges

logger = logging.getLogger("attack-path.validators.eks_worker")


def validate_eks_worker(
    di_conn: Any,
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
) -> int:
    """Write worker_node_of edges for EC2 EKS worker nodes → EKS cluster.

    Non-fatal — any DB error returns 0.
    """
    if provider.lower() not in ("aws", ""):
        return 0

    # ── Step 1: Find EKS cluster UIDs from resource_security_posture ─────────
    # EKS clusters have resource_type like 'eks.cluster' or 'eks_cluster'.
    # The cluster ARN format is: arn:aws:eks:REGION:ACCOUNT:cluster/NAME
    eks_by_account_region: Dict[str, List[str]] = defaultdict(list)
    try:
        with di_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT DISTINCT rsp.resource_uid
                FROM resource_security_posture rsp
                WHERE rsp.tenant_id = %s
                  AND rsp.resource_uid LIKE 'arn:aws:eks:%%'
                """,
                (tenant_id,),
            )
            for row in cur.fetchall():
                uid = row["resource_uid"]
                parts = uid.split(":")
                # Valid cluster ARN: 6 colon-separated parts, last = 'cluster/NAME'
                if (
                    len(parts) == 6
                    and parts[5].startswith("cluster/")
                    and "/" not in parts[5][8:]
                ):
                    region = parts[3]
                    acct = parts[4]
                    eks_by_account_region[f"{acct}:{region}"].append(uid)
    except Exception as exc:
        logger.warning("eks_worker: EKS cluster load failed: %s", exc)
        try:
            di_conn.rollback()
        except Exception:
            pass
        return 0

    if not eks_by_account_region:
        logger.info("eks_worker: no EKS clusters found for tenant=%s — skipping", tenant_id)
        return 0

    # ── Step 2: Find EC2 instances with EKS nodegroup instance profiles ───────
    ec2_rows: list = []
    try:
        with di_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT DISTINCT resource_uid, region, account_id
                FROM asset_inventory
                WHERE tenant_id = %s
                  AND resource_type LIKE 'ec2%%'
                  AND resource_uid LIKE 'arn:aws:ec2:%%:instance/%%'
                  AND resource_uid NOT LIKE '%%/sir-%%'
                  AND (emitted_fields->'IamInstanceProfile'->>'Arn') LIKE '%%instance-profile/eks-%%'
                """,
                (tenant_id,),
            )
            ec2_rows = cur.fetchall()
    except Exception as exc:
        logger.warning("eks_worker: EC2 nodegroup query failed: %s", exc)
        try:
            di_conn.rollback()
        except Exception:
            pass
        return 0

    if not ec2_rows:
        logger.info("eks_worker: no EKS worker EC2 instances for tenant=%s", tenant_id)
        return 0

    # ── Step 3: Build edges ───────────────────────────────────────────────────
    edges: List[Dict[str, Any]] = []
    seen: set = set()

    for row in ec2_rows:
        ec2_uid = row["resource_uid"]
        region = row["region"] or ""
        acct = row["account_id"] or ""
        key_lookup = f"{acct}:{region}"
        for cluster_arn in eks_by_account_region.get(key_lookup, []):
            dedup_key = (ec2_uid, "worker_node_of", cluster_arn)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            edges.append({
                "source_uid":            ec2_uid,
                "source_type":           "ec2.instance",
                "target_uid":            cluster_arn,
                "target_type":           "eks.cluster",
                "relation_type":         "worker_node_of",
                "attack_edge_type":      "WORKER_NODE_OF",
                "validation_rule_id":    "AWS-EKS-001",
                "relationship_category": "infrastructure",
                "attack_path_category":  "lateral_movement",
                "confidence":            "high",
                "attack_evidence": {
                    "derived_from": "eks_worker_validator",
                    "account":      acct,
                    "region":       region,
                },
            })

    if not edges:
        logger.info("eks_worker: 0 edges after mapping (tenant=%s)", tenant_id)
        return 0

    written = _upsert_attack_edges(di_conn, edges, scan_run_id, tenant_id, account_id, provider)
    logger.info(
        "eks_worker: %d worker_node_of edges → tenant=%s scan=%s",
        written, tenant_id, scan_run_id,
    )
    return written
