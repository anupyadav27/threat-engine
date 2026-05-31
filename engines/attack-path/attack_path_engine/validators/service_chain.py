"""
Validator: Service Chain (AWS-SVC-001..005, VAL-SVC-*)

Creates:
  ALB / CloudFront / API Gateway → CAN_REACH → Target
  API Gateway / EventBridge / SNS → CAN_INVOKE → Lambda
  EKS cluster → CONTAINS → nodegroup → CONTAINS → EC2 (lateral movement chain)
  ELB → TG → EC2/Lambda (derived from asset_inventory when catalog edges are missing)

Reads ROUTES_TO, INVOKES, HAS_INTEGRATION, TRIGGERS, CONTAINS edges from asset_relationships.
Also builds ELB→TG→target edges directly from asset_inventory as a fallback when
catalog relationship writer hasn't yet processed elbv2 discovery data.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

import psycopg2.extras

from .base import _upsert_attack_edges

logger = logging.getLogger("attack-path.validators.service_chain")

# relation_type → (attack_edge_type, validation_rule_id, attack_path_category)
_CHAIN_RULES: Dict[str, tuple] = {
    "routes_to":          ("CAN_REACH",  "AWS-SVC-001", "internet_exposure"),
    "invokes":            ("CAN_INVOKE", "AWS-SVC-003", "internet_exposure"),
    "has_integration":    ("CAN_INVOKE", "AWS-SVC-003", "internet_exposure"),
    "triggers":           ("CAN_INVOKE", "AWS-SVC-005", "lateral_movement"),
    "forwards_to":        ("CAN_REACH",  "AWS-SVC-002", "internet_exposure"),
    "serves_traffic_for": ("CAN_REACH",  "AWS-SVC-002", "internet_exposure"),
    # EKS containment: cluster→nodegroup→EC2 lateral movement chain
    "contains":           ("CAN_REACH",  "AWS-SVC-006", "lateral_movement"),
    # SSM agent reachability
    "managed_by_agent":   ("CAN_REACH",  "AWS-SSM-001", "lateral_movement"),
    # Event-driven chains: SNS→SQS/Lambda, EventBridge→targets
    "publishes_to":       ("CAN_REACH",  "AWS-SVC-007", "lateral_movement"),
    # Pull-based consumers: SQS→Lambda trigger, Kinesis→Lambda
    "delivers_to":        ("CAN_REACH",  "AWS-SVC-008", "lateral_movement"),
    "subscribes_to":      ("CAN_REACH",  "AWS-SVC-008", "lateral_movement"),
    # Orchestration: Step Functions→Lambda/ECS, Batch→ECS task
    "executes":           ("CAN_INVOKE", "AWS-SVC-009", "lateral_movement"),
    "orchestrates":       ("CAN_INVOKE", "AWS-SVC-009", "lateral_movement"),
    # AppSync→Lambda resolvers, IoT→Lambda rules
    "resolves_via":       ("CAN_INVOKE", "AWS-SVC-010", "lateral_movement"),
}


def validate_service_chain(
    di_conn: Any,
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
) -> int:
    """Write CAN_REACH / CAN_INVOKE edges for service routing chains."""
    rel_types = list(_CHAIN_RULES.keys())
    placeholders = ",".join(["%s"] * len(rel_types))

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
                (tenant_id, scan_run_id, *rel_types),
            )
            rows = cur.fetchall()
    except Exception as exc:
        logger.warning("service_chain: query failed: %s", exc)
        try:
            di_conn.rollback()
        except Exception:
            pass
        return 0

    if not rows:
        logger.info("service_chain: 0 routing edges found tenant=%s scan=%s", tenant_id, scan_run_id)
        return 0

    edges: List[Dict[str, Any]] = []
    for row in rows:
        rel = row["rel_type"]
        edge_type, rule_id, ap_cat = _CHAIN_RULES.get(rel, ("CAN_REACH", "AWS-SVC-001", "internet_exposure"))
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
                "raw_relation_type": row["rel_type"],
                "derived_from":      "service_chain_validator",
            },
        })

    written = _upsert_attack_edges(di_conn, edges, scan_run_id, tenant_id, account_id, provider)

    # ELB chain: build LB→TG and TG→EC2/Lambda edges from asset_inventory.
    # The catalog relationship writer needs elbv2 discovery data to write these; this
    # fallback derives them directly so attack paths work even before a full rescan.
    elb_written = _build_elb_chain_edges(di_conn, scan_run_id, tenant_id, account_id, provider)

    total = written + elb_written
    logger.info(
        "service_chain: %d CAN_REACH/CAN_INVOKE edges (%d elb chain) → tenant=%s scan=%s",
        total, elb_written, tenant_id, scan_run_id,
    )
    return total


def _build_elb_chain_edges(
    di_conn: Any,
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
) -> int:
    """Derive LB→TG and TG→EC2/Lambda attack edges from asset_inventory emitted_fields.

    Runs only when the catalog relationship writer hasn't yet produced elbv2 ROUTES_TO
    edges (i.e. the first scan after step6 elbv2 discovery data is available).
    Skips if asset_relationships already has elbv2_load_balancer→elbv2_target_group edges.
    """
    # Check if edges already exist — avoid double-writing
    try:
        with di_conn.cursor() as cur:
            cur.execute(
                """
                SELECT COUNT(*) FROM asset_relationships
                WHERE tenant_id = %s AND is_attack_edge = TRUE
                  AND source_type = 'elbv2_load_balancer'
                  AND UPPER(relation_type) IN ('ROUTES_TO', 'CAN_REACH')
                """,
                (tenant_id,),
            )
            if (cur.fetchone() or [0])[0] > 0:
                return 0
    except Exception:
        return 0

    edges: List[Dict[str, Any]] = []
    try:
        # Step 1: internet-facing LBs
        with di_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT resource_uid, emitted_fields
                FROM asset_inventory
                WHERE tenant_id = %s AND resource_type = 'elbv2_load_balancer'
                  AND emitted_fields->>'Scheme' = 'internet-facing'
                  AND resource_uid IS NOT NULL
                ORDER BY last_seen_at DESC
                """,
                (tenant_id,),
            )
            lbs = cur.fetchall()

        if not lbs:
            return 0

        lb_arns = {row["resource_uid"] for row in lbs}

        # Step 2: target groups referencing these LBs (via LoadBalancerArns JSONB array)
        with di_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT resource_uid AS tg_arn,
                       emitted_fields->>'TargetType' AS target_type_field,
                       emitted_fields->'LoadBalancerArns' AS lb_arns_json
                FROM asset_inventory
                WHERE tenant_id = %s AND resource_type = 'elbv2_target_group'
                  AND resource_uid IS NOT NULL
                ORDER BY last_seen_at DESC
                """,
                (tenant_id,),
            )
            tgs = cur.fetchall()

        tg_to_lbs: Dict[str, List[str]] = {}
        for tg in tgs:
            tg_arn = tg["tg_arn"]
            lb_arns_json = tg["lb_arns_json"]
            if not lb_arns_json:
                continue
            referenced_lbs = lb_arns_json if isinstance(lb_arns_json, list) else []
            matched = [lb for lb in referenced_lbs if lb in lb_arns]
            if matched:
                tg_to_lbs[tg_arn] = matched

        # Write LB → TG edges
        for tg_arn, matched_lbs in tg_to_lbs.items():
            for lb_arn in matched_lbs:
                edges.append({
                    "source_uid":           lb_arn,
                    "source_type":          "elbv2_load_balancer",
                    "target_uid":           tg_arn,
                    "target_type":          "elbv2_target_group",
                    "relation_type":        "CAN_REACH",
                    "attack_edge_type":     "CAN_REACH",
                    "validation_rule_id":   "AWS-SVC-002",
                    "attack_path_category": "internet_exposure",
                    "confidence":           "high",
                    "attack_evidence":      {"derived_from": "elb_chain_builder"},
                })

        # Step 3: EC2/Lambda targets via target health emitted_fields
        if tg_to_lbs:
            with di_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT resource_uid AS tg_arn,
                           emitted_fields->'Target'->>'Id' AS target_id
                    FROM asset_inventory
                    WHERE tenant_id = %s
                      AND resource_type = 'elbv2_describe_target_health'
                      AND emitted_fields->'Target'->>'Id' IS NOT NULL
                    ORDER BY last_seen_at DESC
                    """,
                    (tenant_id,),
                )
                health_rows = cur.fetchall()

            for h in health_rows:
                tg_arn = h["tg_arn"] or ""
                target_id = h["target_id"] or ""
                if not target_id or tg_arn not in tg_to_lbs:
                    continue
                tgt_type = "lambda_function" if target_id.startswith("arn:aws:lambda:") else "ec2_instance"
                edges.append({
                    "source_uid":           tg_arn,
                    "source_type":          "elbv2_target_group",
                    "target_uid":           target_id,
                    "target_type":          tgt_type,
                    "relation_type":        "CAN_REACH",
                    "attack_edge_type":     "CAN_REACH",
                    "validation_rule_id":   "AWS-SVC-002",
                    "attack_path_category": "internet_exposure",
                    "confidence":           "high",
                    "attack_evidence":      {"derived_from": "elb_chain_builder"},
                })

    except Exception as exc:
        logger.warning("elb_chain_builder failed (non-fatal): %s", exc)
        try:
            di_conn.rollback()
        except Exception:
            pass
        return 0

    if not edges:
        return 0
    return _upsert_attack_edges(di_conn, edges, scan_run_id, tenant_id, account_id, provider)
