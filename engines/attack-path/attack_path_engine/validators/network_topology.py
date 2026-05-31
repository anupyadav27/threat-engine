"""
Validator: Network Topology (VAL-NET-001..002)

Creates: CAN_REACH edges between resources co-located in the same placement domain
(PLACED_IN) or governed by the same policy group (GOVERNED_BY), seeded from entry points.

Catalog-driven: reads PLACED_IN and GOVERNED_BY edges from asset_relationships with no
CSP-specific ARN patterns. Works for AWS, Azure, GCP, OCI — any CSP whose catalog rules
write PLACED_IN (subnet/VNet/VPC placement) and GOVERNED_BY (security group / NSG / NACL).

Logic:
  1. Find all current internet entry points (targets of CAN_REACH from pseudo:internet).
  2. For each entry point, find its co-location domain(s) via PLACED_IN edges.
  3. Find all other resources in those same domains (same target_uid).
  4. Write CAN_REACH: entry_point → co-located resource (confidence=medium).

  Also:
  5. Find resources governed by the same policy group as an entry point (GOVERNED_BY).
  6. Write CAN_REACH: entry_point → co-governed resource (confidence=low).

Confidence levels:
  - medium: same placement domain (subnet/VPC/VNet)
  - low:    same governance group (SG/NSG) — shared group ≠ direct connectivity
"""
from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any, Dict, List, Set

import psycopg2.extras

from .base import INTERNET_NODE, _upsert_attack_edges

logger = logging.getLogger("attack-path.validators.network_topology")


def validate_network_topology(
    di_conn: Any,
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
) -> int:
    """Write CAN_REACH lateral movement edges based on subnet/SG co-location."""
    # Step 1: current internet entry points (targets of existing CAN_REACH edges)
    entry_uids: Set[str] = set()
    try:
        with di_conn.cursor() as cur:
            cur.execute(
                """
                SELECT DISTINCT target_uid
                FROM asset_relationships
                WHERE tenant_id = %s
                  AND is_attack_edge = TRUE
                  AND source_uid = %s
                  AND UPPER(relation_type) = 'CAN_REACH'
                  AND target_uid IS NOT NULL
                """,
                (tenant_id, INTERNET_NODE),
            )
            entry_uids = {row[0] for row in cur.fetchall()}
    except Exception as exc:
        logger.warning("network_topology: entry_uid query failed: %s", exc)
        try:
            di_conn.rollback()
        except Exception:
            pass
        return 0

    if not entry_uids:
        logger.info("network_topology: no entry points, skipping (tenant=%s)", tenant_id)
        return 0

    # Step 2: PLACED_IN edges — resource → subnet
    # Build: subnet_uid → set of resource_uids in that subnet
    subnet_to_resources: Dict[str, Set[str]] = defaultdict(set)
    resource_types: Dict[str, str] = {}
    try:
        with di_conn.cursor() as cur:
            cur.execute(
                """
                SELECT DISTINCT source_uid, target_uid,
                       COALESCE(source_type, '') AS src_type
                FROM asset_relationships
                WHERE tenant_id = %s
                  AND UPPER(relation_type) = 'PLACED_IN'
                  AND source_uid IS NOT NULL
                  AND target_uid IS NOT NULL
                """,
                (tenant_id,),
            )
            for src_uid, subnet_uid, src_type in cur.fetchall():
                subnet_to_resources[subnet_uid].add(src_uid)
                if src_uid not in resource_types:
                    resource_types[src_uid] = src_type
    except Exception as exc:
        logger.warning("network_topology: PLACED_IN query failed: %s", exc)
        try:
            di_conn.rollback()
        except Exception:
            pass

    # Step 3: GOVERNED_BY edges — resource → security_group
    # Build: sg_uid → set of resource_uids governed by that SG
    sg_to_resources: Dict[str, Set[str]] = defaultdict(set)
    try:
        with di_conn.cursor() as cur:
            cur.execute(
                """
                SELECT DISTINCT source_uid, target_uid,
                       COALESCE(source_type, '') AS src_type
                FROM asset_relationships
                WHERE tenant_id = %s
                  AND UPPER(relation_type) = 'GOVERNED_BY'
                  AND source_uid IS NOT NULL
                  AND target_uid IS NOT NULL
                """,
                (tenant_id,),
            )
            for src_uid, sg_uid, src_type in cur.fetchall():
                sg_to_resources[sg_uid].add(src_uid)
                if src_uid not in resource_types:
                    resource_types[src_uid] = src_type
    except Exception as exc:
        logger.warning("network_topology: GOVERNED_BY query failed: %s", exc)
        try:
            di_conn.rollback()
        except Exception:
            pass

    edges: List[Dict[str, Any]] = []
    seen_pairs: Set[tuple] = set()

    # Step 4: entry_point → co-subnet resources (confidence=medium)
    for entry_uid in entry_uids:
        for subnet_uid, residents in subnet_to_resources.items():
            if entry_uid not in residents:
                continue
            for co_uid in residents:
                if co_uid == entry_uid:
                    continue
                pair = (entry_uid, co_uid)
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)
                edges.append({
                    "source_uid":           entry_uid,
                    "source_type":          resource_types.get(entry_uid, ""),
                    "target_uid":           co_uid,
                    "target_type":          resource_types.get(co_uid, ""),
                    "relation_type":        "CAN_REACH",
                    "attack_edge_type":     "CAN_REACH",
                    "validation_rule_id":   "VAL-NET-001",
                    "attack_path_category": "lateral_movement",
                    "confidence":           "medium",
                    "attack_evidence":      {
                        "derived_from": "network_topology_subnet",
                        "via_subnet":   subnet_uid,
                    },
                })

    # Step 5: entry_point → co-SG resources (confidence=low)
    for entry_uid in entry_uids:
        for sg_uid, members in sg_to_resources.items():
            if entry_uid not in members:
                continue
            for co_uid in members:
                if co_uid == entry_uid:
                    continue
                pair = (entry_uid, co_uid)
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)
                edges.append({
                    "source_uid":           entry_uid,
                    "source_type":          resource_types.get(entry_uid, ""),
                    "target_uid":           co_uid,
                    "target_type":          resource_types.get(co_uid, ""),
                    "relation_type":        "CAN_REACH",
                    "attack_edge_type":     "CAN_REACH",
                    "validation_rule_id":   "VAL-NET-002",
                    "attack_path_category": "lateral_movement",
                    "confidence":           "low",
                    "attack_evidence":      {
                        "derived_from": "network_topology_sg",
                        "via_sg":       sg_uid,
                    },
                })

    if not edges:
        logger.info(
            "network_topology: 0 lateral movement edges (entry=%d subnets=%d sgs=%d) tenant=%s",
            len(entry_uids), len(subnet_to_resources), len(sg_to_resources), tenant_id,
        )
        return 0

    written = _upsert_attack_edges(di_conn, edges, scan_run_id, tenant_id, account_id, provider)
    logger.info(
        "network_topology: %d CAN_REACH lateral edges "
        "(entry=%d subnets=%d sgs=%d) tenant=%s scan=%s",
        written, len(entry_uids), len(subnet_to_resources), len(sg_to_resources),
        tenant_id, scan_run_id,
    )
    return written
