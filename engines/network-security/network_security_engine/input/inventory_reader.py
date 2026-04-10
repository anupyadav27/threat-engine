"""
Network Security — Inventory Reader

Reads inventory_relationships to build network topology graph.
Used by L1 (topology) and L4 (SG→resource attachment).
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

import psycopg2
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)

# Relationship types relevant to network topology
NETWORK_RELATIONSHIP_TYPES = {
    "connected_to",         # subnet → vpc
    "routes_to",            # route_table → subnet
    "allows_traffic_from",  # sg → sg (lateral movement)
    "attached_to",          # sg → eni → ec2
    "internet_connected",   # resource → Internet
    "exposed_through",      # resource → lb
    "serves_traffic_for",   # lb → target
    "protects",             # waf → lb
    "contained_by",         # subnet → vpc, resource → subnet
    "member_of",            # eni → sg
    "manages",              # route_table → subnet
}

# Resource types that represent network infrastructure
NETWORK_INFRA_TYPES = {
    "ec2.security-group", "ec2.instance", "ec2.network-interface",
    "ec2.subnet", "ec2.vpc", "vpc.subnet", "vpc.vpc",
    "vpc.internet-gateway", "vpc.nat-gateway",
    "elasticloadbalancingv2.loadbalancer", "elbv2.loadbalancer",
    "elb.loadbalancer", "wafv2.web-acl",
}


def _get_inventory_conn():
    """Return a fresh psycopg2 connection to the inventory DB."""
    return psycopg2.connect(
        host=os.getenv("INVENTORY_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("INVENTORY_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("INVENTORY_DB_NAME", "threat_engine_inventory"),
        user=os.getenv("INVENTORY_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("INVENTORY_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
        connect_timeout=10,
    )


class NetworkInventoryReader:
    """Read inventory relationships for network topology."""

    def load_network_relationships(
        self,
        scan_run_id: str,
        tenant_id: str,
    ) -> List[Dict[str, Any]]:
        """Load relationships relevant to network topology."""
        conn = _get_inventory_conn()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT
                        source_resource_uid,
                        source_resource_type,
                        target_resource_uid,
                        target_resource_type,
                        relationship_type,
                        relationship_data
                    FROM inventory_relationships
                    WHERE scan_run_id = %s
                      AND tenant_id = %s
                      AND (
                          relationship_type = ANY(%s)
                          OR source_resource_type = ANY(%s)
                          OR target_resource_type = ANY(%s)
                      )
                """, [scan_run_id, tenant_id,
                      list(NETWORK_RELATIONSHIP_TYPES),
                      list(NETWORK_INFRA_TYPES),
                      list(NETWORK_INFRA_TYPES)])
                rows = cur.fetchall()

            logger.info("Loaded %d network relationships for scan %s",
                        len(rows), scan_run_id)
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def load_sg_attachments(
        self,
        scan_run_id: str,
        tenant_id: str,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Load security group → resource attachments.

        Returns:
            Dict keyed by sg_id with lists of attached resource dicts.
        """
        conn = _get_inventory_conn()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT
                        source_resource_uid,
                        source_resource_type,
                        target_resource_uid,
                        target_resource_type,
                        relationship_type
                    FROM inventory_relationships
                    WHERE scan_run_id = %s
                      AND tenant_id = %s
                      AND (
                          (source_resource_type LIKE '%%security-group%%'
                           AND relationship_type IN ('attached_to', 'member_of'))
                          OR
                          (target_resource_type LIKE '%%security-group%%'
                           AND relationship_type IN ('attached_to', 'member_of'))
                      )
                """, [scan_run_id, tenant_id])
                rows = cur.fetchall()

            # Build sg_id → [resources] map
            sg_map: Dict[str, List[Dict]] = {}
            for r in rows:
                src_type = r.get("source_resource_type", "")
                tgt_type = r.get("target_resource_type", "")

                if "security-group" in src_type:
                    sg_uid = r["source_resource_uid"]
                    resource = {
                        "uid": r["target_resource_uid"],
                        "type": tgt_type,
                    }
                else:
                    sg_uid = r["target_resource_uid"]
                    resource = {
                        "uid": r["source_resource_uid"],
                        "type": src_type,
                    }
                sg_map.setdefault(sg_uid, []).append(resource)

            return sg_map
        finally:
            conn.close()

    def load_internet_connected_resources(
        self,
        scan_run_id: str,
        tenant_id: str,
    ) -> List[Dict[str, Any]]:
        """Load resources marked as internet_connected by inventory."""
        conn = _get_inventory_conn()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT
                        source_resource_uid,
                        source_resource_type,
                        target_resource_uid,
                        target_resource_type,
                        relationship_data
                    FROM inventory_relationships
                    WHERE scan_run_id = %s
                      AND tenant_id = %s
                      AND relationship_type = 'internet_connected'
                """, [scan_run_id, tenant_id])
                return [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()
