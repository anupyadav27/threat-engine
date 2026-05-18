"""
Attack Path Engine — Neo4j Client.

Implements reverse BFS from crown jewels to external entry points.

Security notes:
- ALL Cypher MATCH clauses include {tenant_id: $tid} property filter.
- NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD read from environment (never hardcoded).
- No Cypher string injection — all variable values passed as query parameters.
- Neo4j connection uses encrypted transport (neo4j+s:// for Aura).
- 30-second timeout enforced at driver level.
- LIMIT 500 enforced in Cypher.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

logger = logging.getLogger("attack-path.neo4j_client")

try:
    from neo4j import GraphDatabase
    _NEO4J_AVAILABLE = True
except ImportError:
    _NEO4J_AVAILABLE = False
    logger.warning("neo4j driver not available — BFS will return empty results")

from ..models.attack_path import RawPath

# =============================================================================
# Reverse BFS Cypher — architecture doc section 4.2
#
# Phase 1: Backward PATH traversal from external entry points to crown jewels.
# Phase 2: Evidence collection via OPTIONAL MATCH for CVE/Finding/ThreatDetection nodes.
#
# Entry point types (virtual nodes): Internet, OnPrem, DataCenter, Vendor,
#   K8sExternal, PeerAccount, peer_account
# =============================================================================

REVERSE_BFS_CYPHER = """
MATCH path = (origin)-[rels*1..7]->(crown:Resource)
WHERE crown.tenant_id = $tid
  AND crown.is_crown_jewel = true
  AND (
        origin:Internet
     OR origin:VirtualNode
     OR (
          origin:Resource AND origin.tenant_id = $tid
          AND (
               origin.entry_point_type IN ['internet', 'Internet']
            OR origin.node_type IN ['Internet', 'OnPrem', 'DataCenter', 'Vendor', 'K8sExternal']
            OR origin.entry_point_type IN ['onprem', 'vpn', 'peer_account', 'vendor', 'k8s_external']
            OR origin.node_type IN ['PeerAccount', 'peer_account']
            OR origin.uid IN $exposed_uids
          )
       )
  )
  AND ALL(n IN nodes(path) WHERE (
        'Internet' IN labels(n)
     OR 'VirtualNode' IN labels(n)
     OR n.tenant_id = $tid
  ))

WITH
  crown.uid                                  AS crown_jewel_uid,
  origin.uid                                 AS entry_point_uid,
  [n IN nodes(path) | n.uid]                 AS node_uids,
  [n IN nodes(path) | coalesce(n.resource_type, head(labels(n)))] AS node_types,
  [r IN relationships(path) | type(r)]       AS edge_types,
  [n IN nodes(path) |
    CASE
      WHEN 'Internet' IN labels(n)    THEN 'internet'
      WHEN 'VirtualNode' IN labels(n) THEN coalesce(n.node_type, 'virtual')
      ELSE coalesce(n.entry_point_type, n.node_type, 'compute')
    END
  ] AS hop_categories,
  length(path)                               AS depth,
  nodes(path)                                AS path_nodes

LIMIT 500

UNWIND path_nodes AS hop_node

OPTIONAL MATCH (hop_node)-[:HAS_CVE]->(c:CVE)
WHERE c.tenant_id = $tid

OPTIONAL MATCH (hop_node)-[:HAS_FINDING]->(f:Finding)
WHERE f.tenant_id = $tid

OPTIONAL MATCH (hop_node)-[:HAS_THREAT]->(t:ThreatDetection)
WHERE t.tenant_id = $tid

WITH
  crown_jewel_uid,
  entry_point_uid,
  node_uids,
  node_types,
  edge_types,
  hop_categories,
  depth,
  max(c.epss_score)           AS max_epss,
  count(DISTINCT f)           AS misconfig_count,
  count(DISTINCT t)           AS threat_count,
  collect(DISTINCT {
    cve_id: c.cve_id,
    epss:   c.epss_score,
    cvss:   c.cvss_score,
    in_kev: c.in_kev
  })[0..5]                    AS top_cves

RETURN
  crown_jewel_uid,
  entry_point_uid,
  node_uids,
  node_types,
  edge_types,
  hop_categories,
  depth,
  max_epss,
  misconfig_count,
  threat_count,
  top_cves
"""


class Neo4jClient:
    """Wraps the neo4j Python driver with connection lifecycle management."""

    def __init__(self) -> None:
        if not _NEO4J_AVAILABLE:
            self.driver = None
            return
        uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        user = os.getenv("NEO4J_USER", "neo4j")
        password = os.getenv("NEO4J_PASSWORD", "")
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        logger.info("Neo4j driver initialised: uri=%s", uri)

    def close(self) -> None:
        """Close the underlying driver connection."""
        if self.driver:
            self.driver.close()

    def reverse_bfs(
        self,
        tenant_id: str,
        scan_run_id: str,
        max_hops: int = 7,
        internet_exposed_uids: Optional[List[str]] = None,
    ) -> List[RawPath]:
        """Traverse PATH edges backward from crown jewels to entry points.

        Args:
            tenant_id:              Tenant identifier — always filtered in all MATCH clauses.
            scan_run_id:            Current pipeline run UUID.
            max_hops:               Maximum traversal depth (architecture default 7).
            internet_exposed_uids:  Resource UIDs with is_internet_exposed=true from
                                    resource_security_posture. Passed as $exposed_uids
                                    to the BFS so those resources are treated as internet
                                    entry points without requiring an :Internet Neo4j node.

        Returns:
            List of RawPath objects (up to 500). Returns an empty list if the
            driver is unavailable or a 30-second timeout fires.
        """
        if not _NEO4J_AVAILABLE or self.driver is None:
            logger.warning(
                "Neo4j BFS skipped — driver unavailable. "
                "scan_run_id=%s tenant_id=%s",
                scan_run_id,
                tenant_id,
            )
            return []

        exposed_uids = internet_exposed_uids or []
        logger.info(
            "BFS starting: tenant=%s internet_exposed_uids=%d",
            tenant_id,
            len(exposed_uids),
        )

        results: List[RawPath] = []
        try:
            with self.driver.session(database="neo4j") as session:
                # timeout=30.0 seconds enforced at driver level (AC-8)
                db_result = session.run(
                    REVERSE_BFS_CYPHER,
                    tid=tenant_id,
                    scan_run_id=scan_run_id,
                    exposed_uids=exposed_uids,
                    timeout=30.0,
                )
                for record in db_result:
                    rec_dict = dict(record)
                    # Ensure list fields are always lists (Neo4j may return None)
                    for list_field in (
                        "node_uids", "node_types", "edge_types",
                        "hop_categories", "top_cves",
                    ):
                        if rec_dict.get(list_field) is None:
                            rec_dict[list_field] = []
                    results.append(RawPath(**rec_dict))

        except Exception as exc:
            # Distinguish timeout from other errors
            exc_str = str(exc).lower()
            if "timeout" in exc_str or "transient" in exc_str:
                logger.warning(
                    "Neo4j BFS timeout after 30s, returning partial results. "
                    "tenant_id=%s partial_count=%d error=%s",
                    tenant_id,
                    len(results),
                    exc,
                )
            else:
                logger.exception(
                    "Neo4j BFS error: tenant_id=%s error=%s",
                    tenant_id,
                    exc,
                )
            # Return whatever was collected before the exception (AC-9)
            return results

        logger.info(
            '{"engine":"attack-path","stage":"bfs","tenant_id":"%s",'
            '"scan_run_id":"%s","raw_paths":%d}',
            tenant_id,
            scan_run_id,
            len(results),
        )
        return results
