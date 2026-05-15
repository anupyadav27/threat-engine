"""
EdgeBuilder — reads inventory_relationships and creates typed security edges
between Resource nodes in Neo4j.

Each relation_type maps to a specific Neo4j edge type (ASSUMES, ROUTES_TO, etc.)
via a type-dispatch map. No APOC dependency, no CONNECTED_TO fallback.

Edge type IS the semantic in a property graph — [:ASSUMES] means something
fundamentally different from [:ROUTES_TO]. Collapsing everything into
[:CONNECTED_TO {relation_type: ...}] and filtering by property fights the data
model, breaks pattern selectivity, and causes cartesian-product noise in T2/T3
queries (internet_exposed × all edges = false positives).

CP1-01: all Cypher via $parameter bindings (edge types are code literals, not params).
"""
from __future__ import annotations

import os
import logging
from typing import Any, Dict, List

from neo4j import Driver

logger = logging.getLogger(__name__)

# relation_type → attack_path_category
_CATEGORY_MAP: Dict[str, str] = {
    "assumes":               "privilege_escalation",
    "uses":                  "privilege_escalation",
    "provides_identity_for": "privilege_escalation",
    "internet_connected":    "exposure",
    "attached_to":           "lateral_movement",
    "routes_to":             "lateral_movement",
    "runs_on":               "execution",
    "invokes":               "execution",
    "encrypted_by":          "data_access",
    "logging_enabled_to":    "data_flow",
    "backs_up_to":           "data_flow",
    "replicates_to":         "data_flow",
}

# Typed-edge Cypher per relation_type.
# Edge type is a Cypher literal — Neo4j does not allow parameterized edge types.
# Stub both endpoint nodes ON CREATE so edges are written even for resources
# that have no FAIL findings in MisconfigLoader (e.g. Lambda, KMS keys).
_TYPED_EDGE_CYPHER: Dict[str, str] = {
    "assumes": """
        MERGE (f:Resource {resource_uid: $from_uid, tenant_id: $tid})
        ON CREATE SET f.resource_type=$from_type, f.account_id=$account_id, f.region='', f.provider=$provider
        MERGE (t:Resource {resource_uid: $to_uid, tenant_id: $tid})
        ON CREATE SET t.resource_type=$to_type, t.account_id=$account_id, t.region='', t.provider=$provider
        MERGE (f)-[e:ASSUMES {tenant_id: $tid}]->(t)
        SET e.attack_path_category = $category
    """,
    "uses": """
        MERGE (f:Resource {resource_uid: $from_uid, tenant_id: $tid})
        ON CREATE SET f.resource_type=$from_type, f.account_id=$account_id, f.region='', f.provider=$provider
        MERGE (t:Resource {resource_uid: $to_uid, tenant_id: $tid})
        ON CREATE SET t.resource_type=$to_type, t.account_id=$account_id, t.region='', t.provider=$provider
        MERGE (f)-[e:USES {tenant_id: $tid}]->(t)
        SET e.attack_path_category = $category
    """,
    "provides_identity_for": """
        MERGE (f:Resource {resource_uid: $from_uid, tenant_id: $tid})
        ON CREATE SET f.resource_type=$from_type, f.account_id=$account_id, f.region='', f.provider=$provider
        MERGE (t:Resource {resource_uid: $to_uid, tenant_id: $tid})
        ON CREATE SET t.resource_type=$to_type, t.account_id=$account_id, t.region='', t.provider=$provider
        MERGE (f)-[e:PROVIDES_IDENTITY_FOR {tenant_id: $tid}]->(t)
        SET e.attack_path_category = $category
    """,
    "attached_to": """
        MERGE (f:Resource {resource_uid: $from_uid, tenant_id: $tid})
        ON CREATE SET f.resource_type=$from_type, f.account_id=$account_id, f.region='', f.provider=$provider
        MERGE (t:Resource {resource_uid: $to_uid, tenant_id: $tid})
        ON CREATE SET t.resource_type=$to_type, t.account_id=$account_id, t.region='', t.provider=$provider
        MERGE (f)-[e:ATTACHED_TO {tenant_id: $tid}]->(t)
        SET e.attack_path_category = $category
    """,
    "routes_to": """
        MERGE (f:Resource {resource_uid: $from_uid, tenant_id: $tid})
        ON CREATE SET f.resource_type=$from_type, f.account_id=$account_id, f.region='', f.provider=$provider
        MERGE (t:Resource {resource_uid: $to_uid, tenant_id: $tid})
        ON CREATE SET t.resource_type=$to_type, t.account_id=$account_id, t.region='', t.provider=$provider
        MERGE (f)-[e:ROUTES_TO {tenant_id: $tid}]->(t)
        SET e.attack_path_category = $category
    """,
    "runs_on": """
        MERGE (f:Resource {resource_uid: $from_uid, tenant_id: $tid})
        ON CREATE SET f.resource_type=$from_type, f.account_id=$account_id, f.region='', f.provider=$provider
        MERGE (t:Resource {resource_uid: $to_uid, tenant_id: $tid})
        ON CREATE SET t.resource_type=$to_type, t.account_id=$account_id, t.region='', t.provider=$provider
        MERGE (f)-[e:RUNS_ON {tenant_id: $tid}]->(t)
        SET e.attack_path_category = $category
    """,
    "invokes": """
        MERGE (f:Resource {resource_uid: $from_uid, tenant_id: $tid})
        ON CREATE SET f.resource_type=$from_type, f.account_id=$account_id, f.region='', f.provider=$provider
        MERGE (t:Resource {resource_uid: $to_uid, tenant_id: $tid})
        ON CREATE SET t.resource_type=$to_type, t.account_id=$account_id, t.region='', t.provider=$provider
        MERGE (f)-[e:INVOKES {tenant_id: $tid}]->(t)
        SET e.attack_path_category = $category
    """,
    "encrypted_by": """
        MERGE (f:Resource {resource_uid: $from_uid, tenant_id: $tid})
        ON CREATE SET f.resource_type=$from_type, f.account_id=$account_id, f.region='', f.provider=$provider
        MERGE (t:Resource {resource_uid: $to_uid, tenant_id: $tid})
        ON CREATE SET t.resource_type=$to_type, t.account_id=$account_id, t.region='', t.provider=$provider
        MERGE (f)-[e:ENCRYPTED_BY {tenant_id: $tid}]->(t)
        SET e.attack_path_category = $category
    """,
    "logging_enabled_to": """
        MERGE (f:Resource {resource_uid: $from_uid, tenant_id: $tid})
        ON CREATE SET f.resource_type=$from_type, f.account_id=$account_id, f.region='', f.provider=$provider
        MERGE (t:Resource {resource_uid: $to_uid, tenant_id: $tid})
        ON CREATE SET t.resource_type=$to_type, t.account_id=$account_id, t.region='', t.provider=$provider
        MERGE (f)-[e:LOGGING_ENABLED_TO {tenant_id: $tid}]->(t)
        SET e.attack_path_category = $category
    """,
    "backs_up_to": """
        MERGE (f:Resource {resource_uid: $from_uid, tenant_id: $tid})
        ON CREATE SET f.resource_type=$from_type, f.account_id=$account_id, f.region='', f.provider=$provider
        MERGE (t:Resource {resource_uid: $to_uid, tenant_id: $tid})
        ON CREATE SET t.resource_type=$to_type, t.account_id=$account_id, t.region='', t.provider=$provider
        MERGE (f)-[e:BACKS_UP_TO {tenant_id: $tid}]->(t)
        SET e.attack_path_category = $category
    """,
    "replicates_to": """
        MERGE (f:Resource {resource_uid: $from_uid, tenant_id: $tid})
        ON CREATE SET f.resource_type=$from_type, f.account_id=$account_id, f.region='', f.provider=$provider
        MERGE (t:Resource {resource_uid: $to_uid, tenant_id: $tid})
        ON CREATE SET t.resource_type=$to_type, t.account_id=$account_id, t.region='', t.provider=$provider
        MERGE (f)-[e:REPLICATES_TO {tenant_id: $tid}]->(t)
        SET e.attack_path_category = $category
    """,
}

# Special: Internet VirtualNode sentinel for internet_connected edges.
_MERGE_INTERNET_EDGE = """
MERGE (from:Resource {resource_uid: $from_uid, tenant_id: $tid})
ON CREATE SET from.resource_type = $from_type,
              from.account_id    = $account_id,
              from.region        = '',
              from.provider      = $provider
MERGE (internet:Internet:VirtualNode {resource_uid: 'internet:0.0.0.0/0', tenant_id: $tid})
ON CREATE SET internet.resource_type = 'Internet'
MERGE (from)-[e:INTERNET_CONNECTED {tenant_id: $tid}]->(internet)
SET e.attack_path_category = 'exposure'
"""


class EdgeBuilder:
    """Loads typed security relationship edges into the Neo4j threat graph."""

    def __init__(
        self,
        inventory_conn: Any,
        neo4j_driver: Driver,
    ) -> None:
        self._inventory_conn = inventory_conn
        self._driver = neo4j_driver

    def build(
        self,
        tenant_id: str,
        account_id: str,
    ) -> Dict[str, int]:
        """Create typed attack-path edges between Resource nodes in Neo4j.

        Returns:
            Dict with edge_count and skipped_count.
        """
        rows = self._fetch_edges(tenant_id, account_id)
        if not rows:
            logger.info(
                "No attack-path edges found for tenant %s / account %s",
                tenant_id, account_id,
            )
            return {"edge_count": 0, "skipped_count": 0}

        edge_count = 0
        skipped_count = 0
        db = os.environ.get("NEO4J_DATABASE", "neo4j")

        with self._driver.session(database=db) as session:
            for row in rows:
                relation_type = (row.get("relation_type") or "").lower()

                if relation_type not in _CATEGORY_MAP:
                    skipped_count += 1
                    continue

                from_uid = row.get("from_resource_uid") or ""
                to_uid = row.get("to_resource_uid") or ""
                from_type = row.get("from_resource_type") or "Unknown"
                to_type = row.get("to_resource_type") or "Unknown"

                if not from_uid:
                    skipped_count += 1
                    continue

                if relation_type == "internet_connected":
                    session.run(
                        _MERGE_INTERNET_EDGE,
                        from_uid=from_uid,
                        from_type=from_type,
                        tid=tenant_id,
                        account_id=account_id,
                        provider=row.get("provider", "aws"),
                    )
                    edge_count += 1
                    continue

                if not to_uid:
                    skipped_count += 1
                    continue

                cypher = _TYPED_EDGE_CYPHER.get(relation_type)
                if not cypher:
                    skipped_count += 1
                    continue

                session.run(
                    cypher,
                    from_uid=from_uid,
                    to_uid=to_uid,
                    from_type=from_type,
                    to_type=to_type,
                    tid=tenant_id,
                    account_id=account_id,
                    provider=row.get("provider", "aws"),
                    category=_CATEGORY_MAP[relation_type],
                )
                edge_count += 1

        logger.info(
            "EdgeBuilder: %d edges written, %d skipped",
            edge_count, skipped_count,
            extra={"tenant_id": tenant_id, "account_id": account_id},
        )
        return {"edge_count": edge_count, "skipped_count": skipped_count}

    def _fetch_edges(
        self,
        tenant_id: str,
        account_id: str,
    ) -> List[Dict[str, Any]]:
        """Query inventory_relationships for all known attack-path relation types."""
        cur = self._inventory_conn.cursor()
        cur.execute(
            """
            SELECT
                from_uid            AS from_resource_uid,
                to_uid              AS to_resource_uid,
                from_resource_type,
                to_resource_type,
                relation_type,
                'aws'               AS provider
            FROM inventory_relationships
            WHERE tenant_id  = %s
              AND account_id = %s
              AND relation_type IN (
                  'assumes', 'uses', 'provides_identity_for',
                  'internet_connected',
                  'attached_to', 'routes_to',
                  'runs_on', 'invokes',
                  'encrypted_by',
                  'logging_enabled_to', 'backs_up_to', 'replicates_to'
              )
            """,
            (tenant_id, account_id),
        )
        rows = cur.fetchall()
        cur.close()
        return list(rows)
