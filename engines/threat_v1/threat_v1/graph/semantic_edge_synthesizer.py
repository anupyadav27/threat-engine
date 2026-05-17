"""
SemanticEdgeSynthesizer — derives high-level attack-path edges from existing
typed edges + boolean flags set by FlagMapper.

Must run AFTER EdgeBuilder and FlagMapper so all source edges and flags exist.

Synthesized edges (never written by EdgeBuilder — these are semantic inferences):

  CAN_ESCALATE_TO  — Resource -[:ASSUMES]-> IAM role where is_admin_role=true
                     "this compute resource can reach an admin IAM role"

  CAN_ACCESS       — Resource -[:ASSUMES]-> admin role with crown-jewel data path,
                     OR Resource -[:ATTACHED_TO|RUNS_ON]-> data resource directly.
                     "this resource has a read/write path to a sensitive data store"

  EXECUTES_IN      — Resource -[:RUNS_ON|INVOKES]-> execution environment.
                     "this workload runs inside this container/task/VPC context"

  FLOWS_TO         — Resource -[:ROUTES_TO|ATTACHED_TO]-> downstream resource.
                     "network traffic can flow from here to there"

CP1-01: edge types are code literals; all runtime values are $parameter bindings.
"""
from __future__ import annotations

import logging
import os
from typing import Any

from neo4j import Driver

logger = logging.getLogger(__name__)

_DB = lambda: os.environ.get("NEO4J_DATABASE", "neo4j")  # noqa: E731

# Synthesize CAN_ESCALATE_TO: compute → admin IAM role via ASSUMES
_SYNTH_CAN_ESCALATE_TO = """
MATCH (r:Resource {tenant_id: $tid})-[:ASSUMES]->(iam:Resource {tenant_id: $tid})
WHERE iam.is_admin_role = true
  AND r.account_id = $account_id
MERGE (r)-[e:CAN_ESCALATE_TO {tenant_id: $tid}]->(iam)
SET e.synthesized = true
RETURN count(e) AS created
"""

# Synthesize CAN_ACCESS (path A): resource → admin role → crown-jewel data resource
# via variable-length ASSUMES chain (max depth 2) ending at is_crown_jewel node
_SYNTH_CAN_ACCESS_VIA_ROLE = """
MATCH (r:Resource {tenant_id: $tid})-[:ASSUMES*1..2]->(data:Resource {tenant_id: $tid})
WHERE r.account_id = $account_id
  AND data.is_crown_jewel = true
  AND data.resource_type IN $data_resource_types
MERGE (r)-[e:CAN_ACCESS {tenant_id: $tid}]->(data)
SET e.synthesized = true, e.via = 'role_chain'
RETURN count(e) AS created
"""

# Synthesize CAN_ACCESS (path B): direct attachment to data resource
_SYNTH_CAN_ACCESS_DIRECT = """
MATCH (r:Resource {tenant_id: $tid})-[:ATTACHED_TO|RUNS_ON]->(data:Resource {tenant_id: $tid})
WHERE r.account_id = $account_id
  AND data.resource_type IN $data_resource_types
MERGE (r)-[e:CAN_ACCESS {tenant_id: $tid}]->(data)
SET e.synthesized = true, e.via = 'direct'
RETURN count(e) AS created
"""

# Synthesize EXECUTES_IN: workload → execution environment
_SYNTH_EXECUTES_IN = """
MATCH (r:Resource {tenant_id: $tid})-[:RUNS_ON|INVOKES]->(env:Resource {tenant_id: $tid})
WHERE r.account_id = $account_id
  AND env.resource_type IN $exec_env_types
MERGE (r)-[e:EXECUTES_IN {tenant_id: $tid}]->(env)
SET e.synthesized = true
RETURN count(e) AS created
"""

# Synthesize FLOWS_TO: resource → downstream resource via network edges
_SYNTH_FLOWS_TO = """
MATCH (r:Resource {tenant_id: $tid})-[:ROUTES_TO|ATTACHED_TO]->(dst:Resource {tenant_id: $tid})
WHERE r.account_id = $account_id
MERGE (r)-[e:FLOWS_TO {tenant_id: $tid}]->(dst)
SET e.synthesized = true
RETURN count(e) AS created
"""

# Data resource types that CAN_ACCESS targets
_DATA_RESOURCE_TYPES = [
    "aws_s3_bucket", "aws_rds_instance", "aws_db_instance",
    "aws_dynamodb_table", "aws_redshift_cluster", "aws_elasticache_cluster",
    "azurerm_storage_account", "azurerm_sql_database", "azurerm_cosmosdb_account",
    "google_storage_bucket", "google_sql_database_instance", "google_bigtable_instance",
    "oci_object_storage_bucket", "oci_database",
]

# Execution environment types that EXECUTES_IN targets
_EXEC_ENV_TYPES = [
    "aws_ecs_task_definition", "aws_ecs_cluster", "aws_eks_cluster",
    "aws_instance", "aws_lambda_function",
    "azurerm_kubernetes_cluster", "azurerm_container_group",
    "google_container_cluster", "google_compute_instance",
    "oci_container_instance",
]


class SemanticEdgeSynthesizer:
    """Synthesizes high-level semantic edges from existing typed edges and flags."""

    def __init__(self, neo4j_driver: Driver) -> None:
        self._driver = neo4j_driver

    def synthesize(self, tenant_id: str, account_id: str) -> dict[str, Any]:
        """Run all synthesis passes. Returns counts per edge type."""
        db = _DB()
        counts: dict[str, int] = {}

        with self._driver.session(database=db) as session:
            counts["CAN_ESCALATE_TO"] = self._run(
                session, _SYNTH_CAN_ESCALATE_TO,
                tid=tenant_id, account_id=account_id,
            )
            counts["CAN_ACCESS_via_role"] = self._run(
                session, _SYNTH_CAN_ACCESS_VIA_ROLE,
                tid=tenant_id, account_id=account_id,
                data_resource_types=_DATA_RESOURCE_TYPES,
            )
            counts["CAN_ACCESS_direct"] = self._run(
                session, _SYNTH_CAN_ACCESS_DIRECT,
                tid=tenant_id, account_id=account_id,
                data_resource_types=_DATA_RESOURCE_TYPES,
            )
            counts["EXECUTES_IN"] = self._run(
                session, _SYNTH_EXECUTES_IN,
                tid=tenant_id, account_id=account_id,
                exec_env_types=_EXEC_ENV_TYPES,
            )
            counts["FLOWS_TO"] = self._run(
                session, _SYNTH_FLOWS_TO,
                tid=tenant_id, account_id=account_id,
            )

        total = sum(counts.values())
        logger.info(
            "SemanticEdgeSynthesizer: %d edges synthesized — %s",
            total, counts,
            extra={"tenant_id": tenant_id, "account_id": account_id},
        )
        return {"edge_count": total, "by_type": counts}

    def _run(self, session: Any, cypher: str, **params: Any) -> int:
        result = session.run(cypher, parameters=params)
        record = result.single()
        return int(record["created"]) if record else 0
