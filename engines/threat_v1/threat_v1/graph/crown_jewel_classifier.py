"""
CrownJewelClassifier — marks Resource nodes as is_crown_jewel=true in Neo4j.

Two-pass classification:

Pass 1 — Cypher heuristic seed (primary, fast):
  Directly marks Resource nodes in Neo4j whose resource_type matches known
  sensitive categories (S3, RDS, DynamoDB, KMS, secrets, etc.).
  Runs regardless of inventory DB state.

Pass 2 — Inventory score-based (enrichment):
  Reads inventory_findings, enriched via di_resource_catalog (DI DB).
  Uses 6 scoring criteria from REQUIREMENTS §6.3.
  The JOIN uses SPLIT_PART to strip the 'service.' prefix from
  inventory_findings.resource_type (e.g. 's3.bucket' → 'bucket').

Manual overrides in threat_crown_jewels always take unconditional precedence.

CP1-01: all Cypher via $parameter bindings.
"""
from __future__ import annotations

import os
import logging
from typing import Any, Dict, List, Set

from neo4j import Driver

logger = logging.getLogger(__name__)

_SENSITIVE_TAG_KEYWORDS = frozenset({"sensitive", "pii", "phi", "pci", "confidential", "secret"})
_HIGH_CRITICALITY_VALUES = frozenset({"high", "critical", "very_high"})

# Expanded to match actual values in di_resource_catalog
_CROWN_JEWEL_CATEGORIES = frozenset({
    "data_store",
    "data",
    "database",
    "secrets",
    "secret_store",   # kept for future normalisation
    "identity",
    "identity_provider",  # kept for future normalisation
    "storage",
})

_CROWN_JEWEL_ACCESS_PATTERNS = frozenset({"cross_account", "public"})
_RISK_SCORE_THRESHOLD = 80.0

# Cypher heuristic seed: mark by resource_type string or Neo4j label
# These are the resource_type values written by MisconfigLoader from check_findings.
_HEURISTIC_SEED_TYPES = [
    # AWS
    "S3Bucket", "s3.bucket",
    "RDSInstance", "rds.db_instance", "rds.cluster",
    "DynamoDBTable", "dynamodb.table",
    "KMSKey", "kms.key",
    "SecretManagerSecret", "secretsmanager.secret",
    "RedshiftCluster", "redshift.cluster",
    "ElasticsearchDomain", "opensearch.domain",
    "GlueDatabase", "glue.database",
    "GlueTable", "glue.table",
    "ECRRepository", "ecr.repository",
    # GCP
    "GCSBucket", "gcp.gcs_bucket",
    "BigQueryDataset", "gcp.bigquery_dataset",
    "GCPSecret",
    # Azure
    "STORAGEStorageaccount", "StorageAccount",
    "KEYVAULTKeyvault",
    # OCI
    "OBJECT_STORAGEOci.objectstorage/bucket",
    "KEY_MANAGEMENTOci.keyManagement/vault",
]

_HEURISTIC_CYPHER = """
MATCH (r:Resource)
WHERE r.tenant_id = $tid
  AND (
    r.resource_type IN $seed_types
    OR ANY(lbl IN labels(r) WHERE lbl IN $seed_types)
  )
SET r.is_crown_jewel = true
RETURN count(r) AS seeded
"""

_SET_CROWN_JEWEL = """
MATCH (r:Resource {resource_uid: $resource_uid, tenant_id: $tid})
SET r.is_crown_jewel = true
"""


class CrownJewelClassifier:
    """Classifies which Resource nodes are crown jewels and marks them in Neo4j."""

    def __init__(
        self,
        inventory_conn: Any,
        threat_conn: Any,
        neo4j_driver: Driver,
    ) -> None:
        self._inventory_conn = inventory_conn
        self._threat_conn = threat_conn
        self._driver = neo4j_driver

    def classify(
        self,
        tenant_id: str,
        account_id: str,
    ) -> Dict[str, int]:
        """Run classification and mark crown jewels in Neo4j.

        Returns:
            Dict with crown_jewel_count (total marked nodes).
        """
        db = os.environ.get("NEO4J_DATABASE", "neo4j")
        heuristic_count = 0
        score_count = 0

        with self._driver.session(database=db) as session:
            # Pass 1: heuristic seed by resource_type
            result = session.run(
                _HEURISTIC_CYPHER,
                tid=tenant_id,
                seed_types=_HEURISTIC_SEED_TYPES,
            )
            record = result.single()
            heuristic_count = record["seeded"] if record else 0
            logger.info(
                "CrownJewel heuristic seed: %d resources marked (tenant=%s)",
                heuristic_count, tenant_id,
            )

            # Pass 2: manual overrides (unconditional)
            manual_uids = self._fetch_manual_overrides(tenant_id)
            for uid in manual_uids:
                session.run(_SET_CROWN_JEWEL, resource_uid=uid, tid=tenant_id)

            # Pass 3: inventory score-based enrichment
            inventory_rows = self._fetch_inventory(tenant_id, account_id)
            scored_uids: Set[str] = set()
            for row in inventory_rows:
                if self._is_crown_jewel(row):
                    scored_uids.add(row["resource_uid"])

            for uid in scored_uids:
                session.run(_SET_CROWN_JEWEL, resource_uid=uid, tid=tenant_id)
            score_count = len(scored_uids)

        total = heuristic_count + len(manual_uids) + score_count
        logger.info(
            "CrownJewelClassifier complete: heuristic=%d manual=%d scored=%d",
            heuristic_count, len(manual_uids), score_count,
            extra={"tenant_id": tenant_id, "account_id": account_id},
        )
        return {"crown_jewel_count": total}

    def _is_crown_jewel(self, row: Dict[str, Any]) -> bool:
        """Apply the 6-criteria scoring rule."""
        score = 0

        category = (row.get("asset_category") or "").lower()
        if category in _CROWN_JEWEL_CATEGORIES:
            score += 2

        access_pattern = (row.get("access_pattern") or "").lower()
        if access_pattern in _CROWN_JEWEL_ACCESS_PATTERNS:
            score += 1

        criticality = (row.get("criticality") or "").lower()
        if criticality in _HIGH_CRITICALITY_VALUES:
            score += 1

        environment = (row.get("environment") or "").lower()
        if environment == "production":
            score += 1

        risk_score = float(row.get("risk_score") or 0.0)
        if risk_score >= _RISK_SCORE_THRESHOLD:
            score += 1

        tags = row.get("tags")
        if isinstance(tags, dict):
            combined = " ".join(str(v).lower() for v in tags.values()) + \
                       " ".join(str(k).lower() for k in tags.keys())
        elif isinstance(tags, str):
            combined = tags.lower()
        else:
            combined = ""
        if any(kw in combined for kw in _SENSITIVE_TAG_KEYWORDS):
            score += 2

        return score >= 2

    def _load_di_catalog_index(self) -> Dict[Any, Dict[str, str]]:
        """Load asset_category + access_pattern from di_resource_catalog.

        Returns {(csp, service, resource_type): {asset_category, access_pattern}}.
        di_resource_catalog is in threat_engine_di — opened separately from inventory.
        """
        try:
            from engine_common.db_connections import get_di_conn
            conn = get_di_conn()
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT csp, service, resource_type, asset_category, access_pattern"
                        " FROM di_resource_catalog"
                        " WHERE asset_category IS NOT NULL OR access_pattern IS NOT NULL"
                    )
                    index = {}
                    for csp, svc, rt, cat, ap in cur.fetchall():
                        index[(csp, svc, rt)] = {"asset_category": cat, "access_pattern": ap}
                    return index
            finally:
                conn.close()
        except Exception as exc:
            logger.warning("Could not load di_resource_catalog index: %s", exc)
            return {}

    def _fetch_inventory(
        self,
        tenant_id: str,
        account_id: str,
    ) -> List[Dict[str, Any]]:
        """Query inventory_findings, enrich with di_resource_catalog classifications.

        di_resource_catalog lives in threat_engine_di (different DB from inventory).
        The join is done in Python: resource_type 'ec2.instance' splits to
        service='ec2', resource_type='instance' for the catalog lookup.
        """
        catalog_index = self._load_di_catalog_index()

        cur = self._inventory_conn.cursor()
        cur.execute(
            """
            SELECT
                f.resource_uid,
                f.resource_type,
                f.provider,
                f.criticality,
                f.environment,
                f.risk_score,
                f.tags
            FROM inventory_findings f
            WHERE f.tenant_id  = %s
              AND f.account_id = %s
            """,
            (tenant_id, account_id),
        )
        rows = cur.fetchall()
        cur.close()

        result = []
        for row in rows:
            rt_full = (row.get("resource_type") or "") if isinstance(row, dict) else ""
            if not isinstance(row, dict):
                row = dict(row)
                rt_full = row.get("resource_type") or ""
            parts = rt_full.split(".", 1)
            svc = parts[0] if len(parts) >= 1 else ""
            rt_bare = parts[1] if len(parts) >= 2 else ""
            csp = row.get("provider") or ""
            catalog = catalog_index.get((csp, svc, rt_bare), {})
            row["asset_category"] = catalog.get("asset_category")
            row["access_pattern"] = catalog.get("access_pattern")
            result.append(row)
        return result

    def _fetch_manual_overrides(self, tenant_id: str) -> List[str]:
        """Return resource_uids explicitly marked as crown jewels by the tenant."""
        cur = self._threat_conn.cursor()
        cur.execute(
            """
            SELECT resource_uid
            FROM threat_crown_jewels
            WHERE tenant_id = %s
            """,
            (tenant_id,),
        )
        rows = cur.fetchall()
        cur.close()
        return [row["resource_uid"] for row in rows]
