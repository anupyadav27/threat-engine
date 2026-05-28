"""
ExposureLoader — bridges network engine INTERNET_ACCESSIBLE edges in asset_relationships
(DI DB) to Neo4j EXPOSES edges between the Internet node and Resource nodes.

Primary path:
  1. Read rows WHERE relation_type = 'INTERNET_ACCESSIBLE' from asset_relationships
     in threat_engine_di (via pg_conn_fn).
  2. For each row, MERGE (:Internet {uid:'INTERNET'})-[:EXPOSES]->(:Resource {uid:…})
     in Neo4j, carrying port/protocol metadata.

Fallback (primary returns 0 rows and NETWORK_DB_HOST is set):
  Read network_findings with exposure-related rule_ids from the network engine DB
  and infer EXPOSES edges from is_public / open_port findings.

SECURITY: source_uid values from asset_relationships are compared against a known
Internet sentinel before Cypher write — no raw DB string is interpolated into Cypher.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

_INTERNET_UID = "pseudo:internet:global"
_NEO4J_INTERNET_UID = "INTERNET"

_EXPOSURE_RULES = frozenset(
    [
        "aws-sg-ssh-open",
        "aws-sg-rdp-open",
        "aws-sg-all-open",
        "aws-sg-unrestricted-ingress",
        "aws-nacl-unrestricted",
        "aws-ec2-public",
        "aws-alb-public",
        "aws-elb-public",
    ]
)


def build_network_db_config() -> Dict[str, Any]:
    """Read NETWORK_DB_* env vars for the network engine PostgreSQL connection.

    Returns an empty dict (safe default) when NETWORK_DB_HOST is not set so
    ExposureLoader can gracefully degrade to inferred exposure.

    Returns:
        Dict with keys: host, port, dbname, user, password.  Empty dict when
        NETWORK_DB_HOST is absent or empty.
    """
    host = os.environ.get("NETWORK_DB_HOST", "").strip()
    if not host:
        return {}
    return {
        "host": host,
        "port": int(os.environ.get("NETWORK_DB_PORT", "5432")),
        "dbname": os.environ.get("NETWORK_DB_NAME", "threat_engine_network"),
        "user": os.environ.get("NETWORK_DB_USER", "postgres"),
        "password": os.environ.get("NETWORK_DB_PASSWORD", ""),
    }


class ExposureLoader:
    """Loads EXPOSES edges from network data into Neo4j.

    Primary path reads INTERNET_ACCESSIBLE rows from asset_relationships in
    threat_engine_di (written by the network engine relationship writer).
    Fallback path reads network_findings directly when primary returns nothing.
    """

    def __init__(
        self,
        neo4j_driver: Any,
        network_db_config: Dict[str, Any],
        pg_conn_fn: Callable[[str], Any],
    ) -> None:
        """Initialise ExposureLoader.

        Args:
            neo4j_driver:       Active Neo4j driver instance.
            network_db_config:  Dict from build_network_db_config().  May be empty.
            pg_conn_fn:         Callable(db_name) → psycopg2 connection.  Used to
                                open threat_engine_di and optionally network DB.
        """
        self._driver = neo4j_driver
        self._network_db_config = network_db_config
        self._pg_conn = pg_conn_fn

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load(self, tenant_id: str, scan_run_id: str) -> Dict[str, int]:
        """Write EXPOSES edges to Neo4j for the given scan.

        Args:
            tenant_id:   Tenant UUID string (scopes DI DB query).
            scan_run_id: Current scan UUID string.

        Returns:
            Dict with keys:
              "exposes_edges"  — edges written from primary (asset_relationships)
              "inferred_edges" — edges written from fallback (network_findings)
        """
        exposes_edges = self._load_from_asset_relationships(tenant_id, scan_run_id)

        inferred_edges = 0
        if exposes_edges == 0 and self._network_db_config:
            inferred_edges = self._load_from_network_findings(tenant_id, scan_run_id)

        if exposes_edges == 0 and inferred_edges == 0:
            inferred_edges = self._infer_from_resource_properties(tenant_id)

        return {"exposes_edges": exposes_edges, "inferred_edges": inferred_edges}

    # ------------------------------------------------------------------
    # Primary path — asset_relationships
    # ------------------------------------------------------------------

    def _load_from_asset_relationships(self, tenant_id: str, scan_run_id: str) -> int:
        """Read INTERNET_ACCESSIBLE edges from DI DB and write EXPOSES to Neo4j."""
        rows: List[Dict[str, Any]] = []
        try:
            conn = self._pg_conn("threat_engine_di")
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT source_uid, source_type, relation_metadata
                        FROM   asset_relationships
                        WHERE  tenant_id     = %s
                          AND  scan_run_id   = %s
                          AND  relation_type = 'INTERNET_ACCESSIBLE'
                          AND  target_uid    = %s
                        """,
                        (tenant_id, scan_run_id, _INTERNET_UID),
                    )
                    for row in cur.fetchall():
                        rows.append(
                            {
                                "resource_uid": row[0],
                                "resource_type": row[1] or "resource",
                                "metadata": row[2] or {},
                            }
                        )
            finally:
                conn.close()
        except Exception as exc:
            logger.warning("ExposureLoader: DI DB read failed: %s", exc, exc_info=True)
            return 0

        if not rows:
            logger.debug(
                "ExposureLoader: no INTERNET_ACCESSIBLE rows in asset_relationships "
                "for scan %s (tenant %s)",
                scan_run_id,
                tenant_id,
            )
            return 0

        return self._write_exposes_edges(rows, source="asset_relationships")

    # ------------------------------------------------------------------
    # Fallback — network_findings table in network engine DB
    # ------------------------------------------------------------------

    def _load_from_network_findings(self, tenant_id: str, scan_run_id: str) -> int:
        """Read exposure findings from network DB and write EXPOSES to Neo4j."""
        rows: List[Dict[str, Any]] = []
        try:
            import psycopg2
            import psycopg2.extras

            conn = psycopg2.connect(
                host=self._network_db_config["host"],
                port=self._network_db_config["port"],
                dbname=self._network_db_config["dbname"],
                user=self._network_db_config["user"],
                password=self._network_db_config["password"],
                connect_timeout=10,
            )
            try:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute(
                        """
                        SELECT DISTINCT resource_uid, resource_type, finding_data
                        FROM   network_findings
                        WHERE  tenant_id   = %s
                          AND  scan_run_id = %s
                          AND  status      = 'FAIL'
                          AND  severity    IN ('CRITICAL', 'HIGH')
                          AND  (
                                finding_data->>'effective_exposure' = 'INTERNET'
                             OR resource_uid IN (
                                    SELECT source_uid
                                    FROM   asset_relationships
                                    WHERE  tenant_id     = %s
                                      AND  scan_run_id   = %s
                                      AND  relation_type = 'INTERNET_ACCESSIBLE'
                                )
                          )
                        LIMIT 5000
                        """,
                        (tenant_id, scan_run_id, tenant_id, scan_run_id),
                    )
                    for row in cur.fetchall():
                        if not row.get("resource_uid"):
                            continue
                        rows.append(
                            {
                                "resource_uid": row["resource_uid"],
                                "resource_type": row.get("resource_type") or "resource",
                                "metadata": {
                                    "source": "network_findings_fallback",
                                    "effective_exposure": (row.get("finding_data") or {}).get(
                                        "effective_exposure", "INTERNET"
                                    ),
                                },
                            }
                        )
            finally:
                conn.close()
        except Exception as exc:
            logger.warning(
                "ExposureLoader: network DB fallback failed: %s", exc, exc_info=True
            )
            return 0

        if not rows:
            return 0

        return self._write_exposes_edges(rows, source="network_findings")

    # ------------------------------------------------------------------
    # Second fallback — Resource.is_public in Neo4j
    # ------------------------------------------------------------------

    def _infer_from_resource_properties(self, tenant_id: str) -> int:
        """Create EXPOSES edges from Resource nodes that have is_public=true in Neo4j."""
        try:
            with self._driver.session() as session:
                result = session.run(
                    """
                    MATCH (r:Resource {tenant_id: $tid})
                    WHERE r.is_public = true
                    MERGE (i:Internet:VirtualNode {uid: $internet_uid})
                      ON CREATE SET i.name = 'Internet'
                    MERGE (i)-[e:EXPOSES]->(r)
                      ON CREATE SET e.source = 'inferred_is_public',
                                    e.created_at = datetime()
                      ON MATCH  SET e.source = 'inferred_is_public'
                    RETURN count(e) AS cnt
                    """,
                    tid=tenant_id,
                    internet_uid=_NEO4J_INTERNET_UID,
                )
                record = result.single()
                cnt = record["cnt"] if record else 0
                logger.info(
                    "ExposureLoader: inferred %d EXPOSES edges from is_public for tenant %s",
                    cnt,
                    tenant_id,
                )
                return cnt
        except Exception as exc:
            logger.warning(
                "ExposureLoader: is_public inference failed: %s", exc, exc_info=True
            )
            return 0

    # ------------------------------------------------------------------
    # Neo4j write
    # ------------------------------------------------------------------

    def _write_exposes_edges(
        self, rows: List[Dict[str, Any]], source: str
    ) -> int:
        """MERGE EXPOSES edges in Neo4j for each resource row.

        Args:
            rows:   List of dicts with resource_uid, resource_type, metadata.
            source: Tag string stored on the edge for traceability.

        Returns:
            Number of edges merged.
        """
        if not rows:
            return 0

        # Deduplicate by resource_uid so we don't send duplicate Cypher params
        seen: set = set()
        unique_rows = []
        for r in rows:
            uid = r.get("resource_uid", "")
            if uid and uid not in seen:
                seen.add(uid)
                unique_rows.append(r)

        batch_size = 500
        total = 0

        try:
            with self._driver.session() as session:
                for i in range(0, len(unique_rows), batch_size):
                    batch = unique_rows[i : i + batch_size]
                    params_list = [
                        {
                            "uid": r["resource_uid"],
                            "rtype": r.get("resource_type", "resource"),
                            "ports": _extract_ports(r.get("metadata") or {}),
                            "protocol": _extract_protocol(r.get("metadata") or {}),
                            "source": source,
                        }
                        for r in batch
                    ]
                    result = session.run(
                        """
                        UNWIND $rows AS row
                        MERGE (i:Internet:VirtualNode {uid: $internet_uid})
                          ON CREATE SET i.name = 'Internet'
                        MATCH (r:Resource {uid: row.uid})
                        MERGE (i)-[e:EXPOSES]->(r)
                          ON CREATE SET e.ports     = row.ports,
                                        e.protocol  = row.protocol,
                                        e.source    = row.source,
                                        e.created_at = datetime()
                          ON MATCH  SET e.ports     = row.ports,
                                        e.protocol  = row.protocol,
                                        e.source    = row.source
                        RETURN count(e) AS cnt
                        """,
                        rows=params_list,
                        internet_uid=_NEO4J_INTERNET_UID,
                    )
                    record = result.single()
                    batch_cnt = record["cnt"] if record else 0
                    total += batch_cnt

            logger.info(
                "ExposureLoader: wrote %d EXPOSES edges from %s", total, source
            )
        except Exception as exc:
            logger.warning(
                "ExposureLoader: Neo4j write failed (source=%s): %s",
                source,
                exc,
                exc_info=True,
            )

        return total


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _extract_ports(metadata: Dict[str, Any]) -> List[int]:
    """Extract port list from relationship metadata."""
    raw = metadata.get("open_ports") or metadata.get("ports") or []
    if isinstance(raw, list):
        result = []
        for p in raw:
            try:
                result.append(int(p))
            except (TypeError, ValueError):
                pass
        return result
    return []


def _extract_protocol(metadata: Dict[str, Any]) -> str:
    """Extract protocol string from relationship metadata."""
    return str(metadata.get("protocol") or metadata.get("proto") or "tcp").lower()
