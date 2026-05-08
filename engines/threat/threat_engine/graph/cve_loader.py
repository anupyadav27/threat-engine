"""CVE node loader for the security graph (GRAPH-S2-03).

Reads vulnerability data from the vulnerability engine's PostgreSQL database
(``vulnerability_db``) and writes CVE nodes + HAS_CVE edges into Neo4j so
that attack paths can show CVE exploitability context on affected resources.

Design decisions:
  - Separate class (``CVELoader``) — keeps graph_builder.py focused on
    inventory/threat data.  The builder calls ``CVELoader.load()`` as the final
    enrichment step after ``_expand_config_properties()``.
  - 500-row UNWIND batches — matches the existing pattern in graph_builder.py.
  - Parameterised Cypher only — no f-string interpolation in Cypher queries.
  - Graceful degradation — if VULN_DB_HOST is missing or the query fails, the
    loader logs a warning/error and returns zero counts; the graph build is
    never aborted.
  - sslmode=require — mandatory for RDS connections in production.
  - tenant_id always comes from the caller, never from DB rows.

MITRE ATT&CK:
  - T1190 Exploit Public-Facing Application (CVE exploitation path)
  - T1525 Implant Internal Image (vulnerable image CVEs)

NIST CSF 2.0: ID.RA-01, PR.PS-01
CSA CCM v4: IVS-04, TVM-01
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

logger = logging.getLogger(__name__)

# Rows per UNWIND batch sent to Neo4j
_BATCH_SIZE = 500


class CVELoader:
    """Load CVE nodes and HAS_CVE edges into Neo4j from the vulnerability DB.

    Args:
        neo4j_driver: An active neo4j.GraphDatabase driver instance.
        vuln_db_config: Dict with keys host, dbname, user, password, port.
    """

    def __init__(self, neo4j_driver: Any, vuln_db_config: Dict[str, Any]) -> None:
        self._driver = neo4j_driver
        self._cfg = vuln_db_config

    # ── Public interface ───────────────────────────────────────────────────

    def load(self, tenant_id: str, scan_run_id: str) -> Dict[str, int]:
        """Load CVE data from vulnerability DB and write to Neo4j.

        Queries ``scan_vulnerabilities`` filtered by tenant_id and scan_run_id,
        merges CVE nodes, and creates HAS_CVE edges from matching Resource nodes.

        Args:
            tenant_id:   Tenant UUID — used to scope both the PG query and
                         the Neo4j MATCH (never read from DB rows).
            scan_run_id: Scan run UUID — narrows to the latest scan's vulns.

        Returns:
            Dict with keys ``cve_nodes`` (int) and ``has_cve_edges`` (int).
        """
        host = self._cfg.get("host", "")
        if not host:
            logger.warning(
                "CVELoader: VULN_DB_HOST is not configured — skipping CVE node load"
            )
            return {"cve_nodes": 0, "has_cve_edges": 0}

        rows = self._query_vulnerabilities(tenant_id, scan_run_id)
        if not rows:
            logger.info(
                "CVELoader: no vulnerabilities found for tenant=%s scan_run_id=%s",
                tenant_id,
                scan_run_id,
            )
            return {"cve_nodes": 0, "has_cve_edges": 0}

        cve_nodes, has_cve_edges = self._write_to_neo4j(rows, tenant_id)
        logger.info(
            "CVELoader: tenant=%s — merged %d CVE nodes, %d HAS_CVE edges",
            tenant_id,
            cve_nodes,
            has_cve_edges,
        )
        return {"cve_nodes": cve_nodes, "has_cve_edges": has_cve_edges}

    # ── Constraints (called once at startup by graph_builder) ──────────────

    def ensure_constraints(self, session: Any) -> None:
        """Create Neo4j uniqueness constraints and indexes for CVE nodes.

        Safe to call multiple times — uses IF NOT EXISTS.

        Args:
            session: An active Neo4j driver session.
        """
        ddl_statements = [
            "CREATE CONSTRAINT IF NOT EXISTS FOR (c:CVE) REQUIRE c.cve_id IS UNIQUE",
            "CREATE INDEX IF NOT EXISTS FOR (c:CVE) ON (c.tenant_id)",
            "CREATE INDEX IF NOT EXISTS FOR (c:CVE) ON (c.in_kev)",
            "CREATE INDEX IF NOT EXISTS FOR (c:CVE) ON (c.cvss_score)",
        ]
        for stmt in ddl_statements:
            try:
                session.run(stmt)
            except Exception as exc:
                logger.debug("CVELoader constraint/index note: %s", exc)

    # ── Internal helpers ───────────────────────────────────────────────────

    def _connect(self) -> Any:
        """Open a psycopg2 connection to vulnerability_db with sslmode=require.

        Returns:
            A psycopg2 connection object.

        Raises:
            psycopg2.OperationalError: If the connection cannot be established.
        """
        import psycopg2

        cfg = self._cfg
        # SECURITY: never log the password or connection string
        logger.debug(
            "CVELoader: connecting to %s/%s as %s",
            cfg.get("host"),
            cfg.get("dbname"),
            cfg.get("user"),
        )
        return psycopg2.connect(
            host=cfg.get("host"),
            port=int(cfg.get("port", 5432)),
            dbname=cfg.get("dbname", "vulnerability_db"),
            user=cfg.get("user"),
            password=cfg.get("password"),
            sslmode="require",
            connect_timeout=10,
        )

    def _query_vulnerabilities(
        self, tenant_id: str, scan_run_id: str
    ) -> List[Tuple[str, str, str, float, float, bool]]:
        """Fetch vulnerability rows from scan_vulnerabilities.

        Args:
            tenant_id:   Tenant UUID to scope the query.
            scan_run_id: Scan run UUID to restrict to the current pipeline run.

        Returns:
            List of tuples (resource_uid, cve_id, severity, cvss_score,
            epss_score, in_kev) — empty list on any error.
        """
        import psycopg2

        try:
            conn = self._connect()
        except psycopg2.OperationalError as exc:
            logger.error(
                "CVELoader: cannot connect to vulnerability DB — %s", exc
            )
            return []

        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT resource_uid,
                           cve_id,
                           severity,
                           cvss_score,
                           epss_score,
                           in_kev
                    FROM   scan_vulnerabilities
                    WHERE  tenant_id   = %s
                      AND  scan_run_id = %s
                      AND  cve_id IS NOT NULL
                      AND  cve_id != ''
                    """,
                    (str(tenant_id), str(scan_run_id)),
                )
                return cur.fetchall()
        except psycopg2.Error as exc:
            logger.error("CVELoader: query failed — %s", exc)
            return []
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _write_to_neo4j(
        self,
        rows: List[Tuple[str, str, str, float, float, bool]],
        tenant_id: str,
    ) -> Tuple[int, int]:
        """Merge CVE nodes and HAS_CVE edges into Neo4j using UNWIND batches.

        Args:
            rows:      Rows from _query_vulnerabilities.
            tenant_id: Tenant UUID — written onto every CVE node; used in
                       Resource MATCH (never taken from DB rows).

        Returns:
            (cve_nodes_merged, has_cve_edges_created) tuple.
        """
        cve_batch: List[Dict[str, Any]] = []
        edge_batch: List[Dict[str, Any]] = []

        total_cve_nodes = 0
        total_has_cve_edges = 0

        def _flush() -> None:
            nonlocal total_cve_nodes, total_has_cve_edges
            if not cve_batch:
                return
            n, e = self._flush_batches(cve_batch, edge_batch, tenant_id)
            total_cve_nodes += n
            total_has_cve_edges += e
            cve_batch.clear()
            edge_batch.clear()

        for row in rows:
            resource_uid, cve_id, severity, cvss_score, epss_score, in_kev = row

            cve_batch.append(
                {
                    "cve_id": cve_id,
                    "severity": severity or "unknown",
                    "cvss_score": float(cvss_score or 0.0),
                    "epss_score": float(epss_score or 0.0),
                    "in_kev": bool(in_kev),
                    # tenant_id on the node supports multi-tenant graph queries
                    "tenant_id": tenant_id,
                }
            )
            if resource_uid:
                edge_batch.append(
                    {
                        "resource_uid": resource_uid,
                        "cve_id": cve_id,
                    }
                )

            if len(cve_batch) >= _BATCH_SIZE:
                _flush()

        _flush()

        return total_cve_nodes, total_has_cve_edges

    def _flush_batches(
        self,
        cve_batch: List[Dict[str, Any]],
        edge_batch: List[Dict[str, Any]],
        tenant_id: str,
    ) -> Tuple[int, int]:
        """Write one UNWIND batch of CVE nodes and HAS_CVE edges to Neo4j.

        Uses parameterised Cypher only — no f-string interpolation.

        Args:
            cve_batch:  List of CVE property dicts to MERGE as CVE nodes.
            edge_batch: List of {resource_uid, cve_id} dicts for HAS_CVE edges.
            tenant_id:  Tenant UUID used in Resource MATCH for multi-tenancy.

        Returns:
            (cve_nodes_merged, has_cve_edges_created) tuple for this batch.
        """
        cve_nodes = 0
        has_cve_edges = 0

        with self._driver.session() as session:
            # 1. Merge CVE nodes — cve_id is the unique key across tenants
            #    (CVE identifiers are global; tenant_id is an additional property
            #    for filtering but NOT part of the uniqueness key so shared CVEs
            #    are written once and linked from multiple tenants).
            try:
                result = session.run(
                    """
                    UNWIND $batch AS c
                    MERGE (n:CVE {cve_id: c.cve_id})
                    SET n.severity   = c.severity,
                        n.cvss_score = c.cvss_score,
                        n.epss_score = c.epss_score,
                        n.in_kev     = c.in_kev,
                        n.tenant_id  = c.tenant_id
                    RETURN count(n) AS merged
                    """,
                    batch=cve_batch,
                )
                record = result.single()
                cve_nodes = int(record["merged"]) if record else 0
            except Exception as exc:
                logger.error(
                    "CVELoader: CVE node MERGE failed for batch of %d — %s",
                    len(cve_batch),
                    exc,
                )

            # 2. Create HAS_CVE edges: Resource -[:HAS_CVE]-> CVE
            #    Resource MATCH is scoped by tenant_id (multi-tenant safety).
            if edge_batch:
                try:
                    result = session.run(
                        """
                        UNWIND $batch AS e
                        MATCH (r:Resource {uid: e.resource_uid, tenant_id: $tenant_id})
                        MATCH (c:CVE {cve_id: e.cve_id})
                        MERGE (r)-[rel:HAS_CVE]->(c)
                        SET rel.edge_kind = 'association'
                        RETURN count(rel) AS created
                        """,
                        batch=edge_batch,
                        tenant_id=tenant_id,
                    )
                    record = result.single()
                    has_cve_edges = int(record["created"]) if record else 0
                except Exception as exc:
                    logger.error(
                        "CVELoader: HAS_CVE edge MERGE failed for batch of %d — %s",
                        len(edge_batch),
                        exc,
                    )

        return cve_nodes, has_cve_edges
