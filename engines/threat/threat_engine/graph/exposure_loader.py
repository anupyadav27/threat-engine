"""
GRAPH-S2-04 — Network EXPOSES Edge Loader.

Reads FAIL findings from the network engine's ``network_findings`` table and
creates topology-accurate ``EXPOSES`` edges in Neo4j between an ``Internet``
virtual node and the exposed ``Resource`` nodes.

Security constraints:
- All inputs from network_findings are validated before writing to Neo4j
  (injection risk: cross-DB data entering the graph store).
- ``rule_id``, ``sg_id``, and ``cidr_range`` are validated with strict regexes /
  ipaddress before use.
- Rows that fail validation are logged at WARNING level (rule_id only — not
  CIDR/sg_id to avoid log injection) and skipped; they never reach Cypher.
- Cypher parameters are always passed as named params, NEVER via f-strings.
- psycopg2 connects with ``sslmode=require``.
- If NETWORK_DB_HOST is empty the loader skips DB entirely and falls back to
  inferred exposure from Resource.is_public properties.

MITRE ATT&CK:
  T1190  Exploit Public-Facing Application
  T1021.001  Remote Services: RDP (port-specific exposure)
  T1021.004  Remote Services: SSH

NIST CSF 2.0:
  ID.AM-03, PR.AC-05, DE.CM-01

CSA CCM v4:
  IVS-06, IVS-09
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# ── Input validation regexes ──────────────────────────────────────────────────
# rule_id: alphanumeric + . _ - only (blocks Cypher/SQL injection via id fields)
RULE_ID_RE = re.compile(r"^[a-zA-Z0-9._-]{1,255}$")
# sg_id: AWS security-group IDs — sg- followed by 8-17 hex chars
SG_ID_RE = re.compile(r"^sg-[a-f0-9]{8,17}$")

# Batch size for Neo4j UNWIND writes
_BATCH_SIZE = 200


def _validate_cidr(cidr: str) -> bool:
    """Return True if cidr is a syntactically valid IPv4/IPv6 network.

    Args:
        cidr: CIDR string to validate (e.g. ``"0.0.0.0/0"``).

    Returns:
        True when the string is a valid network notation; False otherwise.
    """
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


class ExposureLoader:
    """Loads network engine FAIL findings and writes EXPOSES edges to Neo4j.

    Usage::

        loader = ExposureLoader(neo4j_driver, network_db_config)
        stats = loader.load(tenant_id="588989875114", scan_run_id="<uuid>")
        # stats == {"exposes_edges": N, "inferred_edges": M}

    The ``network_db_config`` dict must contain:
        ``host``, ``dbname``, ``user``, ``password``, ``port`` (int).

    If ``host`` is empty the DB phase is skipped and ``_infer_internet_exposure``
    is called instead, returning ``{"exposes_edges": 0, "inferred_edges": M}``.
    """

    def __init__(
        self,
        neo4j_driver: Any,
        network_db_config: Dict[str, Any],
        pg_conn_fn: Optional[Callable[[str], Any]] = None,
    ) -> None:
        """Initialise the loader.

        Args:
            neo4j_driver: An active ``neo4j.GraphDatabase`` driver instance.
            network_db_config: Connection parameters for the network engine DB.
                Expected keys: ``host``, ``dbname``, ``user``, ``password``,
                ``port`` (int, default 5432).
            pg_conn_fn: Optional callable ``(db_name) -> psycopg2.connection``
                used as the fallback connection factory for
                ``_infer_internet_exposure``.  When None the infer step is
                skipped if the main connection is unavailable.
        """
        self._driver = neo4j_driver
        self._db_cfg = network_db_config
        self._pg_conn_fn = pg_conn_fn

    # ── Public API ────────────────────────────────────────────────────────────

    def load(
        self,
        tenant_id: str,
        scan_run_id: Optional[str] = None,
    ) -> Dict[str, int]:
        """Load EXPOSES edges from network_findings into Neo4j.

        Args:
            tenant_id: The tenant to scope all queries (mandatory).
            scan_run_id: When provided, restricts network_findings to this
                scan run only.  When None, loads all FAIL rows for the tenant
                (useful for ad-hoc graph rebuilds without a current pipeline run).

        Returns:
            ``{"exposes_edges": int, "inferred_edges": int}``
        """
        host = self._db_cfg.get("host", "")
        if not host:
            logger.warning(
                "ExposureLoader: NETWORK_DB_HOST is empty — "
                "skipping network DB, falling back to inferred exposure"
            )
            inferred = self._infer_internet_exposure(tenant_id)
            return {"exposes_edges": 0, "inferred_edges": inferred}

        rows = self._fetch_network_findings(tenant_id, scan_run_id)
        if not rows:
            logger.warning(
                "ExposureLoader: 0 rows from network_findings "
                "(tenant=%s scan_run_id=%s) — falling back to inferred exposure",
                tenant_id,
                scan_run_id or "ALL",
            )
            inferred = self._infer_internet_exposure(tenant_id)
            return {"exposes_edges": 0, "inferred_edges": inferred}

        validated = self._validate_rows(rows)
        exposes_count = self._write_exposes_edges(validated, tenant_id)
        return {"exposes_edges": exposes_count, "inferred_edges": 0}

    # ── DB fetch ──────────────────────────────────────────────────────────────

    def _pg_conn_network(self):
        """Open a psycopg2 connection to the network engine DB (sslmode=require).

        Returns:
            An open psycopg2 connection.

        Raises:
            RuntimeError: If required env vars are missing.
            psycopg2.OperationalError: If the connection cannot be established.
        """
        import psycopg2  # local import keeps startup fast when DB is unavailable

        cfg = self._db_cfg
        host = cfg.get("host", "")
        user = cfg.get("user", "")
        password = cfg.get("password", "")
        if not all([host, user, password]):
            raise RuntimeError(
                "NETWORK_DB_HOST, NETWORK_DB_USER, NETWORK_DB_PASSWORD are all required"
            )
        return psycopg2.connect(
            host=host,
            dbname=cfg.get("dbname", "threat_engine_network"),
            user=user,
            password=password,
            port=cfg.get("port", 5432),
            sslmode="require",
            connect_timeout=10,
        )

    def _fetch_network_findings(
        self,
        tenant_id: str,
        scan_run_id: Optional[str],
    ) -> List[Dict[str, Any]]:
        """Query network_findings for FAIL rows scoped to the tenant.

        Args:
            tenant_id: Tenant to scope the query.
            scan_run_id: Optional scan run to further scope the query.

        Returns:
            List of raw row dicts; empty list on any error.
        """
        try:
            conn = self._pg_conn_network()
        except Exception as exc:
            logger.error("ExposureLoader: cannot connect to network DB: %s", exc)
            return []

        try:
            with conn:
                with conn.cursor() as cur:
                    if scan_run_id:
                        cur.execute(
                            """
                            SELECT resource_uid,
                                   rule_id,
                                   severity,
                                   finding_metadata
                            FROM network_findings
                            WHERE tenant_id = %s
                              AND scan_run_id = %s
                              AND status = 'FAIL'
                            """,
                            (tenant_id, scan_run_id),
                        )
                    else:
                        cur.execute(
                            """
                            SELECT resource_uid,
                                   rule_id,
                                   severity,
                                   finding_metadata
                            FROM network_findings
                            WHERE tenant_id = %s
                              AND status = 'FAIL'
                            """,
                            (tenant_id,),
                        )
                    cols = [desc[0] for desc in cur.description]
                    rows = [dict(zip(cols, row)) for row in cur.fetchall()]
            logger.info(
                "ExposureLoader: fetched %d FAIL rows from network_findings "
                "(tenant=%s scan_run_id=%s)",
                len(rows),
                tenant_id,
                scan_run_id or "ALL",
            )
            return rows
        except Exception as exc:
            logger.error("ExposureLoader: DB query error: %s", exc)
            return []
        finally:
            try:
                conn.close()
            except Exception:
                pass

    # ── Input validation ──────────────────────────────────────────────────────

    def _validate_rows(
        self,
        rows: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Validate and sanitise raw rows from network_findings.

        Rules:
        - ``rule_id`` must match ``RULE_ID_RE``; row is rejected if not.
        - ``sg_id`` (from finding_metadata) must match ``SG_ID_RE`` when present.
        - ``cidr_range`` (from finding_metadata) must parse via ``ipaddress`` when present.
        - Rejected rows are logged at WARNING (rule_id only; not CIDR/sg_id to
          prevent log injection) and skipped.

        Args:
            rows: Raw rows fetched from ``_fetch_network_findings``.

        Returns:
            Validated rows ready for Cypher write.
        """
        validated: List[Dict[str, Any]] = []
        skipped = 0

        for row in rows:
            resource_uid = row.get("resource_uid") or ""
            rule_id = row.get("rule_id") or ""
            severity = row.get("severity") or ""

            # finding_metadata is JSONB — psycopg2 returns it as a dict already.
            # NEVER call json.loads() on it.
            meta = row.get("finding_metadata")
            if meta is None:
                meta = {}
            if not isinstance(meta, dict):
                logger.warning(
                    "ExposureLoader: unexpected finding_metadata type %s for rule_id=%s — skipping",
                    type(meta).__name__,
                    rule_id[:50] if rule_id else "<empty>",
                )
                skipped += 1
                continue

            sg_id = meta.get("sg_id") or ""
            cidr_range = meta.get("cidr_range") or ""
            port = meta.get("port")
            protocol = meta.get("protocol") or ""
            exposed_resource_uid = meta.get("exposed_resource_uid") or ""

            # Validate rule_id (required — reject row if invalid)
            if not rule_id or not RULE_ID_RE.match(rule_id):
                logger.warning(
                    "ExposureLoader: invalid rule_id format — skipping row (rule_id length=%d)",
                    len(rule_id),
                )
                skipped += 1
                continue

            # Validate sg_id if present
            if sg_id and not SG_ID_RE.match(sg_id):
                logger.warning(
                    "ExposureLoader: invalid sg_id format for rule_id=%s — skipping row",
                    rule_id,
                )
                skipped += 1
                continue

            # Validate cidr_range if present
            if cidr_range and not _validate_cidr(cidr_range):
                logger.warning(
                    "ExposureLoader: invalid cidr_range for rule_id=%s — skipping row",
                    rule_id,
                )
                skipped += 1
                continue

            # Normalise port to string (Neo4j stores as property; None stays None)
            port_str = str(port) if port is not None else None

            validated.append(
                {
                    "resource_uid": resource_uid,
                    "rule_id": rule_id,
                    "severity": severity,
                    "sg_id": sg_id or None,
                    "cidr": cidr_range or None,
                    "port": port_str,
                    "protocol": protocol or None,
                    "exposed_resource_uid": exposed_resource_uid or None,
                    "layer": "L4_security_group",
                }
            )

        if skipped:
            logger.warning(
                "ExposureLoader: skipped %d rows due to validation failures", skipped
            )
        logger.info(
            "ExposureLoader: %d rows passed validation out of %d fetched",
            len(validated),
            len(rows),
        )
        return validated

    # ── Neo4j writes ──────────────────────────────────────────────────────────

    def _write_exposes_edges(
        self,
        rows: List[Dict[str, Any]],
        tenant_id: str,
    ) -> int:
        """Write EXPOSES edges to Neo4j in batches.

        Uses UNWIND + MERGE to avoid duplicate edges (AC-4 in the story).
        The Internet virtual node is identified by ``uid = 'INTERNET'`` and
        ``tenant_id`` — matching the virtual node created by
        ``_create_virtual_nodes`` in graph_builder.

        NEVER uses f-string Cypher — all dynamic values go via parameters.

        Args:
            rows: Validated rows from ``_validate_rows``.
            tenant_id: Tenant to scope the Internet node lookup.

        Returns:
            Total number of edges written.
        """
        if not rows:
            return 0

        total_written = 0
        with self._driver.session() as session:
            for i in range(0, len(rows), _BATCH_SIZE):
                batch = rows[i : i + _BATCH_SIZE]
                try:
                    result = session.run(
                        """
                        UNWIND $rows AS row
                        MATCH (r:Resource {uid: row.resource_uid, tenant_id: $tenant_id})
                        MERGE (internet:Internet:VirtualNode {uid: 'INTERNET', tenant_id: $tenant_id})
                        ON CREATE SET
                            internet.name = 'Internet',
                            internet.risk_score = 100
                        MERGE (internet)-[e:EXPOSES {
                            rule_id: row.rule_id,
                            sg_id: row.sg_id,
                            cidr: row.cidr,
                            severity: row.severity
                        }]->(r)
                        SET e.port       = row.port,
                            e.protocol   = row.protocol,
                            e.layer      = row.layer,
                            e.edge_kind  = 'path',
                            e.attack_path_category = 'exposure'
                        RETURN COUNT(e) AS written
                        """,
                        rows=batch,
                        tenant_id=tenant_id,
                    )
                    record = result.single()
                    batch_count = record["written"] if record else 0
                    total_written += batch_count
                    logger.debug(
                        "ExposureLoader: wrote %d EXPOSES edges in batch %d/%d",
                        batch_count,
                        i // _BATCH_SIZE + 1,
                        (len(rows) + _BATCH_SIZE - 1) // _BATCH_SIZE,
                    )
                except Exception as exc:
                    logger.error(
                        "ExposureLoader: Cypher write failed for batch starting at row %d: %s",
                        i,
                        exc,
                    )

        logger.info(
            "ExposureLoader: wrote %d EXPOSES edges total for tenant=%s",
            total_written,
            tenant_id,
        )
        return total_written

    # ── Fallback: infer from Resource.is_public ───────────────────────────────

    def _infer_internet_exposure(self, tenant_id: str) -> int:
        """Fallback: create EXPOSES edges for Resource nodes with is_public=true.

        Used when the network DB is unavailable (empty NETWORK_DB_HOST) or
        returns 0 FAIL rows.  Queries Neo4j for Resource nodes with the
        ``is_public`` property set to ``true`` and creates EXPOSES edges from a
        synthetic ``Internet`` virtual node.

        Args:
            tenant_id: Tenant to scope the query.

        Returns:
            Number of inferred EXPOSES edges created.
        """
        try:
            with self._driver.session() as session:
                result = session.run(
                    """
                    MATCH (r:Resource {tenant_id: $tenant_id})
                    WHERE r.is_public = true
                    MERGE (internet:Internet:VirtualNode {uid: 'INTERNET', tenant_id: $tenant_id})
                    ON CREATE SET
                        internet.name = 'Internet',
                        internet.risk_score = 100
                    MERGE (internet)-[e:EXPOSES]->(r)
                    ON CREATE SET
                        e.rule_id    = 'inferred.public_resource',
                        e.layer      = 'inferred',
                        e.edge_kind  = 'path',
                        e.attack_path_category = 'exposure'
                    RETURN COUNT(e) AS created
                    """,
                    tenant_id=tenant_id,
                )
                record = result.single()
                count = record["created"] if record else 0
                logger.info(
                    "ExposureLoader: inferred %d EXPOSES edges from is_public=true "
                    "for tenant=%s",
                    count,
                    tenant_id,
                )
                return count
        except Exception as exc:
            logger.error(
                "ExposureLoader: inferred exposure query failed: %s", exc
            )
            return 0


def build_network_db_config() -> Dict[str, Any]:
    """Build the network DB config dict from environment variables.

    Returns the dict expected by ``ExposureLoader.__init__``.  Called from
    ``SecurityGraphBuilder.__init__`` so the config is available at graph-build
    time without re-reading env vars.

    Returns:
        Dict with keys ``host``, ``dbname``, ``user``, ``password``, ``port``.
    """
    return {
        "host": os.environ.get("NETWORK_DB_HOST", ""),
        "dbname": os.environ.get("NETWORK_DB_NAME", "threat_engine_network"),
        "user": os.environ.get("NETWORK_DB_USER", ""),
        "password": os.environ.get("NETWORK_DB_PASSWORD", ""),
        "port": 5432,
    }
