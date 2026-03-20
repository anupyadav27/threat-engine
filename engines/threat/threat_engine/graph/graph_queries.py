"""
Security Graph Queries — Cypher-based attack path analysis, blast radius,
and threat hunting against the Neo4j security graph.

Provides Wiz-style graph queries:
  - Attack paths from Internet → sensitive resources
  - Blast radius (how far can attacker go from compromised resource)
  - Reachability analysis (which resources are exposed)
  - Toxic combinations (resource with multiple high-severity threats)
  - Threat hunting with custom Cypher patterns

=== DATABASE & TABLE MAP ===
Tables READ:
  - threat_hunt_queries : SELECT hunt_id, query_name, description, hunt_type,
                                 query_language, query_text, tags
                          FROM   threat_hunt_queries
                          WHERE  tenant_id IN (%s, '__global__')
                            AND  hunt_type = %s AND is_active = TRUE
  - threat_intelligence : (via correlate_intel_with_threats in threat_intel_writer.py)

Tables WRITTEN:
  - threat_hunt_results : INSERT (hunt_id, tenant_id, total_results,
                                  execution_time_ms, results_data, status)
                          via save_hunt_result() after each toxic combo / hunt execution
===
"""

from __future__ import annotations

import logging
import os
import time as _time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ── DB helpers for loading hunt queries / saving results ──────────────────


def _load_hunt_queries(
    tenant_id: str,
    hunt_type: str = "toxic_combination",
) -> List[Dict[str, Any]]:
    """
    Load hunt queries from threat_hunt_queries table.

    Loads queries for both the given tenant AND '__global__' (system-wide).
    """
    import psycopg2
    from psycopg2.extras import RealDictCursor

    conn_str = _threat_db_url()
    try:
        conn = psycopg2.connect(conn_str)
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT hunt_id, tenant_id, query_name, description,
                       hunt_type, query_language, query_text, tags,
                       mitre_tactics, mitre_techniques
                FROM   threat_hunt_queries
                WHERE  tenant_id IN (%s, '__global__')
                  AND  hunt_type = %s
                  AND  is_active = TRUE
                ORDER BY query_name
            """, (tenant_id, hunt_type))
            rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows
    except Exception as exc:
        logger.warning("Failed to load hunt queries (type=%s): %s", hunt_type, exc)
        return []


def _save_hunt_execution(
    hunt_id: str,
    tenant_id: str,
    total_results: int,
    execution_time_ms: int,
    status: str = "completed",
    error_message: Optional[str] = None,
) -> None:
    """Save hunt execution result to threat_hunt_results and update stats."""
    try:
        from ..storage.threat_intel_writer import save_hunt_result
        save_hunt_result({
            "hunt_id": hunt_id,
            "tenant_id": tenant_id,
            "total_results": total_results,
            "new_detections": 0,
            "execution_time_ms": execution_time_ms,
            "results_data": {"total": total_results},
            "status": status,
            "error_message": error_message,
        })
    except Exception as exc:
        logger.warning("Failed to save hunt result for %s: %s", hunt_id, exc)


def _extract_severity_from_tags(tags: Any) -> str:
    """Extract severity from tags list (e.g. ['critical', 'data-exposure'] → 'critical')."""
    if not tags:
        return "medium"
    if isinstance(tags, str):
        tags = [tags]
    for sev in ("critical", "high", "medium", "low"):
        if sev in tags:
            return sev
    return "medium"


def _threat_db_url() -> str:
    """Build threat DB connection URL from env vars."""
    host = os.getenv("THREAT_DB_HOST", "localhost")
    port = os.getenv("THREAT_DB_PORT", "5432")
    db = os.getenv("THREAT_DB_NAME", "threat_engine_threat")
    user = os.getenv("THREAT_DB_USER", "threat_user")
    pwd = os.getenv("THREAT_DB_PASSWORD", "threat_password")
    return f"postgresql://{user}:{pwd}@{host}:{port}/{db}"


class SecurityGraphQueries:
    """
    Query the Neo4j security graph for attack paths, blast radius, etc.

    Usage:
        gq = SecurityGraphQueries()
        paths = gq.attack_paths(tenant_id="588989875114")
        blast = gq.blast_radius("arn:aws:s3:::my-bucket", tenant_id="...")
    """

    def __init__(
        self,
        neo4j_uri: Optional[str] = None,
        neo4j_user: Optional[str] = None,
        neo4j_password: Optional[str] = None,
    ):
        self._uri = neo4j_uri or os.getenv("NEO4J_URI", "neo4j+s://17ec5cbb.databases.neo4j.io")
        self._user = neo4j_user or os.getenv("NEO4J_USER", "neo4j")
        self._password = neo4j_password or os.getenv("NEO4J_PASSWORD", "")
        self._driver = None

    def _get_driver(self):
        if self._driver is None:
            from neo4j import GraphDatabase
            self._driver = GraphDatabase.driver(
                self._uri, auth=(self._user, self._password)
            )
        return self._driver

    def close(self):
        if self._driver:
            self._driver.close()
            self._driver = None

    def _run(self, query: str, **kwargs) -> List[Dict[str, Any]]:
        """Execute Cypher and return list of record dicts."""
        driver = self._get_driver()
        with driver.session() as session:
            result = session.run(query, **kwargs)
            return [dict(r) for r in result]

    # ── Attack Path Queries ──────────────────────────────────────────────

    def attack_paths(
        self,
        tenant_id: str,
        max_hops: int = 5,
        min_severity: str = "medium",
        entry_point: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Find attack paths from ANY entry point to resources with threats.

        Entry points:
          - Internet (EXPOSES edges) — if entry_point is None or "internet"
          - Specific resource — if entry_point is a resource UID
          - All threatened resources — if entry_point is "all"

        Only traverses attack-relevant edges (where attack_path_category != '').
        Uses relationship property attack_path_category set by graph_builder.
        """
        severity_order = ["info", "low", "medium", "high", "critical"]
        min_idx = severity_order.index(min_severity) if min_severity in severity_order else 2

        if entry_point and entry_point not in ("internet", "all"):
            # Path from a specific resource
            results = self._run(f"""
                MATCH path = (start:Resource)-[rels*1..{max_hops}]->(target:Resource)
                WHERE start.uid = $entry AND target.tenant_id = $tid
                  AND start <> target
                  AND ALL(r IN rels WHERE r.attack_path_category IS NOT NULL AND r.attack_path_category <> '')
                WITH target, path,
                     [r IN rels | r.attack_path_category] AS categories,
                     [n IN nodes(path) | coalesce(n.name, n.uid)] AS node_names,
                     [r IN relationships(path) | type(r)] AS rel_types,
                     length(path) AS hops
                OPTIONAL MATCH (target)-[:HAS_THREAT]->(t:ThreatDetection)
                RETURN DISTINCT
                    $entry AS entry_point,
                    target.uid AS resource_uid,
                    target.name AS resource_name,
                    target.resource_type AS resource_type,
                    t.detection_id AS threat_id,
                    t.severity AS threat_severity,
                    t.risk_score AS risk_score,
                    categories,
                    node_names,
                    rel_types,
                    hops
                ORDER BY hops ASC
                LIMIT 200
            """, entry=entry_point, tid=tenant_id)

        elif entry_point == "all":
            # Paths from ALL resources that have threats
            results = self._run(f"""
                MATCH (start:Resource)-[:HAS_THREAT]->(st:ThreatDetection)
                WHERE start.tenant_id = $tid AND st.severity IN $severities
                WITH DISTINCT start
                MATCH path = (start)-[rels*1..{max_hops}]->(target:Resource)
                WHERE start <> target
                  AND ALL(r IN rels WHERE r.attack_path_category IS NOT NULL AND r.attack_path_category <> '')
                WITH start, target, path,
                     [r IN rels | r.attack_path_category] AS categories,
                     [n IN nodes(path) | coalesce(n.name, n.uid)] AS node_names,
                     [r IN relationships(path) | type(r)] AS rel_types,
                     length(path) AS hops
                RETURN DISTINCT
                    start.uid AS entry_point,
                    target.uid AS resource_uid,
                    target.name AS resource_name,
                    target.resource_type AS resource_type,
                    categories,
                    node_names,
                    rel_types,
                    hops
                ORDER BY hops ASC
                LIMIT 500
            """, tid=tenant_id, severities=severity_order[min_idx:])

        else:
            # Internet entry point (default) — merged internet_exposed + attack_paths
            results = self._run(f"""
                MATCH (internet:Internet)-[:EXPOSES]->(entry:Resource)
                WHERE entry.tenant_id = $tid
                WITH entry
                OPTIONAL MATCH path = (entry)-[rels*0..{max_hops - 1}]->(target:Resource)
                WHERE ALL(r IN rels WHERE r.attack_path_category IS NOT NULL AND r.attack_path_category <> '')
                WITH coalesce(target, entry) AS resource,
                     entry,
                     CASE WHEN path IS NULL
                          THEN [entry.name]
                          ELSE ['Internet'] + [n IN nodes(path) | coalesce(n.name, n.uid)]
                     END AS node_names,
                     CASE WHEN path IS NULL
                          THEN ['EXPOSES']
                          ELSE ['EXPOSES'] + [r IN relationships(path) | type(r)]
                     END AS rel_types,
                     CASE WHEN path IS NULL
                          THEN ['exposure']
                          ELSE ['exposure'] + [r IN CASE WHEN relationships(path) IS NULL THEN [] ELSE relationships(path) END | r.attack_path_category]
                     END AS categories,
                     CASE WHEN path IS NULL THEN 1 ELSE length(path) + 1 END AS hops
                OPTIONAL MATCH (resource)-[:HAS_THREAT]->(threat:ThreatDetection)
                WHERE threat.severity IN $severities
                RETURN DISTINCT
                    'Internet' AS entry_point,
                    resource.uid AS resource_uid,
                    resource.name AS resource_name,
                    resource.resource_type AS resource_type,
                    threat.detection_id AS threat_id,
                    threat.severity AS threat_severity,
                    threat.risk_score AS risk_score,
                    threat.verdict AS verdict,
                    threat.mitre_techniques AS mitre_techniques,
                    categories,
                    node_names,
                    rel_types,
                    hops
                ORDER BY
                    CASE threat.severity
                        WHEN 'critical' THEN 0
                        WHEN 'high' THEN 1
                        WHEN 'medium' THEN 2
                        WHEN 'low' THEN 3
                        ELSE 4
                    END ASC,
                    hops ASC
                LIMIT 200
            """, tid=tenant_id, severities=severity_order[min_idx:])

        return results

    def blast_radius(
        self,
        resource_uid: str,
        tenant_id: str,
        max_hops: int = 5,
    ) -> Dict[str, Any]:
        """
        Compute blast radius from a specific resource using graph traversal.
        Only follows attack-relevant edges (attack_path_category != '').

        Returns:
            reachable_resources, depth_distribution, resources_with_threats
        """
        reachable = self._run(f"""
            MATCH path = (start:Resource)-[rels*1..{max_hops}]->(target:Resource)
            WHERE start.uid STARTS WITH $uid AND target.tenant_id = $tid
              AND start <> target
              AND ALL(r IN rels WHERE r.attack_path_category IS NOT NULL AND r.attack_path_category <> '')
            WITH DISTINCT target, min(length(path)) AS min_hops
            OPTIONAL MATCH (target)-[:HAS_THREAT]->(t:ThreatDetection)
            OPTIONAL MATCH (target)-[:HAS_FINDING]->(f:Finding)
            RETURN
                target.uid AS uid,
                target.name AS name,
                target.resource_type AS resource_type,
                target.risk_score AS risk_score,
                min_hops AS hops,
                collect(DISTINCT t.detection_id) AS threats,
                count(DISTINCT f) AS finding_count
            ORDER BY min_hops, target.risk_score DESC
        """, uid=resource_uid, tid=tenant_id)

        depth_dist: Dict[int, int] = {}
        threat_overlap = 0
        for r in reachable:
            hop = r.get("hops", 0)
            depth_dist[hop] = depth_dist.get(hop, 0) + 1
            if r.get("threats"):
                threat_overlap += 1

        return {
            "source_resource": resource_uid,
            "reachable_count": len(reachable),
            "reachable_resources": reachable,
            "depth_distribution": depth_dist,
            "resources_with_threats": threat_overlap,
        }

    def toxic_combinations(
        self,
        tenant_id: str,
    ) -> List[Dict[str, Any]]:
        """
        Find dangerous multi-factor threat combinations on resources.

        Loads curated toxic combination patterns from the threat_hunt_queries
        table (hunt_type='toxic_combination') and executes each against the
        Neo4j graph. Results are saved to threat_hunt_results for tracking.

        Returns results sorted by combo_severity (critical > high).
        """
        patterns = _load_hunt_queries(tenant_id, hunt_type="toxic_combination")
        if not patterns:
            logger.info("No curated toxic patterns — using default multi-threat query")
            return self._default_toxic_combinations(tenant_id)

        results: List[Dict[str, Any]] = []
        seen_uids: set = set()

        for pattern in patterns:
            hunt_id = str(pattern["hunt_id"])
            query_text = pattern["query_text"]
            severity = _extract_severity_from_tags(pattern.get("tags", []))
            start = _time.time()

            try:
                matches = self._run(query_text, tid=tenant_id)
            except Exception as exc:
                logger.warning("Toxic pattern %s failed: %s", pattern["query_name"], exc)
                _save_hunt_execution(hunt_id, tenant_id, 0, 0, "failed", str(exc))
                continue

            duration_ms = int((_time.time() - start) * 1000)

            for m in matches:
                uid = m.get("resource_uid", "")
                if uid and uid not in seen_uids:
                    seen_uids.add(uid)
                    results.append({
                        "resource_uid": uid,
                        "resource_name": m.get("resource_name", ""),
                        "resource_type": m.get("resource_type", ""),
                        "combo_name": pattern["query_name"],
                        "combo_severity": severity,
                        "combo_description": pattern.get("description", ""),
                        "hunt_id": hunt_id,
                        "threat_count": m.get("threat_count", 0),
                        "threat_details": m.get("threat_details", []),
                        "matched_rules": m.get("matched_rules", []),
                    })

            # Save execution result to threat_hunt_results
            _save_hunt_execution(
                hunt_id, tenant_id, len(matches), duration_ms, "completed",
            )

        # Sort: critical first, then high, then by threat_count
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        results.sort(key=lambda x: (
            sev_order.get(x.get("combo_severity", "medium"), 2),
            -(x.get("threat_count", 0)),
        ))

        return results

    def _default_toxic_combinations(
        self,
        tenant_id: str,
        min_threats: int = 2,
    ) -> List[Dict[str, Any]]:
        """
        Default toxic combination query when no curated patterns exist.
        Finds resources with multiple threats of different categories.
        """
        try:
            results = self._run("""
                MATCH (r:Resource {tenant_id: $tid})-[:HAS_THREAT]->(t:ThreatDetection)
                WITH r,
                     count(t) AS threat_count,
                     collect(DISTINCT t.threat_category) AS categories,
                     collect(DISTINCT t.severity) AS severities,
                     collect({
                         detection_id: t.detection_id,
                         severity: t.severity,
                         category: t.threat_category,
                         rule_name: t.rule_name,
                         risk_score: t.risk_score
                     }) AS threat_details,
                     max(coalesce(t.risk_score, 0)) AS max_risk
                WHERE threat_count >= $min_threats
                RETURN
                    r.uid AS resource_uid,
                    r.name AS resource_name,
                    r.resource_type AS resource_type,
                    r.account_id AS account_id,
                    r.region AS region,
                    threat_count,
                    categories,
                    severities,
                    threat_details,
                    max_risk
                ORDER BY
                    CASE WHEN 'critical' IN severities THEN 0
                         WHEN 'high' IN severities THEN 1
                         ELSE 2
                    END,
                    threat_count DESC
                LIMIT 50
            """, tid=tenant_id, min_threats=min_threats)
        except Exception as exc:
            logger.warning("Default toxic combination query failed: %s", exc)
            return []

        combos = []
        for m in results:
            severities = m.get("severities") or []
            sev = "critical" if "critical" in severities else \
                  "high" if "high" in severities else "medium"
            cats = m.get("categories") or []
            details = m.get("threat_details") or []
            combos.append({
                "resource_uid": m.get("resource_uid", ""),
                "resource_name": m.get("resource_name", ""),
                "resource_type": m.get("resource_type", ""),
                "account": m.get("account_id", ""),
                "account_id": m.get("account_id", ""),
                "region": m.get("region", ""),
                "provider": "",  # populated by BFF from account map
                "combo_name": f"Multi-threat: {' + '.join(cats[:3])}" if cats else "Multiple threats",
                "combo_severity": sev,
                "combo_description": f"{m.get('threat_count', 0)} overlapping threats across {len(cats)} categories",
                "threat_count": m.get("threat_count", 0),
                "threat_details": details,
                "overlapping_threats": details,  # BFF compat
                "combined_risk_score": m.get("max_risk", 0),
                "mitre_techniques": cats[:5],
            })
        return combos

    def resource_context(
        self,
        resource_uid: str,
        tenant_id: str,
    ) -> Dict[str, Any]:
        """
        Get complete context for a single resource: neighbors, threats, findings, analysis.
        """
        # Resource properties
        resource = self._run("""
            MATCH (r:Resource)
            WHERE r.uid STARTS WITH $uid AND r.tenant_id = $tid
            RETURN r {.*} AS resource
            LIMIT 1
        """, uid=resource_uid, tid=tenant_id)

        # Neighbors
        neighbors = self._run("""
            MATCH (r:Resource)-[rel]-(neighbor)
            WHERE r.uid STARTS WITH $uid AND r.tenant_id = $tid
            RETURN
                type(rel) AS relationship,
                neighbor.uid AS neighbor_uid,
                neighbor.name AS neighbor_name,
                labels(neighbor) AS neighbor_labels,
                neighbor.risk_score AS neighbor_risk
            LIMIT 50
        """, uid=resource_uid, tid=tenant_id)

        # Threats
        threats = self._run("""
            MATCH (r:Resource)-[:HAS_THREAT]->(t:ThreatDetection)
            WHERE r.uid STARTS WITH $uid AND r.tenant_id = $tid
            RETURN t {.*} AS threat
        """, uid=resource_uid, tid=tenant_id)

        # Findings
        findings = self._run("""
            MATCH (r:Resource)-[:HAS_FINDING]->(f:Finding)
            WHERE r.uid STARTS WITH $uid AND r.tenant_id = $tid
            RETURN f.finding_id AS finding_id,
                   f.rule_id AS rule_id,
                   f.title AS title,
                   f.severity AS severity,
                   f.service AS service
            LIMIT 100
        """, uid=resource_uid, tid=tenant_id)

        return {
            "resource": resource[0]["resource"] if resource else {},
            "neighbors": neighbors,
            "threats": [t["threat"] for t in threats],
            "findings": findings,
            "neighbor_count": len(neighbors),
            "threat_count": len(threats),
            "finding_count": len(findings),
        }

    def graph_summary(self, tenant_id: str) -> Dict[str, Any]:
        """Get summary statistics of the security graph."""
        counts = self._run("""
            MATCH (n {tenant_id: $tid})
            WITH labels(n) AS lbls, n
            UNWIND lbls AS label
            RETURN label, count(n) AS count
            ORDER BY count DESC
        """, tid=tenant_id)

        rel_counts = self._run("""
            MATCH (a {tenant_id: $tid})-[r]->()
            RETURN type(r) AS rel_type, count(r) AS count
            ORDER BY count DESC
        """, tid=tenant_id)

        # Resources by type
        by_type = self._run("""
            MATCH (r:Resource {tenant_id: $tid})
            RETURN r.resource_type AS resource_type, count(r) AS count
            ORDER BY count DESC
        """, tid=tenant_id)

        # Threats by severity
        by_severity = self._run("""
            MATCH (t:ThreatDetection {tenant_id: $tid})
            RETURN t.severity AS severity, count(t) AS count
            ORDER BY count DESC
        """, tid=tenant_id)

        return {
            "node_counts": {r["label"]: r["count"] for r in counts},
            "relationship_counts": {r["rel_type"]: r["count"] for r in rel_counts},
            "resources_by_type": {r["resource_type"]: r["count"] for r in by_type},
            "threats_by_severity": {r["severity"]: r["count"] for r in by_severity},
        }

    # ── Threat Hunting ───────────────────────────────────────────────────

    def execute_hunt_query(
        self,
        cypher: str,
        tenant_id: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Execute a custom Cypher query for threat hunting.

        Safety: Only read queries are allowed. Mutations are blocked.
        """
        # Block mutations
        cypher_upper = cypher.upper().strip()
        blocked = ["CREATE", "DELETE", "SET ", "REMOVE", "MERGE", "DROP", "CALL {"]
        for keyword in blocked:
            if keyword in cypher_upper:
                raise ValueError(f"Mutation keyword '{keyword.strip()}' not allowed in hunt queries")

        all_params = {"tid": tenant_id}
        if params:
            all_params.update(params)

        return self._run(cypher, **all_params)

    # ── Pre-built Hunt Queries (DB-driven) ────────────────────────────────
    # All hunt queries are stored in threat_hunt_queries table
    # (hunt_type='predefined_hunt'). Seed with:
    #   python engines/threat/scripts/seed_hunt_queries.py

    def list_predefined_hunts(self, tenant_id: str = "__global__") -> List[Dict[str, str]]:
        """List all available pre-defined hunt queries from DB."""
        hunts = _load_hunt_queries(tenant_id, hunt_type="predefined_hunt")
        return [
            {
                "id": str(h["hunt_id"]),
                "name": h["query_name"],
                "description": h.get("description", ""),
            }
            for h in hunts
        ]

    def run_predefined_hunt(
        self, hunt_id: str, tenant_id: str
    ) -> List[Dict[str, Any]]:
        """Execute a pre-defined hunt query by hunt_id or query_name."""
        from ..storage.threat_intel_writer import get_hunt_query

        # Try by UUID first (hunt_id), then search by query_name
        hunt = get_hunt_query(hunt_id)
        if not hunt:
            # Search by query_name in predefined hunts
            hunts = _load_hunt_queries(tenant_id, hunt_type="predefined_hunt")
            hunt = next((h for h in hunts if h["query_name"] == hunt_id), None)

        if not hunt:
            raise ValueError(f"Unknown hunt query: {hunt_id}")

        start = _time.time()
        results = self._run(hunt["query_text"], tid=tenant_id)
        duration_ms = int((_time.time() - start) * 1000)

        # Save execution result
        _save_hunt_execution(
            str(hunt["hunt_id"]), tenant_id, len(results), duration_ms, "completed",
        )

        return results
