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
    provider: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Load hunt queries from threat_hunt_queries table.

    Loads queries for both the given tenant AND '__global__' (system-wide).
    If provider is given, only returns queries tagged for that provider
    (i.e. tags contains the provider string, or tags is NULL/empty = applies to all).
    """
    import psycopg2
    from psycopg2.extras import RealDictCursor

    conn_str = _threat_db_url()
    try:
        conn = psycopg2.connect(conn_str)
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            if provider:
                # tags is JSONB array; match queries tagged for this provider
                # or queries with no provider tag (NULL or empty array = universal)
                cur.execute("""
                    SELECT hunt_id, tenant_id, query_name, description,
                           hunt_type, query_language, query_text, tags,
                           mitre_tactics, mitre_techniques
                    FROM   threat_hunt_queries
                    WHERE  tenant_id IN (%s, '__global__')
                      AND  hunt_type = %s
                      AND  is_active = TRUE
                      AND  (
                               tags IS NULL
                           OR  tags = '[]'::jsonb
                           OR  tags @> to_jsonb(%s::text)
                      )
                    ORDER BY query_name
                """, (tenant_id, hunt_type, provider))
            else:
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

    # ── Attack Path Queries ──────────────────────────────────────────��───

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
        # ── Origin risk signals (threats + critical/high findings on the origin) ──
        origin_rows = self._run("""
            MATCH (origin:Resource)
            WHERE origin.uid STARTS WITH $uid AND origin.tenant_id = $tid
            OPTIONAL MATCH (origin)-[:HAS_THREAT]->(ot:ThreatDetection)
            OPTIONAL MATCH (origin)-[:HAS_FINDING]->(of:Finding)
            WHERE of.severity IN ['critical', 'high']
            RETURN
                collect(DISTINCT ot.detection_id) AS origin_threats,
                count(DISTINCT of)                AS origin_critical_high_findings
            LIMIT 1
        """, uid=resource_uid, tid=tenant_id)
        origin_row = origin_rows[0] if origin_rows else {}
        origin_threats: List = origin_row.get("origin_threats") or []
        origin_critical_high: int = origin_row.get("origin_critical_high_findings") or 0

        # ── Reachable nodes — include severity-bucketed finding counts ──────────
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
                count(DISTINCT f) AS finding_count,
                sum(CASE WHEN f.severity IN ['critical', 'high'] THEN 1 ELSE 0 END)
                    AS critical_high_findings
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
            # Origin risk — used by BFF to determine if origin is itself at risk
            "origin_threats": origin_threats,
            "origin_critical_high_findings": origin_critical_high,
            "reachable_count": len(reachable),
            "reachable_resources": reachable,
            "depth_distribution": depth_dist,
            "resources_with_threats": threat_overlap,
        }

    def toxic_combinations(
        self,
        tenant_id: str,
        provider: Optional[str] = None,
        min_threats: int = 2,
    ) -> List[Dict[str, Any]]:
        """
        Find dangerous multi-factor threat combinations on resources.

        Loads curated toxic combination patterns from the threat_hunt_queries
        table (hunt_type='toxic_combination') and executes each against the
        Neo4j graph. Results are saved to threat_hunt_results for tracking.

        Args:
            tenant_id: Tenant to scope the query to.
            provider: Optional CSP filter ("aws", "azure", "gcp", "k8s", ...).
                      When set, only patterns tagged for this provider (or
                      untagged universal patterns) are executed.

        Returns results sorted by combo_severity (critical > high).
        """
        patterns = _load_hunt_queries(tenant_id, hunt_type="toxic_combination", provider=provider)
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

    def fix_impact(
        self,
        tenant_id: str,
        resource_uid: Optional[str] = None,
        finding_id: Optional[str] = None,
        max_hops: int = 5,
    ) -> Dict[str, Any]:
        """
        Calculate how many attack paths disappear if a finding/resource is remediated.

        Logic:
          1. Count total attack paths from Internet → threatened resources (baseline).
          2. Count paths that pass THROUGH or END AT the specified resource.
          3. elimination_count = paths that include this resource.
          4. elimination_pct = elimination_count / total_paths * 100.

        If finding_id is given instead of resource_uid, we look up the resource
        from the threat_findings table first.

        Returns:
            resource_uid, total_paths, paths_eliminated, elimination_pct,
            affected_paths (list of path entry/target pairs), remediation_priority
        """
        # ── Resolve resource_uid from finding_id if needed ────────────────────
        resolved_uid = resource_uid
        if not resolved_uid and finding_id:
            try:
                import psycopg2
                conn = psycopg2.connect(_threat_db_url())
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT resource_uid FROM threat_findings WHERE finding_id = %s LIMIT 1",
                        (finding_id,),
                    )
                    row = cur.fetchone()
                    if row:
                        resolved_uid = row[0]
                conn.close()
            except Exception as exc:
                logger.warning("fix_impact: could not resolve finding_id %s: %s", finding_id, exc)

        if not resolved_uid:
            return {
                "error": "resource_uid or a valid finding_id is required",
                "total_paths": 0,
                "paths_eliminated": 0,
                "elimination_pct": 0.0,
            }

        # ── Count total Internet-sourced attack paths (baseline) ──────────────
        baseline_rows = self._run(f"""
            MATCH (internet:Internet)-[:EXPOSES]->(entry:Resource)
            WHERE entry.tenant_id = $tid
            OPTIONAL MATCH path = (entry)-[rels*0..{max_hops - 1}]->(target:Resource)
            WHERE target <> entry
              AND ALL(r IN rels WHERE r.attack_path_category IS NOT NULL AND r.attack_path_category <> '')
            WITH coalesce(target, entry) AS resource, entry
            OPTIONAL MATCH (resource)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN count(DISTINCT [entry.uid, resource.uid]) AS total_paths
        """, tid=tenant_id)
        total_paths: int = (baseline_rows[0].get("total_paths") or 0) if baseline_rows else 0

        # ── Count paths that include the target resource ───────────────────────
        affected_rows = self._run(f"""
            MATCH (internet:Internet)-[:EXPOSES]->(entry:Resource)
            WHERE entry.tenant_id = $tid
            OPTIONAL MATCH path = (entry)-[rels*0..{max_hops - 1}]->(target:Resource)
            WHERE target <> entry
              AND ALL(r IN rels WHERE r.attack_path_category IS NOT NULL AND r.attack_path_category <> '')
            WITH entry, coalesce(target, entry) AS resource, path
            WHERE entry.uid STARTS WITH $uid
               OR resource.uid STARTS WITH $uid
               OR any(n IN nodes(path) WHERE n.uid STARTS WITH $uid)
            RETURN DISTINCT
                entry.uid AS from_uid,
                resource.uid AS to_uid,
                entry.name AS from_name,
                resource.name AS to_name,
                resource.resource_type AS to_type
            LIMIT 100
        """, tid=tenant_id, uid=resolved_uid)

        paths_eliminated = len(affected_rows)
        elimination_pct = round((paths_eliminated / total_paths * 100) if total_paths > 0 else 0.0, 1)

        # Remediation priority: critical if eliminates >20% paths, high >10%, medium >5%
        if elimination_pct >= 20:
            priority = "critical"
        elif elimination_pct >= 10:
            priority = "high"
        elif elimination_pct >= 5:
            priority = "medium"
        else:
            priority = "low"

        return {
            "resource_uid": resolved_uid,
            "finding_id": finding_id,
            "total_paths": total_paths,
            "paths_eliminated": paths_eliminated,
            "elimination_pct": elimination_pct,
            "remediation_priority": priority,
            "affected_paths": [
                {
                    "from_uid": r.get("from_uid"),
                    "to_uid": r.get("to_uid"),
                    "from_name": r.get("from_name"),
                    "to_name": r.get("to_name"),
                    "to_type": r.get("to_type"),
                }
                for r in affected_rows
            ],
        }

    def explore_graph(
        self,
        tenant_id: str,
        resource_type: Optional[str] = None,
        security_status: Optional[str] = None,
        connected_to: Optional[str] = None,
        via_edge: Optional[str] = None,
        edge_kind: Optional[str] = None,
        within_hops: int = 2,
        limit: int = 300,
    ) -> Dict[str, Any]:
        """
        Structured graph exploration — structured filter params → Cypher → graph data.

        All params are validated enum values (no free text), safe to embed in Cypher.

        Args:
            resource_type: "EC2" | "S3" | "IAM" | "Lambda" | "RDS" | "KMS" | "SecurityGroup" | ...
            security_status: "has_threat" | "internet_exposed" | "high_risk" | "critical_findings"
            connected_to: resource type the matched resource must be connected to
            via_edge: relationship type for connected_to filter (ASSUMES | CAN_ACCESS | EXPOSES | ...)
            edge_kind: "path" | "association" | None (all edges). Filters edges in the result.
            within_hops: 0-5. 0 = return only matched nodes, no neighbor traversal.

        Returns:
            {nodes: [...], edges: [...], total_nodes, total_edges, cypher_summary}
        """
        # Validate edge_kind to prevent injection
        if edge_kind not in ("path", "association", None):
            edge_kind = None

        # ── Resource type → Neo4j resource_type values ───────────────────────
        _TYPE_MAP: Dict[str, List[str]] = {
            "EC2":           ["ec2.instance"],
            "S3":            ["s3.bucket", "s3.resource"],
            "IAM":           ["iam.role", "iam.user", "iam.policy", "iam.group"],
            "Lambda":        ["lambda.function", "lambda.resource"],
            "RDS":           ["rds.instance", "rds.db-instance", "rds.cluster"],
            "EKS":           ["eks.cluster"],
            "SecurityGroup": ["ec2.security-group"],
            "KMS":           ["kms.key", "kms.alias"],
            "VPC":           ["vpc.vpc", "ec2.vpc"],
            "Subnet":        ["vpc.subnet", "ec2.subnet"],
            "LoadBalancer":  ["elasticloadbalancingv2.loadbalancer", "elbv2.loadbalancer", "elb.loadbalancer"],
            "DynamoDB":      ["dynamodb.table", "dynamodb.resource"],
            "StorageAccount":["azure.storage_account"],
            "VirtualMachine":["azure.virtual_machine"],
            "GCSBucket":     ["gcp.gcs_bucket"],
            "ComputeInstance":["gcp.compute_instance"],
            "K8sPod":        ["k8s.pod"],
            "K8sDeployment": ["k8s.deployment"],
        }

        # Allowed edge types (whitelist — prevents Cypher injection)
        _ALLOWED_EDGES = {
            # Path edges
            "ASSUMES", "CAN_ACCESS", "EXPOSES", "ROUTES_TO",
            "CONNECTS_TO", "IN_VPC", "HOSTED_IN", "ACCESSES",
            "STORES", "ATTACHED_TO", "RUNS_ON",
            # Association edges
            "ENCRYPTED_BY", "PROTECTED_BY", "MEMBER_OF", "LOGS_TO",
            "DEPENDS_ON", "PROTECTS", "AFFECTED_BY", "OWNS",
            "HAS_THREAT", "HAS_FINDING",
        }

        # ── Build MATCH + WHERE ───────────────────────────────────────────────
        where_parts = ["r.tenant_id = $tid"]
        params: Dict[str, Any] = {"tid": tenant_id, "limit": limit}

        if resource_type and resource_type in _TYPE_MAP:
            where_parts.append("r.resource_type IN $rt_list")
            params["rt_list"] = _TYPE_MAP[resource_type]

        status_clause = ""
        if security_status == "has_threat":
            status_clause = "EXISTS { MATCH (r)-[:HAS_THREAT]->(:ThreatDetection) }"
        elif security_status == "internet_exposed":
            status_clause = "EXISTS { MATCH (:Internet)-[:EXPOSES]->(r) }"
        elif security_status == "high_risk":
            where_parts.append("r.risk_score >= 70")
        elif security_status == "critical_findings":
            status_clause = "EXISTS { MATCH (r)-[:HAS_FINDING]->(f:Finding) WHERE f.severity = 'critical' }"
        if status_clause:
            where_parts.append(status_clause)

        # ── Connected-to clause ───────────────────────────────────────────────
        edge_str = f":`{via_edge}`" if (via_edge and via_edge in _ALLOWED_EDGES) else ""
        connected_clause = ""
        if connected_to:
            if connected_to == "Internet":
                connected_clause = f"EXISTS {{ MATCH (:Internet)-[{edge_str}]->(r) }}"
            elif connected_to in _TYPE_MAP:
                params["ct_list"] = _TYPE_MAP[connected_to]
                connected_clause = (
                    f"EXISTS {{ MATCH (r)-[{edge_str}*1..{within_hops}]-(nb:Resource) "
                    f"WHERE nb.resource_type IN $ct_list AND nb.tenant_id = $tid }}"
                )
            if connected_clause:
                where_parts.append(connected_clause)

        where_cypher = " AND ".join(where_parts)

        # ── edge_kind filter on neighbor edges ───────────────────────────────
        # When edge_kind is set, only return edges of that kind in the result.
        # "path" → attacker traversal; "association" → context (findings, encryption)
        edge_kind_clause = ""
        if edge_kind:
            params["edge_kind"] = edge_kind
            edge_kind_clause = "AND (rel.edge_kind = $edge_kind)"

        # ── Main query ───────────────────────────────────────────────────────
        # within_hops=0: return only matched nodes (no neighbor traversal).
        # within_hops>=1: also fetch immediate neighbors for graph context.
        if within_hops == 0:
            cypher = f"""
                MATCH (r:Resource)
                WHERE {where_cypher}
                WITH r LIMIT $limit
                OPTIONAL MATCH (r)-[:HAS_THREAT]->(t:ThreatDetection)
                RETURN
                    r.uid            AS uid,
                    r.name           AS name,
                    r.resource_type  AS resource_type,
                    r.provider       AS provider,
                    r.account_id     AS account_id,
                    r.region         AS region,
                    r.risk_score     AS risk_score,
                    [] AS neighbors,
                    collect(DISTINCT t.severity) AS threat_severities,
                    max(t.risk_score)            AS max_threat_risk
            """
        else:
            cypher = f"""
                MATCH (r:Resource)
                WHERE {where_cypher}
                WITH r LIMIT $limit
                OPTIONAL MATCH (r)-[rel]->(nb:Resource)
                WHERE nb.tenant_id = $tid {edge_kind_clause}
                OPTIONAL MATCH (r)-[:HAS_THREAT]->(t:ThreatDetection)
                OPTIONAL MATCH (nb)-[:HAS_THREAT]->(nbt:ThreatDetection)
                RETURN
                    r.uid            AS uid,
                    r.name           AS name,
                    r.resource_type  AS resource_type,
                    r.provider       AS provider,
                    r.account_id     AS account_id,
                    r.region         AS region,
                    r.risk_score     AS risk_score,
                    collect(DISTINCT {{
                        nb_uid:      nb.uid,
                        nb_name:     nb.name,
                        nb_type:     nb.resource_type,
                        nb_provider: nb.provider,
                        rel_type:    type(rel),
                        rel_kind:    rel.edge_kind,
                        nb_risk:     nb.risk_score,
                        nb_threat:   nbt.severity
                    }}) AS neighbors,
                    collect(DISTINCT t.severity) AS threat_severities,
                    max(t.risk_score)            AS max_threat_risk
            """

        rows = self._run(cypher, **params)

        # ── Shape into nodes + edges ──────────────────────────────────────────
        seen_nodes: Dict[str, Dict] = {}
        edges: List[Dict] = []
        seen_edges: set = set()

        for row in rows:
            uid = row.get("uid")
            if not uid:
                continue
            sevs = row.get("threat_severities") or []
            seen_nodes[uid] = {
                "id": uid,
                "name": row.get("name") or uid.split("/")[-1],
                "type": row.get("resource_type", ""),
                "provider": row.get("provider", ""),
                "account_id": row.get("account_id", ""),
                "region": row.get("region", ""),
                "risk_score": row.get("risk_score") or row.get("max_threat_risk") or 0,
                "has_threat": bool(sevs and any(s for s in sevs)),
                "threat_severity": sevs[0] if sevs else None,
                "matched": True,  # this node matched the filter
            }
            for nb in (row.get("neighbors") or []):
                nb_uid = nb.get("nb_uid")
                rel_type = nb.get("rel_type")
                if not nb_uid or not rel_type:
                    continue
                if nb_uid not in seen_nodes:
                    seen_nodes[nb_uid] = {
                        "id": nb_uid,
                        "name": nb.get("nb_name") or nb_uid.split("/")[-1],
                        "type": nb.get("nb_type", ""),
                        "provider": nb.get("nb_provider", ""),
                        "risk_score": nb.get("nb_risk") or 0,
                        "has_threat": bool(nb.get("nb_threat")),
                        "threat_severity": nb.get("nb_threat"),
                        "matched": False,  # neighbor context node
                    }
                edge_key = f"{uid}|{rel_type}|{nb_uid}"
                if edge_key not in seen_edges:
                    seen_edges.add(edge_key)
                    edges.append({
                        "source": uid,
                        "target": nb_uid,
                        "type": rel_type,
                        "label": rel_type,
                        "edge_kind": nb.get("rel_kind") or "path",
                    })

        nodes = list(seen_nodes.values())

        # Build human-readable summary of what was queried
        summary_parts = []
        if resource_type:
            summary_parts.append(resource_type)
        if security_status:
            summary_parts.append(security_status.replace("_", " "))
        if connected_to:
            hop_str = f"within {within_hops} hop{'s' if within_hops > 1 else ''}"
            via_str = f" via {via_edge}" if via_edge else ""
            summary_parts.append(f"connected to {connected_to}{via_str} {hop_str}")
        cypher_summary = " · ".join(summary_parts) if summary_parts else "all resources"

        return {
            "nodes": nodes,
            "edges": edges,
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "matched_nodes": sum(1 for n in nodes if n.get("matched")),
            "cypher_summary": cypher_summary,
        }

    def orca_attack_paths(
        self,
        tenant_id: str,
        max_hops: int = 5,
        min_severity: str = "medium",
    ) -> List[Dict[str, Any]]:
        """Orca-style attack paths: PATH edges only, with per-node ASSOCIATION context.

        Returns structured paths where every node includes finding_count, threat_count
        so the UI can render both the route and the blast impact in a single view.

        Each path:
          - nodes: ordered list of resources from entry → target
          - edges: relationship hops with type + category
          - path_id: stable sha256[:8] of the node UIDs
          - total_risk: max risk score on any node in the path
        """
        import hashlib

        severity_order = ["info", "low", "medium", "high", "critical"]
        min_idx = severity_order.index(min_severity) if min_severity in severity_order else 2
        min_sevs = severity_order[min_idx:]

        # Relationship types that define attacker traversal routes.
        # Used as fallback for edges built before edge_kind was added to graph_builder.
        _PATH_TYPES = [
            "EXPOSES", "ASSUMES", "CAN_ACCESS", "CONNECTS_TO", "ACCESSES",
            "STORES", "ROUTES_TO", "HOSTED_IN", "IN_VPC", "RUNS_ON",
            "ATTACHED_TO", "MEMBER_OF",
        ]

        # Step 1: Discover paths (no enrichment join — keeps memory within Aura limits)
        raw = self._run(f"""
            MATCH path = (entry)-[path_rels*1..{max_hops}]->(target:Resource)
            WHERE (entry:VirtualNode OR entry:Resource)
              AND target.tenant_id = $tid
              AND ALL(r IN path_rels WHERE
                    r.edge_kind = 'path'
                    OR (r.edge_kind IS NULL AND type(r) IN $path_types)
              )
              AND length(path) >= 1
              // Exclude pure IAM role-chaining paths (Role→Role ASSUMES noise)
              AND NOT ALL(n IN nodes(path) WHERE n:IAMRole OR n:VirtualNode)
            WITH [n IN nodes(path) | n.uid]                               AS node_uids,
                 [n IN nodes(path) | coalesce(n.name, n.uid)]             AS node_names,
                 [n IN nodes(path) | coalesce(n.resource_type,'VirtualNode')] AS node_types,
                 [n IN nodes(path) | coalesce(n.risk_score, 0)]           AS node_risks,
                 [r IN relationships(path) | type(r)]                     AS rel_types,
                 [r IN relationships(path) | coalesce(r.attack_path_category,'')] AS rel_cats,
                 [r IN relationships(path) | coalesce(r.edge_kind,'path')] AS rel_kinds,
                 reduce(mx=0, s IN [n IN nodes(path) | coalesce(n.risk_score,0)]
                        | CASE WHEN s > mx THEN s ELSE mx END) AS max_risk
            RETURN node_uids, node_names, node_types, node_risks,
                   rel_types, rel_cats, rel_kinds, max_risk
            ORDER BY max_risk DESC
            LIMIT 200
        """, tid=tenant_id, path_types=_PATH_TYPES)

        # Step 2: collect all unique node UIDs from discovered paths
        all_node_uids: List[str] = []
        seen_uid_set: set = set()
        raw_rows = list(raw)
        for row in raw_rows:
            for uid in (row.get("node_uids") or []):
                if uid and uid not in seen_uid_set:
                    seen_uid_set.add(uid)
                    all_node_uids.append(uid)

        # Step 3: batch-fetch enrichment for all nodes in one query
        enrichment_map: Dict[str, Dict] = {}
        if all_node_uids:
            enrich_rows = self._run("""
                UNWIND $uids AS uid
                MATCH (pn:Resource {uid: uid})
                OPTIONAL MATCH (pn)-[:HAS_FINDING]->(f:Finding)
                WHERE f.severity IN ['critical', 'high']
                OPTIONAL MATCH (pn)-[:HAS_THREAT]->(t:ThreatDetection)
                WITH uid, pn,
                     count(DISTINCT f) AS f_count,
                     count(DISTINCT t) AS t_count,
                     max(t.risk_score) AS t_risk,
                     collect(DISTINCT t.severity)[0] AS t_sev,
                     collect(DISTINCT {
                         rule_name: coalesce(f.rule_name, f.title, f.finding_id),
                         severity:  f.severity,
                         finding_id: f.finding_id
                     })[..5] AS f_details,
                     collect(DISTINCT {
                         rule_name: coalesce(t.rule_name, t.technique_name, t.threat_id),
                         severity:  t.severity,
                         technique: t.technique_id
                     })[..4] AS t_details
                RETURN uid, f_count, t_count, t_risk, t_sev, f_details, t_details
            """, uids=all_node_uids)
            for er in enrich_rows:
                enrichment_map[er["uid"]] = {
                    "finding_count": er.get("f_count") or 0,
                    "threat_count":  er.get("t_count") or 0,
                    "threat_risk":   er.get("t_risk"),
                    "threat_severity": er.get("t_sev"),
                    "findings": [f for f in (er.get("f_details") or [])
                                 if isinstance(f, dict) and f.get("rule_name")],
                    "threats":  [t for t in (er.get("t_details") or [])
                                 if isinstance(t, dict) and t.get("rule_name")],
                }

        results: List[Dict[str, Any]] = []
        seen_paths: set = set()

        for row in raw_rows:
            node_uids  = row.get("node_uids") or []
            node_names = row.get("node_names") or []
            node_types = row.get("node_types") or []
            node_risks = row.get("node_risks") or []
            rel_types  = row.get("rel_types") or []
            rel_cats   = row.get("rel_cats") or []
            rel_kinds  = row.get("rel_kinds") or []
            enrichment = enrichment_map  # use pre-fetched enrichment by uid

            if not node_uids:
                continue

            # Deduplicate by path signature
            path_sig = "|".join(node_uids)
            if path_sig in seen_paths:
                continue
            seen_paths.add(path_sig)

            path_id = hashlib.sha256(path_sig.encode()).hexdigest()[:8]

            nodes_out = []
            for i, uid in enumerate(node_uids):
                enrich = enrichment.get(uid, {})
                # Filter out null-only finding/threat dicts from Cypher collect
                raw_findings = [
                    f for f in (enrich.get("findings") or [])
                    if isinstance(f, dict) and f.get("rule_name")
                ]
                raw_threats = [
                    t for t in (enrich.get("threats") or [])
                    if isinstance(t, dict) and t.get("rule_name")
                ]
                nodes_out.append({
                    "uid": uid,
                    "name": node_names[i] if i < len(node_names) else uid.split("/")[-1],
                    "type": node_types[i] if i < len(node_types) else "",
                    "risk_score": node_risks[i] if i < len(node_risks) else 0,
                    "finding_count": enrich.get("finding_count") or 0,
                    "threat_count": enrich.get("threat_count") or 0,
                    "threat_severity": enrich.get("threat_severity"),
                    "threat_risk": enrich.get("threat_risk"),
                    "findings": raw_findings,
                    "threats": raw_threats,
                })

            edges_out = []
            for i, rt in enumerate(rel_types):
                if i < len(node_uids) - 1:
                    edges_out.append({
                        "from_uid": node_uids[i],
                        "to_uid":   node_uids[i + 1],
                        "type":     rt,
                        "category": rel_cats[i] if i < len(rel_cats) else "",
                        "kind":     rel_kinds[i] if i < len(rel_kinds) else "path",
                    })

            # Entry point is the first node
            entry_uid = node_uids[0]
            entry_name = node_names[0] if node_names else entry_uid
            is_internet = "INTERNET" in entry_uid.upper() or entry_name == "Internet"

            results.append({
                "path_id":    path_id,
                "entry_point": "Internet" if is_internet else entry_uid,
                "entry_type":  "Internet" if is_internet else (node_types[0] if node_types else ""),
                "target_uid":  node_uids[-1],
                "target_type": node_types[-1] if node_types else "",
                "hops":        len(rel_types),
                "total_risk":  int(row.get("max_risk") or 0),
                "nodes":       nodes_out,
                "edges":       edges_out,
            })

        return results

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

    # ── Subgraph (Wiz-style topology) ────────────────────────────────────

    def subgraph(
        self,
        tenant_id: str,
        max_nodes: int = 500,
        include_types: str = "all",
    ) -> Dict[str, Any]:
        """Return a topology-first subgraph with threat/finding overlays.

        Layer 1: TOPOLOGY — all resources with relationships (infrastructure fabric)
        Layer 2: SECURITY OVERLAY — threats, risk scores, severity per resource
        Layer 3: INTERNET EXPOSURE — Internet → exposed resources

        Returns {nodes: [...], edges: [...], stats: {...}} where:
          - nodes have: id, label, type, riskScore, severity, threatCount, accountId, region
          - edges have: source, target, type, attackPathCategory
        """
        node_map = {}
        edges = []
        edge_set = set()

        # ── Layer 1: TOPOLOGY — all resources with at least one relationship ──
        # Start with resources that have edges (connected topology), ranked by
        # threat relevance (threatened first, then by degree)
        topology = self._run("""
            MATCH (r:Resource {tenant_id: $tid})-[rel]-(other)
            WHERE NOT type(rel) IN ['HAS_THREAT', 'HAS_FINDING']
              AND other:Resource
            WITH r, count(DISTINCT other) AS degree
            OPTIONAL MATCH (r)-[:HAS_THREAT]->(t:ThreatDetection)
            WITH r, degree,
                 count(t) AS tc,
                 max(t.risk_score) AS max_risk,
                 collect(DISTINCT t.severity)[0] AS top_sev
            RETURN r.uid AS uid,
                   r.name AS name,
                   r.resource_type AS resource_type,
                   r.account_id AS account_id,
                   r.region AS region,
                   coalesce(max_risk, 0) AS risk_score,
                   coalesce(top_sev, '') AS severity,
                   tc AS threat_count,
                   degree
            ORDER BY tc DESC, degree DESC, risk_score DESC
            LIMIT $limit
        """, tid=tenant_id, limit=max_nodes)

        for r in topology:
            uid = r.get("uid", "")
            if not uid:
                continue
            node_map[uid] = {
                "id": uid,
                "label": r.get("name") or uid.split("/")[-1].split(":")[-1],
                "type": r.get("resource_type", ""),
                "riskScore": r.get("risk_score", 0),
                "severity": r.get("severity", ""),
                "threatCount": r.get("threat_count", 0),
                "accountId": r.get("account_id", ""),
                "region": r.get("region", ""),
            }

        # Also include threatened resources that may be isolated (no topology edges)
        if len(node_map) < max_nodes:
            remaining = max_nodes - len(node_map)
            threatened = self._run("""
                MATCH (r:Resource {tenant_id: $tid})-[:HAS_THREAT]->(t:ThreatDetection)
                WHERE NOT r.uid IN $existing
                WITH r,
                     count(t) AS tc,
                     max(t.risk_score) AS max_risk,
                     collect(DISTINCT t.severity)[0] AS top_sev
                RETURN r.uid AS uid,
                       r.name AS name,
                       r.resource_type AS resource_type,
                       r.account_id AS account_id,
                       r.region AS region,
                       coalesce(max_risk, 0) AS risk_score,
                       coalesce(top_sev, '') AS severity,
                       tc AS threat_count
                ORDER BY max_risk DESC
                LIMIT $limit
            """, tid=tenant_id, existing=list(node_map.keys()), limit=remaining)
            for r in threatened:
                uid = r.get("uid", "")
                if uid and uid not in node_map:
                    node_map[uid] = {
                        "id": uid,
                        "label": r.get("name") or uid.split("/")[-1].split(":")[-1],
                        "type": r.get("resource_type", ""),
                        "riskScore": r.get("risk_score", 0),
                        "severity": r.get("severity", ""),
                        "threatCount": r.get("threat_count", 0),
                        "accountId": r.get("account_id", ""),
                        "region": r.get("region", ""),
                    }

        if not node_map:
            return {"nodes": [], "edges": [], "stats": {}}

        uids = list(node_map.keys())

        # ── Layer 2: ALL edges between selected nodes ──
        rels = self._run("""
            MATCH (a:Resource {tenant_id: $tid})-[r]->(b:Resource {tenant_id: $tid})
            WHERE a.uid IN $uids AND b.uid IN $uids
              AND a <> b
              AND NOT type(r) IN ['HAS_THREAT', 'HAS_FINDING']
            RETURN DISTINCT a.uid AS source, b.uid AS target,
                   type(r) AS rel_type,
                   coalesce(r.attack_path_category, '') AS attack_path_category
            LIMIT 2000
        """, tid=tenant_id, uids=uids)

        for rel in rels:
            key = f"{rel['source']}|{rel['target']}|{rel['rel_type']}"
            if key not in edge_set:
                edge_set.add(key)
                edges.append({
                    "source": rel["source"],
                    "target": rel["target"],
                    "type": rel["rel_type"],
                    "attackPathCategory": rel.get("attack_path_category", ""),
                })

        # ── Layer 2b: Neighbor expansion — add 1-hop neighbors for context ���─
        neighbors = self._run("""
            MATCH (a:Resource {tenant_id: $tid})-[r]->(b:Resource {tenant_id: $tid})
            WHERE a.uid IN $uids AND NOT b.uid IN $uids
              AND NOT type(r) IN ['HAS_THREAT', 'HAS_FINDING']
            WITH b, count(DISTINCT a) AS connections, collect(DISTINCT type(r))[0] AS rt,
                 collect(DISTINCT a.uid)[0] AS src_uid
            WHERE connections >= 1
            ORDER BY connections DESC
            LIMIT 100
            OPTIONAL MATCH (b)-[:HAS_THREAT]->(t:ThreatDetection)
            WITH b, rt, src_uid, count(t) AS tc, max(t.risk_score) AS mr
            RETURN b.uid AS uid,
                   coalesce(b.name, b.uid) AS name,
                   coalesce(b.resource_type, '') AS resource_type,
                   b.account_id AS account_id,
                   b.region AS region,
                   coalesce(mr, 0) AS risk_score,
                   tc AS threat_count
        """, tid=tenant_id, uids=uids)

        neighbor_uids = []
        for n in neighbors:
            uid = n.get("uid", "")
            if uid and uid not in node_map:
                node_map[uid] = {
                    "id": uid,
                    "label": n.get("name") or uid.split("/")[-1].split(":")[-1],
                    "type": n.get("resource_type", ""),
                    "riskScore": n.get("risk_score", 0),
                    "severity": "",
                    "threatCount": n.get("threat_count", 0),
                    "accountId": n.get("account_id", ""),
                    "region": n.get("region", ""),
                }
                neighbor_uids.append(uid)

        # Get edges involving newly added neighbors
        if neighbor_uids:
            all_uids = uids + neighbor_uids
            extra_rels = self._run("""
                MATCH (a:Resource {tenant_id: $tid})-[r]->(b:Resource {tenant_id: $tid})
                WHERE a.uid IN $uids AND b.uid IN $nuids
                  AND NOT type(r) IN ['HAS_THREAT', 'HAS_FINDING']
                RETURN DISTINCT a.uid AS source, b.uid AS target,
                       type(r) AS rel_type,
                       coalesce(r.attack_path_category, '') AS attack_path_category
                LIMIT 500
            """, tid=tenant_id, uids=uids, nuids=neighbor_uids)
            for rel in extra_rels:
                key = f"{rel['source']}|{rel['target']}|{rel['rel_type']}"
                if key not in edge_set:
                    edge_set.add(key)
                    edges.append({
                        "source": rel["source"],
                        "target": rel["target"],
                        "type": rel["rel_type"],
                        "attackPathCategory": rel.get("attack_path_category", ""),
                    })

        # ── Layer 3: Internet exposure ──
        # First, seed any internet-exposed resources not yet in node_map
        exposed_seed = self._run("""
            MATCH (i:Internet)-[:EXPOSES]->(r:Resource {tenant_id: $tid})
            WHERE NOT r.uid IN $existing
            OPTIONAL MATCH (r)-[:HAS_THREAT]->(t:ThreatDetection)
            WITH r, count(t) AS tc, max(t.risk_score) AS mr,
                 collect(DISTINCT t.severity)[0] AS top_sev
            RETURN r.uid AS uid,
                   coalesce(r.name, r.uid) AS name,
                   coalesce(r.resource_type, '') AS resource_type,
                   r.account_id AS account_id,
                   r.region AS region,
                   coalesce(mr, 0) AS risk_score,
                   coalesce(top_sev, '') AS severity,
                   tc AS threat_count
            LIMIT 200
        """, tid=tenant_id, existing=list(node_map.keys()))
        for r in exposed_seed:
            uid = r.get("uid", "")
            if uid and uid not in node_map:
                node_map[uid] = {
                    "id": uid,
                    "label": r.get("name") or uid.split("/")[-1].split(":")[-1],
                    "type": r.get("resource_type", ""),
                    "riskScore": r.get("risk_score", 0),
                    "severity": r.get("severity", ""),
                    "threatCount": r.get("threat_count", 0),
                    "accountId": r.get("account_id", ""),
                    "region": r.get("region", ""),
                }

        internet_rels = self._run("""
            MATCH (i:Internet)-[e:EXPOSES]->(r:Resource {tenant_id: $tid})
            WHERE r.uid IN $uids
            RETURN r.uid AS target, coalesce(e.reason, 'internet_exposed') AS reason
            LIMIT 200
        """, tid=tenant_id, uids=list(node_map.keys()))

        if internet_rels:
            node_map["Internet"] = {
                "id": "Internet",
                "label": "Internet",
                "type": "Internet",
                "riskScore": 0,
                "severity": "",
                "threatCount": 0,
            }
            for ir in internet_rels:
                key = f"Internet|{ir['target']}|EXPOSES"
                if key not in edge_set:
                    edge_set.add(key)
                    edges.append({
                        "source": "Internet",
                        "target": ir["target"],
                        "type": "EXPOSES",
                        "attackPathCategory": "exposure",
                    })

        # Stats
        total_threatened = sum(1 for n in node_map.values() if n.get("threatCount", 0) > 0)

        return {
            "nodes": list(node_map.values()),
            "edges": edges,
            "stats": {
                "totalNodes": len(node_map),
                "totalEdges": len(edges),
                "threatenedNodes": total_threatened,
                "internetExposed": len(internet_rels) if internet_rels else 0,
            },
        }

    # ── Threat Hunting ──────────��────────────────────────────────────────

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
