"""
Security Graph Queries — Cypher-based attack path analysis, blast radius,
and threat hunting against the Neo4j security graph.

Provides Wiz-style graph queries:
  - Attack paths from Internet → sensitive resources
  - Blast radius (how far can attacker go from compromised resource)
  - Reachability analysis (which resources are exposed)
  - Toxic combinations (resource with multiple high-severity threats)
  - Threat hunting with custom Cypher patterns
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class SecurityGraphQueries:
    """
    Query the Neo4j security graph for attack paths, blast radius, etc.

    Usage:
        gq = SecurityGraphQueries()
        paths = gq.attack_paths_from_internet(tenant_id="588989875114")
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

    def attack_paths_from_internet(
        self,
        tenant_id: str,
        max_hops: int = 5,
        min_severity: str = "high",
    ) -> List[Dict[str, Any]]:
        """
        Find all attack paths from Internet → Resources with threats.

        Returns paths like:
            Internet → SecurityGroup → S3Bucket → ThreatDetection(high)

        This is the core "Wiz-style" query.
        """
        severity_order = ["info", "low", "medium", "high", "critical"]
        min_idx = severity_order.index(min_severity) if min_severity in severity_order else 3

        results = self._run(f"""
            MATCH path = (internet:Internet)-[*1..{max_hops}]->(resource:Resource)
            WHERE resource.tenant_id = $tid
            WITH resource, path,
                 [n IN nodes(path) | n.name] AS node_names,
                 [r IN relationships(path) | type(r)] AS rel_types,
                 length(path) AS hops
            OPTIONAL MATCH (resource)-[:HAS_THREAT]->(threat:ThreatDetection)
            WHERE threat.severity IN $severities
            RETURN
                resource.uid AS resource_uid,
                resource.name AS resource_name,
                resource.resource_type AS resource_type,
                threat.detection_id AS threat_id,
                threat.severity AS threat_severity,
                threat.risk_score AS risk_score,
                threat.verdict AS verdict,
                threat.mitre_techniques AS mitre_techniques,
                node_names,
                rel_types,
                hops
            ORDER BY threat.risk_score DESC, hops ASC
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

        Returns:
            reachable_resources, attack_paths, depth_distribution, threat_overlap
        """
        # Get all reachable nodes
        reachable = self._run(f"""
            MATCH path = (start:Resource)-[*1..{max_hops}]->(target:Resource)
            WHERE start.uid STARTS WITH $uid AND target.tenant_id = $tid
              AND start <> target
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

        # Depth distribution
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

    def internet_exposed_resources(
        self,
        tenant_id: str,
    ) -> List[Dict[str, Any]]:
        """Find all resources directly or indirectly exposed to the internet."""
        return self._run("""
            MATCH path = (internet:Internet)-[*1..3]->(resource:Resource)
            WHERE resource.tenant_id = $tid
            WITH DISTINCT resource, min(length(path)) AS exposure_hops
            OPTIONAL MATCH (resource)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                resource.uid AS resource_uid,
                resource.name AS name,
                resource.resource_type AS resource_type,
                resource.risk_score AS risk_score,
                exposure_hops,
                collect(t.severity) AS threat_severities,
                count(t) AS threat_count
            ORDER BY threat_count DESC, exposure_hops ASC
        """, tid=tenant_id)

    def toxic_combinations(
        self,
        tenant_id: str,
        min_threats: int = 2,
    ) -> List[Dict[str, Any]]:
        """
        Find resources with multiple overlapping threat detections (toxic combinations).

        E.g., S3 bucket that is both publicly accessible AND has data destruction risk.
        """
        return self._run("""
            MATCH (r:Resource {tenant_id: $tid})-[:HAS_THREAT]->(t:ThreatDetection)
            WITH r, collect(t) AS threats, count(t) AS threat_count
            WHERE threat_count >= $min_threats
            UNWIND threats AS t
            RETURN
                r.uid AS resource_uid,
                r.name AS resource_name,
                r.resource_type AS resource_type,
                threat_count,
                collect({
                    detection_id: t.detection_id,
                    severity: t.severity,
                    threat_category: t.threat_category,
                    risk_score: t.risk_score,
                    mitre_techniques: t.mitre_techniques
                }) AS threat_details
            ORDER BY threat_count DESC
        """, tid=tenant_id, min_threats=min_threats)

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

    # ── Pre-built Hunt Queries ───────────────────────────────────────────

    PREDEFINED_HUNTS: Dict[str, Dict[str, str]] = {
        "internet_to_sensitive_data": {
            "name": "Internet → Sensitive Data Path",
            "description": "Find attack paths from internet to S3 buckets with data destruction risk",
            "cypher": """
                MATCH path = (i:Internet)-[*1..5]->(s:S3Bucket {tenant_id: $tid})
                WHERE EXISTS { (s)-[:HAS_THREAT]->(t:ThreatDetection) WHERE 'T1485' IN t.mitre_techniques }
                RETURN
                    s.uid AS target_bucket,
                    s.name AS bucket_name,
                    length(path) AS path_length,
                    [n IN nodes(path) | coalesce(n.name, n.uid)] AS path_nodes,
                    [r IN relationships(path) | type(r)] AS path_rels
                ORDER BY length(path) ASC
            """,
        },
        "lateral_movement_iam": {
            "name": "IAM Lateral Movement Paths",
            "description": "Find IAM roles/policies that could enable lateral movement",
            "cypher": """
                MATCH (role:IAMRole {tenant_id: $tid})-[:REFERENCES|RELATES_TO*1..3]->(target:Resource)
                WHERE role <> target
                OPTIONAL MATCH (target)-[:HAS_THREAT]->(t:ThreatDetection)
                RETURN
                    role.uid AS role_arn,
                    role.name AS role_name,
                    target.uid AS reachable_resource,
                    target.resource_type AS target_type,
                    collect(t.severity) AS threat_severities
                ORDER BY size(collect(t.severity)) DESC
                LIMIT 50
            """,
        },
        "public_buckets_with_threats": {
            "name": "Public S3 Buckets with Active Threats",
            "description": "S3 buckets exposed to internet that have active threat detections",
            "cypher": """
                MATCH (i:Internet)-[:EXPOSES*1..2]->(b:S3Bucket {tenant_id: $tid})
                MATCH (b)-[:HAS_THREAT]->(t:ThreatDetection)
                RETURN
                    b.uid AS bucket_arn,
                    b.name AS bucket_name,
                    collect({severity: t.severity, category: t.threat_category, techniques: t.mitre_techniques}) AS threats,
                    count(t) AS threat_count
                ORDER BY threat_count DESC
            """,
        },
        "high_blast_radius": {
            "name": "Resources with High Blast Radius",
            "description": "Find resources where compromise could reach 5+ other resources",
            "cypher": """
                MATCH (r:Resource {tenant_id: $tid})-[:REFERENCES|RELATES_TO|ATTACK_PATH*1..4]->(target:Resource)
                WHERE r <> target
                WITH r, count(DISTINCT target) AS blast_count
                WHERE blast_count >= 3
                OPTIONAL MATCH (r)-[:HAS_THREAT]->(t:ThreatDetection)
                RETURN
                    r.uid AS resource_uid,
                    r.name AS resource_name,
                    r.resource_type AS resource_type,
                    blast_count,
                    collect(t.severity) AS threat_severities
                ORDER BY blast_count DESC
                LIMIT 20
            """,
        },
        "unprotected_critical_resources": {
            "name": "Critical Resources Without Protection",
            "description": "High-criticality resources with threats but no security group protection",
            "cypher": """
                MATCH (r:Resource {tenant_id: $tid})
                WHERE r.criticality = 'high'
                  AND NOT EXISTS { (sg:SecurityGroup)-[:REFERENCES]->(r) }
                OPTIONAL MATCH (r)-[:HAS_THREAT]->(t:ThreatDetection)
                RETURN
                    r.uid AS resource_uid,
                    r.name AS resource_name,
                    r.resource_type AS resource_type,
                    r.risk_score AS risk_score,
                    count(t) AS threat_count
                ORDER BY threat_count DESC, r.risk_score DESC
                LIMIT 30
            """,
        },
    }

    def list_predefined_hunts(self) -> List[Dict[str, str]]:
        """List all available pre-defined hunt queries."""
        return [
            {"id": k, "name": v["name"], "description": v["description"]}
            for k, v in self.PREDEFINED_HUNTS.items()
        ]

    def run_predefined_hunt(
        self, hunt_id: str, tenant_id: str
    ) -> List[Dict[str, Any]]:
        """Execute a pre-defined hunt query."""
        hunt = self.PREDEFINED_HUNTS.get(hunt_id)
        if not hunt:
            raise ValueError(f"Unknown hunt query: {hunt_id}")

        return self._run(hunt["cypher"], tid=tenant_id)
