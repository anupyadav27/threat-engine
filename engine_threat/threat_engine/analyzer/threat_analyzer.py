"""
Threat Analyzer — Automated triage, blast-radius scoring and prioritization.

Reads from:
  - threat_detections   (the 21 threats we already generate)
  - inventory_relationships  (814 asset relationship rows — graph edges)
  - check_findings + rule_metadata  (severity & MITRE enrichment)

Writes to:
  - threat_analysis  (one row per detection, FK → threat_detections)

Analysis types produced:
  - blast_radius     — how many resources are reachable from the affected resource
  - risk_triage      — composite risk score = severity × reachability × MITRE impact
  - attack_chain     — ordered list of relationships forming potential attack paths
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ── MITRE technique → impact weight ──────────────────────────────────────────
# Higher weight = more dangerous if exploited.
MITRE_TECHNIQUE_WEIGHTS: Dict[str, float] = {
    "T1190": 1.0,   # Exploit Public-Facing Application
    "T1078": 0.9,   # Valid Accounts
    "T1098": 0.9,   # Account Manipulation
    "T1530": 0.85,  # Data from Cloud Storage
    "T1537": 0.85,  # Transfer Data to Cloud Account
    "T1485": 0.8,   # Data Destruction
    "T1486": 0.8,   # Data Encrypted for Impact (ransomware)
    "T1490": 0.8,   # Inhibit System Recovery
    "T1562": 0.75,  # Impair Defenses
    "T1499": 0.7,   # Endpoint Denial of Service
    "T1119": 0.65,  # Automated Collection
    "T1040": 0.6,   # Network Sniffing
    "T1578": 0.6,   # Modify Cloud Compute Infrastructure
}

SEVERITY_WEIGHTS: Dict[str, float] = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.5,
    "low": 0.25,
    "info": 0.1,
}

VERDICT_THRESHOLDS: List[Tuple[int, str]] = [
    (85, "critical_action_required"),
    (70, "high_risk"),
    (50, "medium_risk"),
    (30, "low_risk"),
    (0,  "informational"),
]


# ── Helper: Build adjacency list from inventory_relationships ────────────────

def _build_adjacency(
    relationships: List[Dict[str, Any]],
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Build directed adjacency list from inventory_relationships rows.

    Uses both legacy (from_uid / to_uid) and new (source_resource_uid /
    target_resource_uid) columns.  Bi-directional edges are added in both
    directions.
    """
    adj: Dict[str, List[Dict[str, Any]]] = {}

    for rel in relationships:
        # Prefer new columns; fall back to legacy
        src = rel.get("source_resource_uid") or rel.get("from_uid") or ""
        dst = rel.get("target_resource_uid") or rel.get("to_uid") or ""
        rel_type = rel.get("relationship_type") or rel.get("relation_type") or "related"

        if not src or not dst:
            continue
        # Skip self-referencing edges (references to same resource)
        if src == dst:
            continue

        edge = {
            "target": dst,
            "relationship_type": rel_type,
            "strength": rel.get("relationship_strength", "strong"),
            "properties": rel.get("properties") or {},
        }
        adj.setdefault(src, []).append(edge)

        # If bi-directional, add reverse
        if rel.get("bidirectional"):
            rev = {
                "target": src,
                "relationship_type": rel_type,
                "strength": rel.get("relationship_strength", "strong"),
                "properties": rel.get("properties") or {},
            }
            adj.setdefault(dst, []).append(rev)

    return adj


def _bfs_reachable(
    adj: Dict[str, List[Dict[str, Any]]],
    start: str,
    max_depth: int = 4,
) -> Tuple[Set[str], List[Dict[str, Any]]]:
    """
    BFS from *start* up to *max_depth* hops.

    Returns:
        reachable: set of reachable resource UIDs (excluding start)
        path_edges: ordered list of edges traversed
    """
    visited: Set[str] = {start}
    queue: List[Tuple[str, int]] = [(start, 0)]
    path_edges: List[Dict[str, Any]] = []

    while queue:
        node, depth = queue.pop(0)
        if depth >= max_depth:
            continue
        for edge in adj.get(node, []):
            tgt = edge["target"]
            if tgt not in visited:
                visited.add(tgt)
                path_edges.append({
                    "from": node,
                    "to": tgt,
                    "hop": depth + 1,
                    "relationship_type": edge["relationship_type"],
                    "strength": edge["strength"],
                })
                queue.append((tgt, depth + 1))

    reachable = visited - {start}
    return reachable, path_edges


# ── Core analysis functions ──────────────────────────────────────────────────

def compute_blast_radius(
    resource_arn: str,
    adjacency: Dict[str, List[Dict[str, Any]]],
    max_depth: int = 4,
) -> Dict[str, Any]:
    """
    Compute blast radius for a resource.

    Returns dict with:
        reachable_count, reachable_resources, path_edges, depth_distribution
    """
    reachable, path_edges = _bfs_reachable(adjacency, resource_arn, max_depth)

    # Depth distribution
    depth_dist: Dict[int, int] = {}
    for edge in path_edges:
        hop = edge["hop"]
        depth_dist[hop] = depth_dist.get(hop, 0) + 1

    return {
        "reachable_count": len(reachable),
        "reachable_resources": sorted(reachable),
        "path_edges": path_edges,
        "depth_distribution": depth_dist,
    }


def compute_mitre_impact_score(techniques: List[str]) -> float:
    """
    Average MITRE technique weight (0 – 1).
    Unknown techniques get a default weight of 0.5.
    """
    if not techniques:
        return 0.5  # No techniques mapped → neutral
    weights = [MITRE_TECHNIQUE_WEIGHTS.get(t, 0.5) for t in techniques]
    return sum(weights) / len(weights)


def compute_risk_score(
    severity: str,
    blast_radius_count: int,
    mitre_impact: float,
    is_internet_reachable: bool = False,
) -> int:
    """
    Composite risk score (0–100).

    Formula:
        base  = severity_weight × 40
        blast = min(blast_radius_count / 10, 1.0) × 25
        mitre = mitre_impact × 25
        bonus = 10 if internet-reachable
    """
    base = SEVERITY_WEIGHTS.get(severity, 0.5) * 40
    blast = min(blast_radius_count / 10.0, 1.0) * 25
    mitre = mitre_impact * 25
    bonus = 10 if is_internet_reachable else 0

    score = int(round(base + blast + mitre + bonus))
    return max(0, min(100, score))


def determine_verdict(risk_score: int) -> str:
    """Map risk score → human-readable verdict."""
    for threshold, verdict in VERDICT_THRESHOLDS:
        if risk_score >= threshold:
            return verdict
    return "informational"


def build_attack_chain(
    path_edges: List[Dict[str, Any]],
    resource_arn: str,
    techniques: List[str],
) -> List[Dict[str, Any]]:
    """
    Build simplified attack chain from path edges + MITRE techniques.
    """
    chain: List[Dict[str, Any]] = []

    # Step 1: Initial compromise at the affected resource
    chain.append({
        "step": 1,
        "resource": resource_arn,
        "action": "initial_compromise",
        "description": f"Misconfiguration detected on {resource_arn}",
        "mitre_techniques": techniques[:3],
    })

    # Steps 2+: Each hop in the blast radius
    for i, edge in enumerate(path_edges[:5], start=2):  # Max 5 hops in chain
        chain.append({
            "step": i,
            "resource": edge["to"],
            "action": edge["relationship_type"],
            "description": f"Lateral movement via {edge['relationship_type']} to {edge['to']}",
            "hop_from": edge["from"],
        })

    return chain


def build_recommendations(
    severity: str,
    blast_radius_count: int,
    mitre_techniques: List[str],
    is_internet_reachable: bool,
    verdict: str,
) -> List[Dict[str, Any]]:
    """Build prioritized recommendations list."""
    recs: List[Dict[str, Any]] = []

    if is_internet_reachable:
        recs.append({
            "priority": "critical",
            "action": "restrict_network_access",
            "description": "Resource is internet-reachable. Restrict inbound access via security groups or WAF.",
        })

    if severity in ("critical", "high"):
        recs.append({
            "priority": "high",
            "action": "remediate_misconfiguration",
            "description": f"Fix the {severity}-severity misconfiguration immediately.",
        })

    if blast_radius_count > 5:
        recs.append({
            "priority": "high",
            "action": "isolate_resource",
            "description": f"Blast radius includes {blast_radius_count} resources. Consider isolating the affected resource.",
        })

    if any(t in ("T1485", "T1486", "T1490") for t in mitre_techniques):
        recs.append({
            "priority": "critical",
            "action": "enable_backups",
            "description": "MITRE techniques indicate data destruction/ransomware risk. Ensure backups and immutability.",
        })

    if any(t in ("T1078", "T1098") for t in mitre_techniques):
        recs.append({
            "priority": "high",
            "action": "review_iam_policies",
            "description": "MITRE techniques indicate credential/account abuse risk. Review IAM policies and MFA.",
        })

    if not recs:
        recs.append({
            "priority": "medium",
            "action": "review_and_remediate",
            "description": "Review the misconfiguration and apply recommended remediation.",
        })

    return recs


# ── Main orchestrator ────────────────────────────────────────────────────────

class ThreatAnalyzer:
    """
    Orchestrates threat analysis for all detections in a scan.

    Usage:
        analyzer = ThreatAnalyzer()
        results = analyzer.analyze_scan(tenant_id, scan_run_id)
        # results is a list of analysis dicts ready for DB insert.
    """

    def __init__(self):
        self._conn_str: Optional[str] = None

    def _threat_conn_str(self) -> str:
        host = os.getenv("THREAT_DB_HOST", "localhost")
        port = os.getenv("THREAT_DB_PORT", "5432")
        db = os.getenv("THREAT_DB_NAME", "threat_engine_threat")
        user = os.getenv("THREAT_DB_USER", "threat_user")
        pwd = os.getenv("THREAT_DB_PASSWORD", "threat_password")
        return f"postgresql://{user}:{pwd}@{host}:{port}/{db}"

    def _inventory_conn_str(self) -> str:
        host = os.getenv("INVENTORY_DB_HOST", os.getenv("THREAT_DB_HOST", "localhost"))
        port = os.getenv("INVENTORY_DB_PORT", os.getenv("THREAT_DB_PORT", "5432"))
        db = os.getenv("INVENTORY_DB_NAME", "threat_engine_inventory")
        user = os.getenv("INVENTORY_DB_USER", os.getenv("THREAT_DB_USER", "threat_user"))
        pwd = os.getenv("INVENTORY_DB_PASSWORD", os.getenv("THREAT_DB_PASSWORD", "threat_password"))
        return f"postgresql://{user}:{pwd}@{host}:{port}/{db}"

    # ── Data loaders ─────────────────────────────────────────────────────

    def _load_detections(self, tenant_id: str, scan_run_id: str) -> List[Dict[str, Any]]:
        """Load threat_detections rows for the given scan."""
        import psycopg2
        from psycopg2.extras import RealDictCursor

        conn = psycopg2.connect(self._threat_conn_str())
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT
                        detection_id, tenant_id, scan_id,
                        detection_type, rule_id, rule_name,
                        resource_arn, resource_id, resource_type,
                        account_id, region, provider,
                        severity, confidence, status,
                        threat_category,
                        mitre_tactics, mitre_techniques,
                        evidence, context,
                        first_seen_at, last_seen_at
                    FROM threat_detections
                    WHERE tenant_id = %s AND scan_id = %s
                    ORDER BY severity, detection_type
                """, (tenant_id, scan_run_id))
                return [dict(row) for row in cur.fetchall()]
        finally:
            conn.close()

    def _load_relationships(self, tenant_id: str) -> List[Dict[str, Any]]:
        """Load inventory_relationships for adjacency graph."""
        import psycopg2
        from psycopg2.extras import RealDictCursor

        conn = psycopg2.connect(self._inventory_conn_str())
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT
                        from_uid, to_uid, relation_type,
                        source_resource_uid, target_resource_uid, relationship_type,
                        relationship_strength, bidirectional,
                        properties
                    FROM inventory_relationships
                    WHERE tenant_id = %s
                """, (tenant_id,))
                return [dict(row) for row in cur.fetchall()]
        finally:
            conn.close()

    def _load_internet_reachable(self, tenant_id: str) -> Set[str]:
        """
        Identify internet-reachable resources from inventory_relationships.

        Looks for relationships of type 'exposes', 'routes_to', 'allows_traffic'
        that originate from internet-like sources.
        """
        import psycopg2
        from psycopg2.extras import RealDictCursor

        reachable: Set[str] = set()
        conn = psycopg2.connect(self._inventory_conn_str())
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT DISTINCT
                        COALESCE(target_resource_uid, to_uid) as target
                    FROM inventory_relationships
                    WHERE tenant_id = %s
                      AND (
                        COALESCE(relationship_type, relation_type) IN ('exposes', 'routes_to', 'allows_traffic')
                        OR COALESCE(relationship_type, relation_type) LIKE '%%public%%'
                      )
                """, (tenant_id,))
                for row in cur.fetchall():
                    if row["target"]:
                        reachable.add(row["target"])
        finally:
            conn.close()

        return reachable

    # ── Analysis orchestrator ────────────────────────────────────────────

    def analyze_scan(
        self,
        tenant_id: str,
        scan_run_id: str,
    ) -> List[Dict[str, Any]]:
        """
        Analyze all threat_detections for a scan.

        Returns a list of analysis result dicts (one per detection) matching
        the threat_analysis table schema.
        """
        logger.info("Starting threat analysis", extra={"extra_fields": {
            "tenant_id": tenant_id, "scan_run_id": scan_run_id
        }})

        # 1. Load detections
        detections = self._load_detections(tenant_id, scan_run_id)
        if not detections:
            logger.info("No detections found for scan")
            return []

        logger.info(f"Loaded {len(detections)} detections for analysis")

        # 2. Load relationships & build graph
        try:
            relationships = self._load_relationships(tenant_id)
            adjacency = _build_adjacency(relationships)
            logger.info(f"Built adjacency graph: {len(adjacency)} nodes, {sum(len(v) for v in adjacency.values())} edges")
        except Exception as e:
            logger.warning(f"Could not load inventory relationships: {e}. Continuing without blast radius.")
            adjacency = {}

        # 3. Identify internet-reachable resources
        try:
            internet_reachable = self._load_internet_reachable(tenant_id)
            logger.info(f"Internet-reachable resources: {len(internet_reachable)}")
        except Exception as e:
            logger.warning(f"Could not load reachability data: {e}")
            internet_reachable = set()

        # 4. Analyze each detection
        analysis_results: List[Dict[str, Any]] = []
        now = datetime.now(timezone.utc)

        for det in detections:
            detection_id = str(det["detection_id"])
            resource_arn = det.get("resource_arn") or ""
            severity = (det.get("severity") or "medium").lower()
            mitre_techniques = det.get("mitre_techniques") or []
            mitre_tactics = det.get("mitre_tactics") or []

            # Blast radius
            blast = compute_blast_radius(resource_arn, adjacency)

            # MITRE impact
            mitre_impact = compute_mitre_impact_score(mitre_techniques)

            # Internet reachable?
            is_reachable = resource_arn in internet_reachable

            # Risk score
            risk_score = compute_risk_score(
                severity, blast["reachable_count"], mitre_impact, is_reachable
            )

            # Verdict
            verdict = determine_verdict(risk_score)

            # Attack chain
            attack_chain = build_attack_chain(
                blast["path_edges"], resource_arn, mitre_techniques
            )

            # Recommendations
            recommendations = build_recommendations(
                severity, blast["reachable_count"], mitre_techniques,
                is_reachable, verdict
            )

            # Related threats (same resource_arn or overlapping blast radius)
            related = []
            for other in detections:
                if str(other["detection_id"]) == detection_id:
                    continue
                other_arn = other.get("resource_arn") or ""
                if other_arn == resource_arn or other_arn in blast.get("reachable_resources", []):
                    related.append(str(other["detection_id"]))
            related = related[:10]  # Cap at 10

            # Build analysis_results JSONB
            analysis_result = {
                "blast_radius": {
                    "reachable_count": blast["reachable_count"],
                    "reachable_resources": blast["reachable_resources"][:20],  # Cap
                    "depth_distribution": blast["depth_distribution"],
                },
                "mitre_analysis": {
                    "techniques": mitre_techniques,
                    "tactics": mitre_tactics,
                    "impact_score": round(mitre_impact, 3),
                },
                "reachability": {
                    "is_internet_reachable": is_reachable,
                },
                "severity_weight": SEVERITY_WEIGHTS.get(severity, 0.5),
                "composite_formula": "severity×40 + blast_radius×25 + mitre_impact×25 + reachability×10",
            }

            row = {
                "detection_id": detection_id,
                "tenant_id": tenant_id,
                "analysis_type": "risk_triage",
                "analyzer": "threat_analyzer.v1",
                "analysis_status": "completed",
                "risk_score": risk_score,
                "verdict": verdict,
                "analysis_results": analysis_result,
                "recommendations": recommendations,
                "related_threats": related,
                "attack_chain": attack_chain,
                "started_at": now,
                "completed_at": datetime.now(timezone.utc),
            }

            analysis_results.append(row)

        logger.info(f"Threat analysis complete: {len(analysis_results)} analyses produced", extra={
            "extra_fields": {
                "tenant_id": tenant_id,
                "scan_run_id": scan_run_id,
                "analyses": len(analysis_results),
            }
        })

        return analysis_results
