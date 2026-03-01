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
# These are hardcoded defaults. The ThreatAnalyzer also loads severity_base
# from mitre_technique_reference DB and maps it to weights at runtime.
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

# severity_base → weight mapping (used when loading from DB)
SEVERITY_TO_WEIGHT: Dict[str, float] = {
    "critical": 1.0,
    "high": 0.85,
    "medium": 0.6,
    "low": 0.35,
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


def compute_mitre_impact_score(
    techniques: List[str],
    mitre_guidance: Optional[Dict[str, Dict[str, Any]]] = None,
) -> float:
    """
    Average MITRE technique weight (0 – 1).

    Resolution order for each technique:
      1. mitre_guidance[technique_id]["severity_base"] → SEVERITY_TO_WEIGHT map
      2. Hardcoded MITRE_TECHNIQUE_WEIGHTS (legacy fallback)
      3. Default 0.5 (unknown technique)
    """
    if not techniques:
        return 0.5  # No techniques mapped → neutral

    weights: List[float] = []
    for t in techniques:
        # Try DB guidance first
        if mitre_guidance and t in mitre_guidance:
            sev = mitre_guidance[t].get("severity_base")
            if sev and sev.lower() in SEVERITY_TO_WEIGHT:
                weights.append(SEVERITY_TO_WEIGHT[sev.lower()])
                continue
        # Hardcoded fallback
        weights.append(MITRE_TECHNIQUE_WEIGHTS.get(t, 0.5))

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
    mitre_guidance: Optional[Dict[str, Dict[str, Any]]] = None,
    provider: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Build prioritized recommendations list.

    If mitre_guidance is available (loaded from mitre_technique_reference DB),
    appends technique-specific remediation steps from the DB.

    When ``provider`` is given (e.g. "aws", "azure", "gcp", "oci", "ibm",
    "alicloud", "k8s"), CSP-specific guidance sections are preferred.
    Falls back to top-level (AWS) keys when no CSP-specific section exists.
    """
    recs: List[Dict[str, Any]] = []

    # ── Context-based recommendations (unchanged) ────────────────────────

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

    # ── MITRE guidance-based recommendations (from DB) ───────────────────
    # CSP-aware: reads provider-specific sections (azure, gcp, oci, ibm,
    # alicloud, k8s) when available, otherwise falls back to top-level
    # AWS keys (cloudtrail_events, guardduty_types, immediate, preventive).

    # Map provider → JSONB key in guidance + CSP-specific field names
    _CSP_DETECTION_FIELDS = {
        "aws":      {"audit_key": "cloudtrail_events", "alert_key": "guardduty_types",
                     "audit_label": "CloudTrail", "alert_label": "GuardDuty"},
        "azure":    {"audit_key": "activity_logs", "alert_key": "defender_alerts",
                     "audit_label": "Activity Log", "alert_label": "Defender"},
        "gcp":      {"audit_key": "audit_logs", "alert_key": "scc_findings",
                     "audit_label": "Audit Log", "alert_label": "SCC"},
        "oci":      {"audit_key": "audit_logs", "alert_key": "cloud_guard_findings",
                     "audit_label": "OCI Audit", "alert_label": "Cloud Guard"},
        "ibm":      {"audit_key": "activity_tracker_events", "alert_key": "security_advisor_findings",
                     "audit_label": "Activity Tracker", "alert_label": "Security Advisor"},
        "alicloud": {"audit_key": "actiontrail_events", "alert_key": "security_center_alerts",
                     "audit_label": "ActionTrail", "alert_label": "Security Center"},
        "k8s":      {"audit_key": "audit_logs", "alert_key": "falco_alerts",
                     "audit_label": "K8s Audit", "alert_label": "Falco/Runtime"},
    }

    if mitre_guidance:
        seen_actions: set = {r["action"] for r in recs}  # avoid duplicates
        csp = (provider or "aws").lower()

        for tech_id in mitre_techniques:
            g = mitre_guidance.get(tech_id)
            if not g:
                continue

            raw_remediation = g.get("remediation_guidance") or {}
            raw_detection = g.get("detection_guidance") or {}
            tech_name = g.get("technique_name", tech_id)
            tech_sev = g.get("severity_base", "medium")

            # Resolve CSP-specific sections; fall back to top-level (AWS)
            if csp != "aws" and csp in raw_remediation:
                remediation = raw_remediation[csp]
            else:
                remediation = raw_remediation

            if csp != "aws" and csp in raw_detection:
                detection = raw_detection[csp]
            else:
                detection = raw_detection

            # Immediate remediation steps
            for step in remediation.get("immediate", []):
                action_key = f"mitre_remediate_{tech_id}_{step[:20]}"
                if action_key not in seen_actions:
                    seen_actions.add(action_key)
                    recs.append({
                        "priority": "high" if tech_sev in ("critical", "high") else "medium",
                        "action": action_key,
                        "description": f"[{tech_id}] {step}",
                        "source": "mitre_technique_reference",
                        "technique_id": tech_id,
                        "technique_name": tech_name,
                    })

            # Preventive measures
            for step in remediation.get("preventive", []):
                action_key = f"mitre_prevent_{tech_id}_{step[:20]}"
                if action_key not in seen_actions:
                    seen_actions.add(action_key)
                    recs.append({
                        "priority": "medium",
                        "action": action_key,
                        "description": f"[{tech_id} preventive] {step}",
                        "source": "mitre_technique_reference",
                        "technique_id": tech_id,
                        "technique_name": tech_name,
                    })

            # Detection monitoring recommendations (CSP-aware)
            csp_fields = _CSP_DETECTION_FIELDS.get(csp, _CSP_DETECTION_FIELDS["aws"])
            audit_events = detection.get(csp_fields["audit_key"], [])
            alert_types = detection.get(csp_fields["alert_key"], [])

            if audit_events:
                action_key = f"mitre_monitor_audit_{tech_id}"
                if action_key not in seen_actions:
                    seen_actions.add(action_key)
                    events_str = ", ".join(str(e) for e in audit_events[:5])
                    recs.append({
                        "priority": "medium",
                        "action": action_key,
                        "description": f"[{tech_id}] Monitor {csp_fields['audit_label']} events: {events_str}",
                        "source": "mitre_technique_reference",
                        "technique_id": tech_id,
                    })

            if alert_types:
                action_key = f"mitre_monitor_alert_{tech_id}"
                if action_key not in seen_actions:
                    seen_actions.add(action_key)
                    alert_str = ", ".join(str(a) for a in alert_types[:3])
                    recs.append({
                        "priority": "medium",
                        "action": action_key,
                        "description": f"[{tech_id}] Enable {csp_fields['alert_label']} detection: {alert_str}",
                        "source": "mitre_technique_reference",
                        "technique_id": tech_id,
                    })

    # ── Fallback if nothing matched ──────────────────────────────────────

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

    def _shared_conn_str(self) -> str:
        """Connection to shared DB for scan_orchestration lookups."""
        host = os.getenv("SHARED_DB_HOST", os.getenv("THREAT_DB_HOST", "localhost"))
        port = os.getenv("SHARED_DB_PORT", "5432")
        db = os.getenv("SHARED_DB_NAME", "threat_engine_shared")
        user = os.getenv("SHARED_DB_USER", os.getenv("THREAT_DB_USER", "threat_user"))
        pwd = os.getenv("SHARED_DB_PASSWORD", os.getenv("THREAT_DB_PASSWORD", "threat_password"))
        return f"postgresql://{user}:{pwd}@{host}:{port}/{db}"

    def _inventory_conn_str(self) -> str:
        """Build connection string for inventory DB.

        REQUIRES explicit INVENTORY_DB_* env vars. Does NOT fall back to
        THREAT_DB — if inventory is not configured, we raise early so the
        operator knows blast-radius scoring is disabled by misconfiguration,
        not silently zeroed out.
        """
        host = os.getenv("INVENTORY_DB_HOST")
        if not host:
            raise EnvironmentError(
                "INVENTORY_DB_HOST is not set. "
                "Blast-radius analysis requires a connection to the inventory DB. "
                "Set INVENTORY_DB_HOST, INVENTORY_DB_PORT, INVENTORY_DB_NAME, "
                "INVENTORY_DB_USER, INVENTORY_DB_PASSWORD or disable blast-radius."
            )
        port = os.getenv("INVENTORY_DB_PORT", "5432")
        db = os.getenv("INVENTORY_DB_NAME", "threat_engine_inventory")
        user = os.getenv("INVENTORY_DB_USER")
        pwd = os.getenv("INVENTORY_DB_PASSWORD")
        if not user or not pwd:
            raise EnvironmentError(
                "INVENTORY_DB_USER and INVENTORY_DB_PASSWORD are required. "
                "Cannot connect to inventory DB for blast-radius analysis."
            )
        return f"postgresql://{user}:{pwd}@{host}:{port}/{db}"

    # ── Scan ID resolution ──────────────────────────────────────────────

    def _resolve_inventory_scan_id(self, orchestration_id: str) -> Optional[str]:
        """Look up inventory_scan_id from scan_orchestration table in shared DB.

        Uses orchestration_id to find the inventory_scan_id that was generated
        during the same pipeline run. Returns None if not found.
        """
        import psycopg2
        from psycopg2.extras import RealDictCursor

        try:
            conn = psycopg2.connect(self._shared_conn_str())
            try:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("""
                        SELECT inventory_scan_id
                        FROM scan_orchestration
                        WHERE orchestration_id = %s::uuid
                    """, (orchestration_id,))
                    row = cur.fetchone()
                    if row and row.get("inventory_scan_id"):
                        inv_id = str(row["inventory_scan_id"])
                        logger.info(f"Resolved inventory_scan_id={inv_id} "
                                    f"from orchestration_id={orchestration_id}")
                        return inv_id
                    logger.warning(f"No inventory_scan_id in scan_orchestration "
                                   f"for orchestration_id={orchestration_id}")
                    return None
            finally:
                conn.close()
        except Exception as e:
            logger.warning(f"Could not resolve inventory_scan_id from shared DB: {e}")
            return None

    # ── Data loaders ─────────────────────────────────────────────────────

    def _load_mitre_guidance(self) -> Dict[str, Dict[str, Any]]:
        """Load detection/remediation guidance from mitre_technique_reference.

        Reads from the threat DB (same DB as threat_detections/threat_analysis).
        Returns a dict keyed by technique_id with:
            - severity_base: str ("critical", "high", "medium", "low")
            - detection_guidance: dict (cloudtrail_events, guardduty_types, etc.)
            - remediation_guidance: dict (immediate, preventive, detective, aws_services)
            - technique_name: str
            - tactics: list
        Only loads rows that actually have guidance populated (not empty {}).
        """
        import psycopg2
        from psycopg2.extras import RealDictCursor

        guidance: Dict[str, Dict[str, Any]] = {}
        try:
            conn = psycopg2.connect(self._threat_conn_str())
            try:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("""
                        SELECT
                            technique_id,
                            technique_name,
                            tactics,
                            severity_base,
                            detection_guidance,
                            remediation_guidance
                        FROM mitre_technique_reference
                        WHERE severity_base IS NOT NULL
                           OR (detection_guidance IS NOT NULL AND detection_guidance::text != '{}')
                           OR (remediation_guidance IS NOT NULL AND remediation_guidance::text != '{}')
                    """)
                    for row in cur.fetchall():
                        guidance[row["technique_id"]] = {
                            "technique_name": row["technique_name"],
                            "tactics": row.get("tactics") or [],
                            "severity_base": row.get("severity_base"),
                            "detection_guidance": row.get("detection_guidance") or {},
                            "remediation_guidance": row.get("remediation_guidance") or {},
                        }
                logger.info(f"Loaded MITRE guidance for {len(guidance)} techniques")
            finally:
                conn.close()
        except Exception as e:
            logger.warning(f"Could not load MITRE guidance from DB: {e}. "
                           f"Falling back to hardcoded weights.")
        return guidance

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

    def _load_relationships(
        self,
        tenant_id: str,
        inventory_scan_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Load inventory_relationships for adjacency graph.

        Args:
            tenant_id: Tenant isolation filter (always required).
            inventory_scan_id: If provided, only load relationships from this
                specific inventory scan (scoped to the pipeline run).
                If None, loads ALL relationships for the tenant (full snapshot).
        """
        import psycopg2
        from psycopg2.extras import RealDictCursor

        conn = psycopg2.connect(self._inventory_conn_str())
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                if inventory_scan_id:
                    logger.info(f"Loading relationships for inventory_scan_id={inventory_scan_id}")
                    cur.execute("""
                        SELECT
                            from_uid, to_uid, relation_type,
                            source_resource_uid, target_resource_uid, relationship_type,
                            relationship_strength, bidirectional,
                            properties
                        FROM inventory_relationships
                        WHERE tenant_id = %s AND inventory_scan_id = %s
                    """, (tenant_id, inventory_scan_id))
                else:
                    logger.info("Loading ALL relationships for tenant (no inventory_scan_id filter)")
                    cur.execute("""
                        SELECT
                            from_uid, to_uid, relation_type,
                            source_resource_uid, target_resource_uid, relationship_type,
                            relationship_strength, bidirectional,
                            properties
                        FROM inventory_relationships
                        WHERE tenant_id = %s
                    """, (tenant_id,))
                rows = [dict(row) for row in cur.fetchall()]
                logger.info(f"Loaded {len(rows)} inventory relationships")
                return rows
        finally:
            conn.close()

    def _load_internet_reachable(
        self,
        tenant_id: str,
        inventory_scan_id: Optional[str] = None,
    ) -> Set[str]:
        """
        Identify internet-reachable resources from inventory_relationships.

        Looks for relationships of type 'exposes', 'routes_to', 'allows_traffic'
        that originate from internet-like sources.

        Args:
            tenant_id: Tenant isolation filter.
            inventory_scan_id: If provided, scope to this inventory scan only.
        """
        import psycopg2
        from psycopg2.extras import RealDictCursor

        reachable: Set[str] = set()
        conn = psycopg2.connect(self._inventory_conn_str())
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                base_query = """
                    SELECT DISTINCT
                        COALESCE(target_resource_uid, to_uid) as target
                    FROM inventory_relationships
                    WHERE tenant_id = %s
                      AND (
                        COALESCE(relationship_type, relation_type) IN ('exposes', 'routes_to', 'allows_traffic')
                        OR COALESCE(relationship_type, relation_type) LIKE '%%public%%'
                      )
                """
                if inventory_scan_id:
                    base_query += " AND inventory_scan_id = %s"
                    cur.execute(base_query, (tenant_id, inventory_scan_id))
                else:
                    cur.execute(base_query, (tenant_id,))
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
        orchestration_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Analyze all threat_detections for a scan.

        Args:
            tenant_id: Tenant isolation filter.
            scan_run_id: The threat scan's scan_run_id (for loading detections).
            orchestration_id: Pipeline-wide UUID. If provided, we look up
                inventory_scan_id from scan_orchestration so we load ONLY the
                relationships from this specific pipeline run (not the full
                tenant snapshot). This is important for incremental scans
                that cover a subset of accounts/services.

        Returns a list of analysis result dicts (one per detection) matching
        the threat_analysis table schema.
        """
        logger.info("Starting threat analysis", extra={"extra_fields": {
            "tenant_id": tenant_id,
            "scan_run_id": scan_run_id,
            "orchestration_id": orchestration_id,
        }})

        # 1. Load detections
        detections = self._load_detections(tenant_id, scan_run_id)
        if not detections:
            logger.info("No detections found for scan")
            return []

        logger.info(f"Loaded {len(detections)} detections for analysis")

        # 1b. Resolve inventory_scan_id from orchestration_id
        #     This lets us filter inventory relationships to the specific scan
        #     rather than loading the entire tenant snapshot.
        inventory_scan_id: Optional[str] = None
        if orchestration_id:
            inventory_scan_id = self._resolve_inventory_scan_id(orchestration_id)
            if not inventory_scan_id:
                logger.warning(
                    f"orchestration_id={orchestration_id} provided but no "
                    f"inventory_scan_id found in scan_orchestration. "
                    f"Will load full tenant inventory snapshot."
                )

        # 1c. Load MITRE guidance from mitre_technique_reference table.
        #     Used for: severity_base → impact weights, detection/remediation recs.
        #     Graceful: if DB read fails, falls back to hardcoded weights.
        mitre_guidance = self._load_mitre_guidance()

        # 2. Load relationships & build graph
        #    Requires INVENTORY_DB_* env vars. If not configured, we log an
        #    ERROR (not warning) so operators know blast-radius is broken.
        adjacency: Dict[str, List[Dict[str, Any]]] = {}
        internet_reachable: Set[str] = set()
        inventory_available = False

        try:
            relationships = self._load_relationships(tenant_id, inventory_scan_id)
            adjacency = _build_adjacency(relationships)
            inventory_available = True
            logger.info(f"Built adjacency graph: {len(adjacency)} nodes, "
                        f"{sum(len(v) for v in adjacency.values())} edges")
        except EnvironmentError as e:
            # INVENTORY_DB not configured — this is an operator error, not transient
            logger.error(f"INVENTORY_DB not configured: {e}. "
                         f"Blast-radius will score ZERO for all detections.")
        except Exception as e:
            logger.error(f"Failed to load inventory relationships: {e}. "
                         f"Blast-radius will score ZERO.", exc_info=True)

        # 3. Identify internet-reachable resources
        if inventory_available:
            try:
                internet_reachable = self._load_internet_reachable(
                    tenant_id, inventory_scan_id
                )
                logger.info(f"Internet-reachable resources: {len(internet_reachable)}")
            except Exception as e:
                logger.error(f"Failed to load reachability data: {e}", exc_info=True)
        else:
            logger.warning("Skipping internet-reachability check — inventory DB not available")

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

            # MITRE impact (uses DB severity_base when available)
            mitre_impact = compute_mitre_impact_score(mitre_techniques, mitre_guidance)

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

            # Recommendations (enriched with DB guidance, CSP-aware)
            detection_provider = (det.get("provider") or "aws").lower()
            recommendations = build_recommendations(
                severity, blast["reachable_count"], mitre_techniques,
                is_reachable, verdict, mitre_guidance, detection_provider
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

            # Build per-technique detail from DB guidance (for JSONB output)
            technique_details: List[Dict[str, Any]] = []
            for tech_id in mitre_techniques:
                g = mitre_guidance.get(tech_id)
                if g:
                    technique_details.append({
                        "technique_id": tech_id,
                        "technique_name": g["technique_name"],
                        "severity_base": g.get("severity_base"),
                        "weight_used": SEVERITY_TO_WEIGHT.get(
                            (g.get("severity_base") or "").lower(),
                            MITRE_TECHNIQUE_WEIGHTS.get(tech_id, 0.5),
                        ),
                        "has_detection_guidance": bool(g.get("detection_guidance")),
                        "has_remediation_guidance": bool(g.get("remediation_guidance")),
                    })
                else:
                    technique_details.append({
                        "technique_id": tech_id,
                        "technique_name": None,
                        "severity_base": None,
                        "weight_used": MITRE_TECHNIQUE_WEIGHTS.get(tech_id, 0.5),
                        "has_detection_guidance": False,
                        "has_remediation_guidance": False,
                    })

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
                    "technique_details": technique_details,
                    "guidance_coverage": f"{sum(1 for t in technique_details if t.get('has_detection_guidance'))}/{len(technique_details)}",
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
