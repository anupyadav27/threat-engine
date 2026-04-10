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


# ── Attack path category classification (loaded from DB, inline fallback) ────
# Used when DB lookup fails or for relation types not yet seeded.
_ATTACK_PATH_CATEGORIES: Dict[str, Optional[str]] = {
    # ── Exposure ─────────────────────────────────────────────────────────────
    "internet_connected": "exposure", "exposed_through": "exposure",
    "serves_traffic_for": "exposure",
    # ── Lateral movement ─────────────────────────────────────────────────────
    "connected_to": "lateral_movement", "routes_to": "lateral_movement",
    "allows_traffic_from": "lateral_movement", "attached_to": "lateral_movement",
    "runs_on": "lateral_movement",
    # ── Privilege escalation ─────────────────────────────────────────────────
    "assumes": "privilege_escalation", "has_policy": "privilege_escalation",
    "grants_access_to": "privilege_escalation", "provides_identity_for": "privilege_escalation",
    "can_assume": "privilege_escalation",     # alias for assumes
    "can_access": "privilege_escalation",     # general access grant
    # ── Data access ──────────────────────────────────────────────────────────
    "stores_data_in": "data_access", "backs_up_to": "data_access",
    "replicates_to": "data_access", "cached_by": "data_access",
    "stores": "data_access",                  # canonical STORES edge
    # ── Execution ────────────────────────────────────────────────────────────
    "triggers": "execution", "invokes": "execution", "uses": "execution",
    # ── Data flow ────────────────────────────────────────────────────────────
    "publishes_to": "data_flow", "subscribes_to": "data_flow",
    "resolves_to": "data_flow",
    # ── Association edges (NOT attack paths) — stored for context only ───────
    "contained_by": None, "controlled_by": None, "encrypted_by": None,
    "logging_enabled_to": None, "monitored_by": None, "member_of": None,
    "scales_with": None, "manages": None, "deployed_by": None,
    "depends_on": None, "authenticated_by": None, "protected_by": None,
    "scanned_by": None, "complies_with": None,
    "protects": None,        # association: SG protects EC2 (context, not path)
    "owns": None,            # association: account/org ownership
    "1st_layer": None, "2nd_layer": None, "3rd_layer": None,
    "4th_layer": None, "on_prem_datacenter": None,
}

# Target value scores by asset_category (used in path scoring)
_ASSET_CATEGORY_SCORES: Dict[str, int] = {
    "secrets":    30,
    "data_store": 25,
    "identity":   25,
    "compute":    15,
    "network":    10,
    "messaging":  10,
    "deployment": 10,
    "monitoring":  5,
    "governance":  5,
}

# Hop category scores for path scoring
_HOP_CATEGORY_SCORES: Dict[str, int] = {
    "exposure":             5,
    "lateral_movement":    10,
    "privilege_escalation": 15,
    "data_access":         12,
    "execution":           12,
    "data_flow":            8,
}


# ── Helper: Build adjacency list from inventory_relationships ────────────────

def _build_adjacency(
    relationships: List[Dict[str, Any]],
    attack_path_categories: Optional[Dict[str, Optional[str]]] = None,
    attack_only: bool = False,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Build directed adjacency list from inventory_relationships rows.

    Args:
        relationships: Raw rows from inventory_relationships.
        attack_path_categories: Mapping of relation_type → category (or None).
            If not provided, uses the inline _ATTACK_PATH_CATEGORIES.
        attack_only: If True, only include edges with a non-None attack_path_category.
    """
    categories = attack_path_categories or _ATTACK_PATH_CATEGORIES
    adj: Dict[str, List[Dict[str, Any]]] = {}

    for rel in relationships:
        src = rel.get("source_resource_uid") or rel.get("from_uid") or ""
        dst = rel.get("target_resource_uid") or rel.get("to_uid") or ""
        rel_type = rel.get("relationship_type") or rel.get("relation_type") or "related"

        if not src or not dst or src == dst:
            continue

        category = categories.get(rel_type)

        # If attack_only, skip edges with no attack category
        if attack_only and category is None:
            continue

        edge = {
            "target": dst,
            "relationship_type": rel_type,
            "attack_path_category": category,
            "strength": rel.get("relationship_strength", "strong"),
            "properties": rel.get("properties") or {},
        }
        adj.setdefault(src, []).append(edge)

        if rel.get("bidirectional"):
            rev = {
                "target": src,
                "relationship_type": rel_type,
                "attack_path_category": category,
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
    Only follows edges that have attack_path_category set (non-None).

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
            # Only follow attack-relevant edges
            if not edge.get("attack_path_category"):
                continue
            tgt = edge["target"]
            if tgt not in visited:
                visited.add(tgt)
                path_edges.append({
                    "from": node,
                    "to": tgt,
                    "hop": depth + 1,
                    "relationship_type": edge["relationship_type"],
                    "attack_path_category": edge["attack_path_category"],
                    "strength": edge["strength"],
                })
                queue.append((tgt, depth + 1))

    reachable = visited - {start}
    return reachable, path_edges


# ── DFS: Find all attack paths from a resource ──────────────────────────────

def _find_attack_paths(
    adj: Dict[str, List[Dict[str, Any]]],
    start: str,
    asset_categories: Dict[str, str],
    internet_reachable: Set[str],
    max_depth: int = 5,
    max_paths: int = 20,
) -> List[Dict[str, Any]]:
    """
    DFS from *start* to find all distinct attack paths to valuable targets.

    A path is recorded when it reaches:
      - A resource with a known asset_category (data_store, secrets, identity, etc.)
      - A resource that is different from the start (any reachable target)

    Only follows edges with attack_path_category set.

    Args:
        adj: Adjacency list (with attack_path_category on edges).
        start: Starting resource UID.
        asset_categories: resource_uid → asset_category lookup.
        internet_reachable: Set of internet-reachable resource UIDs.
        max_depth: Max hops per path.
        max_paths: Max number of paths to return.

    Returns:
        List of path dicts with hops, chain_type, path_score, etc.
    """
    paths: List[Dict[str, Any]] = []

    # Determine if start is internet-reachable (entry type matters for scoring)
    start_is_internet = start in internet_reachable

    def dfs(node: str, current_hops: List[Dict[str, Any]], visited: Set[str], depth: int):
        if len(paths) >= max_paths:
            return
        if depth > max_depth:
            return

        # Record path if we've moved and reached a categorized target
        if depth > 0:
            target_category = asset_categories.get(node)
            if target_category:
                path = _build_path_result(
                    start, node, target_category, current_hops,
                    start_is_internet, asset_categories,
                )
                paths.append(path)

        for edge in adj.get(node, []):
            if len(paths) >= max_paths:
                return
            if not edge.get("attack_path_category"):
                continue
            tgt = edge["target"]
            if tgt in visited:
                continue

            hop = {
                "from": node,
                "to": tgt,
                "rel": edge["relationship_type"],
                "category": edge["attack_path_category"],
            }
            visited.add(tgt)
            current_hops.append(hop)
            dfs(tgt, current_hops, visited, depth + 1)
            current_hops.pop()
            visited.remove(tgt)

    dfs(start, [], {start}, 0)

    # Sort by path_score descending
    paths.sort(key=lambda p: p.get("path_score", 0), reverse=True)
    return paths


def _build_path_result(
    start: str,
    target: str,
    target_category: str,
    hops: List[Dict[str, Any]],
    start_is_internet: bool,
    asset_categories: Dict[str, str],
) -> Dict[str, Any]:
    """Build a structured path result with classification and scoring."""
    chain_type = _classify_chain(hops, start_is_internet, target_category)
    path_score = _score_path(hops, start_is_internet, target_category)

    return {
        "chain_type": chain_type,
        "path_score": path_score,
        "entry_point": start,
        "target": target,
        "target_category": target_category,
        "depth": len(hops),
        "hops": [dict(h) for h in hops],  # deep copy
    }


def _classify_chain(
    hops: List[Dict[str, Any]],
    start_is_internet: bool,
    target_category: str,
) -> str:
    """Derive chain_type from hop categories + entry/target context."""
    categories = {h["category"] for h in hops}
    prefix = "internet_to" if start_is_internet else "internal"

    if target_category == "secrets":
        return f"{prefix}_secrets"
    if target_category == "data_store":
        return f"{prefix}_data"
    if target_category == "identity":
        if "privilege_escalation" in categories:
            return f"{prefix}_privilege_escalation"
        return f"{prefix}_identity"
    if target_category == "compute":
        if "execution" in categories:
            return f"{prefix}_code_execution"
        if "lateral_movement" in categories:
            return f"{prefix}_lateral_movement"
        return f"{prefix}_compute"

    # Generic based on dominant hop category
    if "privilege_escalation" in categories:
        return f"{prefix}_privilege_escalation"
    if "data_access" in categories:
        return f"{prefix}_data_access"
    if categories == {"lateral_movement"}:
        return f"{prefix}_lateral_movement"
    return f"{prefix}_generic"


def _score_path(
    hops: List[Dict[str, Any]],
    start_is_internet: bool,
    target_category: str,
) -> int:
    """Score an attack path for criticality (0-100)."""
    score = 0

    # Entry point score
    score += 30 if start_is_internet else 10

    # Hop category scores
    for hop in hops:
        score += _HOP_CATEGORY_SCORES.get(hop.get("category", ""), 5)

    # Target value score
    score += _ASSET_CATEGORY_SCORES.get(target_category, 5)

    # Shorter paths are more dangerous (attacker friction)
    if len(hops) <= 2:
        score += 5

    return min(100, score)


def _infer_asset_category(resource_type: str) -> Optional[str]:
    """Infer asset_category from resource_type string when DB lookup unavailable."""
    rt = resource_type.lower()
    # Secrets
    if any(k in rt for k in ("secret", "kms", "ssm.parameter", "acm")):
        return "secrets"
    # Data stores
    if any(k in rt for k in ("s3.bucket", "rds.", "dynamodb", "redshift", "elasticache",
                              "efs.", "docdb", "neptune", "aurora", "backup")):
        return "data_store"
    # Identity
    if any(k in rt for k in ("iam.role", "iam.user", "iam.policy", "iam.group",
                              "cognito", "sso", "identitystore")):
        return "identity"
    # Compute
    if any(k in rt for k in ("ec2.instance", "lambda.function", "ecs.", "eks.",
                              "batch.", "sagemaker", "emr")):
        return "compute"
    # Network
    if any(k in rt for k in ("vpc", "subnet", "security-group", "security_group",
                              "elb", "apigateway", "cloudfront", "route53",
                              "internet-gateway", "nat-gateway")):
        return "network"
    # Messaging
    if any(k in rt for k in ("sqs", "sns", "eventbridge", "kinesis", "msk")):
        return "messaging"
    # Monitoring
    if any(k in rt for k in ("cloudwatch", "cloudtrail", "config.", "guardduty")):
        return "monitoring"
    return None


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
    attack_paths: List[Dict[str, Any]],
    resource_uid: str,
    techniques: List[str],
) -> List[Dict[str, Any]]:
    """
    Build attack chain from DFS-discovered attack paths.

    Returns a list of chain steps combining the initial compromise
    with the most critical attack path found.
    """
    chain: List[Dict[str, Any]] = []

    # Step 1: Initial compromise at the affected resource
    chain.append({
        "step": 1,
        "resource": resource_uid,
        "action": "initial_compromise",
        "description": f"Misconfiguration detected on {resource_uid}",
        "mitre_techniques": techniques[:3],
    })

    # Use the highest-scored path for the chain
    if attack_paths:
        best_path = attack_paths[0]  # Already sorted by path_score desc
        for i, hop in enumerate(best_path.get("hops", [])[:5], start=2):
            chain.append({
                "step": i,
                "resource": hop["to"],
                "action": hop["rel"],
                "attack_path_category": hop["category"],
                "description": f"{hop['category'].replace('_', ' ').title()} via {hop['rel']} to {hop['to']}",
                "hop_from": hop["from"],
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

    def _resolve_inventory_scan_id(self, scan_run_id: str) -> Optional[str]:
        """Return scan_run_id directly — all engines share the same ID.

        The scan_orchestration table no longer has per-engine scan ID columns.
        """
        return scan_run_id

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
                        resource_uid, resource_id, resource_type,
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
        scan_run_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Load inventory_relationships for adjacency graph.

        Args:
            tenant_id: Tenant isolation filter (always required).
            scan_run_id: If provided, only load relationships from this
                specific inventory scan (scoped to the pipeline run).
                If None, loads ALL relationships for the tenant (full snapshot).
        """
        import psycopg2
        from psycopg2.extras import RealDictCursor

        conn = psycopg2.connect(self._inventory_conn_str())
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                if scan_run_id:
                    logger.info(f"Loading relationships for scan_run_id={scan_run_id}")
                    cur.execute("""
                        SELECT
                            from_uid, to_uid, relation_type,
                            source_resource_uid, target_resource_uid, relationship_type,
                            relationship_strength, bidirectional,
                            properties
                        FROM inventory_relationships
                        WHERE tenant_id = %s AND scan_run_id = %s
                    """, (tenant_id, scan_run_id))
                else:
                    logger.info("Loading ALL relationships for tenant (no scan_run_id filter)")
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
        scan_run_id: Optional[str] = None,
    ) -> Set[str]:
        """
        Identify internet-reachable resources from two sources:

        1. inventory_relationships: edges of type 'exposes', 'routes_to',
           'allows_traffic', 'internet_connected', or containing 'public'.
        2. check_findings: FAIL findings whose rule_id matches internet
           exposure patterns (public_access, exposed_to_internet, etc.).

        Args:
            tenant_id: Tenant isolation filter.
            scan_run_id: If provided, scope inventory query to this scan.
        """
        import psycopg2
        from psycopg2.extras import RealDictCursor

        reachable: Set[str] = set()

        # ── Source 1: inventory_relationships ──────────────────────────────
        try:
            conn = psycopg2.connect(self._inventory_conn_str())
            try:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    base_query = """
                        SELECT DISTINCT
                            COALESCE(target_resource_uid, to_uid) as target,
                            COALESCE(source_resource_uid, from_uid) as source
                        FROM inventory_relationships
                        WHERE tenant_id = %s
                          AND (
                            COALESCE(relationship_type, relation_type) IN (
                                'exposes', 'routes_to', 'allows_traffic', 'internet_connected'
                            )
                            OR COALESCE(relationship_type, relation_type) LIKE '%%public%%'
                          )
                    """
                    if scan_run_id:
                        base_query += " AND scan_run_id = %s"
                        cur.execute(base_query, (tenant_id, scan_run_id))
                    else:
                        cur.execute(base_query, (tenant_id,))
                    for row in cur.fetchall():
                        # For internet_connected, the FROM side is the exposed resource
                        if row["source"]:
                            reachable.add(row["source"])
                        if row["target"]:
                            reachable.add(row["target"])
            finally:
                conn.close()
        except Exception as e:
            logger.warning(f"Could not query inventory for reachability: {e}")

        inv_count = len(reachable)

        # ── Source 2: check_findings with internet exposure patterns ───────
        try:
            check_host = os.getenv("CHECK_DB_HOST", os.getenv("THREAT_DB_HOST", "localhost"))
            check_port = os.getenv("CHECK_DB_PORT", "5432")
            check_db = os.getenv("CHECK_DB_NAME", "threat_engine_check")
            check_user = os.getenv("CHECK_DB_USER", os.getenv("THREAT_DB_USER", "postgres"))
            check_pwd = os.getenv("CHECK_DB_PASSWORD", os.getenv("THREAT_DB_PASSWORD", ""))
            check_conn_str = f"postgresql://{check_user}:{check_pwd}@{check_host}:{check_port}/{check_db}"

            conn = psycopg2.connect(check_conn_str)
            try:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("""
                        SELECT DISTINCT resource_uid
                        FROM check_findings
                        WHERE tenant_id = %s
                          AND status = 'FAIL'
                          AND resource_uid IS NOT NULL
                          AND (
                            rule_id ILIKE '%%exposed_to_internet%%'
                            OR rule_id ILIKE '%%public_access%%'
                            OR rule_id ILIKE '%%publicly_accessible%%'
                            OR rule_id ILIKE '%%public_ip%%'
                            OR rule_id ILIKE '%%unrestricted%%'
                            OR rule_id ILIKE '%%open_to_world%%'
                            OR rule_id ILIKE '%%0_0_0_0%%'
                            OR rule_id ILIKE '%%internet_facing%%'
                            OR rule_id ILIKE '%%internet_ingress%%'
                            OR rule_id ILIKE '%%not_publicly%%'
                            OR rule_id ILIKE '%%public_read%%'
                            OR rule_id ILIKE '%%public_write%%'
                            OR rule_id ILIKE '%%block_public%%'
                            OR rule_id ILIKE '%%no_public_ip%%'
                            OR rule_id ILIKE '%%ami_public%%'
                          )
                    """, (tenant_id,))
                    for row in cur.fetchall():
                        if row["resource_uid"]:
                            reachable.add(row["resource_uid"])
            finally:
                conn.close()
        except Exception as e:
            logger.warning(f"Could not query check_findings for internet exposure: {e}")

        check_count = len(reachable) - inv_count
        logger.info(f"Internet-reachable resources: {len(reachable)} "
                    f"(inventory={inv_count}, check_findings={check_count})")

        return reachable

    # ── Attack path + asset category loaders ─────────────────────────────

    def _load_attack_path_categories(self) -> Dict[str, Optional[str]]:
        """Load attack_path_category mapping from resource_security_relationship_rules.

        Returns dict: relation_type → category (or None for non-attack edges).
        Falls back to inline _ATTACK_PATH_CATEGORIES if DB read fails.
        """
        import psycopg2
        from psycopg2.extras import RealDictCursor

        try:
            conn = psycopg2.connect(self._inventory_conn_str())
            try:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("""
                        SELECT DISTINCT relation_type, attack_path_category
                        FROM resource_security_relationship_rules
                        WHERE is_active = TRUE
                    """)
                    categories: Dict[str, Optional[str]] = {}
                    for row in cur.fetchall():
                        categories[row["relation_type"]] = row.get("attack_path_category")
                    if categories:
                        # Merge: inline fallback first, then DB overrides
                        merged = dict(_ATTACK_PATH_CATEGORIES)
                        merged.update(categories)
                        logger.info(f"Loaded attack_path_category for {len(categories)} relation types from DB, "
                                    f"merged with {len(_ATTACK_PATH_CATEGORIES)} inline → {len(merged)} total")
                        return merged
            finally:
                conn.close()
        except Exception as e:
            logger.warning(f"Could not load attack_path_categories from DB: {e}")

        logger.info("Using inline attack_path_categories fallback")
        return dict(_ATTACK_PATH_CATEGORIES)

    def _load_asset_categories(self, tenant_id: str) -> Dict[str, str]:
        """Load asset_category for all inventoried resources.

        Joins inventory_findings with resource_inventory_identifier to map
        each resource_uid → asset_category.

        Returns dict: resource_uid → asset_category (only non-None entries).
        """
        import psycopg2
        from psycopg2.extras import RealDictCursor

        categories: Dict[str, str] = {}
        try:
            conn = psycopg2.connect(self._inventory_conn_str())
            try:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("""
                        SELECT f.resource_uid, r.asset_category
                        FROM inventory_findings f
                        JOIN resource_inventory_identifier r
                          ON r.csp = split_part(f.resource_type, '.', 1)
                         AND r.service = split_part(f.resource_type, '.', 1)
                         AND r.canonical_type = split_part(f.resource_type, '.', 2)
                        WHERE f.tenant_id = %s
                          AND r.asset_category IS NOT NULL
                    """, (tenant_id,))
                    for row in cur.fetchall():
                        if row["resource_uid"] and row["asset_category"]:
                            categories[row["resource_uid"]] = row["asset_category"]

                    # Fallback: infer from resource_type if JOIN yielded few results
                    if len(categories) < 10:
                        cur.execute("""
                            SELECT resource_uid, resource_type
                            FROM inventory_findings
                            WHERE tenant_id = %s AND resource_uid IS NOT NULL
                        """, (tenant_id,))
                        for row in cur.fetchall():
                            uid = row["resource_uid"]
                            if uid in categories:
                                continue
                            rt = (row.get("resource_type") or "").lower()
                            cat = _infer_asset_category(rt)
                            if cat:
                                categories[uid] = cat

                logger.info(f"Loaded asset_category for {len(categories)} resources")
            finally:
                conn.close()
        except Exception as e:
            logger.warning(f"Could not load asset_categories: {e}")
        return categories

    # ── Analysis orchestrator ────────────────────────────────────────────

    def analyze_scan(
        self,
        tenant_id: str,
        scan_run_id: str,
    ) -> List[Dict[str, Any]]:
        """
        Analyze all threat_detections for a scan.

        Args:
            tenant_id: Tenant isolation filter.
            scan_run_id: The scan_run_id shared by all engines in this pipeline run.

        Returns a list of analysis result dicts (one per detection) matching
        the threat_analysis table schema.
        """
        logger.info("Starting threat analysis", extra={"extra_fields": {
            "tenant_id": tenant_id,
            "scan_run_id": scan_run_id,
        }})

        # 1. Load detections
        detections = self._load_detections(tenant_id, scan_run_id)
        if not detections:
            logger.info("No detections found for scan")
            return []

        logger.info(f"Loaded {len(detections)} detections for analysis")

        # 1b. All engines share the same scan_run_id — use it directly
        #     to filter inventory relationships to this specific scan.
        inventory_scan_id: Optional[str] = scan_run_id

        # 1c. Load MITRE guidance from mitre_technique_reference table.
        #     Used for: severity_base → impact weights, detection/remediation recs.
        #     Graceful: if DB read fails, falls back to hardcoded weights.
        mitre_guidance = self._load_mitre_guidance()

        # 2. Load relationships & build attack-path-filtered graph
        #    Requires INVENTORY_DB_* env vars. If not configured, we log an
        #    ERROR (not warning) so operators know blast-radius is broken.
        adjacency: Dict[str, List[Dict[str, Any]]] = {}
        asset_categories: Dict[str, str] = {}
        internet_reachable: Set[str] = set()
        inventory_available = False

        try:
            # Load attack_path_category classification from DB
            attack_path_cats = self._load_attack_path_categories()

            relationships = self._load_relationships(tenant_id, scan_run_id)
            # Build adjacency with attack-path filtering
            adjacency = _build_adjacency(relationships, attack_path_cats, attack_only=True)
            inventory_available = True

            total_edges = sum(len(v) for v in adjacency.values())
            logger.info(f"Built attack-path adjacency: {len(adjacency)} nodes, "
                        f"{total_edges} attack-relevant edges "
                        f"(filtered from {len(relationships)} total relationships)")

            # Load asset categories for target scoring
            asset_categories = self._load_asset_categories(tenant_id)
        except EnvironmentError as e:
            logger.error(f"INVENTORY_DB not configured: {e}. "
                         f"Blast-radius will score ZERO for all detections.")
        except Exception as e:
            logger.error(f"Failed to load inventory relationships: {e}. "
                         f"Blast-radius will score ZERO.", exc_info=True)

        # 3. Identify internet-reachable resources
        if inventory_available:
            try:
                internet_reachable = self._load_internet_reachable(
                    tenant_id, scan_run_id
                )
                logger.info(f"Internet-reachable resources: {len(internet_reachable)}")
            except Exception as e:
                logger.error(f"Failed to load reachability data: {e}", exc_info=True)
        else:
            logger.warning("Skipping internet-reachability check — inventory DB not available")

        # 3b. Load threat intelligence correlations
        #     Matches intel entries with detections by MITRE technique overlap.
        #     Used to enrich analysis with external context (IOCs, TTPs, sources).
        intel_by_detection: Dict[str, List[Dict[str, Any]]] = {}
        try:
            from ..storage.threat_intel_writer import correlate_intel_with_threats
            correlations = correlate_intel_with_threats(tenant_id)
            for c in correlations:
                det_id = str(c.get("detection_id", ""))
                if det_id:
                    intel_by_detection.setdefault(det_id, []).append({
                        "intel_id": str(c.get("intel_id", "")),
                        "source": c.get("intel_source", ""),
                        "intel_type": c.get("intel_type", ""),
                        "severity": c.get("intel_severity", ""),
                    })
            if correlations:
                logger.info(f"Threat intel correlations: {len(correlations)} matches "
                            f"across {len(intel_by_detection)} detections")
        except Exception as e:
            logger.warning(f"Threat intelligence correlation skipped: {e}")

        # 4. Analyze each detection
        analysis_results: List[Dict[str, Any]] = []
        now = datetime.now(timezone.utc)

        for det in detections:
            detection_id = str(det["detection_id"])
            resource_uid = det.get("resource_uid") or ""
            severity = (det.get("severity") or "medium").lower()
            mitre_techniques = det.get("mitre_techniques") or []
            mitre_tactics = det.get("mitre_tactics") or []

            # Blast radius (BFS — only attack-relevant edges)
            blast = compute_blast_radius(resource_uid, adjacency)

            # Attack paths (DFS — full path enumeration to valuable targets)
            is_reachable = resource_uid in internet_reachable
            attack_paths = _find_attack_paths(
                adjacency, resource_uid, asset_categories,
                internet_reachable, max_depth=5, max_paths=20,
            )

            # MITRE impact (uses DB severity_base when available)
            mitre_impact = compute_mitre_impact_score(mitre_techniques, mitre_guidance)

            # Risk score
            risk_score = compute_risk_score(
                severity, blast["reachable_count"], mitre_impact, is_reachable
            )

            # Verdict
            verdict = determine_verdict(risk_score)

            # Attack chain (from DFS paths, not raw BFS edges)
            attack_chain = build_attack_chain(
                attack_paths, resource_uid, mitre_techniques
            )

            # Recommendations (enriched with DB guidance, CSP-aware)
            detection_provider = (det.get("provider") or "aws").lower()
            recommendations = build_recommendations(
                severity, blast["reachable_count"], mitre_techniques,
                is_reachable, verdict, mitre_guidance, detection_provider
            )

            # Related threats (same resource_uid or overlapping blast radius)
            related = []
            for other in detections:
                if str(other["detection_id"]) == detection_id:
                    continue
                other_uid = other.get("resource_uid") or ""
                if other_uid == resource_uid or other_uid in blast.get("reachable_resources", []):
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

            # Summarize attack paths
            chain_types = list({p["chain_type"] for p in attack_paths})
            critical_paths = [p for p in attack_paths if p.get("path_score", 0) >= 70]

            # Build analysis_results JSONB
            analysis_result = {
                "blast_radius": {
                    "reachable_count": blast["reachable_count"],
                    "reachable_resources": blast["reachable_resources"][:20],
                    "path_edges": blast.get("path_edges", [])[:30],
                    "depth_distribution": blast["depth_distribution"],
                },
                "attack_paths": attack_paths[:10],  # Top 10 paths by score
                "attack_paths_summary": {
                    "total_paths": len(attack_paths),
                    "critical_paths": len(critical_paths),
                    "chain_types": chain_types,
                    "deepest_path": max((p["depth"] for p in attack_paths), default=0),
                    "highest_score": attack_paths[0]["path_score"] if attack_paths else 0,
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
                "threat_intel": intel_by_detection.get(detection_id, []),
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
