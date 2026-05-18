"""Match attack paths against threat_v1 incidents to compute confidence levels."""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, TypedDict

logger = logging.getLogger(__name__)


class MatchResult(TypedDict):
    confidence: str   # 'confirmed' | 'likely' | 'speculative'
    incident: Optional[Any]  # ThreatIncidentRow or None


def overlap_ratio(path_nodes: List[str], incident_resources: List[str]) -> float:
    """Fraction of path nodes covered by incident resources.

    Args:
        path_nodes: Resource UIDs that form the attack path.
        incident_resources: Resource UIDs recorded in the threat incident.

    Returns:
        Float in [0.0, 1.0] representing coverage of path nodes.
    """
    if not path_nodes:
        return 0.0
    path_set = set(path_nodes)
    match_count = sum(1 for r in incident_resources if r in path_set)
    return match_count / len(path_nodes)


def compute_confidence(
    path_node_uids: List[str],
    incidents: List[Any],
) -> MatchResult:
    """Determine confidence level for one attack path.

    Confidence tiers:
      - confirmed: T3 incident overlaps >= 70% of path nodes.
      - likely:    T3 incident overlaps >= 50%, OR T2 incident overlaps >= 50%.
      - speculative: no meaningful overlap found.

    Args:
        path_node_uids: Ordered list of resource UIDs in the path.
        incidents: T2/T3 ThreatIncidentRows (pre-loaded for the tenant/scan).

    Returns:
        MatchResult with confidence label and best matching incident (or None).
    """
    if not incidents:
        return MatchResult(confidence="speculative", incident=None)

    t3_incidents = [i for i in incidents if i["tier"] == 3]
    t2_incidents = [i for i in incidents if i["tier"] == 2]

    best_t3 = max(
        t3_incidents,
        key=lambda i: overlap_ratio(path_node_uids, i["involved_resources"]),
        default=None,
    )
    best_t2 = max(
        t2_incidents,
        key=lambda i: overlap_ratio(path_node_uids, i["involved_resources"]),
        default=None,
    )

    if best_t3 and overlap_ratio(path_node_uids, best_t3["involved_resources"]) >= 0.70:
        return MatchResult(confidence="confirmed", incident=best_t3)
    if best_t3 and overlap_ratio(path_node_uids, best_t3["involved_resources"]) >= 0.50:
        return MatchResult(confidence="likely", incident=best_t3)
    if best_t2 and overlap_ratio(path_node_uids, best_t2["involved_resources"]) >= 0.50:
        return MatchResult(confidence="likely", incident=best_t2)
    return MatchResult(confidence="speculative", incident=None)


def build_technique_chain(incident: Any, path_node_uids: List[str]) -> List[Dict]:
    """Build ordered technique chain from incident for this path.

    Returns techniques whose resource_uid overlaps with path nodes.
    Falls back to all techniques if none match (still useful context).

    Args:
        incident: ThreatIncidentRow with technique_sequence field.
        path_node_uids: Resource UIDs that form the attack path.

    Returns:
        List of technique dicts (technique_id, tactic, description, resource_uid).
    """
    if not incident:
        return []
    ts = incident.get("technique_sequence") or []
    path_set = set(path_node_uids)
    relevant = [t for t in ts if t.get("resource_uid") in path_set]
    return relevant if relevant else ts


def build_attack_story(
    incident: Any,
    path_node_uids: List[str],
    confidence: str,
) -> Optional[str]:
    """Build a human-readable attack story from matched incident.

    Returns None for speculative confidence — no story is more accurate
    than an invented one.

    Args:
        incident: ThreatIncidentRow or None.
        path_node_uids: Resource UIDs that form the attack path.
        confidence: 'confirmed' | 'likely' | 'speculative'.

    Returns:
        Human-readable narrative string, or None if speculative/no incident.
    """
    if confidence == "speculative" or not incident:
        return None

    pattern_name = incident.get("pattern_name") or "Unknown Attack Pattern"
    hop_count = len(path_node_uids)
    ts = incident.get("technique_sequence") or []
    technique_names = [t.get("technique_id", "") for t in ts[:3]]
    tech_str = " → ".join(technique_names) if technique_names else "unknown techniques"

    return (
        f"[{confidence.upper()}] {pattern_name}: {hop_count}-hop attack path detected. "
        f"MITRE chain: {tech_str}. "
        f"Path traverses {hop_count} resources from external entry point to crown jewel. "
        f"Confidence based on {incident.get('tier', 2)}-tier pattern match."
    )
