"""Update attack_paths rows with threat pattern enrichment data."""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List

from ..core.threat_enricher import build_attack_story, build_technique_chain, compute_confidence

logger = logging.getLogger(__name__)

_UPDATE_SQL = """
UPDATE attack_paths
SET confidence_level       = %s,
    attack_name            = %s,
    attack_technique_chain = %s,
    threat_pattern_ids     = %s,
    attack_story           = %s
WHERE path_id = %s
  AND tenant_id = %s
"""


def enrich_paths(
    attack_path_conn: Any,
    paths: List[Any],
    incidents: List[Any],
    tenant_id: str,
) -> Dict[str, int]:
    """Match paths against incidents and write enrichment columns.

    Each path is matched against the pre-loaded T2/T3 incidents.
    confidence_level, attack_name, attack_technique_chain, threat_pattern_ids,
    and attack_story are written to attack_paths in a single batch commit.

    Does NOT log individual incident rows — technique_sequence may contain
    sensitive pattern detail.

    Args:
        attack_path_conn: psycopg2 connection to threat_engine_attack_path DB.
        paths: List of path objects with .path_id and .node_uids attributes.
        incidents: T2/T3 ThreatIncidentRow list (may be empty).
        tenant_id: Tenant scope for the UPDATE WHERE clause.

    Returns:
        Dict with confirmed/likely/speculative counts.
    """
    counts: Dict[str, int] = {"confirmed": 0, "likely": 0, "speculative": 0}
    cur = attack_path_conn.cursor()

    for path in paths:
        node_uids: List[str] = getattr(path, "node_uids", []) or []
        match = compute_confidence(node_uids, incidents)
        confidence = match["confidence"]
        incident = match["incident"]

        attack_name: Any = incident.get("pattern_name") if incident else None
        tech_chain = build_technique_chain(incident, node_uids) if incident else []
        pattern_ids = [str(incident["incident_id"])] if incident else []
        story = build_attack_story(incident, node_uids, confidence)

        cur.execute(
            _UPDATE_SQL,
            (
                confidence,
                attack_name,
                json.dumps(tech_chain) if tech_chain else None,
                json.dumps(pattern_ids) if pattern_ids else None,
                story,
                str(path.path_id),
                tenant_id,
            ),
        )
        counts[confidence] = counts.get(confidence, 0) + 1

    attack_path_conn.commit()
    logger.info(
        "path_enricher: enriched %d paths — confirmed=%d likely=%d speculative=%d",
        len(paths),
        counts["confirmed"],
        counts["likely"],
        counts["speculative"],
    )
    return counts
