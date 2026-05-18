"""Load T2/T3 threat pattern incidents for enrichment matching."""
from __future__ import annotations

import logging
from typing import Any, Dict, List, TypedDict

logger = logging.getLogger(__name__)


class ThreatIncidentRow(TypedDict):
    incident_id: str
    pattern_id: str
    pattern_name: str
    tier: int
    involved_resources: List[str]     # ordered list of resource UIDs
    technique_sequence: List[Dict]    # [{technique_id, tactic, description, resource_uid}]
    severity: str


def load_threat_incidents(
    threat_conn: Any,
    tenant_id: str,
    scan_run_id: str,
) -> List[ThreatIncidentRow]:
    """Load T2+T3 incidents from threat_scenario_incidents.

    Only T2/T3 loaded for full matching; T1 incidents checked separately per-node.
    Returns empty list if table empty or scan has no incidents.

    Args:
        threat_conn: psycopg2 connection to threat_engine_threat DB.
        tenant_id: Tenant scope — all queries filtered by this value.
        scan_run_id: Pipeline run UUID — matches incidents to this scan.

    Returns:
        List of ThreatIncidentRow dicts, ordered by tier desc then severity desc.
    """
    from psycopg2.extras import RealDictCursor

    try:
        with threat_conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT incident_id::text, pattern_id, pattern_name, tier,
                       involved_resources, technique_sequence, severity
                FROM threat_scenario_incidents
                WHERE tenant_id = %s AND scan_run_id = %s
                  AND tier >= 2
                ORDER BY tier DESC, severity DESC
                """,
                (tenant_id, scan_run_id),
            )
            rows = cur.fetchall()
    except Exception as exc:
        logger.warning("threat_incidents_loader: query failed — %s", exc)
        return []

    incidents: List[ThreatIncidentRow] = []
    for row in rows:
        ir = row.get("involved_resources") or []
        ts = row.get("technique_sequence") or []
        # JSONB auto-deserialized by psycopg2 — no json.loads needed.
        # Guard against edge case where column arrives as raw string.
        if isinstance(ir, str):
            import json
            ir = json.loads(ir)
        if isinstance(ts, str):
            import json
            ts = json.loads(ts)
        incidents.append(
            ThreatIncidentRow(
                incident_id=str(row["incident_id"]),
                pattern_id=row.get("pattern_id") or "",
                pattern_name=row.get("pattern_name") or "",
                tier=int(row.get("tier") or 2),
                involved_resources=list(ir),
                technique_sequence=list(ts),
                severity=row.get("severity") or "medium",
            )
        )

    logger.info(
        "threat_incidents_loader: loaded %d T2/T3 incidents for scan %s",
        len(incidents),
        scan_run_id,
    )
    return incidents
