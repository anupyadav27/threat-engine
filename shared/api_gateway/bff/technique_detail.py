"""BFF view: GET /api/v1/views/threats/technique/{technique_id}

Returns MITRE technique metadata enriched with tenant-scoped impact counts
and D3FEND countermeasure mappings.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

import psycopg2
import psycopg2.extras
from fastapi import APIRouter, HTTPException, Request

from ._auth import _parse_auth_context, resolve_tenant_id

logger = logging.getLogger("api-gateway.bff.technique_detail")

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


# ── Static D3FEND countermeasure map ─────────────────────────────────────────

D3FEND_MAP: Dict[str, List[str]] = {
    "T1190": ["D3-NTF (Network Traffic Filtering)", "D3-WSAF (Web Session Activity Analysis)"],
    "T1078": ["D3-OAA (One-time Password)", "D3-MFA (Multi-factor Authentication)"],
    "T1098": ["D3-AEPP (Auth Event Thresholding)", "D3-ANET (Authorization Event Thresholding)"],
    "T1530": ["D3-EAL (Executable Allowlisting)", "D3-PLM (Platform Monitoring)"],
    "T1537": ["D3-NTF (Network Traffic Filtering)", "D3-OAT (Outbound Traffic Filtering)"],
    "T1485": ["D3-BKUP (Backup Data)"],
    "T1562": ["D3-DLIC (Driver Load Integrity Checking)", "D3-PLA (Platform Monitoring Log Analysis)"],
    "T1119": ["D3-DCOM (Data Component Monitoring)"],
    "T1040": ["D3-NTA (Network Traffic Analysis)"],
    "T1578": ["D3-CCE (Cloud Configuration Enforcement)"],
}


def _parse_d3fend_entry(entry: str) -> Dict[str, str]:
    if " (" in entry and entry.endswith(")"):
        d3_id, rest = entry.split(" (", 1)
        label = rest[:-1]
    else:
        d3_id = entry
        label = entry
    return {"id": d3_id.strip(), "label": label.strip()}


# ── DB connection ─────────────────────────────────────────────────────────────

def _get_threat_conn():
    return psycopg2.connect(
        host=os.getenv("THREAT_DB_HOST", "localhost"),
        port=int(os.getenv("THREAT_DB_PORT", "5432")),
        dbname=os.getenv("THREAT_DB_NAME", "threat_engine_threat"),
        user=os.getenv("THREAT_DB_USER", "threat_user"),
        password=os.getenv("THREAT_DB_PASSWORD", "threat_password"),
    )


# ── Endpoint ──────────────────────────────────────────────────────────────────

@router.get("/threats/technique/{technique_id}")
async def view_technique_detail(request: Request, technique_id: str) -> Dict[str, Any]:
    """BFF for TechniqueDetailModal — technique metadata + tenant impact counts."""
    # Auth — raises 401 if unauthenticated
    ctx = _parse_auth_context(request)
    if ctx is None:
        raise HTTPException(status_code=401, detail="Authentication required")

    if not ctx.has_permission("threat:read"):
        raise HTTPException(status_code=403, detail="threat:read permission required")

    # tenant_id ONLY from AuthContext — never from query param
    tenant_id = resolve_tenant_id(request)

    conn = _get_threat_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            # Query 1: technique metadata
            cur.execute(
                """
                SELECT technique_id, technique_name, tactics,
                       severity_base, remediation_guidance
                FROM mitre_technique_reference
                WHERE technique_id = %s
                """,
                (technique_id,),
            )
            tech_row = cur.fetchone()
            if tech_row is None:
                raise HTTPException(status_code=404, detail="Technique not found")

            # Query 2: tenant-scoped affected counts (handles dual JSONB form)
            cur.execute(
                """
                SELECT
                    COUNT(DISTINCT resource_uid) AS affected_resources,
                    COUNT(*)                     AS detection_count
                FROM threat_detections
                WHERE tenant_id = %s
                  AND (
                    mitre_techniques @> jsonb_build_array(%s)
                    OR mitre_techniques @> jsonb_build_array(jsonb_build_object('id', %s))
                  )
                """,
                (tenant_id, technique_id, technique_id),
            )
            counts_row = cur.fetchone()
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("technique_detail DB error for %s: %s", technique_id, exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal error fetching technique detail")
    finally:
        conn.close()

    tech = dict(tech_row)

    # tactics is already a list (psycopg2 deserializes JSONB) — never json.loads()
    tactics: List[str] = tech.get("tactics") or []

    # complianceControls from remediation_guidance JSONB
    remediation_guidance = tech.get("remediation_guidance") or {}
    compliance_controls: Any = {}
    if isinstance(remediation_guidance, dict):
        compliance_controls = remediation_guidance.get("compliance_controls", {})

    # D3FEND mappings
    d3fend_entries = D3FEND_MAP.get(technique_id, [])
    d3fend_mappings = [_parse_d3fend_entry(e) for e in d3fend_entries]

    # MITRE ATT&CK URL — handles sub-techniques (T1078.001 → /techniques/T1078/001/)
    mitre_url = f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"

    counts = dict(counts_row) if counts_row else {}

    return {
        "techniqueId": tech["technique_id"],
        "techniqueName": tech.get("technique_name") or technique_id,
        "tactics": tactics,
        "severityBase": tech.get("severity_base"),
        "url": mitre_url,
        "affectedResources": int(counts.get("affected_resources") or 0),
        "detectionCount": int(counts.get("detection_count") or 0),
        "d3fendMappings": d3fend_mappings,
        "complianceControls": compliance_controls,
    }
