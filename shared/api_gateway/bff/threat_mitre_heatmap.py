"""BFF view: /api/v1/views/threat-mitre-heatmap (MITRE ATT&CK Heatmap page).

Reshapes the threat engine's mitre_matrix into a tactic-grouped heatmap
payload that the frontend Attack Map page consumes directly.

Endpoint:
    GET /api/v1/views/threat-mitre-heatmap
    Query params:
        tenant_id   (required)
        scan_run_id (optional, default "latest")
        provider    (optional)
        account     (optional)
        region      (optional)

Response shape:
    {
        "summary": {
            "tactics_covered":    int,   -- how many of the 14 canonical tactics have hits
            "techniques_detected": int,   -- total distinct technique IDs found
            "total_findings":     int,   -- sum of detection counts across all techniques
            "critical_count":     int,
            "high_count":         int,
            "scan_run_id":        str
        },
        "tactics": [
            {
                "name":        str,              -- canonical tactic name
                "short":       str,              -- abbreviated label for tight UI
                "order":       int,              -- 1-14 canonical order
                "total_count": int,              -- sum of detection counts for this tactic
                "severity":    str,              -- worst severity across techniques
                "techniques":  [
                    {
                        "id":       str,   -- e.g. "T1078"
                        "name":     str,   -- human name from mitre_technique_reference
                        "count":    int,   -- detection_count
                        "severity": str    -- severity_base or derived
                    }
                ]
            }
        ]
    }
"""

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query, Request

from ._auth import resolve_tenant_id
from ._shared import fetch_many, safe_get, THREAT_URL
from ._cache import cache_key, cached_view, auth_level_from_header

logger = logging.getLogger("api-gateway.bff")

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])

# ── Canonical 14 ATT&CK for Cloud tactics (ordered) ──────────────────────────

_TACTICS: List[Dict[str, Any]] = [
    {"order": 1,  "name": "Reconnaissance",       "short": "Recon"},
    {"order": 2,  "name": "Resource Development",  "short": "Res Dev"},
    {"order": 3,  "name": "Initial Access",        "short": "Init Access"},
    {"order": 4,  "name": "Execution",             "short": "Execution"},
    {"order": 5,  "name": "Persistence",           "short": "Persistence"},
    {"order": 6,  "name": "Privilege Escalation",  "short": "Priv Esc"},
    {"order": 7,  "name": "Defense Evasion",       "short": "Def Evasion"},
    {"order": 8,  "name": "Credential Access",     "short": "Cred Access"},
    {"order": 9,  "name": "Discovery",             "short": "Discovery"},
    {"order": 10, "name": "Lateral Movement",      "short": "Lat Movement"},
    {"order": 11, "name": "Collection",            "short": "Collection"},
    {"order": 12, "name": "Exfiltration",          "short": "Exfiltration"},
    {"order": 13, "name": "Impact",                "short": "Impact"},
    {"order": 14, "name": "Command and Control",   "short": "C2"},
]

_TACTIC_NAME_SET = {t["name"].lower() for t in _TACTICS}

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "": 5}


def _worst_severity(severities: List[str]) -> str:
    """Return the worst (highest priority) severity from a list."""
    if not severities:
        return "medium"
    return min(severities, key=lambda s: _SEV_ORDER.get(s.lower(), 5))


def _build_heatmap(mitre_matrix: List[dict], scan_run_id: str) -> dict:
    """Reshape raw mitre_matrix list into tactic-grouped heatmap payload."""

    # Index techniques by tactic
    tactic_buckets: Dict[str, List[dict]] = {t["name"].lower(): [] for t in _TACTICS}

    for entry in mitre_matrix:
        technique_id   = entry.get("technique_id") or ""
        technique_name = entry.get("technique_name") or technique_id
        count          = int(entry.get("detection_count") or 0)
        severity       = (entry.get("severity_base") or "medium").lower()

        raw_tactics = entry.get("tactics") or []
        if isinstance(raw_tactics, str):
            raw_tactics = [raw_tactics]

        matched_any = False
        for tname in raw_tactics:
            key = tname.lower()
            if key in tactic_buckets:
                tactic_buckets[key].append({
                    "id":       technique_id,
                    "name":     technique_name,
                    "count":    count,
                    "severity": severity,
                })
                matched_any = True

        if not matched_any and technique_id:
            tactic_buckets["defense evasion"].append({
                "id":       technique_id,
                "name":     technique_name,
                "count":    count,
                "severity": severity,
            })

    tactics_out = []
    for tdef in _TACTICS:
        key        = tdef["name"].lower()
        techniques = tactic_buckets.get(key, [])
        techniques.sort(key=lambda t: (-t["count"], t["id"]))
        total      = sum(t["count"] for t in techniques)
        severity   = _worst_severity([t["severity"] for t in techniques]) if techniques else ""

        tactics_out.append({
            "name":        tdef["name"],
            "short":       tdef["short"],
            "order":       tdef["order"],
            "total_count": total,
            "severity":    severity,
            "techniques":  techniques,
        })

    tactics_covered    = sum(1 for t in tactics_out if t["total_count"] > 0)
    techniques_all     = [tech for t in tactics_out for tech in t["techniques"]]
    unique_technique_ids = {t["id"] for t in techniques_all}
    total_findings     = sum(t["count"] for t in techniques_all)
    critical_count     = sum(t["count"] for t in techniques_all if t["severity"] == "critical")
    high_count         = sum(t["count"] for t in techniques_all if t["severity"] == "high")

    return {
        "summary": {
            "tactics_covered":     tactics_covered,
            "techniques_detected": len(unique_technique_ids),
            "total_findings":      total_findings,
            "critical_count":      critical_count,
            "high_count":          high_count,
            "scan_run_id":         scan_run_id,
        },
        "tactics": tactics_out,
    }


@router.get("/threat-mitre-heatmap")
async def get_threat_mitre_heatmap(
    request: Request,
    scan_run_id: Optional[str] = Query(None, alias="scan_run_id"),
    provider: Optional[str]  = Query(None),
    account: Optional[str]   = Query(None),
    region: Optional[str]    = Query(None),
) -> dict:
    """Return MITRE ATT&CK heatmap data for the Attack Map page."""
    resolved_tenant = resolve_tenant_id(request)
    auth_header     = request.headers.get("X-Auth-Context", "")
    role_level      = auth_level_from_header(auth_header)

    ck = cache_key("threat-mitre-heatmap", resolved_tenant, role_level,
                   scan_run_id or "latest", provider or "", account or "", region or "")
    cached = cached_view(ck)
    if cached is not None:
        return cached

    params: Dict[str, str] = {"tenant_id": resolved_tenant}
    if scan_run_id:
        params["scan_run_id"] = scan_run_id
    if provider:
        params["provider"] = provider
    if account:
        params["account"] = account
    if region:
        params["region"] = region

    (raw,) = await fetch_many(
        [("threat", "/api/v1/threat/ui-data", params)],
        auth_headers={"X-Auth-Context": auth_header} if auth_header else None,
    )

    mitre_matrix  = safe_get(raw, "mitre_matrix") or []
    used_scan_run = safe_get(raw, "scan_run_id") or scan_run_id or ""

    result = _build_heatmap(mitre_matrix, used_scan_run)

    cached_view(ck, result, ttl=300)
    return result
