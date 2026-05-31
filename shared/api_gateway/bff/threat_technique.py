"""BFF view: GET /views/threats/technique/{technique_id}

Proxies to threat engine GET /api/v1/techniques/{technique_id} and normalises
the snake_case DB shape into the camelCase shape expected by TechniqueDetailModal.

Response shape consumed by frontend:
    techniqueId, techniqueName, tactics[], url,
    affectedResources, detectionCount,
    d3fendMappings[]{id, label}, complianceControls{}
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from ._auth import resolve_tenant_id
from ._shared import ENGINE_URLS, ENGINE_TIMEOUTS, DEFAULT_TIMEOUT

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])

_TECHNIQUE_ID_RE = re.compile(r"^T[0-9]{4}(\.[0-9]{3,4})?$")

_EMPTY_RESPONSE = {
    "techniqueId": None,
    "techniqueName": "Unknown",
    "tactics": [],
    "url": None,
    "affectedResources": 0,
    "detectionCount": 0,
    "d3fendMappings": [],
    "complianceControls": {},
    "available": False,
}


def _normalise(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Map threat engine snake_case → UI camelCase."""
    d3fend: List[Dict[str, str]] = []
    for m in (raw.get("d3fend_mappings") or []):
        if isinstance(m, dict):
            d3fend.append({"id": m.get("id", ""), "label": m.get("name") or m.get("label", "")})

    return {
        "techniqueId":       raw.get("technique_id"),
        "techniqueName":     raw.get("name") or raw.get("technique_name", ""),
        "tactics":           raw.get("tactic_ids") or raw.get("tactics") or [],
        "url":               raw.get("url"),
        "affectedResources": int(raw.get("affected_count") or 0),
        "detectionCount":    int(raw.get("affected_count_with_subs") or 0),
        "description":       raw.get("description"),
        "platforms":         raw.get("platforms") or [],
        "mitigations":       raw.get("mitigations") or [],
        "d3fendMappings":    d3fend,
        "complianceControls": {},
        "available":         True,
    }


@router.get("/threats/technique/{technique_id}")
async def view_technique_detail(
    request: Request,
    technique_id: str,
) -> JSONResponse:
    """Return MITRE technique detail for TechniqueDetailModal.

    Forwards the X-Auth-Context header to the threat engine so tenant-scoped
    affected counts are returned without leaking cross-tenant data.
    """
    if not _TECHNIQUE_ID_RE.match(technique_id):
        return JSONResponse(status_code=200, content={**_EMPTY_RESPONSE, "reason": "invalid_technique_id"})

    # TODO: decommission after engine-threat teardown — no attack-path equivalent.
    threat_base = ENGINE_URLS.get("threat", "")
    url = f"{threat_base}/api/v1/techniques/{technique_id}"

    auth_ctx = request.headers.get("X-Auth-Context")
    fwd_headers: Dict[str, str] = {}
    if auth_ctx:
        fwd_headers["X-Auth-Context"] = auth_ctx

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                url, headers=fwd_headers,
                timeout=ENGINE_TIMEOUTS.get("threat", DEFAULT_TIMEOUT),
            )
    except Exception as exc:
        logger.warning("technique detail call failed for %s: %s", technique_id, exc)
        return JSONResponse(status_code=200, content={**_EMPTY_RESPONSE, "reason": "engine_unavailable"})

    if resp.status_code == 404:
        return JSONResponse(status_code=200, content={**_EMPTY_RESPONSE, "reason": "not_found"})
    if resp.status_code == 410:
        body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
        detail = body.get("detail", {}) if isinstance(body, dict) else {}
        return JSONResponse(status_code=200, content={
            **_EMPTY_RESPONSE,
            "techniqueId": technique_id,
            "reason": "deprecated_or_revoked",
            "flag": detail.get("flag") if isinstance(detail, dict) else None,
        })
    if resp.status_code != 200:
        logger.warning("technique detail %s returned %s", technique_id, resp.status_code)
        return JSONResponse(status_code=200, content={**_EMPTY_RESPONSE, "reason": "engine_error"})

    try:
        raw = resp.json()
    except Exception:
        return JSONResponse(status_code=200, content={**_EMPTY_RESPONSE, "reason": "parse_error"})

    return JSONResponse(status_code=200, content=_normalise(raw))
