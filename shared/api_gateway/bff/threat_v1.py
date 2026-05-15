"""
BFF view: /threat_v1 page.

Threat Engine v1 — 3-tier pattern-based threat detection.
Provides incident list, summary KPIs, and scan status for the Threat Center UI.

Data shape:
  kpiGroups: [{id: 'threats', title: 'Threat Summary', kpis: [...]}]
  incidents: {items: [...], total: N, page: N, page_size: N}
  scan_status: last build + execution status
  top_patterns: top 5 fired patterns (by incident count)
  severity_distribution: {critical, high, medium, low}

Authentication: all calls forwarded with X-Auth-Context header (tenant isolation).
CDR evidence fields stripped at this layer — detail view goes directly to
engine-threat-v1 via gateway.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, Query, Request

from ._auth import resolve_tenant_id
from ._cache import TTL_CIEM, cache_key, cached_view
from ._shared import fetch_many, safe_get

logger = logging.getLogger("api-gateway.bff.threat_v1")

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


@router.get("/threat_v1")
async def view_threat_v1(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    severity: Optional[str] = Query(default=None),
    incident_class: Optional[str] = Query(default=None),
    tier: Optional[int] = Query(default=None),
    status: Optional[str] = Query(default="open"),
    scan_run_id: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    """BFF aggregation for Threat Center v1 UI page."""
    tenant_id = resolve_tenant_id(request)
    auth_header = request.headers.get("X-Auth-Context") or getattr(
        request.state, "auth_header", None
    )
    # Patch engine_tenant_id into the forwarded header so the engine dev-mode
    # fallback receives the correct tenant even when the session has no active
    # tenant selection (platform_admin scenario).
    fwd_headers: Dict[str, str] = {}
    if auth_header:
        try:
            ctx_dict = json.loads(auth_header)
            # Always overwrite engine_tenant_id — even with None — so the stale
            # login-time default in scope_cache doesn't leak to the engine.
            ctx_dict["engine_tenant_id"] = tenant_id
            auth_header = json.dumps(ctx_dict)
        except Exception:
            pass
        fwd_headers["X-Auth-Context"] = auth_header

    ck = cache_key(
        "threat_v1", tenant_id,
        severity or "", incident_class or "", str(tier or ""), status or "",
        str(page), str(page_size),
    )
    cached = cached_view(ck)
    if cached:
        return cached

    # Build query params for incidents
    inc_params: Dict[str, Any] = {"page": page, "page_size": page_size}
    if severity:
        inc_params["severity"] = severity
    if incident_class:
        inc_params["incident_class"] = incident_class
    if tier is not None:
        inc_params["tier"] = tier
    if status:
        inc_params["status"] = status

    # Build scan status params
    scan_params: Dict[str, Any] = {}
    scan_path = f"/api/v1/scan/status/{scan_run_id}" if scan_run_id else None

    # KPI aggregate fetch — unfiltered (all statuses = open) to get accurate
    # global counts that don't change with the user's filter selection.
    kpi_params: Dict[str, Any] = {"page": 1, "page_size": 200, "status": status or "open"}

    # Fetch in parallel: [incidents_page, kpi_all, optional_scan_status]
    requests_list = [
        ("threat_v1", "/api/v1/incidents", inc_params),
        ("threat_v1", "/api/v1/incidents", kpi_params),
    ]
    if scan_path:
        requests_list.append(("threat_v1", scan_path, scan_params))

    results = await fetch_many(requests_list, auth_headers=fwd_headers)

    incidents_data = results[0] or {"items": [], "total": 0, "page": page, "page_size": page_size}
    kpi_data = results[1] or incidents_data  # fallback to paginated data if aggregate fails
    scan_status = results[2] if scan_path and len(results) > 2 else {}
    scan_status = scan_status or {}

    kpi_groups = _build_kpi_groups(kpi_data, scan_status)
    severity_dist = _severity_distribution(kpi_data)
    tier_dist = _tier_distribution(kpi_data)
    top_patterns = _top_patterns(kpi_data)

    result = {
        "kpiGroups": kpi_groups,
        "incidents": incidents_data,
        "scan_status": scan_status,
        "severity_distribution": severity_dist,
        "tier_distribution": tier_dist,
        "top_patterns": top_patterns,
    }

    cached_view(ck, result, ttl=TTL_CIEM)
    return result


def _build_kpi_groups(
    incidents_data: Dict[str, Any],
    scan_status: Dict[str, Any],
) -> list:
    items = incidents_data.get("items", [])
    total = incidents_data.get("total", 0)

    active_count = sum(1 for i in items if i.get("incident_class") == "active")
    suspicious_count = sum(1 for i in items if i.get("incident_class") == "suspicious")
    critical_count = sum(1 for i in items if i.get("severity") == "critical")
    tier3_count = sum(1 for i in items if i.get("tier") == 3)

    return [
        {
            "id": "threats",
            "title": "Threat Summary",
            "kpis": [
                {"id": "total_incidents", "label": "Total Incidents", "value": total, "trend": None},
                {"id": "active_incidents", "label": "Active (CDR Confirmed)", "value": active_count, "severity": "critical"},
                {"id": "suspicious_incidents", "label": "Suspicious", "value": suspicious_count, "severity": "high"},
                {"id": "critical_severity", "label": "Critical Severity", "value": critical_count, "severity": "critical"},
                {"id": "full_path_chains", "label": "Full Attack Chains (Tier 3)", "value": tier3_count, "severity": "high"},
                {"id": "crown_jewels_at_risk", "label": "Crown Jewels at Risk", "value": scan_status.get("crown_jewel_count", 0)},
            ],
        }
    ]


def _tier_distribution(incidents_data: Dict[str, Any]) -> Dict[int, int]:
    items = incidents_data.get("items", [])
    dist: Dict[int, int] = {1: 0, 2: 0, 3: 0}
    for item in items:
        t = item.get("tier")
        if t in dist:
            dist[t] += 1
    return dist


def _severity_distribution(incidents_data: Dict[str, Any]) -> Dict[str, int]:
    items = incidents_data.get("items", [])
    dist = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for item in items:
        sev = item.get("severity", "low")
        if sev in dist:
            dist[sev] += 1
    return dist


def _top_patterns(incidents_data: Dict[str, Any]) -> list:
    from collections import Counter
    items = incidents_data.get("items", [])
    counts = Counter(i.get("pattern_id", "") for i in items if i.get("pattern_id"))
    return [
        {"pattern_id": pid, "incident_count": count}
        for pid, count in counts.most_common(5)
    ]
