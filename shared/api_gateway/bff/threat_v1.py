"""
BFF view: /threat_v1 page.

Reads from engine-attack-path (replaced engine-threat-v1 — all threat detection
patterns and crown jewel classification live in the attack-path engine now).

Data shape:
  kpiGroups: [{id: 'threats', title: 'Threat Summary', kpis: [...]}]
  incidents: {items: [...], total: N, page: N, page_size: N}
  scan_status: last build + execution status
  severity_distribution: {critical, high, medium, low}
  confidence_distribution: {confirmed, likely, speculative}
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
    """BFF aggregation for Threat Center v1 UI page — backed by engine-attack-path."""
    tenant_id = resolve_tenant_id(request)
    auth_header = request.headers.get("X-Auth-Context") or getattr(
        request.state, "auth_header", None
    )
    fwd_headers: Dict[str, str] = {}
    if auth_header:
        try:
            ctx_dict = json.loads(auth_header)
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

    # Map incident_class filter → confidence_level for attack-path
    confidence_filter: Optional[str] = None
    if incident_class == "active":
        confidence_filter = "confirmed"
    elif incident_class == "suspicious":
        confidence_filter = "likely"

    inc_params: Dict[str, Any] = {
        "page": page,
        "page_size": page_size,
        "representative_only": False,
    }
    if severity:
        inc_params["severity"] = severity
    if confidence_filter:
        inc_params["confidence_level"] = confidence_filter

    kpi_params: Dict[str, Any] = {"page": 1, "page_size": 200, "representative_only": False}

    requests_list = [
        ("attack_path", "/api/v1/attack-paths", inc_params),
        ("attack_path", "/api/v1/attack-paths", kpi_params),
    ]

    results = await fetch_many(requests_list, auth_headers=fwd_headers)

    raw_page = results[0] or {"items": [], "total": 0}
    raw_kpi = results[1] or raw_page

    # Reshape attack-path items to incident-like objects for UI compatibility
    incidents_items = [_path_to_incident(p) for p in raw_page.get("items", [])]
    incidents_data = {
        "items": incidents_items,
        "total": raw_page.get("total", len(incidents_items)),
        "page": page,
        "page_size": page_size,
    }

    kpi_items = [_path_to_incident(p) for p in raw_kpi.get("items", [])]
    kpi_data = {"items": kpi_items, "total": raw_kpi.get("total", len(kpi_items))}

    result = {
        "kpiGroups": _build_kpi_groups(kpi_data),
        "incidents": incidents_data,
        "scan_status": {},
        "severity_distribution": _severity_distribution(kpi_data),
        "confidence_distribution": _confidence_distribution(kpi_data),
        "top_entry_points": _top_entry_points(kpi_data),
    }

    cached_view(ck, result, ttl=TTL_CIEM)
    return result


def _path_to_incident(path: Dict[str, Any]) -> Dict[str, Any]:
    """Map an attack-path object to an incident-compatible dict for UI."""
    confidence = path.get("confidence_level", "speculative")
    has_cdr = path.get("has_active_cdr_actor", False)
    depth = path.get("depth", 1)

    # incident_class: confirmed CDR-backed paths = active, rest = suspicious
    incident_class = "active" if (has_cdr or confidence == "confirmed") else "suspicious"

    # tier: depth 1 = T1, depth 2 = T2, depth 3+ = T3
    tier = min(depth, 3) if depth >= 1 else 1

    return {
        "incident_id": path.get("path_id"),
        "pattern_id": path.get("entry_point_type", ""),
        "incident_class": incident_class,
        "severity": path.get("severity", "low"),
        "tier": tier,
        "confidence_level": confidence,
        "resource_uid": path.get("crown_jewel_uid"),
        "entry_point_uid": path.get("entry_point_uid"),
        "depth": depth,
        "misconfig_count": path.get("misconfig_count", 0),
        "threat_count": path.get("threat_count", 0),
        "has_active_cdr_actor": has_cdr,
        "path_score": path.get("path_score"),
        "created_at": path.get("first_seen_at"),
    }


def _build_kpi_groups(kpi_data: Dict[str, Any]) -> list:
    items = kpi_data.get("items", [])
    total = kpi_data.get("total", len(items))

    active_count = sum(1 for i in items if i.get("incident_class") == "active")
    suspicious_count = sum(1 for i in items if i.get("incident_class") == "suspicious")
    critical_count = sum(1 for i in items if i.get("severity") == "critical")
    deep_chains = sum(1 for i in items if i.get("tier", 0) >= 3)
    cdr_confirmed = sum(1 for i in items if i.get("has_active_cdr_actor"))

    return [
        {
            "id": "threats",
            "title": "Threat Summary",
            "kpis": [
                {"id": "total_paths", "label": "Total Attack Paths", "value": total},
                {"id": "active_incidents", "label": "Active (CDR Confirmed)", "value": active_count, "severity": "critical"},
                {"id": "suspicious_incidents", "label": "Suspicious", "value": suspicious_count, "severity": "high"},
                {"id": "critical_severity", "label": "Critical Severity", "value": critical_count, "severity": "critical"},
                {"id": "deep_chains", "label": "Deep Attack Chains (3+ hops)", "value": deep_chains, "severity": "high"},
                {"id": "cdr_confirmed", "label": "CDR Confirmed", "value": cdr_confirmed},
            ],
        }
    ]


def _confidence_distribution(data: Dict[str, Any]) -> Dict[str, int]:
    items = data.get("items", [])
    dist = {"confirmed": 0, "likely": 0, "speculative": 0}
    for item in items:
        c = item.get("confidence_level", "speculative")
        if c in dist:
            dist[c] += 1
    return dist


def _severity_distribution(data: Dict[str, Any]) -> Dict[str, int]:
    items = data.get("items", [])
    dist = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for item in items:
        sev = item.get("severity", "low")
        if sev in dist:
            dist[sev] += 1
    return dist


def _top_entry_points(data: Dict[str, Any]) -> list:
    from collections import Counter
    items = data.get("items", [])
    counts = Counter(i.get("pattern_id", "") for i in items if i.get("pattern_id"))
    return [
        {"entry_point_type": ep, "path_count": count}
        for ep, count in counts.most_common(5)
    ]
