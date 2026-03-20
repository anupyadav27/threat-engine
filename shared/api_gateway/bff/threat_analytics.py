"""BFF view: /threats/analytics page.

Consolidates threat analytics — KPIs, severity distribution, category breakdown,
provider split, trend data, top services, MITRE techniques, account heatmap,
and detection patterns.

All data derived from the single /ui-data endpoint (the analytics-specific
engine endpoints don't exist yet).
"""

from typing import Optional, Dict, List

from fastapi import APIRouter, Query

from ._shared import fetch_many, safe_get
from ._transforms import (
    normalize_threat, build_mitre_matrix, build_mitre_matrix_from_raw,
    severity_chart, _safe_lower,
)

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


@router.get("/threats/analytics")
async def view_threat_analytics(
    tenant_id: str = Query(...),
    days: int = Query(30, ge=1, le=365),
):
    """BFF view for threat analytics page — single endpoint call."""

    results = await fetch_many([
        ("threat", "/api/v1/threat/ui-data", {
            "tenant_id": tenant_id,
            "scan_run_id": "latest",
            "limit": "1000",
            "days": str(days),
        }),
    ])

    ui_data = results[0]
    if not isinstance(ui_data, dict):
        ui_data = {}

    # Extract raw threats for local aggregation
    raw = (
        safe_get(ui_data, "threats", [])
        or safe_get(ui_data, "findings", [])
        or safe_get(ui_data, "data", [])
    )
    threats = [normalize_threat(t) for t in raw]

    # KPI — prefer engine summary (has totals for entire scan, not just paginated slice)
    engine_summary = safe_get(ui_data, "summary", {})
    if isinstance(engine_summary, dict) and engine_summary.get("total", 0) > 0:
        total = engine_summary.get("total", 0)
        sev = engine_summary.get("by_severity", {}) or {}
        critical = sev.get("critical", engine_summary.get("critical", 0))
        high = sev.get("high", engine_summary.get("high", 0))
        medium = sev.get("medium", engine_summary.get("medium", 0))
        low = sev.get("low", engine_summary.get("low", 0))
        active = total
    else:
        total = len(threats)
        critical = sum(1 for t in threats if t["severity"] == "critical")
        high = sum(1 for t in threats if t["severity"] == "high")
        medium = sum(1 for t in threats if t["severity"] == "medium")
        low = sum(1 for t in threats if t["severity"] == "low")
        active = sum(1 for t in threats if t["status"] == "active")

    risk_scores = [t.get("riskScore", 0) for t in threats if t.get("riskScore")]
    avg_risk = round(sum(risk_scores) / len(risk_scores), 1) if risk_scores else 50

    # Severity distribution
    sev_counts = {"critical": critical, "high": high, "medium": medium, "low": low}

    # By category — from engine summary or local aggregation
    raw_by_category = safe_get(engine_summary, "by_category", {}) or {}
    if isinstance(raw_by_category, list):
        by_category: Dict[str, int] = {
            item.get("category", "Uncategorized"): item.get("count", item.get("total", 0))
            for item in raw_by_category if isinstance(item, dict)
        }
    elif isinstance(raw_by_category, dict):
        by_category = raw_by_category
    else:
        by_category = {}
    if not by_category:
        for t in raw:
            cat = t.get("threat_category") or t.get("category") or "Uncategorized"
            by_category[cat] = by_category.get(cat, 0) + 1

    # By provider
    by_provider: Dict[str, int] = {}
    for t in threats:
        p = (t.get("provider") or "UNKNOWN").upper()
        by_provider[p] = by_provider.get(p, 0) + 1

    # Trend — from ui-data
    trend_list: List[dict] = []
    engine_trend = safe_get(ui_data, "trend", [])
    if isinstance(engine_trend, list):
        for t in engine_trend:
            if isinstance(t, dict):
                trend_list.append({
                    "date": t.get("date", ""),
                    "critical": t.get("critical", 0),
                    "high": t.get("high", 0),
                    "medium": t.get("medium", 0),
                    "low": t.get("low", 0),
                    "total": t.get("total", 0) or sum(
                        t.get(s, 0) for s in ("critical", "high", "medium", "low")
                    ),
                })
    elif isinstance(engine_trend, dict):
        for date_str in sorted(engine_trend.keys()):
            day_data = engine_trend[date_str]
            if isinstance(day_data, dict):
                sd = day_data.get("by_severity", {})
                trend_list.append({
                    "date": date_str,
                    "critical": sd.get("critical", 0),
                    "high": sd.get("high", 0),
                    "medium": sd.get("medium", 0),
                    "low": sd.get("low", 0),
                    "total": day_data.get("total_threats", 0) or sum(
                        sd.get(s, 0) for s in ("critical", "high", "medium", "low")
                    ),
                })

    # Top services — from engine summary.by_service
    raw_by_service = safe_get(ui_data, "summary.by_service", []) or []
    if isinstance(raw_by_service, list):
        by_service: Dict[str, int] = {
            item.get("service", "unknown"): item.get("count", item.get("total", 0))
            for item in raw_by_service if isinstance(item, dict)
        }
    elif isinstance(raw_by_service, dict):
        by_service = raw_by_service
    else:
        by_service = {}
    if not by_service:
        for t in raw:
            svc = t.get("resource_type") or t.get("service") or "unknown"
            by_service[svc] = by_service.get(svc, 0) + 1
    top_services = sorted(
        [{"service": k, "count": v} for k, v in by_service.items()],
        key=lambda x: x["count"],
        reverse=True,
    )[:10]

    # Top MITRE techniques — from engine mitre_matrix or local
    engine_mitre = safe_get(ui_data, "mitre_matrix", [])
    top_techniques: List[dict] = []
    if isinstance(engine_mitre, list) and engine_mitre:
        for entry in engine_mitre:
            tactics_raw = entry.get("tactics") or entry.get("tactic") or ["Uncategorized"]
            if isinstance(tactics_raw, str):
                tactics_raw = [tactics_raw]
            top_techniques.append({
                "techniqueId": entry.get("technique_id", ""),
                "techniqueName": entry.get("technique_name", ""),
                "tactic": tactics_raw[0] if tactics_raw else "Uncategorized",
                "count": entry.get("count", 0),
                "severity": entry.get("severity_base", "medium"),
            })
    else:
        mitre_matrix = build_mitre_matrix_from_raw(raw)
        for tactic, techs in mitre_matrix.items():
            for tech in techs:
                top_techniques.append({
                    "techniqueId": tech["id"],
                    "techniqueName": tech["name"],
                    "tactic": tactic,
                    "count": tech["count"],
                    "severity": tech["severity"],
                })
    top_techniques.sort(key=lambda x: x["count"], reverse=True)
    top_techniques = top_techniques[:15]

    # Account heatmap
    # Prefer engine summary.by_account, fall back to local
    raw_by_account = safe_get(ui_data, "summary.by_account", []) or []
    account_heatmap: List[dict] = []
    if isinstance(raw_by_account, list) and raw_by_account:
        account_heatmap = [
            {
                "account": item.get("account_id", "unknown"),
                "critical": item.get("critical", 0),
                "high": item.get("high", 0),
                "medium": item.get("medium", 0),
                "low": item.get("low", 0),
                "total": item.get("count", 0),
            }
            for item in raw_by_account if isinstance(item, dict)
        ]
    else:
        acct_map: Dict[str, dict] = {}
        for t in threats:
            acct = t.get("account") or "unknown"
            if acct not in acct_map:
                acct_map[acct] = {
                    "account": acct,
                    "critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0,
                }
            s = t.get("severity", "low")
            if s in acct_map[acct]:
                acct_map[acct][s] += 1
            acct_map[acct]["total"] += 1
        account_heatmap = sorted(acct_map.values(), key=lambda x: x["total"], reverse=True)

    return {
        "kpi": {
            "total": total,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "active": active,
            "avgRiskScore": avg_risk,
        },
        "severityDistribution": severity_chart(sev_counts),
        "byCategory": [
            {"name": k, "count": v}
            for k, v in sorted(by_category.items(), key=lambda x: x[1], reverse=True)
        ],
        "byProvider": [
            {"name": k, "count": v}
            for k, v in sorted(by_provider.items(), key=lambda x: x[1], reverse=True)
        ],
        "trendData": trend_list,
        "topServices": top_services,
        "topMitreTechniques": top_techniques,
        "accountHeatmap": account_heatmap,
        "patterns": [],
    }
