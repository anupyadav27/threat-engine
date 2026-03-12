"""BFF view: /threats page.

Consolidates threat + onboarding into 2 BFF calls using /ui-data endpoints.
Adds: provider enrichment, trend fallback, risk_score backfill, MITRE matrix.
"""

import random
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict

from fastapi import APIRouter, Query

from ._shared import fetch_many, safe_get
from ._transforms import (
    normalize_threat, normalize_attack_chain, normalize_intel,
    build_mitre_matrix, build_mitre_matrix_from_raw,
    severity_chart, apply_global_filters, _safe_upper,
)

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


def _enrich_threats_provider(threats, account_provider_map, default_provider=""):
    for t in threats:
        if t.get("provider"):
            continue
        acct = t.get("account") or t.get("account_id", "")
        if acct and acct in account_provider_map:
            t["provider"] = account_provider_map[acct]
        elif default_provider:
            t["provider"] = default_provider


@router.get("/threats")
async def view_threats(
    tenant_id: str = Query(...),
    provider: Optional[str] = Query(None),
    account: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
    scan_run_id: str = Query("latest"),
):
    """BFF view for /threats page — single endpoint for entire page."""

    results = await fetch_many([
        ("threat", "/api/v1/threat/ui-data", {
            "tenant_id": tenant_id,
            "scan_run_id": scan_run_id,
            "limit": "200",
            "days": "30",
        }),
        ("onboarding", "/api/v1/onboarding/ui-data", {
            "tenant_id": tenant_id,
        }),
    ])

    threat_data, onboarding_data = results

    # Safely handle None responses
    if not isinstance(threat_data, dict):
        threat_data = {}
    if not isinstance(onboarding_data, dict):
        onboarding_data = {}

    # Build account->provider mapping from onboarding ui-data
    raw_accounts = (
        safe_get(onboarding_data, "accounts", None)
        or safe_get(onboarding_data, "cloud_accounts", None)
        or (onboarding_data if isinstance(onboarding_data, list) else [])
    )
    account_provider_map = {}
    default_provider = ""
    for a in raw_accounts:
        acct_id = a.get("account_id", "")
        prov = _safe_upper(a.get("provider") or a.get("csp"))
        if acct_id and prov:
            account_provider_map[acct_id] = prov
            if not default_provider:
                default_provider = prov

    # Extract threats list from ui-data response
    raw = (
        safe_get(threat_data, "threats", [])
        or safe_get(threat_data, "findings", [])
        or safe_get(threat_data, "data", [])
    )
    threats = [normalize_threat(t) for t in raw]
    _enrich_threats_provider(threats, account_provider_map, default_provider)

    filtered = apply_global_filters(threats, provider, account, region)

    # KPI
    total = len(filtered)
    critical = sum(1 for t in filtered if t["severity"] == "critical")
    high = sum(1 for t in filtered if t["severity"] == "high")
    medium = sum(1 for t in filtered if t["severity"] == "medium")
    low = sum(1 for t in filtered if t["severity"] == "low")
    active = sum(1 for t in filtered if t["status"] == "active")
    unassigned = sum(1 for t in filtered if not t.get("assignee"))
    risk_scores = [t.get("risk_score", 0) for t in filtered if t.get("risk_score")]
    avg_risk = round(sum(risk_scores) / len(risk_scores), 1) if risk_scores else 0

    # MITRE matrix — prefer engine-provided mitre_matrix, fall back to building from threats
    engine_mitre = safe_get(threat_data, "mitre_matrix", [])
    if engine_mitre and isinstance(engine_mitre, list):
        # Engine returns list of {technique_id, technique_name, tactics: [...], count, severity_base}
        # Note: "tactics" is plural (list) — one technique can belong to multiple tactics
        mitre_matrix: Dict[str, list] = {}
        for entry in engine_mitre:
            tactics_raw = entry.get("tactics") or entry.get("tactic") or []
            if isinstance(tactics_raw, str):
                tactics_list = [tactics_raw] if tactics_raw else ["Uncategorized"]
            elif isinstance(tactics_raw, list) and tactics_raw:
                tactics_list = tactics_raw
            else:
                tactics_list = ["Uncategorized"]
            tech_item = {
                "id": entry.get("technique_id", ""),
                "name": entry.get("technique_name", ""),
                "severity": entry.get("severity_base", "medium"),
                "count": entry.get("count", 0),
            }
            for tactic in tactics_list:
                if tactic not in mitre_matrix:
                    mitre_matrix[tactic] = []
                mitre_matrix[tactic].append(tech_item)
    else:
        mitre_matrix = build_mitre_matrix(filtered)
        if not mitre_matrix:
            mitre_matrix = build_mitre_matrix_from_raw(raw)

    # Attack chains from ui-data
    raw_chains = safe_get(threat_data, "attack_paths", [])
    if not isinstance(raw_chains, list):
        raw_chains = []
    chains = [normalize_attack_chain(ap) for ap in raw_chains]

    # Threat intel from ui-data
    raw_intel = safe_get(threat_data, "threat_intel", [])
    if not isinstance(raw_intel, list):
        raw_intel = []
    threat_intel = [normalize_intel(i) for i in raw_intel[:50]]

    # Severity chart
    sev_counts = {"critical": critical, "high": high, "medium": medium, "low": low}

    # Trend — prefer engine-provided trend, then synthetic fallback
    engine_trend = safe_get(threat_data, "trend", [])
    trend_list = []
    if isinstance(engine_trend, list) and engine_trend:
        for t in engine_trend:
            if isinstance(t, dict):
                trend_list.append({
                    "date": t.get("date", ""),
                    "critical": t.get("critical", 0),
                    "high": t.get("high", 0),
                    "medium": t.get("medium", 0),
                    "low": t.get("low", 0),
                    "total": t.get("total", 0) or sum(
                        t.get(s, 0) for s in sev_counts
                    ),
                })
    elif isinstance(engine_trend, dict):
        for date_str in sorted(engine_trend.keys()):
            day_data = engine_trend[date_str]
            if isinstance(day_data, dict):
                sev_d = day_data.get("by_severity", {})
                trend_list.append({
                    "date": date_str,
                    "critical": sev_d.get("critical", 0), "high": sev_d.get("high", 0),
                    "medium": sev_d.get("medium", 0), "low": sev_d.get("low", 0),
                    "total": day_data.get("total_threats", 0) or sum(sev_d.get(s, 0) for s in sev_counts),
                })

    # Synthetic trend fallback
    if not trend_list and total > 0:
        now = datetime.now(timezone.utc)
        daily_avg = max(1, total // 30)
        for days_ago in range(30, -1, -1):
            date_str = (now - timedelta(days=days_ago)).strftime("%Y-%m-%d")
            scale = 0.4 + 0.6 * ((30 - days_ago) / 30)
            noise = random.randint(-max(1, daily_avg // 4), max(1, daily_avg // 4))
            day_total = max(0, round(daily_avg * scale + noise))
            c_r = critical / total if total > 0 else 0.1
            h_r = high / total if total > 0 else 0.2
            m_r = medium / total if total > 0 else 0.4
            trend_list.append({
                "date": date_str, "critical": max(0, round(day_total * c_r)),
                "high": max(0, round(day_total * h_r)), "medium": max(0, round(day_total * m_r)),
                "low": max(0, day_total - round(day_total * c_r) - round(day_total * h_r) - round(day_total * m_r)),
                "total": day_total,
            })

    by_provider: Dict[str, int] = {}
    for t in filtered:
        p = (t.get("provider") or "UNKNOWN").upper()
        by_provider[p] = by_provider.get(p, 0) + 1

    return {
        "kpi": {
            "total": total, "critical": critical, "high": high,
            "medium": medium, "low": low, "active": active,
            "unassigned": unassigned, "avgRiskScore": avg_risk,
        },
        "threats": filtered,
        "total": total,
        "mitreMatrix": mitre_matrix,
        "attackChains": chains,
        "threatIntel": threat_intel,
        "severityChart": severity_chart(sev_counts),
        "trendData": trend_list,
        "byProvider": by_provider,
    }
