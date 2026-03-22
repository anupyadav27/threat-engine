"""BFF view: /threats page (Threat Detection).

Consolidates threat + onboarding into 2 BFF calls using /ui-data endpoints.
Threat ui-data now returns DETECTIONS (grouped threats with risk scores),
not atomic findings.

This is the merged "Threat Detection" page — combines the former Overview
and Analytics pages into a single comprehensive view.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, List

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
    """BFF view for /threats page — detection-level data."""

    results = await fetch_many([
        ("threat", "/api/v1/threat/ui-data", {
            "tenant_id": tenant_id,
            "scan_run_id": scan_run_id,
            "limit": "2000",
            "days": "90",
        }),
        ("onboarding", "/api/v1/cloud-accounts", {
            "tenant_id": tenant_id,
        }),
    ])

    threat_data, onboarding_data = results

    if not isinstance(threat_data, dict):
        threat_data = {}
    if not isinstance(onboarding_data, dict):
        onboarding_data = {}

    # Build account->provider mapping from onboarding
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

    # Extract threats (detections) from ui-data
    raw = safe_get(threat_data, "threats", []) or []
    threats = [normalize_threat(t) for t in raw]
    _enrich_threats_provider(threats, account_provider_map, default_provider)

    filtered = apply_global_filters(threats, provider, account, region)

    # KPI — use engine summary (detection-level counts)
    engine_summary = safe_get(threat_data, "summary", {})
    if isinstance(engine_summary, dict) and engine_summary.get("total_detections", 0) > 0:
        total = engine_summary.get("total_detections", 0)
        critical = engine_summary.get("critical", 0)
        high = engine_summary.get("high", 0)
        medium = engine_summary.get("medium", 0)
        low = engine_summary.get("low", 0)
        avg_risk = engine_summary.get("avg_risk_score", 0)
        total_findings = engine_summary.get("total_findings", 0)
        # Apply global filters if set
        if provider or account or region:
            total = len(filtered)
            critical = sum(1 for t in filtered if t["severity"] == "critical")
            high = sum(1 for t in filtered if t["severity"] == "high")
            medium = sum(1 for t in filtered if t["severity"] == "medium")
            low = sum(1 for t in filtered if t["severity"] == "low")
    else:
        total = len(filtered)
        critical = sum(1 for t in filtered if t["severity"] == "critical")
        high = sum(1 for t in filtered if t["severity"] == "high")
        medium = sum(1 for t in filtered if t["severity"] == "medium")
        low = sum(1 for t in filtered if t["severity"] == "low")
        avg_risk = 0
        total_findings = engine_summary.get("total_findings", 0) or engine_summary.get("total", 0)

    risk_scores = [t.get("risk_score", 0) for t in filtered if t.get("risk_score")]
    if risk_scores:
        avg_risk = round(sum(risk_scores) / len(risk_scores), 1)

    # MITRE matrix
    engine_mitre = safe_get(threat_data, "mitre_matrix", [])
    if engine_mitre and isinstance(engine_mitre, list):
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

    # Attack paths
    raw_chains = safe_get(threat_data, "attack_paths", [])
    if not isinstance(raw_chains, list):
        raw_chains = []
    chains = [normalize_attack_chain(ap) for ap in raw_chains]

    # Threat intel
    raw_intel = safe_get(threat_data, "threat_intel", [])
    if not isinstance(raw_intel, list):
        raw_intel = []
    threat_intel = [normalize_intel(i) for i in raw_intel[:50]]

    # Severity chart
    sev_counts = {"critical": critical, "high": high, "medium": medium, "low": low}

    # Trend
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

    # If engine returned no trend data, build from detection timestamps
    if not trend_list and filtered:
        date_counts: Dict[str, Dict[str, int]] = {}
        for t in filtered:
            ts = t.get("detected") or t.get("detected_at") or t.get("first_seen_at") or ""
            if ts and len(ts) >= 10:
                d = ts[:10]  # YYYY-MM-DD
                if d not in date_counts:
                    date_counts[d] = {"date": d, "critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
                sev = t.get("severity", "low")
                if sev in date_counts[d]:
                    date_counts[d][sev] += 1
                date_counts[d]["total"] += 1
        trend_list = [date_counts[k] for k in sorted(date_counts.keys())]

    by_provider: Dict[str, int] = {}
    for t in filtered:
        p = (t.get("provider") or "UNKNOWN").upper()
        by_provider[p] = by_provider.get(p, 0) + 1

    # Top services — with severity breakdown for stacked bar chart
    svc_sev: Dict[str, Dict[str, int]] = {}
    for t in filtered:
        svc = t.get("resourceType") or t.get("service") or "unknown"
        if svc not in svc_sev:
            svc_sev[svc] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
        s = t.get("severity", "low")
        if s in svc_sev[svc]:
            svc_sev[svc][s] += 1
        svc_sev[svc]["total"] += 1
    top_services = sorted(
        [{"name": k, **v} for k, v in svc_sev.items()],
        key=lambda x: x["total"],
        reverse=True,
    )[:10]

    # By category — from engine summary or local aggregation
    engine_summary_safe = engine_summary if isinstance(engine_summary, dict) else {}
    raw_by_category = safe_get(engine_summary_safe, "by_category", {}) or {}
    by_category: Dict[str, int] = {}
    if isinstance(raw_by_category, list):
        by_category = {
            item.get("category", "Uncategorized"): item.get("count", item.get("total", 0))
            for item in raw_by_category if isinstance(item, dict)
        }
    elif isinstance(raw_by_category, dict):
        by_category = raw_by_category
    if not by_category:
        for t in raw:
            cat = t.get("threat_category") or t.get("category") or "Uncategorized"
            by_category[cat] = by_category.get(cat, 0) + 1

    # Account heatmap — severity breakdown per account
    raw_by_account = safe_get(threat_data, "summary.by_account", []) or []
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
        for t in filtered:
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

    # Enrich threats with attack path / internet exposed flags
    attack_path_uids: set = set()
    for ap in raw_chains:
        for res in ap.get("resources", []):
            uid = res if isinstance(res, str) else (res.get("resource_uid") or res.get("id", ""))
            if uid:
                attack_path_uids.add(uid)

    internet_exposed_uids: set = set()
    raw_exposed = safe_get(threat_data, "internet_exposed", {})
    if isinstance(raw_exposed, dict):
        for exp in raw_exposed.get("resources", []):
            uid = exp if isinstance(exp, str) else (exp.get("resource_uid") or exp.get("id", ""))
            if uid:
                internet_exposed_uids.add(uid)

    for t in filtered:
        t_resource = t.get("resource_uid", "")
        t["hasAttackPath"] = bool(t_resource and t_resource in attack_path_uids)
        t["isInternetExposed"] = bool(t_resource and t_resource in internet_exposed_uids)

    # Status counts from verdict or status field
    by_verdict = engine_summary.get("by_verdict", {}) if isinstance(engine_summary, dict) else {}
    active_count = by_verdict.get("active", 0) or sum(
        1 for t in filtered if (t.get("status") or "active").lower() == "active"
    )
    unassigned_count = sum(1 for t in filtered if not t.get("assignee"))

    # Scan metadata — so the UI can show "data as of ..."
    scan_meta = safe_get(threat_data, "scan_meta", {}) or {}
    latest_detection_ts = ""
    if filtered:
        timestamps = [
            t.get("detected") or t.get("detected_at") or t.get("first_seen_at") or ""
            for t in filtered if t.get("detected") or t.get("detected_at") or t.get("first_seen_at")
        ]
        if timestamps:
            latest_detection_ts = max(timestamps)

    return {
        "kpi": {
            "total": total, "critical": critical, "high": high,
            "medium": medium, "low": low,
            "active": active_count,
            "unassigned": unassigned_count,
            "avgRiskScore": avg_risk,
            "totalFindings": total_findings,
            "criticalAndHigh": critical + high,
            "byVerdict": by_verdict,
        },
        "scanMeta": {
            "scanRunId": scan_meta.get("scan_run_id") or scan_run_id,
            "latestDetection": latest_detection_ts,
            "dataScope": "all_scans" if scan_run_id == "latest" else "single_scan",
        },
        "threats": filtered,
        "total": total,
        "mitreMatrix": mitre_matrix,
        "attackChains": chains,
        "threatIntel": threat_intel,
        "severityChart": severity_chart(sev_counts),
        "trendData": trend_list,
        "byProvider": [
            {"name": k, "count": v}
            for k, v in sorted(by_provider.items(), key=lambda x: x[1], reverse=True)
        ],
        "topServices": top_services,
        "byCategory": [
            {"name": k, "count": v}
            for k, v in sorted(by_category.items(), key=lambda x: x[1], reverse=True)
        ],
        "accountHeatmap": account_heatmap,
    }
