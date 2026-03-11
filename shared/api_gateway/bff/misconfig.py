"""BFF view: /misconfig page.

Single call to threat engine /ui-data (was 2 calls to check + threat).
threat_findings IS the enriched version of all FAIL check findings,
with severity, MITRE, remediation, risk_score baked in by the threat engine.
No check engine call needed.
"""

from typing import Optional, Dict

from fastapi import APIRouter, Query

from ._shared import fetch_many, safe_get
from ._transforms import normalize_check_finding, build_misconfig_heatmap, apply_global_filters

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


@router.get("/misconfig")
async def view_misconfig(
    tenant_id: str = Query(...),
    provider: Optional[str] = Query(None),
    account: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
    scan_run_id: str = Query("latest"),
):
    """Single endpoint returning everything the misconfig page needs."""

    results = await fetch_many([
        ("threat", "/api/v1/threat/ui-data", {
            "tenant_id": tenant_id, "scan_run_id": scan_run_id, "limit": "500",
        }),
    ])

    data = results[0] or {}

    # threat_findings = enriched check findings (FAIL/WARN only)
    raw_threats = safe_get(data, "threats", [])
    summary = safe_get(data, "summary", {})

    findings = [normalize_check_finding({
        "finding_id": t.get("finding_id") or t.get("id", ""),
        "rule_id": t.get("rule_id", ""),
        "rule_name": t.get("title", ""),
        "severity": t.get("severity", "medium"),
        "resource_type": t.get("service") or t.get("resource_type", ""),
        "resource_id": t.get("resource_uid") or t.get("resource_arn", ""),
        "provider": t.get("provider", ""),
        "account_id": t.get("account_id", ""),
        "region": t.get("region", ""),
        "remediation": t.get("remediation", ""),
        "auto_remediable": t.get("auto_remediable", False),
        "age_days": t.get("age_days"),
        "status": t.get("status", "FAIL"),
        "framework": t.get("framework", ""),
        "environment": t.get("environment", ""),
    }) for t in raw_threats]

    # Apply scope filters
    filtered = apply_global_filters(findings, provider, account, region)

    # KPIs
    total = len(filtered)
    failed = sum(1 for f in filtered if f["status"] == "FAIL")
    passed = total - failed
    critical = sum(1 for f in filtered if f["severity"] == "critical")
    high = sum(1 for f in filtered if f["severity"] == "high")
    medium = sum(1 for f in filtered if f["severity"] == "medium")
    auto_remediable = sum(1 for f in filtered if f.get("auto_remediable"))
    sla_breached = sum(1 for f in filtered if f.get("sla_status") == "breached")
    ages = [f.get("age_days", 0) for f in filtered if f.get("age_days") is not None]
    avg_age = round(sum(ages) / len(ages), 1) if ages else 0

    # Use engine summary counts as fallback
    if not auto_remediable:
        auto_remediable = safe_get(summary, "auto_remediable", 0)

    heatmap = build_misconfig_heatmap(filtered)

    # Quick wins: critical + auto-remediable
    quick_wins = [f for f in filtered if f["severity"] == "critical" and f.get("auto_remediable")][:5]

    # By service breakdown
    by_service: Dict[str, int] = {}
    for f in filtered:
        svc = f.get("service") or "other"
        by_service[svc] = by_service.get(svc, 0) + 1

    return {
        "kpi": {
            "total": total,
            "failed": failed,
            "passed": passed,
            "critical": critical,
            "high": high,
            "medium": medium,
            "autoRemediable": auto_remediable,
            "slaBreached": sla_breached,
            "avgAge": avg_age,
        },
        "findings": filtered,
        "heatmap": heatmap,
        "quickWins": quick_wins,
        "byService": dict(sorted(by_service.items(), key=lambda x: x[1], reverse=True)[:15]),
    }
