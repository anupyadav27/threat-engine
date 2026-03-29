"""BFF view: /misconfig page.

Single call to threat engine /ui-data (was 2 calls to check + threat).
threat_findings IS the enriched version of all FAIL check findings,
with severity, MITRE, remediation, risk_score baked in by the threat engine.
No check engine call needed.
"""

from typing import Optional, Dict

from fastapi import APIRouter, Query

from ._shared import fetch_many, safe_get, mock_fallback, is_empty_or_health
from ._transforms import normalize_check_finding, build_misconfig_heatmap, apply_global_filters
from ._page_context import misconfig_page_context, misconfig_filter_schema

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


def _extract_service(t: dict) -> str:
    """Extract clean service name from threat data.

    Prefer resource_type (clean: 'iam', 's3') over service field which may
    contain full rule_id|resource_uid|account|region concatenations from the
    threat engine.
    """
    # resource_type is the clean service name set by the threat engine
    rt = t.get("resource_type", "")
    if rt and "|" not in rt:
        return rt
    # Try to extract from rule_id: e.g. "aws.iam.policy.xxx" → "iam"
    rule_id = t.get("rule_id", "")
    if rule_id:
        parts = rule_id.split(".")
        if len(parts) >= 3:
            return parts[1]  # e.g. "aws.iam.policy.xxx" → "iam"
    # Fallback: try service field, stripping concatenated parts
    svc = t.get("service", "")
    if svc and "|" in svc:
        # Full concatenation — take the first dotted segment's 2nd part
        first_part = svc.split("|")[0]  # "aws.iam.policy.xxx"
        dot_parts = first_part.split(".")
        if len(dot_parts) >= 2:
            return dot_parts[1]
    return svc or rt or "other"


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

    # Mock fallback when engine data is empty
    if is_empty_or_health(data):
        m = mock_fallback("misconfig")
        if m is not None:
            return m

    # threat_findings = enriched check findings (FAIL/WARN only)
    raw_threats = safe_get(data, "threats", [])
    summary = safe_get(data, "summary", {})

    findings = [normalize_check_finding({
        "finding_id": t.get("finding_id") or t.get("id", ""),
        "rule_id": t.get("rule_id", ""),
        "rule_name": t.get("title", ""),
        "severity": t.get("severity", "medium"),
        "resource_type": _extract_service(t),
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
        # Detail slide-out panel fields from threat engine
        "description": t.get("description") or t.get("rationale", ""),
        "compliance_frameworks": t.get("compliance_frameworks") or t.get("frameworks", []),
        "mitre_tactics": t.get("mitre_tactics", []),
        "mitre_techniques": t.get("mitre_techniques", []),
        "posture_category": t.get("posture_category", ""),
        "domain": t.get("domain") or t.get("security_domain", ""),
        "risk_score": t.get("risk_score"),
        "checked_fields": t.get("checked_fields", []),
        "actual_values": t.get("actual_values", []),
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
    low = sum(1 for f in filtered if f["severity"] == "low")
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

    page_ctx = misconfig_page_context({"total_findings": total})
    page_ctx["tabs"] = [
        {"id": "findings", "label": "Findings", "count": total},
        {"id": "heatmap", "label": "Heatmap", "count": len(heatmap)},
        {"id": "quick_wins", "label": "Quick Wins", "count": len(quick_wins)},
    ]

    return {
        "pageContext": page_ctx,
        "filterSchema": misconfig_filter_schema(),
        "kpiGroups": [
            {
                "title": "Finding Summary",
                "items": [
                    {"label": "Total Findings", "value": total},
                    {"label": "Critical", "value": critical},
                    {"label": "High", "value": high},
                    {"label": "Medium", "value": medium},
                ],
            },
            {
                "title": "Remediation",
                "items": [
                    {"label": "Auto-Remediable", "value": auto_remediable},
                    {"label": "Avg Age", "value": avg_age, "suffix": " days"},
                    {"label": "SLA Breached", "value": sla_breached},
                    {"label": "Quick Wins", "value": len(quick_wins)},
                ],
            },
        ],
        "findings": filtered,
        "heatmap": heatmap,
        "quickWins": quick_wins,
        "byService": by_service,
        # Legacy kpi object for UI severity cards
        "kpi": {
            "total": total,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "failed": sum(1 for f in filtered if f.get("status") == "FAIL"),
            "passed": sum(1 for f in filtered if f.get("status") == "PASS"),
            "auto_remediable": auto_remediable,
            "avg_age": avg_age,
            "sla_breached": sla_breached,
        },
    }
