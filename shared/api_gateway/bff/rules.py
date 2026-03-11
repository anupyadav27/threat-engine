"""BFF view: /rules page.

Single call to rule engine /ui-data (was 4 separate calls).
"""

from typing import Optional, Dict

from fastapi import APIRouter, Query

from ._shared import fetch_many, safe_get
from ._transforms import normalize_rule

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


@router.get("/rules")
async def view_rules(
    tenant_id: str = Query(...),
    provider: Optional[str] = Query(None),
):
    """Single endpoint returning everything the rules page needs."""

    params: Dict[str, str] = {"tenant_id": tenant_id, "limit": "500"}
    if provider:
        params["provider"] = provider

    results = await fetch_many([
        ("rule", "/api/v1/rules/ui-data", params),
    ])

    data = results[0] or {}

    # Normalize rules
    raw_rules = safe_get(data, "rules", [])
    rules = [normalize_rule(r) for r in raw_rules]

    # Filter by provider if specified
    if provider:
        p = provider.upper()
        rules = [r for r in rules if r.get("provider") == p or not r.get("provider")]

    # Engine statistics (pre-computed by /ui-data)
    engine_stats = safe_get(data, "statistics", {})
    templates = safe_get(data, "templates", [])
    provider_status = safe_get(data, "providers_status", {})

    # KPI derivation
    total = len(rules)
    active = sum(1 for r in rules if r.get("status") == "active")
    custom = sum(1 for r in rules if r.get("rule_type") == "custom")
    built_in = total - custom

    by_severity: Dict[str, int] = {}
    for r in rules:
        sev = r.get("severity", "medium")
        by_severity[sev] = by_severity.get(sev, 0) + 1

    by_provider: Dict[str, int] = {}
    for r in rules:
        p = r.get("provider") or "ALL"
        by_provider[p] = by_provider.get(p, 0) + 1

    by_service: Dict[str, int] = {}
    for r in rules:
        svc = r.get("service") or "other"
        by_service[svc] = by_service.get(svc, 0) + 1

    by_framework: Dict[str, int] = {}
    for r in rules:
        fws = r.get("frameworks") or []
        for fw in fws:
            by_framework[fw] = by_framework.get(fw, 0) + 1

    return {
        "kpi": {
            "totalRules": engine_stats.get("total_rules") or total,
            "activeRules": active,
            "builtInRules": built_in,
            "customRules": engine_stats.get("custom_rules_count") or custom,
            "bySeverity": by_severity,
            "byProvider": engine_stats.get("by_provider") or by_provider,
            "byService": engine_stats.get("by_service") or dict(
                sorted(by_service.items(), key=lambda x: x[1], reverse=True)[:15]
            ),
            "byFramework": dict(sorted(by_framework.items(), key=lambda x: x[1], reverse=True)),
            "providers": len(by_provider),
        },
        "rules": rules,
        "statistics": engine_stats,
        "templates": templates,
        "providerStatus": provider_status,
    }
