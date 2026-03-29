"""BFF view: /rules page.

Single call to rule engine /ui-data (was 4 separate calls).
"""

from typing import Optional, Dict

from fastapi import APIRouter, Query

import os
import logging
import psycopg2
from psycopg2.extras import RealDictCursor

from ._shared import fetch_many, safe_get, mock_fallback, is_empty_or_health
from ._transforms import normalize_rule
from ._page_context import rules_page_context, rules_filter_schema

logger = logging.getLogger("api-gateway.bff")


def _get_rules_from_db(provider_filter=None, limit=500):
    """Query rule_metadata from check DB directly."""
    try:
        conn = psycopg2.connect(
            host=os.getenv("CHECK_DB_HOST", ""),
            port=os.getenv("CHECK_DB_PORT", "5432"),
            dbname=os.getenv("CHECK_DB_NAME", "threat_engine_check"),
            user=os.getenv("CHECK_DB_USER", "postgres"),
            password=os.getenv("CHECK_DB_PASSWORD", ""),
            connect_timeout=5,
        )
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            where = "WHERE provider = %s" if provider_filter else ""
            params = [provider_filter, limit] if provider_filter else [limit]
            cur.execute(f"""
                SELECT rule_id, title, description, severity, service, provider,
                       compliance_frameworks, remediation, domain, threat_category
                FROM rule_metadata
                {where}
                ORDER BY severity, service, rule_id
                LIMIT %s
            """, params)
            return [dict(r) for r in cur.fetchall()]
        conn.close()
    except Exception as e:
        logger.warning("Failed to query rule_metadata: %s", e)
        return []

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

    # Mock fallback when engine data is empty
    if is_empty_or_health(data):
        m = mock_fallback("rules")
        if m is not None:
            return m

    # Normalize rules from rule engine
    raw_rules = safe_get(data, "rules", [])
    rules = [normalize_rule(r) for r in raw_rules]

    # If rule engine returned nothing, query check DB directly
    if not rules:
        db_rules = _get_rules_from_db(provider_filter=provider.lower() if provider else None, limit=500)
        rules = []
        for r in db_rules:
            cf = r.get("compliance_frameworks") or {}
            frameworks = list(cf.keys()) if isinstance(cf, dict) else (cf if isinstance(cf, list) else [])
            rules.append({
                "rule_id": r.get("rule_id", ""),
                "title": r.get("title") or r.get("description", ""),
                "description": r.get("description", ""),
                "severity": r.get("severity", "medium"),
                "service": r.get("service", ""),
                "provider": (r.get("provider") or "").upper(),
                "status": "active",
                "rule_type": "built-in",
                "frameworks": frameworks,
                "domain": r.get("domain", ""),
                "threat_category": r.get("threat_category", ""),
                "remediation": r.get("remediation", ""),
            })

    # Filter by provider if specified
    if provider and raw_rules:
        p = provider.upper()
        rules = [r for r in rules if r.get("provider") == p or not r.get("provider")]

    engine_stats = safe_get(data, "statistics", {})
    raw_templates = safe_get(data, "templates", [])
    # Normalize template fields: engine uses template_id, UI expects id
    templates = []
    for tmpl in raw_templates:
        if isinstance(tmpl, dict):
            templates.append({
                "id": tmpl.get("template_id") or tmpl.get("id", ""),
                "name": tmpl.get("name", ""),
                "description": tmpl.get("description", ""),
                "framework": tmpl.get("framework") or tmpl.get("service", ""),
                "provider": tmpl.get("provider", ""),
            })
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

    page_ctx = rules_page_context()
    page_ctx["tabs"] = [
        {"id": "rules", "label": "Rules", "count": total},
        {"id": "templates", "label": "Templates", "count": len(templates)},
    ]

    return {
        "pageContext": page_ctx,
        "filterSchema": rules_filter_schema(),
        "kpiGroups": [
            {
                "title": "Rule Catalog",
                "items": [
                    {"label": "Total Rules", "value": engine_stats.get("total") or total},
                    {"label": "Active", "value": active},
                    {"label": "Built-in", "value": built_in},
                    {"label": "Custom", "value": engine_stats.get("custom_rules_count") or custom},
                ],
            },
            {
                "title": "Coverage",
                "items": [
                    {"label": "Providers", "value": len(by_provider)},
                    {"label": "Services", "value": len(by_service)},
                    {"label": "Frameworks", "value": len(by_framework)},
                    {"label": "Templates", "value": len(templates)},
                ],
            },
        ],
        "rules": rules,
        "statistics": engine_stats,
        "templates": templates,
        "providerStatus": provider_status,
        # Legacy kpi object for UI KPI cards
        "kpi": {
            "totalRules": engine_stats.get("total") or total,
            "total_rules": engine_stats.get("total") or total,
            "activeRules": active,
            "active_rules": active,
            "builtInRules": built_in,
            "built_in_rules": built_in,
            "customRules": custom,
            "custom_rules": custom,
            "providers": len(by_provider),
            "byProvider": by_provider,
            "bySeverity": by_severity,
            "byService": by_service,
            "byFramework": by_framework,
        },
    }
