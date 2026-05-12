"""BFF view: /rules page — unified Rule Library.

Merges three rule sources:
  1. Check engine rule_metadata catalog  → rule_type: "config" | "cdr" | "threat"
  2. Rule engine custom YAML catalog     → rule_type: "custom"

Suppression state is annotated server-side from rule_suppressions.
"""

from typing import Optional, Dict
import logging

from fastapi import APIRouter, Query, Request

from ._auth import resolve_tenant_id
from ._shared import fetch_many, safe_get, BFFMeta
from .schemas.rules import RulesResponse
from ._transforms import normalize_rule
from ._page_context import rules_page_context, rules_filter_schema

logger = logging.getLogger("api-gateway.bff")

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


@router.get("/rules", response_model=RulesResponse, response_model_exclude_none=False)
async def view_rules(
    request: Request,
    provider: Optional[str] = Query(None),
    rule_type: Optional[str] = Query(None),   # "config" | "cdr" | "threat" | "custom"
    search: Optional[str] = Query(None),
):
    """Single endpoint returning everything the Rules Library page needs.

    Merges check engine catalog (config/CDR/threat rules) with rule engine
    custom YAML rules. Annotates is_suppressed from rule_suppressions table.
    """
    tenant_id = resolve_tenant_id(request)
    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None
    meta = BFFMeta("rules")

    # Build check catalog params
    catalog_params: Dict[str, str] = {"limit": "15000"}
    if provider:
        catalog_params["provider"] = provider
    if rule_type and rule_type != "custom":
        catalog_params["rule_type"] = rule_type
    if search:
        catalog_params["search"] = search

    # Custom rules params (rule engine)
    custom_params: Dict[str, str] = {"tenant_id": tenant_id or "", "limit": "500"}
    if provider:
        custom_params["provider"] = provider

    supp_params: Dict[str, str] = {}

    # Fetch in parallel: check catalog + custom rules + suppressions
    results = await fetch_many([
        ("check", "/api/v1/check/rules/catalog", catalog_params),
        ("rule",  "/api/v1/rules/ui-data",       custom_params),
        ("rule",  "/api/v1/rules/suppressions",  supp_params),
    ], auth_headers=fwd_headers)

    catalog_data = results[0] or {}
    custom_data  = results[1] or {}
    supp_data    = results[2] or {}

    meta.record_engine("check", "/api/v1/check/rules/catalog", catalog_data)
    meta.record_engine("rule",  "/api/v1/rules/ui-data",       custom_data)

    # Build suppression lookup sets
    raw_suppressions = safe_get(supp_data, "suppressions", [])
    suppressed_rule_ids: set = {
        s["scope_value"] for s in raw_suppressions if s.get("scope_type") == "rule"
    }
    suppressed_services: set = {
        s["scope_value"] for s in raw_suppressions if s.get("scope_type") == "service"
    }
    suppressed_techs: set = {
        s["scope_value"] for s in raw_suppressions if s.get("scope_type") == "technology"
    }

    # ── Build unified rule list ───────────────────────────────────────────
    rules: list = []

    # 1. Check engine catalog rules (config / cdr / threat)
    for r in safe_get(catalog_data, "rules", []):
        rule_type_val = r.get("rule_type", "config")
        if rule_type and rule_type != rule_type_val:
            continue
        rules.append({
            "rule_id":    r.get("rule_id", ""),
            "provider":   (r.get("provider") or "").upper(),
            "service":    r.get("service", ""),
            "title":      r.get("title", ""),
            "severity":   r.get("severity", "medium"),
            "domain":     r.get("domain", ""),
            "description": r.get("description", ""),
            "rule_type":  rule_type_val,
            "status":     "active",
            "is_suppressed": False,
        })

    # 2. Custom YAML rules (only when not filtering by a non-custom rule_type)
    if not rule_type or rule_type == "custom":
        for r in safe_get(custom_data, "rules", []):
            normalized = normalize_rule(r)
            normalized["rule_type"] = "custom"
            normalized.setdefault("status", "active")
            normalized["is_suppressed"] = False
            rules.append(normalized)

    # ── Annotate suppression status ───────────────────────────────────────
    for rule in rules:
        rid = rule.get("rule_id", "")
        svc = rule.get("service", "")
        suppressed = (
            rid in suppressed_rule_ids
            or svc in suppressed_services
            or svc in suppressed_techs
        )
        if suppressed:
            rule["is_suppressed"] = True
            rule["status"] = "suppressed"

    # ── Aggregates ────────────────────────────────────────────────────────
    total      = len(rules)
    active     = sum(1 for r in rules if r.get("status") == "active")
    suppressed_count = sum(1 for r in rules if r.get("is_suppressed"))
    by_type    = {"config": 0, "cdr": 0, "threat": 0, "custom": 0}
    by_provider: Dict[str, int] = {}
    by_service:  Dict[str, int] = {}
    by_severity: Dict[str, int] = {}

    for r in rules:
        rt  = r.get("rule_type", "config")
        by_type[rt]  = by_type.get(rt, 0) + 1
        pv = r.get("provider") or "ALL"
        by_provider[pv] = by_provider.get(pv, 0) + 1
        sv = r.get("service") or "other"
        by_service[sv]  = by_service.get(sv, 0) + 1
        se = r.get("severity", "medium")
        by_severity[se] = by_severity.get(se, 0) + 1

    engine_stats = safe_get(custom_data, "statistics", {})
    raw_templates = safe_get(custom_data, "templates", [])
    templates = []
    for tmpl in raw_templates:
        if isinstance(tmpl, dict):
            templates.append({
                "id":          tmpl.get("template_id") or tmpl.get("id", ""),
                "name":        tmpl.get("name", ""),
                "description": tmpl.get("description", ""),
                "framework":   tmpl.get("framework") or tmpl.get("service", ""),
                "provider":    tmpl.get("provider", ""),
            })

    page_ctx = rules_page_context()
    page_ctx["tabs"] = [
        {"id": "rules",     "label": "Rules",     "count": total},
        {"id": "templates", "label": "Templates",  "count": len(templates)},
    ]

    return {
        "pageContext":  page_ctx,
        "filterSchema": rules_filter_schema(),
        "kpiGroups": [
            {
                "title": "Rule Catalog",
                "items": [
                    {"label": "Total",      "value": total},
                    {"label": "Active",     "value": active},
                    {"label": "Suppressed", "value": suppressed_count},
                    {"label": "Custom",     "value": by_type.get("custom", 0)},
                ],
            },
            {
                "title": "By Type",
                "items": [
                    {"label": "Config",     "value": by_type.get("config", 0)},
                    {"label": "CDR",        "value": by_type.get("cdr", 0)},
                    {"label": "Threat",     "value": by_type.get("threat", 0)},
                    {"label": "Custom",     "value": by_type.get("custom", 0)},
                ],
            },
        ],
        "rules":       rules,
        "statistics":  engine_stats,
        "templates":   templates,
        "providerStatus": safe_get(custom_data, "providers_status", {}),
        "kpi": {
            "totalRules":   total,
            "total_rules":  total,
            "activeRules":  active,
            "active_rules": active,
            "suppressed":   suppressed_count,
            "byType":       by_type,
            "byProvider":   by_provider,
            "bySeverity":   by_severity,
            "byService":    by_service,
        },
        "_meta": meta.to_dict(),
    }
