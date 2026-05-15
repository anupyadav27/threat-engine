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

    # Custom rules params — only user-created rules from user_check_rules table
    custom_params: Dict[str, str] = {"limit": "500"}
    if tenant_id:
        custom_params["tenant_id"] = tenant_id
    if provider:
        custom_params["provider"] = provider

    supp_params: Dict[str, str] = {}

    # Fetch in parallel: check catalog + user-created rules + suppressions
    results = await fetch_many([
        ("check", "/api/v1/check/rules/catalog", catalog_params),
        ("rule",  "/api/v1/user-rules",          custom_params),
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
            "rule_id":             r.get("rule_id", ""),
            "provider":            (r.get("provider") or "").upper(),
            "service":             r.get("service", ""),
            "resource":            r.get("resource") or "",
            "title":               r.get("title", ""),
            "severity":            r.get("severity", "medium"),
            "domain":              r.get("domain") or "",
            "subcategory":         r.get("subcategory") or "",
            "posture_category":    r.get("posture_category") or "",
            "description":         r.get("description") or "",
            "remediation":         r.get("remediation") or "",
            "rationale":           r.get("rationale") or "",
            "compliance_frameworks": r.get("compliance_frameworks") or {},
            "mitre_tactics":       r.get("mitre_tactics") or [],
            "mitre_techniques":    r.get("mitre_techniques") or [],
            "risk_score":          r.get("risk_score"),
            "remediation_effort":  r.get("remediation_effort") or "",
            "rule_type":           rule_type_val,
            "status":              "active",
            "is_suppressed":       False,
        })

    # 2. User-created rules from user_check_rules (only when not filtering to a non-custom type)
    if not rule_type or rule_type == "custom":
        for r in safe_get(custom_data, "rules", []):
            # user_check_rules has flat columns: title, severity, category, etc.
            frameworks_raw = r.get("frameworks") or []
            rules.append({
                "rule_id":             r.get("rule_id", ""),
                "provider":            (r.get("provider") or "").upper(),
                "service":             r.get("service", ""),
                "resource":            "",
                "title":               r.get("title", ""),
                "severity":            (r.get("severity") or "medium").lower(),
                "domain":              r.get("category") or "",
                "subcategory":         "",
                "posture_category":    "",
                "description":         r.get("description") or "",
                "remediation":         "",
                "rationale":           "",
                "compliance_frameworks": {f: [] for f in frameworks_raw} if isinstance(frameworks_raw, list) else {},
                "mitre_tactics":       [],
                "mitre_techniques":    [],
                "risk_score":          None,
                "remediation_effort":  "",
                "rule_type":           "custom",
                "status":              "active",
                "is_suppressed":       False,
            })

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

    return {
        "rules":     rules,
        "templates": templates,
        "summary": {
            "total":      total,
            "active":     active,
            "suppressed": suppressed_count,
            "by_type":    by_type,
        },
        "_meta": meta.to_dict(),
    }
