"""BFF view: /suppressions page.

Merges two suppression tables:
  - rule_suppressions    (rule/service/technology/provider scope — tenant_admin+)
  - finding_suppressions (resource-level — analyst+)

GET /api/v1/views/suppressions → canonical
GET /api/v1/views/policies     → legacy alias
"""

from fastapi import APIRouter, Query, Request

from ._auth import resolve_tenant_id
from ._shared import fetch_many, safe_get, BFFMeta

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


async def _build_suppressions_response(request: Request, include_expired: bool = False) -> dict:
    """Fetch both suppression types from the rule engine and merge for UI."""
    tenant_id = resolve_tenant_id(request)
    auth_ctx_header = (
        request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    )
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None
    meta = BFFMeta("suppressions")

    params = {"include_expired": str(include_expired).lower()}

    results = await fetch_many(
        [
            ("rule", "/api/v1/rules/suppressions",    params),
            ("rule", "/api/v1/findings/suppressions", params),
        ],
        auth_headers=fwd_headers,
    )

    rule_data    = results[0] or {}
    finding_data = results[1] or {}
    meta.record_engine("rule", "/api/v1/rules/suppressions",    rule_data)
    meta.record_engine("rule", "/api/v1/findings/suppressions", finding_data)

    rule_suppressions    = safe_get(rule_data,    "suppressions", [])
    finding_suppressions = safe_get(finding_data, "suppressions", [])

    # Tag each record with its suppression_type for the UI
    for s in rule_suppressions:
        s["suppression_type"] = "rule_scope"
    for s in finding_suppressions:
        s["suppression_type"] = "finding"

    all_suppressions = rule_suppressions + finding_suppressions

    rule_kpi    = safe_get(rule_data,    "kpi", {})
    finding_kpi = safe_get(finding_data, "kpi", {})

    tenant_wide   = rule_kpi.get("tenant_wide", 0)
    account_level = rule_kpi.get("account_level", 0)
    by_scope_type = rule_kpi.get("by_scope_type", {})

    from datetime import datetime, timezone, timedelta
    soon = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    expiring_soon = sum(
        1 for s in all_suppressions
        if s.get("expires_at") and s["expires_at"] <= soon
    )

    return {
        "suppressions":          all_suppressions,
        "rule_suppressions":     rule_suppressions,
        "finding_suppressions":  finding_suppressions,
        "total":                 len(all_suppressions),
        "kpi": {
            "total":                 len(all_suppressions),
            "rule_scope_total":      len(rule_suppressions),
            "finding_total":         len(finding_suppressions),
            "tenant_wide":           tenant_wide,
            "account_level":         account_level + len(finding_suppressions),
            "expiring_soon":         expiring_soon,
            "by_scope_type":         by_scope_type,
            "finding_resource_specific": finding_kpi.get("resource_specific", 0),
            "finding_rule_in_account":   finding_kpi.get("rule_in_account", 0),
        },
        "kpiGroups": [
            {
                "title": "Suppression Overview",
                "items": [
                    {"label": "Total",           "value": len(all_suppressions)},
                    {"label": "Rule Scope",      "value": len(rule_suppressions)},
                    {"label": "Finding Level",   "value": len(finding_suppressions)},
                    {"label": "Expiring in 30d", "value": expiring_soon},
                ],
            },
            {
                "title": "Rule Scope Breakdown",
                "items": [
                    {"label": "Tenant-wide",    "value": tenant_wide},
                    {"label": "Account-level",  "value": account_level},
                    {"label": "By Rule",        "value": by_scope_type.get("rule", 0)},
                    {"label": "By Service",     "value": by_scope_type.get("service", 0)},
                ],
            },
        ],
        "filterSchema": [
            {
                "key": "suppression_type",
                "label": "Type",
                "type": "enum",
                "values": ["rule_scope", "finding"],
            },
            {
                "key": "scope_level",
                "label": "Level",
                "type": "enum",
                "values": ["tenant", "account"],
            },
            {
                "key": "scope_type",
                "label": "Scope",
                "type": "enum",
                "values": ["rule", "service", "technology", "provider"],
            },
            {
                "key": "provider",
                "label": "Provider",
                "type": "enum",
                "values": ["aws", "azure", "gcp", "oci", "alicloud", "ibm", "k8s"],
            },
        ],
        "_meta": meta.to_dict(),
    }


@router.get("/suppressions")
async def view_suppressions(
    request: Request,
    include_expired: bool = Query(False),
):
    """Suppression management — merges rule-scope and finding-level suppressions."""
    return await _build_suppressions_response(request, include_expired)


@router.get("/policies")
async def view_policies(request: Request):
    """Legacy /policies endpoint — returns suppressions data."""
    return await _build_suppressions_response(request)
