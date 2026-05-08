"""BFF view: /policies page.

Proxies the rule engine's /api/v1/rules endpoint and shapes the
response into the standard BFF envelope (kpiGroups, filterSchema, data).

GET /api/v1/views/policies
"""

from typing import Optional

from fastapi import APIRouter, Query, Request

from ._auth import resolve_tenant_id
from ._shared import fetch_many, safe_get
from ._cache import cache_key, cached_view, TTL_POLICIES, auth_level_from_header

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


@router.get("/policies")
async def view_policies(
    request: Request,
    limit: int = Query(200),
):
    tenant_id = resolve_tenant_id(request)
    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None
    role_level = auth_level_from_header(auth_ctx_header)

    ck = cache_key("policies", tenant_id, role_level=role_level)
    cached = cached_view(ck)
    if cached is not None:
        return cached

    results = await fetch_many([
        ("rule", "/api/v1/rules", {"limit": str(limit)}),
    ], auth_headers=fwd_headers)

    raw = results[0]
    policies = []
    if isinstance(raw, dict):
        policies = raw.get("rules") or raw.get("data") or raw.get("policies") or raw.get("results") or []
    elif isinstance(raw, list):
        policies = raw

    # Aggregate KPIs
    by_status: dict = {}
    by_category: dict = {}
    by_provider: dict = {}
    for p in policies:
        status   = (p.get("status")   or "unknown").lower()
        category = (p.get("category") or "general").lower()
        provider = (p.get("provider") or "all").lower()
        by_status[status]     = by_status.get(status, 0) + 1
        by_category[category] = by_category.get(category, 0) + 1
        by_provider[provider] = by_provider.get(provider, 0) + 1

    active    = by_status.get("active",   0)
    draft     = by_status.get("draft",    0)
    archived  = by_status.get("archived", 0)
    total     = len(policies)

    # Enrich each policy with UI-expected table columns
    enriched = []
    for p in policies:
        enriched.append({
            **p,
            "id":             p.get("rule_id") or p.get("id", ""),
            "name":           p.get("name") or p.get("rule_name") or p.get("title", ""),
            "category":       p.get("category", "general"),
            "provider":       p.get("provider", "all"),
            "severity":       p.get("severity", "medium"),
            "status":         p.get("status", "active"),
            "violations":     p.get("violations") or p.get("fail_count", 0),
            "pass_rate":      p.get("pass_rate", 0),
            "auto_remediate": p.get("auto_remediate", False),
            "frameworks":     p.get("frameworks") or [],
            "evaluations":    p.get("evaluations") or p.get("total_checks", 0),
            "last_updated":   p.get("last_updated") or p.get("updated_at", ""),
            "exceptions":     p.get("exceptions") or [],
            "version_history":p.get("version_history") or [],
        })

    by_status_list = [{"status": k, "count": v} for k, v in
                      sorted(by_status.items(), key=lambda x: -x[1])]

    tabs = [
        {"id": "policies",   "label": "Policies",    "count": total},
        {"id": "exceptions", "label": "Exceptions",  "count": 0},
        {"id": "changelog",  "label": "Change Log",  "count": 0},
    ]

    result = {
        "policies":   enriched,
        "total":      total,
        "brief":      f"{active} active, {draft} draft — {total} total policies",
        "details":    {},
        "tabs":       tabs,
        "kpiGroups": [
            {
                "title": "Policy Coverage",
                "items": [
                    {"label": "Total Policies", "value": total},
                    {"label": "Active",         "value": active},
                    {"label": "Draft",          "value": draft},
                    {"label": "Archived",       "value": archived},
                ],
            }
        ],
        "byCategory": [{"category": k, "count": v} for k, v in
                       sorted(by_category.items(), key=lambda x: -x[1])],
        "byProvider": [{"provider": k, "count": v} for k, v in
                       sorted(by_provider.items(), key=lambda x: -x[1])],
        "byStatus":   by_status_list,
        "items":      enriched,
        "filterSchema": [
            {"key": "status",   "label": "Status",   "type": "enum",
             "values": ["active", "draft", "archived"]},
            {"key": "category", "label": "Category", "type": "string"},
            {"key": "provider", "label": "Provider", "type": "enum",
             "values": ["aws", "azure", "gcp", "oci", "alicloud", "ibm", "all"]},
            {"key": "severity", "label": "Severity", "type": "enum",
             "values": ["critical", "high", "medium", "low"]},
        ],
    }

    cached_view(ck, result, ttl=TTL_POLICIES)
    return result
