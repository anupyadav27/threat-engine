"""BFF view: /iam page.

Standardized layout: pageContext, two-part KPI, filterSchema, tabs + table data.
No charts — charts live only on the dashboard.
"""

from typing import Optional, Dict, Any

from fastapi import APIRouter, Query

from ._shared import fetch_many, safe_get, mock_fallback, is_empty_or_health
from ._transforms import (
    group_iam_findings_to_identities, normalize_iam_role,
    normalize_access_key, normalize_privilege_escalation,
    normalize_service_account, apply_global_filters,
)
from ._page_context import iam_page_context, iam_filter_schema

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


@router.get("/iam")
async def view_iam(
    tenant_id: str = Query(...),
    provider: Optional[str] = Query(None),
    account: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
    csp: str = Query("aws"),
    scan_id: str = Query("latest"),
):
    effective_csp = csp or (provider.lower() if provider else "aws")

    results = await fetch_many([
        ("iam", "/api/v1/iam-security/ui-data", {
            "tenant_id": tenant_id, "csp": effective_csp, "scan_id": scan_id,
        }),
    ])

    data = results[0] or {}

    # Mock fallback when engine data is empty
    if is_empty_or_health(data):
        m = mock_fallback("iam")
        if m is not None:
            return m

    summary = safe_get(data, "summary", {})
    by_module = safe_get(summary, "by_module", {})
    by_severity = safe_get(summary, "by_severity", {})

    # ── Tab data ──
    raw_findings = safe_get(data, "findings", [])
    identities = group_iam_findings_to_identities(raw_findings)
    filtered = apply_global_filters(identities, provider, account, region)

    roles = [normalize_iam_role(r) for r in safe_get(data, "roles", [])]
    access_keys = [normalize_access_key(k) for k in safe_get(data, "access_keys", [])]
    priv_esc = [normalize_privilege_escalation(p) for p in safe_get(data, "privilege_escalation", [])]
    svc_accounts = [normalize_service_account(s) for s in safe_get(data, "service_accounts", [])]

    # ── Derived metrics ──
    posture_score = safe_get(summary, "posture_score", 0) or safe_get(summary, "risk_score", 0)
    if not posture_score and filtered:
        posture_score = min(100, round(sum(45 for _ in filtered) / max(len(filtered), 1)))

    no_mfa = sum(1 for u in filtered if not u.get("mfa"))
    mfa_total = len(filtered)
    mfa_adoption = round(((mfa_total - no_mfa) / mfa_total * 100), 1) if mfa_total > 0 else 0

    critical = by_severity.get("critical", 0)
    high = by_severity.get("high", 0)
    medium = by_severity.get("medium", 0)

    # ── Page context ──
    page_ctx = iam_page_context(summary)
    page_ctx["tabs"] = [
        {"id": "overview", "label": "Overview", "count": len(filtered)},
        {"id": "roles", "label": "Roles & Policies", "count": len(roles)},
        {"id": "access_keys", "label": "Access Control", "count": len(access_keys)},
        {"id": "privilege_escalation", "label": "Privilege Escalation", "count": len(priv_esc)},
    ]

    return {
        "pageContext": page_ctx,
        "filterSchema": iam_filter_schema(list(by_module.keys())),
        "kpiGroups": [
            {
                "title": "Identity Risk",
                "items": [
                    {"label": "Critical", "value": critical},
                    {"label": "High", "value": high},
                    {"label": "Medium", "value": medium},
                    {"label": "Posture Score", "value": posture_score, "suffix": "/100"},
                    {"label": "Total Findings", "value": safe_get(summary, "total_findings") or len(raw_findings)},
                ],
            },
            {
                "title": "Access Hygiene",
                "items": [
                    {"label": "MFA Adoption", "value": mfa_adoption, "suffix": "%"},
                    {"label": "Keys to Rotate", "value": len(access_keys)},
                    {"label": "Overprivileged", "value": by_module.get("least_privilege", 0)},
                    {"label": "Identities", "value": len(filtered)},
                    {"label": "Modules", "value": len(by_module)},
                ],
            },
        ],
        "findingsByModule": by_module,
        "byAccount": safe_get(summary, "by_account", []),
        "byRegion": safe_get(summary, "by_region", []),
        "identities": filtered,
        "roles": roles,
        "accessKeys": access_keys,
        "privilegeEscalation": priv_esc,
        "serviceAccounts": svc_accounts,
    }
