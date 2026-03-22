"""BFF view: /iam page.

Single call to IAM engine /ui-data (was 2 calls to findings + modules).
Engine /ui-data returns pre-organized: summary, modules, findings,
roles, access_keys, privilege_escalation, service_accounts.
"""

from typing import Optional, Dict, Any

from fastapi import APIRouter, Query

from ._shared import fetch_many, safe_get
from ._transforms import (
    group_iam_findings_to_identities, normalize_iam_role,
    normalize_access_key, normalize_privilege_escalation,
    normalize_service_account, apply_global_filters, _safe_upper,
)

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
    """BFF view for /iam page — single endpoint for entire page."""
    effective_csp = csp or (provider.lower() if provider else "aws")

    results = await fetch_many([
        ("iam", "/api/v1/iam-security/ui-data", {
            "tenant_id": tenant_id, "csp": effective_csp, "scan_id": scan_id,
        }),
    ])

    data = results[0] or {}

    summary = safe_get(data, "summary", {})
    by_module = safe_get(summary, "by_module", {})

    # Identities — group raw findings into identity rows
    raw_findings = safe_get(data, "findings", [])
    identities = group_iam_findings_to_identities(raw_findings)
    filtered = apply_global_filters(identities, provider, account, region)

    # Roles — normalize from engine-provided roles
    raw_roles = safe_get(data, "roles", [])
    roles = [normalize_iam_role(r) for r in raw_roles]

    # Access keys
    raw_keys = safe_get(data, "access_keys", [])
    access_keys = [normalize_access_key(k) for k in raw_keys]

    # Privilege escalation
    raw_priv = safe_get(data, "privilege_escalation", [])
    priv_esc = [normalize_privilege_escalation(p) for p in raw_priv]

    # Service accounts
    raw_svc = safe_get(data, "service_accounts", [])
    svc_accounts = [normalize_service_account(s) for s in raw_svc]

    # KPI derivation
    over_privileged = sum(1 for u in filtered if u.get("policies", 0) > 5 or u.get("risk_score", 0) >= 75)
    no_mfa = sum(1 for u in filtered if not u.get("mfa"))
    mfa_total = len(filtered)
    mfa_adoption = round(((mfa_total - no_mfa) / mfa_total * 100), 1) if mfa_total > 0 else 0
    wildcard_roles = sum(1 for r in roles if r.get("wildcard"))
    inactive = sum(1 for u in filtered if u.get("status") == "inactive")

    total_perms = sum(r.get("permissions", 0) for r in roles)
    unused_perms = safe_get(summary, "unused_permissions", 0)
    unused_pct = round((unused_perms / total_perms * 100), 1) if total_perms > 0 else 0

    risk_score = safe_get(summary, "risk_score", 0)
    if not risk_score and filtered:
        sev_w = {"critical": 90, "high": 70, "medium": 45, "low": 20}
        total_w = sum(sev_w.get("medium", 45) for _ in filtered)
        risk_score = min(100, round(total_w / max(len(filtered), 1)))

    return {
        "kpi": {
            "totalIdentities": safe_get(summary, "total_findings") or len(filtered),
            "overPrivileged": by_module.get("privilege_escalation") or over_privileged,
            "noMfa": by_module.get("mfa_disabled") or by_module.get("mfa") or no_mfa,
            "inactive": by_module.get("inactive_accounts") or inactive,
            "mfaAdoption": mfa_adoption,
            "keysToRotate": len(access_keys),
            "wildcardRoles": wildcard_roles,
            "unusedPermissionsPct": unused_pct,
        },
        "riskScore": risk_score,
        "findingsByModule": by_module,
        "identities": filtered,
        "roles": roles,
        "accessKeys": access_keys,
        "privilegeEscalation": priv_esc,
        "serviceAccounts": svc_accounts,
    }
