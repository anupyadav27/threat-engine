"""BFF view: /iam page.

Primary:  engine-iam /api/v1/iam-security/ui-data
Fallback: engine-check /api/v1/check/findings?domain=identity_and_access_management

IAM findings from the check engine are grouped into identity rows using the
existing group_iam_findings_to_identities() transform.
"""

from typing import Optional

from fastapi import APIRouter, Query

from ._shared import fetch_many, fetch_all_check_findings, safe_get, mock_fallback, is_empty_or_health
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

    # ── Fallback: use check engine filtered by IAM domain ──────────────────
    if is_empty_or_health(data):
        check_raw = await fetch_all_check_findings({
            "tenant_id": tenant_id,
            "domain": "identity_and_access_management",
        })
        if check_raw:
            # check findings feed straight into the same grouping transform
            data = {"findings": check_raw, "summary": {}}
        else:
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

    roles        = [normalize_iam_role(r)                for r in safe_get(data, "roles",                [])]
    access_keys  = [normalize_access_key(k)              for k in safe_get(data, "access_keys",          [])]
    priv_esc     = [normalize_privilege_escalation(p)    for p in safe_get(data, "privilege_escalation", [])]
    svc_accounts = [normalize_service_account(s)         for s in safe_get(data, "service_accounts",     [])]

    # When falling back from check engine, derive roles/keys/privesc from raw findings
    if not roles and raw_findings:
        role_findings = [f for f in raw_findings
                         if 'role' in (f.get('resource_type') or '').lower()
                         or 'role' in (f.get('resource_uid')  or '').lower()]
        roles = [normalize_iam_role(f) for f in role_findings]

    if not access_keys and raw_findings:
        key_findings = [f for f in raw_findings
                        if 'access' in (f.get('rule_id') or '').lower()
                        or 'key'    in (f.get('rule_id') or '').lower()]
        access_keys = [normalize_access_key(f) for f in key_findings]

    if not priv_esc and raw_findings:
        pe_findings = [f for f in raw_findings
                       if 'priv' in (f.get('rule_id') or '').lower()
                       or 'escalat' in (f.get('rule_id') or '').lower()
                       or 'passrole' in (f.get('rule_id') or '').lower()]
        priv_esc = [normalize_privilege_escalation(f) for f in pe_findings]

    # ── Derived metrics ──
    posture_score = safe_get(summary, "posture_score", 0) or safe_get(summary, "risk_score", 0)
    if not posture_score and filtered:
        sev_weights = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        total_weight = sum(sev_weights.get((f.get("severity") or "low").lower(), 1) for f in filtered)
        max_weight   = len(filtered) * 4
        posture_score = max(0, 100 - round((total_weight / max_weight) * 100)) if max_weight else 100

    no_mfa     = sum(1 for u in filtered if not u.get("mfa"))
    mfa_total  = len(filtered)
    mfa_adoption = round(((mfa_total - no_mfa) / mfa_total * 100), 1) if mfa_total > 0 else 0

    # by_severity from check fallback
    if not by_severity and raw_findings:
        for f in raw_findings:
            sev = (f.get("severity") or "medium").lower()
            by_severity[sev] = by_severity.get(sev, 0) + 1

    critical = by_severity.get("critical", 0)
    high     = by_severity.get("high",     0)
    medium   = by_severity.get("medium",   0)

    # ── Page context ──
    page_ctx = iam_page_context(summary)
    page_ctx["tabs"] = [
        {"id": "overview",              "label": "Overview"                                          },
        {"id": "findings",              "label": "Findings",              "count": len(raw_findings)  },
        {"id": "roles",                 "label": "Roles & Policies",      "count": len(roles)        },
        {"id": "access_keys",           "label": "Access Control",        "count": len(access_keys)  },
        {"id": "privilege_escalation",  "label": "Privilege Escalation",  "count": len(priv_esc)     },
    ]

    return {
        "pageContext":       page_ctx,
        "filterSchema":     iam_filter_schema(list(by_module.keys())),
        "kpiGroups": [
            {
                "title": "Identity Risk",
                "items": [
                    {"label": "Critical",       "value": critical                                              },
                    {"label": "High",           "value": high                                                  },
                    {"label": "Medium",         "value": medium                                                },
                    {"label": "Posture Score",  "value": posture_score, "suffix": "/100"                      },
                    {"label": "Total Findings", "value": safe_get(summary, "total_findings") or len(raw_findings)},
                ],
            },
            {
                "title": "Access Hygiene",
                "items": [
                    {"label": "MFA Adoption",  "value": mfa_adoption,                        "suffix": "%"},
                    {"label": "Keys to Rotate","value": len(access_keys)                                   },
                    {"label": "Overprivileged","value": by_module.get("least_privilege", 0)                },
                    {"label": "Identities",    "value": len(filtered)                                      },
                    {"label": "Modules",       "value": len(by_module) or len(set(
                        (f.get("service") or "") for f in raw_findings if f.get("service")
                    ))},
                ],
            },
        ],
        "findingsByModule":    by_module,
        "byAccount":           safe_get(summary, "by_account",         []),
        "byRegion":            safe_get(summary, "by_region",          []),
        "identities":          filtered,
        "findings":            raw_findings,
        "roles":               roles,
        "accessKeys":          access_keys,
        "privilegeEscalation": priv_esc,
        "serviceAccounts":     svc_accounts,
        "scanTrend":           safe_get(data, "scan_trend",            []),
    }
