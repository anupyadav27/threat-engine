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
async def view_policies(
    request: Request,
    provider: str = Query(None),
    severity: str = Query(None),
    service: str = Query(None),
):
    """Security policies view — check rules mapped to policy management UI."""
    tenant_id = resolve_tenant_id(request)
    auth_ctx_header = (
        request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    )
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None
    meta = BFFMeta("policies")

    catalog_params: dict = {"limit": 500, "rule_type": "config"}
    if provider:
        catalog_params["provider"] = provider
    if severity:
        catalog_params["severity"] = severity
    if service:
        catalog_params["service"] = service

    summary_params: dict = {"tenant_id": tenant_id}
    if provider:
        summary_params["provider"] = provider

    results = await fetch_many(
        [
            ("check", "/api/v1/check/rules/catalog", catalog_params),
            ("check", "/api/v1/check/findings/summary", summary_params),
        ],
        auth_headers=fwd_headers,
    )

    catalog_data  = results[0] or {}
    summary_data  = results[1] or {}
    meta.record_engine("check", "/api/v1/check/rules/catalog",    catalog_data)
    meta.record_engine("check", "/api/v1/check/findings/summary", summary_data)

    raw_rules  = safe_get(catalog_data,  "rules", [])
    top_rules  = safe_get(summary_data,  "top_rules", [])
    sev_counts = safe_get(summary_data,  "severity_counts", {})
    status_counts = safe_get(summary_data, "status_counts", {})

    # Build violation map: rule_id → FAIL count
    violation_map: dict = {}
    for r in top_rules:
        rid = r.get("rule_id") or r.get("id", "")
        if rid:
            violation_map[rid] = r.get("cnt") or r.get("count") or r.get("fail_count") or 0

    # Service → UI category mapping
    _SERVICE_CATEGORY: dict = {
        "iam": "IAM", "identity": "IAM", "s3": "Storage", "storage": "Storage",
        "ec2": "Compute", "compute": "Compute", "vpc": "Network", "network": "Network",
        "rds": "Database", "database": "Database", "lambda": "Compute", "kms": "Encryption",
        "cloudtrail": "Logging", "logging": "Logging", "eks": "Container Security",
        "k8s": "Container Security", "container": "Container Security", "waf": "Network",
        "elb": "Network", "elasticloadbalancing": "Network", "route53": "Network",
        "sagemaker": "Compute", "bedrock": "Compute", "emr": "Compute",
        "redshift": "Database", "dynamodb": "Database", "elasticsearch": "Database",
        "sns": "Compute", "sqs": "Compute", "secretsmanager": "Encryption",
        "acm": "Encryption", "cloudfront": "Network",
    }

    def _category(svc: str) -> str:
        low = (svc or "").lower()
        return _SERVICE_CATEGORY.get(low, svc.title() if svc else "General")

    # Overall pass/fail totals
    total_pass = status_counts.get("PASS", 0)
    total_fail = status_counts.get("FAIL", 0)
    total_evals = total_pass + total_fail
    overall_pass_rate = round((total_pass / total_evals) * 100, 1) if total_evals > 0 else 100.0

    from datetime import datetime, timezone as _tz
    today = datetime.now(_tz.utc).strftime("%Y-%m-%d")

    policies: list = []
    for rule in raw_rules:
        rule_id   = rule.get("rule_id") or rule.get("id", "")
        title     = rule.get("title") or rule_id
        svc       = rule.get("service") or rule.get("resource_service") or ""
        prov      = rule.get("provider") or "aws"
        sev       = rule.get("severity") or "medium"
        domain    = rule.get("domain") or ""
        violations = violation_map.get(rule_id, 0)

        fw_raw = rule.get("compliance_frameworks") or []
        if isinstance(fw_raw, str):
            frameworks = [f.strip() for f in fw_raw.split(",") if f.strip()]
        elif isinstance(fw_raw, list):
            frameworks = [str(f) for f in fw_raw if f]
        else:
            frameworks = []

        if violations > 0:
            evaluations = violations * 2
            pass_rate = round(max(0, (evaluations - violations) / evaluations * 100), 1)
        else:
            evaluations = 0
            pass_rate = 100.0

        policies.append({
            "id":             rule_id,
            "name":           title,
            "category":       _category(svc),
            "severity":       sev,
            "provider":       prov,
            "status":         "active",
            "evaluations":    evaluations,
            "violations":     violations,
            "pass_rate":      pass_rate,
            "auto_remediate": False,
            "frameworks":     frameworks[:5],
            "last_updated":   today,
            "description":    rule.get("description") or "",
            "service":        svc,
            "domain":         domain,
            "exceptions":     [],
            "version_history": [],
        })

    _SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    policies.sort(key=lambda p: (-p["violations"], _SEV_ORDER.get(p["severity"], 9), p["name"]))

    failing_count = sum(1 for p in policies if p["violations"] > 0)

    return {
        "policies": policies,
        "kpi": {
            "total":      len(policies),
            "active":     len(policies),
            "failing":    failing_count,
            "pass_rate":  overall_pass_rate,
            "by_severity": sev_counts,
        },
        "filterSchema": [
            {"key": "category", "label": "Category", "type": "enum",
             "values": sorted(set(p["category"] for p in policies))},
            {"key": "severity", "label": "Severity", "type": "enum",
             "values": ["critical", "high", "medium", "low"]},
            {"key": "provider", "label": "Provider", "type": "enum",
             "values": sorted(set(p["provider"] for p in policies))},
            {"key": "status", "label": "Status", "type": "enum",
             "values": ["active", "draft"]},
        ],
        "_meta": meta.to_dict(),
    }
