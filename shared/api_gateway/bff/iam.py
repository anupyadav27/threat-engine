"""BFF view: /iam page — single findings source.

Primary:  engine-iam /api/v1/iam-security/ui-data
Fallback: engine-check /api/v1/check/findings?domain=identity_and_access_management

All three UI tabs (What is Broken / Who is Risky / What Paths Exist) are driven
from a single flat findings list.  The BFF enriches each finding with:
  - iam_module       (routing key, e.g. "role_management", "least_privilege")
  - identity_name    (top-level shorthand for the affected identity)
  - title            (flattened from finding_data)
  - description      (flattened from finding_data)
  - remediation      (flattened from finding_data)
  - technique        (privesc findings only, from finding_data or rule_id)
  - target_privilege (privesc findings only)

Non-IAM findings are filtered out so the page only shows identity-related issues.
"""

from typing import Optional

from fastapi import APIRouter, Query, Request

from ._auth import resolve_tenant_id
from ._shared import fetch_many, fetch_all_check_findings, safe_get, is_empty_or_health, read_findings
from ._cache import cache_key, cached_view, TTL_IAM, auth_level_from_header
from ._transforms import _get_iam_module
from ._page_context import iam_page_context, iam_filter_schema
from ._common_schemas import IamViewResponse

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])

# Signals that a finding belongs to the IAM/identity domain.
_IAM_DOMAINS   = {"identity_and_access_management", "iam", "identity", "access_management"}
_IAM_SERVICES  = {"iam", "identity", "accessanalyzer", "sso", "sts", "cognito", "directoryservice", "organizations"}
_IAM_RULE_KEYS = ("iam_", "role_", "access_key", "mfa", "password_policy", "privilege", "passrole", "assume_role", "sso_", "service_account")
_IAM_RES_TYPES = ("role", "user", "group", "policy", "access_key", "service_account", "identity", "principal")
_IAM_MODULES   = {"role_management", "access_keys", "mfa", "password_policy", "least_privilege", "service_accounts", "access_control"}


def _is_iam_finding(f: dict) -> bool:
    domain  = (f.get("domain")         or "").lower()
    service = (f.get("service")        or "").lower()
    rule_id = (f.get("rule_id")        or "").lower()
    rtype   = (f.get("resource_type")  or "").lower()
    module  = f.get("iam_module")       or ""

    if any(d in domain  for d in _IAM_DOMAINS):   return True
    if any(s in service for s in _IAM_SERVICES):   return True
    if module in _IAM_MODULES:                      return True
    if any(k in rule_id for k in _IAM_RULE_KEYS):  return True
    if any(k in rtype   for k in _IAM_RES_TYPES):  return True
    return False


def _enrich_finding(f: dict) -> dict:
    """Flatten finding_data fields onto the top-level finding dict in-place."""
    fd = f.get("finding_data") or {}

    if not f.get("title"):
        f["title"] = (fd.get("title") or fd.get("rule_title") or
                      (fd.get("rule_description") or "")[:80] or f.get("rule_id", ""))

    if not f.get("description"):
        f["description"] = fd.get("description") or fd.get("rule_description", "")

    if not f.get("remediation"):
        rem = fd.get("remediation", "")
        if isinstance(rem, dict):
            rem = rem.get("summary") or " ".join(rem.get("steps", [])) or ""
        f["remediation"] = rem

    # identity_name for grouping "Who is Risky?" in the UI
    if not f.get("identity_name"):
        f["identity_name"] = (fd.get("identity_name") or f.get("resource_id") or
                              (f.get("resource_uid") or "").rsplit("/", 1)[-1])

    # Extra fields for "What Paths Exist?" (iam_module == least_privilege)
    if f.get("iam_module") == "least_privilege":
        rule_id_lower = (f.get("rule_id") or "").lower()
        f.setdefault("technique", fd.get("technique") or (
            "PassRole Abuse"   if "passrole" in rule_id_lower else
            "AssumeRole Chain" if "assume"   in rule_id_lower else
            "Privilege Escalation"
        ))
        f.setdefault("target_privilege", fd.get("target_privilege") or fd.get("privilege_level") or "Administrator")

    return f


@router.get("/iam", response_model=IamViewResponse, response_model_exclude_none=False)
async def view_iam(
    request: Request,
    provider: Optional[str] = Query(None),
    account: Optional[str] = Query(None),
    tenant_ids: Optional[str] = Query(None),
    account_ids: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
    csp: str = Query("aws"),
    scan_id: str = Query("latest"),
):
    tenant_id = resolve_tenant_id(request)
    effective_csp = csp or (provider.lower() if provider else "aws")

    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None
    role_level = auth_level_from_header(auth_ctx_header)

    ck = cache_key("iam", tenant_id, scan_id, effective_csp, provider or "", account or "", region or "", role_level=role_level)
    cached = cached_view(ck)
    if cached is not None:
        return cached

    results = await fetch_many([
        ("iam", "/api/v1/iam-security/ui-data", {
            "tenant_id": tenant_id, "csp": effective_csp, "scan_id": scan_id,
        }),
    ], auth_headers=fwd_headers)

    data = results[0] or {}

    # ── Fallback: check engine filtered by IAM domain ──
    if is_empty_or_health(data):
        check_raw = await fetch_all_check_findings({
            "tenant_id": tenant_id,
            "domain": "identity_and_access_management",
        }, auth_headers=fwd_headers)
        if check_raw:
            data = {"findings": check_raw, "summary": {}}

    summary    = safe_get(data, "summary", {})
    by_module  = safe_get(summary, "by_module", {})
    by_severity = safe_get(summary, "by_severity", {})

    # ── Build single findings list ──
    raw = safe_get(data, "findings", [])

    # Enrich, classify module, filter to IAM-only
    findings: list = []
    for f in raw:
        if not f.get("iam_module"):
            f["iam_module"] = _get_iam_module(f)
        _enrich_finding(f)
        if _is_iam_finding(f):
            findings.append(f)

    # Apply global provider/account/region filters
    if provider or account or region:
        findings = [
            f for f in findings
            if (not provider or (f.get("provider") or "").lower() == provider.lower())
            and (not account  or f.get("account_id") == account)
            and (not region   or f.get("region") == region)
        ]

    # ── Second-chance fallback from security_findings table ──
    if not findings:
        sf = read_findings(tenant_id=tenant_id, source_engines=["iam"], limit=500)
        if sf["total"] > 0:
            for f in sf["findings"]:
                if not f.get("iam_module"):
                    f["iam_module"] = _get_iam_module(f)
                _enrich_finding(f)
            findings = sf["findings"]

    # ── Compute metrics from flat findings ──
    if not by_severity:
        for f in findings:
            sev = (f.get("severity") or "medium").lower()
            by_severity[sev] = by_severity.get(sev, 0) + 1

    critical = by_severity.get("critical", 0)
    high     = by_severity.get("high",     0)
    medium   = by_severity.get("medium",   0)

    posture_score = safe_get(summary, "posture_score", 0) or safe_get(summary, "risk_score", 0)
    if not posture_score and findings:
        sev_weights  = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        total_weight = sum(sev_weights.get((f.get("severity") or "low").lower(), 1) for f in findings)
        max_weight   = len(findings) * 4
        posture_score = max(0, 100 - round((total_weight / max_weight) * 100)) if max_weight else 100

    # Unique identities and MFA
    identity_names = {f.get("identity_name", "") for f in findings if f.get("identity_name")}
    identity_count = len(identity_names)
    no_mfa_ids = {
        f.get("identity_name", "") for f in findings
        if "mfa" in (f.get("rule_id") or "").lower() and f.get("identity_name")
    }
    mfa_adoption = round(((identity_count - len(no_mfa_ids)) / identity_count * 100), 1) if identity_count > 0 else 100
    keys_count   = sum(1 for f in findings if f.get("iam_module") == "access_keys")
    privesc_count = sum(1 for f in findings if f.get("iam_module") == "least_privilege")

    # ── Page context ──
    page_ctx = iam_page_context(summary)
    page_ctx["tabs"] = [
        {"id": "findings",             "label": "What is Broken?",   "count": len(findings)   },
        {"id": "identities",           "label": "Who is Risky?",     "count": identity_count  },
        {"id": "privilege_escalation", "label": "What Paths Exist?", "count": privesc_count   },
    ]

    result = {
        "pageContext":   page_ctx,
        "filterSchema":  iam_filter_schema(list(by_module.keys())),
        "kpiGroups": [
            {
                "title": "Identity Risk",
                "items": [
                    {"label": "Critical",       "value": critical                                               },
                    {"label": "High",           "value": high                                                   },
                    {"label": "Medium",         "value": medium                                                 },
                    {"label": "Posture Score",  "value": posture_score, "suffix": "/100"                       },
                    {"label": "Total Findings", "value": safe_get(summary, "total_findings") or len(findings)  },
                ],
            },
            {
                "title": "Access Hygiene",
                "items": [
                    {"label": "MFA Adoption",  "value": mfa_adoption,  "suffix": "%"},
                    {"label": "Keys to Rotate","value": keys_count                  },
                    {"label": "Overprivileged","value": privesc_count               },
                    {"label": "Identities",    "value": identity_count              },
                    {"label": "Modules",       "value": len({f.get("iam_module") for f in findings if f.get("iam_module")})},
                ],
            },
        ],
        "findingsByModule": by_module,
        "byAccount":        safe_get(summary, "by_account", []),
        "byRegion":         safe_get(summary, "by_region",  []),
        "findings":         findings,
        "scanTrend":        safe_get(data, "scan_trend", []),
    }

    cached_view(ck, result, ttl=TTL_IAM)
    return result
