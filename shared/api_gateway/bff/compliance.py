"""BFF view: /compliance page.

Consolidates into 3 parallel calls (compliance/ui-data + onboarding/ui-data + threat/ui-data).
Adds resilience: score computation from passed/failed ratio, trend fallback,
framework score derivation when engine returns all zeros.
"""

from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

from fastapi import APIRouter, Query, Request

from ._auth import resolve_tenant_id
from ._shared import fetch_many, safe_get
from ._transforms import normalize_framework, normalize_failing_control
from ._page_context import compliance_page_context, compliance_filter_schema
from ._cache import cache_key, cached_view, TTL_COMPLIANCE, auth_level_from_header
from ._common_schemas import ComplianceViewResponse
router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])

MATRIX_FRAMEWORKS = ["CIS", "NIST", "SOC2", "PCI", "HIPAA", "ISO", "GDPR"]


@router.get("/compliance", response_model=ComplianceViewResponse, response_model_exclude_none=False)
async def view_compliance(
    request: Request,
    provider: Optional[str] = Query(None),
    account: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
    scan_run_id: str = Query("latest"),
):
    """Single endpoint returning everything the compliance page needs."""

    tenant_id = resolve_tenant_id(request)
    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None
    role_level = auth_level_from_header(auth_ctx_header)

    ck = cache_key("compliance", tenant_id, scan_run_id, provider or "", account or "", region or "", role_level=role_level)
    cached = cached_view(ck)
    if cached is not None:
        return cached

    # ── 4 parallel calls ───────────────────────────────────────────────────
    results = await fetch_many([
        ("compliance", "/api/v1/compliance/ui-data", {"tenant_id": tenant_id, "scan_id": "latest"}),
        ("compliance", "/api/v1/compliance/frameworks/summary", {"tenant_id": tenant_id}),
        ("onboarding", "/api/v1/cloud-accounts", {"tenant_id": tenant_id}),
        ("threat",     "/api/v1/threat/ui-data",     {"tenant_id": tenant_id, "scan_run_id": "latest", "limit": "1"}),
    ], auth_headers=fwd_headers)

    compliance_data, all_frameworks_data, onboarding_data, threat_data = results

    # Safely unwrap responses
    compliance_data = compliance_data if isinstance(compliance_data, dict) else {}
    all_frameworks_data = all_frameworks_data if isinstance(all_frameworks_data, dict) else {}
    onboarding_data = onboarding_data if isinstance(onboarding_data, dict) else {}
    threat_data = threat_data if isinstance(threat_data, dict) else {}

    # ── Normalize frameworks — prefer all_frameworks (multi-CSP) ──────────
    all_fw_list = all_frameworks_data.get("frameworks", [])
    if all_fw_list:
        # Use the comprehensive frameworks list (includes CSP-specific CIS, all 23 frameworks)
        frameworks = []
        for fw in all_fw_list:
            frameworks.append({
                "id": fw.get("id") or fw.get("framework_id", ""),
                "name": fw.get("name") or fw.get("framework_name", ""),
                "version": fw.get("version"),
                "authority": fw.get("authority"),
                "category": fw.get("category"),
                "provider": fw.get("provider", "multi"),
                "score": fw.get("score", 0),
                "controls": fw.get("total_controls", 0),
                "passed": fw.get("passed", 0),
                "failed": fw.get("failed", 0),
                "findings": fw.get("findings", 0),
                "failing_controls": fw.get("failed", 0),
                "has_assessment": fw.get("has_assessment", False),
                "last_assessed": fw.get("last_assessed"),
            })
    else:
        # Fallback to compliance_data frameworks
        fw_list = compliance_data.get("frameworks", [])
        if not isinstance(fw_list, list):
            fw_list = []
        frameworks = [normalize_framework(fw) for fw in fw_list if isinstance(fw, dict)]
        for fw in frameworks:
            if "failing_controls" not in fw:
                fw["failing_controls"] = fw.get("failed", 0)

    # Drop degenerate rows where both id AND name are empty
    frameworks = [fw for fw in frameworks if fw.get("id") or fw.get("name")]

    # Ensure failing_controls is set on every framework object
    for fw in frameworks:
        if "failing_controls" not in fw:
            fw["failing_controls"] = fw.get("failed", 0)

    # When engine has findings but no assessment (compliance_assessments empty),
    # the engine returns passed=0, failed=0 even though findings > 0.
    # Promote findings count to failed so the frontend can show "assessed" status.
    for fw in frameworks:
        if fw.get("passed", 0) == 0 and fw.get("failed", 0) == 0 and fw.get("findings", 0) > 0:
            fw["failed"] = fw["findings"]
            fw["has_assessment"] = True

    # If all scores are 0, derive from passed/failed
    all_zero = all(fw.get("score", 0) == 0 for fw in frameworks) if frameworks else True
    if all_zero and frameworks:
        for fw in frameworks:
            passed  = fw.get("passed", 0)
            failed  = fw.get("failed", 0)
            total_c = passed + failed
            if total_c > 0:
                fw["score"] = round((passed / total_c) * 100, 1)

    # If no frameworks at all, try building from raw strings
    if not frameworks and isinstance(fw_list, list):
        for fw in fw_list:
            if isinstance(fw, str) and fw:
                frameworks.append({"id": fw, "name": fw, "score": 0, "controls": 0, "passed": 0, "failed": 0, "last_assessed": None})

    # ── Overall score -- multi-level fallback ────────────────────────────
    overall_score = compliance_data.get("overall_score", 0)
    if not overall_score and frameworks:
        scores = [fw["score"] for fw in frameworks if fw.get("score", 0) > 0]
        if scores:
            overall_score = round(sum(scores) / len(scores), 1)

    passed_total = sum(fw.get("passed", 0) for fw in frameworks)
    failed_total = sum(fw.get("failed", 0) for fw in frameworks)
    total_controls = passed_total + failed_total
    pass_rate = (passed_total / total_controls * 100) if total_controls > 0 else 0

    # Use posture_summary totals if framework-level totals are empty
    if total_controls == 0:
        posture = compliance_data.get("posture_summary", {})
        if isinstance(posture, dict):
            passed_total = posture.get("controls_passed", 0)
            failed_total = posture.get("controls_failed", 0)
            total_controls = posture.get("total_controls", 0) or (passed_total + failed_total)
            if total_controls > 0:
                pass_rate = (passed_total / total_controls * 100)

    if not overall_score and total_controls > 0:
        overall_score = round(pass_rate, 1)

    # ── Failing controls ─────────────────────────────────────────────────
    raw_fc = compliance_data.get("failing_controls", [])
    if not isinstance(raw_fc, list):
        raw_fc = []
    failing = [normalize_failing_control(c) for c in raw_fc]

    # Fallback: derive from threat summary by_category
    if not failing:
        threat_summary = threat_data.get("summary", {})
        if isinstance(threat_summary, dict):
            by_cat = threat_summary.get("by_category", {})
            if not by_cat:
                by_cat = threat_summary.get("threats_by_category", {})
            if isinstance(by_cat, dict):
                for cat, count in by_cat.items():
                    if isinstance(count, int) and count > 0:
                        failing.append({
                            "control_id": cat, "title": cat.replace("_", " ").title(),
                            "framework": "CIS", "account": "", "region": "",
                            "severity": "high" if count > 10 else "medium",
                            "total_failed": count, "days_open": 0,
                        })

    # ── Trend data -- with synthetic fallback ────────────────────────────
    trend_data_raw = compliance_data.get("trends", [])
    if not isinstance(trend_data_raw, list):
        trend_data_raw = []
    trend_data_out = trend_data_raw

    # If no trend data but we have a current score, return a single data point
    if not trend_data_out and overall_score and overall_score > 0:
        now = datetime.now(timezone.utc)
        trend_data_out = [{"date": now.strftime("%Y-%m-%d"), "score": round(overall_score, 1)}]

    exceptions: List[dict] = compliance_data.get("exceptions", []) or []

    audit_deadlines: List[dict] = compliance_data.get("audit_deadlines", []) or []

    # ── Matrix key mapping: framework_id (snake_case) → MATRIX_FRAMEWORKS key ──
    _FW_KEY_MAP: Dict[str, str] = {}
    for mk in MATRIX_FRAMEWORKS:
        _FW_KEY_MAP[mk.lower()] = mk                     # exact match (e.g. "cis" → "CIS")
    # Common full IDs emitted by the engine
    _KNOWN_FW_IDS: Dict[str, str] = {
        "cis_aws":          "CIS",  "cis_aws_1_2":      "CIS",  "cis_aws_1_4":      "CIS",
        "cis_aws_1_5":      "CIS",  "cis_benchmark":    "CIS",
        "nist_csf_1_1":     "NIST", "nist_800_53":      "NIST", "nist_sp_800_53":   "NIST",
        "soc2_type2":       "SOC2", "soc2_type1":       "SOC2", "soc_2":            "SOC2",
        "pci_dss_3_2_1":    "PCI",  "pci_dss_4_0":      "PCI",  "pci_dss":          "PCI",
        "hipaa_security":   "HIPAA","hipaa":             "HIPAA",
        "iso_27001_2013":   "ISO",  "iso_27001_2022":   "ISO",  "iso_27001":        "ISO",
        "gdpr":             "GDPR", "gdpr_2016_679":    "GDPR",
    }

    def _normalize_fw_key(raw_key: str) -> Optional[str]:
        """Map a raw framework_id to a MATRIX_FRAMEWORKS key."""
        low = raw_key.lower().replace("-", "_")
        if low in _KNOWN_FW_IDS:
            return _KNOWN_FW_IDS[low]
        for mk in MATRIX_FRAMEWORKS:
            if mk.lower() in low or low.startswith(mk.lower()):
                return mk
        return None

    # Per-account score lookup (from compliance ui-data if available)
    # Engine now returns: [{account_id, nist_csf_1_1: 75.0, iso_27001_2013: 68.0, ...}, ...]
    per_account_scores: Dict[str, dict] = {}
    for entry in compliance_data.get("per_account_scores", []):
        acct_id = entry.get("account_id", "")
        if not acct_id:
            continue
        normalized: Dict[str, Any] = {"account_id": acct_id}
        for key, val in entry.items():
            if key == "account_id":
                continue
            mk = _normalize_fw_key(key)
            if mk and isinstance(val, (int, float)):
                normalized[mk] = round(float(val), 1)
        per_account_scores[acct_id] = normalized

    # ── Account compliance matrix ────────────────────────────────────────
    raw_accounts = onboarding_data.get("accounts", [])
    if not isinstance(raw_accounts, list):
        raw_accounts = []
    # If no accounts from onboarding, build from compliance data account breakdown
    if not raw_accounts:
        seen_accounts = set()
        for fc in failing:
            aid = fc.get("account") or fc.get("account_id")
            if aid and aid not in seen_accounts:
                seen_accounts.add(aid)
                raw_accounts.append({"account_id": aid, "account_name": aid, "provider": "aws"})
        # Also try extracting from per_account_scores
        for aid in per_account_scores:
            if aid not in seen_accounts:
                seen_accounts.add(aid)
                raw_accounts.append({"account_id": aid, "account_name": aid, "provider": "aws"})
        # Final fallback: if we have compliance data but no account info, use tenant as account
        if not raw_accounts and total_controls > 0:
            raw_accounts = [{"account_id": tenant_id, "account_name": tenant_id, "provider": "aws"}]
    account_matrix = []
    for acct in raw_accounts:
        acct_id = acct.get("account_id", "")
        acct_scores = per_account_scores.get(acct_id, {})
        prov = (acct.get("provider") or acct.get("csp") or "").upper()
        row: Dict[str, Any] = {
            "account": acct.get("account_name") or acct_id,
            "account_id": acct_id,
            "provider": prov,
            "environment": "production" if "prod" in (acct.get("account_name") or "").lower() else "development",
            "cred_expired": acct.get("cred_expired", False),
            "status": acct.get("status") or acct.get("account_status", "active"),
        }
        for fw_key in MATRIX_FRAMEWORKS:
            row[fw_key] = acct_scores.get(fw_key) or acct.get(fw_key) or None
        scores = [(row.get(k) or 0) for k in MATRIX_FRAMEWORKS if (row.get(k) or 0) > 0]
        row["avg"] = round(sum(scores) / len(scores), 1) if scores else 0
        account_matrix.append(row)

    if provider and isinstance(provider, str):
        provider_upper = provider.upper()
        account_matrix = [r for r in account_matrix if r.get("provider") == provider_upper]
    if account and isinstance(account, str):
        account_matrix = [r for r in account_matrix if r.get("account_id") == account or r.get("account") == account]

    critical_failures = sum(1 for c in failing if c.get("severity") == "critical")
    at_risk_count = sum(1 for fw in frameworks if fw.get("score", 0) < 70)

    page_ctx = compliance_page_context({})
    page_ctx["brief"] = f"{round(pass_rate, 1)}% pass rate — {passed_total} passed, {failed_total} failed across {len(frameworks)} frameworks"
    page_ctx["tabs"] = [
        {"id": "overview", "label": "Overview", "count": total_controls},
        {"id": "frameworks", "label": "Frameworks", "count": len(frameworks)},
        {"id": "controls", "label": "Failing Controls", "count": len(failing)},
        {"id": "matrix", "label": "Account Matrix", "count": len(account_matrix)},
    ]

    # -- Build config_checks and cdr_checks from failing controls -------------
    config_checks = []
    cdr_checks   = []
    for ctrl in failing:
        check_obj = {
            "check_id":     ctrl.get("control_id", ""),
            "control_id":   ctrl.get("control_id", ""),
            "control_name": ctrl.get("title", ""),
            "severity":     ctrl.get("severity", "medium"),
            "status":       "FAIL",
            "failing_count":ctrl.get("total_failed", 0),
            "provider":     ctrl.get("account", ""),
            "framework":    ctrl.get("framework", ""),
        }
        if "cdr" in ctrl.get("framework", "").lower() or "identity" in ctrl.get("title", "").lower():
            cdr_checks.append(check_obj)
        else:
            config_checks.append(check_obj)

    # -- filteredControls — normalized control list for UI table ---------------
    filtered_controls = [
        {
            "control_id":      c.get("control_id", ""),
            "control_name":    c.get("title", ""),
            "fail_count":      c.get("total_failed", 0),
            "failing_count":   c.get("total_failed", 0),
            "total_resources": c.get("total_resources") or c.get("total_tested", 0),
            "severity":        c.get("severity", "medium"),
            "status":          "FAIL" if c.get("total_failed", 0) > 0 else "PASS",
            "framework":       c.get("framework", ""),
            "account":         c.get("account", ""),
            "provider":        c.get("provider") or c.get("account", ""),
            "region":          c.get("region", ""),
            "days_open":       c.get("days_open", 0),
        }
        for c in failing
    ]

    # -- totals summary object ------------------------------------------------
    totals = {
        "score":    overall_score or round(pass_rate, 1),
        "passed":   passed_total,
        "failed":   failed_total,
        "controls": total_controls,
        "pass_rate":round(pass_rate, 1),
    }

    # -- modes (available display modes) -------------------------------------
    modes = [
        {"id": "frameworks", "label": "Frameworks"},
        {"id": "controls",   "label": "Controls"},
        {"id": "matrix",     "label": "Account Matrix"},
    ]

    result = {
        "pageContext": page_ctx,
        "filterSchema": compliance_filter_schema(),
        "kpiGroups": [
            {
                "title": "Compliance Posture",
                "items": [
                    {"label": "Overall Score", "value": overall_score or round(pass_rate, 1), "suffix": "%"},
                    {"label": "Pass Rate",     "value": round(pass_rate, 1), "suffix": "%"},
                    {"label": "Frameworks",    "value": len(frameworks)},
                    {"label": "At Risk",       "value": at_risk_count},
                ],
            },
            {
                "title": "Control Status",
                "items": [
                    {"label": "Total Controls", "value": total_controls},
                    {"label": "Passed",         "value": passed_total},
                    {"label": "Failed",         "value": failed_total},
                    {"label": "Critical Gaps",  "value": critical_failures},
                ],
            },
        ],
        "frameworks":       frameworks,
        "failingControls":  failing,
        "filteredControls": filtered_controls,
        "config_checks":    config_checks,
        "cdr_checks":      cdr_checks,
        "totals":           totals,
        "modes":            modes,
        "trendData":        trend_data_out,
        "auditDeadlines":   audit_deadlines,
        "exceptions":       exceptions,
        "accountMatrix":    account_matrix,
    }
    cached_view(ck, result, ttl=TTL_COMPLIANCE)
    return result


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# ── Matrix endpoint helpers ────────────────────────────────────────────────────

_PROVIDERS = ["aws", "azure", "gcp", "oci", "alicloud", "ibm", "k8s"]

# CIS framework_id prefix → CSP provider key
_CIS_PROVIDER: Dict[str, str] = {
    "cis_aws":         "aws",
    "cis_azure":       "azure",
    "cis_gcp":         "gcp",
    "cis_k8s":         "k8s",
    "cis_kubernetes":  "k8s",
    "cis_ibm":         "ibm",
    "cis_alicloud":    "alicloud",
    "cis_ali":         "alicloud",
    "cis_oci":         "oci",
    "cis_oracle":      "oci",
}

# Regulatory/universal framework_id prefix → matrix key (matches frontend FRAMEWORKS ids)
_REG_FW_KEY: Dict[str, str] = {
    "pci_dss":          "PCI_DSS",
    "hipaa":            "HIPAA",
    "gdpr":             "GDPR",
    "soc2":             "SOC2",
    "soc_2":            "SOC2",
    "iso_27001":        "ISO27001",
    "iso27001":         "ISO27001",
    "nist_csf":         "NIST",
    "nist_800_53":      "NIST",
    "nist_sp_800_53":   "NIST",
    "nist_800_171":     "NIST",
    "fedramp":          "FedRAMP",
    "canada_pbmm":      "CANADA_PBMM",
    "rbi_bank":         "RBI_BANK",
    "rbi_nbfc":         "RBI_NBFC",
    "cisa_ce":          "CISA_CE",
}


def _classify_fw(fw_id_raw: str):
    """Returns (matrix_key, cis_provider_or_None). Unknown → (None, None)."""
    low = fw_id_raw.lower().replace("-", "_")
    for prefix, prov in _CIS_PROVIDER.items():
        if low == prefix or low.startswith(prefix + "_"):
            return "CIS", prov
    if low.startswith("cis_"):
        for prov in _PROVIDERS:
            if prov in low:
                return "CIS", prov
        return "CIS", None
    for prefix, key in _REG_FW_KEY.items():
        if low == prefix or low.startswith(prefix + "_"):
            return key, None
    return None, None


@router.get("/compliance/matrix")
async def view_compliance_matrix(
    request: Request,
    view: str = Query("config"),
):
    """Multi-cloud compliance matrix: framework family × provider → score.

    CIS row: each CSP column shows its own CIS benchmark score.
    Regulatory rows: cross-cloud framework score per provider that has accounts.
    """
    tenant_id = resolve_tenant_id(request)
    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None

    results = await fetch_many([
        ("compliance", "/api/v1/compliance/frameworks/summary", {"tenant_id": tenant_id}),
        ("compliance", "/api/v1/compliance/ui-data",            {"tenant_id": tenant_id, "scan_id": "latest"}),
        ("onboarding", "/api/v1/cloud-accounts",                {"tenant_id": tenant_id}),
    ], auth_headers=fwd_headers)

    frameworks_data, compliance_data, onboarding_data = results
    frameworks_data  = frameworks_data  if isinstance(frameworks_data,  dict) else {}
    compliance_data  = compliance_data  if isinstance(compliance_data,  dict) else {}
    onboarding_data  = onboarding_data  if isinstance(onboarding_data,  dict) else {}

    fw_list          = frameworks_data.get("frameworks",        []) or []
    raw_accounts     = onboarding_data.get("accounts",          []) or []
    per_account_raw  = compliance_data.get("per_account_scores", []) or []

    # account_id → provider
    account_provider: Dict[str, str] = {}
    for acct in raw_accounts:
        if isinstance(acct, dict):
            aid  = acct.get("account_id", "")
            prov = (acct.get("provider") or acct.get("csp") or "").lower()
            if aid and prov in _PROVIDERS:
                account_provider[aid] = prov

    active_providers = set(account_provider.values())

    # matrix[fw_key][provider] = score
    # framework_ids[fw_key][provider] = original engine framework_id (for direct detail navigation)
    matrix: Dict[str, Dict[str, float]] = {}
    framework_ids: Dict[str, Dict[str, str]] = {}

    # Pass 1 — build from framework summary (global scores per framework)
    for fw in fw_list:
        if not isinstance(fw, dict):
            continue
        fw_id_raw = fw.get("id") or fw.get("framework_id") or ""
        score = fw.get("score") or 0
        if not score:
            passed = fw.get("passed") or 0
            failed = fw.get("failed") or 0
            total  = passed + failed
            score  = round((passed / total) * 100, 1) if total > 0 else None
        else:
            score = round(float(score), 1)

        if not score:
            continue

        fw_key, cis_provider = _classify_fw(fw_id_raw)
        if not fw_key:
            continue

        if fw_key not in matrix:
            matrix[fw_key] = {}
        if fw_key not in framework_ids:
            framework_ids[fw_key] = {}

        if cis_provider:
            # CIS: score in the specific CSP column only
            matrix[fw_key][cis_provider] = score
            framework_ids[fw_key][cis_provider] = fw_id_raw
        else:
            # Regulatory: apply to all providers that have active accounts
            for prov in (active_providers or _PROVIDERS):
                if prov not in matrix[fw_key]:
                    matrix[fw_key][prov] = score
                    framework_ids[fw_key][prov] = fw_id_raw

    # Pass 2 — refine with per-account scores for provider-level accuracy
    if per_account_raw:
        from collections import defaultdict
        prov_fw_scores: Dict[str, Dict[str, List[float]]] = defaultdict(lambda: defaultdict(list))

        for entry in per_account_raw:
            if not isinstance(entry, dict):
                continue
            acct_id = entry.get("account_id", "")
            acct_prov = account_provider.get(acct_id)
            if not acct_prov:
                continue
            for raw_key, val in entry.items():
                if raw_key == "account_id" or not isinstance(val, (int, float)):
                    continue
                fw_key, cis_provider = _classify_fw(raw_key)
                if not fw_key:
                    continue
                effective_prov = cis_provider if cis_provider else acct_prov
                prov_fw_scores[effective_prov][fw_key].append(float(val))

        for prov, fw_scores in prov_fw_scores.items():
            for fw_key, scores in fw_scores.items():
                if scores:
                    if fw_key not in matrix:
                        matrix[fw_key] = {}
                    matrix[fw_key][prov] = round(sum(scores) / len(scores), 1)

    return {"matrix": matrix, "frameworkIds": framework_ids}


@router.get("/compliance/remediation")
async def view_compliance_remediation(
    request: Request,
    provider: Optional[str] = Query(None),
    account: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    limit: int = Query(1000),
):
    """Remediation Queue — all failing controls sorted by severity.

    Returns the complete list of failing controls so the UI can paginate
    and filter client-side. bySeverity and totalFailing always reflect
    the full dataset before any limit is applied.
    """
    tenant_id = resolve_tenant_id(request)
    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None

    results = await fetch_many([
        ("compliance", "/api/v1/compliance/ui-data",         {"tenant_id": tenant_id, "scan_id": "latest"}),
        ("compliance", "/api/v1/compliance/frameworks/summary", {"tenant_id": tenant_id}),
        ("onboarding", "/api/v1/cloud-accounts",             {"tenant_id": tenant_id}),
    ], auth_headers=fwd_headers)

    compliance_data, frameworks_data, onboarding_data = results
    compliance_data  = compliance_data  if isinstance(compliance_data,  dict) else {}
    frameworks_data  = frameworks_data  if isinstance(frameworks_data,  dict) else {}
    onboarding_data  = onboarding_data  if isinstance(onboarding_data,  dict) else {}

    # Build a lookup: account_id → account display name
    raw_accounts = onboarding_data.get("accounts", [])
    if not isinstance(raw_accounts, list):
        raw_accounts = []
    account_names: Dict[str, str] = {
        a.get("account_id", ""): (a.get("account_name") or a.get("account_id", ""))
        for a in raw_accounts
        if isinstance(a, dict) and a.get("account_id")
    }

    # Pull failing controls from compliance engine response
    raw_fc = compliance_data.get("failing_controls", [])
    if not isinstance(raw_fc, list):
        raw_fc = []

    # If ui-data has no failing_controls, derive from ALL failing framework assessments.
    if not raw_fc:
        fw_list = frameworks_data.get("frameworks", []) or []
        failing_fws = sorted(
            [fw for fw in fw_list if isinstance(fw, dict) and (fw.get("failed") or 0) > 0],
            key=lambda x: x.get("failed", 0),
            reverse=True,
        )  # no [:6] cap — read every failing framework

        if failing_fws:
            assessment_calls = [
                ("compliance",
                 f"/api/v1/compliance/framework/{fw.get('id') or fw.get('framework_id')}/assessment",
                 {"tenant_id": tenant_id})
                for fw in failing_fws
            ]
            assessments = await fetch_many(assessment_calls, auth_headers=fwd_headers)

            for i, assessment in enumerate(assessments):
                if not isinstance(assessment, dict):
                    continue
                fw_name = (
                    assessment.get("framework", {}).get("framework_name")
                    or assessment.get("framework", {}).get("framework_id")
                    or (failing_fws[i].get("name") or failing_fws[i].get("id") or "")
                )
                for family in (assessment.get("families") or []):
                    for ctrl in (family.get("controls") or []):
                        status = (ctrl.get("status") or "").upper()
                        if status not in ("FAIL", "PARTIAL"):
                            continue
                        raw_fc.append({
                            "control_id":   ctrl.get("control_id") or ctrl.get("id", ""),
                            "title":        ctrl.get("title") or ctrl.get("control_name", ""),
                            "framework":    fw_name,
                            "severity":     ctrl.get("severity") or "medium",
                            "total_failed": ctrl.get("failed_resources") or ctrl.get("failed") or 1,
                            "account":      "",
                            "days_open":    0,
                        })

    now_utc = datetime.now(timezone.utc)
    failing_controls = []
    for c in raw_fc:
        if not isinstance(c, dict):
            continue
        raw_sev = (c.get("severity") or "LOW").upper()
        acct_id = c.get("account") or c.get("account_id", "")
        acct_name = account_names.get(acct_id, acct_id) if acct_id else ""
        last_checked = c.get("last_checked") or c.get("last_seen_at") or c.get("assessed_at")
        # Compute days_open: prefer stored value, fall back to days since last_checked
        days_open = c.get("days_open") or 0
        if not days_open and last_checked:
            try:
                lc_dt = datetime.fromisoformat(str(last_checked).replace("Z", "+00:00"))
                if lc_dt.tzinfo is None:
                    lc_dt = lc_dt.replace(tzinfo=timezone.utc)
                days_open = max(0, (now_utc - lc_dt).days)
            except Exception:
                pass
        failing_controls.append({
            "framework":              c.get("framework") or c.get("framework_id", ""),
            "control_id":             c.get("control_id", ""),
            "control_title":          c.get("title") or c.get("control_name", ""),
            "severity":               raw_sev,
            "affected_accounts":      [acct_id] if acct_id else [],
            "affected_account_names": [acct_name] if acct_name else [],
            "affected_account_count": 1 if acct_id else 0,
            "last_checked":           last_checked,
            "days_open":              days_open,
        })

    # Optional server-side filters (provider carries no data in failing_controls, skip)
    if severity:
        sev_upper = severity.upper()
        failing_controls = [c for c in failing_controls if c["severity"] == sev_upper]
    if account:
        failing_controls = [
            c for c in failing_controls
            if account in c.get("affected_accounts", [])
        ]

    # Sort: CRITICAL → HIGH → MEDIUM → LOW → INFO
    failing_controls.sort(key=lambda x: SEVERITY_ORDER.get(x.get("severity", "INFO"), 99))

    # Compute totals from the full sorted list — before any limit is applied.
    total_failing = len(failing_controls)
    by_severity: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for c in failing_controls:
        sev = c.get("severity", "LOW")
        if sev in by_severity:
            by_severity[sev] += 1

    # Safety cap (default 1000 — effectively unlimited for realistic data volumes)
    if limit > 0:
        failing_controls = failing_controls[:limit]

    return {
        "failingControls": failing_controls,
        "totalFailing":    total_failing,
        "bySeverity":      by_severity,
    }


@router.get("/compliance/framework/{framework_id}")
async def view_framework_detail(
    request: Request,
    framework_id: str,
    scan_run_id: str = Query("latest"),
):
    """Framework detail view — controls grouped by family with assessment status.

    Calls compliance engine /framework/{framework_id}/assessment in parallel with
    frameworks/summary so the UI can show both the strict Pass Rate and the
    engine's weighted Assessed Score side by side.
    """
    tenant_id = resolve_tenant_id(request)
    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None

    results = await fetch_many([
        ("compliance", f"/api/v1/compliance/framework/{framework_id}/assessment",
         {"tenant_id": tenant_id, "scan_run_id": scan_run_id}),
        ("compliance", "/api/v1/compliance/frameworks/summary",
         {"tenant_id": tenant_id}),
    ], auth_headers=fwd_headers)

    data         = results[0] if results[0] and isinstance(results[0], dict) else {}
    summary_data = results[1] if results[1] and isinstance(results[1], dict) else {}

    # Pull the engine's stored weighted score (Assessed Score) from the summary list.
    # This uses a different formula than the strict PASS/total score in `data["score"]`.
    assessed_score: Optional[float] = None
    for fw in (summary_data.get("frameworks") or []):
        if isinstance(fw, dict):
            fid = (fw.get("id") or fw.get("framework_id") or "").lower()
            if fid == framework_id.lower():
                assessed_score = fw.get("score")
                break

    if not data or data.get("error"):
        return {
            "framework": {"framework_id": framework_id, "framework_name": framework_id},
            "score": 0,
            "total_controls": 0,
            "summary": {},
            "families": [],
            "assessed_score": None,
        }

    result = dict(data)
    result["assessed_score"] = assessed_score
    return result


@router.get("/compliance/framework/{framework_id}/report")
async def view_framework_report(
    request: Request,
    framework_id: str,
    scan_run_id: str = Query("latest"),
    format: str = Query("json"),
):
    """Framework compliance report — full data for export (CSV/JSON)."""
    tenant_id = resolve_tenant_id(request)
    from fastapi.responses import StreamingResponse

    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None

    results = await fetch_many([
        ("compliance", f"/api/v1/compliance/framework/{framework_id}/report",
         {"tenant_id": tenant_id, "scan_run_id": scan_run_id, "format": format}),
    ], auth_headers=fwd_headers)

    data = results[0] if results[0] else {}

    if format == "csv" and isinstance(data, bytes):
        return StreamingResponse(
            iter([data]),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={framework_id}_report.csv"},
        )

    return data
