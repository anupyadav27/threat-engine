"""
BFF (Backend-For-Frontend) Views Layer

Aggregates data from multiple engine endpoints and returns UI-ready JSON.
Each view corresponds to a top-level page in the CSPM frontend.

All engine calls go through httpx to the internal K8s service URLs
defined in SERVICE_ROUTES (main.py).
"""

import os
import logging
from typing import Optional, Dict, Any, List
from fastapi import APIRouter, Query, HTTPException
import httpx

logger = logging.getLogger(__name__)

# ── Internal engine base URLs (same as SERVICE_ROUTES in main.py) ──

INVENTORY_URL = os.getenv("INVENTORY_ENGINE_URL", "http://engine-inventory:8022")
THREAT_URL = os.getenv("THREAT_ENGINE_URL", "http://engine-threat:8020")
CHECK_URL = os.getenv("CHECK_ENGINE_URL", "http://engine-check:8002")
COMPLIANCE_URL = os.getenv("COMPLIANCE_ENGINE_URL", "http://engine-compliance:8010")
IAM_URL = os.getenv("IAM_ENGINE_URL", "http://engine-iam:8003")
DATASEC_URL = os.getenv("DATASEC_ENGINE_URL", "http://engine-datasec:8004")
SECOPS_URL = os.getenv("SECOPS_ENGINE_URL", "http://engine-secops:8000")
RISK_URL = os.getenv("RISK_ENGINE_URL", "http://engine-risk:8009")
ONBOARDING_URL = os.getenv("ONBOARDING_ENGINE_URL", "http://engine-onboarding:8008")
RULE_URL = os.getenv("RULE_ENGINE_URL", "http://engine-rule:8000")

# Timeout for inter-service calls (seconds)
ENGINE_TIMEOUT = float(os.getenv("BFF_ENGINE_TIMEOUT", "15"))

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


# ── Helpers ──────────────────────────────────────────────────────────

async def _fetch(url: str, timeout: float = ENGINE_TIMEOUT) -> Dict[str, Any]:
    """GET an internal engine URL and return parsed JSON (or empty dict on error)."""
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                return resp.json()
            logger.warning("BFF fetch %s → %d", url, resp.status_code)
    except Exception as exc:
        logger.warning("BFF fetch %s failed: %s", url, exc)
    return {}


def _qs(params: Dict[str, Any]) -> str:
    """Build query string from non-None params."""
    parts = [f"{k}={v}" for k, v in params.items() if v is not None]
    return ("?" + "&".join(parts)) if parts else ""


# ── INVENTORY VIEW ───────────────────────────────────────────────────

@router.get("/inventory")
async def view_inventory(
    tenant_id: str = Query(...),
    provider: Optional[str] = Query(None),
    account: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
    limit: int = Query(500, ge=1, le=2000),
    offset: int = Query(0, ge=0),
):
    """
    BFF view for /inventory page.

    Aggregates:
      1. Asset list from inventory engine
      2. Scan summary (totals + drift KPIs) from inventory engine

    Returns UI-ready JSON with `assets[]` and `summary{}`.
    """
    qs_common = {"tenant_id": tenant_id}
    if provider:
        qs_common["provider"] = provider
    if account:
        qs_common["account_id"] = account
    if region:
        qs_common["region"] = region

    # Build URLs
    asset_params = {**qs_common, "limit": limit, "offset": offset}
    assets_url = f"{INVENTORY_URL}/api/v1/inventory/assets{_qs(asset_params)}"
    summary_url = f"{INVENTORY_URL}/api/v1/inventory/runs/latest/summary{_qs({'tenant_id': tenant_id})}"

    # Parallel fetch
    import asyncio
    assets_data, summary_data = await asyncio.gather(
        _fetch(assets_url),
        _fetch(summary_url),
    )

    # Reshape assets — ensure all UI-required fields have safe defaults
    raw_assets = assets_data.get("assets", [])
    _default_findings = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for asset in raw_assets:
        tags = asset.get("tags") or {}
        # Derive convenience fields from tags
        if not asset.get("owner"):
            asset["owner"] = (
                tags.get("Owner")
                or tags.get("owner")
                or tags.get("CreatedBy")
                or tags.get("team")
                or ""
            )
        if not asset.get("environment"):
            asset["environment"] = (
                tags.get("Environment")
                or tags.get("environment")
                or tags.get("Env")
                or tags.get("env")
                or ""
            )
        # Ensure findings severity counts (UI table cell reads .critical)
        if not asset.get("findings") or not isinstance(asset.get("findings"), dict):
            sev = asset.get("threat_severity") or asset.get("severity_counts") or {}
            asset["findings"] = {
                "critical": sev.get("critical", 0),
                "high": sev.get("high", 0),
                "medium": sev.get("medium", 0),
                "low": sev.get("low", 0),
            }
        # Ensure string fields never None (UI calls .substring / .toUpperCase)
        if not asset.get("resource_id"):
            asset["resource_id"] = asset.get("resource_uid") or ""
        if not asset.get("account_id"):
            asset["account_id"] = asset.get("account") or ""
        if not asset.get("resource_name"):
            asset["resource_name"] = asset.get("name") or ""
        if not asset.get("resource_type"):
            asset["resource_type"] = asset.get("type") or ""
        if asset.get("risk_score") is None:
            asset["risk_score"] = 0
        if not asset.get("status"):
            asset["status"] = "active"
        if not asset.get("last_scanned"):
            asset["last_scanned"] = asset.get("updated_at") or asset.get("created_at") or ""

    # Reshape summary
    drift = summary_data.get("drift_summary", {})
    summary = {
        "total_assets": summary_data.get("total_assets", len(raw_assets)),
        "total_relationships": summary_data.get("total_relationships", 0),
        "total_drift": drift.get("total_drift", 0),
        "new_assets": drift.get("assets_added", 0),
        "removed_assets": drift.get("assets_removed", 0),
        "changed_assets": drift.get("assets_changed", 0),
        "providers_scanned": summary_data.get("providers_scanned"),
        "accounts_scanned": summary_data.get("accounts_scanned"),
        "regions_scanned": summary_data.get("regions_scanned"),
        "assets_by_provider": summary_data.get("assets_by_provider"),
        "assets_by_resource_type": summary_data.get("assets_by_resource_type"),
        "assets_by_region": summary_data.get("assets_by_region"),
    }

    return {
        "assets": raw_assets,
        "total": assets_data.get("total", len(raw_assets)),
        "has_more": assets_data.get("has_more", False),
        "summary": summary,
    }


# ── THREATS VIEW ─────────────────────────────────────────────────────

@router.get("/threats")
async def view_threats(
    tenant_id: str = Query(...),
    provider: Optional[str] = Query(None),
    account: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
    scan_run_id: str = Query("latest"),
):
    """
    BFF view for /threats page.

    Aggregates from threat engine:
      - Threat list
      - Trend data
      - Attack chains
      - MITRE matrix
    """
    import asyncio

    qs_base = {"tenant_id": tenant_id, "scan_run_id": scan_run_id}
    if provider:
        qs_base["provider"] = provider

    threats_url = f"{THREAT_URL}/api/v1/threat/list{_qs(qs_base)}"
    trend_url = f"{THREAT_URL}/api/v1/threat/analytics/trend{_qs({'tenant_id': tenant_id})}"
    attack_url = f"{THREAT_URL}/api/v1/graph/attack-paths{_qs(qs_base)}"
    mitre_url = f"{THREAT_URL}/api/v1/threat/analytics/mitre{_qs(qs_base)}"
    intel_url = f"{THREAT_URL}/api/v1/intel{_qs({'tenant_id': tenant_id})}"

    threats_data, trend_data, attack_data, mitre_data, intel_data = await asyncio.gather(
        _fetch(threats_url),
        _fetch(trend_url),
        _fetch(attack_url),
        _fetch(mitre_url),
        _fetch(intel_url),
    )

    return {
        "threats": threats_data.get("threats", threats_data.get("findings", [])),
        "total": threats_data.get("total", 0),
        "trendData": trend_data.get("trend", trend_data.get("data", [])),
        "attackChains": attack_data.get("attack_paths", attack_data.get("chains", [])),
        "mitreMatrix": mitre_data.get("matrix", mitre_data),
        "threatIntel": intel_data.get("intelligence", intel_data.get("data", [])),
    }


# ── COMPLIANCE VIEW ──────────────────────────────────────────────────

@router.get("/compliance")
async def view_compliance(
    tenant_id: str = Query(...),
    provider: Optional[str] = Query(None),
    account: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
    csp: str = Query("aws"),
):
    """
    BFF view for /compliance page.

    Aggregates from compliance engine:
      - Dashboard summary: framework_scores (13 frameworks) + posture_summary
      - Failing controls
      - Trends (if available)

    The ``compliance/dashboard`` endpoint is the richest source — it returns
    per-framework scores, overall posture, and total findings counts from the
    ``compliance_report`` table.
    """
    import asyncio

    tenant_qs: Dict[str, Any] = {"tenant_id": tenant_id}
    if provider:
        tenant_qs["provider"] = provider

    dashboard_url = f"{COMPLIANCE_URL}/api/v1/compliance/dashboard{_qs(tenant_qs)}"
    failing_url = f"{COMPLIANCE_URL}/api/v1/compliance/failing-controls{_qs(tenant_qs)}"
    trends_url = f"{COMPLIANCE_URL}/api/v1/compliance/trends{_qs(tenant_qs)}"
    accounts_url = f"{ONBOARDING_URL}/api/v1/accounts{_qs({'tenant_id': tenant_id})}"

    dash_data, failing_data, trends_data, accounts_data = await asyncio.gather(
        _fetch(dashboard_url),
        _fetch(failing_url),
        _fetch(trends_url),
        _fetch(accounts_url),
    )

    # framework_scores: [{compliance_framework, total_controls, passed_controls,
    #                      failed_controls, partial_controls, framework_score}, ...]
    framework_scores = dash_data.get("framework_scores", [])

    # Posture summary
    posture = dash_data.get("posture_summary", {})
    total_controls = posture.get("total_controls", 0)
    controls_passed = posture.get("controls_passed", 0)
    overall = round(controls_passed / total_controls * 100, 1) if total_controls else 0

    # Frameworks overview (total, passing, failing)
    fw_summary = dash_data.get("frameworks", {})

    # Build accountMatrix: one row per cloud account with per-framework scores
    raw_accounts = accounts_data.get("accounts", accounts_data.get("data", []))
    account_matrix = []
    for acct in raw_accounts:
        row = {
            "account": acct.get("account_name", acct.get("name", "")),
            "account_id": acct.get("account_id", ""),
            "provider": acct.get("provider", acct.get("csp", "aws")),
            "csp": acct.get("csp", acct.get("provider", "aws")),
            "env": acct.get("environment", acct.get("env", "")),
        }
        # Add per-framework scores (same score for all accounts as a baseline)
        for fw in framework_scores:
            fw_name = fw.get("compliance_framework", fw.get("framework", ""))
            row[fw_name] = fw.get("framework_score", 0)
        account_matrix.append(row)

    return {
        "frameworks": framework_scores,
        "frameworkSummary": fw_summary,
        "overallScore": overall,
        "postureSummary": posture,
        "failingControls": failing_data.get("controls", failing_data.get("findings", [])),
        "trendData": trends_data.get("trends", trends_data.get("data", [])),
        "auditDeadlines": [],
        "exceptions": [],
        "accountMatrix": account_matrix,
    }


# ── IAM VIEW ─────────────────────────────────────────────────────────

@router.get("/iam")
async def view_iam(
    tenant_id: str = Query(...),
    provider: Optional[str] = Query(None),
    csp: str = Query("aws"),
    scan_id: str = Query("latest"),
):
    """
    BFF view for /iam page.

    Aggregates from IAM engine.
    """
    import asyncio

    qs = {"tenant_id": tenant_id, "csp": csp, "scan_id": scan_id}

    findings_url = f"{IAM_URL}/api/v1/iam-security/findings{_qs(qs)}"
    summary_url = f"{IAM_URL}/api/v1/iam-security/summary{_qs(qs)}"
    roles_url = f"{IAM_URL}/api/v1/iam-security/roles{_qs(qs)}"
    keys_url = f"{IAM_URL}/api/v1/iam-security/access-keys{_qs(qs)}"
    privesc_url = f"{IAM_URL}/api/v1/iam-security/privilege-escalation{_qs(qs)}"
    svc_accts_url = f"{IAM_URL}/api/v1/iam-security/service-accounts{_qs(qs)}"

    findings, summary, roles, keys, privesc, svc_accts = await asyncio.gather(
        _fetch(findings_url),
        _fetch(summary_url),
        _fetch(roles_url),
        _fetch(keys_url),
        _fetch(privesc_url),
        _fetch(svc_accts_url),
    )

    return {
        "identities": findings.get("identities", findings.get("findings", [])),
        "kpi": summary.get("kpi", summary),
        "roles": roles.get("roles", []),
        "accessKeys": keys.get("access_keys", keys.get("keys", [])),
        "privilegeEscalation": privesc.get("escalation_paths", privesc.get("findings", [])),
        "serviceAccounts": svc_accts.get("service_accounts", svc_accts.get("findings", [])),
    }


# ── DATASEC VIEW ─────────────────────────────────────────────────────

@router.get("/datasec")
async def view_datasec(
    tenant_id: str = Query(...),
    provider: Optional[str] = Query(None),
    csp: str = Query("aws"),
    scan_id: str = Query("latest"),
):
    """
    BFF view for /datasec page.

    Aggregates from datasec engine.
    """
    import asyncio

    qs = {"tenant_id": tenant_id, "csp": csp, "scan_id": scan_id}

    catalog_url = f"{DATASEC_URL}/api/v1/data-security/catalog{_qs(qs)}"
    classify_url = f"{DATASEC_URL}/api/v1/data-security/classification{_qs(qs)}"
    findings_url = f"{DATASEC_URL}/api/v1/data-security/findings{_qs(qs)}"
    residency_url = f"{DATASEC_URL}/api/v1/data-security/residency{_qs(qs)}"
    activity_url = f"{DATASEC_URL}/api/v1/data-security/activity{_qs(qs)}"

    catalog, classify, findings, residency, activity = await asyncio.gather(
        _fetch(catalog_url),
        _fetch(classify_url),
        _fetch(findings_url),
        _fetch(residency_url),
        _fetch(activity_url),
    )

    return {
        "catalog": catalog.get("catalog", catalog.get("data", [])),
        "classifications": classify.get("classifications", classify.get("data", [])),
        "dlp": [f for f in findings.get("findings", []) if (f.get("category") or "").lower() in ("dlp", "data_loss")],
        "encryption": [f for f in findings.get("findings", []) if (f.get("category") or "").lower() in ("encryption",)],
        "residency": residency.get("residency", residency.get("data", [])),
        "accessMonitoring": activity.get("activity_log", activity.get("access_patterns", activity.get("data", []))),
    }


# ── MISCONFIG VIEW ───────────────────────────────────────────────────

@router.get("/misconfig")
async def view_misconfig(
    tenant_id: str = Query(...),
    provider: Optional[str] = Query(None),
    account: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
    scan_run_id: str = Query("latest"),
):
    """
    BFF view for /misconfig page.

    Sources from threat engine findings — threat_findings are enriched
    check_findings with MITRE ATT&CK mapping.  Every rule violation discovered
    by the check engine is captured as a threat finding, so this covers all
    misconfigurations.
    """
    qs: Dict[str, Any] = {"tenant_id": tenant_id, "scan_run_id": scan_run_id}
    if provider:
        qs["provider"] = provider
    if account:
        qs["account_id"] = account
    if region:
        qs["region"] = region

    # Threat engine list contains all rule-evaluated findings
    threat_url = f"{THREAT_URL}/api/v1/threat/list{_qs(qs)}"
    data = await _fetch(threat_url)

    findings = data.get("threats", data.get("findings", []))

    # Compute severity summary
    summary = {"total": len(findings), "critical": 0, "high": 0, "medium": 0, "low": 0}
    by_service: Dict[str, int] = {}
    by_account: Dict[str, int] = {}
    by_category: Dict[str, int] = {}
    for f in findings:
        sev = (f.get("severity") or "medium").lower()
        if sev in summary:
            summary[sev] += 1
        svc = f.get("service") or f.get("resource_type", "unknown").split(".")[0]
        by_service[svc] = by_service.get(svc, 0) + 1
        acc = f.get("account_id", "unknown")
        by_account[acc] = by_account.get(acc, 0) + 1
        cat = f.get("threat_category") or f.get("category") or "misconfiguration"
        by_category[cat] = by_category.get(cat, 0) + 1

    return {
        "findings": findings,
        "kpi": summary,
        "byService": [{"service": k, "count": v} for k, v in sorted(by_service.items(), key=lambda x: -x[1])],
        "byAccount": [{"account": k, "count": v} for k, v in sorted(by_account.items(), key=lambda x: -x[1])],
        "byCategory": [{"category": k, "count": v} for k, v in sorted(by_category.items(), key=lambda x: -x[1])],
    }


# ── RISK VIEW ────────────────────────────────────────────────────────

@router.get("/risk")
async def view_risk(
    tenant_id: str = Query(...),
    provider: Optional[str] = Query(None),
):
    """
    BFF view for /risk page.

    Aggregates from risk engine:
      - dashboard  → risk_score, risk_register, mitigation_roadmap
      - scenarios  → risk scenarios with exposure calculations
      - trends     → historical risk trend data
    """
    import asyncio

    qs: Dict[str, Any] = {"tenant_id": tenant_id}
    if provider:
        qs["provider"] = provider

    dashboard_url = f"{RISK_URL}/api/v1/risk/dashboard{_qs(qs)}"
    scenarios_url = f"{RISK_URL}/api/v1/risk/scenarios{_qs(qs)}"
    trends_url = f"{RISK_URL}/api/v1/risk/trends{_qs(qs)}"
    compliance_url = f"{COMPLIANCE_URL}/api/v1/compliance/dashboard{_qs({'tenant_id': tenant_id})}"
    breakdown_url = f"{RISK_URL}/api/v1/risk/breakdown{_qs(qs)}"

    dashboard, scenarios, trends, comp_data, breakdown = await asyncio.gather(
        _fetch(dashboard_url),
        _fetch(scenarios_url),
        _fetch(trends_url),
        _fetch(compliance_url),
        _fetch(breakdown_url),
    )

    # Compute complianceIndex from compliance engine posture_summary
    comp_posture = comp_data.get("posture_summary", {})
    comp_total = comp_posture.get("total_controls", 0)
    comp_passed = comp_posture.get("controls_passed", 0)
    compliance_index = round(comp_passed / comp_total * 100, 1) if comp_total else 0

    # Count critical risks from risk_register
    risk_register = dashboard.get("risk_register", [])
    critical_risks = sum(
        1 for r in risk_register
        if (r.get("risk_rating") or r.get("severity") or "").lower() == "critical"
    )

    return {
        "riskScore": dashboard.get("risk_score", 0),
        "level": _risk_level(dashboard.get("risk_score", 0)),
        "criticalRisks": critical_risks,
        "acceptedRisks": dashboard.get("accepted_risks", 0),
        "averageLoss": dashboard.get("average_loss", 0),
        "riskReduction": dashboard.get("risk_reduction", 0),
        "complianceIndex": compliance_index,
        "riskRegister": risk_register,
        "mitigationRoadmap": dashboard.get("mitigation_roadmap", []),
        "scenarios": scenarios.get("data", scenarios.get("scenarios", [])),
        "trendData": trends.get("data", trends.get("trends", [])),
        "riskCategories": breakdown.get("breakdown_by_category", breakdown.get("data", [])),
    }


def _risk_level(score: int) -> str:
    """Map numeric risk score to human-readable level."""
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "minimal"


# ── SCANS VIEW ───────────────────────────────────────────────────────

@router.get("/scans")
async def view_scans(
    tenant_id: str = Query(...),
    provider: Optional[str] = Query(None),
    account: Optional[str] = Query(None),
    limit: int = Query(50),
):
    """
    BFF view for /scans page.

    Sources from onboarding engine (scan_orchestration table).
    """
    qs: Dict[str, Any] = {"tenant_id": tenant_id, "limit": limit}
    if provider:
        qs["provider"] = provider
    if account:
        qs["account_id"] = account

    scans_url = f"{ONBOARDING_URL}/api/v1/scans/recent{_qs(qs)}"
    data = await _fetch(scans_url)

    return {
        "scans": data.get("scans", data.get("data", [])),
        "scheduled": [],
    }


# ── REPORTS VIEW ─────────────────────────────────────────────────────

@router.get("/reports")
async def view_reports(
    tenant_id: str = Query(...),
):
    """
    BFF view for /reports page.

    Sources from compliance engine.
    """
    qs = {"tenant_id": tenant_id}
    reports_url = f"{COMPLIANCE_URL}/api/v1/compliance/reports{_qs(qs)}"
    data = await _fetch(reports_url)

    return {
        "reports": data.get("reports", data.get("data", [])),
        "scheduled": [],
    }


# ── RULES VIEW ───────────────────────────────────────────────────────

@router.get("/rules")
async def view_rules(
    tenant_id: str = Query(...),
    provider: Optional[str] = Query(None),
):
    """
    BFF view for /rules page.

    Aggregates rule list + statistics from rule engine.
    """
    import asyncio

    qs: Dict[str, Any] = {"tenant_id": tenant_id}
    if provider:
        qs["provider"] = provider

    rules_url = f"{RULE_URL}/api/v1/rules{_qs(qs)}"
    stats_url = f"{RULE_URL}/api/v1/rules/statistics{_qs(qs)}"

    rules_data, stats_data = await asyncio.gather(
        _fetch(rules_url),
        _fetch(stats_url),
    )

    return {
        "rules": rules_data.get("rules", rules_data.get("data", [])),
        "kpi": stats_data.get("statistics", stats_data),
        "templates": [],
    }


# ── DASHBOARD VIEW ───────────────────────────────────────────────────

@router.get("/dashboard")
async def view_dashboard(
    tenant_id: str = Query(...),
    provider: Optional[str] = Query(None),
    account: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
    csp: str = Query("aws"),
):
    """
    BFF view for /dashboard page.

    Cross-engine aggregation: inventory, threat, compliance, risk.
    """
    import asyncio

    tenant_qs: Dict[str, Any] = {"tenant_id": tenant_id}
    if provider:
        tenant_qs["provider"] = provider

    # Parallel calls to multiple engines
    inv_summary_url = f"{INVENTORY_URL}/api/v1/inventory/runs/latest/summary{_qs(tenant_qs)}"
    threat_qs = {**tenant_qs, "scan_run_id": "latest"}
    threat_list_url = f"{THREAT_URL}/api/v1/threat/list{_qs(threat_qs)}"
    threat_trend_url = f"{THREAT_URL}/api/v1/threat/analytics/trend{_qs({'tenant_id': tenant_id})}"
    compliance_dash_url = f"{COMPLIANCE_URL}/api/v1/compliance/dashboard{_qs(tenant_qs)}"
    risk_url = f"{RISK_URL}/api/v1/risk/dashboard{_qs(tenant_qs)}"
    recent_scans_url = f"{ONBOARDING_URL}/api/v1/scans/recent{_qs({'tenant_id': tenant_id, 'limit': 5})}"
    toxic_url = f"{THREAT_URL}/api/v1/graph/toxic-combinations{_qs(threat_qs)}"
    exposed_url = f"{THREAT_URL}/api/v1/graph/internet-exposed{_qs({'tenant_id': tenant_id})}"

    (inv_data, threat_data, trend_data, comp_dash, risk_data,
     scans_data, toxic_data, exposed_data) = await asyncio.gather(
        _fetch(inv_summary_url),
        _fetch(threat_list_url),
        _fetch(threat_trend_url),
        _fetch(compliance_dash_url),
        _fetch(risk_url),
        _fetch(recent_scans_url),
        _fetch(toxic_url),
        _fetch(exposed_url),
    )

    # Inventory KPIs
    total_assets = inv_data.get("total_assets", 0)
    drift_summary = inv_data.get("drift_summary", {})

    # Threat KPIs
    threats = threat_data.get("threats", threat_data.get("findings", []))
    total_threats = len(threats)
    critical_threats = sum(1 for t in threats if (t.get("severity") or "").lower() == "critical")
    high_threats = sum(1 for t in threats if (t.get("severity") or "").lower() == "high")

    # Compliance KPIs — derive from dashboard posture_summary + framework_scores
    posture = comp_dash.get("posture_summary", {})
    total_controls = posture.get("total_controls", 0)
    controls_passed = posture.get("controls_passed", 0)
    compliance_score = round(controls_passed / total_controls * 100, 1) if total_controls else 0
    framework_scores = comp_dash.get("framework_scores", [])

    # Risk KPIs (from /api/v1/risk/dashboard)
    risk_score = risk_data.get("risk_score", 0)
    risk_level = _risk_level(risk_score)

    # Trend data
    trend = trend_data.get("trend", trend_data.get("data", []))

    # Severity breakdown for findings-by-category
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    category_map: Dict[str, int] = {}
    mitre_tech_map: Dict[str, int] = {}
    for t in threats:
        sev = (t.get("severity") or "medium").lower()
        if sev in sev_counts:
            sev_counts[sev] += 1
        cat = t.get("threat_category") or t.get("category") or "misconfiguration"
        category_map[cat] = category_map.get(cat, 0) + 1
        for tech in (t.get("mitre_techniques") or []):
            tech_name = tech if isinstance(tech, str) else tech.get("name", str(tech))
            mitre_tech_map[tech_name] = mitre_tech_map.get(tech_name, 0) + 1

    # Build KPI block matching UI's kpiData state shape
    kpi = {
        "totalAssets": total_assets,
        "totalAssetsChange": drift_summary.get("assets_added", 0),
        "openFindings": total_threats,
        "openFindingsChange": 0,
        "criticalHighFindings": critical_threats + high_threats,
        "criticalHighFindingsChange": 0,
        "complianceScore": compliance_score,
        "complianceScoreChange": 0,
        "attackSurfaceScore": 0,
        "attackSurfaceScoreChange": 0,
        "mttr": None,
        "mttrChange": None,
        "activeThreats": total_threats,
        "activeThreatsChange": 0,
        "slaCompliance": None,
        "slaComplianceChange": None,
    }

    # Cloud provider distribution from inventory
    by_provider = inv_data.get("assets_by_provider", {})
    cloud_providers = [
        {"provider": p, "count": c}
        for p, c in (by_provider.items() if isinstance(by_provider, dict) else [])
    ]

    # Cloud health grid (one row per provider/account)
    cloud_health = []
    for p, count in (by_provider.items() if isinstance(by_provider, dict) else []):
        cloud_health.append({
            "provider": p,
            "account": "All",
            "resources": count,
            "activeFindings": sev_counts.get("critical", 0) + sev_counts.get("high", 0),
            "complianceScore": compliance_score,
            "lastScan": "",
            "status": "healthy" if compliance_score > 50 else "at_risk",
        })

    # Critical immediate actions (top critical threats)
    critical_actions = {
        "immediate": [
            {"title": t.get("rule_id", ""), "description": t.get("evidence", ""), "severity": "critical"}
            for t in threats if (t.get("severity") or "").lower() == "critical"
        ][:5],
        "thisWeek": [
            {"title": t.get("rule_id", ""), "description": t.get("evidence", ""), "severity": "high"}
            for t in threats if (t.get("severity") or "").lower() == "high"
        ][:5],
        "thisMonth": [],
    }

    # Top MITRE techniques
    mitre_top = [
        {"technique": k, "count": v}
        for k, v in sorted(mitre_tech_map.items(), key=lambda x: -x[1])[:10]
    ]

    # Findings by category for donut chart
    findings_by_cat = [
        {"category": k, "count": v, "color": "#ef4444" if k == "misconfiguration" else "#f97316"}
        for k, v in sorted(category_map.items(), key=lambda x: -x[1])[:8]
    ]

    return {
        # KPI block (UI reads data.kpi → setKpiData)
        "kpi": kpi,
        # Trend data
        "securityScoreTrendData": trend,
        "threatActivityTrend": trend,
        # Findings by category
        "findingsByCategoryData": findings_by_cat,
        # Compliance frameworks
        "frameworks": framework_scores,
        # Cloud providers
        "cloudProviders": cloud_providers,
        # Cloud health grid
        "cloudHealthData": cloud_health,
        # Critical actions
        "criticalActions": critical_actions,
        # Critical alerts
        "criticalAlerts": [],
        # MITRE techniques
        "mitreTopTechniques": mitre_top,
        # Attack surface — internet-exposed resources from threat engine
        "attackSurfaceData": exposed_data.get("exposed_resources", exposed_data.get("data", [])),
        # Remediation SLA
        "remediationSLA": [],
        # Risky resources (top critical/high threats)
        "riskyResources": [
            {
                "resource": t.get("resource_uid", ""),
                "type": t.get("resource_type", ""),
                "provider": t.get("provider", "aws"),
                "region": t.get("region", ""),
                "findings": 1,
                "riskScore": 90 if (t.get("severity") or "").lower() == "critical" else 70,
            }
            for t in threats if (t.get("severity") or "").lower() in ("critical", "high")
        ][:10],
        # Recent scans from onboarding engine
        "recentScans": scans_data.get("scans", scans_data.get("data", [])),
        # Toxic combinations from threat engine
        "toxicCombinations": toxic_data.get("toxic_combinations", toxic_data.get("data", [])),
    }
