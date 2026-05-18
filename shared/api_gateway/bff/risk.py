"""BFF view: /risk (Risk Quantification) page.

Consolidates Risk Quantification Engine (FAIR model) + threat data into 2 BFF calls.
Risk Quantification converts security findings into dollar-denominated exposure estimates.
Domain-level "posture scores" (0-100 severity index) live in each engine.
This page shows "financial risk exposure" — what the CFO/board cares about.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Query, Request

from ._auth import resolve_tenant_id
from ._shared import fetch_many, safe_get, BFFMeta
from .schemas.risk import RiskResponse
from ._transforms import normalize_risk_scenario
from ._page_context import risk_page_context

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


@router.get("/risk", response_model=RiskResponse, response_model_exclude_none=False)
async def view_risk(
    request: Request,
    provider: Optional[str] = Query(None),
    account: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
):
    """Single endpoint returning everything the risk page needs."""

    tenant_id = resolve_tenant_id(request)
    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None
    meta = BFFMeta("risk")

    results = await fetch_many([
        ("risk", "/api/v1/risk/ui-data", {
            "tenant_id": tenant_id,
        }),
        ("threat", "/api/v1/threat/ui-data", {
            "tenant_id": tenant_id,
            "scan_run_id": "latest",
            "limit": "1",
        }),
    ], auth_headers=fwd_headers)

    risk_data, threat_data = results

    meta.record_engine("risk",   "/api/v1/risk/ui-data",    risk_data)
    meta.record_engine("threat", "/api/v1/threat/ui-data",  threat_data)
    if risk_data is None:
        meta.warn("Risk engine returned no data — scores and scenarios will be zero")
    if threat_data is None:
        meta.warn("Threat engine returned no data — risk score fallback unavailable")

    # Safely handle None responses
    if not isinstance(risk_data, dict):
        risk_data = {}
    if not isinstance(threat_data, dict):
        threat_data = {}

    # Scenarios from risk ui-data
    raw_scenarios = safe_get(risk_data, "scenarios", [])
    if not isinstance(raw_scenarios, list):
        raw_scenarios = []
    scenarios = [normalize_risk_scenario(s) for s in raw_scenarios]

    if account:
        scenarios = [s for s in scenarios if s.get("account") == account or not s.get("account")]

    # Trend from risk ui-data — with synthetic fallback
    trend_data = safe_get(risk_data, "trends", [])
    if not isinstance(trend_data, list):
        trend_data = []

    # Risk score — try risk engine first
    risk_score = safe_get(risk_data, "risk_score") or safe_get(risk_data, "riskScore", 0)

    # If risk engine returns 0, derive from threat ui-data summary
    if not risk_score:
        threat_summary = safe_get(threat_data, "summary", {})
        if isinstance(threat_summary, dict):
            crit = threat_summary.get("critical", 0)
            high = threat_summary.get("high", 0)
            med = threat_summary.get("medium", 0)
            low_count = threat_summary.get("low", 0)
            total = crit + high + med + low_count
            if total > 0:
                weighted = crit * 4 + high * 3 + med * 2 + low_count
                risk_score = min(100, round((weighted / (total * 4)) * 100))

    critical_risks = sum(1 for s in scenarios if s.get("risk_rating") == "critical")

    # Risk categories — try risk engine breakdown first
    risk_categories = safe_get(risk_data, "risk_categories", []) or safe_get(risk_data, "riskCategories", [])

    # If no categories, derive from risk engine breakdown
    # Risk engine returns: {"domain": "IAM", "score": 0, "weight": 0.25, "findings": 0}
    if not risk_categories:
        breakdown = safe_get(risk_data, "breakdown", [])
        if isinstance(breakdown, list):
            for item in breakdown:
                if isinstance(item, dict):
                    cat = item.get("category") or item.get("domain", "")
                    score = item.get("score", 0)
                    count = item.get("count") or item.get("findings", 0)
                    if cat:
                        risk_categories.append({
                            "category": cat.replace("_", " ").title(),
                            "score": score,
                            "count": count if isinstance(count, int) else 0,
                            "weight": item.get("weight", 0),
                        })
        elif isinstance(breakdown, dict):
            for cat, val in breakdown.items():
                if isinstance(val, (int, float)) and cat not in ("risk_score", "total"):
                    risk_categories.append({
                        "category": cat.replace("_", " ").title(),
                        "score": val,
                        "count": val if isinstance(val, int) else 0,
                    })

    # Fallback: generate from threat categories in summary
    if not risk_categories:
        threat_summary = safe_get(threat_data, "summary", {})
        if isinstance(threat_summary, dict):
            by_cat = threat_summary.get("by_category", {})
            if isinstance(by_cat, dict):
                for cat, count in by_cat.items():
                    if isinstance(count, int) and count > 0:
                        risk_categories.append({
                            "category": cat.replace("_", " ").title(),
                            "score": min(100, count * 5),
                            "count": count,
                        })

    # Risk register from risk engine
    risk_register = safe_get(risk_data, "risk_register", []) or safe_get(risk_data, "riskRegister", [])
    if not isinstance(risk_register, list):
        risk_register = []

    # Mitigation roadmap — from risk engine only; empty list until engine supplies data
    mitigation_roadmap = safe_get(risk_data, "mitigation_roadmap", [])
    if not isinstance(mitigation_roadmap, list):
        mitigation_roadmap = []

    # Top risky assets from risk engine
    top_assets = safe_get(risk_data, "top_assets", [])
    if not isinstance(top_assets, list):
        top_assets = []

    # If no trend data but we have a current score, return a single data point
    if not trend_data and risk_score and risk_score > 0:
        from datetime import datetime as dt, timezone as tz
        trend_data = [{"date": dt.now(tz.utc).strftime("%Y-%m-%d"), "score": round(risk_score, 1)}]

    # Derive risk level from score
    if risk_score >= 80:
        risk_level = "critical"
    elif risk_score >= 60:
        risk_level = "high"
    elif risk_score >= 40:
        risk_level = "medium"
    elif risk_score >= 20:
        risk_level = "low"
    else:
        risk_level = "minimal"

    page_ctx = risk_page_context({"risk_score": risk_score, "risk_level": risk_level})
    page_ctx["tabs"] = [
        {"id": "overview", "label": "Overview", "count": 0},
        {"id": "scenarios", "label": "FAIR Scenarios", "count": len(scenarios)},
        {"id": "register", "label": "Risk Register", "count": len(risk_register)},
        {"id": "roadmap", "label": "Mitigation Roadmap", "count": len(mitigation_roadmap)},
    ]

    accepted = safe_get(risk_data, "accepted_risks") or safe_get(risk_data, "acceptedRisks", 0)
    reduction = safe_get(risk_data, "risk_reduction") or safe_get(risk_data, "riskReduction", 0)

    # ── activeScanTrend: trendData items with risk_score field ───────────────
    active_scan_trend = []
    for d in trend_data:
        score = d.get("score") or d.get("risk_score") or 0
        active_scan_trend.append({
            "date": d.get("date", ""),
            "risk_score": score,
            "score": score,
        })

    first_pt  = active_scan_trend[0]  if active_scan_trend else {}
    last_pt   = active_scan_trend[-1] if active_scan_trend else {}
    first_obj = {"date": first_pt.get("date", ""), "risk_score": first_pt.get("risk_score", 0)}
    last_obj  = {"date": last_pt.get("date",  ""), "risk_score": last_pt.get("risk_score",  0)}

    # ── domainBreakdown: same as riskCategories with category field ──────────
    domain_breakdown = [
        {**c, "category": c.get("category", "")} for c in risk_categories
    ]

    # ── filterSchema: domain filter keys ────────────────────────────────────
    filter_schema = [
        {"key": "iam_security",        "label": "IAM Security",        "type": "boolean"},
        {"key": "network_security",    "label": "Network Security",    "type": "boolean"},
        {"key": "data_security",       "label": "Data Security",       "type": "boolean"},
        {"key": "container_security",  "label": "Container Security",  "type": "boolean"},
        {"key": "database_security",   "label": "Database Security",   "type": "boolean"},
        {"key": "encryption",          "label": "Encryption",          "type": "boolean"},
        {"key": "misconfig",           "label": "Misconfiguration",    "type": "boolean"},
        {"key": "provider",            "label": "Provider",            "type": "enum",
         "values": ["aws", "azure", "gcp", "oci"]},
    ]

    return {
        "pageContext": page_ctx,
        "kpiGroups": [
            {
                "title": "Financial Risk Exposure",
                "items": [
                    {"label": "Risk Exposure Score", "value": risk_score, "suffix": "/100"},
                    {"label": "Exposure Level", "value": risk_level},
                    {"label": "Critical Scenarios", "value": critical_risks},
                    {"label": "Risk Domains", "value": len(risk_categories)},
                ],
            },
            {
                "title": "Risk Quantification",
                "items": [
                    {"label": "Accepted Risks", "value": accepted},
                    {"label": "Risk Reduction", "value": reduction, "suffix": "%"},
                    {"label": "FAIR Scenarios", "value": len(scenarios)},
                    {"label": "Top Exposed Assets", "value": len(top_assets)},
                ],
            },
        ],
        "riskScore":          risk_score,
        "riskLevel":          risk_level,
        "riskCategories":     risk_categories,
        "domainBreakdown":    domain_breakdown,
        "riskRegister":       risk_register,
        "scenarios":          scenarios,
        "trendData":          trend_data,
        "activeScanTrend":    active_scan_trend,
        "first":              first_obj,
        "last":               last_obj,
        "mitigationRoadmap":  mitigation_roadmap,
        "topAssets":          top_assets,
        "filterSchema":       filter_schema,
        "_meta":              meta.to_dict(),
    }


# ── BFF wrappers for asset-list integration (Constitution §4.5 BFF-only rule) ──


@router.get("/risk/blast-radius")
async def view_risk_blast_radius(
    request: Request,
    limit: int = Query(50, ge=1, le=500),
):
    """Top-N assets ranked by blast-radius score, proxied via BFF.

    Replaces the prior frontend direct call to /risk/api/v1/risk/blast-radius
    (which 401s because the engine does not accept session cookies).
    """
    tenant_id = resolve_tenant_id(request)
    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None

    # Risk engine caps limit at 50.
    (raw,) = await fetch_many(
        [("risk", "/api/v1/risk/assets/top", {"tenant_id": tenant_id, "limit": str(min(limit, 50))})],
        auth_headers=fwd_headers,
    )
    if not isinstance(raw, dict):
        raw = {}
    items = raw.get("assets") or raw.get("items") or []
    if not isinstance(items, list):
        items = []
    # Normalize field names so the FE can rely on a single shape regardless
    # of how the underlying engine evolves.
    norm = []
    for it in items:
        if not isinstance(it, dict):
            continue
        rscore = int(it.get("blast_radius_score") or it.get("risk_score") or 0)
        cscore = int(it.get("compound_risk_score") or 0) or min(int(it.get("threat_count") or 0) * 25, 100)
        norm.append({
            **it,
            "blast_radius_score": rscore,
            "compound_risk_score": cscore,
        })
    return {"items": norm, "tenant_id": tenant_id}


@router.get("/risk/compound-risk")
async def view_risk_compound_risk(request: Request):
    """Compound-risk scenarios proxied via BFF.

    Returns an empty list with not_yet_available=true when the engine has not
    surfaced compound-risk data (the endpoint is on the risk engine roadmap).
    """
    tenant_id = resolve_tenant_id(request)
    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None

    (raw,) = await fetch_many(
        [("risk", "/api/v1/risk/ui-data", {"tenant_id": tenant_id})],
        auth_headers=fwd_headers,
    )
    if not isinstance(raw, dict):
        raw = {}
    scenarios = raw.get("compound_risk") or raw.get("compound_scenarios") or []
    if not isinstance(scenarios, list):
        scenarios = []
    return {
        "items": scenarios,
        "tenant_id": tenant_id,
        "not_yet_available": len(scenarios) == 0,
    }

