"""BFF view: /ai-security page (AI Security Posture Management / AI-SPM).

Fetches data from the AI Security engine's /ui-data endpoint and transforms
it into the shape expected by the frontend dashboard.

Modules covered: Model Security, Endpoint Security, Prompt Security,
Data Pipeline, AI Governance, Access Control.
"""

from typing import Optional, Dict, List

from fastapi import APIRouter, Query

from ._shared import fetch_many, safe_get, mock_fallback, is_empty_or_health
from ._transforms import apply_global_filters
from ._page_context import ai_security_page_context, ai_security_filter_schema

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])

# Module key → display name mapping
MODULE_DISPLAY: Dict[str, str] = {
    "model_security": "Model Security",
    "endpoint_security": "Endpoint Security",
    "prompt_security": "Prompt Security",
    "data_pipeline": "Data Pipeline",
    "ai_governance": "AI Governance",
    "access_control": "Access Control",
}

SEV_SORT = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _severity_sort_key(item: dict) -> int:
    """Return sort order for severity (critical first)."""
    return SEV_SORT.get((item.get("severity") or "medium").lower(), 3)


def _build_modules(by_module: dict) -> List[dict]:
    """Transform engine by_module summary into frontend module cards."""
    modules = []
    for key, display_name in MODULE_DISPLAY.items():
        mod = by_module.get(key, {})
        if isinstance(mod, dict):
            modules.append({
                "name": display_name,
                "key": key,
                "score": mod.get("score", 0),
                "findings": mod.get("findings", 0),
                "critical": mod.get("critical", 0),
            })
        elif isinstance(mod, int):
            # Engine returned just a count per module
            modules.append({
                "name": display_name,
                "key": key,
                "score": 0,
                "findings": mod,
                "critical": 0,
            })
    return modules


def _normalize_ai_finding(f: dict) -> dict:
    """Normalize an AI security finding into UI-ready shape."""
    severity = (f.get("severity") or "medium").lower()
    frameworks = f.get("frameworks") or f.get("compliance_frameworks") or []
    if isinstance(frameworks, str):
        frameworks = [frameworks]
    return {
        "id": f.get("finding_id") or f.get("id", ""),
        "severity": severity,
        "rule_id": f.get("rule_id", ""),
        "title": f.get("title") or f.get("rule_name", ""),
        "resource_uid": f.get("resource_uid") or f.get("resource_arn", ""),
        "resource_type": f.get("resource_type", ""),
        "category": f.get("category") or f.get("module", ""),
        "status": (f.get("status") or "FAIL").upper(),
        "frameworks": frameworks,
        "provider": (f.get("provider") or "").upper(),
        "account": f.get("account_id") or f.get("account", ""),
        "region": f.get("region", ""),
        "remediation": f.get("remediation", ""),
    }


def _normalize_inventory_row(r: dict) -> dict:
    """Normalize an AI/ML resource inventory item."""
    return {
        "resource_uid": r.get("resource_uid") or r.get("resource_id", ""),
        "name": r.get("name") or (r.get("resource_uid") or "").rsplit("/", 1)[-1],
        "service": r.get("service") or r.get("resource_type", ""),
        "type": r.get("type") or r.get("resource_type", ""),
        "region": r.get("region", ""),
        "public": r.get("public") or r.get("public_access", False),
        "guardrails": r.get("guardrails", False),
        "risk_score": r.get("risk_score", 0),
        "provider": (r.get("provider") or "").upper(),
        "account": r.get("account_id") or r.get("account", ""),
    }


def _normalize_shadow_ai_item(item: dict) -> dict:
    """Normalize a shadow AI detection item."""
    return {
        "service": item.get("service", ""),
        "operation": item.get("operation", ""),
        "actor": item.get("actor") or item.get("principal", ""),
        "calls": item.get("calls") or item.get("count", 0),
        "last_seen": item.get("last_seen") or item.get("last_seen_at", ""),
    }


@router.get("/ai-security")
async def view_ai_security(
    tenant_id: str = Query(...),
    provider: Optional[str] = Query(None),
    account: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
    csp: str = Query("aws"),
    scan_id: str = Query("latest"),
):
    """Single endpoint returning everything the AI Security page needs."""

    effective_csp = csp or (provider.lower() if provider else "aws")

    results = await fetch_many([
        ("ai_security", "/api/v1/ai-security/ui-data", {
            "tenant_id": tenant_id,
            "csp": effective_csp,
            "scan_id": scan_id,
        }),
    ])

    data = results[0]
    if not isinstance(data, dict):
        data = {}

    # Mock fallback when engine data is empty
    if is_empty_or_health(data):
        m = mock_fallback("ai_security")
        if m is not None:
            return m

    summary = safe_get(data, "summary", {})
    by_severity = safe_get(summary, "by_severity", {})
    by_module = safe_get(summary, "by_module", {})

    # ── Findings ──
    raw_findings = safe_get(data, "findings", [])
    findings = [_normalize_ai_finding(f) for f in raw_findings]
    findings = apply_global_filters(findings, provider, account, region)
    findings.sort(key=_severity_sort_key)

    # ── Inventory (ML/AI resources) ──
    raw_inventory = safe_get(data, "inventory", [])
    inventory_rows = [_normalize_inventory_row(r) for r in raw_inventory]
    inventory_rows = apply_global_filters(inventory_rows, provider, account, region)

    # ── Shadow AI ──
    raw_shadow = safe_get(data, "shadow_ai", {})
    shadow_items = [_normalize_shadow_ai_item(s) for s in safe_get(raw_shadow, "items", [])]
    shadow_count = safe_get(raw_shadow, "count", None)
    if shadow_count is None:
        shadow_count = len(shadow_items)

    # ── Modules ──
    modules = _build_modules(by_module)

    # ── Top failing rules ──
    raw_top_rules = safe_get(data, "top_failing_rules", [])
    top_failing_rules = [
        {
            "rule_id": r.get("rule_id", ""),
            "title": r.get("title") or r.get("rule_name", ""),
            "count": r.get("count") or r.get("total", 0),
            "severity": (r.get("severity") or "medium").lower(),
        }
        for r in raw_top_rules
    ]

    # ── KPIs ──
    total_findings = safe_get(summary, "total_findings", None)
    if total_findings is None:
        total_findings = len(findings)

    total_ml_resources = safe_get(summary, "total_ml_resources", None)
    if total_ml_resources is None:
        total_ml_resources = len(inventory_rows)

    risk_score = safe_get(summary, "risk_score", 0)
    posture_score = safe_get(summary, "posture_score", 0)

    critical = by_severity.get("critical", 0)
    high = by_severity.get("high", 0)
    medium = by_severity.get("medium", 0)
    low = by_severity.get("low", 0)

    # Recount from filtered findings if scope filters are active
    if provider or account or region:
        total_findings = len(findings)
        total_ml_resources = len(inventory_rows)
        critical = sum(1 for f in findings if f["severity"] == "critical")
        high = sum(1 for f in findings if f["severity"] == "high")
        medium = sum(1 for f in findings if f["severity"] == "medium")
        low = sum(1 for f in findings if f["severity"] == "low")

    # Coverage metrics
    coverage = safe_get(summary, "coverage", {})

    # ── Page context ──
    page_ctx = ai_security_page_context(summary)
    page_ctx["tabs"] = [
        {"id": "overview", "label": "Overview", "count": total_findings},
        {"id": "inventory", "label": "AI Inventory", "count": total_ml_resources},
        {"id": "findings", "label": "Findings", "count": total_findings},
        {"id": "shadow_ai", "label": "Shadow AI", "count": shadow_count},
    ]

    return {
        "pageContext": page_ctx,
        "filterSchema": ai_security_filter_schema(list(MODULE_DISPLAY.keys())),
        "kpiGroups": [
            {
                "title": "AI Risk",
                "items": [
                    {"label": "Critical", "value": critical},
                    {"label": "High", "value": high},
                    {"label": "Medium", "value": medium},
                    {"label": "Risk Score", "value": risk_score, "suffix": "/100"},
                    {"label": "Total Findings", "value": total_findings},
                ],
            },
            {
                "title": "AI Posture",
                "items": [
                    {"label": "Posture Score", "value": posture_score, "suffix": "/100"},
                    {"label": "ML Resources", "value": total_ml_resources},
                    {"label": "Shadow AI", "value": shadow_count},
                    {"label": "Guardrails", "value": coverage.get("guardrails_pct", 0), "suffix": "%"},
                    {"label": "Modules", "value": len(modules)},
                ],
            },
        ],
        "modules": modules,
        "coverage": {
            "vpc_isolation_pct": coverage.get("vpc_isolation_pct", 0),
            "encryption_rest_pct": coverage.get("encryption_rest_pct", 0),
            "encryption_transit_pct": coverage.get("encryption_transit_pct", 0),
            "model_card_pct": coverage.get("model_card_pct", 0),
            "monitoring_pct": coverage.get("monitoring_pct", 0),
            "guardrails_pct": coverage.get("guardrails_pct", 0),
        },
        "inventory": inventory_rows,
        "shadowAi": {
            "count": shadow_count,
            "items": shadow_items,
        },
        "findings": findings,
        "topFailingRules": top_failing_rules,
    }
