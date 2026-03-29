"""BFF view: /database-security page.

Uses the database-security engine's /ui-data endpoint which returns all
database security data pre-organized: databases, findings, domain scores,
and a summary with KPI-ready metrics.

Single call to engine-dbsec/api/v1/database-security/ui-data.
"""

from typing import Optional

from fastapi import APIRouter, Query

from ._shared import fetch_many, safe_get, mock_fallback, is_empty_or_health
from ._transforms import apply_global_filters
from ._page_context import database_security_page_context, database_security_filter_schema

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


@router.get("/database-security")
async def view_database_security(
    tenant_id: str = Query(...),
    provider: Optional[str] = Query(None),
    account: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
    scan_id: str = Query("latest"),
):
    """Single endpoint returning everything the database security page needs."""

    results = await fetch_many([
        ("dbsec", "/api/v1/database-security/ui-data", {
            "tenant_id": tenant_id,
            "scan_id": scan_id,
        }),
    ])

    dbsec_data = results[0]
    if not isinstance(dbsec_data, dict):
        dbsec_data = {}

    # Mock fallback when engine data is empty
    if is_empty_or_health(dbsec_data):
        m = mock_fallback("database_security")
        if m is not None:
            return m

    summary = safe_get(dbsec_data, "summary", {})

    # ── Databases ───────────────────────────────────────────────────────────
    raw_databases = safe_get(dbsec_data, "databases", [])
    filtered_databases = apply_global_filters(raw_databases, provider, account, region)

    # ── Findings ────────────────────────────────────────────────────────────
    raw_findings = safe_get(dbsec_data, "findings", [])
    filtered_findings = apply_global_filters(raw_findings, provider, account, region)

    # ── Domain scores ───────────────────────────────────────────────────────
    domain_scores = safe_get(dbsec_data, "domain_scores", {})

    # ── KPI derivation ──────────────────────────────────────────────────────
    total_databases = safe_get(summary, "total_databases", None)
    if total_databases is None:
        total_databases = len(filtered_databases)

    public_databases = safe_get(summary, "public_databases", None)
    if public_databases is None:
        public_databases = sum(
            1 for db in filtered_databases
            if db.get("publicly_accessible") in (True, "true", "True", "yes")
        )

    # Posture score from summary or derived from findings
    posture_score = safe_get(summary, "posture_score", 0)
    if not posture_score and filtered_findings:
        sev_weights = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        total_weight = sum(
            sev_weights.get((f.get("severity") or "medium").lower(), 2)
            for f in filtered_findings
        )
        max_weight = len(filtered_findings) * 4
        posture_score = max(0, 100 - round((total_weight / max_weight) * 100)) if max_weight else 100

    # Findings by severity
    by_severity = safe_get(summary, "by_severity", {})
    if not by_severity and filtered_findings:
        by_severity = {}
        for f in filtered_findings:
            sev = (f.get("severity") or "medium").lower()
            by_severity[sev] = by_severity.get(sev, 0) + 1

    # Default domain scores if not provided
    default_domains = [
        "access_control", "encryption", "audit_logging",
        "backup_recovery", "network_security", "configuration",
    ]
    if not domain_scores:
        domain_scores = {d: 0 for d in default_domains}

    # ── Page context ────────────────────────────────────────────────────────
    page_ctx = database_security_page_context(summary)
    page_ctx["brief"] = (
        f"{total_databases} databases monitored — "
        f"{public_databases} publicly accessible, posture score {posture_score}/100"
    )
    page_ctx["tabs"] = [
        {"id": "overview", "label": "Overview"},
        {"id": "inventory", "label": "Inventory", "count": len(filtered_databases)},
        {"id": "findings", "label": "Findings", "count": len(filtered_findings)},
        {"id": "access_control", "label": "Access Control"},
        {"id": "encryption", "label": "Encryption"},
        {"id": "audit_logging", "label": "Audit Logging"},
    ]

    return {
        "pageContext": page_ctx,
        "filterSchema": database_security_filter_schema(),
        "kpiGroups": [
            {
                "title": "Database Posture",
                "items": [
                    {"label": "Posture Score", "value": posture_score, "suffix": "/100"},
                    {"label": "Total Databases", "value": total_databases},
                    {"label": "Public Databases", "value": public_databases},
                ],
            },
            {
                "title": "Findings by Severity",
                "items": [
                    {"label": "Critical", "value": by_severity.get("critical", 0)},
                    {"label": "High", "value": by_severity.get("high", 0)},
                    {"label": "Medium", "value": by_severity.get("medium", 0)},
                    {"label": "Low", "value": by_severity.get("low", 0)},
                ],
            },
        ],
        "data": {
            "databases": filtered_databases,
            "findings": filtered_findings,
            "domain_scores": domain_scores,
        },
    }
