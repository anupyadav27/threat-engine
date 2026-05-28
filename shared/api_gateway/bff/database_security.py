"""BFF view: /database-security page.

Uses the database-security engine's /ui-data endpoint which returns all
database security data pre-organized: databases, findings, domain scores,
and a summary with KPI-ready metrics.

Single call to engine-dbsec/api/v1/database-security/ui-data.
"""

from typing import Optional

from fastapi import APIRouter, Query, Request

from ._auth import resolve_tenant_id
from ._shared import fetch_many, fetch_all_check_findings, safe_get, is_empty_or_health, BFFMeta
from .schemas.database_security import DatabaseSecurityResponse
from ._transforms import apply_global_filters
from ._page_context import database_security_page_context, database_security_filter_schema

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


@router.get("/database-security", response_model=DatabaseSecurityResponse, response_model_exclude_none=False)
async def view_database_security(
    request: Request,
    provider: Optional[str] = Query(None),
    account: Optional[str] = Query(None),
    tenant_ids: Optional[str] = Query(None),
    account_ids: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
    scan_id: str = Query("latest"),
):
    """Single endpoint returning everything the database security page needs."""

    tenant_id = resolve_tenant_id(request)
    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None
    meta = BFFMeta("database_security")

    results = await fetch_many([
        ("dbsec", "/api/v1/database-security/ui-data", {
            "tenant_id": tenant_id,
            "scan_id": scan_id,
        }),
    ], auth_headers=fwd_headers)

    dbsec_data = results[0]
    meta.record_engine("dbsec", "/api/v1/database-security/ui-data", dbsec_data)
    if not isinstance(dbsec_data, dict):
        dbsec_data = {}

    # Fallback: check engine (database_security domain) when dedicated engine has no data
    _has_dbsec = safe_get(dbsec_data, "findings", []) or safe_get(dbsec_data, "databases", [])
    if is_empty_or_health(dbsec_data) or not _has_dbsec:
        check_raw = await fetch_all_check_findings({
            "tenant_id": tenant_id,
            "domain": "database_security",
        }, auth_headers=fwd_headers)
        if check_raw:
            meta.set_fallback("dbsec engine returned no data; using check engine database_security domain")
            dbsec_data = {"findings": check_raw, "databases": [], "summary": {}}
        else:
            meta.warn("Both dbsec engine and check engine fallback returned no data")

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

    # -- Enrich database rows with required table columns ---------------------
    enriched_databases = []
    for db in filtered_databases:
        enriched_databases.append({
            **db,
            'name':               db.get('name') or db.get('db_instance_id') or db.get('resource_uid', ''),
            'db_engine':          db.get('db_engine') or db.get('engine', ''),
            'db_service':         db.get('db_service') or db.get('db_type', ''),
            'provider':           (db.get('provider') or '').upper(),
            'region':             db.get('region', ''),
            'account_id':         db.get('account_id') or db.get('account', ''),
            'publicly_accessible':db.get('publicly_accessible', False),
            'encrypted':          db.get('encrypted') or db.get('storage_encrypted', False),
            'multi_az':           db.get('multi_az', False),
            'posture_score':      db.get('posture_score', 0),
            'status':             db.get('status', ''),
        })

    # -- Enrich finding rows with required table columns ----------------------
    color_map = {'critical': '#ef4444', 'high': '#f97316', 'medium': '#eab308', 'low': '#3b82f6'}
    enriched_findings = []
    for f in filtered_findings:
        uid = f.get('resource_arn') or f.get('resource_uid') or ''
        sev = (f.get('severity') or 'medium').lower()
        enriched_findings.append({
            **f,
            'resource_name':   f.get('resource_name') or uid.rsplit('/', 1)[-1] or uid,
            'severity':        sev,
            'status':          f.get('status') or f.get('result') or 'FAIL',
            'title':           f.get('title') or f.get('rule_name') or '',
            'rule_id':         f.get('rule_id', ''),
            'account_id':      f.get('account_id') or f.get('account', ''),
            'region':          f.get('region', ''),
            'provider':        f.get('provider', ''),
            'resource_type':   f.get('resource_type', ''),
            'db_service':      f.get('db_service') or f.get('service', ''),
            'db_engine':       f.get('db_engine') or f.get('engine', ''),
            'security_domain': f.get('security_domain') or f.get('domain', ''),
            'finding_id':      str(f.get('finding_id') or f.get('id') or ''),
            'original':        {'account': f.get('account_id') or f.get('account', ''),
                                'db_service': f.get('db_service') or f.get('service', ''),
                                'security_domain': f.get('security_domain', '')},
            'meta':            {'color': color_map.get(sev, '#6b7280'), 'label': sev.title()},
        })

    # -- Scan trend with chart dataKeys ----------------------------------------
    raw_trend = safe_get(dbsec_data, "scan_trend", [])
    scan_trend = []
    for pt in raw_trend:
        sev_pt = pt.get("by_severity") or {}
        total_pt = pt.get("total_findings") or pt.get("total", 0)
        scan_trend.append({
            "date":     pt.get("scan_date") or pt.get("date", ""),
            "critical": sev_pt.get("critical", pt.get("critical", 0)),
            "high":     sev_pt.get("high",     pt.get("high",     0)),
            "medium":   sev_pt.get("medium",   pt.get("medium",   0)),
            "low":      sev_pt.get("low",      pt.get("low",      0)),
            "passRate": pt.get("pass_rate") or pt.get("passRate", 0),
            "total":    total_pt,
        })

    first_pt  = scan_trend[0]  if scan_trend else {}
    last_pt   = scan_trend[-1] if scan_trend else {}
    first_obj = {k: first_pt.get(k, 0) for k in ("date", "critical", "high", "total")}
    last_obj  = {k: last_pt.get(k, 0)  for k in ("date", "critical", "high", "total")}

    # -- Donut slices ----------------------------------------------------------
    donut_slices = [
        {"name": sev.title(), "value": by_severity.get(sev, 0), "color": color_map[sev]}
        for sev in ("critical", "high", "medium", "low")
        if by_severity.get(sev, 0) > 0
    ]

    # -- Active module scores (domain scores as module cards) ------------------
    active_module_scores = [
        {
            "key":   domain,
            "label": domain.replace("_", " ").title(),
            "score": domain_scores.get(domain, 0),
            "pass":  (domain_scores.get(domain) or 0) >= 70,
        }
        for domain in default_domains
    ]

    # -- Domain breakdown -------------------------------------------------------
    domain_breakdown = safe_get(dbsec_data, "domain_breakdown", [])
    db_domains = domain_breakdown if isinstance(domain_breakdown, list) else []

    meta.expect_fields(
        dbsec_data,
        ["findings", "databases", "summary"],
        context="dbsec engine ui-data",
    )

    return {
        "pageContext": page_ctx,
        "filterSchema": database_security_filter_schema(),
        "kpiGroups": [
            {
                "title": "Database Posture",
                "items": [
                    {"label": "Posture Score",    "value": posture_score,                          "suffix": "/100"},
                    {"label": "Total Findings",   "value": len(enriched_findings)},
                    {"label": "Total Databases",  "value": total_databases},
                    {"label": "Public Databases", "value": public_databases},
                    {"label": "Critical",         "value": by_severity.get("critical", 0)},
                    {"label": "High",             "value": by_severity.get("high", 0)},
                    {"label": "Medium",           "value": by_severity.get("medium", 0)},
                    {"label": "Low",              "value": by_severity.get("low", 0)},
                ],
            },
        ],
        "databases":          enriched_databases,
        "findings":           enriched_findings,
        "domain_scores":      domain_scores,
        "domainBreakdown":    domain_breakdown,
        "db":                 db_domains,
        "scanTrend":          scan_trend,
        "activeScanTrend":    scan_trend,
        "first":              first_obj,
        "last":               last_obj,
        "donutSlices":        donut_slices,
        "activeModuleScores": active_module_scores,
        "_meta":              meta.to_dict(),
    }
