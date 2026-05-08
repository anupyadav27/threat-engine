"""BFF view: /reports page.

Consolidates compliance + onboarding ui-data endpoints into 1 BFF call.
Derives scheduled reports from cloud account schedule data
since /api/v1/compliance/reports/scheduled doesn't exist.

Uses:
  - compliance /api/v1/compliance/ui-data  -> reports, frameworks
  - onboarding /api/v1/onboarding/ui-data  -> accounts
"""

from typing import Dict

from fastapi import APIRouter, Query, Request

from ._auth import resolve_tenant_id
from ._shared import fetch_many, safe_get, BFFMeta
from .schemas.reports import ReportsResponse
from ._transforms import normalize_report, normalize_scheduled_report, _safe_upper

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


@router.get("/reports", response_model=ReportsResponse, response_model_exclude_none=False)
async def view_reports(
    request: Request,
):
    """Single endpoint returning everything the reports page needs."""

    tenant_id = resolve_tenant_id(request)
    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None
    meta = BFFMeta("reports")

    results = await fetch_many([
        ("compliance", "/api/v1/compliance/ui-data", {"tenant_id": tenant_id, "scan_id": "latest"}),
        ("onboarding", "/api/v1/cloud-accounts", {"tenant_id": tenant_id}),
    ], auth_headers=fwd_headers)

    compliance_data, onboarding_data = results
    meta.record_engine("compliance", "/api/v1/compliance/ui-data", compliance_data)
    meta.record_engine("onboarding", "/api/v1/cloud-accounts", onboarding_data)

    # Extract reports from compliance/ui-data
    raw_reports = safe_get(compliance_data, "reports", []) if isinstance(compliance_data, dict) else []
    reports = [normalize_report(r) for r in raw_reports]

    # If no reports, generate from framework data in compliance/ui-data
    if not reports:
        raw_fw = safe_get(compliance_data, "frameworks", []) if isinstance(compliance_data, dict) else []
        for i, fw in enumerate(raw_fw):
            fw_name = fw if isinstance(fw, str) else (fw.get("framework_name") or fw.get("compliance_framework") or fw.get("name", ""))
            if fw_name:
                reports.append({
                    "id": f"report-{i}",
                    "name": f"{fw_name} Compliance Report",
                    "template": fw_name,
                    "generated": None,
                    "generatedBy": "System",
                    "format": "PDF",
                    "size": "",
                    "status": "available",
                })

    # Build scheduled reports from cloud account schedules in onboarding/ui-data
    scheduled = []
    raw_accounts = safe_get(onboarding_data, "accounts", []) if isinstance(onboarding_data, dict) else []
    for a in raw_accounts:
        if not a.get("schedule_enabled"):
            continue
        acct_name = a.get("account_name") or a.get("account_id", "")
        prov = _safe_upper(a.get("provider") or a.get("csp"))
        scheduled.append(normalize_scheduled_report({
            "id": a.get("account_id", ""),
            "name": f"{prov} - {acct_name} Compliance Report",
            "report_type": "Compliance",
            "schedule": a.get("schedule_cron_expression", ""),
            "email_recipients": a.get("schedule_notification_emails", []),
            "format": "PDF",
            "next_run": a.get("schedule_next_run_at"),
            "last_run": a.get("schedule_last_run_at"),
            "status": "active" if a.get("schedule_enabled") else "paused",
        }))

    # KPI derivation
    total = len(reports)
    by_format: Dict[str, int] = {}
    for r in reports:
        fmt = r.get("format", "PDF")
        by_format[fmt] = by_format.get(fmt, 0) + 1
    by_template: Dict[str, int] = {}
    for r in reports:
        tmpl = r.get("template", "Unknown")
        by_template[tmpl] = by_template.get(tmpl, 0) + 1

    # Normalize report rows to have all table columns the UI expects
    def _enrich_report(r: dict) -> dict:
        return {
            **r,
            "date":        r.get("generated") or r.get("date", ""),
            "framework":   r.get("template") or r.get("framework", ""),
            "assessed":    r.get("assessed", ""),
            "attestedBy":  r.get("generatedBy") or r.get("attestedBy", ""),
            "auditPeriod": r.get("auditPeriod", ""),
            "collected":   r.get("collected", ""),
        }

    def _enrich_scheduled(s: dict) -> dict:
        return {
            **s,
            "frequency": s.get("schedule") or s.get("frequency", ""),
            "lastRun":   s.get("last_run") or s.get("lastRun", ""),
            "nextRun":   s.get("next_run") or s.get("nextRun", ""),
            "recipients": s.get("email_recipients") or s.get("recipients", []),
        }

    enriched_reports    = [_enrich_report(r) for r in reports]
    enriched_scheduled  = [_enrich_scheduled(s) for s in scheduled]

    # Report templates (derived from unique frameworks)
    templates = [
        {"id": tmpl, "name": tmpl, "desc": f"{tmpl} compliance report template", "format": "PDF"}
        for tmpl in by_template.keys()
    ]

    tabs = [
        {"id": "reports",   "label": "Reports",           "count": total},
        {"id": "scheduled", "label": "Scheduled Reports", "count": len(scheduled)},
        {"id": "templates", "label": "Templates",         "count": len(templates)},
    ]

    return {
        "kpi": {
            "totalReports": total,
            "scheduledCount": len(scheduled),
            "byFormat": by_format,
            "byTemplate": by_template,
        },
        "reports":   enriched_reports,
        "scheduled": enriched_scheduled,
        "templates": templates,
        "tabs":      tabs,
        "_meta":     meta.to_dict(),
    }
