"""BFF view: /reports page.

Consolidates compliance + onboarding ui-data endpoints into 1 BFF call.
Derives scheduled reports from cloud account schedule data
since /api/v1/compliance/reports/scheduled doesn't exist.

Uses:
  - compliance /api/v1/compliance/ui-data  -> reports, frameworks
  - onboarding /api/v1/onboarding/ui-data  -> accounts
"""

from typing import Dict

from fastapi import APIRouter, Query

from ._shared import fetch_many, safe_get
from ._transforms import normalize_report, normalize_scheduled_report, _safe_upper

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


@router.get("/reports")
async def view_reports(
    tenant_id: str = Query(...),
):
    """Single endpoint returning everything the reports page needs."""

    results = await fetch_many([
        ("compliance", "/api/v1/compliance/ui-data", {"tenant_id": tenant_id, "scan_id": "latest"}),
        ("onboarding", "/api/v1/onboarding/ui-data", {"tenant_id": tenant_id}),
    ])

    compliance_data, onboarding_data = results

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

    return {
        "kpi": {
            "totalReports": total,
            "scheduledCount": len(scheduled),
            "byFormat": by_format,
            "byTemplate": by_template,
        },
        "reports": reports,
        "scheduled": scheduled,
    }
