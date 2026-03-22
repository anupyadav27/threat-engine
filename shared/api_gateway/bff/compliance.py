"""BFF view: /compliance page.

Consolidates into 3 parallel calls (compliance/ui-data + onboarding/ui-data + threat/ui-data).
Adds resilience: score computation from passed/failed ratio, trend fallback,
framework score derivation when engine returns all zeros.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

from fastapi import APIRouter, Query

from ._shared import fetch_many, safe_get
from ._transforms import normalize_framework, normalize_failing_control

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])

MATRIX_FRAMEWORKS = ["CIS", "NIST", "SOC2", "PCI", "HIPAA", "ISO", "GDPR"]


@router.get("/compliance")
async def view_compliance(
    tenant_id: str = Query(...),
    provider: Optional[str] = Query(None),
    account: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
    scan_run_id: str = Query("latest"),
):
    """Single endpoint returning everything the compliance page needs."""

    # ── 3 parallel calls instead of 5 ────────────────────────────────────
    results = await fetch_many([
        ("compliance", "/api/v1/compliance/ui-data", {"tenant_id": tenant_id, "scan_id": "latest"}),
        ("onboarding", "/api/v1/cloud-accounts", {"tenant_id": tenant_id}),
        ("threat",     "/api/v1/threat/ui-data",     {"tenant_id": tenant_id, "scan_run_id": "latest", "limit": "1"}),
    ])

    compliance_data, onboarding_data, threat_data = results

    # Safely unwrap responses
    compliance_data = compliance_data if isinstance(compliance_data, dict) else {}
    onboarding_data = onboarding_data if isinstance(onboarding_data, dict) else {}
    threat_data = threat_data if isinstance(threat_data, dict) else {}

    # ── Normalize frameworks ─────────────────────────────────────────────
    fw_list = compliance_data.get("frameworks", [])
    if not isinstance(fw_list, list):
        fw_list = []
    frameworks = [normalize_framework(fw) for fw in fw_list if isinstance(fw, dict)]

    # If all scores are 0, derive from passed/failed
    all_zero = all(fw.get("score", 0) == 0 for fw in frameworks) if frameworks else True
    if all_zero and frameworks:
        for fw in frameworks:
            passed = fw.get("passed", 0)
            failed = fw.get("failed", 0)
            total_c = passed + failed
            if total_c > 0:
                fw["score"] = round((passed / total_c) * 100, 1)

    # If still no frameworks, create from raw strings
    if not frameworks and isinstance(fw_list, list):
        for fw in fw_list:
            if isinstance(fw, str):
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

    audit_deadlines = compliance_data.get("audit_deadlines", [])
    exceptions = compliance_data.get("exceptions", [])

    # Per-account score lookup (from compliance ui-data if available)
    per_account_scores: Dict[str, dict] = {}
    for entry in compliance_data.get("per_account_scores", []):
        acct_id = entry.get("account_id", "")
        if acct_id:
            per_account_scores[acct_id] = entry

    # ── Account compliance matrix ────────────────────────────────────────
    raw_accounts = onboarding_data.get("accounts", [])
    if not isinstance(raw_accounts, list):
        raw_accounts = []
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
            row[fw_key] = acct_scores.get(fw_key, 0) or acct.get(fw_key, 0)
        if all(row.get(k, 0) == 0 for k in MATRIX_FRAMEWORKS) and overall_score:
            for fw_key in MATRIX_FRAMEWORKS:
                row[fw_key] = round(overall_score)
        scores = [row.get(k, 0) for k in MATRIX_FRAMEWORKS if row.get(k, 0) > 0]
        row["avg"] = round(sum(scores) / len(scores), 1) if scores else 0
        account_matrix.append(row)

    if provider:
        account_matrix = [r for r in account_matrix if r["provider"] == provider.upper()]
    if account:
        account_matrix = [r for r in account_matrix if r["account_id"] == account or r["account"] == account]

    critical_failures = sum(1 for c in failing if c.get("severity") == "critical")
    at_risk_count = sum(1 for fw in frameworks if fw.get("score", 0) < 70)

    return {
        "overallScore": overall_score or round(pass_rate, 1),
        "passRate": round(pass_rate, 1),
        "passedControls": passed_total,
        "failedControls": failed_total,
        "totalControls": total_controls,
        "criticalFailures": critical_failures,
        "atRiskFrameworks": at_risk_count,
        "frameworks": frameworks,
        "failingControls": failing,
        "trendData": trend_data_out,
        "auditDeadlines": audit_deadlines,
        "exceptions": exceptions,
        "accountMatrix": account_matrix,
    }
