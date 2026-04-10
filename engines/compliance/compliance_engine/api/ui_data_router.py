"""
Compliance Engine - Unified UI Data Endpoint

Provides a single GET endpoint that returns all compliance data needed
by the frontend in one request, avoiding multiple round-trips.

Endpoint: GET /api/v1/compliance/ui-data?tenant_id=X&scan_id=latest
"""

import os
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

import psycopg2
import psycopg2.extras
from fastapi import APIRouter, HTTPException, Query

logger = logging.getLogger(__name__)

router = APIRouter(tags=["ui-data"])


def _get_compliance_db_connection():
    """Create a connection to the compliance database.

    Returns:
        psycopg2 connection object.

    Raises:
        psycopg2.Error: If connection cannot be established.
    """
    return psycopg2.connect(
        host=os.getenv("COMPLIANCE_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("COMPLIANCE_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("COMPLIANCE_DB_NAME", "threat_engine_compliance"),
        user=os.getenv("COMPLIANCE_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("COMPLIANCE_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        connect_timeout=10,
    )


def _resolve_latest_report(
    cur: Any,
    tenant_id: str,
) -> Optional[Dict[str, Any]]:
    """Resolve the most recent compliance_report row for a tenant.

    Args:
        cur: Database cursor (RealDictCursor).
        tenant_id: The tenant identifier.

    Returns:
        The report row as a dict, or None if no report exists.
    """
    cur.execute(
        """
        SELECT scan_run_id, tenant_id, check_scan_id,
               total_controls, controls_passed, controls_failed,
               report_data, created_at, status, provider
        FROM compliance_report
        WHERE tenant_id = %s
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (tenant_id,),
    )
    return cur.fetchone()


def _resolve_report_by_scan_id(
    cur: Any,
    tenant_id: str,
    scan_id: str,
) -> Optional[Dict[str, Any]]:
    """Resolve a compliance_report row by scan_run_id.

    Args:
        cur: Database cursor (RealDictCursor).
        tenant_id: The tenant identifier.
        scan_id: The scan_run_id to look up.

    Returns:
        The report row as a dict, or None if not found.
    """
    cur.execute(
        """
        SELECT scan_run_id, tenant_id, check_scan_id,
               total_controls, controls_passed, controls_failed,
               report_data, created_at, status, provider
        FROM compliance_report
        WHERE tenant_id = %s AND scan_run_id = %s
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (tenant_id, scan_id),
    )
    return cur.fetchone()


def _extract_posture_summary(report_row: Dict[str, Any]) -> Dict[str, Any]:
    """Extract posture_summary from report_data JSONB or fall back to columns.

    IMPORTANT: psycopg2 auto-deserializes JSONB to dict -- never call
    json.loads() on report_data.

    Args:
        report_row: A compliance_report row dict.

    Returns:
        A posture_summary dict with all expected keys.
    """
    report_data = report_row.get("report_data")
    posture = {}

    if isinstance(report_data, dict):
        posture = report_data.get("posture_summary", {})
        if not isinstance(posture, dict):
            posture = {}

    # Ensure all expected keys are present, falling back to column values
    return {
        "total_controls": posture.get(
            "total_controls", report_row.get("total_controls", 0)
        ),
        "controls_passed": posture.get(
            "controls_passed", report_row.get("controls_passed", 0)
        ),
        "controls_failed": posture.get(
            "controls_failed", report_row.get("controls_failed", 0)
        ),
        "total_findings": posture.get("total_findings", 0),
        "findings_by_severity": posture.get("findings_by_severity", {}),
    }


def _compute_overall_score(posture: Dict[str, Any]) -> float:
    """Compute overall compliance score as a percentage.

    Args:
        posture: The posture_summary dict.

    Returns:
        Score from 0.0 to 100.0, rounded to one decimal.
    """
    total = posture.get("total_controls", 0)
    passed = posture.get("controls_passed", 0)
    if total and total > 0:
        return round((passed / total) * 100, 1)
    return 0.0


def _get_framework_summaries(
    cur: Any,
    report_id: str,
    tenant_id: str,
    report_data: Any,
) -> List[Dict[str, Any]]:
    """Build per-framework summary objects including last_assessed timestamp.

    IMPORTANT: The compliance_db_writer writes ALL findings with status='open'
    (it only persists FAIL checks). Framework name may be stored in
    finding_data->>'framework' when compliance_framework column is empty.
    Passed controls are derived from (report total_controls - fail findings count).

    Args:
        cur: Database cursor (RealDictCursor).
        report_id: The compliance report identifier.
        tenant_id: The tenant identifier.
        report_data: The report_data JSONB value (already deserialized).

    Returns:
        A list of framework summary dicts.
    """
    # Use finding_data->>'framework' as fallback when compliance_framework is empty.
    # ALL findings stored here are failures (writer only inserts check_result='FAIL'),
    # so COUNT(*) = failed_controls. Passed = report-level passed / framework count.
    cur.execute(
        """
        WITH fw_keys AS (
            SELECT
                COALESCE(
                    NULLIF(cf.compliance_framework, ''),
                    cf.finding_data->>'framework',
                    'Unknown'
                ) AS framework_key,
                COUNT(*)          AS failed_controls,
                MAX(cf.last_seen_at) AS last_assessed
            FROM compliance_findings cf
            WHERE cf.scan_run_id = %s AND cf.tenant_id = %s
            GROUP BY framework_key
        )
        SELECT
            fk.framework_key,
            COALESCE(fw.framework_name, fk.framework_key, 'Unknown Framework') AS framework_name,
            fw.framework_id     AS fw_table_id,
            fw.version          AS framework_version,
            fw.authority        AS framework_authority,
            fw.category         AS framework_category,
            fk.failed_controls,
            fk.last_assessed
        FROM fw_keys fk
        LEFT JOIN compliance_frameworks fw ON fk.framework_key = fw.framework_id
        ORDER BY fk.framework_key
        """,
        (report_id, tenant_id),
    )
    rows = cur.fetchall()

    # Get report-level totals so we can compute passed = total - failed
    total_from_report   = int((report_data or {}).get("total_controls", 0)
                              if isinstance(report_data, dict) else 0)
    passed_from_report  = int((report_data or {}).get("controls_passed", 0)
                              if isinstance(report_data, dict) else 0)

    if rows:
        frameworks = []
        num_fw = len(rows)
        for row in rows:
            failed       = int(row["failed_controls"] or 0)
            # Distribute report-level passed evenly across frameworks when
            # we cannot tell per-framework pass counts (all-fail writer pattern).
            passed       = max(0, passed_from_report // num_fw) if num_fw else 0
            total        = failed + passed
            score        = round((passed / total) * 100, 1) if total > 0 else 0.0
            last_assessed = row.get("last_assessed")
            frameworks.append(
                {
                    "framework_id":        row.get("fw_table_id") or row["framework_key"],
                    "framework_name":      row["framework_name"],
                    "framework_version":   row.get("framework_version"),
                    "framework_authority": row.get("framework_authority"),
                    "framework_category":  row.get("framework_category"),
                    "score":               score,
                    "passed_controls":     passed,
                    "failed_controls":     failed,
                    "total_controls":      total,
                    "last_assessed": (
                        last_assessed.isoformat()
                        if isinstance(last_assessed, datetime)
                        else str(last_assessed) if last_assessed else None
                    ),
                }
            )
        return frameworks

    # Fallback: extract framework names from report_data JSONB
    if isinstance(report_data, dict):
        # Try framework_reports dict (full report structure)
        fw_reports = report_data.get("framework_reports", {})
        if isinstance(fw_reports, dict) and fw_reports:
            out = []
            for fw_key, fw_val in fw_reports.items():
                if not fw_key:
                    continue
                stats = fw_val.get("statistics", {}) if isinstance(fw_val, dict) else {}
                passed = int(stats.get("controls_passed", 0))
                failed = int(stats.get("controls_failed", 0))
                total  = int(stats.get("controls_total", passed + failed))
                score  = round((passed / total) * 100, 1) if total > 0 else 0.0
                out.append({
                    "framework_id":    fw_key,
                    "framework_name":  fw_val.get("framework_name", fw_key) if isinstance(fw_val, dict) else fw_key,
                    "score":           score,
                    "passed_controls": passed,
                    "failed_controls": failed,
                    "total_controls":  total,
                    "last_assessed":   None,
                })
            if out:
                return out
        # Try simple framework_ids list
        framework_ids = report_data.get("framework_ids", [])
        if isinstance(framework_ids, list) and framework_ids:
            return [
                {
                    "framework_id":    fid,
                    "framework_name":  fid,
                    "score":           0.0,
                    "passed_controls": 0,
                    "failed_controls": 0,
                    "total_controls":  0,
                    "last_assessed":   None,
                }
                for fid in framework_ids if fid
            ]

    return []


def _get_failing_controls(
    cur: Any,
    report_id: str,
    tenant_id: str,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """Retrieve the top failing controls with account, region, and days_open.

    IMPORTANT: The compliance_db_writer only stores FAIL findings and marks
    them status='open'. Do NOT filter on status='FAIL' — every row here is
    a failure. Use finding_data JSONB as fallback for empty columns.

    Args:
        cur: Database cursor (RealDictCursor).
        report_id: The compliance report identifier.
        tenant_id: The tenant identifier.
        limit: Maximum number of failing controls to return.

    Returns:
        A list of failing control dicts.
    """
    cur.execute(
        """
        SELECT
            COALESCE(NULLIF(cf.control_id, ''), cf.finding_data->>'control_id', cf.rule_id)
                                                                          AS eff_control_id,
            COALESCE(
                NULLIF(cf.compliance_framework, ''),
                cf.finding_data->>'framework',
                'Unknown'
            )                                                             AS eff_framework,
            cf.severity,
            cf.account_id,
            cf.region,
            COUNT(*)                                                      AS failed_resources,
            COALESCE(
                cc.control_name,
                NULLIF(cf.control_name, ''),
                cf.finding_data->>'control_title',
                cf.finding_data->>'control_id',
                cf.rule_id
            )                                                             AS control_name,
            cc.control_description,
            cc.control_family,
            EXTRACT(DAY FROM (NOW() - MIN(cf.first_seen_at)))::INT        AS days_open
        FROM compliance_findings cf
        LEFT JOIN compliance_controls cc
            ON COALESCE(NULLIF(cf.control_id, ''), cf.finding_data->>'control_id') = cc.control_id
        WHERE cf.scan_run_id = %s
          AND cf.tenant_id   = %s
          AND UPPER(cf.status) NOT IN ('PASS', 'RESOLVED', 'CLOSED', 'FIXED', 'SUPPRESSED')
        GROUP BY
            COALESCE(NULLIF(cf.control_id, ''), cf.finding_data->>'control_id', cf.rule_id),
            COALESCE(NULLIF(cf.compliance_framework, ''), cf.finding_data->>'framework', 'Unknown'),
            cf.severity, cf.account_id, cf.region,
            cc.control_name, cf.control_name, cf.finding_data->>'control_title',
            cf.finding_data->>'control_id', cf.rule_id,
            cc.control_description, cc.control_family
        ORDER BY failed_resources DESC
        LIMIT %s
        """,
        (report_id, tenant_id, limit),
    )
    rows = cur.fetchall()
    return [
        {
            "control_id":          row["eff_control_id"] or "",
            "control_name":        row["control_name"] or row["eff_control_id"] or "",
            "control_description": row.get("control_description"),
            "control_family":      row.get("control_family"),
            "framework_id":        row["eff_framework"],
            "severity":            row["severity"],
            "account_id":          row.get("account_id") or "",
            "region":              row.get("region") or "",
            "failed_resources":    int(row["failed_resources"] or 0),
            "days_open":           int(row.get("days_open") or 0),
        }
        for row in rows
    ]


def _get_per_account_scores(
    cur: Any,
    tenant_id: str,
    report_id: str,
    report_data: Any = None,
) -> List[Dict[str, Any]]:
    """Compute actual per-account compliance scores per framework.

    IMPORTANT: The compliance_db_writer ONLY writes FAIL findings (status='open').
    There are no PASS rows in compliance_findings, so we cannot count passed rows
    directly. Instead we:
      1. Count failures per account + framework (all stored rows are failures).
      2. Look up total controls per framework from report_data JSONB
         (framework_reports[fw_name].statistics.controls_total).
      3. Score = (total_per_account - failed) / total_per_account × 100,
         where total_per_account = fw_total / num_distinct_accounts.

    Args:
        cur: Database cursor (RealDictCursor).
        tenant_id: The tenant identifier.
        report_id: The scan_run_id of the target report.
        report_data: Deserialized compliance_report.report_data JSONB (optional).

    Returns:
        A list of dicts: {account_id, <framework_key>: score, ...}
    """
    cur.execute(
        """
        SELECT
            cf.account_id,
            COALESCE(
                NULLIF(cf.compliance_framework, ''),
                cf.finding_data->>'framework',
                'Unknown'
            )                   AS framework_id,
            COUNT(*)            AS failed_count
        FROM compliance_findings cf
        WHERE cf.scan_run_id = %s AND cf.tenant_id = %s
          AND cf.account_id IS NOT NULL AND cf.account_id != ''
          AND UPPER(cf.status) NOT IN ('PASS', 'RESOLVED', 'CLOSED', 'FIXED', 'SUPPRESSED')
        GROUP BY cf.account_id,
                 COALESCE(NULLIF(cf.compliance_framework, ''), cf.finding_data->>'framework', 'Unknown')
        ORDER BY cf.account_id, framework_id
        """,
        (report_id, tenant_id),
    )
    rows = cur.fetchall()
    if not rows:
        return []

    # Total controls per framework from report_data (if available)
    fw_totals: Dict[str, int] = {}
    if isinstance(report_data, dict):
        for fw_key, fw_val in report_data.get("framework_reports", {}).items():
            if isinstance(fw_val, dict):
                total = int((fw_val.get("statistics") or {}).get("controls_total", 0))
                if total > 0:
                    fw_totals[fw_key] = total

    # Distinct accounts to distribute framework totals
    accounts = {row["account_id"] for row in rows}
    num_accounts = max(len(accounts), 1)

    # Pivot: account_id → {framework_id: score}
    pivot: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        acct   = row["account_id"]
        fw     = row["framework_id"]
        failed = int(row["failed_count"] or 0)

        # Controls assigned to this account for this framework
        fw_total_all = fw_totals.get(fw, 0)
        acct_total   = fw_total_all // num_accounts if fw_total_all > 0 else max(failed * 2, 1)
        failed_capped = min(failed, acct_total)
        score = round(max(0.0, (acct_total - failed_capped) / acct_total * 100), 1)

        if acct not in pivot:
            pivot[acct] = {"account_id": acct}
        pivot[acct][fw] = score

    return list(pivot.values())


def _get_audit_deadlines(
    cur: Any,
    tenant_id: str,
    limit: int = 20,
) -> List[Dict[str, Any]]:
    """Retrieve upcoming audit deadlines from compliance_assessments.

    Args:
        cur: Database cursor (RealDictCursor).
        tenant_id: The tenant identifier.
        limit: Maximum number of assessments to return.

    Returns:
        A list of audit deadline dicts ordered by target_completion_at ASC.
    """
    cur.execute(
        """
        SELECT
            ca.assessment_id,
            ca.framework_id,
            COALESCE(fw.framework_name, ca.framework_id) AS framework_name,
            ca.assessment_name,
            ca.assessment_type,
            ca.assessor,
            ca.status,
            ca.target_completion_at,
            ca.started_at,
            GREATEST(0,
                EXTRACT(DAY FROM (ca.target_completion_at - NOW()))
            )::INT AS days_remaining
        FROM compliance_assessments ca
        LEFT JOIN compliance_frameworks fw ON ca.framework_id = fw.framework_id
        WHERE ca.tenant_id   = %s
          AND ca.status      NOT IN ('completed', 'cancelled')
          AND ca.target_completion_at IS NOT NULL
        ORDER BY ca.target_completion_at ASC
        LIMIT %s
        """,
        (tenant_id, limit),
    )
    rows = cur.fetchall()
    result = []
    for row in rows:
        target = row.get("target_completion_at")
        days   = int(row.get("days_remaining") or 0)
        result.append(
            {
                "assessment_id":  str(row["assessment_id"]),
                "framework":      row["framework_name"],
                "framework_id":   row["framework_id"],
                "type":           row.get("assessment_type") or "Compliance Audit",
                "due_date":       (
                    target.isoformat()
                    if isinstance(target, datetime)
                    else str(target) if target else None
                ),
                "days_remaining": days,
                "owner":          row.get("assessor") or "Compliance Team",
                "status":         "at-risk" if days <= 30 else "on-track",
            }
        )
    return result


def _get_exceptions(
    cur: Any,
    tenant_id: str,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """Retrieve compliance exceptions from control_assessment_results.

    Exceptions are control_assessment_results rows where
    implementation_status is 'exception', 'not_applicable', or
    'compensating_control', or where compensating_controls is populated.

    Args:
        cur: Database cursor (RealDictCursor).
        tenant_id: The tenant identifier.
        limit: Maximum number of exceptions to return.

    Returns:
        A list of exception dicts.
    """
    cur.execute(
        """
        SELECT
            car.result_id,
            car.control_id,
            COALESCE(cc.control_name, car.control_id) AS control_name,
            cc.framework_id,
            COALESCE(fw.framework_name, cc.framework_id, 'Unknown') AS framework_name,
            car.implementation_status,
            car.compensating_controls,
            car.deficiencies,
            car.residual_risk,
            car.assessed_by,
            car.target_remediation_date,
            car.assessed_at
        FROM control_assessment_results car
        LEFT JOIN compliance_controls cc  ON car.control_id = cc.control_id
        LEFT JOIN compliance_frameworks fw ON cc.framework_id = fw.framework_id
        WHERE car.tenant_id = %s
          AND (
              car.implementation_status IN ('exception', 'not_applicable', 'compensating_control')
              OR (car.compensating_controls IS NOT NULL AND car.compensating_controls != '')
          )
        ORDER BY car.assessed_at DESC NULLS LAST
        LIMIT %s
        """,
        (tenant_id, limit),
    )
    rows = cur.fetchall()
    result = []
    for row in rows:
        target = row.get("target_remediation_date")
        assessed = row.get("assessed_at")
        # Determine expiry status from target_remediation_date
        status = "active"
        if target:
            try:
                from datetime import timezone
                now = datetime.now(timezone.utc)
                target_dt = target if isinstance(target, datetime) else datetime.combine(target, datetime.min.time()).replace(tzinfo=timezone.utc)
                days_left = (target_dt - now).days
                status = "expiring-soon" if days_left <= 30 else "active"
            except Exception:
                status = "active"
        result.append(
            {
                "exception_id":         str(row["result_id"]),
                "framework":            row["framework_name"],
                "framework_id":         row.get("framework_id") or "",
                "control":              row["control_id"],
                "control_name":         row["control_name"],
                "justification":        row.get("compensating_controls") or row.get("deficiencies") or "Exception approved",
                "approved_by":          row.get("assessed_by") or "Compliance Team",
                "expiry_date":          (
                    target.isoformat() if isinstance(target, datetime)
                    else str(target) if target else None
                ),
                "residual_risk":        row.get("residual_risk") or "low",
                "implementation_status": row.get("implementation_status"),
                "status":               status,
            }
        )
    return result


def _get_trends(
    cur: Any,
    tenant_id: str,
    limit: int = 30,
) -> List[Dict[str, Any]]:
    """Retrieve compliance score trend data from recent reports.

    Args:
        cur: Database cursor (RealDictCursor).
        tenant_id: The tenant identifier.
        limit: Number of historical data points to return.

    Returns:
        A list of trend dicts with date and score, oldest first.
    """
    cur.execute(
        """
        SELECT total_controls, controls_passed, created_at
        FROM compliance_report
        WHERE tenant_id = %s
        ORDER BY created_at DESC
        LIMIT %s
        """,
        (tenant_id, limit),
    )
    rows = cur.fetchall()

    trends = []
    for row in rows:
        total = row["total_controls"] or 0
        passed = row["controls_passed"] or 0
        score = round((passed / total) * 100, 1) if total > 0 else 0.0
        created = row["created_at"]
        date_str = (
            created.strftime("%Y-%m-%d") if isinstance(created, datetime) else str(created)
        )
        trends.append({"date": date_str, "score": score})

    # Return oldest-first for charting
    trends.reverse()
    return trends


def _get_recent_reports(
    cur: Any,
    tenant_id: str,
    limit: int = 20,
) -> List[Dict[str, Any]]:
    """Retrieve a list of recent compliance reports for the tenant.

    Args:
        cur: Database cursor (RealDictCursor).
        tenant_id: The tenant identifier.
        limit: Maximum number of reports to return.

    Returns:
        A list of report summary dicts.
    """
    cur.execute(
        """
        SELECT scan_run_id, created_at, status, provider
        FROM compliance_report
        WHERE tenant_id = %s
        ORDER BY created_at DESC
        LIMIT %s
        """,
        (tenant_id, limit),
    )
    rows = cur.fetchall()
    return [
        {
            "report_id": row["scan_run_id"],
            "created_at": (
                row["created_at"].isoformat()
                if isinstance(row["created_at"], datetime)
                else str(row["created_at"])
            ),
            "status": row["status"],
            "provider": row["provider"],
        }
        for row in rows
    ]


@router.get("/api/v1/compliance/ui-data")
async def get_compliance_ui_data(
    tenant_id: str = Query(..., description="Tenant identifier"),
    scan_id: str = Query("latest", description="Scan run ID or 'latest'"),
) -> Dict[str, Any]:
    """Return all compliance data needed by the frontend in a single response.

    Resolves the latest (or specified) compliance report for the tenant,
    then assembles posture summary, framework breakdowns, failing controls,
    per-account scores, audit deadlines, exceptions, trend history,
    and recent reports into one payload.

    Args:
        tenant_id: The tenant to query data for.
        scan_id: Either a specific scan_run_id or 'latest' (default).

    Returns:
        A dict matching the unified UI data contract:
        {
          overall_score, posture_summary, frameworks, failing_controls,
          per_account_scores, audit_deadlines, exceptions,
          trends, reports, scan_id
        }

    Raises:
        HTTPException 404: If no compliance report is found.
        HTTPException 500: On unexpected database or processing errors.
    """
    conn = None
    try:
        conn = _get_compliance_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        # 1. Resolve the target report
        if scan_id == "latest":
            report_row = _resolve_latest_report(cur, tenant_id)
        else:
            report_row = _resolve_report_by_scan_id(cur, tenant_id, scan_id)

        if not report_row:
            raise HTTPException(
                status_code=404,
                detail=f"No compliance report found for tenant_id={tenant_id}, scan_id={scan_id}",
            )

        report_id = report_row["scan_run_id"]
        report_data = report_row.get("report_data")

        # 2. Build posture summary
        posture = _extract_posture_summary(report_row)

        # 3. Compute overall score
        overall_score = _compute_overall_score(posture)

        # 4. Per-framework breakdowns (includes last_assessed)
        frameworks = _get_framework_summaries(cur, report_id, tenant_id, report_data)

        # 5. Failing controls (includes account_id, region, days_open)
        failing_controls = _get_failing_controls(cur, report_id, tenant_id)

        # 6. Per-account compliance scores (replaces BFF synthetic generation)
        per_account_scores = _get_per_account_scores(cur, tenant_id, report_id)

        # 7. Audit deadlines from compliance_assessments
        audit_deadlines = _get_audit_deadlines(cur, tenant_id)

        # 8. Exceptions from control_assessment_results
        exceptions = _get_exceptions(cur, tenant_id)

        # 9. Trend data
        trends = _get_trends(cur, tenant_id)

        # 10. Recent reports list
        recent_reports = _get_recent_reports(cur, tenant_id)

        cur.close()

        return {
            "overall_score":     overall_score,
            "posture_summary":   posture,
            "frameworks":        frameworks,
            "failing_controls":  failing_controls,
            "per_account_scores": per_account_scores,
            "audit_deadlines":   audit_deadlines,
            "exceptions":        exceptions,
            "trends":            trends,
            "reports":           recent_reports,
            "scan_id":           report_row.get("scan_run_id") or report_id,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Error fetching compliance UI data",
            exc_info=True,
            extra={"extra_fields": {"tenant_id": tenant_id, "scan_id": scan_id}},
        )
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch compliance UI data: {str(e)}",
        )
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


# ── All Frameworks List (multi-CSP) ──────────────────────────────────────

@router.get("/api/v1/compliance/frameworks/summary")
async def get_all_frameworks_with_status(
    tenant_id: str = Query(...),
):
    """Return ALL frameworks from compliance_frameworks + compliance_controls
    with control counts and latest assessment scores.

    Used by the compliance list page to show all 23 frameworks including
    CSP-specific CIS benchmarks.
    """
    conn = None
    try:
        conn = _get_compliance_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        # Get all frameworks with control counts
        cur.execute("""
            SELECT cf.framework_id, cf.framework_name, cf.version, cf.authority, cf.category,
                   COUNT(cc.control_id) AS total_controls,
                   cf.framework_data
            FROM compliance_frameworks cf
            LEFT JOIN compliance_controls cc ON cc.framework_id = cf.framework_id AND cc.is_active = true
            WHERE cf.is_active = true
            GROUP BY cf.framework_id, cf.framework_name, cf.version, cf.authority, cf.category, cf.framework_data
            ORDER BY COUNT(cc.control_id) DESC
        """)
        fw_rows = cur.fetchall()

        # Get latest assessment per framework
        cur.execute("""
            SELECT DISTINCT ON (framework_id)
                framework_id, overall_score, total_controls,
                controls_implemented, controls_deficient, controls_not_applicable,
                assessment_data
            FROM compliance_assessments
            WHERE tenant_id = %s
            ORDER BY framework_id, completed_at DESC NULLS LAST
        """, (tenant_id,))
        assessments = {r["framework_id"]: dict(r) for r in cur.fetchall()}

        # Get finding counts per framework from compliance_findings
        cur.execute("""
            SELECT compliance_framework AS fw, COUNT(*) AS cnt
            FROM compliance_findings
            WHERE tenant_id = %s
            GROUP BY compliance_framework
        """, (tenant_id,))
        finding_counts = {r["fw"]: r["cnt"] for r in cur.fetchall()}

        frameworks = []
        for fw in fw_rows:
            fid = fw["framework_id"]
            fname = fw["framework_name"] or fid
            total = fw["total_controls"] or 0
            if total == 0:
                continue

            assessment = assessments.get(fid, {})
            asmt_data = assessment.get("assessment_data") or {}
            if isinstance(asmt_data, str):
                asmt_data = json.loads(asmt_data)
            summary = asmt_data.get("summary", {})

            passed = summary.get("PASS", 0) + summary.get("PARTIAL", 0)
            failed = summary.get("FAIL", 0)
            score = assessment.get("overall_score") or (round(100 * passed / total, 1) if total > 0 else 0)

            # Match findings by framework_name (findings use name like "CIS", controls use id like "cis_aws")
            findings = finding_counts.get(fname, 0)

            # Provider from framework_data
            fw_data = fw.get("framework_data") or {}
            if isinstance(fw_data, str):
                fw_data = json.loads(fw_data)
            provider = fw_data.get("provider", "multi")

            frameworks.append({
                "id": fid,
                "name": fname,
                "version": fw.get("version"),
                "authority": fw.get("authority"),
                "category": fw.get("category"),
                "provider": provider,
                "score": score,
                "total_controls": total,
                "passed": passed,
                "failed": failed,
                "findings": findings,
                "has_assessment": bool(assessment),
            })

        return {
            "frameworks": frameworks,
            "total": len(frameworks),
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get frameworks: {e}")
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


# ── Single Control Detail ────────────────────────────────────────────────

@router.get("/api/v1/compliance/control/{control_id}")
async def get_control_detail(
    control_id: str,
    tenant_id: str = Query(...),
):
    """Return full detail for a single control including remediation guidance."""
    conn = None
    try:
        conn = _get_compliance_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT control_id, framework_id, control_name, control_description,
                   control_family, severity, assessment_type, profile_level,
                   implementation_guidance, testing_procedures, rationale,
                   remediation, default_value, impact
            FROM compliance_controls
            WHERE control_id = %s
        """, (control_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"Control not found: {control_id}")
        return dict(row)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get control: {e}")
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


# ── Framework Assessment Endpoint ───────────────────────────────────────

@router.get("/api/v1/compliance/framework/{framework_id}/assessment")
async def get_framework_assessment(
    framework_id: str,
    tenant_id: str = Query(...),
    scan_run_id: str = Query("latest"),
):
    """Return per-control assessment status for a framework.

    Groups controls by control_family. Each control has:
    status (PASS/FAIL/PARTIAL/MANUAL_REVIEW/NOT_APPLICABLE),
    pass_count, fail_count, total_resources.
    """
    conn = None
    try:
        conn = _get_compliance_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        # Resolve latest scan
        if scan_run_id == "latest":
            cur.execute(
                "SELECT scan_run_id FROM compliance_report WHERE tenant_id = %s ORDER BY completed_at DESC NULLS LAST LIMIT 1",
                (tenant_id,),
            )
            row = cur.fetchone()
            if row:
                scan_run_id = row["scan_run_id"]
            else:
                return {"framework_id": framework_id, "controls": [], "families": [], "summary": {}}

        # Get framework metadata — try by framework_id first, then by framework_name
        cur.execute("SELECT * FROM compliance_frameworks WHERE framework_id = %s", (framework_id,))
        fw_row = cur.fetchone()
        if not fw_row:
            cur.execute("SELECT * FROM compliance_frameworks WHERE UPPER(framework_name) = UPPER(%s)", (framework_id,))
            fw_row = cur.fetchone()
        effective_fw_id = fw_row["framework_id"] if fw_row else framework_id
        fw_meta = dict(fw_row) if fw_row else {"framework_id": framework_id, "framework_name": framework_id}
        for k in ("created_at", "updated_at", "framework_data"):
            fw_meta.pop(k, None)

        # Get controls — lightweight fields only (no large text blobs)
        cur.execute("""
            SELECT control_id, control_name,
                   LEFT(control_description, 200) AS control_description,
                   control_family, severity, assessment_type, profile_level, provider
            FROM compliance_controls
            WHERE framework_id = %s AND is_active = true
            ORDER BY control_family, control_id
        """, (effective_fw_id,))
        controls = [dict(r) for r in cur.fetchall()]

        # Get latest assessment results for these controls
        cur.execute("""
            SELECT car.control_id, car.implementation_status, car.test_results
            FROM control_assessment_results car
            JOIN compliance_assessments ca ON car.assessment_id = ca.assessment_id
            WHERE ca.tenant_id = %s AND ca.framework_id = %s
            ORDER BY ca.completed_at DESC
        """, (tenant_id, effective_fw_id))
        assessment_map = {}
        for r in cur.fetchall():
            if r["control_id"] not in assessment_map:
                test_res = r["test_results"]
                if isinstance(test_res, str):
                    try:
                        test_res = json.loads(test_res)
                    except Exception:
                        test_res = {}
                assessment_map[r["control_id"]] = {
                    "status": r["implementation_status"],
                    "pass_count": (test_res or {}).get("pass_count", 0),
                    "fail_count": (test_res or {}).get("fail_count", 0),
                    "total_resources": (test_res or {}).get("total_resources", 0),
                }

        # If no assessment results, compute status from compliance_findings directly
        if not assessment_map:
            # Get fail counts per control from findings
            cur.execute("""
                SELECT COALESCE(NULLIF(control_id, ''), finding_data->>'control_id', rule_id) AS cid,
                       COUNT(*) AS fail_count
                FROM compliance_findings
                WHERE scan_run_id = %s AND tenant_id = %s
                  AND compliance_framework = %s
                GROUP BY cid
            """, (scan_run_id, tenant_id, fw_meta.get("framework_name", framework_id)))
            for r in cur.fetchall():
                if r["cid"]:
                    assessment_map[r["cid"]] = {
                        "status": "FAIL",
                        "pass_count": 0,
                        "fail_count": r["fail_count"],
                        "total_resources": r["fail_count"],
                    }

        # Build response grouped by family
        import json as _json
        families = {}
        summary = {"PASS": 0, "FAIL": 0, "PARTIAL": 0, "MANUAL_REVIEW": 0, "NOT_APPLICABLE": 0, "NOT_ASSESSED": 0}

        for ctrl in controls:
            cid = ctrl["control_id"]
            family = ctrl.get("control_family") or "General"
            assessment = assessment_map.get(cid, {})

            status = assessment.get("status", "NOT_ASSESSED")
            if ctrl.get("assessment_type") == "manual" and status == "NOT_ASSESSED":
                status = "MANUAL_REVIEW"

            summary[status] = summary.get(status, 0) + 1

            ctrl_entry = {
                **ctrl,
                "status": status,
                "pass_count": assessment.get("pass_count", 0),
                "fail_count": assessment.get("fail_count", 0),
                "total_resources": assessment.get("total_resources", 0),
            }

            if family not in families:
                families[family] = {"family": family, "controls": [], "pass": 0, "fail": 0, "total": 0}
            families[family]["controls"].append(ctrl_entry)
            families[family]["total"] += 1
            if status == "PASS":
                families[family]["pass"] += 1
            elif status in ("FAIL", "PARTIAL"):
                families[family]["fail"] += 1

        total = len(controls)
        passed = summary.get("PASS", 0)
        score = round(100 * passed / total, 1) if total > 0 else 0

        return {
            "framework": fw_meta,
            "scan_run_id": scan_run_id,
            "score": score,
            "total_controls": total,
            "summary": summary,
            "families": sorted(families.values(), key=lambda f: -f["fail"]),
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Framework assessment failed: {e}")
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


@router.get("/api/v1/compliance/framework/{framework_id}/checklist")
async def get_framework_checklist(
    framework_id: str,
    tenant_id: str = Query(...),
    scan_run_id: str = Query("latest"),
    format: str = Query("json"),
):
    """Return framework checklist in flat table format for export."""
    # Reuse assessment endpoint
    data = await get_framework_assessment(framework_id, tenant_id, scan_run_id)

    checklist = []
    for fam in data.get("families", []):
        for ctrl in fam.get("controls", []):
            checklist.append({
                "control_id": ctrl["control_id"],
                "control_name": ctrl.get("control_name", ""),
                "family": fam["family"],
                "severity": ctrl.get("severity", ""),
                "assessment_type": ctrl.get("assessment_type", "automated"),
                "profile_level": ctrl.get("profile_level", ""),
                "status": ctrl.get("status", "NOT_ASSESSED"),
                "pass_count": ctrl.get("pass_count", 0),
                "fail_count": ctrl.get("fail_count", 0),
                "total_resources": ctrl.get("total_resources", 0),
            })

    if format == "csv":
        import io, csv
        from fastapi.responses import StreamingResponse
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=checklist[0].keys() if checklist else [])
        writer.writeheader()
        writer.writerows(checklist)
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={framework_id}_checklist.csv"},
        )

    return {
        "framework_id": framework_id,
        "total": len(checklist),
        "score": data.get("score", 0),
        "checklist": checklist,
    }


# ── Full Report Export ───────────────────────────────────────────────────

@router.get("/api/v1/compliance/framework/{framework_id}/report")
async def get_framework_report(
    framework_id: str,
    tenant_id: str = Query(...),
    scan_run_id: str = Query("latest"),
    format: str = Query("json"),
):
    """Generate a full compliance report for a framework.

    Includes ALL fields: control details, audit procedures, remediation steps,
    assessment status, findings count. Designed for PDF/CSV/Excel export.

    Formats: json (default), csv
    """
    conn = None
    try:
        conn = _get_compliance_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        # Resolve framework
        cur.execute("SELECT * FROM compliance_frameworks WHERE framework_id = %s", (framework_id,))
        fw_row = cur.fetchone()
        if not fw_row:
            cur.execute("SELECT * FROM compliance_frameworks WHERE UPPER(framework_name) = UPPER(%s)", (framework_id,))
            fw_row = cur.fetchone()
        effective_fw_id = fw_row["framework_id"] if fw_row else framework_id
        fw_name = fw_row["framework_name"] if fw_row else framework_id
        fw_version = fw_row.get("version") if fw_row else None

        # Get ALL control fields (full data for report)
        cur.execute("""
            SELECT control_id, control_name, control_description, control_family,
                   severity, assessment_type, profile_level, provider,
                   section_id, section_name, subsection_id, sort_order,
                   testing_procedures, implementation_guidance, rationale,
                   audit_console, audit_cli, remediation_console, remediation_cli,
                   default_value, impact
            FROM compliance_controls
            WHERE framework_id = %s AND is_active = true
            ORDER BY sort_order NULLS LAST, control_id
        """, (effective_fw_id,))
        controls = [dict(r) for r in cur.fetchall()]

        # Get assessment results
        cur.execute("""
            SELECT car.control_id, car.implementation_status, car.test_results
            FROM control_assessment_results car
            JOIN compliance_assessments ca ON car.assessment_id = ca.assessment_id
            WHERE ca.tenant_id = %s AND ca.framework_id = %s
            ORDER BY ca.completed_at DESC
        """, (tenant_id, effective_fw_id))
        assessment_map = {}
        for r in cur.fetchall():
            if r["control_id"] not in assessment_map:
                test_res = r["test_results"]
                if isinstance(test_res, str):
                    try:
                        test_res = json.loads(test_res)
                    except Exception:
                        test_res = {}
                assessment_map[r["control_id"]] = {
                    "status": r["implementation_status"],
                    "pass_count": (test_res or {}).get("pass_count", 0),
                    "fail_count": (test_res or {}).get("fail_count", 0),
                    "total_resources": (test_res or {}).get("total_resources", 0),
                }

        # Build report rows
        report_rows = []
        summary = {"PASS": 0, "FAIL": 0, "PARTIAL": 0, "NOT_APPLICABLE": 0, "MANUAL_REVIEW": 0, "NOT_ASSESSED": 0}

        for ctrl in controls:
            cid = ctrl["control_id"]
            asmt = assessment_map.get(cid, {})
            status = asmt.get("status", "NOT_ASSESSED")
            summary[status] = summary.get(status, 0) + 1

            report_rows.append({
                "section": ctrl.get("section_name") or ctrl.get("control_family") or "",
                "control_id": cid,
                "control_name": ctrl.get("control_name") or "",
                "description": ctrl.get("control_description") or "",
                "severity": ctrl.get("severity") or "",
                "assessment_type": ctrl.get("assessment_type") or "automated",
                "profile_level": ctrl.get("profile_level") or "",
                "status": status,
                "pass_count": asmt.get("pass_count", 0),
                "fail_count": asmt.get("fail_count", 0),
                "total_resources": asmt.get("total_resources", 0),
                "rationale": ctrl.get("rationale") or "",
                "audit_console": ctrl.get("audit_console") or ctrl.get("testing_procedures") or "",
                "audit_cli": ctrl.get("audit_cli") or "",
                "remediation_console": ctrl.get("remediation_console") or ctrl.get("implementation_guidance") or "",
                "remediation_cli": ctrl.get("remediation_cli") or "",
                "default_value": ctrl.get("default_value") or "",
                "impact": ctrl.get("impact") or "",
            })

        total = len(report_rows)
        passed = summary.get("PASS", 0)
        score = round(100 * passed / total, 1) if total > 0 else 0

        report = {
            "framework": fw_name,
            "framework_id": effective_fw_id,
            "version": fw_version,
            "tenant_id": tenant_id,
            "scan_run_id": scan_run_id,
            "generated_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
            "score": score,
            "total_controls": total,
            "summary": summary,
            "controls": report_rows,
        }

        if format == "csv":
            import io, csv
            from fastapi.responses import StreamingResponse
            output = io.StringIO()
            if report_rows:
                writer = csv.DictWriter(output, fieldnames=report_rows[0].keys())
                writer.writeheader()
                writer.writerows(report_rows)
            return StreamingResponse(
                iter([output.getvalue()]),
                media_type="text/csv",
                headers={"Content-Disposition": f"attachment; filename={effective_fw_id}_report.csv"},
            )

        return report

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {e}")
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


# ── Admin: Load Master Data ─────────────────────────────────────────────

@router.post("/api/v1/compliance/admin/load-master-data")
async def load_master_data_endpoint(
    master_path: str = Query(None),
):
    """Load compliance_master.json into DB tables."""
    try:
        from ..loader.master_data_loader import load_master_data
        result = load_master_data(master_path)
        return {"status": "ok", **result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load master data: {e}")


@router.post("/api/v1/compliance/admin/compute-assessment")
async def compute_assessment_endpoint(
    tenant_id: str = Query(...),
    scan_run_id: str = Query(...),
    framework_id: str = Query(None),
):
    """Compute control-level assessment from compliance findings."""
    try:
        from ..assessor.control_assessor import compute_assessment
        result = compute_assessment(scan_run_id, tenant_id, framework_id)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Assessment computation failed: {e}")
