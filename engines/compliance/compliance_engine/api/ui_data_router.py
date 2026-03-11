"""
Compliance Engine - Unified UI Data Endpoint

Provides a single GET endpoint that returns all compliance data needed
by the frontend in one request, avoiding multiple round-trips.

Endpoint: GET /api/v1/compliance/ui-data?tenant_id=X&scan_id=latest
"""

import os
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
        SELECT compliance_scan_id, tenant_id, scan_run_id, check_scan_id,
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
        SELECT compliance_scan_id, tenant_id, scan_run_id, check_scan_id,
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
    """Build per-framework summary objects.

    Queries compliance_findings grouped by framework_id for the given report.
    Falls back to framework_ids from report_data when no findings exist.

    Args:
        cur: Database cursor (RealDictCursor).
        report_id: The compliance report identifier.
        tenant_id: The tenant identifier.
        report_data: The report_data JSONB value (already deserialized).

    Returns:
        A list of framework summary dicts.
    """
    cur.execute(
        """
        SELECT
            cf.compliance_framework,
            COALESCE(fw.framework_name, cf.compliance_framework) AS framework_name,
            fw.version AS framework_version,
            fw.authority AS framework_authority,
            fw.category AS framework_category,
            COUNT(*) FILTER (WHERE cf.status = 'PASS') AS passed_controls,
            COUNT(*) FILTER (WHERE cf.status = 'FAIL') AS failed_controls,
            COUNT(*) AS total_controls
        FROM compliance_findings cf
        LEFT JOIN compliance_frameworks fw
            ON cf.compliance_framework = fw.framework_id
        WHERE cf.compliance_scan_id = %s AND cf.tenant_id = %s
        GROUP BY cf.compliance_framework, fw.framework_name,
                 fw.version, fw.authority, fw.category
        ORDER BY cf.compliance_framework
        """,
        (report_id, tenant_id),
    )
    rows = cur.fetchall()

    if rows:
        frameworks = []
        for row in rows:
            total = row["total_controls"] or 0
            passed = row["passed_controls"] or 0
            failed = row["failed_controls"] or 0
            score = round((passed / total) * 100, 1) if total > 0 else 0.0
            frameworks.append(
                {
                    "framework_id": row["compliance_framework"],
                    "framework_name": row["framework_name"],
                    "framework_version": row.get("framework_version"),
                    "framework_authority": row.get("framework_authority"),
                    "framework_category": row.get("framework_category"),
                    "score": score,
                    "passed_controls": passed,
                    "failed_controls": failed,
                    "total_controls": total,
                }
            )
        return frameworks

    # Fallback: list framework_ids from report_data without detailed counts
    if isinstance(report_data, dict):
        framework_ids = report_data.get("framework_ids", [])
        if isinstance(framework_ids, list):
            return [
                {
                    "framework_id": fid,
                    "framework_name": fid,
                    "score": 0.0,
                    "passed_controls": 0,
                    "failed_controls": 0,
                    "total_controls": 0,
                }
                for fid in framework_ids
            ]

    return []


def _get_failing_controls(
    cur: Any,
    report_id: str,
    tenant_id: str,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """Retrieve the top failing controls for a report.

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
        SELECT cf.control_id,
               cf.compliance_framework,
               cf.severity,
               COUNT(*) AS failed_resources,
               COALESCE(cc.control_name, cf.control_name, cf.control_id) AS control_name,
               cc.control_description,
               cc.control_family
        FROM compliance_findings cf
        LEFT JOIN compliance_controls cc
            ON cf.control_id = cc.control_id
        WHERE cf.compliance_scan_id = %s AND cf.tenant_id = %s AND cf.status = 'FAIL'
        GROUP BY cf.control_id, cf.compliance_framework, cf.severity,
                 cc.control_name, cf.control_name, cc.control_description,
                 cc.control_family
        ORDER BY failed_resources DESC
        LIMIT %s
        """,
        (report_id, tenant_id, limit),
    )
    rows = cur.fetchall()
    return [
        {
            "control_id": row["control_id"],
            "control_name": row["control_name"],
            "control_description": row.get("control_description"),
            "control_family": row.get("control_family"),
            "framework_id": row["compliance_framework"],
            "severity": row["severity"],
            "failed_resources": row["failed_resources"] or 0,
        }
        for row in rows
    ]


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
        SELECT compliance_scan_id, created_at, status, provider
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
            "report_id": row["compliance_scan_id"],
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
    trend history, and recent reports into one payload.

    Args:
        tenant_id: The tenant to query data for.
        scan_id: Either a specific scan_run_id or 'latest' (default).

    Returns:
        A dict matching the unified UI data contract.

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

        report_id = report_row["compliance_scan_id"]
        report_data = report_row.get("report_data")

        # 2. Build posture summary
        posture = _extract_posture_summary(report_row)

        # 3. Compute overall score
        overall_score = _compute_overall_score(posture)

        # 4. Per-framework breakdowns
        frameworks = _get_framework_summaries(cur, report_id, tenant_id, report_data)

        # 5. Failing controls
        failing_controls = _get_failing_controls(cur, report_id, tenant_id)

        # 6. Trend data
        trends = _get_trends(cur, tenant_id)

        # 7. Recent reports list
        recent_reports = _get_recent_reports(cur, tenant_id)

        cur.close()

        return {
            "overall_score": overall_score,
            "posture_summary": posture,
            "frameworks": frameworks,
            "failing_controls": failing_controls,
            "trends": trends,
            "reports": recent_reports,
            "scan_id": report_row.get("scan_run_id") or report_id,
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
