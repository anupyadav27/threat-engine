"""
Read pipeline status from scan_orchestration + all engine *_report tables.
Each engine report table is queried independently — failures are non-fatal.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from engine_common.db_connections import (
    get_check_conn,
    get_ciem_conn,
    get_compliance_conn,
    get_datasec_conn,
    get_discoveries_conn,
    get_iam_conn,
    get_inventory_conn,
    get_network_conn,
    get_risk_conn,
    get_threat_conn,
    get_encryption_conn,
    get_container_sec_conn,
    get_dbsec_conn,
    get_ai_security_conn,
)

logger = logging.getLogger(__name__)

# Maps engine name → (conn_factory, db_name, report_table, status_col, findings_col)
ENGINE_REPORT_MAP = {
    "discovery":         (get_discoveries_conn, "discovery_report",      "status", "total_findings"),
    "check":             (get_check_conn,        "check_report",          "status", "total_checks"),
    "inventory":         (get_inventory_conn,    "inventory_report",      "status", "total_assets"),
    "threat":            (get_threat_conn,        "threat_report",         "status", "total_findings"),
    "compliance":        (get_compliance_conn,    "compliance_report",     "status", "total_controls"),
    "iam":               (get_iam_conn,           "iam_report",            "status", "total_findings"),
    "network":           (get_network_conn,       "network_report",        "status", "total_findings"),
    "datasec":           (get_datasec_conn,       "datasec_report",        "status", "total_findings"),
    "ciem":              (get_ciem_conn,          "ciem_report",           "status", "total_findings"),
    "risk":              (get_risk_conn,          "risk_report",           "status", "total_scenarios"),
    "encryption":        (get_encryption_conn,    "encryption_report",     "status", "total_findings"),
    "container":         (get_container_sec_conn, "container_sec_report",  "status", "total_findings"),
    "dbsec":             (get_dbsec_conn,         "dbsec_report",          "status", "total_findings"),
    "ai_security":       (get_ai_security_conn,   "ai_security_report",    "status", "total_findings"),
}


def _query_report(conn_factory, table: str, scan_run_id: str,
                  status_col: str, findings_col: str) -> Dict[str, Any]:
    """Query a single engine report table. Returns {} on any error."""
    try:
        conn = conn_factory()
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT {status_col}, {findings_col},
                       started_at, completed_at,
                       EXTRACT(EPOCH FROM (COALESCE(completed_at, NOW()) - started_at))::int
                FROM {table}
                WHERE scan_run_id = %s
                LIMIT 1
                """,
                (scan_run_id,),
            )
            row = cur.fetchone()
        conn.close()
        if not row:
            return {"status": "not_started"}
        status, findings, started, completed, duration_s = row
        result = {"status": status or "unknown", "findings": findings or 0,
                  "duration_s": duration_s or 0}
        if started:
            result["started_at"] = started.isoformat()
        if completed:
            result["completed_at"] = completed.isoformat()
        return result
    except Exception as e:
        logger.warning("Report query failed [%s]: %s", table, e)
        return {"status": "unavailable", "error": str(e)}


def get_orchestration(scan_run_id: str) -> Dict[str, Any]:
    """Read scan_orchestration for overall status and engine list."""
    try:
        conn = get_discoveries_conn()
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT overall_status, engines_requested, engines_completed,
                       started_at, completed_at,
                       tenant_id, account_id, provider,
                       EXTRACT(EPOCH FROM (COALESCE(completed_at, NOW()) - started_at))::int
                FROM scan_orchestration WHERE scan_run_id = %s
                """,
                (scan_run_id,),
            )
            row = cur.fetchone()
        conn.close()
        if not row:
            return {}
        status, requested, completed, started, finished, tenant, account, provider, duration = row
        return {
            "overall_status":      status,
            "engines_requested":   requested or [],
            "engines_completed":   completed or [],
            "started_at":          started.isoformat() if started else None,
            "completed_at":        finished.isoformat() if finished else None,
            "duration_s":          duration or 0,
            "tenant_id":           tenant,
            "account_id":          account,
            "provider":            provider,
        }
    except Exception as e:
        logger.error("scan_orchestration query failed: %s", e)
        return {"error": str(e)}


def get_scan_history(tenant_id: Optional[str] = None, limit: int = 20) -> List[Dict[str, Any]]:
    """Return recent scan runs from scan_orchestration."""
    try:
        conn = get_discoveries_conn()
        with conn.cursor() as cur:
            if tenant_id:
                cur.execute(
                    """
                    SELECT scan_run_id, overall_status, tenant_id, account_id, provider,
                           started_at, completed_at,
                           EXTRACT(EPOCH FROM (COALESCE(completed_at, NOW()) - started_at))::int
                    FROM scan_orchestration
                    WHERE tenant_id = %s
                    ORDER BY started_at DESC LIMIT %s
                    """,
                    (tenant_id, limit),
                )
            else:
                cur.execute(
                    """
                    SELECT scan_run_id, overall_status, tenant_id, account_id, provider,
                           started_at, completed_at,
                           EXTRACT(EPOCH FROM (COALESCE(completed_at, NOW()) - started_at))::int
                    FROM scan_orchestration
                    ORDER BY started_at DESC LIMIT %s
                    """,
                    (limit,),
                )
            rows = cur.fetchall()
        conn.close()
        results = []
        for row in rows:
            sid, status, tenant, account, provider, started, finished, duration = row
            results.append({
                "scan_run_id":   sid,
                "overall_status": status,
                "tenant_id":     tenant,
                "account_id":    account,
                "provider":      provider,
                "started_at":    started.isoformat() if started else None,
                "completed_at":  finished.isoformat() if finished else None,
                "duration_s":    duration or 0,
            })
        return results
    except Exception as e:
        logger.error("scan history query failed: %s", e)
        return []


def get_full_pipeline_status(scan_run_id: str) -> Dict[str, Any]:
    """Combine orchestration + all engine reports into one status object."""
    orchestration = get_orchestration(scan_run_id)
    if not orchestration:
        return {"scan_run_id": scan_run_id, "error": "scan not found"}

    stages = {}
    for engine, (conn_factory, table, status_col, findings_col) in ENGINE_REPORT_MAP.items():
        stages[engine] = _query_report(conn_factory, table, scan_run_id, status_col, findings_col)

    # Compute summary counts
    counts = {"completed": 0, "running": 0, "failed": 0, "not_started": 0, "unavailable": 0}
    for s in stages.values():
        counts[s.get("status", "unavailable")] = counts.get(s.get("status", "unavailable"), 0) + 1

    return {
        "scan_run_id":     scan_run_id,
        "overall_status":  orchestration.get("overall_status"),
        "tenant_id":       orchestration.get("tenant_id"),
        "account_id":      orchestration.get("account_id"),
        "provider":        orchestration.get("provider"),
        "started_at":      orchestration.get("started_at"),
        "completed_at":    orchestration.get("completed_at"),
        "duration_s":      orchestration.get("duration_s"),
        "stage_summary":   counts,
        "stages":          stages,
    }
