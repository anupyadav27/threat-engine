"""
Unified UI data endpoint for Database Security Engine.

Returns a single aggregated payload for the CSPM frontend Database Security
page, reading from the engine's own database tables.
"""

import logging
import os
from typing import Any, Dict, List, Optional

import psycopg2
from psycopg2.extras import RealDictCursor
from fastapi import APIRouter, Query

logger = logging.getLogger(__name__)

router = APIRouter(tags=["ui-data"])


def _get_dbsec_conn():
    return psycopg2.connect(
        host=os.getenv("DBSEC_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("DBSEC_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("DBSEC_DB_NAME", "threat_engine_database_security"),
        user=os.getenv("DBSEC_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("DBSEC_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        connect_timeout=10,
    )


def _query_scan_trend(cur, tenant_id: str) -> list:
    """Return last 8 database-security scan summaries for trend charts (oldest-first)."""
    try:
        cur.execute(
            """
            SELECT
                to_char(r.generated_at, 'Mon DD')   AS date,
                COALESCE(r.total_findings, 0)        AS total,
                COALESCE(r.critical_findings, 0)     AS critical,
                COALESCE(r.high_findings, 0)         AS high,
                COALESCE(r.medium_findings, 0)       AS medium,
                COALESCE(r.low_findings, 0)          AS low,
                COALESCE(r.posture_score, 0)         AS pass_rate,
                (SELECT COUNT(*)
                 FROM dbsec_inventory di
                 WHERE di.scan_run_id        = r.scan_run_id
                   AND di.tenant_id          = r.tenant_id
                   AND di.publicly_accessible = TRUE)  AS public_databases,
                (SELECT COUNT(*)
                 FROM dbsec_inventory di
                 WHERE di.scan_run_id        = r.scan_run_id
                   AND di.tenant_id          = r.tenant_id
                   AND di.encryption_at_rest  = FALSE) AS unencrypted_dbs
            FROM dbsec_report r
            WHERE r.tenant_id = %s AND r.status = 'completed'
            ORDER BY r.generated_at DESC
            LIMIT 8
            """,
            (tenant_id,),
        )
        return [dict(r) for r in reversed(cur.fetchall())]
    except Exception:
        logger.warning("dbsec scan_trend query failed", exc_info=True)
        return []


def _resolve_latest_scan(cur, tenant_id: str) -> Optional[str]:
    cur.execute(
        """SELECT scan_run_id FROM dbsec_report
           WHERE tenant_id = %s AND status = 'completed'
           ORDER BY generated_at DESC LIMIT 1""",
        (tenant_id,),
    )
    row = cur.fetchone()
    return row["scan_run_id"] if row else None


@router.get("/api/v1/database-security/ui-data")
async def get_dbsec_ui_data(
    tenant_id: str = Query(..., description="Tenant ID"),
    scan_id: str = Query(default="latest", description="Scan ID or 'latest'"),
    limit: int = Query(default=200, ge=1, le=1000, description="Max findings"),
) -> Dict[str, Any]:
    """Return aggregated Database Security data for the frontend."""
    conn = None
    try:
        conn = _get_dbsec_conn()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            scan_run_id = _resolve_latest_scan(cur, tenant_id) if scan_id == "latest" else scan_id
            if not scan_run_id:
                return _empty_response()

            # Report summary
            cur.execute(
                "SELECT * FROM dbsec_report WHERE scan_run_id = %s AND tenant_id = %s LIMIT 1",
                (scan_run_id, tenant_id),
            )
            report = cur.fetchone()
            if not report:
                return _empty_response()

            # Database inventory
            cur.execute(
                """SELECT resource_uid, resource_name, db_service, db_engine,
                          db_engine_version, instance_class, posture_score,
                          publicly_accessible, encryption_at_rest, encryption_in_transit,
                          iam_auth_enabled, audit_logging_enabled, backup_enabled,
                          backup_retention_days, deletion_protection, multi_az, vpc_id,
                          total_checks, passed_checks, failed_checks, critical_checks,
                          data_classification, has_sensitive_data,
                          account_id, region, provider
                   FROM dbsec_inventory
                   WHERE scan_run_id = %s AND tenant_id = %s
                   ORDER BY posture_score ASC, publicly_accessible DESC""",
                (scan_run_id, tenant_id),
            )
            inventory = [dict(r) for r in cur.fetchall()]

            # Domain breakdown
            cur.execute(
                """SELECT security_domain,
                          COUNT(*) as total,
                          COUNT(*) FILTER (WHERE status = 'FAIL') as fail_count,
                          COUNT(*) FILTER (WHERE status = 'PASS') as pass_count
                   FROM dbsec_findings
                   WHERE scan_run_id = %s AND tenant_id = %s
                   GROUP BY security_domain ORDER BY fail_count DESC""",
                (scan_run_id, tenant_id),
            )
            domain_breakdown = [dict(r) for r in cur.fetchall()]

            # Service breakdown
            cur.execute(
                """SELECT db_service,
                          COUNT(*) as total,
                          COUNT(*) FILTER (WHERE status = 'FAIL') as fail_count
                   FROM dbsec_findings
                   WHERE scan_run_id = %s AND tenant_id = %s
                   GROUP BY db_service ORDER BY fail_count DESC""",
                (scan_run_id, tenant_id),
            )
            service_breakdown = [dict(r) for r in cur.fetchall()]

            # Publicly accessible databases (attack surface)
            public_dbs = [d for d in inventory if d.get("publicly_accessible")]

            # Scan trend (last 8 scans, oldest-first)
            scan_trend = _query_scan_trend(cur, tenant_id)

            # Findings (paginated)
            cur.execute(
                """SELECT finding_id, resource_uid, resource_type,
                          db_engine, db_service, security_domain,
                          severity, status, rule_id, title,
                          description, remediation, finding_data,
                          account_id, region
                   FROM dbsec_findings
                   WHERE scan_run_id = %s AND tenant_id = %s
                   ORDER BY
                       CASE severity
                           WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                           WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5
                       END,
                       finding_id
                   LIMIT %s""",
                (scan_run_id, tenant_id, limit),
            )
            findings = []
            for f in cur.fetchall():
                fd = f.get("finding_data")
                if not isinstance(fd, dict):
                    fd = {}
                findings.append({**dict(f), "finding_data": fd, "source": fd.get("source", "check")})

        return {
            "summary": {
                "posture_score": report.get("posture_score", 0),
                "access_control_score": report.get("access_control_score", 0),
                "encryption_score": report.get("encryption_score", 0),
                "audit_logging_score": report.get("audit_logging_score", 0),
                "backup_recovery_score": report.get("backup_recovery_score", 0),
                "network_security_score": report.get("network_security_score", 0),
                "configuration_score": report.get("configuration_score", 0),
                "total_databases": report.get("total_databases", 0),
                "total_findings": report.get("total_findings", 0),
                "critical_findings": report.get("critical_findings", 0),
                "high_findings": report.get("high_findings", 0),
                "medium_findings": report.get("medium_findings", 0),
                "low_findings": report.get("low_findings", 0),
                "pass_count": report.get("pass_count", 0),
                "fail_count": report.get("fail_count", 0),
                "public_databases": len(public_dbs),
            },
            "domain_breakdown": domain_breakdown,
            "service_breakdown": service_breakdown,
            "inventory": inventory,
            "public_databases": public_dbs,
            "findings": findings,
            "scan_trend": scan_trend,
            "total_findings": report.get("total_findings", 0),
            "scan_id": scan_run_id,
        }

    except Exception:
        logger.exception("Error building Database Security UI data")
        return _empty_response()
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


def _empty_response() -> Dict[str, Any]:
    return {
        "summary": {
            "posture_score": 0, "access_control_score": 0, "encryption_score": 0,
            "audit_logging_score": 0, "backup_recovery_score": 0,
            "network_security_score": 0, "configuration_score": 0,
            "total_databases": 0, "total_findings": 0,
            "critical_findings": 0, "high_findings": 0,
            "medium_findings": 0, "low_findings": 0,
            "pass_count": 0, "fail_count": 0, "public_databases": 0,
        },
        "domain_breakdown": [],
        "service_breakdown": [],
        "inventory": [],
        "public_databases": [],
        "findings": [],
        "total_findings": 0,
        "scan_id": None,
    }
