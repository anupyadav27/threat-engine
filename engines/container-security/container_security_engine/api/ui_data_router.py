"""
Unified UI data endpoint for Container Security Engine.
"""

import logging
import os
from typing import Any, Dict, List, Optional

import psycopg2
from psycopg2.extras import RealDictCursor
from fastapi import APIRouter, Query

logger = logging.getLogger(__name__)
router = APIRouter(tags=["ui-data"])


def _get_csec_conn():
    return psycopg2.connect(
        host=os.getenv("CSEC_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("CSEC_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("CSEC_DB_NAME", "threat_engine_container_security"),
        user=os.getenv("CSEC_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("CSEC_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        connect_timeout=10,
    )


def _query_scan_trend(cur, tenant_id: str) -> list:
    """Return last 8 container-security scan summaries for trend charts (oldest-first)."""
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
                (SELECT COUNT(DISTINCT cf.resource_uid)
                 FROM container_sec_findings cf
                 WHERE cf.scan_run_id     = r.scan_run_id
                   AND cf.tenant_id       = r.tenant_id
                   AND cf.security_domain = 'image_security'
                   AND cf.status          = 'FAIL')          AS vulnerable_images,
                COALESCE(r.privileged_container_count, 0)    AS privileged_containers
            FROM container_sec_report r
            WHERE r.tenant_id = %s AND r.status = 'completed'
            ORDER BY r.generated_at DESC
            LIMIT 8
            """,
            (tenant_id,),
        )
        return [dict(r) for r in reversed(cur.fetchall())]
    except Exception:
        logger.warning("container_sec scan_trend query failed", exc_info=True)
        return []


def _resolve_latest_scan(cur, tenant_id: str) -> Optional[str]:
    cur.execute(
        """SELECT scan_run_id FROM container_sec_report
           WHERE tenant_id = %s AND status = 'completed'
           ORDER BY generated_at DESC LIMIT 1""",
        (tenant_id,),
    )
    row = cur.fetchone()
    return row["scan_run_id"] if row else None


@router.get("/api/v1/container-security/ui-data")
async def get_container_sec_ui_data(
    tenant_id: str = Query(...),
    scan_id: str = Query(default="latest"),
    limit: int = Query(default=200, ge=1, le=1000),
) -> Dict[str, Any]:
    conn = None
    try:
        conn = _get_csec_conn()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            scan_run_id = _resolve_latest_scan(cur, tenant_id) if scan_id == "latest" else scan_id
            if not scan_run_id:
                return _empty_response()

            # Report
            cur.execute("SELECT * FROM container_sec_report WHERE scan_run_id = %s AND tenant_id = %s LIMIT 1",
                        (scan_run_id, tenant_id))
            report = cur.fetchone()
            if not report:
                return _empty_response()

            # Inventory
            cur.execute(
                """SELECT resource_uid, resource_name, resource_type, container_service,
                          k8s_version, platform_version, posture_score,
                          endpoint_public, encryption_enabled, logging_enabled,
                          secrets_encrypted, network_policy_enabled,
                          total_checks, passed_checks, failed_checks, critical_checks,
                          account_id, region, provider
                   FROM container_sec_inventory
                   WHERE scan_run_id = %s AND tenant_id = %s
                   ORDER BY posture_score ASC, endpoint_public DESC""",
                (scan_run_id, tenant_id))
            inventory = [dict(r) for r in cur.fetchall()]

            # Domain breakdown
            cur.execute(
                """SELECT security_domain, COUNT(*) as total,
                          COUNT(*) FILTER (WHERE status = 'FAIL') as fail_count,
                          COUNT(*) FILTER (WHERE status = 'PASS') as pass_count
                   FROM container_sec_findings
                   WHERE scan_run_id = %s AND tenant_id = %s
                   GROUP BY security_domain ORDER BY fail_count DESC""",
                (scan_run_id, tenant_id))
            domain_breakdown = [dict(r) for r in cur.fetchall()]

            # Service breakdown
            cur.execute(
                """SELECT container_service, COUNT(*) as total,
                          COUNT(*) FILTER (WHERE status = 'FAIL') as fail_count
                   FROM container_sec_findings
                   WHERE scan_run_id = %s AND tenant_id = %s
                   GROUP BY container_service ORDER BY fail_count DESC""",
                (scan_run_id, tenant_id))
            service_breakdown = [dict(r) for r in cur.fetchall()]

            # Public endpoints
            public_clusters = [i for i in inventory if i.get("endpoint_public")]

            # Findings
            cur.execute(
                """SELECT finding_id, resource_uid, resource_type,
                          container_service, cluster_name, security_domain,
                          severity, status, rule_id, title,
                          description, remediation, finding_data,
                          account_id, region
                   FROM container_sec_findings
                   WHERE scan_run_id = %s AND tenant_id = %s
                   ORDER BY CASE severity
                       WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                       WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5
                   END, finding_id
                   LIMIT %s""",
                (scan_run_id, tenant_id, limit))
            findings = []
            for f in cur.fetchall():
                fd = f.get("finding_data")
                if not isinstance(fd, dict):
                    fd = {}
                findings.append({**dict(f), "finding_data": fd, "source": fd.get("source", "check")})

            # Scan trend (last 8 scans, oldest-first)
            scan_trend = _query_scan_trend(cur, tenant_id)

        return {
            "summary": {
                "posture_score": report.get("posture_score", 0),
                "cluster_security_score": report.get("cluster_security_score", 0),
                "workload_security_score": report.get("workload_security_score", 0),
                "image_security_score": report.get("image_security_score", 0),
                "network_exposure_score": report.get("network_exposure_score", 0),
                "rbac_access_score": report.get("rbac_access_score", 0),
                "runtime_audit_score": report.get("runtime_audit_score", 0),
                "total_clusters": report.get("total_clusters", 0),
                "total_workloads": report.get("total_workloads", 0),
                "total_images": report.get("total_images", 0),
                "total_findings": report.get("total_findings", 0),
                "critical_findings": report.get("critical_findings", 0),
                "high_findings": report.get("high_findings", 0),
                "medium_findings": report.get("medium_findings", 0),
                "low_findings": report.get("low_findings", 0),
                "pass_count": report.get("pass_count", 0),
                "fail_count": report.get("fail_count", 0),
                "public_clusters": len(public_clusters),
            },
            "domain_breakdown": domain_breakdown,
            "service_breakdown": service_breakdown,
            "inventory": inventory,
            "public_clusters": public_clusters,
            "findings": findings,
            "total_findings": report.get("total_findings", 0),
            "scan_id": scan_run_id,
            "scan_trend": scan_trend,
        }
    except Exception:
        logger.exception("Error building Container Security UI data")
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
            "posture_score": 0, "cluster_security_score": 0, "workload_security_score": 0,
            "image_security_score": 0, "network_exposure_score": 0,
            "rbac_access_score": 0, "runtime_audit_score": 0,
            "total_clusters": 0, "total_workloads": 0, "total_images": 0,
            "total_findings": 0, "critical_findings": 0, "high_findings": 0,
            "medium_findings": 0, "low_findings": 0,
            "pass_count": 0, "fail_count": 0, "public_clusters": 0,
        },
        "domain_breakdown": [], "service_breakdown": [],
        "inventory": [], "public_clusters": [],
        "findings": [], "total_findings": 0, "scan_id": None,
    }
