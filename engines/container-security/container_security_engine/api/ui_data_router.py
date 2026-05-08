"""
Unified UI data endpoint for Container Security Engine.
"""

import logging
from typing import Any, Dict, List, Optional

from psycopg2.extras import RealDictCursor
from fastapi import APIRouter, Depends, Query

from engine_common.db_connections import get_container_sec_conn

# ── Auth imports (engine_auth is COPY shared/auth/ ./engine_auth/ in Dockerfile) ──
# container:read is seeded in platform DB (migration 0009 / permissions seed).
try:
    from engine_auth.fastapi.dependencies import require_permission
    from engine_auth.core.models import AuthContext
    _AUTH_AVAILABLE = True
except ImportError:
    _AUTH_AVAILABLE = False
    AuthContext = None  # type: ignore[assignment,misc]

logger = logging.getLogger(__name__)
router = APIRouter(tags=["ui-data"])


def _strip_sensitive_fields(data: List[Dict[str, Any]], auth: Any) -> List[Dict[str, Any]]:
    """Remove credential_ref/credential_type for non-platform-admin callers."""
    if not isinstance(data, list):
        return data
    stripped = []
    for row in data:
        r = dict(row) if not isinstance(row, dict) else row.copy()
        if auth is not None and hasattr(auth, "level") and auth.level > 1:
            r.pop("credential_ref", None)
            r.pop("credential_type", None)
        stripped.append(r)
    return stripped


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
    """Resolve 'latest' to the most recent scan_run_id for a tenant.

    Skips orphaned reports (no backing findings). Falls back to container_sec_findings.
    """
    cur.execute(
        """
        SELECT r.scan_run_id FROM container_sec_report r
        WHERE r.tenant_id = %s AND r.status = 'completed'
          AND EXISTS (
              SELECT 1 FROM container_sec_findings f
              WHERE f.scan_run_id = r.scan_run_id AND f.tenant_id = r.tenant_id
          )
        ORDER BY r.generated_at DESC NULLS LAST LIMIT 1
        """,
        (tenant_id,),
    )
    row = cur.fetchone()
    if row:
        return row["scan_run_id"]
    # Fallback: latest scan_run_id directly from findings
    cur.execute(
        """
        SELECT scan_run_id, COUNT(*) AS cnt
        FROM container_sec_findings
        WHERE tenant_id = %s
        GROUP BY scan_run_id
        ORDER BY MAX(last_seen_at) DESC NULLS LAST, cnt DESC
        LIMIT 1
        """,
        (tenant_id,),
    )
    row = cur.fetchone()
    return row["scan_run_id"] if row else None


@router.get("/api/v1/container-security/ui-data")
async def get_container_sec_ui_data(
    tenant_id: str = Query(...),
    scan_id: str = Query(default="latest"),
    limit: int = Query(default=200, ge=1, le=1000),
    auth: Any = Depends(require_permission("container:read") if _AUTH_AVAILABLE else (lambda: None)),
) -> Dict[str, Any]:
    conn = None
    try:
        conn = get_container_sec_conn()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            scan_run_id = _resolve_latest_scan(cur, tenant_id) if scan_id == "latest" else scan_id
            if not scan_run_id:
                return _empty_response()

            # Report
            cur.execute("SELECT * FROM container_sec_report WHERE scan_run_id = %s AND tenant_id = %s LIMIT 1",
                        (scan_run_id, tenant_id))
            report = cur.fetchone() or {}

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

            # Domain breakdown — extended with severity counts and distinct resource count
            cur.execute(
                """SELECT security_domain,
                          COUNT(*) AS total,
                          COUNT(*) FILTER (WHERE status = 'FAIL') AS fail_count,
                          COUNT(*) FILTER (WHERE status = 'PASS') AS pass_count,
                          COUNT(*) FILTER (WHERE severity = 'CRITICAL' AND status = 'FAIL') AS critical_count,
                          COUNT(*) FILTER (WHERE severity = 'HIGH'     AND status = 'FAIL') AS high_count,
                          COUNT(DISTINCT resource_uid) AS resources_affected
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

        # Strip sensitive fields before returning
        findings = _strip_sensitive_fields(findings, auth)

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
