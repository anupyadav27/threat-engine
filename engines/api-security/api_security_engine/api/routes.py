import subprocess
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

try:
    from engine_auth.fastapi.dependencies import require_permission
    from engine_auth.core.models import AuthContext
    _AUTH_AVAILABLE = True
except ImportError:
    _AUTH_AVAILABLE = False
    require_permission = lambda p: lambda: None  # noqa: E731
    class AuthContext:  # type: ignore[no-redef]
        tenant_id: str = "default"

router = APIRouter()


class ScanRequest(BaseModel):
    scan_run_id: UUID
    tenant_id: str
    account_id: str
    provider: str
    credential_ref: str
    credential_type: str
    region: str | None = None


class ScanResponse(BaseModel):
    scan_run_id: UUID
    status: str
    message: str


@router.get("/health/live")
def liveness():
    return {"status": "ok"}


@router.get("/health/ready")
def readiness():
    return {"status": "ok"}


@router.post("/apisec/scan", response_model=ScanResponse)
def trigger_scan(
    req: ScanRequest,
    auth: AuthContext = Depends(require_permission("api_security:write")),
):
    """Trigger API security scan for a scan_run_id.
    Called by Argo workflow. Validates scan_run_id belongs to tenant before dispatching.
    """
    from engine_common.db_connections import get_onboarding_conn

    with get_onboarding_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT 1 FROM scan_runs WHERE scan_run_id = %s AND tenant_id = %s",
                (str(req.scan_run_id), req.tenant_id),
            )
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="scan_run_id not found for tenant")

    cmd = [
        "python3", "run_scan.py",
        "--scan-run-id", str(req.scan_run_id),
        "--tenant-id", req.tenant_id,
        "--account-id", req.account_id,
        "--provider", req.provider,
        "--credential-ref", req.credential_ref,
        "--credential-type", req.credential_type,
    ]
    if req.region:
        cmd += ["--region", req.region]

    subprocess.Popen(cmd)
    return ScanResponse(
        scan_run_id=req.scan_run_id,
        status="dispatched",
        message="API security scan started",
    )


@router.get("/apisec/report/{scan_run_id}")
def get_report(
    scan_run_id: UUID,
    auth: AuthContext = Depends(require_permission("api_security:read")),
):
    """Fetch api_security_report for completed scan. Scoped to auth tenant."""
    from engine_common.db_connections import get_api_security_conn

    with get_api_security_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT report_id, scan_run_id, tenant_id, provider, account_id, status,
                       critical_count, high_count, medium_count, low_count, total_findings,
                       owasp_api1_count, owasp_api2_count, owasp_api4_count,
                       owasp_api7_count, owasp_api8_count, owasp_api9_count,
                       cdr_enriched_count, started_at, completed_at, report_data
                FROM api_security_report
                WHERE scan_run_id = %s AND tenant_id = %s
                """,
                (str(scan_run_id), auth.tenant_id),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Report not found")
            cols = [d[0] for d in cur.description]
    return dict(zip(cols, row))


@router.get("/apisec/findings")
def list_findings(
    tenant_id: Optional[str] = Query(None),
    scan_run_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None, description="critical|high|medium|low"),
    owasp_category: Optional[str] = Query(None, description="API1..API9"),
    finding_source: Optional[str] = Query(None, description="config|cdr"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    auth: AuthContext = Depends(require_permission("api_security:read")),
):
    """Paginated findings list. tenant_id always scoped to auth.tenant_id (multi-tenant guard)."""
    from engine_common.db_connections import get_api_security_conn

    # Always enforce auth context tenant regardless of query param
    effective_tenant = auth.tenant_id

    conditions = ["tenant_id = %s"]
    params: List = [effective_tenant]

    if scan_run_id:
        conditions.append("scan_run_id = %s")
        params.append(scan_run_id)
    if severity:
        conditions.append("severity = %s")
        params.append(severity.lower())
    if owasp_category:
        conditions.append("owasp_api_category = %s")
        params.append(owasp_category.upper())
    if finding_source:
        conditions.append("finding_source = %s")
        params.append(finding_source.lower())

    where = " AND ".join(conditions)
    count_sql = f"SELECT COUNT(*) FROM api_security_findings WHERE {where}"
    data_sql = f"""
        SELECT finding_id, scan_run_id, tenant_id, account_id, provider,
               resource_uid, resource_type, rule_id, severity, status,
               title, description, remediation, owasp_api_category,
               finding_source, auth_type, has_waf, has_rate_limit,
               is_publicly_accessible, api_gateway_id, api_name, api_stage,
               evidence, first_seen_at, last_seen_at
        FROM api_security_findings
        WHERE {where}
        ORDER BY severity DESC, last_seen_at DESC
        LIMIT %s OFFSET %s
    """

    with get_api_security_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(count_sql, params)
            total = cur.fetchone()[0]

            cur.execute(data_sql, params + [limit, offset])
            cols = [d[0] for d in cur.description]
            rows = cur.fetchall()

    findings = [dict(zip(cols, row)) for row in rows]
    return {
        "findings": findings,
        "total": total,
        "limit": limit,
        "offset": offset,
    }
