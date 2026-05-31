"""
Network Security Engine — FastAPI Server (Port 8004)

Endpoints:
  POST /api/v1/network-security/scan          — Trigger scan (K8s Job)
  GET  /api/v1/network-security/{id}/status    — Poll scan status
  GET  /api/v1/network-security/ui-data        — Unified UI payload
  GET  /api/v1/network-security/findings       — Query findings
  GET  /api/v1/network-security/topology       — Network topology map
  GET  /api/v1/health/live                     — Liveness probe
  GET  /api/v1/health/ready                    — Readiness probe
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query
from pydantic import BaseModel
import psycopg2.extras
from psycopg2.extras import RealDictCursor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "shared"))

from api.ui_data_router import router as ui_data_router
from engine_common.db_connections import get_network_conn, get_onboarding_conn

# ── Auth imports (engine_auth is COPY shared/auth/ ./engine_auth/ in Dockerfile) ──
try:
    from engine_auth.fastapi.middleware import AuthMiddleware
    _AUTH_AVAILABLE = True
except ImportError:
    _AUTH_AVAILABLE = False

try:
    from engine_auth.fastapi.dependencies import require_permission
    from engine_auth.core.models import AuthContext
    _AUTH_DEPS_AVAILABLE = True
except ImportError:
    _AUTH_DEPS_AVAILABLE = False
    AuthContext = None  # type: ignore[assignment,misc]

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger("network_security.api_server")

app = FastAPI(
    title="Network Security Engine",
    description="Layered network posture analysis (7 layers: topology → SG → WAF → flow)",
    version="1.0.0",
)
app.include_router(ui_data_router)

# AuthMiddleware validates access_token / X-Auth-Context for every non-health path
if _AUTH_AVAILABLE:
    app.add_middleware(AuthMiddleware)

SCANNER_IMAGE = os.getenv("NETWORK_SCANNER_IMAGE", "yadavanup84/engine-network:v-std-cols")
SCANNER_CPU_REQUEST = "100m"
SCANNER_MEM_REQUEST = "512Mi"
SCANNER_CPU_LIMIT = "250m"
SCANNER_MEM_LIMIT = "1Gi"


# ── Health Checks ─────────────────────────────────────────────────────────────

@app.get("/")
@app.get("/health")
async def health():
    return {"status": "ok", "engine": "network-security", "port": 8004}


@app.get("/api/v1/health/live")
async def health_live():
    return {"status": "ok"}


@app.get("/api/v1/health/ready")
async def health_ready():
    try:
        conn = get_network_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
        conn.close()
        return {"status": "ready", "database": "connected"}
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Database not ready: {e}")


# ── Scan Trigger ──────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    scan_run_id: Optional[str] = None
    scan_id: Optional[str] = None
    tenant_id: Optional[str] = None


@app.post("/api/v1/network-security/scan")
async def trigger_scan(request: ScanRequest):
    """Trigger a network security scan by creating a K8s Job."""
    orch_id = request.scan_run_id or request.scan_id
    if not orch_id:
        raise HTTPException(400, "scan_run_id is required")

    # Get orchestration metadata
    tenant_id = request.tenant_id
    provider = "aws"
    try:
        conn = get_onboarding_conn()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM scan_runs WHERE scan_run_id = %s", (orch_id,))
            row = cur.fetchone()
            if row:
                tenant_id = tenant_id or row.get("tenant_id", "default-tenant")
                provider = (row.get("provider") or row.get("provider_type", "aws")).lower()
        conn.close()
    except Exception as e:
        logger.warning("Could not read orchestration metadata: %s", e)

    tenant_id = tenant_id or "default-tenant"

    # Pre-create report row
    try:
        conn = get_network_conn()
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO tenants (tenant_id, tenant_name) VALUES (%s, %s)
                ON CONFLICT (tenant_id) DO NOTHING
            """, (tenant_id, tenant_id))
            cur.execute("""
                INSERT INTO network_report (scan_run_id, tenant_id, provider, status, started_at)
                VALUES (%s, %s, %s, 'running', NOW())
                ON CONFLICT (scan_run_id) DO UPDATE SET status = 'running', started_at = NOW()
            """, (orch_id, tenant_id, provider))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning("Failed to pre-create network_report: %s", e)

    # Create K8s Job
    job_name = None
    try:
        from engine_common.job_creator import create_engine_job
        job_name = create_engine_job(
            engine_name="network",
            scan_id=orch_id,
            scan_run_id=orch_id,
            image=SCANNER_IMAGE,
            cpu_request=SCANNER_CPU_REQUEST,
            mem_request=SCANNER_MEM_REQUEST,
            cpu_limit=SCANNER_CPU_LIMIT,
            mem_limit=SCANNER_MEM_LIMIT,
            active_deadline_seconds=1800,
        )
    except Exception as e:
        logger.warning("K8s job creation failed (may be running locally): %s", e)
        job_name = f"network-scan-{orch_id[:8]}"

    return {
        "scan_id": orch_id,
        "scan_run_id": orch_id,
        "status": "running",
        "job_name": job_name,
        "message": "Network security scan initiated",
    }


# ── Scan Status ───────────────────────────────────────────────────────────────

@app.get("/api/v1/network-security/{scan_id}/status")
async def get_scan_status(scan_id: str):
    conn = get_network_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT scan_run_id, status, provider, posture_score,
                       total_findings, critical_findings, high_findings,
                       scan_duration_ms, generated_at, error_message
                FROM network_report WHERE scan_run_id = %s
            """, (scan_id,))
            row = cur.fetchone()

        if not row:
            raise HTTPException(404, f"Scan {scan_id} not found")

        return dict(row)
    finally:
        conn.close()


# ── Query Findings ────────────────────────────────────────────────────────────

@app.get("/api/v1/network-security/findings")
async def query_findings(
    tenant_id: str = Query(...),
    scan_id: str = Query("latest"),
    severity: Optional[str] = Query(None),
    layer: Optional[str] = Query(None),
    module: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(1000),
    offset: int = Query(0),
):
    conn = get_network_conn()
    try:
        # Resolve latest
        if scan_id == "latest":
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT scan_run_id FROM network_report
                    WHERE tenant_id = %s AND status = 'completed'
                    ORDER BY generated_at DESC LIMIT 1
                """, (tenant_id,))
                row = cur.fetchone()
                scan_id = row[0] if row else None
            if not scan_id:
                return {"findings": [], "total": 0}

        where = ["scan_run_id = %s", "tenant_id = %s"]
        params: list = [scan_id, tenant_id]

        if severity:
            where.append("severity = %s")
            params.append(severity)
        if layer:
            where.append("network_layer = %s")
            params.append(layer)
        if module:
            where.append("%s = ANY(network_modules)")
            params.append(module)
        if status:
            where.append("status = %s")
            params.append(status)

        where_sql = " AND ".join(where)

        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(f"SELECT COUNT(*) as total FROM network_findings WHERE {where_sql}", params)
            total = cur.fetchone()["total"]

            cur.execute(f"""
                SELECT * FROM network_findings WHERE {where_sql}
                ORDER BY CASE severity
                    WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3 ELSE 4 END
                LIMIT %s OFFSET %s
            """, params + [limit, offset])
            findings = [dict(r) for r in cur.fetchall()]

        return {"findings": findings, "total": total, "scan_id": scan_id}
    finally:
        conn.close()


# ── Topology Endpoint ─────────────────────────────────────────────────────────

@app.get("/api/v1/network-security/topology")
async def get_topology(
    tenant_id: str = Query(...),
    scan_id: str = Query("latest"),
):
    conn = get_network_conn()
    try:
        if scan_id == "latest":
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT scan_run_id FROM network_report
                    WHERE tenant_id = %s AND status = 'completed'
                    ORDER BY generated_at DESC LIMIT 1
                """, (tenant_id,))
                row = cur.fetchone()
                scan_id = row[0] if row else None
            if not scan_id:
                return {"topology": [], "scan_id": None}

        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT * FROM network_topology_snapshot
                WHERE scan_run_id = %s AND tenant_id = %s
            """, (scan_id, tenant_id))
            snapshots = [dict(r) for r in cur.fetchall()]

        return {"topology": snapshots, "scan_id": scan_id}
    finally:
        conn.close()


# ── Findings-by-resource models ───────────────────────────────────────────────

class FindingItem(BaseModel):
    """Single network finding row returned by the asset-context endpoint."""

    finding_id: str
    title: str
    severity: str
    status: str
    rule_id: Optional[str] = None
    resource_uid: str
    resource_type: Optional[str] = None
    account_id: Optional[str] = None
    region: Optional[str] = None
    provider: Optional[str] = None
    first_seen_at: str
    last_seen_at: str
    network_layer: Optional[str] = None
    effective_exposure: Optional[str] = None


class FindingsByResourceResponse(BaseModel):
    """Response for GET /api/v1/network-security/findings/by-resource."""

    findings: List[FindingItem]
    total: int
    resource_uid: str
    scan_run_id: str


_NET_TABLE = "network_findings"


@app.get("/api/v1/network-security/findings/by-resource", response_model=FindingsByResourceResponse)
async def get_network_findings_by_resource(
    resource_uid: str = Query(..., description="Full resource ARN or UID"),
    scan_run_id: str = Query("latest"),
    limit: int = Query(50, ge=1, le=100),
    status: Optional[str] = Query(None),
    auth: Any = Depends(
        require_permission("network:read") if _AUTH_DEPS_AVAILABLE else (lambda: None)
    ),
):
    """Return network findings for a specific resource_uid — used by gateway asset-context aggregator.

    Args:
        resource_uid: Full resource ARN or UID to filter findings by.
        scan_run_id: Scan run UUID, or 'latest' to resolve automatically.
        limit: Maximum number of findings to return (1-100).
        status: Optional status filter (FAIL | PASS | WARN).
        auth: Injected AuthContext from require_permission dependency.

    Returns:
        FindingsByResourceResponse with findings list, total count, and resolved scan_run_id.
    """
    scoped_tenant = (
        getattr(auth, "engine_tenant_id", None)
        or getattr(auth, "tenant_id", None)
        or "default-tenant"
    )

    status_clause = "AND status = %(status)s" if status else ""
    params: Dict[str, Any] = {
        "tenant_id": scoped_tenant,
        "resource_uid": resource_uid,
        "status": status,
        "limit": limit,
    }

    conn = get_network_conn()
    try:
        with conn.cursor() as cur:
            # Step 1: resolve scan_run_id
            cur.execute(f"""
                SELECT scan_run_id FROM {_NET_TABLE}
                WHERE tenant_id = %(tenant_id)s
                  AND resource_uid = %(resource_uid)s
                  {status_clause}
                ORDER BY last_seen_at DESC LIMIT 1
            """, params)
            row = cur.fetchone()
            if not row:
                return FindingsByResourceResponse(
                    findings=[], total=0,
                    resource_uid=resource_uid, scan_run_id=scan_run_id,
                )
            resolved_scan = row[0]
            params["resolved_scan"] = resolved_scan

            # Step 2: total count
            cur.execute(f"""
                SELECT COUNT(*) FROM {_NET_TABLE}
                WHERE tenant_id = %(tenant_id)s
                  AND resource_uid = %(resource_uid)s
                  AND scan_run_id = %(resolved_scan)s
                  {status_clause}
            """, params)
            total = cur.fetchone()[0]

            # Step 3: top N findings sorted by severity
            cur.execute(f"""
                SELECT finding_id,
                       title,
                       severity, status,
                       rule_id, resource_uid, resource_type,
                       account_id, region, provider,
                       first_seen_at, last_seen_at,
                       network_layer, effective_exposure
                FROM {_NET_TABLE}
                WHERE tenant_id = %(tenant_id)s
                  AND resource_uid = %(resource_uid)s
                  AND scan_run_id = %(resolved_scan)s
                  {status_clause}
                ORDER BY
                    CASE severity
                        WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                        WHEN 'medium'   THEN 2 WHEN 'low'  THEN 1 ELSE 0
                    END DESC,
                    last_seen_at DESC
                LIMIT %(limit)s
            """, params)
            cols = [d[0] for d in cur.description]
            findings = [
                FindingItem(**{k: (str(v) if v is not None else v) if k in ("first_seen_at", "last_seen_at") else v
                               for k, v in dict(zip(cols, r)).items()})
                for r in cur.fetchall()
            ]
    except Exception as exc:
        logger.error("Error in get_network_findings_by_resource: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))
    finally:
        conn.close()

    return FindingsByResourceResponse(
        findings=findings,
        total=total,
        resource_uid=resource_uid,
        scan_run_id=resolved_scan,
    )


# ── IEDS Exposure Findings ────────────────────────────────────────────────────

@app.get("/api/v1/network-security/exposure")
async def get_exposure_findings(
    scan_run_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    origin_type: Optional[str] = None,
    tier: Optional[int] = None,
    severity: Optional[str] = None,
    limit: int = 200,
    offset: int = 0,
    auth: dict = Depends(require_permission("network:read")),
):
    """Return IEDS network_exposure_findings for this tenant/scan.

    Supports filtering by origin_type (internet/vpn/connected_network/…),
    exposure_tier (1/2/3), and severity.
    """
    resolved_tid = auth.get("engine_tenant_id") or auth.get("tenant_id", "")
    if not resolved_tid:
        raise HTTPException(status_code=400, detail="tenant_id required")

    conn = get_network_conn()
    try:
        conditions = ["tenant_id = %s"]
        params: list = [resolved_tid]

        if scan_run_id:
            conditions.append("scan_run_id = %s")
            params.append(scan_run_id)
        if origin_type:
            conditions.append("origin_type = %s")
            params.append(origin_type)
        if tier is not None:
            conditions.append("exposure_tier = %s")
            params.append(tier)
        if severity:
            conditions.append("severity = %s")
            params.append(severity.lower())

        where = " AND ".join(conditions)
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(f"SELECT COUNT(*) AS cnt FROM network_exposure_findings WHERE {where}", params)
            total = (cur.fetchone() or {}).get("cnt", 0)

            cur.execute(
                f"""
                SELECT finding_id, scan_run_id, tenant_id, account_id, provider,
                       region, resource_uid, resource_type, resource_name,
                       exposure_tier, origin_type, rule_id, exposure_reason,
                       exposure_detail, chain_hops, severity, status,
                       first_seen_at, last_seen_at
                FROM   network_exposure_findings
                WHERE  {where}
                ORDER  BY severity DESC, first_seen_at DESC
                LIMIT  %s OFFSET %s
                """,
                params + [min(limit, 1000), offset],
            )
            findings = [dict(r) for r in cur.fetchall()]
    except Exception as exc:
        logger.error("Error in get_exposure_findings: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))
    finally:
        conn.close()

    return {"findings": findings, "total": total, "scan_run_id": scan_run_id}


# ── Modules List ──────────────────────────────────────────────────────────────

@app.get("/api/v1/network-security/modules")
async def list_modules():
    return {
        "modules": [
            {"id": "network_isolation", "name": "Network Isolation", "layer": "L1"},
            {"id": "network_reachability", "name": "Network Reachability", "layer": "L2"},
            {"id": "network_acl", "name": "Network ACL", "layer": "L3"},
            {"id": "security_group_rules", "name": "Security Group Rules", "layer": "L4"},
            {"id": "load_balancer_security", "name": "Load Balancer Security", "layer": "L5"},
            {"id": "waf_protection", "name": "WAF Protection", "layer": "L6"},
            {"id": "internet_exposure", "name": "Internet Exposure", "layer": "L4+L5"},
            {"id": "network_monitoring", "name": "Network Monitoring", "layer": "L7"},
        ]
    }


# ── Run ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8004"))
    uvicorn.run(app, host="0.0.0.0", port=port)
