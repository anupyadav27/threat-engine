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

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
import psycopg2
from psycopg2.extras import RealDictCursor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "shared"))

from api.ui_data_router import router as ui_data_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger("network_security.api_server")

app = FastAPI(
    title="Network Security Engine",
    description="Layered network posture analysis (7 layers: topology → SG → WAF → flow)",
    version="1.0.0",
)
app.include_router(ui_data_router)

SCANNER_IMAGE = os.getenv("NETWORK_SCANNER_IMAGE", "yadavanup84/engine-network:v-std-cols")
SCANNER_CPU_REQUEST = "100m"
SCANNER_MEM_REQUEST = "512Mi"
SCANNER_CPU_LIMIT = "250m"
SCANNER_MEM_LIMIT = "1Gi"


def _get_network_conn():
    return psycopg2.connect(
        host=os.getenv("NETWORK_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("NETWORK_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("NETWORK_DB_NAME", "threat_engine_network"),
        user=os.getenv("NETWORK_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("NETWORK_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
        connect_timeout=10,
    )


def _get_onboarding_conn():
    return psycopg2.connect(
        host=os.getenv("ONBOARDING_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("ONBOARDING_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("ONBOARDING_DB_NAME", "threat_engine_onboarding"),
        user=os.getenv("ONBOARDING_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("ONBOARDING_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
        connect_timeout=10,
    )


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
        conn = _get_network_conn()
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
        conn = _get_onboarding_conn()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM scan_orchestration WHERE scan_run_id = %s", (orch_id,))
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
        conn = _get_network_conn()
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
        from common.orchestration import create_engine_job
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
    conn = _get_network_conn()
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
    conn = _get_network_conn()
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
    conn = _get_network_conn()
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
