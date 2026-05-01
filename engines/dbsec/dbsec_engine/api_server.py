"""
DBSec Engine — FastAPI server.

Port: 8007 (matches K8s manifest)
Endpoints:
  GET  /api/v1/health/live
  GET  /api/v1/health/ready
  POST /api/v1/scan
  GET  /api/v1/findings/{scan_run_id}
"""

import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

logger = logging.getLogger(__name__)

app = FastAPI(
    title="DBSec Engine",
    description="5-pillar database security analysis — Network Exposure, Encryption, Authentication, Audit, Compliance",
    version="2.0.0",
)


class ScanRequest(BaseModel):
    """Request body for /api/v1/scan."""

    scan_run_id: str
    tenant_id: str
    account_id: str
    provider: str
    credential_ref: Optional[str] = ""
    credential_type: Optional[str] = ""


class ScanResponse(BaseModel):
    """Response body for /api/v1/scan."""

    scan_run_id: str
    status: str
    findings_count: int
    message: str


@app.get("/api/v1/health/live")
async def liveness() -> Dict[str, str]:
    """Liveness probe — returns 200 if process is alive."""
    return {"status": "ok", "engine": "dbsec"}


@app.get("/api/v1/health/ready")
async def readiness() -> Dict[str, Any]:
    """Readiness probe — checks DB connectivity."""
    try:
        from engine_common.db_connections import get_dbsec_conn

        conn = get_dbsec_conn()
        conn.close()
        return {"status": "ready", "engine": "dbsec", "db": "connected"}
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"DB not ready: {exc}")


@app.post("/api/v1/scan", response_model=ScanResponse)
async def trigger_scan(request: ScanRequest) -> ScanResponse:
    """Trigger a DBSec 5-pillar scan for a given scan_run_id."""
    import asyncio

    logger.info(
        "DBSec scan triggered scan_run_id=%s provider=%s tenant=%s",
        request.scan_run_id,
        request.provider,
        request.tenant_id,
    )

    loop = asyncio.get_event_loop()
    try:
        findings_count = await loop.run_in_executor(
            None,
            _run_scan_sync,
            request.scan_run_id,
            request.tenant_id,
            request.account_id,
            request.provider,
            request.credential_ref or "",
            request.credential_type or "",
        )
        return ScanResponse(
            scan_run_id=request.scan_run_id,
            status="completed",
            findings_count=findings_count,
            message=f"DBSec scan completed: {findings_count} findings written",
        )
    except Exception as exc:
        logger.error("DBSec scan failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


def _run_scan_sync(
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
    credential_ref: str,
    credential_type: str,
) -> int:
    """Synchronous scan execution (runs in executor thread)."""
    from engine_common.db_connections import get_dbsec_conn, get_discoveries_conn, get_check_conn
    from dbsec_engine.providers import get_provider
    from dbsec_engine.storage.dbsec_db_writer import save_findings_to_db

    discoveries_conn = get_discoveries_conn()
    check_conn = get_check_conn()
    dbsec_conn = get_dbsec_conn()

    try:
        provider_impl = get_provider(provider)
        findings = provider_impl.analyze(
            scan_run_id=scan_run_id,
            tenant_id=tenant_id,
            account_id=account_id,
            discoveries_conn=discoveries_conn,
            check_conn=check_conn,
        )
        if findings:
            # Inject credential fields
            for f in findings:
                f["credential_ref"] = credential_ref
                f["credential_type"] = credential_type
            written = save_findings_to_db(findings, dbsec_conn)
            logger.info(
                "DBSec scan_run_id=%s provider=%s findings=%d written=%d",
                scan_run_id,
                provider,
                len(findings),
                written,
            )
            return written
        return 0
    finally:
        discoveries_conn.close()
        check_conn.close()
        dbsec_conn.close()


@app.get("/api/v1/findings/{scan_run_id}")
async def get_findings(
    scan_run_id: str,
    tenant_id: str,
    provider: Optional[str] = None,
    pillar: Optional[str] = None,
) -> Dict[str, Any]:
    """Retrieve DBSec findings for a scan run."""
    from engine_common.db_connections import get_dbsec_conn

    conn = get_dbsec_conn()
    try:
        with conn.cursor() as cur:
            query = """
                SELECT finding_id, provider, region, resource_uid, resource_type,
                       pillar, severity, status, pillar_detail, first_seen_at
                FROM dbsec_findings
                WHERE scan_run_id = %s AND tenant_id = %s
            """
            params: List[Any] = [scan_run_id, tenant_id]
            if provider:
                query += " AND provider = %s"
                params.append(provider)
            if pillar:
                query += " AND pillar = %s"
                params.append(pillar)
            query += " ORDER BY severity, pillar LIMIT 1000"
            cur.execute(query, params)
            rows = cur.fetchall()
            findings = [
                {
                    "finding_id": r[0],
                    "provider": r[1],
                    "region": r[2],
                    "resource_uid": r[3],
                    "resource_type": r[4],
                    "pillar": r[5],
                    "severity": r[6],
                    "status": r[7],
                    "pillar_detail": r[8],
                    "first_seen_at": r[9].isoformat() if r[9] else None,
                }
                for r in rows
            ]
        return {
            "scan_run_id": scan_run_id,
            "tenant_id": tenant_id,
            "total": len(findings),
            "findings": findings,
        }
    finally:
        conn.close()
