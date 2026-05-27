"""
DBSec Engine — FastAPI server.

Port: 8007 (matches K8s manifest)
Endpoints:
  GET  /api/v1/health/live
  GET  /api/v1/health/ready
  POST /api/v1/scan                        → 202 (async trigger)
  GET  /api/v1/scan/{scan_run_id}/status   → running|completed|failed
  GET  /api/v1/findings/{scan_run_id}
"""

import asyncio
import logging
import threading
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

# In-memory scan job status (keyed by scan_run_id).
# Avoids blocking Argo trigger step while scan runs.
_scan_jobs: Dict[str, Dict[str, Any]] = {}
_scan_jobs_lock = threading.Lock()


class ScanRequest(BaseModel):
    """Request body for /api/v1/scan."""

    scan_run_id: str
    tenant_id: str
    account_id: str
    provider: str
    credential_ref: Optional[str] = ""
    credential_type: Optional[str] = ""


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


@app.post("/api/v1/scan", status_code=202)
async def trigger_scan(request: ScanRequest) -> Dict[str, Any]:
    """Start an async DBSec 5-pillar scan. Returns 202 immediately."""
    scan_run_id = request.scan_run_id

    with _scan_jobs_lock:
        existing = _scan_jobs.get(scan_run_id)
        if existing and existing["status"] == "running":
            logger.info("DBSec scan_run_id=%s already running", scan_run_id)
            return {"scan_run_id": scan_run_id, "status": "running", "message": "Scan already in progress"}
        _scan_jobs[scan_run_id] = {"status": "running", "total_findings": 0, "message": "Started"}

    logger.info(
        "DBSec scan triggered scan_run_id=%s provider=%s tenant=%s",
        scan_run_id,
        request.provider,
        request.tenant_id,
    )
    asyncio.create_task(_run_scan_background(request))
    return {"scan_run_id": scan_run_id, "status": "running", "message": "DBSec scan started"}


async def _run_scan_background(request: ScanRequest) -> None:
    """Run scan in executor thread; update _scan_jobs on completion."""
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
        with _scan_jobs_lock:
            _scan_jobs[request.scan_run_id] = {
                "status": "completed",
                "total_findings": findings_count,
                "message": f"DBSec scan completed: {findings_count} findings written",
            }
        logger.info("DBSec background scan_run_id=%s completed findings=%d", request.scan_run_id, findings_count)
    except Exception as exc:
        logger.error("DBSec background scan failed scan_run_id=%s: %s", request.scan_run_id, exc, exc_info=True)
        with _scan_jobs_lock:
            _scan_jobs[request.scan_run_id] = {
                "status": "failed",
                "total_findings": 0,
                "message": str(exc),
            }


@app.get("/api/v1/scan/{scan_run_id}/status")
async def get_scan_status(scan_run_id: str) -> Dict[str, Any]:
    """Poll scan progress. Returns status=running|completed|failed + total_findings."""
    with _scan_jobs_lock:
        job = _scan_jobs.get(scan_run_id)

    if job:
        return {
            "scan_run_id": scan_run_id,
            "status": job["status"],
            "total_findings": job.get("total_findings", 0),
            "message": job.get("message", ""),
        }

    # Fallback: check DB for a completed scan (handles pod restarts)
    try:
        from engine_common.db_connections import get_dbsec_conn
        conn = get_dbsec_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT status, total_findings FROM dbsec_report WHERE scan_run_id = %s",
                    (scan_run_id,),
                )
                row = cur.fetchone()
        finally:
            conn.close()
        if row:
            return {"scan_run_id": scan_run_id, "status": row[0], "total_findings": row[1] or 0}
    except Exception as exc:
        logger.warning("DBSec status DB fallback failed: %s", exc)

    raise HTTPException(status_code=404, detail=f"No scan found for scan_run_id={scan_run_id}")


def _write_dbsec_report(
    dbsec_conn: Any,
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
    findings: list,
    written: int,
    started_at: "datetime",
) -> None:
    """Insert a completed row into dbsec_report for Phase 2 pipeline verification."""
    from collections import Counter
    sev_counts: Counter = Counter()
    for f in findings:
        sev_counts[f.get("severity", "medium")] += 1

    try:
        with dbsec_conn.cursor() as cur:
            cur.execute(
                "INSERT INTO tenants (tenant_id, tenant_name) VALUES (%s, %s) ON CONFLICT (tenant_id) DO NOTHING",
                (tenant_id, tenant_id),
            )
            cur.execute(
                """
                INSERT INTO dbsec_report (
                    scan_run_id, tenant_id, account_id, provider, status,
                    total_findings, critical_findings, high_findings,
                    medium_findings, low_findings,
                    started_at, completed_at, scan_duration_ms
                ) VALUES (%s, %s, %s, %s, 'completed', %s, %s, %s, %s, %s, %s, NOW(),
                    EXTRACT(EPOCH FROM (NOW() - %s)) * 1000
                )
                ON CONFLICT (scan_run_id) DO UPDATE SET
                    status           = 'completed',
                    total_findings   = EXCLUDED.total_findings,
                    critical_findings = EXCLUDED.critical_findings,
                    high_findings    = EXCLUDED.high_findings,
                    medium_findings  = EXCLUDED.medium_findings,
                    low_findings     = EXCLUDED.low_findings,
                    completed_at     = NOW()
                """,
                (
                    scan_run_id, tenant_id, account_id, provider,
                    written,
                    sev_counts.get("critical", 0),
                    sev_counts.get("high", 0),
                    sev_counts.get("medium", 0),
                    sev_counts.get("low", 0),
                    started_at, started_at,
                ),
            )
        dbsec_conn.commit()
        logger.info("DBSec report written for scan_run_id=%s", scan_run_id)
    except Exception as exc:
        logger.warning("dbsec_report write failed (non-fatal): %s", exc)


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

    started_at = datetime.now(timezone.utc)
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
            for f in findings:
                f["credential_ref"] = credential_ref
                f["credential_type"] = credential_type
            written = save_findings_to_db(findings, dbsec_conn)
            logger.info(
                "DBSec scan_run_id=%s provider=%s findings=%d written=%d",
                scan_run_id, provider, len(findings), written,
            )
        else:
            findings = []
            written = 0

        _write_dbsec_report(dbsec_conn, scan_run_id, tenant_id, account_id,
                            provider, findings, written, started_at)

        # Write posture signals to resource_security_posture (non-fatal)
        try:
            from engine_common.db_connections import get_di_conn as _get_inv_conn
            _rsp_by_uid: dict = {}
            for _f in findings:
                _uid = _f.get("resource_uid", "")
                if not _uid:
                    continue
                if _uid not in _rsp_by_uid:
                    _rsp_by_uid[_uid] = {
                        "resource_type": _f.get("resource_type", ""),
                        "account_id": _f.get("account_id", account_id),
                        "region": _f.get("region", ""),
                        "db_auth_type": None,
                    }
                if _f.get("pillar") == "authentication" and not _rsp_by_uid[_uid]["db_auth_type"]:
                    _pd = _f.get("pillar_detail") or {}
                    _check = _pd.get("check", "") if isinstance(_pd, dict) else ""
                    if _pd.get("iam_auth_enabled") or "iam_controlled" in _check:
                        _rsp_by_uid[_uid]["db_auth_type"] = "IAM"
                    elif _pd.get("auth_token_enabled"):
                        _rsp_by_uid[_uid]["db_auth_type"] = "token"
                    elif not _pd.get("iam_auth_enabled") and "iam_auth_enabled" in _check:
                        _rsp_by_uid[_uid]["db_auth_type"] = "password"
                    elif "master_username" in _check or "password" in _check:
                        _rsp_by_uid[_uid]["db_auth_type"] = "password"
                    elif _check:
                        _rsp_by_uid[_uid]["db_auth_type"] = _check

            if _rsp_by_uid:
                _inv_conn = _get_inv_conn()
                try:
                    with _inv_conn.cursor() as _cur:
                        _cur.execute(
                            "INSERT INTO tenants (tenant_id, tenant_name) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                            (tenant_id, tenant_id),
                        )
                        _rows = [
                            (tenant_id, scan_run_id, _m["account_id"], provider,
                             _m["region"], _uid, _m["resource_type"], _m["db_auth_type"])
                            for _uid, _m in _rsp_by_uid.items()
                        ]
                        _cur.executemany(
                            """INSERT INTO resource_security_posture
                               (tenant_id, scan_run_id, account_id, provider, region,
                                resource_uid, resource_type, db_auth_type)
                               VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                               ON CONFLICT (resource_uid, tenant_id) DO UPDATE SET
                                   scan_run_id  = EXCLUDED.scan_run_id,
                                   db_auth_type = EXCLUDED.db_auth_type,
                                   updated_at   = NOW()""",
                            _rows,
                        )
                        _inv_conn.commit()
                    logger.info("Posture: wrote %d DBSec rows to resource_security_posture", len(_rows))
                finally:
                    _inv_conn.close()
        except Exception as _pe:
            logger.warning("DBSec posture write failed (non-fatal): %s", _pe)

        return written
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
