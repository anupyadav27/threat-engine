"""
tech-discovery FastAPI app — Port 8030
POST /api/v1/scan  → triggers K8s Job via Argo
GET  /api/v1/health/live
GET  /api/v1/health/ready
"""
from __future__ import annotations

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional

app = FastAPI(title="tech-discovery", version="1.0.0")


class ScanRequest(BaseModel):
    scan_run_id: str
    tenant_id:   str
    account_ids: List[str]
    force:       bool = False


@app.get("/api/v1/health/live")
def live():
    return {"status": "ok"}


@app.get("/api/v1/health/ready")
def ready():
    return {"status": "ok"}


@app.post("/api/v1/scan", status_code=202)
async def trigger_scan(body: ScanRequest):
    """
    Accept scan request and dispatch K8s Jobs via Argo (one job per account_id).
    Sprint 0 implementation: validate and enqueue.
    """
    from common.database.tech_db_manager import TechDBManager
    db = TechDBManager()
    jobs = []
    for account_id in body.account_ids:
        cred = db.get_credential(account_id=account_id)
        if not cred:
            raise HTTPException(status_code=404, detail=f"No credential for account_id={account_id}")
        # TODO Sprint 0: submit Argo WorkflowTemplate for tech-scan
        jobs.append({
            "account_id": account_id,
            "tech_type":  cred["tech_type"],
            "status":     "queued",
        })
    return {"scan_run_id": body.scan_run_id, "jobs": jobs}


@app.get("/api/v1/findings/{scan_run_id}")
async def get_findings(scan_run_id: str, tenant_id: str):
    from common.database.tech_db_manager import TechDBManager
    db = TechDBManager()
    findings = db.list_findings(scan_run_id=scan_run_id, tenant_id=tenant_id)
    return {"scan_run_id": scan_run_id, "count": len(findings), "findings": findings}
