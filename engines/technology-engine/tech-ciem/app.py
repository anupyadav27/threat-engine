"""
tech-ciem FastAPI app — Port 8033
GET  /api/v1/ciem/{scan_run_id}  → list CIEM findings
GET  /api/v1/health/live
GET  /api/v1/health/ready
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from fastapi import FastAPI, Query

app = FastAPI(title="tech-ciem", version="1.0.0")


@app.get("/api/v1/health/live")
def live():
    return {"status": "ok"}


@app.get("/api/v1/health/ready")
def ready():
    return {"status": "ok"}


@app.get("/api/v1/ciem/{scan_run_id}")
async def get_ciem_findings(scan_run_id: str, tenant_id: str = Query(...)):
    from common.database.tech_db_manager import TechDBManager
    db = TechDBManager()
    findings = db.list_ciem_findings(scan_run_id=scan_run_id, tenant_id=tenant_id)
    critical = sum(1 for f in findings if f.get("severity") == "critical")
    high     = sum(1 for f in findings if f.get("severity") == "high")
    return {
        "scan_run_id":    scan_run_id,
        "total":          len(findings),
        "critical_count": critical,
        "high_count":     high,
        "findings":       findings,
    }
