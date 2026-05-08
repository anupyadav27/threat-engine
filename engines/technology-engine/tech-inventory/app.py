"""
tech-inventory FastAPI app — Port 8031
GET  /api/v1/assets          → list normalized inventory assets
GET  /api/v1/assets/{asset_id}
GET  /api/v1/health/live
GET  /api/v1/health/ready
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from fastapi import FastAPI, HTTPException, Query
from typing import Optional

app = FastAPI(title="tech-inventory", version="1.0.0")


@app.get("/api/v1/health/live")
def live():
    return {"status": "ok"}


@app.get("/api/v1/health/ready")
def ready():
    return {"status": "ok"}


@app.get("/api/v1/assets")
async def list_assets(
    tenant_id: str = Query(...),
    provider:  Optional[str] = Query(None),
):
    from common.database.tech_db_manager import TechDBManager
    db = TechDBManager()
    assets = db.list_assets(tenant_id=tenant_id, provider=provider)
    return {"count": len(assets), "assets": assets}


@app.get("/api/v1/assets/{asset_id}")
async def get_asset(asset_id: str, tenant_id: str = Query(...)):
    from common.database.tech_db_manager import TechDBManager
    db = TechDBManager()
    assets = db.list_assets(tenant_id=tenant_id)
    match = next((a for a in assets if a["asset_id"] == asset_id), None)
    if not match:
        raise HTTPException(status_code=404, detail=f"Asset {asset_id} not found")
    return match
