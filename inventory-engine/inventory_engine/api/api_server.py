"""
Inventory Engine API Server

FastAPI server for inventory scanning and querying.
"""

import os
import json
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException, Query, Body
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from datetime import datetime

from ..api.orchestrator import ScanOrchestrator
from ..schemas.asset_schema import Provider

app = FastAPI(
    title="Inventory Engine API",
    description="Cloud Resource Inventory Discovery and Graph Building",
    version="1.0.0"
)


class ScanRequest(BaseModel):
    """Request model for inventory scan"""
    tenant_id: str
    providers: List[str] = ["aws"]
    accounts: List[str]
    regions: List[str]
    services: Optional[List[str]] = None
    previous_scan_id: Optional[str] = None


class ScanResponse(BaseModel):
    """Response model for scan execution"""
    scan_run_id: str
    status: str
    started_at: str
    completed_at: str
    total_assets: int
    total_relationships: int
    total_drift: int
    artifact_paths: Dict[str, str]


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "inventory-engine",
        "version": "1.0.0",
        "status": "running"
    }


@app.get("/health")
async def health():
    """Health check endpoint"""
    return {"status": "healthy"}


@app.post("/api/v1/inventory/scan", response_model=ScanResponse)
async def run_inventory_scan(request: ScanRequest):
    """
    Run inventory scan.
    
    Collects resources, normalizes to assets/relationships, detects drift,
    and saves artifacts to S3/local storage.
    """
    try:
        orchestrator = ScanOrchestrator(
            tenant_id=request.tenant_id,
            s3_bucket=os.getenv("S3_BUCKET", "cspm-lgtech"),
            db_url=os.getenv("DATABASE_URL"),
            neo4j_uri=os.getenv("NEO4J_URI"),
            neo4j_username=os.getenv("NEO4J_USERNAME"),
            neo4j_password=os.getenv("NEO4J_PASSWORD")
        )
        
        result = orchestrator.run_scan(
            providers=request.providers,
            accounts=request.accounts,
            regions=request.regions,
            services=request.services,
            previous_scan_id=request.previous_scan_id
        )
        
        return ScanResponse(**result)
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to run inventory scan: {str(e)}"
        )


@app.get("/api/v1/inventory/runs/{scan_run_id}/summary")
async def get_scan_summary(scan_run_id: str, tenant_id: str = Query(...)):
    """Get scan summary"""
    try:
        # Load summary from S3/local
        use_s3 = os.getenv("USE_S3", "false").lower() == "true"
        
        if use_s3:
            import boto3
            s3_client = boto3.client('s3')
            bucket = os.getenv("S3_BUCKET", "cspm-lgtech")
            key = f"inventory/{tenant_id}/{scan_run_id}/normalized/summary.json"
            
            response = s3_client.get_object(Bucket=bucket, Key=key)
            summary = json.loads(response['Body'].read().decode('utf-8'))
        else:
            base_path = os.getenv("INVENTORY_OUTPUT_DIR", "/Users/apple/Desktop/threat-engine/engines-output/inventory-engine/output")
            summary_path = os.path.join(base_path, tenant_id, scan_run_id, "normalized", "summary.json")
            
            with open(summary_path, 'r') as f:
                summary = json.load(f)
        
        return summary
    
    except Exception as e:
        raise HTTPException(
            status_code=404,
            detail=f"Scan summary not found: {str(e)}"
        )


@app.get("/api/v1/inventory/assets")
async def list_assets(
    tenant_id: str = Query(...),
    provider: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
    resource_type: Optional[str] = Query(None),
    scan_run_id: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    cursor: Optional[str] = Query(None)
):
    """List assets with filters"""
    # TODO: Implement asset listing from index or artifacts
    return {
        "assets": [],
        "total": 0,
        "cursor": None
    }


@app.get("/api/v1/inventory/assets/{resource_uid}")
async def get_asset(resource_uid: str, tenant_id: str = Query(...)):
    """Get asset details"""
    # TODO: Implement asset detail lookup
    return {"resource_uid": resource_uid, "not_implemented": True}


@app.get("/api/v1/inventory/assets/{resource_uid}/relationships")
async def get_asset_relationships(
    resource_uid: str,
    tenant_id: str = Query(...),
    depth: int = Query(1, ge=1, le=3)
):
    """Get asset relationships (graph edges)"""
    # TODO: Implement relationship lookup from Neo4j or index
    return {
        "resource_uid": resource_uid,
        "relationships": [],
        "depth": depth
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)

