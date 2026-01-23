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
from ..api.data_loader import DataLoader
from ..schemas.asset_schema import Provider
from ..connectors.discovery_reader_factory import get_discovery_reader

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


class DiscoveryScanRequest(BaseModel):
    """Request model for discovery-based inventory scan"""
    tenant_id: str
    configscan_scan_id: str
    providers: Optional[List[str]] = None
    accounts: Optional[List[str]] = None
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


@app.post("/api/v1/inventory/scan/discovery", response_model=ScanResponse)
async def run_discovery_scan(request: DiscoveryScanRequest):
    """
    Run inventory scan from configscan-engine discovery output.
    
    Reads discovery records from configscan-engine output, normalizes to assets/relationships,
    detects drift, and saves artifacts to S3/local storage.
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
        
        result = orchestrator.run_scan_from_discovery(
            configscan_scan_id=request.configscan_scan_id,
            providers=request.providers,
            accounts=request.accounts,
            previous_scan_id=request.previous_scan_id
        )
        
        return ScanResponse(**result)
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to run discovery scan: {str(e)}"
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
    scan_run_id: Optional[str] = Query(None),
    provider: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
    resource_type: Optional[str] = Query(None),
    account_id: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """List assets with filters and pagination"""
    try:
        loader = DataLoader()
        
        # Load assets with filters
        assets = loader.load_assets(
            tenant_id=tenant_id,
            scan_run_id=scan_run_id or "latest",
            provider=provider,
            region=region,
            resource_type=resource_type,
            limit=limit,
            offset=offset
        )
        
        # Get total count
        total = loader.count_assets(
            tenant_id=tenant_id,
            scan_run_id=scan_run_id or "latest",
            provider=provider,
            region=region,
            resource_type=resource_type
        )
        
        return {
            "assets": assets,
            "total": total,
            "limit": limit,
            "offset": offset,
            "has_more": (offset + len(assets)) < total
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to load assets: {str(e)}"
        )


@app.get("/api/v1/inventory/assets/{resource_uid:path}")
async def get_asset(resource_uid: str, tenant_id: str = Query(...), scan_run_id: Optional[str] = Query(None)):
    """Get asset details by resource_uid"""
    try:
        loader = DataLoader()
        
        asset = loader.load_asset_by_uid(
            tenant_id=tenant_id,
            scan_run_id=scan_run_id or "latest",
            resource_uid=resource_uid
        )
        
        if not asset:
            raise HTTPException(
                status_code=404,
                detail=f"Asset not found: {resource_uid}"
            )
        
        return asset
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to load asset: {str(e)}"
        )


@app.get("/api/v1/inventory/assets/{resource_uid:path}/relationships")
async def get_asset_relationships(
    resource_uid: str,
    tenant_id: str = Query(...),
    scan_run_id: Optional[str] = Query(None),
    depth: int = Query(1, ge=1, le=3),
    relation_type: Optional[str] = Query(None),
    direction: Optional[str] = Query(None, regex="^(inbound|outbound|both)$")
):
    """Get asset relationships with depth traversal"""
    try:
        loader = DataLoader()
        
        # Load direct relationships
        relationships = loader.load_relationships(
            tenant_id=tenant_id,
            scan_run_id=scan_run_id or "latest",
            resource_uid=resource_uid,
            relation_type=relation_type
        )
        
        # Filter by direction
        if direction == "inbound":
            relationships = [r for r in relationships if r.get("to_uid") == resource_uid]
        elif direction == "outbound":
            relationships = [r for r in relationships if r.get("from_uid") == resource_uid]
        
        # TODO: Implement depth traversal for depth > 1
        
        return {
            "resource_uid": resource_uid,
            "relationships": relationships,
            "depth": depth,
            "total": len(relationships)
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to load relationships: {str(e)}"
        )


@app.get("/api/v1/inventory/graph")
async def get_graph(
    tenant_id: str = Query(...),
    scan_run_id: Optional[str] = Query(None),
    resource_uid: Optional[str] = Query(None),
    depth: int = Query(2, ge=1, le=3),
    limit: int = Query(100, ge=1, le=500)
):
    """Get graph visualization data (nodes and edges)"""
    try:
        loader = DataLoader()
        
        # Load assets (nodes)
        if resource_uid:
            # Get specific asset and its relationships
            asset = loader.load_asset_by_uid(tenant_id, scan_run_id or "latest", resource_uid)
            nodes = [asset] if asset else []
            
            # Get related assets
            relationships = loader.load_relationships(tenant_id, scan_run_id or "latest", resource_uid)
            
            # Collect related asset UIDs
            related_uids = set()
            for rel in relationships:
                if rel.get("from_uid") != resource_uid:
                    related_uids.add(rel.get("from_uid"))
                if rel.get("to_uid") != resource_uid:
                    related_uids.add(rel.get("to_uid"))
            
            # Load related assets
            for uid in related_uids:
                related_asset = loader.load_asset_by_uid(tenant_id, scan_run_id or "latest", uid)
                if related_asset:
                    nodes.append(related_asset)
        else:
            # Get all assets (limited)
            nodes = loader.load_assets(tenant_id, scan_run_id or "latest", limit=limit)
            relationships = loader.load_relationships(tenant_id, scan_run_id or "latest", limit=limit)
        
        return {
            "nodes": nodes,
            "edges": relationships,
            "depth": depth,
            "total_nodes": len(nodes),
            "total_edges": len(relationships)
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to load graph: {str(e)}"
        )


@app.get("/api/v1/inventory/drift")
async def get_drift(
    tenant_id: str = Query(...),
    scan_run_id: Optional[str] = Query(None),
    change_type: Optional[str] = Query(None),
    provider: Optional[str] = Query(None),
    resource_type: Optional[str] = Query(None),
    account_id: Optional[str] = Query(None)
):
    """Get drift records with filters"""
    try:
        loader = DataLoader()
        
        # Load drift records
        drift_records = loader.load_drift_records(
            tenant_id=tenant_id,
            scan_run_id=scan_run_id or "latest",
            change_type=change_type
        )
        
        # Apply additional filters
        if provider:
            drift_records = [d for d in drift_records if d.get("provider") == provider]
        if resource_type:
            drift_records = [d for d in drift_records if d.get("resource_type") == resource_type]
        if account_id:
            drift_records = [d for d in drift_records if d.get("account_id") == account_id]
        
        # Group by change type
        by_change_type = {}
        for drift in drift_records:
            change = drift.get("change_type", "unknown")
            if change not in by_change_type:
                by_change_type[change] = []
            by_change_type[change].append(drift)
        
        return {
            "drift_records": drift_records,
            "total": len(drift_records),
            "by_change_type": {k: len(v) for k, v in by_change_type.items()},
            "details": by_change_type
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to load drift: {str(e)}"
        )


@app.get("/api/v1/inventory/accounts/{account_id}")
async def get_account_summary(
    account_id: str,
    tenant_id: str = Query(...),
    scan_run_id: Optional[str] = Query(None)
):
    """Get account summary with service breakdown and regional distribution"""
    try:
        loader = DataLoader()
        
        # Load all assets for this account
        assets = loader.load_assets(tenant_id, scan_run_id or "latest")
        
        # Filter by account
        account_assets = [a for a in assets if a.get("account_id") == account_id]
        
        # Group by service
        by_service = {}
        for asset in account_assets:
            service = asset.get("resource_type", "unknown").split(".")[0]
            by_service[service] = by_service.get(service, 0) + 1
        
        # Group by region
        by_region = {}
        for asset in account_assets:
            region = asset.get("region", "unknown")
            by_region[region] = by_region.get(region, 0) + 1
        
        return {
            "account_id": account_id,
            "total_assets": len(account_assets),
            "by_service": by_service,
            "by_region": by_region,
            "provider": account_assets[0].get("provider") if account_assets else "unknown"
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to load account summary: {str(e)}"
        )


@app.get("/api/v1/inventory/services/{service}")
async def get_service_summary(
    service: str,
    tenant_id: str = Query(...),
    scan_run_id: Optional[str] = Query(None)
):
    """Get service-specific summary with configuration statistics"""
    try:
        loader = DataLoader()
        
        # Load all assets for this service
        assets = loader.load_assets(tenant_id, scan_run_id or "latest")
        
        # Filter by service (resource_type starts with service)
        service_assets = [a for a in assets if a.get("resource_type", "").startswith(f"{service}.")]
        
        # Group by account
        by_account = {}
        for asset in service_assets:
            acct = asset.get("account_id", "unknown")
            by_account[acct] = by_account.get(acct, 0) + 1
        
        # Group by region
        by_region = {}
        for asset in service_assets:
            region = asset.get("region", "unknown")
            by_region[region] = by_region.get(region, 0) + 1
        
        # Group by resource type
        by_resource_type = {}
        for asset in service_assets:
            rtype = asset.get("resource_type", "unknown")
            by_resource_type[rtype] = by_resource_type.get(rtype, 0) + 1
        
        return {
            "service": service,
            "total_assets": len(service_assets),
            "by_account": by_account,
            "by_region": by_region,
            "by_resource_type": by_resource_type
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to load service summary: {str(e)}"
        )


@app.get("/api/v1/inventory/scans")
async def list_scans(tenant_id: Optional[str] = Query(None)):
    """
    List available discovery scans.
    
    Note: tenant_id is required for database mode (USE_DATABASE=true),
    optional for local file mode.
    """
    try:
        reader = get_discovery_reader(tenant_id=tenant_id)
        
        # Both readers have compatible interfaces, but DBReader methods use instance tenant_id
        scans = reader.list_available_scans()
        latest = reader.get_latest_scan_id()
        
        return {
            "scans": scans,
            "total": len(scans),
            "latest": latest
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to list scans: {str(e)}"
        )


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)

