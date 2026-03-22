"""
Discovery Results API Router

REST API endpoints for viewing configScan discovery results.
Reads from PostgreSQL discoveries table or NDJSON files.
"""

from fastapi import APIRouter, HTTPException, Query
from typing import Optional, List
import math

from ..schemas.discovery_models import (
    DiscoveryDashboard,
    DiscoveryScanList,
    DiscoveryScanListItem,
    DiscoveryScanSummary,
    ServiceDiscoveryStats,
    ServiceDiscoveryDetail,
    DiscoveryList,
    DiscoveryDetail,
    ResourceDiscoveries,
    DiscoveryFunctionDetail
)
from ..database.discovery_queries import DiscoveryDatabaseQueries

# Create router
router = APIRouter(prefix="/api/v1/discoveries", tags=["discoveries"])

# Initialize database queries (will be injected with DatabaseManager)
_db_queries: Optional[DiscoveryDatabaseQueries] = None


def init_discovery_router(db_manager):
    """Initialize router with database manager"""
    global _db_queries
    _db_queries = DiscoveryDatabaseQueries(db_manager)


def get_db():
    """Get database queries instance"""
    global _db_queries
    if not _db_queries:
        # Try to initialize with new DatabaseManager
        try:
            _db_queries = DiscoveryDatabaseQueries()
        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail=f"Database not available: {str(e)}"
            )
    return _db_queries


# ============================================================================
# Dashboard & Overview
# ============================================================================

@router.get("/dashboard", response_model=DiscoveryDashboard)
async def get_dashboard(
    tenant_id: str = Query(..., description="Tenant identifier"),
    customer_id: Optional[str] = Query(None, description="Customer identifier"),
    limit_recent: int = Query(5, ge=1, le=20, description="Number of recent scans to include")
):
    """
    Get discovery scan dashboard with overall statistics.
    
    Returns:
    - Total discoveries across all scans
    - Unique resources discovered
    - Top services by discovery count
    - Recent scans
    """
    db = get_db()
    stats = db.get_dashboard_stats(tenant_id, customer_id, limit_recent_scans=limit_recent)
    
    # Process top_services
    top_services = []
    for svc in (stats.get('top_services') or []):
        top_services.append(ServiceDiscoveryStats(
            service=svc['service'],
            total_discoveries=svc.get('total_discoveries', svc.get('total', 0)),
            unique_resources=svc.get('unique_resources', 0),
            regions=svc.get('regions', []),
            discovery_functions=svc.get('discovery_functions', [])
        ))
    
    # Process recent_scans
    recent = []
    for scan in (stats.get('recent_scans') or []):
        recent.append(DiscoveryScanSummary(
            scan_id=scan['scan_id'],
            customer_id=tenant_id,  # From aggregation
            tenant_id=tenant_id,
            provider="aws",  # Default
            account_id="",  # Not in aggregation
            hierarchy_type="account",
            total_discoveries=scan.get('total_discoveries', 0),
            unique_resources=scan.get('unique_resources', 0),
            services_scanned=0,  # Not in aggregation
            regions_scanned=0,  # Not in aggregation
            first_seen_at=scan.get('first_seen_at')
        ))
    
    return DiscoveryDashboard(
        total_discoveries=stats['total_discoveries'],
        unique_resources=stats.get('unique_resources', 0),
        services_scanned=stats['services_scanned'],
        accounts_scanned=stats.get('accounts_scanned', 1),
        top_services=top_services,
        recent_scans=recent,
        last_first_seen_at=recent[0].first_seen_at if recent else None
    )


# ============================================================================
# Scan Management
# ============================================================================

@router.get("/scans", response_model=DiscoveryScanList)
async def list_scans(
    tenant_id: str = Query(..., description="Tenant identifier"),
    customer_id: Optional[str] = Query(None, description="Customer identifier"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Results per page")
):
    """
    List discovery scans with pagination.
    
    Returns paginated list of scans with basic statistics.
    """
    db = get_db()
    scans, total = db.list_scans(tenant_id, customer_id, page, page_size)
    
    # Convert to DiscoveryScanListItem
    scan_items = []
    for scan in scans:
        scan_items.append(DiscoveryScanListItem(
            scan_id=scan['scan_id'],
            customer_id=scan['customer_id'],
            tenant_id=scan['tenant_id'],
            provider=scan['provider'],
            account_id=scan['account_id'],
            total_discoveries=scan['total_discoveries'],
            unique_resources=scan.get('unique_resources', 0),
            services_scanned=scan.get('services_scanned', 0),
            regions_scanned=scan.get('regions_scanned', 0),
            first_seen_at=scan['first_seen_at']
        ))
    
    return DiscoveryScanList(
        scans=scan_items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=math.ceil(total / page_size) if total > 0 else 0
    )


@router.get("/scans/{scan_id}", response_model=DiscoveryScanSummary)
async def get_scan(
    scan_id: str,
    tenant_id: str = Query(..., description="Tenant identifier")
):
    """
    Get summary for a specific discovery scan.
    
    Returns scan metadata and overall statistics.
    """
    db = get_db()
    scan = db.get_scan_summary(scan_id, tenant_id)
    
    if not scan:
        raise HTTPException(
            status_code=404,
            detail=f"Scan not found: {scan_id}"
        )
    
    return DiscoveryScanSummary(
        scan_id=scan['scan_id'],
        customer_id=scan['customer_id'],
        tenant_id=scan['tenant_id'],
        provider=scan['provider'],
        account_id=scan['account_id'],
        hierarchy_type=scan['hierarchy_type'],
        total_discoveries=scan['total_discoveries'],
        unique_resources=scan.get('unique_resources', 0),
        services_scanned=scan.get('services_scanned', 0),
        regions_scanned=scan.get('regions_scanned', 0),
        first_seen_at=scan['first_seen_at']
    )


@router.get("/scans/{scan_id}/services", response_model=List[ServiceDiscoveryStats])
async def get_scan_services(
    scan_id: str,
    tenant_id: str = Query(..., description="Tenant identifier")
):
    """
    Get service breakdown for a discovery scan.
    
    Returns statistics for each service scanned.
    """
    db = get_db()
    services = db.get_service_stats(scan_id, tenant_id)
    
    if not services:
        raise HTTPException(
            status_code=404,
            detail=f"No services found for scan: {scan_id}"
        )
    
    return [ServiceDiscoveryStats(**s) for s in services]


@router.get("/scans/{scan_id}/services/{service}", response_model=ServiceDiscoveryDetail)
async def get_service_detail(
    scan_id: str,
    service: str,
    tenant_id: str = Query(..., description="Tenant identifier")
):
    """
    Get detailed statistics for a specific service in a discovery scan.
    
    Returns service stats, discovery function breakdown, and top resources.
    """
    db = get_db()
    detail = db.get_service_detail(scan_id, service, tenant_id)
    
    if not detail:
        raise HTTPException(
            status_code=404,
            detail=f"Service '{service}' not found in scan '{scan_id}'"
        )
    
    return ServiceDiscoveryDetail(**detail)


# ============================================================================
# Discoveries
# ============================================================================

@router.get("/scans/{scan_id}/discoveries", response_model=DiscoveryList)
async def get_scan_discoveries(
    scan_id: str,
    tenant_id: str = Query(..., description="Tenant identifier"),
    customer_id: Optional[str] = Query(None),
    service: Optional[str] = Query(None, description="Filter by service"),
    discovery_id: Optional[str] = Query(None, description="Filter by discovery function"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=1000)
):
    """
    Get discoveries for a scan with filtering and pagination.
    
    Supports filtering by service and discovery function.
    """
    db = get_db()
    discoveries, total = db.get_discoveries(
        scan_id=scan_id,
        tenant_id=tenant_id,
        customer_id=customer_id,
        service=service,
        discovery_id=discovery_id,
        page=page,
        page_size=page_size
    )
    
    # Convert to DiscoveryDetail
    discovery_details = []
    for d in discoveries:
        discovery_details.append(DiscoveryDetail(
            id=d.get('id'),
            scan_id=d['scan_id'],
            customer_id=d['customer_id'],
            tenant_id=d['tenant_id'],
            provider=d['provider'],
            account_id=d['account_id'],
            hierarchy_type=d['hierarchy_type'],
            discovery_id=d['discovery_id'],
            region=d.get('region'),
            service=d['service'],
            resource_arn=d.get('resource_arn'),
            resource_id=d.get('resource_id'),
            raw_response=d.get('raw_response', {}),
            emitted_fields=d.get('emitted_fields', {}),
            config_hash=d.get('config_hash'),
            first_seen_at=d['first_seen_at'],
            version=d.get('version', 1)
        ))
    
    return DiscoveryList(
        discoveries=discovery_details,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=math.ceil(total / page_size) if total > 0 else 0
    )


@router.get("/discoveries/search", response_model=DiscoveryList)
async def search_discoveries(
    query: str = Query(..., min_length=1, description="Search query (ARN, discovery ID, or service)"),
    tenant_id: str = Query(..., description="Tenant identifier"),
    customer_id: Optional[str] = Query(None),
    scan_id: Optional[str] = Query(None, description="Filter by specific scan"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=1000)
):
    """
    Search discoveries across all scans.
    
    Supports searching by:
    - Resource ARN (starts with 'arn:aws:')
    - Discovery ID (contains '.')
    - Service name
    """
    db = get_db()
    
    # Determine search type
    if query.startswith('arn:aws:'):
        # ARN search
        discoveries, total = db.get_discoveries(
            scan_id=scan_id,
            tenant_id=tenant_id,
            customer_id=customer_id,
            resource_arn=query,
            page=page,
            page_size=page_size
        )
    elif '.' in query and query.startswith('aws.'):
        # Discovery ID search
        discoveries, total = db.get_discoveries(
            scan_id=scan_id,
            tenant_id=tenant_id,
            customer_id=customer_id,
            discovery_id=query,
            page=page,
            page_size=page_size
        )
    else:
        # Service search
        discoveries, total = db.get_discoveries(
            scan_id=scan_id,
            tenant_id=tenant_id,
            customer_id=customer_id,
            service=query,
            page=page,
            page_size=page_size
        )
    
    # Convert to DiscoveryDetail
    discovery_details = []
    for d in discoveries:
        discovery_details.append(DiscoveryDetail(
            id=d.get('id'),
            scan_id=d['scan_id'],
            customer_id=d['customer_id'],
            tenant_id=d['tenant_id'],
            provider=d['provider'],
            account_id=d['account_id'],
            hierarchy_type=d['hierarchy_type'],
            discovery_id=d['discovery_id'],
            region=d.get('region'),
            service=d['service'],
            resource_arn=d.get('resource_arn'),
            resource_id=d.get('resource_id'),
            raw_response=d.get('raw_response', {}),
            emitted_fields=d.get('emitted_fields', {}),
            config_hash=d.get('config_hash'),
            first_seen_at=d['first_seen_at'],
            version=d.get('version', 1)
        ))
    
    return DiscoveryList(
        discoveries=discovery_details,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=math.ceil(total / page_size) if total > 0 else 0
    )


# ============================================================================
# Resource & Discovery Function Drill-down
# ============================================================================

@router.get("/resources/{resource_arn:path}", response_model=ResourceDiscoveries)
async def get_resource_discoveries(
    resource_arn: str,
    tenant_id: str = Query(..., description="Tenant identifier"),
    customer_id: Optional[str] = Query(None)
):
    """
    Get all discoveries for a specific resource ARN.
    
    Returns all discovery records for the resource across all scans.
    """
    db = get_db()
    resource_data = db.get_resource_discoveries(resource_arn, tenant_id, customer_id)
    
    if not resource_data:
        raise HTTPException(
            status_code=404,
            detail=f"No discoveries found for resource: {resource_arn}"
        )
    
    # Convert discoveries to DiscoveryDetail
    discoveries = []
    for d in resource_data['discoveries']:
        discoveries.append(DiscoveryDetail(
            id=d.get('id'),
            scan_id=d['scan_id'],
            customer_id=d['customer_id'],
            tenant_id=d['tenant_id'],
            provider=d['provider'],
            account_id=d['account_id'],
            hierarchy_type=d['hierarchy_type'],
            discovery_id=d['discovery_id'],
            region=d.get('region'),
            service=d['service'],
            resource_arn=d.get('resource_arn'),
            resource_id=d.get('resource_id'),
            raw_response=d.get('raw_response', {}),
            emitted_fields=d.get('emitted_fields', {}),
            config_hash=d.get('config_hash'),
            first_seen_at=d['first_seen_at'],
            version=d.get('version', 1)
        ))
    
    return ResourceDiscoveries(
        resource_arn=resource_data['resource_arn'],
        resource_id=resource_data['resource_id'],
        resource_type=resource_data['resource_type'],
        total_discoveries=resource_data['total_discoveries'],
        discovery_functions=resource_data.get('discovery_functions', []),
        discoveries=discoveries
    )


@router.get("/functions/{discovery_id:path}", response_model=DiscoveryFunctionDetail)
async def get_discovery_function_detail(
    discovery_id: str,
    tenant_id: str = Query(..., description="Tenant identifier"),
    customer_id: Optional[str] = Query(None),
    scan_id: Optional[str] = Query(None, description="Filter by specific scan")
):
    """
    Get all discoveries for a specific discovery function.
    
    Returns all discovery records for the function across scans.
    """
    db = get_db()
    function_data = db.get_discovery_function_detail(discovery_id, tenant_id, customer_id, scan_id)
    
    if not function_data:
        raise HTTPException(
            status_code=404,
            detail=f"No discoveries found for function: {discovery_id}"
        )
    
    # Convert discoveries
    discoveries = []
    for d in function_data['discoveries']:
        discoveries.append(DiscoveryDetail(
            id=d.get('id'),
            scan_id=d['scan_id'],
            customer_id=d['customer_id'],
            tenant_id=d['tenant_id'],
            provider=d['provider'],
            account_id=d['account_id'],
            hierarchy_type=d.get('hierarchy_type', 'account'),
            discovery_id=d['discovery_id'],
            region=d.get('region'),
            service=d['service'],
            resource_arn=d.get('resource_arn'),
            resource_id=d.get('resource_id'),
            raw_response=d.get('raw_response', {}),
            emitted_fields=d.get('emitted_fields', {}),
            config_hash=d.get('config_hash'),
            first_seen_at=d['first_seen_at'],
            version=d.get('version', 1)
        ))
    
    return DiscoveryFunctionDetail(
        discovery_id=function_data['discovery_id'],
        total_discoveries=function_data['total_discoveries'],
        service=function_data['service'],
        resources_discovered=function_data.get('resources_discovered', []),
        discoveries=discoveries
    )


# ============================================================================
# Export
# ============================================================================

@router.get("/scans/{scan_id}/export")
async def export_scan(
    scan_id: str,
    tenant_id: str = Query(..., description="Tenant identifier"),
    customer_id: Optional[str] = Query(None),
    format: str = Query("json", description="Export format: json or csv"),
    service: Optional[str] = Query(None, description="Filter by service")
):
    """
    Export discovery scan results in various formats.
    
    Supports JSON and CSV export with optional service filtering.
    """
    db = get_db()
    
    # Get all discoveries for the scan
    discoveries, total = db.get_discoveries(
        scan_id=scan_id,
        tenant_id=tenant_id,
        customer_id=customer_id,
        service=service,
        page=1,
        page_size=100000  # Get all
    )
    
    if not discoveries:
        raise HTTPException(
            status_code=404,
            detail=f"No discoveries found for scan: {scan_id}"
        )
    
    if format == "json":
        return {
            "scan_id": scan_id,
            "total_discoveries": total,
            "discoveries": discoveries
        }
    
    elif format == "csv":
        import io
        import csv
        from fastapi.responses import StreamingResponse
        
        # Create CSV
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=[
            'scan_id', 'discovery_id', 'service', 'region', 'resource_arn', 'resource_id',
            'first_seen_at'
        ])
        writer.writeheader()
        
        for d in discoveries:
            writer.writerow({
                'scan_id': d['scan_id'],
                'discovery_id': d['discovery_id'],
                'service': d['service'],
                'region': d.get('region', ''),
                'resource_arn': d.get('resource_arn', ''),
                'resource_id': d.get('resource_id', ''),
                'first_seen_at': d['first_seen_at']
            })
        
        output.seek(0)
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=discovery_scan_{scan_id}.csv"}
        )
    
    else:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported format: {format}. Use 'json' or 'csv'"
        )
