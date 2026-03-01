"""
Check Results API Router

REST API endpoints for viewing configScan check results.
Reads from PostgreSQL check_results table.
"""

from fastapi import APIRouter, HTTPException, Query
from typing import Optional, List
import math

from ..schemas.check_models import (
    CheckDashboard,
    ScanList,
    ScanListItem,
    ScanSummary,
    ServiceStats,
    ServiceDetail,
    FindingList,
    FindingDetail,
    ResourceFindings,
    RuleFindings,
    CheckStatus,
    SearchRequest,
    ExportRequest
)
from ..database.check_queries import CheckDatabaseQueries

# Create router
router = APIRouter(prefix="/api/v1/checks", tags=["checks"])

# Initialize database queries (will be injected with DatabaseManager)
_db_queries: Optional[CheckDatabaseQueries] = None


def init_check_router(db_manager):
    """Initialize router with database manager"""
    global _db_queries
    _db_queries = CheckDatabaseQueries(db_manager)


def get_db():
    """Get database queries instance"""
    global _db_queries
    if not _db_queries:
        # Try to initialize with new DatabaseManager
        try:
            _db_queries = CheckDatabaseQueries()
        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail=f"Database not available: {str(e)}"
            )
    return _db_queries


# ============================================================================
# Dashboard & Overview
# ============================================================================

@router.get("/dashboard", response_model=CheckDashboard)
async def get_dashboard(
    tenant_id: str = Query(..., description="Tenant identifier"),
    customer_id: Optional[str] = Query(None, description="Customer identifier"),
    limit_recent: int = Query(5, ge=1, le=20, description="Number of recent scans to include")
):
    """
    Get check scan dashboard with overall statistics.
    
    Returns:
    - Total checks across all scans
    - Pass/fail/error counts
    - Top failing services
    - Recent scans
    """
    db = get_db()
    stats = db.get_dashboard_stats(tenant_id, customer_id, limit_recent_scans=limit_recent)
    
    # Process top_failing_services
    top_services = []
    for svc in (stats.get('top_failing_services') or []):
        total = svc['total']
        passed = svc['passed']
        top_services.append(ServiceStats(
            service=svc['service'],
            total=total,
            passed=passed,
            failed=svc['failed'],
            error=svc['error'],
            pass_rate=round((passed / total * 100) if total > 0 else 0.0, 2)
        ))
    
    # Process recent_scans
    recent = []
    for scan in (stats.get('recent_scans') or []):
        total = scan['total_checks']
        passed = scan['passed']
        recent.append(ScanSummary(
            scan_id=scan['scan_id'],
            discovery_scan_id=None,  # Not available in aggregation
            customer_id=tenant_id,  # From aggregation
            tenant_id=tenant_id,
            provider="aws",  # Default
            hierarchy_id="",  # Not in aggregation
            hierarchy_type="account",
            total_checks=total,
            passed=passed,
            failed=scan['failed'],
            error=scan.get('error', 0),
            services_scanned=0,  # Not in aggregation
            scan_timestamp=scan['scan_timestamp']
        ))
    
    return CheckDashboard(
        total_checks=stats['total_checks'],
        passed=stats['passed'],
        failed=stats['failed'],
        error=stats['error'],
        pass_rate=stats['pass_rate'],
        services_scanned=stats['services_scanned'],
        accounts_scanned=stats.get('accounts_scanned', 1),
        top_failing_services=top_services,
        recent_scans=recent,
        last_scan_timestamp=recent[0].scan_timestamp if recent else None
    )


# ============================================================================
# Scan Management
# ============================================================================

@router.get("/scans", response_model=ScanList)
async def list_scans(
    tenant_id: str = Query(..., description="Tenant identifier"),
    customer_id: Optional[str] = Query(None, description="Customer identifier"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Results per page")
):
    """
    List check scans with pagination.
    
    Returns paginated list of scans with basic statistics.
    """
    db = get_db()
    scans, total = db.list_scans(tenant_id, customer_id, page, page_size)
    
    # Convert to ScanListItem
    scan_items = []
    for scan in scans:
        total_checks = scan['total_checks']
        passed = scan['passed']
        scan_items.append(ScanListItem(
            scan_id=scan['scan_id'],
            discovery_scan_id=scan.get('discovery_scan_id'),
            customer_id=scan['customer_id'],
            tenant_id=scan['tenant_id'],
            provider=scan['provider'],
            hierarchy_id=scan['hierarchy_id'],
            total_checks=total_checks,
            passed=passed,
            failed=scan['failed'],
            error=scan.get('error', 0),
            pass_rate=scan['pass_rate'],
            services_scanned=scan['services_scanned'],
            scan_timestamp=scan['scan_timestamp']
        ))
    
    return ScanList(
        scans=scan_items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=math.ceil(total / page_size) if total > 0 else 0
    )


@router.get("/scans/{scan_id}", response_model=ScanSummary)
async def get_scan(
    scan_id: str,
    tenant_id: str = Query(..., description="Tenant identifier")
):
    """
    Get summary for a specific scan.
    
    Returns scan metadata and overall statistics.
    """
    db = get_db()
    scan = db.get_scan_summary(scan_id, tenant_id)
    
    if not scan:
        raise HTTPException(
            status_code=404,
            detail=f"Scan not found: {scan_id}"
        )
    
    return ScanSummary(
        scan_id=scan['scan_id'],
        discovery_scan_id=None,  # TODO: Extract from finding_data
        customer_id=scan['customer_id'],
        tenant_id=scan['tenant_id'],
        provider=scan['provider'],
        hierarchy_id=scan['hierarchy_id'],
        hierarchy_type=scan['hierarchy_type'],
        total_checks=scan['total_checks'],
        passed=scan['passed'],
        failed=scan['failed'],
        error=scan.get('error', 0),
        services_scanned=scan['services_scanned'],
        scan_timestamp=scan['scan_timestamp']
    )


@router.get("/scans/{scan_id}/services", response_model=List[ServiceStats])
async def get_scan_services(
    scan_id: str,
    tenant_id: str = Query(..., description="Tenant identifier")
):
    """
    Get service breakdown for a scan.
    
    Returns statistics for each service scanned.
    """
    db = get_db()
    services = db.get_service_stats(scan_id, tenant_id)
    
    if not services:
        raise HTTPException(
            status_code=404,
            detail=f"No services found for scan: {scan_id}"
        )
    
    return [ServiceStats(**s) for s in services]


@router.get("/scans/{scan_id}/services/{service}", response_model=ServiceDetail)
async def get_service_detail(
    scan_id: str,
    service: str,
    tenant_id: str = Query(..., description="Tenant identifier")
):
    """
    Get detailed statistics for a specific service in a scan.
    
    Returns service stats, rule breakdown, and top failing rules.
    """
    db = get_db()
    detail = db.get_service_detail(scan_id, service, tenant_id)
    
    if not detail:
        raise HTTPException(
            status_code=404,
            detail=f"Service '{service}' not found in scan '{scan_id}'"
        )
    
    return ServiceDetail(**detail)


# ============================================================================
# Findings
# ============================================================================

@router.get("/scans/{scan_id}/findings", response_model=FindingList)
async def get_scan_findings(
    scan_id: str,
    tenant_id: str = Query(..., description="Tenant identifier"),
    customer_id: Optional[str] = Query(None),
    service: Optional[str] = Query(None, description="Filter by service"),
    status: Optional[CheckStatus] = Query(None, description="Filter by status"),
    rule_id: Optional[str] = Query(None, description="Filter by rule ID"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=1000)
):
    """
    Get findings for a scan with filtering and pagination.
    
    Supports filtering by service, status, and rule ID.
    """
    db = get_db()
    findings, total = db.get_findings(
        scan_id=scan_id,
        tenant_id=tenant_id,
        customer_id=customer_id,
        service=service,
        status=status.value if status else None,
        rule_id=rule_id,
        page=page,
        page_size=page_size
    )
    
    # Convert to FindingDetail
    finding_details = []
    for f in findings:
        finding_details.append(FindingDetail(
            id=f.get('id'),
            scan_id=f['scan_id'],
            discovery_scan_id=f.get('discovery_scan_id'),
            customer_id=f['customer_id'],
            tenant_id=f['tenant_id'],
            provider=f['provider'],
            hierarchy_id=f['hierarchy_id'],
            hierarchy_type=f['hierarchy_type'],
            rule_id=f['rule_id'],
            resource_arn=f.get('resource_arn'),
            resource_id=f.get('resource_id'),
            resource_type=f['resource_type'],
            status=CheckStatus(f['status']),
            checked_fields=f.get('checked_fields', []),
            finding_data=f.get('finding_data', {}),
            scan_timestamp=f['scan_timestamp']
        ))
    
    return FindingList(
        findings=finding_details,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=math.ceil(total / page_size) if total > 0 else 0
    )


@router.get("/findings/search", response_model=FindingList)
async def search_findings(
    query: str = Query(..., min_length=1, description="Search query (ARN, rule ID, or service)"),
    tenant_id: str = Query(..., description="Tenant identifier"),
    customer_id: Optional[str] = Query(None),
    status: Optional[CheckStatus] = Query(None, description="Filter by status"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=1000)
):
    """
    Search findings across all scans.
    
    Supports searching by:
    - Resource ARN (starts with 'arn:aws:')
    - Rule ID (contains '.')
    - Service name
    """
    db = get_db()
    
    filters = {'status': status.value} if status else {}
    
    findings, total = db.search_findings(
        query=query,
        tenant_id=tenant_id,
        customer_id=customer_id,
        filters=filters,
        page=page,
        page_size=page_size
    )
    
    # Convert to FindingDetail
    finding_details = []
    for f in findings:
        finding_details.append(FindingDetail(
            id=f.get('id'),
            scan_id=f['scan_id'],
            discovery_scan_id=f.get('discovery_scan_id'),
            customer_id=f['customer_id'],
            tenant_id=f['tenant_id'],
            provider=f['provider'],
            hierarchy_id=f['hierarchy_id'],
            hierarchy_type=f['hierarchy_type'],
            rule_id=f['rule_id'],
            resource_arn=f.get('resource_arn'),
            resource_id=f.get('resource_id'),
            resource_type=f['resource_type'],
            status=CheckStatus(f['status']),
            checked_fields=f.get('checked_fields', []),
            finding_data=f.get('finding_data', {}),
            scan_timestamp=f['scan_timestamp']
        ))
    
    return FindingList(
        findings=finding_details,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=math.ceil(total / page_size) if total > 0 else 0
    )


# ============================================================================
# Resource & Rule Drill-down
# ============================================================================

@router.get("/resources/{resource_arn:path}", response_model=ResourceFindings)
async def get_resource_findings(
    resource_arn: str,
    tenant_id: str = Query(..., description="Tenant identifier"),
    customer_id: Optional[str] = Query(None)
):
    """
    Get all findings for a specific resource ARN.
    
    Returns all check results for the resource across all scans.
    """
    db = get_db()
    resource_data = db.get_resource_findings(resource_arn, tenant_id, customer_id)
    
    if not resource_data:
        raise HTTPException(
            status_code=404,
            detail=f"No findings found for resource: {resource_arn}"
        )
    
    # Convert findings to FindingDetail
    findings = []
    for f in resource_data['findings']:
        findings.append(FindingDetail(
            id=f.get('id'),
            scan_id=f['scan_id'],
            discovery_scan_id=f.get('discovery_scan_id'),
            customer_id=f['customer_id'],
            tenant_id=f['tenant_id'],
            provider=f['provider'],
            hierarchy_id=f['hierarchy_id'],
            hierarchy_type=f['hierarchy_type'],
            rule_id=f['rule_id'],
            resource_arn=f.get('resource_arn'),
            resource_id=f.get('resource_id'),
            resource_type=f['resource_type'],
            status=CheckStatus(f['status']),
            checked_fields=f.get('checked_fields', []),
            finding_data=f.get('finding_data', {}),
            scan_timestamp=f['scan_timestamp']
        ))
    
    return ResourceFindings(
        resource_arn=resource_data['resource_arn'],
        resource_id=resource_data['resource_id'],
        resource_type=resource_data['resource_type'],
        total_findings=resource_data['total_findings'],
        passed=resource_data['passed'],
        failed=resource_data['failed'],
        findings=findings
    )


@router.get("/rules/{rule_id:path}", response_model=RuleFindings)
async def get_rule_findings(
    rule_id: str,
    tenant_id: str = Query(..., description="Tenant identifier"),
    customer_id: Optional[str] = Query(None),
    scan_id: Optional[str] = Query(None, description="Filter by specific scan")
):
    """
    Get all findings for a specific rule.
    
    Returns all check results for the rule across scans.
    """
    db = get_db()
    rule_data = db.get_rule_findings(rule_id, tenant_id, customer_id, scan_id)
    
    if not rule_data:
        raise HTTPException(
            status_code=404,
            detail=f"No findings found for rule: {rule_id}"
        )
    
    # Convert findings
    findings = []
    for f in rule_data['findings']:
        findings.append(FindingDetail(
            id=f.get('id'),
            scan_id=f['scan_id'],
            discovery_scan_id=f.get('discovery_scan_id'),
            customer_id=f['customer_id'],
            tenant_id=f['tenant_id'],
            provider=f['provider'],
            hierarchy_id=f['hierarchy_id'],
            hierarchy_type=f.get('hierarchy_type', 'account'),
            rule_id=f['rule_id'],
            resource_arn=f.get('resource_arn'),
            resource_id=f.get('resource_id'),
            resource_type=f['resource_type'],
            status=CheckStatus(f['status']),
            checked_fields=f.get('checked_fields', []),
            finding_data=f.get('finding_data', {}),
            scan_timestamp=f['scan_timestamp']
        ))
    
    return RuleFindings(
        rule_id=rule_data['rule_id'],
        service=rule_data['service'],
        total_findings=rule_data['total_findings'],
        passed=rule_data['passed'],
        failed=rule_data['failed'],
        error=rule_data.get('error', 0),
        findings=findings,
        resources_affected=rule_data.get('resources_affected', [])
    )


# ============================================================================
# Statistics
# ============================================================================

@router.get("/stats")
async def get_statistics(
    tenant_id: str = Query(..., description="Tenant identifier"),
    customer_id: Optional[str] = Query(None),
    scan_id: Optional[str] = Query(None, description="Filter by specific scan"),
    group_by: str = Query("service", description="Group by: service, status, rule")
):
    """
    Get aggregated statistics.
    
    Supports grouping by service, status, or rule.
    """
    db = get_db()
    
    if group_by == "service":
        if scan_id:
            services = db.get_service_stats(scan_id, tenant_id)
            return {"group_by": "service", "data": services}
        else:
            # Get services across all scans
            findings, _ = db.get_findings(
                tenant_id=tenant_id,
                customer_id=customer_id,
                page=1,
                page_size=100000  # Get all for aggregation
            )
            
            # Aggregate by service
            from collections import defaultdict
            service_stats = defaultdict(lambda: {'total': 0, 'passed': 0, 'failed': 0, 'error': 0})
            
            for f in findings:
                svc = f['resource_type']
                service_stats[svc]['total'] += 1
                if f['status'] == 'PASS':
                    service_stats[svc]['passed'] += 1
                elif f['status'] == 'FAIL':
                    service_stats[svc]['failed'] += 1
                else:
                    service_stats[svc]['error'] += 1
            
            result = []
            for svc, stats in service_stats.items():
                total = stats['total']
                result.append({
                    'service': svc,
                    **stats,
                    'pass_rate': round((stats['passed'] / total * 100) if total > 0 else 0.0, 2)
                })
            
            return {"group_by": "service", "data": result}
    
    elif group_by == "status":
        findings, _ = db.get_findings(
            scan_id=scan_id,
            tenant_id=tenant_id,
            customer_id=customer_id,
            page=1,
            page_size=100000
        )
        
        status_stats = {
            'PASS': 0,
            'FAIL': 0,
            'ERROR': 0
        }
        
        for f in findings:
            status_stats[f['status']] = status_stats.get(f['status'], 0) + 1
        
        return {"group_by": "status", "data": status_stats}
    
    else:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid group_by parameter: {group_by}. Use 'service' or 'status'"
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
    Export scan results in various formats.
    
    Supports JSON and CSV export with optional service filtering.
    """
    db = get_db()
    
    # Get all findings for the scan
    findings, total = db.get_findings(
        scan_id=scan_id,
        tenant_id=tenant_id,
        customer_id=customer_id,
        service=service,
        page=1,
        page_size=100000  # Get all
    )
    
    if not findings:
        raise HTTPException(
            status_code=404,
            detail=f"No findings found for scan: {scan_id}"
        )
    
    if format == "json":
        return {
            "scan_id": scan_id,
            "total_findings": total,
            "findings": findings
        }
    
    elif format == "csv":
        import io
        import csv
        from fastapi.responses import StreamingResponse
        
        # Create CSV
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=[
            'scan_id', 'rule_id', 'resource_arn', 'resource_id', 'resource_type',
            'status', 'checked_fields', 'scan_timestamp'
        ])
        writer.writeheader()
        
        for f in findings:
            writer.writerow({
                'scan_id': f['scan_id'],
                'rule_id': f['rule_id'],
                'resource_arn': f.get('resource_arn', ''),
                'resource_id': f.get('resource_id', ''),
                'resource_type': f['resource_type'],
                'status': f['status'],
                'checked_fields': ','.join(f.get('checked_fields', [])),
                'scan_timestamp': f['scan_timestamp']
            })
        
        output.seek(0)
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=check_scan_{scan_id}.csv"}
        )
    
    else:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported format: {format}. Use 'json' or 'csv'"
        )
