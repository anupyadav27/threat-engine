"""
Threat Engine API Server

FastAPI server for threat detection and reporting.
"""

import os
import json
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException, Query, Body
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from datetime import datetime

from .schemas.threat_report_schema import (
    ThreatReport,
    Tenant,
    ScanContext,
    Cloud,
    TriggerType
)
from .schemas.misconfig_normalizer import (
    normalize_ndjson_to_findings,
    load_ndjson_from_file,
    load_ndjson_from_s3
)
from .detector.threat_detector import ThreatDetector
from .reporter.threat_reporter import ThreatReporter
from .storage.threat_storage import ThreatStorage
from .schemas.threat_report_schema import ThreatStatus, ThreatType, Severity

app = FastAPI(
    title="Threat Engine API",
    description="Cloud Security Threat Detection and Reporting",
    version="1.0.0"
)

# Initialize storage
storage = ThreatStorage()

# Include check results router
try:
    from .api.check_router import router as check_router, init_check_router
    
    # Try to initialize with DatabaseManager
    try:
        import sys
        from pathlib import Path
        CONFIGSCAN_PATH = Path(__file__).parent.parent.parent.parent / "configScan_engines" / "aws-configScan-engine"
        sys.path.insert(0, str(CONFIGSCAN_PATH))
        from engine.database_manager import DatabaseManager
        
        db_manager = DatabaseManager()
        init_check_router(db_manager)
    except:
        pass  # Router will initialize on first request
    
    app.include_router(check_router)
except ImportError as e:
    print(f"Warning: Check router not available: {e}")

# Include discovery results router
try:
    from .api.discovery_router import router as discovery_router, init_discovery_router
    
    # Try to initialize with DatabaseManager
    try:
        import sys
        from pathlib import Path
        CONFIGSCAN_PATH = Path(__file__).parent.parent.parent.parent / "configScan_engines" / "aws-configScan-engine"
        if str(CONFIGSCAN_PATH) not in sys.path:
            sys.path.insert(0, str(CONFIGSCAN_PATH))
        from engine.database_manager import DatabaseManager
        
        if 'db_manager' not in locals():
            db_manager = DatabaseManager()
        init_discovery_router(db_manager)
    except:
        pass  # Router will initialize on first request
    
    app.include_router(discovery_router)
except ImportError as e:
    print(f"Warning: Discovery router not available: {e}")


class ThreatReportRequest(BaseModel):
    """Request model for threat report generation"""
    tenant_id: str
    tenant_name: Optional[str] = None
    scan_run_id: str
    cloud: Cloud
    trigger_type: TriggerType = TriggerType.MANUAL
    accounts: List[str] = []
    regions: List[str] = []
    services: List[str] = []
    started_at: str
    completed_at: Optional[str] = None
    engine_version: Optional[str] = None
    scan_context: Optional[Dict[str, Any]] = None


def get_csp_s3_path(csp: str) -> str:
    """Map CSP to S3 output path"""
    csp_mapping = {
        "aws": "aws-configScan-engine",
        "azure": "azure-configScan-engine",
        "gcp": "gcp-configScan-engine",
        "alicloud": "alicloud-configScan-engine",
        "oci": "oci-configScan-engine",
        "ibm": "ibm-configScan-engine",
        "k8s": "k8s-configScan-engine"
    }
    return csp_mapping.get(csp.lower(), f"{csp}-configScan-engine")


def load_scan_results_from_s3(scan_run_id: str, csp: str) -> List[str]:
    """Load scan results from S3"""
    import boto3
    
    bucket = "cspm-lgtech"
    s3_path = get_csp_s3_path(csp)
    key = f"{s3_path}/output/{scan_run_id}/results.ndjson"
    
    try:
        s3_client = boto3.client('s3')
        response = s3_client.get_object(Bucket=bucket, Key=key)
        content = response['Body'].read().decode('utf-8')
        return [line.strip() for line in content.split('\n') if line.strip()]
    except Exception as e:
        raise HTTPException(
            status_code=404,
            detail=f"Failed to load scan results from S3: {str(e)}"
        )


def load_scan_results_from_local(scan_run_id: str, csp: str) -> List[str]:
    """Load scan results from local filesystem"""
    base_path = os.getenv("SCAN_RESULTS_DIR", "/Users/apple/Desktop/threat-engine/engines-output")
    csp_path = get_csp_s3_path(csp)
    file_path = os.path.join(base_path, csp_path, "output", scan_run_id, "results.ndjson")
    
    if not os.path.exists(file_path):
        raise HTTPException(
            status_code=404,
            detail=f"Scan results not found at {file_path}"
        )
    
    return load_ndjson_from_file(file_path)


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "threat-engine",
        "version": "1.0.0",
        "status": "running"
    }


@app.get("/health")
async def health():
    """Health check endpoint"""
    return {"status": "healthy"}


@app.post("/api/v1/threat/generate")
async def generate_threat_report(request: ThreatReportRequest):
    """
    Generate threat report from scan results.
    
    Supports both S3 and local file sources.
    """
    try:
        # Load scan results
        use_s3 = os.getenv("USE_S3", "false").lower() == "true"
        
        if use_s3:
            ndjson_lines = load_scan_results_from_s3(request.scan_run_id, request.cloud.value)
        else:
            ndjson_lines = load_scan_results_from_local(request.scan_run_id, request.cloud.value)
        
        if not ndjson_lines:
            raise HTTPException(
                status_code=404,
                detail="No scan results found"
            )
        
        # Normalize misconfig findings
        findings = normalize_ndjson_to_findings(ndjson_lines, request.cloud)
        
        if not findings:
            # Return empty report if no findings
            tenant = Tenant(tenant_id=request.tenant_id, tenant_name=request.tenant_name)
            scan_context = ScanContext(
                scan_run_id=request.scan_run_id,
                trigger_type=request.trigger_type,
                cloud=request.cloud,
                accounts=request.accounts,
                regions=request.regions,
                services=request.services,
                started_at=request.started_at,
                completed_at=request.completed_at,
                engine_version=request.engine_version
            )
            
            from .reporter.threat_reporter import ThreatReporter
            reporter = ThreatReporter()
            report = reporter.generate_report(
                tenant=tenant,
                scan_context=scan_context,
                threats=[],
                misconfig_findings=[]
            )
            
            return report.dict()
        
        # Detect threats
        detector = ThreatDetector()
        threats = detector.detect_threats(findings)
        
        # Generate report
        tenant = Tenant(tenant_id=request.tenant_id, tenant_name=request.tenant_name)
        scan_context = ScanContext(
            scan_run_id=request.scan_run_id,
            trigger_type=request.trigger_type,
            cloud=request.cloud,
            accounts=request.accounts,
            regions=request.regions,
            services=request.services,
            started_at=request.started_at,
            completed_at=request.completed_at,
            engine_version=request.engine_version
        )
        
        reporter = ThreatReporter()
        report = reporter.generate_report(
            tenant=tenant,
            scan_context=scan_context,
            threats=threats,
            misconfig_findings=findings
        )
        
        # Save report to storage
        storage.save_report(report)
        
        return report.dict()
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate threat report: {str(e)}"
        )


@app.post("/api/v1/threat/generate/from-ndjson")
async def generate_threat_report_from_ndjson(
    tenant_id: str = Body(...),
    tenant_name: Optional[str] = Body(None),
    scan_run_id: str = Body(...),
    cloud: Cloud = Body(...),
    trigger_type: TriggerType = Body(TriggerType.MANUAL),
    accounts: List[str] = Body([]),
    regions: List[str] = Body([]),
    services: List[str] = Body([]),
    started_at: str = Body(...),
    completed_at: Optional[str] = Body(None),
    engine_version: Optional[str] = Body(None),
    ndjson_content: str = Body(..., description="NDJSON content as string")
):
    """
    Generate threat report directly from NDJSON content.
    Useful for testing or when results are already in memory.
    """
    try:
        # Parse NDJSON content
        ndjson_lines = [line.strip() for line in ndjson_content.split('\n') if line.strip()]
        
        if not ndjson_lines:
            raise HTTPException(status_code=400, detail="No NDJSON content provided")
        
        # Normalize misconfig findings
        findings = normalize_ndjson_to_findings(ndjson_lines, cloud)
        
        # Detect threats
        detector = ThreatDetector()
        threats = detector.detect_threats(findings)
        
        # Generate report
        tenant = Tenant(tenant_id=tenant_id, tenant_name=tenant_name)
        scan_context = ScanContext(
            scan_run_id=scan_run_id,
            trigger_type=trigger_type,
            cloud=cloud,
            accounts=accounts,
            regions=regions,
            services=services,
            started_at=started_at,
            completed_at=completed_at,
            engine_version=engine_version
        )
        
        reporter = ThreatReporter()
        report = reporter.generate_report(
            tenant=tenant,
            scan_context=scan_context,
            threats=threats,
            misconfig_findings=findings
        )
        
        # Save report to storage
        storage.save_report(report)
        
        return report.dict()
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate threat report: {str(e)}"
        )


# ============================================================================
# GET Endpoints - Retrieve Threat Reports
# ============================================================================

@app.get("/api/v1/threat/reports/{scan_run_id}")
async def get_threat_report(
    scan_run_id: str,
    tenant_id: str = Query(..., description="Tenant identifier")
):
    """Get existing threat report by scan_run_id"""
    report = storage.get_report(scan_run_id, tenant_id)
    if not report:
        raise HTTPException(
            status_code=404,
            detail=f"Threat report not found for scan_run_id: {scan_run_id}"
        )
    return report


@app.get("/api/v1/threat/summary")
async def get_threat_summary(
    scan_run_id: str = Query(..., description="Scan run identifier"),
    tenant_id: str = Query(..., description="Tenant identifier")
):
    """Get threat summary only (lightweight)"""
    summary = storage.get_summary(scan_run_id, tenant_id)
    if not summary:
        raise HTTPException(
            status_code=404,
            detail=f"Threat report not found for scan_run_id: {scan_run_id}"
        )
    return summary


@app.get("/api/v1/threat/list")
async def list_threats(
    scan_run_id: str = Query(..., description="Scan run identifier"),
    tenant_id: str = Query(..., description="Tenant identifier"),
    severity: Optional[Severity] = Query(None, description="Filter by severity"),
    threat_type: Optional[ThreatType] = Query(None, description="Filter by threat type"),
    status: Optional[ThreatStatus] = Query(None, description="Filter by status"),
    account: Optional[str] = Query(None, description="Filter by account"),
    region: Optional[str] = Query(None, description="Filter by region"),
    confidence: Optional[str] = Query(None, description="Filter by confidence (high/medium/low)")
):
    """Get filtered list of threats"""
    report = storage.get_report(scan_run_id, tenant_id)
    if not report:
        raise HTTPException(
            status_code=404,
            detail=f"Threat report not found for scan_run_id: {scan_run_id}"
        )
    
    threats = report.get("threats", [])
    
    # Apply filters
    if severity:
        threats = [t for t in threats if t.get("severity") == severity.value]
    if threat_type:
        threats = [t for t in threats if t.get("threat_type") == threat_type.value]
    if status:
        threats = [t for t in threats if t.get("status") == status.value]
    if confidence:
        threats = [t for t in threats if t.get("confidence") == confidence.lower()]
    if account:
        threats = [
            t for t in threats
            if any(a.get("account") == account for a in t.get("affected_assets", []))
        ]
    if region:
        threats = [
            t for t in threats
            if any(a.get("region") == region for a in t.get("affected_assets", []))
        ]
    
    return {
        "scan_run_id": scan_run_id,
        "total": len(threats),
        "threats": threats
    }


@app.get("/api/v1/threat/{threat_id}")
async def get_threat(
    threat_id: str,
    tenant_id: str = Query(..., description="Tenant identifier")
):
    """Get single threat by ID with full details"""
    threat_data = storage.get_threat(threat_id, tenant_id)
    if not threat_data:
        raise HTTPException(
            status_code=404,
            detail=f"Threat not found: {threat_id}"
        )
    return threat_data


@app.get("/api/v1/threat/{threat_id}/misconfig-findings")
async def get_threat_misconfig_findings(
    threat_id: str,
    tenant_id: str = Query(..., description="Tenant identifier")
):
    """Get root cause misconfig findings for a threat"""
    threat_data = storage.get_threat(threat_id, tenant_id)
    if not threat_data:
        raise HTTPException(
            status_code=404,
            detail=f"Threat not found: {threat_id}"
        )
    return {
        "threat_id": threat_id,
        "misconfig_findings": threat_data.get("misconfig_findings", [])
    }


@app.get("/api/v1/threat/{threat_id}/assets")
async def get_threat_assets(
    threat_id: str,
    tenant_id: str = Query(..., description="Tenant identifier")
):
    """Get affected assets for a threat"""
    threat_data = storage.get_threat(threat_id, tenant_id)
    if not threat_data:
        raise HTTPException(
            status_code=404,
            detail=f"Threat not found: {threat_id}"
        )
    threat = threat_data.get("threat", {})
    return {
        "threat_id": threat_id,
        "affected_assets": threat.get("affected_assets", [])
    }


# ============================================================================
# PATCH Endpoints - Update Threat Status
# ============================================================================

class ThreatUpdateRequest(BaseModel):
    """Request model for updating threat"""
    status: Optional[ThreatStatus] = None
    notes: Optional[str] = None
    assignee: Optional[str] = None


@app.patch("/api/v1/threat/{threat_id}")
async def update_threat(
    threat_id: str,
    update: ThreatUpdateRequest,
    tenant_id: str = Query(..., description="Tenant identifier")
):
    """Update threat status, notes, or assignee"""
    if not update.status and not update.notes and not update.assignee:
        raise HTTPException(
            status_code=400,
            detail="At least one field (status, notes, assignee) must be provided"
        )
    
    threat_data = storage.get_threat(threat_id, tenant_id)
    if not threat_data:
        raise HTTPException(
            status_code=404,
            detail=f"Threat not found: {threat_id}"
        )
    
    # Update status if provided
    if update.status:
        success = storage.update_threat_status(threat_id, update.status, update.notes)
        if not success:
            raise HTTPException(
                status_code=500,
                detail="Failed to update threat status"
            )
    
    # Get updated threat
    updated_threat = storage.get_threat(threat_id, tenant_id)
    return updated_threat


# ============================================================================
# Threat Map Endpoints
# ============================================================================

@app.get("/api/v1/threat/map/geographic")
async def get_threat_map_geographic(
    scan_run_id: str = Query(..., description="Scan run identifier"),
    tenant_id: str = Query(..., description="Tenant identifier")
):
    """Get threats grouped by region (geographic view)"""
    report = storage.get_report(scan_run_id, tenant_id)
    if not report:
        raise HTTPException(
            status_code=404,
            detail=f"Threat report not found for scan_run_id: {scan_run_id}"
        )
    
    threats_by_region = {}
    for threat in report.get("threats", []):
        for asset in threat.get("affected_assets", []):
            region = asset.get("region", "unknown")
            if region not in threats_by_region:
                threats_by_region[region] = {
                    "region": region,
                    "threats": [],
                    "count": 0,
                    "by_severity": {}
                }
            threats_by_region[region]["threats"].append(threat)
            threats_by_region[region]["count"] += 1
            severity = threat.get("severity", "unknown")
            threats_by_region[region]["by_severity"][severity] = \
                threats_by_region[region]["by_severity"].get(severity, 0) + 1
    
    # Deduplicate threats per region
    for region_data in threats_by_region.values():
        seen = set()
        unique_threats = []
        for threat in region_data["threats"]:
            threat_id = threat.get("threat_id")
            if threat_id not in seen:
                seen.add(threat_id)
                unique_threats.append(threat)
        region_data["threats"] = unique_threats
        region_data["count"] = len(unique_threats)
    
    return {
        "scan_run_id": scan_run_id,
        "regions": list(threats_by_region.values())
    }


@app.get("/api/v1/threat/map/account")
async def get_threat_map_account(
    scan_run_id: str = Query(..., description="Scan run identifier"),
    tenant_id: str = Query(..., description="Tenant identifier")
):
    """Get threats grouped by account"""
    report = storage.get_report(scan_run_id, tenant_id)
    if not report:
        raise HTTPException(
            status_code=404,
            detail=f"Threat report not found for scan_run_id: {scan_run_id}"
        )
    
    threats_by_account = {}
    for threat in report.get("threats", []):
        for asset in threat.get("affected_assets", []):
            account = asset.get("account", "unknown")
            if account not in threats_by_account:
                threats_by_account[account] = {
                    "account": account,
                    "threats": [],
                    "count": 0,
                    "by_severity": {},
                    "by_type": {}
                }
            threats_by_account[account]["threats"].append(threat)
            threats_by_account[account]["count"] += 1
            severity = threat.get("severity", "unknown")
            threat_type = threat.get("threat_type", "unknown")
            threats_by_account[account]["by_severity"][severity] = \
                threats_by_account[account]["by_severity"].get(severity, 0) + 1
            threats_by_account[account]["by_type"][threat_type] = \
                threats_by_account[account]["by_type"].get(threat_type, 0) + 1
    
    # Deduplicate threats per account
    for account_data in threats_by_account.values():
        seen = set()
        unique_threats = []
        for threat in account_data["threats"]:
            threat_id = threat.get("threat_id")
            if threat_id not in seen:
                seen.add(threat_id)
                unique_threats.append(threat)
        account_data["threats"] = unique_threats
        account_data["count"] = len(unique_threats)
    
    return {
        "scan_run_id": scan_run_id,
        "accounts": list(threats_by_account.values())
    }


@app.get("/api/v1/threat/map/service")
async def get_threat_map_service(
    scan_run_id: str = Query(..., description="Scan run identifier"),
    tenant_id: str = Query(..., description="Tenant identifier")
):
    """Get threats grouped by service"""
    report = storage.get_report(scan_run_id, tenant_id)
    if not report:
        raise HTTPException(
            status_code=404,
            detail=f"Threat report not found for scan_run_id: {scan_run_id}"
        )
    
    threats_by_service = {}
    for threat in report.get("threats", []):
        for asset in threat.get("affected_assets", []):
            resource_type = asset.get("resource_type", "unknown")
            service = resource_type.split(":")[0] if ":" in resource_type else resource_type
            if service not in threats_by_service:
                threats_by_service[service] = {
                    "service": service,
                    "threats": [],
                    "count": 0,
                    "by_severity": {}
                }
            threats_by_service[service]["threats"].append(threat)
            threats_by_service[service]["count"] += 1
            severity = threat.get("severity", "unknown")
            threats_by_service[service]["by_severity"][severity] = \
                threats_by_service[service]["by_severity"].get(severity, 0) + 1
    
    # Deduplicate threats per service
    for service_data in threats_by_service.values():
        seen = set()
        unique_threats = []
        for threat in service_data["threats"]:
            threat_id = threat.get("threat_id")
            if threat_id not in seen:
                seen.add(threat_id)
                unique_threats.append(threat)
        service_data["threats"] = unique_threats
        service_data["count"] = len(unique_threats)
    
    return {
        "scan_run_id": scan_run_id,
        "services": list(threats_by_service.values())
    }


# ============================================================================
# Analytics Endpoints
# ============================================================================

@app.get("/api/v1/threat/analytics/patterns")
async def get_threat_patterns(
    scan_run_id: str = Query(..., description="Scan run identifier"),
    tenant_id: str = Query(..., description="Tenant identifier"),
    limit: int = Query(10, description="Number of patterns to return")
):
    """Get common threat patterns (grouped by misconfig combinations)"""
    report = storage.get_report(scan_run_id, tenant_id)
    if not report:
        raise HTTPException(
            status_code=404,
            detail=f"Threat report not found for scan_run_id: {scan_run_id}"
        )
    
    patterns = {}
    for threat in report.get("threats", []):
        # Create pattern key from misconfig finding refs
        finding_refs = threat.get("correlations", {}).get("misconfig_finding_refs", [])
        pattern_key = "|".join(sorted(finding_refs))
        
        if pattern_key not in patterns:
            patterns[pattern_key] = {
                "pattern": pattern_key,
                "misconfig_finding_refs": finding_refs,
                "count": 0,
                "threats": [],
                "severity": threat.get("severity"),
                "threat_type": threat.get("threat_type")
            }
        
        patterns[pattern_key]["count"] += 1
        patterns[pattern_key]["threats"].append(threat)
    
    # Sort by count and return top patterns
    sorted_patterns = sorted(
        patterns.values(),
        key=lambda x: x["count"],
        reverse=True
    )[:limit]
    
    return {
        "scan_run_id": scan_run_id,
        "patterns": sorted_patterns
    }


@app.get("/api/v1/threat/analytics/correlation")
async def get_threat_correlation(
    scan_run_id: str = Query(..., description="Scan run identifier"),
    tenant_id: str = Query(..., description="Tenant identifier")
):
    """Get threat correlation matrix"""
    report = storage.get_report(scan_run_id, tenant_id)
    if not report:
        raise HTTPException(
            status_code=404,
            detail=f"Threat report not found for scan_run_id: {scan_run_id}"
        )
    
    threats = report.get("threats", [])
    threat_types = list(set(t.get("threat_type") for t in threats))
    
    # Build correlation matrix
    correlation_matrix = {}
    for type1 in threat_types:
        correlation_matrix[type1] = {}
        for type2 in threat_types:
            if type1 == type2:
                correlation_matrix[type1][type2] = 1.0
            else:
                # Count threats that have both types (via shared assets)
                count_both = 0
                for threat1 in threats:
                    if threat1.get("threat_type") == type1:
                        assets1 = set(
                            a.get("resource_uid") or a.get("resource_arn")
                            for a in threat1.get("affected_assets", [])
                        )
                        for threat2 in threats:
                            if threat2.get("threat_type") == type2:
                                assets2 = set(
                                    a.get("resource_uid") or a.get("resource_arn")
                                    for a in threat2.get("affected_assets", [])
                                )
                                if assets1 & assets2:  # Shared assets
                                    count_both += 1
                
                # Calculate correlation score (0-1)
                total_threats = len([t for t in threats if t.get("threat_type") in [type1, type2]])
                correlation_score = count_both / total_threats if total_threats > 0 else 0.0
                correlation_matrix[type1][type2] = round(correlation_score, 2)
    
    return {
        "scan_run_id": scan_run_id,
        "correlation_matrix": correlation_matrix
    }


@app.get("/api/v1/threat/analytics/distribution")
async def get_threat_distribution(
    scan_run_id: str = Query(..., description="Scan run identifier"),
    tenant_id: str = Query(..., description="Tenant identifier")
):
    """Get threat distribution statistics"""
    report = storage.get_report(scan_run_id, tenant_id)
    if not report:
        raise HTTPException(
            status_code=404,
            detail=f"Threat report not found for scan_run_id: {scan_run_id}"
        )
    
    summary = report.get("threat_summary", {})
    
    return {
        "scan_run_id": scan_run_id,
        "distribution": {
            "by_severity": summary.get("threats_by_severity", {}),
            "by_category": summary.get("threats_by_category", {}),
            "by_status": summary.get("threats_by_status", {}),
            "top_categories": summary.get("top_threat_categories", [])
        }
    }


# ============================================================================
# Remediation Endpoints
# ============================================================================

@app.get("/api/v1/threat/remediation/queue")
async def get_remediation_queue(
    tenant_id: str = Query(..., description="Tenant identifier"),
    status: Optional[ThreatStatus] = Query(None, description="Filter by status"),
    limit: int = Query(100, description="Maximum number of threats to return")
):
    """Get remediation queue (all threats across all reports)"""
    reports = storage.list_reports(tenant_id, limit=100)
    
    all_threats = []
    for report_meta in reports:
        scan_run_id = report_meta.get("scan_run_id")
        report = storage.get_report(scan_run_id, tenant_id)
        if report:
            for threat in report.get("threats", []):
                if not status or threat.get("status") == status.value:
                    all_threats.append({
                        **threat,
                        "scan_run_id": scan_run_id
                    })
    
    # Sort by severity (critical first)
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    all_threats.sort(key=lambda t: severity_order.get(t.get("severity", "info"), 99))
    
    return {
        "total": len(all_threats),
        "threats": all_threats[:limit]
    }


@app.get("/api/v1/threat/{threat_id}/remediation")
async def get_threat_remediation(
    threat_id: str,
    tenant_id: str = Query(..., description="Tenant identifier")
):
    """Get remediation workflow for a threat"""
    threat_data = storage.get_threat(threat_id, tenant_id)
    if not threat_data:
        raise HTTPException(
            status_code=404,
            detail=f"Threat not found: {threat_id}"
        )
    
    threat = threat_data.get("threat", {})
    misconfig_findings = threat_data.get("misconfig_findings", [])
    
    # Build remediation steps from misconfig findings
    remediation_steps = []
    for finding in misconfig_findings:
        remediation_steps.append({
            "step_id": finding.get("misconfig_finding_id"),
            "finding_id": finding.get("misconfig_finding_id"),
            "rule_id": finding.get("rule_id"),
            "description": f"Remediate: {finding.get('rule_id')}",
            "status": "pending",  # Can be enhanced with actual tracking
            "severity": finding.get("severity")
        })
    
    return {
        "threat_id": threat_id,
        "threat": threat,
        "remediation": threat.get("remediation", {}),
        "steps": remediation_steps,
        "total_steps": len(remediation_steps),
        "completed_steps": 0  # Can be enhanced with actual tracking
    }


@app.get("/api/v1/threat/reports")
async def list_threat_reports(
    tenant_id: str = Query(..., description="Tenant identifier"),
    limit: int = Query(100, description="Maximum number of reports to return")
):
    """List all threat reports for a tenant"""
    reports = storage.list_reports(tenant_id, limit=limit)
    return {
        "tenant_id": tenant_id,
        "total": len(reports),
        "reports": reports
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)

