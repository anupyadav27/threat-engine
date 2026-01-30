"""
Threat Engine API Server

FastAPI server for threat detection and reporting.
"""

import os
import json
import sys
from typing import Optional, List, Dict, Any
import time
import random
from fastapi import FastAPI, HTTPException, Query, Body
import asyncio
import threading
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime

# Add common to path for logger import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))
from engine_common.logger import setup_logger, LogContext, log_duration, audit_log
from engine_common.middleware import RequestLoggingMiddleware, CorrelationIDMiddleware

from .schemas.threat_report_schema import (
    ThreatReport,
    Tenant,
    ScanContext,
    Cloud,
    TriggerType
)
from .schemas.misconfig_normalizer import (
    normalize_db_check_results_to_findings,
    normalize_ndjson_to_findings,
)
from .database.metadata_enrichment import get_enriched_check_results
from .detector.threat_detector import ThreatDetector
from .detector.drift_detector import DriftDetector
from .detector.check_drift_detector import CheckDriftDetector
from .reporter.threat_reporter import ThreatReporter
from .storage.threat_storage import ThreatStorage
from .schemas.threat_report_schema import ThreatStatus, ThreatType, Severity

logger = setup_logger(__name__, engine_name="engine-threat")

app = FastAPI(
    title="Threat Engine API",
    description="Cloud Security Threat Detection and Reporting",
    version="1.0.0"
)

# Lightweight in-memory job tracker for async generation.
# NOTE: This is per-pod memory; for HA move to Redis/DB.
threat_jobs: Dict[str, Dict[str, Any]] = {}

# Add logging middleware
app.add_middleware(CorrelationIDMiddleware)
app.add_middleware(RequestLoggingMiddleware, engine_name="engine-threat")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
        CONFIGSCAN_PATH = Path(__file__).parent.parent.parent.parent / "engine_configscan" / "engine_configscan_aws"
        sys.path.insert(0, str(CONFIGSCAN_PATH))
        from engine.database_manager import DatabaseManager
        
        db_manager = DatabaseManager()
        init_check_router(db_manager)
    except:
        pass  # Router will initialize on first request
    
    app.include_router(check_router)
except ImportError as e:
    logger.warning("Check router not available", extra={"extra_fields": {"error": str(e)}})

# Include discovery results router
try:
    from .api.discovery_router import router as discovery_router, init_discovery_router
    
    # Try to initialize with DatabaseManager
    try:
        from pathlib import Path
        CONFIGSCAN_PATH = Path(__file__).parent.parent.parent.parent / "engine_configscan" / "engine_configscan_aws"
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
    logger.warning("Discovery router not available", extra={"extra_fields": {"error": str(e)}})


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
    discovery_scan_id: Optional[str] = None


#
# DB-first only: removed file/S3 loaders for scan results.
# Threat generation reads from Check DB (check_results + rule_metadata).


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "engine-threat",
        "version": "1.0.0",
        "status": "running"
    }


@app.get("/health")
async def health():
    """Health check endpoint"""
    import time
    start = time.time()
    
    health_status = {"status": "healthy"}
    
    duration_ms = (time.time() - start) * 1000
    logger.info("Health check", extra={
        "extra_fields": {
            "status": "healthy",
            "duration_ms": duration_ms
        }
    })
    
    return health_status


@app.post("/api/v1/threat/generate")
async def generate_threat_report(request: ThreatReportRequest):
    """
    Generate threat report from scan results.
    
    Supports both S3 and local file sources.
    """
    import time
    start_time = time.time()
    
    with LogContext(
        tenant_id=request.tenant_id,
        scan_run_id=request.scan_run_id
    ):
        logger.info("Generating threat report", extra={
            "extra_fields": {
                "cloud": request.cloud.value,
                "trigger_type": request.trigger_type.value,
                "accounts": request.accounts,
                "regions": request.regions
            }
        })
        
        try:
            # DB-first only: read failures from Check DB and enrich with rule_metadata.
            if os.getenv("THREAT_USE_DATABASE", "true").lower() != "true":
                raise HTTPException(status_code=400, detail="Threat engine is DB-only. Set THREAT_USE_DATABASE=true.")

            logger.info("Loading check results from database with metadata enrichment", extra={
                "extra_fields": {
                    "scan_run_id": request.scan_run_id,
                    "tenant_id": request.tenant_id
                }
            })

            check_results = get_enriched_check_results(
                scan_id=request.scan_run_id,
                schema="check_db",
                status_filter=["FAIL", "WARN"]
            )

            if not check_results:
                raise HTTPException(status_code=404, detail="No failing check results found in database for scan_run_id")

            logger.info("Normalizing check results from database (with metadata)", extra={
                "extra_fields": {
                    "total_results": len(check_results),
                    "has_metadata": bool(check_results[0].get('severity'))
                }
            })

            findings = normalize_db_check_results_to_findings(
                check_results,
                request.cloud,
                include_metadata=True
            )
        
            if not findings:
                logger.info("No findings found, generating empty report")
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
                
                reporter = ThreatReporter()
                report = reporter.generate_report(
                    tenant=tenant,
                    scan_context=scan_context,
                    threats=[],
                    misconfig_findings=[]
                )
                
                # Persist even empty reports (DB is primary)
                storage.save_report(report)
                
                duration_ms = (time.time() - start_time) * 1000
                log_duration(logger, "Threat report generated (empty)", duration_ms)
                audit_log(
                    logger,
                    "threat_report_generated",
                    f"scan:{request.scan_run_id}",
                    tenant_id=request.tenant_id,
                    result="success",
                    details={"threats_count": 0, "findings_count": 0}
                )
                
                return report.dict()
            
            logger.info("Detecting threats", extra={
                "extra_fields": {
                    "findings_count": len(findings)
                }
            })
            
            # Detect threats
            detector = ThreatDetector()
            threats = detector.detect_threats(findings)

            # Drift detection (optional - skip if no discovery_scan_id or if it fails)
            if request.discovery_scan_id:
                try:
                    from .database.discovery_queries import DiscoveryDatabaseQueries
                    from .database.check_queries import CheckDatabaseQueries
                    
                    drift_detector = DriftDetector(discovery_queries=DiscoveryDatabaseQueries())
                    check_drift_detector = CheckDriftDetector(check_queries=CheckDatabaseQueries())
                    
                    drift_threats = drift_detector.detect_configuration_drift(
                        tenant_id=request.tenant_id,
                        hierarchy_id=request.accounts[0] if request.accounts else None,
                        service=request.services[0] if request.services else None,
                        current_scan_id=request.discovery_scan_id
                    )
                    check_drift_threats = check_drift_detector.detect_check_status_drift(
                        tenant_id=request.tenant_id,
                        hierarchy_id=request.accounts[0] if request.accounts else None,
                        service=request.services[0] if request.services else None,
                        current_scan_id=request.scan_run_id
                    )
                    threats.extend(drift_threats)
                    threats.extend(check_drift_threats)
                except Exception as e:
                    logger.warning(f"Drift detection failed (continuing without drift threats): {e}")
            
            logger.info("Threats detected", extra={
                "extra_fields": {
                    "threats_count": len(threats)
                }
            })
            
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
            
            duration_ms = (time.time() - start_time) * 1000
            log_duration(logger, "Threat report generated", duration_ms)
            audit_log(
                logger,
                "threat_report_generated",
                f"scan:{request.scan_run_id}",
                tenant_id=request.tenant_id,
                result="success",
                details={
                    "threats_count": len(threats),
                    "findings_count": len(findings)
                }
            )
            
            logger.info("Threat report saved", extra={
                "extra_fields": {
                    "threats_count": len(threats),
                    "findings_count": len(findings)
                }
            })
            
            return report.dict()
        
        except HTTPException:
            raise
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            logger.error("Failed to generate threat report", exc_info=True, extra={
                "extra_fields": {
                    "error": str(e),
                    "duration_ms": duration_ms
                }
            })
            audit_log(
                logger,
                "threat_report_generation_failed",
                f"scan:{request.scan_run_id}",
                tenant_id=request.tenant_id,
                result="failure",
                details={"error": str(e)}
            )
            raise HTTPException(
                status_code=500,
                detail=f"Failed to generate threat report: {str(e)}"
            )


@app.post("/api/v1/threat/generate/async")
async def generate_threat_report_async(request: ThreatReportRequest):
    """
    DB-first async wrapper for threat generation.

    Returns immediately with a job_id so callers can poll `/api/v1/threat/jobs/{job_id}`.
    """
    job_id = f"threatjob_{int(time.time()*1000)}_{random.randint(1000,9999)}"
    threat_jobs[job_id] = {
        "job_id": job_id,
        "status": "running",
        "scan_run_id": request.scan_run_id,
        "tenant_id": request.tenant_id,
        "started_at": datetime.utcnow().isoformat(),
        "error": None,
    }

    def _worker():
        try:
            asyncio.run(generate_threat_report(request))
            threat_jobs[job_id]["status"] = "completed"
            threat_jobs[job_id]["completed_at"] = datetime.utcnow().isoformat()
        except Exception as e:
            threat_jobs[job_id]["status"] = "failed"
            threat_jobs[job_id]["error"] = str(e)
            threat_jobs[job_id]["completed_at"] = datetime.utcnow().isoformat()

    threading.Thread(target=_worker, daemon=True).start()
    return threat_jobs[job_id]


@app.get("/api/v1/threat/jobs/{job_id}")
async def get_threat_job(job_id: str):
    job = threat_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


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
    discovery_scan_id: Optional[str] = Body(None),
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

        # Detect configuration and check-status drift (using provided scan IDs)
        drift_detector = DriftDetector()
        check_drift_detector = CheckDriftDetector()
        drift_threats = drift_detector.detect_configuration_drift(
            tenant_id=tenant_id,
            hierarchy_id=accounts[0] if accounts else None,
            service=services[0] if services else None,
            current_scan_id=discovery_scan_id
        )
        check_drift_threats = check_drift_detector.detect_check_status_drift(
            tenant_id=tenant_id,
            hierarchy_id=accounts[0] if accounts else None,
            service=services[0] if services else None,
            current_scan_id=scan_run_id  # This is the check_scan_id
        )
        threats.extend(drift_threats)
        threats.extend(check_drift_threats)
        
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
    with LogContext(tenant_id=tenant_id, scan_run_id=scan_run_id):
        logger.info("Retrieving threat report")
        report = storage.get_report(scan_run_id, tenant_id)
        if not report:
            logger.warning("Threat report not found", extra={
                "extra_fields": {
                    "scan_run_id": scan_run_id,
                    "tenant_id": tenant_id
                }
            })
            raise HTTPException(
                status_code=404,
                detail=f"Threat report not found for scan_run_id: {scan_run_id}"
            )
        logger.info("Threat report retrieved", extra={
            "extra_fields": {
                "threats_count": len(report.get("threats", []))
            }
        })
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


@app.get("/api/v1/threat/drift")
async def get_drift_threats(
    tenant_id: str = Query(..., description="Tenant identifier"),
    account_id: Optional[str] = Query(None, description="Account/hierarchy identifier"),
    service: Optional[str] = Query(None, description="Service filter"),
    region: Optional[str] = Query(None, description="Region filter"),
    start_time: Optional[str] = Query(None, description="Start time (ISO-8601)"),
    end_time: Optional[str] = Query(None, description="End time (ISO-8601)")
):
    """
    Get configuration and check-status drift threats.
    Uses latest scans from database for baseline comparison.
    """
    try:
        def _parse_dt(val: Optional[str]) -> Optional[datetime]:
            if not val:
                return None
            v = val.strip()
            # Allow Z suffix
            if v.endswith("Z"):
                v = v[:-1] + "+00:00"
            return datetime.fromisoformat(v)

        start_dt = _parse_dt(start_time)
        end_dt = _parse_dt(end_time)

        drift_detector = DriftDetector()
        check_drift_detector = CheckDriftDetector()

        configuration_drift = drift_detector.detect_configuration_drift(
            tenant_id=tenant_id,
            hierarchy_id=account_id,
            service=service,
            current_scan_id=None,
            region=region,
            start_time=start_dt,
            end_time=end_dt
        )
        check_status_drift = check_drift_detector.detect_check_status_drift(
            tenant_id=tenant_id,
            hierarchy_id=account_id,
            service=service,
            current_scan_id=None
        )

        all_threats = configuration_drift + check_status_drift
        by_severity = {}
        by_type = {}
        for threat in all_threats:
            sev = threat.severity.value
            by_severity[sev] = by_severity.get(sev, 0) + 1
            ttype = threat.threat_type.value
            by_type[ttype] = by_type.get(ttype, 0) + 1

        return {
            "configuration_drift": [t.dict() for t in configuration_drift],
            "check_status_drift": [t.dict() for t in check_status_drift],
            "summary": {
                "total": len(all_threats),
                "by_severity": by_severity,
                "by_type": by_type
            }
        }
    except Exception as e:
        logger.error("Drift threat retrieval failed", extra={
            "extra_fields": {"error": str(e)}
        }, exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


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

@app.get("/api/v1/threat/analytics/trend")
async def get_threat_trend(
    tenant_id: str = Query(..., description="Tenant identifier"),
    days: int = Query(30, description="Number of days to include"),
    scan_run_id: Optional[str] = Query(None, description="Specific scan to analyze (default: all scans)"),
    severity: Optional[str] = Query(None, description="Filter by severity")
):
    """Get historical threat trends over time"""
    import time
    start_time = time.time()
    
    with LogContext(tenant_id=tenant_id):
        logger.info("Getting threat trends", extra={
            "extra_fields": {
                "days": days,
                "scan_run_id": scan_run_id,
                "severity": severity
            }
        })
        
        try:
            # Get all reports for tenant
            reports = storage.list_reports(tenant_id, limit=1000)
            
            if not reports:
                return {
                    "tenant_id": tenant_id,
                    "days": days,
                    "trend_data": [],
                    "summary": {
                        "average_daily_threats": 0,
                        "trend_direction": "neutral",
                        "percent_change": 0.0
                    }
                }
            
            # Filter by scan_run_id if provided
            if scan_run_id:
                reports = [r for r in reports if r.get("scan_run_id") == scan_run_id]
            
            # Group by date
            from collections import defaultdict
            from datetime import datetime, timedelta
            
            trend_by_date = defaultdict(lambda: {
                "total_threats": 0,
                "by_severity": defaultdict(int),
                "by_category": defaultdict(int)
            })
            
            # Calculate date range
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days)
            
            for report_meta in reports:
                report = storage.get_report(report_meta.get("scan_run_id"), tenant_id)
                if not report:
                    continue
                
                # Get report date
                generated_at = report.get("generated_at")
                if generated_at:
                    try:
                        report_date = datetime.fromisoformat(generated_at.replace('Z', '+00:00'))
                        if report_date < start_date:
                            continue
                        
                        date_key = report_date.strftime("%Y-%m-%d")
                        
                        summary = report.get("threat_summary", {})
                        trend_by_date[date_key]["total_threats"] = summary.get("total_threats", 0)
                        
                        # Aggregate by severity
                        for sev, count in summary.get("threats_by_severity", {}).items():
                            if not severity or sev == severity:
                                trend_by_date[date_key]["by_severity"][sev] = count
                        
                        # Aggregate by category
                        for cat, count in summary.get("threats_by_category", {}).items():
                            trend_by_date[date_key]["by_category"][cat] = count
                    except Exception as e:
                        logger.warning("Error parsing date", extra={"extra_fields": {"error": str(e)}})
                        continue
            
            # Convert to sorted list
            trend_data = []
            for date_str in sorted(trend_by_date.keys()):
                date_data = trend_by_date[date_str]
                trend_data.append({
                    "date": date_str,
                    "total_threats": date_data["total_threats"],
                    "by_severity": dict(date_data["by_severity"]),
                    "by_category": dict(date_data["by_category"])
                })
            
            # Calculate summary
            if len(trend_data) >= 2:
                first_count = trend_data[0]["total_threats"]
                last_count = trend_data[-1]["total_threats"]
                avg_count = sum(d["total_threats"] for d in trend_data) / len(trend_data) if trend_data else 0
                
                if first_count > 0:
                    percent_change = ((last_count - first_count) / first_count) * 100
                else:
                    percent_change = 0.0
                
                trend_direction = "increasing" if percent_change > 0 else "decreasing" if percent_change < 0 else "neutral"
            else:
                avg_count = trend_data[0]["total_threats"] if trend_data else 0
                percent_change = 0.0
                trend_direction = "neutral"
            
            duration_ms = (time.time() - start_time) * 1000
            log_duration(logger, "Threat trend retrieved", duration_ms)
            
            return {
                "tenant_id": tenant_id,
                "days": days,
                "trend_data": trend_data,
                "summary": {
                    "average_daily_threats": round(avg_count, 2),
                    "trend_direction": trend_direction,
                    "percent_change": round(percent_change, 2)
                }
            }
        
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            logger.error("Error getting threat trends", exc_info=True, extra={
                "extra_fields": {
                    "error": str(e),
                    "duration_ms": duration_ms
                }
            })
            raise HTTPException(status_code=500, detail=str(e))


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


# ============================================================================
# NORMALIZED QUERY ENDPOINTS (for new schema)
# ============================================================================

@app.get("/api/v1/threat/threats")
async def list_threats(
    tenant_id: str = Query(...),
    scan_run_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None, regex="^(critical|high|medium|low|info)$"),
    category: Optional[str] = Query(None),
    status: Optional[str] = Query(None, regex="^(open|resolved|suppressed|false_positive)$"),
    resource_uid: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """
    Query threats from normalized threats table.
    
    Supports filtering by severity, category, status, resource, scan.
    """
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
        
        host = os.getenv("THREAT_DB_HOST", "localhost")
        port = os.getenv("THREAT_DB_PORT", "5432")
        db = os.getenv("THREAT_DB_NAME", "threat_engine_threat")
        user = os.getenv("THREAT_DB_USER", "threat_user")
        pwd = os.getenv("THREAT_DB_PASSWORD", "threat_password")
        conn_str = f"postgresql://{user}:{pwd}@{host}:{port}/{db}"
        
        conn = psycopg2.connect(conn_str)
        
        # Build WHERE clause
        where_parts = ["t.tenant_id = %s"]
        params = [tenant_id]
        
        if scan_run_id:
            where_parts.append("t.scan_run_id = %s")
            params.append(scan_run_id)
        
        if severity:
            where_parts.append("t.severity = %s")
            params.append(severity)
        
        if category:
            where_parts.append("t.category = %s")
            params.append(category)
        
        if status:
            where_parts.append("t.status = %s")
            params.append(status)
        
        if resource_uid:
            where_parts.append("EXISTS (SELECT 1 FROM threat_resources tr WHERE tr.threat_id = t.threat_id AND tr.resource_uid = %s)")
            params.append(resource_uid)
        
        where_clause = " AND ".join(where_parts)
        
        # Get total count
        with conn.cursor() as cur:
            cur.execute(f"SELECT COUNT(*) FROM threats t WHERE {where_clause}", params)
            total = cur.fetchone()[0]
        
        # Get paginated results
        query = f"""
            SELECT 
                t.threat_id, t.scan_run_id, t.threat_type, t.category,
                t.severity, t.confidence, t.status, t.title, t.description,
                t.primary_rule_id, t.misconfig_count, t.affected_resource_count,
                t.first_seen_at, t.last_seen_at, t.resolved_at
            FROM threats t
            WHERE {where_clause}
            ORDER BY 
                CASE t.severity 
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END,
                t.first_seen_at DESC
            LIMIT %s OFFSET %s
        """
        params.extend([limit, offset])
        
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(query, params)
            threats = [dict(row) for row in cur.fetchall()]
        
        conn.close()
        
        return {
            "threats": threats,
            "total": total,
            "limit": limit,
            "offset": offset,
            "has_more": (offset + len(threats)) < total
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to query threats: {str(e)}")


@app.get("/api/v1/threat/threats/{threat_id}")
async def get_threat_detail(
    threat_id: str,
    tenant_id: str = Query(...)
):
    """Get detailed threat information including affected resources"""
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
        
        host = os.getenv("THREAT_DB_HOST", "localhost")
        port = os.getenv("THREAT_DB_PORT", "5432")
        db = os.getenv("THREAT_DB_NAME", "threat_engine_threat")
        user = os.getenv("THREAT_DB_USER", "threat_user")
        pwd = os.getenv("THREAT_DB_PASSWORD", "threat_password")
        conn_str = f"postgresql://{user}:{pwd}@{host}:{port}/{db}"
        
        conn = psycopg2.connect(conn_str)
        
        # Get threat details
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT * FROM threats
                WHERE threat_id = %s AND tenant_id = %s
            """, (threat_id, tenant_id))
            threat = cur.fetchone()
        
        if not threat:
            raise HTTPException(status_code=404, detail="Threat not found")
        
        # Get affected resources
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT * FROM threat_resources
                WHERE threat_id = %s
            """, (threat_id,))
            resources = [dict(row) for row in cur.fetchall()]
        
        conn.close()
        
        return {
            **dict(threat),
            "affected_resources": resources
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get threat: {str(e)}")


@app.get("/api/v1/threat/resources/{resource_uid:path}/posture")
async def get_resource_posture(
    resource_uid: str,
    tenant_id: str = Query(...),
    scan_id: Optional[str] = Query(None, description="Check scan ID, defaults to latest")
):
    """
    Get resource posture (check results summary) from Check DB.
    
    Shows:
    - Total checks run
    - Pass/Fail/Warn counts
    - Failed rule IDs
    - Severity breakdown
    """
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
        
        host = os.getenv("CHECK_DB_HOST", "localhost")
        port = os.getenv("CHECK_DB_PORT", "5432")
        db = os.getenv("CHECK_DB_NAME", "threat_engine_check")
        user = os.getenv("CHECK_DB_USER", "check_user")
        pwd = os.getenv("CHECK_DB_PASSWORD", "check_password")
        conn_str = f"postgresql://{user}:{pwd}@{host}:{port}/{db}"
        
        conn = psycopg2.connect(conn_str)
        
        # Get latest scan_id if not provided
        if not scan_id or scan_id == "latest":
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT scan_id FROM scans
                    WHERE tenant_id = %s AND status = 'completed'
                    ORDER BY scan_timestamp DESC LIMIT 1
                """, (tenant_id,))
                row = cur.fetchone()
                scan_id = row[0] if row else None
        
        if not scan_id:
            raise HTTPException(status_code=404, detail="No scans found for tenant")
        
        # Get resource posture
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT 
                    cr.resource_uid,
                    cr.resource_type,
                    cr.resource_arn,
                    cr.hierarchy_id as account_id,
                    COUNT(*) as total_checks,
                    COUNT(*) FILTER (WHERE cr.status = 'PASS') as passed,
                    COUNT(*) FILTER (WHERE cr.status = 'FAIL') as failed,
                    COUNT(*) FILTER (WHERE cr.status = 'WARN') as warnings,
                    COUNT(*) FILTER (WHERE cr.status = 'ERROR') as errors,
                    jsonb_agg(cr.rule_id) FILTER (WHERE cr.status = 'FAIL') as failed_rule_ids,
                    COUNT(*) FILTER (WHERE rm.severity = 'critical' AND cr.status = 'FAIL') as critical_failures,
                    COUNT(*) FILTER (WHERE rm.severity = 'high' AND cr.status = 'FAIL') as high_failures,
                    COUNT(*) FILTER (WHERE rm.severity = 'medium' AND cr.status = 'FAIL') as medium_failures,
                    MAX(cr.created_at) as last_scanned
                FROM check_results cr
                LEFT JOIN rule_metadata rm ON cr.rule_id = rm.rule_id
                WHERE cr.tenant_id = %s AND cr.scan_id = %s AND cr.resource_uid = %s
                GROUP BY cr.resource_uid, cr.resource_type, cr.resource_arn, cr.hierarchy_id
            """, (tenant_id, scan_id, resource_uid))
            posture = cur.fetchone()
        
        conn.close()
        
        if not posture:
            raise HTTPException(status_code=404, detail="Resource not found in scan")
        
        return dict(posture)
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get resource posture: {str(e)}")


@app.get("/api/v1/threat/drift")
async def list_drift_records(
    tenant_id: str = Query(...),
    current_scan_id: Optional[str] = Query(None),
    change_type: Optional[str] = Query(None, regex="^(added|removed|modified|unchanged)$"),
    config_drift_only: bool = Query(False),
    status_drift_only: bool = Query(False),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """
    Query drift records (configuration and check status drift).
    
    Supports filtering by scan, change type, drift type.
    """
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
        
        host = os.getenv("THREAT_DB_HOST", "localhost")
        port = os.getenv("THREAT_DB_PORT", "5432")
        db = os.getenv("THREAT_DB_NAME", "threat_engine_threat")
        user = os.getenv("THREAT_DB_USER", "threat_user")
        pwd = os.getenv("THREAT_DB_PASSWORD", "threat_password")
        conn_str = f"postgresql://{user}:{pwd}@{host}:{port}/{db}"
        
        conn = psycopg2.connect(conn_str)
        
        # Build WHERE clause
        where_parts = ["tenant_id = %s"]
        params = [tenant_id]
        
        if current_scan_id:
            where_parts.append("current_scan_id = %s")
            params.append(current_scan_id)
        
        if change_type:
            where_parts.append("change_type = %s")
            params.append(change_type)
        
        if config_drift_only:
            where_parts.append("config_drift_detected = TRUE")
        
        if status_drift_only:
            where_parts.append("status_drift_detected = TRUE")
        
        where_clause = " AND ".join(where_parts)
        
        # Get total count
        with conn.cursor() as cur:
            cur.execute(f"SELECT COUNT(*) FROM drift_records WHERE {where_clause}", params)
            total = cur.fetchone()[0]
        
        # Get paginated results
        query = f"""
            SELECT 
                drift_id, resource_uid, resource_type, account_id, region,
                current_scan_id, previous_scan_id, detected_at,
                config_drift_detected, change_type, status_drift_detected,
                previous_check_status, current_check_status,
                newly_failed_rules, newly_passed_rules, still_failing_rules,
                threat_id
            FROM drift_records
            WHERE {where_clause}
            ORDER BY detected_at DESC
            LIMIT %s OFFSET %s
        """
        params.extend([limit, offset])
        
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(query, params)
            drift_records = [dict(row) for row in cur.fetchall()]
        
        conn.close()
        
        return {
            "drift_records": drift_records,
            "total": total,
            "limit": limit,
            "offset": offset,
            "has_more": (offset + len(drift_records)) < total
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to query drift: {str(e)}")


@app.get("/api/v1/threat/resources/{resource_uid:path}/threats")
async def get_resource_threats(
    resource_uid: str,
    tenant_id: str = Query(...),
    scan_run_id: Optional[str] = Query(None)
):
    """Get all threats affecting a specific resource"""
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
        
        host = os.getenv("THREAT_DB_HOST", "localhost")
        port = os.getenv("THREAT_DB_PORT", "5432")
        db = os.getenv("THREAT_DB_NAME", "threat_engine_threat")
        user = os.getenv("THREAT_DB_USER", "threat_user")
        pwd = os.getenv("THREAT_DB_PASSWORD", "threat_password")
        conn_str = f"postgresql://{user}:{pwd}@{host}:{port}/{db}"
        
        conn = psycopg2.connect(conn_str)
        
        # Build query
        where_parts = ["tr.resource_uid = %s", "t.tenant_id = %s"]
        params = [resource_uid, tenant_id]
        
        if scan_run_id:
            where_parts.append("t.scan_run_id = %s")
            params.append(scan_run_id)
        
        where_clause = " AND ".join(where_parts)
        
        query = f"""
            SELECT 
                t.threat_id, t.scan_run_id, t.threat_type, t.category,
                t.severity, t.status, t.title, t.description,
                t.misconfig_count, t.first_seen_at, t.last_seen_at,
                tr.failed_rule_ids
            FROM threats t
            JOIN threat_resources tr ON t.threat_id = tr.threat_id
            WHERE {where_clause}
            ORDER BY 
                CASE t.severity 
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END
        """
        
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(query, params)
            threats = [dict(row) for row in cur.fetchall()]
        
        conn.close()
        
        return {
            "resource_uid": resource_uid,
            "threats": threats,
            "total": len(threats)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get resource threats: {str(e)}")


@app.get("/api/v1/threat/scans/{scan_run_id}/summary")
async def get_scan_summary(
    scan_run_id: str,
    tenant_id: str = Query(...)
):
    """Get threat scan summary from threat_scans table"""
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
        
        host = os.getenv("THREAT_DB_HOST", "localhost")
        port = os.getenv("THREAT_DB_PORT", "5432")
        db = os.getenv("THREAT_DB_NAME", "threat_engine_threat")
        user = os.getenv("THREAT_DB_USER", "threat_user")
        pwd = os.getenv("THREAT_DB_PASSWORD", "threat_password")
        conn_str = f"postgresql://{user}:{pwd}@{host}:{port}/{db}"
        
        conn = psycopg2.connect(conn_str)
        
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT * FROM threat_scans
                WHERE scan_run_id = %s AND tenant_id = %s
            """, (scan_run_id, tenant_id))
            summary = cur.fetchone()
        
        conn.close()
        
        if not summary:
            raise HTTPException(status_code=404, detail="Scan summary not found")
        
        return dict(summary)
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get scan summary: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)

