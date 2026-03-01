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
import psycopg2

# Add common to path for logger import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))
from engine_common.logger import setup_logger, LogContext, log_duration, audit_log
from engine_common.telemetry import configure_telemetry
from engine_common.middleware import RequestLoggingMiddleware, CorrelationIDMiddleware
from engine_common.orchestration import get_orchestration_metadata

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
from .storage.threat_db_writer import save_analyses_to_db, get_analyses_from_db
from .storage.threat_intel_writer import (
    save_intel, save_intel_batch, get_intel, correlate_intel_with_threats,
    save_hunt_query, get_hunt_queries, get_hunt_query,
    save_hunt_result, get_hunt_results,
)
from .analyzer.threat_analyzer import ThreatAnalyzer
from .graph.graph_builder import SecurityGraphBuilder
from .graph.graph_queries import SecurityGraphQueries
from .schemas.threat_report_schema import ThreatStatus, ThreatType, Severity

logger = setup_logger(__name__, engine_name="engine-threat")

app = FastAPI(
    title="Threat Engine API",
    description="Cloud Security Threat Detection and Reporting",
    version="1.0.0"
)
configure_telemetry("engine-threat", app)

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


# DEPRECATED: Replaced by get_orchestration_metadata() from engine_common.orchestration
# def get_check_scan_id_from_orchestration(scan_run_id: str) -> Optional[str]:
#     """Query scan_orchestration table to get check_scan_id for a given scan_run_id."""
#     # This function is no longer used - use get_orchestration_metadata() instead
#     # which returns ALL metadata (tenant_id, account_id, provider_type, etc.)
#     pass

# Placeholder to avoid breaking references
def get_check_scan_id_from_orchestration(scan_run_id: str) -> Optional[str]:
    try:
        metadata = get_orchestration_metadata(scan_run_id)
        if metadata:
            logger.info(f"Found check_scan_id={metadata.get('check_scan_id')} for scan_run_id={scan_run_id}")
            return metadata.get("check_scan_id")
        else:
            logger.warning(f"No check_scan_id found in scan_orchestration for scan_run_id={scan_run_id}")
            return None
    except Exception as e:
        logger.error(f"Error querying scan_orchestration table: {e}", exc_info=True)
        return None


# Include check results router (standalone - no configscan dependency)
try:
    from .api.check_router import router as check_router
    app.include_router(check_router)
except ImportError as e:
    logger.warning("Check router not available", extra={"extra_fields": {"error": str(e)}})

# Include discovery results router (standalone - no configscan dependency)
try:
    from .api.discovery_router import router as discovery_router
    app.include_router(discovery_router)
except ImportError as e:
    logger.warning("Discovery router not available", extra={"extra_fields": {"error": str(e)}})


class ThreatReportRequest(BaseModel):
    """Request model for threat report generation"""
    tenant_id: str
    tenant_name: Optional[str] = None
    customer_id: Optional[str] = None
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
    orchestration_id: Optional[str] = None
    check_scan_id: Optional[str] = None


#
# DB-first only: removed file/S3 loaders for scan results.
# Threat generation reads from Check DB (check_findings + rule_metadata).


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


@app.get("/api/v1/health/live")
async def liveness():
    """Kubernetes liveness probe — returns 200 if process is alive."""
    return {"status": "alive"}


@app.get("/api/v1/health/ready")
async def readiness():
    """Kubernetes readiness probe — DB ping."""
    try:
        conn = psycopg2.connect(
            host=os.getenv("THREAT_DB_HOST", "localhost"),
            port=int(os.getenv("THREAT_DB_PORT", "5432")),
            dbname=os.getenv("THREAT_DB_NAME", "threat"),
            user=os.getenv("THREAT_DB_USER", "postgres"),
            password=os.getenv("THREAT_DB_PASSWORD", ""),
            connect_timeout=3,
        )
        conn.close()
        return {"status": "ready"}
    except Exception as e:
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=503, content={"status": "not ready", "error": str(e)})


@app.get("/api/v1/health")
async def api_health():
    """Full health check with DB connectivity."""
    try:
        conn = psycopg2.connect(
            host=os.getenv("THREAT_DB_HOST", "localhost"),
            port=int(os.getenv("THREAT_DB_PORT", "5432")),
            dbname=os.getenv("THREAT_DB_NAME", "threat"),
            user=os.getenv("THREAT_DB_USER", "postgres"),
            password=os.getenv("THREAT_DB_PASSWORD", ""),
            connect_timeout=3,
        )
        conn.close()
        return {"status": "healthy", "database": "connected", "service": "engine-threat", "version": "1.0.0"}
    except Exception as e:
        return {"status": "degraded", "database": "disconnected", "error": str(e), "service": "engine-threat", "version": "1.0.0"}


@app.post("/api/v1/scan")
async def generate_threat_report(request: ThreatReportRequest):
    """
    Run threat scan and generate threat report from check results.

    Supports both S3 and local file sources.
    """
    import time
    start_time = time.time()
    
    # Determine check_scan_id and metadata
    # Priority: direct check_scan_id (ad-hoc) > orchestration_id (pipeline)
    check_query_scan_id = None
    tenant_id = None

    if request.check_scan_id:
        # MODE 1: Ad-hoc mode - use provided check_scan_id and tenant_id
        check_query_scan_id = request.check_scan_id
        tenant_id = request.tenant_id
        logger.info(f"Ad-hoc mode: Using direct check_scan_id: {check_query_scan_id}")

    elif request.orchestration_id or request.scan_run_id:
        # MODE 2: Pipeline mode - query scan_orchestration for ALL metadata
        orchestration_id = request.orchestration_id or request.scan_run_id

        try:
            metadata = get_orchestration_metadata(orchestration_id)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))

        check_query_scan_id = metadata.get("check_scan_id")
        if not check_query_scan_id:
            raise HTTPException(status_code=400, detail=f"Check not completed yet for orchestration_id={orchestration_id}")

        # Get ALL metadata from orchestration table
        tenant_id = metadata.get("tenant_id")

        logger.info(f"Pipeline mode: Got metadata from orchestration_id={orchestration_id}", extra={
            "extra_fields": {
                "check_scan_id": check_query_scan_id,
                "tenant_id": tenant_id
            }
        })
    else:
        raise HTTPException(status_code=400, detail="Either check_scan_id OR orchestration_id must be provided")

    with LogContext(
        tenant_id=tenant_id,
        scan_run_id=request.scan_run_id
    ):
        logger.info("Generating threat report", extra={
            "extra_fields": {
                "cloud": request.cloud.value,
                "trigger_type": request.trigger_type.value,
                "check_scan_id": check_query_scan_id,
                "tenant_id": tenant_id
            }
        })

        try:
            # DB-first only: read failures from Check DB and enrich with rule_metadata.
            if os.getenv("THREAT_USE_DATABASE", "true").lower() != "true":
                raise HTTPException(status_code=400, detail="Threat engine is DB-only. Set THREAT_USE_DATABASE=true.")

            logger.info("Loading check results from database with metadata enrichment", extra={
                "extra_fields": {
                    "check_scan_id": check_query_scan_id,
                    "tenant_id": tenant_id
                }
            })

            check_results = get_enriched_check_results(
                scan_id=check_query_scan_id,  # Use the resolved check_scan_id
                schema="check_db",
                status_filter=["FAIL", "WARN"],
                tenant_id=tenant_id,
            )

            if not check_results:
                raise HTTPException(status_code=404, detail=f"No failing check results found in database for check_scan_id={check_query_scan_id}")

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
            
            # Save report to storage (writes to threat_report + threat_findings in threat DB)
            storage.save_report(report)

            # ── Write threat_scan_id back to scan_orchestration (pipeline mode only) ──
            if request.orchestration_id:
                try:
                    threat_scan_id = f"threat_{request.scan_run_id}"
                    from engine_common.orchestration import update_orchestration_scan_id
                    update_orchestration_scan_id(
                        orchestration_id=request.orchestration_id,
                        engine="threat",
                        scan_id=threat_scan_id,
                    )
                    logger.info(f"Updated scan_orchestration with threat_scan_id={threat_scan_id}")
                except Exception as e:
                    logger.error(f"Failed to write threat_scan_id to orchestration: {e}")
                    # Non-fatal — report is saved; downstream engines will fail gracefully

            # ── Run threat analysis (blast radius, risk scoring, attack chains) ──
            analysis_count = 0
            try:
                analyzer = ThreatAnalyzer()
                analyses = analyzer.analyze_scan(
                    tenant_id=request.tenant_id,
                    scan_run_id=request.scan_run_id,
                    orchestration_id=request.orchestration_id,
                )
                if analyses:
                    analysis_count = save_analyses_to_db(analyses)
                    logger.info("Threat analysis complete", extra={
                        "extra_fields": {
                            "analyses_saved": analysis_count,
                            "verdicts": {a["verdict"]: 0 for a in analyses},
                        }
                    })
            except Exception as e:
                logger.warning(f"Threat analysis failed (report still saved): {e}", exc_info=True)

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
                    "findings_count": len(findings),
                    "analyses_count": analysis_count,
                }
            )

            logger.info("Threat report saved", extra={
                "extra_fields": {
                    "threats_count": len(threats),
                    "findings_count": len(findings),
                    "analyses_count": analysis_count,
                }
            })

            report_dict = report.dict()
            report_dict["analysis_summary"] = {
                "analyses_count": analysis_count,
                "verdicts": {},
            }
            if analyses:
                verdict_counts = {}
                for a in analyses:
                    v = a.get("verdict", "unknown")
                    verdict_counts[v] = verdict_counts.get(v, 0) + 1
                report_dict["analysis_summary"]["verdicts"] = verdict_counts
                report_dict["analysis_summary"]["avg_risk_score"] = round(
                    sum(a.get("risk_score", 0) for a in analyses) / len(analyses), 1
                )

            return report_dict
        
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


# ============================================================================
# Threat Analysis Endpoints (MUST be before {threat_id} wildcard)
# ============================================================================

@app.post("/api/v1/threat/analysis/run")
async def run_threat_analysis(
    tenant_id: str = Body(...),
    scan_run_id: str = Body(...),
    orchestration_id: Optional[str] = Body(None),
):
    """
    Run threat analysis (blast radius, risk scoring, attack chains) for a scan.

    Can be called independently or is auto-triggered by /generate.
    Reads threat_detections for the scan, cross-references inventory_relationships,
    and writes results to threat_analysis table.

    If orchestration_id is provided, inventory relationships are scoped to
    the specific pipeline run (via inventory_scan_id lookup in scan_orchestration).
    """
    import time as _time
    start = _time.time()

    try:
        analyzer = ThreatAnalyzer()
        analyses = analyzer.analyze_scan(
            tenant_id=tenant_id,
            scan_run_id=scan_run_id,
            orchestration_id=orchestration_id,
        )

        if not analyses:
            raise HTTPException(status_code=404, detail="No threat detections found for scan")

        count = save_analyses_to_db(analyses)

        # Summarize verdicts
        verdict_counts: Dict[str, int] = {}
        for a in analyses:
            v = a.get("verdict", "unknown")
            verdict_counts[v] = verdict_counts.get(v, 0) + 1

        avg_risk = round(sum(a.get("risk_score", 0) for a in analyses) / len(analyses), 1)

        duration_ms = (_time.time() - start) * 1000

        return {
            "status": "completed",
            "scan_run_id": scan_run_id,
            "analyses_saved": count,
            "verdicts": verdict_counts,
            "avg_risk_score": avg_risk,
            "duration_ms": round(duration_ms, 1),
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Threat analysis failed: {str(e)}")


@app.get("/api/v1/threat/analysis/prioritized")
async def get_prioritized_threats(
    tenant_id: str = Query(...),
    scan_run_id: Optional[str] = Query(None),
    top_n: int = Query(10, ge=1, le=100),
):
    """
    Get top-N prioritized threats by risk score.

    Returns the most critical threats with full analysis context —
    ideal for SOC dashboards and triage workflows.
    """
    try:
        analyses = get_analyses_from_db(
            tenant_id=tenant_id,
            scan_run_id=scan_run_id,
        )

        # Sort by risk score descending (already sorted by DB, but ensure)
        analyses.sort(key=lambda a: a.get("risk_score") or 0, reverse=True)

        top = analyses[:top_n]

        return {
            "prioritized_threats": top,
            "total_analyzed": len(analyses),
            "top_n": top_n,
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get prioritized threats: {str(e)}")


@app.get("/api/v1/threat/analysis/{detection_id}")
async def get_threat_analysis_detail(
    detection_id: str,
    tenant_id: str = Query(...),
):
    """
    Get detailed analysis for a specific threat detection.

    Returns blast radius, attack chain, risk score breakdown, and recommendations.
    """
    try:
        analyses = get_analyses_from_db(
            tenant_id=tenant_id,
            detection_id=detection_id,
        )

        if not analyses:
            raise HTTPException(status_code=404, detail="No analysis found for this detection")

        # Return the most recent analysis
        return analyses[0]

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get analysis: {str(e)}")


@app.get("/api/v1/threat/analysis")
async def list_threat_analyses(
    tenant_id: str = Query(...),
    scan_run_id: Optional[str] = Query(None),
    min_risk_score: Optional[int] = Query(None, ge=0, le=100),
    verdict: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """
    List threat analyses with optional filters.

    Returns prioritized list of analyzed threats with risk scores, verdicts,
    blast radius summaries, and recommendations.
    """
    try:
        analyses = get_analyses_from_db(
            tenant_id=tenant_id,
            scan_run_id=scan_run_id,
        )

        # Apply in-memory filters
        if min_risk_score is not None:
            analyses = [a for a in analyses if (a.get("risk_score") or 0) >= min_risk_score]
        if verdict:
            analyses = [a for a in analyses if a.get("verdict") == verdict]

        total = len(analyses)
        page = analyses[offset:offset + limit]

        # Summarize
        verdicts: Dict[str, int] = {}
        scores = []
        for a in analyses:
            v = a.get("verdict", "unknown")
            verdicts[v] = verdicts.get(v, 0) + 1
            if a.get("risk_score") is not None:
                scores.append(a["risk_score"])

        return {
            "analyses": page,
            "total": total,
            "limit": limit,
            "offset": offset,
            "has_more": (offset + len(page)) < total,
            "summary": {
                "verdicts": verdicts,
                "avg_risk_score": round(sum(scores) / len(scores), 1) if scores else 0,
                "max_risk_score": max(scores) if scores else 0,
            },
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list analyses: {str(e)}")


# ============================================================================
# Single Threat Endpoints (wildcard {threat_id} — must be AFTER specific paths)
# ============================================================================

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
        
        # Build WHERE clause (using threat_detections table)
        where_parts = ["t.tenant_id = %s"]
        params = [tenant_id]

        if scan_run_id:
            where_parts.append("t.scan_id = %s")
            params.append(scan_run_id)

        if severity:
            where_parts.append("t.severity = %s")
            params.append(severity)

        if category:
            where_parts.append("t.threat_category = %s")
            params.append(category)

        if status:
            where_parts.append("t.status = %s")
            params.append(status)

        if resource_uid:
            where_parts.append("t.resource_arn = %s")
            params.append(resource_uid)

        where_clause = " AND ".join(where_parts)

        # Get total count
        with conn.cursor() as cur:
            cur.execute(f"SELECT COUNT(*) FROM threat_detections t WHERE {where_clause}", params)
            total = cur.fetchone()[0]

        # Get paginated results
        query = f"""
            SELECT
                t.detection_id as threat_id, t.scan_id as scan_run_id,
                t.detection_type as threat_type, t.threat_category as category,
                t.severity, t.confidence, t.status, t.rule_name as title,
                t.rule_id as primary_rule_id,
                t.resource_arn, t.resource_type, t.account_id, t.region,
                t.mitre_techniques, t.mitre_tactics,
                t.first_seen_at, t.last_seen_at, t.resolved_at
            FROM threat_detections t
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
        
        # Get threat details from threat_detections
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT
                    detection_id as threat_id, scan_id as scan_run_id,
                    detection_type as threat_type, threat_category as category,
                    severity, confidence, status, rule_name as title,
                    rule_id, resource_arn, resource_id, resource_type,
                    account_id, region, provider,
                    mitre_techniques, mitre_tactics,
                    evidence, context,
                    first_seen_at, last_seen_at, resolved_at
                FROM threat_detections
                WHERE detection_id = %s::uuid AND tenant_id = %s
            """, (threat_id, tenant_id))
            threat = cur.fetchone()

        if not threat:
            raise HTTPException(status_code=404, detail="Threat not found")

        # Extract affected resources from evidence JSONB
        evidence_data = threat.get('evidence') or {}
        affected_resources = evidence_data.get('affected_assets', [])

        conn.close()

        result = dict(threat)
        result["affected_resources"] = affected_resources
        return result
        
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
                    SELECT DISTINCT check_scan_id FROM check_findings
                    WHERE tenant_id = %s
                    ORDER BY check_scan_id DESC LIMIT 1
                """, (tenant_id,))
                row = cur.fetchone()
                scan_id = row[0] if row else None

        if not scan_id:
            raise HTTPException(status_code=404, detail="No scans found for tenant")

        # Get resource posture from check_findings + rule_metadata
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT
                    cf.resource_uid,
                    cf.resource_type,
                    cf.resource_arn,
                    cf.hierarchy_id as account_id,
                    COUNT(*) as total_checks,
                    COUNT(*) FILTER (WHERE cf.status = 'PASS') as passed,
                    COUNT(*) FILTER (WHERE cf.status = 'FAIL') as failed,
                    COUNT(*) FILTER (WHERE cf.status = 'WARN') as warnings,
                    COUNT(*) FILTER (WHERE cf.status = 'ERROR') as errors,
                    jsonb_agg(cf.rule_id) FILTER (WHERE cf.status = 'FAIL') as failed_rule_ids,
                    COUNT(*) FILTER (WHERE rm.severity = 'critical' AND cf.status = 'FAIL') as critical_failures,
                    COUNT(*) FILTER (WHERE rm.severity = 'high' AND cf.status = 'FAIL') as high_failures,
                    COUNT(*) FILTER (WHERE rm.severity = 'medium' AND cf.status = 'FAIL') as medium_failures,
                    MAX(cf.created_at) as last_scanned
                FROM check_findings cf
                LEFT JOIN rule_metadata rm ON cf.rule_id = rm.rule_id
                WHERE cf.tenant_id = %s AND cf.check_scan_id = %s AND cf.resource_uid = %s
                GROUP BY cf.resource_uid, cf.resource_type, cf.resource_arn, cf.hierarchy_id
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
    Query drift detections from threat_detections table.

    Drift-type threats (configuration_drift, check_status_drift) are stored
    in threat_detections with detection_type containing 'drift'.
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

        # Build WHERE clause - filter drift-type detections
        where_parts = ["tenant_id = %s", "detection_type LIKE '%drift%'"]
        params = [tenant_id]

        if current_scan_id:
            where_parts.append("scan_id = %s")
            params.append(current_scan_id)

        if status:
            where_parts.append("status = %s")
            params.append(status)

        where_clause = " AND ".join(where_parts)

        # Get total count
        with conn.cursor() as cur:
            cur.execute(f"SELECT COUNT(*) FROM threat_detections WHERE {where_clause}", params)
            total = cur.fetchone()[0]

        # Get paginated results
        query = f"""
            SELECT
                detection_id, detection_type, resource_arn, resource_type,
                account_id, region, severity, status,
                rule_id, rule_name, mitre_techniques, mitre_tactics,
                evidence, context,
                first_seen_at, last_seen_at, detection_timestamp
            FROM threat_detections
            WHERE {where_clause}
            ORDER BY detection_timestamp DESC
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
        
        # Build query using threat_detections (resource_arn matches resource_uid)
        where_parts = ["t.resource_arn = %s", "t.tenant_id = %s"]
        params = [resource_uid, tenant_id]

        if scan_run_id:
            where_parts.append("t.scan_id = %s")
            params.append(scan_run_id)

        where_clause = " AND ".join(where_parts)

        query = f"""
            SELECT
                t.detection_id as threat_id, t.scan_id as scan_run_id,
                t.detection_type as threat_type, t.threat_category as category,
                t.severity, t.status, t.rule_name as title,
                t.rule_id, t.mitre_techniques, t.mitre_tactics,
                t.first_seen_at, t.last_seen_at
            FROM threat_detections t
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
    """Get threat scan summary from threat_report table"""
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
                SELECT
                    threat_scan_id, scan_run_id, provider as cloud,
                    total_findings as total_threats,
                    critical_findings, high_findings, medium_findings, low_findings,
                    threat_score, status,
                    started_at, completed_at, created_at,
                    report_data
                FROM threat_report
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


# ============================================================================
# Security Graph Endpoints (Neo4j)
# ============================================================================

@app.post("/api/v1/graph/build")
async def build_security_graph(
    tenant_id: str = Body(..., embed=True),
):
    """
    Build/rebuild the Neo4j security graph for a tenant.

    Loads data from all 3 PostgreSQL databases (inventory, checks, threats)
    and creates nodes + relationships in Neo4j.
    """
    import asyncio
    import time as _time
    start = _time.time()

    def _run_build() -> dict:
        builder = SecurityGraphBuilder()
        try:
            return builder.build_graph(tenant_id=tenant_id)
        finally:
            builder.close()

    try:
        # Run blocking Neo4j/PostgreSQL operations in a thread pool so the
        # asyncio event loop stays free (liveness probe can still respond).
        loop = asyncio.get_event_loop()
        stats = await loop.run_in_executor(None, _run_build)

        duration_ms = (_time.time() - start) * 1000

        return {
            "status": "completed",
            "tenant_id": tenant_id,
            "stats": stats,
            "duration_ms": round(duration_ms, 1),
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Graph build failed: {str(e)}")


@app.get("/api/v1/graph/summary")
async def get_graph_summary(
    tenant_id: str = Query(...),
):
    """Get summary statistics of the security graph."""
    try:
        gq = SecurityGraphQueries()
        summary = gq.graph_summary(tenant_id=tenant_id)
        gq.close()
        return summary
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Graph query failed: {str(e)}")


@app.get("/api/v1/graph/attack-paths")
async def get_attack_paths(
    tenant_id: str = Query(...),
    max_hops: int = Query(5, ge=1, le=10),
    min_severity: str = Query("high"),
):
    """
    Find attack paths from Internet to resources with threats.

    This is the core "Wiz-style" attack path query.
    """
    try:
        gq = SecurityGraphQueries()
        paths = gq.attack_paths_from_internet(
            tenant_id=tenant_id, max_hops=max_hops, min_severity=min_severity
        )
        gq.close()

        return {
            "attack_paths": paths,
            "total": len(paths),
            "filters": {"max_hops": max_hops, "min_severity": min_severity},
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Attack path query failed: {str(e)}")


@app.get("/api/v1/graph/blast-radius/{resource_uid:path}")
async def get_graph_blast_radius(
    resource_uid: str,
    tenant_id: str = Query(...),
    max_hops: int = Query(5, ge=1, le=10),
):
    """
    Compute blast radius from a specific resource using Neo4j graph traversal.

    Returns reachable resources, depth distribution, and threat overlap.
    """
    try:
        gq = SecurityGraphQueries()
        result = gq.blast_radius(
            resource_uid=resource_uid, tenant_id=tenant_id, max_hops=max_hops
        )
        gq.close()
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Blast radius query failed: {str(e)}")


@app.get("/api/v1/graph/internet-exposed")
async def get_internet_exposed(
    tenant_id: str = Query(...),
):
    """Find all resources exposed to the internet."""
    try:
        gq = SecurityGraphQueries()
        exposed = gq.internet_exposed_resources(tenant_id=tenant_id)
        gq.close()
        return {
            "exposed_resources": exposed,
            "total": len(exposed),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Exposure query failed: {str(e)}")


@app.get("/api/v1/graph/toxic-combinations")
async def get_toxic_combinations(
    tenant_id: str = Query(...),
    min_threats: int = Query(2, ge=1),
):
    """Find resources with multiple overlapping threat detections."""
    try:
        gq = SecurityGraphQueries()
        results = gq.toxic_combinations(tenant_id=tenant_id, min_threats=min_threats)
        gq.close()
        return {
            "toxic_combinations": results,
            "total": len(results),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Toxic combination query failed: {str(e)}")


@app.get("/api/v1/graph/resource/{resource_uid:path}")
async def get_resource_graph_context(
    resource_uid: str,
    tenant_id: str = Query(...),
):
    """Get complete graph context for a single resource."""
    try:
        gq = SecurityGraphQueries()
        context = gq.resource_context(resource_uid=resource_uid, tenant_id=tenant_id)
        gq.close()
        return context
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Resource context query failed: {str(e)}")


# ============================================================================
# Threat Intelligence Endpoints
# ============================================================================

@app.post("/api/v1/intel/feed")
async def ingest_intel(
    intel: Dict[str, Any] = Body(...),
):
    """
    Ingest a single threat intelligence entry.

    Required: tenant_id, source, intel_type, severity, confidence, threat_data
    """
    try:
        intel_id = save_intel(intel)
        return {"intel_id": intel_id, "status": "saved"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save intel: {str(e)}")


@app.post("/api/v1/intel/feed/batch")
async def ingest_intel_batch(
    items: List[Dict[str, Any]] = Body(...),
):
    """Ingest multiple threat intelligence entries."""
    try:
        count = save_intel_batch(items)
        return {"saved": count, "total": len(items)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Batch intel failed: {str(e)}")


@app.get("/api/v1/intel")
async def list_intel(
    tenant_id: str = Query(...),
    intel_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    active_only: bool = Query(True),
    limit: int = Query(100, ge=1, le=1000),
):
    """List threat intelligence entries with optional filters."""
    try:
        results = get_intel(
            tenant_id=tenant_id, intel_type=intel_type,
            severity=severity, source=source,
            active_only=active_only, limit=limit,
        )
        return {"intel": results, "total": len(results)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list intel: {str(e)}")


@app.get("/api/v1/intel/correlate")
async def correlate_intel(
    tenant_id: str = Query(...),
):
    """
    Correlate threat intelligence with existing threat detections.

    Matches by MITRE technique overlap.
    """
    try:
        correlations = correlate_intel_with_threats(tenant_id=tenant_id)
        return {
            "correlations": correlations,
            "total": len(correlations),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Correlation failed: {str(e)}")


# ============================================================================
# Threat Hunting Endpoints
# ============================================================================

@app.post("/api/v1/hunt/queries")
async def create_hunt_query(
    query: Dict[str, Any] = Body(...),
):
    """
    Save a new threat hunt query.

    Required: tenant_id, query_name, query_text
    Optional: hunt_type, query_language, mitre_tactics, mitre_techniques, tags
    """
    try:
        hunt_id = save_hunt_query(query)
        return {"hunt_id": hunt_id, "status": "saved"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save hunt query: {str(e)}")


@app.get("/api/v1/hunt/queries")
async def list_hunt_queries(
    tenant_id: str = Query(...),
    active_only: bool = Query(True),
    limit: int = Query(100),
):
    """List saved threat hunt queries."""
    try:
        queries = get_hunt_queries(tenant_id=tenant_id, active_only=active_only, limit=limit)
        return {"queries": queries, "total": len(queries)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list hunt queries: {str(e)}")


@app.get("/api/v1/hunt/predefined")
async def list_predefined_hunts():
    """List pre-defined threat hunt queries (built into the system)."""
    gq = SecurityGraphQueries()
    hunts = gq.list_predefined_hunts()
    gq.close()
    return {"hunts": hunts, "total": len(hunts)}


@app.post("/api/v1/hunt/execute")
async def execute_hunt(
    tenant_id: str = Body(...),
    hunt_id: Optional[str] = Body(None),
    predefined_id: Optional[str] = Body(None),
    cypher: Optional[str] = Body(None),
):
    """
    Execute a threat hunt query.

    Provide ONE of:
      - hunt_id: Execute a saved query from threat_hunt_queries
      - predefined_id: Execute a built-in hunt (internet_to_sensitive_data, etc.)
      - cypher: Execute an ad-hoc Cypher query (read-only)
    """
    import time as _time
    start = _time.time()

    try:
        gq = SecurityGraphQueries()
        results = []

        if hunt_id:
            # Load saved query
            q = get_hunt_query(hunt_id)
            if not q:
                raise HTTPException(status_code=404, detail="Hunt query not found")
            cypher_text = q["query_text"]
            results = gq.execute_hunt_query(cypher_text, tenant_id=tenant_id)
            query_name = q["query_name"]

        elif predefined_id:
            results = gq.run_predefined_hunt(predefined_id, tenant_id=tenant_id)
            query_name = predefined_id

        elif cypher:
            results = gq.execute_hunt_query(cypher, tenant_id=tenant_id)
            query_name = "ad_hoc"

        else:
            raise HTTPException(status_code=400, detail="Provide hunt_id, predefined_id, or cypher")

        gq.close()

        duration_ms = (_time.time() - start) * 1000

        # Save result to DB
        result_data = {
            "hunt_id": hunt_id or predefined_id or "ad_hoc",
            "tenant_id": tenant_id,
            "total_results": len(results),
            "new_detections": 0,
            "execution_time_ms": int(duration_ms),
            "results_data": {"query_name": query_name, "results": results[:500]},
            "status": "completed",
        }

        # Only save to DB if it was a saved hunt_id
        result_id = None
        if hunt_id:
            try:
                result_id = save_hunt_result(result_data)
            except Exception as e:
                logger.warning(f"Failed to save hunt result: {e}")

        return {
            "status": "completed",
            "query_name": query_name,
            "results": results,
            "total": len(results),
            "execution_time_ms": round(duration_ms, 1),
            "result_id": result_id,
        }

    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Hunt execution failed: {str(e)}")


@app.get("/api/v1/hunt/results")
async def list_hunt_results(
    tenant_id: str = Query(...),
    hunt_id: Optional[str] = Query(None),
    limit: int = Query(50),
):
    """List previous hunt execution results."""
    try:
        results = get_hunt_results(tenant_id=tenant_id, hunt_id=hunt_id, limit=limit)
        return {"results": results, "total": len(results)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list hunt results: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)

