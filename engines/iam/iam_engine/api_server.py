"""
FastAPI server for IAM Security Engine.

Provides endpoints for IAM posture queries and report generation.
"""

import sys
import os
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Any

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))
from engine_common.logger import setup_logger, LogContext, log_duration, audit_log
from engine_common.telemetry import configure_telemetry
from engine_common.middleware import RequestLoggingMiddleware, CorrelationIDMiddleware
from engine_common.orchestration import get_orchestration_metadata

from .input.threat_db_reader import ThreatDBReader
from .enricher.finding_enricher import FindingEnricher
from .reporter.iam_reporter import IAMReporter
from .storage.report_storage import ReportStorage

import json

logger = setup_logger(__name__, engine_name="engine-iam")

app = FastAPI(
    title="IAM Security Engine API",
    description="Identity & Access Management posture for CSPM - least privilege, MFA, policy, roles",
    version="1.0.0",
)
configure_telemetry("engine-iam", app)

app.add_middleware(CorrelationIDMiddleware)
app.add_middleware(RequestLoggingMiddleware, engine_name="engine-iam")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

threat_db_reader = ThreatDBReader()
finding_enricher = FindingEnricher()
reporter = IAMReporter()
report_storage = ReportStorage()


class ScanRequest(BaseModel):
    """Request to generate IAM security report."""
    csp: str = Field(..., description="Cloud service provider (e.g., 'aws')")
    scan_id: Optional[str] = Field(default=None, description="Threat scan_run_id (from Threat engine) - for ad-hoc mode")
    orchestration_id: Optional[str] = Field(default=None, description="Orchestration ID - for pipeline mode")
    tenant_id: str = Field(default="default-tenant", description="Tenant ID")
    max_findings: Optional[int] = Field(default=None, description="Max findings to process")


class ReportResponse(BaseModel):
    """IAM security report response."""
    schema_version: str
    tenant_id: str
    scan_context: Dict[str, Any]
    summary: Dict[str, Any]
    findings: List[Dict[str, Any]]


@app.get("/")
async def root():
    return {"service": "IAM Security Engine", "version": "1.0.0", "status": "operational"}


@app.get("/health")
async def health():
    import time
    start = time.time()
    health_status = {"status": "healthy"}
    logger.info("Health check", extra={"extra_fields": {"status": "healthy", "duration_ms": (time.time() - start) * 1000}})
    return health_status


@app.get("/api/v1/health/live")
async def liveness():
    """Kubernetes liveness probe — returns 200 if process is alive."""
    return {"status": "alive"}


@app.get("/api/v1/health/ready")
async def readiness():
    """Kubernetes readiness probe — returns 200 when ready to serve traffic."""
    return {"status": "ready"}


@app.get("/api/v1/health")
async def api_health():
    """Full health check with DB connectivity."""
    try:
        import psycopg2
        conn = psycopg2.connect(
            host=os.getenv("THREAT_DB_HOST", "localhost"),
            port=int(os.getenv("THREAT_DB_PORT", "5432")),
            dbname=os.getenv("THREAT_DB_NAME", "threat"),
            user=os.getenv("THREAT_DB_USER", "postgres"),
            password=os.getenv("THREAT_DB_PASSWORD", ""),
            connect_timeout=3,
        )
        conn.close()
        return {"status": "healthy", "database": "connected", "service": "engine-iam", "version": "1.0.0"}
    except Exception as e:
        return {"status": "degraded", "database": "disconnected", "error": str(e), "service": "engine-iam", "version": "1.0.0"}


@app.post("/api/v1/iam-security/scan", response_model=ReportResponse)
async def generate_report(request: ScanRequest):
    """Generate IAM security report (findings filtered by IAM-relevant rules, enriched)."""
    import time
    start_time = time.time()

    # Determine threat_scan_id and tenant_id
    # Priority: direct scan_id (ad-hoc) > orchestration_id (pipeline)
    threat_scan_id = None
    tenant_id = request.tenant_id

    if request.scan_id:
        # MODE 1: Ad-hoc mode - use provided threat scan_id
        threat_scan_id = request.scan_id
        logger.info(f"Ad-hoc mode: Using direct threat_scan_id: {threat_scan_id}")

    elif request.orchestration_id:
        # MODE 2: Pipeline mode - query scan_orchestration for threat_scan_id
        try:
            metadata = get_orchestration_metadata(request.orchestration_id)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))

        threat_scan_id = metadata.get("threat_scan_id")
        if not threat_scan_id:
            raise HTTPException(status_code=400, detail=f"Threat scan not completed yet for orchestration_id={request.orchestration_id}")

        # Get tenant_id and csp from orchestration metadata
        tenant_id = metadata.get("tenant_id") or request.tenant_id
        orchestration_csp = metadata.get("provider") or metadata.get("provider_type") or metadata.get("csp")
        if orchestration_csp:
            request = request.model_copy(update={"csp": orchestration_csp.lower()})

        logger.info(f"Pipeline mode: Got threat_scan_id={threat_scan_id} from orchestration_id={request.orchestration_id}, csp={request.csp}")

    else:
        raise HTTPException(status_code=400, detail="Either scan_id OR orchestration_id must be provided")

    with LogContext(tenant_id=tenant_id, scan_run_id=threat_scan_id):
        try:
            report = reporter.generate_report(
                csp=request.csp,
                scan_id=threat_scan_id,
                tenant_id=tenant_id,
                max_findings=request.max_findings,
            )
            
            # Add report_id if missing
            if "report_id" not in report:
                import uuid
                report["report_id"] = str(uuid.uuid4())
            
            # Save to local file storage
            try:
                report_path = report_storage.save_report(
                    report=report,
                    tenant_id=tenant_id,
                    scan_id=threat_scan_id
                )
                logger.info(f"IAM report saved to: {report_path}")
            except Exception as e:
                logger.error(f"Error saving IAM report to file storage: {e}")

            # Save to /output for S3 sync
            try:
                output_dir = os.getenv("OUTPUT_DIR", "/output")
                if output_dir and os.path.exists(output_dir):
                    iam_dir = os.path.join(output_dir, "iam", tenant_id, threat_scan_id)
                    os.makedirs(iam_dir, exist_ok=True)

                    with open(os.path.join(iam_dir, "iam_report.json"), "w") as f:
                        json.dump(report, f, indent=2, default=str)

                    logger.info(f"IAM report saved to {iam_dir}")
            except Exception as e:
                logger.error(f"Error saving IAM report to output dir: {e}")

            # Save to database
            try:
                from .storage.iam_db_writer import save_iam_report_to_db
                saved_id = save_iam_report_to_db(report)
                logger.info(f"IAM report saved to database: {saved_id}")
            except Exception as e:
                logger.error(f"Error saving IAM report to database: {e}", exc_info=True)

            # Update scan_orchestration with iam_scan_id (if in pipeline mode)
            if request.orchestration_id:
                try:
                    from engine_common.orchestration import update_orchestration_scan_id
                    iam_scan_id = report.get("report_id")
                    update_orchestration_scan_id(
                        orchestration_id=request.orchestration_id,
                        engine="iam",
                        scan_id=iam_scan_id,
                    )
                    logger.info(f"Updated scan_orchestration with iam_scan_id: {iam_scan_id}")
                except Exception as e:
                    logger.error(f"Failed to update scan_orchestration: {e}")
                    # Non-fatal — report is saved; this is tracking only
            
            duration_ms = (time.time() - start_time) * 1000
            log_duration(logger, "IAM security report generated", duration_ms)
            audit_log(
                logger,
                "iam_report_generated",
                f"scan:{request.scan_id}",
                tenant_id=request.tenant_id,
                result="success",
                details={"csp": request.csp, "findings_count": len(report.get("findings", []))},
            )
            return report
        except Exception as e:
            logger.error("Error generating IAM report", exc_info=True, extra={"extra_fields": {"error": str(e), "scan_id": request.scan_id}})
            audit_log(logger, "iam_report_generation_failed", f"scan:{request.scan_id}", tenant_id=request.tenant_id, result="failure", details={"error": str(e)})
            raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/iam-security/rules/{rule_id}")
async def get_rule_info(rule_id: str):
    """Get IAM security info for a rule based on rule_id pattern."""
    from .mapper.rule_to_module_mapper import _is_iam_relevant, _derive_modules
    is_relevant = _is_iam_relevant(rule_id)
    modules = _derive_modules(rule_id) if is_relevant else []
    return {
        "rule_id": rule_id,
        "is_iam_relevant": is_relevant,
        "iam_security_modules": modules,
    }


@app.get("/api/v1/iam-security/modules")
async def list_modules():
    """List IAM security modules."""
    from .mapper.rule_to_module_mapper import MODULE_KEYWORDS
    return {"modules": list(MODULE_KEYWORDS.keys())}


@app.get("/api/v1/iam-security/findings")
async def get_findings(
    csp: str = Query(default="aws", description="Cloud service provider"),
    scan_id: str = Query(default="latest", description="Threat scan_run_id (from Threat engine)"),
    tenant_id: str = Query(default="default-tenant", description="Tenant ID"),
    account_id: Optional[str] = Query(None),
    hierarchy_id: Optional[str] = Query(None),
    service: Optional[str] = Query(None),
    module: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    resource_id: Optional[str] = Query(None),
):
    """Get IAM security findings from Threat DB with optional filters."""
    try:
        # Load all findings and enrich (IAM relevance determined by rule_id pattern)
        findings = threat_db_reader.get_misconfig_findings(
            tenant_id=tenant_id,
            scan_run_id=scan_id
        )
        enriched = finding_enricher.enrich_findings(findings)
        # Keep only IAM-relevant findings
        enriched = [f for f in enriched if f.get("is_iam_relevant", False)]
        if account_id:
            enriched = [f for f in enriched if f.get("account_id") == account_id]
        if hierarchy_id:
            enriched = [f for f in enriched if f.get("hierarchy_id") == hierarchy_id]
        if service:
            enriched = [f for f in enriched if (f.get("service") or "").lower() == service.lower()]
        if module:
            enriched = [f for f in enriched if module in f.get("iam_security_modules", [])]
        if status:
            enriched = [f for f in enriched if f.get("status") == status.upper()]
        if resource_id:
            enriched = [f for f in enriched if resource_id in (f.get("resource_uid") or "") or resource_id in (f.get("resource_arn") or "")]
        summary = {"total_findings": len(enriched), "by_module": {}, "by_status": {}}
        for f in enriched:
            summary["by_status"][f.get("status", "UNKNOWN")] = summary["by_status"].get(f.get("status", "UNKNOWN"), 0) + 1
            for m in f.get("iam_security_modules", []):
                summary["by_module"][m] = summary["by_module"].get(m, 0) + 1
        return {"filters": {"account_id": account_id, "hierarchy_id": hierarchy_id, "service": service, "module": module, "status": status, "resource_id": resource_id}, "summary": summary, "findings": enriched}
    except Exception as e:
        logger.error(f"Error getting IAM findings: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/iam-security/rule-ids")
async def get_iam_rule_ids():
    """Get info about IAM rule identification patterns."""
    from .mapper.rule_to_module_mapper import IAM_RULE_PATTERNS
    return {
        "method": "rule_id_pattern_matching",
        "patterns": [p.pattern for p in IAM_RULE_PATTERNS],
        "description": "IAM relevance is determined by matching rule_id against these patterns",
    }


@app.get("/api/v1/iam-security/accounts/{account_id}")
async def get_account_iam_posture(
    account_id: str,
    csp: str = Query(default="aws", description="Cloud service provider"),
    scan_id: str = Query(default="latest", description="Threat scan_run_id"),
    tenant_id: str = Query(default="default-tenant", description="Tenant ID"),
    module: Optional[str] = Query(None, description="Filter by IAM module"),
    status: Optional[str] = Query(None, description="Filter by status (PASS/FAIL)"),
):
    """Get IAM security posture for a specific account from Threat DB."""
    try:
        findings = threat_db_reader.get_misconfig_findings(tenant_id=tenant_id, scan_run_id=scan_id)
        enriched = finding_enricher.enrich_findings(findings)
        enriched = [f for f in enriched if f.get("is_iam_relevant", False) and f.get("account_id") == account_id]
        if module:
            enriched = [f for f in enriched if module in f.get("iam_security_modules", [])]
        if status:
            enriched = [f for f in enriched if f.get("status") == status.upper()]
        summary = {
            "account_id": account_id,
            "total_findings": len(enriched),
            "findings_by_status": {},
            "findings_by_module": {},
            "findings_by_severity": {},
        }
        for f in enriched:
            s = f.get("status", "UNKNOWN")
            summary["findings_by_status"][s] = summary["findings_by_status"].get(s, 0) + 1
            sev = f.get("severity", "unknown")
            summary["findings_by_severity"][sev] = summary["findings_by_severity"].get(sev, 0) + 1
            for m in f.get("iam_security_modules", []):
                summary["findings_by_module"][m] = summary["findings_by_module"].get(m, 0) + 1
        return {"account_id": account_id, "summary": summary, "findings": enriched}
    except Exception as e:
        logger.error(f"Error getting account IAM posture: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/iam-security/services/{service}")
async def get_service_iam_posture(
    service: str,
    csp: str = Query(default="aws", description="Cloud service provider"),
    scan_id: str = Query(default="latest", description="Threat scan_run_id"),
    tenant_id: str = Query(default="default-tenant", description="Tenant ID"),
    account_id: Optional[str] = Query(None, description="Filter by account ID"),
    module: Optional[str] = Query(None, description="Filter by IAM module"),
):
    """Get IAM security posture for a specific service (e.g. iam, sts, cognito) from Threat DB."""
    try:
        findings = threat_db_reader.get_misconfig_findings(tenant_id=tenant_id, scan_run_id=scan_id)
        enriched = finding_enricher.enrich_findings(findings)
        enriched = [
            f for f in enriched
            if f.get("is_iam_relevant", False) and service.lower() in (f.get("service") or "").lower()
        ]
        if account_id:
            enriched = [f for f in enriched if f.get("account_id") == account_id]
        if module:
            enriched = [f for f in enriched if module in f.get("iam_security_modules", [])]
        summary = {
            "service": service,
            "total_findings": len(enriched),
            "findings_by_status": {},
            "findings_by_module": {},
            "accounts": list({f.get("account_id", "") for f in enriched}),
        }
        for f in enriched:
            s = f.get("status", "UNKNOWN")
            summary["findings_by_status"][s] = summary["findings_by_status"].get(s, 0) + 1
            for m in f.get("iam_security_modules", []):
                summary["findings_by_module"][m] = summary["findings_by_module"].get(m, 0) + 1
        return {"service": service, "account_id": account_id, "summary": summary, "findings": enriched}
    except Exception as e:
        logger.error(f"Error getting service IAM posture: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/iam-security/resources/{resource_uid}")
async def get_resource_iam_findings(
    resource_uid: str,
    csp: str = Query(default="aws", description="Cloud service provider"),
    scan_id: str = Query(default="latest", description="Threat scan_run_id"),
    tenant_id: str = Query(default="default-tenant", description="Tenant ID"),
):
    """Get IAM findings for a specific resource (by resource_uid or ARN) from Threat DB."""
    try:
        findings = threat_db_reader.get_findings_by_resource(
            tenant_id=tenant_id, scan_run_id=scan_id, resource_uid=resource_uid
        )
        enriched = finding_enricher.enrich_findings(findings)
        iam_findings = [f for f in enriched if f.get("is_iam_relevant", False)]
        return {
            "resource_uid": resource_uid,
            "total_findings": len(iam_findings),
            "findings": iam_findings,
        }
    except Exception as e:
        logger.error(f"Error getting resource IAM findings: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ── Standard route aliases ─────────────────────────────────────────────────────
# POST /api/v1/scan — standard scan alias (same handler as /api/v1/iam-security/scan)
app.add_api_route("/api/v1/scan", generate_report, methods=["POST"], response_model=ReportResponse)

# GET /api/v1/iam/* — standard prefix aliases for all /api/v1/iam-security/* routes
from fastapi import APIRouter as _APIRouter
_iam_router = _APIRouter(prefix="/api/v1/iam")
_iam_router.add_api_route("/findings", get_findings, methods=["GET"])
_iam_router.add_api_route("/modules", list_modules, methods=["GET"])
_iam_router.add_api_route("/rule-ids", get_iam_rule_ids, methods=["GET"])
_iam_router.add_api_route("/rules/{rule_id}", get_rule_info, methods=["GET"])
_iam_router.add_api_route("/accounts/{account_id}", get_account_iam_posture, methods=["GET"])
_iam_router.add_api_route("/services/{service}", get_service_iam_posture, methods=["GET"])
_iam_router.add_api_route("/resources/{resource_uid}", get_resource_iam_findings, methods=["GET"])
app.include_router(_iam_router)


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("IAM_ENGINE_PORT", "8003"))  # Changed from 8001 to avoid conflict
    uvicorn.run(app, host="0.0.0.0", port=port)
