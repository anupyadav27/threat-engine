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
from engine_common.middleware import RequestLoggingMiddleware, CorrelationIDMiddleware

from .input.threat_db_reader import ThreatDBReader
from .input.rule_db_reader import RuleDBReader
from .enricher.finding_enricher import FindingEnricher
from .reporter.iam_reporter import IAMReporter
from .storage.report_storage import ReportStorage

logger = setup_logger(__name__, engine_name="engine-iam")

app = FastAPI(
    title="IAM Security Engine API",
    description="Identity & Access Management posture for CSPM - least privilege, MFA, policy, roles",
    version="1.0.0",
)

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
rule_db_reader = RuleDBReader()
finding_enricher = FindingEnricher()
reporter = IAMReporter()
report_storage = ReportStorage()


class ScanRequest(BaseModel):
    """Request to generate IAM security report."""
    csp: str = Field(..., description="Cloud service provider (e.g., 'aws')")
    scan_id: str = Field(..., description="Threat scan_run_id (from Threat engine)")
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


@app.post("/api/v1/iam-security/scan", response_model=ReportResponse)
async def generate_report(request: ScanRequest):
    """Generate IAM security report (findings filtered by IAM-relevant rules, enriched)."""
    import time
    start_time = time.time()
    with LogContext(tenant_id=request.tenant_id, scan_run_id=request.scan_id):
        try:
            report = reporter.generate_report(
                csp=request.csp,
                scan_id=request.scan_id,
                tenant_id=request.tenant_id,
                max_findings=request.max_findings,
            )
            
            # Save report to engine_output/iam/reports/
            try:
                report_path = report_storage.save_report(
                    report=report,
                    tenant_id=request.tenant_id,
                    scan_id=request.scan_id
                )
                logger.info(f"IAM report saved to: {report_path}")
            except Exception as e:
                logger.error(f"Error saving IAM report to storage: {e}")
            
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
async def get_rule_info(rule_id: str, service: Optional[str] = None):
    """Get IAM security info for a rule."""
    if not service:
        parts = rule_id.split(".")
        if len(parts) >= 2:
            service = parts[1]
    if not service:
        raise HTTPException(status_code=400, detail="Could not determine service from rule_id")
    metadata = rule_db_reader.read_metadata(service, rule_id)
    if not metadata:
        raise HTTPException(status_code=404, detail=f"Rule not found: {rule_id}")
    iam_security = rule_db_reader.get_iam_security_info(service, rule_id)
    return {"rule_id": rule_id, "metadata": metadata, "iam_security": iam_security}


@app.get("/api/v1/iam-security/modules")
async def list_modules():
    """List IAM security modules."""
    from .input.rule_db_reader import IAM_MODULES
    return {"modules": IAM_MODULES}


@app.get("/api/v1/iam-security/modules/{module}/rules")
async def get_rules_by_module(
    module: str,
    service: Optional[str] = Query(None, description="Filter by service"),
):
    """Get rules for a specific IAM module."""
    try:
        services = [service] if service else rule_db_reader.list_services()
        rules = {}
        for svc in services:
            rule_list = rule_db_reader.get_rules_by_module(svc, module)
            if rule_list:
                rules[svc] = rule_list
        return {"module": module, "rules": rules}
    except Exception as e:
        logger.error(f"Error getting rules by module: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/iam-security/findings")
async def get_findings(
    csp: str = Query(..., description="Cloud service provider"),
    scan_id: str = Query(..., description="Threat scan_run_id (from Threat engine)"),
    tenant_id: str = Query(default="default-tenant", description="Tenant ID"),
    account_id: Optional[str] = Query(None),
    service: Optional[str] = Query(None),
    module: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    resource_id: Optional[str] = Query(None),
):
    """Get IAM security findings from Threat DB with optional filters."""
    try:
        iam_rule_ids = rule_db_reader.get_all_iam_security_rule_ids()
        findings = threat_db_reader.get_misconfig_findings(
            tenant_id=tenant_id,
            scan_run_id=scan_id,
            iam_rule_ids=iam_rule_ids
        )
        enriched = finding_enricher.enrich_findings(findings)
        if account_id:
            enriched = [f for f in enriched if f.get("account_id") == account_id]
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
        return {"filters": {"account_id": account_id, "service": service, "module": module, "status": status, "resource_id": resource_id}, "summary": summary, "findings": enriched}
    except Exception as e:
        logger.error(f"Error getting IAM findings: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/iam-security/rule-ids")
async def get_iam_rule_ids(service: Optional[str] = Query(None, description="Filter by service")):
    """Get set of all IAM-relevant rule IDs (for pre-filtering)."""
    try:
        services = [service] if service else None
        ids = rule_db_reader.get_all_iam_security_rule_ids(services=services)
        return {"count": len(ids), "rule_ids": sorted(ids)}
    except Exception as e:
        logger.error(f"Error getting IAM rule IDs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("IAM_ENGINE_PORT", "8003"))  # Changed from 8001 to avoid conflict
    uvicorn.run(app, host="0.0.0.0", port=port)
