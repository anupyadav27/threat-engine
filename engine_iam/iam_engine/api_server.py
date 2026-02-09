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
            
            # Add report_id if missing
            if "report_id" not in report:
                import uuid
                report["report_id"] = str(uuid.uuid4())
            
            # Save to local file storage
            try:
                report_path = report_storage.save_report(
                    report=report,
                    tenant_id=request.tenant_id,
                    scan_id=request.scan_id
                )
                logger.info(f"IAM report saved to: {report_path}")
            except Exception as e:
                logger.error(f"Error saving IAM report to file storage: {e}")
            
            # Save to /output for S3 sync
            try:
                output_dir = os.getenv("OUTPUT_DIR", "/output")
                if output_dir and os.path.exists(output_dir):
                    iam_dir = os.path.join(output_dir, "iam", request.tenant_id, request.scan_id)
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
async def get_iam_rule_ids():
    """Get info about IAM rule identification patterns."""
    from .mapper.rule_to_module_mapper import IAM_RULE_PATTERNS
    return {
        "method": "rule_id_pattern_matching",
        "patterns": [p.pattern for p in IAM_RULE_PATTERNS],
        "description": "IAM relevance is determined by matching rule_id against these patterns",
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("IAM_ENGINE_PORT", "8003"))  # Changed from 8001 to avoid conflict
    uvicorn.run(app, host="0.0.0.0", port=port)
