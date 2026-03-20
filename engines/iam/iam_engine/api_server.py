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
from engine_common.logger import setup_logger
from engine_common.telemetry import configure_telemetry
from engine_common.middleware import RequestLoggingMiddleware, CorrelationIDMiddleware
from engine_common.orchestration import get_orchestration_metadata
from engine_common.job_creator import create_engine_job

from .input.threat_db_reader import ThreatDBReader
from .enricher.finding_enricher import FindingEnricher
from .reporter.iam_reporter import IAMReporter
from .storage.report_storage import ReportStorage

import json

logger = setup_logger(__name__, engine_name="engine-iam")

# ── Scanner Job config ───────────────────────────────────────────────────────
SCANNER_IMAGE = os.getenv("IAM_SCANNER_IMAGE", "yadavanup84/engine-iam:v-job")
SCANNER_CPU_REQUEST = os.getenv("SCANNER_CPU_REQUEST", "100m")
SCANNER_MEM_REQUEST = os.getenv("SCANNER_MEM_REQUEST", "512Mi")
SCANNER_CPU_LIMIT = os.getenv("SCANNER_CPU_LIMIT", "250m")
SCANNER_MEM_LIMIT = os.getenv("SCANNER_MEM_LIMIT", "1Gi")

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


def _get_iam_conn():
    """Get psycopg2 connection to the IAM database for status queries."""
    import psycopg2
    return psycopg2.connect(
        host=os.getenv("IAM_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("IAM_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("IAM_DB_NAME", "threat_engine_iam"),
        user=os.getenv("IAM_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("IAM_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
    )


@app.post("/api/v1/iam-security/scan")
async def generate_report(request: ScanRequest):
    """
    Start an IAM security scan by creating a K8s Job on a spot node.

    **Pipeline mode** -- provide `orchestration_id`:
      Fetches metadata from scan_orchestration table.

    **Ad-hoc mode** -- provide `scan_id`:
      Uses the supplied threat_scan_id.

    Returns immediately with iam_scan_id. Poll status via
    GET /api/v1/iam-security/{iam_scan_id}/status.
    """
    if not request.orchestration_id and not request.scan_id:
        raise HTTPException(status_code=400, detail="Either scan_id OR orchestration_id must be provided")

    if request.orchestration_id:
        orch_id = request.orchestration_id
        iam_scan_id = orch_id
        try:
            metadata = get_orchestration_metadata(orch_id)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))

        threat_scan_id = metadata.get("threat_scan_id")
        if not threat_scan_id:
            raise HTTPException(status_code=400, detail=f"Threat scan not completed yet for orchestration_id={orch_id}")

        tenant_id = metadata.get("tenant_id") or request.tenant_id
        csp = (metadata.get("provider") or metadata.get("provider_type", "aws")).lower()
        logger.info(f"Pipeline mode: orch={orch_id} threat={threat_scan_id} csp={csp}")
    else:
        # Ad-hoc: orchestration_id is required for Job-based execution
        raise HTTPException(status_code=400, detail="orchestration_id is required for Job-based execution")

    # Pre-create iam_report row in DB (so status endpoint works immediately)
    try:
        conn = _get_iam_conn()
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO iam_report
                   (iam_scan_id, tenant_id, provider, threat_scan_id, status, generated_at, metadata)
                   VALUES (%s, %s, %s, %s, 'running', NOW(), %s)
                   ON CONFLICT (iam_scan_id) DO UPDATE SET status = 'running'""",
                (iam_scan_id, tenant_id, csp, threat_scan_id,
                 json.dumps({"orchestration_id": orch_id, "mode": "job"})),
            )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning(f"Failed to pre-create iam_report: {e}")

    # Create K8s Job on spot node
    try:
        job_name = create_engine_job(
            engine_name="iam",
            scan_id=iam_scan_id,
            orchestration_id=orch_id,
            image=SCANNER_IMAGE,
            cpu_request=SCANNER_CPU_REQUEST,
            mem_request=SCANNER_MEM_REQUEST,
            cpu_limit=SCANNER_CPU_LIMIT,
            mem_limit=SCANNER_MEM_LIMIT,
            active_deadline_seconds=1800,
        )
    except Exception as e:
        logger.error(f"Failed to create IAM scanner Job: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to create scanner Job: {e}")

    return {
        "iam_scan_id": iam_scan_id,
        "status": "running",
        "message": f"Scanner Job '{job_name}' created on spot node (image={SCANNER_IMAGE})",
        "orchestration_id": orch_id,
    }


@app.get("/api/v1/iam-security/{iam_scan_id}/status")
async def get_iam_status(iam_scan_id: str):
    """Get IAM scan status from iam_report DB table."""
    from psycopg2.extras import RealDictCursor
    try:
        conn = _get_iam_conn()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT iam_scan_id, status, provider, threat_scan_id, generated_at, metadata "
                "FROM iam_report WHERE iam_scan_id = %s",
                (iam_scan_id,),
            )
            row = cur.fetchone()
        conn.close()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Database error: {e}")

    if not row:
        raise HTTPException(status_code=404, detail=f"IAM scan {iam_scan_id} not found")

    return {
        "iam_scan_id": row["iam_scan_id"],
        "status": row["status"],
        "provider": row.get("provider"),
        "threat_scan_id": row.get("threat_scan_id"),
        "generated_at": str(row.get("generated_at")) if row.get("generated_at") else None,
    }


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
app.add_api_route("/api/v1/scan", generate_report, methods=["POST"])

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

# Include unified UI data router
try:
    from .api.ui_data_router import router as ui_data_router
    app.include_router(ui_data_router)
except ImportError as e:
    logger.warning("UI data router not available", extra={"extra_fields": {"error": str(e)}})


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("IAM_ENGINE_PORT", "8003"))  # Changed from 8001 to avoid conflict
    uvicorn.run(app, host="0.0.0.0", port=port)
