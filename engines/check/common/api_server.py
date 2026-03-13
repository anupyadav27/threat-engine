"""
Common FastAPI server for Multi-CSP Check Engine

The check engine is 100% database-driven:
  - Rules    → rule_checks table   (populated by rule engine / YAML loader)
  - Data     → discovery_findings  (written by discovery engine)
  - Results  → check_findings      (written by this engine)

No cloud API credentials are needed.  The only provider-specific work is
parsing resource identifiers from the emitted_fields JSON already in the DB.

Request modes:
  1. Pipeline  — supply orchestration_id; tenant/hierarchy/discovery_scan_id
                 are fetched from scan_orchestration table.
  2. Ad-hoc    — supply discovery_scan_id + tenant_id + hierarchy_id directly.
"""

import asyncio
import os
import sys
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# engine_common is one level above engine_check/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))
from engine_common.logger import LogContext, setup_logger
from engine_common.orchestration import get_orchestration_metadata

# Common layer
from common.database.database_manager import DatabaseManager
from common.database.rule_reader import RuleReader
from common.models.evaluator_interface import CheckEvaluator, CheckEvaluationError
from common.orchestration.check_engine import CheckEngine

# CSP-specific evaluators (no credentials required — DB-only)
from providers.aws.evaluator.check_evaluator import AWSCheckEvaluator

logger = setup_logger(__name__, engine_name="engine-check-common")

app = FastAPI(
    title="Multi-CSP Check Engine API",
    description=(
        "Compliance check evaluation engine. "
        "Reads pre-discovered resources from discovery_findings, "
        "evaluates rules from rule_checks, writes results to check_findings. "
        "No cloud credentials required."
    ),
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Provider registry ─────────────────────────────────────────────────────────
# Maps provider name → CheckEvaluator class.
# Add new CSP evaluators here once implemented.
# No credentials/auth needed — evaluators only parse DB data.

PROVIDER_EVALUATORS: Dict[str, type] = {
    "aws": AWSCheckEvaluator,
    # "azure": AzureCheckEvaluator,  # TODO
    # "gcp":   GCPCheckEvaluator,    # TODO
    # "oci":   OCICheckEvaluator,    # TODO
}

# ── Shared DB manager (health checks only) ───────────────────────────────────

_health_db: Optional[DatabaseManager] = None


def _get_health_db() -> Optional[DatabaseManager]:
    global _health_db
    if _health_db is None:
        try:
            _health_db = DatabaseManager()
        except Exception:
            pass
    return _health_db


# ── In-memory scan registry ──────────────────────────────────────────────────

scans: Dict[str, Dict] = {}
metrics: Dict[str, Any] = {
    "total_scans": 0,
    "successful_scans": 0,
    "failed_scans": 0,
    "total_duration_seconds": 0,
}


# ── Request / Response models ─────────────────────────────────────────────────


class CheckRequest(BaseModel):
    """Check scan request — no credentials required."""

    # Pipeline mode: fetch metadata from scan_orchestration table
    orchestration_id: Optional[str] = None
    scan_run_id: Optional[str] = None       # alias for backward compat

    # Ad-hoc mode: supply these directly
    discovery_scan_id: Optional[str] = None
    tenant_id: Optional[str] = None
    customer_id: Optional[str] = None
    hierarchy_id: Optional[str] = None
    hierarchy_type: str = "account"
    provider: str = "aws"

    # Optional filters
    include_services: Optional[List[str]] = None
    check_source: str = "default"


class CheckResponse(BaseModel):
    check_scan_id: str
    status: str
    message: str
    orchestration_id: Optional[str] = None
    provider: Optional[str] = None


# ── Helpers ───────────────────────────────────────────────────────────────────


def _get_evaluator(provider: str) -> CheckEvaluator:
    """Return the CheckEvaluator for *provider* (no credentials needed)."""
    key = provider.lower()
    if key not in PROVIDER_EVALUATORS:
        supported = ", ".join(PROVIDER_EVALUATORS)
        raise HTTPException(
            status_code=400,
            detail=f"Provider '{provider}' not supported. Supported: {supported}",
        )
    cls = PROVIDER_EVALUATORS[key]
    logger.info("Using evaluator %s for provider %s", cls.__name__, provider)
    return cls(provider=key)


async def _fetch_orchestration(orch_id: str) -> Dict[str, Any]:
    """Fetch scan metadata from scan_orchestration table."""
    try:
        metadata = get_orchestration_metadata(orch_id)
        if not metadata:
            raise ValueError(f"No record for orchestration_id: {orch_id}")
        return metadata
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.error("Failed to fetch orchestration metadata: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


def _default_services(provider: str) -> List[str]:
    """Services with active rules in rule_checks for *provider*."""
    try:
        return RuleReader().get_services_for_provider(provider)
    except Exception as exc:
        logger.warning("Could not load service list from rule_checks: %s", exc)
        return []


# ── Background task ───────────────────────────────────────────────────────────


def _run_check_sync(check_scan_id: str, request: CheckRequest) -> None:
    """Execute check scan synchronously (runs in a thread pool)."""
    with LogContext(tenant_id=request.tenant_id, scan_run_id=check_scan_id):
        start = datetime.now(timezone.utc)
        try:
            # No authenticate() — DB-only engine
            evaluator = _get_evaluator(request.provider)
            db_manager = DatabaseManager()
            engine = CheckEngine(evaluator=evaluator, db_manager=db_manager)

            services = request.include_services or _default_services(request.provider)

            results = engine.run_check_scan(
                discovery_scan_id=request.discovery_scan_id,
                check_scan_id=check_scan_id,
                customer_id=request.customer_id or "default",
                tenant_id=request.tenant_id or "default-tenant",
                provider=request.provider,
                hierarchy_id=request.hierarchy_id or request.discovery_scan_id or "",
                hierarchy_type=request.hierarchy_type,
                services=services,
                check_source=request.check_source,
            )

            duration = (datetime.now(timezone.utc) - start).total_seconds()
            scans[check_scan_id].update(
                {
                    "status": "completed",
                    "results": results,
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                }
            )
            metrics["successful_scans"] += 1
            metrics["total_duration_seconds"] += duration

            logger.info(
                "Check scan completed: %s — %d checks in %.1fs",
                check_scan_id,
                results.get("total_checks", 0),
                duration,
            )

        except CheckEvaluationError as exc:
            logger.error("Check evaluation error for %s: %s", check_scan_id, exc)
            scans[check_scan_id].update(
                {"status": "failed", "error": str(exc), "completed_at": datetime.now(timezone.utc).isoformat()}
            )
            metrics["failed_scans"] += 1

        except Exception as exc:
            logger.error("Check scan failed: %s", check_scan_id, exc_info=True)
            scans[check_scan_id].update(
                {"status": "failed", "error": str(exc), "completed_at": datetime.now(timezone.utc).isoformat()}
            )
            metrics["failed_scans"] += 1


async def _run_check(check_scan_id: str, request: CheckRequest) -> None:
    """Offload to thread pool — keeps event loop free."""
    await asyncio.to_thread(_run_check_sync, check_scan_id, request)


# ── Endpoints ─────────────────────────────────────────────────────────────────


@app.post("/api/v1/scan", response_model=CheckResponse)
async def create_check(request: CheckRequest, background_tasks: BackgroundTasks):
    """
    Start a compliance check scan.

    **Pipeline mode** — provide `orchestration_id`:
      Fetches tenant_id, hierarchy_id, discovery_scan_id, and provider from
      the scan_orchestration table. No credentials needed.

    **Ad-hoc mode** — provide `discovery_scan_id`:
      Uses the supplied discovery_scan_id with optional tenant/hierarchy overrides.
    """
    check_scan_id = str(uuid.uuid4())
    orch_id = request.orchestration_id or request.scan_run_id

    if orch_id:
        # ── Pipeline mode ────────────────────────────────────────────────────
        meta = await _fetch_orchestration(orch_id)

        discovery_scan_id = meta.get("discovery_scan_id")
        if not discovery_scan_id:
            raise HTTPException(
                status_code=400,
                detail=f"Discovery scan not yet completed for orchestration_id={orch_id}",
            )

        provider = meta.get("provider") or meta.get("provider_type", "aws")
        account_id = meta.get("account_id")

        request.orchestration_id = orch_id
        request.discovery_scan_id = discovery_scan_id
        request.tenant_id = request.tenant_id or meta.get("tenant_id", "default-tenant")
        request.customer_id = request.customer_id or meta.get("customer_id", "default")
        request.provider = provider
        request.hierarchy_id = (
            request.hierarchy_id or meta.get("hierarchy_id") or account_id or ""
        )
        request.hierarchy_type = meta.get("hierarchy_type", "account")
        request.include_services = request.include_services or meta.get("include_services")

        logger.info(
            "Pipeline mode: orch=%s disc=%s provider=%s",
            orch_id, discovery_scan_id, provider,
        )

    elif request.discovery_scan_id:
        # ── Ad-hoc mode ──────────────────────────────────────────────────────
        logger.info("Ad-hoc mode: discovery_scan_id=%s", request.discovery_scan_id)

    else:
        raise HTTPException(
            status_code=400,
            detail="Either orchestration_id or discovery_scan_id must be provided",
        )

    # Validate provider
    if request.provider.lower() not in PROVIDER_EVALUATORS:
        supported = ", ".join(PROVIDER_EVALUATORS)
        raise HTTPException(
            status_code=400,
            detail=f"Provider '{request.provider}' not supported. Supported: {supported}",
        )

    # Register scan
    scans[check_scan_id] = {
        "status": "running",
        "provider": request.provider,
        "discovery_scan_id": request.discovery_scan_id,
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    metrics["total_scans"] += 1

    background_tasks.add_task(_run_check, check_scan_id, request)

    return CheckResponse(
        check_scan_id=check_scan_id,
        status="running",
        message=f"Check scan started for provider: {request.provider}",
        orchestration_id=orch_id,
        provider=request.provider,
    )


@app.get("/api/v1/check/{check_scan_id}/status")
async def get_check_status(check_scan_id: str):
    """Get status and summary for a check scan."""
    if check_scan_id not in scans:
        raise HTTPException(status_code=404, detail="Check scan not found")
    data = scans[check_scan_id]
    return {
        "check_scan_id": check_scan_id,
        "status": data["status"],
        "provider": data.get("provider"),
        "discovery_scan_id": data.get("discovery_scan_id"),
        "error": data.get("error"),
        "started_at": data.get("started_at"),
        "completed_at": data.get("completed_at"),
        "results": data.get("results"),
    }


@app.get("/api/v1/checks")
async def list_checks(
    status: Optional[str] = Query(None),
    provider: Optional[str] = Query(None),
    discovery_scan_id: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=1000),
):
    """List check scans with optional filters."""
    result = [
        {
            "check_scan_id": sid,
            "status": d.get("status"),
            "provider": d.get("provider"),
            "discovery_scan_id": d.get("discovery_scan_id"),
            "started_at": d.get("started_at"),
            "completed_at": d.get("completed_at"),
        }
        for sid, d in scans.items()
        if (not status or d.get("status") == status)
        and (not provider or d.get("provider") == provider)
        and (not discovery_scan_id or d.get("discovery_scan_id") == discovery_scan_id)
    ]
    return {"scans": result[:limit], "total": len(result)}


@app.get("/api/v1/providers")
async def list_providers():
    """Supported cloud providers."""
    return {"providers": list(PROVIDER_EVALUATORS.keys())}


# ── Health & metrics ──────────────────────────────────────────────────────────


@app.get("/api/v1/health")
async def health():
    """Health check — reports database connectivity."""
    db = _get_health_db()
    if db is None:
        return {"status": "degraded", "version": "2.0.0", "database": "disconnected"}
    try:
        db.test_connection()
        return {
            "status": "healthy",
            "version": "2.0.0",
            "database": "connected",
            "database_details": db.get_database_info(),
            "providers": list(PROVIDER_EVALUATORS),
        }
    except Exception as exc:
        return {"status": "degraded", "version": "2.0.0", "database": "error", "error": str(exc)}


@app.get("/api/v1/health/live")
async def liveness():
    """Kubernetes liveness probe."""
    return {"status": "alive"}


@app.get("/api/v1/health/ready")
async def readiness():
    """Kubernetes readiness probe — verifies check DB is reachable."""
    db = _get_health_db()
    if db is None:
        raise HTTPException(status_code=503, detail="Database not initialised")
    try:
        db.test_connection()
        return {"status": "ready"}
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Not ready: {exc}") from exc


@app.get("/api/v1/metrics")
async def get_metrics():
    """Scan metrics."""
    return metrics


# ── Per-resource finding endpoints (used by BFF asset detail) ─────────────

@app.get("/api/v1/check/findings/resource/{resource_uid:path}")
async def get_findings_for_resource(
    resource_uid: str,
    tenant_id: str = Query(...),
    limit: int = Query(200, ge=1, le=1000),
):
    """
    Return check findings for a specific resource.

    Used by the BFF layer to enrich asset detail views with
    compliance posture (severity counts + detailed finding list).
    Matches on both resource_uid and resource_arn to handle format differences.
    """
    import psycopg2
    from psycopg2.extras import RealDictCursor

    try:
        conn = psycopg2.connect(
            host=os.getenv("CHECK_DB_HOST", os.getenv("DB_HOST", "localhost")),
            port=int(os.getenv("CHECK_DB_PORT", os.getenv("DB_PORT", "5432"))),
            dbname=os.getenv("CHECK_DB_NAME", "threat_engine_check"),
            user=os.getenv("CHECK_DB_USER", os.getenv("DB_USER", "postgres")),
            password=os.getenv("CHECK_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
            connect_timeout=5,
        )
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Database unavailable: {e}")

    try:
        # Severity counts (FAIL only)
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT
                    LOWER(COALESCE(rm.severity, 'medium')) AS severity,
                    COUNT(*) AS cnt
                FROM check_findings cf
                LEFT JOIN rule_metadata rm ON rm.rule_id = cf.rule_id
                WHERE COALESCE(cf.resource_uid, cf.resource_arn) = %s
                  AND cf.tenant_id = %s
                  AND cf.status = 'FAIL'
                GROUP BY LOWER(COALESCE(rm.severity, 'medium'))
            """, (resource_uid, tenant_id))
            sev_rows = cur.fetchall()

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for r in sev_rows:
            sev = r.get("severity", "medium")
            if sev in severity_counts:
                severity_counts[sev] = int(r.get("cnt") or 0)

        # Detailed findings
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT
                    cf.rule_id,
                    rm.title,
                    LOWER(COALESCE(rm.severity, 'medium')) AS severity,
                    COALESCE(rm.service, cf.service) AS service,
                    cf.status,
                    cf.region,
                    cf.resource_type,
                    cf.created_at
                FROM check_findings cf
                LEFT JOIN rule_metadata rm ON rm.rule_id = cf.rule_id
                WHERE COALESCE(cf.resource_uid, cf.resource_arn) = %s
                  AND cf.tenant_id = %s
                ORDER BY
                    CASE LOWER(COALESCE(rm.severity, 'medium'))
                        WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                        WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5
                    END,
                    cf.created_at DESC
                LIMIT %s
            """, (resource_uid, tenant_id, limit))
            detail_rows = cur.fetchall()

        findings = []
        for r in detail_rows:
            created = r.get("created_at")
            findings.append({
                "rule_id": r["rule_id"],
                "title": r.get("title") or r["rule_id"],
                "severity": r.get("severity") or "medium",
                "service": r.get("service") or "",
                "status": r.get("status") or "FAIL",
                "region": r.get("region") or "",
                "resource_type": r.get("resource_type") or "",
                "created_at": created.isoformat() if created else None,
            })

        return {
            "resource_uid": resource_uid,
            "severity_counts": severity_counts,
            "findings": findings,
        }
    finally:
        conn.close()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8002")))
