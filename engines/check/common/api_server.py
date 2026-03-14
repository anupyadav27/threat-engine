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


# ── All-findings endpoints (misconfigurations page) ──────────────────────


def _get_check_conn():
    """Get a psycopg2 connection to the check DB."""
    import psycopg2
    return psycopg2.connect(
        host=os.getenv("CHECK_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("CHECK_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("CHECK_DB_NAME", "threat_engine_check"),
        user=os.getenv("CHECK_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("CHECK_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        connect_timeout=5,
    )


@app.get("/api/v1/check/findings/summary")
async def get_findings_summary(
    tenant_id: str = Query(...),
    provider: Optional[str] = Query(None),
    hierarchy_id: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
    service: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    domain: Optional[str] = Query(None),
    posture_category: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    check_scan_id: Optional[str] = Query(None),
):
    """
    Aggregated summary for the misconfigurations dashboard.

    Returns severity counts, top failing rules, service breakdown,
    posture category breakdown, and provider distribution.
    Supports multi-CSP filtering by provider, account (hierarchy_id), region.
    """
    from psycopg2.extras import RealDictCursor

    try:
        conn = _get_check_conn()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Database unavailable: {e}")

    try:
        # Build dynamic WHERE clause
        conditions = ["cf.tenant_id = %s"]
        params: list = [tenant_id]

        if provider:
            conditions.append("cf.provider = %s")
            params.append(provider.lower())
        if hierarchy_id:
            conditions.append("cf.hierarchy_id = %s")
            params.append(hierarchy_id)
        if region:
            conditions.append("cf.region = %s")
            params.append(region)
        if service:
            conditions.append("""
                COALESCE(
                    CASE WHEN cf.resource_uid LIKE 'arn:aws:%%:%%'
                         THEN split_part(cf.resource_uid, ':', 3) ELSE NULL END,
                    rm.resource_service, rm.service,
                    cf.resource_service, cf.service
                ) = %s
            """)
            params.append(service.lower())
        if status:
            conditions.append("cf.status = %s")
            params.append(status.upper())
        if severity:
            conditions.append("LOWER(COALESCE(rm.severity, 'medium')) = %s")
            params.append(severity.lower())
        if domain:
            conditions.append("COALESCE(rm.domain, 'uncategorized') = %s")
            params.append(domain)
        if posture_category:
            conditions.append("COALESCE(rm.posture_category, 'configuration') = %s")
            params.append(posture_category)
        if search:
            conditions.append("(rm.title ILIKE %s OR cf.rule_id ILIKE %s OR cf.resource_uid ILIKE %s)")
            like_val = f"%{search}%"
            params.extend([like_val, like_val, like_val])
        if check_scan_id:
            conditions.append("cf.check_scan_id = %s")
            params.append(check_scan_id)

        where = " AND ".join(conditions)
        base_join = """
            FROM check_findings cf
            LEFT JOIN rule_metadata rm ON rm.rule_id = cf.rule_id
            WHERE {where}
        """.format(where=where)

        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # 1. Severity counts
            cur.execute(f"""
                SELECT LOWER(COALESCE(rm.severity, 'medium')) AS severity,
                       COUNT(*) AS cnt
                {base_join}
                GROUP BY LOWER(COALESCE(rm.severity, 'medium'))
            """, params)
            sev_rows = cur.fetchall()

            # 2. Status counts
            cur.execute(f"""
                SELECT cf.status, COUNT(*) AS cnt
                {base_join}
                GROUP BY cf.status
            """, params)
            status_rows = cur.fetchall()

            # 3. Top 10 failing rules
            cur.execute(f"""
                SELECT cf.rule_id,
                       MAX(rm.title) AS title,
                       MAX(LOWER(COALESCE(rm.severity, 'medium'))) AS severity,
                       COUNT(*) AS cnt
                {base_join} AND cf.status = 'FAIL'
                GROUP BY cf.rule_id
                ORDER BY cnt DESC
                LIMIT 10
            """, params)
            top_rules = cur.fetchall()

            # 4. Service breakdown
            cur.execute(f"""
                SELECT
                    COALESCE(
                        CASE WHEN cf.resource_uid LIKE 'arn:aws:%%:%%'
                             THEN split_part(cf.resource_uid, ':', 3) ELSE NULL END,
                        rm.resource_service, rm.service,
                        cf.resource_service, cf.service
                    ) AS svc,
                    COUNT(*) AS cnt,
                    SUM(CASE WHEN cf.status = 'FAIL' THEN 1 ELSE 0 END) AS fail_cnt
                {base_join}
                GROUP BY svc
                ORDER BY cnt DESC
                LIMIT 20
            """, params)
            svc_rows = cur.fetchall()

            # 5. Posture category breakdown
            cur.execute(f"""
                SELECT COALESCE(rm.posture_category, 'configuration') AS category,
                       COUNT(*) AS cnt,
                       SUM(CASE WHEN cf.status = 'FAIL' THEN 1 ELSE 0 END) AS fail_cnt
                {base_join}
                GROUP BY category
                ORDER BY cnt DESC
            """, params)
            posture_rows = cur.fetchall()

            # 6. Provider breakdown
            cur.execute(f"""
                SELECT cf.provider, COUNT(*) AS cnt
                {base_join}
                GROUP BY cf.provider
                ORDER BY cnt DESC
            """, params)
            provider_rows = cur.fetchall()

            # 7. Region breakdown
            cur.execute(f"""
                SELECT cf.region, COUNT(*) AS cnt
                {base_join} AND cf.region IS NOT NULL AND cf.region != ''
                GROUP BY cf.region
                ORDER BY cnt DESC
                LIMIT 15
            """, params)
            region_rows = cur.fetchall()

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for r in sev_rows:
            s = r.get("severity", "medium")
            if s in severity_counts:
                severity_counts[s] = int(r.get("cnt") or 0)

        status_counts = {}
        for r in status_rows:
            status_counts[r["status"]] = int(r.get("cnt") or 0)

        total = sum(severity_counts.values())

        return {
            "total": total,
            "severity_counts": severity_counts,
            "status_counts": status_counts,
            "top_rules": [
                {"rule_id": r["rule_id"], "title": r.get("title") or r["rule_id"],
                 "severity": r.get("severity") or "medium", "count": int(r["cnt"])}
                for r in top_rules
            ],
            "by_service": [
                {"service": r.get("svc") or "unknown", "total": int(r["cnt"]),
                 "fail": int(r.get("fail_cnt") or 0)}
                for r in svc_rows if r.get("svc")
            ],
            "by_posture": [
                {"category": r["category"], "total": int(r["cnt"]),
                 "fail": int(r.get("fail_cnt") or 0)}
                for r in posture_rows
            ],
            "by_provider": [
                {"provider": r["provider"], "count": int(r["cnt"])}
                for r in provider_rows if r.get("provider")
            ],
            "by_region": [
                {"region": r["region"], "count": int(r["cnt"])}
                for r in region_rows if r.get("region")
            ],
        }
    finally:
        conn.close()


@app.get("/api/v1/check/findings")
async def list_findings(
    tenant_id: str = Query(...),
    provider: Optional[str] = Query(None),
    hierarchy_id: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
    service: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    domain: Optional[str] = Query(None),
    posture_category: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    check_scan_id: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    sort_by: str = Query("severity"),
    sort_order: str = Query("asc"),
):
    """
    List all check findings with filtering, pagination, and sorting.

    Multi-CSP: filter by provider, hierarchy_id (account), region.
    Security: filter by severity, status, service, domain, posture_category.
    Enriches each finding with rule_metadata (title, severity, remediation, etc.).
    """
    from psycopg2.extras import RealDictCursor

    try:
        conn = _get_check_conn()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Database unavailable: {e}")

    try:
        # Build dynamic WHERE
        conditions = ["cf.tenant_id = %s"]
        params: list = [tenant_id]

        if provider:
            conditions.append("cf.provider = %s")
            params.append(provider.lower())
        if hierarchy_id:
            conditions.append("cf.hierarchy_id = %s")
            params.append(hierarchy_id)
        if region:
            conditions.append("cf.region = %s")
            params.append(region)
        if service:
            conditions.append("""
                COALESCE(
                    CASE WHEN cf.resource_uid LIKE 'arn:aws:%%:%%'
                         THEN split_part(cf.resource_uid, ':', 3) ELSE NULL END,
                    rm.resource_service, rm.service,
                    cf.resource_service, cf.service
                ) = %s
            """)
            params.append(service.lower())
        if status:
            conditions.append("cf.status = %s")
            params.append(status.upper())
        if severity:
            conditions.append("LOWER(COALESCE(rm.severity, 'medium')) = %s")
            params.append(severity.lower())
        if domain:
            conditions.append("COALESCE(rm.domain, 'uncategorized') = %s")
            params.append(domain)
        if posture_category:
            conditions.append("COALESCE(rm.posture_category, 'configuration') = %s")
            params.append(posture_category)
        if search:
            conditions.append("(rm.title ILIKE %s OR cf.rule_id ILIKE %s OR cf.resource_uid ILIKE %s)")
            like_val = f"%{search}%"
            params.extend([like_val, like_val, like_val])
        if check_scan_id:
            conditions.append("cf.check_scan_id = %s")
            params.append(check_scan_id)

        where = " AND ".join(conditions)
        base_join = f"""
            FROM check_findings cf
            LEFT JOIN rule_metadata rm ON rm.rule_id = cf.rule_id
            WHERE {where}
        """

        # Sort mapping
        sort_map = {
            "severity": """CASE LOWER(COALESCE(rm.severity, 'medium'))
                           WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                           WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END""",
            "title": "COALESCE(rm.title, cf.rule_id)",
            "status": "cf.status",
            "service": """COALESCE(
                CASE WHEN cf.resource_uid LIKE 'arn:aws:%%:%%'
                     THEN split_part(cf.resource_uid, ':', 3) ELSE NULL END,
                rm.resource_service, rm.service, cf.resource_service, cf.service)""",
            "created_at": "cf.created_at",
            "region": "cf.region",
            "resource": "cf.resource_uid",
        }
        order_col = sort_map.get(sort_by, sort_map["severity"])
        order_dir = "DESC" if sort_order.lower() == "desc" else "ASC"

        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Total count
            cur.execute(f"SELECT COUNT(*) AS total {base_join}", params)
            total = int(cur.fetchone()["total"])

            # Paginated results
            offset = (page - 1) * page_size
            cur.execute(f"""
                SELECT
                    cf.id,
                    cf.rule_id,
                    cf.check_scan_id,
                    cf.provider,
                    cf.hierarchy_id,
                    cf.resource_uid,
                    cf.resource_id,
                    cf.resource_type,
                    COALESCE(
                        CASE WHEN cf.resource_uid LIKE 'arn:aws:%%:%%'
                             THEN split_part(cf.resource_uid, ':', 3) ELSE NULL END,
                        rm.resource_service, rm.service,
                        cf.resource_service, cf.service
                    ) AS service,
                    cf.region,
                    cf.status,
                    cf.created_at,
                    rm.title,
                    LOWER(COALESCE(rm.severity, 'medium')) AS severity,
                    rm.description,
                    rm.remediation,
                    rm.rationale,
                    COALESCE(rm.domain, 'uncategorized') AS domain,
                    rm.subcategory,
                    COALESCE(rm.posture_category, 'configuration') AS posture_category,
                    rm.compliance_frameworks,
                    rm.mitre_tactics,
                    rm.mitre_techniques,
                    rm.risk_score,
                    cf.checked_fields,
                    cf.actual_values
                {base_join}
                ORDER BY {order_col} {order_dir}, cf.created_at DESC
                LIMIT %s OFFSET %s
            """, (*params, page_size, offset))
            rows = cur.fetchall()

        findings = []
        for r in rows:
            created = r.get("created_at")
            # Parse compliance_frameworks if present
            frameworks = r.get("compliance_frameworks")
            if isinstance(frameworks, str):
                import json
                try:
                    frameworks = json.loads(frameworks)
                except Exception:
                    frameworks = None

            findings.append({
                "id": r.get("id"),
                "rule_id": r["rule_id"],
                "title": r.get("title") or r["rule_id"],
                "severity": r.get("severity") or "medium",
                "status": r.get("status") or "FAIL",
                "resource_uid": r.get("resource_uid") or "",
                "resource_type": r.get("resource_type") or "",
                "service": r.get("service") or "",
                "region": r.get("region") or "",
                "provider": r.get("provider") or "",
                "hierarchy_id": r.get("hierarchy_id") or "",
                "domain": r.get("domain") or "",
                "posture_category": r.get("posture_category") or "configuration",
                "description": r.get("description") or "",
                "remediation": r.get("remediation") or "",
                "rationale": r.get("rationale") or "",
                "compliance_frameworks": frameworks,
                "mitre_tactics": r.get("mitre_tactics"),
                "mitre_techniques": r.get("mitre_techniques"),
                "risk_score": r.get("risk_score"),
                "checked_fields": r.get("checked_fields"),
                "actual_values": r.get("actual_values"),
                "created_at": created.isoformat() if created else None,
            })

        return {
            "findings": findings,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": (total + page_size - 1) // page_size,
        }
    finally:
        conn.close()


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
    Matches on resource_uid to handle format differences.
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
        # ── Resolve the canonical resource_uid stored in check_findings ─────
        # Inventory may use short names (e.g. "my-role") while check_findings
        # stores full ARNs ("arn:aws:iam::123:role/my-role"). Try exact match
        # first, then fall back to suffix match (LIKE '%/<short_name>').
        resolved_uid = resource_uid
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Exact match
            cur.execute("""
                SELECT resource_uid AS uid, check_scan_id
                FROM check_findings
                WHERE resource_uid = %s
                  AND tenant_id = %s
                ORDER BY created_at DESC
                LIMIT 1
            """, (resource_uid, tenant_id))
            row = cur.fetchone()

            if not row and '/' not in resource_uid and ':' not in resource_uid:
                # Short-name → try suffix match
                cur.execute("""
                    SELECT resource_uid AS uid, check_scan_id
                    FROM check_findings
                    WHERE resource_uid LIKE %s
                      AND tenant_id = %s
                    ORDER BY created_at DESC
                    LIMIT 1
                """, (f'%/{resource_uid}', tenant_id))
                row = cur.fetchone()

            if row:
                resolved_uid = row["uid"]
                latest_scan_id = row["check_scan_id"]
            else:
                latest_scan_id = None

        # Build the reusable WHERE params — always use resolved_uid + latest scan
        uid_match = "cf.resource_uid = %s"
        scan_filter = ""
        base_params: list = [resolved_uid, tenant_id]
        if latest_scan_id:
            scan_filter = " AND cf.check_scan_id = %s"
            base_params = [resolved_uid, tenant_id, latest_scan_id]

        # Severity counts (FAIL only)
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(f"""
                SELECT
                    LOWER(COALESCE(rm.severity, 'medium')) AS severity,
                    COUNT(*) AS cnt
                FROM check_findings cf
                LEFT JOIN rule_metadata rm ON rm.rule_id = cf.rule_id
                WHERE {uid_match}
                  AND cf.tenant_id = %s
                  {scan_filter}
                  AND cf.status = 'FAIL'
                GROUP BY LOWER(COALESCE(rm.severity, 'medium'))
            """, (*base_params,))
            sev_rows = cur.fetchall()

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for r in sev_rows:
            sev = r.get("severity", "medium")
            if sev in severity_counts:
                severity_counts[sev] = int(r.get("cnt") or 0)

        # Posture by domain (pass/fail counts per security domain)
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(f"""
                SELECT
                    COALESCE(rm.domain, 'uncategorized') AS domain,
                    cf.status,
                    COUNT(*) AS cnt
                FROM check_findings cf
                LEFT JOIN rule_metadata rm ON rm.rule_id = cf.rule_id
                WHERE {uid_match}
                  AND cf.tenant_id = %s
                  {scan_filter}
                GROUP BY COALESCE(rm.domain, 'uncategorized'), cf.status
            """, (*base_params,))
            posture_rows = cur.fetchall()

        posture_by_domain = {}
        for r in posture_rows:
            domain = r.get("domain", "uncategorized")
            status = (r.get("status") or "").upper()
            cnt = int(r.get("cnt") or 0)
            if domain not in posture_by_domain:
                posture_by_domain[domain] = {"pass": 0, "fail": 0, "total": 0}
            if status == "PASS":
                posture_by_domain[domain]["pass"] += cnt
            else:
                posture_by_domain[domain]["fail"] += cnt
            posture_by_domain[domain]["total"] += cnt

        # Detailed findings
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(f"""
                SELECT
                    cf.rule_id,
                    rm.title,
                    LOWER(COALESCE(rm.severity, 'medium')) AS severity,
                    COALESCE(
                        CASE WHEN cf.resource_uid LIKE 'arn:aws:%%:%%'
                             THEN split_part(cf.resource_uid, ':', 3)
                             ELSE NULL END,
                        rm.resource_service, rm.service,
                        cf.resource_service, cf.service
                    ) AS service,
                    cf.status,
                    cf.region,
                    cf.resource_type,
                    cf.created_at,
                    rm.domain,
                    COALESCE(rm.posture_category, 'configuration') AS posture_category
                FROM check_findings cf
                LEFT JOIN rule_metadata rm ON rm.rule_id = cf.rule_id
                WHERE {uid_match}
                  AND cf.tenant_id = %s
                  {scan_filter}
                ORDER BY
                    CASE LOWER(COALESCE(rm.severity, 'medium'))
                        WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                        WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5
                    END,
                    cf.created_at DESC
                LIMIT %s
            """, (*base_params, limit))
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
                "domain": r.get("domain") or "",
                "posture_category": r.get("posture_category") or "configuration",
                "created_at": created.isoformat() if created else None,
            })

        return {
            "resource_uid": resource_uid,
            "severity_counts": severity_counts,
            "posture_by_domain": posture_by_domain,
            "findings": findings,
        }
    finally:
        conn.close()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8002")))
