"""
Common FastAPI server for Multi-CSP Check Engine

The check engine is 100% database-driven:
  - Rules    → rule_checks table   (populated by rule engine / YAML loader)
  - Data     → discovery_findings  (written by discovery engine)
  - Results  → check_findings      (written by this engine)

No cloud API credentials are needed.  The only provider-specific work is
parsing resource identifiers from the emitted_fields JSON already in the DB.

Request modes:
  1. Pipeline  — supply scan_run_id; tenant/account metadata
                 are fetched from scan_orchestration table.
  2. Ad-hoc    — supply scan_run_id + tenant_id + account_id directly.
"""

import os
import sys
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# engine_common is one level above engine_check/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))
from engine_common.logger import setup_logger
from engine_common.orchestration import get_orchestration_metadata
from engine_common.job_creator import create_engine_job

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


# ── Scanner Job config ───────────────────────────────────────────────────────

SCANNER_IMAGE = os.getenv("CHECK_SCANNER_IMAGE", "yadavanup84/engine-check:v-job")
SCANNER_CPU_REQUEST = os.getenv("SCANNER_CPU_REQUEST", "500m")
SCANNER_MEM_REQUEST = os.getenv("SCANNER_MEM_REQUEST", "2Gi")
SCANNER_CPU_LIMIT = os.getenv("SCANNER_CPU_LIMIT", "1")
SCANNER_MEM_LIMIT = os.getenv("SCANNER_MEM_LIMIT", "4Gi")

metrics: Dict[str, Any] = {
    "total_scans": 0,
    "successful_scans": 0,
    "failed_scans": 0,
}


# ── Request / Response models ─────────────────────────────────────────────────


class CheckRequest(BaseModel):
    """Check scan request — no credentials required."""

    # Pipeline mode: fetch metadata from scan_orchestration table
    scan_run_id: Optional[str] = None

    # Ad-hoc mode: supply these directly
    discovery_scan_id: Optional[str] = None
    tenant_id: Optional[str] = None
    customer_id: Optional[str] = None
    account_id: Optional[str] = None
    hierarchy_type: str = "account"
    provider: str = "aws"

    # Optional filters
    include_services: Optional[List[str]] = None
    check_source: str = "default"


class CheckResponse(BaseModel):
    scan_run_id: str
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


# ── Endpoints ─────────────────────────────────────────────────────────────────


@app.post("/api/v1/scan", response_model=CheckResponse)
async def create_check(request: CheckRequest):
    """
    Start a compliance check scan by creating a K8s Job on a spot node.

    **Pipeline mode** — provide `orchestration_id`:
      Fetches metadata from scan_orchestration table.

    **Ad-hoc mode** — provide `discovery_scan_id`:
      Uses the supplied discovery_scan_id with optional overrides.
    """
    orch_id = request.scan_run_id
    scan_run_id = orch_id

    if orch_id:
        meta = await _fetch_orchestration(orch_id)

        resolved_scan_run_id = meta.get("scan_run_id")
        if not resolved_scan_run_id:
            raise HTTPException(
                status_code=400,
                detail=f"Discovery scan not yet completed for scan_run_id={orch_id}",
            )

        provider = meta.get("provider") or meta.get("provider_type", "aws")
        logger.info("Pipeline mode: scan_run_id=%s provider=%s", resolved_scan_run_id, provider)

    elif request.discovery_scan_id:
        logger.info("Ad-hoc mode: discovery_scan_id=%s", request.discovery_scan_id)
        if not orch_id:
            raise HTTPException(
                status_code=400,
                detail="orchestration_id required for Job-based execution",
            )

    else:
        raise HTTPException(
            status_code=400,
            detail="orchestration_id is required",
        )

    # Validate provider
    provider = (request.provider or "aws").lower()
    if provider not in PROVIDER_EVALUATORS:
        supported = ", ".join(PROVIDER_EVALUATORS)
        raise HTTPException(
            status_code=400,
            detail=f"Provider '{provider}' not supported. Supported: {supported}",
        )

    # Resolve metadata for report row
    tenant_id = request.tenant_id or "default-tenant"
    customer_id = request.customer_id or "default"
    disc_scan_id = request.discovery_scan_id or ""
    account_id = request.account_id or ""

    # Pre-create check_report row in DB (so status endpoint works immediately)
    try:
        import json as _json
        conn = _get_check_conn()
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO check_report
                   (scan_run_id, customer_id, tenant_id, provider, discovery_scan_id,
                    account_id, status, first_seen_at, metadata)
                   VALUES (%s, %s, %s, %s, %s, %s, 'running', NOW(), %s)
                   ON CONFLICT (scan_run_id) DO UPDATE SET status = 'running'""",
                (scan_run_id, customer_id, tenant_id, provider,
                 disc_scan_id, account_id,
                 _json.dumps({"scan_run_id": orch_id, "mode": "job"})),
            )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning(f"Failed to pre-create check_report: {e}")

    # Create K8s Job on spot node
    try:
        job_name = create_engine_job(
            engine_name="check",
            scan_id=scan_run_id,
            scan_run_id=orch_id,
            image=SCANNER_IMAGE,
            cpu_request=SCANNER_CPU_REQUEST,
            mem_request=SCANNER_MEM_REQUEST,
            cpu_limit=SCANNER_CPU_LIMIT,
            mem_limit=SCANNER_MEM_LIMIT,
            active_deadline_seconds=3600,
        )
    except Exception as e:
        logger.error(f"Failed to create check scanner Job: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to create scanner Job: {e}")

    metrics["total_scans"] += 1

    return CheckResponse(
        scan_run_id=scan_run_id,
        status="running",
        message=f"Scanner Job '{job_name}' created on spot node (image={SCANNER_IMAGE})",
        orchestration_id=orch_id,
        provider=provider,
    )


@app.get("/api/v1/check/{scan_run_id}/status")
async def get_check_status(scan_run_id: str):
    """Get check scan status from check_report DB table."""
    from psycopg2.extras import RealDictCursor
    try:
        conn = _get_check_conn()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT scan_run_id, status, provider, discovery_scan_id, first_seen_at, metadata "
                "FROM check_report WHERE scan_run_id = %s",
                (scan_run_id,),
            )
            row = cur.fetchone()
        conn.close()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Database error: {e}")

    if not row:
        raise HTTPException(status_code=404, detail="Check scan not found")

    return {
        "scan_run_id": row["scan_run_id"],
        "status": row["status"],
        "provider": row.get("provider"),
        "discovery_scan_id": row.get("discovery_scan_id"),
        "started_at": str(row.get("first_seen_at", "")),
    }


@app.get("/api/v1/checks")
async def list_checks(
    tenant_id: str = Query(...),
    status: Optional[str] = Query(None),
    provider: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=1000),
):
    """List check scans from DB."""
    from psycopg2.extras import RealDictCursor
    try:
        conn = _get_check_conn()
        conditions = ["tenant_id = %s"]
        params: list = [tenant_id]
        if status:
            conditions.append("status = %s")
            params.append(status)
        if provider:
            conditions.append("provider = %s")
            params.append(provider.lower())
        where = " AND ".join(conditions)
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                f"SELECT scan_run_id, status, provider, discovery_scan_id, first_seen_at "
                f"FROM check_report WHERE {where} ORDER BY first_seen_at DESC LIMIT %s",
                params + [limit],
            )
            rows = cur.fetchall()
        conn.close()
        return {"scans": rows, "total": len(rows)}
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Database error: {e}")


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
    account_id: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
    service: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    domain: Optional[str] = Query(None),
    posture_category: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    scan_run_id: Optional[str] = Query(None),
):
    """
    Aggregated summary for the misconfigurations dashboard.

    Returns severity counts, top failing rules, service breakdown,
    posture category breakdown, and provider distribution.
    Supports multi-CSP filtering by provider, account (account_id), region.
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
        if account_id:
            conditions.append("cf.account_id = %s")
            params.append(account_id)
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
        if scan_run_id:
            conditions.append("cf.scan_run_id = %s")
            params.append(scan_run_id)

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
    account_id: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
    service: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    domain: Optional[str] = Query(None),
    posture_category: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    scan_run_id: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    sort_by: str = Query("severity"),
    sort_order: str = Query("asc"),
):
    """
    List all check findings with filtering, pagination, and sorting.

    Multi-CSP: filter by provider, account_id (account), region.
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
        if account_id:
            conditions.append("cf.account_id = %s")
            params.append(account_id)
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
        if scan_run_id:
            conditions.append("cf.scan_run_id = %s")
            params.append(scan_run_id)

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
            "first_seen_at": "cf.first_seen_at",
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
                    cf.scan_run_id,
                    cf.provider,
                    cf.account_id,
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
                    cf.first_seen_at,
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
                ORDER BY {order_col} {order_dir}, cf.first_seen_at DESC
                LIMIT %s OFFSET %s
            """, (*params, page_size, offset))
            rows = cur.fetchall()

        findings = []
        for r in rows:
            created = r.get("first_seen_at")
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
                "account_id": r.get("account_id") or "",
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
                "first_seen_at": created.isoformat() if created else None,
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
                SELECT resource_uid AS uid, scan_run_id
                FROM check_findings
                WHERE resource_uid = %s
                  AND tenant_id = %s
                ORDER BY first_seen_at DESC
                LIMIT 1
            """, (resource_uid, tenant_id))
            row = cur.fetchone()

            if not row and '/' not in resource_uid and ':' not in resource_uid:
                # Short-name → try suffix match
                cur.execute("""
                    SELECT resource_uid AS uid, scan_run_id
                    FROM check_findings
                    WHERE resource_uid LIKE %s
                      AND tenant_id = %s
                    ORDER BY first_seen_at DESC
                    LIMIT 1
                """, (f'%/{resource_uid}', tenant_id))
                row = cur.fetchone()

            if row:
                resolved_uid = row["uid"]
                latest_scan_id = row["scan_run_id"]
            else:
                latest_scan_id = None

        # Build the reusable WHERE params — always use resolved_uid + latest scan
        uid_match = "cf.resource_uid = %s"
        scan_filter = ""
        base_params: list = [resolved_uid, tenant_id]
        if latest_scan_id:
            scan_filter = " AND cf.scan_run_id = %s"
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
                    cf.first_seen_at,
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
                    cf.first_seen_at DESC
                LIMIT %s
            """, (*base_params, limit))
            detail_rows = cur.fetchall()

        findings = []
        for r in detail_rows:
            created = r.get("first_seen_at")
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
                "first_seen_at": created.isoformat() if created else None,
            })

        return {
            "resource_uid": resource_uid,
            "severity_counts": severity_counts,
            "posture_by_domain": posture_by_domain,
            "findings": findings,
        }
    finally:
        conn.close()


# ── Batch severity endpoint (used by BFF graph view) ─────────────────────


class BatchSeverityRequest(BaseModel):
    """Request body for batch severity lookup."""
    resource_uids: List[str]
    tenant_id: str


@app.post("/api/v1/check/findings/batch-severity")
async def batch_severity(payload: BatchSeverityRequest):
    """
    Return severity counts grouped by resource_uid for a list of UIDs.

    Used by the BFF graph view to enrich architecture diagram nodes
    with posture data in a single batch call (instead of N individual calls).

    Handles UID format mismatch: inventory uses canonical UIDs
    (provider/account/region/service.type/id) while check_findings may use
    ARN format. Matches on both resource_uid and suffix of resource_uid.
    """
    from psycopg2.extras import RealDictCursor

    resource_uids = payload.resource_uids
    tenant_id = payload.tenant_id

    if not resource_uids or not tenant_id:
        return {"results": {}}

    # Extract short IDs (last segment after '/') for suffix matching
    short_ids = [uid.rsplit("/", 1)[-1] for uid in resource_uids]

    try:
        conn = _get_check_conn()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Database unavailable: {e}")

    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Match on full resource_uid OR resource_id (short form)
            # Only count FAIL findings (misconfigurations)
            cur.execute("""
                SELECT
                    COALESCE(cf.resource_uid, cf.resource_id) AS matched_uid,
                    cf.resource_id,
                    LOWER(COALESCE(rm.severity, 'medium')) AS severity,
                    COUNT(*) AS cnt
                FROM check_findings cf
                LEFT JOIN rule_metadata rm ON rm.rule_id = cf.rule_id
                WHERE cf.tenant_id = %s
                  AND cf.status = 'FAIL'
                  AND (cf.resource_uid = ANY(%s) OR cf.resource_id = ANY(%s))
                GROUP BY COALESCE(cf.resource_uid, cf.resource_id), cf.resource_id,
                         LOWER(COALESCE(rm.severity, 'medium'))
            """, (tenant_id, resource_uids, short_ids))
            rows = cur.fetchall()

        # Build results map: keyed by both full UID and short ID for flexible matching
        results: Dict[str, Dict[str, int]] = {}

        for r in rows:
            matched_uid = r.get("matched_uid", "")
            resource_id = r.get("resource_id", "")
            sev = r.get("severity", "medium")
            cnt = int(r.get("cnt") or 0)

            # Populate for the matched UID
            if matched_uid:
                if matched_uid not in results:
                    results[matched_uid] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                if sev in results[matched_uid]:
                    results[matched_uid][sev] += cnt

            # Also populate for the short resource_id (cross-reference)
            if resource_id and resource_id != matched_uid:
                if resource_id not in results:
                    results[resource_id] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                if sev in results[resource_id]:
                    results[resource_id][sev] += cnt

        return {"results": results}
    finally:
        conn.close()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8002")))
