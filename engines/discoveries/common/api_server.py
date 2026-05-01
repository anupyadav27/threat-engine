"""
Common FastAPI server for Multi-CSP Discoveries Engine (Lightweight API)

This server is a thin API layer that:
1. Receives scan requests (scan_run_id)
2. Creates a K8s Job on a spot node to run the actual scan
3. Exposes scan status by reading discovery_report DB table

The heavy scan work runs in a separate K8s Job pod (run_scan.py).
"""

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Any, Dict, List, Optional
import sys
import psycopg2
import psycopg2.extras
import os
import logging

# Add project root for engine_common
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))
from engine_common.logger import setup_logger, LogContext, log_duration
from engine_common.telemetry import configure_telemetry
from engine_common.orchestration import get_orchestration_metadata

from common.database.database_manager import DatabaseManager
from engine_common.job_creator import create_engine_job

logger = setup_logger(__name__, engine_name="engine-discoveries-common")

# ── Auth imports (engine_auth is COPY shared/auth/ ./engine_auth/ in Dockerfile) ──
try:
    from engine_auth.fastapi.middleware import AuthMiddleware
    from engine_auth.fastapi.dependencies import require_permission
    from engine_auth.core.models import AuthContext
    _AUTH_AVAILABLE = True
except ImportError:
    _AUTH_AVAILABLE = False
    AuthContext = None  # type: ignore[assignment,misc]


def strip_sensitive_fields(data: List[Dict[str, Any]], auth: Any) -> List[Dict[str, Any]]:
    """Remove credential and raw-evidence fields based on caller's auth level.

    Args:
        data: List of resource/finding dicts.
        auth: AuthContext instance (or None when auth is unavailable).

    Returns:
        New list with sensitive fields removed; original dicts are not mutated.
    """
    if not isinstance(data, list):
        return data
    stripped = []
    for row in data:
        r = dict(row) if not isinstance(row, dict) else row.copy()
        if auth is not None and auth.level > 1:
            r.pop("credential_ref", None)
            r.pop("credential_type", None)
        if auth is not None and auth.level >= 4:
            r.pop("raw_data", None)
            r.pop("evidence", None)
        stripped.append(r)
    return stripped


app = FastAPI(
    title="Multi-CSP Discoveries Engine API",
    description="Lightweight API layer — scans run as on-demand K8s Jobs on spot nodes",
    version="3.0.0"
)
configure_telemetry("engine-discoveries", app)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# AuthMiddleware validates access_token / X-Auth-Context for every non-health path
if _AUTH_AVAILABLE:
    app.add_middleware(AuthMiddleware)

# Scanner image (same Docker image, different CMD)
SCANNER_IMAGE = os.getenv(
    "DISCOVERY_SCANNER_IMAGE",
    "yadavanup84/engine-discoveries:v-scan-upload",
)
SCANNER_NAMESPACE = os.getenv("SCANNER_NAMESPACE", "threat-engine-engines")
SCANNER_SERVICE_ACCOUNT = os.getenv("SCANNER_SERVICE_ACCOUNT", "engine-sa")
SCANNER_CPU_REQUEST = os.getenv("SCANNER_CPU_REQUEST", "4")
SCANNER_MEM_REQUEST = os.getenv("SCANNER_MEM_REQUEST", "8Gi")
SCANNER_CPU_LIMIT = os.getenv("SCANNER_CPU_LIMIT", "4")    # 4 vCPU — doubles thread throughput vs old 2 vCPU
SCANNER_MEM_LIMIT = os.getenv("SCANNER_MEM_LIMIT", "16Gi") # 16 Gi — headroom for org-wide in-memory results

# Shared DatabaseManager for health checks and status queries
_db_manager = None

def _get_db_manager():
    global _db_manager
    if _db_manager is None:
        try:
            _db_manager = DatabaseManager()
        except Exception:
            pass
    return _db_manager

metrics = {
    "total_scans": 0,
    "successful_scans": 0,
    "failed_scans": 0,
}


def _coerce_list(v):
    """Accept str (comma-separated), list, or None → List[str] or None."""
    if v is None or v == "" or v == []:
        return None
    if isinstance(v, str):
        return [s.strip() for s in v.split(",") if s.strip()]
    return v


class DiscoveryRequest(BaseModel):
    """Discovery scan request model (CSP-agnostic)"""
    # Pipeline scan_run_id
    scan_run_id: Optional[str] = None

    # Legacy parameters (optional when scan_run_id is provided)
    customer_id: Optional[str] = None
    tenant_id: Optional[str] = None
    provider: str = "aws"  # aws, azure, gcp, oci, alicloud
    account_id: Optional[str] = None
    hierarchy_type: str = "account"  # account, subscription, project, tenancy
    include_services: Optional[List[str]] = None
    include_regions: Optional[List[str]] = None
    exclude_regions: Optional[List[str]] = None
    credentials: Optional[Dict[str, Any]] = None
    use_database: Optional[bool] = None  # If None, auto-detect

    from pydantic import model_validator

    @model_validator(mode="before")
    @classmethod
    def _coerce_filters(cls, values):
        for field in ("include_services", "include_regions", "exclude_regions"):
            if field in values:
                values[field] = _coerce_list(values[field])
        return values


class DiscoveryResponse(BaseModel):
    """Discovery scan response model"""
    scan_run_id: str
    status: str
    message: str
    scan_run_id_ref: Optional[str] = None
    provider: Optional[str] = None


# ── K8s Job creation ─────────────────────────────────────────────────────────

def _create_scanner_job(scan_run_id: str, scan_run_id_ref: str, provider: str) -> str:
    """Create a K8s Job to run the discovery scan on a spot node."""
    from kubernetes import client as k8s_client

    extra_env = [
        k8s_client.V1EnvVar(name="MAX_CONCURRENT_TASKS", value=os.getenv("MAX_CONCURRENT_TASKS", "1000")),
        k8s_client.V1EnvVar(name="OPERATION_TIMEOUT", value=os.getenv("OPERATION_TIMEOUT", "60")),
        k8s_client.V1EnvVar(name="SERVICE_SCAN_TIMEOUT", value=os.getenv("SERVICE_SCAN_TIMEOUT", "900")),
        k8s_client.V1EnvVar(name="DISCOVERY_MODE", value="database"),
        k8s_client.V1EnvVar(name="DISCOVERY_CONFIG_SOURCE", value="database"),
    ]
    return create_engine_job(
        engine_name="discovery",
        scan_id=scan_run_id,
        scan_run_id=scan_run_id_ref,
        image=SCANNER_IMAGE,
        cpu_request=SCANNER_CPU_REQUEST,
        mem_request=SCANNER_MEM_REQUEST,
        cpu_limit=SCANNER_CPU_LIMIT,
        mem_limit=SCANNER_MEM_LIMIT,
        active_deadline_seconds=7200,
        extra_env=extra_env,
    )


# ── Orchestration helper ─────────────────────────────────────────────────────

async def _get_scan_context_from_orchestration(scan_run_id: str) -> Dict[str, Any]:
    """Query onboarding DB for scan context using scan_run_id."""
    try:
        metadata = get_orchestration_metadata(scan_run_id)
        if not metadata:
            raise ValueError(f"No orchestration metadata for {scan_run_id}")
        return metadata
    except Exception as e:
        logger.error(f"Failed to retrieve orchestration metadata: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# ── POST /api/v1/discovery — create a K8s Job ───────────────────────────────

@app.post("/api/v1/discovery", response_model=DiscoveryResponse)
async def create_discovery(request: DiscoveryRequest):
    """
    Trigger a discovery scan by creating a K8s Job on a spot node.

    Flow:
    1. Resolve orchestration metadata (account, provider)
    2. Pre-create discovery_report row in DB (status=running)
    3. Create K8s Job (spot node, high CPU/RAM)
    4. Return scan_run_id immediately
    """
    scan_run_id_param = request.scan_run_id

    if not scan_run_id_param:
        raise HTTPException(status_code=400, detail="scan_run_id is required")

    scan_run_id = scan_run_id_param

    try:
        # 1. Resolve orchestration metadata
        metadata = await _get_scan_context_from_orchestration(scan_run_id)
        provider = metadata.get("provider", "aws")
        account_id = metadata.get("account_id")
        tenant_id = metadata.get("tenant_id", "default-tenant")
        customer_id = metadata.get("customer_id", "default")
        account_id = metadata.get("account_id") or account_id

        # 2. Pre-create scan record in DB so GET endpoint works immediately
        db = _get_db_manager()
        if db:
            db.create_scan(
                scan_id=scan_run_id,
                customer_id=customer_id,
                tenant_id=tenant_id,
                provider=provider,
                account_id=account_id,
                metadata={"scan_run_id": scan_run_id, "mode": "job"},
            )

        # 3. Create K8s Job on spot node
        job_name = _create_scanner_job(scan_run_id, scan_run_id, provider)

        metrics["total_scans"] += 1

        return DiscoveryResponse(
            scan_run_id=scan_run_id,
            status="running",
            message=f"Scanner Job '{job_name}' created on spot node (image={SCANNER_IMAGE})",
            scan_run_id_ref=scan_run_id,
            provider=provider,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create discovery scan: {e}", exc_info=True)
        # Mark as failed if DB row was created
        try:
            db = _get_db_manager()
            if db:
                db.update_scan_status(scan_run_id, "failed")
        except Exception:
            pass
        raise HTTPException(status_code=500, detail=str(e))


# ── GET /api/v1/discovery/{scan_id} — read status from DB ───────────────────

@app.get("/api/v1/discovery/{scan_id}")
async def get_scan_status(scan_id: str):
    """Get discovery scan status from discovery_report DB table.

    If DB shows 'running' but the K8s Job has failed, auto-updates to 'failed'
    so Argo step pods don't poll forever.
    """
    db = _get_db_manager()
    if not db:
        raise HTTPException(status_code=503, detail="Database unavailable")

    conn = db._get_connection()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT status, provider, metadata, first_seen_at "
                "FROM discovery_report WHERE scan_run_id = %s",
                (scan_id,),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Scan not found")

            status = row["status"]

            # If still 'running', check whether the K8s Job actually failed
            # (scanner crash before DB update leaves status stuck at 'running')
            if status == "running":
                try:
                    from kubernetes import client as k8s_client, config as k8s_config
                    try:
                        k8s_config.load_incluster_config()
                    except Exception:
                        k8s_config.load_kube_config()
                    batch = k8s_client.BatchV1Api()
                    short_id = scan_id.replace("-", "")[:12]
                    jobs = batch.list_namespaced_job(
                        namespace=SCANNER_NAMESPACE,
                        label_selector=f"scan-run-id={scan_id}",
                    )
                    for job in jobs.items:
                        conditions = job.status.conditions or []
                        failed = any(c.type == "Failed" and c.status == "True" for c in conditions)
                        if failed:
                            cur.execute(
                                "UPDATE discovery_report SET status='failed' WHERE scan_run_id=%s",
                                (scan_id,),
                            )
                            conn.commit()
                            status = "failed"
                            logger.warning(f"Auto-marked scan {scan_id} as failed (K8s Job failed)")
                            break
                except Exception as e:
                    logger.debug(f"K8s Job check skipped: {e}")

            meta = row["metadata"] if isinstance(row["metadata"], dict) else {}
            return {
                "status": status,
                "provider": row.get("provider"),
                "started_at": str(row.get("first_seen_at") or ""),
                "metadata": meta,
            }
    finally:
        db._return_connection(conn)


@app.get("/api/v1/discovery/{scan_id}/timing")
async def get_scan_timing(scan_id: str):
    """
    Return the structured timing report for a completed discovery scan.

    The report is persisted into discovery_report.metadata['timing'] at the
    end of every scan.  It breaks down total, phase1, phase2, per-account,
    global pool vs regional pool elapsed times, and top-5 slowest services.

    Used by the API gateway /api/v1/views/scan-timing endpoint.
    """
    db = _get_db_manager()
    if not db:
        raise HTTPException(status_code=503, detail="Database unavailable")

    conn = db._get_connection()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT status, metadata FROM discovery_report WHERE scan_run_id = %s",
                (scan_id,),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Scan not found")

            meta = row["metadata"] if isinstance(row["metadata"], dict) else {}
            timing = meta.get("timing")

            return {
                "scan_run_id": scan_id,
                "scan_status": row["status"],
                "timing_available": timing is not None,
                "timing": timing or {},
            }
    finally:
        db._return_connection(conn)


@app.get("/api/v1/discovery/{scan_id}/service-results")
async def get_service_results(
    scan_id: str,
    status: Optional[str] = None,
    service: Optional[str] = None,
):
    """Per-service discovery outcomes for a scan.

    Returns one row per (service, region) pair attempted.
    Use ?status=failed or ?status=access_denied to filter for errors.
    """
    db = _get_db_manager()
    if db is None:
        raise HTTPException(status_code=503, detail="Database unavailable")

    conn = db._get_connection()
    try:
        with conn.cursor() as cur:
            query = """
                SELECT service, region, status, discoveries_count,
                       error_code, error_message, scan_duration_ms, created_at
                FROM service_scan_attempts
                WHERE scan_run_id = %s
            """
            params: list = [scan_id]
            if status:
                query += " AND status = %s"
                params.append(status)
            if service:
                query += " AND service = %s"
                params.append(service)
            query += " ORDER BY status, service, region"

            cur.execute(query, params)
            cols = [d[0] for d in cur.description]
            rows = [dict(zip(cols, row)) for row in cur.fetchall()]

        # Build summary counts
        from collections import Counter
        status_counts = Counter(r["status"] for r in rows)
        return {
            "scan_run_id": scan_id,
            "total": len(rows),
            "summary": dict(status_counts),
            "results": rows,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db._return_connection(conn)


def _get_onboarding_conn():
    """Direct psycopg2 connection to onboarding DB."""
    return psycopg2.connect(
        host=os.getenv("ONBOARDING_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("ONBOARDING_DB_PORT", os.getenv("DB_PORT", "5432"))),
        database=os.getenv("ONBOARDING_DB_NAME", "threat_engine_onboarding"),
        user=os.getenv("ONBOARDING_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("ONBOARDING_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        connect_timeout=10,
    )


def _get_discoveries_conn():
    """Direct psycopg2 connection to discoveries DB."""
    return psycopg2.connect(
        host=os.getenv("DISCOVERIES_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("DISCOVERIES_DB_PORT", os.getenv("DB_PORT", "5432"))),
        database=os.getenv("DISCOVERIES_DB_NAME", "threat_engine_discoveries"),
        user=os.getenv("DISCOVERIES_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("DISCOVERIES_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        connect_timeout=10,
    )


# ── GET /api/v1/accounts ─────────────────────────────────────────────────────
#
# Unified account list used by CIEM and any other engine that needs to know
# ALL accounts in scope — both manually onboarded AND sub-accounts discovered
# via org-level scanning (AWS Organizations, Azure Management Groups, GCP Folders).
#
# is_onboarded=True  → cloud_accounts row exists; has its own credential_ref
# is_onboarded=False → discovered sub-account only; inherits parent credentials
#
@app.get("/api/v1/accounts")
async def list_accounts(
    tenant_id: str = Query(..., description="Tenant identifier"),
    provider: Optional[str] = Query(None, description="Filter by provider (aws/azure/gcp/...)"),
    include_sub_accounts: bool = Query(True, description="Include sub-accounts found in discovery"),
):
    """Return all accounts in scope: onboarded masters + discovered sub-accounts.

    Called by CIEM scan/all, and any engine that needs the full account universe.
    """
    accounts: List[Dict[str, Any]] = []

    # ── 1. Onboarded master accounts (cloud_accounts table) ──
    try:
        conn_onb = _get_onboarding_conn()
        with conn_onb.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            where = "tenant_id = %s AND account_status = 'active'"
            params: list = [tenant_id]
            if provider:
                where += " AND provider = %s"
                params.append(provider.lower())
            cur.execute(
                f"""
                SELECT account_number AS account_id,
                       tenant_id, provider,
                       credential_type, credential_ref,
                       account_name
                FROM cloud_accounts
                WHERE {where}
                ORDER BY provider, account_number
                """,
                params,
            )
            for row in cur.fetchall():
                accounts.append({
                    **dict(row),
                    "is_onboarded": True,
                    "parent_account_id": None,
                    "parent_credential_ref": None,
                    "regions": [],           # filled from discovery below
                    "source": "cloud_accounts",
                })
        conn_onb.close()
    except Exception as e:
        logger.warning(f"/api/v1/accounts: could not query cloud_accounts: {e}")

    onboarded_ids = {a["account_id"] for a in accounts}

    # ── 2. Discovered account regions (discovery_findings) ──
    # Two uses:
    #   a) Fill `regions` for onboarded accounts (which regions were actually scanned)
    #   b) Find sub-accounts discovered during org scanning (account_id not in cloud_accounts)
    if include_sub_accounts or accounts:
        try:
            conn_disc = _get_discoveries_conn()
            with conn_disc.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                disc_where = "tenant_id = %s AND account_id IS NOT NULL AND region IS NOT NULL"
                disc_params: list = [tenant_id]
                if provider:
                    disc_where += " AND provider = %s"
                    disc_params.append(provider.lower())

                cur.execute(
                    f"""
                    SELECT account_id, provider,
                           array_agg(DISTINCT region ORDER BY region) AS regions
                    FROM discovery_findings
                    WHERE {disc_where}
                    GROUP BY account_id, provider
                    """,
                    disc_params,
                )
                for row in cur.fetchall():
                    acc_id = row["account_id"]
                    regions = list(row["regions"] or [])
                    prov = row["provider"] or (provider or "")

                    if acc_id in onboarded_ids:
                        # Enrich existing onboarded account with its discovered regions
                        for a in accounts:
                            if a["account_id"] == acc_id:
                                a["regions"] = regions
                                break
                    elif include_sub_accounts:
                        # Sub-account — discovered but not onboarded.
                        # Find the parent (onboarded account for same tenant+provider)
                        parent = next(
                            (a for a in accounts
                             if a["tenant_id"] == tenant_id
                             and a["provider"] == prov
                             and a["is_onboarded"]),
                            None,
                        )
                        accounts.append({
                            "account_id": acc_id,
                            "tenant_id": tenant_id,
                            "provider": prov,
                            "account_name": acc_id,
                            "credential_type": parent["credential_type"] if parent else None,
                            "credential_ref": parent["credential_ref"] if parent else None,
                            "is_onboarded": False,
                            "parent_account_id": parent["account_id"] if parent else None,
                            "parent_credential_ref": parent["credential_ref"] if parent else None,
                            "regions": regions,
                            "source": "discovery",
                        })
            conn_disc.close()
        except Exception as e:
            logger.warning(f"/api/v1/accounts: could not query discovery_findings: {e}")

    return {
        "total": len(accounts),
        "onboarded": sum(1 for a in accounts if a["is_onboarded"]),
        "discovered": sum(1 for a in accounts if not a["is_onboarded"]),
        "accounts": accounts,
    }


# ── GET /api/v1/resources ────────────────────────────────────────────────────
#
# Generic resource query — any engine can call this to get discovered resources
# of a given type. Backed by discovery_findings.
#
# Examples:
#   GET /api/v1/resources?tenant_id=t1&service=s3            → all S3 buckets
#   GET /api/v1/resources?tenant_id=t1&service=ec2&region=us-east-1
#   GET /api/v1/resources?tenant_id=t1&resource_type=bucket
#
@app.get("/api/v1/resources")
async def query_resources(
    tenant_id: str = Query(..., description="Tenant identifier"),
    service: Optional[str] = Query(None, description="Service filter, e.g. s3, ec2, organizations"),
    resource_type: Optional[str] = Query(None, description="resource_type filter (partial match)"),
    provider: Optional[str] = Query(None, description="Provider filter (aws/azure/gcp/...)"),
    account_id: Optional[str] = Query(None, description="Account ID filter"),
    region: Optional[str] = Query(None, description="Region filter"),
    scan_run_id: Optional[str] = Query(None, description="Limit to a specific scan"),
    limit: int = Query(1000, le=10000),
    offset: int = Query(0),
    auth: Any = Depends(require_permission("discoveries:read") if _AUTH_AVAILABLE else (lambda: None)),
):
    """Query discovery_findings for a given resource type or service.

    Used by downstream engines (CIEM, check, threat) to query specific
    resource classes without direct DB access.
    """
    try:
        conn = _get_discoveries_conn()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            conditions = ["tenant_id = %s"]
            params: list = [tenant_id]

            if provider:
                conditions.append("provider = %s")
                params.append(provider.lower())
            if account_id:
                conditions.append("account_id = %s")
                params.append(account_id)
            if region:
                conditions.append("region = %s")
                params.append(region)
            if scan_run_id:
                conditions.append("scan_run_id = %s")
                params.append(scan_run_id)
            if service:
                conditions.append("service = %s")
                params.append(service.lower())
            if resource_type:
                conditions.append("resource_type ILIKE %s")
                params.append(f"%{resource_type}%")

            where = " AND ".join(conditions)
            params_count = params[:]
            cur.execute(f"SELECT COUNT(*) AS total FROM discovery_findings WHERE {where}", params_count)
            total = cur.fetchone()["total"]

            params.extend([limit, offset])
            cur.execute(
                f"""
                SELECT resource_uid, resource_type, resource_name,
                       service, provider, account_id, region,
                       scan_run_id, first_seen_at, last_seen_at
                FROM discovery_findings
                WHERE {where}
                ORDER BY first_seen_at DESC
                LIMIT %s OFFSET %s
                """,
                params,
            )
            resources = [dict(r) for r in cur.fetchall()]
        conn.close()
        shaped = strip_sensitive_fields(resources, auth)
        return {"total": total, "resources": shaped, "limit": limit, "offset": offset}
    except Exception as e:
        logger.error(f"/api/v1/resources error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
async def health_check():
    """Health check endpoint (CSP-agnostic)"""
    db = _get_db_manager()
    if db is None:
        return {"status": "degraded", "database": "unavailable"}

    try:
        db.test_connection()
        return {"status": "healthy", "database": "connected"}
    except Exception:
        return {"status": "degraded", "database": "error"}


@app.get("/api/v1/health/live")
async def liveness_check():
    """Kubernetes liveness probe endpoint"""
    return {"status": "alive"}


@app.get("/api/v1/health/ready")
async def readiness_check():
    """Kubernetes readiness probe endpoint - lightweight check without database"""
    # For now, just return ready if the app started successfully
    # Database connection will be checked on first scan request
    return {"status": "ready", "message": "Application started successfully"}


@app.get("/metrics")
async def get_metrics():
    """Get scan metrics (CSP-agnostic)"""
    return metrics


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
