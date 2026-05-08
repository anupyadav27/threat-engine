"""
CIEM Engine API Server

FastAPI server for CIEM log collection and detection findings.
Port: 8025

Endpoints:
  POST /api/v1/scan                       — Start log collection for one account (K8s Job)
  POST /api/v1/scan/all                   — Start log collection for all accounts (hourly CronWorkflow)

  GET  /api/v1/ciem/findings              — Query CIEM detection findings
  GET  /api/v1/ciem/findings/{finding_id} — Get single finding detail
  GET  /api/v1/ciem/dashboard             — Dashboard summary (counts, trends)
  GET  /api/v1/ciem/identities            — Identity risk summary
  GET  /api/v1/ciem/top-rules             — Top triggered rules
  GET  /api/v1/ciem/log-sources           — Log source coverage status
  GET  /api/v1/ciem/report/{scan_run_id}  — Scan report

  GET  /api/v1/health/live                — Liveness probe
  GET  /api/v1/health/ready               — Readiness probe
"""

import os
import sys
import json
import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import unquote
from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from engine_common.db_connections import get_ciem_conn, get_onboarding_conn
from engine_common.logger import setup_logger
from engine_common.telemetry import configure_telemetry
from engine_common.middleware import RequestLoggingMiddleware, CorrelationIDMiddleware
from engine_common.orchestration import get_orchestration_metadata
from engine_common.job_creator import create_engine_job

# ── Auth imports (engine_auth is COPY shared/auth/ ./engine_auth/ in Dockerfile) ──
try:
    from engine_auth.fastapi.middleware import AuthMiddleware
    from engine_auth.fastapi.dependencies import require_permission
    from engine_auth.core.models import AuthContext
    _AUTH_AVAILABLE = True
except ImportError:
    _AUTH_AVAILABLE = False
    AuthContext = None  # type: ignore[assignment,misc]

    def require_permission(_perm: str):  # type: ignore[no-redef]
        """Fallback used only when engine_auth is unavailable.

        Returns a dependency that always raises 401 — fail-closed instead
        of silently bypassing auth. Production images bundle engine_auth so
        this branch only fires in stripped test/dev images.
        """
        def _denied():
            from fastapi import HTTPException
            raise HTTPException(status_code=401, detail="auth module unavailable")
        return _denied


def strip_sensitive_fields(data: List[Dict[str, Any]], auth: Any) -> List[Dict[str, Any]]:
    """Remove credential and raw audit-log fields based on caller's auth level.

    For CIEM engine:
    - level > 1: strip credential_ref, credential_type
    - level >= 4: also strip event_raw (raw CloudTrail / audit log line)

    Args:
        data: List of finding dicts.
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
            r.pop("event_raw", None)
        stripped.append(r)
    return stripped

logger = setup_logger(__name__, engine_name="engine-ciem")

app = FastAPI(
    title="Log Collection Engine API",
    description="Cloud log collection, normalization, and querying",
    version="1.0.0",
)
configure_telemetry("engine-ciem", app)

app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(CorrelationIDMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# AuthMiddleware validates access_token / X-Auth-Context for every non-health path
if _AUTH_AVAILABLE:
    app.add_middleware(AuthMiddleware)
else:
    logger.critical(
        "engine_auth module not available — all API requests will return 401. "
        "Production images MUST include engine_auth. Failing closed."
    )

# Scanner job config
SCANNER_IMAGE = os.getenv("CIEM_SCANNER_IMAGE", "yadavanup84/engine-ciem:v-std-cols")
SCANNER_CPU = os.getenv("SCANNER_CPU_REQUEST", "250m")
SCANNER_MEM = os.getenv("SCANNER_MEM_REQUEST", "512Mi")
SCANNER_MEM_LIMIT = os.getenv("SCANNER_MEM_LIMIT", "4Gi")


# ── Models ──

class ScanRequest(BaseModel):
    scan_run_id: str
    tenant_id: str = "default-tenant"
    provider: str = "aws"
    account_id: str = ""
    lookback_hours: int = 24
    max_events: int = 100000
    source_types: Optional[List[str]] = None  # ["cloudtrail", "vpc_flow", "alb"]


class ScanResponse(BaseModel):
    scan_run_id: str
    status: str
    message: str


# ── Health ──

@app.get("/api/v1/health/live")
async def health_live():
    return {"status": "alive"}


@app.get("/api/v1/health/ready")
async def health_ready():
    return {"status": "ready"}


@app.get("/")
async def root():
    return {"service": "Log Collection Engine", "version": "1.0.0"}


# ── Scan ──

@app.post("/api/v1/scan", response_model=ScanResponse)
async def start_log_collection(request: ScanRequest):
    """Start log collection by creating a K8s Job."""
    scan_run_id = request.scan_run_id

    meta = get_orchestration_metadata(scan_run_id)
    if not meta:
        raise HTTPException(status_code=404, detail=f"Scan run {scan_run_id} not found in scan_runs")

    from kubernetes import client as k8s_client
    # Always forward lookback/max_events so scanner Job gets the right value.
    # If caller didn't specify, fall back to this pod's own env (set via deployment).
    _lookback = str(request.lookback_hours) if request.lookback_hours else os.getenv("LOG_LOOKBACK_HOURS", "1")
    _max_ev   = str(request.max_events)    if request.max_events    else os.getenv("LOG_MAX_EVENTS", "500000")
    extra_env = [
        k8s_client.V1EnvVar(name="LOG_LOOKBACK_HOURS", value=_lookback),
        k8s_client.V1EnvVar(name="LOG_MAX_EVENTS",     value=_max_ev),
    ]

    try:
        job_name = create_engine_job(
            engine_name="log-collection",
            scan_id=scan_run_id,
            scan_run_id=scan_run_id,
            image=SCANNER_IMAGE,
            cpu_request=SCANNER_CPU,
            mem_request=SCANNER_MEM,
            mem_limit=SCANNER_MEM_LIMIT,
            active_deadline_seconds=7200,
            extra_env=extra_env or None,
            use_spot=True,  # TODO: switch to dedicated on-demand node group when provisioned
        )
    except Exception as e:
        logger.error(f"Failed to create log collection Job: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to create Job: {e}")

    return ScanResponse(
        scan_run_id=scan_run_id,
        status="running",
        message=f"Log collection Job '{job_name}' created (image={SCANNER_IMAGE})",
    )


DISCOVERIES_API_URL = os.getenv("DISCOVERIES_API_URL", "http://engine-discoveries")


def _fetch_all_accounts() -> List[dict]:
    """Fetch all accounts (onboarded + discovered sub-accounts) from discoveries API.

    The discoveries engine merges cloud_accounts (onboarding DB) with
    sub-accounts found in discovery_findings, so CIEM gets the complete
    account universe without needing its own DB queries.

    Falls back to querying cloud_accounts directly if discoveries API is down.
    """
    import urllib.request as _req

    # Get distinct tenant IDs from onboarding DB first
    tenants: List[str] = []
    try:
        import psycopg2.extras
        conn = get_onboarding_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT DISTINCT tenant_id FROM cloud_accounts WHERE account_status = 'active'")
            tenants = [row[0] for row in cur.fetchall()]
        conn.close()
    except Exception as e:
        logger.warning(f"scan/all: could not fetch tenants from onboarding DB: {e}")

    all_accounts: List[dict] = []
    for tenant_id in tenants:
        url = f"{DISCOVERIES_API_URL}/api/v1/accounts?tenant_id={tenant_id}&include_sub_accounts=true"
        try:
            with _req.urlopen(url, timeout=15) as resp:
                data = json.loads(resp.read())
                all_accounts.extend(data.get("accounts", []))
                logger.info(
                    f"scan/all: tenant={tenant_id} → "
                    f"{data.get('onboarded', 0)} onboarded + {data.get('discovered', 0)} sub-accounts"
                )
        except Exception as e:
            logger.warning(f"scan/all: discoveries API unavailable for tenant={tenant_id}: {e} — falling back to cloud_accounts")
            # Fallback: query cloud_accounts directly for this tenant
            try:
                import psycopg2.extras
                conn = get_onboarding_conn()
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute(
                        "SELECT account_number AS account_id, tenant_id, provider, credential_type, credential_ref FROM cloud_accounts WHERE account_status = 'active' AND tenant_id = %s",
                        (tenant_id,),
                    )
                    for row in cur.fetchall():
                        all_accounts.append({**dict(row), "is_onboarded": True, "regions": []})
                conn.close()
            except Exception as fb_err:
                logger.error(f"scan/all: fallback also failed for tenant={tenant_id}: {fb_err}")

    return all_accounts


@app.post("/api/v1/scan/all")
async def start_all_accounts_ciem(
    auth: Any = Depends(require_permission("ciem:read")),
):
    """Start CIEM log collection for ALL active cloud accounts.

    Called by the CIEM CronWorkflow every hour. Fetches all accounts
    (onboarded + sub-accounts) from the discoveries engine, spawns one
    K8s Job per account on on-demand nodes. Fire-and-forget — no polling.
    Each Job handles all regions for that account via LogSourceFinder,
    which reads region data from discovery_findings.
    """
    accounts = _fetch_all_accounts()

    if not accounts:
        logger.warning("scan/all: no active cloud accounts found")
        return {"jobs_created": 0, "accounts": []}

    logger.info(f"scan/all: found {len(accounts)} active accounts — spawning CIEM Jobs")

    jobs_created = []
    skipped = []

    for acct in accounts:
        account_id  = acct.get("account_id") or acct.get("account_number") or ""
        tenant_id   = acct.get("tenant_id") or "default-tenant"
        provider    = (acct.get("provider") or "aws").lower()
        cred_type   = acct.get("credential_type") or "access_key"
        cred_ref    = acct.get("credential_ref") or acct.get("parent_credential_ref") or ""
        scan_run_id = str(uuid.uuid4())

        # Skip accounts with no usable account identifier — they can't be
        # referenced in scan_runs (FK → cloud_accounts.account_id)
        if not account_id:
            logger.warning(f"scan/all: skipping account with empty account_id for tenant={tenant_id} provider={provider}")
            skipped.append({"account_id": "", "error": "empty account_id"})
            continue

        # 2. Create scan record so run_scan.py can read metadata via get_orchestration_metadata
        try:
            conn_onb2 = get_onboarding_conn()
            with conn_onb2.cursor() as cur:
                cur.execute(
                    "INSERT INTO tenants (tenant_id, customer_id, tenant_name) VALUES (%s, %s, %s) ON CONFLICT (tenant_id) DO NOTHING",
                    (tenant_id, tenant_id, tenant_id),
                )
                cur.execute("""
                    INSERT INTO scan_runs
                        (scan_run_id, tenant_id, account_id, provider,
                         credential_type, credential_ref,
                         overall_status, engines_requested, engines_completed,
                         created_at, started_at)
                    VALUES (%s, %s, %s, %s, %s, %s,
                            'running', '["ciem"]'::jsonb, '{}'::jsonb,
                            NOW(), NOW())
                    ON CONFLICT (scan_run_id) DO NOTHING
                """, (scan_run_id, tenant_id, account_id, provider, cred_type, cred_ref))
            conn_onb2.commit()
            conn_onb2.close()
        except Exception as rec_err:
            logger.warning(f"Could not create scan record for {account_id}: {rec_err}")
            # Non-fatal — run_scan will fall back to params from meta or env

        # 3. Spawn K8s Job for this account (on-demand node)
        try:
            from kubernetes import client as k8s_client
            _lookback = os.getenv("LOG_LOOKBACK_HOURS", "1")
            _max_events = os.getenv("LOG_MAX_EVENTS", "500000")
            job_name = create_engine_job(
                engine_name="log-collection",
                scan_id=scan_run_id,
                scan_run_id=scan_run_id,
                image=SCANNER_IMAGE,
                cpu_request=SCANNER_CPU,
                mem_request=SCANNER_MEM,
                mem_limit=SCANNER_MEM_LIMIT,
                active_deadline_seconds=7200,
                use_spot=True,  # TODO: switch to dedicated on-demand node group when provisioned
                extra_env=[
                    k8s_client.V1EnvVar(name="LOG_LOOKBACK_HOURS", value=_lookback),
                    k8s_client.V1EnvVar(name="LOG_MAX_EVENTS", value=_max_events),
                ],
            )
            jobs_created.append({
                "scan_run_id": scan_run_id,
                "account_id": account_id,
                "tenant_id": tenant_id,
                "provider": provider,
                "job": job_name,
            })
            logger.info(f"scan/all: created Job {job_name} for account={account_id} provider={provider}")
        except Exception as job_err:
            logger.error(f"scan/all: failed to create Job for account={account_id}: {job_err}")
            skipped.append({"account_id": account_id, "error": str(job_err)})

    return {
        "jobs_created": len(jobs_created),
        "jobs_skipped": len(skipped),
        "accounts": jobs_created,
        "skipped": skipped,
    }


@app.post("/api/v1/internal/scan/all")
async def start_all_accounts_ciem_internal():
    """Internal-only: start CIEM log collection for ALL active cloud accounts.

    Identical to POST /api/v1/scan/all but has NO auth dependency.
    Called by the Argo CronWorkflow from inside the cluster, which does
    not carry an access_token cookie or X-Auth-Context header.

    NOTE: This path is intentionally NOT routed through the API gateway —
    it is cluster-internal only (engine-ciem service, port 80).
    Do not expose it externally.
    """
    accounts = _fetch_all_accounts()

    if not accounts:
        logger.warning("internal/scan/all: no active cloud accounts found")
        return {"jobs_created": 0, "jobs_skipped": 0, "accounts": []}

    logger.info(f"internal/scan/all: found {len(accounts)} active accounts — spawning CIEM Jobs")

    jobs_created = []
    skipped = []

    for acct in accounts:
        account_id  = acct.get("account_id") or acct.get("account_number") or ""
        tenant_id   = acct.get("tenant_id") or "default-tenant"
        provider    = (acct.get("provider") or "aws").lower()
        cred_type   = acct.get("credential_type") or "access_key"
        cred_ref    = acct.get("credential_ref") or acct.get("parent_credential_ref") or ""
        scan_run_id = str(uuid.uuid4())

        if not account_id:
            logger.warning(
                f"internal/scan/all: skipping account with empty account_id "
                f"for tenant={tenant_id} provider={provider}"
            )
            skipped.append({"account_id": "", "error": "empty account_id"})
            continue

        try:
            conn_onb2 = get_onboarding_conn()
            with conn_onb2.cursor() as cur:
                cur.execute(
                    "INSERT INTO tenants (tenant_id, customer_id, tenant_name) VALUES (%s, %s, %s) ON CONFLICT (tenant_id) DO NOTHING",
                    (tenant_id, tenant_id, tenant_id),
                )
                cur.execute("""
                    INSERT INTO scan_runs
                        (scan_run_id, tenant_id, account_id, provider,
                         credential_type, credential_ref,
                         overall_status, engines_requested, engines_completed,
                         created_at, started_at)
                    VALUES (%s, %s, %s, %s, %s, %s,
                            'running', '["ciem"]'::jsonb, '{}'::jsonb,
                            NOW(), NOW())
                    ON CONFLICT (scan_run_id) DO NOTHING
                """, (scan_run_id, tenant_id, account_id, provider, cred_type, cred_ref))
            conn_onb2.commit()
            conn_onb2.close()
        except Exception as rec_err:
            logger.warning(f"Could not create scan record for {account_id}: {rec_err}")

        try:
            from kubernetes import client as k8s_client
            _lookback = os.getenv("LOG_LOOKBACK_HOURS", "1")
            _max_events = os.getenv("LOG_MAX_EVENTS", "500000")
            job_name = create_engine_job(
                engine_name="log-collection",
                scan_id=scan_run_id,
                scan_run_id=scan_run_id,
                image=SCANNER_IMAGE,
                cpu_request=SCANNER_CPU,
                mem_request=SCANNER_MEM,
                mem_limit=SCANNER_MEM_LIMIT,
                active_deadline_seconds=7200,
                use_spot=True,
                extra_env=[
                    k8s_client.V1EnvVar(name="LOG_LOOKBACK_HOURS", value=_lookback),
                    k8s_client.V1EnvVar(name="LOG_MAX_EVENTS", value=_max_events),
                ],
            )
            jobs_created.append({
                "scan_run_id": scan_run_id,
                "account_id": account_id,
                "tenant_id": tenant_id,
                "provider": provider,
                "job": job_name,
            })
            logger.info(
                f"internal/scan/all: created Job {job_name} "
                f"for account={account_id} provider={provider}"
            )
        except Exception as job_err:
            logger.error(f"internal/scan/all: failed to create Job for account={account_id}: {job_err}")
            skipped.append({"account_id": account_id, "error": str(job_err)})

    return {
        "jobs_created": len(jobs_created),
        "jobs_skipped": len(skipped),
        "accounts": jobs_created,
        "skipped": skipped,
    }


# ═══════════════════════════════════════════════════════════════
# CIEM Findings & Dashboard
# ═══════════════════════════════════════════════════════════════

@app.get("/api/v1/ciem/findings")
async def query_findings(
    scan_run_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    rule_source: Optional[str] = Query(None),
    primary_engine: Optional[str] = Query(None),
    actor_principal: Optional[str] = Query(None),
    resource_uid: Optional[str] = Query(None),
    rule_id: Optional[str] = Query(None),
    service: Optional[str] = Query(None),
    limit: int = Query(100, le=10000),
    offset: int = Query(0),
    auth: Any = Depends(require_permission("ciem:read")),
):
    """Query CIEM detection findings with filters."""
    import psycopg2.extras
    tenant_id = (
        getattr(auth, "engine_tenant_id", None)
        or getattr(auth, "tenant_id", None)
        or "default-tenant"
    )
    conn = get_ciem_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            conditions = ["tenant_id = %s"]
            params = [tenant_id]

            if scan_run_id:
                conditions.append("scan_run_id = %s")
                params.append(scan_run_id)
            if severity:
                conditions.append("severity = %s")
                params.append(severity)
            if rule_source:
                conditions.append("rule_source = %s")
                params.append(rule_source)
            if primary_engine:
                conditions.append("primary_engine = %s")
                params.append(primary_engine)
            if actor_principal:
                conditions.append("actor_principal LIKE %s")
                params.append(f"%{actor_principal}%")
            if resource_uid:
                conditions.append("resource_uid LIKE %s")
                params.append(f"%{resource_uid}%")
            if rule_id:
                conditions.append("rule_id = %s")
                params.append(rule_id)
            if service:
                conditions.append("service = %s")
                params.append(service)

            where = " AND ".join(conditions)

            cur.execute(f"""
                SELECT finding_id, scan_run_id, rule_id, rule_source,
                       severity, status, primary_engine,
                       resource_uid, resource_type, resource_name,
                       account_id, region, provider,
                       actor_principal, actor_ip,
                       event_time, service, operation,
                       title, description, action_category,
                       mitre_tactics, mitre_techniques
                FROM ciem_findings
                WHERE {where}
                ORDER BY
                    CASE severity
                        WHEN 'critical' THEN 1
                        WHEN 'high' THEN 2
                        WHEN 'medium' THEN 3
                        WHEN 'low' THEN 4
                        ELSE 5
                    END,
                    event_time DESC
                LIMIT %s OFFSET %s
            """, params + [limit, offset])
            findings = [dict(r) for r in cur.fetchall()]

            cur.execute(f"SELECT count(*) FROM ciem_findings WHERE {where}", params)
            total = cur.fetchone()["count"]

        return {"total": total, "findings": strip_sensitive_fields(findings, auth), "limit": limit, "offset": offset}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


@app.get("/api/v1/ciem/findings/{finding_id}")
async def get_finding(finding_id: str):
    """Get detailed finding by ID."""
    import psycopg2.extras
    conn = get_ciem_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM ciem_findings WHERE finding_id = %s", (finding_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")
            return dict(row)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


def _strip_step_fields(steps: List[Dict[str, Any]], auth: Any) -> List[Dict[str, Any]]:
    """Strip sensitive IP fields from contributing_steps for lower-trust callers.

    Removes 'actor_ip' from each step when the caller's auth level is >= 4
    (viewer-tier users should not see raw IP addresses from correlation steps).
    The field is omitted entirely, not set to null.

    Args:
        steps: List of contributing_step dicts from finding_data JSONB.
        auth: AuthContext instance; may be None when auth unavailable.

    Returns:
        New list of step dicts with actor_ip removed for auth.level >= 4.
    """
    if auth is None or getattr(auth, "level", 0) < 4:
        return steps
    return [{k: v for k, v in step.items() if k != "actor_ip"} for step in steps]


@app.get("/api/v1/ciem/findings/{finding_id}/timeline")
async def get_finding_timeline(
    finding_id: str,
    auth: Any = Depends(require_permission("ciem:read")),
):
    """Return ordered contributing steps for an L2 correlation finding.

    Each step represents one L1 finding that contributed to the correlation,
    ordered by event_time ascending so step_idx 0 = the earliest event.
    The timeline endpoint is only valid for findings with rule_source = 'log_correlation'.

    Security: DB query requires BOTH finding_id AND tenant_id to prevent cross-tenant
    reads via predictable finding_id values. Returns 404 (not 403) when tenant check
    fails to avoid disclosing whether a finding_id exists in another tenant.

    Args:
        finding_id: CIEM finding identifier (path parameter).
        auth: AuthContext from require_permission dependency.

    Returns:
        Dict with 'finding_id', 'rule_id', 'steps', 'first_event', 'last_event',
        'event_count'.

    Raises:
        HTTPException 404: Finding not found or belongs to a different tenant.
        HTTPException 400: Finding is not a log_correlation finding, or predates
                          step ordering (contributing_steps absent).
        HTTPException 500: Unexpected database error.
    """
    import psycopg2.extras

    tenant_id = (
        getattr(auth, "engine_tenant_id", None)
        or getattr(auth, "tenant_id", None)
        or "default-tenant"
    )
    conn = get_ciem_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            # Both finding_id AND tenant_id required — prevents cross-tenant reads
            cur.execute(
                """
                SELECT finding_id, rule_id, rule_source, finding_data,
                       first_seen_at, last_seen_at
                FROM ciem_findings
                WHERE finding_id = %s AND tenant_id = %s
                """,
                (finding_id, tenant_id),
            )
            row = cur.fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="Finding not found")

        if row["rule_source"] != "log_correlation":
            raise HTTPException(status_code=400, detail="finding is not a correlation finding")

        # finding_data is JSONB — psycopg2 returns it as a Python dict; never call json.loads()
        finding_data: Dict[str, Any] = row["finding_data"] or {}
        contributing_steps = finding_data.get("contributing_steps")

        if contributing_steps is None:
            raise HTTPException(
                status_code=400,
                detail="finding predates step ordering — re-run CIEM scan to generate steps",
            )

        steps = _strip_step_fields(list(contributing_steps), auth)

        return {
            "finding_id": row["finding_id"],
            "rule_id": row["rule_id"],
            "steps": steps,
            "first_event": finding_data.get("first_event"),
            "last_event": finding_data.get("last_event"),
            "event_count": finding_data.get("event_count", len(steps)),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


def _query_ciem_scan_trend(cur, tenant_id: str) -> list:
    """Last 8 CIEM scan runs — identities_at_risk and rules_triggered per scan."""
    try:
        cur.execute(
            """
            SELECT
                to_char(MAX(event_time), 'Mon DD')                      AS date,
                COUNT(*)                                                  AS total,
                COUNT(*) FILTER (WHERE severity = 'critical')            AS critical,
                COUNT(*) FILTER (WHERE severity = 'high')                AS high,
                COUNT(*) FILTER (WHERE severity = 'medium')              AS medium,
                COUNT(*) FILTER (WHERE severity = 'low')                 AS low,
                COUNT(DISTINCT actor_principal)
                    FILTER (WHERE actor_principal IS NOT NULL
                              AND actor_principal != '')                  AS identities_at_risk,
                COUNT(DISTINCT rule_id)                                   AS rules_triggered
            FROM ciem_findings
            WHERE tenant_id = %s AND scan_run_id IS NOT NULL
            GROUP BY scan_run_id
            ORDER BY MAX(event_time) DESC
            LIMIT 8
            """,
            (tenant_id,),
        )
        rows = list(reversed(cur.fetchall()))
        result = []
        for row in rows:
            total = int(row["total"] or 0)
            crit  = int(row["critical"] or 0)
            high  = int(row["high"] or 0)
            med   = int(row["medium"] or 0)
            low   = int(row["low"] or 0)
            if total > 0:
                weight = crit * 4 + high * 3 + med * 2 + low * 1
                pass_rate = max(0, min(100, round(100 - (weight / (total * 4)) * 100)))
            else:
                pass_rate = 100
            result.append({
                "date":               row["date"] or "",
                "total":              total,
                "critical":           crit,
                "high":               high,
                "medium":             med,
                "low":                low,
                "pass_rate":          pass_rate,
                "identities_at_risk": int(row["identities_at_risk"] or 0),
                "rules_triggered":    int(row["rules_triggered"] or 0),
            })
        return result
    except Exception:
        logger.warning("ciem scan_trend query failed", exc_info=True)
        return []


@app.get("/api/v1/ciem/dashboard")
async def ciem_dashboard(
    scan_run_id: Optional[str] = Query(None),
    auth: Any = Depends(require_permission("ciem:read")),
):
    """CIEM dashboard — summary counts, severity breakdown, engine breakdown, trends."""
    tenant_id = (
        getattr(auth, "engine_tenant_id", None)
        or getattr(auth, "tenant_id", None)
        or "default-tenant"
    )
    import psycopg2.extras
    conn = get_ciem_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            scan_filter = "AND scan_run_id = %s" if scan_run_id else ""
            params = [tenant_id, scan_run_id] if scan_run_id else [tenant_id]

            # Summary counts
            cur.execute(f"""
                SELECT
                    count(*) AS total_findings,
                    count(DISTINCT rule_id) AS rules_triggered,
                    count(DISTINCT actor_principal) FILTER (WHERE actor_principal != '') AS unique_actors,
                    count(DISTINCT resource_uid) FILTER (WHERE resource_uid != '') AS unique_resources,
                    count(DISTINCT account_id) FILTER (WHERE account_id != '') AS accounts,
                    count(*) FILTER (WHERE rule_source = 'log_correlation') AS l2_findings,
                    count(*) FILTER (WHERE rule_source = 'baseline') AS l3_findings
                FROM ciem_findings
                WHERE tenant_id = %s {scan_filter}
            """, params)
            summary = dict(cur.fetchone())

            # By severity
            cur.execute(f"""
                SELECT severity, count(*) AS count
                FROM ciem_findings WHERE tenant_id = %s {scan_filter}
                GROUP BY severity ORDER BY
                    CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END
            """, params)
            by_severity = [dict(r) for r in cur.fetchall()]

            # By engine
            cur.execute(f"""
                SELECT primary_engine, count(*) AS count
                FROM ciem_findings WHERE tenant_id = %s {scan_filter}
                GROUP BY primary_engine ORDER BY count DESC
            """, params)
            by_engine = [dict(r) for r in cur.fetchall()]

            # By rule_source (L1/L2/L3)
            cur.execute(f"""
                SELECT rule_source, count(*) AS count
                FROM ciem_findings WHERE tenant_id = %s {scan_filter}
                GROUP BY rule_source ORDER BY count DESC
            """, params)
            by_source = [dict(r) for r in cur.fetchall()]

            # By action category
            cur.execute(f"""
                SELECT action_category, count(*) AS count
                FROM ciem_findings WHERE tenant_id = %s {scan_filter}
                AND action_category != ''
                GROUP BY action_category ORDER BY count DESC
            """, params)
            by_category = [dict(r) for r in cur.fetchall()]

            # Top 10 critical/high findings
            cur.execute(f"""
                SELECT finding_id, rule_id, severity, title,
                       actor_principal, resource_uid, event_time
                FROM ciem_findings
                WHERE tenant_id = %s {scan_filter}
                AND severity IN ('critical', 'high')
                ORDER BY event_time DESC LIMIT 10
            """, params)
            top_critical = [dict(r) for r in cur.fetchall()]

            # Scan trend (last 8 scans, oldest-first — for sparklines)
            scan_trend = _query_ciem_scan_trend(cur, tenant_id)

        return {
            "summary": summary,
            "by_severity": by_severity,
            "by_engine": by_engine,
            "by_rule_source": by_source,
            "by_category": by_category,
            "top_critical": top_critical,
            "scan_trend": scan_trend,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


@app.get("/api/v1/ciem/identities")
async def identity_summary(
    scan_run_id: Optional[str] = Query(None),
    limit: int = Query(50, le=500),
    auth: Any = Depends(require_permission("ciem:read")),
):
    """Identity risk summary — top actors by finding count and severity."""
    tenant_id = (
        getattr(auth, "engine_tenant_id", None)
        or getattr(auth, "tenant_id", None)
        or "default-tenant"
    )
    import psycopg2.extras
    conn = get_ciem_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            scan_filter = "AND scan_run_id = %s" if scan_run_id else ""
            params = [tenant_id, scan_run_id] if scan_run_id else [tenant_id]

            cur.execute(f"""
                SELECT
                    actor_principal,
                    actor_principal_type,
                    count(*) AS total_findings,
                    count(*) FILTER (WHERE severity = 'critical') AS critical,
                    count(*) FILTER (WHERE severity = 'high') AS high,
                    count(*) FILTER (WHERE severity = 'medium') AS medium,
                    count(DISTINCT rule_id) AS rules_triggered,
                    count(DISTINCT service) AS services_used,
                    count(DISTINCT resource_uid) FILTER (WHERE resource_uid != '') AS resources_touched,
                    array_agg(DISTINCT actor_ip) FILTER (WHERE actor_ip != '') AS source_ips,
                    max(event_time) AS last_activity,
                    COUNT(*) FILTER (WHERE rule_source = 'log_correlation') AS l2_findings,
                    COUNT(*) FILTER (WHERE rule_source = 'baseline') AS l3_findings
                FROM ciem_findings
                WHERE tenant_id = %s {scan_filter}
                AND actor_principal IS NOT NULL AND actor_principal != ''
                GROUP BY actor_principal, actor_principal_type
                ORDER BY
                    count(*) FILTER (WHERE severity = 'critical') DESC,
                    count(*) FILTER (WHERE severity = 'high') DESC,
                    count(*) DESC
                LIMIT %s
            """, params + [limit])
            rows = cur.fetchall()
            identities = []
            for r in rows:
                identity = dict(r)
                identity["actor_principal_type"] = identity.get("actor_principal_type") or "unknown"
                identity["l2_findings"] = int(identity.get("l2_findings") or 0)
                identity["l3_findings"] = int(identity.get("l3_findings") or 0)
                identities.append(identity)

        return {"identities": identities, "count": len(identities)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


@app.get("/api/v1/ciem/identities/heatmap")
async def get_identity_heatmap(
    scan_run_id: Optional[str] = Query(None),
    auth: Any = Depends(require_permission("ciem:read")),
):
    """Identity risk heatmap — (account_id × actor_principal_type) matrix with max_severity and finding_count.

    Returns a matrix of cells where each cell represents one (account, principal_type) pair.
    Used by the CIEM Stage 1 UI to render the fleet-wide heatmap grid.

    Args:
        scan_run_id: Optional scan run filter. When absent, defaults to the last 30 days.
        auth: AuthContext from require_permission dependency.

    Returns:
        Dict with 'matrix' list, 'accounts' sorted list, and 'principal_types' sorted list.
    """
    import psycopg2.extras

    tenant_id = (
        getattr(auth, "engine_tenant_id", None)
        or getattr(auth, "tenant_id", None)
        or "default-tenant"
    )
    conn = get_ciem_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SET LOCAL statement_timeout = 5000")

            if scan_run_id:
                scan_filter = "AND scan_run_id = %s"
                params: list = [tenant_id, scan_run_id]
            else:
                scan_filter = "AND event_time >= NOW() - INTERVAL '30 days'"
                params = [tenant_id]

            cur.execute(f"""
                SELECT
                    account_id,
                    actor_principal_type,
                    COUNT(*) AS finding_count,
                    MAX(CASE severity
                        WHEN 'critical' THEN 4
                        WHEN 'high' THEN 3
                        WHEN 'medium' THEN 2
                        WHEN 'low' THEN 1
                        ELSE 0 END) AS max_severity_ord
                FROM ciem_findings
                WHERE tenant_id = %s
                {scan_filter}
                GROUP BY account_id, actor_principal_type
                ORDER BY account_id, actor_principal_type
                LIMIT 500
            """, params)
            rows = cur.fetchall()

        _severity_map = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "none"}
        matrix = []
        accounts_set: set = set()
        principal_types_set: set = set()

        for row in rows:
            account_id = row["account_id"] or ""
            principal_type = row["actor_principal_type"] or "unknown"
            max_sev_ord = int(row["max_severity_ord"] or 0)
            finding_count = int(row["finding_count"] or 0)

            accounts_set.add(account_id)
            principal_types_set.add(principal_type)
            matrix.append({
                "account_id": account_id,
                "principal_type": principal_type,
                "max_severity": _severity_map.get(max_sev_ord, "none"),
                "finding_count": finding_count,
            })

        return {
            "matrix": matrix,
            "accounts": sorted(accounts_set),
            "principal_types": sorted(principal_types_set),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


@app.get("/api/v1/ciem/identities/{principal_encoded}/hourly-activity")
async def get_identity_hourly_activity(
    principal_encoded: str,
    scan_run_id: Optional[str] = Query(None),
    auth: Any = Depends(require_permission("ciem:read")),
):
    """Hourly and day-of-week activity distribution for a specific identity over the last 14 days.

    Returns 24-element hourly distribution and 7-element day-of-week distribution.
    Hours and days with zero findings are explicitly included so the response arrays
    are always fixed-length (24 and 7 elements respectively).

    The principal ARN is URL-encoded in the path (e.g. %3A for colons, %2F for slashes).
    It is decoded before parameterized DB query — no SQL injection risk.

    Args:
        principal_encoded: URL-encoded actor_principal identifier (path parameter).
        scan_run_id: Optional scan run filter. When absent, queries the last 14 days.
        auth: AuthContext from require_permission dependency.

    Returns:
        Dict with 'actor_principal', 'hourly_distribution' (24 items), and
        'day_of_week_distribution' (7 items).

    Raises:
        HTTPException 400: Decoded principal exceeds 512 chars or contains null bytes.
        HTTPException 404: No findings for this principal in the tenant.
        HTTPException 500: Unexpected database error.
    """
    import psycopg2.extras

    actor_principal = unquote(principal_encoded)

    # Validate decoded value to prevent abuse
    if len(actor_principal) > 512 or "\x00" in actor_principal:
        raise HTTPException(status_code=400, detail="Invalid principal identifier")

    tenant_id = (
        getattr(auth, "engine_tenant_id", None)
        or getattr(auth, "tenant_id", None)
        or "default-tenant"
    )

    conn = get_ciem_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            if scan_run_id:
                scan_filter = "AND scan_run_id = %s AND event_time >= NOW() - INTERVAL '14 days'"
                base_params: list = [tenant_id, actor_principal, scan_run_id]
            else:
                scan_filter = "AND event_time >= NOW() - INTERVAL '14 days'"
                base_params = [tenant_id, actor_principal]

            # Hourly distribution
            cur.execute(f"""
                SELECT EXTRACT(HOUR FROM event_time)::int AS hour, COUNT(*) AS count
                FROM ciem_findings
                WHERE tenant_id = %s AND actor_principal = %s
                {scan_filter}
                GROUP BY hour
                ORDER BY hour
            """, base_params)
            hourly_rows = {int(r["hour"]): int(r["count"]) for r in cur.fetchall()}

            # Day-of-week distribution
            cur.execute(f"""
                SELECT EXTRACT(DOW FROM event_time)::int AS dow, COUNT(*) AS count
                FROM ciem_findings
                WHERE tenant_id = %s AND actor_principal = %s
                {scan_filter}
                GROUP BY dow
                ORDER BY dow
            """, base_params)
            dow_rows = {int(r["dow"]): int(r["count"]) for r in cur.fetchall()}

        # Return 404 when no data at all for this principal in this tenant
        if not hourly_rows and not dow_rows:
            raise HTTPException(
                status_code=404,
                detail=f"No findings found for principal in the last 14 days",
            )

        _dow_names = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]

        # Build fixed-length arrays — fill missing buckets with 0
        hourly_distribution = [
            {"hour": h, "count": hourly_rows.get(h, 0)}
            for h in range(24)
        ]
        day_of_week_distribution = [
            {"dow": d, "dow_name": _dow_names[d], "count": dow_rows.get(d, 0)}
            for d in range(7)
        ]

        return {
            "actor_principal": actor_principal,
            "hourly_distribution": hourly_distribution,
            "day_of_week_distribution": day_of_week_distribution,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


@app.get("/api/v1/ciem/top-rules")
async def top_rules(
    scan_run_id: Optional[str] = Query(None),
    limit: int = Query(20, le=100),
    auth: Any = Depends(require_permission("ciem:read")),
):
    """Top triggered detection rules by finding count."""
    tenant_id = (
        getattr(auth, "engine_tenant_id", None)
        or getattr(auth, "tenant_id", None)
        or "default-tenant"
    )
    import psycopg2.extras
    conn = get_ciem_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            scan_filter = "AND scan_run_id = %s" if scan_run_id else ""
            params = [tenant_id, scan_run_id] if scan_run_id else [tenant_id]

            cur.execute(f"""
                SELECT
                    rule_id,
                    rule_source,
                    severity,
                    title,
                    primary_engine,
                    action_category,
                    count(*) AS finding_count,
                    count(DISTINCT actor_principal) FILTER (WHERE actor_principal != '') AS unique_actors,
                    count(DISTINCT resource_uid) FILTER (WHERE resource_uid != '') AS unique_resources
                FROM ciem_findings
                WHERE tenant_id = %s {scan_filter}
                GROUP BY rule_id, rule_source, severity, title, primary_engine, action_category
                ORDER BY count(*) DESC
                LIMIT %s
            """, params + [limit])
            rules = [dict(r) for r in cur.fetchall()]

        return {"rules": rules, "count": len(rules)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


@app.get("/api/v1/ciem/log-sources")
async def log_sources(
    auth: Any = Depends(require_permission("ciem:read")),
) -> Dict[str, Any]:
    """Return log source coverage status for the CIEM logSources tab.

    Aggregates ciem_findings by source_type and account, deriving an
    active/stale/unknown status based on last_seen_at recency (48h threshold).
    Excludes findings where finding_data->>'source_type' IS NULL.

    Returns:
        Dict with 'sources' list and 'total' count. Each source entry contains:
        log_type, source_name, provider, account_id, finding_count,
        last_seen_at (ISO), first_ingested_at (ISO), status.
    """
    import time
    import psycopg2.extras
    from datetime import datetime, timezone, timedelta

    tenant_id = (
        getattr(auth, "engine_tenant_id", None)
        or getattr(auth, "tenant_id", None)
        or "default-tenant"
    )

    STALE_THRESHOLD = timedelta(hours=48)
    t_start = time.monotonic()
    conn = get_ciem_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SET statement_timeout = 5000")
            cur.execute("""
                SELECT
                    finding_data->>'source_type'           AS log_type,
                    finding_data->>'log_source'            AS source_name,
                    provider,
                    account_id,
                    COUNT(*)                               AS finding_count,
                    MAX(last_seen_at)                      AS last_seen_at,
                    MIN(first_seen_at)                     AS first_ingested_at
                FROM ciem_findings
                WHERE tenant_id = %s
                  AND finding_data->>'source_type' IS NOT NULL
                GROUP BY
                    finding_data->>'source_type',
                    finding_data->>'log_source',
                    provider,
                    account_id
                ORDER BY log_type, account_id
                LIMIT 500
            """, [tenant_id])
            rows = [dict(r) for r in cur.fetchall()]

        now = datetime.now(timezone.utc)
        for row in rows:
            last_seen = row.get("last_seen_at")
            if last_seen is None:
                row["status"] = "unknown"
            elif (now - last_seen) < STALE_THRESHOLD:
                row["status"] = "active"
            else:
                row["status"] = "stale"
            # source_name fallback: use log_type when log_source not populated
            if not row.get("source_name"):
                row["source_name"] = row.get("log_type", "unknown")
            # Convert datetime objects to ISO strings for JSON serialisation
            if isinstance(last_seen, datetime):
                row["last_seen_at"] = last_seen.isoformat()
            first = row.get("first_ingested_at")
            if isinstance(first, datetime):
                row["first_ingested_at"] = first.isoformat()

        duration_ms = round((time.monotonic() - t_start) * 1000)
        logger.info(
            "log_sources called",
            extra={
                "tenant_id": tenant_id,
                "result_count": len(rows),
                "caller_level": getattr(auth, "level", "unknown"),
                "duration_ms": duration_ms,
            },
        )
        return {"sources": rows, "total": len(rows)}
    except Exception as e:
        logger.error("log_sources query failed", extra={"tenant_id": tenant_id}, exc_info=True)
        return {"sources": [], "total": 0}
    finally:
        conn.close()


@app.get("/api/v1/ciem/report/{scan_run_id}")
async def scan_report(scan_run_id: str):
    """Get CIEM scan report with full summary."""
    import psycopg2.extras
    conn = get_ciem_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM ciem_report WHERE scan_run_id = %s", (scan_run_id,))
            report = cur.fetchone()
            if not report:
                raise HTTPException(status_code=404, detail=f"Report not found for {scan_run_id}")
            return dict(report)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


# ── Findings-by-resource models ───────────────────────────────────────────────

class CiemFindingItem(BaseModel):
    """Single CIEM finding row returned by the asset-context endpoint."""

    finding_id: str
    title: str
    severity: str
    status: str
    rule_id: Optional[str] = None
    resource_uid: str
    resource_type: Optional[str] = None
    account_id: Optional[str] = None
    region: Optional[str] = None
    provider: Optional[str] = None
    first_seen_at: str
    last_seen_at: str
    anomaly_type: Optional[str] = None
    anomaly_score: Optional[float] = None
    event_count: Optional[int] = None


class CiemFindingsByResourceResponse(BaseModel):
    """Response for GET /api/v1/ciem/findings/by-resource."""

    findings: List[CiemFindingItem]
    total: int
    resource_uid: str
    scan_run_id: str


_CIEM_TABLE = "ciem_findings"
_CIEM_TITLE_EXPR = "COALESCE(title, rule_id)"


@app.get("/api/v1/ciem/findings/by-resource", response_model=CiemFindingsByResourceResponse)
async def get_ciem_findings_by_resource(
    resource_uid: str = Query(..., description="Full resource ARN, UID, or identity ARN (actor_principal)"),
    scan_run_id: str = Query("latest"),
    limit: int = Query(50, ge=1, le=100),
    status: Optional[str] = Query(None),
    auth: Any = Depends(require_permission("ciem:read")),
):
    """Return CIEM findings for a specific resource_uid or actor_principal.

    Used by the gateway asset-context aggregator. Matches on both resource_uid
    and actor_principal so identity ARNs resolve correctly.

    Args:
        resource_uid: Resource ARN/UID or identity ARN (actor_principal) to filter by.
        scan_run_id: Scan run UUID, or 'latest' to resolve automatically.
        limit: Maximum number of findings to return (1-100).
        status: Optional status filter (FAIL | PASS | WARN).
        auth: Injected AuthContext from require_permission dependency.

    Returns:
        CiemFindingsByResourceResponse with findings list, total count, and resolved scan_run_id.
    """
    tenant_id = (
        getattr(auth, "engine_tenant_id", None)
        or getattr(auth, "tenant_id", None)
        or "default-tenant"
    )

    status_clause = "AND status = %(status)s" if status else ""
    # CIEM: match both resource_uid and actor_principal for identity ARNs
    resource_clause = (
        "(resource_uid = %(resource_uid)s OR actor_principal = %(resource_uid)s)"
    )
    params: Dict[str, Any] = {
        "tenant_id": tenant_id,
        "resource_uid": resource_uid,
        "status": status,
        "limit": limit,
    }

    conn = get_ciem_conn()
    try:
        with conn.cursor() as cur:
            # Step 1: resolve scan_run_id
            cur.execute(f"""
                SELECT scan_run_id FROM {_CIEM_TABLE}
                WHERE tenant_id = %(tenant_id)s
                  AND {resource_clause}
                  {status_clause}
                ORDER BY last_seen_at DESC LIMIT 1
            """, params)
            row = cur.fetchone()
            if not row:
                return CiemFindingsByResourceResponse(
                    findings=[], total=0,
                    resource_uid=resource_uid, scan_run_id=scan_run_id,
                )
            resolved_scan = row[0]
            params["resolved_scan"] = resolved_scan

            # Step 2: total count
            cur.execute(f"""
                SELECT COUNT(*) FROM {_CIEM_TABLE}
                WHERE tenant_id = %(tenant_id)s
                  AND {resource_clause}
                  AND scan_run_id = %(resolved_scan)s
                  {status_clause}
            """, params)
            total = cur.fetchone()[0]

            # Step 3: top N findings sorted by severity
            # credential_ref excluded from SELECT
            cur.execute(f"""
                SELECT finding_id,
                       {_CIEM_TITLE_EXPR} AS title,
                       severity, status,
                       rule_id, resource_uid, resource_type,
                       account_id, region, provider,
                       first_seen_at, last_seen_at,
                       anomaly_type, anomaly_score, event_count
                FROM {_CIEM_TABLE}
                WHERE tenant_id = %(tenant_id)s
                  AND {resource_clause}
                  AND scan_run_id = %(resolved_scan)s
                  {status_clause}
                ORDER BY
                    CASE severity
                        WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                        WHEN 'medium'   THEN 2 WHEN 'low'  THEN 1 ELSE 0
                    END DESC,
                    last_seen_at DESC
                LIMIT %(limit)s
            """, params)
            cols = [d[0] for d in cur.description]
            findings = [
                CiemFindingItem(**{k: (str(v) if v is not None else v) if k in ("first_seen_at", "last_seen_at") else v
                                   for k, v in dict(zip(cols, r)).items()})
                for r in cur.fetchall()
            ]
    except Exception as exc:
        logger.error(f"Error in get_ciem_findings_by_resource: {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))
    finally:
        conn.close()

    return CiemFindingsByResourceResponse(
        findings=findings,
        total=total,
        resource_uid=resource_uid,
        scan_run_id=resolved_scan,
    )
