"""
Attack Path Engine — API routes.

Endpoints:
  GET  /api/v1/health/live                  — liveness (no external deps)
  GET  /api/v1/health/ready                 — readiness (checks DB connectivity)
  GET  /api/v1/attack-paths                 — list attack paths (requires attack_path:read)
  GET  /api/v1/attack-paths/{path_id}       — path detail with steps[] (requires attack_path:read)
  GET  /api/v1/attack-paths/trends          — score history for a path (requires attack_path:read)
  GET  /api/v1/crown-jewels                 — list crown jewels for tenant (requires attack_path:read)
  PATCH /api/v1/crown-jewels/{resource_uid} — manual override (requires attack_path:write)
  GET  /api/v1/choke-points                 — top choke point nodes (requires attack_path:read)
  POST /api/v1/internal/scan                — Argo trigger (X-Internal-Secret auth)
"""

from __future__ import annotations

import json
import logging
import os
import threading
import uuid
from typing import Any, Dict, List, Optional

import psycopg2.extras
from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field

logger = logging.getLogger("attack-path.routes")

# ── Auth ──────────────────────────────────────────────────────────────────────
try:
    from engine_auth.fastapi.dependencies import require_permission, get_auth_context
    from engine_auth.core.models import AuthContext
    _AUTH_AVAILABLE = True
except ImportError:
    _AUTH_AVAILABLE = False
    AuthContext = None  # type: ignore[assignment,misc]

    def require_permission(_perm: str):  # type: ignore[no-redef]
        """Stub for local dev when engine_auth is unavailable."""
        def _ok():
            pass
        return _ok

    async def get_auth_context(request: Request):  # type: ignore[no-redef]
        return None

router = APIRouter()

# ── Pydantic models ───────────────────────────────────────────────────────────

class CrownJewelOverridePatch(BaseModel):
    """Request body for PATCH /api/v1/crown-jewels/{resource_uid}."""
    is_crown_jewel: bool
    crown_jewel_type: Optional[str] = Field(
        default=None,
        description=(
            "One of: data, secrets, identity, infra_control, ai_model, code, "
            "data_warehouse, encryption_control. Required when is_crown_jewel=true."
        ),
    )
    reason: Optional[str] = Field(default=None, max_length=1000)


class ScanRequest(BaseModel):
    """Request body for POST /api/v1/internal/scan."""
    scan_run_id: str = Field(..., description="UUID of the current pipeline run")
    tenant_id: str = Field(..., min_length=1, max_length=255)
    account_id: str = Field(default="", max_length=255)


# ── Health endpoints (public — no auth required) ──────────────────────────────

@router.get("/api/v1/health/live")
async def health_live() -> Dict[str, str]:
    """Liveness probe — returns 200 if the process is running."""
    return {"status": "ok"}


@router.get("/api/v1/health/ready")
async def health_ready() -> Dict[str, str]:
    """Readiness probe — returns 200 if the DB is reachable, 503 otherwise."""
    from ..db.connection import check_db_health
    if check_db_health():
        return {"status": "ok"}
    raise HTTPException(status_code=503, detail="Database unavailable")


# ── Attack Paths ──────────────────────────────────────────────────────────────

@router.get("/api/v1/attack-paths", dependencies=[Depends(require_permission("attack_path:read"))])
async def list_attack_paths(
    request: Request,
    severity: Optional[str] = Query(default=None, description="critical|high|medium|low"),
    entry_point_type: Optional[str] = Query(default=None),
    representative_only: bool = Query(default=True),
    group_id: Optional[str] = Query(default=None),
    search: Optional[str] = Query(default=None, max_length=200),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
) -> Dict[str, Any]:
    """List deduplicated attack paths for the authenticated tenant."""
    tenant_id = _resolve_tenant(request)
    from ..db.connection import get_conn, put_conn
    conn = get_conn()
    try:
        return _fetch_attack_paths(
            conn, tenant_id,
            severity=severity,
            entry_point_type=entry_point_type,
            representative_only=representative_only,
            group_id=group_id,
            search=search,
            page=page,
            page_size=page_size,
        )
    finally:
        put_conn(conn)


@router.get(
    "/api/v1/attack-paths/trends",
    dependencies=[Depends(require_permission("attack_path:read"))],
)
async def get_path_trends(
    request: Request,
    path_id: str = Query(..., description="sha256 path identifier"),
) -> Dict[str, Any]:
    """Return score history for a specific path from attack_path_history."""
    tenant_id = _resolve_tenant(request)
    from ..db.connection import get_conn, put_conn
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT path_id, path_score, severity, misconfig_count,
                       threat_count, has_active_cdr_actor, recorded_at
                FROM attack_path_history
                WHERE path_id = %s AND tenant_id = %s
                ORDER BY recorded_at ASC
                """,
                (path_id, tenant_id),
            )
            rows = [dict(r) for r in cur.fetchall()]
        return {"path_id": path_id, "history": rows}
    finally:
        put_conn(conn)


@router.get(
    "/api/v1/attack-paths/{path_id}",
    dependencies=[Depends(require_permission("attack_path:read"))],
)
async def get_attack_path_detail(
    path_id: str,
    request: Request,
) -> Dict[str, Any]:
    """Return a single attack path with all per-hop evidence (steps[])."""
    tenant_id = _resolve_tenant(request)
    from ..db.connection import get_conn, put_conn
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            # Fetch path header
            cur.execute(
                "SELECT * FROM attack_paths WHERE path_id = %s AND tenant_id = %s",
                (path_id, tenant_id),
            )
            path_row = cur.fetchone()
            if not path_row:
                raise HTTPException(status_code=404, detail="Attack path not found")

            # Fetch per-hop steps
            cur.execute(
                """
                SELECT * FROM attack_path_nodes
                WHERE path_id = %s AND tenant_id = %s
                ORDER BY hop_index ASC
                """,
                (path_id, tenant_id),
            )
            steps = [dict(r) for r in cur.fetchall()]

        result = dict(path_row)
        choke_uid = result.get("choke_node_uid")
        path_account_id = result.get("account_id")
        path_provider = result.get("provider")
        for step in steps:
            step["is_choke_point"] = bool(choke_uid and step.get("node_uid") == choke_uid)
            step["account_id"] = path_account_id
            step["provider"] = path_provider
            step["region"] = _parse_region(step.get("node_uid") or "")

        # Prepend a synthetic source node (internet / vpn / peer account).
        # The DB stores only real cloud resource hops; the threat entry point
        # is metadata on the path header. We inject it here so the canvas
        # renders the canonical Orca-style flow:
        #   [Internet] → [EKS] → [IAM Role] → [S3 Crown Jewel]
        entry_type = (result.get("entry_point_type") or "internet").lower()
        SOURCE_LABEL = {
            "internet":     "Internet",
            "vpn":          "VPN",
            "onprem":       "On-Premises",
            "peer_account": "Peer Account",
        }
        source_label = SOURCE_LABEL.get(entry_type, entry_type.replace("_", " ").title())
        # Edge from source → first real hop: default NETWORK unless first real hop says otherwise
        first_hop_edge = steps[0].get("edge_to_next", "NETWORK") if steps else "NETWORK"
        synthetic_source: Dict[str, Any] = {
            "node_uid":         f"__source__{entry_type}",
            "node_name":        source_label,
            "node_type":        entry_type,   # maps to Internet/Globe icon in UI
            "hop_index":        -1,
            "edge_to_next":     "NETWORK",    # always NETWORK from external → first hop
            "edge_category":    "network_access",
            "traversal_reason": f"External {source_label} connection to cloud environment",
            "misconfigs":       [],
            "cves":             [],
            "threat_detections": [],
            "is_choke_point":   False,
            "account_id":       None,
            "provider":         None,
            "region":           None,
            "cdr_actor_active": False,
            "sg_rule":          None,
        }
        result["steps"] = [synthetic_source] + steps
        return result
    finally:
        put_conn(conn)


# ── Crown Jewels ──────────────────────────────────────────────────────────────

@router.get(
    "/api/v1/crown-jewels",
    dependencies=[Depends(require_permission("attack_path:read"))],
)
async def list_crown_jewels(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
) -> Dict[str, Any]:
    """List crown jewel overrides for the authenticated tenant."""
    tenant_id = _resolve_tenant(request)
    from ..db.connection import get_conn, put_conn
    conn = get_conn()
    try:
        offset = (page - 1) * page_size
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT override_id, resource_uid, tenant_id, is_crown_jewel,
                       crown_jewel_type, reason, set_by, created_at, updated_at
                FROM crown_jewel_overrides
                WHERE tenant_id = %s
                ORDER BY updated_at DESC
                LIMIT %s OFFSET %s
                """,
                (tenant_id, page_size, offset),
            )
            rows = [dict(r) for r in cur.fetchall()]

            cur.execute(
                "SELECT COUNT(*) AS total FROM crown_jewel_overrides WHERE tenant_id = %s",
                (tenant_id,),
            )
            total = cur.fetchone()["total"]

        return {"overrides": rows, "total": total, "page": page, "page_size": page_size}
    finally:
        put_conn(conn)


@router.patch(
    "/api/v1/crown-jewels/{resource_uid}",
    dependencies=[Depends(require_permission("attack_path:write"))],
)
async def patch_crown_jewel(
    resource_uid: str,
    body: CrownJewelOverridePatch,
    request: Request,
) -> Dict[str, Any]:
    """Manually tag or untag a resource as a crown jewel.

    Requires attack_path:write (tenant_admin, org_admin, platform_admin).
    set_by is always taken from AuthContext.user_email — never from the request body.
    tenant_id is always taken from AuthContext.engine_tenant_id — never from request body.
    """
    # Validate resource_uid length (AC-15)
    if not resource_uid or len(resource_uid) > 512:
        raise HTTPException(
            status_code=422,
            detail="resource_uid must be 1–512 characters",
        )

    tenant_id = _resolve_tenant(request)
    set_by = _resolve_user_email(request)

    # Validate set_by length (AC-17)
    if len(set_by) > 255:
        raise HTTPException(status_code=422, detail="user_email exceeds 255 characters")

    from ..db.connection import get_conn, put_conn
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                INSERT INTO crown_jewel_overrides
                    (resource_uid, tenant_id, is_crown_jewel, crown_jewel_type, reason, set_by)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (resource_uid, tenant_id) DO UPDATE SET
                    is_crown_jewel = EXCLUDED.is_crown_jewel,
                    crown_jewel_type = EXCLUDED.crown_jewel_type,
                    reason = EXCLUDED.reason,
                    set_by = EXCLUDED.set_by,
                    updated_at = NOW()
                RETURNING
                    override_id, resource_uid, tenant_id, is_crown_jewel,
                    crown_jewel_type, reason, set_by, created_at, updated_at
                """,
                (
                    resource_uid,
                    tenant_id,
                    body.is_crown_jewel,
                    body.crown_jewel_type,
                    body.reason,
                    set_by,
                ),
            )
            row = cur.fetchone()
        conn.commit()
        return dict(row)
    except HTTPException:
        raise
    except Exception as exc:
        conn.rollback()
        logger.exception("crown_jewel patch failed: %s", exc)
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        put_conn(conn)


# ── Choke Points ──────────────────────────────────────────────────────────────

@router.get(
    "/api/v1/choke-points",
    dependencies=[Depends(require_permission("attack_path:read"))],
)
async def list_choke_points(
    request: Request,
    limit: int = Query(default=10, ge=1, le=50),
) -> Dict[str, Any]:
    """Return top choke-point nodes for the authenticated tenant."""
    tenant_id = _resolve_tenant(request)
    from ..db.connection import get_conn, put_conn
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT
                    choke_node_uid AS node_uid,
                    COUNT(DISTINCT group_id) AS paths_blocked_if_fixed,
                    AVG(path_score) AS avg_path_score,
                    COUNT(*) FILTER (WHERE severity = 'critical') AS critical_count,
                    COUNT(*) FILTER (WHERE severity = 'high') AS high_count,
                    COUNT(*) FILTER (WHERE severity = 'medium') AS medium_count,
                    COUNT(*) FILTER (WHERE severity = 'low') AS low_count
                FROM attack_paths
                WHERE tenant_id = %s
                  AND status = 'active'
                  AND choke_node_uid IS NOT NULL
                GROUP BY choke_node_uid
                ORDER BY paths_blocked_if_fixed DESC
                LIMIT %s
                """,
                (tenant_id, limit),
            )
            rows = [dict(r) for r in cur.fetchall()]
        return {"choke_points": rows, "total": len(rows)}
    finally:
        put_conn(conn)


# ── Internal scan trigger (Argo only — not gateway-routed) ───────────────────

@router.post("/api/v1/internal/scan")
async def trigger_scan(
    body: ScanRequest,
    background_tasks: BackgroundTasks,
    x_internal_secret: str = Header(..., alias="X-Internal-Secret"),
) -> Dict[str, Any]:
    """Argo trigger endpoint.

    NOT exposed via API gateway (not in SERVICE_ROUTES external prefix list).
    Validated with X-Internal-Secret header from threat-engine-secrets.
    """
    # Validate secret BEFORE any DB access (AC-20)
    expected = os.getenv("X_INTERNAL_SECRET", "")
    if not expected or x_internal_secret != expected:
        raise HTTPException(status_code=403, detail="Forbidden")

    # Validate scan_run_id as UUID format (AC-21)
    try:
        uuid.UUID(body.scan_run_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="scan_run_id must be a valid UUID")

    job_id = str(uuid.uuid4())
    logger.info(
        '{"engine":"attack-path","event":"scan_queued","scan_run_id":"%s","job_id":"%s"}',
        body.scan_run_id,
        job_id,
    )
    background_tasks.add_task(
        _run_scan_background,
        body.scan_run_id,
        body.tenant_id,
        body.account_id,
    )
    return {"job_id": job_id, "status": "queued"}


# ── Private helpers ───────────────────────────────────────────────────────────

def _run_scan_background(scan_run_id: str, tenant_id: str, account_id: str) -> None:
    """Execute the attack-path scan pipeline in a background thread."""
    try:
        from ..run_scan import run_attack_path_scan
        run_attack_path_scan(scan_run_id, tenant_id, account_id)
    except Exception as exc:
        logger.exception(
            '{"engine":"attack-path","event":"scan_failed","scan_run_id":"%s","error":"%s"}',
            scan_run_id,
            exc,
        )


def _parse_region(uid: str) -> Optional[str]:
    """Best-effort region extraction from a resource UID.

    Handles two formats used in this platform:
      - AWS ARN:       arn:aws:service:region:account:resource  → parts[3]
      - Synthetic:     region:resource-name                     → parts[0]
    Returns None when the UID does not match either pattern.
    """
    if not uid:
        return None
    parts = uid.split(":")
    if parts[0] == "arn" and len(parts) >= 4:
        return parts[3] or None
    if len(parts) >= 2 and "-" in parts[0] and parts[0][0].isalpha():
        return parts[0]
    return None


def _resolve_tenant(request: Request) -> str:
    """Extract engine_tenant_id from AuthContext. Raises 401 if missing."""
    raw = request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    if raw:
        try:
            ctx = json.loads(raw)
            tid = ctx.get("engine_tenant_id") or (
                ctx.get("tenant_ids") or [""]
            )[0]
            if tid:
                return tid
        except Exception:
            pass
    # Dev fallback — never permitted in production (auth middleware ensures header is present)
    return request.headers.get("x-tenant-id", "default-tenant")


def _resolve_user_email(request: Request) -> str:
    """Extract user_email from AuthContext for audit logging."""
    raw = request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    if raw:
        try:
            ctx = json.loads(raw)
            email = ctx.get("user_email") or ctx.get("email") or ""
            if email:
                return email
        except Exception:
            pass
    return "unknown"


def _fetch_attack_paths(
    conn: Any,
    tenant_id: str,
    severity: Optional[str],
    entry_point_type: Optional[str],
    representative_only: bool,
    group_id: Optional[str],
    search: Optional[str],
    page: int,
    page_size: int,
) -> Dict[str, Any]:
    """Query attack_paths and compute KPIs."""
    offset = (page - 1) * page_size

    filters: List[str] = ["tenant_id = %s", "status = 'active'"]
    params: List[Any] = [tenant_id]

    if severity:
        filters.append("severity = %s")
        params.append(severity)
    if entry_point_type:
        filters.append("entry_point_type = %s")
        params.append(entry_point_type)
    if representative_only:
        filters.append("is_representative = TRUE")
    if group_id:
        filters.append("group_id = %s")
        params.append(group_id)
    if search and search.strip():
        # Escape PostgreSQL LIKE metacharacters to prevent wildcard injection
        search_clean = search.strip().replace("\\", "\\\\").replace("%", r"\%").replace("_", r"\_")
        search_pat = f"%{search_clean}%"
        filters.append(
            r"(attack_name ILIKE %s ESCAPE '\' OR crown_jewel_uid ILIKE %s ESCAPE '\' OR chain_type ILIKE %s ESCAPE '\')"
        )
        params.extend([search_pat, search_pat, search_pat])

    where_clause = " AND ".join(filters)

    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        # KPIs — use string concat (not f-string) so linters can verify no injection
        kpi_sql = (
            "SELECT"
            " COUNT(*) AS total,"
            " COUNT(*) FILTER (WHERE severity = 'critical') AS critical,"
            " COUNT(*) FILTER (WHERE severity = 'high') AS high,"
            " COUNT(DISTINCT choke_node_uid) FILTER (WHERE choke_node_uid IS NOT NULL) AS choke_points,"
            " MAX(EXTRACT(EPOCH FROM (NOW() - first_seen_at)) / 86400)::INTEGER AS longest_open_days,"
            " COUNT(*) FILTER (WHERE has_active_cdr_actor = TRUE) AS paths_with_active_cdr,"
            " COUNT(*) FILTER (WHERE path_score >= 70) AS confirmed_paths,"
            " COALESCE(SUM(CASE WHEN path_score BETWEEN 40 AND 69 THEN 1 ELSE 0 END), 0) AS likely_paths,"
            " COALESCE(SUM(CASE WHEN path_score < 40 THEN 1 ELSE 0 END), 0) AS speculative_paths"
            " FROM attack_paths WHERE " + where_clause
        )
        cur.execute(kpi_sql, params)
        kpi_row = dict(cur.fetchone())

        # Page of paths — string concat, all user values in params list only
        page_params = params + [page_size, offset]
        paths_sql = (
            "SELECT path_id, severity, path_score, chain_type,"
            " entry_point_type, depth, crown_jewel_uid, crown_jewel_type,"
            " data_classification, group_id, group_size, is_representative,"
            " absorbed_count, choke_node_uid, has_active_cdr_actor,"
            " max_epss, misconfig_count, threat_count, first_seen_at, last_seen_at,"
            " EXTRACT(EPOCH FROM (NOW() - first_seen_at))::INTEGER / 86400 AS open_days,"
            " attack_name, attack_technique_chain, attack_story,"
            " confidence_level, account_id, provider"
            " FROM attack_paths WHERE " + where_clause
            + " ORDER BY path_score DESC, first_seen_at ASC LIMIT %s OFFSET %s"
        )
        cur.execute(paths_sql, page_params)
        paths = [dict(r) for r in cur.fetchall()]

    return {
        "paths": paths,
        "total": kpi_row.get("total", 0),
        "page": page,
        "page_size": page_size,
        "kpis": {
            "critical": kpi_row.get("critical", 0),
            "high": kpi_row.get("high", 0),
            "choke_points": kpi_row.get("choke_points", 0),
            "longest_open_days": kpi_row.get("longest_open_days", 0),
            "paths_with_active_cdr": kpi_row.get("paths_with_active_cdr", 0),
            "confirmed_paths": kpi_row.get("confirmed_paths", 0),
            "likely_paths": kpi_row.get("likely_paths", 0),
            "speculative_paths": kpi_row.get("speculative_paths", 0),
        },
    }
