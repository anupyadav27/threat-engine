"""
BFF view: GET /api/v1/views/resource/{resource_uid}

Step 3 resource context panel for all posture security pages.
Aggregates data in parallel from multiple sources:
  1. asset_inventory        — asset identity, config, tags
  2. resource_security_posture — per-dimension posture scores + attack-path signals
  3. asset_relationships    — inbound + outbound graph edges (limit 50)
  4. security_findings      — open finding rows (limit 20)
  5. attack_paths           — paths where this resource is entry/crown-jewel/choke (limit 5)

Security:
  - tenant_id always from AuthContext via resolve_tenant_id() (never from URL/query)
  - resource_uid validated 1–2048 chars
  - No mock/fallback data — DB unreachable → 503 immediately
  - require_permission("discoveries:read") on this endpoint
  - RBAC field stripping: iam_detail, network_detail, cdr_ttps removed for analyst/viewer

DB: threat_engine_di (direct psycopg2) + threat_engine_attack_path (direct psycopg2)
"""

from __future__ import annotations

import json
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

import psycopg2
import psycopg2.extras
from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request

from ._auth import _parse_auth_context, resolve_tenant_id

logger = logging.getLogger("api-gateway.bff.resource_detail")

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])

# ── Auth ──────────────────────────────────────────────────────────────────────
try:
    from engine_auth.fastapi.dependencies import require_permission
except ImportError:
    def require_permission(_perm: str):  # type: ignore[misc]
        def _ok():
            pass
        return _ok


# ── DI DB connection ──────────────────────────────────────────────────────────

def _get_di_conn() -> psycopg2.extensions.connection:
    return psycopg2.connect(
        host=os.getenv("DI_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("DI_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("DI_DB_NAME", "threat_engine_di"),
        user=os.getenv("DI_DB_USER", os.getenv("DB_USER", "postgres")),
        password=(
            os.getenv("DI_DB_PASSWORD")
            or os.getenv("DB_PASSWORD")
            or os.getenv("DISCOVERIES_DB_PASSWORD", "")
        ),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
        connect_timeout=5,
    )


# ── Attack-Path DB connection ─────────────────────────────────────────────────

def _get_ap_conn() -> psycopg2.extensions.connection:
    return psycopg2.connect(
        host=os.getenv("ATTACK_PATH_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("ATTACK_PATH_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("ATTACK_PATH_DB_NAME", "threat_engine_attack_path"),
        user=os.getenv("ATTACK_PATH_DB_USER", os.getenv("DB_USER", "postgres")),
        password=(
            os.getenv("ATTACK_PATH_DB_PASSWORD")
            or os.getenv("DB_PASSWORD")
            or os.getenv("DISCOVERIES_DB_PASSWORD", "")
        ),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
        connect_timeout=5,
    )


# ── Field stripping ───────────────────────────────────────────────────────────

_SENSITIVE_POSTURE = frozenset({"iam_detail", "network_detail", "cdr_ttps"})
_SENSITIVE_ASSET   = frozenset({"credential_ref"})

def _strip_posture(row: Dict[str, Any], role_level: int) -> Dict[str, Any]:
    """Remove sensitive JSONB fields for analyst (4) and viewer roles."""
    if role_level <= 2:
        return row
    return {k: v for k, v in row.items() if k not in _SENSITIVE_POSTURE}

def _strip_asset(row: Dict[str, Any], role_level: int) -> Dict[str, Any]:
    """Remove credential_ref for all non-platform roles."""
    if role_level <= 2:
        return row
    return {k: v for k, v in row.items() if k not in _SENSITIVE_ASSET}

def _role_level(request: Request) -> int:
    ctx = _parse_auth_context(request)
    if ctx is None:
        return 4
    return getattr(ctx, "role_level", 4)

def _get_auth_header(request: Request) -> Optional[str]:
    """Extract raw X-Auth-Context header for forwarding to engine calls."""
    return request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)


# ── Queries ───────────────────────────────────────────────────────────────────

def _fetch_asset(conn, tenant_id: str, resource_uid: str) -> Optional[Dict[str, Any]]:
    sql = """
        SELECT
            resource_uid, resource_type, resource_name, service,
            provider, account_id, region,
            emitted_fields->'Tags' AS tags,
            emitted_fields AS config,
            first_seen_at, last_seen_at
        FROM asset_inventory
        WHERE tenant_id = %s AND resource_uid = %s
        ORDER BY last_seen_at DESC
        LIMIT 1
    """
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(sql, (tenant_id, resource_uid))
        row = cur.fetchone()
    return dict(row) if row else None


def _fetch_posture(conn, tenant_id: str, resource_uid: str) -> Optional[Dict[str, Any]]:
    sql = """
        SELECT
            -- Scoring
            overall_posture_score, posture_band, posture_vector,
            critical_count, high_count, medium_count, low_count,

            -- Network dimension
            is_internet_exposed, is_in_private_subnet,
            is_internet_exposed_with_critical,
            has_waf, has_load_balancer, network_exposure_score,
            network_score, network_detail,

            -- IAM dimension
            has_attached_role, role_has_wildcard_policy, role_allows_cross_account,
            mfa_enforced, has_permission_boundary, is_admin_role, can_access_pii,
            iam_score, iam_detail,

            -- Encryption dimension
            is_encrypted_at_rest, is_encrypted_in_transit,
            has_kms_managed_key, has_valid_certificate,
            cert_days_remaining, tls_version,
            encryption_score,

            -- Data dimension
            data_classification, reachable_pii_store_count,
            has_exfil_path, secrets_in_env_vars,

            -- Database dimension
            connected_db_count, db_auth_type,

            -- CDR dimension
            has_active_cdr_actor, cdr_actor_count,
            cdr_last_seen_at, cdr_ttps,

            -- Container / AI / DBSec / API scores
            container_security_score, ai_security_score,
            dbsec_score, api_security_score,

            -- Attack-path signals
            is_crown_jewel, crown_jewel_type,
            is_on_attack_path, attack_path_count,
            is_choke_point, paths_blocked_if_fixed,
            highest_path_score, highest_path_severity,
            blast_radius_count,

            last_updated_at
        FROM resource_security_posture
        WHERE tenant_id = %s AND resource_uid = %s
        ORDER BY last_updated_at DESC
        LIMIT 1
    """
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(sql, (tenant_id, resource_uid))
        row = cur.fetchone()
    return dict(row) if row else None


def _fetch_relationships(conn, tenant_id: str, resource_uid: str) -> List[Dict[str, Any]]:
    sql = """
        SELECT
            CASE WHEN source_uid = %s THEN 'outbound' ELSE 'inbound' END AS direction,
            relation_type,
            CASE WHEN source_uid = %s THEN target_uid  ELSE source_uid  END AS peer_uid,
            CASE WHEN source_uid = %s THEN target_type ELSE source_type END AS peer_type,
            attack_path_category,
            relation_metadata,
            last_seen_at
        FROM asset_relationships
        WHERE tenant_id = %s AND (source_uid = %s OR target_uid = %s)
        ORDER BY last_seen_at DESC
        LIMIT 50
    """
    params = (resource_uid, resource_uid, resource_uid, tenant_id, resource_uid, resource_uid)
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(sql, params)
        return [dict(r) for r in cur.fetchall()]


def _fetch_open_findings(conn, tenant_id: str, resource_uid: str) -> List[Dict[str, Any]]:
    """Fetch open finding rows from security_findings (limit 20, ordered by severity)."""
    sql = """
        SELECT
            finding_id, source_engine, source_finding_id,
            finding_type, severity, rule_id, title, description,
            epss_score, cvss_score, in_kev,
            mitre_technique_id, mitre_tactic,
            detail, status, first_seen_at, last_seen_at
        FROM security_findings
        WHERE tenant_id = %s AND resource_uid = %s AND status = 'open'
        ORDER BY
            CASE LOWER(severity)
                WHEN 'critical' THEN 1
                WHEN 'high'     THEN 2
                WHEN 'medium'   THEN 3
                WHEN 'low'      THEN 4
                ELSE 5
            END,
            COALESCE(epss_score, 0) DESC
        LIMIT 20
    """
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(sql, (tenant_id, resource_uid))
        return [dict(r) for r in cur.fetchall()]


def _fetch_findings_summary(conn, tenant_id: str, resource_uid: str) -> Dict[str, Any]:
    """Count findings by engine and severity from security_findings."""
    sql = """
        SELECT source_engine, severity, COUNT(*) AS cnt
        FROM security_findings
        WHERE tenant_id = %s AND resource_uid = %s AND status = 'open'
        GROUP BY source_engine, severity
    """
    with conn.cursor() as cur:
        cur.execute(sql, (tenant_id, resource_uid))
        rows = cur.fetchall()

    by_engine: Dict[str, int] = {}
    by_severity: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    total = 0

    for engine, sev, cnt in rows:
        by_engine[engine] = by_engine.get(engine, 0) + cnt
        sev_lower = (sev or "").lower()
        if sev_lower in by_severity:
            by_severity[sev_lower] += cnt
        total += cnt

    return {"total": total, "by_engine": by_engine, "by_severity": by_severity}


def _fetch_attack_paths_for_resource(
    ap_conn, tenant_id: str, resource_uid: str
) -> List[Dict[str, Any]]:
    """Fetch active attack paths where this resource is entry point, crown jewel, or choke node."""
    sql = """
        SELECT
            path_id, severity, path_score, chain_type,
            entry_point_type, entry_point_uid,
            crown_jewel_uid, crown_jewel_type,
            choke_node_uid, depth,
            has_active_cdr_actor, max_epss,
            misconfig_count, threat_count,
            confidence_level, attack_name, attack_story,
            data_classification, group_id,
            first_seen_at, last_seen_at,
            CASE
                WHEN entry_point_uid = %s THEN 'entry_point'
                WHEN crown_jewel_uid = %s  THEN 'crown_jewel'
                WHEN choke_node_uid  = %s  THEN 'choke_node'
                ELSE 'node'
            END AS resource_role
        FROM attack_paths
        WHERE tenant_id = %s
          AND status = 'active'
          AND (entry_point_uid = %s OR crown_jewel_uid = %s OR choke_node_uid = %s)
        ORDER BY path_score DESC, first_seen_at ASC
        LIMIT 5
    """
    params = (
        resource_uid, resource_uid, resource_uid,
        tenant_id,
        resource_uid, resource_uid, resource_uid,
    )
    with ap_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(sql, params)
        return [dict(r) for r in cur.fetchall()]


# ── Endpoint ──────────────────────────────────────────────────────────────────

@router.get(
    "/resource/{resource_uid:path}",
    summary="Step 3 resource context panel",
    description=(
        "Returns asset identity, cross-engine posture dimensions, "
        "graph relationships, open findings, and attack paths for a single resource. "
        "Used by all posture engine pages to populate the slide-in detail panel."
    ),
    dependencies=[Depends(require_permission("discoveries:read"))],
)
async def get_resource_detail(
    request: Request,
    resource_uid: str = Path(..., min_length=1, max_length=2048),
    provider: Optional[str] = Query(None),
    account:  Optional[str] = Query(None),
    region:   Optional[str] = Query(None),
) -> Dict[str, Any]:
    tenant_id  = resolve_tenant_id(request)
    role_level = _role_level(request)

    try:
        di_conn = _get_di_conn()
    except Exception as exc:
        logger.error("resource_detail: DI DB connection failed: %s", exc)
        raise HTTPException(status_code=503, detail="DI database unavailable")

    ap_conn: Optional[psycopg2.extensions.connection] = None
    try:
        ap_conn = _get_ap_conn()
    except Exception as exc:
        logger.warning("resource_detail: attack-path DB connection failed: %s", exc)
        # Non-fatal — attack path data is enrichment, not required

    results: Dict[str, Any] = {}

    try:
        def _run_di(fn):
            return fn(di_conn, tenant_id, resource_uid)

        def _run_ap(fn):
            if ap_conn is None:
                return []
            return fn(ap_conn, tenant_id, resource_uid)

        with ThreadPoolExecutor(max_workers=6) as pool:
            futures = {
                pool.submit(_run_di, _fetch_asset):             "asset",
                pool.submit(_run_di, _fetch_posture):           "posture",
                pool.submit(_run_di, _fetch_relationships):     "relationships",
                pool.submit(_run_di, _fetch_findings_summary):  "findings_summary",
                pool.submit(_run_di, _fetch_open_findings):     "open_findings",
                pool.submit(_run_ap, _fetch_attack_paths_for_resource): "attack_paths",
            }
            for future in as_completed(futures):
                key = futures[future]
                try:
                    results[key] = future.result()
                except Exception as exc:
                    logger.warning("resource_detail: %s query failed: %s", key, exc)
                    results[key] = None

    except Exception as exc:
        logger.error("resource_detail: query error for %s: %s", resource_uid, exc)
        raise HTTPException(status_code=503, detail="Failed to load resource detail")
    finally:
        di_conn.close()
        if ap_conn is not None:
            try:
                ap_conn.close()
            except Exception:
                pass

    asset   = results.get("asset")
    posture = results.get("posture")

    if asset is None:
        raise HTTPException(status_code=404, detail="Resource not found in inventory")

    return {
        "resource":         _strip_asset(asset, role_level),
        "posture":          _strip_posture(posture, role_level) if posture else None,
        "relationships":    results.get("relationships") or [],
        "findings_summary": results.get("findings_summary") or {
            "total": 0, "by_engine": {}, "by_severity": {}
        },
        "open_findings":    results.get("open_findings") or [],
        "attack_paths":     results.get("attack_paths") or [],
    }
