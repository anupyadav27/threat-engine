"""
BFF view handlers for security_findings queries (SF-P2-01).

Reads threat_engine_inventory.security_findings directly — no per-engine API calls.

Two endpoints:
  GET /api/v1/views/inventory/asset/{uid}/findings  — all findings for one resource
  GET /api/v1/views/findings                        — tenant-wide paginated findings

Field stripping by role (RBAC):
  platform_admin / org_admin : all fields
  tenant_admin / analyst      : CDR rows → detail stripped (contains actor_hash)
  viewer                      : detail=None, epss_score=None on all rows

Security:
  - tenant_id always from AuthContext via resolve_tenant_id() (never from query param)
  - No mock/fallback data — DB unreachable → 503 immediately
  - require_permission("discoveries:read") on both endpoints
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

import psycopg2
import psycopg2.extras
from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request

from ._auth import _parse_auth_context, resolve_tenant_id

logger = logging.getLogger("api-gateway.bff.asset_findings")

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])

# ── Auth ───────────────────────────────────────────────────────────────────────
try:
    from engine_auth.fastapi.dependencies import require_permission
    _AUTH_AVAILABLE = True
except ImportError:
    _AUTH_AVAILABLE = False

    def require_permission(_perm: str):  # type: ignore[misc]
        def _ok():
            pass
        return _ok


# ── DI DB connection (security_findings lives here after di_008 migration) ────

def _get_inventory_conn() -> psycopg2.extensions.connection:
    """Open a direct psycopg2 connection to threat_engine_di DB for findings reads."""
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


# ── Severity sort order (hardcoded — NO user input) ───────────────────────────
_SEVERITY_RANK_SQL = (
    "CASE severity "
    "WHEN 'critical' THEN 1 "
    "WHEN 'high'     THEN 2 "
    "WHEN 'medium'   THEN 3 "
    "ELSE 4 END"
)


# ── Category filter (PC-INFRA-03) — maps category name → rule_id prefixes ─────

_CATEGORY_PREFIXES: Dict[str, List[str]] = {
    "escalation":    ["aws.iam.role.privilege_escalation"],
    "cross_account": ["aws.s3.bucket.no_cross_account", "aws.s3.bucket.cross_account", "aws.lakeformation"],
    "container_ecr": ["aws.ecr.repository", "aws.eks.node_group", "azure.aks.cluster"],
    "cdr_sequence":  ["aws.cdr.sequence"],
}


# ── Field stripping ────────────────────────────────────────────────────────────

def _strip_finding(row: Dict[str, Any], role: str) -> Dict[str, Any]:
    """Apply RBAC field stripping to a single finding row.

    Args:
        row:  dict from psycopg2 RealDictCursor
        role: AuthContext.role string (e.g. "viewer", "analyst")
    """
    result = dict(row)
    if role == "viewer":
        # viewer: strip sensitive detail + EPSS score on all rows
        result["detail"] = None
        result["epss_score"] = None
    elif role == "analyst" and result.get("source_engine") == "cdr":
        # analyst: strip CDR detail only (may contain actor_hash — sensitive)
        result["detail"] = None
    return result


# ── Helpers ────────────────────────────────────────────────────────────────────

def _resolve_ctx(request: Request):
    """Return (tenant_id, role) from the request AuthContext."""
    ctx = _parse_auth_context(request)
    role = getattr(ctx, "role", "viewer") if ctx else "viewer"
    tenant_id = resolve_tenant_id(request)
    return tenant_id, role


# ── Endpoint 1: per-asset findings ────────────────────────────────────────────

@router.get(
    "/inventory/asset/{uid}/findings",
    dependencies=[Depends(require_permission("discoveries:read"))],
)
async def get_asset_findings(
    uid: str = Path(..., min_length=1, max_length=512),
    status: str = Query("open"),
    request: Request = None,
) -> Dict[str, Any]:
    """All security findings for one resource, ordered by severity then recency.

    Returns findings list + KPIs (by_engine, by_severity counts).
    Multi-tenant: tenant_id from AuthContext.
    """
    tenant_id, role = _resolve_ctx(request)
    if not tenant_id:
        raise HTTPException(status_code=422, detail="tenant_id required")

    conn: Optional[psycopg2.extensions.connection] = None
    try:
        conn = _get_inventory_conn()
    except Exception as exc:
        logger.error("asset_findings: cannot connect to inventory DB: %s", exc)
        raise HTTPException(status_code=503, detail={"error": "inventory DB unavailable"})

    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            # Main findings query — up to 100 rows per asset
            cur.execute(
                f"""
                SELECT finding_id::text, source_engine, source_finding_id,
                       resource_uid, finding_type, severity, rule_id, title,
                       epss_score, cvss_score, in_kev, mitre_technique_id,
                       mitre_tactic, detail, status, first_seen_at, last_seen_at
                FROM security_findings
                WHERE resource_uid = %s
                  AND tenant_id    = %s
                  AND status       = %s
                ORDER BY {_SEVERITY_RANK_SQL}, last_seen_at DESC
                LIMIT 100
                """,
                (uid, tenant_id, status),
            )
            rows = [dict(r) for r in cur.fetchall()]

            # KPI: count by severity
            cur.execute(
                """
                SELECT severity, COUNT(*) AS cnt
                FROM security_findings
                WHERE resource_uid = %s AND tenant_id = %s AND status = %s
                GROUP BY severity
                """,
                (uid, tenant_id, status),
            )
            by_severity: Dict[str, int] = {r["severity"]: r["cnt"] for r in cur.fetchall()}

            # KPI: count by source engine
            cur.execute(
                """
                SELECT source_engine, COUNT(*) AS cnt
                FROM security_findings
                WHERE resource_uid = %s AND tenant_id = %s AND status = %s
                GROUP BY source_engine
                """,
                (uid, tenant_id, status),
            )
            by_engine: Dict[str, int] = {r["source_engine"]: r["cnt"] for r in cur.fetchall()}

    except Exception as exc:
        logger.error("asset_findings: query failed: %s", exc)
        raise HTTPException(status_code=503, detail={"error": "findings query failed"})
    finally:
        conn.close()

    findings = [_strip_finding(r, role) for r in rows]
    total = sum(by_engine.values())

    return {
        "findings":    findings,
        "total":       total,
        "by_engine":   by_engine,
        "by_severity": by_severity,
    }


# ── Endpoint 2: tenant-wide paginated findings ────────────────────────────────

@router.get(
    "/findings",
    dependencies=[Depends(require_permission("discoveries:read"))],
)
async def get_findings(
    severity: Optional[str] = Query(None),
    finding_type: Optional[str] = Query(None),
    source_engine: Optional[str] = Query(None),
    status: str = Query("open"),
    resource_uid: Optional[str] = Query(None),
    category: Optional[str] = Query(None, description="Rule-id prefix group: escalation|cross_account|container_ecr|cdr_sequence"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    request: Request = None,
) -> Dict[str, Any]:
    """Tenant-wide paginated cross-engine findings with summary KPIs.

    KPIs returned:
      critical, high, open_cves_in_kev, open_cdr_events
    """
    tenant_id, role = _resolve_ctx(request)
    if not tenant_id:
        raise HTTPException(status_code=422, detail="tenant_id required")

    # Build WHERE clause dynamically from filters
    filters: List[str] = ["tenant_id = %s", "status = %s"]
    params: List[Any] = [tenant_id, status]

    if severity:
        filters.append("severity = %s")
        params.append(severity)
    if finding_type:
        filters.append("finding_type = %s")
        params.append(finding_type)
    if source_engine:
        filters.append("source_engine = %s")
        params.append(source_engine)
    if resource_uid:
        filters.append("resource_uid = %s")
        params.append(resource_uid)
    if category:
        prefixes = _CATEGORY_PREFIXES.get(category, [])
        if prefixes:
            prefix_clauses = " OR ".join(["rule_id LIKE %s"] * len(prefixes))
            filters.append(f"({prefix_clauses})")
            params.extend(f"{p}%" for p in prefixes)

    where_clause = " AND ".join(filters)
    offset = (page - 1) * page_size

    conn: Optional[psycopg2.extensions.connection] = None
    try:
        conn = _get_inventory_conn()
    except Exception as exc:
        logger.error("get_findings: cannot connect to inventory DB: %s", exc)
        raise HTTPException(status_code=503, detail={"error": "inventory DB unavailable"})

    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            # Total row count (for pagination)
            cur.execute(
                f"SELECT COUNT(*) FROM security_findings WHERE {where_clause}",
                params,
            )
            total: int = cur.fetchone()["count"]

            # Main paginated query
            cur.execute(
                f"""
                SELECT finding_id::text, source_engine, source_finding_id,
                       resource_uid, finding_type, severity, rule_id, title,
                       epss_score, cvss_score, in_kev, mitre_technique_id,
                       mitre_tactic, detail, status, first_seen_at, last_seen_at
                FROM security_findings
                WHERE {where_clause}
                ORDER BY {_SEVERITY_RANK_SQL}, last_seen_at DESC
                LIMIT %s OFFSET %s
                """,
                params + [page_size, offset],
            )
            rows = [dict(r) for r in cur.fetchall()]

            # Aggregate KPIs (scoped to same filters as the main query)
            cur.execute(
                f"""
                SELECT
                    SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) AS critical,
                    SUM(CASE WHEN severity = 'high'     THEN 1 ELSE 0 END) AS high,
                    SUM(CASE WHEN in_kev = TRUE         THEN 1 ELSE 0 END) AS open_cves_in_kev,
                    SUM(CASE WHEN source_engine = 'cdr' THEN 1 ELSE 0 END) AS open_cdr_events
                FROM security_findings
                WHERE {where_clause}
                """,
                params,
            )
            kpi_row = dict(cur.fetchone())

    except Exception as exc:
        logger.error("get_findings: query failed: %s", exc)
        raise HTTPException(status_code=503, detail={"error": "findings query failed"})
    finally:
        conn.close()

    findings = [_strip_finding(r, role) for r in rows]

    return {
        "findings":  findings,
        "total":     total,
        "page":      page,
        "page_size": page_size,
        "kpis": {
            "critical":         int(kpi_row.get("critical") or 0),
            "high":             int(kpi_row.get("high") or 0),
            "open_cves_in_kev": int(kpi_row.get("open_cves_in_kev") or 0),
            "open_cdr_events":  int(kpi_row.get("open_cdr_events") or 0),
        },
    }
