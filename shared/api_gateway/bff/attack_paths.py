"""
BFF view handler: /api/v1/views/attack-paths

Attack Path Engine — view layer for the Attack Paths UI page.

Endpoints:
  GET /api/v1/views/attack-paths
      Returns paths list + KPI groups + choke_points_preview (top-3).
      Viewer role: returns only { total, kpis } — paths[] array omitted.

  GET /api/v1/views/attack-paths/{path_id}
      Returns full path detail with steps[] array.
      Viewer role: 403 Forbidden.

Security:
  - require_permission("attack_path:read") on all endpoints.
  - Viewer receives only summary (no paths[] array) on list endpoint.
  - Viewer receives 403 on detail endpoint.
  - NO fallback/mock data — engine unavailable → 503 immediately.
  - tenant_id always from AuthContext (resolved server-side).
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request

from ._auth import resolve_tenant_id
from ._shared import safe_get

logger = logging.getLogger("api-gateway.bff.attack_paths")

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])

_ATTACK_PATH_ENGINE = "http://engine-attack-path.threat-engine-engines.svc.cluster.local:80"

# ── Auth ──────────────────────────────────────────────────────────────────────
try:
    from engine_auth.fastapi.dependencies import require_permission
    _AUTH_AVAILABLE = True
except ImportError:
    _AUTH_AVAILABLE = False

    def require_permission(_perm: str):  # type: ignore[misc]
        def _ok():
            pass
        return _ok


def _engine_url() -> str:
    import os
    return os.getenv("ATTACK_PATH_ENGINE_URL", _ATTACK_PATH_ENGINE)


def _fwd_headers(request: Request) -> Dict[str, str]:
    """Build forwarded auth headers with correct engine_tenant_id.

    resolve_tenant_id() returns None for platform_admin "All Tenants" mode.
    In that case we preserve the original engine_tenant_id from the auth
    context (the user's default tenant) rather than overwriting it with None,
    which would cause engines to fall back to "default-tenant" (no data).
    """
    raw = request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    headers: Dict[str, str] = {}
    if raw:
        try:
            ctx = json.loads(raw)
            resolved = resolve_tenant_id(request)
            if resolved is not None:
                ctx["engine_tenant_id"] = resolved
            # If resolved is None (platform_admin all-tenants view), keep the
            # original engine_tenant_id from the session scope_cache so the engine
            # gets a valid tenant filter rather than falling back to "default-tenant".
            headers["X-Auth-Context"] = json.dumps(ctx)
        except Exception:
            headers["X-Auth-Context"] = raw
    return headers


def _is_viewer(request: Request) -> bool:
    """Return True if the authenticated role is 'viewer'."""
    raw = request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    if not raw:
        return False
    try:
        ctx = json.loads(raw)
        return ctx.get("role") == "viewer"
    except Exception:
        return False


# ---------------------------------------------------------------------------
# GET /api/v1/views/attack-paths
# ---------------------------------------------------------------------------

@router.get("/attack-paths", dependencies=[Depends(require_permission("attack_path:read"))])
async def view_attack_paths(
    request: Request,
    severity: Optional[str] = Query(default=None),
    entry_point_type: Optional[str] = Query(default=None),
    representative_only: bool = Query(default=True),
    group_id: Optional[str] = Query(default=None),
    search: Optional[str] = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
) -> Dict[str, Any]:
    """BFF aggregation for the Attack Paths UI page.

    Viewer role receives only { total, kpis } — paths[] array omitted.
    """
    headers = _fwd_headers(request)

    # Build query params to forward
    params: Dict[str, Any] = {
        "page": page,
        "page_size": page_size,
        "representative_only": representative_only,
    }
    if severity:
        params["severity"] = severity
    if entry_point_type:
        params["entry_point_type"] = entry_point_type
    if group_id:
        params["group_id"] = group_id
    search_stripped = (search or "").strip()
    if search_stripped:
        params["search"] = search_stripped

    engine = _engine_url()

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Parallel: paths list + choke points preview
            import asyncio
            paths_task = client.get(
                f"{engine}/api/v1/attack-paths",
                params=params,
                headers=headers,
            )
            choke_task = client.get(
                f"{engine}/api/v1/choke-points",
                params={"limit": 3},
                headers=headers,
            )
            paths_resp, choke_resp = await asyncio.gather(paths_task, choke_task)

    except Exception as exc:
        logger.error("attack-path engine unavailable: %s", exc)
        raise HTTPException(
            status_code=503,
            detail={"error": "attack-path engine unavailable"},
        )

    if paths_resp.status_code not in (200, 404):
        logger.error("attack-path engine returned %d", paths_resp.status_code)
        raise HTTPException(
            status_code=503,
            detail={"error": "attack-path engine unavailable"},
        )

    data = paths_resp.json() if paths_resp.status_code == 200 else {"paths": [], "total": 0, "kpis": {}}
    choke_data = choke_resp.json() if choke_resp.status_code == 200 else {"choke_points": []}

    # Ensure new KPI fields are present (guards against older engine images)
    engine_kpis = data.get("kpis", {})
    engine_kpis.setdefault("likely_paths", 0)
    engine_kpis.setdefault("speculative_paths", 0)
    data["kpis"] = engine_kpis

    # Viewer restriction: return only summary (AC-8)
    if _is_viewer(request):
        return {
            "total": data.get("total", 0),
            "kpis": data.get("kpis", {}),
        }

    # Add choke_points_preview (top-3 from choke endpoint)
    data["choke_points_preview"] = choke_data.get("choke_points", [])[:3]

    # Add open_days to each path if not already present
    for p in data.get("paths", []):
        if "open_days" not in p:
            p["open_days"] = 0

    return data


# ---------------------------------------------------------------------------
# GET /api/v1/views/attack-paths/{path_id}
# ---------------------------------------------------------------------------

@router.get(
    "/attack-paths/{path_id}",
    dependencies=[Depends(require_permission("attack_path:read"))],
)
async def view_attack_path_detail(
    path_id: str,
    request: Request,
) -> Dict[str, Any]:
    """BFF detail view for a single attack path with steps[].

    Viewer role: 403 Forbidden (AC-9).
    """
    # Viewer restriction: 403 on detail endpoint
    if _is_viewer(request):
        raise HTTPException(status_code=403, detail="Access restricted for viewer role")

    headers = _fwd_headers(request)
    engine = _engine_url()

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                f"{engine}/api/v1/attack-paths/{path_id}",
                headers=headers,
            )
    except Exception as exc:
        logger.error("attack-path engine unavailable: %s", exc)
        raise HTTPException(
            status_code=503,
            detail={"error": "attack-path engine unavailable"},
        )

    if resp.status_code == 404:
        raise HTTPException(status_code=404, detail="Attack path not found")
    if resp.status_code != 200:
        raise HTTPException(
            status_code=503,
            detail={"error": "attack-path engine unavailable"},
        )

    data = resp.json()

    # Ensure steps is present and traversal_reason is passed through
    if "steps" not in data:
        data["steps"] = []

    return data
