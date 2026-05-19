"""BFF view: /onboarding/schedules — scan schedule list.

Proxies GET /api/v1/schedules from the onboarding engine and normalises the
response so the UI can read it via fetchView('onboarding/schedules') instead
of getFromEngine('onboarding', '/api/v1/schedules').

This is the JNY-17.1 BFF migration for onboarding schedule reads.
Write operations (POST/PUT/DELETE) remain in ALLOWED_DIRECT_ENGINE_BYPASSES
pending STORY-ONBOARDING-WRITE-BFF-MIGRATION.

Security: tenant_id resolved from AuthContext, never from query param.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query, Request

from ._auth import _parse_auth_context, resolve_tenant_id
from ._shared import _fetch_engine
import httpx

logger = logging.getLogger("api-gateway.bff.onboarding_schedules")

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


@router.get("/onboarding/schedules")
async def view_onboarding_schedules(
    request: Request,
    limit: int = Query(200, ge=1, le=500),
    account_id: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """Return scan schedules for the authenticated tenant.

    Args:
        request: FastAPI Request — AuthContext header must be present.
        limit: Max schedules to return (default 200).
        account_id: Optional filter by cloud account.

    Returns:
        Dict with schedules list and summary KPIs.
    """
    ctx = _parse_auth_context(request)
    tenant_id = resolve_tenant_id(request)

    if ctx is None:
        return {"schedules": [], "total": 0, "kpiGroups": []}

    auth_ctx_header = (
        request.headers.get("X-Auth-Context")
        or getattr(request.state, "auth_header", None)
    )
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None

    params: Dict[str, Any] = {"limit": str(limit)}
    if tenant_id:
        params["tenant_id"] = tenant_id
    if account_id:
        params["account_id"] = account_id

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            data = await _fetch_engine(
                client, "onboarding", "/api/v1/schedules",
                params=params, auth_headers=fwd_headers,
            )
    except Exception as exc:
        logger.warning("onboarding schedules BFF fetch failed: %s", exc)
        return {"schedules": [], "total": 0, "kpiGroups": []}

    schedules: List[Dict[str, Any]] = []
    if isinstance(data, dict):
        schedules = data.get("schedules", []) or []
    elif isinstance(data, list):
        schedules = data

    enabled = sum(1 for s in schedules if s.get("schedule_enabled", False))

    kpi_groups = [
        {
            "title": "Scan Schedules",
            "items": [
                {"label": "Total Schedules", "value": len(schedules)},
                {"label": "Enabled", "value": enabled},
                {"label": "Disabled", "value": len(schedules) - enabled},
            ],
        }
    ]

    return {
        "schedules": schedules,
        "total": len(schedules),
        "kpiGroups": kpi_groups,
    }
