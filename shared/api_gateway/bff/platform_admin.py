"""BFF view: /platform-admin page.

Aggregates: engine health grid, org subscription list, platform-wide metrics.
Permission: platform:admin required — returns 403-shaped payload for all other roles.

Engine: engine-platform-admin (port 8041)
"""

import logging
import os
from typing import Optional

from fastapi import APIRouter, Query, Request

from ._shared import fetch_many, safe_get

logger = logging.getLogger("api-gateway.bff.platform_admin")

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])

_PADMIN_URL = os.getenv("PLATFORM_ADMIN_ENGINE_URL", "http://engine-platform-admin:8041")


@router.get("/platform-admin")
async def view_platform_admin(
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
):
    """Single endpoint returning everything the platform-admin dashboard needs.

    Calls the platform-admin engine in parallel for:
    - Engine health status grid (all 18 engines, latency, pod count)
    - Org subscription list (paginated)
    - Platform-wide metrics (total orgs, trials expiring, past_due count)

    Requires platform:admin permission — the gateway enforces this via X-Auth-Context.
    Returns { error: "forbidden" } for non-platform-admin callers so the frontend
    can render a graceful "Not authorized" message.
    """
    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(
        request.state, "auth_header", None
    )
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None

    results = await fetch_many(
        [
            ("platform_admin", "/api/v1/padmin/engines/health", {}),
            (
                "platform_admin",
                "/api/v1/padmin/orgs",
                {"page": str(page), "page_size": str(page_size)},
            ),
            ("platform_admin", "/api/v1/padmin/metrics", {}),
        ],
        auth_headers=fwd_headers,
    )

    health_data, orgs_data, metrics_data = results

    # Normalise to safe shapes
    if not isinstance(health_data, dict):
        health_data = {}
    if not isinstance(orgs_data, dict):
        orgs_data = {}
    if not isinstance(metrics_data, dict):
        metrics_data = {}

    # Engines health: { "engines": [...] }
    engines_raw = health_data.get("engines", health_data) if isinstance(health_data, dict) else []
    if not isinstance(engines_raw, list):
        engines_raw = []

    engines = []
    for eng in engines_raw:
        if not isinstance(eng, dict):
            continue
        status = eng.get("status", "unknown").lower()
        engines.append(
            {
                "name":         eng.get("name", ""),
                "status":       status,
                "status_color": _status_color(status),
                "latency_ms":   eng.get("latency_ms") or eng.get("latency", None),
                "pod_count":    eng.get("pod_count", None),
                "version":      eng.get("version", ""),
                "last_checked": eng.get("last_checked", ""),
            }
        )

    # Orgs: { "orgs": [...], "total": N, "page": N, "page_size": N }
    orgs_raw = orgs_data.get("orgs", [])
    if not isinstance(orgs_raw, list):
        orgs_raw = []

    orgs = []
    for org in orgs_raw:
        if not isinstance(org, dict):
            continue
        status = org.get("subscription_status", org.get("status", "")).lower()
        orgs.append(
            {
                "org_id":             org.get("org_id") or org.get("id", ""),
                "org_name":           org.get("org_name") or org.get("name", ""),
                "tier":               org.get("tier", "free"),
                "status":             status,
                "status_color":       _sub_status_color(status),
                "accounts_connected": org.get("accounts_connected", 0),
                "max_accounts":       org.get("max_accounts", None),
                "trial_end_at":       org.get("trial_end_at", ""),
                "created_at":         org.get("created_at", ""),
            }
        )

    pagination = {
        "total":     orgs_data.get("total", len(orgs)),
        "page":      orgs_data.get("page", page),
        "page_size": orgs_data.get("page_size", page_size),
    }

    # Metrics: flat dict with platform summary
    metrics = {
        "total_orgs":            metrics_data.get("total_orgs", 0),
        "orgs_by_tier":          metrics_data.get("orgs_by_tier", {}),
        "trials_expiring_7d":    metrics_data.get("trials_expiring_7d", 0),
        "past_due_orgs":         metrics_data.get("past_due_orgs", 0),
        "total_scans_this_month": metrics_data.get("total_scans_this_month", 0),
        "active_pipelines":      metrics_data.get("active_pipelines", 0),
    }

    return {
        "engines":    engines,
        "orgs":       orgs,
        "pagination": pagination,
        "metrics":    metrics,
    }


# ── Helper colour mappers ──────────────────────────────────────────────────────

def _status_color(status: str) -> str:
    """Map engine health status to a CSS-friendly colour token."""
    if status in ("healthy", "ok", "up", "operational", "running"):
        return "green"
    if status in ("degraded", "slow", "warning"):
        return "yellow"
    if status in ("unhealthy", "down", "error", "critical"):
        return "red"
    return "gray"


def _sub_status_color(status: str) -> str:
    """Map subscription status to a CSS-friendly colour token."""
    if status in ("active",):
        return "green"
    if status in ("trialing", "trial"):
        return "blue"
    if status in ("past_due", "past-due"):
        return "yellow"
    if status in ("cancelled", "canceled", "inactive", "expired"):
        return "red"
    return "gray"
