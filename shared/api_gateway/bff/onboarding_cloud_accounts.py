"""BFF views: cloud accounts list + scan run history (onboarding-D6).

Endpoints
---------
GET  /api/v1/views/onboarding/cloud_accounts  — cloud accounts visible to the caller's tenant
GET  /api/v1/views/scan_history               — paginated scan run history (D-6 AC1)
GET  /api/v1/views/scan_detail                — single scan run detail with engine breakdown (D-6 AC3)
POST /api/v1/views/scan_rerun                 — re-run a previous scan by scan_run_id (D-6 AC4)

Security
--------
- tenant_id resolved server-side from X-Auth-Context (never accepted from query)
- per-permission gate: ``cloud_accounts:read`` / ``scans:read`` / ``scans:create``
- forwards X-Auth-Context verbatim to engine for downstream RBAC enforcement
- scan_rerun: account_id is resolved server-side from the original scan record,
  never from the caller's request body
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx
from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

try:
    from engine_auth.fastapi.dependencies import require_permission
except ImportError:  # pragma: no cover
    def require_permission(_perm: str):  # type: ignore[no-redef]
        def _denied():
            raise HTTPException(status_code=401, detail="auth module unavailable")
        return _denied

from ._auth import resolve_tenant_id
from ._shared import ENGINE_URLS, fetch_many, safe_get


logger = logging.getLogger("api-gateway.bff.onboarding_cloud_accounts")

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


# ── Pydantic schemas (camelCase) ────────────────────────────────────────────

class CloudAccountItem(BaseModel):
    """Single cloud account row for list rendering."""

    accountId: str = Field(..., description="Account UUID (engine PK)")
    customerId: Optional[str] = None
    tenantId: Optional[str] = None
    tenantName: Optional[str] = Field(None, description="Workspace name from tenants JOIN")
    tenantEnvironment: Optional[str] = Field(None, description="production|staging|development|test")
    provider: Optional[str] = Field(None, description="aws|azure|gcp|oci|alicloud|ibm|k8s")
    accountIdentifier: Optional[str] = Field(
        None, description="CSP-native identifier (e.g. AWS 12-digit)"
    )
    accountName: Optional[str] = None
    accountCategory: Optional[str] = Field(
        None, description="cloud|onprem|saas|k8s — was account_type"
    )
    account_type: Optional[str] = Field(
        None, description="snake_case alias of accountCategory for frontend compatibility"
    )
    accountStatus: Optional[str] = None
    onboardingStatus: Optional[str] = None
    credentialRef: Optional[str] = Field(None, description="SM path — non-empty means credentials stored")
    credentialValidationStatus: Optional[str] = None
    credentialValidatedAt: Optional[str] = None
    scheduleEnabled: Optional[bool] = None
    scheduleNextRunAt: Optional[str] = None
    lastScanAt: Optional[str] = None
    createdAt: Optional[str] = None
    updatedAt: Optional[str] = None


class CloudAccountsListResponse(BaseModel):
    """Response envelope for cloud_accounts list view."""

    accounts: List[CloudAccountItem]
    count: int


def _to_camel(row: dict) -> dict:
    """Project an engine snake_case account row into the camelCase schema.

    Tolerant of missing fields — the engine row is the source of truth.
    """
    cred_ref = row.get("credential_ref") or ""
    return {
        "accountId":                  row.get("account_id") or row.get("id") or "",
        "customerId":                 row.get("customer_id"),
        "tenantId":                   row.get("tenant_id"),
        "tenantName":                 row.get("tenant_name"),
        "tenantEnvironment":          row.get("tenant_environment"),
        "provider":                   row.get("provider"),
        "accountIdentifier":          row.get("account_identifier"),
        "accountName":                row.get("account_name"),
        "accountCategory":            row.get("account_type") or row.get("account_category"),
        "account_type":               row.get("account_type") or row.get("account_category"),
        "accountStatus":              row.get("account_status"),
        "onboardingStatus":           row.get("account_onboarding_status")
                                       or row.get("onboarding_status"),
        "credentialRef":              cred_ref if cred_ref not in ("", "pending") else "",
        "credentialValidationStatus": row.get("credential_validation_status"),
        "credentialValidatedAt":      row.get("credential_validated_at"),
        "scheduleEnabled":            row.get("schedule_enabled"),
        "scheduleNextRunAt":          row.get("schedule_next_run_at"),
        "lastScanAt":                 row.get("last_scan_at"),
        "createdAt":                  row.get("created_at"),
        "updatedAt":                  row.get("updated_at"),
    }


@router.get(
    "/onboarding/cloud_accounts",
    response_model=CloudAccountsListResponse,
)
async def view_onboarding_cloud_accounts(
    request: Request,
    provider: Optional[str] = Query(None, description="Filter by provider"),
    accountCategory: Optional[str] = Query(None, description="cloud|onprem|saas|k8s"),
    status: Optional[str] = Query(None, description="account_status filter"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    _: Any = Depends(require_permission("cloud_accounts:read")),
) -> CloudAccountsListResponse:
    """Return the caller's cloud accounts via the onboarding engine."""

    tenant_id = resolve_tenant_id(request)
    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(
        request.state, "auth_header", None
    )
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None

    params: dict = {"limit": str(limit), "offset": str(offset)}
    if tenant_id:
        params["tenant_id"] = tenant_id
    if provider:
        params["provider"] = provider
    if accountCategory:
        params["account_category"] = accountCategory
    if status:
        params["status"] = status

    results = await fetch_many(
        [("onboarding", "/api/v1/cloud-accounts", params)],
        auth_headers=fwd_headers,
    )
    raw = results[0] or {}

    accounts_raw = safe_get(raw, "accounts", []) or []
    if not isinstance(accounts_raw, list):
        accounts_raw = []

    items = [CloudAccountItem(**_to_camel(r)) for r in accounts_raw if isinstance(r, dict)]
    return CloudAccountsListResponse(accounts=items, count=len(items))


# ── D-6: Scan History, Scan Detail, Scan Re-run ──────────────────────────────

_TERMINAL_STATUSES = {"completed", "failed"}

_ONBOARDING_URL = ENGINE_URLS.get("onboarding", os.getenv("ONBOARDING_ENGINE_URL", "http://engine-onboarding:8008"))


def _compute_duration(created_at: Optional[str], updated_at: Optional[str], status: Optional[str]) -> Optional[int]:
    """Compute duration_seconds from timestamps when status is terminal.

    Args:
        created_at: ISO-8601 timestamp of scan creation/start.
        updated_at: ISO-8601 timestamp of last update (completion).
        status:     Scan overall_status string.

    Returns:
        Integer seconds elapsed, or None if status is not terminal or timestamps are missing.
    """
    if status not in _TERMINAL_STATUSES:
        return None
    if not created_at or not updated_at:
        return None
    try:
        dt_created = datetime.fromisoformat(str(created_at).replace("Z", "+00:00"))
        dt_updated = datetime.fromisoformat(str(updated_at).replace("Z", "+00:00"))
        delta = (dt_updated - dt_created).total_seconds()
        return int(delta) if delta >= 0 else None
    except (ValueError, TypeError):
        return None


def _shape_scan_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """Project a scan_orchestration row into the AC2 contract shape.

    ``engines_requested`` and ``engines_completed`` come from psycopg2 as
    Python lists (JSONB is auto-deserialised) — never call json.loads() on them.

    Args:
        row: Raw scan run dict from the onboarding engine.

    Returns:
        Dict conforming to the AC2 scan history item contract.
    """
    status = row.get("overall_status") or row.get("status")

    # created_at is the canonical scan start; use completed_at as updated_at proxy.
    created_at = row.get("created_at") or row.get("started_at")
    updated_at = row.get("completed_at") or row.get("updated_at") or created_at

    # Ensure engines_requested / engines_completed are lists, not strings.
    # The onboarding engine already returns them as lists, but guard defensively.
    engines_requested = row.get("engines_requested") or []
    if isinstance(engines_requested, str):
        try:
            engines_requested = json.loads(engines_requested)
        except (ValueError, TypeError):
            engines_requested = []

    engines_completed = row.get("engines_completed") or []
    if isinstance(engines_completed, str):
        try:
            engines_completed = json.loads(engines_completed)
        except (ValueError, TypeError):
            engines_completed = []

    return {
        "scan_run_id":        str(row.get("scan_run_id", "")),
        "account_id":         row.get("account_id"),
        "status":             status,
        "engines_requested":  engines_requested,
        "engines_completed":  engines_completed,
        "created_at":         created_at,
        "updated_at":         updated_at,
        "duration_seconds":   _compute_duration(created_at, updated_at, status),
    }


@router.get("/scan_history")
async def view_scan_history(
    request: Request,
    account_id: Optional[str] = Query(None, description="Filter by cloud account UUID"),
    page: int = Query(1, ge=1, description="Page number (1-based)"),
    page_size: int = Query(20, ge=1, le=100, description="Results per page"),
    _: Any = Depends(require_permission("scans:read")),
) -> Dict[str, Any]:
    """Return paginated scan run history for the caller's tenant (D-6 AC1, AC2).

    Tenant isolation is enforced by the onboarding engine — the BFF forwards
    the X-Auth-Context header verbatim and never injects a tenant_id override.
    No fallback data is returned if the engine returns an empty list (AC5).

    Args:
        request:    FastAPI Request (supplies X-Auth-Context forwarding).
        account_id: Optional cloud account UUID to filter results.
        page:       1-based page number.
        page_size:  Items per page (max 100).

    Returns:
        Dict with ``scans`` list (AC2 shape), ``total``, ``page``, ``page_size``.
    """
    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(
        request.state, "auth_header", None
    )
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None

    params: Dict[str, str] = {"page": str(page), "page_size": str(page_size)}
    if account_id:
        params["account_id"] = account_id

    results = await fetch_many(
        [("onboarding", "/api/v1/scans/history", params)],
        auth_headers=fwd_headers,
    )
    raw = results[0] or {}

    # AC5: if engine returns empty, return empty — no fallback data.
    scans_raw = raw.get("scans", []) if isinstance(raw, dict) else []
    if not isinstance(scans_raw, list):
        scans_raw = []

    return {
        "scans":     [_shape_scan_row(r) for r in scans_raw if isinstance(r, dict)],
        "total":     raw.get("total", len(scans_raw)) if isinstance(raw, dict) else 0,
        "page":      page,
        "page_size": page_size,
    }


@router.get("/scan_detail")
async def view_scan_detail(
    request: Request,
    scan_run_id: str = Query(..., description="scan_run_id UUID"),
    _: Any = Depends(require_permission("scans:read")),
) -> Dict[str, Any]:
    """Return single scan run detail with per-engine status breakdown (D-6 AC3).

    The onboarding engine enforces tenant isolation on the scan-run lookup.
    The BFF adds a ``per_engine`` breakdown from ``engine_statuses`` JSONB.

    Args:
        request:     FastAPI Request (supplies X-Auth-Context forwarding).
        scan_run_id: UUID of the scan run to retrieve.

    Returns:
        Detailed scan run dict including ``per_engine`` status map.

    Raises:
        HTTPException 404: scan_run_id not found.
        HTTPException 502: engine call failed.
    """
    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(
        request.state, "auth_header", None
    )
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None

    results = await fetch_many(
        [("onboarding", f"/api/v1/scan-runs/{scan_run_id}", {})],
        auth_headers=fwd_headers,
    )
    raw = results[0]

    if not raw or not isinstance(raw, dict):
        raise HTTPException(status_code=404, detail=f"Scan run {scan_run_id} not found")

    shaped = _shape_scan_row(raw)

    # Per-engine breakdown from engine_statuses JSONB (already a dict, never json.loads).
    engine_statuses = raw.get("engine_statuses") or {}
    if isinstance(engine_statuses, str):
        try:
            engine_statuses = json.loads(engine_statuses)
        except (ValueError, TypeError):
            engine_statuses = {}

    shaped["per_engine"] = engine_statuses
    shaped["results_summary"] = raw.get("results_summary") or {}
    shaped["error_details"] = raw.get("error_details") or {}
    shaped["scan_type"] = raw.get("scan_type")
    shaped["trigger_type"] = raw.get("trigger_type")
    shaped["provider"] = raw.get("provider")

    return shaped


# ── D-9: Agent status view ─────────────────────────────────────────────────────


@router.get("/agent_status")
async def view_agent_status(
    request: Request,
    account_id: str = Query(..., description="Cloud account UUID to poll"),
    _: Any = Depends(require_permission("cloud_accounts:read")),
) -> Dict[str, Any]:
    """Return the current agent connection status for the given account (D9 AC6).

    Proxies ``GET /api/v1/cloud-accounts/{account_id}/agent-status`` on the
    onboarding engine and forwards the caller's X-Auth-Context for tenant
    isolation enforcement by the engine.

    The UI polls this endpoint every 5 seconds until ``status == "connected"``
    or the 5-minute timeout is reached.

    Args:
        request:    FastAPI Request (supplies X-Auth-Context forwarding).
        account_id: UUID of the cloud account whose agent status is requested.

    Returns:
        Dict with ``status`` (``"pending"`` | ``"connected"``) and
        ``last_heartbeat`` (ISO-8601 string or None).
    """
    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(
        request.state, "auth_header", None
    )
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None

    results = await fetch_many(
        [("onboarding", f"/api/v1/cloud-accounts/{account_id}/agent-status", {})],
        auth_headers=fwd_headers,
    )
    raw = results[0]

    # 404 from engine → treat as still-pending (agent not yet registered).
    if raw is None or not isinstance(raw, dict):
        return {"status": "pending", "last_heartbeat": None}

    return {
        "status": raw.get("status", "pending"),
        "last_heartbeat": raw.get("last_heartbeat"),
    }


class ScanRerunRequest(BaseModel):
    """Request body for the scan re-run BFF action."""

    scan_run_id: str = Field(..., description="UUID of the original scan run to re-run")


@router.post("/scan_rerun", status_code=202)
async def action_scan_rerun(
    request: Request,
    body: ScanRerunRequest,
    _: Any = Depends(require_permission("scans:create")),
) -> Dict[str, Any]:
    """Re-run a previous scan identified by ``scan_run_id`` (D-6 AC4).

    Security contract:
    - ``account_id`` is resolved server-side from the original scan record.
      It is NEVER accepted from the caller's request body.
    - The X-Auth-Context header is forwarded verbatim so the onboarding engine
      enforces tenant isolation on both the lookup and the new scan trigger.

    Args:
        request: FastAPI Request (supplies X-Auth-Context forwarding).
        body:    Request body containing the ``scan_run_id`` to re-run.

    Returns:
        202 Accepted with the new ``scan_run_id`` and ``original_run_id``.

    Raises:
        HTTPException 404: Original scan run not found.
        HTTPException 502: Onboarding engine re-run call failed.
    """
    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(
        request.state, "auth_header", None
    )
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None

    # Step 1: Verify the original scan run exists and retrieve its account_id
    # (never trust account_id from caller body — only from the engine DB lookup).
    detail_results = await fetch_many(
        [("onboarding", f"/api/v1/scan-runs/{body.scan_run_id}", {})],
        auth_headers=fwd_headers,
    )
    original = detail_results[0]
    if not original or not isinstance(original, dict):
        raise HTTPException(
            status_code=404,
            detail=f"Scan run {body.scan_run_id} not found",
        )

    # Step 2: Call the onboarding engine's re-run endpoint with the resolved scan_run_id.
    # The engine creates a new scan_orchestration row and submits the Argo pipeline.
    rerun_url = f"{_ONBOARDING_URL}/api/v1/scan-runs/{body.scan_run_id}/re-run"
    headers: Dict[str, str] = {"Content-Type": "application/json"}
    if fwd_headers:
        headers.update(fwd_headers)

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(rerun_url, headers=headers)
    except httpx.TimeoutException as exc:
        logger.error("scan_rerun: timeout calling onboarding engine: %s", exc)
        raise HTTPException(status_code=502, detail="Scan re-run request timed out")
    except httpx.RequestError as exc:
        logger.error("scan_rerun: network error calling onboarding engine: %s", exc)
        raise HTTPException(status_code=502, detail="Could not reach onboarding engine")

    if resp.status_code == 202:
        return resp.json()

    logger.error(
        "scan_rerun: onboarding engine returned %s for scan_run_id=%s: %s",
        resp.status_code,
        body.scan_run_id,
        resp.text[:200],
    )
    raise HTTPException(
        status_code=502,
        detail=f"Scan re-run failed (engine status {resp.status_code})",
    )
