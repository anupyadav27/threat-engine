"""BFF view: cloud accounts list (JNY-17.1).

Endpoint
--------
GET /api/v1/views/onboarding/cloud_accounts
    — read-only list of cloud accounts visible to the caller's tenant.

Migrates the direct `/onboarding/api/v1/cloud-accounts` bypass to the
BFF-only contract (ADR §3.1.c). Mutating operations (create/update/credential
validation/agent token/CloudFormation template) are NOT migrated by this
story — they remain on the engine's REST API and will be addressed in a
follow-up sprint that introduces write-side BFF semantics.

Security
--------
- tenant_id resolved server-side from X-Auth-Context (never accepted from query)
- per-permission gate: ``cloud_accounts:read``
- forwards X-Auth-Context verbatim to engine for downstream RBAC enforcement
"""

from __future__ import annotations

import logging
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

try:
    from engine_auth.fastapi.dependencies import require_permission
except ImportError:  # pragma: no cover
    def require_permission(_perm: str):  # type: ignore[no-redef]
        def _denied():
            raise HTTPException(status_code=401, detail="auth module unavailable")
        return _denied

from ._auth import resolve_tenant_id
from ._shared import fetch_many, safe_get


logger = logging.getLogger("api-gateway.bff.onboarding_cloud_accounts")

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


# ── Pydantic schemas (camelCase) ────────────────────────────────────────────

class CloudAccountItem(BaseModel):
    """Single cloud account row for list rendering."""

    accountId: str = Field(..., description="Account UUID (engine PK)")
    customerId: Optional[str] = None
    tenantId: Optional[str] = None
    provider: Optional[str] = Field(None, description="aws|azure|gcp|oci|alicloud|ibm|k8s")
    accountIdentifier: Optional[str] = Field(
        None, description="CSP-native identifier (e.g. AWS 12-digit)"
    )
    accountName: Optional[str] = None
    accountCategory: Optional[str] = Field(
        None, description="cloud|onprem|saas|k8s — was account_type"
    )
    accountStatus: Optional[str] = None
    onboardingStatus: Optional[str] = None
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
    return {
        "accountId":                  row.get("account_id") or row.get("id") or "",
        "customerId":                 row.get("customer_id"),
        "tenantId":                   row.get("tenant_id"),
        "provider":                   row.get("provider"),
        "accountIdentifier":          row.get("account_identifier"),
        "accountName":                row.get("account_name"),
        "accountCategory":            row.get("account_type") or row.get("account_category"),
        "accountStatus":              row.get("account_status"),
        "onboardingStatus":           row.get("account_onboarding_status")
                                       or row.get("onboarding_status"),
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
