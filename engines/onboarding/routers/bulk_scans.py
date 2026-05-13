"""
Bulk scan endpoint — POST /api/v1/scans/run-all

Triggers immediate on-demand scans for all eligible cloud accounts in a tenant.
Requires scans:create permission AND org_admin or platform_admin role.

Story: onboarding-C9 (gap S-05)
"""
import logging
import uuid
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

try:
    from engine_auth.fastapi.dependencies import require_permission, get_auth_context
    from engine_auth.core.models import AuthContext
    _AUTH_AVAILABLE = True
except ImportError:
    _AUTH_AVAILABLE = False
    AuthContext = Any

    def require_permission(perm: str):  # type: ignore[misc]
        """No-op stub when engine_auth is not installed."""
        async def _noop() -> None:
            return None
        return _noop

    async def get_auth_context() -> None:  # type: ignore[misc]
        return None

from engine_onboarding.database.cloud_accounts_operations import get_active_accounts_for_tenant
from engine_onboarding.database.scan_run_operations import create_scan_run

try:
    from engine_onboarding.scheduler.argo_client import ArgoClient
    _ARGO_AVAILABLE = True
except ImportError:
    _ARGO_AVAILABLE = False
    ArgoClient = None  # type: ignore[assignment, misc]

try:
    from engine_common.logger import setup_logger
    logger = setup_logger(__name__, engine_name="onboarding")
except Exception:
    logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/scans", tags=["bulk-scans"])

_ALL_ENGINES = ["discovery", "check", "inventory", "threat", "compliance", "iam", "datasec"]


# ── Request / Response models ─────────────────────────────────────────────────

class RunAllRequest(BaseModel):
    """Request body for POST /api/v1/scans/run-all.

    tenant_id is validated against auth.tenant_id for org_admin.
    platform_admin may pass any tenant_id to target a different tenant.
    """

    tenant_id: str

    class Config:
        extra = "ignore"


class TriggeredAccount(BaseModel):
    account_id: str
    scan_run_id: str


class SkippedAccount(BaseModel):
    account_id: str
    reason: str


class RunAllResponse(BaseModel):
    triggered: List[TriggeredAccount]
    skipped: List[SkippedAccount]


# ── Endpoint ──────────────────────────────────────────────────────────────────

@router.post("/run-all", status_code=202, response_model=RunAllResponse)
async def run_all_scans(
    body: RunAllRequest,
    auth: Any = Depends(get_auth_context),
    _: Any = Depends(require_permission("scans:create")),
) -> RunAllResponse:
    """Trigger immediate scans for all eligible accounts in the tenant.

    Eligibility: credential_validation_status = 'pass' AND account_status != 'INACTIVE'.
    Each scan submission is independent — one failure does not abort the rest.
    Failed submissions appear in the ``skipped`` list with reason 'submission_error'.

    Args:
        body: RunAllRequest containing tenant_id (validated against auth context).
        auth: AuthContext injected by gateway middleware.

    Returns:
        HTTP 202 with triggered and skipped account lists.

    Raises:
        HTTPException 403: Caller is not org_admin or platform_admin.
        HTTPException 403: org_admin attempts to scan a different tenant.
    """
    # AC2: role gate — only org_admin and platform_admin may bulk-scan.
    caller_role: Optional[str] = None
    if auth is not None:
        caller_role = getattr(auth, "role", None)

    if caller_role not in ("org_admin", "platform_admin"):
        raise HTTPException(
            status_code=403,
            detail="Only org_admin or platform_admin can trigger bulk scans",
        )

    # AC3: derive tenant_id from auth; org_admin cannot cross tenant boundary.
    auth_tenant_id: Optional[str] = None
    if auth is not None:
        auth_tenant_id = getattr(auth, "tenant_id", None) or getattr(auth, "engine_tenant_id", None)

    if caller_role == "org_admin":
        if auth_tenant_id and body.tenant_id != auth_tenant_id:
            raise HTTPException(
                status_code=403,
                detail="org_admin can only trigger scans for their own tenant",
            )
        effective_tenant_id = auth_tenant_id or body.tenant_id
    else:
        # platform_admin: honour body.tenant_id to allow cross-tenant bulk scans.
        effective_tenant_id = body.tenant_id

    if not effective_tenant_id:
        raise HTTPException(status_code=400, detail="tenant_id is required")

    # AC4: fetch all non-deleted accounts for the tenant.
    try:
        accounts = get_active_accounts_for_tenant(effective_tenant_id)
    except Exception as exc:
        logger.error("run-all: DB error fetching accounts for tenant %s: %s", effective_tenant_id, exc)
        raise HTTPException(status_code=500, detail="Failed to retrieve accounts") from exc

    argo = ArgoClient() if (_ARGO_AVAILABLE and ArgoClient is not None) else None

    triggered: List[TriggeredAccount] = []
    skipped: List[SkippedAccount] = []

    for account in accounts:
        account_id = str(account["account_id"])

        # AC4 / AC6: skip INACTIVE or non-passing credentials.
        cred_status = account.get("credential_validation_status") or ""
        acct_status = account.get("account_status") or ""

        if acct_status.upper() == "INACTIVE":
            skipped.append(SkippedAccount(account_id=account_id, reason="INACTIVE credential"))
            continue

        if cred_status.lower() != "pass":
            skipped.append(
                SkippedAccount(
                    account_id=account_id,
                    reason=f"credential_validation_status={cred_status or 'unknown'}",
                )
            )
            continue

        # AC5 / AC9: create scan_orchestration row + submit Argo pipeline independently.
        scan_run_id = str(uuid.uuid4())

        try:
            create_scan_run(
                {
                    "scan_run_id": scan_run_id,
                    "customer_id": account.get("customer_id", ""),
                    "tenant_id": effective_tenant_id,
                    "account_id": account_id,
                    "provider": account.get("provider", "aws"),
                    "credential_type": account.get("credential_type", ""),
                    "credential_ref": account.get("credential_ref", ""),
                    "scan_type": "full",
                    "trigger_type": "manual",
                    "engines_requested": _ALL_ENGINES,
                }
            )
        except Exception as exc:
            logger.error(
                "run-all: failed to create scan_orchestration for account %s: %s",
                account_id,
                exc,
            )
            skipped.append(SkippedAccount(account_id=account_id, reason="submission_error"))
            continue

        # Fire Argo pipeline best-effort — failure does not abort the loop.
        try:
            if argo is not None:
                argo.submit_pipeline(
                    scan_run_id=scan_run_id,
                    tenant_id=effective_tenant_id,
                    account_id=account_id,
                    provider=account.get("provider", "aws"),
                    credential_type=account.get("credential_type", ""),
                    credential_ref=account.get("credential_ref", ""),
                )
        except Exception as exc:
            logger.warning(
                "run-all: Argo submit failed for %s (account %s): %s",
                scan_run_id,
                account_id,
                exc,
            )
            # scan_orchestration row was created; log the warning but still count as triggered.

        triggered.append(TriggeredAccount(account_id=account_id, scan_run_id=scan_run_id))

    logger.info(
        "run-all: tenant=%s triggered=%d skipped=%d",
        effective_tenant_id,
        len(triggered),
        len(skipped),
    )

    # AC7 / AC8: always 202; empty triggered list is valid.
    return RunAllResponse(triggered=triggered, skipped=skipped)
