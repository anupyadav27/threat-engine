"""
Ad-hoc scan endpoint — POST /api/v1/scans/run-now (onboarding-C7).

Triggers an immediate scan for a cloud account without requiring a
pre-existing schedule.  Handles both regular CSP accounts (via Argo) and
vulnerability agent accounts (via run_now_requested flag poll).
"""
import uuid
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

try:
    from engine_auth.fastapi.dependencies import require_permission, get_auth_context
    from engine_auth.core.models import AuthContext
    _AUTH_AVAILABLE = True
except ImportError:
    _AUTH_AVAILABLE = False
    AuthContext = Any

    def require_permission(perm: str):  # type: ignore[misc]
        async def _noop() -> None:
            return None
        return _noop

    async def get_auth_context() -> None:  # type: ignore[misc]
        return None

try:
    from engine_common.logger import setup_logger
    logger = setup_logger(__name__, engine_name="onboarding")
except ImportError:
    import logging
    logger = logging.getLogger(__name__)

from engine_onboarding.database.cloud_accounts_operations import get_cloud_account, set_agent_run_now
from engine_onboarding.database.scan_run_operations import create_scan_run

router = APIRouter(prefix="/api/v1", tags=["scans"])


class RunNowRequest(BaseModel):
    """Request body for the ad-hoc scan trigger endpoint."""

    account_id: str = Field(..., description="UUID of the cloud account to scan")


class RunNowResponse(BaseModel):
    """Response returned when a scan is successfully queued."""

    scan_run_id: str = Field(..., description="UUID of the queued scan run")
    status: str = Field(..., description="Always 'queued'")


def _get_tenant_id(auth: Any) -> Optional[str]:
    """Extract tenant_id from AuthContext, checking both attribute names.

    Args:
        auth: AuthContext object (may be None in test/dev without auth).

    Returns:
        Tenant ID string or None.
    """
    if auth is None:
        return None
    return getattr(auth, "tenant_id", None) or getattr(auth, "engine_tenant_id", None)


@router.post("/scans/run-now", status_code=202, response_model=RunNowResponse)
async def run_scan_now(
    body: RunNowRequest,
    auth: Any = Depends(get_auth_context),
    _: Any = Depends(require_permission("scans:create")),
) -> RunNowResponse:
    """Trigger an immediate ad-hoc scan for a cloud account.

    Creates a ``scan_orchestration`` row and submits the Argo pipeline (for
    CSP accounts) or sets the ``run_now_requested`` flag on the
    ``agent_registrations`` row (for vulnerability-agent accounts).

    The ``tenant_id`` is always taken from the authenticated ``AuthContext``
    and is never accepted from the request body.

    Args:
        body: Request payload containing the ``account_id`` to scan.
        auth: Resolved AuthContext from the gateway X-Auth-Context header.
        _: RBAC guard — ``scans:create`` permission required.

    Returns:
        202 Accepted with ``scan_run_id`` and ``status="queued"``.

    Raises:
        HTTPException 404: Account not found or belongs to a different tenant.
        HTTPException 409: Account credentials are not valid or account is inactive.
        HTTPException 500: scan_orchestration record could not be persisted.
    """
    tenant_id = _get_tenant_id(auth)

    # AC4 — Validate account existence and tenant ownership.
    account = get_cloud_account(body.account_id)
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")

    if tenant_id and account.get("tenant_id") != tenant_id:
        # Treat cross-tenant lookup as 404 to avoid leaking account existence.
        raise HTTPException(status_code=404, detail="Account not found")

    # AC5 — Reject accounts that are not ready to scan.
    validation_status = account.get("credential_validation_status", "")
    account_status = account.get("account_status", "")
    if validation_status != "pass" or account_status == "INACTIVE":
        raise HTTPException(
            status_code=409,
            detail="Account credentials are not valid or account is inactive",
        )

    scan_run_id = str(uuid.uuid4())

    # AC9 — Vulnerability agent accounts: set poll flag instead of Argo.
    account_type = account.get("account_type", "cloud_csp")
    if account_type == "vulnerability":
        # AC6 — Still create a scan_orchestration row for tracking.
        try:
            create_scan_run({
                "scan_run_id":       scan_run_id,
                "customer_id":       account.get("customer_id", ""),
                "tenant_id":         tenant_id or account.get("tenant_id", ""),
                "account_id":        body.account_id,
                "provider":          account.get("provider", ""),
                "credential_type":   account.get("credential_type", ""),
                "credential_ref":    account.get("credential_ref", ""),
                "scan_type":         "full",
                "trigger_type":      "manual",
                "engines_requested": ["vulnerability"],
                "scan_name":         f"Ad-hoc scan — {account.get('account_name', body.account_id)}",
            })
        except Exception as exc:
            logger.error(
                "Failed to create scan_orchestration for agent run-now account=%s: %s",
                body.account_id,
                exc,
            )
            raise HTTPException(status_code=500, detail="Failed to create scan record")

        set_agent_run_now(body.account_id)
        logger.info(
            "Ad-hoc scan (agent): run_now_requested set account=%s scan_run_id=%s",
            body.account_id,
            scan_run_id,
        )
        return RunNowResponse(scan_run_id=scan_run_id, status="queued")

    # AC6 — Create scan_orchestration row for CSP accounts.
    try:
        create_scan_run({
            "scan_run_id":       scan_run_id,
            "customer_id":       account.get("customer_id", ""),
            "tenant_id":         tenant_id or account.get("tenant_id", ""),
            "account_id":        body.account_id,
            "provider":          account.get("provider", ""),
            "credential_type":   account.get("credential_type", ""),
            "credential_ref":    account.get("credential_ref", ""),
            "scan_type":         "full",
            "trigger_type":      "manual",
            "engines_requested": [
                "discovery", "check", "inventory", "threat",
                "compliance", "iam", "datasec", "network-security", "risk",
            ],
            "scan_name": f"Ad-hoc scan — {account.get('account_name', body.account_id)}",
        })
    except Exception as exc:
        logger.error(
            "Failed to create scan_orchestration for run-now account=%s: %s",
            body.account_id,
            exc,
        )
        raise HTTPException(status_code=500, detail="Failed to create scan record")

    # AC7 — Pull exclude_regions from the account's active schedule (joined by get_cloud_account).
    exclude_regions: Optional[list] = None
    raw_exclude = account.get("exclude_regions")
    if isinstance(raw_exclude, list) and raw_exclude:
        exclude_regions = raw_exclude

    # AC7 — Submit Argo pipeline (best-effort; scan_orchestration row already committed).
    try:
        from engine_onboarding.scheduler.argo_client import trigger_scan
        await trigger_scan(
            scan_run_id=scan_run_id,
            tenant_id=tenant_id or account.get("tenant_id", ""),
            account_id=body.account_id,
            provider=account.get("provider", "aws"),
            credential_type=account.get("credential_type", ""),
            credential_ref=account.get("credential_ref", ""),
            exclude_regions=exclude_regions,
        )
    except Exception as exc:
        logger.warning(
            "Argo submission failed for run-now scan_run_id=%s account=%s: %s",
            scan_run_id,
            body.account_id,
            exc,
        )
        # Non-fatal — scan_orchestration row exists for retry/monitoring.

    logger.info(
        "Ad-hoc scan queued: scan_run_id=%s account=%s tenant=%s",
        scan_run_id,
        body.account_id,
        tenant_id,
    )
    return RunNowResponse(scan_run_id=scan_run_id, status="queued")
