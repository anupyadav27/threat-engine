"""
Internal API endpoints for service-to-service calls within the cluster.

These routes are NOT exposed through the API gateway and are protected by
the X-Internal-Secret shared header. They are intended for Django platform
to push tenant data to the onboarding engine after provisioning.
"""
import os
import sys

from typing import Optional

from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel, Field

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from engine_common.logger import setup_logger

from engine_onboarding.database.tenant_operations import create_tenant, get_tenant
from engine_onboarding.database.cloud_accounts_operations import (
    get_agent_registration_by_token_hash,
    consume_registration_token,
)

logger = setup_logger(__name__, engine_name="onboarding")

router = APIRouter(prefix="/internal", tags=["internal"])

_X_INTERNAL_SECRET = os.getenv("X_INTERNAL_SECRET", "")


def _verify_secret(secret: str) -> None:
    """Reject requests with a missing or mismatched X-Internal-Secret header.

    Args:
        secret: Value from the X-Internal-Secret request header.

    Raises:
        HTTPException: 403 when the secret is missing or does not match.
    """
    if not _X_INTERNAL_SECRET:
        logger.error("X_INTERNAL_SECRET env var is not set — rejecting all internal calls")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Internal endpoint misconfigured",
        )
    if secret != _X_INTERNAL_SECRET:
        logger.warning("internal: X-Internal-Secret mismatch — request rejected")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden",
        )


class TenantSyncRequest(BaseModel):
    """Payload for the tenant sync endpoint."""

    tenant_id: str = Field(..., description="UUID of the tenant from Django platform DB")
    customer_id: str = Field(..., description="Customer-level identifier (cust_<12hex>)")
    tenant_name: Optional[str] = Field(None, description="Django-canonical display name for this tenant")


@router.post(
    "/tenants/sync",
    status_code=200,
    summary="Sync tenant from Django platform to onboarding engine (internal)",
)
async def sync_tenant(
    body: TenantSyncRequest,
    x_internal_secret: str = Header(
        default="",
        alias="X-Internal-Secret",
        description="Shared secret for service-to-service calls",
    ),
) -> dict:
    """Upsert a tenant row in the onboarding DB.

    Called by the Django Celery task ``sync_tenant_to_onboarding`` after a new
    user completes registration. Idempotent: if the tenant already exists (409
    from ``create_tenant``), returns 200 with ``already_exists=True``.

    Args:
        body: TenantSyncRequest containing tenant_id and customer_id.
        x_internal_secret: Header value validated against X_INTERNAL_SECRET env var.

    Returns:
        dict with ``tenant_id``, ``customer_id``, and ``already_exists`` flag.

    Raises:
        HTTPException 403: When the X-Internal-Secret header does not match.
        HTTPException 500: When the DB upsert fails for an unexpected reason.
    """
    _verify_secret(x_internal_secret)

    tenant_id = body.tenant_id
    customer_id = body.customer_id
    # Use the Django-canonical name when provided; fall back to a generic slug.
    tenant_name = body.tenant_name or f"org-{customer_id[:8]}"

    # Check if tenant already exists — update name if it changed, then return.
    existing = get_tenant(tenant_id)
    if existing:
        if body.tenant_name and existing.get("tenant_name") != body.tenant_name:
            from engine_onboarding.database.tenant_operations import update_tenant
            update_tenant(tenant_id, {"tenant_name": body.tenant_name})
            logger.info("internal.tenant_name_updated tenant_id=%s name=%r", tenant_id, body.tenant_name)
        else:
            logger.info("internal.tenant_sync_idempotent tenant_id=%s", tenant_id)
        return {"tenant_id": tenant_id, "customer_id": customer_id, "already_exists": True}

    try:
        create_tenant(
            {
                "tenant_id": tenant_id,
                "customer_id": customer_id,
                "tenant_name": tenant_name,
                "tenant_description": "Auto-provisioned via Django platform",
            }
        )
        logger.info("internal.tenant_sync_ok tenant_id=%s customer_id=%s", tenant_id, customer_id)
        return {"tenant_id": tenant_id, "customer_id": customer_id, "already_exists": False}

    except ValueError:
        # create_tenant raises ValueError on duplicate tenant_id — treat as idempotent
        logger.info("internal.tenant_sync_conflict tenant_id=%s", tenant_id)
        return {"tenant_id": tenant_id, "customer_id": customer_id, "already_exists": True}

    except Exception as exc:
        logger.error("internal.tenant_sync_error tenant_id=%s: %s", tenant_id, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to sync tenant",
        )


class AgentValidateRequest(BaseModel):
    """Payload for the agent token validation endpoint."""

    token_hash: str = Field(..., description="SHA-256 hex digest of the raw agent token")
    agent_id: str = Field(..., description="agent_id value from the X-Agent-Id header")


@router.post(
    "/agent/validate",
    status_code=200,
    summary="Validate agent token hash + agent_id + status (internal)",
)
async def validate_agent(
    body: AgentValidateRequest,
    x_internal_secret: str = Header(
        default="",
        alias="X-Internal-Secret",
        description="Shared secret for service-to-service calls",
    ),
) -> dict:
    """Validate that a raw agent Bearer token matches the registration and is connected.

    Called by the vulnerability engine before accepting scan data from any agent.
    Checks: token_hash matches a row, agent_id matches, status is 'connected' or 'active'.

    Returns:
        dict with ``valid``, ``account_id``, ``tenant_id``, ``status``, ``agent_id``.

    Raises:
        HTTPException 401: When token, agent_id, or status does not pass validation.
        HTTPException 403: When the X-Internal-Secret header does not match.
    """
    _verify_secret(x_internal_secret)

    reg = get_agent_registration_by_token_hash(body.token_hash)

    if reg is None:
        logger.warning("internal.agent_validate: token_hash not found")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid agent token")

    if reg.agent_id != body.agent_id:
        logger.warning(
            "internal.agent_validate: agent_id mismatch expected=%s got=%s",
            reg.agent_id,
            body.agent_id,
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid agent token")

    if reg.status not in ("connected", "active"):
        logger.warning(
            "internal.agent_validate: agent not active agent_id=%s status=%s",
            body.agent_id,
            reg.status,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Agent is not active",
        )

    logger.info(
        "internal.agent_validate: ok agent_id=%s account_id=%s tenant_id=%s",
        reg.agent_id,
        reg.account_id,
        reg.tenant_id,
    )
    return {
        "valid": True,
        "account_id": reg.account_id,
        "tenant_id": reg.tenant_id,
        "status": reg.status,
        "agent_id": reg.agent_id,
    }


class ConsumeTokenRequest(BaseModel):
    """Payload for the registration token consumption endpoint."""

    token_hash: str = Field(..., description="SHA-256 hex digest of the raw registration token")


@router.post(
    "/agents/validate-token",
    status_code=200,
    summary="Validate and consume a registration token (internal — called by vul engine at register time)",
)
async def validate_and_consume_token(
    body: ConsumeTokenRequest,
    x_internal_secret: str = Header(
        default="",
        alias="X-Internal-Secret",
        description="Shared secret for service-to-service calls",
    ),
) -> dict:
    """Validate a 30-min registration token and consume it (single-use).

    Called by the vulnerability engine's POST /api/v1/agents/register endpoint
    to exchange a registration token for agent identity (agent_id, account_id, tenant_id).

    The token is marked consumed (status='connected') on first successful call.
    A second call with the same token hash returns 409.
    An expired token returns 404.

    Args:
        body: ConsumeTokenRequest with token_hash.
        x_internal_secret: Shared secret header for service-to-service auth.

    Returns:
        dict with agent_id, account_id, tenant_id, expires_at.

    Raises:
        HTTPException 403: X-Internal-Secret mismatch.
        HTTPException 404: Token not found or expired.
        HTTPException 409: Token already consumed.
        HTTPException 500: Unexpected DB error.
    """
    _verify_secret(x_internal_secret)

    try:
        result = consume_registration_token(body.token_hash)
    except ValueError as exc:
        logger.warning("internal.validate_token: already consumed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Token already consumed. Please re-provision from portal.",
        )
    except Exception as exc:
        logger.error("internal.validate_token: DB error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token validation failed",
        )

    if result is None:
        logger.warning("internal.validate_token: token not found or expired")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Token not found or expired. Please re-download from portal.",
        )

    logger.info(
        "internal.validate_token: ok agent_id=%s account_id=%s",
        result["agent_id"],
        result["account_id"],
    )
    return result
