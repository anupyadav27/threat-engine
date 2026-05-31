"""
Agent-facing heartbeat endpoint.

GET /api/v1/agent/heartbeat
    Called by installed agents to report liveness.
    Auth: Authorization: Bearer <raw_agent_token>
    Does NOT require the platform cookie / X-Auth-Context — agents call this
    directly using the token issued by POST /api/v1/cloud-accounts/{id}/agent-token.

Security design (BLOCK-04):
    - Raw token is NEVER stored in PostgreSQL.
    - On each heartbeat the raw token is SHA-256 hashed and looked up in
      agent_registrations.agent_token_hash.
    - last_heartbeat is updated, status promoted to 'connected' on first call.
    - run_now flag is read-and-cleared atomically so only one poll per trigger
      receives run_now=True.
"""
import hashlib
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Header, HTTPException

from engine_onboarding.database.cloud_accounts_operations import (
    get_agent_registration_by_token_hash,
    get_and_clear_run_now,
    set_agent_connected,
    update_agent_heartbeat,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/agent", tags=["agent-heartbeat"])


# ---------------------------------------------------------------------------
# AC5 / AC8: Bearer token auth — no platform cookie required.
# ---------------------------------------------------------------------------

def _extract_and_validate_bearer(authorization: Optional[str]) -> str:
    """Extract raw token from Authorization header and compute its SHA-256 hash.

    Args:
        authorization: Value of the Authorization header (expected: ``Bearer <token>``).

    Returns:
        SHA-256 hex digest of the raw token.

    Raises:
        HTTPException 401: If the header is missing or malformed.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Authorization: Bearer <agent_token> header is required",
        )
    raw_token = authorization[len("Bearer "):].strip()
    if not raw_token:
        raise HTTPException(status_code=401, detail="Bearer token must not be empty")
    return hashlib.sha256(raw_token.encode()).hexdigest()


# ---------------------------------------------------------------------------
# GET /api/v1/agent/heartbeat
# ---------------------------------------------------------------------------

@router.get("/heartbeat")
async def agent_heartbeat(
    authorization: Optional[str] = Header(None),
    x_agent_host: Optional[str] = Header(None, alias="X-Agent-Host"),
    x_agent_version: Optional[str] = Header(None, alias="X-Agent-Version"),
) -> dict:
    """Agent liveness ping — authenticates via Bearer raw_agent_token.

    The agent calls this endpoint periodically (e.g., every 60 seconds) to
    report liveness and to discover whether an ad-hoc scan has been requested
    from the platform UI.

    Authentication:
        ``Authorization: Bearer <raw_token>``
        The raw token is SHA-256 hashed and looked up in ``agent_registrations``
        — no platform cookie or X-Auth-Context is used or required.

    Args:
        authorization: Standard HTTP Authorization header containing the Bearer token.
        x_agent_host: Optional hostname reported by the agent binary.
        x_agent_version: Optional semver version reported by the agent binary.

    Returns:
        JSON object with:
            - ``status``: always ``"ok"`` on success.
            - ``run_now``: ``true`` if an ad-hoc scan trigger is pending.
            - ``updated_at``: ISO-8601 timestamp of this heartbeat.

    Raises:
        HTTPException 401: Missing, malformed, or unknown Bearer token.
        HTTPException 500: Unexpected database error.
    """
    # AC5: Authenticate by hashing the raw token and looking it up.
    token_hash = _extract_and_validate_bearer(authorization)

    registration = get_agent_registration_by_token_hash(token_hash)
    if registration is None:
        logger.warning("Heartbeat received with unknown token hash (prefix: %s...)", token_hash[:8])
        raise HTTPException(status_code=401, detail="Unknown agent token")

    try:
        # AC6: Update last_heartbeat and promote status to 'connected' on first call.
        update_agent_heartbeat(
            token_hash=token_hash,
            host=x_agent_host,
            version=x_agent_version,
        )
        if registration.status == "pending":
            set_agent_connected(token_hash)

        # AC7: Read and atomically clear run_now flag.
        run_now = get_and_clear_run_now(token_hash)
    except Exception as exc:
        logger.error(
            "Heartbeat DB update failed for registration %s: %s",
            registration.registration_id, exc,
        )
        raise HTTPException(status_code=500, detail="Heartbeat update failed")

    logger.debug(
        "Heartbeat ok: agent_id=%s registration=%s account=%s run_now=%s",
        registration.agent_id,
        registration.registration_id,
        registration.account_id,
        run_now,
    )

    return {
        "status": "ok",
        "agent_id": registration.agent_id,
        "run_now": run_now,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# GET /api/v1/agent/download/{platform}
# ---------------------------------------------------------------------------

@router.get("/download/{platform}")
async def download_agent(platform: str):
    """Redirect to S3-hosted agent script for the target platform.

    Agents are distributed from S3 (``onam-security-agents-588989875114``).
    This endpoint issues a 302 redirect to the public S3 URL so:
    - The engine never serves large files
    - S3 versioning handles rollbacks
    - ``latest/`` always points to the current stable release

    Supported platforms: ``linux``, ``macos``, ``windows``

    No authentication required — scripts contain no secrets; token/agent-id
    are passed as CLI flags by the operator at install time.
    """
    import os
    from fastapi.responses import RedirectResponse

    platform = platform.lower()
    if platform not in ("linux", "macos", "windows"):
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported platform '{platform}'. Use: linux, macos, windows",
        )

    s3_base = os.environ.get(
        "AGENT_S3_BASE_URL",
        "https://onam-security-agents-588989875114.s3.ap-south-1.amazonaws.com/agents/latest",
    )
    s3_url = f"{s3_base}/{platform}/onam-agent.py"
    return RedirectResponse(url=s3_url, status_code=302)
