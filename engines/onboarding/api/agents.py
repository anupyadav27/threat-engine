"""
Agent bootstrap and lifecycle endpoints.

POST /api/v1/agents/bootstrap          — PKCE exchange: code_verifier → session JWT
POST /api/v1/agents/{id}/heartbeat     — agent liveness ping (Bearer JWT auth)
GET  /api/v1/agents/{id}/status        — wizard polling endpoint (X-Auth-Context)

Bootstrap is excluded from AuthMiddleware (PUBLIC_PATHS in shared/auth/fastapi/middleware.py).
Heartbeat uses agent-issued JWT (Bearer), not the user session cookie.
Status uses standard require_permission("cloud_accounts:read").
"""
import hashlib
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field

try:
    import jwt as _jwt
    _JWT_AVAILABLE = True
except ImportError:
    _jwt = None  # type: ignore[assignment]
    _JWT_AVAILABLE = False

try:
    from engine_auth.fastapi.dependencies import require_permission
    _AUTH_AVAILABLE = True
except ImportError:
    _AUTH_AVAILABLE = False
    def require_permission(perm: str):  # type: ignore[misc]
        async def _noop():
            return None
        return _noop

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/agents", tags=["agents"])

_AGENT_JWT_SECRET = os.getenv("AGENT_JWT_SECRET", "")
_AGENT_SESSION_DAYS = 30


# ── Pydantic models ───────────────────────────────────────────────────────────

class AgentBootstrapRequest(BaseModel):
    registration_id: str = Field(..., description="UUID from agent_registrations")
    code_verifier:   str = Field(..., min_length=32, max_length=128,
                                 description="The verifier used to compute the code_challenge at issue time")
    agent_version:   Optional[str] = None
    agent_hostname:  Optional[str] = None
    agent_os:        Optional[str] = None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _issue_agent_jwt(registration_id: str, account_id: str, tenant_id: str) -> str:
    if not _JWT_AVAILABLE or not _AGENT_JWT_SECRET:
        raise RuntimeError("AGENT_JWT_SECRET not configured or PyJWT not installed")
    exp = datetime.now(timezone.utc) + timedelta(days=_AGENT_SESSION_DAYS)
    payload = {
        "sub":        registration_id,
        "account_id": account_id,
        "tenant_id":  tenant_id,
        "type":       "agent",
        "exp":        int(exp.timestamp()),
    }
    return _jwt.encode(payload, _AGENT_JWT_SECRET, algorithm="HS256")


def _verify_agent_jwt(token: str) -> dict:
    if not _JWT_AVAILABLE or not _AGENT_JWT_SECRET:
        raise HTTPException(status_code=503, detail="Agent JWT not configured")
    try:
        return _jwt.decode(token, _AGENT_JWT_SECRET, algorithms=["HS256"])
    except _jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Agent token expired")
    except _jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid agent token")


def _get_registration(registration_id: str) -> Optional[dict]:
    try:
        from engine_onboarding.database.connection import get_db_connection
        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT registration_id, account_id, tenant_id, customer_id,
                           token_hash, status, expires_at, activated_at, last_heartbeat_at
                    FROM agent_registrations
                    WHERE registration_id = %s
                    """,
                    (registration_id,),
                )
                row = cur.fetchone()
        finally:
            conn.close()
        if not row:
            return None
        cols = ["registration_id", "account_id", "tenant_id", "customer_id",
                "token_hash", "status", "expires_at", "activated_at", "last_heartbeat_at"]
        return dict(zip(cols, row))
    except Exception as exc:
        logger.error("Failed to fetch agent registration %s: %s", registration_id, exc)
        raise


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/bootstrap", status_code=200)
async def bootstrap(body: AgentBootstrapRequest):
    """Exchange code_verifier for a 30-day agent session JWT (PKCE pattern).

    This endpoint is excluded from AuthMiddleware — no X-Auth-Context required.
    """
    reg = _get_registration(body.registration_id)
    if not reg or reg["status"] not in ("pending", "issued"):
        raise HTTPException(status_code=404, detail="Registration not found or already activated")

    if reg["expires_at"] and reg["expires_at"] < datetime.now(timezone.utc):
        raise HTTPException(status_code=410, detail="Bootstrap token has expired. Request a new agent token.")

    # PKCE verification: SHA-256(code_verifier) must match stored token_hash
    computed = hashlib.sha256(body.code_verifier.encode()).hexdigest()
    if computed != reg["token_hash"]:
        raise HTTPException(status_code=403, detail="Invalid code verifier")

    now = datetime.now(timezone.utc)
    new_expires = now + timedelta(days=_AGENT_SESSION_DAYS)

    try:
        from engine_onboarding.database.connection import get_db_connection
        from engine_onboarding.database.cloud_accounts_operations import update_cloud_account
        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE agent_registrations
                    SET status = 'active',
                        activated_at = %s,
                        expires_at = %s,
                        agent_version = COALESCE(%s, agent_version),
                        agent_hostname = COALESCE(%s, agent_hostname),
                        agent_os = COALESCE(%s, agent_os)
                    WHERE registration_id = %s
                    """,
                    (now, new_expires,
                     body.agent_version, body.agent_hostname, body.agent_os,
                     body.registration_id),
                )
            conn.commit()
        finally:
            conn.close()

        update_cloud_account(reg["account_id"], {
            "account_status":               "active",
            "credential_validation_status": "valid",
            "account_onboarding_status":    "deployed",
            "credential_validated_at":      now,
        })
    except Exception as exc:
        logger.error("Bootstrap activation failed for %s: %s", body.registration_id, exc)
        raise HTTPException(status_code=500, detail="Bootstrap activation failed")

    session_jwt = _issue_agent_jwt(body.registration_id, reg["account_id"], reg["tenant_id"])

    return {
        "session_jwt": session_jwt,
        "expires_in":  _AGENT_SESSION_DAYS * 86400,
        "account_id":  reg["account_id"],
        "tenant_id":   reg["tenant_id"],
    }


@router.post("/{registration_id}/heartbeat", status_code=200)
async def heartbeat(
    registration_id: str,
    authorization: Optional[str] = Header(None),
):
    """Agent liveness ping — requires Bearer agent JWT."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")

    token = authorization.split(" ", 1)[1]
    claims = _verify_agent_jwt(token)

    if claims.get("sub") != registration_id:
        raise HTTPException(status_code=403, detail="Token does not match registration_id")
    if claims.get("type") != "agent":
        raise HTTPException(status_code=403, detail="Not an agent token")

    try:
        from engine_onboarding.database.connection import get_db_connection
        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE agent_registrations
                    SET last_heartbeat_at = %s
                    WHERE registration_id = %s AND status = 'active'
                    RETURNING registration_id
                    """,
                    (datetime.now(timezone.utc), registration_id),
                )
                updated = cur.fetchone()
            conn.commit()
        finally:
            conn.close()
        if not updated:
            raise HTTPException(status_code=404, detail="Active registration not found")
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Heartbeat failed for %s: %s", registration_id, exc)
        raise HTTPException(status_code=500, detail="Heartbeat failed")

    return {"status": "ok", "next_heartbeat_in": 300}


@router.get("/{registration_id}/status", status_code=200)
async def get_status(
    registration_id: str,
    _: Any = Depends(require_permission("cloud_accounts:read")),
):
    """Wizard polling endpoint — returns agent registration status."""
    reg = _get_registration(registration_id)
    if not reg:
        raise HTTPException(status_code=404, detail="Registration not found")

    return {
        "registration_id":  reg["registration_id"],
        "status":           reg["status"],
        "account_id":       reg["account_id"],
        "activated_at":     reg["activated_at"].isoformat() if reg.get("activated_at") else None,
        "last_heartbeat_at": reg["last_heartbeat_at"].isoformat() if reg.get("last_heartbeat_at") else None,
        "expires_at":       reg["expires_at"].isoformat() if reg.get("expires_at") else None,
    }
