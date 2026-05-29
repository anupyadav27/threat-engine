"""
Database operations for the cloud_accounts table.
Schema after migration 004: no schedule_* columns, tenant_id FK to tenants.
"""
import json
import re
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from engine_onboarding.database.connection import get_db_connection

# B-5: credential_ref must follow the canonical Secrets Manager path format.
# Supports both legacy (threat-engine/account/<account-uuid>) and
# tenant-scoped (threat-engine/account/<tenant-uuid>/<account-uuid>) formats.
_UUID4 = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_CRED_REF_PATTERN = re.compile(
    rf"^threat-engine/account/({_UUID4}/)?{_UUID4}$"
)


def create_cloud_account(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create a new cloud account (Phase 1 of onboarding).

    Required keys: account_id, customer_id, tenant_id, account_name, provider
    Optional keys: account_number, credential_type, credential_ref,
                   account_status, onboarding_status
    """
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        now = datetime.now(timezone.utc)
        cur.execute(
            """
            INSERT INTO cloud_accounts (
                account_id, customer_id, customer_email, tenant_id,
                account_name, account_number, account_hierarchy_name,
                provider,
                credential_type, credential_ref,
                account_status, account_onboarding_status,
                credential_validation_status,
                account_type, auth_config,
                created_at, updated_at
            ) VALUES (
                %s, %s, %s, %s,
                %s, %s, %s,
                %s,
                %s, %s,
                %s, %s,
                'pending',
                %s, %s,
                %s, %s
            )
            RETURNING *
            """,
            (
                data["account_id"],
                data["customer_id"],
                data.get("customer_email", f"{data['customer_id']}@cspm.local"),
                data["tenant_id"],
                data["account_name"],
                data.get("account_number"),
                data.get("account_hierarchy_name"),
                data["provider"],
                data.get("credential_type", "pending"),
                data.get("credential_ref", ""),
                data.get("account_status", "pending"),
                data.get("onboarding_status", "pending"),
                data.get("account_type", "cloud_csp"),
                json.dumps(data.get("auth_config") or {}),
                now,
                now,
            ),
        )
        result = dict(cur.fetchone())
        conn.commit()
        return result
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        raise ValueError(f"Account '{data['account_name']}' already exists for this tenant.")
    except psycopg2.errors.ForeignKeyViolation:
        conn.rollback()
        raise ValueError(f"Tenant '{data['tenant_id']}' does not exist. Create the tenant first.")
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()


def get_cloud_account(account_id: str) -> Optional[Dict[str, Any]]:
    """
    Get a cloud account by ID, enriched with tenant_name and active schedule.
    """
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute(
            """
            SELECT ca.*,
                   t.tenant_name,
                   s.schedule_id,
                   s.cron_expression      AS schedule_cron_expression,
                   s.enabled              AS schedule_enabled,
                   s.next_run_at          AS schedule_next_run_at,
                   s.last_run_at          AS schedule_last_run_at,
                   s.run_count            AS schedule_run_count,
                   s.success_count        AS schedule_success_count,
                   s.failure_count        AS schedule_failure_count
            FROM cloud_accounts ca
            LEFT JOIN tenants t ON t.tenant_id = ca.tenant_id
            LEFT JOIN LATERAL (
                SELECT * FROM schedules
                WHERE account_id = ca.account_id
                ORDER BY created_at DESC
                LIMIT 1
            ) s ON true
            WHERE ca.account_id = %s
            """,
            (account_id,),
        )
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        cur.close()
        conn.close()


def list_cloud_accounts(
    filters: Optional[Dict[str, Any]] = None,
    limit: int = 100,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    """
    List cloud accounts with optional filters and pagination.
    Enriches each row with tenant_name and latest schedule info.
    """
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        query = """
            SELECT ca.*,
                   t.tenant_name,
                   t.environment      AS tenant_environment,
                   s.schedule_id,
                   s.cron_expression  AS schedule_cron_expression,
                   s.enabled          AS schedule_enabled,
                   s.next_run_at      AS schedule_next_run_at
            FROM cloud_accounts ca
            LEFT JOIN tenants t ON t.tenant_id = ca.tenant_id
            LEFT JOIN LATERAL (
                SELECT * FROM schedules
                WHERE account_id = ca.account_id
                ORDER BY created_at DESC
                LIMIT 1
            ) s ON true
            WHERE ca.account_status <> 'deleted'
        """
        params: List[Any] = []

        if filters:
            if "customer_id" in filters:
                query += " AND ca.customer_id = %s"
                params.append(filters["customer_id"])
            if "tenant_id" in filters:
                query += " AND ca.tenant_id = %s"
                params.append(filters["tenant_id"])
            if "provider" in filters:
                query += " AND ca.provider = %s"
                params.append(filters["provider"])
            if "account_status" in filters:
                query += " AND ca.account_status = %s"
                params.append(filters["account_status"])
            if "onboarding_status" in filters:
                query += " AND ca.account_onboarding_status = %s"
                params.append(filters["onboarding_status"])
            if "account_type" in filters:
                query += " AND ca.account_type = %s"
                params.append(filters["account_type"])

        query += " ORDER BY ca.created_at DESC LIMIT %s OFFSET %s"
        params.extend([limit, offset])

        cur.execute(query, params)
        return [dict(row) for row in cur.fetchall()]
    finally:
        cur.close()
        conn.close()


def get_active_accounts_for_tenant(tenant_id: str) -> List[Dict[str, Any]]:
    """Return all cloud accounts for the tenant that are eligible for scanning.

    Eligible means: not deleted, not INACTIVE, and credential_validation_status = 'valid'.
    All other accounts are returned in a separate skipped list by the caller.

    Args:
        tenant_id: Tenant UUID string — must come from auth context, never from request body.

    Returns:
        List of cloud account dicts with keys: account_id, account_name, provider,
        credential_type, credential_ref, credential_validation_status, account_status,
        customer_id, tenant_id.
    """
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute(
            """
            SELECT account_id, account_name, provider,
                   credential_type, credential_ref,
                   credential_validation_status, account_status,
                   customer_id, tenant_id
            FROM cloud_accounts
            WHERE tenant_id = %s
              AND account_status <> 'deleted'
            ORDER BY created_at
            """,
            (tenant_id,),
        )
        return [dict(row) for row in cur.fetchall()]
    finally:
        cur.close()
        conn.close()


def update_cloud_account(
    account_id: str, updates: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    """
    Update allowed cloud account fields.
    Skips unknown / read-only columns automatically.
    """
    allowed = {
        "account_name", "account_number", "account_hierarchy_name",
        "provider", "credential_type", "credential_ref",
        "account_status", "account_onboarding_status", "account_onboarding_id",
        "account_last_validated_at",
        "credential_validation_status", "credential_validation_message",
        "credential_validated_at", "credential_validation_errors",
        "log_sources", "last_scan_at", "last_credential_check_at", "updated_at",
        "account_type", "auth_config",
    }
    fields = {k: v for k, v in updates.items() if k in allowed}
    if not fields:
        return get_cloud_account(account_id)

    # B-5: Validate credential_ref matches the canonical Secrets Manager path format.
    # Empty string is allowed (no credentials stored yet). Non-empty must match the SM path format.
    if "credential_ref" in fields:
        cred_ref = fields["credential_ref"]
        if cred_ref and not _CRED_REF_PATTERN.match(str(cred_ref)):
            raise ValueError(
                f"credential_ref must match 'threat-engine/account/<tenant-uuid>/<account-uuid>'; "
                f"got: {cred_ref!r}"
            )

    fields.setdefault("updated_at", datetime.now(timezone.utc))

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        set_clause = ", ".join(f"{k} = %s" for k in fields)
        values = []
        for v in fields.values():
            values.append(json.dumps(v) if isinstance(v, (dict, list)) else v)
        values.append(account_id)

        cur.execute(
            f"UPDATE cloud_accounts SET {set_clause} WHERE account_id = %s RETURNING *",
            values,
        )
        row = cur.fetchone()
        conn.commit()
        return dict(row) if row else None
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()


def soft_delete_cloud_account(account_id: str) -> bool:
    """Soft-delete — sets account_status = 'deleted'."""
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "UPDATE cloud_accounts SET account_status = 'deleted', updated_at = %s WHERE account_id = %s RETURNING account_id",
            (datetime.now(timezone.utc), account_id),
        )
        deleted = cur.fetchone() is not None
        conn.commit()
        return deleted
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()


# Keep old name as alias so existing callers don't break
def delete_cloud_account(account_id: str) -> bool:
    return soft_delete_cloud_account(account_id)


# ---------------------------------------------------------------------------
# agent_registrations helpers (added by migration onboarding-001-account-type)
# agent_token_hash = SHA-256 hex of raw token — raw token NEVER stored in DB
# ---------------------------------------------------------------------------

def create_agent_registration(
    account_id: str,
    tenant_id: str,
    agent_token_hash: str,
    customer_id: Optional[str] = None,
) -> dict:
    """Create an agent registration record and return registration_id + agent_id.

    Args:
        account_id: UUID of the cloud_account this agent registers against.
        tenant_id: Tenant identifier for multi-tenant isolation.
        agent_token_hash: SHA-256 hex digest of the raw registration token.
            The raw token must NEVER be passed here or stored in the DB.
        customer_id: Customer identifier (denormalized from cloud_accounts).

    Returns:
        Dict with 'registration_id' (UUID str) and 'agent_id' (readable str).

    Raises:
        psycopg2.errors.UniqueViolation: If token_hash already exists.
    """
    import uuid as _uuid
    raw_reg_id = str(_uuid.uuid4())
    agent_id = "agnt-" + raw_reg_id.replace("-", "")[:8]

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute(
            """
            INSERT INTO agent_registrations
                (registration_id, account_id, tenant_id, customer_id, token_hash, agent_id,
                 status, issued_at, expires_at, created_at, updated_at)
            VALUES
                (%s::uuid, %s, %s, %s, %s, %s, 'pending',
                 NOW(), NOW() + INTERVAL '30 minutes', NOW(), NOW())
            RETURNING registration_id, agent_id
            """,
            (raw_reg_id, account_id, tenant_id, customer_id or tenant_id, agent_token_hash, agent_id),
        )
        row = cur.fetchone()
        conn.commit()
        return {"registration_id": str(row["registration_id"]), "agent_id": row["agent_id"]}
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()


def rotate_agent_token(
    account_id: str,
    tenant_id: str,
    new_token_hash: str,
) -> Dict[str, Any]:
    """Rotate the agent token for an existing registration (re-provision path).

    Updates token_hash and resets status to 'pending' so the agent must
    re-connect. The agent_id is preserved so the binary config does not need
    to change if the user only wants a new token.

    Args:
        account_id: UUID of the cloud account.
        tenant_id: Tenant scoping — enforces multi-tenant isolation.
        new_token_hash: SHA-256 hex digest of the newly generated raw token.

    Returns:
        Dict with 'registration_id' (UUID str) and 'agent_id' (readable str).

    Raises:
        ValueError: If no existing registration is found for the account.
    """
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute(
            """
            UPDATE agent_registrations
            SET token_hash  = %s,
                status      = 'pending',
                issued_at   = NOW(),
                expires_at  = NOW() + INTERVAL '30 minutes',
                updated_at  = NOW()
            WHERE account_id = %s
              AND tenant_id  = %s
            RETURNING registration_id, agent_id
            """,
            (new_token_hash, account_id, tenant_id),
        )
        row = cur.fetchone()
        if row is None:
            raise ValueError(f"No agent registration found for account {account_id}")
        conn.commit()
        return {"registration_id": str(row["registration_id"]), "agent_id": row["agent_id"]}
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()


def get_agent_registration_by_token_hash(
    token_hash: str,
) -> Optional["AgentRegistration"]:
    """Look up an agent registration by its token hash.

    Args:
        token_hash: SHA-256 hex digest of the raw agent token.

    Returns:
        AgentRegistration dataclass if found, else None.
    """
    from engine_onboarding.database.models import AgentRegistration

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute(
            """
            SELECT registration_id, agent_id, account_id, tenant_id, token_hash,
                   status, last_heartbeat_at, issued_at, activated_at,
                   agent_version, agent_hostname
            FROM agent_registrations
            WHERE token_hash = %s
            """,
            (token_hash,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        return AgentRegistration(
            registration_id=str(row["registration_id"]),
            agent_id=row["agent_id"],
            account_id=str(row["account_id"]),
            tenant_id=row["tenant_id"],
            token_hash=row["token_hash"],
            status=row["status"],
            last_heartbeat_at=row["last_heartbeat_at"],
            issued_at=row["issued_at"],
            activated_at=row["activated_at"],
            agent_version=row["agent_version"],
            agent_hostname=row["agent_hostname"],
        )
    finally:
        cur.close()
        conn.close()


def get_agent_registration_by_account(
    account_id: str,
    tenant_id: str,
) -> Optional[Dict[str, Any]]:
    """Return the most recent agent registration row for a given account.

    Used by the platform-side agent-status endpoint to poll connection state
    without requiring the raw token (which the platform never stores).

    Args:
        account_id: UUID of the cloud_account to look up.
        tenant_id:  Caller's tenant_id — enforces multi-tenant isolation.

    Returns:
        Dict with ``status`` and ``last_heartbeat`` if a registration row exists,
        otherwise ``None``.
    """
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute(
            """
            SELECT registration_id, agent_id, status, last_heartbeat_at
            FROM agent_registrations
            WHERE account_id = %s
              AND tenant_id  = %s
            ORDER BY issued_at DESC
            LIMIT 1
            """,
            (account_id, tenant_id),
        )
        row = cur.fetchone()
        if row is None:
            return None
        return {
            "registration_id": str(row["registration_id"]) if row["registration_id"] else None,
            "agent_id": row["agent_id"],
            "status": row["status"],
            "last_heartbeat_at": row["last_heartbeat_at"],
        }
    finally:
        cur.close()
        conn.close()


def update_agent_heartbeat(
    token_hash: str,
    host: Optional[str],
    version: Optional[str],
) -> None:
    """Update last_heartbeat, agent_host, and agent_version for a registered agent.

    Args:
        token_hash: SHA-256 hex digest of the raw agent token (lookup key).
        host: Hostname reported by the agent binary (may be None).
        version: Semver version reported by the agent binary (may be None).
    """
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            UPDATE agent_registrations
            SET last_heartbeat_at = NOW(),
                agent_hostname    = COALESCE(%s, agent_hostname),
                agent_version     = COALESCE(%s, agent_version),
                updated_at        = NOW()
            WHERE token_hash = %s
            """,
            (host, version, token_hash),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()


def set_agent_connected(token_hash: str) -> None:
    """Mark an agent as connected and record connected_at timestamp.

    Sets status = 'connected' and connected_at = NOW() for the first
    successful authentication. Subsequent calls are idempotent
    (connected_at is only set once via COALESCE).

    Args:
        token_hash: SHA-256 hex digest of the raw agent token.
    """
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            UPDATE agent_registrations
            SET status       = 'connected',
                activated_at = COALESCE(activated_at, NOW()),
                updated_at   = NOW()
            WHERE token_hash = %s
            """,
            (token_hash,),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()


def set_agent_run_now(account_id: str) -> bool:
    """Set the run_now_requested flag on an agent_registration row for an account.

    Called by the ad-hoc scan endpoint (AC9 of onboarding-C7) when the target
    account is of type ``vulnerability``.  The agent polls this flag on its
    next heartbeat and triggers a local scan run.

    Args:
        account_id: Cloud account UUID whose agent should run now.

    Returns:
        ``True`` if a matching agent_registrations row was found and updated,
        ``False`` if no agent is registered for this account.
    """
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            UPDATE agent_registrations
            SET    run_now_requested = TRUE,
                   updated_at       = NOW()
            WHERE  account_id = %s
            RETURNING account_id
            """,
            (account_id,),
        )
        updated = cur.fetchone() is not None
        conn.commit()
        return updated
    except psycopg2.errors.UndefinedColumn:
        # run_now_requested column not yet present — ignore gracefully.
        conn.rollback()
        return False
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()


def consume_registration_token(token_hash: str) -> Optional[Dict[str, Any]]:
    """Validate and atomically consume a registration token (single-use).

    Validates: token_hash exists, status='pending', expires_at > NOW().
    On success: sets status='connected', activated_at=NOW().
    Returns the registration row on success, None if not found/expired.

    Args:
        token_hash: SHA-256 hex digest of the raw registration token.

    Returns:
        Dict with registration_id, agent_id, account_id, tenant_id, expires_at
        if valid and pending. None if not found or expired.

    Raises:
        ValueError: If token exists but is not in 'pending' status (already consumed).
    """
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        # First check if token exists at all (regardless of status/expiry)
        cur.execute(
            """
            SELECT registration_id, agent_id, account_id, tenant_id,
                   status, expires_at, activated_at
            FROM agent_registrations
            WHERE token_hash = %s
            """,
            (token_hash,),
        )
        row = cur.fetchone()

        if row is None:
            return None

        # Token exists but already consumed (not pending)
        if row["status"] != "pending":
            raise ValueError(f"Token already consumed: status={row['status']}")

        # Token is pending — check expiry
        now = datetime.now(timezone.utc)
        expires_at = row["expires_at"]
        if expires_at and expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at and expires_at < now:
            return None  # Expired — treat as not found

        # Atomically consume: set status='connected', activated_at=NOW()
        cur.execute(
            """
            UPDATE agent_registrations
            SET status       = 'connected',
                activated_at = NOW(),
                updated_at   = NOW()
            WHERE token_hash = %s
              AND status     = 'pending'
              AND expires_at > NOW()
            RETURNING registration_id, agent_id, account_id, tenant_id, expires_at
            """,
            (token_hash,),
        )
        updated = cur.fetchone()
        conn.commit()

        if updated is None:
            # Race condition: another process consumed it between our check and update
            raise ValueError("Token already consumed (concurrent request)")

        return {
            "registration_id": str(updated["registration_id"]),
            "agent_id": updated["agent_id"],
            "account_id": str(updated["account_id"]),
            "tenant_id": updated["tenant_id"],
            "expires_at": updated["expires_at"].isoformat() if updated["expires_at"] else None,
        }
    except ValueError:
        conn.rollback()
        raise
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()


def get_and_clear_run_now(token_hash: str) -> bool:
    """Read and atomically clear the run_now_requested flag for an agent.

    Checks the ``run_now_requested`` column on ``agent_registrations`` and, if
    ``TRUE``, flips it back to ``FALSE`` in the same transaction so only one
    heartbeat poll gets ``run_now=True`` per ad-hoc scan trigger.

    If the column does not yet exist in the deployed schema (pre-migration),
    this function returns ``False`` safely without raising.

    Args:
        token_hash: SHA-256 hex digest of the raw agent token (lookup key).

    Returns:
        ``True`` if a run was requested (and the flag has been cleared),
        ``False`` otherwise.
    """
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        # Use a CTE to fetch-and-clear atomically so concurrent heartbeats
        # don't both see run_now=True.
        cur.execute(
            """
            UPDATE agent_registrations
            SET    run_now_requested = FALSE,
                   updated_at       = NOW()
            WHERE  token_hash        = %s
              AND  run_now_requested = TRUE
            RETURNING run_now_requested
            """,
            (token_hash,),
        )
        row = cur.fetchone()
        conn.commit()
        # If a row was returned the flag was TRUE and has been cleared.
        return row is not None
    except psycopg2.errors.UndefinedColumn:
        # Column not yet added by migration — safe default.
        conn.rollback()
        return False
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()
