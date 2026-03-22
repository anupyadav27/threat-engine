"""
PostgreSQL Row-Level Security (RLS) helpers.

Every engine database has ``tenant_isolation`` RLS policies on its tenant_id
tables.  Use these helpers to set the per-transaction tenant context before
running queries so that non-postgres application users only see their own rows.

PgBouncer compatibility note
-----------------------------
PgBouncer runs in *transaction* pool mode, meaning SET is cleared between
transactions.  ``set_config('app.tenant_id', $1, TRUE)`` sets the value as
*transaction-local* (the third argument ``TRUE`` = ``is_local``), so it is
automatically cleared when the transaction ends — safe with PgBouncer and
explicit transactions alike.

RLS enforcement note
---------------------
All tables use ``ENABLE + FORCE ROW LEVEL SECURITY`` so the policy applies
even to the ``postgres`` role (the table owner).  The ``postgres`` role is
granted ``BYPASSRLS`` in the migrations, so existing engine code that does
*not* call these helpers continues to work unchanged.  New application-level
users (non-postgres) will be subject to the policy and must always set the
tenant context via these helpers.
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager, contextmanager
from typing import Any, AsyncGenerator, Generator

logger = logging.getLogger(__name__)

# ── Psycopg2 (synchronous) helpers ────────────────────────────────────────────


def set_tenant_context(cursor: Any, tenant_id: str) -> None:
    """Set ``app.tenant_id`` for the current transaction (psycopg2 cursor).

    Call this inside an open transaction before issuing any query that touches
    RLS-protected tables::

        conn = psycopg2.connect(...)
        with conn.cursor() as cur:
            rls.set_tenant_context(cur, tenant_id)
            cur.execute("SELECT * FROM threat_findings")

    Args:
        cursor: An open psycopg2 cursor.
        tenant_id: The tenant identifier string (VARCHAR 255).
    """
    cursor.execute("SELECT set_config('app.tenant_id', %s, TRUE)", (tenant_id,))
    logger.debug("tenant context → %s", tenant_id)


@contextmanager
def tenant_cursor(conn: Any, tenant_id: str) -> Generator[Any, None, None]:
    """Context manager that yields a psycopg2 cursor with tenant context set.

    Opens a cursor, sets ``app.tenant_id`` as a transaction-local setting, and
    yields the cursor.  The transaction (and therefore the setting) is cleared
    automatically when the context exits::

        with psycopg2.connect(...) as conn:
            with rls.tenant_cursor(conn, tenant_id) as cur:
                cur.execute("SELECT * FROM threat_findings")
                rows = cur.fetchall()

    Args:
        conn: An open psycopg2 connection.
        tenant_id: The tenant identifier string.

    Yields:
        The psycopg2 cursor with tenant context active.
    """
    with conn.cursor() as cur:
        set_tenant_context(cur, tenant_id)
        yield cur


# ── Asyncpg (asynchronous) helpers ────────────────────────────────────────────


@asynccontextmanager
async def tenant_acquire(pool: Any, tenant_id: str) -> AsyncGenerator[Any, None]:
    """Async context manager: acquires an asyncpg connection with tenant context.

    Acquires a connection from *pool*, begins a transaction, sets
    ``app.tenant_id`` as transaction-local, and yields the connection.
    The transaction commits (or rolls back on exception) and the connection
    is released when the context exits::

        async with rls.tenant_acquire(pool, tenant_id) as conn:
            rows = await conn.fetch("SELECT * FROM iam_findings")

    Args:
        pool: An ``asyncpg.Pool`` instance.
        tenant_id: The tenant identifier string.

    Yields:
        The asyncpg connection with an active transaction and tenant context.
    """
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                "SELECT set_config('app.tenant_id', $1, TRUE)", tenant_id
            )
            logger.debug("async tenant context → %s", tenant_id)
            yield conn
