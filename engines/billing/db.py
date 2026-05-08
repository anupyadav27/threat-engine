"""
Billing Engine — Database connection pool.

Provides a ThreadedConnectionPool against threat_engine_billing (RDS).
All env vars are sourced from K8s secret billing-db-passwords and
ConfigMap threat-engine-db-config.
"""

import os

import psycopg2
from psycopg2 import pool

_pool: pool.ThreadedConnectionPool | None = None


def get_pool() -> pool.ThreadedConnectionPool:
    """Return (or lazily create) the shared connection pool.

    Returns:
        A ThreadedConnectionPool configured from environment variables.

    Raises:
        psycopg2.OperationalError: If the database is unreachable at startup.
    """
    global _pool
    if _pool is None:
        _pool = psycopg2.pool.ThreadedConnectionPool(
            minconn=2,
            maxconn=10,
            host=os.environ["BILLING_DB_HOST"],
            port=int(os.environ.get("BILLING_DB_PORT", "5432")),
            dbname=os.environ["BILLING_DB_NAME"],
            user=os.environ["BILLING_DB_USER"],
            password=os.environ["BILLING_DB_PASSWORD"],
            connect_timeout=10,
            sslmode=os.environ.get("DB_SSLMODE", "require"),
        )
    return _pool


def get_conn() -> psycopg2.extensions.connection:
    """Acquire a connection from the pool.

    Returns:
        A psycopg2 connection. Caller must call put_conn() when done.
    """
    return get_pool().getconn()


def put_conn(conn: psycopg2.extensions.connection) -> None:
    """Return a connection to the pool.

    Args:
        conn: The connection to return.
    """
    get_pool().putconn(conn)
