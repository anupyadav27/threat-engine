"""
Platform Admin Engine — Database connection pools.

Two pools are provided:
  - _readonly_pool  : uses billing_readonly credentials (SELECT only — no writes).
  - _app_pool       : uses billing_app credentials (writes for tier override,
                      suspend, etc.).

All env vars are sourced from the billing-db-passwords K8s Secret and the
threat-engine-db-config ConfigMap.
"""

from __future__ import annotations

import os

import psycopg2
from psycopg2 import pool

_readonly_pool: pool.ThreadedConnectionPool | None = None
_app_pool: pool.ThreadedConnectionPool | None = None


def _get_readonly_pool() -> pool.ThreadedConnectionPool:
    """Return (or lazily create) the billing_readonly connection pool.

    Returns:
        A ThreadedConnectionPool configured from BILLING_DB_* env vars
        using the billing_readonly role.

    Raises:
        psycopg2.OperationalError: If the database is unreachable.
    """
    global _readonly_pool
    if _readonly_pool is None:
        _readonly_pool = psycopg2.pool.ThreadedConnectionPool(
            minconn=1,
            maxconn=5,
            host=os.environ["BILLING_DB_HOST"],
            port=int(os.environ.get("BILLING_DB_PORT", "5432")),
            dbname=os.environ["BILLING_DB_NAME"],
            user=os.environ.get("BILLING_DB_USER", "billing_readonly"),
            password=os.environ["BILLING_DB_PASSWORD"],
            connect_timeout=10,
        )
    return _readonly_pool


def _get_app_pool() -> pool.ThreadedConnectionPool:
    """Return (or lazily create) the billing_app (write) connection pool.

    Returns:
        A ThreadedConnectionPool configured from BILLING_APP_DB_* env vars
        using the billing_app role.

    Raises:
        psycopg2.OperationalError: If the database is unreachable.
    """
    global _app_pool
    if _app_pool is None:
        _app_pool = psycopg2.pool.ThreadedConnectionPool(
            minconn=1,
            maxconn=5,
            host=os.environ["BILLING_DB_HOST"],
            port=int(os.environ.get("BILLING_DB_PORT", "5432")),
            dbname=os.environ["BILLING_DB_NAME"],
            user=os.environ.get("BILLING_APP_DB_USER", "billing_app"),
            password=os.environ["BILLING_APP_DB_PASSWORD"],
            connect_timeout=10,
        )
    return _app_pool


def get_conn() -> psycopg2.extensions.connection:
    """Acquire a read-only connection from the billing_readonly pool.

    Returns:
        A psycopg2 connection. Caller must call put_conn() when done.
    """
    return _get_readonly_pool().getconn()


def put_conn(conn: psycopg2.extensions.connection) -> None:
    """Return a read-only connection to the pool.

    Args:
        conn: The connection to return.
    """
    _get_readonly_pool().putconn(conn)


def get_write_conn() -> psycopg2.extensions.connection:
    """Acquire a writable connection from the billing_app pool.

    Returns:
        A psycopg2 connection. Caller must call put_write_conn() when done.
    """
    return _get_app_pool().getconn()


def put_write_conn(conn: psycopg2.extensions.connection) -> None:
    """Return a writable connection to the pool.

    Args:
        conn: The connection to return.
    """
    _get_app_pool().putconn(conn)
