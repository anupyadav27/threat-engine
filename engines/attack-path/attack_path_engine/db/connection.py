"""
Attack Path Engine — DB connection pool.

Uses the shared get_attack_path_conn() factory from engine_common.
The pool provides min=2, max=10 connections per architecture doc section 5.2.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

import psycopg2
import psycopg2.pool

logger = logging.getLogger(__name__)

_pool: Optional[psycopg2.pool.ThreadedConnectionPool] = None


def _get_pool() -> psycopg2.pool.ThreadedConnectionPool:
    """Return (or lazily initialise) the connection pool."""
    global _pool
    if _pool is None:
        _pool = psycopg2.pool.ThreadedConnectionPool(
            minconn=2,
            maxconn=10,
            host=os.getenv("ATTACK_PATH_DB_HOST", os.getenv("DB_HOST", "localhost")),
            port=int(os.getenv("ATTACK_PATH_DB_PORT", os.getenv("DB_PORT", "5432"))),
            dbname=os.getenv("ATTACK_PATH_DB_NAME", "threat_engine_attack_path"),
            user=os.getenv("ATTACK_PATH_DB_USER", os.getenv("DB_USER", "postgres")),
            password=(
                os.getenv("ATTACK_PATH_DB_PASSWORD")
                or os.getenv("DB_PASSWORD")
                or os.getenv("DISCOVERIES_DB_PASSWORD", "")
            ),
            sslmode=os.getenv("DB_SSLMODE", "prefer"),
            connect_timeout=10,
        )
        logger.info("Attack-path DB pool created (min=2, max=10)")
    return _pool


def get_conn() -> psycopg2.extensions.connection:
    """Get a pooled psycopg2 connection. Caller must call putconn() when done."""
    return _get_pool().getconn()


def put_conn(conn: psycopg2.extensions.connection) -> None:
    """Return a connection to the pool."""
    _get_pool().putconn(conn)


def check_db_health() -> bool:
    """Return True if the DB is reachable; False otherwise. Used by /health/ready."""
    try:
        conn = get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
            return True
        finally:
            put_conn(conn)
    except Exception as exc:
        logger.warning("Attack-path DB health check failed: %s", exc)
        return False
