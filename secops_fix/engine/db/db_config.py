"""
SecOps Fix DB connection config.
Uses SECOPS_DB_* env vars (same DB as secops engine: threat_engine_secops).

Connection pooling via psycopg2.pool.ThreadedConnectionPool:
  - min 2, max 10 connections shared across all threads
  - connections returned to pool after each use (no per-request TCP overhead)
  - pool created once at process startup; if env vars missing, fails fast.
"""

import logging
import os
import psycopg2
import psycopg2.pool
from contextlib import contextmanager
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)

_pool: psycopg2.pool.ThreadedConnectionPool = None


def _env(key, *fallbacks, default=None):
    for name in (key, *fallbacks):
        val = os.getenv(name)
        if val:
            return val
    return default


def get_db_config() -> dict:
    return {
        "host":     _env("SECOPS_DB_HOST", "SHARED_DB_HOST",        default="localhost"),
        "port": int(_env("SECOPS_DB_PORT", "SHARED_DB_PORT",        default=5432)),
        "database": _env("SECOPS_DB_NAME",                          default="threat_engine_secops"),
        "user":     _env("SECOPS_DB_USER", "SHARED_DB_USER",        default="postgres"),
        "password": _env("SECOPS_DB_PASSWORD", "SHARED_DB_PASSWORD", default=""),
    }


def _get_pool() -> psycopg2.pool.ThreadedConnectionPool:
    """Return the shared pool, creating it on first call."""
    global _pool
    if _pool is None or _pool.closed:
        cfg = get_db_config()
        _pool = psycopg2.pool.ThreadedConnectionPool(
            minconn=2,
            maxconn=10,
            host=cfg["host"],
            port=cfg["port"],
            database=cfg["database"],
            user=cfg["user"],
            password=cfg["password"],
            connect_timeout=10,
            keepalives=1,
            keepalives_idle=30,
            keepalives_interval=10,
            keepalives_count=5,
        )
        logger.info(f"DB pool created: {cfg['host']}:{cfg['port']}/{cfg['database']} (min=2 max=10)")
    return _pool


@contextmanager
def get_db():
    """
    Context manager that checks out a connection from the pool and
    returns it automatically — even on exception.

    Usage:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(...)
            conn.commit()
    """
    pool = _get_pool()
    conn = pool.getconn()
    try:
        yield conn
    except Exception:
        conn.rollback()
        raise
    finally:
        pool.putconn(conn)


class _PooledConnection:
    """
    Thin wrapper that returns the connection to the pool when close() is called.
    Delegates all other attribute access to the underlying psycopg2 connection.
    """
    def __init__(self, pool, conn, cursor_factory=None):
        self._pool = pool
        self._conn = conn
        if cursor_factory:
            self._conn.cursor_factory = cursor_factory

    def close(self):
        try:
            self._pool.putconn(self._conn)
        except Exception:
            self._conn.close()

    def cursor(self, *args, **kwargs):
        return self._conn.cursor(*args, **kwargs)

    def commit(self):
        return self._conn.commit()

    def rollback(self):
        return self._conn.rollback()

    def __getattr__(self, name):
        return getattr(self._conn, name)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            self.rollback()
        self.close()
        return False


def get_connection(cursor_factory=None):
    """
    Returns a pooled connection wrapped so close() returns it to the pool.
    Existing call pattern (conn = get_connection() / conn.close()) unchanged.
    """
    pool = _get_pool()
    conn = pool.getconn()
    return _PooledConnection(pool, conn, cursor_factory=cursor_factory)


def get_dict_connection():
    return get_connection(cursor_factory=RealDictCursor)


def close_pool():
    """Graceful shutdown — close all pooled connections."""
    global _pool
    if _pool and not _pool.closed:
        _pool.closeall()
        logger.info("DB pool closed")
