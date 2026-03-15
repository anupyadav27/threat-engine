"""
Database connection pool configuration with retry and health monitoring.

Provides a standardized way to create SQLAlchemy or psycopg2 connection pools
with proper retry logic, pre-ping, and pool recycling.

Usage::

    from shared.common.db_pool import create_pool, create_psycopg2_conn

    # SQLAlchemy pool
    engine = create_pool("postgresql://user:pass@host/db", service_name="engine-threat")

    # Simple psycopg2 with retry
    conn = create_psycopg2_conn(
        host="localhost", port=5432, dbname="threat_engine_threat",
        user="postgres", password="secret",
    )
"""
from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# ── Pool defaults ─────────────────────────────────────────────────────────────

DEFAULT_POOL_SIZE = int(os.getenv("DB_POOL_SIZE", "10"))
DEFAULT_MAX_OVERFLOW = int(os.getenv("DB_MAX_OVERFLOW", "20"))
DEFAULT_POOL_RECYCLE = int(os.getenv("DB_POOL_RECYCLE", "3600"))  # 1 hour
DEFAULT_POOL_TIMEOUT = int(os.getenv("DB_POOL_TIMEOUT", "30"))
DEFAULT_CONNECT_RETRIES = int(os.getenv("DB_CONNECT_RETRIES", "5"))
DEFAULT_RETRY_DELAY = float(os.getenv("DB_RETRY_DELAY", "2.0"))


def create_pool(
    url: str,
    service_name: str = "unknown",
    pool_size: int = DEFAULT_POOL_SIZE,
    max_overflow: int = DEFAULT_MAX_OVERFLOW,
    pool_recycle: int = DEFAULT_POOL_RECYCLE,
    pool_timeout: int = DEFAULT_POOL_TIMEOUT,
) -> Any:
    """Create a SQLAlchemy engine with production-ready pool configuration.

    Args:
        url: Database connection URL.
        service_name: Service name for logging and metrics.
        pool_size: Number of persistent connections in the pool.
        max_overflow: Max additional connections beyond pool_size.
        pool_recycle: Recycle connections after this many seconds.
        pool_timeout: Seconds to wait for a connection from the pool.

    Returns:
        SQLAlchemy Engine instance.
    """
    try:
        from sqlalchemy import create_engine, event

        engine = create_engine(
            url,
            pool_size=pool_size,
            max_overflow=max_overflow,
            pool_recycle=pool_recycle,
            pool_timeout=pool_timeout,
            pool_pre_ping=True,  # Verify connections before use
            echo=os.getenv("DB_ECHO", "false").lower() == "true",
        )

        # Track connection errors for metrics
        @event.listens_for(engine, "handle_error")
        def _handle_error(context):
            try:
                from shared.common.metrics import record_db_error
                record_db_error(service_name, error_type="query")
            except Exception:
                pass

        logger.info(
            "DB pool created service=%s pool_size=%d max_overflow=%d recycle=%ds",
            service_name, pool_size, max_overflow, pool_recycle,
        )
        return engine

    except ImportError:
        logger.error("sqlalchemy not installed — cannot create pool")
        raise


def create_psycopg2_conn(
    host: str,
    port: int,
    dbname: str,
    user: str,
    password: str,
    max_retries: int = DEFAULT_CONNECT_RETRIES,
    retry_delay: float = DEFAULT_RETRY_DELAY,
    service_name: str = "unknown",
) -> Any:
    """Create a psycopg2 connection with retry logic.

    Attempts to connect with exponential backoff on failure.

    Args:
        host: Database hostname.
        port: Database port.
        dbname: Database name.
        user: Database user.
        password: Database password.
        max_retries: Maximum connection attempts.
        retry_delay: Initial delay between retries (doubles each attempt).
        service_name: Service name for logging.

    Returns:
        psycopg2 connection object.

    Raises:
        psycopg2.OperationalError: If all retries are exhausted.
    """
    import psycopg2

    delay = retry_delay
    last_exc = None

    for attempt in range(max_retries + 1):
        try:
            conn = psycopg2.connect(
                host=host,
                port=port,
                dbname=dbname,
                user=user,
                password=password,
                connect_timeout=10,
                options="-c statement_timeout=30000",  # 30s query timeout
            )
            conn.autocommit = False
            logger.info(
                "DB connected service=%s host=%s db=%s attempt=%d",
                service_name, host, dbname, attempt + 1,
            )
            return conn

        except psycopg2.OperationalError as exc:
            last_exc = exc
            if attempt < max_retries:
                logger.warning(
                    "DB connect failed service=%s attempt=%d/%d error=%s — retrying in %.1fs",
                    service_name, attempt + 1, max_retries + 1, exc, delay,
                )
                try:
                    from shared.common.metrics import record_db_error
                    record_db_error(service_name, error_type="connection")
                except Exception:
                    pass
                time.sleep(delay)
                delay = min(delay * 2, 60.0)
            else:
                logger.error(
                    "DB connect exhausted retries service=%s error=%s",
                    service_name, exc,
                )
                raise

    raise last_exc  # type: ignore[misc]


def get_pool_status(engine: Any) -> Dict[str, Any]:
    """Get current pool status from a SQLAlchemy engine.

    Returns:
        Dict with pool size, checked out, overflow, etc.
    """
    try:
        pool = engine.pool
        return {
            "pool_size": pool.size(),
            "checked_in": pool.checkedin(),
            "checked_out": pool.checkedout(),
            "overflow": pool.overflow(),
            "invalid": pool._invalidate_time if hasattr(pool, "_invalidate_time") else None,
        }
    except Exception as exc:
        return {"error": str(exc)}
