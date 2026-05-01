"""
SecOps DB connection config.
Uses SECOPS_DB_* env vars, falls back to SHARED_DB_* then defaults.
"""

import os
import psycopg2
from psycopg2.extras import RealDictCursor

_DEFAULTS = {
    "host": "localhost",
    "port": 5432,
    "database": "threat_engine_secops",
    "user": "postgres",
    "password": "",
}


def _env(key, *fallbacks, default=None):
    """Read env var with fallback chain."""
    for name in (key, *fallbacks):
        val = os.getenv(name)
        if val:
            return val
    return default


def get_db_config() -> dict:
    return {
        "host": _env("SECOPS_DB_HOST", "SHARED_DB_HOST", default=_DEFAULTS["host"]),
        "port": int(_env("SECOPS_DB_PORT", "SHARED_DB_PORT", default=_DEFAULTS["port"])),
        "database": _env("SECOPS_DB_NAME", default=_DEFAULTS["database"]),
        "user": _env("SECOPS_DB_USER", "SHARED_DB_USER", default=_DEFAULTS["user"]),
        "password": _env("SECOPS_DB_PASSWORD", "SHARED_DB_PASSWORD", default=_DEFAULTS["password"]),
    }


def get_connection(cursor_factory=None):
    """Get a new psycopg2 connection with TCP keepalives."""
    cfg = get_db_config()
    kwargs = dict(
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
    if cursor_factory:
        kwargs["cursor_factory"] = cursor_factory
    return psycopg2.connect(**kwargs)


def get_dict_connection():
    """Convenience: connection with RealDictCursor."""
    return get_connection(cursor_factory=RealDictCursor)
