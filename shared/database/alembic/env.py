"""Alembic migration environment — multi-engine, multi-database.

Each engine runs in its own PostgreSQL database on the shared RDS instance.
Pass the target engine via -x engine=<name> or ALEMBIC_ENGINE env var.

  alembic -x engine=check upgrade head
  ALEMBIC_ENGINE=inventory alembic upgrade head

Version files live per-engine under alembic/versions/{engine}/.
Alembic tracks applied versions in the alembic_version table inside
each engine's own database (so engines never interfere with each other).
"""
from __future__ import annotations

import logging
import os
import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import create_engine, pool

# ── Alembic config object ──────────────────────────────────────────────────────
config = context.config

# Set up logging from alembic.ini
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

logger = logging.getLogger("alembic.env")

# ── Engine → database mapping ─────────────────────────────────────────────────
# Maps the short engine name to the RDS database name.
ENGINE_DB_MAP: dict[str, str] = {
    "check":       "threat_engine_check",
    "discoveries": "threat_engine_discoveries",
    "compliance":  "threat_engine_compliance",
    "inventory":   "threat_engine_inventory",
    "threat":      "threat_engine_threat",
    "onboarding":  "threat_engine_onboarding",
    "iam":         "threat_engine_iam",
    "datasec":     "threat_engine_datasec",
    "secops":      "threat_engine_secops",
}

# ── Helpers ────────────────────────────────────────────────────────────────────

def get_engine_name() -> str:
    """Return the engine name from -x engine=xxx or ALEMBIC_ENGINE env var."""
    # Alembic passes -x key=value via get_x_argument()
    x_args = context.get_x_argument(as_dictionary=True)
    engine = x_args.get("engine") or os.environ.get("ALEMBIC_ENGINE", "").strip()
    if not engine:
        raise ValueError(
            "Engine not specified.\n"
            "  alembic -x engine=check upgrade head\n"
            "  ALEMBIC_ENGINE=check alembic upgrade head\n"
            f"Valid engines: {sorted(ENGINE_DB_MAP)}"
        )
    if engine not in ENGINE_DB_MAP:
        raise ValueError(
            f"Unknown engine '{engine}'. Valid: {sorted(ENGINE_DB_MAP)}"
        )
    return engine


def build_db_url(engine_name: str) -> str:
    """Build the PostgreSQL connection URL from environment variables.

    Reads env vars in priority order:
      1. <ENGINE>_DB_HOST  (per-engine override, e.g. CHECK_DB_HOST)
      2. DB_HOST           (shared default)
      3. Hardcoded fallback for local dev

    All engines share the same RDS host and password in this deployment.
    """
    prefix = engine_name.upper()
    host     = os.environ.get(f"{prefix}_DB_HOST")     or os.environ.get("DB_HOST", "localhost")
    port     = os.environ.get(f"{prefix}_DB_PORT")     or os.environ.get("DB_PORT", "5432")
    user     = os.environ.get(f"{prefix}_DB_USER")     or os.environ.get("DB_USER", "postgres")
    password = os.environ.get(f"{prefix}_DB_PASSWORD") or os.environ.get("DB_PASSWORD", "")
    dbname   = ENGINE_DB_MAP[engine_name]

    # URL-encode the password in case it contains special chars
    from urllib.parse import quote_plus
    encoded_pw = quote_plus(password)
    return f"postgresql+psycopg2://{user}:{encoded_pw}@{host}:{port}/{dbname}"


def get_version_location(engine_name: str) -> str:
    """Return the absolute path to this engine's versions directory."""
    here = Path(__file__).parent
    return str(here / "versions" / engine_name)


# ── Offline migrations (generate SQL script without connecting) ────────────────

def run_migrations_offline(engine_name: str) -> None:
    """Emit migration SQL to stdout without connecting to the DB.

    Used to preview what will be executed:
      alembic -x engine=check upgrade head --sql
    """
    url = build_db_url(engine_name)
    context.configure(
        url=url,
        target_metadata=None,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        version_locations=[get_version_location(engine_name)],
        version_table="alembic_version",
        include_schemas=False,
    )
    with context.begin_transaction():
        context.run_migrations()


# ── Online migrations (connect and execute) ────────────────────────────────────

def run_migrations_online(engine_name: str) -> None:
    """Connect to the target DB and run pending migrations."""
    url = build_db_url(engine_name)
    connectable = create_engine(
        url,
        poolclass=pool.NullPool,   # No pooling for migration runs
        echo=False,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=None,
            version_locations=[get_version_location(engine_name)],
            version_table="alembic_version",
            include_schemas=False,
            # Wrap each migration in a transaction so partial failures roll back
            transaction_per_migration=True,
        )
        with context.begin_transaction():
            context.run_migrations()


# ── Entry point ────────────────────────────────────────────────────────────────

engine_name = get_engine_name()
logger.info("Running migrations for engine: %s → %s", engine_name, ENGINE_DB_MAP[engine_name])

if context.is_offline_mode():
    run_migrations_offline(engine_name)
else:
    run_migrations_online(engine_name)
