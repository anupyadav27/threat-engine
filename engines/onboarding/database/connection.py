"""
PostgreSQL database connection and session management.
Uses onboarding DB (threat_engine_onboarding) when ONBOARDING_DB_* is set, else shared DB.
Tables: cloud_accounts, scan_orchestration, etc. in public schema.
"""
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import NullPool
from contextlib import contextmanager
from typing import Generator
import logging
import os

# Import local database config
from engine_onboarding.database.connection_config.database_config import get_database_config

from engine_onboarding.database.models import Base

logger = logging.getLogger(__name__)

# Get shared database config (onboarding uses shared DB with engine_onboarding schema)
try:
    db_config = get_database_config("shared")
    database_url = db_config.connection_string
    logger.info(f"Using consolidated shared database: {db_config.database} on {db_config.host}")
except Exception as e:
    logger.error(f"Failed to get consolidated DB config: {e}")
    raise RuntimeError("Consolidated database configuration is required. Cannot proceed without it.") from e

# Set schema search_path for engine_onboarding and engine_shared
# This ensures tables are found in the correct schemas
_schema = os.getenv("DB_SCHEMA", "engine_onboarding,engine_shared")
_connect_opts = {
    "connect_timeout": 10,
    "options": f"-c timezone=utc -c search_path={_schema}"
}

engine = create_engine(
    database_url,
    poolclass=NullPool,
    pool_pre_ping=True,
    echo=False,
    connect_args=_connect_opts,
)

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db():
    """
    Initialize database.
    Note: With consolidated DB, tables are created via init-databases.sql script.
    This function is kept for compatibility but does not create tables.
    """
    logger.info("Using consolidated DB with schema-based tables. Tables should be created via init-databases.sql")
    logger.info(f"Schema search_path: {_schema}")
    # Verify connection works
    try:
        with engine.connect() as conn:
            result = conn.execute(text("SELECT current_schema(), current_schemas(false)"))
            schema_info = result.fetchone()
            logger.info(f"Database connection verified. Current schema: {schema_info[0] if schema_info else 'unknown'}")
    except Exception as e:
        logger.error(f"Error verifying database connection: {e}")
        raise


def get_db() -> Generator[Session, None, None]:
    """
    Dependency function for FastAPI to get database session.
    Usage:
        @app.get("/items")
        def get_items(db: Session = Depends(get_db)):
            ...
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def get_db_session() -> Generator[Session, None, None]:
    """
    Context manager for database sessions.
    Usage:
        with get_db_session() as db:
            account = db.query(Account).filter(...).first()
    """
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def check_connection() -> bool:
    """Check if database connection is working"""
    try:
        with engine.connect() as conn:
            result = conn.execute(text("SELECT 1"))
            result.fetchone()  # Execute the query
        return True
    except Exception as e:
        logger.error(f"Database connection check failed: {e}")
        return False


async def check_connection_async() -> bool:
    """Async database connection check"""
    # For now, use synchronous check (asyncpg not required for SQLAlchemy)
    return check_connection()


def get_db_connection():
    """
    Get a raw psycopg2 database connection for direct SQL operations.
    Used by cloud_accounts_operations.py
    """
    import psycopg2

    # Extract connection parameters from database_url
    # Format: postgresql://user:password@host:port/database
    url_parts = database_url.replace("postgresql://", "").split("@")
    user_pass = url_parts[0].split(":")
    host_db = url_parts[1].split("/")
    host_port = host_db[0].split(":")

    return psycopg2.connect(
        host=host_port[0],
        port=int(host_port[1]) if len(host_port) > 1 else 5432,
        user=user_pass[0],
        password=user_pass[1],
        dbname=host_db[1].split("?")[0],  # Remove query params if any
        connect_timeout=10
    )

