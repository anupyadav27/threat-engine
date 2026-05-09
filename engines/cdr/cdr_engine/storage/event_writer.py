"""
Event Writer — watermark tracking for incremental CIEM log collection.

No raw events are written to DB. Each source's last-collected timestamp is
stored here so the next run resumes where the previous one left off.
"""

import logging
import os
from datetime import datetime
from typing import Optional

import psycopg2

logger = logging.getLogger(__name__)

CREATE_WATERMARK_DDL = """
CREATE TABLE IF NOT EXISTS cdr_collection_watermark (
    tenant_id    VARCHAR(256) NOT NULL,
    account_id   VARCHAR(256) NOT NULL,
    source_type  VARCHAR(50)  NOT NULL,
    watermark_at TIMESTAMPTZ  NOT NULL DEFAULT '1970-01-01',
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, account_id, source_type)
);
"""


class EventWriter:
    """Watermark store for CIEM incremental log collection."""

    def __init__(self, db_url: str = None):
        self.db_url = db_url or self._build_db_url()

    def _build_db_url(self) -> str:
        host = os.getenv("CDR_DB_HOST", os.getenv("DB_HOST", "localhost"))
        port = os.getenv("CDR_DB_PORT", os.getenv("DB_PORT", "5432"))
        name = os.getenv("CDR_DB_NAME", "threat_engine_cdr")
        user = os.getenv("CDR_DB_USER", os.getenv("DB_USER", "postgres"))
        pw = os.getenv("CDR_DB_PASSWORD", os.getenv("INVENTORY_DB_PASSWORD", os.getenv("DB_PASSWORD", "")))
        return f"postgresql://{user}:{pw}@{host}:{port}/{name}"

    def ensure_table(self):
        """Create cdr_collection_watermark table if not exists."""
        conn = psycopg2.connect(self.db_url)
        try:
            with conn.cursor() as cur:
                cur.execute(CREATE_WATERMARK_DDL)
            conn.commit()
        finally:
            conn.close()

    def get_watermark(self, tenant_id: str, account_id: str, source_type: str) -> Optional[datetime]:
        """Return the last collected watermark for this source, or None if first run."""
        conn = psycopg2.connect(self.db_url)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT watermark_at FROM cdr_collection_watermark
                    WHERE tenant_id = %s AND account_id = %s AND source_type = %s
                    """,
                    (tenant_id, account_id, source_type),
                )
                row = cur.fetchone()
            return row[0] if row else None
        except Exception as exc:
            logger.warning(f"get_watermark failed: {exc}")
            return None
        finally:
            conn.close()

    def update_watermark(self, tenant_id: str, account_id: str, source_type: str, watermark_at: datetime) -> None:
        """Advance the watermark to watermark_at after successful collection."""
        conn = psycopg2.connect(self.db_url)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO cdr_collection_watermark
                        (tenant_id, account_id, source_type, watermark_at, updated_at)
                    VALUES (%s, %s, %s, %s, NOW())
                    ON CONFLICT (tenant_id, account_id, source_type)
                    DO UPDATE SET watermark_at = EXCLUDED.watermark_at, updated_at = NOW()
                    """,
                    (tenant_id, account_id, source_type, watermark_at),
                )
            conn.commit()
            logger.info(f"Watermark updated: {source_type} → {watermark_at.isoformat()}")
        except Exception as exc:
            logger.warning(f"update_watermark failed: {exc}")
        finally:
            conn.close()
