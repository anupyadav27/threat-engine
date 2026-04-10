"""
Event Writer — stores normalized events to log_events table.

The table is partitioned by event_time for efficient time-range queries.
Downstream engines (threat, datasec, iam) query this table.
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Dict, List

import psycopg2
from psycopg2.extras import execute_values

from ..normalizer.schema import NormalizedEvent

logger = logging.getLogger(__name__)

# DDL for log_events table (run once)
CREATE_TABLE_DDL = """
CREATE TABLE IF NOT EXISTS log_events (
    event_id VARCHAR(64) PRIMARY KEY,
    scan_run_id VARCHAR(64),
    tenant_id VARCHAR(64),
    account_id VARCHAR(64),

    -- Classification
    category VARCHAR(50),
    source_type VARCHAR(30),
    severity VARCHAR(20) DEFAULT 'info',

    -- Time
    event_time TIMESTAMPTZ NOT NULL,
    ingestion_time TIMESTAMPTZ DEFAULT NOW(),

    -- Action
    service VARCHAR(100),
    operation VARCHAR(200),
    outcome VARCHAR(20),
    error_code VARCHAR(100),
    error_message TEXT,

    -- Actor
    actor_principal VARCHAR(500),
    actor_principal_type VARCHAR(50),
    actor_account_id VARCHAR(30),
    actor_ip VARCHAR(50),
    actor_user_agent TEXT,
    actor_geo_country VARCHAR(10),

    -- Resource
    resource_uid TEXT,
    resource_type VARCHAR(200),
    resource_name VARCHAR(500),
    resource_region VARCHAR(50),

    -- Network (for VPC flow, ALB)
    src_ip VARCHAR(50),
    dst_ip VARCHAR(50),
    src_port INTEGER,
    dst_port INTEGER,
    protocol VARCHAR(10),
    bytes_in BIGINT DEFAULT 0,
    bytes_out BIGINT DEFAULT 0,
    packets INTEGER DEFAULT 0,
    flow_action VARCHAR(10),

    -- HTTP (for ALB, CloudFront)
    http_method VARCHAR(10),
    http_url TEXT,
    http_status INTEGER,

    -- Enrichment
    asset_matched BOOLEAN DEFAULT FALSE,
    risk_indicators TEXT[],

    -- Source
    source_bucket VARCHAR(200),
    source_key TEXT,
    source_region VARCHAR(30),

    -- Raw
    raw_event JSONB
);

CREATE INDEX IF NOT EXISTS idx_log_events_time ON log_events (event_time);
CREATE INDEX IF NOT EXISTS idx_log_events_scan ON log_events (scan_run_id);
CREATE INDEX IF NOT EXISTS idx_log_events_tenant ON log_events (tenant_id);
CREATE INDEX IF NOT EXISTS idx_log_events_source ON log_events (source_type);
CREATE INDEX IF NOT EXISTS idx_log_events_resource ON log_events (resource_uid);
CREATE INDEX IF NOT EXISTS idx_log_events_actor ON log_events (actor_principal);
CREATE INDEX IF NOT EXISTS idx_log_events_severity ON log_events (severity) WHERE severity != 'info';
CREATE INDEX IF NOT EXISTS idx_log_events_category ON log_events (category);
"""


class EventWriter:
    """Write normalized events to log_events table."""

    def __init__(self, db_url: str = None):
        self.db_url = db_url or self._build_db_url()

    def _build_db_url(self) -> str:
        host = os.getenv("LOG_DB_HOST", os.getenv("INVENTORY_DB_HOST", os.getenv("DB_HOST", "localhost")))
        port = os.getenv("LOG_DB_PORT", os.getenv("INVENTORY_DB_PORT", os.getenv("DB_PORT", "5432")))
        name = os.getenv("LOG_DB_NAME", os.getenv("INVENTORY_DB_NAME", "threat_engine_inventory"))
        user = os.getenv("LOG_DB_USER", os.getenv("INVENTORY_DB_USER", os.getenv("DB_USER", "postgres")))
        pw = os.getenv("LOG_DB_PASSWORD", os.getenv("INVENTORY_DB_PASSWORD", os.getenv("DB_PASSWORD", "")))
        return f"postgresql://{user}:{pw}@{host}:{port}/{name}"

    def ensure_table(self):
        """Create log_events table if not exists."""
        conn = psycopg2.connect(self.db_url)
        try:
            with conn.cursor() as cur:
                cur.execute(CREATE_TABLE_DDL)
            conn.commit()
        finally:
            conn.close()

    def write_events(self, events: List[NormalizedEvent]) -> int:
        """Write batch of normalized events to DB.

        Returns number of events written.
        """
        if not events:
            return 0

        conn = psycopg2.connect(self.db_url)
        try:
            values = []
            for e in events:
                values.append((
                    e.event_id, e.scan_run_id, e.tenant_id,
                    e.actor.account_id or e.resource.account_id,
                    e.category, e.source_type, e.severity,
                    e.event_time, e.ingestion_time,
                    e.service, e.operation, e.outcome,
                    e.error_code, e.error_message,
                    e.actor.principal, e.actor.principal_type,
                    e.actor.account_id, e.actor.ip_address,
                    e.actor.user_agent, e.actor.geo_country,
                    e.resource.uid, e.resource.resource_type,
                    e.resource.name, e.resource.region,
                    e.network.src_ip if e.network else None,
                    e.network.dst_ip if e.network else None,
                    e.network.src_port if e.network else None,
                    e.network.dst_port if e.network else None,
                    e.network.protocol if e.network else None,
                    e.network.bytes_in if e.network else 0,
                    e.network.bytes_out if e.network else 0,
                    e.network.packets if e.network else 0,
                    e.network.flow_action if e.network else None,
                    e.http.method if e.http else None,
                    e.http.url if e.http else None,
                    e.http.status_code if e.http else None,
                    e.asset_matched,
                    e.risk_indicators or [],
                    e.source_bucket, e.source_key, e.source_region,
                    json.dumps(e.raw_event) if e.raw_event else "{}",
                ))

            with conn.cursor() as cur:
                execute_values(cur, """
                    INSERT INTO log_events (
                        event_id, scan_run_id, tenant_id, account_id,
                        category, source_type, severity,
                        event_time, ingestion_time,
                        service, operation, outcome,
                        error_code, error_message,
                        actor_principal, actor_principal_type,
                        actor_account_id, actor_ip, actor_user_agent, actor_geo_country,
                        resource_uid, resource_type, resource_name, resource_region,
                        src_ip, dst_ip, src_port, dst_port, protocol,
                        bytes_in, bytes_out, packets, flow_action,
                        http_method, http_url, http_status,
                        asset_matched, risk_indicators,
                        source_bucket, source_key, source_region,
                        raw_event
                    ) VALUES %s
                    ON CONFLICT (event_id) DO NOTHING
                """, values, page_size=1000)
            conn.commit()
            written = len(values)
            logger.info(f"EventWriter: wrote {written} events to log_events")
            return written
        except Exception as exc:
            logger.error(f"EventWriter failed: {exc}")
            conn.rollback()
            return 0
        finally:
            conn.close()

    def cleanup_old_events(self, tenant_id: str, keep_days: int = 30):
        """Delete events older than keep_days."""
        conn = psycopg2.connect(self.db_url)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM log_events WHERE tenant_id = %s AND event_time < NOW() - INTERVAL '%s days'",
                    (tenant_id, keep_days),
                )
                deleted = cur.rowcount
                if deleted:
                    logger.info(f"EventWriter: cleaned up {deleted} old events for {tenant_id}")
            conn.commit()
        finally:
            conn.close()
