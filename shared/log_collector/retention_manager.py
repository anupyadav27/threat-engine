"""
Retention Manager — Task 0.2.9 [Seq 21 | BD]

Automatically deletes old log events beyond the retention window so that
tables don't grow unboundedly.

Schedule: Cron job running daily at 02:00 UTC (K8s CronJob).

Retention policy:
  - log_events (vpc_flow):        30 days
  - event_aggregations:           90 days
  - cloudtrail_events:            30 days
  - log_collection_status:        90 days

Dependencies:
  - Task 0.2.1 (tables exist)
"""

import asyncio
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Dict

import asyncpg

logger = logging.getLogger("log_collector.retention_manager")

# ---------------------------------------------------------------------------
# Retention policies (table → column → interval)
# ---------------------------------------------------------------------------
RETENTION_POLICIES = [
    {
        "table": "log_events",
        "column": "created_at",
        "interval": "30 days",
        "description": "Raw log events older than 30 days",
    },
    {
        "table": "event_aggregations",
        "column": "created_at",
        "interval": "90 days",
        "description": "Aggregations older than 90 days",
    },
    {
        "table": "cloudtrail_events",
        "column": "created_at",
        "interval": "30 days",
        "description": "CloudTrail/K8s audit events older than 30 days",
    },
    {
        "table": "log_collection_status",
        "column": "created_at",
        "interval": "90 days",
        "description": "Collection status records older than 90 days",
    },
]


class RetentionManager:
    """Manages data retention by deleting old records from log tables.

    Args:
        pool: asyncpg connection pool for threat_engine_logs.
        batch_size: Maximum rows to delete per batch (prevents long-running txns).
    """

    def __init__(self, pool: asyncpg.Pool, batch_size: int = 10000) -> None:
        self._pool = pool
        self._batch_size = batch_size

    async def run_cleanup(self) -> Dict[str, int]:
        """Execute retention cleanup for all tables.

        Returns:
            Dict mapping table name to total rows deleted.
        """
        logger.info("Starting retention cleanup at %s", datetime.now(timezone.utc).isoformat())
        results: Dict[str, int] = {}

        for policy in RETENTION_POLICIES:
            table = policy["table"]
            column = policy["column"]
            interval = policy["interval"]

            total_deleted = await self._cleanup_table(table, column, interval)
            results[table] = total_deleted

            if total_deleted > 0:
                logger.info(
                    "Retention cleanup: %s — deleted %d rows older than %s",
                    table, total_deleted, interval,
                )
            else:
                logger.info(
                    "Retention cleanup: %s — no rows to delete (interval=%s)",
                    table, interval,
                )

        logger.info("Retention cleanup complete: %s", results)
        return results

    async def _cleanup_table(
        self, table: str, column: str, interval: str
    ) -> int:
        """Delete old rows from a single table in batches.

        Uses batched deletes to avoid holding long locks on large tables.

        Args:
            table: Table name.
            column: Timestamp column for age comparison.
            interval: PostgreSQL interval string (e.g., '30 days').

        Returns:
            Total number of rows deleted.
        """
        total_deleted = 0

        while True:
            # Delete in batches using ctid for efficient sub-select
            sql = f"""
                DELETE FROM {table}
                WHERE ctid IN (
                    SELECT ctid FROM {table}
                    WHERE {column} < NOW() - INTERVAL '{interval}'
                    LIMIT $1
                )
            """
            async with self._pool.acquire() as conn:
                result = await conn.execute(sql, self._batch_size)

            # Parse "DELETE N" result
            try:
                count = int(result.split()[-1])
            except (ValueError, IndexError):
                count = 0

            total_deleted += count

            if count < self._batch_size:
                break  # No more rows to delete

            # Yield control between batches
            await asyncio.sleep(0.1)

        return total_deleted

    async def get_table_sizes(self) -> Dict[str, Dict[str, int]]:
        """Get row counts and estimated sizes for all log tables.

        Returns:
            Dict mapping table name to {'row_count': N, 'size_bytes': N}.
        """
        tables = [p["table"] for p in RETENTION_POLICIES]
        results: Dict[str, Dict[str, int]] = {}

        async with self._pool.acquire() as conn:
            for table in tables:
                row = await conn.fetchrow(
                    f"SELECT COUNT(*) as cnt FROM {table}"
                )
                size_row = await conn.fetchrow(
                    "SELECT pg_total_relation_size($1) as size",
                    table,
                )
                results[table] = {
                    "row_count": row["cnt"] if row else 0,
                    "size_bytes": size_row["size"] if size_row else 0,
                }

        return results


# ---------------------------------------------------------------------------
# Entrypoint (for K8s CronJob)
# ---------------------------------------------------------------------------
async def main() -> None:
    """Run retention cleanup as a standalone process."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    pool = await asyncpg.create_pool(
        host=os.environ.get("LOG_COLLECTOR_DB_HOST", "localhost"),
        port=int(os.environ.get("LOG_COLLECTOR_DB_PORT", "5432")),
        database=os.environ.get("LOG_COLLECTOR_DB_NAME", "threat_engine_logs"),
        user=os.environ.get("LOG_COLLECTOR_DB_USER", "postgres"),
        password=os.environ.get("LOG_COLLECTOR_DB_PASSWORD", ""),
        min_size=1,
        max_size=3,
    )

    try:
        manager = RetentionManager(pool)
        results = await manager.run_cleanup()
        total = sum(results.values())
        logger.info("Retention cleanup finished: %d total rows deleted", total)
    finally:
        await pool.close()


if __name__ == "__main__":
    asyncio.run(main())
