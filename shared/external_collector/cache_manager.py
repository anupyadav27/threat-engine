"""
Cache Manager — Task 0.3.12 [Seq 36 | BD]

Manages cache refresh schedules and TTL expiration for vuln_cache,
package_metadata, and threat_intel_ioc tables.

TTL Policies:
  - vuln_cache: 24h refresh (NVD + EPSS + KEV daily)
  - package_metadata: 24h refresh
  - threat_intel_ioc: 6h refresh

Dependencies:
  - Tasks 0.3.6-0.3.10 (all adapters)
  - Task 0.3.1 (DB tables)
"""

import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Callable, Dict, List, Optional

import asyncpg

logger = logging.getLogger("external_collector.cache_manager")

# TTL configurations (in hours)
TTL_CONFIG = {
    "vuln_cache": 24,
    "package_metadata": 24,
    "threat_intel_ioc": 6,
}

# Staleness thresholds (beyond this, data is critically stale)
STALE_MULTIPLIER = 2  # 2x TTL = critically stale


class CacheManager:
    """Manages refresh schedules and staleness detection for external data.

    Args:
        pool: asyncpg connection pool for threat_engine_external.
    """

    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool
        self._refresh_callbacks: Dict[str, Callable] = {}
        self._running = False
        self._tasks: Dict[str, asyncio.Task] = {}

    def register_refresh(self, source: str, callback: Callable) -> None:
        """Register a refresh callback for a data source.

        Args:
            source: Source name (e.g., 'nvd', 'epss', 'kev', 'threat_intel').
            callback: Async callable that performs the refresh.
        """
        self._refresh_callbacks[source] = callback
        logger.info("Registered refresh callback for '%s'", source)

    async def get_cache_status(self) -> Dict[str, Any]:
        """Get freshness status for all cached data sources.

        Returns:
            Dict mapping table name to freshness info.
        """
        status: Dict[str, Any] = {}

        for table, ttl_hours in TTL_CONFIG.items():
            ttl_td = timedelta(hours=ttl_hours)
            stale_td = timedelta(hours=ttl_hours * STALE_MULTIPLIER)

            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(f"""
                    SELECT
                        COUNT(*) AS total_rows,
                        MAX(refreshed_at) AS latest_refresh,
                        MIN(refreshed_at) AS oldest_refresh,
                        COUNT(*) FILTER (
                            WHERE refreshed_at < NOW() - INTERVAL '{ttl_hours} hours'
                        ) AS stale_rows
                    FROM {table}
                """)

            latest = row["latest_refresh"]
            now = datetime.now(timezone.utc)

            freshness = "unknown"
            if latest:
                age = now - latest.replace(tzinfo=timezone.utc)
                if age < ttl_td:
                    freshness = "fresh"
                elif age < stale_td:
                    freshness = "stale"
                else:
                    freshness = "critically_stale"

            status[table] = {
                "total_rows": row["total_rows"],
                "latest_refresh": latest.isoformat() if latest else None,
                "oldest_refresh": row["oldest_refresh"].isoformat() if row["oldest_refresh"] else None,
                "stale_rows": row["stale_rows"],
                "ttl_hours": ttl_hours,
                "freshness": freshness,
            }

        return status

    async def refresh_source(self, source: str) -> Dict[str, Any]:
        """Trigger a refresh for a specific source.

        Args:
            source: Source name.

        Returns:
            Result dict from the refresh callback.
        """
        callback = self._refresh_callbacks.get(source)
        if not callback:
            return {"error": f"No refresh callback registered for '{source}'"}

        try:
            result = await callback()
            await self._update_collection_status(source, "completed", result)
            return result
        except Exception as exc:
            error_msg = str(exc)
            logger.error("Refresh failed for '%s': %s", source, exc, exc_info=True)
            await self._update_collection_status(source, "failed", {"error": error_msg})
            return {"error": error_msg}

    async def refresh_all(self) -> Dict[str, Any]:
        """Refresh all registered sources.

        Returns:
            Dict mapping source to refresh result.
        """
        results: Dict[str, Any] = {}
        for source in self._refresh_callbacks:
            results[source] = await self.refresh_source(source)
        return results

    async def start_scheduler(self) -> None:
        """Start background refresh scheduler.

        Schedules:
          - Daily 02:00 UTC: NVD bulk refresh
          - Daily 03:00 UTC: EPSS refresh
          - Daily 03:30 UTC: KEV refresh
          - Every 6h: Threat intel refresh
        """
        self._running = True
        logger.info("Cache manager scheduler started")

        # Launch periodic tasks
        self._tasks["daily_vuln"] = asyncio.create_task(
            self._periodic_refresh(["nvd", "epss", "kev"], interval_hours=24)
        )
        self._tasks["threat_intel"] = asyncio.create_task(
            self._periodic_refresh(["threat_intel"], interval_hours=6)
        )

    async def stop_scheduler(self) -> None:
        """Stop the background scheduler."""
        self._running = False
        for task in self._tasks.values():
            task.cancel()
        self._tasks.clear()
        logger.info("Cache manager scheduler stopped")

    async def _periodic_refresh(
        self, sources: List[str], interval_hours: int
    ) -> None:
        """Run periodic refresh for given sources."""
        interval = interval_hours * 3600

        while self._running:
            for source in sources:
                if source in self._refresh_callbacks:
                    try:
                        await self.refresh_source(source)
                    except Exception as exc:
                        logger.error("Periodic refresh error for '%s': %s", source, exc)

            await asyncio.sleep(interval)

    async def cleanup_expired(self) -> Dict[str, int]:
        """Remove expired entries beyond staleness threshold.

        Returns:
            Dict mapping table name to rows deleted.
        """
        deleted: Dict[str, int] = {}

        for table, ttl_hours in TTL_CONFIG.items():
            stale_hours = ttl_hours * STALE_MULTIPLIER * 2  # 4x TTL for hard delete

            async with self._pool.acquire() as conn:
                result = await conn.execute(f"""
                    DELETE FROM {table}
                    WHERE refreshed_at < NOW() - INTERVAL '{stale_hours} hours'
                """)
                count = int(result.split()[-1]) if result else 0
                deleted[table] = count

            if count > 0:
                logger.info("Cleaned up %d expired rows from %s", count, table)

        return deleted

    async def _update_collection_status(
        self, source: str, status: str, result: Dict[str, Any]
    ) -> None:
        """Update external_collection_status table."""
        sql = """
            INSERT INTO external_collection_status (
                source_type, status, last_run_at, result_summary
            ) VALUES ($1, $2, NOW(), $3::jsonb)
            ON CONFLICT (source_type)
            DO UPDATE SET
                status = EXCLUDED.status,
                last_run_at = NOW(),
                result_summary = EXCLUDED.result_summary
        """
        try:
            import json
            async with self._pool.acquire() as conn:
                await conn.execute(sql, source, status, json.dumps(result))
        except Exception as exc:
            logger.error("Failed to update collection status for '%s': %s", source, exc)
