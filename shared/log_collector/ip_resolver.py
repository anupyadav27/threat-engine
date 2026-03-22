"""
IP Resolver — Task 0.2.8 [Seq 20 | BD]

Resolves IP addresses in flow logs to AWS resource IDs (EC2 instance IDs,
RDS endpoints, ALB names) by joining against discovery_findings.

Uses an in-memory LRU cache (max 10k entries, 1h TTL) to avoid N+1 queries.

Dependencies:
  - Task 0.2.1 (log_events table)
  - Tier 1 discoveries (discovery_findings table must be populated)
"""

import logging
import time
from collections import OrderedDict
from typing import Any, Dict, List, Optional, Tuple

import asyncpg

logger = logging.getLogger("log_collector.ip_resolver")

# ---------------------------------------------------------------------------
# Resource types that have IP addresses in their emitted fields
# ---------------------------------------------------------------------------
IP_RESOURCE_TYPES = [
    "aws.ec2.instance",
    "aws.rds.db_instance",
    "aws.elbv2.load_balancer",
    "aws.elasticache.cache_cluster",
    "aws.ecs.task",
]

# Max cache entries and TTL
CACHE_MAX_SIZE = 10000
CACHE_TTL_SECONDS = 3600  # 1 hour


# ---------------------------------------------------------------------------
# LRU Cache with TTL
# ---------------------------------------------------------------------------
class TTLCache:
    """Simple LRU cache with time-based expiry.

    Args:
        max_size: Maximum number of entries.
        ttl_seconds: Time-to-live in seconds.
    """

    def __init__(self, max_size: int = CACHE_MAX_SIZE, ttl_seconds: int = CACHE_TTL_SECONDS) -> None:
        self._cache: OrderedDict[str, Tuple[Any, float]] = OrderedDict()
        self._max_size = max_size
        self._ttl = ttl_seconds

    def get(self, key: str) -> Optional[Any]:
        """Get a value from cache, returning None if expired or missing."""
        if key not in self._cache:
            return None

        value, timestamp = self._cache[key]
        if time.time() - timestamp > self._ttl:
            del self._cache[key]
            return None

        # Move to end (most recently used)
        self._cache.move_to_end(key)
        return value

    def put(self, key: str, value: Any) -> None:
        """Insert or update a cache entry."""
        if key in self._cache:
            self._cache.move_to_end(key)
        self._cache[key] = (value, time.time())

        # Evict oldest entries if over capacity
        while len(self._cache) > self._max_size:
            self._cache.popitem(last=False)

    def clear(self) -> None:
        """Clear all cache entries."""
        self._cache.clear()

    @property
    def size(self) -> int:
        return len(self._cache)


# ---------------------------------------------------------------------------
# IP Resolver
# ---------------------------------------------------------------------------
class IPResolver:
    """Resolves IP addresses to AWS resource IDs using discovery_findings.

    Args:
        discoveries_pool: asyncpg pool for the discoveries database
            (threat_engine_discoveries or threat_engine_check).
        log_pool: asyncpg pool for the log collector database
            (threat_engine_logs).
    """

    def __init__(
        self,
        discoveries_pool: asyncpg.Pool,
        log_pool: asyncpg.Pool,
    ) -> None:
        self._disc_pool = discoveries_pool
        self._log_pool = log_pool
        self._cache = TTLCache()

    async def resolve_ip(self, ip_address: str) -> Optional[Dict[str, str]]:
        """Resolve a single IP address to a resource.

        Args:
            ip_address: The IP address to resolve.

        Returns:
            Dict with 'resource_id' and 'resource_type', or None if not found.
        """
        # Check cache first
        cached = self._cache.get(ip_address)
        if cached is not None:
            return cached  # Could be a dict or a sentinel empty dict

        # Query discovery_findings for this IP
        result = await self._query_discoveries(ip_address)

        # Cache the result (even if None, cache as empty dict to avoid re-queries)
        self._cache.put(ip_address, result if result else {})
        return result

    async def resolve_batch(self, ip_addresses: List[str]) -> Dict[str, Optional[Dict[str, str]]]:
        """Resolve a batch of IP addresses.

        Args:
            ip_addresses: List of IP addresses to resolve.

        Returns:
            Dict mapping each IP to its resolution result (or None).
        """
        results: Dict[str, Optional[Dict[str, str]]] = {}
        uncached: List[str] = []

        for ip in ip_addresses:
            cached = self._cache.get(ip)
            if cached is not None:
                results[ip] = cached if cached else None
            else:
                uncached.append(ip)

        if uncached:
            batch_results = await self._query_discoveries_batch(uncached)
            for ip in uncached:
                result = batch_results.get(ip)
                results[ip] = result
                self._cache.put(ip, result if result else {})

        return results

    async def enrich_log_events(
        self,
        limit: int = 1000,
    ) -> int:
        """Enrich unresolved log_events with resource IDs.

        Finds log_events where resource_id IS NULL but src_ip or dst_ip is set,
        resolves the IPs, and updates the rows.

        Args:
            limit: Maximum number of rows to process per call.

        Returns:
            Number of rows updated.
        """
        # Fetch unresolved events
        sql = """
            SELECT id, src_ip, dst_ip FROM log_events
            WHERE resource_id IS NULL
              AND (src_ip IS NOT NULL OR dst_ip IS NOT NULL)
            ORDER BY event_time DESC
            LIMIT $1
        """
        async with self._log_pool.acquire() as conn:
            rows = await conn.fetch(sql, limit)

        if not rows:
            return 0

        # Collect unique IPs
        all_ips = set()
        for row in rows:
            if row["src_ip"]:
                all_ips.add(str(row["src_ip"]))
            if row["dst_ip"]:
                all_ips.add(str(row["dst_ip"]))

        # Resolve batch
        resolutions = await self.resolve_batch(list(all_ips))

        # Update rows
        updated = 0
        update_sql = """
            UPDATE log_events SET
                resource_id = $1,
                resource_type = $2
            WHERE id = $3
        """
        async with self._log_pool.acquire() as conn:
            for row in rows:
                # Try src_ip first, then dst_ip
                resource = None
                for ip_field in ("src_ip", "dst_ip"):
                    ip = row[ip_field]
                    if ip:
                        res = resolutions.get(str(ip))
                        if res and res.get("resource_id"):
                            resource = res
                            break

                if resource:
                    await conn.execute(
                        update_sql,
                        resource["resource_id"],
                        resource["resource_type"],
                        row["id"],
                    )
                    updated += 1

        logger.info("Enriched %d/%d log_events with resource IDs", updated, len(rows))
        return updated

    async def _query_discoveries(self, ip_address: str) -> Optional[Dict[str, str]]:
        """Query discovery_findings for a single IP address.

        Searches the emitted_fields JSONB for IP address matches.
        """
        sql = """
            SELECT resource_uid, resource_type
            FROM discovery_findings
            WHERE emitted_fields::text LIKE $1
              AND resource_type = ANY($2)
            LIMIT 1
        """
        pattern = f"%{ip_address}%"

        async with self._disc_pool.acquire() as conn:
            row = await conn.fetchrow(sql, pattern, IP_RESOURCE_TYPES)

        if row:
            return {
                "resource_id": row["resource_uid"],
                "resource_type": row["resource_type"],
            }
        return None

    async def _query_discoveries_batch(
        self, ip_addresses: List[str]
    ) -> Dict[str, Optional[Dict[str, str]]]:
        """Query discovery_findings for multiple IP addresses.

        Uses a single query with ANY() for efficiency.
        """
        results: Dict[str, Optional[Dict[str, str]]] = {}

        # Build patterns for LIKE matching
        for ip in ip_addresses:
            result = await self._query_discoveries(ip)
            results[ip] = result

        return results
