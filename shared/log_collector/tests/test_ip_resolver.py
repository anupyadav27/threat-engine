"""
Unit Tests — IP Resolver
Task 0.2.12 [Seq 24 | QA]

Tests: mock discovery_findings queries, caching behavior, batch resolution.
"""

import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from shared.log_collector.ip_resolver import (
    IPResolver,
    TTLCache,
)


# ---------------------------------------------------------------------------
# TTLCache tests
# ---------------------------------------------------------------------------
class TestTTLCache:
    def test_put_and_get(self):
        cache = TTLCache(max_size=100, ttl_seconds=60)
        cache.put("10.0.0.1", {"resource_id": "i-abc123", "resource_type": "aws.ec2.instance"})

        result = cache.get("10.0.0.1")
        assert result is not None
        assert result["resource_id"] == "i-abc123"

    def test_get_missing_key(self):
        cache = TTLCache()
        assert cache.get("192.168.1.1") is None

    def test_ttl_expiry(self):
        cache = TTLCache(max_size=100, ttl_seconds=0)  # 0s TTL = immediate expiry
        cache.put("10.0.0.1", {"resource_id": "i-abc123"})

        time.sleep(0.01)  # Ensure expiry
        assert cache.get("10.0.0.1") is None

    def test_max_size_eviction(self):
        cache = TTLCache(max_size=3, ttl_seconds=3600)

        cache.put("ip1", "val1")
        cache.put("ip2", "val2")
        cache.put("ip3", "val3")
        cache.put("ip4", "val4")  # Should evict ip1

        assert cache.get("ip1") is None
        assert cache.get("ip4") == "val4"
        assert cache.size == 3

    def test_clear(self):
        cache = TTLCache()
        cache.put("ip1", "val1")
        cache.put("ip2", "val2")
        cache.clear()
        assert cache.size == 0
        assert cache.get("ip1") is None

    def test_lru_ordering(self):
        cache = TTLCache(max_size=3, ttl_seconds=3600)

        cache.put("ip1", "val1")
        cache.put("ip2", "val2")
        cache.put("ip3", "val3")

        # Access ip1 to make it most recently used
        cache.get("ip1")

        # Add ip4 — should evict ip2 (least recently used)
        cache.put("ip4", "val4")

        assert cache.get("ip1") == "val1"  # Still present (was accessed)
        assert cache.get("ip2") is None     # Evicted
        assert cache.get("ip3") == "val3"
        assert cache.get("ip4") == "val4"


# ---------------------------------------------------------------------------
# IPResolver tests
# ---------------------------------------------------------------------------
class TestIPResolver:
    @pytest.fixture
    def mock_disc_pool(self):
        pool = AsyncMock()
        conn = AsyncMock()
        pool.acquire.return_value.__aenter__ = AsyncMock(return_value=conn)
        pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)

        # Default: return a matching resource
        conn.fetchrow.return_value = {
            "resource_uid": "i-0abc123def456",
            "resource_type": "aws.ec2.instance",
        }
        return pool

    @pytest.fixture
    def mock_log_pool(self):
        pool = AsyncMock()
        conn = AsyncMock()
        pool.acquire.return_value.__aenter__ = AsyncMock(return_value=conn)
        pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)
        return pool

    @pytest.mark.asyncio
    async def test_resolve_known_ip(self, mock_disc_pool, mock_log_pool):
        resolver = IPResolver(mock_disc_pool, mock_log_pool)
        result = await resolver.resolve_ip("10.0.0.5")

        assert result is not None
        assert result["resource_id"] == "i-0abc123def456"
        assert result["resource_type"] == "aws.ec2.instance"

    @pytest.mark.asyncio
    async def test_resolve_unknown_ip(self, mock_disc_pool, mock_log_pool):
        # Override to return None (no match)
        conn = AsyncMock()
        conn.fetchrow.return_value = None
        mock_disc_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=conn)

        resolver = IPResolver(mock_disc_pool, mock_log_pool)
        result = await resolver.resolve_ip("8.8.8.8")

        assert result is None

    @pytest.mark.asyncio
    async def test_caching_avoids_duplicate_queries(self, mock_disc_pool, mock_log_pool):
        resolver = IPResolver(mock_disc_pool, mock_log_pool)

        # First call — should query DB
        await resolver.resolve_ip("10.0.0.5")
        # Second call — should use cache
        await resolver.resolve_ip("10.0.0.5")

        conn = mock_disc_pool.acquire.return_value.__aenter__.return_value
        # fetchrow should only be called once (cached on second call)
        assert conn.fetchrow.call_count == 1

    @pytest.mark.asyncio
    async def test_resolve_batch(self, mock_disc_pool, mock_log_pool):
        resolver = IPResolver(mock_disc_pool, mock_log_pool)
        results = await resolver.resolve_batch(["10.0.0.1", "10.0.0.2", "10.0.0.3"])

        assert len(results) == 3
        for ip, result in results.items():
            assert result is not None
