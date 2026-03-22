"""
Unit Tests — Cache Manager
Task 0.3.17 [Seq 41 | QA]

Tests: TTL expiration, refresh scheduling, staleness detection.
"""

from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from shared.external_collector.cache_manager import CacheManager, TTL_CONFIG


class TestCacheManager:
    @pytest.fixture
    def mock_pool(self):
        pool = AsyncMock()
        conn = AsyncMock()
        pool.acquire.return_value.__aenter__ = AsyncMock(return_value=conn)
        pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)
        return pool

    def test_register_refresh(self, mock_pool):
        cm = CacheManager(pool=mock_pool)
        callback = AsyncMock(return_value={"ok": True})
        cm.register_refresh("nvd", callback)
        assert "nvd" in cm._refresh_callbacks

    @pytest.mark.asyncio
    async def test_refresh_source_success(self, mock_pool):
        cm = CacheManager(pool=mock_pool)
        callback = AsyncMock(return_value={"cves_stored": 100})
        cm.register_refresh("nvd", callback)

        result = await cm.refresh_source("nvd")
        assert result["cves_stored"] == 100
        callback.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_refresh_source_not_registered(self, mock_pool):
        cm = CacheManager(pool=mock_pool)
        result = await cm.refresh_source("unknown_source")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_refresh_source_failure(self, mock_pool):
        cm = CacheManager(pool=mock_pool)
        callback = AsyncMock(side_effect=Exception("API down"))
        cm.register_refresh("nvd", callback)

        result = await cm.refresh_source("nvd")
        assert "error" in result
        assert "API down" in result["error"]

    @pytest.mark.asyncio
    async def test_refresh_all(self, mock_pool):
        cm = CacheManager(pool=mock_pool)
        cm.register_refresh("nvd", AsyncMock(return_value={"ok": True}))
        cm.register_refresh("epss", AsyncMock(return_value={"ok": True}))

        result = await cm.refresh_all()
        assert "nvd" in result
        assert "epss" in result

    @pytest.mark.asyncio
    async def test_get_cache_status(self, mock_pool):
        conn = mock_pool.acquire.return_value.__aenter__.return_value
        conn.fetchrow.return_value = {
            "total_rows": 1000,
            "latest_refresh": datetime.now(timezone.utc),
            "oldest_refresh": datetime.now(timezone.utc) - timedelta(hours=12),
            "stale_rows": 50,
        }

        cm = CacheManager(pool=mock_pool)
        status = await cm.get_cache_status()

        assert "vuln_cache" in status
        assert "threat_intel_ioc" in status

    def test_ttl_config(self):
        assert TTL_CONFIG["vuln_cache"] == 24
        assert TTL_CONFIG["package_metadata"] == 24
        assert TTL_CONFIG["threat_intel_ioc"] == 6

    @pytest.mark.asyncio
    async def test_cleanup_expired(self, mock_pool):
        conn = mock_pool.acquire.return_value.__aenter__.return_value
        conn.execute.return_value = "DELETE 50"

        cm = CacheManager(pool=mock_pool)
        deleted = await cm.cleanup_expired()

        assert isinstance(deleted, dict)
        assert "vuln_cache" in deleted
