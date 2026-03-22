"""
Unit Tests — Rate Limiter
Task 0.3.17 [Seq 41 | QA]

Tests: token bucket, per-source limits, acquire/try_acquire.
"""

import asyncio
import time

import pytest

from shared.external_collector.rate_limiter import (
    DEFAULT_RATE_LIMITS,
    RateLimiter,
    TokenBucket,
)


class TestTokenBucket:
    def test_initial_tokens(self):
        bucket = TokenBucket(max_tokens=100, refill_rate=10.0, name="test")
        assert bucket.available_tokens == 100.0

    def test_try_acquire_success(self):
        bucket = TokenBucket(max_tokens=10, refill_rate=1.0, name="test")
        assert bucket.try_acquire(1) is True
        assert bucket.available_tokens < 10

    def test_try_acquire_insufficient(self):
        bucket = TokenBucket(max_tokens=1, refill_rate=0.01, name="test")
        bucket.try_acquire(1)  # Consume the only token
        assert bucket.try_acquire(1) is False

    @pytest.mark.asyncio
    async def test_acquire_no_wait(self):
        bucket = TokenBucket(max_tokens=100, refill_rate=10.0, name="test")
        wait = await bucket.acquire(1)
        assert wait == 0.0

    @pytest.mark.asyncio
    async def test_acquire_with_wait(self):
        bucket = TokenBucket(max_tokens=1, refill_rate=100.0, name="test")
        await bucket.acquire(1)  # Consume token
        start = time.monotonic()
        await bucket.acquire(1)  # Should wait briefly
        elapsed = time.monotonic() - start
        assert elapsed < 0.5  # Should be very short with 100/s refill

    def test_refill(self):
        bucket = TokenBucket(max_tokens=10, refill_rate=1000.0, name="test")
        bucket.try_acquire(5)
        time.sleep(0.01)
        tokens = bucket.available_tokens
        assert tokens > 5.0  # Should have refilled some

    def test_max_cap(self):
        bucket = TokenBucket(max_tokens=10, refill_rate=1000.0, name="test")
        time.sleep(0.1)
        assert bucket.available_tokens <= 10.0


class TestRateLimiter:
    def test_default_sources(self):
        limiter = RateLimiter()
        status = limiter.get_status()
        assert "github" in status
        assert "nvd_free" in status
        assert "abuseipdb" in status

    def test_custom_overrides(self):
        limiter = RateLimiter(overrides={"custom_api": (100, 10.0)})
        status = limiter.get_status()
        assert "custom_api" in status
        assert status["custom_api"]["max"] == 100

    @pytest.mark.asyncio
    async def test_acquire_known_source(self):
        limiter = RateLimiter()
        wait = await limiter.acquire("github")
        assert wait == 0.0

    @pytest.mark.asyncio
    async def test_acquire_unknown_source(self):
        limiter = RateLimiter()
        wait = await limiter.acquire("nonexistent_api")
        assert wait == 0.0  # Unknown sources are allowed through

    def test_try_acquire(self):
        limiter = RateLimiter()
        assert limiter.try_acquire("github") is True

    def test_add_source(self):
        limiter = RateLimiter()
        limiter.add_source("new_api", max_tokens=50, refill_rate=1.0)
        status = limiter.get_status()
        assert "new_api" in status

    def test_default_rate_limits_coverage(self):
        assert "github" in DEFAULT_RATE_LIMITS
        assert "gitlab" in DEFAULT_RATE_LIMITS
        assert "nvd_free" in DEFAULT_RATE_LIMITS
        assert "dockerhub" in DEFAULT_RATE_LIMITS
        assert "abuseipdb" in DEFAULT_RATE_LIMITS
