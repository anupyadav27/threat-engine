"""
Rate Limiter — Task 0.3.13 [Seq 37 | BD]

Token-bucket rate limiter for external API calls. Enforces per-source
rate limits to prevent API blacklisting.

Rate limits:
  - GitHub GraphQL: 5000 points/hour
  - GitLab REST: 600/minute
  - NVD REST: 50/30s (free) → 5000/30s (keyed)
  - npm: unlimited
  - PyPI: 60/minute
  - Docker Hub: 200/6h (unauth) → higher with token
  - AbuseIPDB: 4000/24h
  - OTX: 100/hour

Dependencies:
  - Tasks 0.3.3-0.3.10 (all adapters)
"""

import asyncio
import logging
import time
from typing import Dict, Optional

logger = logging.getLogger("external_collector.rate_limiter")


class TokenBucket:
    """Token-bucket rate limiter for a single source.

    Tokens are added at a fixed rate. Each API call consumes one token.
    If no tokens are available, the caller waits until a token is refilled.

    Args:
        max_tokens: Maximum bucket capacity.
        refill_rate: Tokens added per second.
        name: Source name (for logging).
    """

    def __init__(
        self,
        max_tokens: int,
        refill_rate: float,
        name: str = "unknown",
    ) -> None:
        self.name = name
        self.max_tokens = max_tokens
        self._tokens = float(max_tokens)
        self._refill_rate = refill_rate
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    def _refill(self) -> None:
        """Add tokens based on elapsed time."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(
            self.max_tokens,
            self._tokens + elapsed * self._refill_rate,
        )
        self._last_refill = now

    async def acquire(self, tokens: int = 1) -> float:
        """Acquire tokens, waiting if necessary.

        Args:
            tokens: Number of tokens to acquire.

        Returns:
            Wait time in seconds (0 if no wait needed).
        """
        async with self._lock:
            self._refill()

            if self._tokens >= tokens:
                self._tokens -= tokens
                return 0.0

            # Calculate wait time for enough tokens
            deficit = tokens - self._tokens
            wait_time = deficit / self._refill_rate

            logger.debug(
                "Rate limit %s: waiting %.1fs for %d tokens (%.1f available)",
                self.name, wait_time, tokens, self._tokens,
            )

            await asyncio.sleep(wait_time)

            self._refill()
            self._tokens -= tokens
            return wait_time

    def try_acquire(self, tokens: int = 1) -> bool:
        """Try to acquire tokens without waiting.

        Args:
            tokens: Number of tokens to acquire.

        Returns:
            True if tokens were acquired, False otherwise.
        """
        self._refill()
        if self._tokens >= tokens:
            self._tokens -= tokens
            return True
        return False

    @property
    def available_tokens(self) -> float:
        """Current available tokens."""
        self._refill()
        return self._tokens


# Default rate limit configurations
# Format: {source: (max_tokens, refill_rate_per_second)}
DEFAULT_RATE_LIMITS: Dict[str, tuple] = {
    "github":       (5000, 5000 / 3600),          # 5000/hour
    "gitlab":       (600, 600 / 60),               # 600/minute
    "nvd_free":     (50, 50 / 30),                 # 50/30s
    "nvd_keyed":    (5000, 5000 / 30),             # 5000/30s
    "npm":          (1000, 1000 / 60),             # ~unlimited, self-imposed 1000/min
    "pypi":         (60, 60 / 60),                 # 60/minute
    "dockerhub":    (200, 200 / 21600),            # 200/6h
    "abuseipdb":    (4000, 4000 / 86400),          # 4000/24h
    "otx":          (100, 100 / 3600),             # 100/hour
    "crates":       (100, 100 / 60),               # Self-imposed 100/min
    "maven":        (100, 100 / 60),               # Self-imposed 100/min
}


class RateLimiter:
    """Manages rate limiters for all external API sources.

    Args:
        overrides: Optional dict of {source: (max_tokens, refill_rate)} overrides.
    """

    def __init__(
        self, overrides: Optional[Dict[str, tuple]] = None
    ) -> None:
        self._buckets: Dict[str, TokenBucket] = {}

        config = dict(DEFAULT_RATE_LIMITS)
        if overrides:
            config.update(overrides)

        for source, (max_tokens, refill_rate) in config.items():
            self._buckets[source] = TokenBucket(
                max_tokens=max_tokens,
                refill_rate=refill_rate,
                name=source,
            )

    async def acquire(self, source: str, tokens: int = 1) -> float:
        """Acquire rate limit tokens for a source.

        Args:
            source: API source name.
            tokens: Number of tokens to consume.

        Returns:
            Wait time in seconds.

        Raises:
            ValueError: If source is unknown.
        """
        bucket = self._buckets.get(source)
        if not bucket:
            logger.warning("No rate limiter for source '%s', allowing request", source)
            return 0.0
        return await bucket.acquire(tokens)

    def try_acquire(self, source: str, tokens: int = 1) -> bool:
        """Try to acquire tokens without waiting.

        Args:
            source: API source name.
            tokens: Number of tokens to consume.

        Returns:
            True if tokens acquired.
        """
        bucket = self._buckets.get(source)
        if not bucket:
            return True
        return bucket.try_acquire(tokens)

    def get_status(self) -> Dict[str, Dict[str, float]]:
        """Get rate limit status for all sources.

        Returns:
            Dict mapping source to {available, max, refill_rate}.
        """
        status: Dict[str, Dict[str, float]] = {}
        for source, bucket in self._buckets.items():
            status[source] = {
                "available": round(bucket.available_tokens, 1),
                "max": bucket.max_tokens,
                "refill_rate_per_sec": bucket._refill_rate,
            }
        return status

    def add_source(
        self, source: str, max_tokens: int, refill_rate: float
    ) -> None:
        """Add a new rate-limited source at runtime.

        Args:
            source: Source name.
            max_tokens: Bucket capacity.
            refill_rate: Tokens per second refill rate.
        """
        self._buckets[source] = TokenBucket(
            max_tokens=max_tokens,
            refill_rate=refill_rate,
            name=source,
        )
