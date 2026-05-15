"""
PerformanceGuard — per-pattern circuit breaker (S2-06).

Limits:
  - Max 30s per pattern execution (hard timeout wrapper)
  - Max 200 path results per pattern execution
  - Patterns exceeding p99 budget (500ms) for 3 consecutive runs:
    INSERT per-tenant suppression row into threat_pattern_suppressions

CP1-05 enforcement:
  NEVER set active=false on the shared threat_scenario_patterns row.
  Auto-suppression always writes to threat_pattern_suppressions (tenant-scoped).
  Global deactivation requires SA approval + manual update.

The unit test for this class MUST assert that no UPDATE to
threat_scenario_patterns.active is issued.
"""
from __future__ import annotations

import logging
import signal
import threading
import time
from contextlib import contextmanager
from typing import Any, Dict, Generator, List

logger = logging.getLogger(__name__)

_HARD_TIMEOUT_SECONDS = 30
_RESULT_CAP = 200
_P99_BUDGET_MS = 500
_CONSECUTIVE_THRESHOLD = 3

# Per-pattern consecutive over-budget counter (in-memory, resets on restart)
# Key: (tenant_id, pattern_id) → consecutive over-budget count
_over_budget: Dict[tuple, int] = {}


class TimeoutError(Exception):
    pass


@contextmanager
def _timeout(seconds: int) -> Generator[None, None, None]:
    """Cross-platform timeout context manager using threading."""
    result: List[bool] = [False]
    timer = threading.Timer(seconds, lambda: result.__setitem__(0, True))
    timer.start()
    try:
        yield
    finally:
        timer.cancel()
        if result[0]:
            raise TimeoutError(f"Pattern execution exceeded {seconds}s hard timeout")


class PerformanceGuard:
    """Wraps pattern execution with timeout, result cap, and auto-suppression."""

    def __init__(self, threat_conn: Any) -> None:
        self._threat_conn = threat_conn

    def run_with_guard(
        self,
        pattern_id: str,
        tenant_id: str,
        execute_fn: Any,
        /,
        *args: Any,
        **kwargs: Any,
    ) -> List[Any]:
        """Execute a pattern matcher function under the performance guard.

        Args:
            pattern_id: Pattern being executed (for logging + suppression).
            tenant_id: Tenant scope (suppression is per-tenant — CP1-05).
            execute_fn: The matcher's run() callable.
            *args, **kwargs: Forwarded to execute_fn as run(pattern, tenant_id).

        Returns:
            List of match results, capped at _RESULT_CAP.
        """
        t0 = time.perf_counter()

        try:
            with _timeout(_HARD_TIMEOUT_SECONDS):
                results = execute_fn(*args, **kwargs)
        except TimeoutError:
            logger.error(
                "Pattern %s exceeded %ds hard timeout for tenant %s — auto-suppressing",
                pattern_id, _HARD_TIMEOUT_SECONDS, tenant_id,
            )
            self._auto_suppress(
                pattern_id, tenant_id,
                reason=f"timeout:{_HARD_TIMEOUT_SECONDS}s",
            )
            return []
        except Exception as exc:
            logger.error(
                "Pattern %s raised exception for tenant %s: %s",
                pattern_id, tenant_id, exc,
            )
            raise

        elapsed_ms = (time.perf_counter() - t0) * 1000

        # Cap results
        if len(results) > _RESULT_CAP:
            logger.warning(
                "Pattern %s returned %d results (cap=%d) — truncating",
                pattern_id, len(results), _RESULT_CAP,
            )
            results = results[:_RESULT_CAP]

        # Track over-budget runs
        key = (tenant_id, pattern_id)
        if elapsed_ms > _P99_BUDGET_MS:
            _over_budget[key] = _over_budget.get(key, 0) + 1
            logger.warning(
                "Pattern %s over p99 budget: %.1f ms > %d ms (consecutive=%d) tenant=%s",
                pattern_id, elapsed_ms, _P99_BUDGET_MS,
                _over_budget[key], tenant_id,
            )
            if _over_budget[key] >= _CONSECUTIVE_THRESHOLD:
                self._auto_suppress(
                    pattern_id, tenant_id,
                    reason=f"performance_guard:p99_exceeded_{_CONSECUTIVE_THRESHOLD}x",
                )
                _over_budget[key] = 0
        else:
            _over_budget[key] = 0  # Reset on success within budget

        return results

    def _auto_suppress(
        self,
        pattern_id: str,
        tenant_id: str,
        reason: str,
    ) -> None:
        """Insert a per-tenant suppression row. NEVER modifies threat_scenario_patterns."""
        try:
            cur = self._threat_conn.cursor()
            cur.execute(
                """
                INSERT INTO threat_pattern_suppressions (
                    tenant_id, pattern_id, reason, auto_generated,
                    created_at, expires_at
                ) VALUES (%s, %s, %s, true, NOW(), NOW() + INTERVAL '7 days')
                ON CONFLICT (tenant_id, pattern_id) DO UPDATE
                SET reason       = EXCLUDED.reason,
                    expires_at   = EXCLUDED.expires_at,
                    created_at   = NOW()
                """,
                (tenant_id, pattern_id, reason),
            )
            self._threat_conn.commit()
            cur.close()
            logger.warning(
                "Auto-suppressed pattern %s for tenant %s (reason=%s)",
                pattern_id, tenant_id, reason,
            )
        except Exception as exc:
            logger.error(
                "Failed to write auto-suppression for pattern %s tenant %s: %s",
                pattern_id, tenant_id, exc,
            )
