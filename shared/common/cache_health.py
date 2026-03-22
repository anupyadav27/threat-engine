"""
Cache health monitoring for external data sources.

Monitors the freshness and completeness of critical caches:
- vuln_cache: NVD/CVE vulnerability data (max 7 days)
- threat_intel_ioc: Threat intelligence IOCs (max 3 days)
- package_metadata: npm/PyPI package metadata (max 30 days)

Usage::

    from shared.common.cache_health import CacheHealthMonitor

    monitor = CacheHealthMonitor(db_conn)
    status = monitor.check_all()
    # Returns: {"vuln_cache": {"status": "HEALTHY", "age_days": 1.2, ...}, ...}
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, asdict
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class CacheStatus(str, Enum):
    HEALTHY = "HEALTHY"
    STALE = "STALE"
    EMPTY = "EMPTY"
    ERROR = "ERROR"


@dataclass
class CacheHealthResult:
    cache_name: str
    status: CacheStatus
    row_count: int
    age_seconds: float
    age_days: float
    max_age_days: float
    min_rows_expected: int
    last_refresh: Optional[str]
    message: str

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d


# ── Cache definitions ─────────────────────────────────────────────────────────

CACHE_CONFIGS = {
    "vuln_cache": {
        "table": "vuln_cache",
        "timestamp_col": "last_updated",
        "max_age_days": 7,
        "min_rows": 10000,
        "description": "NVD/CVE vulnerability database",
    },
    "threat_intel_ioc": {
        "table": "threat_intel_ioc",
        "timestamp_col": "last_seen",
        "max_age_days": 3,
        "min_rows": 1000,
        "description": "Threat intelligence IOC feed",
    },
    "package_metadata": {
        "table": "package_metadata",
        "timestamp_col": "last_checked",
        "max_age_days": 30,
        "min_rows": 100,
        "description": "npm/PyPI package metadata",
    },
}


class CacheHealthMonitor:
    """Monitor freshness and completeness of external data caches.

    Args:
        db_conn: Database connection to the external collector DB
                 (threat_engine_external).
    """

    def __init__(self, db_conn):
        self.conn = db_conn

    def check_cache(self, cache_name: str) -> CacheHealthResult:
        """Check health of a single cache.

        Args:
            cache_name: One of 'vuln_cache', 'threat_intel_ioc', 'package_metadata'.

        Returns:
            CacheHealthResult with status and details.
        """
        config = CACHE_CONFIGS.get(cache_name)
        if not config:
            return CacheHealthResult(
                cache_name=cache_name,
                status=CacheStatus.ERROR,
                row_count=0,
                age_seconds=0,
                age_days=0,
                max_age_days=0,
                min_rows_expected=0,
                last_refresh=None,
                message=f"Unknown cache: {cache_name}",
            )

        table = config["table"]
        ts_col = config["timestamp_col"]
        max_age_days = config["max_age_days"]
        min_rows = config["min_rows"]

        try:
            cur = self.conn.cursor()

            # Count rows
            cur.execute(f"SELECT COUNT(*) FROM {table}")
            row_count = cur.fetchone()[0]

            if row_count == 0:
                return CacheHealthResult(
                    cache_name=cache_name,
                    status=CacheStatus.EMPTY,
                    row_count=0,
                    age_seconds=0,
                    age_days=0,
                    max_age_days=max_age_days,
                    min_rows_expected=min_rows,
                    last_refresh=None,
                    message=f"{config['description']} is empty — collection may have never run",
                )

            # Get most recent timestamp
            cur.execute(f"SELECT MAX({ts_col}) FROM {table}")
            last_refresh = cur.fetchone()[0]

            if last_refresh is None:
                age_seconds = float("inf")
                age_days = float("inf")
            else:
                # Convert to epoch for age calculation
                cur.execute(f"SELECT EXTRACT(EPOCH FROM NOW() - MAX({ts_col})) FROM {table}")
                age_seconds = cur.fetchone()[0] or 0
                age_days = age_seconds / 86400

            cur.close()

            # Determine status
            if age_days > max_age_days:
                status = CacheStatus.STALE
                message = (
                    f"{config['description']} is {age_days:.1f} days old "
                    f"(max allowed: {max_age_days} days)"
                )
            elif row_count < min_rows:
                status = CacheStatus.STALE
                message = (
                    f"{config['description']} has only {row_count} rows "
                    f"(expected at least {min_rows})"
                )
            else:
                status = CacheStatus.HEALTHY
                message = (
                    f"{config['description']}: {row_count} rows, "
                    f"{age_days:.1f} days old"
                )

            # Update Prometheus metrics
            try:
                from shared.common.metrics import set_cache_age, set_cache_row_count
                set_cache_age(cache_name, age_seconds)
                set_cache_row_count(cache_name, row_count)
            except Exception:
                pass  # Metrics may not be initialized

            return CacheHealthResult(
                cache_name=cache_name,
                status=status,
                row_count=row_count,
                age_seconds=age_seconds,
                age_days=round(age_days, 2),
                max_age_days=max_age_days,
                min_rows_expected=min_rows,
                last_refresh=str(last_refresh) if last_refresh else None,
                message=message,
            )

        except Exception as exc:
            logger.error("Cache health check failed cache=%s error=%s", cache_name, exc)
            return CacheHealthResult(
                cache_name=cache_name,
                status=CacheStatus.ERROR,
                row_count=0,
                age_seconds=0,
                age_days=0,
                max_age_days=max_age_days,
                min_rows_expected=min_rows,
                last_refresh=None,
                message=f"Health check error: {exc}",
            )

    def check_all(self) -> Dict[str, Dict]:
        """Check health of all configured caches.

        Returns:
            Dict mapping cache_name to health result dict.
        """
        results = {}
        for cache_name in CACHE_CONFIGS:
            result = self.check_cache(cache_name)
            results[cache_name] = result.to_dict()
        return results

    def is_ready(self) -> bool:
        """Check if all caches are healthy (for K8s readiness probe).

        Returns:
            True if all caches are HEALTHY, False otherwise.
        """
        for cache_name in CACHE_CONFIGS:
            result = self.check_cache(cache_name)
            if result.status != CacheStatus.HEALTHY:
                return False
        return True

    def get_stale_caches(self) -> List[str]:
        """Return list of cache names that are stale or empty."""
        stale = []
        for cache_name in CACHE_CONFIGS:
            result = self.check_cache(cache_name)
            if result.status in (CacheStatus.STALE, CacheStatus.EMPTY):
                stale.append(cache_name)
        return stale
