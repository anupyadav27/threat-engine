"""
RuleCache — DB-primary rule cache for SecOps scanners.

On startup: full load from secops_rule_metadata into memory.
Before scans: check for DB changes via MAX(updated_at); reload if stale.
Scanners call get_rules(scanner) instead of loading JSON files.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from .db_config import get_connection

logger = logging.getLogger(__name__)


class RuleCache:
    """In-memory cache of secops_rule_metadata, keyed by scanner."""

    def __init__(self) -> None:
        self._cache: Dict[str, Dict[str, Any]] = {}  # scanner → {rule_id → metadata}
        self._last_sync: Optional[datetime] = None
        self._db_max_updated: Optional[datetime] = None

    # ------------------------------------------------------------------
    # Full load (startup)
    # ------------------------------------------------------------------

    def load_all(self) -> Dict[str, int]:
        """Full load from DB into memory. Returns scanner → count."""
        conn = get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT rule_id, scanner, raw_metadata
                    FROM secops_rule_metadata
                    WHERE status NOT IN ('deprecated', 'disabled')
                """)
                self._cache.clear()
                for row in cur.fetchall():
                    rule_id, scanner, meta = row[0], row[1], row[2]
                    if isinstance(meta, str):
                        meta = json.loads(meta)
                    self._cache.setdefault(scanner, {})[rule_id] = meta

                # Track latest updated_at for incremental checks
                cur.execute("SELECT MAX(updated_at) FROM secops_rule_metadata")
                result = cur.fetchone()
                self._db_max_updated = result[0] if result else None

            self._last_sync = datetime.now(timezone.utc)
            totals = {s: len(rules) for s, rules in self._cache.items()}
            total = sum(totals.values())
            logger.info(f"RuleCache: loaded {total} rules across {len(totals)} scanners")
            for scanner, count in sorted(totals.items(), key=lambda x: -x[1]):
                logger.info(f"  {scanner}: {count} rules")
            return totals
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Incremental refresh
    # ------------------------------------------------------------------

    def refresh_if_needed(self, scanner: Optional[str] = None) -> bool:
        """Check DB for changes since last sync. Reload if rules changed.

        Args:
            scanner: If provided, only refresh that scanner. None = check all.

        Returns:
            True if cache was refreshed, False if still fresh.
        """
        if not self._last_sync:
            self.load_all()
            return True

        conn = get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT MAX(updated_at) FROM secops_rule_metadata")
                result = cur.fetchone()
                current_max = result[0] if result else None

                if current_max and current_max != self._db_max_updated:
                    logger.info("RuleCache: DB rules changed, reloading...")
                    # Reload — close this conn first to avoid holding it
                    conn.close()
                    self.load_all()
                    return True

            return False
        except Exception:
            # If conn was already closed by load_all, ignore
            return False
        finally:
            try:
                conn.close()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Read (used by scanners)
    # ------------------------------------------------------------------

    def get_rules(self, scanner: str) -> Dict[str, Any]:
        """Return cached rules for a scanner.

        Args:
            scanner: Scanner name (python, terraform, java, etc.)

        Returns:
            dict[rule_id → metadata] — same format as load_rule_metadata().
        """
        if not self._cache:
            self.load_all()

        self.refresh_if_needed()
        return self._cache.get(scanner, {})

    @property
    def is_loaded(self) -> bool:
        return bool(self._cache)

    @property
    def total_rules(self) -> int:
        return sum(len(rules) for rules in self._cache.values())

    @property
    def scanner_counts(self) -> Dict[str, int]:
        return {s: len(rules) for s, rules in self._cache.items()}


# Module-level singleton — import and use directly
rule_cache = RuleCache()
