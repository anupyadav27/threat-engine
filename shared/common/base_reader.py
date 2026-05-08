"""
Base DB reader — lazy connection management and safe-fetch helper.

All domain engine readers subclass this instead of reimplementing
_ensure_conn / rollback / logging boilerplate.

Usage:
    from engine_common.base_reader import BaseDBReader
    from engine_common.db_connections import get_check_conn

    class MyReader(BaseDBReader):
        def __init__(self):
            super().__init__(get_check_conn)

        def load_something(self, scan_run_id, tenant_id):
            return self._safe_fetch(
                "SELECT ... FROM t WHERE scan_run_id = %s AND tenant_id = %s",
                (scan_run_id, tenant_id),
                label=f"something for scan {scan_run_id}",
            )
"""

import logging
from typing import Any, Callable, Dict, List

from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)


class BaseDBReader:
    def __init__(self, conn_factory: Callable):
        self._conn_factory = conn_factory
        self.conn = None

    def _ensure_conn(self):
        if self.conn is None or self.conn.closed:
            self.conn = self._conn_factory()

    def _safe_fetch(
        self,
        query: str,
        params,
        label: str = "rows",
    ) -> List[Dict[str, Any]]:
        """Execute a SELECT query and return list of dicts.

        On any exception: logs the error, rolls back the connection,
        and returns [] so callers always get a usable value.
        """
        self._ensure_conn()
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(query, params)
                rows = cur.fetchall()
                logger.info("Loaded %d %s", len(rows), label)
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error("Failed to load %s: %s", label, e, exc_info=True)
            if self.conn and not self.conn.closed:
                self.conn.rollback()
            return []

    def _safe_fetch_one(
        self,
        query: str,
        params,
        label: str = "row",
    ) -> Dict[str, Any]:
        """Execute a SELECT and return first row as dict, or {}."""
        rows = self._safe_fetch(query, params, label)
        return rows[0] if rows else {}

    def close(self):
        if self.conn and not self.conn.closed:
            self.conn.close()
