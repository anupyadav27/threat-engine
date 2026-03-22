"""
PostgreSQL Database Manager — Check Engine

Writes to:   check_report (scan metadata)
             check_findings (PASS/FAIL/ERROR per rule per resource)

All config is read from CHECK_DB_* environment variables (set via ConfigMap +
ExternalSecret in Kubernetes). No hardcoded credentials.
"""

import os
import json
import logging
import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2.pool import SimpleConnectionPool
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class DatabaseManager:
    """PostgreSQL database manager for Check Engine."""

    def __init__(self, db_config: Optional[Dict] = None):
        """
        Initialize connection pool.

        Args:
            db_config: Optional override dict (testing only).
                       Production config comes from CHECK_DB_* env vars.
        """
        self.db_config: Dict[str, Any] = {
            "host":     os.getenv("CHECK_DB_HOST",     "localhost"),
            "port":     int(os.getenv("CHECK_DB_PORT", "5432")),
            "database": os.getenv("CHECK_DB_NAME",     "threat_engine_check"),
            "user":     os.getenv("CHECK_DB_USER",     "check_user"),
            "password": os.getenv("CHECK_DB_PASSWORD", ""),
        }
        if db_config:
            self.db_config.update(db_config)
            logger.warning("Using db_config override (testing mode)")

        logger.info(
            "Check DB: %s on %s:%s",
            self.db_config["database"],
            self.db_config["host"],
            self.db_config["port"],
        )
        self.connection_pool: Optional[SimpleConnectionPool] = None
        self._init_pool()

    # ── Connection pool ───────────────────────────────────────────────────────

    def _init_pool(self) -> None:
        min_c = int(os.getenv("DB_POOL_MIN", "1"))
        max_c = int(os.getenv("DB_POOL_MAX", "10"))
        try:
            self.connection_pool = SimpleConnectionPool(
                min_c, max_c,
                host=self.db_config["host"],
                port=self.db_config["port"],
                database=self.db_config["database"],
                user=self.db_config["user"],
                password=self.db_config["password"],
                connect_timeout=10,
            )
            logger.info("DB pool initialised (min=%d, max=%d)", min_c, max_c)
        except Exception as exc:
            logger.error("Failed to init connection pool: %s", exc)
            raise

    def _get_connection(self):
        if not self.connection_pool:
            self._init_pool()
        return self.connection_pool.getconn()

    def _return_connection(self, conn) -> None:
        if self.connection_pool and conn:
            self.connection_pool.putconn(conn)

    # ── Info / health ─────────────────────────────────────────────────────────

    def get_database_info(self) -> Dict[str, Any]:
        """Return connection info (never includes password)."""
        return {
            "host":     self.db_config.get("host"),
            "database": self.db_config.get("database"),
            "user":     self.db_config.get("user"),
        }

    def test_connection(self) -> None:
        """Raise if the database is unreachable."""
        conn = self._get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
        finally:
            self._return_connection(conn)

    # ── Scan management ───────────────────────────────────────────────────────

    def create_scan(
        self,
        scan_id: str,
        customer_id: str,
        tenant_id: str,
        provider: str,
        account_id: str = None,
        hierarchy_type: str = None,
        region: str = None,
        service: str = None,
        scan_type: str = "check",
        metadata: Dict = None,
        discovery_scan_run_id: str = None,
    ) -> None:
        """Insert a check_report row (status = 'running')."""
        conn = self._get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO check_report
                        (scan_run_id, customer_id, tenant_id, provider,
                         account_id, hierarchy_type, region, service,
                         scan_type, status, metadata, discovery_scan_run_id)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (scan_run_id) DO NOTHING
                    """,
                    (
                        scan_id, customer_id, tenant_id, provider,
                        account_id, hierarchy_type, region, service,
                        scan_type, "running",
                        json.dumps(metadata or {}),
                        discovery_scan_run_id,
                    ),
                )
            conn.commit()
        finally:
            self._return_connection(conn)

    def update_scan_status(self, scan_id: str, status: str) -> None:
        """Update check_report.status."""
        conn = self._get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE check_report SET status = %s WHERE scan_run_id = %s",
                    (status, scan_id),
                )
            conn.commit()
        finally:
            self._return_connection(conn)

    # ── Finding storage ───────────────────────────────────────────────────────

    def store_check_result(
        self,
        scan_id: str,
        customer_id: str,
        tenant_id: str,
        provider: str,
        account_id: str,
        hierarchy_type: str,
        rule_id: str,
        service: str = None,
        discovery_id: str = None,
        region: str = None,
        resource_arn: str = None,
        resource_uid: str = None,
        resource_id: str = None,
        resource_type: str = None,
        resource_service: str = None,
        status: str = None,
        checked_fields: List[str] = None,
        actual_values: Dict = None,
        finding_data: Dict = None,
    ) -> None:
        """Insert one row into check_findings."""
        resource_uid = resource_uid or resource_arn
        conn = self._get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO check_findings
                        (scan_run_id, customer_id, tenant_id, provider,
                         account_id, hierarchy_type, rule_id,
                         service, discovery_id, region,
                         resource_uid, resource_id, resource_type,
                         resource_service,
                         status, checked_fields, actual_values, finding_data)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (
                        scan_id, customer_id, tenant_id, provider,
                        account_id, hierarchy_type, rule_id,
                        service, discovery_id, region,
                        resource_uid, resource_id, resource_type,
                        resource_service,
                        status,
                        json.dumps(checked_fields or []),
                        json.dumps(actual_values or {}),
                        json.dumps(finding_data or {}),
                    ),
                )
            conn.commit()
        finally:
            self._return_connection(conn)

    # ── Query ─────────────────────────────────────────────────────────────────

    def export_check_results(self, scan_id: str) -> List[Dict]:
        """Return all check_findings rows for a scan."""
        conn = self._get_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM check_findings WHERE scan_run_id = %s ORDER BY first_seen_at",
                    (scan_id,),
                )
                return [dict(r) for r in cur.fetchall()]
        finally:
            self._return_connection(conn)

    def query_check_results(
        self,
        scan_id: str = None,
        tenant_id: str = None,
        rule_id: str = None,
        status: str = None,
        resource_uid: str = None,
    ) -> List[Dict]:
        """Flexible parameterised query against check_findings."""
        filters: List[str] = []
        params: List[Any] = []
        if scan_id:
            filters.append("scan_run_id = %s"); params.append(scan_id)
        if tenant_id:
            filters.append("tenant_id = %s"); params.append(tenant_id)
        if rule_id:
            filters.append("rule_id = %s"); params.append(rule_id)
        if status:
            filters.append("status = %s"); params.append(status)
        if resource_uid:
            filters.append("resource_uid = %s"); params.append(resource_uid)
        where = ("WHERE " + " AND ".join(filters)) if filters else ""
        conn = self._get_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    f"SELECT * FROM check_findings {where} ORDER BY first_seen_at DESC",
                    params,
                )
                return [dict(r) for r in cur.fetchall()]
        finally:
            self._return_connection(conn)

    def close(self) -> None:
        if self.connection_pool:
            self.connection_pool.closeall()
