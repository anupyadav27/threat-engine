"""
PostgreSQL Database Manager for Check Engine
Handles check results storage
"""
import os
import json
import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2.pool import SimpleConnectionPool
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse
import sys
import logging

# Import local database config
_engine_path = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, _engine_path)
from database.connection.database_config import get_database_config

logger = logging.getLogger(__name__)


def _parse_database_url(url: str) -> Dict[str, Any]:
    """Parse DATABASE_URL into host, port, database, user, password."""
    u = urlparse(url)
    if u.scheme not in ("postgresql", "postgres"):
        raise ValueError(f"Unsupported scheme: {u.scheme}")
    path = (u.path or "").lstrip("/")
    return {
        "host": u.hostname or "localhost",
        "port": u.port or 5432,
        "database": path or "postgres",
        "user": u.username or "postgres",
        "password": u.password or "",
    }


class DatabaseManager:
    """PostgreSQL database manager for Check Engine"""

    def __init__(self, db_config: Optional[Dict] = None):
        """
        Initialize database connection for check engine.
        
        Args:
            db_config: Optional override (for testing). Normally uses consolidated DB config.
        """
        # Get consolidated database config (required - no fallback)
        try:
            db_config_obj = get_database_config("check")
            # Convert to dict format for compatibility
            self.db_config = {
                "host": db_config_obj.host,
                "port": db_config_obj.port,
                "database": db_config_obj.database,
                "user": db_config_obj.username,
                "password": db_config_obj.password,
            }
            logger.info(f"Using consolidated check database: {db_config_obj.database} on {db_config_obj.host}")
        except Exception as e:
            logger.error(f"Failed to get consolidated DB config: {e}")
            raise RuntimeError("Consolidated database configuration is required. Cannot proceed without it.") from e
        
        # Allow override for testing
        if db_config is not None:
            self.db_config.update(db_config)
            logger.warning("Using provided db_config override (testing mode)")
        
        # Set schema search_path - use public schema for now
        self.search_path = os.getenv("DB_SCHEMA", "public")
        self.use_consolidated_db = True
        
        self.connection_pool = None
        self._init_pool()

    def _init_pool(self):
        """Initialize connection pool"""
        try:
            self.connection_pool = SimpleConnectionPool(
                1, 10,
                host=self.db_config["host"],
                port=self.db_config["port"],
                database=self.db_config["database"],
                user=self.db_config["user"],
                password=self.db_config["password"],
                options=f"-c search_path={self.search_path}"
            )
            logger.info("Database connection pool initialized (consolidated DB)")
        except Exception as e:
            logger.error(f"Failed to initialize connection pool: {e}")
            raise

    def _get_connection(self):
        """Get connection from pool"""
        if not self.connection_pool:
            self._init_pool()
        return self.connection_pool.getconn()

    def _return_connection(self, conn):
        """Return connection to pool"""
        if self.connection_pool:
            self.connection_pool.putconn(conn)

    # Customer Management (shared)
    def create_customer(self, customer_id: str, customer_name: str = None,
                       metadata: Dict = None) -> None:
        """Create or update customer"""
        conn = self._get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO customers (customer_id, customer_name, metadata)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (customer_id) 
                    DO UPDATE SET 
                        customer_name = EXCLUDED.customer_name,
                        metadata = EXCLUDED.metadata
                """, (customer_id, customer_name, json.dumps(metadata or {}) if metadata else None))
            conn.commit()
        finally:
            self._return_connection(conn)
    
    # Tenant Management (shared)
    def create_tenant(self, tenant_id: str, customer_id: str, provider: str,
                     tenant_name: str = None, metadata: Dict = None) -> None:
        """Create or update tenant"""
        conn = self._get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO tenants (tenant_id, customer_id, provider, tenant_name, metadata)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (tenant_id)
                    DO UPDATE SET
                        customer_id = EXCLUDED.customer_id,
                        provider = EXCLUDED.provider,
                        tenant_name = EXCLUDED.tenant_name,
                        metadata = EXCLUDED.metadata
                """, (
                    tenant_id, customer_id, provider, tenant_name,
                    json.dumps(metadata or {}) if metadata else None
                ))
            conn.commit()
        finally:
            self._return_connection(conn)
    
    # Scan Management (shared)
    def create_scan(self, scan_id: str, customer_id: str, tenant_id: str,
                   provider: str, hierarchy_id: str = None,
                   hierarchy_type: str = None, region: str = None,
                   service: str = None, scan_type: str = 'check',
                   metadata: Dict = None) -> None:
        """Create scan record"""
        conn = self._get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO scans
                    (scan_id, customer_id, tenant_id, provider, hierarchy_id, hierarchy_type,
                     region, service, scan_type, status, metadata)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    scan_id, customer_id, tenant_id, provider,
                    hierarchy_id, hierarchy_type, region, service,
                    scan_type, 'running',
                    json.dumps(metadata or {}) if metadata else None
                ))
            conn.commit()
        finally:
            self._return_connection(conn)
    
    def update_scan_status(self, scan_id: str, status: str) -> None:
        """Update scan status"""
        conn = self._get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE scans SET status = %s WHERE scan_id = %s
                """, (status, scan_id))
            conn.commit()
        finally:
            self._return_connection(conn)
    
    # Check Results Storage
    def store_check_result(self, scan_id: str, customer_id: str, tenant_id: str,
                          provider: str, rule_id: str, resource_arn: str = None,
                          resource_id: str = None, resource_type: str = None,
                          status: str = 'FAIL', checked_fields: List[str] = None,
                          finding_data: Dict = None, hierarchy_id: str = None,
                          hierarchy_type: str = None, resource_uid: str = None) -> None:
        """Store check result"""
        # For AWS: resource_uid = resource_arn if not provided
        if not resource_uid:
            resource_uid = resource_arn
        
        conn = self._get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO check_results
                    (scan_id, customer_id, tenant_id, provider, hierarchy_id, hierarchy_type,
                     rule_id, resource_arn, resource_uid, resource_id, resource_type, status,
                     checked_fields, finding_data)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    scan_id, customer_id, tenant_id, provider,
                    hierarchy_id, hierarchy_type, rule_id,
                    resource_arn, resource_uid, resource_id, resource_type, status,
                    json.dumps(checked_fields or []),
                    json.dumps(finding_data or {})
                ))
            conn.commit()
        finally:
            self._return_connection(conn)
    
    def export_check_results(self, scan_id: str) -> List[Dict]:
        """Export check results as JSON"""
        conn = self._get_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT * FROM check_results
                    WHERE scan_id = %s
                    ORDER BY rule_id, resource_uid
                """, (scan_id,))
                return [dict(row) for row in cur.fetchall()]
        finally:
            self._return_connection(conn)
    
    def query_check_results(self, scan_id: str = None, tenant_id: str = None,
                           rule_id: str = None, status: str = None,
                           resource_uid: str = None) -> List[Dict]:
        """Query check results"""
        conn = self._get_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                query = "SELECT * FROM check_results WHERE 1=1"
                params = []
                
                if scan_id:
                    query += " AND scan_id = %s"
                    params.append(scan_id)
                if tenant_id:
                    query += " AND tenant_id = %s"
                    params.append(tenant_id)
                if rule_id:
                    query += " AND rule_id = %s"
                    params.append(rule_id)
                if status:
                    query += " AND status = %s"
                    params.append(status)
                if resource_uid:
                    query += " AND resource_uid = %s"
                    params.append(resource_uid)
                
                query += " ORDER BY scan_id, rule_id, resource_uid"
                cur.execute(query, params)
                return [dict(row) for row in cur.fetchall()]
        finally:
            self._return_connection(conn)
    
    def close(self):
        """Close connection pool"""
        if self.connection_pool:
            self.connection_pool.closeall()
