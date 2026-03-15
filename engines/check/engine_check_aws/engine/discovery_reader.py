"""
Discovery Reader for Check Engine
Reads discoveries from the discoveries database (cross-engine integration)
"""
import os
import sys
import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2.pool import SimpleConnectionPool
from typing import Dict, List, Any, Optional
import logging
import json

# Import discoveries database config
_engine_path = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, _engine_path)

logger = logging.getLogger(__name__)


class DiscoveryReader:
    """Reads discoveries from the discoveries database"""
    
    def __init__(self, db_config: Optional[Dict] = None):
        """
        Initialize discovery reader with discoveries database connection
        
        Args:
            db_config: Optional override (for testing). Normally uses consolidated DB config.
        """
        # Use environment variables directly (cross-engine: reading from discoveries DB)
        # Prefer DISCOVERY_DB_* (singular, standardized) with DISCOVERIES_DB_* fallback
        self.db_config = {
            "host": os.getenv("DISCOVERY_DB_HOST", os.getenv("DISCOVERIES_DB_HOST", "localhost")),
            "port": int(os.getenv("DISCOVERY_DB_PORT", os.getenv("DISCOVERIES_DB_PORT", "5432"))),
            "database": os.getenv("DISCOVERY_DB_NAME", os.getenv("DISCOVERIES_DB_NAME", "threat_engine_discoveries")),
            "user": os.getenv("DISCOVERY_DB_USER", os.getenv("DISCOVERIES_DB_USER", "discoveries_user")),
            "password": os.getenv("DISCOVERY_DB_PASSWORD", os.getenv("DISCOVERIES_DB_PASSWORD", "discoveries_password")),
        }
        logger.info(f"DiscoveryReader: Using discoveries database: {self.db_config['database']} on {self.db_config['host']}")
        
        # Allow override for testing
        if db_config is not None:
            self.db_config.update(db_config)
            logger.warning("Using provided db_config override (testing mode)")
        
        self.connection_pool = None
        self._init_pool()

    def _init_pool(self):
        """Initialize connection pool"""
        try:
            self.connection_pool = SimpleConnectionPool(
                1, 5,
                host=self.db_config["host"],
                port=self.db_config["port"],
                database=self.db_config["database"],
                user=self.db_config["user"],
                password=self.db_config["password"],
                connect_timeout=10,
            )
            logger.info("DiscoveryReader: Connection pool initialized")
        except Exception as e:
            logger.warning(f"DiscoveryReader: Failed to init pool, will use direct connections: {e}")
            self.connection_pool = None

    def _get_connection(self):
        """Get database connection from pool"""
        if self.connection_pool:
            return self.connection_pool.getconn()
        return psycopg2.connect(
            host=self.db_config["host"],
            port=self.db_config["port"],
            database=self.db_config["database"],
            user=self.db_config["user"],
            password=self.db_config["password"],
            connect_timeout=10,
        )

    def _return_connection(self, conn):
        """Return connection to pool"""
        if self.connection_pool:
            self.connection_pool.putconn(conn)
        else:
            conn.close()
    
    def read_discovery_records(self, discovery_id: str, tenant_id: str,
                              hierarchy_id: str, scan_id: Optional[str] = None,
                              service: Optional[str] = None) -> List[Dict]:
        """
        Read discovery records from discoveries database

        Args:
            discovery_id: Discovery ID (e.g., 'aws.s3.list_buckets')
            tenant_id: Tenant ID
            hierarchy_id: Hierarchy ID (account_id, etc.) - IGNORED if scan_id provided
            scan_id: Discovery scan ID to filter by (PREFERRED - scopes to specific scan)
            service: Optional service name to filter

        Returns:
            List of discovery items with emitted_fields
        """
        conn = None
        try:
            conn = self._get_connection()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # ARCHITECTURE: Use discovery_scan_id to scope the query (preferred)
                # This ensures we only get discoveries from the specific scan run
                if scan_id:
                    # PREFERRED: Filter by discovery_scan_id (most precise)
                    query = """
                        SELECT DISTINCT ON (resource_uid)
                            resource_uid as resource_uid,

                            resource_id,
                            emitted_fields,
                            service,
                            region,
                            discovery_id,
                            discovery_scan_id,
                            hierarchy_id,
                            tenant_id
                        FROM discovery_findings
                        WHERE discovery_id = %s
                          AND discovery_scan_id = %s
                    """
                    params = [discovery_id, scan_id]
                else:
                    # FALLBACK: Filter by tenant_id + hierarchy_id (gets latest across all scans)
                    logger.warning(f"No scan_id provided for discovery_id={discovery_id}, using tenant_id + hierarchy_id filter (may return stale data)")
                    query = """
                        SELECT DISTINCT ON (resource_uid)
                            resource_uid as resource_uid,

                            resource_id,
                            emitted_fields,
                            service,
                            region,
                            discovery_id,
                            discovery_scan_id,
                            hierarchy_id,
                            tenant_id
                        FROM discovery_findings
                        WHERE discovery_id = %s
                          AND tenant_id = %s
                          AND hierarchy_id = %s
                    """
                    params = [discovery_id, tenant_id, hierarchy_id]

                if service:
                    query += " AND service = %s"
                    params.append(service)

                query += " ORDER BY resource_uid, scan_timestamp DESC"

                cur.execute(query, params)
                rows = cur.fetchall()

                # Convert to list of dicts and parse JSON fields
                items = []
                for row in rows:
                    item = dict(row)
                    # Parse emitted_fields JSONB
                    if item.get('emitted_fields'):
                        if isinstance(item['emitted_fields'], str):
                            item['emitted_fields'] = json.loads(item['emitted_fields'])
                        # emitted_fields is already a dict if from RealDictCursor

                    items.append(item)

                logger.info(f"[DiscoveryReader] Read {len(items)} discovery records for discovery_id={discovery_id}, scan_id={scan_id}")
                return items
                
        except Exception as e:
            logger.error(f"Failed to read discoveries from database: {e}", exc_info=True)
            return []
        finally:
            if conn:
                self._return_connection(conn)
    
    def get_discovery_scan_info(self, scan_id: str) -> Optional[Dict]:
        """Get discovery scan information"""
        conn = None
        try:
            conn = self._get_connection()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT discovery_scan_id, customer_id, tenant_id, provider,
                           hierarchy_id, hierarchy_type, status, scan_timestamp
                    FROM discovery_report
                    WHERE discovery_scan_id = %s AND scan_type = 'discovery'
                """, (scan_id,))
                row = cur.fetchone()
                return dict(row) if row else None
        except Exception as e:
            logger.error(f"Failed to get scan info: {e}")
            return None
        finally:
            if conn:
                self._return_connection(conn)
    
    def list_available_scans(self, tenant_id: str, hierarchy_id: Optional[str] = None) -> List[Dict]:
        """List available discovery scans"""
        conn = None
        try:
            conn = self._get_connection()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                query = """
                    SELECT discovery_scan_id, customer_id, tenant_id, provider,
                           hierarchy_id, hierarchy_type, status, scan_timestamp
                    FROM discovery_report
                    WHERE tenant_id = %s AND scan_type = 'discovery'
                """
                params = [tenant_id]
                
                if hierarchy_id:
                    query += " AND hierarchy_id = %s"
                    params.append(hierarchy_id)
                
                query += " ORDER BY scan_timestamp DESC"
                
                cur.execute(query, params)
                rows = cur.fetchall()
                return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Failed to list scans: {e}")
            return []
        finally:
            if conn:
                self._return_connection(conn)
