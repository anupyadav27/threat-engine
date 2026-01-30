"""
Discovery Reader for Check Engine
Reads discoveries from the discoveries database (cross-engine integration)
"""
import os
import sys
import psycopg2
from psycopg2.extras import RealDictCursor
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
        self.db_config = {
            "host": os.getenv("DISCOVERIES_DB_HOST", "localhost"),
            "port": int(os.getenv("DISCOVERIES_DB_PORT", "5432")),
            "database": os.getenv("DISCOVERIES_DB_NAME", "threat_engine_discoveries"),
            "user": os.getenv("DISCOVERIES_DB_USER", "discoveries_user"),
            "password": os.getenv("DISCOVERIES_DB_PASSWORD", "discoveries_password"),
        }
        logger.info(f"DiscoveryReader: Using discoveries database: {self.db_config['database']} on {self.db_config['host']}")
        
        # Allow override for testing
        if db_config is not None:
            self.db_config.update(db_config)
            logger.warning("Using provided db_config override (testing mode)")
        
        self.connection_pool = None
    
    def _get_connection(self):
        """Get database connection"""
        return psycopg2.connect(
            host=self.db_config["host"],
            port=self.db_config["port"],
            database=self.db_config["database"],
            user=self.db_config["user"],
            password=self.db_config["password"],
        )
    
    def read_discovery_records(self, discovery_id: str, tenant_id: str, 
                              hierarchy_id: str, scan_id: Optional[str] = None,
                              service: Optional[str] = None) -> List[Dict]:
        """
        Read discovery records from discoveries database
        
        Args:
            discovery_id: Discovery ID (e.g., 'aws.s3.list_buckets')
            tenant_id: Tenant ID
            hierarchy_id: Hierarchy ID (account_id, etc.)
            scan_id: Optional scan ID to filter by specific scan
            service: Optional service name to filter
        
        Returns:
            List of discovery items with emitted_fields
        """
        conn = None
        try:
            conn = self._get_connection()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Build query - Always get LATEST version of each resource
                # Don't filter by scan_id in main query since UPDATE mechanism means
                # resources can have different scan_ids but we want latest of each
                query = """
                    SELECT 
                        COALESCE(resource_uid, resource_arn) as resource_uid,
                        resource_arn,
                        resource_id,
                        emitted_fields,
                        service,
                        region,
                        discovery_id,
                        scan_id
                    FROM discoveries d1
                    WHERE discovery_id = %s
                      AND tenant_id = %s
                      AND hierarchy_id = %s
                      AND scan_timestamp = (
                          SELECT MAX(scan_timestamp)
                          FROM discoveries d2
                          WHERE d2.resource_uid = d1.resource_uid
                            AND d2.discovery_id = d1.discovery_id
                            AND d2.tenant_id = d1.tenant_id
                            AND d2.hierarchy_id = d1.hierarchy_id
                      )
                """
                params = [discovery_id, tenant_id, hierarchy_id]
                
                # Note: Removed scan_id filter - we always want LATEST version
                # This handles partial scans where resources have different scan_ids
                
                if service:
                    query += " AND service = %s"
                    params.append(service)
                
                query += " ORDER BY COALESCE(resource_uid, resource_arn)"
                
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
                
                logger.debug(f"Read {len(items)} discovery records for discovery_id={discovery_id}, scan_id={scan_id}")
                return items
                
        except Exception as e:
            logger.error(f"Failed to read discoveries from database: {e}", exc_info=True)
            return []
        finally:
            if conn:
                conn.close()
    
    def get_discovery_scan_info(self, scan_id: str) -> Optional[Dict]:
        """Get discovery scan information"""
        conn = None
        try:
            conn = self._get_connection()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT scan_id, customer_id, tenant_id, provider, 
                           hierarchy_id, hierarchy_type, status, scan_timestamp
                    FROM scans
                    WHERE scan_id = %s AND scan_type = 'discovery'
                """, (scan_id,))
                row = cur.fetchone()
                return dict(row) if row else None
        except Exception as e:
            logger.error(f"Failed to get scan info: {e}")
            return None
        finally:
            if conn:
                conn.close()
    
    def list_available_scans(self, tenant_id: str, hierarchy_id: Optional[str] = None) -> List[Dict]:
        """List available discovery scans"""
        conn = None
        try:
            conn = self._get_connection()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                query = """
                    SELECT scan_id, customer_id, tenant_id, provider,
                           hierarchy_id, hierarchy_type, status, scan_timestamp
                    FROM scans
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
                conn.close()
