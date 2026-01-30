"""
PostgreSQL Database Manager for Discoveries Engine
Handles discovery storage and drift detection
"""
import os
import json
import hashlib
import psycopg2
from psycopg2.extras import RealDictCursor, execute_values
from psycopg2.pool import SimpleConnectionPool
from datetime import datetime
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
    """PostgreSQL database manager for Discoveries Engine"""

    def __init__(self, db_config: Optional[Dict] = None):
        """
        Initialize database connection for discoveries engine.
        
        Args:
            db_config: Optional override (for testing). Normally uses consolidated DB config.
        """
        # Get consolidated database config (required - no fallback)
        try:
            db_config_obj = get_database_config("discoveries")
            # Convert to dict format for compatibility
            self.db_config = {
                "host": db_config_obj.host,
                "port": db_config_obj.port,
                "database": db_config_obj.database,
                "user": db_config_obj.username,
                "password": db_config_obj.password,
            }
            logger.info(f"Using consolidated discoveries database: {db_config_obj.database} on {db_config_obj.host}")
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
                   service: str = None, scan_type: str = 'discovery',
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
    
    # Discovery Storage
    def _calculate_config_hash(self, item: Dict) -> str:
        """Calculate SHA256 hash of configuration"""
        config_dict = {
            k: v for k, v in item.items()
            if k not in ['_raw_response', 'scan_timestamp', 'version', 'metadata']
        }
        config_str = json.dumps(config_dict, sort_keys=True, default=str)
        return hashlib.sha256(config_str.encode()).hexdigest()
    
    def store_discoveries_batch(self, scan_id: str, customer_id: str, tenant_id: str,
                                provider: str, discovery_id: str, items: List[Dict],
                                hierarchy_id: str = None, hierarchy_type: str = None,
                                region: str = None, service: str = None) -> Dict[str, Any]:
        """
        Store discovery results in batch (optimized for performance)
        
        Returns:
            Dict with drift detection results
        """
        if not items:
            return {
                'new_resources': 0,
                'modified_resources': 0,
                'unchanged_resources': 0,
                'deleted_resources': 0,
                'drifts': []
            }
        
        drift_results = {
            'new_resources': 0,
            'modified_resources': 0,
            'unchanged_resources': 0,
            'deleted_resources': 0,
            'drifts': []
        }
        
        conn = self._get_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Batch: Get all previous versions in one query
                resource_uids = [item.get('resource_uid') or item.get('resource_arn') for item in items]
                resource_uids = [uid for uid in resource_uids if uid]  # Filter None values
                
                previous_versions = {}
                if resource_uids:
                    placeholders = ','.join(['%s'] * len(resource_uids))
                    cur.execute(f"""
                        SELECT discovery_id, resource_uid, config_hash, version, scan_id, scan_timestamp, emitted_fields
                        FROM discoveries
                        WHERE discovery_id = %s 
                          AND resource_uid IN ({placeholders})
                          AND customer_id = %s
                          AND tenant_id = %s
                          AND hierarchy_id = %s
                        ORDER BY scan_timestamp DESC
                    """, (discovery_id, *resource_uids, customer_id, tenant_id, hierarchy_id))
                    
                    # Build lookup map: resource_uid -> latest version
                    for row in cur.fetchall():
                        uid = row['resource_uid']
                        if uid not in previous_versions:
                            previous_versions[uid] = row
                
                # Prepare batch data with drift detection
                discoveries_to_insert = []
                discoveries_to_update = []
                history_batch = []
                
                def json_serial(obj):
                    """JSON serializer for objects not serializable by default json code"""
                    if isinstance(obj, (datetime,)):
                        return obj.isoformat()
                    raise TypeError(f"Type {type(obj)} not serializable")
                
                for item in items:
                    resource_arn = item.get('resource_arn')
                    resource_uid = item.get('resource_uid') or resource_arn
                    resource_id = item.get('resource_id')
                    config_hash = self._calculate_config_hash(item)
                    
                    # Check previous version from batch lookup
                    previous = previous_versions.get(resource_uid) if resource_uid else None
                    
                    raw_response_json = json.dumps(item.get('_raw_response', {}), default=json_serial)
                    emitted_fields_json = json.dumps(item, default=json_serial)
                    history_resource_uid = resource_uid or f"account:{hierarchy_id}:{discovery_id}"
                    
                    if previous:
                        previous_hash = previous['config_hash']
                        if config_hash == previous_hash:
                            # UNCHANGED: UPDATE existing record with new scan_id and timestamp
                            change_type = 'unchanged'
                            version = previous['version']
                            drift_results['unchanged_resources'] += 1
                            diff_summary = None
                            
                            discoveries_to_update.append((
                                scan_id,  # new scan_id
                                resource_uid,
                                discovery_id,
                                customer_id,
                                tenant_id,
                                hierarchy_id
                            ))
                        else:
                            # MODIFIED: INSERT new version
                            change_type = 'modified'
                            version = previous['version'] + 1
                            drift_results['modified_resources'] += 1
                            
                            # Calculate diff
                            old_item = json.loads(previous.get('emitted_fields', '{}'))
                            diff_summary = self._calculate_diff_summary(old_item, item)
                            
                            drift_results['drifts'].append({
                                'resource_uid': resource_uid,
                                'discovery_id': discovery_id,
                                'change_type': 'configuration',
                                'severity': self._calculate_severity(diff_summary),
                                'change_summary': diff_summary
                            })
                            
                            discoveries_to_insert.append((
                                scan_id, customer_id, tenant_id, provider,
                                hierarchy_id, hierarchy_type, discovery_id,
                                region, service, resource_arn, resource_uid, resource_id,
                                raw_response_json, emitted_fields_json, config_hash, version
                            ))
                    else:
                        # NEW: INSERT
                        change_type = 'created'
                        version = 1
                        drift_results['new_resources'] += 1
                        diff_summary = None
                        
                        discoveries_to_insert.append((
                            scan_id, customer_id, tenant_id, provider,
                            hierarchy_id, hierarchy_type, discovery_id,
                            region, service, resource_arn, resource_uid, resource_id,
                            raw_response_json, emitted_fields_json, config_hash, version
                        ))
                    
                    # Always add to history
                    history_batch.append((
                        customer_id, tenant_id, provider, hierarchy_id, hierarchy_type,
                        discovery_id, resource_arn, resource_uid, scan_id, config_hash,
                        raw_response_json, emitted_fields_json, version, change_type,
                        previous['config_hash'] if previous else None,
                        json.dumps(diff_summary, default=json_serial) if diff_summary else None
                    ))
                
                # Execute UPDATE for unchanged resources
                if discoveries_to_update:
                    cur.executemany("""
                        UPDATE discoveries
                        SET scan_id = %s, scan_timestamp = CURRENT_TIMESTAMP
                        WHERE resource_uid = %s 
                          AND discovery_id = %s
                          AND customer_id = %s
                          AND tenant_id = %s
                          AND hierarchy_id = %s
                    """, discoveries_to_update)
                
                # Execute INSERT for new/modified resources
                if discoveries_to_insert:
                    cur.executemany("""
                        INSERT INTO discoveries
                        (scan_id, customer_id, tenant_id, provider, hierarchy_id, hierarchy_type,
                         discovery_id, region, service, resource_arn, resource_uid, resource_id,
                         raw_response, emitted_fields, config_hash, version)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """, discoveries_to_insert)
                
                # Batch insert history
                if history_batch:
                    cur.executemany("""
                        INSERT INTO discovery_history
                        (customer_id, tenant_id, provider, hierarchy_id, hierarchy_type,
                         discovery_id, resource_arn, resource_uid, scan_id, config_hash,
                         raw_response, emitted_fields, version, change_type,
                         previous_hash, diff_summary)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """, history_batch)
            
            conn.commit()
        finally:
            self._return_connection(conn)
        
        return drift_results
    
    def store_discovery(self, scan_id: str, customer_id: str, tenant_id: str,
                       provider: str, discovery_id: str, items: List[Dict],
                       hierarchy_id: str = None, hierarchy_type: str = None,
                       region: str = None, service: str = None) -> Dict[str, Any]:
        """
        Store discovery results with drift detection (legacy - calls batch method)
        
        Returns:
            Dict with drift detection results
        """
        # Use batch method for better performance
        return self.store_discoveries_batch(
            scan_id, customer_id, tenant_id, provider, discovery_id, items,
            hierarchy_id, hierarchy_type, region, service
        )
    
    def _calculate_diff_summary(self, old_item: Dict, new_item: Dict) -> Dict:
        """Calculate summary of changes"""
        changes = {
            'fields_added': [],
            'fields_removed': [],
            'fields_modified': []
        }
        
        old_keys = set(old_item.keys())
        new_keys = set(new_item.keys())
        
        changes['fields_added'] = list(new_keys - old_keys)
        changes['fields_removed'] = list(old_keys - new_keys)
        
        common_keys = old_keys & new_keys
        for key in common_keys:
            if old_item[key] != new_item[key]:
                changes['fields_modified'].append({
                    'field': key,
                    'old_value': str(old_item[key])[:100],
                    'new_value': str(new_item[key])[:100]
                })
        
        return changes
    
    def _calculate_severity(self, diff_summary: Dict) -> str:
        """Calculate severity based on changes"""
        critical_fields = ['Policy', 'Encryption', 'PublicAccessBlock', 'Versioning']
        
        modified_fields = [c['field'] for c in diff_summary.get('fields_modified', [])]
        added_fields = diff_summary.get('fields_added', [])
        removed_fields = diff_summary.get('fields_removed', [])
        
        if any(field in modified_fields or field in added_fields or field in removed_fields
               for field in critical_fields):
            return 'high'
        
        total_changes = len(modified_fields) + len(added_fields) + len(removed_fields)
        if total_changes > 5:
            return 'medium'
        
        return 'low'
    
    # Query Methods
    def query_discovery(self, discovery_id: str = None, tenant_id: str = None,
                       hierarchy_id: str = None, scan_id: str = None,
                       customer_id: str = None, service: str = None) -> List[Dict]:
        """Query discoveries"""
        conn = self._get_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                if scan_id:
                    # Query specific scan
                    query = "SELECT * FROM discoveries WHERE scan_id = %s"
                    params = [scan_id]
                    
                    if discovery_id:
                        query += " AND discovery_id = %s"
                        params.append(discovery_id)
                    if tenant_id:
                        query += " AND tenant_id = %s"
                        params.append(tenant_id)
                    if hierarchy_id:
                        query += " AND hierarchy_id = %s"
                        params.append(hierarchy_id)
                    if service:
                        query += " AND service = %s"
                        params.append(service)
                    
                    cur.execute(query, params)
                else:
                    # Query latest version
                    query = """
                        SELECT d1.* FROM discoveries d1
                        INNER JOIN (
                            SELECT discovery_id, COALESCE(resource_uid, resource_arn, '') as resource_uid, 
                                   customer_id, tenant_id, hierarchy_id,
                                   MAX(scan_timestamp) as max_ts
                            FROM discoveries
                            WHERE 1=1
                    """
                    params = []
                    
                    if discovery_id:
                        query += " AND discovery_id = %s"
                        params.append(discovery_id)
                    
                    query += """
                            GROUP BY discovery_id, COALESCE(resource_uid, resource_arn, ''), customer_id, tenant_id, hierarchy_id
                        ) d2 ON d1.discovery_id = d2.discovery_id 
                            AND COALESCE(d1.resource_uid, d1.resource_arn, '') = d2.resource_uid
                            AND d1.customer_id = d2.customer_id
                            AND d1.tenant_id = d2.tenant_id
                            AND d1.hierarchy_id = d2.hierarchy_id
                            AND d1.scan_timestamp = d2.max_ts
                        WHERE 1=1
                    """
                    
                    if tenant_id:
                        query += " AND d1.tenant_id = %s"
                        params.append(tenant_id)
                    if hierarchy_id:
                        query += " AND d1.hierarchy_id = %s"
                        params.append(hierarchy_id)
                    if customer_id:
                        query += " AND d1.customer_id = %s"
                        params.append(customer_id)
                    if service:
                        query += " AND d1.service = %s"
                        params.append(service)
                    
                    cur.execute(query, params)
                
                return [dict(row) for row in cur.fetchall()]
        finally:
            self._return_connection(conn)
    
    def close(self):
        """Close connection pool"""
        if self.connection_pool:
            self.connection_pool.closeall()
