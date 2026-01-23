"""
PostgreSQL Database Manager for Multi-Tenant CSPM Platform
"""
import os
import json
import hashlib
import psycopg2
from psycopg2.extras import RealDictCursor, execute_values
from psycopg2.pool import SimpleConnectionPool
from datetime import datetime
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)

class DatabaseManager:
    """PostgreSQL database manager for CSPM platform"""
    
    def __init__(self, db_config: Optional[Dict] = None):
        """
        Initialize database connection
        
        Args:
            db_config: Dict with keys: host, port, database, user, password
                      If None, reads from environment or secrets file
        """
        if db_config is None:
            db_config = self._load_db_config()
        
        self.db_config = db_config
        self.connection_pool = None
        self._init_pool()
        self._ensure_schema()
    
    def _load_db_config(self) -> Dict:
        """Load database config from environment or secrets file"""
        # Try environment variables first
        config = {
            'host': os.getenv('CSPM_DB_HOST', 'localhost'),
            'port': int(os.getenv('CSPM_DB_PORT', '5432')),
            'database': os.getenv('CSPM_DB_NAME', 'cspm_db'),
            'user': os.getenv('CSPM_DB_USER', 'postgres'),
            'password': os.getenv('CSPM_DB_PASSWORD', '')
        }
        
        # Override with secrets file if exists
        secrets_file = os.path.join(
            os.path.dirname(__file__),
            '..', 'database', 'secrets', 'db_config.json'
        )
        if os.path.exists(secrets_file):
            with open(secrets_file) as f:
                file_config = json.load(f)
                config.update(file_config)
        
        return config
    
    def _init_pool(self):
        """Initialize connection pool"""
        try:
            self.connection_pool = SimpleConnectionPool(
                1, 10,
                host=self.db_config['host'],
                port=self.db_config['port'],
                database=self.db_config['database'],
                user=self.db_config['user'],
                password=self.db_config['password']
            )
            logger.info("Database connection pool initialized")
        except Exception as e:
            logger.error(f"Failed to initialize database pool: {e}")
            raise
    
    def _get_connection(self):
        """Get connection from pool"""
        if self.connection_pool is None:
            self._init_pool()
        return self.connection_pool.getconn()
    
    def _return_connection(self, conn):
        """Return connection to pool"""
        if self.connection_pool:
            self.connection_pool.putconn(conn)
    
    def _ensure_schema(self):
        """Ensure database schema exists"""
        schema_file = os.path.join(
            os.path.dirname(__file__),
            '..', 'database', 'schema.sql'
        )
        if os.path.exists(schema_file):
            conn = self._get_connection()
            try:
                with open(schema_file) as f:
                    schema_sql = f.read()
                with conn.cursor() as cur:
                    cur.execute(schema_sql)
                conn.commit()
                logger.info("Database schema ensured")
            except Exception as e:
                conn.rollback()
                logger.warning(f"Schema already exists or error: {e}")
            finally:
                self._return_connection(conn)
    
    # Customer Management
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
    
    # Tenant Management
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
    
    # Hierarchy Management
    def register_hierarchy(self, tenant_id: str, provider: str,
                          hierarchy_type: str, hierarchy_id: str,
                          hierarchy_name: str = None, parent_id: int = None,
                          metadata: Dict = None) -> int:
        """Register CSP hierarchy (account, project, subscription, etc.)"""
        conn = self._get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO csp_hierarchies
                    (tenant_id, provider, hierarchy_type, hierarchy_id, hierarchy_name, parent_id, metadata)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (tenant_id, provider, hierarchy_type, hierarchy_id)
                    DO UPDATE SET
                        hierarchy_name = EXCLUDED.hierarchy_name,
                        parent_id = EXCLUDED.parent_id,
                        metadata = EXCLUDED.metadata
                    RETURNING id
                """, (
                    tenant_id, provider, hierarchy_type, hierarchy_id,
                    hierarchy_name, parent_id,
                    json.dumps(metadata or {}) if metadata else None
                ))
                result = cur.fetchone()
                conn.commit()
                return result[0] if result else None
        finally:
            self._return_connection(conn)
    
    # Scan Management
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
                resource_arns = [item.get('resource_arn') or item.get('resource_uid') for item in items]
                resource_arns = [arn for arn in resource_arns if arn]  # Filter None values
                
                previous_versions = {}
                if resource_arns:
                    placeholders = ','.join(['%s'] * len(resource_arns))
                    cur.execute(f"""
                        SELECT discovery_id, resource_arn, config_hash, version, scan_id, scan_timestamp, emitted_fields
                        FROM discoveries
                        WHERE discovery_id = %s 
                          AND resource_arn IN ({placeholders})
                          AND customer_id = %s
                          AND tenant_id = %s
                          AND hierarchy_id = %s
                        ORDER BY scan_timestamp DESC
                    """, (discovery_id, *resource_arns, customer_id, tenant_id, hierarchy_id))
                    
                    # Build lookup map: resource_arn -> latest version
                    for row in cur.fetchall():
                        arn = row['resource_arn']
                        if arn not in previous_versions:
                            previous_versions[arn] = row
                
                # Prepare batch insert data
                discoveries_batch = []
                history_batch = []
                
                def json_serial(obj):
                    """JSON serializer for objects not serializable by default json code"""
                    if isinstance(obj, (datetime,)):
                        return obj.isoformat()
                    raise TypeError(f"Type {type(obj)} not serializable")
                
                for item in items:
                    resource_arn = item.get('resource_arn') or item.get('resource_uid')
                    resource_id = item.get('resource_id')
                    config_hash = self._calculate_config_hash(item)
                    
                    # Check previous version from batch lookup
                    previous = previous_versions.get(resource_arn) if resource_arn else None
                    
                    if previous:
                        previous_hash = previous['config_hash']
                        if config_hash == previous_hash:
                            change_type = 'unchanged'
                            version = previous['version']
                            drift_results['unchanged_resources'] += 1
                            diff_summary = None
                        else:
                            change_type = 'modified'
                            version = previous['version'] + 1
                            drift_results['modified_resources'] += 1
                            
                            # Calculate diff
                            old_item = json.loads(previous.get('emitted_fields', '{}'))
                            diff_summary = self._calculate_diff_summary(old_item, item)
                            
                            drift_results['drifts'].append({
                                'resource_arn': resource_arn,
                                'discovery_id': discovery_id,
                                'change_type': 'configuration',
                                'severity': self._calculate_severity(diff_summary),
                                'change_summary': diff_summary
                            })
                    else:
                        change_type = 'created'
                        version = 1
                        drift_results['new_resources'] += 1
                        diff_summary = None
                    
                    # Prepare batch insert data
                    raw_response_json = json.dumps(item.get('_raw_response', {}), default=json_serial)
                    emitted_fields_json = json.dumps(item, default=json_serial)
                    history_resource_arn = resource_arn or f"account:{hierarchy_id}:{discovery_id}"
                    
                    discoveries_batch.append((
                        scan_id, customer_id, tenant_id, provider,
                        hierarchy_id, hierarchy_type, discovery_id,
                        region, service, resource_arn, resource_id,
                        raw_response_json, emitted_fields_json, config_hash, version
                    ))
                    
                    history_batch.append((
                        customer_id, tenant_id, provider, hierarchy_id, hierarchy_type,
                        discovery_id, history_resource_arn, scan_id, config_hash,
                        raw_response_json, emitted_fields_json, version, change_type,
                        previous['config_hash'] if previous else None,
                        json.dumps(diff_summary, default=json_serial) if diff_summary else None
                    ))
                
                # Batch insert discoveries
                if discoveries_batch:
                    cur.executemany("""
                        INSERT INTO discoveries
                        (scan_id, customer_id, tenant_id, provider, hierarchy_id, hierarchy_type,
                         discovery_id, region, service, resource_arn, resource_id,
                         raw_response, emitted_fields, config_hash, version)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """, discoveries_batch)
                
                # Batch insert history
                if history_batch:
                    cur.executemany("""
                        INSERT INTO discovery_history
                        (customer_id, tenant_id, provider, hierarchy_id, hierarchy_type,
                         discovery_id, resource_arn, scan_id, config_hash,
                         raw_response, emitted_fields, version, change_type,
                         previous_hash, diff_summary)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
                            SELECT discovery_id, COALESCE(resource_arn, '') as resource_arn, 
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
                            GROUP BY discovery_id, COALESCE(resource_arn, ''), customer_id, tenant_id, hierarchy_id
                        ) d2 ON d1.discovery_id = d2.discovery_id 
                            AND COALESCE(d1.resource_arn, '') = d2.resource_arn
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
    
    # Check Results Storage
    def store_check_result(self, scan_id: str, customer_id: str, tenant_id: str,
                          provider: str, rule_id: str, resource_arn: str = None,
                          resource_id: str = None, resource_type: str = None,
                          status: str = 'FAIL', checked_fields: List[str] = None,
                          finding_data: Dict = None, hierarchy_id: str = None,
                          hierarchy_type: str = None) -> None:
        """Store check result"""
        conn = self._get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO check_results
                    (scan_id, customer_id, tenant_id, provider, hierarchy_id, hierarchy_type,
                     rule_id, resource_arn, resource_id, resource_type, status,
                     checked_fields, finding_data)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    scan_id, customer_id, tenant_id, provider,
                    hierarchy_id, hierarchy_type, rule_id,
                    resource_arn, resource_id, resource_type, status,
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
                    ORDER BY rule_id, resource_arn
                """, (scan_id,))
                return [dict(row) for row in cur.fetchall()]
        finally:
            self._return_connection(conn)
    
    def close(self):
        """Close connection pool"""
        if self.connection_pool:
            self.connection_pool.closeall()

