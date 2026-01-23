"""
Database queries for ConfigScan Discovery Results

Reads from PostgreSQL discoveries table created by configScan engine.
Optimized queries using existing indexes for performance.
Supports NDJSON fallback for local testing.
"""

import os
import sys
import json
import psycopg2
from psycopg2.extras import RealDictCursor
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
from pathlib import Path
from collections import defaultdict, Counter

# Add configScan engine to path for DatabaseManager
THREAT_ENGINE_ROOT = Path(__file__).parent.parent.parent.parent
CONFIGSCAN_ENGINE_PATH = THREAT_ENGINE_ROOT / "configScan_engines" / "aws-configScan-engine"

if str(CONFIGSCAN_ENGINE_PATH) not in sys.path:
    sys.path.insert(0, str(CONFIGSCAN_ENGINE_PATH))

try:
    from engine.database_manager import DatabaseManager
except ImportError as e:
    print(f"Warning: DatabaseManager import failed: {e}")
    DatabaseManager = None

# Import NDJSON reader as fallback
try:
    from .discovery_ndjson_reader import DiscoveryNDJSONReader
except ImportError:
    DiscoveryNDJSONReader = None


class DiscoveryDatabaseQueries:
    """Database queries for discovery results using existing DatabaseManager with NDJSON fallback"""
    
    def __init__(self, db_manager: Optional['DatabaseManager'] = None, use_ndjson_fallback: bool = True):
        """
        Initialize with existing DatabaseManager or create new one
        
        Args:
            db_manager: Optional DatabaseManager instance (reuses connection pool)
            use_ndjson_fallback: If True, fallback to NDJSON when database is empty
        """
        self.use_ndjson_fallback = use_ndjson_fallback
        self.ndjson_reader = None
        
        if db_manager:
            self.db = db_manager
            self.own_connection = False
        elif DatabaseManager:
            try:
                self.db = DatabaseManager()
                self.own_connection = True
            except Exception as e:
                print(f"Warning: DatabaseManager initialization failed: {e}")
                self.db = None
        else:
            self.db = None
        
        # Initialize NDJSON reader if fallback enabled
        if use_ndjson_fallback and DiscoveryNDJSONReader:
            self.ndjson_reader = DiscoveryNDJSONReader()
    
    def _has_database_data(self, tenant_id: str) -> bool:
        """Check if database has data for tenant"""
        if not self.db:
            return False
        
        try:
            result = self._execute_query_one(
                "SELECT COUNT(*) as count FROM discoveries WHERE tenant_id = %s LIMIT 1",
                [tenant_id]
            )
            return result and result.get('count', 0) > 0
        except:
            return False
    
    def _execute_query(self, query: str, params: List = None):
        """Execute a query using DatabaseManager"""
        conn = self.db._get_connection()
        try:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute(query, params or [])
            results = cur.fetchall()
            conn.commit()
            return results
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            self.db._return_connection(conn)
    
    def _execute_query_one(self, query: str, params: List = None):
        """Execute a query and return single result"""
        conn = self.db._get_connection()
        try:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute(query, params or [])
            result = cur.fetchone()
            conn.commit()
            return result
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            self.db._return_connection(conn)
    
    def _get_ndjson_fallback(self, method_name: str, *args, **kwargs):
        """Get data from NDJSON fallback"""
        if not self.ndjson_reader:
            raise ValueError("NDJSON fallback not available")
        
        method = getattr(self.ndjson_reader, method_name, None)
        if not method:
            raise ValueError(f"Method {method_name} not found in NDJSON reader")
        
        return method(*args, **kwargs)
    
    def get_dashboard_stats(self, tenant_id: str, customer_id: Optional[str] = None,
                           limit_recent_scans: int = 5) -> Dict[str, Any]:
        """
        Get dashboard statistics with aggregations.
        Falls back to NDJSON if database is empty.
        """
        # Try database first
        if self.db and self._has_database_data(tenant_id):
            try:
                return self._get_dashboard_stats_db(tenant_id, customer_id, limit_recent_scans)
            except Exception as e:
                print(f"Database query failed, using NDJSON fallback: {e}")
        
        # Fallback to NDJSON
        if self.use_ndjson_fallback and self.ndjson_reader:
            return self._get_ndjson_fallback('get_dashboard_stats', tenant_id, customer_id, limit_recent_scans)
        
        # Return empty if no fallback
        return {
            'total_discoveries': 0,
            'unique_resources': 0,
            'services_scanned': 0,
            'top_services': [],
            'recent_scans': []
        }
    
    def _get_dashboard_stats_db(self, tenant_id: str, customer_id: Optional[str] = None,
                                limit_recent_scans: int = 5) -> Dict[str, Any]:
        """Get dashboard statistics from database"""
        # Build customer filter
        if customer_id:
            customer_filter = "AND customer_id = %s"
            params = [tenant_id, customer_id]
        else:
            customer_filter = ""
            params = [tenant_id]
        
        query = f"""
        WITH scan_stats AS (
            SELECT 
                scan_id,
                COUNT(*) as total_discoveries,
                COUNT(DISTINCT resource_arn) FILTER (WHERE resource_arn IS NOT NULL) as unique_resources,
                MAX(scan_timestamp) as scan_timestamp
            FROM discoveries
            WHERE tenant_id = %s
              {customer_filter}
            GROUP BY scan_id
        ),
        service_stats AS (
            SELECT 
                service,
                COUNT(*) as total,
                COUNT(DISTINCT resource_arn) FILTER (WHERE resource_arn IS NOT NULL) as unique_resources,
                array_agg(DISTINCT region) FILTER (WHERE region IS NOT NULL) as regions
            FROM discoveries
            WHERE tenant_id = %s
              {customer_filter}
            GROUP BY service
            ORDER BY COUNT(*) DESC
            LIMIT 10
        )
        SELECT 
            (SELECT COALESCE(SUM(total_discoveries), 0) FROM scan_stats) as total_discoveries,
            (SELECT COALESCE(SUM(unique_resources), 0) FROM scan_stats) as unique_resources,
            (SELECT COUNT(DISTINCT scan_id) FROM scan_stats) as total_scans,
            (SELECT COUNT(DISTINCT service) FROM discoveries 
             WHERE tenant_id = %s {customer_filter}) as services_scanned,
            (SELECT json_agg(row_to_json(s.*)) FROM service_stats s) as top_services,
            (SELECT json_agg(row_to_json(sc.*) ORDER BY sc.scan_timestamp DESC) 
             FROM (SELECT * FROM scan_stats ORDER BY scan_timestamp DESC LIMIT %s) sc) as recent_scans;
        """
        
        all_params = params + params + params + [limit_recent_scans]
        result = self._execute_query_one(query, all_params)
        
        if not result:
            return {
                'total_discoveries': 0,
                'unique_resources': 0,
                'services_scanned': 0,
                'top_services': [],
                'recent_scans': []
            }
        
        return {
            'total_discoveries': result['total_discoveries'] or 0,
            'unique_resources': result['unique_resources'] or 0,
            'services_scanned': result['services_scanned'] or 0,
            'top_services': result['top_services'] or [],
            'recent_scans': result['recent_scans'] or []
        }
    
    def list_scans(self, tenant_id: str, customer_id: Optional[str] = None,
                   page: int = 1, page_size: int = 20) -> Tuple[List[Dict], int]:
        """
        List discovery scans with pagination.
        Falls back to NDJSON if database is empty.
        """
        # Try database first
        if self.db and self._has_database_data(tenant_id):
            try:
                return self._list_scans_db(tenant_id, customer_id, page, page_size)
            except Exception as e:
                print(f"Database query failed, using NDJSON fallback: {e}")
        
        # Fallback to NDJSON
        if self.use_ndjson_fallback and self.ndjson_reader:
            return self._get_ndjson_fallback('list_scans', tenant_id, customer_id, page, page_size)
        
        return [], 0
    
    def _list_scans_db(self, tenant_id: str, customer_id: Optional[str] = None,
                       page: int = 1, page_size: int = 20) -> Tuple[List[Dict], int]:
        """List scans from database"""
        offset = (page - 1) * page_size
        
        # Build customer filter
        if customer_id:
            customer_filter = "AND customer_id = %s"
            count_params = [tenant_id, customer_id]
            list_params = [tenant_id, customer_id, page_size, offset]
        else:
            customer_filter = ""
            count_params = [tenant_id]
            list_params = [tenant_id, page_size, offset]
        
        # Get total count
        count_query = f"""
        SELECT COUNT(DISTINCT scan_id)
        FROM discoveries
        WHERE tenant_id = %s
          {customer_filter};
        """
        
        # Get scans with aggregations
        list_query = f"""
        SELECT 
            scan_id,
            customer_id,
            tenant_id,
            provider,
            hierarchy_id,
            hierarchy_type,
            COUNT(*) as total_discoveries,
            COUNT(DISTINCT resource_arn) FILTER (WHERE resource_arn IS NOT NULL) as unique_resources,
            COUNT(DISTINCT service) as services_scanned,
            COUNT(DISTINCT region) FILTER (WHERE region IS NOT NULL) as regions_scanned,
            MAX(scan_timestamp) as scan_timestamp
        FROM discoveries
        WHERE tenant_id = %s
          {customer_filter}
        GROUP BY scan_id, customer_id, tenant_id, provider, hierarchy_id, hierarchy_type
        ORDER BY MAX(scan_timestamp) DESC
        LIMIT %s OFFSET %s;
        """
        
        # Get total
        total_result = self._execute_query_one(count_query, count_params)
        total = total_result['count']
        
        # Get scans
        scans = self._execute_query(list_query, list_params)
        
        return [dict(s) for s in scans], total
    
    def get_scan_summary(self, scan_id: str, tenant_id: str) -> Optional[Dict]:
        """
        Get summary for a specific scan.
        Falls back to NDJSON if database is empty.
        """
        # Try database first
        if self.db and self._has_database_data(tenant_id):
            try:
                return self._get_scan_summary_db(scan_id, tenant_id)
            except Exception as e:
                print(f"Database query failed, using NDJSON fallback: {e}")
        
        # Fallback to NDJSON
        if self.use_ndjson_fallback and self.ndjson_reader:
            return self._get_ndjson_fallback('get_scan_summary', scan_id, tenant_id)
        
        return None
    
    def _get_scan_summary_db(self, scan_id: str, tenant_id: str) -> Optional[Dict]:
        """Get scan summary from database"""
        query = """
        SELECT 
            scan_id,
            customer_id,
            tenant_id,
            provider,
            hierarchy_id,
            hierarchy_type,
            COUNT(*) as total_discoveries,
            COUNT(DISTINCT resource_arn) FILTER (WHERE resource_arn IS NOT NULL) as unique_resources,
            COUNT(DISTINCT service) as services_scanned,
            COUNT(DISTINCT region) FILTER (WHERE region IS NOT NULL) as regions_scanned,
            MAX(scan_timestamp) as scan_timestamp
        FROM discoveries
        WHERE scan_id = %s
          AND tenant_id = %s
        GROUP BY scan_id, customer_id, tenant_id, provider, hierarchy_id, hierarchy_type;
        """
        
        result = self._execute_query_one(query, [scan_id, tenant_id])
        
        if not result:
            return None
        
        return dict(result)
    
    def get_service_stats(self, scan_id: str, tenant_id: str) -> List[Dict]:
        """
        Get statistics for all services in a scan.
        Falls back to NDJSON if database is empty.
        """
        # Try database first
        if self.db and self._has_database_data(tenant_id):
            try:
                return self._get_service_stats_db(scan_id, tenant_id)
            except Exception as e:
                print(f"Database query failed, using NDJSON fallback: {e}")
        
        # Fallback to NDJSON
        if self.use_ndjson_fallback and self.ndjson_reader:
            return self._get_ndjson_fallback('get_service_stats', scan_id, tenant_id)
        
        return []
    
    def _get_service_stats_db(self, scan_id: str, tenant_id: str) -> List[Dict]:
        """Get service stats from database"""
        query = """
        SELECT 
            service,
            COUNT(*) as total_discoveries,
            COUNT(DISTINCT resource_arn) FILTER (WHERE resource_arn IS NOT NULL) as unique_resources,
            array_agg(DISTINCT region) FILTER (WHERE region IS NOT NULL) as regions,
            array_agg(DISTINCT discovery_id) as discovery_functions
        FROM discoveries
        WHERE scan_id = %s
          AND tenant_id = %s
        GROUP BY service
        ORDER BY service;
        """
        
        results = self._execute_query(query, [scan_id, tenant_id])
        return [dict(r) for r in results]
    
    def get_service_detail(self, scan_id: str, service: str, tenant_id: str) -> Optional[Dict]:
        """
        Get detailed statistics for a specific service in a scan.
        Falls back to NDJSON if database is empty.
        """
        # Try database first
        if self.db and self._has_database_data(tenant_id):
            try:
                return self._get_service_detail_db(scan_id, service, tenant_id)
            except Exception as e:
                print(f"Database query failed, using NDJSON fallback: {e}")
        
        # Fallback to NDJSON
        if self.use_ndjson_fallback and self.ndjson_reader:
            return self._get_ndjson_fallback('get_service_detail', scan_id, service, tenant_id)
        
        return None
    
    def _get_service_detail_db(self, scan_id: str, service: str, tenant_id: str) -> Optional[Dict]:
        """Get service detail from database"""
        # Overall stats
        stats_query = """
        SELECT 
            service,
            COUNT(*) as total_discoveries,
            COUNT(DISTINCT resource_arn) FILTER (WHERE resource_arn IS NOT NULL) as unique_resources,
            array_agg(DISTINCT region) FILTER (WHERE region IS NOT NULL) as regions
        FROM discoveries
        WHERE scan_id = %s
          AND service = %s
          AND tenant_id = %s
        GROUP BY service;
        """
        
        # Discovery function stats
        functions_query = """
        SELECT 
            discovery_id,
            COUNT(*) as total,
            COUNT(DISTINCT resource_arn) FILTER (WHERE resource_arn IS NOT NULL) as unique_resources,
            array_agg(DISTINCT resource_arn) FILTER (WHERE resource_arn IS NOT NULL) as resource_arns
        FROM discoveries
        WHERE scan_id = %s
          AND service = %s
          AND tenant_id = %s
        GROUP BY discovery_id
        ORDER BY COUNT(*) DESC
        LIMIT 50;
        """
        
        stats = self._execute_query_one(stats_query, [scan_id, service, tenant_id])
        
        if not stats:
            return None
        
        functions = self._execute_query(functions_query, [scan_id, service, tenant_id])
        
        return {
            'service': service,
            'scan_id': scan_id,
            'total_discoveries': stats['total_discoveries'],
            'unique_resources': stats['unique_resources'],
            'regions': stats['regions'] or [],
            'discovery_functions': [dict(f) for f in functions],
            'top_resources': []  # Can be enhanced
        }
    
    def get_discoveries(self, scan_id: Optional[str] = None, tenant_id: str = None,
                       customer_id: Optional[str] = None, service: Optional[str] = None,
                       discovery_id: Optional[str] = None, resource_arn: Optional[str] = None,
                       page: int = 1, page_size: int = 50) -> Tuple[List[Dict], int]:
        """
        Get discoveries with filtering and pagination.
        Falls back to NDJSON if database is empty.
        """
        # Try database first
        if self.db and tenant_id and self._has_database_data(tenant_id):
            try:
                return self._get_discoveries_db(scan_id, tenant_id, customer_id, service, discovery_id, resource_arn, page, page_size)
            except Exception as e:
                print(f"Database query failed, using NDJSON fallback: {e}")
        
        # Fallback to NDJSON
        if self.use_ndjson_fallback and self.ndjson_reader and tenant_id:
            return self._get_ndjson_fallback('get_discoveries', scan_id, tenant_id, customer_id, service, discovery_id, resource_arn, page, page_size)
        
        return [], 0
    
    def _get_discoveries_db(self, scan_id: Optional[str] = None, tenant_id: str = None,
                           customer_id: Optional[str] = None, service: Optional[str] = None,
                           discovery_id: Optional[str] = None, resource_arn: Optional[str] = None,
                           page: int = 1, page_size: int = 50) -> Tuple[List[Dict], int]:
        """Get discoveries from database"""
        offset = (page - 1) * page_size
        
        # Build WHERE clause dynamically
        where_clauses = []
        params = []
        
        if tenant_id:
            where_clauses.append("tenant_id = %s")
            params.append(tenant_id)
        
        if customer_id:
            where_clauses.append("customer_id = %s")
            params.append(customer_id)
        
        if scan_id:
            where_clauses.append("scan_id = %s")
            params.append(scan_id)
        
        if service:
            where_clauses.append("service = %s")
            params.append(service)
        
        if discovery_id:
            where_clauses.append("discovery_id = %s")
            params.append(discovery_id)
        
        if resource_arn:
            where_clauses.append("resource_arn = %s")
            params.append(resource_arn)
        
        where_sql = " AND ".join(where_clauses) if where_clauses else "TRUE"
        
        # Count query
        count_query = f"""
        SELECT COUNT(*)
        FROM discoveries
        WHERE {where_sql};
        """
        
        # List query
        list_query = f"""
        SELECT 
            id,
            scan_id,
            customer_id,
            tenant_id,
            provider,
            hierarchy_id,
            hierarchy_type,
            discovery_id,
            region,
            service,
            resource_arn,
            resource_id,
            raw_response,
            emitted_fields,
            config_hash,
            scan_timestamp,
            version
        FROM discoveries
        WHERE {where_sql}
        ORDER BY scan_timestamp DESC, id DESC
        LIMIT %s OFFSET %s;
        """
        
        # Get count
        total_result = self._execute_query_one(count_query, params)
        total = total_result['count']
        
        # Get discoveries
        discoveries = self._execute_query(list_query, params + [page_size, offset])
        
        # Format for API
        formatted = []
        for disc in discoveries:
            formatted.append({
                'id': disc.get('id'),
                'scan_id': disc['scan_id'],
                'customer_id': disc['customer_id'],
                'tenant_id': disc['tenant_id'],
                'provider': disc['provider'],
                'hierarchy_id': disc['hierarchy_id'],
                'hierarchy_type': disc['hierarchy_type'],
                'discovery_id': disc['discovery_id'],
                'region': disc.get('region'),
                'service': disc['service'],
                'resource_arn': disc.get('resource_arn'),
                'resource_id': disc.get('resource_id'),
                'raw_response': disc.get('raw_response', {}),
                'emitted_fields': disc.get('emitted_fields', {}),
                'config_hash': disc.get('config_hash'),
                'scan_timestamp': disc['scan_timestamp'],
                'version': disc.get('version', 1)
            })
        
        return formatted, total
    
    def get_resource_discoveries(self, resource_arn: str, tenant_id: str,
                                customer_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Get all discoveries for a specific resource ARN.
        Falls back to NDJSON if database is empty.
        """
        # Try database first
        if self.db and self._has_database_data(tenant_id):
            try:
                return self._get_resource_discoveries_db(resource_arn, tenant_id, customer_id)
            except Exception as e:
                print(f"Database query failed, using NDJSON fallback: {e}")
        
        # Fallback to NDJSON
        if self.use_ndjson_fallback and self.ndjson_reader:
            return self._get_ndjson_fallback('get_resource_discoveries', resource_arn, tenant_id, customer_id)
        
        return None
    
    def _get_resource_discoveries_db(self, resource_arn: str, tenant_id: str,
                                    customer_id: Optional[str] = None) -> Dict[str, Any]:
        """Get resource discoveries from database"""
        where_clauses = ["resource_arn = %s", "tenant_id = %s"]
        params = [resource_arn, tenant_id]
        
        if customer_id:
            where_clauses.append("customer_id = %s")
            params.append(customer_id)
        
        where_sql = " AND ".join(where_clauses)
        
        query = f"""
        SELECT 
            id,
            scan_id,
            customer_id,
            tenant_id,
            provider,
            hierarchy_id,
            discovery_id,
            region,
            service,
            resource_arn,
            resource_id,
            raw_response,
            emitted_fields,
            config_hash,
            scan_timestamp,
            version
        FROM discoveries
        WHERE {where_sql}
        ORDER BY scan_timestamp DESC
        LIMIT 1000;
        """
        
        discoveries = self._execute_query(query, params)
        
        if not discoveries:
            return None
        
        # Calculate stats
        discovery_functions = list(set(d['discovery_id'] for d in discoveries))
        
        return {
            'resource_arn': resource_arn,
            'resource_id': discoveries[0].get('resource_id') if discoveries else None,
            'resource_type': discoveries[0].get('service') if discoveries else None,
            'total_discoveries': len(discoveries),
            'discovery_functions': discovery_functions,
            'discoveries': [dict(d) for d in discoveries]
        }
    
    def get_discovery_function_detail(self, discovery_id: str, tenant_id: str,
                                     customer_id: Optional[str] = None,
                                     scan_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Get all discoveries for a specific discovery function.
        Falls back to NDJSON if database is empty.
        """
        # Try database first
        if self.db and self._has_database_data(tenant_id):
            try:
                return self._get_discovery_function_detail_db(discovery_id, tenant_id, customer_id, scan_id)
            except Exception as e:
                print(f"Database query failed, using NDJSON fallback: {e}")
        
        # Fallback to NDJSON
        if self.use_ndjson_fallback and self.ndjson_reader:
            return self._get_ndjson_fallback('get_discovery_function_detail', discovery_id, tenant_id, customer_id, scan_id)
        
        return None
    
    def _get_discovery_function_detail_db(self, discovery_id: str, tenant_id: str,
                                         customer_id: Optional[str] = None,
                                         scan_id: Optional[str] = None) -> Dict[str, Any]:
        """Get discovery function detail from database"""
        where_clauses = ["discovery_id = %s", "tenant_id = %s"]
        params = [discovery_id, tenant_id]
        
        if customer_id:
            where_clauses.append("customer_id = %s")
            params.append(customer_id)
        
        if scan_id:
            where_clauses.append("scan_id = %s")
            params.append(scan_id)
        
        where_sql = " AND ".join(where_clauses)
        
        query = f"""
        SELECT 
            id,
            scan_id,
            customer_id,
            tenant_id,
            provider,
            hierarchy_id,
            discovery_id,
            region,
            service,
            resource_arn,
            resource_id,
            raw_response,
            emitted_fields,
            config_hash,
            scan_timestamp,
            version
        FROM discoveries
        WHERE {where_sql}
        ORDER BY scan_timestamp DESC
        LIMIT 1000;
        """
        
        discoveries = self._execute_query(query, params)
        
        if not discoveries:
            return None
        
        # Extract service from discovery_id (e.g., aws.s3.list_buckets → s3)
        service = discovery_id.split('.')[1] if '.' in discovery_id else 'unknown'
        
        # Get unique resource ARNs
        resources = list(set(d['resource_arn'] for d in discoveries if d.get('resource_arn')))
        
        return {
            'discovery_id': discovery_id,
            'service': service,
            'total_discoveries': len(discoveries),
            'resources_discovered': resources,
            'discoveries': [dict(d) for d in discoveries]
        }
