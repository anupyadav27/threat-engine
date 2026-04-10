"""
Database queries for Discovery Results

Reads from PostgreSQL discovery_findings table created by discovery engine.
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


def _get_discoveries_conn():
    """Return a fresh psycopg2 connection to the discoveries DB via env vars."""
    return psycopg2.connect(
        host=os.getenv("DISCOVERIES_DB_HOST", "localhost"),
        port=int(os.getenv("DISCOVERIES_DB_PORT", "5432")),
        dbname=os.getenv("DISCOVERIES_DB_NAME", "threat_engine_discoveries"),
        user=os.getenv("DISCOVERIES_DB_USER", "postgres"),
        password=os.getenv("DISCOVERIES_DB_PASSWORD", ""),
        connect_timeout=10,
    )


class DiscoveryDatabaseQueries:
    """Database queries for discovery results using direct psycopg2 connections."""

    def __init__(self, **kwargs):
        """Initialize — connection is created per-query (no pool needed for drift)."""
        pass

    def _has_database_data(self, tenant_id: str) -> bool:
        """Check if database has data for tenant"""
        try:
            result = self._execute_query_one(
                "SELECT COUNT(*) as count FROM discovery_findings WHERE tenant_id = %s LIMIT 1",
                [tenant_id]
            )
            return result and result.get('count', 0) > 0
        except Exception:
            return False

    def _execute_query(self, query: str, params: List = None):
        """Execute a query using direct psycopg2 connection."""
        conn = _get_discoveries_conn()
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
            conn.close()

    def _execute_query_one(self, query: str, params: List = None):
        """Execute a query and return single result"""
        conn = _get_discoveries_conn()
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
            conn.close()

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
        if self._has_database_data(tenant_id):
            try:
                return self._get_dashboard_stats_db(tenant_id, customer_id, limit_recent_scans)
            except Exception as e:
                print(f"Database query failed, using NDJSON fallback: {e}")
        
        # Fallback to NDJSON
        if False:  # NDJSON fallback removed — DB-only mode
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
                scan_run_id,
                COUNT(*) as total_discoveries,
                COUNT(DISTINCT resource_uid) FILTER (WHERE resource_uid IS NOT NULL) as unique_resources,
                MAX(first_seen_at) as first_seen_at
            FROM discovery_findings
            WHERE tenant_id = %s
              {customer_filter}
            GROUP BY scan_run_id
        ),
        service_stats AS (
            SELECT
                service,
                COUNT(*) as total,
                COUNT(DISTINCT resource_uid) FILTER (WHERE resource_uid IS NOT NULL) as unique_resources,
                array_agg(DISTINCT region) FILTER (WHERE region IS NOT NULL) as regions
            FROM discovery_findings
            WHERE tenant_id = %s
              {customer_filter}
            GROUP BY service
            ORDER BY COUNT(*) DESC
            LIMIT 10
        )
        SELECT
            (SELECT COALESCE(SUM(total_discoveries), 0) FROM scan_stats) as total_discoveries,
            (SELECT COALESCE(SUM(unique_resources), 0) FROM scan_stats) as unique_resources,
            (SELECT COUNT(DISTINCT scan_run_id) FROM scan_stats) as total_scans,
            (SELECT COUNT(DISTINCT service) FROM discovery_findings
             WHERE tenant_id = %s {customer_filter}) as services_scanned,
            (SELECT json_agg(row_to_json(s.*)) FROM service_stats s) as top_services,
            (SELECT json_agg(row_to_json(sc.*) ORDER BY sc.first_seen_at DESC)
             FROM (SELECT * FROM scan_stats ORDER BY first_seen_at DESC LIMIT %s) sc) as recent_scans;
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
        if self._has_database_data(tenant_id):
            try:
                return self._list_scans_db(tenant_id, customer_id, page, page_size)
            except Exception as e:
                print(f"Database query failed, using NDJSON fallback: {e}")
        
        # Fallback to NDJSON
        if False:  # NDJSON fallback removed — DB-only mode
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
        SELECT COUNT(DISTINCT scan_run_id)
        FROM discovery_findings
        WHERE tenant_id = %s
          {customer_filter};
        """

        # Get scans with aggregations
        list_query = f"""
        SELECT
            scan_run_id,
            customer_id,
            tenant_id,
            provider,
            account_id,
            hierarchy_type,
            COUNT(*) as total_discoveries,
            COUNT(DISTINCT resource_uid) FILTER (WHERE resource_uid IS NOT NULL) as unique_resources,
            COUNT(DISTINCT service) as services_scanned,
            COUNT(DISTINCT region) FILTER (WHERE region IS NOT NULL) as regions_scanned,
            MAX(first_seen_at) as first_seen_at
        FROM discovery_findings
        WHERE tenant_id = %s
          {customer_filter}
        GROUP BY scan_run_id, customer_id, tenant_id, provider, account_id, hierarchy_type
        ORDER BY MAX(first_seen_at) DESC
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
        if self._has_database_data(tenant_id):
            try:
                return self._get_scan_summary_db(scan_id, tenant_id)
            except Exception as e:
                print(f"Database query failed, using NDJSON fallback: {e}")
        
        # Fallback to NDJSON
        if False:  # NDJSON fallback removed — DB-only mode
            return self._get_ndjson_fallback('get_scan_summary', scan_id, tenant_id)
        
        return None
    
    def _get_scan_summary_db(self, scan_id: str, tenant_id: str) -> Optional[Dict]:
        """Get scan summary from database"""
        query = """
        SELECT
            scan_run_id,
            customer_id,
            tenant_id,
            provider,
            account_id,
            hierarchy_type,
            COUNT(*) as total_discoveries,
            COUNT(DISTINCT resource_uid) FILTER (WHERE resource_uid IS NOT NULL) as unique_resources,
            COUNT(DISTINCT service) as services_scanned,
            COUNT(DISTINCT region) FILTER (WHERE region IS NOT NULL) as regions_scanned,
            MAX(first_seen_at) as first_seen_at
        FROM discovery_findings
        WHERE scan_run_id = %s
          AND tenant_id = %s
        GROUP BY scan_run_id, customer_id, tenant_id, provider, account_id, hierarchy_type;
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
        if self._has_database_data(tenant_id):
            try:
                return self._get_service_stats_db(scan_id, tenant_id)
            except Exception as e:
                print(f"Database query failed, using NDJSON fallback: {e}")
        
        # Fallback to NDJSON
        if False:  # NDJSON fallback removed — DB-only mode
            return self._get_ndjson_fallback('get_service_stats', scan_id, tenant_id)
        
        return []
    
    def _get_service_stats_db(self, scan_id: str, tenant_id: str) -> List[Dict]:
        """Get service stats from database"""
        query = """
        SELECT
            service,
            COUNT(*) as total_discoveries,
            COUNT(DISTINCT resource_uid) FILTER (WHERE resource_uid IS NOT NULL) as unique_resources,
            array_agg(DISTINCT region) FILTER (WHERE region IS NOT NULL) as regions,
            array_agg(DISTINCT discovery_id) as discovery_functions
        FROM discovery_findings
        WHERE scan_run_id = %s
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
        if self._has_database_data(tenant_id):
            try:
                return self._get_service_detail_db(scan_id, service, tenant_id)
            except Exception as e:
                print(f"Database query failed, using NDJSON fallback: {e}")
        
        # Fallback to NDJSON
        if False:  # NDJSON fallback removed — DB-only mode
            return self._get_ndjson_fallback('get_service_detail', scan_id, service, tenant_id)
        
        return None
    
    def _get_service_detail_db(self, scan_id: str, service: str, tenant_id: str) -> Optional[Dict]:
        """Get service detail from database"""
        # Overall stats
        stats_query = """
        SELECT
            service,
            COUNT(*) as total_discoveries,
            COUNT(DISTINCT resource_uid) FILTER (WHERE resource_uid IS NOT NULL) as unique_resources,
            array_agg(DISTINCT region) FILTER (WHERE region IS NOT NULL) as regions
        FROM discovery_findings
        WHERE scan_run_id = %s
          AND service = %s
          AND tenant_id = %s
        GROUP BY service;
        """

        # Discovery function stats
        functions_query = """
        SELECT
            discovery_id,
            COUNT(*) as total,
            COUNT(DISTINCT resource_uid) FILTER (WHERE resource_uid IS NOT NULL) as unique_resources,
            array_agg(DISTINCT resource_uid) FILTER (WHERE resource_uid IS NOT NULL) as resource_uids
        FROM discovery_findings
        WHERE scan_run_id = %s
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
                       discovery_id: Optional[str] = None, resource_uid: Optional[str] = None,
                       page: int = 1, page_size: int = 50) -> Tuple[List[Dict], int]:
        """
        Get discoveries with filtering and pagination.
        Falls back to NDJSON if database is empty.
        """
        # Try database first
        if tenant_id and self._has_database_data(tenant_id):
            try:
                return self._get_discoveries_db(scan_id, tenant_id, customer_id, service, discovery_id, resource_uid, page, page_size)
            except Exception as e:
                print(f"Database query failed, using NDJSON fallback: {e}")
        
        # Fallback to NDJSON
        if False:  # NDJSON fallback removed — DB-only mode
            return self._get_ndjson_fallback('get_discoveries', scan_id, tenant_id, customer_id, service, discovery_id, resource_uid, page, page_size)
        
        return [], 0
    
    def _get_discoveries_db(self, scan_id: Optional[str] = None, tenant_id: str = None,
                           customer_id: Optional[str] = None, service: Optional[str] = None,
                           discovery_id: Optional[str] = None, resource_uid: Optional[str] = None,
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
            where_clauses.append("scan_run_id = %s")
            params.append(scan_id)

        if service:
            where_clauses.append("service = %s")
            params.append(service)
        
        if discovery_id:
            where_clauses.append("discovery_id = %s")
            params.append(discovery_id)
        
        if resource_uid:
            where_clauses.append("resource_uid = %s")
            params.append(resource_uid)
        
        where_sql = " AND ".join(where_clauses) if where_clauses else "TRUE"
        
        # Count query
        count_query = f"""
        SELECT COUNT(*)
        FROM discovery_findings
        WHERE {where_sql};
        """
        
        # List query
        list_query = f"""
        SELECT
            id,
            scan_run_id,
            customer_id,
            tenant_id,
            provider,
            account_id,
            hierarchy_type,
            discovery_id,
            region,
            service,
            resource_uid,
            resource_id,
            raw_response,
            emitted_fields,
            config_hash,
            first_seen_at,
            version
        FROM discovery_findings
        WHERE {where_sql}
        ORDER BY first_seen_at DESC, id DESC
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
                'scan_id': disc['scan_run_id'],
                'customer_id': disc['customer_id'],
                'tenant_id': disc['tenant_id'],
                'provider': disc['provider'],
                'account_id': disc['account_id'],
                'hierarchy_type': disc['hierarchy_type'],
                'discovery_id': disc['discovery_id'],
                'region': disc.get('region'),
                'service': disc['service'],
                'resource_uid': disc.get('resource_uid'),
                'resource_id': disc.get('resource_id'),
                'raw_response': disc.get('raw_response', {}),
                'emitted_fields': disc.get('emitted_fields', {}),
                'config_hash': disc.get('config_hash'),
                'first_seen_at': disc['first_seen_at'],
                'version': disc.get('version', 1)
            })
        
        return formatted, total
    
    def get_resource_discoveries(self, resource_uid: str, tenant_id: str,
                                customer_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Get all discoveries for a specific resource ARN.
        Falls back to NDJSON if database is empty.
        """
        # Try database first
        if self._has_database_data(tenant_id):
            try:
                return self._get_resource_discoveries_db(resource_uid, tenant_id, customer_id)
            except Exception as e:
                print(f"Database query failed, using NDJSON fallback: {e}")
        
        # Fallback to NDJSON
        if False:  # NDJSON fallback removed — DB-only mode
            return self._get_ndjson_fallback('get_resource_discoveries', resource_uid, tenant_id, customer_id)
        
        return None
    
    def _get_resource_discoveries_db(self, resource_uid: str, tenant_id: str,
                                    customer_id: Optional[str] = None) -> Dict[str, Any]:
        """Get resource discoveries from database"""
        where_clauses = ["resource_uid = %s", "tenant_id = %s"]
        params = [resource_uid, tenant_id]
        
        if customer_id:
            where_clauses.append("customer_id = %s")
            params.append(customer_id)
        
        where_sql = " AND ".join(where_clauses)
        
        query = f"""
        SELECT
            id,
            scan_run_id,
            customer_id,
            tenant_id,
            provider,
            account_id,
            discovery_id,
            region,
            service,
            resource_uid,
            resource_id,
            raw_response,
            emitted_fields,
            config_hash,
            first_seen_at,
            version
        FROM discovery_findings
        WHERE {where_sql}
        ORDER BY first_seen_at DESC
        LIMIT 1000;
        """

        discoveries = self._execute_query(query, params)

        if not discoveries:
            return None

        # Calculate stats
        discovery_functions = list(set(d['discovery_id'] for d in discoveries))
        
        return {
            'resource_uid': resource_uid,
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
        if self._has_database_data(tenant_id):
            try:
                return self._get_discovery_function_detail_db(discovery_id, tenant_id, customer_id, scan_id)
            except Exception as e:
                print(f"Database query failed, using NDJSON fallback: {e}")
        
        # Fallback to NDJSON
        if False:  # NDJSON fallback removed — DB-only mode
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
            where_clauses.append("scan_run_id = %s")
            params.append(scan_id)

        where_sql = " AND ".join(where_clauses)

        query = f"""
        SELECT
            id,
            scan_run_id,
            customer_id,
            tenant_id,
            provider,
            account_id,
            discovery_id,
            region,
            service,
            resource_uid,
            resource_id,
            raw_response,
            emitted_fields,
            config_hash,
            first_seen_at,
            version
        FROM discovery_findings
        WHERE {where_sql}
        ORDER BY first_seen_at DESC
        LIMIT 1000;
        """
        
        discoveries = self._execute_query(query, params)
        
        if not discoveries:
            return None
        
        # Extract service from discovery_id (e.g., aws.s3.list_buckets → s3)
        service = discovery_id.split('.')[1] if '.' in discovery_id else 'unknown'
        
        # Get unique resource ARNs
        resources = list(set(d['resource_uid'] for d in discoveries if d.get('resource_uid')))
        
        return {
            'discovery_id': discovery_id,
            'service': service,
            'total_discoveries': len(discoveries),
            'resources_discovered': resources,
            'discoveries': [dict(d) for d in discoveries]
        }

    def get_latest_scan(self, tenant_id: str, account_id: Optional[str] = None,
                        service: Optional[str] = None,
                        start_time: Optional[datetime] = None,
                        end_time: Optional[datetime] = None) -> Optional[Dict[str, Any]]:
        """
        Get latest discovery scan ID and timestamp for tenant/account/service.
        """
        where_clauses = ["tenant_id = %s"]
        params = [tenant_id]

        if account_id:
            where_clauses.append("account_id = %s")
            params.append(account_id)

        if service:
            where_clauses.append("service = %s")
            params.append(service)

        if start_time:
            where_clauses.append("first_seen_at >= %s")
            params.append(start_time)
        if end_time:
            where_clauses.append("first_seen_at <= %s")
            params.append(end_time)

        where_sql = " AND ".join(where_clauses)

        query = f"""
        SELECT scan_run_id, MAX(first_seen_at) as first_seen_at
        FROM discovery_findings
        WHERE {where_sql}
        GROUP BY scan_run_id
        ORDER BY MAX(first_seen_at) DESC
        LIMIT 1;
        """

        return self._execute_query_one(query, params)

    def get_previous_scan(self, tenant_id: str, current_scan_id: str,
                          account_id: Optional[str] = None,
                          service: Optional[str] = None,
                          start_time: Optional[datetime] = None,
                          end_time: Optional[datetime] = None) -> Optional[Dict[str, Any]]:
        """
        Get previous discovery scan (immediately before current) for tenant/account/service.
        """
        where_clauses = ["tenant_id = %s", "scan_run_id != %s"]
        params = [tenant_id, current_scan_id]

        if account_id:
            where_clauses.append("account_id = %s")
            params.append(account_id)

        if service:
            where_clauses.append("service = %s")
            params.append(service)

        if start_time:
            where_clauses.append("first_seen_at >= %s")
            params.append(start_time)
        if end_time:
            where_clauses.append("first_seen_at <= %s")
            params.append(end_time)

        where_sql = " AND ".join(where_clauses)

        query = f"""
        SELECT scan_run_id, MAX(first_seen_at) as first_seen_at
        FROM discovery_findings
        WHERE {where_sql}
        GROUP BY scan_run_id
        ORDER BY MAX(first_seen_at) DESC
        LIMIT 1;
        """

        return self._execute_query_one(query, params)

    def get_configuration_drift(self, tenant_id: str, current_scan_id: str,
                                account_id: Optional[str] = None,
                                service: Optional[str] = None,
                                discovery_id: Optional[str] = None,
                                region: Optional[str] = None,
                                start_time: Optional[datetime] = None,
                                end_time: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """
        Get configuration drift events for a scan from discovery_history.
        """
        where_clauses = ["dh.tenant_id = %s", "dh.discovery_scan_id = %s", "dh.change_type = 'modified'"]
        params = [tenant_id, current_scan_id]

        if account_id:
            where_clauses.append("dh.account_id = %s")
            params.append(account_id)

        if service:
            where_clauses.append("d.service = %s")
            params.append(service)

        if discovery_id:
            where_clauses.append("dh.discovery_id = %s")
            params.append(discovery_id)

        if region:
            where_clauses.append("d.region = %s")
            params.append(region)

        if start_time:
            where_clauses.append("dh.first_seen_at >= %s")
            params.append(start_time)
        if end_time:
            where_clauses.append("dh.first_seen_at <= %s")
            params.append(end_time)

        where_sql = " AND ".join(where_clauses)

        query = f"""
        SELECT
            dh.*,
            d.service,
            d.region,
            prev.scan_run_id as baseline_scan_id
        FROM discovery_history dh
        LEFT JOIN discovery_findings d
          ON d.scan_run_id = dh.discovery_scan_id
         AND d.discovery_id = dh.discovery_id
         AND d.resource_uid = dh.resource_uid
         AND d.tenant_id = dh.tenant_id
        LEFT JOIN LATERAL (
            SELECT scan_run_id
            FROM discovery_history
            WHERE tenant_id = dh.tenant_id
              AND discovery_id = dh.discovery_id
              AND resource_uid = dh.resource_uid
              AND first_seen_at < dh.first_seen_at
            ORDER BY first_seen_at DESC
            LIMIT 1
        ) prev ON true
        WHERE {where_sql}
        ORDER BY dh.first_seen_at DESC;
        """

        results = self._execute_query(query, params)

        # Parse JSONB fields
        for result in results:
            if isinstance(result.get('emitted_fields'), str):
                try:
                    result['emitted_fields'] = json.loads(result['emitted_fields'])
                except Exception:
                    result['emitted_fields'] = {}
            if isinstance(result.get('diff_summary'), str):
                try:
                    result['diff_summary'] = json.loads(result['diff_summary'])
                except Exception:
                    result['diff_summary'] = {}

        return [dict(r) for r in results]
