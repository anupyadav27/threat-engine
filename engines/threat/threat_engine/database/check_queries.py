"""
Database queries for Check Results

Reads from PostgreSQL check_findings table created by check engine.
Optimized queries using existing indexes for performance.
"""

import os
import sys
import json
import psycopg2
from psycopg2.extras import RealDictCursor
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
from pathlib import Path


def _get_check_conn():
    """Return a fresh psycopg2 connection to the check DB via env vars."""
    return psycopg2.connect(
        host=os.getenv("CHECK_DB_HOST", "localhost"),
        port=int(os.getenv("CHECK_DB_PORT", "5432")),
        dbname=os.getenv("CHECK_DB_NAME", "threat_engine_check"),
        user=os.getenv("CHECK_DB_USER", "postgres"),
        password=os.getenv("CHECK_DB_PASSWORD", ""),
        connect_timeout=10,
    )


class CheckDatabaseQueries:
    """Database queries for check results using direct psycopg2 connections."""

    def __init__(self, **kwargs):
        """Initialize — connection is created per-query."""
        pass

    def _has_database_data(self, tenant_id: str) -> bool:
        """Check if database has data for tenant"""
        try:
            result = self._execute_query_one(
                "SELECT COUNT(*) as count FROM check_findings WHERE tenant_id = %s LIMIT 1",
                [tenant_id]
            )
            return result and result.get('count', 0) > 0
        except Exception:
            return False

    def _execute_query(self, query: str, params: List = None):
        """Execute a query using direct psycopg2 connection."""
        conn = _get_check_conn()
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
        conn = _get_check_conn()
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
    
    def get_dashboard_stats(self, tenant_id: str, customer_id: Optional[str] = None,
                           limit_recent_scans: int = 5) -> Dict[str, Any]:
        """
        Get dashboard statistics with aggregations.
        Uses indexes: idx_check_results_tenant, idx_check_results_status
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
            'total_checks': 0,
            'passed': 0,
            'failed': 0,
            'error': 0,
            'pass_rate': 0.0,
            'services_scanned': 0,
            'top_failing_services': [],
            'recent_scans': []
        }
    
    def _get_dashboard_stats_db(self, tenant_id: str, customer_id: Optional[str] = None,
                           limit_recent_scans: int = 5) -> Dict[str, Any]:
        """
        Get dashboard statistics from database.
        """
        # Build customer filter
        if customer_id:
            customer_filter = "AND customer_id = %s"
            scan_params = [tenant_id, customer_id]
            service_params = [tenant_id, customer_id]
            count_params = [tenant_id, customer_id]
        else:
            customer_filter = ""
            scan_params = [tenant_id]
            service_params = [tenant_id]
            count_params = [tenant_id]
        
        query = f"""
        WITH scan_stats AS (
            SELECT 
                scan_run_id,
                COUNT(*) as total_checks,
                SUM(CASE WHEN status = 'PASS' THEN 1 ELSE 0 END) as passed,
                SUM(CASE WHEN status = 'FAIL' THEN 1 ELSE 0 END) as failed,
                SUM(CASE WHEN status = 'ERROR' THEN 1 ELSE 0 END) as error,
                MAX(created_at) as created_at
            FROM check_findings
            WHERE tenant_id = %s
              {customer_filter}
            GROUP BY scan_run_id
        ),
        service_stats AS (
            SELECT
                COALESCE(resource_service, resource_type) as service,
                COUNT(*) as total,
                SUM(CASE WHEN status = 'PASS' THEN 1 ELSE 0 END) as passed,
                SUM(CASE WHEN status = 'FAIL' THEN 1 ELSE 0 END) as failed,
                SUM(CASE WHEN status = 'ERROR' THEN 1 ELSE 0 END) as error
            FROM check_findings
            WHERE tenant_id = %s
              {customer_filter}
            GROUP BY COALESCE(resource_service, resource_type)
            ORDER BY (SUM(CASE WHEN status = 'FAIL' THEN 1 ELSE 0 END)) DESC
            LIMIT 10
        )
        SELECT 
            (SELECT COALESCE(SUM(total_checks), 0) FROM scan_stats) as total_checks,
            (SELECT COALESCE(SUM(passed), 0) FROM scan_stats) as passed,
            (SELECT COALESCE(SUM(failed), 0) FROM scan_stats) as failed,
            (SELECT COALESCE(SUM(error), 0) FROM scan_stats) as error,
            (SELECT COUNT(DISTINCT scan_run_id) FROM scan_stats) as total_scans,
            (SELECT COUNT(DISTINCT resource_type) FROM check_findings 
             WHERE tenant_id = %s {customer_filter}) as services_scanned,
            (SELECT json_agg(row_to_json(s.*)) FROM service_stats s) as top_failing_services,
            (SELECT json_agg(row_to_json(sc.*) ORDER BY sc.created_at DESC) 
             FROM (SELECT * FROM scan_stats ORDER BY created_at DESC LIMIT %s) sc) as recent_scans;
        """
        
        params = scan_params + service_params + count_params + [limit_recent_scans]
        
        result = self._execute_query_one(query, params)
        
        if not result:
            return {
                        'total_checks': 0,
                        'passed': 0,
                        'failed': 0,
                        'error': 0,
                        'pass_rate': 0.0,
                        'services_scanned': 0,
                        'top_failing_services': [],
                        'recent_scans': []
                    }
                
        total = result['total_checks'] or 0
        passed = result['passed'] or 0
        
        return {
            'total_checks': total,
            'passed': passed,
            'failed': result['failed'] or 0,
            'error': result['error'] or 0,
            'pass_rate': round((passed / total * 100) if total > 0 else 0.0, 2),
            'services_scanned': result['services_scanned'] or 0,
            'accounts_scanned': 1,  # TODO: Count distinct account_ids
            'top_failing_services': result['top_failing_services'] or [],
            'recent_scans': result['recent_scans'] or [],
            'last_created_at': None  # Will be populated from recent_scans
        }
    
    def list_scans(self, tenant_id: str, customer_id: Optional[str] = None,
                   page: int = 1, page_size: int = 20) -> Tuple[List[Dict], int]:
        """
        List check scans with pagination.
        Uses index: idx_check_results_tenant, idx_check_results_status
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
        """
        List scans from database.
        """
        offset = (page - 1) * page_size
        
        # Get total count
        count_query = """
        SELECT COUNT(DISTINCT scan_run_id)
        FROM check_findings
        WHERE tenant_id = %s
          AND ($1 OR customer_id = %s);
        """
        
        # Get scans with aggregations
        list_query = """
        SELECT
            scan_run_id,
            MAX(finding_data->>'discovery_id') as scan_run_id,
            customer_id,
            tenant_id,
            provider,
            account_id,
            hierarchy_type,
            COUNT(*) as total_checks,
            SUM(CASE WHEN status = 'PASS' THEN 1 ELSE 0 END) as passed,
            SUM(CASE WHEN status = 'FAIL' THEN 1 ELSE 0 END) as failed,
            SUM(CASE WHEN status = 'ERROR' THEN 1 ELSE 0 END) as error,
            COUNT(DISTINCT resource_type) as services_scanned,
            MAX(created_at) as created_at
        FROM check_findings
        WHERE tenant_id = %s
          AND ($1 OR customer_id = %s)
        GROUP BY scan_run_id, customer_id, tenant_id, provider, account_id, hierarchy_type
        ORDER BY MAX(created_at) DESC
        LIMIT %s OFFSET %s;
        """
        
        # Get total
        total_result = self._execute_query_one(count_query, [customer_id is None, tenant_id, customer_id or ''])
        total = total_result['count']
        
        # Get scans
        scans = self._execute_query(list_query, [
            customer_id is None, tenant_id, customer_id or '',
            page_size, offset
        ])
        
        # Calculate pass_rate for each
        for scan in scans:
            total_checks = scan['total_checks']
            scan['pass_rate'] = round(
                (scan['passed'] / total_checks * 100) if total_checks > 0 else 0.0, 
                2
            )
        
        return scans, total
    
    def get_scan_summary(self, scan_id: str, tenant_id: str) -> Optional[Dict]:
        """
        Get summary for a specific scan.
        Uses index: idx_check_results_scan
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
        """
        Get scan summary from database.
        """
        query = """
        SELECT
            scan_run_id,
            customer_id,
            tenant_id,
            provider,
            account_id,
            hierarchy_type,
            COUNT(*) as total_checks,
            SUM(CASE WHEN status = 'PASS' THEN 1 ELSE 0 END) as passed,
            SUM(CASE WHEN status = 'FAIL' THEN 1 ELSE 0 END) as failed,
            SUM(CASE WHEN status = 'ERROR' THEN 1 ELSE 0 END) as error,
            COUNT(DISTINCT resource_type) as services_scanned,
            MAX(created_at) as created_at,
            array_agg(DISTINCT resource_type ORDER BY resource_type) as services
        FROM check_findings
        WHERE scan_run_id = %s
          AND tenant_id = %s
        GROUP BY scan_run_id, customer_id, tenant_id, provider, account_id, hierarchy_type;
        """
        
        result = self._execute_query_one(query, [scan_id, tenant_id])
        
        if not result:
            return None
        
        total = result['total_checks']
        result['pass_rate'] = round(
            (result['passed'] / total * 100) if total > 0 else 0.0,
            2
        )
        
        return dict(result)
    
    def get_service_stats(self, scan_id: str, tenant_id: str) -> List[Dict]:
        """
        Get statistics for all services in a scan.
        Uses index: idx_check_results_scan
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
        """
        Get service stats from database.
        """
        query = """
        SELECT
            COALESCE(resource_service, resource_type) as service,
            COUNT(*) as total,
            SUM(CASE WHEN status = 'PASS' THEN 1 ELSE 0 END) as passed,
            SUM(CASE WHEN status = 'FAIL' THEN 1 ELSE 0 END) as failed,
            SUM(CASE WHEN status = 'ERROR' THEN 1 ELSE 0 END) as error
        FROM check_findings
        WHERE scan_run_id = %s
          AND tenant_id = %s
        GROUP BY COALESCE(resource_service, resource_type)
        ORDER BY COALESCE(resource_service, resource_type);
        """
        
        results = self._execute_query(query, [scan_id, tenant_id])
        
        # Add pass_rate
        for row in results:
            total = row['total']
            row['pass_rate'] = round(
                (row['passed'] / total * 100) if total > 0 else 0.0,
                2
            )
        
        return results
    
    def get_service_detail(self, scan_id: str, service: str, tenant_id: str) -> Optional[Dict]:
        """
        Get detailed statistics for a specific service in a scan.
        Uses index: idx_check_results_scan
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
        """
        Get service detail from database.
        """
        # Get overall stats
        stats_query = """
        SELECT
            COALESCE(resource_service, resource_type) as service,
            COUNT(*) as total_checks,
            SUM(CASE WHEN status = 'PASS' THEN 1 ELSE 0 END) as passed,
            SUM(CASE WHEN status = 'FAIL' THEN 1 ELSE 0 END) as failed,
            SUM(CASE WHEN status = 'ERROR' THEN 1 ELSE 0 END) as error,
            COUNT(DISTINCT resource_uid) FILTER (WHERE resource_uid IS NOT NULL) as resources_affected
        FROM check_findings
        WHERE scan_run_id = %s
          AND COALESCE(resource_service, resource_type) = %s
          AND tenant_id = %s
        GROUP BY COALESCE(resource_service, resource_type);
        """
        
        # Get rule stats
        rules_query = """
        SELECT 
            rule_id,
            COUNT(*) as total,
            SUM(CASE WHEN status = 'PASS' THEN 1 ELSE 0 END) as passed,
            SUM(CASE WHEN status = 'FAIL' THEN 1 ELSE 0 END) as failed,
            SUM(CASE WHEN status = 'ERROR' THEN 1 ELSE 0 END) as error,
            array_agg(DISTINCT resource_uid) FILTER (WHERE resource_uid IS NOT NULL) as resource_uids
        FROM check_findings
        WHERE scan_run_id = %s
          AND resource_type = %s
          AND tenant_id = %s
        GROUP BY rule_id
        ORDER BY (SUM(CASE WHEN status = 'FAIL' THEN 1 ELSE 0 END)) DESC
        LIMIT 50;
        """
        
        # Get stats
        stats = self._execute_query_one(stats_query, [scan_id, service, tenant_id])
        
        if not stats:
            return None
        
        # Get rules
        rules = self._execute_query(rules_query, [scan_id, service, tenant_id])
        
        total = stats['total_checks']
        
        return {
                    'service': service,
                    'scan_id': scan_id,
                    'total_checks': total,
                    'passed': stats['passed'],
                    'failed': stats['failed'],
                    'error': stats['error'],
                    'pass_rate': round((stats['passed'] / total * 100) if total > 0 else 0.0, 2),
                    'resources_affected': stats['resources_affected'],
                    'rules': [dict(r) for r in rules],
            'top_failing_rules': [dict(r) for r in rules[:10]]
        }
    
    def get_findings(self, scan_id: Optional[str] = None, tenant_id: str = None,
                    customer_id: Optional[str] = None, service: Optional[str] = None,
                    status: Optional[str] = None, rule_id: Optional[str] = None,
                    resource_uid: Optional[str] = None,
                    page: int = 1, page_size: int = 50) -> Tuple[List[Dict], int]:
        """
        Get findings with filtering and pagination.
        Uses indexes: idx_check_results_scan, idx_check_results_tenant, idx_check_results_status
        Falls back to NDJSON if database is empty.
        """
        # Try database first
        if tenant_id and self._has_database_data(tenant_id):
            try:
                return self._get_findings_db(scan_id, tenant_id, customer_id, service, status, rule_id, resource_uid, page, page_size)
            except Exception as e:
                print(f"Database query failed, using NDJSON fallback: {e}")
        
        # Fallback to NDJSON
        if False:  # NDJSON fallback removed — DB-only mode
            return self._get_ndjson_fallback('get_findings', scan_id, tenant_id, customer_id, service, status, rule_id, resource_uid, page, page_size)
        
        return [], 0
    
    def _get_findings_db(self, scan_id: Optional[str] = None, tenant_id: str = None,
                    customer_id: Optional[str] = None, service: Optional[str] = None,
                    status: Optional[str] = None, rule_id: Optional[str] = None,
                    resource_uid: Optional[str] = None,
                    page: int = 1, page_size: int = 50) -> Tuple[List[Dict], int]:
        """
        Get findings from database.
        """
        offset = (page - 1) * page_size
        
        # Build WHERE clause dynamically
        where_clauses = []
        params = []
        
        if tenant_id:
            where_clauses.append(f"tenant_id = %s")
            params.append(tenant_id)
        
        if customer_id:
            where_clauses.append(f"customer_id = %s")
            params.append(customer_id)
        
        if scan_id:
            where_clauses.append(f"scan_run_id = %s")
            params.append(scan_id)

        if service:
            where_clauses.append(f"resource_type = %s")
            params.append(service)
        
        if status:
            where_clauses.append(f"status = %s")
            params.append(status.upper())
        
        if rule_id:
            where_clauses.append(f"rule_id = %s")
            params.append(rule_id)
        
        if resource_uid:
            where_clauses.append(f"resource_uid = %s")
            params.append(resource_uid)
        
        where_sql = " AND ".join(where_clauses) if where_clauses else "TRUE"
        
        # Count query
        count_query = f"""
        SELECT COUNT(*)
        FROM check_findings
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
            rule_id,
            resource_uid,
            resource_id,
            resource_type,
            status,
            checked_fields,
            finding_data,
            created_at
        FROM check_findings
        WHERE {where_sql}
        ORDER BY created_at DESC, id DESC
        LIMIT %s OFFSET %s;
        """
        
        # Get count
        total_result = self._execute_query_one(count_query, params)
        total = total_result['count']
        
        # Get findings
        findings = self._execute_query(list_query, params + [page_size, offset])
        
        # Parse JSONB fields
        for finding in findings:
            if isinstance(finding.get('checked_fields'), str):
                try:
                    finding['checked_fields'] = json.loads(finding['checked_fields'])
                except Exception:
                    finding['checked_fields'] = []
            
            if isinstance(finding.get('finding_data'), str):
                try:
                    finding['finding_data'] = json.loads(finding['finding_data'])
                except Exception:
                    finding['finding_data'] = {}
            
            # Note: discovery_id in finding_data is a discovery function ID, not a scan run ID
        
        return [dict(f) for f in findings], total
    
    def get_resource_findings(self, resource_uid: str, tenant_id: str,
                             customer_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Get all findings for a specific resource ARN.
        Uses index: idx_check_results_tenant (includes resource_uid in query)
        Falls back to NDJSON if database is empty.
        """
        # Try database first
        if self._has_database_data(tenant_id):
            try:
                return self._get_resource_findings_db(resource_uid, tenant_id, customer_id)
            except Exception as e:
                print(f"Database query failed, using NDJSON fallback: {e}")
        
        # Fallback to NDJSON
        if False:  # NDJSON fallback removed — DB-only mode
            return self._get_ndjson_fallback('get_resource_findings', resource_uid, tenant_id, customer_id)
        
        return None
    
    def _get_resource_findings_db(self, resource_uid: str, tenant_id: str,
                             customer_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Get resource findings from database.
        """
        query = """
        SELECT
            id,
            scan_run_id,
            customer_id,
            tenant_id,
            provider,
            account_id,
            hierarchy_type,
            rule_id,
            resource_uid,
            resource_id,
            resource_type,
            status,
            checked_fields,
            finding_data,
            created_at
        FROM check_findings
        WHERE resource_uid = %s
          AND tenant_id = %s
          AND ($1 OR customer_id = %s)
        ORDER BY created_at DESC;
        """
        
        findings = self._execute_query(query, [customer_id is None, resource_uid, tenant_id, customer_id or ''])
        
        if not findings:
            return None
        
        # Parse JSONB fields
        for finding in findings:
            if isinstance(finding.get('checked_fields'), str):
                finding['checked_fields'] = json.loads(finding['checked_fields'])
            if isinstance(finding.get('finding_data'), str):
                finding['finding_data'] = json.loads(finding['finding_data'])
        
        # Calculate stats
        total = len(findings)
        passed = sum(1 for f in findings if f['status'] == 'PASS')
        failed = sum(1 for f in findings if f['status'] == 'FAIL')
        
        return {
            'resource_uid': resource_uid,
            'resource_id': findings[0]['resource_id'] if findings else None,
            'resource_type': findings[0]['resource_type'] if findings else None,
            'total_findings': total,
            'passed': passed,
            'failed': failed,
            'findings': [dict(f) for f in findings]
        }
    
    def get_rule_findings(self, rule_id: str, tenant_id: str,
                         customer_id: Optional[str] = None,
                         scan_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Get all findings for a specific rule.
        Uses index: idx_check_results_rule
        Falls back to NDJSON if database is empty.
        """
        # Try database first
        if self._has_database_data(tenant_id):
            try:
                return self._get_rule_findings_db(rule_id, tenant_id, customer_id, scan_id)
            except Exception as e:
                print(f"Database query failed, using NDJSON fallback: {e}")
        
        # Fallback to NDJSON
        if False:  # NDJSON fallback removed — DB-only mode
            return self._get_ndjson_fallback('get_rule_findings', rule_id, tenant_id, customer_id, scan_id)
        
        return None
    
    def _get_rule_findings_db(self, rule_id: str, tenant_id: str,
                         customer_id: Optional[str] = None,
                         scan_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Get rule findings from database.
        """
        where_clauses = ["rule_id = %s", "tenant_id = %s"]
        params = [rule_id, tenant_id]
        
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
            rule_id,
            resource_uid,
            resource_id,
            resource_type,
            status,
            checked_fields,
            finding_data,
            created_at
        FROM check_findings
        WHERE {where_sql}
        ORDER BY created_at DESC
        LIMIT 1000;
        """
        
        findings = self._execute_query(query, params)
        
        if not findings:
            return None
        
        # Parse JSONB
        for finding in findings:
            if isinstance(finding.get('checked_fields'), str):
                finding['checked_fields'] = json.loads(finding['checked_fields'])
            if isinstance(finding.get('finding_data'), str):
                finding['finding_data'] = json.loads(finding['finding_data'])
        
        # Stats
        total = len(findings)
        passed = sum(1 for f in findings if f['status'] == 'PASS')
        failed = sum(1 for f in findings if f['status'] == 'FAIL')
        error = sum(1 for f in findings if f['status'] == 'ERROR')
        
        # Extract service from rule_id (e.g., aws.s3.bucket.* → s3)
        service = rule_id.split('.')[1] if '.' in rule_id else 'unknown'
        
        # Get unique resource ARNs
        resources = list(set(f['resource_uid'] for f in findings if f.get('resource_uid')))
        
        return {
            'rule_id': rule_id,
            'service': service,
            'total_findings': total,
            'passed': passed,
            'failed': failed,
            'error': error,
            'findings': [dict(f) for f in findings],
            'resources_affected': resources
        }
    
    def search_findings(self, query: str, tenant_id: str,
                       customer_id: Optional[str] = None,
                       filters: Optional[Dict] = None,
                       page: int = 1, page_size: int = 50) -> Tuple[List[Dict], int]:
        """
        Search findings by query string (ARN, rule ID, or service).
        Uses indexes based on search type.
        """
        offset = (page - 1) * page_size
        
        # Determine search type
        if query.startswith('arn:aws:'):
            # ARN search
            return self.get_findings(
                tenant_id=tenant_id,
                customer_id=customer_id,
                resource_uid=query,
                page=page,
                page_size=page_size
            )
        elif '.' in query and query.startswith('aws.'):
            # Rule ID search
            return self.get_findings(
                tenant_id=tenant_id,
                customer_id=customer_id,
                rule_id=query,
                page=page,
                page_size=page_size
            )
        else:
            # Service search
            return self.get_findings(
                tenant_id=tenant_id,
                customer_id=customer_id,
                service=query,
                status=filters.get('status') if filters else None,
                page=page,
                page_size=page_size
            )

    def get_latest_scan(self, tenant_id: str, account_id: Optional[str] = None,
                        service: Optional[str] = None,
                        start_time: Optional[datetime] = None,
                        end_time: Optional[datetime] = None) -> Optional[Dict[str, Any]]:
        """
        Get latest check scan ID and timestamp for tenant/account/service.
        """
        where_clauses = ["tenant_id = %s"]
        params = [tenant_id]

        if account_id:
            where_clauses.append("account_id = %s")
            params.append(account_id)

        if service:
            where_clauses.append("resource_type = %s")
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
        FROM check_findings
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
        Get previous scan (immediately before current) for tenant/account/service.
        """
        where_clauses = ["tenant_id = %s", "scan_run_id != %s"]
        params = [tenant_id, current_scan_id]

        if account_id:
            where_clauses.append("account_id = %s")
            params.append(account_id)

        if service:
            where_clauses.append("resource_type = %s")
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
        FROM check_findings
        WHERE {where_sql}
        GROUP BY scan_run_id
        ORDER BY MAX(first_seen_at) DESC
        LIMIT 1;
        """

        return self._execute_query_one(query, params)

    def get_check_results_for_scan(self, scan_id: str, tenant_id: str,
                                   account_id: Optional[str] = None,
                                   service: Optional[str] = None,
                                   include_metadata: bool = True) -> List[Dict[str, Any]]:
        """
        Get check results for a scan, optionally enriched with rule metadata.
        """
        where_clauses = ["cr.scan_run_id = %s", "cr.tenant_id = %s"]
        params = [scan_id, tenant_id]

        if account_id:
            where_clauses.append("cr.account_id = %s")
            params.append(account_id)

        if service:
            where_clauses.append("cr.resource_type = %s")
            params.append(service)

        where_sql = " AND ".join(where_clauses)

        if include_metadata:
            query = f"""
            SELECT cr.*, rm.severity as rule_severity, rm.title as rule_title
            FROM check_findings cr
            LEFT JOIN rule_metadata rm ON cr.rule_id = rm.rule_id
            WHERE {where_sql}
            ORDER BY cr.rule_id, cr.resource_uid;
            """
        else:
            query = f"""
            SELECT cr.*
            FROM check_findings cr
            WHERE {where_sql}
            ORDER BY cr.rule_id, cr.resource_uid;
            """

        results = self._execute_query(query, params)

        # Parse JSONB fields
        for result in results:
            if isinstance(result.get('checked_fields'), str):
                try:
                    result['checked_fields'] = json.loads(result['checked_fields'])
                except Exception:
                    result['checked_fields'] = []
            if isinstance(result.get('finding_data'), str):
                try:
                    result['finding_data'] = json.loads(result['finding_data'])
                except Exception:
                    result['finding_data'] = {}

        return [dict(r) for r in results]
