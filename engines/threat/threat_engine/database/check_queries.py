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

# Add configScan engine to path for DatabaseManager
THREAT_ENGINE_ROOT = Path(__file__).parent.parent.parent.parent
CONFIGSCAN_ENGINE_PATH = THREAT_ENGINE_ROOT / "engine_configscan" / "engine_configscan_aws"

if str(CONFIGSCAN_ENGINE_PATH) not in sys.path:
    sys.path.insert(0, str(CONFIGSCAN_ENGINE_PATH))

try:
    from engine.database_manager import DatabaseManager
except ImportError as e:
    print(f"Warning: DatabaseManager import failed: {e}")
    print(f"Tried path: {CONFIGSCAN_ENGINE_PATH}")
    DatabaseManager = None

# Import NDJSON reader as fallback
try:
    from .ndjson_reader import NDJSONCheckReader
except ImportError:
    NDJSONCheckReader = None


class CheckDatabaseQueries:
    """Database queries for check results using existing DatabaseManager with NDJSON fallback"""
    
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
                self.own_connection = False
        else:
            self.db = None
            self.own_connection = False
        
        # Initialize NDJSON reader if fallback enabled
        if use_ndjson_fallback and NDJSONCheckReader:
            self.ndjson_reader = NDJSONCheckReader()
    
    def _has_database_data(self, tenant_id: str) -> bool:
        """Check if database has data for tenant"""
        if not self.db:
            return False
        
        try:
            result = self._execute_query_one(
                "SELECT COUNT(*) as count FROM check_findings WHERE tenant_id = %s LIMIT 1",
                [tenant_id]
            )
            return result and result.get('count', 0) > 0
        except:
            return False
    
    def _get_ndjson_fallback(self, method_name: str, *args, **kwargs):
        """Get data from NDJSON fallback"""
        if not self.ndjson_reader:
            raise ValueError("NDJSON fallback not available")
        
        method = getattr(self.ndjson_reader, method_name, None)
        if not method:
            raise ValueError(f"Method {method_name} not found in NDJSON reader")
        
        return method(*args, **kwargs)
    
    def __del__(self):
        """Close connection if we own it"""
        if self.own_connection and hasattr(self, 'db'):
            try:
                self.db.close()
            except:
                pass
    
    def _execute_query(self, query: str, params: List = None):
        """
        Execute a query using DatabaseManager.
        Returns cursor with results.
        """
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
    
    def get_dashboard_stats(self, tenant_id: str, customer_id: Optional[str] = None,
                           limit_recent_scans: int = 5) -> Dict[str, Any]:
        """
        Get dashboard statistics with aggregations.
        Uses indexes: idx_check_results_tenant, idx_check_results_status
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
                check_scan_id,
                COUNT(*) as total_checks,
                SUM(CASE WHEN status = 'PASS' THEN 1 ELSE 0 END) as passed,
                SUM(CASE WHEN status = 'FAIL' THEN 1 ELSE 0 END) as failed,
                SUM(CASE WHEN status = 'ERROR' THEN 1 ELSE 0 END) as error,
                MAX(scan_timestamp) as scan_timestamp
            FROM check_findings
            WHERE tenant_id = %s
              {customer_filter}
            GROUP BY check_scan_id
        ),
        service_stats AS (
            SELECT 
                resource_type as service,
                COUNT(*) as total,
                SUM(CASE WHEN status = 'PASS' THEN 1 ELSE 0 END) as passed,
                SUM(CASE WHEN status = 'FAIL' THEN 1 ELSE 0 END) as failed,
                SUM(CASE WHEN status = 'ERROR' THEN 1 ELSE 0 END) as error
            FROM check_findings
            WHERE tenant_id = %s
              {customer_filter}
            GROUP BY resource_type
            ORDER BY (SUM(CASE WHEN status = 'FAIL' THEN 1 ELSE 0 END)) DESC
            LIMIT 10
        )
        SELECT 
            (SELECT COALESCE(SUM(total_checks), 0) FROM scan_stats) as total_checks,
            (SELECT COALESCE(SUM(passed), 0) FROM scan_stats) as passed,
            (SELECT COALESCE(SUM(failed), 0) FROM scan_stats) as failed,
            (SELECT COALESCE(SUM(error), 0) FROM scan_stats) as error,
            (SELECT COUNT(DISTINCT check_scan_id) FROM scan_stats) as total_scans,
            (SELECT COUNT(DISTINCT resource_type) FROM check_findings 
             WHERE tenant_id = %s {customer_filter}) as services_scanned,
            (SELECT json_agg(row_to_json(s.*)) FROM service_stats s) as top_failing_services,
            (SELECT json_agg(row_to_json(sc.*) ORDER BY sc.scan_timestamp DESC) 
             FROM (SELECT * FROM scan_stats ORDER BY scan_timestamp DESC LIMIT %s) sc) as recent_scans;
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
            'accounts_scanned': 1,  # TODO: Count distinct hierarchy_ids
            'top_failing_services': result['top_failing_services'] or [],
            'recent_scans': result['recent_scans'] or [],
            'last_scan_timestamp': None  # Will be populated from recent_scans
        }
    
    def list_scans(self, tenant_id: str, customer_id: Optional[str] = None,
                   page: int = 1, page_size: int = 20) -> Tuple[List[Dict], int]:
        """
        List check scans with pagination.
        Uses index: idx_check_results_tenant, idx_check_results_status
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
        """
        List scans from database.
        """
        offset = (page - 1) * page_size
        
        # Get total count
        count_query = """
        SELECT COUNT(DISTINCT check_scan_id)
        FROM check_findings
        WHERE tenant_id = %s
          AND ($1 OR customer_id = %s);
        """
        
        # Get scans with aggregations
        list_query = """
        SELECT
            check_scan_id,
            MAX(finding_data->>'discovery_id') as discovery_scan_id,
            customer_id,
            tenant_id,
            provider,
            hierarchy_id,
            hierarchy_type,
            COUNT(*) as total_checks,
            SUM(CASE WHEN status = 'PASS' THEN 1 ELSE 0 END) as passed,
            SUM(CASE WHEN status = 'FAIL' THEN 1 ELSE 0 END) as failed,
            SUM(CASE WHEN status = 'ERROR' THEN 1 ELSE 0 END) as error,
            COUNT(DISTINCT resource_type) as services_scanned,
            MAX(scan_timestamp) as scan_timestamp
        FROM check_findings
        WHERE tenant_id = %s
          AND ($1 OR customer_id = %s)
        GROUP BY check_scan_id, customer_id, tenant_id, provider, hierarchy_id, hierarchy_type
        ORDER BY MAX(scan_timestamp) DESC
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
        """
        Get scan summary from database.
        """
        query = """
        SELECT
            check_scan_id,
            customer_id,
            tenant_id,
            provider,
            hierarchy_id,
            hierarchy_type,
            COUNT(*) as total_checks,
            SUM(CASE WHEN status = 'PASS' THEN 1 ELSE 0 END) as passed,
            SUM(CASE WHEN status = 'FAIL' THEN 1 ELSE 0 END) as failed,
            SUM(CASE WHEN status = 'ERROR' THEN 1 ELSE 0 END) as error,
            COUNT(DISTINCT resource_type) as services_scanned,
            MAX(scan_timestamp) as scan_timestamp,
            array_agg(DISTINCT resource_type ORDER BY resource_type) as services
        FROM check_findings
        WHERE check_scan_id = %s
          AND tenant_id = %s
        GROUP BY check_scan_id, customer_id, tenant_id, provider, hierarchy_id, hierarchy_type;
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
        """
        Get service stats from database.
        """
        query = """
        SELECT 
            resource_type as service,
            COUNT(*) as total,
            SUM(CASE WHEN status = 'PASS' THEN 1 ELSE 0 END) as passed,
            SUM(CASE WHEN status = 'FAIL' THEN 1 ELSE 0 END) as failed,
            SUM(CASE WHEN status = 'ERROR' THEN 1 ELSE 0 END) as error
        FROM check_findings
        WHERE check_scan_id = %s
          AND tenant_id = %s
        GROUP BY resource_type
        ORDER BY resource_type;
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
        """
        Get service detail from database.
        """
        # Get overall stats
        stats_query = """
        SELECT 
            resource_type as service,
            COUNT(*) as total_checks,
            SUM(CASE WHEN status = 'PASS' THEN 1 ELSE 0 END) as passed,
            SUM(CASE WHEN status = 'FAIL' THEN 1 ELSE 0 END) as failed,
            SUM(CASE WHEN status = 'ERROR' THEN 1 ELSE 0 END) as error,
            COUNT(DISTINCT resource_arn) FILTER (WHERE resource_arn IS NOT NULL) as resources_affected
        FROM check_findings
        WHERE check_scan_id = %s
          AND resource_type = %s
          AND tenant_id = %s
        GROUP BY resource_type;
        """
        
        # Get rule stats
        rules_query = """
        SELECT 
            rule_id,
            COUNT(*) as total,
            SUM(CASE WHEN status = 'PASS' THEN 1 ELSE 0 END) as passed,
            SUM(CASE WHEN status = 'FAIL' THEN 1 ELSE 0 END) as failed,
            SUM(CASE WHEN status = 'ERROR' THEN 1 ELSE 0 END) as error,
            array_agg(DISTINCT resource_arn) FILTER (WHERE resource_arn IS NOT NULL) as resource_arns
        FROM check_findings
        WHERE check_scan_id = %s
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
                    resource_arn: Optional[str] = None,
                    page: int = 1, page_size: int = 50) -> Tuple[List[Dict], int]:
        """
        Get findings with filtering and pagination.
        Uses indexes: idx_check_results_scan, idx_check_results_tenant, idx_check_results_status
        Falls back to NDJSON if database is empty.
        """
        # Try database first
        if self.db and tenant_id and self._has_database_data(tenant_id):
            try:
                return self._get_findings_db(scan_id, tenant_id, customer_id, service, status, rule_id, resource_arn, page, page_size)
            except Exception as e:
                print(f"Database query failed, using NDJSON fallback: {e}")
        
        # Fallback to NDJSON
        if self.use_ndjson_fallback and self.ndjson_reader and tenant_id:
            return self._get_ndjson_fallback('get_findings', scan_id, tenant_id, customer_id, service, status, rule_id, resource_arn, page, page_size)
        
        return [], 0
    
    def _get_findings_db(self, scan_id: Optional[str] = None, tenant_id: str = None,
                    customer_id: Optional[str] = None, service: Optional[str] = None,
                    status: Optional[str] = None, rule_id: Optional[str] = None,
                    resource_arn: Optional[str] = None,
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
            where_clauses.append(f"check_scan_id = %s")
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
        
        if resource_arn:
            where_clauses.append(f"resource_arn = %s")
            params.append(resource_arn)
        
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
            check_scan_id,
            customer_id,
            tenant_id,
            provider,
            hierarchy_id,
            hierarchy_type,
            rule_id,
            resource_arn,
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
                except:
                    finding['checked_fields'] = []
            
            if isinstance(finding.get('finding_data'), str):
                try:
                    finding['finding_data'] = json.loads(finding['finding_data'])
                except:
                    finding['finding_data'] = {}
            
            # Add discovery_scan_id from finding_data if available
            if finding.get('finding_data'):
                finding['discovery_scan_id'] = finding['finding_data'].get('discovery_id')
        
        return [dict(f) for f in findings], total
    
    def get_resource_findings(self, resource_arn: str, tenant_id: str,
                             customer_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Get all findings for a specific resource ARN.
        Uses index: idx_check_results_tenant (includes resource_arn in query)
        Falls back to NDJSON if database is empty.
        """
        # Try database first
        if self.db and self._has_database_data(tenant_id):
            try:
                return self._get_resource_findings_db(resource_arn, tenant_id, customer_id)
            except Exception as e:
                print(f"Database query failed, using NDJSON fallback: {e}")
        
        # Fallback to NDJSON
        if self.use_ndjson_fallback and self.ndjson_reader:
            return self._get_ndjson_fallback('get_resource_findings', resource_arn, tenant_id, customer_id)
        
        return None
    
    def _get_resource_findings_db(self, resource_arn: str, tenant_id: str,
                             customer_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Get resource findings from database.
        """
        query = """
        SELECT
            id,
            check_scan_id,
            customer_id,
            tenant_id,
            provider,
            hierarchy_id,
            hierarchy_type,
            rule_id,
            resource_arn,
            resource_id,
            resource_type,
            status,
            checked_fields,
            finding_data,
            created_at
        FROM check_findings
        WHERE resource_arn = %s
          AND tenant_id = %s
          AND ($1 OR customer_id = %s)
        ORDER BY created_at DESC;
        """
        
        findings = self._execute_query(query, [customer_id is None, resource_arn, tenant_id, customer_id or ''])
        
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
            'resource_arn': resource_arn,
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
        if self.db and self._has_database_data(tenant_id):
            try:
                return self._get_rule_findings_db(rule_id, tenant_id, customer_id, scan_id)
            except Exception as e:
                print(f"Database query failed, using NDJSON fallback: {e}")
        
        # Fallback to NDJSON
        if self.use_ndjson_fallback and self.ndjson_reader:
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
            where_clauses.append("check_scan_id = %s")
            params.append(scan_id)

        where_sql = " AND ".join(where_clauses)

        query = f"""
        SELECT
            id,
            check_scan_id,
            customer_id,
            tenant_id,
            provider,
            hierarchy_id,
            rule_id,
            resource_arn,
            resource_id,
            resource_type,
            status,
            checked_fields,
            finding_data,
            created_at
        FROM check_findings
        WHERE {where_sql}
        ORDER BY scan_timestamp DESC
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
        resources = list(set(f['resource_arn'] for f in findings if f.get('resource_arn')))
        
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
                resource_arn=query,
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

    def get_latest_scan(self, tenant_id: str, hierarchy_id: Optional[str] = None,
                        service: Optional[str] = None,
                        start_time: Optional[datetime] = None,
                        end_time: Optional[datetime] = None) -> Optional[Dict[str, Any]]:
        """
        Get latest check scan ID and timestamp for tenant/account/service.
        """
        where_clauses = ["tenant_id = %s"]
        params = [tenant_id]

        if hierarchy_id:
            where_clauses.append("hierarchy_id = %s")
            params.append(hierarchy_id)

        if service:
            where_clauses.append("resource_type = %s")
            params.append(service)

        if start_time:
            where_clauses.append("scan_timestamp >= %s")
            params.append(start_time)
        if end_time:
            where_clauses.append("scan_timestamp <= %s")
            params.append(end_time)

        where_sql = " AND ".join(where_clauses)

        query = f"""
        SELECT check_scan_id, MAX(scan_timestamp) as scan_timestamp
        FROM check_findings
        WHERE {where_sql}
        GROUP BY check_scan_id
        ORDER BY MAX(scan_timestamp) DESC
        LIMIT 1;
        """

        return self._execute_query_one(query, params)

    def get_previous_scan(self, tenant_id: str, current_scan_id: str,
                          hierarchy_id: Optional[str] = None,
                          service: Optional[str] = None,
                          start_time: Optional[datetime] = None,
                          end_time: Optional[datetime] = None) -> Optional[Dict[str, Any]]:
        """
        Get previous scan (immediately before current) for tenant/account/service.
        """
        where_clauses = ["tenant_id = %s", "check_scan_id != %s"]
        params = [tenant_id, current_scan_id]

        if hierarchy_id:
            where_clauses.append("hierarchy_id = %s")
            params.append(hierarchy_id)

        if service:
            where_clauses.append("resource_type = %s")
            params.append(service)

        if start_time:
            where_clauses.append("scan_timestamp >= %s")
            params.append(start_time)
        if end_time:
            where_clauses.append("scan_timestamp <= %s")
            params.append(end_time)

        where_sql = " AND ".join(where_clauses)

        query = f"""
        SELECT check_scan_id, MAX(scan_timestamp) as scan_timestamp
        FROM check_findings
        WHERE {where_sql}
        GROUP BY check_scan_id
        ORDER BY MAX(scan_timestamp) DESC
        LIMIT 1;
        """

        return self._execute_query_one(query, params)

    def get_check_results_for_scan(self, scan_id: str, tenant_id: str,
                                   hierarchy_id: Optional[str] = None,
                                   service: Optional[str] = None,
                                   include_metadata: bool = True) -> List[Dict[str, Any]]:
        """
        Get check results for a scan, optionally enriched with rule metadata.
        """
        where_clauses = ["cr.check_scan_id = %s", "cr.tenant_id = %s"]
        params = [scan_id, tenant_id]

        if hierarchy_id:
            where_clauses.append("cr.hierarchy_id = %s")
            params.append(hierarchy_id)

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
            ORDER BY cr.rule_id, cr.resource_arn;
            """
        else:
            query = f"""
            SELECT cr.*
            FROM check_findings cr
            WHERE {where_sql}
            ORDER BY cr.rule_id, cr.resource_arn;
            """

        results = self._execute_query(query, params)

        # Parse JSONB fields
        for result in results:
            if isinstance(result.get('checked_fields'), str):
                try:
                    result['checked_fields'] = json.loads(result['checked_fields'])
                except:
                    result['checked_fields'] = []
            if isinstance(result.get('finding_data'), str):
                try:
                    result['finding_data'] = json.loads(result['finding_data'])
                except:
                    result['finding_data'] = {}

        return [dict(r) for r in results]
