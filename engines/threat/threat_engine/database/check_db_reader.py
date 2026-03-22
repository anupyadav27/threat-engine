"""
Check Database Reader

Reads check results from PostgreSQL database (threat_engine_check.check_results).
Used by Threat Engine to read check results for threat analysis.
"""
import os
import json
import psycopg2
from psycopg2.extras import RealDictCursor
from typing import Iterator, Dict, Any, Optional, List
import logging

logger = logging.getLogger(__name__)


def _db_url_with_search_path(url: str) -> str:
    """Append options=search_path to URL when DB_SCHEMA is set."""
    schema = (os.getenv("DB_SCHEMA") or "").strip()
    if not schema:
        return url
    sep = "&" if "?" in url else "?"
    opts = f"options=-c%20search_path%3D{schema.replace(',', '%2C')}"
    return f"{url}{sep}{opts}"


class CheckDBReader:
    """Reads check results from PostgreSQL database"""

    def __init__(self, db_url: Optional[str] = None, tenant_id: Optional[str] = None):
        """
        Initialize check database reader.

        Args:
            db_url: PostgreSQL connection URL (if None, uses database_config)
            tenant_id: Tenant identifier (optional, can be set per method call)
        """
        if db_url is None:
            from .connection.database_config import get_database_config
            db_config = get_database_config("check")
            db_url = db_config.connection_string
        
        self.db_url = db_url
        self.tenant_id = tenant_id
        self.conn = psycopg2.connect(_db_url_with_search_path(db_url))
    
    def get_latest_scan_id(self, tenant_id: Optional[str] = None) -> Optional[str]:
        """
        Get latest completed check scan ID for a tenant.
        
        Args:
            tenant_id: Tenant identifier (uses instance tenant_id if not provided)
        
        Returns:
            Latest scan ID or None if no scans found
        """
        tenant_id = tenant_id or self.tenant_id
        if not tenant_id:
            raise ValueError("tenant_id must be provided either in __init__ or method call")
        
        try:
            with self.conn.cursor() as cur:
                cur.execute("""
                    SELECT scan_run_id FROM check_report
                    WHERE tenant_id = %s
                      AND status = 'completed'
                      AND scan_type IN ('check', 'full')
                    ORDER BY first_seen_at DESC
                    LIMIT 1
                """, (tenant_id,))
                result = cur.fetchone()
                return result[0] if result else None
        except Exception as e:
            logger.error(f"Error getting latest scan: {e}")
            return None
    
    def read_check_results(
        self,
        scan_id: str,
        tenant_id: Optional[str] = None,
        account_id: Optional[str] = None,
        region: Optional[str] = None,
        service: Optional[str] = None,
        status_filter: Optional[str] = None  # "FAIL", "WARN", or None for all
    ) -> Iterator[Dict[str, Any]]:
        """
        Read check results from database with filters.
        
        Args:
            scan_id: Scan ID or "latest" for auto-detect
            tenant_id: Tenant identifier (uses instance tenant_id if not provided)
            account_id: Optional filter by account ID (account_id)
            region: Optional filter by region
            service: Optional filter by service name (extracted from resource_type)
            status_filter: Optional filter by status ("FAIL", "WARN", or None for all)
        
        Yields:
            Check result dictionaries
        """
        tenant_id = tenant_id or self.tenant_id
        if not tenant_id:
            raise ValueError("tenant_id must be provided either in __init__ or method call")
        
        # Auto-detect latest scan
        if scan_id == "latest":
            scan_id = self.get_latest_scan_id(tenant_id)
            if not scan_id:
                logger.warning(f"No scans found for tenant: {tenant_id}")
                return
        
        # Build query with filters
        query = """
            SELECT
                scan_run_id, customer_id, tenant_id, provider,
                account_id, hierarchy_type, rule_id,
                resource_uid, resource_arn, resource_id, resource_type,
                status, checked_fields, finding_data, created_at
            FROM check_findings
            WHERE scan_run_id = %s AND tenant_id = %s
        """
        params = [scan_id, tenant_id]
        
        if account_id:
            query += " AND account_id = %s"
            params.append(account_id)
        
        if region:
            # Extract region from resource_arn or resource_uid if possible
            # For now, we'll filter by checking if region is in resource_arn
            query += " AND (resource_arn LIKE %s OR resource_uid LIKE %s)"
            region_pattern = f"%:{region}:%"
            params.extend([region_pattern, region_pattern])
        
        if service:
            # Service is typically in resource_type (e.g., "aws_s3_bucket")
            query += " AND resource_type LIKE %s"
            params.append(f"%{service}%")
        
        if status_filter:
            query += " AND status = %s"
            params.append(status_filter)
        
        query += " ORDER BY created_at DESC, resource_uid"
        
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(query, params)
                for row in cur:
                    result = dict(row)
                    
                    # Parse JSONB fields
                    if isinstance(result.get("checked_fields"), str):
                        try:
                            result["checked_fields"] = json.loads(result["checked_fields"])
                        except (json.JSONDecodeError, TypeError):
                            result["checked_fields"] = []
                    elif result.get("checked_fields") is None:
                        result["checked_fields"] = []
                    
                    if isinstance(result.get("finding_data"), str):
                        try:
                            result["finding_data"] = json.loads(result["finding_data"])
                        except (json.JSONDecodeError, TypeError):
                            result["finding_data"] = {}
                    elif result.get("finding_data") is None:
                        result["finding_data"] = {}
                    
                    yield result
        except Exception as e:
            logger.error(f"Error reading check results: {e}")
            return
    
    def list_available_scans(self, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List all available check scans for a tenant.
        
        Args:
            tenant_id: Tenant identifier (uses instance tenant_id if not provided)
        
        Returns:
            List of scan metadata dictionaries
        """
        tenant_id = tenant_id or self.tenant_id
        if not tenant_id:
            raise ValueError("tenant_id must be provided either in __init__ or method call")
        
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT
                        scan_run_id,
                        first_seen_at,
                        status,
                        scan_type,
                        provider,
                        metadata,
                        (SELECT COUNT(*) FROM check_findings WHERE check_findings.scan_run_id = check_report.scan_run_id) as total_results
                    FROM check_report
                    WHERE tenant_id = %s
                    ORDER BY first_seen_at DESC
                    LIMIT 50
                """, (tenant_id,))

                scans = []
                for row in cur.fetchall():
                    scan_dict = dict(row)
                    scans.append({
                        "scan_id": scan_dict["scan_run_id"],
                        "first_seen_at": scan_dict["first_seen_at"].isoformat() if scan_dict["first_seen_at"] else None,
                        "status": scan_dict["status"],
                        "metadata": scan_dict.get("metadata", {}),
                        "total_results": scan_dict.get("total_results", 0)
                    })
                
                return scans
        except Exception as e:
            logger.error(f"Error listing scans: {e}")
            return []
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
