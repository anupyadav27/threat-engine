"""
Check DB Reader for DataSec Engine

Reads check_findings from threat_engine_check and filters by data-security-relevant rules.
Same pattern as compliance engine's CheckDBLoader.
"""

import os
import json
from typing import Dict, List, Optional, Any
from collections import defaultdict

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    PSYCOPG_AVAILABLE = True
except ImportError:
    PSYCOPG_AVAILABLE = False


def _get_check_db_connection():
    """Get Check DB connection using individual parameters."""
    return psycopg2.connect(
        host=os.getenv('CHECK_DB_HOST', 'localhost'),
        port=int(os.getenv('CHECK_DB_PORT', '5432')),
        database=os.getenv('CHECK_DB_NAME', 'threat_engine_check'),
        user=os.getenv('CHECK_DB_USER', 'check_user'),
        password=os.getenv('CHECK_DB_PASSWORD', 'check_password')
    )


class CheckDBReader:
    """Reads data-security-relevant check results from threat_engine_check database."""

    def __init__(self):
        self._connection = None

    def _get_conn(self):
        if self._connection is None or self._connection.closed:
            if not PSYCOPG_AVAILABLE:
                raise RuntimeError("psycopg2 required. Install psycopg2-binary.")
            self._connection = _get_check_db_connection()
        return self._connection

    def close(self) -> None:
        if self._connection and not self._connection.closed:
            self._connection.close()
            self._connection = None

    def __enter__(self) -> "CheckDBReader":
        return self

    def __exit__(self, *args) -> None:
        self.close()

    def load_datasec_check_results(
        self,
        scan_id: str,
        tenant_id: str,
        datasec_rule_ids: Optional[set] = None,
    ) -> List[Dict[str, Any]]:
        """
        Load data-security-relevant check results from check_findings table.
        
        Args:
            scan_id: Check scan ID
            tenant_id: Tenant ID
            datasec_rule_ids: Set of data security rule IDs to filter by
        
        Returns:
            List of check result rows
        """
        if not PSYCOPG_AVAILABLE:
            return []

        conn = self._get_conn()

        query = """
            SELECT
                cr.check_scan_id, cr.tenant_id, cr.rule_id,
                cr.resource_uid, cr.resource_arn, cr.resource_id, cr.resource_type,
                cr.status, cr.checked_fields, cr.finding_data,
                cr.hierarchy_id as account_id, cr.provider,
                cr.created_at as scan_timestamp
            FROM check_findings cr
            WHERE cr.check_scan_id = %s AND cr.tenant_id = %s
        """
        params = [scan_id, tenant_id]

        # Filter by data security rule IDs if provided
        if datasec_rule_ids:
            query += " AND cr.rule_id = ANY(%s)"
            params.append(list(datasec_rule_ids))

        query += " ORDER BY cr.scan_timestamp DESC"

        rows = []
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(query, params)
                for r in cur.fetchall():
                    rec = dict(r)
                    # Parse JSON fields
                    if isinstance(rec.get("checked_fields"), str):
                        try:
                            rec["checked_fields"] = json.loads(rec["checked_fields"])
                        except:
                            rec["checked_fields"] = []
                    if isinstance(rec.get("finding_data"), str):
                        try:
                            rec["finding_data"] = json.loads(rec["finding_data"])
                        except:
                            rec["finding_data"] = {}
                    rows.append(rec)
        except Exception as e:
            import logging
            logging.getLogger(__name__).error(f"Error loading check results: {e}", exc_info=True)
            raise

        return rows
    
    def filter_data_stores(
        self,
        scan_id: str,
        tenant_id: str,
        datasec_rule_ids: Optional[set] = None,
    ) -> List[Dict[str, Any]]:
        """
        Extract data stores from check results (S3, RDS, DynamoDB, etc.).
        
        Returns unique data resources.
        """
        check_results = self.load_datasec_check_results(scan_id, tenant_id, datasec_rule_ids)
        
        data_services = {"s3", "rds", "dynamodb", "redshift", "glacier", "documentdb", "neptune"}
        seen_resources = set()
        data_stores = []
        
        for result in check_results:
            resource_arn = result.get("resource_arn") or result.get("resource_uid", "")
            service = (result.get("resource_type") or "").lower()
            
            # Try to extract service from rule_id if not in resource_type
            if not service or service == "unknown":
                rule_id = result.get("rule_id", "")
                parts = rule_id.split(".")
                if len(parts) >= 2:
                    service = parts[1]
            
            if service in data_services and resource_arn and resource_arn not in seen_resources:
                seen_resources.add(resource_arn)
                data_stores.append({
                    "resource_arn": resource_arn,
                    "resource_id": result.get("resource_id"),
                    "resource_type": result.get("resource_type"),
                    "service": service,
                    "account_id": result.get("account_id"),
                    "region": self._extract_region_from_arn(resource_arn),
                })
        
        return data_stores
    
    def _extract_region_from_arn(self, arn: str) -> Optional[str]:
        """Extract region from ARN."""
        if not arn or not arn.startswith("arn:"):
            return None
        parts = arn.split(":")
        if len(parts) >= 4:
            return parts[3] or "global"
        return "global"
