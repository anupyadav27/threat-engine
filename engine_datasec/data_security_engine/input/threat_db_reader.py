"""
Threat DB Reader for Data Security Engine

Reads misconfig_findings from Threat DB (threat_reports.report_data),
filters by data-security-relevant rule IDs, and converts to findings format.
"""

import json
import os
from typing import Dict, List, Optional, Any, Set
import logging

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    PSYCOPG_AVAILABLE = True
except ImportError:
    PSYCOPG_AVAILABLE = False

logger = logging.getLogger(__name__)


def _threat_db_connection_string() -> str:
    """Build Threat DB connection string from env vars (same pattern as Compliance's ThreatDBLoader)."""
    base = (
        f"postgresql://{os.getenv('THREAT_DB_USER', 'threat_user')}:"
        f"{os.getenv('THREAT_DB_PASSWORD', 'threat_password')}@"
        f"{os.getenv('THREAT_DB_HOST', 'localhost')}:"
        f"{os.getenv('THREAT_DB_PORT', '5432')}/"
        f"{os.getenv('THREAT_DB_NAME', 'threat_engine_threat')}"
    )
    schema = (os.getenv("DB_SCHEMA") or "engine_threat,engine_shared").strip()
    sep = "&" if "?" in base else "?"
    opts = f"options=-c%20search_path%3D{schema.replace(',', '%2C')}"
    return f"{base}{sep}{opts}"


class ThreatDBReader:
    """Reads misconfig findings from Threat DB (threat_reports.report_data)."""

    def __init__(self, db_url: Optional[str] = None):
        """
        Initialize Threat DB reader.
        
        Args:
            db_url: Optional database URL. Default: from env vars via get_database_config("threat")
        """
        if db_url is None:
            try:
                self.db_url = _threat_db_connection_string()
            except Exception as e:
                logger.warning(f"Could not get Threat DB config, will use env vars: {e}")
                # Fallback to direct env vars
                self.db_url = (
                    f"postgresql://{os.getenv('THREAT_DB_USER', 'threat_user')}:"
                    f"{os.getenv('THREAT_DB_PASSWORD', 'threat_password')}@"
                    f"{os.getenv('THREAT_DB_HOST', 'localhost')}:"
                    f"{os.getenv('THREAT_DB_PORT', '5432')}/"
                    f"{os.getenv('THREAT_DB_NAME', 'threat_engine_threat')}"
                )
        else:
            self.db_url = db_url
        self._conn = None

    def _get_conn(self):
        """Get database connection."""
        if self._conn is None or self._conn.closed:
            if not PSYCOPG_AVAILABLE:
                raise RuntimeError("psycopg2 required for ThreatDBReader. Install psycopg2-binary.")
            self._conn = psycopg2.connect(self.db_url)
        return self._conn

    def close(self):
        """Close database connection."""
        if self._conn and not self._conn.closed:
            self._conn.close()
            self._conn = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def load_threat_report(self, tenant_id: str, scan_run_id: str) -> Optional[Dict[str, Any]]:
        """
        Load full threat report from threat_reports table.
        
        Args:
            tenant_id: Tenant identifier
            scan_run_id: Threat scan_run_id (from Threat engine)
            
        Returns:
            Full threat report dict or None if not found
        """
        if not PSYCOPG_AVAILABLE:
            return None
        conn = self._get_conn()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT report_data, generated_at FROM threat_reports
                    WHERE tenant_id = %s AND scan_run_id = %s
                    """,
                    (tenant_id, scan_run_id),
                )
                row = cur.fetchone()
            if not row:
                logger.warning(f"Threat report not found: tenant_id={tenant_id}, scan_run_id={scan_run_id}")
                return None
            data = row["report_data"]
            report = data if isinstance(data, dict) else json.loads(data)
            return report
        except Exception as e:
            logger.error(f"Error loading threat report: {e}")
            return None

    def get_misconfig_findings(
        self,
        tenant_id: str,
        scan_run_id: str,
        data_security_rule_ids: Optional[Set[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get misconfig findings from threat report, filtered by data security rule IDs.
        
        Args:
            tenant_id: Tenant identifier
            scan_run_id: Threat scan_run_id
            data_security_rule_ids: Set of data-security-relevant rule IDs to filter by
            
        Returns:
            List of misconfig findings (data-security-relevant only if rule_ids provided)
        """
        report = self.load_threat_report(tenant_id, scan_run_id)
        if not report:
            return []
        
        # Extract misconfig_findings from threat report
        misconfig_findings = report.get("misconfig_findings", [])
        
        if not data_security_rule_ids:
            # Return all misconfig findings if no filter
            logger.info(f"Loaded {len(misconfig_findings)} misconfig findings from Threat DB (no data security filter)")
            return misconfig_findings
        
        # Filter by data security rule IDs
        data_findings = [
            f for f in misconfig_findings
            if f.get("rule_id") in data_security_rule_ids
        ]
        
        logger.info(f"Filtered {len(data_findings)} data security findings from {len(misconfig_findings)} total misconfig findings")
        return data_findings
    
    def get_findings_by_resource(
        self,
        tenant_id: str,
        scan_run_id: str,
        resource_uid: str,
        data_security_rule_ids: Optional[Set[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get misconfig findings for a specific resource.
        
        Args:
            tenant_id: Tenant identifier
            scan_run_id: Threat scan_run_id
            resource_uid: Resource UID/ARN
            data_security_rule_ids: Optional filter by data security rule IDs
            
        Returns:
            List of findings for the resource
        """
        findings = self.get_misconfig_findings(tenant_id, scan_run_id, data_security_rule_ids)
        return [
            f for f in findings
            if resource_uid in (f.get("resource_uid") or "") or resource_uid in (f.get("resource_arn") or "")
        ]
    
    def filter_data_stores(
        self,
        tenant_id: str,
        scan_run_id: str,
        data_security_rule_ids: Optional[Set[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Extract data stores from misconfig findings.
        
        Args:
            tenant_id: Tenant identifier
            scan_run_id: Threat scan_run_id
            data_security_rule_ids: Optional filter by data security rule IDs
            
        Returns:
            List of data store dictionaries
        """
        findings = self.get_misconfig_findings(tenant_id, scan_run_id, data_security_rule_ids)
        data_services = {"s3", "rds", "dynamodb", "redshift", "glacier", "documentdb", "neptune"}
        
        seen_resources = set()
        data_stores = []
        for finding in findings:
            resource_arn = finding.get("resource_arn") or finding.get("resource_uid", "")
            service = (finding.get("service") or "").lower()
            
            if service in data_services and resource_arn and resource_arn not in seen_resources:
                seen_resources.add(resource_arn)
                data_stores.append({
                    "resource_arn": resource_arn,
                    "resource_id": finding.get("resource_id"),
                    "resource_type": finding.get("resource_type"),
                    "service": service,
                    "account_id": finding.get("account_id"),
                    "region": finding.get("region"),
                })
        
        return data_stores
