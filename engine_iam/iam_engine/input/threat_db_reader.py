"""
Threat DB Reader for IAM Security Engine

Reads misconfig_findings from Threat DB (threat_reports.report_data),
filters by IAM-relevant rule IDs, and converts to findings format.
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


def _get_threat_db_connection():
    """Get Threat DB connection using individual parameters to avoid password encoding issues."""
    return psycopg2.connect(
        host=os.getenv('THREAT_DB_HOST', 'localhost'),
        port=int(os.getenv('THREAT_DB_PORT', '5432')),
        database=os.getenv('THREAT_DB_NAME', 'threat_engine_threat'),
        user=os.getenv('THREAT_DB_USER', 'postgres'),
        password=os.getenv('THREAT_DB_PASSWORD', '')
    )


class ThreatDBReader:
    """Reads misconfig findings from Threat DB (threat_reports.report_data)."""

    def __init__(self, db_url: Optional[str] = None):
        """
        Initialize Threat DB reader.
        
        Args:
            db_url: Optional database URL (ignored, uses env vars with individual params)
        """
        self.db_url = None  # Not used
        self._conn = None

    def _get_conn(self):
        """Get database connection."""
        if self._conn is None or self._conn.closed:
            if not PSYCOPG_AVAILABLE:
                raise RuntimeError("psycopg2 required for ThreatDBReader. Install psycopg2-binary.")
            self._conn = _get_threat_db_connection()
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
        iam_rule_ids: Optional[Set[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get misconfig findings from threat report, filtered by IAM rule IDs.
        
        Args:
            tenant_id: Tenant identifier
            scan_run_id: Threat scan_run_id
            iam_rule_ids: Set of IAM-relevant rule IDs to filter by
            
        Returns:
            List of misconfig findings (IAM-relevant only if iam_rule_ids provided)
        """
        report = self.load_threat_report(tenant_id, scan_run_id)
        if not report:
            return []
        
        # Extract misconfig_findings from threat report
        misconfig_findings = report.get("misconfig_findings", [])
        
        if not iam_rule_ids:
            # Return all misconfig findings if no filter
            logger.info(f"Loaded {len(misconfig_findings)} misconfig findings from Threat DB (no IAM filter)")
            return misconfig_findings
        
        # Filter by IAM rule IDs
        iam_findings = [
            f for f in misconfig_findings
            if f.get("rule_id") in iam_rule_ids
        ]
        
        logger.info(f"Filtered {len(iam_findings)} IAM findings from {len(misconfig_findings)} total misconfig findings")
        return iam_findings
    
    def get_findings_by_resource(
        self,
        tenant_id: str,
        scan_run_id: str,
        resource_uid: str,
        iam_rule_ids: Optional[Set[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get misconfig findings for a specific resource.
        
        Args:
            tenant_id: Tenant identifier
            scan_run_id: Threat scan_run_id
            resource_uid: Resource UID/ARN
            iam_rule_ids: Optional filter by IAM rule IDs
            
        Returns:
            List of findings for the resource
        """
        findings = self.get_misconfig_findings(tenant_id, scan_run_id, iam_rule_ids)
        return [
            f for f in findings
            if resource_uid in (f.get("resource_uid") or "") or resource_uid in (f.get("resource_arn") or "")
        ]
