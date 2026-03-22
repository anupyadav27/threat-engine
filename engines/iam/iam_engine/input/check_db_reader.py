"""
Check DB Reader for IAM Engine

Reads check_findings from threat_engine_check and filters by IAM-relevant rules.
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
    """Reads IAM-relevant check results from threat_engine_check database."""

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

    def load_iam_check_results(
        self,
        scan_id: str,
        tenant_id: str,
        iam_rule_ids: Optional[set] = None,
    ) -> List[Dict[str, Any]]:
        """
        Load IAM-relevant check results from check_findings table.
        
        Args:
            scan_id: Check scan ID
            tenant_id: Tenant ID
            iam_rule_ids: Set of IAM rule IDs to filter by
        
        Returns:
            List of check result rows
        """
        if not PSYCOPG_AVAILABLE:
            return []

        conn = self._get_conn()

        query = """
            SELECT
                cr.scan_run_id, cr.tenant_id, cr.rule_id,
                cr.resource_uid, cr.resource_arn, cr.resource_id, cr.resource_type,
                cr.status, cr.checked_fields, cr.finding_data,
                cr.account_id, cr.provider,
                cr.created_at as scan_timestamp
            FROM check_findings cr
            WHERE cr.scan_run_id = %s AND cr.tenant_id = %s
        """
        params = [scan_id, tenant_id]

        # Filter by IAM rule IDs if provided
        if iam_rule_ids:
            query += " AND cr.rule_id = ANY(%s)"
            params.append(list(iam_rule_ids))

        query += " ORDER BY cr.first_seen_at DESC"

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
