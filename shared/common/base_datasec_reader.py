"""
Base datasec reader — loads from datasec_findings and
datasec_enhanced_input_transformed.

Domain engines subclass this to read data classification context
without reimplementing the DB connection and SQL boilerplate.

Usage:
    from engine_common.base_datasec_reader import BaseDatasecReader

    class DataSecReader(BaseDatasecReader):
        pass  # inherits load_findings() and load_enhanced_data()
"""

import logging
from typing import Any, Dict, List

from psycopg2.extras import RealDictCursor

from .base_reader import BaseDBReader
from .db_connections import get_datasec_conn

logger = logging.getLogger(__name__)

_DATASEC_FINDING_COLS = """
    finding_id, scan_run_id, tenant_id,
    resource_uid, resource_type, account_id, region,
    severity, status,
    data_classification, sensitivity_score,
    finding_data
"""

_ENHANCED_COLS = """
    resource_arn, resource_type, resource_name,
    data_classification,
    encryption_at_rest, encryption_algorithm,
    kms_key_type, kms_key_rotation,
    encryption_in_transit, tls_version,
    ssl_certificate_valid,
    is_public, cross_account_access,
    account_id, region, csp
"""


class BaseDatasecReader(BaseDBReader):
    def __init__(self):
        super().__init__(get_datasec_conn)

    def load_findings(self, scan_run_id: str, tenant_id: str) -> List[Dict[str, Any]]:
        """Load datasec_findings for this scan."""
        sql = f"""
            SELECT {_DATASEC_FINDING_COLS}
            FROM datasec_findings
            WHERE scan_run_id = %s AND tenant_id = %s
        """
        return self._safe_fetch(sql, (scan_run_id, tenant_id), f"datasec findings for scan {scan_run_id}")

    def load_enhanced_data(self, scan_run_id: str, tenant_id: str) -> List[Dict[str, Any]]:
        """Load datasec_enhanced_input_transformed rows for this scan.

        Gracefully returns [] if the table doesn't exist (not deployed in all envs).
        """
        self._ensure_conn()
        # Check table existence first (separate cursor to avoid aborting the main conn)
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT EXISTS (
                        SELECT FROM information_schema.tables
                        WHERE table_name = 'datasec_enhanced_input_transformed'
                    )
                """)
                row = cur.fetchone()
                if not (row and row["exists"]):
                    logger.info("datasec_enhanced_input_transformed not found — skipping")
                    return []
        except Exception as e:
            logger.error("Failed to check datasec_enhanced_input_transformed: %s", e, exc_info=True)
            if self.conn and not self.conn.closed:
                self.conn.rollback()
            return []

        sql = f"""
            SELECT {_ENHANCED_COLS}
            FROM datasec_enhanced_input_transformed
            WHERE orchestration_id::text = %s
              AND tenant_id = %s
        """
        return self._safe_fetch(sql, (scan_run_id, tenant_id), f"datasec enhanced data for scan {scan_run_id}")
