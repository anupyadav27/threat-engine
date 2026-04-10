"""
DataSec DB Reader for Encryption Engine.

Reads encryption posture fields from datasec_findings and
datasec_enhanced_input_transformed in the DataSec database.
"""

import os
import logging
from typing import List, Dict, Any

import psycopg2
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)


def _get_datasec_conn():
    """Get connection to the DataSec database."""
    return psycopg2.connect(
        host=os.getenv("DATASEC_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("DATASEC_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("DATASEC_DB_NAME", "threat_engine_datasec"),
        user=os.getenv("DATASEC_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("DATASEC_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
    )


class DataSecReader:
    """Reads encryption posture data from DataSec DB."""

    def __init__(self):
        self.conn = None

    def _ensure_conn(self):
        if self.conn is None or self.conn.closed:
            self.conn = _get_datasec_conn()

    def load_encryption_posture(
        self,
        scan_run_id: str,
        tenant_id: str,
    ) -> List[Dict[str, Any]]:
        """Load per-resource encryption fields from datasec_findings.

        Extracts encryption_at_rest, encryption_in_transit, kms_key_id,
        sse_algorithm, key_rotation_enabled, tls_version from finding_data JSONB.
        """
        self._ensure_conn()
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT
                        finding_id, scan_run_id, tenant_id,
                        resource_uid, resource_type, account_id, region,
                        severity, status,
                        data_classification, sensitivity_score,
                        finding_data
                    FROM datasec_findings
                    WHERE scan_run_id = %s
                      AND tenant_id = %s
                """, (scan_run_id, tenant_id))
                rows = cur.fetchall()
                logger.info(f"DataSec: loaded {len(rows)} findings for scan {scan_run_id}")
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"Failed to load datasec findings: {e}", exc_info=True)
            return []

    def load_enhanced_encryption_data(
        self,
        scan_run_id: str,
        tenant_id: str,
    ) -> List[Dict[str, Any]]:
        """Load structured encryption columns from datasec_enhanced_input_transformed.

        This table has explicit columns: encryption_at_rest, encryption_algorithm,
        kms_key_type, kms_key_rotation, encryption_in_transit, tls_version,
        ssl_certificate_valid, encryption_status.
        """
        self._ensure_conn()
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Check if table exists (it may not be deployed in all environments)
                cur.execute("""
                    SELECT EXISTS (
                        SELECT FROM information_schema.tables
                        WHERE table_name = 'datasec_enhanced_input_transformed'
                    )
                """)
                if not cur.fetchone()["exists"]:
                    logger.info("datasec_enhanced_input_transformed table not found — skipping")
                    return []

                cur.execute("""
                    SELECT
                        resource_arn, resource_type, resource_name,
                        data_store_service, data_classification,
                        encryption_at_rest, encryption_algorithm,
                        kms_key_type, kms_key_rotation,
                        encryption_in_transit, tls_version,
                        ssl_certificate_valid,
                        is_public, cross_account_access,
                        account_id, region, csp
                    FROM datasec_enhanced_input_transformed
                    WHERE orchestration_id::text = %s
                      AND tenant_id = %s
                """, (scan_run_id, tenant_id))
                rows = cur.fetchall()
                logger.info(f"DataSec enhanced: loaded {len(rows)} resources for scan {scan_run_id}")
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"Failed to load enhanced datasec data: {e}", exc_info=True)
            return []

    def load_data_catalog(
        self,
        scan_run_id: str,
        tenant_id: str,
    ) -> List[Dict[str, Any]]:
        """Load datasec_enhanced_data_catalog for encryption_status field."""
        self._ensure_conn()
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT EXISTS (
                        SELECT FROM information_schema.tables
                        WHERE table_name = 'datasec_enhanced_data_catalog'
                    )
                """)
                if not cur.fetchone()["exists"]:
                    return []

                cur.execute("""
                    SELECT
                        resource_arn, resource_name, data_store_service,
                        data_classification, encryption_status,
                        is_public, cross_region_transfer,
                        risk_score, account_id, region, csp
                    FROM datasec_enhanced_data_catalog
                    WHERE orchestration_id::text = %s
                      AND tenant_id = %s
                """, (scan_run_id, tenant_id))
                rows = cur.fetchall()
                logger.info(f"DataSec catalog: loaded {len(rows)} entries for scan {scan_run_id}")
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"Failed to load data catalog: {e}", exc_info=True)
            return []

    def close(self):
        if self.conn and not self.conn.closed:
            self.conn.close()
