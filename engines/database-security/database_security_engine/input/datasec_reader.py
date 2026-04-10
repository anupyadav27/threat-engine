"""
DataSec DB Reader for Database Security Engine.

Reads data classification and sensitivity fields from datasec_findings and
datasec_enhanced_input_transformed in the DataSec database, filtered to
database services only.
"""

import os
import logging
from typing import List, Dict, Any

import psycopg2
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)

# Database services to filter on in datasec tables
DB_SERVICES = (
    "rds", "dynamodb", "redshift", "elasticache", "neptune",
    "documentdb", "opensearch", "timestream", "keyspaces", "dax",
)


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
    """Reads database classification data from DataSec DB."""

    def __init__(self):
        self.conn = None

    def _ensure_conn(self):
        if self.conn is None or self.conn.closed:
            self.conn = _get_datasec_conn()

    def load_db_classification(
        self,
        scan_run_id: str,
        tenant_id: str,
    ) -> List[Dict[str, Any]]:
        """Load datasec_findings filtered to database resource types.

        Extracts data_classification, sensitivity_score, and encryption
        fields from finding_data JSONB.

        Args:
            scan_run_id: Pipeline scan run identifier.
            tenant_id: Tenant identifier.

        Returns:
            List of datasec finding dicts for database resources.
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
                      AND data_store_service = ANY(%s)
                """, (scan_run_id, tenant_id, list(DB_SERVICES)))
                rows = cur.fetchall()
                logger.info(f"DataSec: loaded {len(rows)} database classification findings for scan {scan_run_id}")
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"Failed to load datasec database findings: {e}", exc_info=True)
            return []

    def load_enhanced_db_data(
        self,
        scan_run_id: str,
        tenant_id: str,
    ) -> List[Dict[str, Any]]:
        """Load structured columns from datasec_enhanced_input_transformed for DB services.

        This table has explicit columns: encryption_at_rest, encryption_algorithm,
        kms_key_type, kms_key_rotation, encryption_in_transit, tls_version,
        ssl_certificate_valid, data_classification.

        Args:
            scan_run_id: Pipeline scan run identifier.
            tenant_id: Tenant identifier.

        Returns:
            List of enhanced datasec dicts for database services.
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
                      AND data_store_service = ANY(%s)
                """, (scan_run_id, tenant_id, list(DB_SERVICES)))
                rows = cur.fetchall()
                logger.info(f"DataSec enhanced: loaded {len(rows)} database resources for scan {scan_run_id}")
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"Failed to load enhanced datasec database data: {e}", exc_info=True)
            return []

    def close(self):
        if self.conn and not self.conn.closed:
            self.conn.close()
