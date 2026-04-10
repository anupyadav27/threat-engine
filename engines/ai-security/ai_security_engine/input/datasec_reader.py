"""
DataSec DB Reader for AI Security Engine.

Reads ML/AI-related data security findings from the
threat_engine_datasec database to assess training data
classification, encryption, and access governance.
"""

import os
import logging
from typing import List, Dict, Any

import psycopg2
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)

# Resource name patterns indicating ML/AI data stores
ML_DATA_NAME_PATTERNS = (
    "%model%", "%training%", "%dataset%", "%ml-%", "%-ml%",
    "%ai-%", "%-ai%", "%sagemaker%", "%bedrock%",
    "%inference%", "%feature-store%", "%featurestore%",
)

# Resource UID patterns for ML services
ML_RESOURCE_UID_PATTERNS = (
    "%sagemaker%", "%bedrock%", "%comprehend%",
    "%rekognition%", "%textract%", "%forecast%",
    "%personalize%", "%kendra%",
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


class AIDataSecReader:
    """Reads ML/AI data security findings from DataSec DB."""

    def __init__(self):
        self.conn = None

    def _ensure_conn(self):
        if self.conn is None or self.conn.closed:
            self.conn = _get_datasec_conn()

    def get_ml_data_findings(
        self,
        scan_run_id: str,
        tenant_id: str,
    ) -> List[Dict[str, Any]]:
        """Load datasec findings for ML-related resources.

        Matches S3 buckets with ML-related names (model, training, dataset,
        ml, ai, sagemaker) or resources with ML service references in
        resource_uid.

        Args:
            scan_run_id: Pipeline scan run identifier.
            tenant_id: Tenant identifier.

        Returns:
            List of datasec finding dicts.
        """
        self._ensure_conn()
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Build OR conditions for name patterns
                name_conditions = " OR ".join(
                    ["df.resource_uid ILIKE %s" for _ in ML_DATA_NAME_PATTERNS]
                )
                uid_conditions = " OR ".join(
                    ["df.resource_uid ILIKE %s" for _ in ML_RESOURCE_UID_PATTERNS]
                )
                params: list = (
                    [scan_run_id, tenant_id]
                    + list(ML_DATA_NAME_PATTERNS)
                    + list(ML_RESOURCE_UID_PATTERNS)
                )

                cur.execute(f"""
                    SELECT
                        df.finding_id, df.scan_run_id, df.tenant_id,
                        df.resource_uid, df.resource_type,
                        df.account_id, df.region,
                        df.severity, df.status,
                        df.data_classification, df.sensitivity_score,
                        df.finding_data
                    FROM datasec_findings df
                    WHERE df.scan_run_id = %s
                      AND df.tenant_id = %s
                      AND (
                          {name_conditions}
                          OR {uid_conditions}
                      )
                """, params)
                rows = cur.fetchall()
                logger.info(
                    f"DataSec: loaded {len(rows)} ML data findings for scan {scan_run_id}"
                )
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"Failed to load ML data findings: {e}", exc_info=True)
            return []

    def get_training_data_classification(
        self,
        scan_run_id: str,
        tenant_id: str,
    ) -> List[Dict[str, Any]]:
        """Load data classification details for ML training data stores.

        Returns encryption status, data classification (PII/PHI/PCI),
        and access governance status for resources matching ML data patterns.

        Args:
            scan_run_id: Pipeline scan run identifier.
            tenant_id: Tenant identifier.

        Returns:
            List of dicts with resource_uid, data_classification,
            encryption fields, and access governance status.
        """
        self._ensure_conn()
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Check for enhanced table first
                cur.execute("""
                    SELECT EXISTS (
                        SELECT FROM information_schema.tables
                        WHERE table_name = 'datasec_enhanced_input_transformed'
                    )
                """)
                has_enhanced = cur.fetchone()["exists"]

                if has_enhanced:
                    name_conditions = " OR ".join(
                        ["resource_arn ILIKE %s" for _ in ML_DATA_NAME_PATTERNS]
                    )
                    uid_conditions = " OR ".join(
                        ["resource_arn ILIKE %s" for _ in ML_RESOURCE_UID_PATTERNS]
                    )
                    params: list = (
                        [scan_run_id, tenant_id]
                        + list(ML_DATA_NAME_PATTERNS)
                        + list(ML_RESOURCE_UID_PATTERNS)
                    )

                    cur.execute(f"""
                        SELECT
                            resource_arn AS resource_uid,
                            resource_type, resource_name,
                            data_classification,
                            encryption_at_rest, encryption_algorithm,
                            kms_key_type, kms_key_rotation,
                            encryption_in_transit, tls_version,
                            is_public, cross_account_access,
                            account_id, region
                        FROM datasec_enhanced_input_transformed
                        WHERE orchestration_id::text = %s
                          AND tenant_id = %s
                          AND (
                              {name_conditions}
                              OR {uid_conditions}
                          )
                    """, params)
                else:
                    # Fallback to datasec_findings with finding_data extraction
                    name_conditions = " OR ".join(
                        ["resource_uid ILIKE %s" for _ in ML_DATA_NAME_PATTERNS]
                    )
                    params = (
                        [scan_run_id, tenant_id]
                        + list(ML_DATA_NAME_PATTERNS)
                    )

                    cur.execute(f"""
                        SELECT
                            resource_uid, resource_type,
                            data_classification, sensitivity_score,
                            severity, status,
                            finding_data
                        FROM datasec_findings
                        WHERE scan_run_id = %s
                          AND tenant_id = %s
                          AND ({name_conditions})
                    """, params)

                rows = cur.fetchall()
                logger.info(
                    f"DataSec: loaded {len(rows)} training data classifications"
                )
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error(
                f"Failed to load training data classification: {e}", exc_info=True
            )
            return []

    def close(self):
        """Close the database connection."""
        if self.conn and not self.conn.closed:
            self.conn.close()
