"""
Encryption DB Reader for AI Security Engine.

Reads ML/AI-related encryption findings and KMS key usage from
the threat_engine_encryption database to assess encryption posture
of AI/ML resources.
"""

import os
import logging
from typing import List, Dict, Any

import psycopg2
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)

# Resource UID patterns for ML/AI services
ML_RESOURCE_PATTERNS = (
    "%sagemaker%", "%bedrock%", "%comprehend%", "%rekognition%",
    "%textract%", "%translate%", "%transcribe%", "%polly%",
    "%lex%", "%kendra%", "%personalize%", "%forecast%",
    "%frauddetector%", "%lookout%", "%machinelearning%",
)


def _get_encryption_conn():
    """Get connection to the Encryption database."""
    return psycopg2.connect(
        host=os.getenv("ENCRYPTION_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("ENCRYPTION_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("ENCRYPTION_DB_NAME", "threat_engine_encryption"),
        user=os.getenv("ENCRYPTION_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("ENCRYPTION_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
    )


class AIEncryptionReader:
    """Reads ML/AI encryption findings and key usage from Encryption DB."""

    def __init__(self):
        self.conn = None

    def _ensure_conn(self):
        if self.conn is None or self.conn.closed:
            self.conn = _get_encryption_conn()

    def get_ml_encryption_findings(
        self,
        scan_run_id: str,
        tenant_id: str,
    ) -> List[Dict[str, Any]]:
        """Load encryption findings for ML/AI resources.

        Matches findings where resource_uid contains sagemaker, bedrock,
        comprehend, rekognition, textract, or other ML service references.

        Args:
            scan_run_id: Pipeline scan run identifier.
            tenant_id: Tenant identifier.

        Returns:
            List of encryption finding dicts.
        """
        self._ensure_conn()
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                resource_conditions = " OR ".join(
                    ["ef.resource_uid ILIKE %s" for _ in ML_RESOURCE_PATTERNS]
                )
                params: list = [scan_run_id, tenant_id] + list(ML_RESOURCE_PATTERNS)

                cur.execute(f"""
                    SELECT
                        ef.finding_id, ef.scan_run_id, ef.tenant_id,
                        ef.rule_id,
                        ef.resource_uid, ef.resource_type,
                        ef.account_id, ef.region, ef.provider,
                        ef.severity, ef.status,
                        ef.encryption_domain AS category,
                        ef.encryption_status, ef.key_type, ef.algorithm,
                        ef.finding_data
                    FROM encryption_findings ef
                    WHERE ef.scan_run_id = %s
                      AND ef.tenant_id = %s
                      AND ({resource_conditions})
                """, params)
                rows = cur.fetchall()
                logger.info(
                    f"Encryption: loaded {len(rows)} ML findings for scan {scan_run_id}"
                )
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"Failed to load ML encryption findings: {e}", exc_info=True)
            return []

    def get_ml_key_usage(
        self,
        scan_run_id: str,
        tenant_id: str,
    ) -> List[Dict[str, Any]]:
        """Load KMS keys used by ML/AI services.

        Joins encryption_key_inventory with dependency data to find
        keys that ML resources depend on for encryption.

        Args:
            scan_run_id: Pipeline scan run identifier.
            tenant_id: Tenant identifier.

        Returns:
            List of dicts with key details and dependent ML resource info.
        """
        self._ensure_conn()
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Check if encryption_key_inventory table exists
                cur.execute("""
                    SELECT EXISTS (
                        SELECT FROM information_schema.tables
                        WHERE table_name = 'encryption_key_inventory'
                    )
                """)
                if not cur.fetchone()["exists"]:
                    logger.info("encryption_key_inventory table not found — skipping")
                    return []

                resource_conditions = " OR ".join(
                    ["eki.dependent_resources::text ILIKE %s" for _ in ML_RESOURCE_PATTERNS]
                )
                params: list = [scan_run_id, tenant_id] + list(ML_RESOURCE_PATTERNS)

                cur.execute(f"""
                    SELECT
                        eki.key_arn, eki.key_id, eki.key_alias,
                        eki.key_state, eki.key_manager,
                        eki.key_rotation_enabled,
                        eki.key_spec, eki.key_usage,
                        eki.dependent_resources,
                        eki.account_id, eki.region
                    FROM encryption_key_inventory eki
                    WHERE eki.scan_run_id = %s
                      AND eki.tenant_id = %s
                      AND ({resource_conditions})
                """, params)
                rows = cur.fetchall()
                logger.info(
                    f"Encryption: loaded {len(rows)} KMS keys used by ML services"
                )
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"Failed to load ML key usage: {e}", exc_info=True)
            return []

    def close(self):
        """Close the database connection."""
        if self.conn and not self.conn.closed:
            self.conn.close()
