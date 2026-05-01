"""Encryption reader for AI Security Engine — ML/AI encryption findings."""

import logging
from typing import Any, Dict, List

from engine_common.base_reader import BaseDBReader
from engine_common.db_connections import get_encryption_conn
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)

ML_RESOURCE_PATTERNS = (
    "%sagemaker%", "%bedrock%", "%comprehend%", "%rekognition%",
    "%textract%", "%translate%", "%transcribe%", "%polly%",
    "%lex%", "%kendra%", "%personalize%", "%forecast%",
    "%frauddetector%", "%lookout%", "%machinelearning%",
)


class AIEncryptionReader(BaseDBReader):
    def __init__(self):
        super().__init__(get_encryption_conn)

    def get_ml_encryption_findings(self, scan_run_id: str, tenant_id: str) -> List[Dict[str, Any]]:
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
                logger.info("Encryption: loaded %d ML findings for scan %s", len(rows), scan_run_id)
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error("Failed to load ML encryption findings: %s", e)
            if self.conn and not self.conn.closed:
                self.conn.rollback()
            return []

    def get_ml_key_usage(self, scan_run_id: str, tenant_id: str) -> List[Dict[str, Any]]:
        self._ensure_conn()
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
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
                logger.info("Encryption: loaded %d KMS keys used by ML services", len(rows))
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error("Failed to load ML key usage: %s", e)
            if self.conn and not self.conn.closed:
                self.conn.rollback()
            return []
