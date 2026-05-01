"""DataSec reader for AI Security Engine — ML/AI data classification findings."""

import logging
from typing import Any, Dict, List

from engine_common.base_reader import BaseDBReader
from engine_common.db_connections import get_datasec_conn
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)

ML_DATA_NAME_PATTERNS = (
    "%model%", "%training%", "%dataset%", "%ml-%", "%-ml%",
    "%ai-%", "%-ai%", "%sagemaker%", "%bedrock%",
    "%inference%", "%feature-store%", "%featurestore%",
)

ML_RESOURCE_UID_PATTERNS = (
    "%sagemaker%", "%bedrock%", "%comprehend%",
    "%rekognition%", "%textract%", "%forecast%",
    "%personalize%", "%kendra%",
)


class AIDataSecReader(BaseDBReader):
    def __init__(self):
        super().__init__(get_datasec_conn)

    def get_ml_data_findings(self, scan_run_id: str, tenant_id: str) -> List[Dict[str, Any]]:
        self._ensure_conn()
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
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
                logger.info("DataSec: loaded %d ML data findings for scan %s", len(rows), scan_run_id)
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error("Failed to load ML data findings: %s", e)
            if self.conn and not self.conn.closed:
                self.conn.rollback()
            return []

    def get_training_data_classification(self, scan_run_id: str, tenant_id: str) -> List[Dict[str, Any]]:
        self._ensure_conn()
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
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
                logger.info("DataSec: loaded %d training data classifications", len(rows))
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error("Failed to load training data classification: %s", e)
            if self.conn and not self.conn.closed:
                self.conn.rollback()
            return []
