"""IAM reader for AI Security Engine — ML/AI role and policy findings."""

import logging
from typing import Any, Dict, List

from engine_common.base_reader import BaseDBReader
from engine_common.db_connections import get_iam_conn
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)

ML_RESOURCE_PATTERNS = (
    "%sagemaker%", "%bedrock%", "%comprehend%", "%rekognition%",
    "%textract%", "%translate%", "%transcribe%", "%polly%",
    "%lex%", "%kendra%", "%personalize%", "%forecast%",
    "%frauddetector%", "%lookout%", "%machinelearning%",
)

ML_ACTION_PATTERNS = (
    "sagemaker:*", "bedrock:*", "comprehend:*", "rekognition:*",
    "textract:*", "translate:*", "transcribe:*", "polly:*",
    "lex:*", "kendra:*", "personalize:*", "forecast:*",
    "frauddetector:*", "lookoutmetrics:*", "lookoutequipment:*",
    "lookoutvision:*",
)


class AIIAMReader(BaseDBReader):
    def __init__(self):
        super().__init__(get_iam_conn)

    def get_ml_role_findings(self, scan_run_id: str, tenant_id: str) -> List[Dict[str, Any]]:
        self._ensure_conn()
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                resource_conditions = " OR ".join(
                    ["resource_uid ILIKE %s" for _ in ML_RESOURCE_PATTERNS]
                )
                params: list = [scan_run_id, tenant_id] + list(ML_RESOURCE_PATTERNS)
                cur.execute(f"""
                    SELECT
                        finding_id, scan_run_id, rule_id,
                        resource_uid, resource_type,
                        account_id, region, provider,
                        severity, status,
                        finding_data
                    FROM iam_findings
                    WHERE scan_run_id = %s
                      AND tenant_id = %s
                      AND ({resource_conditions})
                """, params)
                rows = cur.fetchall()
                logger.info("IAM: loaded %d ML role findings for scan %s", len(rows), scan_run_id)
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error("Failed to load ML role findings: %s", e)
            if self.conn and not self.conn.closed:
                self.conn.rollback()
            return []

    def get_ml_policy_statements(self, scan_run_id: str, tenant_id: str) -> List[Dict[str, Any]]:
        self._ensure_conn()
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                action_conditions = " OR ".join(
                    ["ps.actions::text ILIKE %s" for _ in ML_ACTION_PATTERNS]
                )
                params: list = [scan_run_id, tenant_id] + [
                    f"%{a}%" for a in ML_ACTION_PATTERNS
                ]
                cur.execute(f"""
                    SELECT
                        ps.policy_arn,
                        ps.attached_to_arn,
                        ps.effect,
                        ps.actions,
                        ps.resources,
                        ps.is_admin,
                        ps.is_wildcard_principal
                    FROM iam_policy_statements ps
                    WHERE ps.scan_run_id = %s
                      AND ps.tenant_id = %s
                      AND ({action_conditions})
                    ORDER BY ps.is_admin DESC, ps.is_wildcard_principal DESC
                """, params)
                rows = cur.fetchall()
                logger.info("IAM: loaded %d ML policy statements for scan %s", len(rows), scan_run_id)
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error("Failed to load ML policy statements: %s", e)
            if self.conn and not self.conn.closed:
                self.conn.rollback()
            return []
