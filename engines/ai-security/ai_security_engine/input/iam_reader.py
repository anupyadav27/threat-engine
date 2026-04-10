"""
IAM DB Reader for AI Security Engine.

Reads ML/AI-related IAM findings and policy statements from
the threat_engine_iam database to assess AI service access controls.
"""

import os
import logging
from typing import List, Dict, Any

import psycopg2
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)

# Patterns to match ML/AI service references in resource_uid
ML_RESOURCE_PATTERNS = (
    "%sagemaker%", "%bedrock%", "%comprehend%", "%rekognition%",
    "%textract%", "%translate%", "%transcribe%", "%polly%",
    "%lex%", "%kendra%", "%personalize%", "%forecast%",
    "%frauddetector%", "%lookout%", "%machinelearning%",
)

# IAM action prefixes that grant ML/AI permissions
ML_ACTION_PATTERNS = (
    "sagemaker:*", "bedrock:*", "comprehend:*", "rekognition:*",
    "textract:*", "translate:*", "transcribe:*", "polly:*",
    "lex:*", "kendra:*", "personalize:*", "forecast:*",
    "frauddetector:*", "lookoutmetrics:*", "lookoutequipment:*",
    "lookoutvision:*",
)


def _get_iam_conn():
    """Get connection to the IAM database."""
    return psycopg2.connect(
        host=os.getenv("IAM_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("IAM_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("IAM_DB_NAME", "threat_engine_iam"),
        user=os.getenv("IAM_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("IAM_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
    )


class AIIAMReader:
    """Reads ML/AI-related IAM findings and policy statements."""

    def __init__(self):
        self.conn = None

    def _ensure_conn(self):
        if self.conn is None or self.conn.closed:
            self.conn = _get_iam_conn()

    def get_ml_role_findings(
        self,
        scan_run_id: str,
        tenant_id: str,
    ) -> List[Dict[str, Any]]:
        """Load IAM findings for ML/AI service roles.

        Matches findings where resource_uid contains ML service names
        or where the iam_modules analysis involves ML services.

        Args:
            scan_run_id: Pipeline scan run identifier.
            tenant_id: Tenant identifier.

        Returns:
            List of IAM finding dicts.
        """
        self._ensure_conn()
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Build OR conditions for resource_uid pattern matching
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
                logger.info(
                    f"IAM: loaded {len(rows)} ML role findings for scan {scan_run_id}"
                )
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"Failed to load ML role findings: {e}", exc_info=True)
            return []

    def get_ml_policy_statements(
        self,
        scan_run_id: str,
        tenant_id: str,
    ) -> List[Dict[str, Any]]:
        """Load IAM policy statements that grant ML/AI permissions.

        Filters policy statements where the actions array contains
        ML service wildcards or specific ML actions.

        Args:
            scan_run_id: Pipeline scan run identifier.
            tenant_id: Tenant identifier.

        Returns:
            List of dicts with policy_arn, attached_to_arn, effect,
            actions, resources, is_admin, is_wildcard_principal.
        """
        self._ensure_conn()
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Match policy statements where actions array overlaps with ML actions
                # Use array text search for JSONB actions arrays
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
                logger.info(
                    f"IAM: loaded {len(rows)} ML policy statements for scan {scan_run_id}"
                )
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"Failed to load ML policy statements: {e}", exc_info=True)
            return []

    def close(self):
        """Close the database connection."""
        if self.conn and not self.conn.closed:
            self.conn.close()
