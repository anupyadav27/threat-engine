"""
Check DB Reader for AI Security Engine.

Reads AI/ML-related check_findings joined with rule_metadata
from the threat_engine_check database.
"""

import os
import logging
from typing import List, Dict, Any, Optional

import psycopg2
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)

# Services whose check rules are AI/ML-relevant
AI_SERVICES = (
    "sagemaker", "sagemaker-runtime", "sagemaker-edge",
    "sagemaker-featurestore-runtime", "bedrock", "bedrock-runtime",
    "bedrock-agent", "bedrock-agent-runtime",
    "comprehend", "comprehendmedical", "textract", "translate",
    "transcribe", "rekognition", "polly", "lex-models", "lexv2-models",
    "kendra", "personalize", "forecast", "machinelearning",
    "frauddetector", "lookoutmetrics", "lookoutequipment", "lookoutvision",
)

# Domain keywords that indicate AI/ML-related rules
AI_DOMAIN_KEYWORDS = ("ai", "machine_learning", "ml", "model", "inference")


def _get_check_conn():
    """Get connection to the Check database."""
    return psycopg2.connect(
        host=os.getenv("CHECK_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("CHECK_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("CHECK_DB_NAME", "threat_engine_check"),
        user=os.getenv("CHECK_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("CHECK_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
    )


class AICheckReader:
    """Reads AI/ML-related findings from Check DB."""

    def __init__(self):
        self.conn = None

    def _ensure_conn(self):
        if self.conn is None or self.conn.closed:
            self.conn = _get_check_conn()

    def load_ai_check_findings(
        self,
        scan_run_id: str,
        tenant_id: str,
    ) -> List[Dict[str, Any]]:
        """Load check findings for AI/ML services.

        Combines two sources:
        1. Findings where service is an AI service.
        2. Findings where rule_metadata.domain matches AI keywords.

        Args:
            scan_run_id: Pipeline scan run identifier.
            tenant_id: Tenant identifier.

        Returns:
            List of check finding dicts with rule metadata joined.
        """
        self._ensure_conn()
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Build domain ILIKE conditions
                domain_conditions = " OR ".join(
                    ["rm.domain ILIKE %s" for _ in AI_DOMAIN_KEYWORDS]
                )
                domain_params = [f"%{kw}%" for kw in AI_DOMAIN_KEYWORDS]

                params: list = [scan_run_id, tenant_id, list(AI_SERVICES)] + domain_params

                cur.execute(f"""
                    SELECT
                        cf.id AS finding_id, cf.scan_run_id, cf.rule_id,
                        cf.resource_service AS service,
                        cf.resource_uid, cf.resource_type, cf.resource_id,
                        cf.region, cf.account_id, cf.provider,
                        cf.status, cf.checked_fields,
                        cf.finding_data, cf.severity,
                        rm.title, rm.description, rm.remediation
                    FROM check_findings cf
                    LEFT JOIN rule_metadata rm ON cf.rule_id = rm.rule_id
                    WHERE cf.scan_run_id = %s
                      AND cf.tenant_id = %s
                      AND (
                          cf.resource_service = ANY(%s)
                          OR {domain_conditions}
                      )
                """, params)
                rows = cur.fetchall()
                logger.info(
                    f"Check: loaded {len(rows)} AI/ML findings for scan {scan_run_id}"
                )
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"Failed to load AI check findings: {e}", exc_info=True)
            return []

    def load_ai_rule_metadata(
        self,
        provider: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Load rule_metadata entries relevant to AI/ML services.

        Includes rules where service matches AI_SERVICES or domain
        contains AI keywords.

        Args:
            provider: Optional provider filter (e.g., 'aws').

        Returns:
            List of rule definition dicts with severity, title, remediation.
        """
        self._ensure_conn()
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                domain_conditions = " OR ".join(
                    ["rm.domain ILIKE %s" for _ in AI_DOMAIN_KEYWORDS]
                )
                domain_params = [f"%{kw}%" for kw in AI_DOMAIN_KEYWORDS]

                params: list = [list(AI_SERVICES)] + domain_params

                sql = f"""
                    SELECT
                        rm.rule_id, rm.service, rm.severity, rm.title,
                        rm.description, rm.remediation, rm.domain,
                        rm.data_security, rm.compliance_frameworks
                    FROM rule_metadata rm
                    WHERE (
                        rm.service = ANY(%s)
                        OR {domain_conditions}
                    )
                """

                if provider:
                    sql += " AND rm.provider = %s"
                    params.append(provider)

                cur.execute(sql, params)
                rows = cur.fetchall()
                logger.info(f"Check: loaded {len(rows)} AI/ML rule metadata entries")
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"Failed to load AI rule metadata: {e}", exc_info=True)
            return []

    def close(self):
        """Close the database connection."""
        if self.conn and not self.conn.closed:
            self.conn.close()
