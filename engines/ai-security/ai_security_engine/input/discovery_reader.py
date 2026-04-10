"""
Discovery DB Reader for AI Security Engine.

Reads AI/ML service resources (SageMaker, Bedrock, Comprehend, Rekognition,
Textract, Translate, Transcribe, Polly, Lex, Kendra, Personalize, Forecast,
Fraud Detector, Lookout) from discovery_findings in threat_engine_discoveries.
"""

import os
import logging
from typing import List, Dict, Any, Optional

import psycopg2
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)

AI_SERVICES = {
    "sagemaker", "sagemaker-runtime", "sagemaker-edge",
    "sagemaker-featurestore-runtime", "bedrock", "bedrock-runtime",
    "bedrock-agent", "bedrock-agent-runtime", "bedrock-agentcore-control",
    "comprehend", "comprehendmedical", "textract", "translate",
    "transcribe", "rekognition", "polly", "lex-models", "lexv2-models",
    "kendra", "personalize", "forecast", "machinelearning",
    "frauddetector", "lookoutmetrics", "lookoutequipment", "lookoutvision",
}

# Discovery IDs that return AWS-managed catalog data (not customer resources).
# These are excluded because they are noise — e.g. 600+ foundation models per region.
CATALOG_NOISE_DISCOVERY_IDS = {
    "aws.bedrock.list_foundation_models",       # AWS-managed model catalog
    "aws.bedrock.list_inference_profiles",       # AWS-managed inference profiles
    "aws.polly.describe_voices",                 # AWS-managed voice catalog
    "aws.personalize.list_recipes",              # AWS-managed recipe catalog
    "aws.lex-models.get_builtin_intents",        # AWS-managed Lex intents
    "aws.lex-models.get_builtin_slot_types",     # AWS-managed Lex slot types
    "aws.comprehend.list_document_classifier_summaries",  # empty if no custom models
}


def _get_discoveries_conn():
    """Get connection to the Discoveries database."""
    return psycopg2.connect(
        host=os.getenv("DISCOVERIES_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("DISCOVERIES_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("DISCOVERIES_DB_NAME", "threat_engine_discoveries"),
        user=os.getenv("DISCOVERIES_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("DISCOVERIES_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
    )


class AIDiscoveryReader:
    """Reads AI/ML service resources from Discovery DB."""

    def __init__(self):
        self.conn = None

    def _ensure_conn(self):
        if self.conn is None or self.conn.closed:
            self.conn = _get_discoveries_conn()

    def load_ai_resources(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Load all AI/ML service resources from discovery_findings.

        Args:
            scan_run_id: Pipeline scan run identifier.
            tenant_id: Tenant identifier.
            account_id: Optional cloud account filter.

        Returns:
            List of resource dicts with emitted_fields and raw_response.
        """
        self._ensure_conn()
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                sql = """
                    SELECT
                        resource_uid, resource_id, resource_type, service,
                        discovery_id, region, account_id, provider,
                        emitted_fields, raw_response,
                        config_hash, version, first_seen_at
                    FROM discovery_findings
                    WHERE scan_run_id = %s
                      AND tenant_id = %s
                      AND service = ANY(%s)
                      AND discovery_id != ALL(%s)
                """
                params: list = [
                    scan_run_id,
                    tenant_id,
                    list(AI_SERVICES),
                    list(CATALOG_NOISE_DISCOVERY_IDS),
                ]

                if account_id:
                    sql += " AND account_id = %s"
                    params.append(account_id)

                cur.execute(sql, params)
                rows = cur.fetchall()
                logger.info(
                    f"Discovery: loaded {len(rows)} AI/ML resources for scan {scan_run_id}"
                    f" (excluded {len(CATALOG_NOISE_DISCOVERY_IDS)} catalog discovery_ids)"
                )
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"Failed to load AI discovery resources: {e}", exc_info=True)
            return []

    def load_by_service(
        self,
        scan_run_id: str,
        tenant_id: str,
        service: str,
        account_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Load discovery_findings filtered by a single AI service.

        Args:
            scan_run_id: Pipeline scan run identifier.
            tenant_id: Tenant identifier.
            service: Service name (e.g., 'sagemaker', 'bedrock').
            account_id: Optional cloud account filter.

        Returns:
            List of resource dicts.
        """
        self._ensure_conn()
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                sql = """
                    SELECT
                        resource_uid, resource_id, resource_type, service,
                        discovery_id, region, account_id, provider,
                        emitted_fields, raw_response,
                        config_hash, version, first_seen_at
                    FROM discovery_findings
                    WHERE scan_run_id = %s
                      AND tenant_id = %s
                      AND service = %s
                      AND discovery_id != ALL(%s)
                """
                params: list = [scan_run_id, tenant_id, service, list(CATALOG_NOISE_DISCOVERY_IDS)]

                if account_id:
                    sql += " AND account_id = %s"
                    params.append(account_id)

                cur.execute(sql, params)
                rows = cur.fetchall()
                logger.info(
                    f"Discovery: loaded {len(rows)} {service} resources for scan {scan_run_id}"
                )
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"Failed to load {service} discovery resources: {e}", exc_info=True)
            return []

    def close(self):
        """Close the database connection."""
        if self.conn and not self.conn.closed:
            self.conn.close()
