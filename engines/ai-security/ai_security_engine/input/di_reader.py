"""DI reader for AI Security Engine — reads from asset_inventory."""

from typing import Any, Dict, List, Optional

from engine_common.base_di_reader import BaseDIReader

AI_SERVICES = frozenset({
    "sagemaker", "sagemaker-runtime", "sagemaker-edge",
    "sagemaker-featurestore-runtime", "bedrock", "bedrock-runtime",
    "bedrock-agent", "bedrock-agent-runtime", "bedrock-agentcore-control",
    "comprehend", "comprehendmedical", "textract", "translate",
    "transcribe", "rekognition", "polly", "lex-models", "lexv2-models",
    "kendra", "personalize", "forecast", "machinelearning",
    "frauddetector", "lookoutmetrics", "lookoutequipment", "lookoutvision",
})

# AWS-managed catalog entries that are not customer resources — excluded as noise.
CATALOG_NOISE_DISCOVERY_IDS = frozenset({
    "aws.bedrock.list_foundation_models",
    "aws.bedrock.list_inference_profiles",
    "aws.polly.describe_voices",
    "aws.personalize.list_recipes",
    "aws.lex-models.get_builtin_intents",
    "aws.lex-models.get_builtin_slot_types",
    "aws.comprehend.list_document_classifier_summaries",
})


class AIDIReader(BaseDIReader):
    def load_ai_resources(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: Optional[str] = None,
        services=None,
    ) -> List[Dict[str, Any]]:
        service_set = list(services) if services is not None else list(AI_SERVICES)
        sql = """
            SELECT
                resource_uid,
                resource_uid AS resource_id,
                resource_type, service,
                region, account_id, provider,
                emitted_fields, raw_response,
                config_hash,
                NULL::text AS version,
                first_seen_at,
                discovery_id
            FROM asset_inventory
            WHERE scan_run_id = %s
              AND tenant_id = %s
              AND service = ANY(%s)
              AND discovery_id != ALL(%s)
        """
        params: list = [
            scan_run_id,
            tenant_id,
            service_set,
            list(CATALOG_NOISE_DISCOVERY_IDS),
        ]
        if account_id:
            sql += " AND account_id = %s"
            params.append(account_id)
        return self._safe_fetch(sql, params, f"AI/ML DI assets for scan {scan_run_id}")

    def load_by_service(self, scan_run_id: str, tenant_id: str, service: str, account_id: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = """
            SELECT
                resource_uid,
                resource_uid AS resource_id,
                resource_type, service,
                region, account_id, provider,
                emitted_fields, raw_response,
                config_hash,
                NULL::text AS version,
                first_seen_at,
                discovery_id
            FROM asset_inventory
            WHERE scan_run_id = %s
              AND tenant_id = %s
              AND service = %s
              AND discovery_id != ALL(%s)
        """
        params: list = [scan_run_id, tenant_id, service, list(CATALOG_NOISE_DISCOVERY_IDS)]
        if account_id:
            sql += " AND account_id = %s"
            params.append(account_id)
        return self._safe_fetch(sql, params, f"{service} AI DI assets for scan {scan_run_id}")
