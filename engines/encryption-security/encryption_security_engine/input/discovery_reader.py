"""Discovery reader for Encryption Security Engine."""

from typing import Any, Dict, List, Optional

from engine_common.base_discovery_reader import BaseDiscoveryReader

ENCRYPTION_SERVICES = ("kms", "acm", "acm-pca", "secretsmanager")

# Discovery IDs that return AWS-managed catalog data — excluded as noise.
CATALOG_NOISE_DISCOVERY_IDS = frozenset({
    "aws.bedrock.list_foundation_models",
    "aws.bedrock.list_inference_profiles",
    "aws.polly.describe_voices",
    "aws.personalize.list_recipes",
    "aws.lex-models.get_builtin_intents",
    "aws.lex-models.get_builtin_slot_types",
})


class DiscoveryReader(BaseDiscoveryReader):
    def load_kms_resources(self, scan_run_id: str, tenant_id: str, account_id: Optional[str] = None) -> List[Dict[str, Any]]:
        return self.load_by_service(scan_run_id, tenant_id, "kms", account_id)

    def load_acm_resources(self, scan_run_id: str, tenant_id: str, account_id: Optional[str] = None) -> List[Dict[str, Any]]:
        return self.load_by_service(scan_run_id, tenant_id, "acm", account_id)

    def load_acm_pca_resources(self, scan_run_id: str, tenant_id: str, account_id: Optional[str] = None) -> List[Dict[str, Any]]:
        return self.load_by_service(scan_run_id, tenant_id, "acm-pca", account_id)

    def load_secrets_resources(self, scan_run_id: str, tenant_id: str, account_id: Optional[str] = None) -> List[Dict[str, Any]]:
        return self.load_by_service(scan_run_id, tenant_id, "secretsmanager", account_id)

    def load_all_encryption_resources(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: Optional[str] = None,
        services=None,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Load encryption resources. services override comes from providers/ factory."""
        service_set = services if services is not None else ENCRYPTION_SERVICES
        return self.load_by_services(scan_run_id, tenant_id, service_set, account_id)
