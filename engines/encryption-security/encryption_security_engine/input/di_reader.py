"""DI reader for Encryption Security Engine — reads from asset_inventory."""

from typing import Any, Dict, List, Optional

from engine_common.base_di_reader import BaseDIReader

ENCRYPTION_SERVICES = ("kms", "acm", "acm-pca", "secretsmanager")


class EncryptionDIReader(BaseDIReader):
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
        service_set = services if services is not None else ENCRYPTION_SERVICES
        return self.load_by_services(scan_run_id, tenant_id, service_set, account_id)
