"""Azure provider for Encryption Security engine."""
import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .base import BaseEncryptionProvider

logger = logging.getLogger(__name__)


def _az_finding_id(rule_id: str, uid: str, acct: str, region: str) -> str:
    return hashlib.sha256(f"{rule_id}|{uid}|{acct}|{region}".encode()).hexdigest()[:16]


class AzureEncryptionProvider(BaseEncryptionProvider):

    @property
    def key_services(self):
        return ["keyvault"]

    @property
    def cert_services(self):
        return ["keyvault"]

    @property
    def secrets_services(self):
        return ["keyvault"]

    @property
    def inventory_resource_prefixes(self):
        return ["keyvault.", "managedidentity.", "disk-encryption."]

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        discovery_resources: Dict[str, List[Dict[str, Any]]],
    ) -> Optional[List[Dict[str, Any]]]:
        """Pattern A: Key Vault soft delete, cert expiry, AppGW TLS findings."""
        now = datetime.now(timezone.utc)
        findings: List[Dict[str, Any]] = []
        for r in discovery_resources.get("keyvault", []):
            uid = r.get("resource_uid") or r.get("id") or ""
            region = r.get("region") or r.get("location") or "eastus"
            ef = r.get("emitted_fields") or r
            props = ef.get("properties") or ef
            soft_delete = props.get("enableSoftDelete") or ef.get("enableSoftDelete") or False
            purge_protection = props.get("enablePurgeProtection") or ef.get("enablePurgeProtection") or False
            if not soft_delete:
                findings.append({
                    "finding_id": _az_finding_id("azure.keyvault.vault.soft_delete_disabled", uid, account_id, region),
                    "resource_uid": uid, "resource_type": "KeyVault::Vault",
                    "account_id": account_id, "region": region,
                    "encryption_domain": "kms_key_management", "severity": "HIGH", "status": "FAIL",
                    "rule_id": "azure.keyvault.vault.soft_delete_disabled",
                    "encryption_status": None, "key_type": None, "algorithm": None,
                    "rotation_compliant": None, "transit_enforced": None,
                    "finding_data": {
                        "title": "Key Vault soft delete not enabled",
                        "description": "Soft delete protects vault objects from accidental deletion. Enable it on all Key Vaults.",
                    },
                })
            if soft_delete and not purge_protection:
                findings.append({
                    "finding_id": _az_finding_id("azure.keyvault.vault.purge_protection_disabled", uid, account_id, region),
                    "resource_uid": uid, "resource_type": "KeyVault::Vault",
                    "account_id": account_id, "region": region,
                    "encryption_domain": "kms_key_management", "severity": "MEDIUM", "status": "FAIL",
                    "rule_id": "azure.keyvault.vault.purge_protection_disabled",
                    "encryption_status": None, "key_type": None, "algorithm": None,
                    "rotation_compliant": None, "transit_enforced": None,
                    "finding_data": {
                        "title": "Key Vault purge protection not enabled",
                        "description": "Purge protection prevents permanent deletion during the soft-delete retention period.",
                    },
                })
            # Cert expiry from attributes.expires (unix epoch)
            certs = ef.get("certificates") or ef.get("Certificates") or []
            for cert in (certs if isinstance(certs, list) else []):
                attrs = cert.get("attributes") or {}
                expires_epoch = attrs.get("expires") or attrs.get("exp")
                cert_id = cert.get("id") or uid
                if expires_epoch:
                    try:
                        exp = datetime.fromtimestamp(int(expires_epoch), tz=timezone.utc)
                        days = (exp - now).days
                        if days < 30:
                            sev = "CRITICAL" if days < 15 else "HIGH"
                            findings.append({
                                "finding_id": _az_finding_id("azure.keyvault.certificate.expiring_soon", cert_id, account_id, region),
                                "resource_uid": cert_id, "resource_type": "KeyVault::Certificate",
                                "account_id": account_id, "region": region,
                                "encryption_domain": "certificate_lifecycle",
                                "severity": sev, "status": "FAIL",
                                "rule_id": "azure.keyvault.certificate.expiring_soon",
                                "encryption_status": None, "key_type": None, "algorithm": None,
                                "rotation_compliant": None, "transit_enforced": None,
                                "finding_data": {
                                    "title": f"Key Vault certificate expires in {days} days",
                                    "description": f"Certificate {cert_id} expires in {days} days.",
                                    "days_until_expiry": days,
                                },
                            })
                    except (TypeError, ValueError, OSError):
                        pass
            # AppGW TLS from sslPolicy.minProtocolVersion
            ssl_policy = ef.get("sslPolicy") or props.get("sslPolicy") or {}
            min_tls = (ssl_policy.get("minProtocolVersion") or "").upper()
            if min_tls and min_tls < "TLSV1_2":
                findings.append({
                    "finding_id": _az_finding_id("azure.appgateway.listener.tls_below_1_2", uid, account_id, region),
                    "resource_uid": uid, "resource_type": "ApplicationGateway",
                    "account_id": account_id, "region": region,
                    "encryption_domain": "in_transit_enforcement", "severity": "HIGH", "status": "FAIL",
                    "rule_id": "azure.appgateway.listener.tls_below_1_2",
                    "encryption_status": None, "key_type": None, "algorithm": None,
                    "rotation_compliant": None, "transit_enforced": False,
                    "finding_data": {
                        "title": f"Application Gateway TLS minimum version is {min_tls}",
                        "description": "TLS 1.0 and 1.1 are deprecated. Set minProtocolVersion to TLSv1_2 or higher.",
                        "tls_version": min_tls,
                    },
                })
        logger.info("Azure Encryption Pattern A: %d rule findings", len(findings))
        return findings
