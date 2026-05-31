"""OCI provider for Encryption Security engine."""
import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .base import BaseEncryptionProvider

logger = logging.getLogger(__name__)


def _oci_finding_id(rule_id: str, uid: str, acct: str, region: str) -> str:
    return hashlib.sha256(f"{rule_id}|{uid}|{acct}|{region}".encode()).hexdigest()[:16]


class OCIEncryptionProvider(BaseEncryptionProvider):

    @property
    def key_services(self):
        return ["vault", "kms"]

    @property
    def cert_services(self):
        return ["certificates"]

    @property
    def secrets_services(self):
        return ["vault"]

    @property
    def inventory_resource_prefixes(self):
        return ["vault.", "kms.", "certificates."]

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        discovery_resources: Dict[str, List[Dict[str, Any]]],
    ) -> Optional[List[Dict[str, Any]]]:
        """Pattern A: vault type, key rotation age, cert expiry, LB TLS version."""
        now = datetime.now(timezone.utc)
        findings: List[Dict[str, Any]] = []
        for r in discovery_resources.get("vault", []) + discovery_resources.get("kms", []):
            uid = r.get("resource_uid") or r.get("id") or ""
            region = r.get("region") or ""
            ef = r.get("emitted_fields") or r
            vault_type = ef.get("vaultType") or ef.get("vault_type") or ""
            if vault_type and vault_type.upper() == "DEFAULT":
                findings.append({
                    "finding_id": _oci_finding_id("oci.vault.vault.default_not_virtual_private", uid, account_id, region),
                    "resource_uid": uid, "resource_type": "Vault::Vault",
                    "account_id": account_id, "region": region,
                    "encryption_domain": "kms_key_management", "severity": "MEDIUM", "status": "FAIL",
                    "rule_id": "oci.vault.vault.default_not_virtual_private",
                    "encryption_status": None, "key_type": None, "algorithm": None,
                    "rotation_compliant": None, "transit_enforced": None,
                    "finding_data": {
                        "title": "OCI Vault is DEFAULT type, not VIRTUAL_PRIVATE",
                        "description": "Virtual Private Vault provides dedicated HSM partitions for higher isolation. Use VIRTUAL_PRIVATE for sensitive workloads.",
                        "vault_type": vault_type,
                    },
                })
            # Key rotation: check timeCreated > 365 days
            time_created = ef.get("timeCreated") or ef.get("time_created")
            if time_created:
                try:
                    if isinstance(time_created, str):
                        from dateutil import parser as _dtp
                        tc = _dtp.parse(time_created)
                    else:
                        tc = time_created
                    if tc.tzinfo is None:
                        tc = tc.replace(tzinfo=timezone.utc)
                    age_days = (now - tc).days
                    if age_days > 365:
                        findings.append({
                            "finding_id": _oci_finding_id("oci.vault.key.rotation_overdue", uid, account_id, region),
                            "resource_uid": uid, "resource_type": "Vault::Key",
                            "account_id": account_id, "region": region,
                            "encryption_domain": "kms_key_management", "severity": "MEDIUM", "status": "FAIL",
                            "rule_id": "oci.vault.key.rotation_overdue",
                            "encryption_status": None, "key_type": None, "algorithm": None,
                            "rotation_compliant": False, "transit_enforced": None,
                            "finding_data": {
                                "title": f"OCI key not rotated in {age_days} days",
                                "description": "OCI keys should be rotated at least annually. Create a new key version.",
                                "age_days": age_days,
                            },
                        })
                except Exception:
                    pass
        for r in discovery_resources.get("certificates", []):
            uid = r.get("resource_uid") or r.get("id") or ""
            region = r.get("region") or ""
            ef = r.get("emitted_fields") or r
            not_after = ef.get("notAfter") or ef.get("not_after") or ef.get("currentVersionSummary", {}).get("timeOfExpiration")
            if not_after:
                try:
                    if isinstance(not_after, str):
                        from dateutil import parser as _dtp2
                        exp = _dtp2.parse(not_after)
                    else:
                        exp = not_after
                    if exp.tzinfo is None:
                        exp = exp.replace(tzinfo=timezone.utc)
                    days = (exp - now).days
                    if days < 30:
                        sev = "CRITICAL" if days < 15 else "HIGH"
                        findings.append({
                            "finding_id": _oci_finding_id("oci.certificates.certificate.expiring_soon", uid, account_id, region),
                            "resource_uid": uid, "resource_type": "Certificates::Certificate",
                            "account_id": account_id, "region": region,
                            "encryption_domain": "certificate_lifecycle",
                            "severity": sev, "status": "FAIL",
                            "rule_id": "oci.certificates.certificate.expiring_soon",
                            "encryption_status": None, "key_type": None, "algorithm": None,
                            "rotation_compliant": None, "transit_enforced": None,
                            "finding_data": {
                                "title": f"OCI certificate expires in {days} days",
                                "description": f"Certificate {uid} expires in {days} days.",
                                "days_until_expiry": days,
                            },
                        })
                except Exception:
                    pass
        # LB TLS: sslConfiguration.protocols list — flag if TLSv1 or TLSv1_1 present
        for r in discovery_resources.get("loadbalancer", []) + discovery_resources.get("networkloadbalancer", []):
            uid = r.get("resource_uid") or r.get("id") or ""
            region = r.get("region") or ""
            ef = r.get("emitted_fields") or r
            protocols = ef.get("sslConfiguration", {}).get("protocols") or []
            weak = [p for p in protocols if p in ("TLSv1", "TLSv1_1", "TLSv1.0", "TLSv1.1")]
            if weak:
                findings.append({
                    "finding_id": _oci_finding_id("oci.loadbalancer.listener.tls_below_1_2", uid, account_id, region),
                    "resource_uid": uid, "resource_type": "LoadBalancer::Listener",
                    "account_id": account_id, "region": region,
                    "encryption_domain": "in_transit_enforcement", "severity": "HIGH", "status": "FAIL",
                    "rule_id": "oci.loadbalancer.listener.tls_below_1_2",
                    "encryption_status": None, "key_type": None, "algorithm": None,
                    "rotation_compliant": None, "transit_enforced": False,
                    "finding_data": {
                        "title": f"OCI load balancer uses deprecated TLS: {weak}",
                        "description": "Remove TLSv1 and TLSv1.1 from sslConfiguration.protocols.",
                        "weak_protocols": weak,
                    },
                })
        logger.info("OCI Encryption Pattern A: %d rule findings", len(findings))
        return findings
