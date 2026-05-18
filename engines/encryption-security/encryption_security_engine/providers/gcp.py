"""GCP provider for Encryption Security engine."""
import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .base import BaseEncryptionProvider

logger = logging.getLogger(__name__)
_GCP_TLS_RANK = {"TLS_1_0": 0, "TLS_1_1": 1, "TLS_1_2": 2, "TLS_1_3": 3}


def _gcp_finding_id(rule_id: str, uid: str, acct: str, region: str) -> str:
    return hashlib.sha256(f"{rule_id}|{uid}|{acct}|{region}".encode()).hexdigest()[:16]


class GCPEncryptionProvider(BaseEncryptionProvider):

    @property
    def key_services(self):
        return ["cloudkms"]

    @property
    def cert_services(self):
        return ["certificatemanager"]

    @property
    def secrets_services(self):
        return ["secretmanager"]

    @property
    def inventory_resource_prefixes(self):
        return ["cloudkms.", "secretmanager.", "certificatemanager."]

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        discovery_resources: Dict[str, List[Dict[str, Any]]],
    ) -> Optional[List[Dict[str, Any]]]:
        """Pattern A: KMS rotation period, cert expiry, SSL policy TLS version."""
        now = datetime.now(timezone.utc)
        findings: List[Dict[str, Any]] = []
        for r in discovery_resources.get("cloudkms", []):
            uid = r.get("resource_uid") or r.get("name") or ""
            region = r.get("region") or r.get("location") or "global"
            ef = r.get("emitted_fields") or r
            rotation_period = ef.get("rotationPeriod") or ef.get("rotation_period") or ""
            # GCP format: "7776000s" (seconds)
            if rotation_period:
                try:
                    secs = int(str(rotation_period).replace("s", "").strip())
                    days = secs // 86400
                    if days > 365:
                        findings.append({
                            "finding_id": _gcp_finding_id("gcp.cloudkms.key.rotation_period_too_long", uid, account_id, region),
                            "resource_uid": uid, "resource_type": "CloudKMS::Key",
                            "account_id": account_id, "region": region,
                            "encryption_domain": "kms_key_management", "severity": "MEDIUM", "status": "FAIL",
                            "rule_id": "gcp.cloudkms.key.rotation_period_too_long",
                            "encryption_status": None, "key_type": None, "algorithm": None,
                            "rotation_compliant": False, "transit_enforced": None,
                            "finding_data": {
                                "title": f"KMS key rotation period is {days} days (>365)",
                                "description": "GCP recommends rotating symmetric keys at least every 365 days.",
                                "rotation_days": days,
                            },
                        })
                except (ValueError, TypeError):
                    pass
        for r in discovery_resources.get("certificatemanager", []):
            uid = r.get("resource_uid") or r.get("name") or ""
            region = r.get("region") or "global"
            ef = r.get("emitted_fields") or r
            expire_time = ef.get("expireTime") or ef.get("expire_time")
            if expire_time:
                try:
                    if isinstance(expire_time, str):
                        from dateutil import parser as _dtp
                        exp = _dtp.parse(expire_time)
                    else:
                        exp = expire_time
                    if exp.tzinfo is None:
                        exp = exp.replace(tzinfo=timezone.utc)
                    days = (exp - now).days
                    if days < 30:
                        sev = "CRITICAL" if days < 15 else "HIGH"
                        findings.append({
                            "finding_id": _gcp_finding_id("gcp.certificatemanager.certificate.expiring_soon", uid, account_id, region),
                            "resource_uid": uid, "resource_type": "CertificateManager::Certificate",
                            "account_id": account_id, "region": region,
                            "encryption_domain": "certificate_lifecycle",
                            "severity": sev, "status": "FAIL",
                            "rule_id": "gcp.certificatemanager.certificate.expiring_soon",
                            "encryption_status": None, "key_type": None, "algorithm": None,
                            "rotation_compliant": None, "transit_enforced": None,
                            "finding_data": {
                                "title": f"GCP certificate expires in {days} days",
                                "description": f"Certificate {uid} expires in {days} days.",
                                "days_until_expiry": days,
                            },
                        })
                except Exception:
                    pass
        # SSL policies: minTlsVersion TLS_1_0 → HIGH, no policy (default = TLS_1_0) → HIGH
        for r in discovery_resources.get("compute", []):
            uid = r.get("resource_uid") or r.get("name") or ""
            region = r.get("region") or "global"
            ef = r.get("emitted_fields") or r
            ssl_policy = ef.get("sslPolicy") or ef.get("ssl_policy") or {}
            min_tls = (ssl_policy.get("minTlsVersion") or "TLS_1_0").upper()
            if _GCP_TLS_RANK.get(min_tls, 0) < _GCP_TLS_RANK.get("TLS_1_2", 2):
                findings.append({
                    "finding_id": _gcp_finding_id("gcp.compute.ssl_policy.min_tls_below_1_2", uid, account_id, region),
                    "resource_uid": uid, "resource_type": "Compute::SslPolicy",
                    "account_id": account_id, "region": region,
                    "encryption_domain": "in_transit_enforcement", "severity": "HIGH", "status": "FAIL",
                    "rule_id": "gcp.compute.ssl_policy.min_tls_below_1_2",
                    "encryption_status": None, "key_type": None, "algorithm": None,
                    "rotation_compliant": None, "transit_enforced": False,
                    "finding_data": {
                        "title": f"GCP SSL policy minimum TLS is {min_tls}",
                        "description": "TLS 1.0 and 1.1 are deprecated. Set minTlsVersion to TLS_1_2 or TLS_1_3.",
                        "tls_version": min_tls,
                    },
                })
        logger.info("GCP Encryption Pattern A: %d rule findings", len(findings))
        return findings
