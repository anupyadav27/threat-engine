"""AWS provider for Encryption Security engine."""
import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .base import BaseEncryptionProvider

logger = logging.getLogger(__name__)

_TLS_POLICY_VERSION = {
    "ELBSecurityPolicy-2015-05": "TLSv1.0",
    "ELBSecurityPolicy-TLS-1-0-2015-04": "TLSv1.0",
    "ELBSecurityPolicy-TLS-1-1-2017-01": "TLSv1.1",
    "ELBSecurityPolicy-TLS-1-2-2017-01": "TLSv1.2",
    "ELBSecurityPolicy-TLS-1-2-Ext-2018-06": "TLSv1.2",
    "ELBSecurityPolicy-FS-2018-06": "TLSv1.2",
    "ELBSecurityPolicy-FS-1-2-2019-08": "TLSv1.2",
    "ELBSecurityPolicy-FS-1-2-Res-2019-08": "TLSv1.2",
    "ELBSecurityPolicy-TLS13-1-2-2021-06": "TLSv1.3",
    "ELBSecurityPolicy-TLS13-1-3-2021-06": "TLSv1.3",
}


def _enc_finding_id(rule_id: str, resource_uid: str, account_id: str, region: str) -> str:
    raw = f"{rule_id}|{resource_uid}|{account_id}|{region}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _enc_finding(
    rule_id: str,
    resource_uid: str,
    resource_type: str,
    account_id: str,
    region: str,
    scan_run_id: str,
    tenant_id: str,
    encryption_domain: str,
    severity: str,
    title: str,
    description: str,
    now: datetime,
    extra: Optional[Dict] = None,
) -> Dict[str, Any]:
    return {
        "finding_id": _enc_finding_id(rule_id, resource_uid, account_id, region),
        "resource_uid": resource_uid,
        "resource_type": resource_type,
        "account_id": account_id,
        "region": region,
        "encryption_domain": encryption_domain,
        "encryption_status": "unencrypted" if "rotation" not in rule_id else "encrypted_managed",
        "key_type": None,
        "algorithm": None,
        "rotation_compliant": "rotation" in rule_id and severity not in ("CRITICAL", "HIGH"),
        "transit_enforced": None,
        "severity": severity,
        "status": "FAIL",
        "rule_id": rule_id,
        "finding_data": {
            "title": title,
            "description": description,
            **(extra or {}),
        },
    }


class AWSEncryptionProvider(BaseEncryptionProvider):

    @property
    def key_services(self):
        return ["kms", "cloudhsm"]

    @property
    def cert_services(self):
        return ["acm", "acm-pca"]

    @property
    def secrets_services(self):
        return ["secretsmanager", "ssm"]

    @property
    def inventory_resource_prefixes(self):
        return ["kms.", "acm.", "secretsmanager.", "ssm.", "cloudhsm."]

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        discovery_resources: Dict[str, List[Dict[str, Any]]],
    ) -> Optional[List[Dict[str, Any]]]:
        """Pattern A: rule-based findings from KMS, ACM, and SecretsManager resources."""
        now = datetime.now(timezone.utc)
        findings: List[Dict[str, Any]] = []
        findings.extend(self._check_kms(discovery_resources.get("kms", []), scan_run_id, tenant_id, account_id, now))
        findings.extend(self._check_acm(discovery_resources.get("acm", []), scan_run_id, tenant_id, account_id, now))
        findings.extend(self._check_secrets(discovery_resources.get("secretsmanager", []), scan_run_id, tenant_id, account_id, now))
        logger.info("AWS Encryption Pattern A: %d rule findings", len(findings))
        return findings

    def _check_kms(
        self,
        kms_resources: List[Dict],
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        now: datetime,
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for r in kms_resources:
            uid = r.get("resource_uid") or r.get("KeyId") or r.get("KeyArn") or ""
            region = r.get("region") or "us-east-1"
            ef = r.get("emitted_fields") or r
            key_state = ef.get("KeyState") or ef.get("KeyMetadata", {}).get("KeyState", "")
            key_manager = ef.get("KeyManager") or ef.get("KeyMetadata", {}).get("KeyManager", "")
            origin = ef.get("Origin") or ef.get("KeyMetadata", {}).get("Origin", "")
            rotation = ef.get("KeyRotationStatus") or ef.get("KeyRotationEnabled") or False
            if isinstance(rotation, dict):
                rotation = rotation.get("KeyRotationEnabled", False)
            key_policy = ef.get("Policy") or ef.get("KeyPolicy") or {}
            if isinstance(key_policy, str):
                import json as _json
                try:
                    key_policy = _json.loads(key_policy)
                except Exception:
                    key_policy = {}

            if key_state == "PendingDeletion":
                findings.append(_enc_finding(
                    rule_id="aws.kms.key.pending_deletion",
                    resource_uid=uid, resource_type="KMS::Key",
                    account_id=account_id, region=region,
                    scan_run_id=scan_run_id, tenant_id=tenant_id,
                    encryption_domain="kms_key_management", severity="HIGH",
                    title="KMS key scheduled for deletion",
                    description="This KMS key is in PendingDeletion state. Resources encrypted with it will lose access after deletion.",
                    now=now,
                ))
            if key_manager == "CUSTOMER" and not rotation:
                findings.append(_enc_finding(
                    rule_id="aws.kms.key.rotation_disabled",
                    resource_uid=uid, resource_type="KMS::Key",
                    account_id=account_id, region=region,
                    scan_run_id=scan_run_id, tenant_id=tenant_id,
                    encryption_domain="kms_key_management", severity="MEDIUM",
                    title="KMS CMK automatic rotation not enabled",
                    description="Customer-managed KMS keys should have automatic annual rotation enabled.",
                    now=now,
                ))
            if origin == "EXTERNAL":
                findings.append(_enc_finding(
                    rule_id="aws.kms.key.imported_key_material",
                    resource_uid=uid, resource_type="KMS::Key",
                    account_id=account_id, region=region,
                    scan_run_id=scan_run_id, tenant_id=tenant_id,
                    encryption_domain="kms_key_management", severity="MEDIUM",
                    title="KMS key uses imported key material",
                    description="Imported key material must be manually rotated and re-imported; automatic rotation is not available.",
                    now=now,
                ))
            for stmt in (key_policy.get("Statement") or []):
                principal = stmt.get("Principal")
                if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                    if stmt.get("Effect") == "Allow":
                        findings.append(_enc_finding(
                            rule_id="aws.kms.key.wildcard_principal_policy",
                            resource_uid=uid, resource_type="KMS::Key",
                            account_id=account_id, region=region,
                            scan_run_id=scan_run_id, tenant_id=tenant_id,
                            encryption_domain="kms_key_management", severity="CRITICAL",
                            title="KMS key policy allows wildcard principal",
                            description="KMS key policy contains an Allow statement with Principal='*', granting access to all AWS principals.",
                            now=now,
                        ))
                        break
        return findings

    def _check_acm(
        self,
        acm_resources: List[Dict],
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        now: datetime,
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for r in acm_resources:
            uid = r.get("resource_uid") or r.get("CertificateArn") or ""
            region = r.get("region") or "us-east-1"
            ef = r.get("emitted_fields") or r
            days = ef.get("DaysUntilExpiry") or ef.get("days_until_expiry")
            if days is None:
                not_after = ef.get("NotAfter") or ef.get("CertificateDetail", {}).get("NotAfter")
                if not_after:
                    try:
                        if isinstance(not_after, str):
                            from dateutil import parser as _dtp
                            exp = _dtp.parse(not_after)
                        else:
                            exp = not_after
                        if exp.tzinfo is None:
                            exp = exp.replace(tzinfo=timezone.utc)
                        days = (exp - now).days
                    except Exception:
                        days = None
            algo = ef.get("KeyAlgorithm") or ef.get("CertificateDetail", {}).get("KeyAlgorithm", "")
            renewal = ef.get("RenewalEligibility") or ef.get("RenewalSummary", {}).get("RenewalStatus", "")
            status = ef.get("Status") or ef.get("CertificateDetail", {}).get("Status", "")

            if days is not None:
                try:
                    days = int(days)
                except (TypeError, ValueError):
                    days = None

            if days is not None and days < 30:
                sev = "CRITICAL" if days < 15 else "HIGH"
                findings.append(_enc_finding(
                    rule_id="aws.acm.certificate.expiring_soon",
                    resource_uid=uid, resource_type="ACM::Certificate",
                    account_id=account_id, region=region,
                    scan_run_id=scan_run_id, tenant_id=tenant_id,
                    encryption_domain="certificate_lifecycle", severity=sev,
                    title=f"ACM certificate expires in {days} days",
                    description=f"Certificate {uid} expires in {days} days. Renew before expiry to avoid service disruption.",
                    now=now, extra={"days_until_expiry": days},
                ))
            elif days is not None and days < 60:
                findings.append(_enc_finding(
                    rule_id="aws.acm.certificate.renewal_due",
                    resource_uid=uid, resource_type="ACM::Certificate",
                    account_id=account_id, region=region,
                    scan_run_id=scan_run_id, tenant_id=tenant_id,
                    encryption_domain="certificate_lifecycle", severity="MEDIUM",
                    title=f"ACM certificate renewal due ({days} days remaining)",
                    description=f"Certificate expires in {days} days. Verify auto-renewal is configured correctly.",
                    now=now, extra={"days_until_expiry": days},
                ))
            if algo and "1024" in str(algo):
                findings.append(_enc_finding(
                    rule_id="aws.acm.certificate.deprecated_key_algorithm",
                    resource_uid=uid, resource_type="ACM::Certificate",
                    account_id=account_id, region=region,
                    scan_run_id=scan_run_id, tenant_id=tenant_id,
                    encryption_domain="certificate_lifecycle", severity="HIGH",
                    title="ACM certificate uses deprecated RSA-1024 key",
                    description="RSA-1024 is deprecated. Reissue with RSA-2048 or ECDSA-256.",
                    now=now, extra={"key_algorithm": algo},
                ))
            if renewal and "FAILED" in str(renewal).upper():
                findings.append(_enc_finding(
                    rule_id="aws.acm.certificate.auto_renewal_failed",
                    resource_uid=uid, resource_type="ACM::Certificate",
                    account_id=account_id, region=region,
                    scan_run_id=scan_run_id, tenant_id=tenant_id,
                    encryption_domain="certificate_lifecycle", severity="HIGH",
                    title="ACM certificate auto-renewal failed",
                    description=f"Auto-renewal status: {renewal}. Manual intervention required before expiry.",
                    now=now,
                ))
            if status and status not in ("ISSUED", "PENDING_VALIDATION", "EXPIRED"):
                findings.append(_enc_finding(
                    rule_id="aws.acm.certificate.orphaned",
                    resource_uid=uid, resource_type="ACM::Certificate",
                    account_id=account_id, region=region,
                    scan_run_id=scan_run_id, tenant_id=tenant_id,
                    encryption_domain="certificate_lifecycle", severity="LOW",
                    title=f"ACM certificate in unexpected status: {status}",
                    description="Certificate is not in ISSUED state and may be orphaned. Review and delete if unused.",
                    now=now,
                ))
        return findings

    def _check_secrets(
        self,
        secrets_resources: List[Dict],
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        now: datetime,
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for r in secrets_resources:
            uid = r.get("resource_uid") or r.get("ARN") or r.get("Name") or ""
            region = r.get("region") or "us-east-1"
            ef = r.get("emitted_fields") or r
            rotation_enabled = ef.get("RotationEnabled") or False
            last_rotated = ef.get("LastRotatedDate") or ef.get("LastChangedDate")
            if not rotation_enabled:
                findings.append(_enc_finding(
                    rule_id="aws.secretsmanager.secret.rotation_disabled",
                    resource_uid=uid, resource_type="SecretsManager::Secret",
                    account_id=account_id, region=region,
                    scan_run_id=scan_run_id, tenant_id=tenant_id,
                    encryption_domain="secrets_management", severity="MEDIUM",
                    title="SecretsManager secret has rotation disabled",
                    description="Automatic rotation should be enabled to limit the blast radius of a compromised secret.",
                    now=now,
                ))
            if last_rotated:
                try:
                    if isinstance(last_rotated, str):
                        from dateutil import parser as _dtp2
                        lr = _dtp2.parse(last_rotated)
                    else:
                        lr = last_rotated
                    if lr.tzinfo is None:
                        lr = lr.replace(tzinfo=timezone.utc)
                    age_days = (now - lr).days
                    if age_days > 90:
                        findings.append(_enc_finding(
                            rule_id="aws.secretsmanager.secret.stale_rotation",
                            resource_uid=uid, resource_type="SecretsManager::Secret",
                            account_id=account_id, region=region,
                            scan_run_id=scan_run_id, tenant_id=tenant_id,
                            encryption_domain="secrets_management", severity="MEDIUM",
                            title=f"SecretsManager secret not rotated in {age_days} days",
                            description=f"Secret was last rotated {age_days} days ago (>90-day threshold). Rotate now.",
                            now=now, extra={"days_since_rotation": age_days},
                        ))
                except Exception:
                    pass
        return findings
