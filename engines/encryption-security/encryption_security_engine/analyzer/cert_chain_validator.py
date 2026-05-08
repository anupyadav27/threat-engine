"""
Certificate Chain Validator.

Validates certificate chains from ACM/ACM-PCA discovery data:
  - Expired intermediate certificates
  - Self-signed certificates in production
  - Weak algorithms (SHA-1, RSA-1024)
  - Unused certificates (not attached to any ALB/CloudFront/API GW)
  - Wildcard certificate tracking
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Weak algorithms that should trigger findings
WEAK_ALGORITHMS = {
    "SHA1", "SHA-1", "SHA1WithRSA", "sha1WithRSAEncryption",
    "RSA_1024", "RSA-1024",
    "MD5", "MD5WithRSA", "md5WithRSAEncryption",
}

# Minimum acceptable key lengths
MIN_KEY_LENGTHS = {
    "RSA": 2048,
    "EC": 256,
}


def validate_cert_chains(
    cert_inventory: List[Dict[str, Any]],
    inventory_relationships: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Validate certificate chains and detect issues.

    Args:
        cert_inventory: Certificate inventory from cert_inventory_builder.
        inventory_relationships: Optional resource relationships for usage detection.

    Returns:
        List of certificate validation findings.
    """
    # Build set of cert ARNs attached to resources
    attached_certs = set()
    if inventory_relationships:
        for rel in inventory_relationships:
            rel_type = (rel.get("relationship_type") or "").lower()
            source_type = (rel.get("source_type") or "").lower()
            target_type = (rel.get("target_type") or "").lower()

            # Certificates attached to LBs, CloudFront, API GW
            if "certificate" in rel_type or "acm" in source_type or "acm" in target_type:
                attached_certs.add(rel.get("source_uid", ""))
                attached_certs.add(rel.get("target_uid", ""))
            if "listener" in rel_type or "distribution" in rel_type:
                attached_certs.add(rel.get("source_uid", ""))
                attached_certs.add(rel.get("target_uid", ""))

    findings = []
    now = datetime.now(timezone.utc)

    for cert in cert_inventory:
        cert_arn = cert.get("cert_arn", "")
        domain = cert.get("domain_name", "")
        days_until = cert.get("days_until_expiry")
        cert_status = cert.get("cert_status", "")
        key_algo = cert.get("key_algorithm", "")
        issuer = cert.get("issuer", "")
        cert_type = cert.get("cert_type", "")
        in_use = cert.get("in_use", False)

        base_info = {
            "cert_arn": cert_arn,
            "domain_name": domain,
            "account_id": cert.get("account_id"),
            "region": cert.get("region"),
            "provider": cert.get("provider", "aws"),
            "cert_type": cert_type,
            "key_algorithm": key_algo,
            "issuer": issuer,
        }

        # 1. Expired certificates
        if days_until is not None and days_until < 0:
            findings.append({
                **base_info,
                "validation_type": "expired_certificate",
                "severity": "CRITICAL",
                "title": f"Certificate expired ({abs(days_until)} days ago)",
                "description": (
                    f"Certificate for {domain} expired {abs(days_until)} days ago. "
                    f"Status: {cert_status}"
                ),
                "remediation": "Renew or replace the expired certificate immediately",
                "days_until_expiry": days_until,
            })

        # 2. Expiring soon (within 7 days)
        elif days_until is not None and days_until <= 7:
            findings.append({
                **base_info,
                "validation_type": "expiring_critical",
                "severity": "CRITICAL",
                "title": f"Certificate expiring in {days_until} days",
                "description": (
                    f"Certificate for {domain} expires in {days_until} days. "
                    f"Renewal eligibility: {cert.get('renewal_eligibility', 'unknown')}"
                ),
                "remediation": "Renew the certificate immediately to prevent service disruption",
                "days_until_expiry": days_until,
            })

        # 3. Expiring within 30 days
        elif days_until is not None and days_until <= 30:
            findings.append({
                **base_info,
                "validation_type": "expiring_warning",
                "severity": "HIGH",
                "title": f"Certificate expiring in {days_until} days",
                "description": (
                    f"Certificate for {domain} expires in {days_until} days. "
                    f"Plan renewal before expiration."
                ),
                "remediation": "Schedule certificate renewal",
                "days_until_expiry": days_until,
            })

        # 4. Self-signed in production (non-Private CA)
        if cert.get("is_self_signed") and cert_type != "PRIVATE_CA":
            findings.append({
                **base_info,
                "validation_type": "self_signed",
                "severity": "HIGH",
                "title": "Self-signed certificate detected",
                "description": (
                    f"Certificate for {domain} appears to be self-signed "
                    f"(issuer: {issuer}). Self-signed certificates should not "
                    f"be used in production."
                ),
                "remediation": "Replace with a certificate from a trusted CA (ACM or third-party)",
            })

        # 5. Weak algorithm detection
        if key_algo and _is_weak_algorithm(key_algo):
            findings.append({
                **base_info,
                "validation_type": "weak_algorithm",
                "severity": "HIGH",
                "title": f"Weak certificate algorithm: {key_algo}",
                "description": (
                    f"Certificate for {domain} uses {key_algo} which is "
                    f"considered cryptographically weak."
                ),
                "remediation": f"Re-issue with RSA-2048+ or ECC P-256+ algorithm",
            })

        # 6. Unused certificates (not attached to any resource)
        if not in_use and cert_arn not in attached_certs and cert_status == "ISSUED":
            findings.append({
                **base_info,
                "validation_type": "unused_certificate",
                "severity": "LOW",
                "title": "Unused certificate detected",
                "description": (
                    f"Certificate for {domain} is issued but not attached to "
                    f"any load balancer, CloudFront distribution, or API Gateway."
                ),
                "remediation": "Attach to a resource or delete if no longer needed",
            })

        # 7. Wildcard certificate tracking
        if cert.get("is_wildcard"):
            findings.append({
                **base_info,
                "validation_type": "wildcard_certificate",
                "severity": "MEDIUM",
                "title": f"Wildcard certificate: {domain}",
                "description": (
                    f"Wildcard certificate covers all subdomains of {domain}. "
                    f"Consider using specific domain certificates for better security isolation."
                ),
                "remediation": "Evaluate if specific domain certificates would reduce risk",
            })

        # 8. Revoked certificates still present
        if cert_status == "REVOKED":
            findings.append({
                **base_info,
                "validation_type": "revoked_certificate",
                "severity": "CRITICAL",
                "title": "Revoked certificate found",
                "description": (
                    f"Certificate for {domain} has been revoked. "
                    f"If still attached to resources, it may cause trust failures."
                ),
                "remediation": "Remove revoked certificate and replace with a new one",
            })

    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: severity_order.get(f["severity"], 9))

    logger.info(
        f"Cert chain validation: {len(findings)} findings "
        f"from {len(cert_inventory)} certificates"
    )
    return findings


def _is_weak_algorithm(algo: str) -> bool:
    """Check if algorithm is considered weak."""
    algo_upper = algo.upper().replace("-", "_")
    for weak in WEAK_ALGORITHMS:
        if weak.upper().replace("-", "_") in algo_upper:
            return True
    # Check RSA key length
    if "RSA" in algo_upper:
        for part in algo.split("_"):
            try:
                bits = int(part)
                if bits < MIN_KEY_LENGTHS.get("RSA", 2048):
                    return True
            except ValueError:
                continue
    return False
