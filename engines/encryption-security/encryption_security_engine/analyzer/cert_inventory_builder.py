"""
Certificate Inventory Builder.

Aggregates ACM certificate data from discovery_findings into structured
certificate inventory records for the encryption_cert_inventory table.
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from dateutil import parser as dateparser

logger = logging.getLogger(__name__)


def build_cert_inventory(
    acm_resources: List[Dict[str, Any]],
    acm_pca_resources: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Build certificate inventory from ACM discovery resources.

    Args:
        acm_resources: ACM discovery_findings rows.
        acm_pca_resources: Optional ACM-PCA (Private CA) discovery rows.

    Returns:
        List of cert inventory dicts ready for save_cert_inventory().
    """
    cert_map = {}
    now = datetime.now(timezone.utc)

    for r in acm_resources:
        emitted = r.get("emitted_fields") or {}
        if not isinstance(emitted, dict):
            continue

        cert_arn = emitted.get("CertificateArn") or r.get("resource_uid", "")
        if not cert_arn or cert_arn in cert_map:
            if cert_arn and cert_arn in cert_map:
                _merge_cert_emitted(cert_map[cert_arn], emitted)
            continue

        not_after = _parse_date(emitted.get("NotAfter"))
        not_before = _parse_date(emitted.get("NotBefore"))
        days_until_expiry = (not_after - now).days if not_after else None

        domain_name = emitted.get("DomainName", "")
        san = emitted.get("SubjectAlternativeNames")
        if isinstance(san, list):
            san = [str(s) for s in san]
        else:
            san = None

        is_wildcard = domain_name.startswith("*.") if domain_name else False
        issuer = emitted.get("Issuer", "")
        is_self_signed = ("self" in issuer.lower()) if issuer else False

        entry = {
            "cert_arn": cert_arn,
            "domain_name": domain_name,
            "subject_alternative_names": san,
            "account_id": r.get("account_id", ""),
            "provider": r.get("provider", "aws"),
            "region": r.get("region", ""),
            "cert_status": emitted.get("Status", "UNKNOWN"),
            "cert_type": emitted.get("Type"),
            "key_algorithm": emitted.get("KeyAlgorithm"),
            "issuer": issuer,
            "serial_number": emitted.get("Serial"),
            "not_before": not_before,
            "not_after": not_after,
            "days_until_expiry": days_until_expiry,
            "renewal_eligibility": emitted.get("RenewalEligibility"),
            "in_use": emitted.get("InUse", False),
            "is_wildcard": is_wildcard,
            "is_self_signed": is_self_signed,
            "chain_valid": None,  # Phase 3: cert chain validation
            "tags": emitted.get("Tags") or {},
            "raw_data": emitted,
        }
        cert_map[cert_arn] = entry

    # Add Private CA certificates if available
    if acm_pca_resources:
        for r in acm_pca_resources:
            emitted = r.get("emitted_fields") or {}
            if not isinstance(emitted, dict):
                continue
            ca_arn = emitted.get("CertificateAuthorityArn") or r.get("resource_uid", "")
            if not ca_arn or ca_arn in cert_map:
                continue

            entry = {
                "cert_arn": ca_arn,
                "domain_name": emitted.get("Subject", {}).get("CommonName", ""),
                "subject_alternative_names": None,
                "account_id": r.get("account_id", ""),
                "provider": r.get("provider", "aws"),
                "region": r.get("region", ""),
                "cert_status": emitted.get("Status", "UNKNOWN"),
                "cert_type": "PRIVATE_CA",
                "key_algorithm": emitted.get("KeyStorageSecurityStandard"),
                "issuer": "Private CA",
                "serial_number": emitted.get("Serial"),
                "not_before": _parse_date(emitted.get("NotBefore")),
                "not_after": _parse_date(emitted.get("NotAfter")),
                "days_until_expiry": None,
                "renewal_eligibility": None,
                "in_use": True,
                "is_wildcard": False,
                "is_self_signed": True,  # Root CAs are self-signed
                "chain_valid": None,
                "tags": emitted.get("Tags") or {},
                "raw_data": emitted,
            }
            not_after = entry["not_after"]
            if not_after:
                entry["days_until_expiry"] = (not_after - now).days
            cert_map[ca_arn] = entry

    certs = list(cert_map.values())
    logger.info(f"Built inventory for {len(certs)} certificates")
    return certs


def _merge_cert_emitted(entry: Dict, emitted: Dict):
    """Merge additional emitted fields into existing cert entry."""
    if emitted.get("InUse") is not None:
        entry["in_use"] = emitted["InUse"]
    if emitted.get("RenewalEligibility"):
        entry["renewal_eligibility"] = emitted["RenewalEligibility"]


def _parse_date(val) -> Optional[datetime]:
    """Parse a date string or return None."""
    if not val:
        return None
    if isinstance(val, datetime):
        return val
    try:
        return dateparser.parse(str(val))
    except Exception:
        return None
