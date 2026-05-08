"""
Cross-Account Key Sharing Analyzer.

Parses KMS key policies from discovery data to identify:
  - Keys shared with external accounts
  - Overly permissive key policies (wildcard principals)
  - Keys accessible by unknown/unauthorized accounts
  - Grant-based cross-account access
"""

import json
import logging
import re
from typing import Dict, Any, List, Optional, Set

logger = logging.getLogger(__name__)

# AWS account ID pattern
ACCOUNT_ID_PATTERN = re.compile(r"\d{12}")


def analyze_cross_account_keys(
    key_inventory: List[Dict[str, Any]],
    own_account_ids: Optional[Set[str]] = None,
) -> List[Dict[str, Any]]:
    """Analyze KMS key policies for cross-account sharing.

    Args:
        key_inventory: Key inventory from key_inventory_builder.
        own_account_ids: Set of known owned account IDs. If None, inferred from inventory.

    Returns:
        List of cross-account sharing findings.
    """
    # Infer owned account IDs if not provided
    if own_account_ids is None:
        own_account_ids = set()
        for k in key_inventory:
            aid = k.get("account_id", "")
            if aid:
                own_account_ids.add(aid)

    findings = []

    for key in key_inventory:
        key_arn = key.get("key_arn", "")
        key_manager = key.get("key_manager", "")
        account_id = key.get("account_id", "")
        region = key.get("region", "")
        principals = key.get("key_policy_principals") or []
        grant_count = key.get("grant_count", 0)
        cross_account = key.get("cross_account_access", False)

        base_info = {
            "key_arn": key_arn,
            "key_id": key.get("key_id"),
            "key_alias": key.get("key_alias"),
            "key_manager": key_manager,
            "account_id": account_id,
            "region": region,
            "provider": key.get("provider", "aws"),
        }

        # Skip AWS-managed keys (their policies are AWS-controlled)
        if key_manager == "AWS":
            continue

        # Analyze principals
        external_accounts = set()
        has_wildcard = False
        has_service_principal = False

        for principal in principals:
            if not isinstance(principal, str):
                continue

            # Wildcard principal
            if principal == "*":
                has_wildcard = True
                continue

            # Service principals (e.g., s3.amazonaws.com)
            if ".amazonaws.com" in principal:
                has_service_principal = True
                continue

            # Extract account IDs from ARNs
            account_matches = ACCOUNT_ID_PATTERN.findall(principal)
            for match in account_matches:
                if match not in own_account_ids:
                    external_accounts.add(match)

        # 1. Wildcard principal — anyone can use the key
        if has_wildcard:
            findings.append({
                **base_info,
                "sharing_type": "wildcard_principal",
                "severity": "CRITICAL",
                "title": "KMS key has wildcard (*) principal",
                "description": (
                    f"Key {key.get('key_alias') or key_arn} has a policy with "
                    f"Principal: *, allowing any AWS account to use the key. "
                    f"This may be intentional (with conditions) but requires review."
                ),
                "remediation": (
                    "Restrict the key policy to specific AWS accounts/roles. "
                    "If conditions are present, verify they adequately restrict access."
                ),
                "external_accounts": [],
                "principal_count": len(principals),
            })

        # 2. Cross-account access detected
        if external_accounts:
            findings.append({
                **base_info,
                "sharing_type": "cross_account_access",
                "severity": "HIGH",
                "title": f"KMS key shared with {len(external_accounts)} external account(s)",
                "description": (
                    f"Key {key.get('key_alias') or key_arn} is accessible by "
                    f"accounts: {', '.join(sorted(external_accounts))}. "
                    f"Verify these are authorized accounts."
                ),
                "remediation": (
                    "Audit cross-account access. Remove unauthorized accounts "
                    "from the key policy. Document authorized sharing."
                ),
                "external_accounts": sorted(external_accounts),
                "principal_count": len(principals),
            })

        # 3. Excessive grants
        if grant_count > 5:
            severity = "HIGH" if grant_count > 20 else "MEDIUM"
            findings.append({
                **base_info,
                "sharing_type": "excessive_grants",
                "severity": severity,
                "title": f"KMS key has {grant_count} grants",
                "description": (
                    f"Key {key.get('key_alias') or key_arn} has {grant_count} "
                    f"active grants. Excessive grants increase the attack surface "
                    f"and make access auditing difficult."
                ),
                "remediation": (
                    "Review and retire unused grants. "
                    "Consider consolidating access via key policy instead of grants."
                ),
                "external_accounts": sorted(external_accounts),
                "grant_count": grant_count,
            })

        # 4. Keys with cross_account flag but no identified accounts
        if cross_account and not external_accounts and not has_wildcard:
            findings.append({
                **base_info,
                "sharing_type": "unresolved_cross_account",
                "severity": "MEDIUM",
                "title": "Cross-account access detected but accounts unresolved",
                "description": (
                    f"Key {key.get('key_alias') or key_arn} has cross-account "
                    f"access indicated but specific external accounts could not "
                    f"be resolved from the key policy."
                ),
                "remediation": "Review the key policy manually to identify external access",
                "external_accounts": [],
            })

    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: severity_order.get(f["severity"], 9))

    logger.info(
        f"Cross-account analysis: {len(findings)} findings "
        f"from {len(key_inventory)} keys, "
        f"own accounts: {own_account_ids}"
    )
    return findings
