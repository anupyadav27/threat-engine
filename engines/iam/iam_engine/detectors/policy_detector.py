"""
IAM Policy-Based Detection Rules

Generates new IAM findings from parsed policy data that go beyond
the check engine's regex-based rules. Focuses on structural policy analysis:
  - Admin access (Action:* + Resource:*)
  - Wildcard actions/resources
  - Wildcard trust principals
  - Cross-account trust without ExternalId

Check engine already covers credential hygiene (MFA, key rotation, password policy).
"""

import hashlib
import logging
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

from ..parsers.policy_parser import ParsedPolicy, PolicyStatement, is_admin_policy
from ..parsers.trust_analyzer import TrustRelationship

logger = logging.getLogger(__name__)


def _finding_id(rule_id: str, resource_uid: str, account_id: str, region: str = "global") -> str:
    """Compute deterministic finding_id matching threat_findings pattern."""
    raw = f"{rule_id}|{resource_uid}|{account_id}|{region}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def detect_admin_policies(
    policies: List[ParsedPolicy],
    account_id: str = "",
) -> List[Dict[str, Any]]:
    """
    Detect policies that grant full admin access (Action:* + Resource:*).

    Skips AWS-managed policies (e.g., AdministratorAccess is expected to be admin).
    """
    findings = []
    for policy in policies:
        if policy.is_aws_managed:
            continue
        if not is_admin_policy(policy):
            continue
        resource_uid = policy.attached_to_arn or policy.policy_arn or policy.policy_name
        findings.append({
            "finding_id": _finding_id("aws.iam.policy.admin_access", resource_uid, account_id),
            "rule_id": "aws.iam.policy.admin_access",
            "severity": "critical",
            "status": "FAIL",
            "resource_type": "iam",
            "resource_uid": resource_uid,
            "resource_id": policy.policy_name,
            "account_id": account_id,
            "region": "global",
            "title": f"Policy '{policy.policy_name}' grants full admin access",
            "description": (
                f"The {policy.source} policy '{policy.policy_name}' allows Action:* on Resource:*. "
                f"This grants unrestricted access to all AWS services and resources."
            ),
            "remediation": "Apply least-privilege: restrict actions and resources to only what is needed.",
            "policy_name": policy.policy_name,
            "policy_arn": policy.policy_arn,
            "policy_type": policy.source,
            "attached_to": policy.attached_to_arn,
            "iam_security_modules": ["least_privilege", "policy_analysis"],
            "is_iam_relevant": True,
        })
    return findings


def detect_wildcard_actions(
    policies: List[ParsedPolicy],
    account_id: str = "",
) -> List[Dict[str, Any]]:
    """
    Detect policies with Action:* but NOT Resource:* (partial wildcard).

    Full admin (Action:* + Resource:*) is caught by detect_admin_policies.
    """
    findings = []
    for policy in policies:
        if policy.is_aws_managed:
            continue
        for stmt in policy.statements:
            if stmt.effect != "Allow":
                continue
            if "*" not in stmt.actions:
                continue
            if "*" in stmt.resources:
                continue  # Already caught by admin detector
            resource_uid = policy.attached_to_arn or policy.policy_arn or policy.policy_name
            findings.append({
                "finding_id": _finding_id("aws.iam.policy.wildcard_actions", resource_uid, account_id),
                "rule_id": "aws.iam.policy.wildcard_actions",
                "severity": "high",
                "status": "FAIL",
                "resource_type": "iam",
                "resource_uid": resource_uid,
                "resource_id": policy.policy_name,
                "account_id": account_id,
                "region": "global",
                "title": f"Policy '{policy.policy_name}' allows all actions",
                "description": (
                    f"The {policy.source} policy '{policy.policy_name}' uses Action:* "
                    f"which grants all possible actions on the specified resources."
                ),
                "remediation": "Replace Action:* with specific required actions.",
                "iam_security_modules": ["least_privilege", "policy_analysis"],
                "is_iam_relevant": True,
            })
            break  # One finding per policy
    return findings


def detect_wildcard_resources(
    policies: List[ParsedPolicy],
    account_id: str = "",
) -> List[Dict[str, Any]]:
    """
    Detect policies with Resource:* but specific actions (broad scope).

    Flags policies that apply specific actions to ALL resources.
    """
    # Services where Resource:* is especially risky
    sensitive_prefixes = {"s3:", "rds:", "dynamodb:", "kms:", "secretsmanager:", "iam:"}

    findings = []
    for policy in policies:
        if policy.is_aws_managed:
            continue
        for stmt in policy.statements:
            if stmt.effect != "Allow":
                continue
            if "*" not in stmt.resources:
                continue
            if "*" in stmt.actions:
                continue  # Already caught by admin detector
            # Check if actions include sensitive services
            has_sensitive = any(
                any(a.lower().startswith(p) for p in sensitive_prefixes)
                for a in stmt.actions
            )
            if not has_sensitive:
                continue
            resource_uid = policy.attached_to_arn or policy.policy_arn or policy.policy_name
            findings.append({
                "finding_id": _finding_id("aws.iam.policy.wildcard_resources", resource_uid, account_id),
                "rule_id": "aws.iam.policy.wildcard_resources",
                "severity": "high",
                "status": "FAIL",
                "resource_type": "iam",
                "resource_uid": resource_uid,
                "resource_id": policy.policy_name,
                "account_id": account_id,
                "region": "global",
                "title": f"Policy '{policy.policy_name}' grants sensitive actions on all resources",
                "description": (
                    f"The {policy.source} policy '{policy.policy_name}' uses Resource:* "
                    f"with sensitive service actions ({', '.join(stmt.actions[:5])}). "
                    f"This grants broad access across all resources of those services."
                ),
                "remediation": "Restrict Resource to specific ARNs instead of *.",
                "iam_security_modules": ["least_privilege", "policy_analysis"],
                "is_iam_relevant": True,
            })
            break
    return findings


def detect_wildcard_trust_principals(
    trust_relationships: List[TrustRelationship],
) -> List[Dict[str, Any]]:
    """Detect trust policies with Principal: *."""
    findings = []
    for trust in trust_relationships:
        if trust.effect != "Allow":
            continue
        if trust.is_service_linked:
            continue
        if trust.principal_type != "wildcard":
            continue
        findings.append({
            "finding_id": _finding_id(
                "aws.iam.role.wildcard_trust_principal",
                trust.source_role_arn, trust.source_account,
            ),
            "rule_id": "aws.iam.role.wildcard_trust_principal",
            "severity": "critical",
            "status": "FAIL",
            "resource_type": "iam",
            "resource_uid": trust.source_role_arn,
            "resource_id": trust.source_role_name,
            "account_id": trust.source_account,
            "region": "global",
            "title": f"Role '{trust.source_role_name}' has wildcard trust principal",
            "description": (
                f"The role '{trust.source_role_name}' allows Principal:* in its trust policy. "
                f"Any AWS account or identity can assume this role."
            ),
            "remediation": "Restrict Principal to specific accounts or roles. Add Condition constraints.",
            "iam_security_modules": ["role_management", "access_control"],
            "is_iam_relevant": True,
        })
    return findings


def detect_cross_account_no_external_id(
    trust_relationships: List[TrustRelationship],
) -> List[Dict[str, Any]]:
    """Detect cross-account trusts without sts:ExternalId condition."""
    findings = []
    seen = set()
    for trust in trust_relationships:
        if trust.effect != "Allow":
            continue
        if trust.is_service_linked:
            continue
        if not trust.is_cross_account:
            continue
        if trust.has_external_id:
            continue
        if trust.principal_type not in ("account", "role", "user"):
            continue
        # Deduplicate per role
        if trust.source_role_arn in seen:
            continue
        seen.add(trust.source_role_arn)

        findings.append({
            "finding_id": _finding_id(
                "aws.iam.role.cross_account_no_external_id",
                trust.source_role_arn, trust.source_account,
            ),
            "rule_id": "aws.iam.role.cross_account_no_external_id",
            "severity": "high",
            "status": "FAIL",
            "resource_type": "iam",
            "resource_uid": trust.source_role_arn,
            "resource_id": trust.source_role_name,
            "account_id": trust.source_account,
            "region": "global",
            "title": f"Role '{trust.source_role_name}' has cross-account trust without ExternalId",
            "description": (
                f"The role '{trust.source_role_name}' trusts account {trust.target_account} "
                f"without requiring an sts:ExternalId condition. This is vulnerable to the "
                f"confused deputy attack."
            ),
            "remediation": (
                "Add a Condition with StringEquals sts:ExternalId to the trust policy "
                "to prevent confused deputy attacks."
            ),
            "iam_security_modules": ["role_management", "access_control"],
            "is_iam_relevant": True,
        })
    return findings


def run_all_detectors(
    managed_policies: List[ParsedPolicy],
    inline_policies: List[ParsedPolicy],
    trust_relationships: List[TrustRelationship],
    account_id: str = "",
) -> List[Dict[str, Any]]:
    """
    Run all policy-based detectors and return combined findings.

    Args:
        managed_policies: Parsed managed policies (excluding AWS-managed)
        inline_policies: Parsed inline policies
        trust_relationships: Analyzed trust relationships
        account_id: AWS account ID

    Returns:
        List of finding dicts ready for iam_findings INSERT
    """
    all_policies = managed_policies + inline_policies
    findings = []
    findings.extend(detect_admin_policies(all_policies, account_id))
    findings.extend(detect_wildcard_actions(all_policies, account_id))
    findings.extend(detect_wildcard_resources(all_policies, account_id))
    findings.extend(detect_wildcard_trust_principals(trust_relationships))
    findings.extend(detect_cross_account_no_external_id(trust_relationships))

    # Deduplicate by finding_id
    seen = set()
    deduped = []
    for f in findings:
        fid = f["finding_id"]
        if fid not in seen:
            seen.add(fid)
            deduped.append(f)

    logger.info(f"Policy detectors generated {len(deduped)} findings")
    return deduped
