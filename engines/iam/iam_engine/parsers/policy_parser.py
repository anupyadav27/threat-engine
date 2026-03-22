"""
IAM Policy Document Parser

Parses AWS IAM policy documents (managed, inline, trust) into structured
PolicyStatement records. Pure functions — no DB or network access.

Handles:
  - Managed policy documents from get_account_authorization_details_policies
  - Inline role/user/group policies from RolePolicyList/UserPolicyList
  - Trust policies from AssumeRolePolicyDocument on roles
  - URL-encoded policy document strings (AWS sometimes returns these)
"""

import hashlib
import json
import logging
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Union
from urllib.parse import unquote

logger = logging.getLogger(__name__)


@dataclass
class PolicyStatement:
    """A single parsed IAM policy statement."""
    sid: Optional[str] = None
    effect: str = "Allow"
    actions: List[str] = field(default_factory=list)
    not_actions: List[str] = field(default_factory=list)
    resources: List[str] = field(default_factory=list)
    not_resources: List[str] = field(default_factory=list)
    conditions: Dict[str, Any] = field(default_factory=dict)
    principals: List[str] = field(default_factory=list)
    principal_type: Optional[str] = None  # AWS, Service, Federated, *


@dataclass
class ParsedPolicy:
    """A fully parsed policy with metadata."""
    policy_arn: Optional[str] = None
    policy_name: str = ""
    version: str = "2012-10-17"
    statements: List[PolicyStatement] = field(default_factory=list)
    is_aws_managed: bool = False
    attachment_count: int = 0
    source: str = "managed"  # managed | inline | trust
    attached_to_arn: Optional[str] = None
    attached_to_type: Optional[str] = None  # role | user | group


def _ensure_list(val: Any) -> List[str]:
    """Normalize a string-or-list field to always be a list."""
    if val is None:
        return []
    if isinstance(val, str):
        return [val]
    if isinstance(val, list):
        return [str(v) for v in val]
    return [str(val)]


def _decode_document(doc: Any) -> Dict[str, Any]:
    """
    Decode a policy document that may be a dict, JSON string, or URL-encoded string.

    AWS sometimes returns policy documents as URL-encoded JSON strings,
    especially in AssumeRolePolicyDocument.
    """
    if isinstance(doc, dict):
        return doc
    if isinstance(doc, str):
        # Try URL-decode first, then JSON parse
        decoded = unquote(doc)
        try:
            return json.loads(decoded)
        except (json.JSONDecodeError, TypeError):
            pass
        # Try raw JSON parse
        try:
            return json.loads(doc)
        except (json.JSONDecodeError, TypeError):
            pass
    logger.debug(f"Could not decode policy document: {type(doc)}")
    return {}


def _extract_principals(principal_field: Any) -> tuple:
    """
    Extract principals from a Statement's Principal field.

    Returns:
        (principals_list, principal_type)
    """
    if principal_field is None:
        return [], None
    if isinstance(principal_field, str):
        if principal_field == "*":
            return ["*"], "wildcard"
        return [principal_field], "AWS"
    if isinstance(principal_field, dict):
        principals = []
        ptype = None
        for key, val in principal_field.items():
            items = _ensure_list(val)
            principals.extend(items)
            ptype = key  # AWS, Service, Federated
        if any(p == "*" for p in principals):
            ptype = "wildcard"
        return principals, ptype
    return [], None


def parse_policy_document(doc: Any) -> List[PolicyStatement]:
    """
    Parse an IAM policy document into a list of PolicyStatements.

    Args:
        doc: Policy document (dict, JSON string, or URL-encoded string)

    Returns:
        List of parsed PolicyStatement objects
    """
    parsed = _decode_document(doc)
    if not parsed:
        return []

    raw_statements = parsed.get("Statement", [])
    if isinstance(raw_statements, dict):
        raw_statements = [raw_statements]

    statements = []
    for stmt in raw_statements:
        if not isinstance(stmt, dict):
            continue
        principals, ptype = _extract_principals(stmt.get("Principal"))
        statements.append(PolicyStatement(
            sid=stmt.get("Sid"),
            effect=stmt.get("Effect", "Allow"),
            actions=_ensure_list(stmt.get("Action")),
            not_actions=_ensure_list(stmt.get("NotAction")),
            resources=_ensure_list(stmt.get("Resource")),
            not_resources=_ensure_list(stmt.get("NotResource")),
            conditions=stmt.get("Condition") or {},
            principals=principals,
            principal_type=ptype,
        ))
    return statements


def parse_trust_policy(assume_role_doc: Any) -> List[PolicyStatement]:
    """Parse AssumeRolePolicyDocument into trust statements."""
    return parse_policy_document(assume_role_doc)


def extract_managed_policies(
    auth_details_policies: List[Dict[str, Any]],
    account_id: str = "",
) -> List[ParsedPolicy]:
    """
    Extract managed policy documents from get_account_authorization_details_policies.

    Each record has PolicyVersionList containing [{VersionId, IsDefaultVersion, Document}].
    We parse only the default version's Document.
    """
    policies = []
    for record in auth_details_policies:
        arn = record.get("Arn", "")
        is_aws = arn.startswith("arn:aws:iam::aws:policy/")

        # Find the default version document
        version_list = record.get("PolicyVersionList") or []
        doc = None
        for ver in version_list:
            if isinstance(ver, dict) and ver.get("IsDefaultVersion"):
                doc = ver.get("Document")
                break

        statements = parse_policy_document(doc) if doc else []

        policies.append(ParsedPolicy(
            policy_arn=arn,
            policy_name=record.get("PolicyName", ""),
            statements=statements,
            is_aws_managed=is_aws,
            attachment_count=record.get("AttachmentCount", 0),
            source="managed",
        ))
    return policies


def extract_inline_policies(
    entity: Dict[str, Any],
    entity_type: str = "role",
) -> List[ParsedPolicy]:
    """
    Extract inline policies from a role/user/group record.

    Roles have RolePolicyList, users have UserPolicyList, groups have GroupPolicyList.
    Each entry: {PolicyName, PolicyDocument}
    """
    key_map = {
        "role": "RolePolicyList",
        "user": "UserPolicyList",
        "group": "GroupPolicyList",
    }
    list_key = key_map.get(entity_type, "RolePolicyList")
    policy_list = entity.get(list_key) or []
    entity_arn = entity.get("Arn", "")

    policies = []
    for pol in policy_list:
        if not isinstance(pol, dict):
            continue
        doc = pol.get("PolicyDocument")
        statements = parse_policy_document(doc) if doc else []
        policies.append(ParsedPolicy(
            policy_name=pol.get("PolicyName", ""),
            statements=statements,
            source="inline",
            attached_to_arn=entity_arn,
            attached_to_type=entity_type,
        ))
    return policies


def extract_trust_policies(roles: List[Dict[str, Any]]) -> List[ParsedPolicy]:
    """
    Extract trust policies (AssumeRolePolicyDocument) from role records.

    Returns one ParsedPolicy per role with source='trust'.
    """
    policies = []
    for role in roles:
        doc = role.get("AssumeRolePolicyDocument")
        if not doc:
            continue
        statements = parse_trust_policy(doc)
        if not statements:
            continue
        policies.append(ParsedPolicy(
            policy_name=f"TrustPolicy:{role.get('RoleName', '')}",
            statements=statements,
            source="trust",
            attached_to_arn=role.get("Arn", ""),
            attached_to_type="role",
        ))
    return policies


def is_admin_policy(policy: ParsedPolicy) -> bool:
    """Check if any statement grants full admin access (Action:* + Resource:*)."""
    for stmt in policy.statements:
        if stmt.effect != "Allow":
            continue
        has_star_action = "*" in stmt.actions or "iam:*" in stmt.actions
        has_star_resource = "*" in stmt.resources
        if has_star_action and has_star_resource:
            return True
    return False


def has_wildcard_principal(statements: List[PolicyStatement]) -> bool:
    """Check if any statement has Principal: *."""
    return any("*" in stmt.principals for stmt in statements)


def missing_external_id(
    statements: List[PolicyStatement],
    source_account: str = "",
) -> bool:
    """
    Check if cross-account trust statements lack sts:ExternalId condition.

    Only relevant for Allow statements with AWS principals from different accounts.
    """
    for stmt in statements:
        if stmt.effect != "Allow":
            continue
        # Check if any principal is from a different account
        for principal in stmt.principals:
            if not isinstance(principal, str):
                continue
            # Skip service principals and wildcards
            if principal == "*" or ":root" not in principal:
                continue
            # Extract account from ARN
            parts = principal.split(":")
            if len(parts) >= 5 and parts[4] != source_account:
                # Cross-account — check for ExternalId condition
                conditions = stmt.conditions
                if not conditions:
                    return True
                str_equals = conditions.get("StringEquals", {})
                if "sts:ExternalId" not in str_equals:
                    return True
    return False


def compute_statement_id(
    scan_run_id: str,
    policy_arn: str,
    sid: str,
    idx: int = 0,
) -> str:
    """Compute deterministic statement_id for deduplication."""
    raw = f"{scan_run_id}|{policy_arn or ''}|{sid or ''}|{idx}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def policies_to_db_rows(
    policies: List[ParsedPolicy],
    scan_run_id: str,
    tenant_id: str,
    account_id: str = "",
) -> List[Dict[str, Any]]:
    """
    Convert parsed policies to flat dicts ready for iam_policy_statements INSERT.

    Skips AWS-managed policies (they're flagged but not written to findings).
    """
    rows = []
    for policy in policies:
        for idx, stmt in enumerate(policy.statements):
            sid = compute_statement_id(
                scan_run_id,
                policy.policy_arn or policy.attached_to_arn or policy.policy_name,
                stmt.sid,
                idx,
            )
            rows.append({
                "statement_id": sid,
                "scan_run_id": scan_run_id,
                "tenant_id": tenant_id,
                "account_id": account_id,
                "policy_arn": policy.policy_arn,
                "policy_name": policy.policy_name,
                "policy_type": policy.source,
                "is_aws_managed": policy.is_aws_managed,
                "attached_to_arn": policy.attached_to_arn,
                "attached_to_type": policy.attached_to_type,
                "sid": stmt.sid,
                "effect": stmt.effect,
                "actions": stmt.actions or stmt.not_actions,
                "resources": stmt.resources or stmt.not_resources,
                "conditions": stmt.conditions or None,
                "principals": stmt.principals or None,
                "is_admin": is_admin_policy(policy) if stmt.effect == "Allow" else False,
                "is_wildcard_principal": "*" in stmt.principals,
                "has_external_id": _has_external_id_condition(stmt.conditions),
                "is_cross_account": None,  # Set by trust_analyzer
            })
    return rows


def _has_external_id_condition(conditions: Dict) -> Optional[bool]:
    """Check if conditions contain sts:ExternalId."""
    if not conditions:
        return None
    str_equals = conditions.get("StringEquals", {})
    return "sts:ExternalId" in str_equals
