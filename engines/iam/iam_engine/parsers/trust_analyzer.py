"""
IAM Trust Relationship Analyzer

Analyzes AssumeRolePolicyDocument trust policies to detect:
  - Cross-account trust relationships
  - Wildcard principals
  - Missing sts:ExternalId conditions
  - Service-linked vs. customer roles

Pure analysis — no DB or network access.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

from .policy_parser import parse_trust_policy, PolicyStatement

logger = logging.getLogger(__name__)

# Pattern to extract account ID from ARN
ARN_ACCOUNT_RE = re.compile(r"arn:aws[^:]*:iam::(\d{12}):")


@dataclass
class TrustRelationship:
    """A single trust relationship from a role's AssumeRolePolicyDocument."""
    source_role_arn: str
    source_role_name: str
    trusted_principal: str
    principal_type: str  # account, service, role, user, federated, wildcard
    effect: str  # Allow, Deny
    conditions: Dict[str, Any] = field(default_factory=dict)
    has_external_id: bool = False
    is_cross_account: bool = False
    source_account: str = ""
    target_account: str = ""
    is_service_linked: bool = False


class TrustAnalyzer:
    """Analyzes IAM role trust policies to build trust chain."""

    def analyze_trust_policies(
        self,
        roles: List[Dict[str, Any]],
        account_id: str,
    ) -> List[TrustRelationship]:
        """
        Parse all role trust policies and extract trust relationships.

        Args:
            roles: List of role dicts (from IAMDiscoveryReader.get_roles())
            account_id: Source AWS account ID

        Returns:
            List of TrustRelationship objects
        """
        relationships = []
        for role in roles:
            doc = role.get("AssumeRolePolicyDocument")
            if not doc:
                continue

            role_arn = role.get("Arn", "")
            role_name = role.get("RoleName", "")
            role_path = role.get("Path", "/")
            is_service_linked = role_path.startswith("/aws-service-role/")

            statements = parse_trust_policy(doc)
            for stmt in statements:
                for principal in stmt.principals:
                    trust = self._classify_principal(
                        principal=principal,
                        role_arn=role_arn,
                        role_name=role_name,
                        effect=stmt.effect,
                        conditions=stmt.conditions,
                        source_account=account_id,
                        is_service_linked=is_service_linked,
                    )
                    relationships.append(trust)

        logger.info(
            f"Analyzed trust policies for {len(roles)} roles: "
            f"{len(relationships)} trust relationships found"
        )
        return relationships

    def _classify_principal(
        self,
        principal: str,
        role_arn: str,
        role_name: str,
        effect: str,
        conditions: Dict,
        source_account: str,
        is_service_linked: bool,
    ) -> TrustRelationship:
        """Classify a single trusted principal."""
        ptype = "unknown"
        target_account = ""
        is_cross_account = False

        if principal == "*":
            ptype = "wildcard"
            is_cross_account = True
        elif principal.endswith(".amazonaws.com"):
            ptype = "service"
        elif ".auth0.com" in principal or "cognito" in principal or "accounts.google.com" in principal:
            ptype = "federated"
        elif ":root" in principal:
            ptype = "account"
            match = ARN_ACCOUNT_RE.match(principal)
            if match:
                target_account = match.group(1)
                is_cross_account = target_account != source_account
        elif ":role/" in principal:
            ptype = "role"
            match = ARN_ACCOUNT_RE.match(principal)
            if match:
                target_account = match.group(1)
                is_cross_account = target_account != source_account
        elif ":user/" in principal:
            ptype = "user"
            match = ARN_ACCOUNT_RE.match(principal)
            if match:
                target_account = match.group(1)
                is_cross_account = target_account != source_account
        elif ":saml-provider/" in principal or ":oidc-provider/" in principal:
            ptype = "federated"

        # Check for ExternalId condition
        has_ext_id = False
        if conditions:
            str_equals = conditions.get("StringEquals", {})
            has_ext_id = "sts:ExternalId" in str_equals

        return TrustRelationship(
            source_role_arn=role_arn,
            source_role_name=role_name,
            trusted_principal=principal,
            principal_type=ptype,
            effect=effect,
            conditions=conditions,
            has_external_id=has_ext_id,
            is_cross_account=is_cross_account,
            source_account=source_account,
            target_account=target_account,
            is_service_linked=is_service_linked,
        )

    def find_cross_account_trusts(
        self, trusts: List[TrustRelationship]
    ) -> List[TrustRelationship]:
        """Filter to cross-account trust relationships."""
        return [t for t in trusts if t.is_cross_account and t.effect == "Allow"]

    def find_risky_trusts(
        self, trusts: List[TrustRelationship]
    ) -> List[TrustRelationship]:
        """
        Find trust relationships that are security risks:
        - Wildcard principals (Principal: *)
        - Cross-account without ExternalId
        """
        risky = []
        for t in trusts:
            if t.effect != "Allow":
                continue
            if t.is_service_linked:
                continue
            if t.principal_type == "wildcard":
                risky.append(t)
            elif t.is_cross_account and not t.has_external_id and t.principal_type in ("account", "role", "user"):
                risky.append(t)
        return risky
