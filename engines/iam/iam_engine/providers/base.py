"""
IAM Provider Base Class

Abstract base class for CSP-specific IAM analysis providers.
Each provider implements analyze() to return a standardized dict of
policy findings, policy statements, trust relationships, and IAM entities.
"""

import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

_EMPTY_RESULT: Dict[str, List] = {
    "policy_findings": [],
    "policy_statements_rows": [],
    "trust_relationships": [],
    "roles": [],
    "users": [],
    "groups": [],
    "instance_profiles": [],
    "managed_policies": [],
    "inline_policies": [],
}


class BaseIAMProvider(ABC):
    """Abstract base for CSP-specific IAM analysis."""

    @abstractmethod
    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
    ) -> Dict[str, Any]:
        """Run CSP-specific IAM analysis.

        Args:
            scan_run_id: Pipeline scan run ID (same across all engines)
            tenant_id: Tenant identifier
            account_id: Cloud account identifier

        Returns:
            Dict with keys:
              - policy_findings: List[dict]  — detector findings
              - policy_statements_rows: List[dict]  — for iam_policy_statements table
              - trust_relationships: List  — TrustRelationship objects or dicts
              - roles: List[dict]
              - users: List[dict]
              - groups: List[dict]
              - instance_profiles: List[dict]
              - managed_policies: List  — ParsedPolicy objects
              - inline_policies: List  — ParsedPolicy objects
        """


class _StubIAMProvider(BaseIAMProvider):
    """Fallback stub for unknown providers — returns empty results."""

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
    ) -> Dict[str, Any]:
        logger.warning("_StubIAMProvider: unknown provider — returning empty results")
        return dict(_EMPTY_RESULT)


def empty_result() -> Dict[str, Any]:
    """Return a fresh empty result dict (all keys, all empty lists)."""
    return dict(_EMPTY_RESULT)
