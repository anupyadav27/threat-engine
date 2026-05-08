"""
IBM Cloud IAM Provider — Stub

IBM Cloud IAM analysis is not yet implemented.
Returns empty results with a log message.

Future implementation should cover:
  - Service IDs with overly broad IAM policies
  - API keys without expiration / rotation
  - Users with Administrator platform role at account level
  - IAM conditions not enforced for sensitive operations
"""

import logging
from typing import Any, Dict

from .base import BaseIAMProvider, empty_result

logger = logging.getLogger(__name__)


class IBMIAMProvider(BaseIAMProvider):
    """IBM Cloud IAM analysis provider (stub)."""

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
    ) -> Dict[str, Any]:
        """IBM Cloud IAM provider stub — returns empty results.

        Args:
            scan_run_id: Pipeline scan run ID
            tenant_id: Tenant identifier
            account_id: IBM Cloud account ID

        Returns:
            Empty standardized result dict.
        """
        logger.info(
            f"IBM Cloud IAM provider: IAM analysis not yet implemented "
            f"(scan={scan_run_id}, account={account_id}) — returning stub results"
        )
        return empty_result()
