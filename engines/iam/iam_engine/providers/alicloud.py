"""
AliCloud IAM Provider — Stub

AliCloud RAM (Resource Access Management) analysis is not yet implemented.
Returns empty results with a log message.

Future implementation should cover:
  - RAM users with overly broad policies
  - AccessKeys without rotation
  - RAM roles with cross-account trust without MFA/ExternalId equivalent
  - Policies allowing sensitive actions (oss:*, ecs:*, rds:*) on all resources
"""

import logging
from typing import Any, Dict

from .base import BaseIAMProvider, empty_result

logger = logging.getLogger(__name__)


class AliCloudIAMProvider(BaseIAMProvider):
    """AliCloud RAM analysis provider (stub)."""

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
    ) -> Dict[str, Any]:
        """AliCloud IAM provider stub — returns empty results.

        Args:
            scan_run_id: Pipeline scan run ID
            tenant_id: Tenant identifier
            account_id: AliCloud account ID

        Returns:
            Empty standardized result dict.
        """
        logger.info(
            f"AliCloud IAM provider: RAM analysis not yet implemented "
            f"(scan={scan_run_id}, account={account_id}) — returning stub results"
        )
        return empty_result()
