"""
CheckEvaluator Interface — Multi-CSP Check Evaluation

The check engine is 100% database-driven:
  - Rules    → rule_checks table
  - Data     → discovery_findings table  (pre-scanned by the discovery engine)
  - Results  → check_findings table

No cloud API calls are made during a check scan.  The only CSP-specific
work is parsing/constructing resource identifiers (ARN, resource_id, etc.)
from the emitted_fields JSON that was stored by the discovery engine.

A CheckEvaluator therefore has exactly ONE responsibility:
  extract_resource_identifiers() — parse already-fetched DB data.

Authentication and live API calls belong in the discovery engine, not here.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional


class CheckEvaluator(ABC):
    """
    Abstract base class for CSP-specific check evaluators.

    Implementations:
      providers/aws/evaluator/check_evaluator.py   (complete)
      providers/azure/ gcp/ oci/                   (future work)
    """

    def __init__(self, provider: str = "unknown", **kwargs):
        """
        Args:
            provider: CSP name — aws | azure | gcp | oci
        """
        self.provider = provider
        # Legacy field: kept so existing code that passes credentials={} won't break
        self.credentials: Dict[str, Any] = kwargs.get("credentials") or {}

    @abstractmethod
    def extract_resource_identifiers(
        self,
        item_record: Dict[str, Any],
        emitted_fields: Dict[str, Any],
        service: str,
        discovery_id: str,
        region: str,
        account_id: str,
    ) -> Dict[str, str]:
        """
        Extract or generate resource identifiers from a discovered resource.

        All input data comes from the discovery_findings DB row — no API calls.

        Args:
            item_record:    Top-level row from discovery_findings
                            (resource_arn, resource_id, region, etc.)
            emitted_fields: Parsed emitted_fields dict — the raw resource data
                            captured by the discovery engine
            service:        Service name        (e.g. 'ec2', 'storage')
            discovery_id:   Discovery operation (e.g. 'aws.ec2.describe_instances')
            region:         Region              (e.g. 'us-east-1')
            account_id:   Account / subscription / project ID

        Returns:
            Dict with all four keys (value may be None if unavailable):
            {
                'resource_arn':  str | None  — full ARN / Azure resource ID / GCP self-link
                'resource_uid':  str | None  — preferred unique ID (ARN preferred)
                'resource_id':   str | None  — short ID or name
                'resource_type': str | None  — resource type string
            }
        """
        pass


class CheckEvaluationError(Exception):
    """Raised when check evaluation encounters a fatal error."""
    pass
