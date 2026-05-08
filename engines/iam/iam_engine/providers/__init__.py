"""
IAM Engine — CSP Provider Factory

Usage:
    from iam_engine.providers import get_provider

    provider = get_provider("aws")
    result = provider.analyze(scan_run_id=..., tenant_id=..., account_id=...)
    policy_findings = result["policy_findings"]
"""

import logging
from typing import Union

from .base import BaseIAMProvider, _StubIAMProvider

logger = logging.getLogger(__name__)


def get_provider(provider_name: str) -> BaseIAMProvider:
    """Return the IAM provider implementation for the given CSP.

    Supported providers: aws, azure, gcp, google, k8s, kubernetes,
    alicloud, oci, ibm.

    Falls back to a stub provider (empty results) for unknown names.

    Args:
        provider_name: CSP identifier string (case-insensitive)

    Returns:
        A concrete BaseIAMProvider instance ready for analyze() calls.
    """
    name = provider_name.lower().strip() if provider_name else ""

    if name == "aws":
        from .aws import AWSIAMProvider
        return AWSIAMProvider()

    if name == "azure":
        from .azure import AzureIAMProvider
        return AzureIAMProvider()

    if name in ("gcp", "google"):
        from .gcp import GCPIAMProvider
        return GCPIAMProvider()

    if name in ("k8s", "kubernetes"):
        from .k8s import K8sIAMProvider
        return K8sIAMProvider()

    if name == "alicloud":
        from .alicloud import AliCloudIAMProvider
        return AliCloudIAMProvider()

    if name == "oci":
        from .oci import OCIIAMProvider
        return OCIIAMProvider()

    if name == "ibm":
        from .ibm import IBMIAMProvider
        return IBMIAMProvider()

    logger.warning(f"Unknown IAM provider '{provider_name}', returning stub (empty results)")
    return _StubIAMProvider()


__all__ = ["get_provider", "BaseIAMProvider"]
