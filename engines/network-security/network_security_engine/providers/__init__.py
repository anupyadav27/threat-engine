"""
Network-security provider factory.

Usage::

    from network_security_engine.providers import get_provider
    provider = get_provider("aws")
    result = provider.analyze(scan_run_id=..., tenant_id=..., ...)

Each provider implements :class:`~.base.BaseNetworkProvider` and returns a
normalized result dict that :func:`run_scan.run_network_scan` persists without
knowing which cloud is being analysed.
"""

from __future__ import annotations

import logging

from .base import BaseNetworkProvider

logger = logging.getLogger(__name__)

__all__ = ["get_provider", "BaseNetworkProvider"]


def get_provider(provider_name: str) -> BaseNetworkProvider:
    """Return the CSP-specific network provider for *provider_name*.

    Unknown provider names fall back to the AliCloud stub (returns 0 findings).
    """
    name = (provider_name or "").lower().strip()

    if name == "aws":
        from .aws import AWSNetworkProvider
        return AWSNetworkProvider()

    if name == "azure":
        from .azure import AzureNetworkProvider
        return AzureNetworkProvider()

    if name in ("gcp", "google", "googlecloud"):
        from .gcp import GCPNetworkProvider
        return GCPNetworkProvider()

    if name in ("k8s", "kubernetes"):
        from .k8s import K8sNetworkProvider
        return K8sNetworkProvider()

    if name == "alicloud":
        from .alicloud import AliCloudNetworkProvider
        return AliCloudNetworkProvider()

    if name == "oci":
        from .oci import OCINetworkProvider
        return OCINetworkProvider()

    if name == "ibm":
        from .ibm import IBMNetworkProvider
        return IBMNetworkProvider()

    logger.warning(
        "Unknown network provider '%s' — returning stub (0 findings)", provider_name
    )
    from .alicloud import AliCloudNetworkProvider
    return AliCloudNetworkProvider()
