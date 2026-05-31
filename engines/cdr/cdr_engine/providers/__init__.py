"""CIEM provider factory — returns a CSP-specific provider instance."""

import logging

from .base import BaseCIEMProvider

logger = logging.getLogger(__name__)


def get_provider(provider_name: str) -> BaseCIEMProvider:
    """Return the CIEM provider implementation for the given CSP name.

    All SDK imports are deferred inside each provider class, so this
    module is safe to import regardless of which cloud SDKs are installed.

    Args:
        provider_name: Cloud provider string (e.g. "aws", "azure", "gcp").

    Returns:
        BaseCIEMProvider instance for the requested provider.
    """
    name = provider_name.lower()

    if name == "aws":
        from .aws import AWSCIEMProvider
        return AWSCIEMProvider()

    elif name == "azure":
        from .azure import AzureCIEMProvider
        return AzureCIEMProvider()

    elif name in ("gcp", "google"):
        from .gcp import GCPCIEMProvider
        return GCPCIEMProvider()

    elif name == "oci":
        from .oci import OCICIEMProvider
        return OCICIEMProvider()

    elif name == "ibm":
        from .ibm import IBMCIEMProvider
        return IBMCIEMProvider()

    elif name in ("k8s", "kubernetes"):
        from .k8s import K8sCIEMProvider
        return K8sCIEMProvider()

    elif name == "alicloud":
        from .alicloud import AliCloudCIEMProvider
        return AliCloudCIEMProvider()

    else:
        logger.warning(f"Unknown CIEM provider '{provider_name}', defaulting to AWS")
        from .aws import AWSCIEMProvider
        return AWSCIEMProvider()
