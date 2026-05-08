"""Provider factory for DBSec engine."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dbsec_engine.providers.base import BaseDBSecProvider


def get_provider(csp: str) -> "BaseDBSecProvider":
    """Return the DBSec provider for the given CSP.

    Args:
        csp: Lowercase CSP name (aws|azure|gcp|oci|alicloud|k8s).

    Returns:
        Concrete provider instance.
    """
    csp = (csp or "aws").lower()
    if csp == "aws":
        from dbsec_engine.providers.aws import AWSDBSecProvider
        return AWSDBSecProvider()
    if csp == "azure":
        from dbsec_engine.providers.azure import AzureDBSecProvider
        return AzureDBSecProvider()
    if csp == "gcp":
        from dbsec_engine.providers.gcp import GCPDBSecProvider
        return GCPDBSecProvider()
    if csp == "oci":
        from dbsec_engine.providers.oci import OCIDBSecProvider
        return OCIDBSecProvider()
    if csp == "alicloud":
        from dbsec_engine.providers.alicloud import AliCloudDBSecProvider
        return AliCloudDBSecProvider()
    if csp == "k8s":
        from dbsec_engine.providers.k8s import K8sDBSecProvider
        return K8sDBSecProvider()
    # Default: return a no-op provider
    from dbsec_engine.providers.base import NoOpDBSecProvider
    return NoOpDBSecProvider(csp)
