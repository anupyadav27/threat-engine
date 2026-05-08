"""Container Security provider factory."""
import logging
from .base import BaseContainerSecurityProvider
logger = logging.getLogger(__name__)


def get_provider(provider_name: str) -> BaseContainerSecurityProvider:
    name = (provider_name or "aws").lower()
    if name == "aws":
        from .aws import AWSContainerSecurityProvider; return AWSContainerSecurityProvider()
    elif name == "azure":
        from .azure import AzureContainerSecurityProvider; return AzureContainerSecurityProvider()
    elif name in ("gcp", "google"):
        from .gcp import GCPContainerSecurityProvider; return GCPContainerSecurityProvider()
    elif name in ("k8s", "kubernetes"):
        from .k8s import K8sContainerSecurityProvider; return K8sContainerSecurityProvider()
    elif name == "alicloud":
        from .alicloud import AlicloudContainerSecurityProvider; return AlicloudContainerSecurityProvider()
    elif name == "oci":
        from .oci import OciContainerSecurityProvider; return OciContainerSecurityProvider()
    elif name == "ibm":
        from .ibm import IbmContainerSecurityProvider; return IbmContainerSecurityProvider()
    else:
        logger.warning("Unknown Container Security provider '%s' — falling back to AWS", provider_name)
        from .aws import AWSContainerSecurityProvider; return AWSContainerSecurityProvider()
