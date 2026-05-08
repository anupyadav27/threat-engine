"""Database Security provider factory."""
import logging
from .base import BaseDBSecurityProvider
logger = logging.getLogger(__name__)


def get_provider(provider_name: str) -> BaseDBSecurityProvider:
    name = (provider_name or "aws").lower()
    if name == "aws":
        from .aws import AWSDBSecurityProvider; return AWSDBSecurityProvider()
    elif name == "azure":
        from .azure import AzureDBSecurityProvider; return AzureDBSecurityProvider()
    elif name in ("gcp", "google"):
        from .gcp import GCPDBSecurityProvider; return GCPDBSecurityProvider()
    elif name in ("k8s", "kubernetes"):
        from .k8s import K8sDBSecurityProvider; return K8sDBSecurityProvider()
    elif name == "alicloud":
        from .alicloud import AlicloudDBSecurityProvider; return AlicloudDBSecurityProvider()
    elif name == "oci":
        from .oci import OciDBSecurityProvider; return OciDBSecurityProvider()
    elif name == "ibm":
        from .ibm import IbmDBSecurityProvider; return IbmDBSecurityProvider()
    else:
        logger.warning("Unknown Database Security provider '%s' — falling back to AWS", provider_name)
        from .aws import AWSDBSecurityProvider; return AWSDBSecurityProvider()
