"""AI Security provider factory."""
import logging
from .base import BaseAISecurityProvider
logger = logging.getLogger(__name__)


def get_provider(provider_name: str) -> BaseAISecurityProvider:
    name = (provider_name or "aws").lower()
    if name == "aws":
        from .aws import AWSAISecurityProvider; return AWSAISecurityProvider()
    elif name == "azure":
        from .azure import AzureAISecurityProvider; return AzureAISecurityProvider()
    elif name in ("gcp", "google"):
        from .gcp import GCPAISecurityProvider; return GCPAISecurityProvider()
    elif name in ("k8s", "kubernetes"):
        from .k8s import K8sAISecurityProvider; return K8sAISecurityProvider()
    elif name == "alicloud":
        from .alicloud import AliCloudAISecurityProvider; return AliCloudAISecurityProvider()
    elif name == "oci":
        from .oci import OCIAISecurityProvider; return OCIAISecurityProvider()
    elif name == "ibm":
        from .ibm import IBMAISecurityProvider; return IBMAISecurityProvider()
    else:
        logger.warning("Unknown AI Security provider '%s' — falling back to AWS", provider_name)
        from .aws import AWSAISecurityProvider; return AWSAISecurityProvider()
