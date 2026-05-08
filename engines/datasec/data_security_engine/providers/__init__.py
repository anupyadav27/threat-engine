"""Data Security provider factory."""
import logging
from .base import BaseDataSecProvider
logger = logging.getLogger(__name__)


def get_provider(provider_name: str) -> BaseDataSecProvider:
    name = (provider_name or "aws").lower()
    if name == "aws":
        from .aws import AWSDataSecProvider; return AWSDataSecProvider()
    elif name == "azure":
        from .azure import AzureDataSecProvider; return AzureDataSecProvider()
    elif name in ("gcp", "google"):
        from .gcp import GCPDataSecProvider; return GCPDataSecProvider()
    elif name in ("k8s", "kubernetes"):
        from .k8s import K8sDataSecProvider; return K8sDataSecProvider()
    elif name == "alicloud":
        from .alicloud import AliCloudDataSecProvider; return AliCloudDataSecProvider()
    elif name == "oci":
        from .oci import OCIDataSecProvider; return OCIDataSecProvider()
    elif name == "ibm":
        from .ibm import IBMDataSecProvider; return IBMDataSecProvider()
    else:
        logger.warning("Unknown Data Security provider '%s' — falling back to AWS", provider_name)
        from .aws import AWSDataSecProvider; return AWSDataSecProvider()
