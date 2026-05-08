"""Encryption Security provider factory."""
import logging
from .base import BaseEncryptionProvider
logger = logging.getLogger(__name__)


def get_provider(provider_name: str) -> BaseEncryptionProvider:
    name = (provider_name or "aws").lower()
    if name == "aws":
        from .aws import AWSEncryptionProvider; return AWSEncryptionProvider()
    elif name == "azure":
        from .azure import AzureEncryptionProvider; return AzureEncryptionProvider()
    elif name in ("gcp", "google"):
        from .gcp import GCPEncryptionProvider; return GCPEncryptionProvider()
    elif name in ("k8s", "kubernetes"):
        from .k8s import K8sEncryptionProvider; return K8sEncryptionProvider()
    elif name == "oci":
        from .oci import OCIEncryptionProvider; return OCIEncryptionProvider()
    elif name == "ibm":
        from .ibm import IBMEncryptionProvider; return IBMEncryptionProvider()
    elif name == "alicloud":
        from .alicloud import AlicloudEncryptionProvider; return AlicloudEncryptionProvider()
    else:
        logger.warning("Unknown Encryption provider '%s' — falling back to AWS", provider_name)
        from .aws import AWSEncryptionProvider; return AWSEncryptionProvider()
