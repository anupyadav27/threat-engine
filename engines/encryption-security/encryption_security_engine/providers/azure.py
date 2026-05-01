"""Azure provider for Encryption Security engine."""
from .base import BaseEncryptionProvider


class AzureEncryptionProvider(BaseEncryptionProvider):

    @property
    def key_services(self):
        return ["keyvault"]

    @property
    def cert_services(self):
        return ["keyvault"]

    @property
    def secrets_services(self):
        return ["keyvault"]

    @property
    def inventory_resource_prefixes(self):
        return ["keyvault.", "managedidentity.", "disk-encryption."]
