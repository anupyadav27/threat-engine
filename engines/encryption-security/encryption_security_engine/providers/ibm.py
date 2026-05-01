"""IBM provider for Encryption Security engine."""
from .base import BaseEncryptionProvider


class IBMEncryptionProvider(BaseEncryptionProvider):

    @property
    def key_services(self):
        return ["keyprotect", "hpcs"]

    @property
    def cert_services(self):
        return ["certificatemanager"]

    @property
    def secrets_services(self):
        return ["secretsmanager"]

    @property
    def inventory_resource_prefixes(self):
        return ["keyprotect.", "hpcs.", "certificatemanager."]
