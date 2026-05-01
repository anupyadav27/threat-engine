"""GCP provider for Encryption Security engine."""
from .base import BaseEncryptionProvider


class GCPEncryptionProvider(BaseEncryptionProvider):

    @property
    def key_services(self):
        return ["cloudkms"]

    @property
    def cert_services(self):
        return ["certificatemanager"]

    @property
    def secrets_services(self):
        return ["secretmanager"]

    @property
    def inventory_resource_prefixes(self):
        return ["cloudkms.", "secretmanager.", "certificatemanager."]
