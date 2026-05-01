"""OCI provider for Encryption Security engine."""
from .base import BaseEncryptionProvider


class OCIEncryptionProvider(BaseEncryptionProvider):

    @property
    def key_services(self):
        return ["vault", "kms"]

    @property
    def cert_services(self):
        return ["certificates"]

    @property
    def secrets_services(self):
        return ["vault"]

    @property
    def inventory_resource_prefixes(self):
        return ["vault.", "kms.", "certificates."]
