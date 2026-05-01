"""AWS provider for Encryption Security engine."""
from .base import BaseEncryptionProvider


class AWSEncryptionProvider(BaseEncryptionProvider):

    @property
    def key_services(self):
        return ["kms", "cloudhsm"]

    @property
    def cert_services(self):
        return ["acm", "acm-pca"]

    @property
    def secrets_services(self):
        return ["secretsmanager", "ssm"]

    @property
    def inventory_resource_prefixes(self):
        return ["kms.", "acm.", "secretsmanager.", "ssm.", "cloudhsm."]
