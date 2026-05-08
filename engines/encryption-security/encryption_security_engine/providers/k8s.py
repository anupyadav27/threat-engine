"""Kubernetes provider for Encryption Security engine."""
from .base import BaseEncryptionProvider


class K8sEncryptionProvider(BaseEncryptionProvider):

    @property
    def key_services(self):
        return ["secrets"]

    @property
    def cert_services(self):
        return ["certificates", "certificaterequests"]

    @property
    def secrets_services(self):
        return ["secrets", "vault"]

    @property
    def inventory_resource_prefixes(self):
        return ["secret.", "certificate."]
