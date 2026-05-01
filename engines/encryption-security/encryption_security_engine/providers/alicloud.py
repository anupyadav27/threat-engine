"""AliCloud provider stub for Encryption Security engine."""
import logging
from .base import BaseEncryptionProvider
logger = logging.getLogger(__name__)


class AlicloudEncryptionProvider(BaseEncryptionProvider):
    @property
    def key_services(self): return ["kms"]
    @property
    def cert_services(self): return ["cas"]
    @property
    def secrets_services(self): return ["kms"]
    @property
    def inventory_resource_prefixes(self): return ["kms.", "cas."]
