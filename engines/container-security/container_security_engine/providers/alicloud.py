"""AliCloud provider stub for Container Security engine."""
import logging
from .base import BaseContainerSecurityProvider
logger = logging.getLogger(__name__)


class AlicloudContainerSecurityProvider(BaseContainerSecurityProvider):
    @property
    def discovery_services(self): return ["cs", "acr"]
    @property
    def inventory_resource_prefixes(self): return ["cs.", "acr."]
    def is_supported(self): return True
