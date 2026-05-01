"""IBM provider stub for Container Security engine."""
import logging
from .base import BaseContainerSecurityProvider
logger = logging.getLogger(__name__)


class IbmContainerSecurityProvider(BaseContainerSecurityProvider):
    @property
    def discovery_services(self): return ["kubernetes-service", "container-registry"]
    @property
    def inventory_resource_prefixes(self): return ["kubernetes-service.", "container-registry."]
    def is_supported(self): return True
