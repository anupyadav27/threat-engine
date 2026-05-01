"""OCI provider stub for Container Security engine."""
import logging
from .base import BaseContainerSecurityProvider
logger = logging.getLogger(__name__)


class OciContainerSecurityProvider(BaseContainerSecurityProvider):
    @property
    def discovery_services(self): return ["oke", "artifacts"]
    @property
    def inventory_resource_prefixes(self): return ["oke.", "artifacts."]
    def is_supported(self): return True
