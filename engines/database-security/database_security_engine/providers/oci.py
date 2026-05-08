"""OCI provider stub for Database Security engine."""
import logging
from .base import BaseDBSecurityProvider
logger = logging.getLogger(__name__)


class OciDBSecurityProvider(BaseDBSecurityProvider):
    @property
    def discovery_services(self): return ["autonomous-database", "mysql", "nosql"]
    @property
    def inventory_resource_prefixes(self): return ["autonomous-database.", "mysql."]
