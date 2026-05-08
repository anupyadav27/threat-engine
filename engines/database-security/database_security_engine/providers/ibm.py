"""IBM provider stub for Database Security engine."""
import logging
from .base import BaseDBSecurityProvider
logger = logging.getLogger(__name__)


class IbmDBSecurityProvider(BaseDBSecurityProvider):
    @property
    def discovery_services(self): return ["db2", "cloudant", "databases-for-postgresql", "databases-for-mongodb"]
    @property
    def inventory_resource_prefixes(self): return ["db2.", "cloudant.", "databases-for-postgresql."]
