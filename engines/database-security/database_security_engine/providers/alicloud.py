"""AliCloud provider stub for Database Security engine."""
import logging
from .base import BaseDBSecurityProvider
logger = logging.getLogger(__name__)


class AlicloudDBSecurityProvider(BaseDBSecurityProvider):
    @property
    def discovery_services(self): return ["rds", "polardb", "mongodb", "tablestore"]
    @property
    def inventory_resource_prefixes(self): return ["rds.", "polardb.", "mongodb."]
