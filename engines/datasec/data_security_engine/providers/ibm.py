"""IBM provider stub for Data Security engine."""
import logging
from .base import BaseDataSecProvider
logger = logging.getLogger(__name__)


class IBMDataSecProvider(BaseDataSecProvider):
    @property
    def storage_services(self): return ["cloud-object-storage"]
    @property
    def database_services(self): return ["db2", "cloudant", "databases-for-postgresql"]
    @property
    def streaming_services(self): return ["event-streams"]
    @property
    def inventory_resource_prefixes(self): return ["cos.", "db2.", "cloudant."]
