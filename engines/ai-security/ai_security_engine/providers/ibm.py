"""IBM provider stub for AI Security engine."""
import logging
from .base import BaseAISecurityProvider
logger = logging.getLogger(__name__)


class IBMAISecurityProvider(BaseAISecurityProvider):
    @property
    def discovery_services(self):
        return ["watson-studio", "watson-ml", "natural-language-understanding"]

    @property
    def inventory_resource_prefixes(self):
        return ["watson.", "ibm-ml."]
