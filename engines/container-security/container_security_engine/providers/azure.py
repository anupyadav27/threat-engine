"""Azure provider for Container Security engine."""
from .base import BaseContainerSecurityProvider


class AzureContainerSecurityProvider(BaseContainerSecurityProvider):

    @property
    def discovery_services(self):
        return ["aks", "containerregistry", "containerinstances", "containerservice"]

    @property
    def inventory_resource_prefixes(self):
        return ["aks.", "containerregistry.", "containerinstances."]
