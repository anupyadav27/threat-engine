"""GCP provider for Container Security engine."""
from .base import BaseContainerSecurityProvider


class GCPContainerSecurityProvider(BaseContainerSecurityProvider):

    @property
    def discovery_services(self):
        return ["gke", "artifactregistry", "run", "cloudrun"]

    @property
    def inventory_resource_prefixes(self):
        return ["gke.", "artifactregistry.", "run."]
