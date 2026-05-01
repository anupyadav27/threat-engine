"""Kubernetes provider for Database Security engine."""
from .base import BaseDBSecurityProvider


class K8sDBSecurityProvider(BaseDBSecurityProvider):

    @property
    def discovery_services(self):
        return ["statefulsets", "persistentvolumes", "persistentvolumeclaims"]

    @property
    def inventory_resource_prefixes(self):
        return ["statefulset.", "persistentvolume."]
