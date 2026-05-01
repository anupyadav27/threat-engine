"""Kubernetes (native) provider for Container Security engine."""
from .base import BaseContainerSecurityProvider


class K8sContainerSecurityProvider(BaseContainerSecurityProvider):

    @property
    def discovery_services(self):
        return [
            "pods", "deployments", "daemonsets", "statefulsets",
            "replicasets", "jobs", "cronjobs", "namespaces",
            "serviceaccounts", "roles", "rolebindings",
            "clusterroles", "clusterrolebindings",
            "networkpolicies", "podsecuritypolicies",
            "services", "ingresses",
        ]

    @property
    def inventory_resource_prefixes(self):
        return ["pod.", "deployment.", "daemonset.", "statefulset.", "namespace.", "serviceaccount."]
