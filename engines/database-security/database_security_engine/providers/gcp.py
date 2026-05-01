"""GCP provider for Database Security engine."""
from .base import BaseDBSecurityProvider


class GCPDBSecurityProvider(BaseDBSecurityProvider):

    @property
    def discovery_services(self):
        return [
            "cloudsql", "firestore", "bigtable", "spanner",
            "memorystore", "bigquery", "datastore",
        ]

    @property
    def inventory_resource_prefixes(self):
        return ["cloudsql.", "firestore.", "bigtable.", "spanner.", "bigquery."]
