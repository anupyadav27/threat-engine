"""Azure provider for Database Security engine."""
from .base import BaseDBSecurityProvider


class AzureDBSecurityProvider(BaseDBSecurityProvider):

    @property
    def discovery_services(self):
        return [
            "sql", "cosmosdb", "cache", "mariadb",
            "mysql", "postgresql", "synapse", "sqldw",
        ]

    @property
    def inventory_resource_prefixes(self):
        return ["sql.", "cosmosdb.", "mysql.", "postgresql.", "mariadb.", "synapse."]
