"""AWS provider for Database Security engine."""
from .base import BaseDBSecurityProvider


class AWSDBSecurityProvider(BaseDBSecurityProvider):

    @property
    def discovery_services(self):
        return [
            "rds", "dynamodb", "redshift", "elasticache",
            "neptune", "documentdb", "opensearch", "timestream",
            "keyspaces", "dax", "aurora",
        ]

    @property
    def inventory_resource_prefixes(self):
        return ["rds.", "dynamodb.", "elasticache.", "redshift.", "neptune.", "documentdb."]
