"""AWS provider for Container Security engine."""
from .base import BaseContainerSecurityProvider


class AWSContainerSecurityProvider(BaseContainerSecurityProvider):

    @property
    def discovery_services(self):
        return ["eks", "ecs", "ecr", "fargate", "batch", "lambda"]

    @property
    def inventory_resource_prefixes(self):
        return ["eks.", "ecs.", "ecr.", "fargate.", "lambda."]
