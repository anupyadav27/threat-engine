"""
Cross-Service Discovery Map — identifies discoveries that return resources
from a different AWS service than the directory they live under.

Used as a runtime fallback when rule_metadata does not have an explicit
``resource_service`` field.  Extend the dict as new cross-service
discoveries are added.

Example:
    ``aws.ec2.describe_iam_instance_profile_associations`` lives under
    the ``ec2`` service directory but returns IAM instance-profile
    association resources → resource_service = ``iam``.
"""

from typing import Optional

# discovery_id → actual resource service
CROSS_SERVICE_DISCOVERY_MAP: dict[str, str] = {
    # EC2 discoveries that return IAM resources
    "aws.ec2.describe_iam_instance_profile_associations": "iam",
}


def get_resource_service(
    discovery_id: str,
    directory_service: str,
) -> str:
    """Return the actual resource service for a discovery_id.

    Falls back to *directory_service* when no cross-service mapping exists.

    Args:
        discovery_id: The ``for_each`` value from the rule YAML.
        directory_service: The service directory the rule lives under.

    Returns:
        The AWS service the discovered resource actually belongs to.
    """
    return CROSS_SERVICE_DISCOVERY_MAP.get(discovery_id, directory_service)
