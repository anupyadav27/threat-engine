"""
Alibaba Cloud Check Evaluator

AliCloud-specific implementation of CheckEvaluator.

Sole responsibility:
  extract_resource_identifiers() — parse Alibaba Cloud resource identifiers
  from the emitted_fields JSON already stored by the discovery engine.

No Alibaba SDK calls are made. The check engine is DB-driven; all resource
data comes from the discovery_findings table.

Alibaba Cloud resource identifier formats:
  ARN:  acs:{service}:{region}:{account-id}:{resource-type}/{resource-id}
        e.g. acs:ecs:cn-hangzhou:123456789:instance/i-abc123
  ID:   Service-specific ID field (InstanceId, BucketName, FunctionName, etc.)
"""

import logging
from typing import Any, Dict, Optional

from common.models.evaluator_interface import CheckEvaluator

logger = logging.getLogger(__name__)


class AliCloudCheckEvaluator(CheckEvaluator):
    """Alibaba Cloud implementation of CheckEvaluator — pure data parsing, no API calls."""

    def __init__(self, provider: str = "alicloud", **kwargs):
        super().__init__(provider=provider, **kwargs)

    def extract_resource_identifiers(
        self,
        item_record: Dict[str, Any],
        emitted_fields: Dict[str, Any],
        service: str,
        discovery_id: str,
        region: str,
        account_id: str,
    ) -> Dict[str, str]:
        """
        Extract AliCloud resource identifiers from already-fetched DB data.

        Strategy (in order):
          1. Use top-level resource_uid / resource_arn from discovery_findings row
          2. Search emitted_fields for ARN / service-specific ID fields
          3. Build AliCloud ARN from parts when possible
        """
        resource_uid: Optional[str] = item_record.get("resource_uid") or item_record.get("resource_arn")
        resource_id: Optional[str] = item_record.get("resource_id")
        resource_type: Optional[str] = item_record.get("service") or service

        if not service:
            service = item_record.get("service", "")
        if not region:
            region = item_record.get("region", "")
        if not account_id:
            account_id = item_record.get("account_id", "")

        # Step 1: Search emitted_fields
        if not resource_uid or not resource_id:
            resource_uid, resource_id = self._search_emitted_fields(
                emitted_fields, resource_uid, resource_id, service
            )

        # Step 2: Build ARN if we have parts
        if not resource_uid and resource_id and service and account_id:
            resource_uid = self._build_arn(service, region, account_id, resource_type, resource_id)

        return {
            "resource_arn":  resource_uid,
            "resource_uid":  resource_uid or resource_id,
            "resource_id":   resource_id,
            "resource_type": resource_type,
        }

    # ── Private helpers ───────────────────────────────────────────────────────

    # Map of service → primary ID field names (from Alibaba Cloud API responses)
    _SERVICE_ID_FIELDS = {
        "ecs":     ["InstanceId", "instance_id"],
        "rds":     ["DBInstanceId", "db_instance_id"],
        "oss":     ["BucketName", "bucket_name", "Name"],
        "ram":     ["UserId", "user_id", "RoleId", "role_id", "PolicyName"],
        "slb":     ["LoadBalancerId", "load_balancer_id"],
        "vpc":     ["VpcId", "vpc_id", "VSwitchId", "RouteTableId"],
        "sg":      ["SecurityGroupId", "security_group_id"],
        "kms":     ["KeyId", "key_id", "AliasName"],
        "sls":     ["ProjectName", "LogstoreName"],
        "fc":      ["FunctionName", "function_name", "ServiceName"],
        "nas":     ["FileSystemId", "file_system_id"],
        "redis":   ["InstanceId", "instance_id"],
        "mongodb": ["DBInstanceId", "db_instance_id"],
        "cs":      ["ClusterId", "cluster_id"],        # Container Service
        "cr":      ["RepoId", "repo_id"],              # Container Registry
    }

    @classmethod
    def _search_emitted_fields(
        cls,
        emitted_fields: Dict,
        resource_uid: Optional[str],
        resource_id: Optional[str],
        service: str,
    ):
        """Recursively search emitted_fields for AliCloud ARN / service ID."""

        def _find(data, keys):
            if isinstance(data, dict):
                for k, v in data.items():
                    if k in keys and isinstance(v, str) and v:
                        return v
                    if isinstance(v, (dict, list)):
                        r = _find(v, keys)
                        if r:
                            return r
            elif isinstance(data, list):
                for item in data:
                    r = _find(item, keys)
                    if r:
                        return r
            return None

        arn_keys = {"arn", "Arn", "resource_uid", "ResourceArn"}
        generic_id_keys = {"Id", "id", "Name", "name", "resource_id"}

        if not resource_uid:
            candidate = _find(emitted_fields, arn_keys)
            if candidate and candidate.startswith("acs:"):
                resource_uid = candidate

        if not resource_id:
            # Try service-specific ID fields first
            svc_fields = set(cls._SERVICE_ID_FIELDS.get(service.lower(), []))
            if svc_fields:
                resource_id = _find(emitted_fields, svc_fields)
            if not resource_id:
                resource_id = _find(emitted_fields, generic_id_keys)

        if not resource_uid and resource_id:
            # Use the resource_id as uid if no ARN found
            resource_uid = resource_id

        return resource_uid, resource_id

    @staticmethod
    def _build_arn(service: str, region: str, account_id: str, resource_type: str, resource_id: str) -> str:
        """Build an Alibaba Cloud ARN from parts."""
        r_type = (resource_type or service).lower()
        r_region = region or "*"
        return f"acs:{service}:{r_region}:{account_id}:{r_type}/{resource_id}"
