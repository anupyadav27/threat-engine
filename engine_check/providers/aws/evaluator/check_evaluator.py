"""
AWS Check Evaluator

AWS-specific implementation of CheckEvaluator.

Sole responsibility:
  extract_resource_identifiers() — parse/construct ARN and resource_id
  from the emitted_fields JSON that was stored by the discovery engine.

No boto3 / AWS API calls are made here.  The check engine is DB-driven;
all resource data comes from the discovery_findings table.
"""

import logging
from typing import Any, Dict, Optional

from common.models.evaluator_interface import CheckEvaluator

logger = logging.getLogger(__name__)


class AWSCheckEvaluator(CheckEvaluator):
    """AWS implementation of CheckEvaluator — pure data parsing, no API calls."""

    def __init__(self, provider: str = "aws", **kwargs):
        super().__init__(provider=provider, **kwargs)

    # ── Resource identifier extraction ────────────────────────────────────────

    def extract_resource_identifiers(
        self,
        item_record: Dict[str, Any],
        emitted_fields: Dict[str, Any],
        service: str,
        discovery_id: str,
        region: str,
        hierarchy_id: str,
    ) -> Dict[str, str]:
        """
        Extract or generate AWS resource identifiers from already-fetched DB data.

        Strategy (in order):
          1. Use top-level resource_arn / resource_id from discovery_findings row
          2. Recursively search emitted_fields for ARN / ID key patterns
          3. Use discovery_resource_mapper for service_list.json ARN templates
          4. For account-level configs, generate account-scoped ARN
        """
        resource_arn: Optional[str] = item_record.get("resource_arn")
        resource_id: Optional[str] = item_record.get("resource_id")
        resource_type: Optional[str] = item_record.get("service") or service

        if not service:
            service = item_record.get("service", "")
        if not region:
            region = item_record.get("region", "")
        if not hierarchy_id:
            hierarchy_id = (
                item_record.get("hierarchy_id")
                or item_record.get("account_id")
                or ""
            )

        # Step 1: Recursive search inside emitted_fields
        if not resource_arn or not resource_id:
            resource_arn, resource_id = self._search_emitted_fields(
                emitted_fields, resource_arn, resource_id
            )

        # Step 2: discovery_resource_mapper (service_list.json driven)
        if not resource_arn and discovery_id and service and hierarchy_id:
            resource_arn, resource_id, resource_type = self._apply_discovery_mapping(
                emitted_fields, discovery_id, service, region, hierarchy_id,
                resource_arn, resource_id, resource_type,
            )

        # Step 3: Account-level ARN for account-scope configurations
        if not resource_arn and discovery_id and hierarchy_id:
            resource_arn = self._build_account_arn(
                discovery_id, service, region, hierarchy_id, resource_id
            )

        return {
            "resource_arn":  resource_arn,
            "resource_uid":  resource_arn or resource_id,
            "resource_id":   resource_id,
            "resource_type": resource_type,
        }

    # ── Private helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _search_emitted_fields(
        emitted_fields: Dict,
        resource_arn: Optional[str],
        resource_id: Optional[str],
    ):
        """Recursively search emitted_fields for ARN / ID values."""

        def _find(data, patterns, is_arn: bool = False):
            if isinstance(data, dict):
                for k, v in data.items():
                    kl = k.lower()
                    if any(p.lower() in kl for p in patterns):
                        if isinstance(v, str):
                            if is_arn and v.startswith("arn:aws:"):
                                return v
                            elif not is_arn and v and not v.startswith("arn:"):
                                return v
                    if isinstance(v, (dict, list)):
                        r = _find(v, patterns, is_arn)
                        if r:
                            return r
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, (dict, list)):
                        r = _find(item, patterns, is_arn)
                        if r:
                            return r
            return None

        arn_keys = [
            "Arn", "ARN", "arn", "ResourceArn", "resource_arn",
            "ResourceARN", "MasterAccountArn", "AccountArn", "SubscriptionArn",
        ]
        id_keys = [
            "Id", "ID", "id", "ResourceId", "resource_id", "ResourceID",
            "Name", "name", "ResourceName", "MasterAccountId", "AccountId",
        ]

        if not resource_arn:
            resource_arn = _find(emitted_fields, arn_keys, is_arn=True)
        if not resource_id:
            resource_id = _find(emitted_fields, id_keys, is_arn=False)
        if not resource_id and resource_arn:
            try:
                resource_id = (
                    resource_arn.split("/")[-1]
                    if "/" in resource_arn
                    else resource_arn.split(":")[-1]
                )
            except Exception:
                pass

        return resource_arn, resource_id

    @staticmethod
    def _apply_discovery_mapping(
        emitted_fields, discovery_id, service, region, hierarchy_id,
        resource_arn, resource_id, resource_type,
    ):
        """Use service_list.json-driven mapper for ARN extraction and generation."""
        try:
            from utils.discovery_resource_mapper import (
                get_discovery_mapping,
                extract_resource_id_from_emitted,
                extract_resource_arn_from_emitted,
            )
            from utils.reporting_manager import generate_arn
            from utils.discovery_resource_mapper import load_service_config

            r_type, arn_pats, id_pats = get_discovery_mapping(discovery_id, emitted_fields)
            if r_type:
                resource_type = r_type

            if not resource_arn and arn_pats:
                resource_arn = extract_resource_arn_from_emitted(emitted_fields, arn_pats)
            if not resource_id and id_pats:
                resource_id = extract_resource_id_from_emitted(emitted_fields, id_pats)

            # ARN generation from pattern
            if not resource_arn and resource_id and resource_type:
                svc_cfg = load_service_config(service) or {}
                scope = svc_cfg.get("scope", "regional")
                arn_region = (
                    region
                    if (scope == "regional" and region and region not in ("global", "None", ""))
                    else ""
                )
                if not arn_region and scope == "regional":
                    arn_region = "us-east-1"
                resource_arn = generate_arn(
                    service=service,
                    region=arn_region,
                    account_id=hierarchy_id,
                    resource_id=str(resource_id),
                    resource_type=resource_type,
                )
                logger.debug(
                    "[ARN-GEN] %s/%s → %s", service, resource_id,
                    resource_arn[:80] if resource_arn else None,
                )

        except Exception as exc:
            logger.debug("[ARN-GEN] mapper error for %s: %s", discovery_id, exc)

        return resource_arn, resource_id, resource_type

    @staticmethod
    def _build_account_arn(
        discovery_id: str, service: str, region: str, hierarchy_id: str,
        resource_id: Optional[str],
    ) -> Optional[str]:
        """Generate account-level ARN for account-scope configurations."""
        try:
            from utils.discovery_resource_mapper import is_account_level_configuration
            if not is_account_level_configuration(discovery_id):
                return None

            op = discovery_id.split(".")[-1] if "." in discovery_id else ""
            if "encryption" in op:
                cfg = "encryption-settings"
            elif "block_public_access" in op:
                cfg = "block-public-access"
            elif "policies" in op:
                cfg = "resource-policy"
            elif "settings" in op:
                cfg = "settings"
            elif "status" in op:
                cfg = "status"
            else:
                cfg = "configuration"

            cid = resource_id or "default"
            arn = f"arn:aws:{service}:{region or ''}:{hierarchy_id}:{cfg}/{cid}"
            logger.debug("[ARN-ACCOUNT] %s", arn)
            return arn

        except Exception as exc:
            logger.debug("[ARN-ACCOUNT] error for %s: %s", discovery_id, exc)
            return None
