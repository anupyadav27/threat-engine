"""
IBM Cloud Check Evaluator

IBM-specific implementation of CheckEvaluator.

Sole responsibility:
  extract_resource_identifiers() — parse IBM CRNs from the emitted_fields
  JSON already stored by the discovery engine.

No IBM SDK calls are made. The check engine is DB-driven; all resource
data comes from the discovery_findings table.

IBM resource identifier formats:
  CRN:  crn:v1:{cname}:{ctype}:{service-name}:{location}:a/{account-id}:{resource-id}:{resource-type}:{resource}
        e.g. crn:v1:bluemix:public:cloud-object-storage:global:a/abc123:my-instance::
  Name: name / resource_name field
"""

import logging
from typing import Any, Dict, Optional

from common.models.evaluator_interface import CheckEvaluator

logger = logging.getLogger(__name__)


class IBMCheckEvaluator(CheckEvaluator):
    """IBM Cloud implementation of CheckEvaluator — pure data parsing, no API calls."""

    def __init__(self, provider: str = "ibm", **kwargs):
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
        Extract IBM resource identifiers from already-fetched DB data.

        Strategy (in order):
          1. Use top-level resource_uid / resource_arn from discovery_findings row
          2. Search emitted_fields for CRN / name fields
          3. Build fallback uid from account + service + id
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
                emitted_fields, resource_uid, resource_id
            )

        # Step 2: Parse short id from CRN
        if not resource_id and resource_uid and resource_uid.startswith("crn:"):
            resource_id = self._crn_resource_id(resource_uid)

        # Step 3: Build minimal CRN if we have enough parts
        if not resource_uid and resource_id and account_id and service:
            location = region or "global"
            resource_uid = f"crn:v1:bluemix:public:{service}:{location}:a/{account_id}:{resource_id}::"

        return {
            "resource_arn":  resource_uid,   # IBM uses CRN as canonical ID
            "resource_uid":  resource_uid or resource_id,
            "resource_id":   resource_id,
            "resource_type": resource_type,
        }

    # ── Private helpers ──────────────��────────────────────────────────────────

    @staticmethod
    def _search_emitted_fields(
        emitted_fields: Dict,
        resource_uid: Optional[str],
        resource_id: Optional[str],
    ):
        """Recursively search emitted_fields for IBM CRN / name / id."""

        def _find(data, keys, prefer_crn: bool = False):
            if isinstance(data, dict):
                for k, v in data.items():
                    if k in keys and isinstance(v, str) and v:
                        if prefer_crn and v.startswith("crn:"):
                            return v
                        elif not prefer_crn:
                            return v
                    if isinstance(v, (dict, list)):
                        r = _find(v, keys, prefer_crn)
                        if r:
                            return r
            elif isinstance(data, list):
                for item in data:
                    r = _find(item, keys, prefer_crn)
                    if r:
                        return r
            return None

        crn_keys = {"crn", "resource_uid", "id"}
        name_keys = {"name", "resource_name", "resourceName", "resource_id", "id"}

        if not resource_uid:
            resource_uid = _find(emitted_fields, crn_keys, prefer_crn=True)
        if not resource_uid:
            resource_uid = _find(emitted_fields, {"crn"})

        if not resource_id:
            resource_id = _find(emitted_fields, name_keys)

        return resource_uid, resource_id

    @staticmethod
    def _crn_resource_id(crn: str) -> Optional[str]:
        """
        Extract the resource instance ID from a CRN.

        crn:v1:bluemix:public:service:region:a/account:RESOURCE-ID:type:resource
                                                         ^^^^^^^^^^ segment 7
        """
        try:
            parts = crn.split(":")
            # segment index 7 is the resource-id (after account a/xxx)
            if len(parts) >= 8 and parts[7]:
                return parts[7]
            # fallback: last non-empty segment
            for seg in reversed(parts):
                if seg and not seg.startswith("a/"):
                    return seg
        except Exception:
            pass
        return None
