"""
OCI Check Evaluator

OCI-specific implementation of CheckEvaluator.

Sole responsibility:
  extract_resource_identifiers() — parse OCI OCIDs from the emitted_fields
  JSON already stored by the discovery engine.

No OCI SDK calls are made. The check engine is DB-driven; all resource
data comes from the discovery_findings table.

OCI resource identifier formats:
  OCID:   ocid1.{resource-type}.{realm}.{region}[.{future-use}].{unique-id}
          e.g. ocid1.instance.oc1.ap-mumbai-1.abcdefg...
  Name:   display_name / name field (human-readable, not necessarily unique)
"""

import logging
from typing import Any, Dict, Optional

from common.models.evaluator_interface import CheckEvaluator

logger = logging.getLogger(__name__)


class OCICheckEvaluator(CheckEvaluator):
    """OCI implementation of CheckEvaluator — pure data parsing, no API calls."""

    def __init__(self, provider: str = "oci", **kwargs):
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
        Extract OCI resource identifiers from already-fetched DB data.

        Strategy (in order):
          1. Use top-level resource_uid / resource_arn from discovery_findings row
          2. Search emitted_fields for OCID / display_name fields
          3. Build fallback uid from compartment + service + id
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

        # Step 2: Build fallback — use OCID as both uid and arn
        if not resource_uid and resource_id and resource_id.startswith("ocid1."):
            resource_uid = resource_id

        return {
            "resource_arn":  resource_uid,   # OCI has no ARN; OCID is the canonical ID
            "resource_uid":  resource_uid or resource_id,
            "resource_id":   resource_id,
            "resource_type": resource_type,
        }

    # ── Private helpers ───────────────────────────────────────────────��───────

    @staticmethod
    def _search_emitted_fields(
        emitted_fields: Dict,
        resource_uid: Optional[str],
        resource_id: Optional[str],
    ):
        """Recursively search emitted_fields for OCI OCID / display_name."""

        def _find(data, keys, prefer_ocid: bool = False):
            if isinstance(data, dict):
                for k, v in data.items():
                    if k in keys and isinstance(v, str) and v:
                        if prefer_ocid and v.startswith("ocid1."):
                            return v
                        elif not prefer_ocid:
                            return v
                    if isinstance(v, (dict, list)):
                        r = _find(v, keys, prefer_ocid)
                        if r:
                            return r
            elif isinstance(data, list):
                for item in data:
                    r = _find(item, keys, prefer_ocid)
                    if r:
                        return r
            return None

        ocid_keys = {"id", "ocid", "resource_uid", "identifier"}
        name_keys = {"display_name", "displayName", "name", "resource_id"}

        if not resource_uid:
            # Prefer OCIDs (start with ocid1.)
            resource_uid = _find(emitted_fields, ocid_keys, prefer_ocid=True)
        if not resource_uid:
            resource_uid = _find(emitted_fields, ocid_keys)

        if not resource_id:
            resource_id = _find(emitted_fields, name_keys)

        # If OCID found but no short id, use last dot-segment of OCID
        if not resource_id and resource_uid and resource_uid.startswith("ocid1."):
            resource_id = resource_uid.split(".")[-1][:16]  # last unique segment

        return resource_uid, resource_id
