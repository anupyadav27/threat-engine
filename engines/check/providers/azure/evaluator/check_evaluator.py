"""
Azure Check Evaluator

Azure-specific implementation of CheckEvaluator.

Sole responsibility:
  extract_resource_identifiers() — parse Azure resource IDs from the
  emitted_fields JSON already stored by the discovery engine.

No Azure SDK calls are made. The check engine is DB-driven; all resource
data comes from the discovery_findings table.

Azure resource identifier formats:
  Resource ID:  /subscriptions/{sub}/resourceGroups/{rg}/providers/{ns}/{type}/{name}
  Short name:   {name}  (last segment of resource ID)
"""

import logging
from typing import Any, Dict, Optional

from common.models.evaluator_interface import CheckEvaluator

logger = logging.getLogger(__name__)


class AzureCheckEvaluator(CheckEvaluator):
    """Azure implementation of CheckEvaluator — pure data parsing, no API calls."""

    def __init__(self, provider: str = "azure", **kwargs):
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
        Extract Azure resource identifiers from already-fetched DB data.

        Strategy (in order):
          1. Use top-level resource_uid / resource_arn from discovery_findings row
          2. Search emitted_fields for id / name fields
          3. Normalise case — Azure resource IDs are case-insensitive
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

        # Step 2: Normalise Azure resource ID to lowercase for consistency
        if resource_uid and resource_uid.startswith("/subscriptions/"):
            resource_uid = self._normalise_resource_id(resource_uid)

        # Step 3: Derive short name from resource ID
        if not resource_id and resource_uid:
            resource_id = resource_uid.rstrip("/").split("/")[-1]

        return {
            "resource_arn":  resource_uid,   # Azure uses resource ID as canonical uid
            "resource_uid":  resource_uid or resource_id,
            "resource_id":   resource_id,
            "resource_type": resource_type,
        }

    # ── Private helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _search_emitted_fields(
        emitted_fields: Dict,
        resource_uid: Optional[str],
        resource_id: Optional[str],
    ):
        """Recursively search emitted_fields for Azure id / name fields."""

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

        # Azure resource IDs start with /subscriptions/
        uid_keys = {"id", "resource_uid", "resourceId", "resource_id"}
        id_keys = {"name", "resource_id", "id"}

        if not resource_uid:
            candidate = _find(emitted_fields, uid_keys)
            if candidate and candidate.startswith("/subscriptions/"):
                resource_uid = candidate

        if not resource_uid:
            # Try any 'id' that looks like an ARM resource id
            candidate = _find(emitted_fields, {"id"})
            if candidate and "/" in candidate:
                resource_uid = candidate

        if not resource_id:
            resource_id = _find(emitted_fields, {"name"})

        if not resource_id and resource_uid:
            resource_id = resource_uid.rstrip("/").split("/")[-1]

        return resource_uid, resource_id

    @staticmethod
    def _normalise_resource_id(resource_id: str) -> str:
        """
        Normalise Azure resource ID segments to a consistent case.

        /subscriptions/SUB/resourceGroups/RG/providers/NS/Type/name
          → /subscriptions/sub/resourceGroups/rg/providers/ns/type/name

        Preserves the actual resource name (last segment) as-is.
        """
        try:
            parts = resource_id.split("/")
            # Lower-case provider namespace and type segments; preserve names
            lowered = []
            i = 0
            while i < len(parts):
                seg = parts[i]
                if seg.lower() in ("subscriptions", "resourcegroups", "providers"):
                    lowered.append(seg.lower())
                    # Next segment is the value — preserve it
                    i += 1
                    if i < len(parts):
                        lowered.append(parts[i].lower())
                else:
                    lowered.append(seg)
                i += 1
            return "/".join(lowered)
        except Exception:
            return resource_id
