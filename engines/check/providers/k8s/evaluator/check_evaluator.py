"""
Kubernetes Check Evaluator

Kubernetes-specific implementation of CheckEvaluator.

Sole responsibility:
  extract_resource_identifiers() — parse K8s resource identifiers from the
  emitted_fields JSON already stored by the discovery engine.

No K8s API calls are made. The check engine is DB-driven; all resource
data comes from the discovery_findings table.

K8s resource identifier formats:
  Namespaced:   {namespace}/{kind}/{name}  e.g. default/Deployment/nginx
  Cluster-wide: {kind}/{name}             e.g. ClusterRole/cluster-admin
  UID:          Kubernetes UUID           e.g. 1a2b3c4d-5e6f-...
"""

import logging
from typing import Any, Dict, Optional

from common.models.evaluator_interface import CheckEvaluator

logger = logging.getLogger(__name__)


class K8sCheckEvaluator(CheckEvaluator):
    """Kubernetes implementation of CheckEvaluator — pure data parsing, no API calls."""

    def __init__(self, provider: str = "k8s", **kwargs):
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
        Extract K8s resource identifiers from already-fetched DB data.

        Strategy (in order):
          1. Use top-level resource_uid / resource_arn from discovery_findings row
          2. Search emitted_fields for uid / namespace + name fields
          3. Build canonical uid as {namespace}/{kind}/{name}
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

        return {
            "resource_arn":  resource_uid,   # K8s has no ARN; use namespaced path
            "resource_uid":  resource_uid or resource_id,
            "resource_id":   resource_id,
            "resource_type": resource_type,
        }

    # ── Private helpers ──────────────���───────────────────────────────────────

    @staticmethod
    def _search_emitted_fields(
        emitted_fields: Dict,
        resource_uid: Optional[str],
        resource_id: Optional[str],
        kind: str,
    ):
        """
        Recursively search emitted_fields for K8s metadata.uid / namespace / name.

        Builds canonical uid as {namespace}/{kind}/{name} when possible.
        """

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

        # Look inside metadata block first
        metadata = emitted_fields.get("metadata") or emitted_fields
        k8s_uid = _find(metadata, {"uid"})
        name = _find(metadata, {"name"})
        namespace = _find(metadata, {"namespace"})

        if not resource_uid:
            if namespace and name:
                resource_uid = f"{namespace}/{kind}/{name}" if kind else f"{namespace}/{name}"
            elif name and kind:
                resource_uid = f"{kind}/{name}"
            elif k8s_uid:
                resource_uid = k8s_uid

        if not resource_id:
            resource_id = name or k8s_uid

        return resource_uid, resource_id
