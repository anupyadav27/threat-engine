"""
GCP Check Evaluator

GCP-specific implementation of CheckEvaluator.

Sole responsibility:
  extract_resource_identifiers() — parse/construct GCP resource identifiers
  from the emitted_fields JSON already stored by the discovery engine.

No GCP API calls are made. The check engine is DB-driven; all resource
data comes from the discovery_findings table.

GCP resource identifier formats:
  selfLink:     https://www.googleapis.com/compute/v1/projects/{proj}/zones/{zone}/instances/{name}
  CAI name:     //compute.googleapis.com/projects/{proj}/zones/{zone}/instances/{name}
  Short name:   projects/{proj}/zones/{zone}/instances/{name}
"""

import logging
import re
from typing import Any, Dict, Optional

from common.models.evaluator_interface import CheckEvaluator

_VERSION_RE = re.compile(r'^v\d')   # matches v1, v2, v1beta1, v2alpha1, …

logger = logging.getLogger(__name__)


class GCPCheckEvaluator(CheckEvaluator):
    """GCP implementation of CheckEvaluator — pure data parsing, no API calls."""

    def __init__(self, provider: str = "gcp", **kwargs):
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
        Extract GCP resource identifiers from already-fetched DB data.

        Strategy (in order):
          1. Use top-level resource_uid / resource_arn from discovery_findings row
          2. Search emitted_fields for selfLink, name, id fields
          3. Build CAI-format resource_uid from project + service + name
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

        # Step 1: Search emitted_fields for GCP identifiers
        if not resource_uid or not resource_id:
            resource_uid, resource_id = self._search_emitted_fields(
                emitted_fields, resource_uid, resource_id
            )

        # Step 2: Normalise selfLink → CAI format
        if resource_uid and resource_uid.startswith("https://"):
            resource_uid = self._selflink_to_cai(resource_uid)

        # Step 3: Fallback — build CAI name from parts
        if not resource_uid and resource_id and service and account_id:
            resource_uid = self._build_cai_name(service, account_id, region, resource_id)

        return {
            "resource_arn":  resource_uid,   # GCP has no ARN; use uid as canonical
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
        """Recursively search emitted_fields for GCP selfLink / name / id."""

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

        uid_keys = {"selfLink", "self_link", "resource_uid", "name", "id"}
        id_keys = {"name", "id", "resource_id", "uniqueId", "unique_id", "email"}

        if not resource_uid:
            # Prefer selfLink as uid
            resource_uid = _find(emitted_fields, {"selfLink", "self_link", "resource_uid"})
        if not resource_uid:
            resource_uid = _find(emitted_fields, uid_keys)
        if not resource_id:
            resource_id = _find(emitted_fields, id_keys)

        # Derive short id from selfLink/uid
        if not resource_id and resource_uid:
            resource_id = resource_uid.rstrip("/").split("/")[-1]

        return resource_uid, resource_id

    @staticmethod
    def _selflink_to_cai(self_link: str) -> str:
        """
        Convert GCP selfLink to Cloud Asset Inventory (CAI) format.

        https://www.googleapis.com/compute/v1/projects/p/zones/z/instances/i
          → //compute.googleapis.com/projects/p/zones/z/instances/i
        """
        try:
            # Strip scheme + host
            if "//" in self_link:
                self_link = self_link.split("//", 1)[1]
            # www.googleapis.com/compute/v1/projects/...
            if self_link.startswith("www.googleapis.com/"):
                _, rest = self_link.split("/", 1)
                # rest = "compute/v1/projects/..."
                parts = rest.split("/")
                api = parts[0]   # e.g. compute
                # drop version segment (v1, v2, v1beta1, …) but keep resource names
                path = "/".join(p for p in parts[1:] if not _VERSION_RE.match(p))
                return f"//{api}.googleapis.com/{path}"
        except Exception as exc:
            logger.debug("selfLink→CAI conversion failed: %s", exc)
        return self_link

    @staticmethod
    def _build_cai_name(service: str, project_id: str, region: str, name: str) -> str:
        """Build a best-effort CAI resource name."""
        # Map service → GCP API host prefix
        service_map = {
            "compute":        "compute.googleapis.com",
            "iam":            "iam.googleapis.com",
            "storage":        "storage.googleapis.com",
            "bigquery":       "bigquery.googleapis.com",
            "gke":            "container.googleapis.com",
            "container":      "container.googleapis.com",
            "cloudfunctions": "cloudfunctions.googleapis.com",
            "run":            "run.googleapis.com",
            "cloudrun":       "run.googleapis.com",
            "sqladmin":       "sqladmin.googleapis.com",
            "cloudsql":       "sqladmin.googleapis.com",
            "dns":            "dns.googleapis.com",
            "pubsub":         "pubsub.googleapis.com",
            "kms":            "cloudkms.googleapis.com",
            "cloudkms":       "cloudkms.googleapis.com",
            "secretmanager":  "secretmanager.googleapis.com",
            "spanner":        "spanner.googleapis.com",
            "bigtable":       "bigtable.googleapis.com",
            "firestore":      "firestore.googleapis.com",
            "logging":        "logging.googleapis.com",
            "monitoring":     "monitoring.googleapis.com",
        }
        api_host = service_map.get(service.lower(), f"{service}.googleapis.com")

        if region and region not in ("global", ""):
            return f"//{api_host}/projects/{project_id}/locations/{region}/{service}/{name}"
        return f"//{api_host}/projects/{project_id}/{service}/{name}"
