"""
Relationship Builder

Builds relationship edges from normalized assets using DB-driven rules.

=== DATABASE & TABLE MAP ===
Source of truth: threat_engine_inventory (INVENTORY DB)
Table: resource_security_relationship_rules

Rules are loaded once per scan from the inventory DB — no local JSON files,
no dependency on the pythonsdk DB at runtime.

Tables READ:
  - resource_security_relationship_rules : SELECT from_resource_type, relation_type,
                                          to_resource_type, source_field,
                                          source_field_item, target_uid_pattern
                                   FROM   resource_security_relationship_rules
                                   WHERE  csp = %s AND is_active = TRUE

Tables WRITTEN: None (returns Relationship objects to callers)

Populate rules with:
  engine_inventory/scripts/load_relationship_rules_to_db.py
===
"""

import json
import logging
import os
import re
from typing import List, Dict, Any, Optional, Set

from ..schemas.asset_schema import Asset, Provider
from ..schemas.relationship_schema import Relationship, RelationType

logger = logging.getLogger(__name__)


class RelationshipBuilder:
    """Builds relationships between assets using inventory-DB-driven relationship rules."""

    def __init__(
        self,
        tenant_id: str,
        scan_run_id: str,
        csp_id: str = "aws",
        db_conn=None,
    ):
        """
        Args:
            tenant_id:    Tenant identifier
            scan_run_id:  Current scan run ID
            csp_id:       Cloud provider key (aws | azure | gcp | oci | ibm | alicloud | k8s)
            db_conn:      Open psycopg2 connection to the inventory DB.
                          When None the builder falls back to opening its own connection
                          via INVENTORY_DB_URL env var (or returns an empty rule set if
                          neither is available — relationships are skipped gracefully).
        """
        self.tenant_id = tenant_id
        self.scan_run_id = scan_run_id
        self.csp_id = csp_id
        self._owns_conn = False
        self._conn = db_conn or self._open_inventory_conn()
        self.relationship_index = self._load_rules_from_db()
        self.relation_types: Set[str] = {rt.value for rt in RelationType}

    # ------------------------------------------------------------------
    # DB connection helpers
    # ------------------------------------------------------------------

    def _open_inventory_conn(self):
        """Open a connection to the inventory DB using env vars."""
        db_url = os.getenv("INVENTORY_DB_URL")
        if db_url:
            try:
                import psycopg2
                conn = psycopg2.connect(db_url)
                self._owns_conn = True
                return conn
            except Exception as exc:
                logger.warning(f"Cannot open inventory DB connection: {exc}")
        return None

    def close(self):
        """Close owned DB connection (if we opened it)."""
        if self._owns_conn and self._conn:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    # ------------------------------------------------------------------
    # Load: read rules from resource_security_relationship_rules (inventory DB)
    # ------------------------------------------------------------------

    def _load_rules_from_db(self) -> Dict[str, Any]:
        """
        Load relationship rules for this CSP from resource_security_relationship_rules.

        Returns index keyed by from_resource_type:
            {"by_resource_type": {type_name: {"relationships": [...]}}}
        """
        if not self._conn:
            logger.warning(
                f"No inventory DB connection — relationship rules unavailable for {self.csp_id}. "
                "Run load_relationship_rules_to_db.py to populate the rules table."
            )
            return {}

        try:
            with self._conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT from_resource_type, relation_type, to_resource_type,
                           source_field, source_field_item, target_uid_pattern
                    FROM   resource_security_relationship_rules
                    WHERE  csp = %s AND is_active = TRUE
                    ORDER BY from_resource_type, relation_type
                    """,
                    (self.csp_id,),
                )
                rows = cur.fetchall()

            by_resource_type: Dict[str, Dict] = {}
            for (from_type, rel_type, to_type,
                 source_field, source_field_item, target_pattern) in rows:
                if from_type not in by_resource_type:
                    by_resource_type[from_type] = {"relationships": []}
                by_resource_type[from_type]["relationships"].append({
                    "relation_type":      rel_type,
                    "target_type":        to_type,
                    "source_field":       source_field,
                    "source_field_item":  source_field_item,
                    "target_uid_pattern": target_pattern,
                })

            logger.info(
                f"Loaded {sum(len(v['relationships']) for v in by_resource_type.values())} "
                f"relationship rules from inventory DB for csp={self.csp_id} "
                f"({len(by_resource_type)} resource types)"
            )
            return {
                "version": "db",
                "source": "inventory_db:resource_security_relationship_rules",
                "classifications": {
                    "by_resource_type": by_resource_type,
                },
            }
        except Exception as exc:
            logger.error(f"Error loading relationship rules from DB for {self.csp_id}: {exc}")
            return {}

    # ------------------------------------------------------------------
    # Build: create Relationship edges from assets
    # ------------------------------------------------------------------

    def build_relationships(self, assets: List[Asset]) -> List[Relationship]:
        """
        Build relationships from assets using the loaded rule index.

        For each asset:
          1. Look up relationship patterns for its resource_type (with type candidates)
          2. Extract field values from asset metadata
          3. Resolve target UIDs from patterns
          4. Emit Relationship edges
          5. Build architecture containment edges (Azure ARM RG, K8s namespace)
        """
        relationships: List[Relationship] = []

        assets_by_uid = {asset.resource_uid: asset for asset in assets}
        assets_by_type: Dict[str, List[Asset]] = {}
        for asset in assets:
            assets_by_type.setdefault(asset.resource_type, []).append(asset)

        for asset in assets:
            relationships.extend(
                self._extract_relationships_from_asset(asset, assets_by_uid, assets_by_type)
            )

        # Architecture containment: Azure resource group, K8s namespace
        relationships.extend(self._build_architecture_containment(assets, assets_by_uid))

        # Special case: internet exposure (public IPs / public buckets)
        relationships.extend(self._build_internet_exposure(assets_by_type))

        return relationships

    # ------------------------------------------------------------------
    # Type normalization — generate candidate DB lookup keys
    # ------------------------------------------------------------------

    def _get_type_candidates(self, resource_type: str) -> List[str]:
        """
        Generate candidate from_resource_type strings for DB rule lookup.

        The DB rules use `resource_inventory_identifier.resource_type` as keys,
        which may differ from the normalizer's output format.  This method emits
        multiple candidates so the rule index is searched in all plausible forms.

        Known transformations:
          K8s:      "pod.k8s.core/Pod"         → "core.pod"
          AliCloud: "ram.alicloud.ram/Role"     → "ram.role"
          OCI:      "compute.oci.core/Instance" → "core.instance", "compute.instance"
          Azure:    "network.NetworkSecurityGroup" → "network.networksecuritygroups"
                    "azure.resource_group"         → "microsoft.resources/resourcegroups"
          GCP:      "gcp.compute_instance"      → "compute.instance"
        """
        candidates: List[str] = [resource_type]

        # ── K8s: "{resource}.k8s.{apigroup}/{Kind}" ───────────────────────────
        if ".k8s." in resource_type and "/" in resource_type:
            # e.g. "pod.k8s.core/Pod" → apigroup="core", kind="pod"
            k8s_suffix = resource_type.split(".k8s.", 1)[-1]          # "core/Pod"
            if "/" in k8s_suffix:
                apigroup = k8s_suffix.split("/")[0]                    # "core"
                kind = k8s_suffix.split("/")[1].lower()                # "pod"
                candidates.append(f"{apigroup}.{kind}")               # "core.pod"
                candidates.append(kind)

        # ── AliCloud: "{svc}.alicloud.{api}/{Kind}" ───────────────────────────
        elif ".alicloud." in resource_type and "/" in resource_type:
            # e.g. "ram.alicloud.ram/Role" → service="ram", kind="role"
            service = resource_type.split(".")[0]                      # "ram"
            kind = resource_type.split("/")[-1].lower()                # "role"
            candidates.append(f"{service}.{kind}")                    # "ram.role"
            candidates.append(kind)

        # ── OCI: "{svc}.oci.{api}/{Kind}" ────────────────────────────────────
        elif ".oci." in resource_type and "/" in resource_type:
            # e.g. "compute.oci.core/Instance" → "core.instance", "compute.instance"
            service = resource_type.split(".")[0]                      # "compute"
            oci_suffix = resource_type.split(".oci.", 1)[-1]           # "core/Instance"
            if "/" in oci_suffix:
                apigroup = oci_suffix.split("/")[0]                    # "core"
                kind = oci_suffix.split("/")[1].lower()                # "instance"
                candidates.append(f"{apigroup}.{kind}")
                candidates.append(f"{service}.{kind}")
                candidates.append(kind)

        # ── Azure ─────────────────────────────────────────────────────────────
        elif self.csp_id == "azure":
            if resource_type.startswith("azure."):
                # e.g. "azure.resource_group" → "microsoft.resources/resourcegroups"
                bare = resource_type[6:]                               # "resource_group"
                bare_no_sep = bare.replace("_", "")                   # "resourcegroup"
                candidates.append(f"microsoft.resources/{bare_no_sep}s")
                candidates.append(f"resources.{bare_no_sep}s")
                candidates.append(bare_no_sep)
            else:
                # e.g. "network.NetworkSecurityGroup" → "network.networksecuritygroups"
                parts = resource_type.split(".", 1)
                if len(parts) == 2:
                    ns, kind = parts[0], parts[1]
                    kind_lower = kind.lower()
                    candidates.append(f"{ns}.{kind_lower}")           # lowercase
                    candidates.append(f"{ns}.{kind_lower}s")          # lowercase plural
                    candidates.append(f"microsoft.{ns}/{kind_lower}s")# full ARM plural
                    candidates.append(f"microsoft.{ns}/{kind_lower}") # full ARM singular

        # ── GCP: "gcp.{service}_{kind}" ──────────────────────────────────────
        elif resource_type.startswith("gcp."):
            bare = resource_type[4:]                                   # "compute_instance"
            first_us = bare.find("_")
            if first_us > 0:
                svc = bare[:first_us]
                kind = bare[first_us + 1:]
                candidates.append(f"{svc}.{kind}")                    # "compute.instance"
                candidates.append(f"gcp.{svc}.{kind}")
            candidates.append(bare)

        return list(dict.fromkeys(candidates))  # preserve order, remove duplicates

    # ------------------------------------------------------------------
    # Architecture containment relationships
    # ------------------------------------------------------------------

    def _build_architecture_containment(
        self,
        assets: List[Asset],
        assets_by_uid: Dict[str, Asset],
    ) -> List[Relationship]:
        """
        Build CONTAINED_BY relationships from architecture structure:
          - Azure: resource → resource_group (parsed from ARM URI)
          - K8s:   namespaced resource → namespace (from emitted_fields)
        """
        relationships: List[Relationship] = []
        csp = self.csp_id.lower()

        if csp == "azure":
            relationships.extend(self._build_azure_rg_containment(assets, assets_by_uid))
        elif csp == "k8s":
            relationships.extend(self._build_k8s_namespace_containment(assets, assets_by_uid))

        return relationships

    def _build_azure_rg_containment(
        self,
        assets: List[Asset],
        assets_by_uid: Dict[str, Asset],
    ) -> List[Relationship]:
        """
        For each Azure resource whose ARM URI contains /resourceGroups/{rg}/,
        emit CONTAINED_BY → the resource group asset.

        ARM URI: /subscriptions/{sub}/resourceGroups/{rg}/providers/{ns}/{type}/{name}
        RG UID:  /subscriptions/{sub}/resourceGroups/{rg}   (case-insensitive match)
        """
        relationships: List[Relationship] = []

        # Build lookup: rg_uri_lower → rg_asset (case-insensitive ARM URI matching)
        rg_by_uri: Dict[str, Asset] = {}
        for asset in assets:
            uid_lower = asset.resource_uid.lower()
            if uid_lower.startswith("/subscriptions/") and "/resourcegroups/" in uid_lower:
                parts = uid_lower.split("/")
                # /subscriptions/sub/resourcegroups/rg → parts[0..4]
                if len(parts) >= 5:
                    rg_uri_lower = "/".join(parts[:5])               # normalised RG URI
                    if asset.resource_type in (
                        "azure.resource_group",
                        "microsoft.resources/resourcegroups",
                        "resources.resourcegroups",
                    ):
                        rg_by_uri[rg_uri_lower] = asset

        for asset in assets:
            uid = asset.resource_uid
            uid_lower = uid.lower()
            if not uid_lower.startswith("/subscriptions/") or "/resourcegroups/" not in uid_lower:
                continue
            parts = uid_lower.split("/")
            if len(parts) < 5:
                continue
            rg_uri_lower = "/".join(parts[:5])
            if rg_uri_lower == uid_lower:
                continue                                              # skip the RG itself
            rg_asset = rg_by_uri.get(rg_uri_lower)
            if not rg_asset:
                continue

            relationships.append(Relationship(
                tenant_id=self.tenant_id,
                scan_run_id=self.scan_run_id,
                provider=asset.provider.value,
                account_id=asset.account_id,
                region=asset.region,
                relation_type=RelationType.CONTAINED_BY,
                from_uid=asset.resource_uid,
                to_uid=rg_asset.resource_uid,
                from_resource_type=asset.resource_type,
                to_resource_type=rg_asset.resource_type,
                properties={"containment": "resource_group"},
            ))

        return relationships

    def _build_k8s_namespace_containment(
        self,
        assets: List[Asset],
        assets_by_uid: Dict[str, Asset],
    ) -> List[Relationship]:
        """
        For each K8s namespaced resource, emit CONTAINED_BY → namespace asset.

        Namespace is extracted from asset.metadata["emitted_fields"]["namespace"].
        Namespace assets are matched by name.
        """
        relationships: List[Relationship] = []

        # K8s Namespace resource types
        namespace_types = {
            "namespace.k8s.core/Namespace",
            "k8s.namespace",
            "core.namespace",
        }

        # Build lookup: namespace_name → namespace_asset
        ns_by_name: Dict[str, Asset] = {}
        for asset in assets:
            if asset.resource_type in namespace_types:
                if asset.name:
                    ns_by_name[asset.name] = asset

        if not ns_by_name:
            return relationships

        for asset in assets:
            if asset.resource_type in namespace_types:
                continue  # skip namespace itself

            emitted = asset.metadata.get("emitted_fields", {}) if asset.metadata else {}
            ns_name = emitted.get("namespace")
            if not ns_name:
                emitted_meta = emitted.get("metadata")
                if isinstance(emitted_meta, dict):
                    ns_name = emitted_meta.get("namespace")
            if not ns_name or not isinstance(ns_name, str):
                continue

            ns_asset = ns_by_name.get(ns_name)
            if not ns_asset:
                continue

            relationships.append(Relationship(
                tenant_id=self.tenant_id,
                scan_run_id=self.scan_run_id,
                provider=asset.provider.value,
                account_id=asset.account_id,
                region=asset.region,
                relation_type=RelationType.CONTAINED_BY,
                from_uid=asset.resource_uid,
                to_uid=ns_asset.resource_uid,
                from_resource_type=asset.resource_type,
                to_resource_type=ns_asset.resource_type,
                properties={"containment": "namespace", "namespace": ns_name},
            ))

        return relationships

    def _extract_relationships_from_asset(
        self,
        asset: Asset,
        assets_by_uid: Dict[str, Asset],
        assets_by_type: Dict[str, List[Asset]],
    ) -> List[Relationship]:
        """Extract all relationships for a single asset using type candidate lookup."""
        relationships: List[Relationship] = []

        if not self.relationship_index:
            return relationships

        by_resource = (
            self.relationship_index
            .get("classifications", {})
            .get("by_resource_type", {})
        )

        # Collect rule patterns from all candidate type keys
        resource_patterns: List[Dict] = []
        seen_patterns: set = set()
        for candidate in self._get_type_candidates(asset.resource_type):
            for p in by_resource.get(candidate, {}).get("relationships", []):
                key = (p.get("relation_type"), p.get("source_field"), p.get("target_uid_pattern"))
                if key not in seen_patterns:
                    seen_patterns.add(key)
                    resource_patterns.append(p)

        if not resource_patterns:
            return relationships

        for pattern in resource_patterns:
            rel_type_str = pattern.get("relation_type", "")
            if rel_type_str not in self.relation_types:
                continue

            try:
                rel_type = RelationType(rel_type_str)
            except ValueError:
                continue

            target_type        = pattern.get("target_type", "")
            source_field       = pattern.get("source_field", "")
            target_uid_pattern = pattern.get("target_uid_pattern", "")
            source_field_item  = pattern.get("source_field_item")

            if not source_field or not target_uid_pattern:
                continue

            field_values = self._extract_field_values(
                asset.metadata, source_field, source_field_item
            )

            for field_value in field_values:
                if not field_value:
                    continue

                target_uid = self._resolve_target_uid(
                    target_uid_pattern, field_value, asset, target_type
                )
                if not target_uid:
                    continue

                relationships.append(Relationship(
                    tenant_id=self.tenant_id,
                    scan_run_id=self.scan_run_id,
                    provider=asset.provider.value,
                    account_id=asset.account_id,
                    region=asset.region,
                    relation_type=rel_type,
                    from_uid=asset.resource_uid,
                    to_uid=target_uid,
                    from_resource_type=asset.resource_type,
                    to_resource_type=target_type,
                    properties=self._extract_relationship_properties(
                        pattern, field_value, asset
                    ),
                ))

        return relationships

    # ------------------------------------------------------------------
    # Field extraction
    # ------------------------------------------------------------------

    def _extract_field_values(
        self,
        metadata: Dict[str, Any],
        source_field: str,
        source_field_item: Optional[str] = None,
    ) -> List[Any]:
        """
        Extract field value(s) from asset metadata.

        Supports:
        - Simple fields:               "VpcId"
        - Nested dot-paths:            "IamInstanceProfile.Arn"
        - Array fields:                "SecurityGroups"        (returns whole list)
        - Array + item extraction:     source_field="SecurityGroups", source_field_item="GroupId"
        - Nested array dot-paths:      "VpcConfig.SubnetIds"
        - JSON-string auto-parse:      field value is a JSON string → strings extracted
        """
        if not source_field:
            return []

        # metadata may contain "emitted_fields" (explicit extractions take priority)
        # or direct raw-response keys — the normalizer already merges both.
        data_source = metadata.get("emitted_fields", metadata)

        # ── Nested dot-path (e.g. "IamInstanceProfile.Arn") ─────────────────
        if "." in source_field and not source_field.endswith("[]"):
            parts = source_field.split(".")
            value = data_source
            for part in parts:
                if isinstance(value, dict):
                    value = value.get(part)
                else:
                    return []
                if value is None:
                    return []

            if isinstance(value, list):
                if source_field_item:
                    extracted: List[Any] = []
                    for item in value:
                        if isinstance(item, dict):
                            iv = item.get(source_field_item)
                            if iv is not None:
                                extracted.append(iv)
                        elif isinstance(item, str):
                            extracted.append(item)
                    return extracted
                return value

            if source_field_item and isinstance(value, dict):
                iv = value.get(source_field_item)
                return [iv] if iv is not None else []

            return [value]

        # ── Simple field ─────────────────────────────────────────────────────
        field_value = data_source.get(source_field)
        if field_value is None:
            return []

        if source_field_item and isinstance(field_value, list):
            extracted = []
            for item in field_value:
                if isinstance(item, dict):
                    item_value = item.get(source_field_item)
                    if item_value:
                        extracted.append(item_value)
                elif isinstance(item, str):
                    extracted.append(item)
            return extracted

        if isinstance(field_value, list):
            return field_value

        # Dict: collect all embedded string values
        if isinstance(field_value, dict):
            results: List[Any] = []
            def _collect(obj: Any) -> None:
                if isinstance(obj, dict):
                    for v in obj.values():
                        _collect(v)
                elif isinstance(obj, list):
                    for it in obj:
                        _collect(it)
                elif isinstance(obj, str):
                    results.append(obj)
            _collect(field_value)
            return list(dict.fromkeys(results))

        # JSON string → auto-parse
        if isinstance(field_value, str):
            s = field_value.strip()
            if (s.startswith("{") and s.endswith("}")) or (s.startswith("[") and s.endswith("]")):
                try:
                    parsed = json.loads(s)
                    results = []
                    def _collect_parsed(obj: Any) -> None:
                        if isinstance(obj, dict):
                            for v in obj.values():
                                _collect_parsed(v)
                        elif isinstance(obj, list):
                            for it in obj:
                                _collect_parsed(it)
                        elif isinstance(obj, str):
                            results.append(obj)
                    _collect_parsed(parsed)
                    return list(dict.fromkeys(results))
                except Exception:
                    pass

        return [field_value]

    # ------------------------------------------------------------------
    # UID resolution
    # ------------------------------------------------------------------

    def _extract_account_from_uid(self, resource_uid: str, asset: Optional["Asset"] = None) -> Optional[str]:
        """Extract account/subscription/project ID from any CSP resource UID."""
        if not resource_uid:
            return asset.account_id if asset else None
        # AWS ARN:  arn:aws:service:region:account:resource
        if resource_uid.startswith("arn:"):
            parts = resource_uid.split(":")
            return parts[4] if len(parts) >= 5 else (asset.account_id if asset else None)
        # Azure ARM: /subscriptions/{sub_id}/resourceGroups/...
        if resource_uid.startswith("/subscriptions/"):
            parts = resource_uid.split("/")
            return parts[2] if len(parts) >= 3 else (asset.account_id if asset else None)
        # GCP: projects/{project}/...  or  //cloudresourcemanager.googleapis.com/projects/{id}
        if resource_uid.startswith("projects/") or "/projects/" in resource_uid:
            seg = resource_uid.split("projects/")[-1].split("/")[0]
            return seg or (asset.account_id if asset else None)
        # OCI OCID: ocid1.resource.oc1.region.unique — account not in UID, use asset
        # IBM, AliCloud, K8s: fall back to asset.account_id
        return asset.account_id if asset else None

    def _extract_region_from_uid(self, resource_uid: str, asset: Optional["Asset"] = None) -> Optional[str]:
        """Extract region/location from any CSP resource UID."""
        if not resource_uid:
            return asset.region if asset else None
        # AWS ARN: arn:aws:service:region:account:resource
        if resource_uid.startswith("arn:"):
            parts = resource_uid.split(":")
            region = parts[3] if len(parts) >= 4 else None
            return region if region else (asset.region if asset else None)
        # Azure ARM: /subscriptions/{sub}/resourceGroups/{rg}/providers/{ns}/{type}/{name}
        # Region is NOT in the ARM URI — use asset.region
        if resource_uid.startswith("/subscriptions/"):
            return asset.region if asset else None
        # GCP: projects/{proj}/zones/{zone}/... or regions/{region}/...
        for seg_key in ("zones/", "regions/", "locations/"):
            if seg_key in resource_uid:
                val = resource_uid.split(seg_key)[-1].split("/")[0]
                return val if val else (asset.region if asset else None)
        return asset.region if asset else None

    def _resolve_target_uid(
        self,
        pattern: str,
        field_value: Any,
        asset: Asset,
        target_type: str,
    ) -> Optional[str]:
        """
        Resolve target UID from pattern.

        Pattern forms:
          "{Arn}"                                    → use field_value directly
          "arn:aws:ec2:{region}:{account_id}:vpc/{VpcId}" → substitute variables
        """
        if not pattern or not field_value:
            return None

        # Direct single-placeholder: e.g. "{Arn}", "{RoleArn}"
        if pattern.startswith("{") and pattern.endswith("}"):
            if isinstance(field_value, str) and field_value.startswith("arn:"):
                return field_value
            if isinstance(field_value, (dict, list)):
                return None
            return str(field_value) if field_value else None

        # Template with variables
        resolved = pattern
        account_id = self._extract_account_from_uid(asset.resource_uid, asset) or asset.account_id
        region     = self._extract_region_from_uid(asset.resource_uid, asset) or asset.region or ""

        resolved = resolved.replace("{region}", region)
        resolved = resolved.replace("{account_id}", account_id)

        # Replace remaining {Field} placeholders with field_value
        for placeholder in re.findall(r'\{([^}]+)\}', resolved):
            if placeholder in ("region", "account_id"):
                continue
            resolved = resolved.replace(f"{{{placeholder}}}", str(field_value))

        # Unresolved placeholders → invalid
        if "{" in resolved or "}" in resolved:
            return None

        return resolved if resolved and resolved != pattern else None

    def _extract_relationship_properties(
        self,
        pattern: Dict[str, Any],
        field_value: Any,
        asset: Asset,
    ) -> Dict[str, Any]:
        props: Dict[str, Any] = {}
        if (pattern.get("relation_type") == "attached_to"
                and "security-group" in pattern.get("target_type", "")):
            props["direction"] = "inbound"
        if isinstance(field_value, (str, int)):
            props["source_field_value"] = str(field_value)
        return props

    # ------------------------------------------------------------------
    # Internet exposure — field-based, works for all CSPs
    # ------------------------------------------------------------------

    # Fields that carry a public IP/address across all CSPs
    _PUBLIC_IP_FIELDS = (
        # AWS EC2, ELB, EIP
        "PublicIpAddress", "PublicDnsName", "public_ip",
        # Azure VM, LB, PIP
        "publicIpAddress", "properties.ipAddress",
        # GCP compute instance, forwarding rule
        "natIP", "IPAddress", "ipAddress",
        # OCI instance, LB
        "publicIp",
        # IBM floating IP
        "floating_ips", "floatingIp",
        # Generic
        "public_ip_address", "publicIP",
    )

    # Fields/values that signal public object/blob/bucket access across CSPs
    _PUBLIC_ACCESS_FIELDS = (
        # AWS S3 — normalizer sets this when BlockPublicAcls=false
        "public_access",
        # Azure Storage — set by discovery
        "AllowBlobPublicAccess", "allowBlobPublicAccess",
        # GCP Storage
        "publicAccessPrevention",
        # Generic
        "isPublic", "is_public", "PublicAccess",
    )

    def _build_internet_exposure(
        self, assets_by_type: Dict[str, List[Asset]]
    ) -> List[Relationship]:
        """
        Detect internet-exposed resources for ALL CSPs by inspecting asset field values.

        Checks every asset (regardless of resource_type) for:
          - Public IP / DNS address fields  → internet_connected
          - Public access flags             → internet_connected
        """
        relationships: List[Relationship] = []

        for assets in assets_by_type.values():
            for asset in assets:
                props: Dict[str, Any] = {}
                exposed = False

                # Collect all metadata fields in one flat dict for easy lookup
                meta = asset.metadata or {}
                config = meta.get("configuration") or {}
                emitted = meta.get("emitted_fields") or {}
                # Merge all layers — explicit metadata wins over nested
                all_fields: Dict[str, Any] = {**emitted, **config, **meta}

                # --- Public IP check ---
                for field in self._PUBLIC_IP_FIELDS:
                    val = all_fields.get(field)
                    if val and isinstance(val, str) and val not in ("None", ""):
                        props["public_ip"] = val
                        exposed = True
                        break

                # --- Public access flag check ---
                if not exposed:
                    for field in self._PUBLIC_ACCESS_FIELDS:
                        val = all_fields.get(field)
                        # AWS public_access = True means public; GCP publicAccessPrevention
                        # = "inherited" means public (absence of enforced = public)
                        if val is True or val in ("true", "True", "1", "inherited"):
                            props["public_access"] = True
                            exposed = True
                            break

                if exposed:
                    relationships.append(Relationship(
                        tenant_id=self.tenant_id,
                        scan_run_id=self.scan_run_id,
                        provider=asset.provider.value,
                        account_id=asset.account_id,
                        region=asset.region,
                        relation_type=RelationType.INTERNET_CONNECTED,
                        from_uid=asset.resource_uid,
                        to_uid="internet:0.0.0.0/0",
                        from_resource_type=asset.resource_type,
                        to_resource_type=None,
                        properties=props,
                    ))

        return relationships
