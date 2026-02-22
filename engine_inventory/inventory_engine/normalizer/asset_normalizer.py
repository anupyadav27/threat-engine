"""
Asset Normalizer

Transforms raw provider JSON into canonical Asset records.

=== DATABASE & TABLE MAP ===
Database: None — pure transformation logic (no direct DB access).

Input:  Raw discovery dicts from DiscoveryDBReader (discovery_findings rows)
Output: List[Asset] Pydantic models consumed by IndexWriter and RelationshipBuilder

Discovery emitted_fields structure (three patterns):
  1. Flat top-level — list_roles:   {Arn, RoleName, Path, CreateDate, resource_arn, _raw_response}
  2. Nested under operation key — get_role:  {get_role: {Role: {Arn, RoleName,...}}, resource_arn, _raw_response}
  3. With dependent data — list_buckets: {Name, BucketArn, _dependent_data: {get_bucket_versioning: {...}}, _enriched_from: [...]}

The normalizer deep-extracts names, tags, resource IDs, and configuration properties
from all three patterns to build rich Asset records.

Tables READ:  None (receives data from callers)
Tables WRITTEN: None (returns Asset objects to callers)
===
"""

import json
import hashlib
import logging
import os
import re
from typing import List, Dict, Any, Optional
from ..schemas.asset_schema import Asset, Provider, Scope, compute_asset_hash
from ..schemas.relationship_schema import Relationship, RelationType
from .resource_classifier import ResourceClassifier, InventoryDecision
from ..metadata.service_metadata_loader import ServiceMetadataLoader

logger = logging.getLogger(__name__)


class AssetNormalizer:
    """Normalizes raw provider data to canonical assets"""

    def __init__(self, tenant_id: str, scan_run_id: str, db_connection=None):
        self.tenant_id = tenant_id
        self.scan_run_id = scan_run_id
        self.classifier = ResourceClassifier()  # Initialize classifier with default index

        # Initialize metadata loader for pattern-based ARN/ID generation
        try:
            if db_connection:
                self.metadata_loader = ServiceMetadataLoader(db_connection=db_connection)
            else:
                # Build connection config from environment variables (all CSPs use same pythonsdk DB)
                db_config = {
                    'host': os.getenv('PYTHONSDK_DB_HOST', os.getenv('DB_HOST', 'localhost')),
                    'port': int(os.getenv('PYTHONSDK_DB_PORT', os.getenv('DB_PORT', '5432'))),
                    'database': os.getenv('PYTHONSDK_DB_NAME', 'threat_engine_pythonsdk'),
                    'user': os.getenv('PYTHONSDK_DB_USER', os.getenv('DB_USER', 'postgres')),
                    'password': os.getenv('PYTHONSDK_DB_PASSWORD', os.getenv('DB_PASSWORD', '')),
                }
                self.metadata_loader = ServiceMetadataLoader(db_config=db_config)
            logger.info(f"AssetNormalizer: ServiceMetadataLoader initialized with {len(self.metadata_loader._services_cache)} services")
        except Exception as e:
            logger.warning(f"Failed to initialize ServiceMetadataLoader: {e}. Falling back to legacy ARN generation.")
            self.metadata_loader = None
    
    def normalize_from_raw(
        self,
        raw_data: Dict[str, Any],
        provider: Provider,
        account_id: str,
        region: str,
        service: str,
        raw_ref: str
    ) -> List[Asset]:
        """
        Normalize raw provider data to Asset records.
        
        Args:
            raw_data: Raw provider JSON data
            provider: Cloud provider
            account_id: Account/subscription/project ID
            region: Region code
            service: Service name (e.g., "s3", "ec2")
            raw_ref: S3 path to raw data
        
        Returns:
            List of normalized Asset records
        """
        assets = []
        
        # Provider-specific normalization
        if provider == Provider.AWS:
            assets.extend(self._normalize_aws(raw_data, account_id, region, service, raw_ref))
        elif provider == Provider.AZURE:
            assets.extend(self._normalize_azure(raw_data, account_id, region, service, raw_ref))
        elif provider == Provider.GCP:
            assets.extend(self._normalize_gcp(raw_data, account_id, region, service, raw_ref))
        elif provider == Provider.K8S:
            assets.extend(self._normalize_k8s(raw_data, account_id, region, service, raw_ref))
        
        return assets
    
    def _normalize_aws(
        self,
        raw_data: Dict[str, Any],
        account_id: str,
        region: str,
        service: str,
        raw_ref: str
    ) -> List[Asset]:
        """Normalize AWS raw data"""
        assets = []
        
        # Extract resources from raw data
        # Structure depends on service, but typically has a list of resources
        resources = self._extract_resources(raw_data, service)
        
        for resource in resources:
            # Extract resource identifiers
            resource_uid = self._extract_aws_resource_uid(resource, service, account_id, region)
            resource_id = self._extract_aws_resource_id(resource, service)
            resource_type = f"{service}.{self._extract_aws_resource_type(resource, service)}"
            name = resource.get("Name") or resource.get("name") or resource_id
            
            # Extract tags
            tags = self._extract_tags(resource)
            
            # Determine scope
            scope = Scope.GLOBAL if service in ["iam", "s3", "cloudfront", "route53"] else Scope.REGIONAL
            
            # Build metadata
            metadata = {
                "created_at": resource.get("CreationDate") or resource.get("CreateDate"),
                "labels": {},
                "raw_refs": [raw_ref]
            }
            
            # Create asset
            asset = Asset(
                tenant_id=self.tenant_id,
                scan_run_id=self.scan_run_id,
                provider=Provider.AWS,
                account_id=account_id,
                region=region,
                scope=scope,
                resource_type=resource_type,
                resource_id=resource_id,
                resource_uid=resource_uid,
                name=name,
                tags=tags,
                metadata=metadata,
                hash_sha256=""  # Will be computed
            )
            
            # Compute hash
            asset.hash_sha256 = compute_asset_hash(asset)
            
            assets.append(asset)
        
        return assets
    
    def _normalize_azure(
        self,
        raw_data: Dict[str, Any],
        account_id: str,
        region: str,
        service: str,
        raw_ref: str
    ) -> List[Asset]:
        """Normalize Azure raw data"""
        assets = []
        # TODO: Implement Azure normalization
        return assets
    
    def _normalize_gcp(
        self,
        raw_data: Dict[str, Any],
        account_id: str,
        region: str,
        service: str,
        raw_ref: str
    ) -> List[Asset]:
        """Normalize GCP raw data"""
        assets = []
        # TODO: Implement GCP normalization
        return assets
    
    def _normalize_k8s(
        self,
        raw_data: Dict[str, Any],
        account_id: str,
        region: str,
        service: str,
        raw_ref: str
    ) -> List[Asset]:
        """Normalize Kubernetes raw data"""
        assets = []
        # TODO: Implement K8s normalization
        return assets
    
    def _extract_resources(self, raw_data: Dict[str, Any], service: str) -> List[Dict[str, Any]]:
        """Extract resource list from raw data"""
        # Common patterns: "Resources", "items", "value", or direct list
        if isinstance(raw_data, list):
            return raw_data
        
        for key in ["Resources", "items", "value", "results"]:
            if key in raw_data and isinstance(raw_data[key], list):
                return raw_data[key]
        
        # If no list found, treat entire object as single resource
        return [raw_data]
    
    def _extract_aws_resource_uid(self, resource: Dict[str, Any], service: str, account_id: str, region: str) -> str:
        """
        Extract AWS resource UID (ARN) using pattern-based generation from database

        This method uses ServiceMetadataLoader to get ARN patterns from the database,
        replacing hardcoded ARN generation for 20 services with pattern-based generation
        for all 429+ AWS services.
        """
        # Try explicit ARN field first
        arn = resource.get("Arn") or resource.get("arn") or resource.get("ARN")
        if arn:
            return arn

        # Use pattern-based ARN generation from database
        if self.metadata_loader:
            try:
                arn_pattern = self.metadata_loader.get_identifier_pattern('aws', service)
                if arn_pattern:
                    generated_arn = self._apply_identifier_pattern(
                        arn_pattern, resource, region, account_id, 'aws'
                    )
                    if generated_arn:
                        return generated_arn
            except Exception as e:
                logger.warning(f"Error generating ARN from pattern for {service}: {e}")

        # Legacy fallback for services without patterns
        # (These fallbacks are only used if database pattern fails)
        if service == "s3":
            bucket_name = resource.get("Name") or resource.get("BucketName")
            if bucket_name:
                return f"arn:aws:s3:::{bucket_name}"
        elif service == "ec2":
            instance_id = resource.get("InstanceId")
            if instance_id:
                return f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}"
        elif service == "iam":
            resource_name = resource.get("UserName") or resource.get("RoleName") or resource.get("GroupName")
            resource_type = "user" if resource.get("UserName") else "role" if resource.get("RoleName") else "group"
            if resource_name:
                return f"arn:aws:iam::{account_id}:{resource_type}/{resource_name}"

        # Final fallback: construct UID
        resource_id = resource.get("Id") or resource.get("ResourceId") or resource.get("Name")
        return f"{service}:{region}:{account_id}:{resource_id}"

    def _apply_identifier_pattern(
        self,
        pattern: str,
        resource: Dict[str, Any],
        region: str,
        account_id: str,
        csp: str
    ) -> Optional[str]:
        """
        Apply identifier pattern with field substitution

        Pattern examples:
        - AWS: "arn:aws:s3:::${BucketName}"
        - Azure: "/subscriptions/${SubscriptionId}/resourceGroups/${ResourceGroup}/..."
        - GCP: "projects/${ProjectId}/zones/${Zone}/instances/${InstanceName}"

        Args:
            pattern: Pattern string with ${FieldName} placeholders
            resource: Resource data dictionary
            region: Region/location
            account_id: Account/subscription/project ID
            csp: Cloud provider (aws, azure, gcp, etc.)

        Returns:
            Generated identifier string or None if pattern cannot be satisfied
        """
        def replace_field(match):
            field_name = match.group(1)

            # Handle special fields
            if field_name in ['Region', 'region']:
                return region
            elif field_name in ['AccountId', 'account']:
                return account_id
            elif field_name in ['SubscriptionId', 'subscription']:
                return account_id
            elif field_name in ['ProjectId', 'project']:
                return account_id
            else:
                # Try to get from resource data
                # Try exact match first
                value = resource.get(field_name)

                # Try case-insensitive match if not found
                if value is None:
                    for key in resource.keys():
                        if key.lower() == field_name.lower():
                            value = resource[key]
                            break

                return str(value) if value is not None else ''

        # Replace all ${FieldName} placeholders
        try:
            identifier = re.sub(r'\$\{(\w+)\}', replace_field, pattern)

            # Check if all placeholders were replaced (no empty values)
            if identifier and '${' not in identifier and identifier != pattern:
                return identifier
        except Exception as e:
            logger.warning(f"Error applying pattern '{pattern}': {e}")

        return None
    
    def _extract_aws_resource_id(self, resource: Dict[str, Any], service: str) -> str:
        """Extract AWS resource ID"""
        # Service-specific ID extraction
        if service == "s3":
            return resource.get("Name") or resource.get("BucketName") or ""
        elif service == "ec2":
            return resource.get("InstanceId") or resource.get("VolumeId") or ""
        elif service == "iam":
            return resource.get("UserName") or resource.get("RoleName") or resource.get("GroupName") or ""
        
        # Generic fallback
        return resource.get("Id") or resource.get("ResourceId") or resource.get("Name") or ""
    
    def _extract_aws_resource_type(self, resource: Dict[str, Any], service: str) -> str:
        """Extract normalized resource type"""
        # Service-specific type extraction
        if service == "s3":
            return "bucket"
        elif service == "ec2":
            if resource.get("InstanceId"):
                return "instance"
            elif resource.get("VolumeId"):
                return "volume"
            elif resource.get("SecurityGroupId"):
                return "security-group"
        elif service == "iam":
            if resource.get("UserName"):
                return "user"
            elif resource.get("RoleName"):
                return "role"
            elif resource.get("GroupName"):
                return "group"
        
        return "resource"
    
    def _extract_tags(self, resource: Dict[str, Any]) -> Dict[str, str]:
        """Extract tags from resource data (supports nested discovery structures)."""
        tags = {}

        # AWS Tags format: [{Key: ..., Value: ...}]
        if "Tags" in resource and isinstance(resource["Tags"], list):
            for tag in resource["Tags"]:
                if isinstance(tag, dict) and "Key" in tag and "Value" in tag:
                    tags[tag["Key"]] = tag["Value"]

        # Direct tags dict
        if "tags" in resource and isinstance(resource["tags"], dict):
            tags.update(resource["tags"])

        # Azure / GCP / generic tags
        if "labels" in resource and isinstance(resource["labels"], dict):
            tags.update(resource["labels"])

        # Deep search: tags inside _dependent_data (e.g. get_bucket_tagging, list_tags)
        dep_data = resource.get("_dependent_data", {})
        if isinstance(dep_data, dict):
            for op_name, op_result in dep_data.items():
                if not isinstance(op_result, dict):
                    continue
                # AWS get_bucket_tagging → {TagSet: [{Key, Value}]}
                tag_set = op_result.get("TagSet")
                if isinstance(tag_set, list):
                    for tag in tag_set:
                        if isinstance(tag, dict) and "Key" in tag and "Value" in tag:
                            tags[tag["Key"]] = str(tag["Value"])
                # AWS list_tags → {Tags: [{Key, Value}]}
                tag_list = op_result.get("Tags")
                if isinstance(tag_list, list):
                    for tag in tag_list:
                        if isinstance(tag, dict) and "Key" in tag and "Value" in tag:
                            tags[tag["Key"]] = str(tag["Value"])
                # AWS list_tags_for_resource → {tags: {k: v}}
                if "tags" in op_result and isinstance(op_result["tags"], dict):
                    tags.update(op_result["tags"])

        # Deep search: tags inside nested operation keys (get_role → {Role: {Tags: [...]}})
        for key, val in resource.items():
            if key.startswith("_") or not isinstance(val, dict):
                continue
            # Traverse one level deeper for nested dicts containing Tags
            for inner_key, inner_val in val.items():
                if isinstance(inner_val, dict):
                    inner_tags = inner_val.get("Tags")
                    if isinstance(inner_tags, list):
                        for tag in inner_tags:
                            if isinstance(tag, dict) and "Key" in tag and "Value" in tag:
                                tags[tag["Key"]] = str(tag["Value"])

        return tags

    def _flatten_emitted_fields(self, emitted_fields: Dict[str, Any], discovery_id: str) -> Dict[str, Any]:
        """
        Flatten emitted_fields that may have data nested under operation keys.

        Discovery engine stores data in three patterns:
          1. Flat:   {Name, Arn, RoleName, ...}
          2. Nested: {get_role: {Role: {Arn, RoleName, ...}}, resource_arn, _raw_response}
          3. Mixed:  {Name, BucketArn, _dependent_data: {...}, _enriched_from: [...]}

        Returns a flat dict with all resource fields merged for easy extraction.
        """
        flat = {}

        # Copy top-level scalar/simple fields (skip internal _ keys and nested dicts)
        for key, val in emitted_fields.items():
            if key.startswith("_"):
                continue
            if not isinstance(val, dict) and not isinstance(val, list):
                flat[key] = val
            elif key in ("Tags", "tags", "labels"):
                flat[key] = val  # Keep tag structures

        # Extract from nested operation keys (pattern 2: get_role → {Role: {...}})
        # The operation key matches the last part of discovery_id
        op_suffix = discovery_id.split(".")[-1] if discovery_id else ""
        for key, val in emitted_fields.items():
            if key.startswith("_") or not isinstance(val, dict):
                continue
            # Operation key matches (e.g. "get_role", "get_function")
            if key == op_suffix or key.startswith("get_") or key.startswith("describe_"):
                # Traverse nested structure to find actual resource dict
                for inner_key, inner_val in val.items():
                    if isinstance(inner_val, dict):
                        # This is the resource object (Role, Function, etc.)
                        for rk, rv in inner_val.items():
                            if rk not in flat and not isinstance(rv, (dict, list)):
                                flat[rk] = rv
                            elif rk in ("Tags", "tags", "labels") and rk not in flat:
                                flat[rk] = rv
                    elif not isinstance(inner_val, list) and inner_key not in flat:
                        flat[inner_key] = inner_val

        # Also include raw_response if it has useful top-level fields
        raw_resp = emitted_fields.get("_raw_response", {})
        if isinstance(raw_resp, dict):
            for key, val in raw_resp.items():
                if key not in flat and not isinstance(val, (dict, list)):
                    flat[key] = val
                elif key in ("Tags", "tags") and key not in flat:
                    flat[key] = val

        return flat
    
    def normalize_from_discovery(
        self,
        discovery_record: Dict[str, Any],
        raw_ref: str,
        skip_classification: bool = False
    ) -> Optional[Asset]:
        """
        Normalize a discovery record to an Asset.

        Args:
            discovery_record: Discovery record from configscan-engine
            raw_ref: Reference to source file
            skip_classification: If True, skip classification check (caller already filtered).
                                Used by the two-pass orchestrator which classifies externally.

        Returns:
            Asset or None if record doesn't represent a resource
        """
        # Extract metadata from discovery record
        provider_str = discovery_record.get("provider", "aws")
        provider = Provider(provider_str.lower())
        # Split-engine discovery records use hierarchy_id (account) rather than account_id
        account_id = discovery_record.get("account_id") or discovery_record.get("hierarchy_id")
        region = discovery_record.get("region")
        service = discovery_record.get("service")
        resource_arn = discovery_record.get("resource_arn")
        resource_id = discovery_record.get("resource_id")
        discovery_id = discovery_record.get("discovery_id", "")

        # Use classification index to determine if this should be inventoried
        # (skip if caller already filtered — e.g. two-pass orchestrator)
        if not skip_classification:
            decision = self.classifier.classify_discovery_record(discovery_record)

            # Filter based on classification decision
            if decision == InventoryDecision.FILTER:
                return None  # Don't inventory ephemeral/config-only resources

            if decision == InventoryDecision.ENRICHMENT_ONLY:
                return None  # Use for enrichment only, don't create asset

        # Extract emitted fields (actual resource data)
        emitted_fields = discovery_record.get("emitted_fields", {})
        # Merge raw_response as fallback field source so relationship builder
        # can find AWS native fields (SecurityGroups, BlockDeviceMappings, etc.)
        # emitted_fields explicit extractions take priority over raw API response
        raw_response = discovery_record.get("raw_response")
        if isinstance(raw_response, dict) and isinstance(emitted_fields, dict):
            emitted_fields = {**raw_response, **emitted_fields}

        # Normalize based on provider
        if provider == Provider.AWS:
            return self._normalize_aws_discovery(
                discovery_record, emitted_fields, account_id, region, service, raw_ref
            )

        # Generic normalization for non-AWS providers (Azure, GCP, K8s, OCI, IBM, Alicloud)
        # Uses resource_uid from discovery_findings directly
        return self._normalize_generic_discovery(
            discovery_record, emitted_fields, provider, account_id, region, service, raw_ref
        )
    
    def _normalize_aws_discovery(
        self,
        discovery_record: Dict[str, Any],
        emitted_fields: Dict[str, Any],
        account_id: str,
        region: Optional[str],
        service: str,
        raw_ref: str
    ) -> Optional[Asset]:
        """
        Normalize AWS discovery record.

        emitted_fields from the discovery engine has three patterns:
          1. Flat:   {Name, Arn, RoleName, resource_arn, _dependent_data, _enriched_from}
          2. Nested: {get_role: {Role: {Arn, RoleName,...}}, resource_arn, _raw_response}
          3. Mixed:  {Name, BucketArn, _dependent_data: {get_bucket_versioning: {...}}}

        Root/independent operations (list_roles, list_buckets) carry the primary resource
        identity at top level. Dependent operations (get_role, get_bucket_acl) store
        enrichment data inside _dependent_data.
        """
        discovery_id = discovery_record.get("discovery_id", "")

        # Flatten nested operation keys to get a uniform dict
        flat = self._flatten_emitted_fields(emitted_fields, discovery_id)

        # --- Resource ARN / UID ---
        resource_arn = discovery_record.get("resource_arn") or discovery_record.get("resource_uid")
        if not resource_arn:
            resource_arn = (
                emitted_fields.get("resource_arn") or
                flat.get("Arn") or flat.get("ARN") or
                flat.get("BucketArn") or flat.get("FunctionArn") or
                flat.get("SecurityGroupRuleArn")
            )

        # --- Resource ID (human-friendly identifier) ---
        resource_id = discovery_record.get("resource_id")
        if not resource_id:
            resource_id = (
                flat.get("Name") or flat.get("BucketName") or
                flat.get("RoleName") or flat.get("UserName") or flat.get("GroupName") or
                flat.get("PolicyName") or flat.get("FunctionName") or
                flat.get("InstanceId") or flat.get("VolumeId") or
                flat.get("SecurityGroupId") or flat.get("VpcId") or flat.get("SubnetId") or
                flat.get("DBInstanceIdentifier") or flat.get("ClusterIdentifier") or
                flat.get("InstanceProfileName") or flat.get("InstanceProfileId") or
                flat.get("Id") or flat.get("ResourceId") or
                emitted_fields.get("resource_name") or
                emitted_fields.get("resource_id")
            )

        if not resource_arn and not resource_id:
            return None

        # --- Resource Type ---
        resource_type = self._extract_aws_resource_type_from_discovery(flat, service, resource_arn)

        # --- Name (human-readable) ---
        name = (
            flat.get("Name") or flat.get("BucketName") or
            flat.get("RoleName") or flat.get("UserName") or flat.get("GroupName") or
            flat.get("PolicyName") or flat.get("FunctionName") or
            flat.get("DBInstanceIdentifier") or flat.get("ClusterIdentifier") or
            flat.get("InstanceProfileName") or
            flat.get("GroupId") or flat.get("SecurityGroupId") or
            emitted_fields.get("resource_name") or
            resource_id
        )

        # Fallback: extract name from ARN (e.g. arn:aws:iam::123:user/admin → admin)
        if not name and resource_arn and resource_arn.startswith("arn:"):
            arn_parts = resource_arn.split(":")
            if len(arn_parts) >= 6:
                resource_part = arn_parts[5]
                if "/" in resource_part:
                    name = resource_part.split("/")[-1]
                elif resource_part:
                    name = resource_part

        # --- Tags ---
        tags = self._extract_tags(emitted_fields)
        # Also try flat fields for tags that the flat extractor kept
        if not tags:
            tags = self._extract_tags(flat)

        # --- Scope ---
        if region in ["global", None]:
            scope = Scope.GLOBAL
        elif service in ["iam", "s3", "cloudfront", "route53", "organizations", "account"]:
            scope = Scope.GLOBAL
        else:
            scope = Scope.REGIONAL

        # --- Region ---
        if region in ["global", None, ""]:
            region = (
                flat.get("BucketRegion") or flat.get("Region") or
                emitted_fields.get("BucketRegion") or
                None
            )
            # Try extracting region from ARN (field 3)
            if not region and resource_arn and resource_arn.startswith("arn:"):
                arn_parts = resource_arn.split(":")
                if len(arn_parts) >= 4 and arn_parts[3]:
                    region = arn_parts[3]
            region = region or "global"

        # --- Configuration / Properties from dependent data ---
        configuration = {}
        dep_data = emitted_fields.get("_dependent_data", {})
        if isinstance(dep_data, dict):
            for dep_op, dep_result in dep_data.items():
                if isinstance(dep_result, dict):
                    configuration[dep_op] = dep_result

        # --- Build metadata ---
        metadata = {
            "created_at": flat.get("CreationDate") or flat.get("CreateDate"),
            "labels": {},
            "raw_refs": [raw_ref],
            "discovery_id": discovery_id,
            "scan_timestamp": discovery_record.get("scan_timestamp"),
            "enriched_from": emitted_fields.get("_enriched_from", []),
            "configuration": configuration,
            "emitted_fields": emitted_fields,
        }

        # --- Generate ARN if missing ---
        if not resource_arn:
            resource_arn = self._generate_arn_from_fields(flat, service, account_id, region)

        # --- Create asset ---
        asset = Asset(
            tenant_id=self.tenant_id,
            scan_run_id=self.scan_run_id,
            provider=Provider.AWS,
            account_id=account_id,
            region=region or "global",
            scope=scope,
            resource_type=resource_type,
            resource_id=resource_id or "",
            resource_uid=resource_arn or f"{service}:{region}:{account_id}:{resource_id}",
            name=name,
            tags=tags,
            metadata=metadata,
            hash_sha256="",
        )

        asset.hash_sha256 = compute_asset_hash(asset)
        return asset
    
    def _normalize_generic_discovery(
        self,
        discovery_record: Dict[str, Any],
        emitted_fields: Dict[str, Any],
        provider: 'Provider',
        account_id: str,
        region: Optional[str],
        service: str,
        raw_ref: str
    ) -> Optional[Asset]:
        """
        Generic normalizer for non-AWS providers (Azure, GCP, K8s, OCI, IBM, Alicloud).

        Uses resource_uid from the discovery record directly (no ARN construction needed).
        Resource type is derived from service + discovery_id or emitted_fields.
        """
        resource_uid = discovery_record.get("resource_uid", "")
        resource_arn = discovery_record.get("resource_arn", "")
        resource_id = discovery_record.get("resource_id", "")
        discovery_id = discovery_record.get("discovery_id", "")

        # Must have at least one identifier
        uid = resource_uid or resource_arn or resource_id
        if not uid:
            return None

        # Extract resource type from discovery_id or emitted fields
        resource_type = self._extract_generic_resource_type(
            discovery_id, emitted_fields, service, provider
        )

        # Extract name
        name = (
            emitted_fields.get("Name") or
            emitted_fields.get("name") or
            emitted_fields.get("display_name") or
            emitted_fields.get("displayName") or
            resource_id or
            uid
        )

        # Extract tags
        tags = self._extract_tags(emitted_fields)

        # Normalize region
        if region in ["global", None, ""]:
            region = emitted_fields.get("location") or emitted_fields.get("region") or "global"

        # Determine scope
        scope = Scope.GLOBAL if region == "global" else Scope.REGIONAL

        # Build metadata
        metadata = {
            "created_at": emitted_fields.get("creationTimestamp") or emitted_fields.get("timeCreated"),
            "labels": emitted_fields.get("labels", {}),
            "raw_refs": [raw_ref],
            "discovery_id": discovery_id,
            "scan_timestamp": discovery_record.get("scan_timestamp"),
            "emitted_fields": emitted_fields
        }

        # Create asset
        asset = Asset(
            tenant_id=self.tenant_id,
            scan_run_id=self.scan_run_id,
            provider=provider,
            account_id=account_id or "",
            region=region or "global",
            scope=scope,
            resource_type=resource_type,
            resource_id=resource_id or uid,
            resource_uid=uid,
            name=name,
            tags=tags,
            metadata=metadata,
            hash_sha256=""
        )

        asset.hash_sha256 = compute_asset_hash(asset)
        return asset

    def _extract_generic_resource_type(
        self,
        discovery_id: str,
        emitted_fields: Dict[str, Any],
        service: str,
        provider: 'Provider'
    ) -> str:
        """Extract resource type for non-AWS providers from discovery_id or emitted fields."""
        # Try emitted fields first
        for field in ["resourceType", "resource_type", "type", "Type", "kind"]:
            if field in emitted_fields and emitted_fields[field]:
                val = str(emitted_fields[field])
                return f"{service}.{val}" if not val.startswith(service) else val

        # Extract from discovery_id: e.g., azure.compute.list_virtual_machines → compute.virtual_machines
        if discovery_id:
            parts = discovery_id.split(".")
            # Remove CSP prefix and operation prefix (list_, describe_, get_)
            if len(parts) >= 3:
                svc = parts[-2] if len(parts) > 2 else service
                op_name = parts[-1]
                # Strip common operation prefixes to get resource type
                for prefix in ["list_", "describe_", "get_", "list", "describe", "get"]:
                    if op_name.lower().startswith(prefix):
                        resource = op_name[len(prefix):]
                        if resource:
                            return f"{service}.{resource}"
                return f"{service}.{op_name}"

        return f"{service}.resource"

    def _extract_aws_resource_type_from_discovery(
        self,
        fields: Dict[str, Any],
        service: str,
        resource_arn: Optional[str] = None
    ) -> str:
        """
        Extract resource type from flat emitted fields or ARN.

        Uses multiple strategies:
          1. ARN resource-type segment (e.g. arn:aws:iam::123:role/name → iam.role)
          2. Known field signatures (RoleName → iam.role, InstanceId → ec2.instance)
          3. DB-based index resolution
          4. Fallback to service.resource
        """
        # --- ARN-based type extraction ---
        if resource_arn and resource_arn.startswith("arn:"):
            arn_parts = resource_arn.split(":")
            if len(arn_parts) >= 6:
                resource_part = arn_parts[5]
                if "/" in resource_part:
                    arn_type = resource_part.split("/")[0]
                    if arn_type:
                        return f"{service}.{arn_type}"
                elif resource_part and ":::" in resource_arn:
                    # S3-style ARN: arn:aws:s3:::bucket-name
                    return f"{service}.bucket"

        # --- Known field signatures ---
        _FIELD_TO_TYPE = {
            "BucketName": "bucket", "BucketArn": "bucket",
            "InstanceId": "instance",
            "VolumeId": "volume",
            "SecurityGroupId": "security-group", "GroupId": "security-group",
            "SecurityGroupRuleId": "security-group-rule",
            "VpcId": "vpc",
            "SubnetId": "subnet",
            "NatGatewayId": "nat-gateway",
            "InternetGatewayId": "internet-gateway",
            "RouteTableId": "route-table",
            "NetworkAclId": "network-acl",
            "TransitGatewayId": "transit-gateway",
            "FlowLogId": "flow-log",
            "UserName": "user",
            "RoleName": "role", "RoleId": "role",
            "GroupName": "group",
            "PolicyName": "policy", "PolicyId": "policy",
            "InstanceProfileName": "instance-profile", "InstanceProfileId": "instance-profile",
            "FunctionName": "function", "FunctionArn": "function",
            "DBInstanceIdentifier": "db-instance",
            "ClusterIdentifier": "cluster",
            "DistributionId": "distribution",
            "HostedZoneId": "hosted-zone",
            "CertificateArn": "certificate",
            "TopicArn": "topic",
            "QueueUrl": "queue",
            "TableName": "table",
            "StreamName": "stream",
        }

        for field_name, rtype in _FIELD_TO_TYPE.items():
            if field_name in fields and fields[field_name]:
                return f"{service}.{rtype}"

        # --- S3 service default ---
        if service == "s3" and ("Name" in fields or "BucketRegion" in fields):
            return "s3.bucket"

        # --- DB-based index resolution ---
        if self.classifier:
            resolved = self.classifier.resolve_resource_type(service, fields, resource_arn or "")
            if resolved:
                return f"{service}.{resolved}"

        return f"{service}.resource"
    
    def enrich_asset(self, asset: Asset, discovery_record: Dict[str, Any]) -> Asset:
        """
        Enrich an existing asset with data from a dependent/enrichment discovery record.

        Dependent discovery records (get_bucket_versioning, get_role, etc.) carry
        operation-specific configuration data that should be merged into the asset's
        metadata.configuration dict.

        The root discovery's _dependent_data may already contain this data, but separate
        dependent discovery records can have additional/different data.

        Args:
            asset: Existing asset to enrich
            discovery_record: Dependent discovery record

        Returns:
            Enriched asset (same object, mutated)
        """
        discovery_id = discovery_record.get("discovery_id", "")
        emitted_fields = discovery_record.get("emitted_fields", {})

        if not isinstance(emitted_fields, dict):
            return asset

        # Extract the operation suffix (e.g. "get_bucket_versioning" from "aws.s3.get_bucket_versioning")
        op_suffix = discovery_id.split(".")[-1] if discovery_id else ""

        # Ensure metadata.configuration exists
        if not asset.metadata:
            asset.metadata = {}
        if "configuration" not in asset.metadata:
            asset.metadata["configuration"] = {}
        configuration = asset.metadata["configuration"]

        # --- Extract operation-specific data ---
        # Pattern 1: Data is directly in emitted_fields under op_suffix key
        #   e.g. get_bucket_versioning: {get_bucket_versioning: {Status: "Enabled", ...}}
        if op_suffix and op_suffix in emitted_fields:
            op_data = emitted_fields[op_suffix]
            if isinstance(op_data, dict) and op_suffix not in configuration:
                configuration[op_suffix] = op_data

        # Pattern 2: Data is in _raw_response
        raw_resp = emitted_fields.get("_raw_response", {})
        if isinstance(raw_resp, dict) and raw_resp and op_suffix not in configuration:
            configuration[op_suffix] = raw_resp

        # Pattern 3: Also check for nested operation keys (get_, describe_)
        for key, val in emitted_fields.items():
            if key.startswith("_") or not isinstance(val, dict):
                continue
            if key.startswith("get_") or key.startswith("describe_") or key.startswith("list_"):
                if key not in configuration:
                    configuration[key] = val

        # --- Extract tags from enrichment record ---
        enrichment_tags = self._extract_tags(emitted_fields)
        if enrichment_tags:
            if not asset.tags:
                asset.tags = {}
            asset.tags.update(enrichment_tags)

        # --- Track enrichment source ---
        if "enriched_from" not in asset.metadata:
            asset.metadata["enriched_from"] = []
        if discovery_id not in asset.metadata["enriched_from"]:
            asset.metadata["enriched_from"].append(discovery_id)

        return asset

    def extract_enrichment_uid(self, discovery_record: Dict[str, Any]) -> Optional[str]:
        """
        Extract the resource UID that an enrichment record refers to.

        This is used to match enrichment records to existing assets during two-pass
        orchestration.

        Args:
            discovery_record: Enrichment discovery record

        Returns:
            Resource UID (ARN or UID) of the parent resource, or None
        """
        # Enrichment records share the same resource_arn/resource_uid as their root
        resource_arn = discovery_record.get("resource_arn")
        resource_uid = discovery_record.get("resource_uid")
        return resource_arn or resource_uid or None

    def _generate_arn_from_fields(self, fields: Dict[str, Any], service: str, account_id: str, region: str) -> Optional[str]:
        """Generate ARN from flat fields if possible."""
        # Try existing ARN fields first
        arn = (
            fields.get("Arn") or fields.get("ARN") or
            fields.get("BucketArn") or fields.get("FunctionArn") or
            fields.get("SecurityGroupRuleArn") or fields.get("TopicArn") or
            fields.get("CertificateArn") or fields.get("PolicyArn")
        )
        if arn:
            return arn

        # Service-specific ARN generation
        region = region or "global"
        if service == "s3":
            name = fields.get("Name") or fields.get("BucketName")
            if name:
                return f"arn:aws:s3:::{name}"
        elif service == "ec2":
            iid = fields.get("InstanceId")
            if iid:
                return f"arn:aws:ec2:{region}:{account_id}:instance/{iid}"
            vid = fields.get("VolumeId")
            if vid:
                return f"arn:aws:ec2:{region}:{account_id}:volume/{vid}"
            sgid = fields.get("SecurityGroupId") or fields.get("GroupId")
            if sgid:
                return f"arn:aws:ec2:{region}:{account_id}:security-group/{sgid}"
            vpcid = fields.get("VpcId")
            if vpcid:
                return f"arn:aws:ec2:{region}:{account_id}:vpc/{vpcid}"
            subid = fields.get("SubnetId")
            if subid:
                return f"arn:aws:ec2:{region}:{account_id}:subnet/{subid}"
        elif service == "iam":
            user = fields.get("UserName")
            if user:
                return f"arn:aws:iam::{account_id}:user/{user}"
            role = fields.get("RoleName")
            if role:
                path = fields.get("Path", "/")
                return f"arn:aws:iam::{account_id}:role{path}{role}" if path != "/" else f"arn:aws:iam::{account_id}:role/{role}"
            group = fields.get("GroupName")
            if group:
                return f"arn:aws:iam::{account_id}:group/{group}"
            policy = fields.get("PolicyName")
            if policy and fields.get("PolicyId"):
                return f"arn:aws:iam::{account_id}:policy/{policy}"
            ip_name = fields.get("InstanceProfileName")
            if ip_name:
                return f"arn:aws:iam::{account_id}:instance-profile/{ip_name}"
        elif service == "lambda":
            fn_name = fields.get("FunctionName")
            if fn_name:
                return f"arn:aws:lambda:{region}:{account_id}:function:{fn_name}"
        elif service == "rds":
            db_id = fields.get("DBInstanceIdentifier")
            if db_id:
                return f"arn:aws:rds:{region}:{account_id}:db:{db_id}"

        return None

