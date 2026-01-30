"""
Asset Normalizer

Transforms raw provider JSON into canonical Asset records.
"""

import json
import hashlib
from typing import List, Dict, Any, Optional
from ..schemas.asset_schema import Asset, Provider, Scope, compute_asset_hash
from ..schemas.relationship_schema import Relationship, RelationType
from .resource_classifier import ResourceClassifier, InventoryDecision


class AssetNormalizer:
    """Normalizes raw provider data to canonical assets"""
    
    def __init__(self, tenant_id: str, scan_run_id: str):
        self.tenant_id = tenant_id
        self.scan_run_id = scan_run_id
        self.classifier = ResourceClassifier()  # Initialize classifier with default index
    
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
        """Extract AWS resource UID (ARN preferred)"""
        # Try ARN first
        arn = resource.get("Arn") or resource.get("arn") or resource.get("ARN")
        if arn:
            return arn
        
        # Generate ARN if possible
        if service == "s3":
            bucket_name = resource.get("Name") or resource.get("BucketName")
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
        
        # Fallback: construct UID
        resource_id = resource.get("Id") or resource.get("ResourceId") or resource.get("Name")
        return f"{service}:{region}:{account_id}:{resource_id}"
    
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
        """Extract tags from resource"""
        tags = {}
        
        # AWS Tags format
        if "Tags" in resource and isinstance(resource["Tags"], list):
            for tag in resource["Tags"]:
                if isinstance(tag, dict) and "Key" in tag and "Value" in tag:
                    tags[tag["Key"]] = tag["Value"]
        
        # Direct tags dict
        if "tags" in resource and isinstance(resource["tags"], dict):
            tags.update(resource["tags"])
        
        return tags
    
    def normalize_from_discovery(
        self,
        discovery_record: Dict[str, Any],
        raw_ref: str
    ) -> Optional[Asset]:
        """
        Normalize a discovery record to an Asset.
        
        Args:
            discovery_record: Discovery record from configscan-engine
            raw_ref: Reference to source file
        
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
        decision = self.classifier.classify_discovery_record(discovery_record)
        
        # Filter based on classification decision
        if decision == InventoryDecision.FILTER:
            return None  # Don't inventory ephemeral/config-only resources
        
        if decision == InventoryDecision.ENRICHMENT_ONLY:
            return None  # Use for enrichment only, don't create asset
        
        # decision == InventoryDecision.INVENTORY - continue processing
        
        # Extract emitted fields (actual resource data)
        emitted_fields = discovery_record.get("emitted_fields", {})
        
        # Normalize based on provider
        if provider == Provider.AWS:
            return self._normalize_aws_discovery(
                discovery_record, emitted_fields, account_id, region, service, raw_ref
            )
        
        return None
    
    def _normalize_aws_discovery(
        self,
        discovery_record: Dict[str, Any],
        emitted_fields: Dict[str, Any],
        account_id: str,
        region: Optional[str],
        service: str,
        raw_ref: str
    ) -> Optional[Asset]:
        """Normalize AWS discovery record"""
        resource_arn = discovery_record.get("resource_arn")
        resource_id = discovery_record.get("resource_id")
        
        # Extract resource identifiers from emitted_fields
        if not resource_arn:
            resource_arn = emitted_fields.get("resource_arn") or emitted_fields.get("Arn") or emitted_fields.get("BucketArn")
        
        if not resource_id:
            resource_id = emitted_fields.get("Name") or emitted_fields.get("InstanceId") or emitted_fields.get("Id")
        
        if not resource_arn and not resource_id:
            return None
        
        # Determine resource type
        resource_type = self._extract_aws_resource_type_from_discovery(emitted_fields, service, resource_arn)
        
        # Extract name
        name = emitted_fields.get("Name") or resource_id
        
        # Extract tags
        tags = self._extract_tags(emitted_fields)
        
        # Determine scope
        if region in ["global", None]:
            scope = Scope.GLOBAL
        elif service in ["iam", "s3", "cloudfront", "route53"]:
            scope = Scope.GLOBAL
        else:
            scope = Scope.REGIONAL
        
        # Normalize region
        if region in ["global", None]:
            # Try to get region from emitted fields
            region = emitted_fields.get("BucketRegion") or emitted_fields.get("Region") or "global"
        
        # Build metadata (include emitted_fields for relationship extraction)
        metadata = {
            "created_at": emitted_fields.get("CreationDate") or emitted_fields.get("CreateDate"),
            "labels": {},
            "raw_refs": [raw_ref],
            "discovery_id": discovery_record.get("discovery_id"),
            "scan_timestamp": discovery_record.get("scan_timestamp"),
            "emitted_fields": emitted_fields  # Store for relationship extraction
        }
        
        # Generate resource_uid if not present
        if not resource_arn:
            resource_arn = self._generate_arn_from_fields(emitted_fields, service, account_id, region)
        
        # Create asset
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
            hash_sha256=""  # Will be computed
        )
        
        # Compute hash
        asset.hash_sha256 = compute_asset_hash(asset)
        
        return asset
    
    def _extract_aws_resource_type_from_discovery(
        self,
        emitted_fields: Dict[str, Any],
        service: str,
        resource_arn: Optional[str] = None
    ) -> str:
        """Extract resource type from discovery emitted fields"""
        # Try index-based resolution first (generic across services)
        if self.classifier:
            resolved = self.classifier.resolve_resource_type(service, emitted_fields, resource_arn or "")
            if resolved:
                return f"{service}.{resolved}"

        # Service-specific type extraction
        if service == "s3":
            return "s3.bucket"
        elif service == "ec2":
            if "InstanceId" in emitted_fields:
                return "ec2.instance"
            elif "VolumeId" in emitted_fields:
                return "ec2.volume"
            elif "SecurityGroupId" in emitted_fields:
                return "ec2.security-group"
            elif "VpcId" in emitted_fields:
                return "ec2.vpc"
            elif "SubnetId" in emitted_fields:
                return "ec2.subnet"
        elif service == "iam":
            if "UserName" in emitted_fields:
                return "iam.user"
            elif "RoleName" in emitted_fields:
                return "iam.role"
            elif "GroupName" in emitted_fields:
                return "iam.group"
        elif service == "rds":
            if "DBInstanceIdentifier" in emitted_fields:
                return "rds.instance"
        
        return f"{service}.resource"
    
    def _generate_arn_from_fields(self, emitted_fields: Dict[str, Any], service: str, account_id: str, region: str) -> Optional[str]:
        """Generate ARN from emitted fields if possible"""
        # Try existing ARN fields
        arn = emitted_fields.get("Arn") or emitted_fields.get("ARN") or emitted_fields.get("BucketArn")
        if arn:
            return arn
        
        # Generate ARN based on service
        if service == "s3":
            bucket_name = emitted_fields.get("Name")
            if bucket_name:
                return f"arn:aws:s3:::{bucket_name}"
        elif service == "ec2":
            instance_id = emitted_fields.get("InstanceId")
            if instance_id:
                return f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}"
        elif service == "iam":
            user_name = emitted_fields.get("UserName")
            role_name = emitted_fields.get("RoleName")
            group_name = emitted_fields.get("GroupName")
            if user_name:
                return f"arn:aws:iam::{account_id}:user/{user_name}"
            elif role_name:
                return f"arn:aws:iam::{account_id}:role/{role_name}"
            elif group_name:
                return f"arn:aws:iam::{account_id}:group/{group_name}"
        
        return None

