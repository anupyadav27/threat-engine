"""
Asset Normalizer

Transforms raw provider JSON into canonical Asset records.
"""

import json
import hashlib
from typing import List, Dict, Any, Optional
from ..schemas.asset_schema import Asset, Provider, Scope, compute_asset_hash
from ..schemas.relationship_schema import Relationship, RelationType


class AssetNormalizer:
    """Normalizes raw provider data to canonical assets"""
    
    def __init__(self, tenant_id: str, scan_run_id: str):
        self.tenant_id = tenant_id
        self.scan_run_id = scan_run_id
    
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

