"""
Resource Classifier

Uses pre-built classification index from pythonsdk-database to determine
if a discovery record should be inventoried, used for enrichment only, or filtered.
"""

import json
import re
from pathlib import Path
from typing import Dict, Any, Optional
from enum import Enum


class ResourceClassification(Enum):
    """Resource classification types"""
    PRIMARY = "primary"           # Should inventory
    SUB_RESOURCE = "sub_resource" # Don't inventory (enrichment only)
    EPHEMERAL = "ephemeral"       # Don't inventory
    CONFIG = "config"             # Don't inventory (enrichment only)
    UNKNOWN = "unknown"           # Default to inventory if has ARN


class InventoryDecision(Enum):
    """Final decision on whether to inventory"""
    INVENTORY = "inventory"           # Create asset
    ENRICHMENT_ONLY = "enrichment"    # Use for enrichment, don't create asset
    FILTER = "filter"                 # Ignore completely


class ResourceClassifier:
    """Classifies discovery records using pre-built classification index"""
    
    def __init__(self, index_path: Optional[Path] = None):
        """
        Initialize classifier with classification index.
        
        Args:
            index_path: Path to classification index JSON file.
                       Default: inventory_engine/config/aws_inventory_classification_index.json
        """
        if index_path is None:
            # Default to config directory
            base_path = Path(__file__).parent.parent
            index_path = base_path / "config" / "aws_inventory_classification_index.json"
        
        self.index_path = index_path
        self.index = self._load_index()
    
    def _load_index(self) -> Dict[str, Any]:
        """Load classification index from file"""
        if not self.index_path.exists():
            # Return empty index if file doesn't exist
            return {
                "classifications": {
                    "by_discovery_operation": {},
                    "by_service_resource": {},
                    "by_service": {},
                    "ephemeral_operations": [],
                    "config_operations": [],
                    "sub_resource_operations": []
                }
            }
        
        try:
            with open(self.index_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: Failed to load classification index: {e}")
            return {
                "classifications": {
                    "by_discovery_operation": {},
                    "by_service_resource": {},
                    "by_service": {},
                    "ephemeral_operations": [],
                    "config_operations": [],
                    "sub_resource_operations": []
                }
            }
    
    def normalize_discovery_id(self, discovery_id: str) -> str:
        """Normalize discovery ID to match index format"""
        # Remove aws. prefix if present
        if discovery_id.startswith("aws."):
            return discovery_id[4:].lower()
        return discovery_id.lower()
    
    def classify_discovery_record(self, discovery_record: Dict[str, Any]) -> InventoryDecision:
        """
        Classify a discovery record and return inventory decision.
        
        Args:
            discovery_record: Discovery record from configscan-engine
        
        Returns:
            InventoryDecision enum value
        """
        discovery_id = discovery_record.get("discovery_id", "")
        service = discovery_record.get("service", "")
        resource_arn = discovery_record.get("resource_arn", "")
        resource_id = discovery_record.get("resource_id", "")
        emitted_fields = discovery_record.get("emitted_fields", {})
        
        # Step 1: Check if record has resource identifier
        if not resource_arn and not resource_id:
            return InventoryDecision.FILTER  # No resource to inventory
        
        # Step 2: Check discovery operation in index
        normalized_id = self.normalize_discovery_id(discovery_id)
        
        # Check ephemeral operations list
        ephemeral_ops = self.index["classifications"].get("ephemeral_operations", [])
        if normalized_id in ephemeral_ops:
            return InventoryDecision.FILTER
        
        # Check config operations list
        config_ops = self.index["classifications"].get("config_operations", [])
        if normalized_id in config_ops:
            return InventoryDecision.ENRICHMENT_ONLY
        
        # Check sub-resource operations list
        sub_resource_ops = self.index["classifications"].get("sub_resource_operations", [])
        if normalized_id in sub_resource_ops:
            return InventoryDecision.ENRICHMENT_ONLY
        
        # Check by_discovery_operation mapping
        op_classification = self.index["classifications"]["by_discovery_operation"].get(normalized_id)
        if op_classification:
            if not op_classification.get("should_inventory", False):
                # Check if it's for enrichment
                if op_classification.get("use_for_enrichment", False):
                    return InventoryDecision.ENRICHMENT_ONLY
                return InventoryDecision.FILTER
            # Should inventory
            return InventoryDecision.INVENTORY
        
        # Step 3: Try to classify by service + resource type
        if service:
            # Try to extract resource type from emitted fields or ARN
            resource_type = self._extract_resource_type(emitted_fields, resource_arn, service)
            if resource_type:
                service_resource_key = f"{service}.{resource_type}"
                resource_classification = self.index["classifications"]["by_service_resource"].get(service_resource_key)
                if resource_classification:
                    if not resource_classification.get("should_inventory", False):
                        if resource_classification.get("use_for_enrichment", False):
                            return InventoryDecision.ENRICHMENT_ONLY
                        return InventoryDecision.FILTER
                    return InventoryDecision.INVENTORY
        
        # Step 4: Default decision - if has ARN, likely a primary resource
        if resource_arn:
            # Additional check: filter known ephemeral ARN patterns
            if self._is_ephemeral_arn(resource_arn):
                return InventoryDecision.FILTER
            return InventoryDecision.INVENTORY
        
        # Step 5: If no ARN but has ID, check if it's a list/describe operation
        if resource_id:
            if any(op in discovery_id.lower() for op in ["list_", "describe_"]):
                return InventoryDecision.INVENTORY
        
        # Default: filter if we can't determine
        return InventoryDecision.FILTER
    
    def _extract_resource_type(self, emitted_fields: Dict[str, Any], resource_arn: str, service: str) -> Optional[str]:
        """Extract resource type from emitted fields or ARN"""
        # Try ARN pattern first
        if resource_arn:
            # Extract from ARN: arn:aws:service:region:account:resource-type/resource-id
            arn_parts = resource_arn.split(":")
            if len(arn_parts) >= 6:
                resource_part = arn_parts[5]
                # Handle format like "security-group-rule/sgr-xxx" or "hub/default"
                if "/" in resource_part:
                    resource_type = resource_part.split("/")[0]
                    # Normalize: security-group-rule -> security_group_rule
                    resource_type = resource_type.replace("-", "_")
                    return resource_type
        
        # Try common field names
        for field in ["ResourceType", "resource_type", "Type", "type"]:
            if field in emitted_fields:
                return str(emitted_fields[field]).lower()
        
        return None

    def get_service_summary(self, service: str) -> Dict[str, Any]:
        """Return service-level classification summary if available."""
        return self.index["classifications"].get("by_service", {}).get(service, {})

    def resolve_resource_type(self, service: str, emitted_fields: Dict[str, Any], resource_arn: str) -> Optional[str]:
        """
        Resolve a specific resource type for a service using the classification index.

        Returns:
            resource_type string (without service prefix) or None
        """
        service_summary = self.get_service_summary(service)
        if not service_summary:
            return None

        candidate_types = (
            service_summary.get("primary_resources", []) +
            service_summary.get("ephemeral_resources", []) +
            service_summary.get("config_resources", []) +
            service_summary.get("sub_resources", [])
        )
        if not candidate_types:
            return None

        # Try to extract from ARN resource part
        arn_type = self._extract_resource_type(emitted_fields, resource_arn, service)
        if arn_type and arn_type in candidate_types:
            # Check if we have normalized_type in index
            service_resource_key = f"{service}.{arn_type}"
            resource_info = self.index["classifications"]["by_service_resource"].get(service_resource_key)
            if resource_info and resource_info.get("normalized_type"):
                return resource_info["normalized_type"]
            return arn_type

        # Try to match resource type by emitted fields
        for field in ["ResourceType", "resource_type", "Type", "type"]:
            if field in emitted_fields:
                value = str(emitted_fields[field]).lower().replace("-", "_")
                if value in candidate_types:
                    # Check for normalized_type
                    service_resource_key = f"{service}.{value}"
                    resource_info = self.index["classifications"]["by_service_resource"].get(service_resource_key)
                    if resource_info and resource_info.get("normalized_type"):
                        return resource_info["normalized_type"]
                    return value

        # Try partial matches for common patterns
        if arn_type:
            for candidate in candidate_types:
                if arn_type in candidate or candidate in arn_type:
                    # Check for normalized_type
                    service_resource_key = f"{service}.{candidate}"
                    resource_info = self.index["classifications"]["by_service_resource"].get(service_resource_key)
                    if resource_info and resource_info.get("normalized_type"):
                        return resource_info["normalized_type"]
                    return candidate

        return None
    
    def _is_ephemeral_arn(self, resource_arn: str) -> bool:
        """Check if ARN matches ephemeral patterns"""
        arn_lower = resource_arn.lower()
        
        # Known ephemeral ARN patterns
        ephemeral_patterns = [
            r':finding/',
            r':product/',
            r':job/',
            r':task/',
            r':workflow/',
            r':request/',
        ]
        
        for pattern in ephemeral_patterns:
            if re.search(pattern, arn_lower):
                return True
        
        return False
    
    def get_classification_info(self, discovery_record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Get detailed classification information for a discovery record.
        
        Returns:
            Dict with classification details or None
        """
        discovery_id = discovery_record.get("discovery_id", "")
        normalized_id = self.normalize_discovery_id(discovery_id)
        
        # Check operation mapping
        op_info = self.index["classifications"]["by_discovery_operation"].get(normalized_id)
        if op_info:
            return op_info
        
        # Check service + resource type
        service = discovery_record.get("service", "")
        emitted_fields = discovery_record.get("emitted_fields", {})
        resource_arn = discovery_record.get("resource_arn", "")
        
        resource_type = self._extract_resource_type(emitted_fields, resource_arn, service)
        if resource_type and service:
            service_resource_key = f"{service}.{resource_type}"
            return self.index["classifications"]["by_service_resource"].get(service_resource_key)
        
        return None
