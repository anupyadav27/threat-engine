"""
Generic Discovery to Resource Mapping
Uses service_list.json as single source of truth for ARN patterns and resource types.
No service-specific hardcoding.
"""

import json
import os
import re
from typing import Dict, List, Tuple, Optional, Any
from pathlib import Path

def _config_dir() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "config"))


def load_service_config(service_name: str) -> Optional[Dict]:
    """Load service configuration from service_list.json"""
    config_path = os.path.join(_config_dir(), "service_list.json")
    
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        
        for svc in config.get("services", []):
            if svc["name"] == service_name:
                return svc
    except Exception as e:
        return None
    
    return None


def infer_resource_type_from_discovery(discovery_id: str, service_config: Dict = None) -> Optional[str]:
    """
    Infer resource type from discovery ID using service_list.json.
    
    Args:
        discovery_id: e.g., "aws.apigateway.get_rest_apis"
        service_config: Optional pre-loaded service config
    
    Returns:
        resource_type (e.g., "restapi", "apikey") or None
    """
    # Extract service and operation from discovery_id
    parts = discovery_id.split('.')
    if len(parts) < 3:
        return None
    
    service = parts[1]
    operation = parts[2]  # e.g., "get_rest_apis", "describe_fpga_images"
    
    # Load service config if not provided
    if not service_config:
        service_config = load_service_config(service)
    
    if not service_config:
        return None
    
    # Get resource types from service config
    resource_types = service_config.get("resource_types", [])
    if not resource_types:
        return None
    
    # Remove common prefixes from operation
    operation_clean = operation
    for prefix in ["describe_", "list_", "get_"]:
        if operation_clean.startswith(prefix):
            operation_clean = operation_clean[len(prefix):]
            break
    
    # Convert snake_case to hyphenated
    if "_" in operation_clean:
        operation_parts = operation_clean.split("_")
        # Remove plural suffixes
        if operation_parts[-1].endswith("s") and len(operation_parts[-1]) > 1:
            operation_parts[-1] = operation_parts[-1][:-1]
        operation_normalized = "-".join(operation_parts)
    else:
        operation_normalized = operation_clean
    
    # Try to match against resource_types in service config
    for resource_type in resource_types:
        # Exact match
        if resource_type == operation_normalized:
            return resource_type
        
        # Partial match (e.g., "rest-api" matches "restapi")
        if resource_type.replace("-", "") == operation_normalized.replace("-", ""):
            return resource_type
        
        # Plural match (e.g., "apis" matches "api")
        if operation_normalized.endswith("s") and resource_type == operation_normalized[:-1]:
            return resource_type
    
    # If no exact match, return first resource type (best guess)
    return resource_types[0] if resource_types else None


def infer_id_field_from_resource_type(resource_type: str, emitted_fields: Dict) -> Optional[str]:
    """
    Infer which field contains the resource ID from emitted_fields.
    Generic approach - tries common patterns.
    
    Args:
        resource_type: e.g., "restapi", "apikey", "fpga-image"
        emitted_fields: Dict of emitted fields from discovery
    
    Returns:
        field name containing the ID, or None
    """
    # Common ID field patterns (ordered by priority)
    id_patterns = [
        # Exact matches (case-sensitive, try lowercase first as API Gateway uses lowercase)
        'id',
        'Id',
        'ID',
        
        # Resource-specific patterns
        f'{resource_type}Id',
        f'{resource_type}_id',
        f'{resource_type.replace("-", "")}Id',
        f'{resource_type.replace("-", "").capitalize()}Id',
        
        # Generic patterns
        'ResourceId',
        'resource_id',
        'Name',
        'name',
        'ResourceName',
        'resource_name',
        
        # Category/Tag specific (for metadata resources)
        'TagKey',  # Cost allocation tags
        'CategoryName',  # Event categories
        'SourceId',  # Source identifiers
        
        # ARN fields (if ID is not found)
        'Arn',
        'arn',
        'ARN',
        'ResourceArn',
        'resource_arn',
    ]
    
    # Try each pattern
    for pattern in id_patterns:
        if pattern in emitted_fields:
            value = emitted_fields[pattern]
            if value:  # Not None, not empty string
                return pattern
    
    return None


def is_account_level_configuration(discovery_id: str) -> bool:
    """
    Determine if a discovery represents account-level configuration (not a resource).
    
    Args:
        discovery_id: e.g., "aws.glue.get_data_catalog_encryption_settings"
    
    Returns:
        True if account-level configuration
    """
    # Universal patterns for account-level configurations
    account_level_patterns = [
        # Settings and configurations
        r'.*_settings?$',
        r'.*_configuration$',
        r'.*_config$',
        r'.*_policies$',
        r'.*_policy$',
        
        # Account attributes
        r'.*account_attributes?$',
        r'.*account_information$',
        r'.*contact.*',
        
        # Block/access controls
        r'.*block_public_access.*',
        r'.*public_access_block.*',
        
        # Status and endpoints
        r'.*_status$',
        r'.*_endpoints?$',
        
        # Metadata and tags
        r'.*describe_regions$',
        r'.*describe_availability_zones$',
        r'.*allocation_tags$',  # Cost allocation tags
        r'.*_tags$',
        
        # Categories and events (metadata, not resources)
        r'.*_categories$',
        r'.*event_categories$',
        
        # Catalogs (metadata lists)
        r'.*get_catalogs$',
        r'.*list_catalogs$',
    ]
    
    # Extract operation from discovery_id
    parts = discovery_id.split('.')
    if len(parts) < 3:
        return False
    
    operation = parts[2]
    
    # Check against patterns
    for pattern in account_level_patterns:
        if re.match(pattern, operation, re.IGNORECASE):
            return True
    
    return False


def get_discovery_mapping(discovery_id: str, emitted_fields: Dict = None) -> Tuple[Optional[str], List[str], List[str]]:
    """
    Get resource type, ARN patterns, and ID patterns for a discovery operation.
    Uses extraction_patterns from service_list.json.
    
    Args:
        discovery_id: e.g., "aws.apigateway.get_rest_apis"
        emitted_fields: Optional dict of emitted fields (for better field detection)
    
    Returns:
        (resource_type, arn_patterns, id_patterns) tuple
        - resource_type: e.g., "restapi", "apikey", or None for account-level
        - arn_patterns: List of field names that might contain ARN directly
        - id_patterns: List of field names that could contain the ID
    """
    # Check if account-level configuration
    if is_account_level_configuration(discovery_id):
        return (None, [], [])
    
    # Extract service from discovery_id
    parts = discovery_id.split('.')
    if len(parts) < 2:
        return (None, [], [])
    
    service = parts[1]
    
    # Load service config
    service_config = load_service_config(service)
    if not service_config:
        return (None, [], [])
    
    # Infer resource type
    resource_type = infer_resource_type_from_discovery(discovery_id, service_config)
    if not resource_type:
        return (None, [], [])
    
    # Get extraction patterns from service config
    extraction_patterns = service_config.get('extraction_patterns', {})
    resource_patterns = extraction_patterns.get(resource_type, {})
    
    # Get ARN and ID patterns from config (fallback to generic if not found)
    arn_patterns = resource_patterns.get('arn_fields', ['Arn', 'ARN', 'arn', 'ResourceArn'])
    id_patterns = resource_patterns.get('id_fields', ['id', 'Id', 'ID', 'ResourceId', 'Name', 'name'])
    
    # If emitted_fields provided, try to find the actual field and prioritize it
    if emitted_fields:
        # Check which ARN field actually exists
        for arn_field in arn_patterns[:]:
            if arn_field in emitted_fields and emitted_fields[arn_field]:
                # Move to front
                arn_patterns = [arn_field] + [p for p in arn_patterns if p != arn_field]
                break
        
        # Check which ID field actually exists
        for id_field in id_patterns[:]:
            if id_field in emitted_fields and emitted_fields[id_field]:
                # Move to front
                id_patterns = [id_field] + [p for p in id_patterns if p != id_field]
                break
    
    return (resource_type, arn_patterns, id_patterns)


def extract_resource_id_from_emitted(emitted_fields: Dict, id_patterns: List[str]) -> Optional[str]:
    """
    Extract resource ID from emitted_fields using pattern list.
    
    Args:
        emitted_fields: Dict of emitted fields
        id_patterns: List of field names to try
    
    Returns:
        Resource ID value or None
    """
    for pattern in id_patterns:
        if pattern in emitted_fields:
            value = emitted_fields[pattern]
            if value:
                return str(value)
    
    return None


def extract_resource_arn_from_emitted(emitted_fields: Dict, arn_patterns: List[str]) -> Optional[str]:
    """
    Extract resource ARN from emitted_fields using pattern list.
    
    Args:
        emitted_fields: Dict of emitted fields
        arn_patterns: List of field names to try
    
    Returns:
        Resource ARN value or None
    """
    for pattern in arn_patterns:
        if pattern in emitted_fields:
            value = emitted_fields[pattern]
            if value and isinstance(value, str) and value.startswith('arn:aws:'):
                return value
    
    return None
