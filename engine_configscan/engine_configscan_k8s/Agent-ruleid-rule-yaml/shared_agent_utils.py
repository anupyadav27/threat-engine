"""
Shared utilities for all platform agents.

Common functions used across Azure, GCP, OCI, IBM, Alibaba, and K8s agents.
"""

from typing import Dict, List, Any, Optional


def normalize_item_fields(item_fields: Any) -> Dict:
    """
    Normalize item_fields to dict format.
    Handles both old (list) and enhanced (dict) catalog formats.
    
    Args:
        item_fields: Either list of field names or dict with field metadata
    
    Returns:
        Dict with field names as keys
    """
    if isinstance(item_fields, dict):
        return item_fields
    elif isinstance(item_fields, list):
        return {f: {} for f in item_fields}
    else:
        return {}


def check_nested_field(field_path: str, available_fields: Dict) -> Dict:
    """
    Check if a field path exists in nested structure.
    Works with enhanced catalogs that have field metadata.
    
    Args:
        field_path: Field path (e.g., "properties.encryption", "iamConfiguration.publicAccessPrevention")
        available_fields: Available fields dict from enhanced catalog
    
    Returns:
        Validation result dict with 'exists', 'correct_name', 'validation', etc.
    """
    # Normalize to dict
    available_fields = normalize_item_fields(available_fields)
    
    parts = field_path.split('.')
    current = available_fields
    
    for i, part in enumerate(parts):
        if part in current:
            field_meta = current[part]
            
            if i == len(parts) - 1:
                # Found the final field
                return {
                    'exists': True,
                    'correct_name': field_path,
                    'validation': 'exact_match',
                    'field_meta': field_meta if isinstance(field_meta, dict) else {},
                    'field_type': field_meta.get('type') if isinstance(field_meta, dict) else 'unknown'
                }
            else:
                # Go deeper into nested fields
                if isinstance(field_meta, dict):
                    nested_fields = field_meta.get('nested_fields', {})
                    if nested_fields:
                        current = nested_fields
                        continue
                    else:
                        # Base field exists but no nested_fields metadata
                        # For Azure/GCP this is common with properties.* fields
                        return {
                            'exists': True,
                            'correct_name': field_path,
                            'validation': 'nested_assumed_valid',
                            'note': f'Base field "{part}" exists (type: {field_meta.get("type", "object")}), nested path assumed valid'
                        }
                else:
                    return {'exists': False, 'reason': f'Field "{part}" is not an object type'}
        else:
            # Field not found at this level
            # Try case-insensitive match
            lower_part = part.lower()
            for key in current.keys():
                if key.lower() == lower_part:
                    return {
                        'exists': True,
                        'correct_name': field_path.replace(part, key),
                        'validation': 'case_corrected',
                        'note': f'Field "{part}" corrected to "{key}"'
                    }
            
            return {'exists': False, 'reason': f'Field "{part}" not found at level {i+1}'}
    
    return {'exists': False, 'reason': 'Unknown error'}


def extract_field_names_from_catalog(operations: List[Dict]) -> List[str]:
    """
    Extract all unique field names from a list of operations.
    
    Args:
        operations: List of operation dicts from catalog
    
    Returns:
        List of unique field names
    """
    all_fields = set()
    
    for op in operations:
        item_fields = op.get('item_fields', {})
        normalized = normalize_item_fields(item_fields)
        all_fields.update(normalized.keys())
    
    return sorted(list(all_fields))


def calculate_field_match_score(required_fields: List[str], available_fields: Dict) -> float:
    """
    Calculate how well available fields match required fields.
    
    Args:
        required_fields: List of field names/paths needed
        available_fields: Dict of available fields from catalog
    
    Returns:
        Match score (0.0 to 1.0)
    """
    if not required_fields:
        return 0.0
    
    available_fields = normalize_item_fields(available_fields)
    matched_fields = 0
    
    for req_field in required_fields:
        # Direct match
        if req_field in available_fields:
            matched_fields += 1
        else:
            # Nested match (check base field)
            if '.' in req_field:
                base_field = req_field.split('.')[0]
                if base_field in available_fields:
                    matched_fields += 0.7  # Partial credit for nested
            
            # Case-insensitive match
            req_lower = req_field.lower()
            for field in available_fields.keys():
                if field.lower() == req_lower:
                    matched_fields += 0.9  # Almost full credit
                    break
    
    return matched_fields / len(required_fields)

