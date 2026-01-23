#!/usr/bin/env python3
"""
Enrich service_list.json with ID and ARN extraction patterns.

For each service and resource_type, add:
- arn_field_patterns: List of field names that might contain ARN directly
- id_field_patterns: List of field names that might contain resource ID
- name_field_patterns: List of field names that might contain resource name

This allows generic ARN extraction without service-specific hardcoding.
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Set

# Paths
SERVICE_LIST_FILE = Path("configScan_engines/aws-configScan-engine/config/service_list.json")
PYTHONSDK_DIR = Path("pythonsdk-database/aws")

def generate_arn_patterns(service: str, resource_type: str) -> List[str]:
    """Generate common ARN field patterns for a resource type"""
    patterns = [
        'Arn',
        'ARN',
        'arn',
        'ResourceArn',
        'resource_arn',
    ]
    
    # Resource-specific patterns
    resource_clean = resource_type.replace('-', '').replace('_', '').capitalize()
    patterns.extend([
        f'{resource_clean}Arn',
        f'{resource_type}Arn',
        f'{resource_type}_arn',
    ])
    
    # Service-specific patterns
    service_clean = service.replace('-', '').capitalize()
    patterns.extend([
        f'{service_clean}Arn',
        f'{service}Arn',
    ])
    
    return list(dict.fromkeys(patterns))  # Remove duplicates while preserving order


def generate_id_patterns(service: str, resource_type: str) -> List[str]:
    """Generate common ID field patterns for a resource type"""
    patterns = [
        'id',
        'Id',
        'ID',
        'ResourceId',
        'resource_id',
    ]
    
    # Resource-specific patterns
    resource_clean = resource_type.replace('-', '').replace('_', '')
    resource_parts = resource_type.split('-')
    
    # Try different capitalizations
    patterns.extend([
        f'{resource_clean}Id',  # e.g., restapiId
        f'{resource_clean.capitalize()}Id',  # e.g., RestapiId
        f'{resource_type}Id',  # e.g., rest-apiId
        f'{resource_type}_id',  # e.g., rest-api_id
    ])
    
    # For multi-word resource types (e.g., "fpga-image")
    if len(resource_parts) > 1:
        camel = ''.join(p.capitalize() for p in resource_parts)
        patterns.extend([
            f'{camel}Id',  # e.g., FpgaImageId
            f'{"".join(resource_parts)}Id',  # e.g., fpgaimageId
        ])
    
    # Service-specific patterns
    service_clean = service.replace('-', '').capitalize()
    patterns.extend([
        f'{service_clean}Id',
        f'{service}Id',
    ])
    
    return list(dict.fromkeys(patterns))


def generate_name_patterns(service: str, resource_type: str) -> List[str]:
    """Generate common Name field patterns for a resource type"""
    patterns = [
        'name',
        'Name',
        'NAME',
        'ResourceName',
        'resource_name',
    ]
    
    # Resource-specific patterns
    resource_clean = resource_type.replace('-', '').replace('_', '')
    resource_parts = resource_type.split('-')
    
    patterns.extend([
        f'{resource_clean}Name',
        f'{resource_clean.capitalize()}Name',
        f'{resource_type}Name',
        f'{resource_type}_name',
    ])
    
    # For multi-word resource types
    if len(resource_parts) > 1:
        camel = ''.join(p.capitalize() for p in resource_parts)
        patterns.append(f'{camel}Name')
    
    return list(dict.fromkeys(patterns))


def extract_id_patterns_from_resource_operations(service_dir: Path, resource_type: str) -> Dict[str, List[str]]:
    """
    Extract actual field patterns from resource_operations_prioritized.json
    """
    prioritized_file = service_dir / "resource_operations_prioritized.json"
    if not prioritized_file.exists():
        return {}
    
    try:
        with open(prioritized_file, 'r') as f:
            data = json.load(f)
        
        # Look for this resource type in primary_resources
        for resource in data.get('primary_resources', []):
            if resource.get('resource_type') == resource_type:
                # Check if there's ARN entity information
                arn_entity = resource.get('arn_entity', '')
                if arn_entity:
                    # Parse ARN entity to get field name
                    # e.g., "apigateway.rest_api_arn" → "rest_api_arn"
                    parts = arn_entity.split('.')
                    if len(parts) >= 2:
                        field_name = parts[1]
                        # Convert to different cases
                        arn_patterns = [field_name]
                        if '_' in field_name:
                            # Convert snake_case to camelCase
                            camel = ''.join(p.capitalize() if i > 0 else p for i, p in enumerate(field_name.split('_')))
                            arn_patterns.append(camel)
                        return {'arn': arn_patterns}
    except:
        pass
    
    return {}


def enrich_service_list():
    """Main function to enrich service_list.json with extraction patterns"""
    
    print("🚀 Enriching service_list.json with ID/ARN extraction patterns")
    print("=" * 80)
    
    # Load existing service_list.json
    with open(SERVICE_LIST_FILE, 'r') as f:
        config = json.load(f)
    
    enriched_count = 0
    
    for service in config['services']:
        service_name = service['name']
        resource_types = service.get('resource_types', [])
        
        if not resource_types:
            continue
        
        # Check if service has pythonsdk-database directory
        service_dir = PYTHONSDK_DIR / service_name
        
        # Create extraction_patterns dict for this service
        extraction_patterns = {}
        
        for resource_type in resource_types:
            # Try to extract from pythonsdk-database first
            actual_patterns = extract_id_patterns_from_resource_operations(service_dir, resource_type)
            
            # Generate generic patterns
            arn_patterns = generate_arn_patterns(service_name, resource_type)
            id_patterns = generate_id_patterns(service_name, resource_type)
            name_patterns = generate_name_patterns(service_name, resource_type)
            
            # Merge actual patterns with generated ones (actual first)
            if actual_patterns.get('arn'):
                arn_patterns = actual_patterns['arn'] + [p for p in arn_patterns if p not in actual_patterns['arn']]
            
            extraction_patterns[resource_type] = {
                'arn_fields': arn_patterns[:10],  # Top 10 most likely
                'id_fields': id_patterns[:10],
                'name_fields': name_patterns[:5],
            }
        
        # Add extraction_patterns to service
        service['extraction_patterns'] = extraction_patterns
        enriched_count += 1
        
        if enriched_count <= 5:
            print(f"\n✅ {service_name}:")
            for rt, patterns in list(extraction_patterns.items())[:2]:
                print(f"   {rt}:")
                print(f"     ARN fields: {patterns['arn_fields'][:5]}")
                print(f"     ID fields: {patterns['id_fields'][:5]}")
    
    # Save enriched config
    with open(SERVICE_LIST_FILE, 'w') as f:
        json.dump(config, f, indent=2)
    
    print(f"\n{'=' * 80}")
    print(f"✅ Enriched {enriched_count} services with extraction patterns")
    print(f"📁 Saved to: {SERVICE_LIST_FILE}")
    print(f"\n💡 Each service now has 'extraction_patterns' with:")
    print(f"   - arn_fields: Fields that might contain ARN directly")
    print(f"   - id_fields: Fields that might contain resource ID")
    print(f"   - name_fields: Fields that might contain resource name")


if __name__ == "__main__":
    enrich_service_list()
