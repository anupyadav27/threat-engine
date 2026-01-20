#!/usr/bin/env python3
"""
Enrich YAML discovery files with pagination metadata from database.
Adds pagination info to each discovery based on boto3_dependencies database.

This makes pagination explicit in YAML and allows the scanner to use
optimal pagination strategies per discovery.
"""

import json
import yaml
import os
from pathlib import Path
from typing import Dict, Any, Optional

# Database path
DB_BASE = Path('/Users/apple/Desktop/threat-engine/pythonsdk-database/aws')

# Service name mappings (YAML service name -> database service name)
SERVICE_MAPPINGS = {
    'parameterstore': 'ssm',
    'eip': 'ec2',
    'ebs': 'ec2',
    'fsx': 'fsx',
    'docdb': 'docdb',
    'rds': 'rds',
    'neptune': 'neptune',
}


def load_service_database(service_name: str) -> Optional[Dict]:
    """Load service database file."""
    # Try direct match
    db_file = DB_BASE / service_name / 'boto3_dependencies_with_python_names_fully_enriched.json'
    
    if not db_file.exists():
        # Try mapping
        mapped_name = SERVICE_MAPPINGS.get(service_name, service_name)
        db_file = DB_BASE / mapped_name / 'boto3_dependencies_with_python_names_fully_enriched.json'
    
    if not db_file.exists():
        # Try main consolidated file
        db_file = DB_BASE / 'boto3_dependencies_with_python_names.json'
    
    if not db_file.exists():
        return None
    
    try:
        with open(db_file, 'r') as f:
            data = json.load(f)
        
        # Extract service data
        if service_name in data:
            return data[service_name]
        elif mapped_name in data:
            return data[mapped_name]
        else:
            # Try first key
            return list(data.values())[0] if data else None
    except Exception as e:
        print(f"Error loading database for {service_name}: {e}")
        return None


def get_pagination_info_for_action(service_data: Dict, action: str) -> Optional[Dict]:
    """Get pagination info for a specific action from service database."""
    if not service_data:
        return None
    
    # Search in independent and dependent operations
    for op_list in [service_data.get('independent', []), service_data.get('dependent', [])]:
        for op in op_list:
            python_method = op.get('python_method')
            if python_method == action:
                # Check if pagination metadata exists
                pagination = op.get('pagination')
                if pagination:
                    return pagination
                
                # Otherwise, detect from metadata
                return detect_pagination_from_metadata(op)
    
    return None


def detect_pagination_from_metadata(operation: Dict) -> Dict:
    """Detect pagination from operation metadata."""
    output_fields = operation.get('output_fields', {})
    optional_params = operation.get('optional_params', [])
    
    # Check for pagination tokens
    pagination_tokens = {
        'nextToken': 'NextToken',
        'marker': 'Marker',
        'nextmarker': 'NextMarker',
        'continuationtoken': 'ContinuationToken'
    }
    token_found = None
    
    if isinstance(output_fields, dict):
        for field_key in output_fields.keys():
            field_lower = field_key.lower()
            for token_key, token_name in pagination_tokens.items():
                if token_key in field_lower:
                    token_found = token_name
                    break
            if token_found:
                break
    elif isinstance(output_fields, list):
        for field in output_fields:
            field_str = str(field).lower()
            for token_key, token_name in pagination_tokens.items():
                if token_key in field_str:
                    token_found = token_name
                    break
            if token_found:
                break
    
    # Check for max results params
    max_results_param = None
    for param in optional_params:
        param_str = str(param).lower()
        if 'maxresults' in param_str:
            max_results_param = 'MaxResults'
            break
        elif 'maxrecords' in param_str:
            max_results_param = 'MaxRecords'
            break
        elif param_str == 'limit':
            max_results_param = 'Limit'
            break
        elif 'maxitems' in param_str:
            max_results_param = 'MaxItems'
            break
    
    supports_pagination = token_found is not None
    
    if supports_pagination:
        if token_found in ['NextToken', 'Marker']:
            pagination_type = 'boto3_paginator'
        else:
            pagination_type = 'manual_token'
    else:
        pagination_type = 'none'
    
    return {
        'supports_pagination': supports_pagination,
        'pagination_type': pagination_type,
        'pagination_token_name': token_found,
        'max_results_param': max_results_param
    }


def enrich_yaml_discovery(discovery: Dict, service_data: Dict) -> Dict:
    """Enrich a single discovery with pagination metadata."""
    # Get action from first call
    calls = discovery.get('calls', [])
    if not calls:
        return discovery
    
    first_call = calls[0]
    action = first_call.get('action')
    if not action:
        return discovery
    
    # Get pagination info from database
    pagination_info = get_pagination_info_for_action(service_data, action)
    
    if pagination_info:
        # Add pagination metadata to discovery (only if not already present)
        if 'pagination' not in discovery:
            discovery['pagination'] = pagination_info
            return True  # Indicates enrichment was applied
        else:
            return False  # Already enriched
    
    return False


def enrich_service_yaml(service_path: Path, service_name: str, dry_run: bool = False) -> bool:
    """Enrich a single service YAML file."""
    print(f"  {service_name}...", end=' ', flush=True)
    
    # Load service database
    service_data = load_service_database(service_name)
    if not service_data:
        print("⚠️  (no database)")
        return False
    
    # Load YAML
    try:
        with open(service_path, 'r') as f:
            yaml_data = yaml.safe_load(f)
    except Exception as e:
        print(f"✗ Error loading: {e}")
        return False
    
    # Enrich discoveries
    discoveries = yaml_data.get('discovery', [])
    enriched_count = 0
    
    for discovery in discoveries:
        if isinstance(discovery, dict) and 'discovery_id' in discovery:
            was_enriched = enrich_yaml_discovery(discovery, service_data)
            if was_enriched:
                enriched_count += 1
    
    if enriched_count == 0:
        print("(no changes needed)")
        return True
    
    if not dry_run:
        # Save enriched YAML
        try:
            with open(service_path, 'w') as f:
                yaml.dump(yaml_data, f, default_flow_style=False, sort_keys=False, allow_unicode=True, width=120)
            print(f"✓ ({enriched_count} discoveries)")
            return True
        except Exception as e:
            print(f"✗ Error saving: {e}")
            return False
    else:
        print(f"✓ ({enriched_count} discoveries - DRY RUN)")
        return True


def enrich_all_services(dry_run: bool = False):
    """Enrich all service YAML files."""
    services_dir = Path('/Users/apple/Desktop/threat-engine/configScan_engines/aws-configScan-engine/services')
    
    print("="*80)
    print("ENRICHING YAML DISCOVERIES WITH PAGINATION METADATA")
    print("="*80)
    if dry_run:
        print("DRY RUN MODE - No files will be modified")
    print()
    
    enriched = 0
    total = 0
    skipped = 0
    
    for service_dir in sorted(services_dir.iterdir()):
        if not service_dir.is_dir() or service_dir.name.startswith('.'):
            continue
        
        service_name = service_dir.name
        yaml_file = service_dir / 'rules' / f'{service_name}.yaml'
        
        if yaml_file.exists():
            total += 1
            if enrich_service_yaml(yaml_file, service_name, dry_run=dry_run):
                enriched += 1
            else:
                skipped += 1
        else:
            print(f"  {service_name}... (no YAML file)")
    
    print()
    print("="*80)
    print(f"✅ Processed {total} services")
    print(f"✅ Enriched {enriched} services")
    if skipped > 0:
        print(f"⚠️  Skipped {skipped} services (no database or errors)")
    print("="*80)
    
    if dry_run:
        print()
        print("Run without --dry-run to apply changes")


if __name__ == '__main__':
    import sys
    
    dry_run = '--dry-run' in sys.argv or '-n' in sys.argv
    
    if len(sys.argv) > 1 and sys.argv[1] not in ['--dry-run', '-n']:
        # Enrich specific service
        service_name = sys.argv[1]
        services_dir = Path('/Users/apple/Desktop/threat-engine/configScan_engines/aws-configScan-engine/services')
        yaml_file = services_dir / service_name / 'rules' / f'{service_name}.yaml'
        if yaml_file.exists():
            enrich_service_yaml(yaml_file, service_name, dry_run=dry_run)
        else:
            print(f"YAML file not found: {yaml_file}")
    else:
        # Enrich all
        enrich_all_services(dry_run=dry_run)

