#!/usr/bin/env python3
"""
Extract ALL service data from data_pythonsdk directory and create comprehensive CSV/NDJSON
for bulk import into rule_discoveries table.

This script processes:
- Discovery YAML files
- Resource ARN mappings
- Inventory reports
- Boto3 dependencies
- All metadata for all CSPs
"""
import os
import json
import yaml
import csv
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

# Base path
BASE_PATH = "/Users/apple/Desktop/data_pythonsdk"
OUTPUT_DIR = "/Users/apple/Desktop/threat-engine/bulk_import"

# Ensure output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

def extract_service_data(service_dir: Path, provider: str) -> Optional[Dict[str, Any]]:
    """Extract all metadata from a service directory"""

    service_name = service_dir.name

    data = {
        'service': service_name,
        'provider': provider,
        'version': '',
        'is_active': True,
        'boto3_client_name': service_name,  # Default
        'scope': 'regional',  # Default
        'arn_pattern': None,
        'arn_identifier': None,
        'arn_identifier_independent_methods': None,
        'arn_identifier_dependent_methods': None,
        'extraction_patterns': None,
        'filter_rules': {'api_filters': [], 'response_filters': []},
        'pagination_config': {
            'default_page_size': 1000,
            'max_pages': 100,
            'timeout_seconds': 600,
            'max_items': 100000,
            'token_field': 'NextToken',
            'result_array_field': None,
            'supports_native_pagination': True,
            'circular_token_detection': True,
            'service_overrides': {}
        },
        'features': {
            'discovery': {'enabled': True, 'priority': 1},
            'checks': {'enabled': False, 'priority': 1},
            'deviation': {'enabled': False, 'priority': 3},
            'drift': {'enabled': False, 'priority': 3}
        },
        'discoveries_data': {},
        'created_at': datetime.now().isoformat(),
        'updated_at': datetime.now().isoformat()
    }

    # 1. Load discovery YAML
    discovery_yaml = service_dir / f"{service_name}_discovery.yaml"
    if discovery_yaml.exists():
        try:
            with open(discovery_yaml, 'r') as f:
                data['discoveries_data'] = yaml.safe_load(f) or {}
        except Exception as e:
            print(f"  ⚠ {service_name}: Failed to load discovery YAML - {e}")

    # 2. Load resource ARN mapping
    arn_mapping_file = service_dir / "resource_arn_mapping.json"
    if arn_mapping_file.exists():
        try:
            with open(arn_mapping_file, 'r') as f:
                arn_data = json.load(f)

                # Extract ARN patterns
                if 'resources' in arn_data and arn_data['resources']:
                    first_resource = list(arn_data['resources'].values())[0]
                    if 'arn_pattern' in first_resource:
                        data['arn_pattern'] = first_resource['arn_pattern']
                    if 'identifier' in first_resource:
                        data['arn_identifier'] = first_resource['identifier']

                # Extract extraction patterns
                if 'resources' in arn_data:
                    extraction_patterns = {}
                    for resource_type, resource_data in arn_data['resources'].items():
                        if 'fields' in resource_data:
                            extraction_patterns[resource_type] = {
                                'id_fields': resource_data['fields'].get('id_fields', []),
                                'arn_fields': resource_data['fields'].get('arn_fields', []),
                                'name_fields': resource_data['fields'].get('name_fields', [])
                            }
                    if extraction_patterns:
                        data['extraction_patterns'] = extraction_patterns

        except Exception as e:
            print(f"  ⚠ {service_name}: Failed to load ARN mapping - {e}")

    # 3. Load inventory report for scope detection
    inventory_file = service_dir / "resource_inventory_report.json"
    if inventory_file.exists():
        try:
            with open(inventory_file, 'r') as f:
                inventory = json.load(f)

                # Detect scope from inventory metadata
                if 'service_metadata' in inventory:
                    metadata = inventory['service_metadata']
                    if 'scope' in metadata:
                        data['scope'] = metadata['scope']
                    elif 'is_global' in metadata and metadata['is_global']:
                        data['scope'] = 'global'

        except Exception as e:
            print(f"  ⚠ {service_name}: Failed to load inventory - {e}")

    # 4. Load boto3 client name from dependencies
    boto3_deps_file = service_dir / "boto3_dependencies_with_python_names_fully_enriched.json"
    if boto3_deps_file.exists():
        try:
            with open(boto3_deps_file, 'r') as f:
                deps = json.load(f)

                # Extract boto3 client name
                if 'service_info' in deps and 'client_name' in deps['service_info']:
                    data['boto3_client_name'] = deps['service_info']['client_name']
                elif 'metadata' in deps and 'boto3_client' in deps['metadata']:
                    data['boto3_client_name'] = deps['metadata']['boto3_client']

        except Exception as e:
            print(f"  ⚠ {service_name}: Failed to load boto3 dependencies - {e}")

    return data

def process_all_csps():
    """Process all CSPs and create comprehensive data files"""

    csps = ['aws', 'azure', 'gcp', 'oci', 'alicloud']
    all_services = []

    stats = {
        'total_services': 0,
        'by_csp': {},
        'with_discovery_yaml': 0,
        'with_arn_mapping': 0,
        'with_inventory': 0
    }

    for csp in csps:
        csp_dir = Path(BASE_PATH) / csp
        if not csp_dir.exists():
            print(f"⚠ {csp.upper()}: Directory not found")
            continue

        # Find all service directories
        service_dirs = [d for d in csp_dir.iterdir() if d.is_dir() and not d.name.startswith('.')]

        print(f"\n=== Processing {csp.upper()} ({len(service_dirs)} services) ===")
        stats['by_csp'][csp] = len(service_dirs)

        for service_dir in service_dirs:
            try:
                service_data = extract_service_data(service_dir, csp)
                if service_data:
                    all_services.append(service_data)
                    stats['total_services'] += 1

                    # Count data availability
                    if service_data['discoveries_data']:
                        stats['with_discovery_yaml'] += 1
                    if service_data['arn_pattern']:
                        stats['with_arn_mapping'] += 1
                    if service_data['extraction_patterns']:
                        stats['with_inventory'] += 1

                    print(f"  ✓ {service_data['service']}")

            except Exception as e:
                print(f"  ✗ {service_dir.name}: Error - {e}")

    return all_services, stats

def write_ndjson(services: List[Dict], output_file: str):
    """Write services to NDJSON format"""
    with open(output_file, 'w') as f:
        for service in services:
            # Convert complex types to JSON strings
            service_copy = service.copy()
            service_copy['discoveries_data'] = json.dumps(service_copy['discoveries_data'])
            service_copy['extraction_patterns'] = json.dumps(service_copy['extraction_patterns']) if service_copy['extraction_patterns'] else None
            service_copy['filter_rules'] = json.dumps(service_copy['filter_rules'])
            service_copy['pagination_config'] = json.dumps(service_copy['pagination_config'])
            service_copy['features'] = json.dumps(service_copy['features'])
            service_copy['arn_identifier_independent_methods'] = json.dumps(service_copy['arn_identifier_independent_methods']) if service_copy['arn_identifier_independent_methods'] else None
            service_copy['arn_identifier_dependent_methods'] = json.dumps(service_copy['arn_identifier_dependent_methods']) if service_copy['arn_identifier_dependent_methods'] else None

            f.write(json.dumps(service_copy) + '\n')

def write_csv(services: List[Dict], output_file: str):
    """Write services to CSV format"""
    if not services:
        return

    # Define columns
    columns = [
        'service', 'provider', 'version', 'is_active', 'boto3_client_name', 'scope',
        'arn_pattern', 'arn_identifier', 'arn_identifier_independent_methods',
        'arn_identifier_dependent_methods', 'extraction_patterns', 'filter_rules',
        'pagination_config', 'features', 'discoveries_data', 'created_at', 'updated_at'
    ]

    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()

        for service in services:
            row = service.copy()
            # Convert complex types to JSON strings
            row['discoveries_data'] = json.dumps(row['discoveries_data'])
            row['extraction_patterns'] = json.dumps(row['extraction_patterns']) if row['extraction_patterns'] else ''
            row['filter_rules'] = json.dumps(row['filter_rules'])
            row['pagination_config'] = json.dumps(row['pagination_config'])
            row['features'] = json.dumps(row['features'])
            row['arn_identifier_independent_methods'] = json.dumps(row['arn_identifier_independent_methods']) if row['arn_identifier_independent_methods'] else ''
            row['arn_identifier_dependent_methods'] = json.dumps(row['arn_identifier_dependent_methods']) if row['arn_identifier_dependent_methods'] else ''

            writer.writerow(row)

def main():
    """Main execution"""
    print("="*60)
    print("Extracting ALL service data from data_pythonsdk")
    print("="*60)

    # Process all CSPs
    all_services, stats = process_all_csps()

    # Write outputs
    print(f"\n=== Writing Output Files ===")

    ndjson_file = os.path.join(OUTPUT_DIR, "rule_discoveries_complete.ndjson")
    write_ndjson(all_services, ndjson_file)
    print(f"✓ NDJSON: {ndjson_file} ({len(all_services)} services)")

    csv_file = os.path.join(OUTPUT_DIR, "rule_discoveries_complete.csv")
    write_csv(all_services, csv_file)
    print(f"✓ CSV: {csv_file} ({len(all_services)} services)")

    # Print statistics
    print("\n" + "="*60)
    print("=== Extraction Statistics ===")
    print(f"Total services extracted: {stats['total_services']}")
    print(f"\nBy CSP:")
    for csp, count in stats['by_csp'].items():
        print(f"  {csp.upper()}: {count} services")
    print(f"\nData Completeness:")
    print(f"  With discovery YAML: {stats['with_discovery_yaml']} ({stats['with_discovery_yaml']/stats['total_services']*100:.1f}%)")
    print(f"  With ARN mapping: {stats['with_arn_mapping']} ({stats['with_arn_mapping']/stats['total_services']*100:.1f}%)")
    print(f"  With inventory data: {stats['with_inventory']} ({stats['with_inventory']/stats['total_services']*100:.1f}%)")
    print("="*60)

if __name__ == "__main__":
    main()
