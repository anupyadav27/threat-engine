#!/usr/bin/env python3
"""
Batch Update Service YAML Files

Adds missing api_name, api_version, and project_param_format to all service rules files
based on GCP_SERVICES_API_MAPPING.yaml.

This ensures all services work with the smart action parser without engine changes.
"""

import os
import yaml
from pathlib import Path

# Load the API mapping
with open('GCP_SERVICES_API_MAPPING.yaml') as f:
    mapping_data = yaml.safe_load(f)

services_mapping = {s['service']: s for s in mapping_data['services']}

# Update each service rules file
services_dir = Path('services')
updated_count = 0
skipped_count = 0

for service_dir in sorted(services_dir.iterdir()):
    if not service_dir.is_dir():
        continue
    
    service_name = service_dir.name
    rules_file = service_dir / f"{service_name}_rules.yaml"
    
    if not rules_file.exists():
        print(f"⚠️  Skipping {service_name}: no rules file")
        skipped_count += 1
        continue
    
    # Load existing rules
    with open(rules_file) as f:
        rules = yaml.safe_load(f)
    
    if service_name not in rules:
        print(f"⚠️  Skipping {service_name}: unexpected YAML structure")
        skipped_count += 1
        continue
    
    service_config = rules[service_name]
    
    # Check if already has api_name
    if 'api_name' in service_config or 'sdk_package' in service_config:
        print(f"✓ {service_name}: already configured")
        continue
    
    # Get mapping for this service
    if service_name not in services_mapping:
        print(f"⚠️  Skipping {service_name}: not in mapping")
        skipped_count += 1
        continue
    
    mapping = services_mapping[service_name]
    
    # Add api metadata
    if mapping.get('api_type') == 'sdk':
        service_config['sdk_package'] = mapping['sdk_package']
        service_config['client_class'] = mapping['client_class']
    else:
        service_config['api_name'] = mapping['api_name']
        service_config['api_version'] = mapping['api_version']
    
    # Add project format if specified
    if mapping.get('project_format'):
        service_config['project_param_format'] = mapping['project_format']
    
    # Update scope if different
    if 'scope' in mapping and mapping['scope'] != service_config.get('scope'):
        service_config['scope'] = mapping['scope']
    
    # Write updated rules
    with open(rules_file, 'w') as f:
        yaml.dump(rules, f, default_flow_style=False, sort_keys=False)
    
    print(f"✅ {service_name}: updated with {mapping.get('api_name', mapping.get('sdk_package'))}")
    updated_count += 1

print(f"\n{'='*50}")
print(f"Summary:")
print(f"  Updated: {updated_count}")
print(f"  Skipped: {skipped_count}")
print(f"  Total: {updated_count + skipped_count}")

