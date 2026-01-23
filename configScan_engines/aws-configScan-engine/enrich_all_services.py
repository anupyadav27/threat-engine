#!/usr/bin/env python3
"""
Batch enrich all service YAML files with explicit emit fields
Similar to what we did for AccessAnalyzer, S3, IAM, EC2
"""
import os
import sys
import json
import yaml
from pathlib import Path
from typing import Dict, List, Any

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def load_boto3_dependencies(boto3_deps_path: str) -> Dict[str, Any]:
    """Load boto3 dependencies JSON"""
    with open(boto3_deps_path) as f:
        return json.load(f)

def enrich_discovery_emit(discovery: Dict, service_name: str, boto3_deps: Dict) -> Dict:
    """Enrich a single discovery with explicit emit fields"""
    discovery_id = discovery.get('discovery_id', '')
    
    # Extract operation name from discovery_id
    # e.g., 'aws.s3.get_bucket_encryption' -> 'get_bucket_encryption'
    operation_name = discovery_id.split('.')[-1] if '.' in discovery_id else ''
    
    # Get service operations from boto3 deps
    service_ops = boto3_deps.get(service_name, {}).get('operations', [])
    
    # Find matching operation
    operation_data = None
    for op in service_ops:
        if op.get('operation_name', '').lower() == operation_name.lower():
            operation_data = op
            break
    
    if not operation_data:
        print(f"  ⚠️  Operation {operation_name} not found in boto3 deps")
        return discovery
    
    # Get output shape fields
    output_shape = operation_data.get('output_shape', {})
    members = output_shape.get('members', {})
    
    # Extract all field names
    all_fields = []
    def extract_fields(shape: Dict, prefix: str = ''):
        if isinstance(shape, dict):
            if 'members' in shape:
                for field_name, field_shape in shape['members'].items():
                    field_path = f"{prefix}.{field_name}" if prefix else field_name
                    all_fields.append(field_path)
                    if isinstance(field_shape, dict) and 'members' in field_shape:
                        extract_fields(field_shape, field_path)
            elif 'member' in shape:
                # List/array type
                extract_fields(shape['member'], prefix)
    
    extract_fields(output_shape)
    
    # Update emit section
    if 'emit' not in discovery:
        discovery['emit'] = {}
    
    emit = discovery['emit']
    
    # If items_for exists, add item fields
    if 'items_for' in emit:
        if 'item' not in emit:
            emit['item'] = {}
        
        item_emit = emit['item']
        
        # Add all fields to item emit
        for field in all_fields:
            # Convert field path to template format
            if '.' in field:
                # Nested field
                field_parts = field.split('.')
                template = '{{ item.' + '.'.join(field_parts) + ' }}'
            else:
                template = f'{{{{ item.{field} }}}}'
            
            # Use field name as key (last part if nested)
            key = field.split('.')[-1]
            if key not in item_emit:
                item_emit[key] = template
    
    return discovery

def enrich_service_yaml(service_name: str, boto3_deps: Dict) -> bool:
    """Enrich a single service YAML file"""
    service_dir = Path(f"services/{service_name}")
    nested_yaml = service_dir / "rules" / f"{service_name}.nested.yaml"
    
    if not nested_yaml.exists():
        print(f"  ⚠️  {nested_yaml} not found")
        return False
    
    # Backup original
    backup_file = nested_yaml.with_suffix('.nested.yaml.backup')
    if not backup_file.exists():
        import shutil
        shutil.copy2(nested_yaml, backup_file)
        print(f"  📦 Backed up to {backup_file.name}")
    
    # Load YAML
    with open(nested_yaml) as f:
        data = yaml.safe_load(f)
    
    if 'discovery' not in data:
        print(f"  ⚠️  No discovery section found")
        return False
    
    # Enrich each discovery
    enriched_count = 0
    for discovery in data.get('discovery', []):
        enriched = enrich_discovery_emit(discovery, service_name, boto3_deps)
        if enriched != discovery:
            enriched_count += 1
    
    # Save enriched YAML
    with open(nested_yaml, 'w') as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
    
    print(f"  ✅ Enriched {enriched_count} discoveries")
    return True

def enrich_all_services():
    """Enrich all service YAML files"""
    # Path to boto3 dependencies
    boto3_deps_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        'pythonsdk-database', 'aws',
        'boto3_dependencies_with_python_names_fully_enriched.json'
    )
    
    if not os.path.exists(boto3_deps_path):
        print(f"❌ Boto3 dependencies file not found: {boto3_deps_path}")
        return
    
    print(f"Loading boto3 dependencies from {boto3_deps_path}...")
    boto3_deps = load_boto3_dependencies(boto3_deps_path)
    print(f"✅ Loaded {len(boto3_deps)} services")
    
    # Get all services
    services_dir = Path("services")
    services = [d.name for d in services_dir.iterdir() if d.is_dir() and not d.name.startswith('.')]
    
    print(f"\nFound {len(services)} services to enrich\n")
    
    success_count = 0
    failed_count = 0
    
    for service in sorted(services):
        print(f"Processing {service}...")
        try:
            if enrich_service_yaml(service, boto3_deps):
                success_count += 1
            else:
                failed_count += 1
        except Exception as e:
            print(f"  ❌ Error: {e}")
            failed_count += 1
        print()
    
    print("=" * 60)
    print(f"Enrichment Complete:")
    print(f"  ✅ Success: {success_count}")
    print(f"  ❌ Failed: {failed_count}")
    print(f"  📊 Total: {len(services)}")
    print("=" * 60)

if __name__ == '__main__':
    enrich_all_services()

