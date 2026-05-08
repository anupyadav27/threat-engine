#!/usr/bin/env python3
"""
Enrich discovery YAML files with explicit emit.item fields
Uses boto3_dependencies_with_python_names_fully_enriched.json to get all available fields
"""
import json
import yaml
from pathlib import Path
from typing import Dict, Any, List

def load_boto3_dependencies(service_dir: Path, service_name: str) -> Dict[str, Dict]:
    """Load boto3 dependencies and create lookup by python_method"""
    deps_file = service_dir / "boto3_dependencies_with_python_names_fully_enriched.json"
    if not deps_file.exists():
        raise FileNotFoundError(f"boto3_dependencies file not found: {deps_file}")
    
    with open(deps_file, 'r') as f:
        data = json.load(f)
    
    # Create lookup: python_method -> operation_data
    lookup = {}
    
    # Handle nested structure: {"accessanalyzer": {"independent": [...], "dependent": [...]}}
    if service_name in data:
        service_data = data[service_name]
        # Get operations from both independent and dependent arrays
        independent_ops = service_data.get('independent', [])
        dependent_ops = service_data.get('dependent', [])
        operations = independent_ops + dependent_ops
    elif 'operations' in data:
        # Flat structure with operations array
        operations = data['operations']
    else:
        # Try to find operations in any nested structure
        operations = []
        for key, value in data.items():
            if isinstance(value, dict):
                if 'operations' in value:
                    operations = value['operations']
                    break
                elif 'independent' in value:
                    operations = value.get('independent', []) + value.get('dependent', [])
                    break
    
    for op_data in operations:
        python_method = op_data.get('python_method')
        if python_method:
            lookup[python_method] = op_data
    
    return lookup

def enrich_discovery_emit(discovery: Dict[str, Any], boto3_lookup: Dict[str, Dict]) -> Dict[str, Any]:
    """Enrich a single discovery with explicit emit.item fields"""
    # Get the action name from calls
    calls = discovery.get('calls', [])
    if not calls:
        return discovery
    
    action = calls[0].get('action')
    if not action:
        return discovery
    
    # Look up in boto3 dependencies
    op_data = boto3_lookup.get(action)
    if not op_data:
        print(f"  ⚠ Warning: No boto3 data found for action: {action}")
        return discovery
    
    # Get item_fields
    item_fields = op_data.get('item_fields', {})
    if not item_fields:
        print(f"  ⚠ Warning: No item_fields found for action: {action}")
        return discovery
    
    # Get or create emit section
    emit = discovery.get('emit', {})
    if not emit:
        emit = {}
        discovery['emit'] = emit
    
    # If items_for exists, add explicit item fields
    if 'items_for' in emit:
        emit['item'] = {}
        for field_name in sorted(item_fields.keys()):
            emit['item'][field_name] = f'{{{{ item.{field_name} }}}}'
        print(f"  ✓ Added {len(item_fields)} explicit fields to {discovery.get('discovery_id')}")
    else:
        # Single item response - store full response (no items_for)
        # Keep emit as {} for bundle approach
        print(f"  ℹ Single item response for {discovery.get('discovery_id')} - keeping emit: {{}}")
    
    return discovery

def enrich_discovery_yaml(discovery_yaml_path: Path, boto3_lookup: Dict[str, Dict]) -> Dict[str, Any]:
    """Enrich entire discovery YAML file"""
    print(f"Processing: {discovery_yaml_path}")
    
    with open(discovery_yaml_path, 'r') as f:
        data = yaml.safe_load(f)
    
    discoveries = data.get('discovery', [])
    print(f"Found {len(discoveries)} discoveries\n")
    
    enriched_count = 0
    for discovery in discoveries:
        discovery_id = discovery.get('discovery_id', 'unknown')
        print(f"  Processing: {discovery_id}")
        
        original_emit = discovery.get('emit', {}).copy()
        enriched = enrich_discovery_emit(discovery, boto3_lookup)
        
        if enriched.get('emit', {}) != original_emit:
            enriched_count += 1
    
    print(f"\n✓ Enriched {enriched_count} discoveries")
    return data

def main():
    import sys
    
    service_name = sys.argv[1] if len(sys.argv) > 1 else "accessanalyzer"
    
    # Paths
    base_dir = Path("/Users/apple/Desktop/threat-engine")
    service_dir = base_dir / "pythonsdk-database" / "aws" / service_name
    discovery_yaml = service_dir / f"{service_name}_discovery.yaml"
    nested_yaml = base_dir / "configScan_engines" / "aws-configScan-engine" / "services" / service_name / "rules" / f"{service_name}.nested.yaml"
    
    print("=" * 80)
    print(f"Enriching Discovery YAML for {service_name}")
    print("=" * 80)
    print()
    
    # Check if files exist
    if not discovery_yaml.exists():
        print(f"❌ Error: Discovery YAML not found: {discovery_yaml}")
        return 1
    
    # Load boto3 dependencies
    print("Loading boto3 dependencies...")
    try:
        boto3_lookup = load_boto3_dependencies(service_dir, service_name)
        print(f"✓ Loaded {len(boto3_lookup)} operations\n")
    except Exception as e:
        print(f"❌ Error loading boto3 dependencies: {e}")
        return 1
    
    # Enrich discovery YAML
    print("=" * 80)
    print("Enriching discovery YAML")
    print("=" * 80)
    enriched_data = enrich_discovery_yaml(discovery_yaml, boto3_lookup)
    
    # Save enriched discovery YAML (backup original first)
    backup_path = discovery_yaml.parent / f"{service_name}_discovery.yaml.backup"
    if not backup_path.exists():
        import shutil
        shutil.copy2(discovery_yaml, backup_path)
        print(f"\n✓ Backed up original to: {backup_path}")
    
    with open(discovery_yaml, 'w') as f:
        yaml.dump(enriched_data, f, default_flow_style=False, sort_keys=False, allow_unicode=True, width=1000)
    print(f"✓ Saved enriched discovery YAML: {discovery_yaml}")
    
    # Update nested YAML
    print("\n" + "=" * 80)
    print("Updating nested YAML")
    print("=" * 80)
    
    if nested_yaml.exists():
        with open(nested_yaml, 'r') as f:
            nested_data = yaml.safe_load(f)
        
        # Replace discovery section
        nested_data['discovery'] = enriched_data['discovery']
        
        # Backup nested YAML
        nested_backup = nested_yaml.parent / f"{service_name}.nested.yaml.backup"
        if not nested_backup.exists():
            import shutil
            shutil.copy2(nested_yaml, nested_backup)
            print(f"✓ Backed up nested YAML to: {nested_backup}")
        
        # Save updated nested YAML
        with open(nested_yaml, 'w') as f:
            yaml.dump(nested_data, f, default_flow_style=False, sort_keys=False, allow_unicode=True, width=1000)
        print(f"✓ Updated nested YAML: {nested_yaml}")
    else:
        print(f"⚠ Nested YAML not found: {nested_yaml}")
        print("  (This is okay if you're only enriching the discovery file)")
    
    print("\n" + "=" * 80)
    print("✓ Done!")
    print("=" * 80)
    return 0

if __name__ == "__main__":
    exit(main())

