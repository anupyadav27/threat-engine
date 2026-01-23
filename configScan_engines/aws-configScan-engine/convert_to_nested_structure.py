#!/usr/bin/env python3
"""
Convert YAML discovery emit configs to nested structure (full response storage)
Creates new files with .nested.yaml suffix to preserve originals
"""
import yaml
import os
from pathlib import Path
from typing import Dict, Any, List
import sys

def convert_emit_config(discovery: Dict[str, Any]) -> tuple[Dict[str, Any], bool]:
    """
    Convert emit config to nested structure:
    - Remove explicit 'item' fields
    - Keep 'items_for' for array responses
    - Set 'emit: {}' for single item responses
    
    Returns: (converted_discovery, was_changed)
    """
    emit_config = discovery.get('emit', {})
    original_emit = emit_config.copy() if emit_config else {}
    was_changed = False
    
    if not emit_config:
        # No emit config - add empty emit
        discovery['emit'] = {}
        was_changed = True
        return discovery, was_changed
    
    # Pattern 1: Single item with explicit fields (no items_for)
    if 'item' in emit_config and 'items_for' not in emit_config:
        # Remove explicit item fields, store full response
        discovery['emit'] = {}
        was_changed = True
        return discovery, was_changed
    
    # Pattern 2 & 5: items_for with explicit item fields
    if 'items_for' in emit_config and 'item' in emit_config:
        # Keep items_for, remove item fields
        new_emit = {
            'items_for': emit_config['items_for']
        }
        if 'as' in emit_config:
            new_emit['as'] = emit_config['as']
        discovery['emit'] = new_emit
        was_changed = True
        return discovery, was_changed
    
    # Pattern 3 & 4: Already correct (emit: {} or items_for without item)
    # No changes needed
    return discovery, was_changed

def convert_yaml_file(yaml_path: Path, output_path: Path) -> tuple[bool, int]:
    """
    Convert a single YAML file and save to output path
    Returns: (success, num_conversions)
    """
    try:
        with open(yaml_path, 'r') as f:
            data = yaml.safe_load(f)
        
        if not data:
            return False, 0
        
        # Skip if no discovery section
        if 'discovery' not in data:
            # Copy as-is if no discovery section
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w') as f:
                yaml.dump(data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
            return True, 0
        
        discoveries = data.get('discovery', [])
        converted_count = 0
        
        for discovery in discoveries:
            original_emit = discovery.get('emit', {})
            converted_discovery, was_changed = convert_emit_config(discovery)
            
            if was_changed:
                converted_count += 1
                discovery_id = discovery.get('discovery_id', 'unknown')
                print(f"    ✓ {discovery_id}")
        
        # Write converted file
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
        
        return True, converted_count
    except Exception as e:
        print(f"    ✗ Error: {e}")
        return False, 0

def convert_all_yaml_files(services_dir: Path, output_suffix: str = '.nested.yaml'):
    """Convert all YAML files in services directory"""
    yaml_files = list(services_dir.rglob('rules/*.yaml'))
    
    # Filter out metadata and nested files
    yaml_files = [f for f in yaml_files if 'metadata' not in str(f) and 'nested' not in str(f.name)]
    
    print(f"Found {len(yaml_files)} YAML rule files to convert")
    print("=" * 80)
    
    converted_count = 0
    total_discoveries_converted = 0
    failed_files = []
    
    for yaml_path in sorted(yaml_files):
        # Create output path with .nested.yaml suffix
        output_path = yaml_path.parent / f"{yaml_path.stem}{output_suffix}"
        
        rel_path = yaml_path.relative_to(services_dir)
        print(f"\n[{converted_count + 1}/{len(yaml_files)}] Converting: {rel_path}")
        
        success, num_conversions = convert_yaml_file(yaml_path, output_path)
        
        if success:
            if num_conversions > 0:
                converted_count += 1
                total_discoveries_converted += num_conversions
                print(f"    → {num_conversions} discovery(ies) converted → {output_path.name}")
            else:
                print(f"    → No changes needed (already nested or no discoveries)")
        else:
            failed_files.append(str(rel_path))
            print(f"    ✗ Failed to convert")
    
    print("\n" + "=" * 80)
    print(f"Conversion Summary:")
    print(f"  ✓ Files converted: {converted_count}/{len(yaml_files)}")
    print(f"  ✓ Total discoveries converted: {total_discoveries_converted}")
    if failed_files:
        print(f"  ✗ Failed files: {len(failed_files)}")
        for f in failed_files[:5]:  # Show first 5
            print(f"    - {f}")
        if len(failed_files) > 5:
            print(f"    ... and {len(failed_files) - 5} more")
    print("=" * 80)
    
    return converted_count, total_discoveries_converted, failed_files

if __name__ == '__main__':
    services_dir = Path('/Users/apple/Desktop/threat-engine/configScan_engines/aws-configScan-engine/services')
    
    if not services_dir.exists():
        print(f"Error: Services directory not found: {services_dir}")
        sys.exit(1)
    
    print("YAML to Nested Structure Converter")
    print("=" * 80)
    print(f"Source: {services_dir}")
    print(f"Output: Same directory with .nested.yaml suffix")
    print()
    
    converted, discoveries, failed = convert_all_yaml_files(services_dir)
    
    if failed:
        sys.exit(1)
    else:
        print("\n✓ All files converted successfully!")
        print("\nNext steps:")
        print("1. Review converted files (*.nested.yaml)")
        print("2. Test with a few services")
        print("3. Replace original files when ready")

