#!/usr/bin/env python3
"""
Convert all dependent discoveries from template-based to bundle approach.
Removes 'item:' sections from emit configs for discoveries with 'for_each'.
"""

import os
import yaml
import sys
from pathlib import Path

def convert_service_yaml(yaml_path):
    """Convert a single service YAML file."""
    try:
        with open(yaml_path, 'r') as f:
            content = f.read()
            config = yaml.safe_load(content)
        
        if not config or 'discovery' not in config:
            return 0
        
        discoveries = config.get('discovery', [])
        converted_count = 0
        modified = False
        
        for disc in discoveries:
            disc_id = disc.get('discovery_id', '')
            has_for_each = False
            
            # Check discovery level for_each
            if disc.get('for_each'):
                has_for_each = True
            
            # Check calls level for_each
            for call in disc.get('calls', []):
                if call.get('for_each'):
                    has_for_each = True
                    break
            
            if has_for_each and 'emit' in disc:
                emit_config = disc.get('emit', {})
                if 'item' in emit_config:
                    # Remove the 'item:' section
                    del emit_config['item']
                    # If emit is now empty, we can remove it entirely
                    # But keep it as empty dict to maintain structure
                    converted_count += 1
                    modified = True
                    print(f"  ✅ Converted: {disc_id}")
        
        if modified:
            # Write back with same formatting style
            with open(yaml_path, 'w') as f:
                yaml.dump(config, f, default_flow_style=False, sort_keys=False, allow_unicode=True, width=1000)
            return converted_count
        
        return 0
    except Exception as e:
        print(f"  ❌ Error converting {yaml_path}: {e}")
        return 0

def main():
    services_dir = Path("configScan_engines/aws-configScan-engine/services")
    
    if not services_dir.exists():
        print(f"Error: Services directory not found: {services_dir}")
        sys.exit(1)
    
    print("="*100)
    print("CONVERTING DEPENDENT DISCOVERIES TO BUNDLE APPROACH")
    print("="*100)
    print()
    
    total_converted = 0
    services_modified = []
    
    for service_dir in sorted(services_dir.iterdir()):
        if not service_dir.is_dir():
            continue
        
        yaml_path = service_dir / "rules" / f"{service_dir.name}.yaml"
        if not yaml_path.exists():
            continue
        
        print(f"📋 {service_dir.name.upper()}")
        count = convert_service_yaml(yaml_path)
        if count > 0:
            total_converted += count
            services_modified.append(service_dir.name)
            print(f"   Converted {count} discoveries")
        else:
            print(f"   No conversions needed")
    
    print()
    print("="*100)
    print(f"CONVERSION COMPLETE")
    print("="*100)
    print(f"Total discoveries converted: {total_converted}")
    print(f"Services modified: {len(services_modified)}")
    print(f"Services: {', '.join(services_modified[:10])}")
    if len(services_modified) > 10:
        print(f"  ... and {len(services_modified) - 10} more")
    print("="*100)

if __name__ == "__main__":
    main()

