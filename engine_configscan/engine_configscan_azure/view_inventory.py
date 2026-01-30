#!/usr/bin/env python3
"""
View inventory files from latest scan
"""

import json
import glob
import os
import sys
from pathlib import Path

def main():
    output_dir = Path(__file__).parent / "output" / "latest"
    
    if not output_dir.exists():
        print(f"❌ Output folder not found: {output_dir}")
        print("   Run a scan first!")
        return 1
    
    # Find all inventory files
    inv_files = sorted(output_dir.glob("subscription_*/*_inventory.json"))
    
    if not inv_files:
        print(f"❌ No inventory files found in {output_dir}")
        return 1
    
    print("=" * 80)
    print("INVENTORY FILES - LATEST SCAN")
    print("=" * 80)
    print()
    print(f"Location: {output_dir.absolute()}")
    print(f"Total files: {len(inv_files)}")
    print()
    
    # Group by subscription
    by_subscription = {}
    for inv_file in inv_files:
        sub_folder = inv_file.parent
        sub_name = sub_folder.name
        
        if sub_name not in by_subscription:
            by_subscription[sub_name] = []
        
        by_subscription[sub_name].append(inv_file)
    
    for sub_name, files in by_subscription.items():
        print(f"📁 {sub_name}")
        print()
        
        services_with_resources = []
        services_without_resources = []
        
        for inv_file in files:
            try:
                with open(inv_file) as f:
                    data = json.load(f)
                
                service = data.get('service', 'unknown')
                count = data.get('count', 0)
                discovered = data.get('discovered', {})
                total_items = sum(len(v) if isinstance(v, list) else 0 for v in discovered.values())
                
                file_name = inv_file.name
                file_path = inv_file.relative_to(Path(__file__).parent)
                
                if total_items > 0:
                    services_with_resources.append((service, total_items, file_path))
                else:
                    services_without_resources.append((service, file_path))
            
            except Exception as e:
                print(f"   ❌ Error reading {inv_file.name}: {e}")
        
        # Show services with resources first
        if services_with_resources:
            print("   ✅ Services WITH resources:")
            for service, count, path in sorted(services_with_resources, key=lambda x: x[1], reverse=True):
                print(f"      • {service:25} {count:4} resources")
                print(f"        {path}")
        
        print()
        
        if services_without_resources:
            print(f"   ❌ Services WITHOUT resources ({len(services_without_resources)}):")
            for service, path in sorted(services_without_resources):
                print(f"      • {service:25} 0 resources")
        
        print()
    
    # Summary
    total_resources = 0
    total_services_with_resources = 0
    
    for inv_file in inv_files:
        try:
            with open(inv_file) as f:
                data = json.load(f)
            discovered = data.get('discovered', {})
            items = sum(len(v) if isinstance(v, list) else 0 for v in discovered.values())
            if items > 0:
                total_resources += items
                total_services_with_resources += 1
        except:
            continue
    
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Total inventory files: {len(inv_files)}")
    print(f"Services with resources: {total_services_with_resources}")
    print(f"Total resources discovered: {total_resources}")
    print()
    print("To view a specific inventory file:")
    print("  cat output/latest/subscription_*/<service>_inventory.json | python3 -m json.tool")
    print()
    print("To open in your editor:")
    print("  code output/latest/subscription_*/<service>_inventory.json")
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
