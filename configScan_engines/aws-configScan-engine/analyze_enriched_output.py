#!/usr/bin/env python3
"""Analyze output from enriched services scan"""
import json
import sys
from pathlib import Path
from collections import defaultdict

def analyze_inventory_file(inventory_path: Path):
    """Analyze a single inventory file"""
    results = {
        'total_items': 0,
        'services': defaultdict(int),
        'resource_types': defaultdict(int),
        'fields_per_service': defaultdict(set),
        'sample_items': {}
    }
    
    try:
        with open(inventory_path, 'r') as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)
                    results['total_items'] += 1
                    
                    service = item.get('service', 'unknown')
                    resource_type = item.get('resource_type', 'unknown')
                    
                    results['services'][service] += 1
                    results['resource_types'][resource_type] += 1
                    
                    # Collect all field names per service
                    for key in item.keys():
                        if not key.startswith('_') and key not in ['schema_version', 'tenant_id', 'scan_run_id', 'provider', 'account_id', 'region', 'scope', 'metadata', 'hash_sha256']:
                            results['fields_per_service'][service].add(key)
                    
                    # Store sample items (first 2 per service)
                    if service not in results['sample_items'] or len(results['sample_items'][service]) < 2:
                        if service not in results['sample_items']:
                            results['sample_items'][service] = []
                        results['sample_items'][service].append(item)
                        
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        return None
    
    return results

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 analyze_enriched_output.py <scan_output_directory>")
        sys.exit(1)
    
    scan_dir = Path(sys.argv[1])
    if not scan_dir.exists():
        print(f"Error: Directory not found: {scan_dir}")
        sys.exit(1)
    
    print("=" * 80)
    print("ANALYZING ENRICHED SERVICES OUTPUT")
    print("=" * 80)
    print(f"Scan directory: {scan_dir}")
    print()
    
    # Find inventory files
    inventory_files = list(scan_dir.glob("inventory_*.ndjson"))
    if not inventory_files:
        print("No inventory files found!")
        sys.exit(1)
    
    print(f"Found {len(inventory_files)} inventory file(s)")
    print()
    
    # Analyze all inventory files
    combined_results = {
        'total_items': 0,
        'services': defaultdict(int),
        'resource_types': defaultdict(int),
        'fields_per_service': defaultdict(set),
        'sample_items': {}
    }
    
    for inv_file in inventory_files:
        print(f"Analyzing: {inv_file.name}")
        file_results = analyze_inventory_file(inv_file)
        if file_results:
            combined_results['total_items'] += file_results['total_items']
            for service, count in file_results['services'].items():
                combined_results['services'][service] += count
            for rtype, count in file_results['resource_types'].items():
                combined_results['resource_types'][rtype] += count
            for service, fields in file_results['fields_per_service'].items():
                combined_results['fields_per_service'][service].update(fields)
            for service, items in file_results['sample_items'].items():
                if service not in combined_results['sample_items']:
                    combined_results['sample_items'][service] = []
                combined_results['sample_items'][service].extend(items[:2])
    
    print()
    print("=" * 80)
    print("ANALYSIS RESULTS")
    print("=" * 80)
    print(f"\n📊 Total Resources: {combined_results['total_items']}")
    
    print(f"\n📦 Resources by Service:")
    for service, count in sorted(combined_results['services'].items()):
        print(f"   {service}: {count}")
    
    print(f"\n🏷️  Resource Types (top 10):")
    for rtype, count in sorted(combined_results['resource_types'].items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"   {rtype}: {count}")
    
    print(f"\n🔍 Fields per Service (explicit emit fields verification):")
    for service in sorted(combined_results['fields_per_service'].keys()):
        fields = sorted(combined_results['fields_per_service'][service])
        print(f"\n   {service.upper()} ({len(fields)} fields):")
        # Show first 20 fields
        for field in fields[:20]:
            print(f"      - {field}")
        if len(fields) > 20:
            print(f"      ... and {len(fields) - 20} more fields")
    
    print(f"\n📋 Sample Items (first item per service):")
    for service in sorted(combined_results['sample_items'].keys()):
        if combined_results['sample_items'][service]:
            item = combined_results['sample_items'][service][0]
            print(f"\n   {service.upper()}:")
            print(f"      Resource ID: {item.get('resource_id', 'N/A')}")
            print(f"      Resource Type: {item.get('resource_type', 'N/A')}")
            print(f"      Name: {item.get('name', 'N/A')}")
            # Show some explicit emit fields
            explicit_fields = [k for k in item.keys() if k not in ['schema_version', 'tenant_id', 'scan_run_id', 'provider', 'service', 'account_id', 'region', 'scope', 'resource_type', 'resource_id', 'resource_arn', 'resource_uid', 'name', 'tags', 'metadata', 'hash_sha256', 'environment', 'category', 'lifecycle_state', 'health_status', 'created_at', 'updated_at', 'is_aws_managed']]
            if explicit_fields:
                print(f"      Explicit Emit Fields (sample): {', '.join(explicit_fields[:10])}")
                if len(explicit_fields) > 10:
                    print(f"      ... and {len(explicit_fields) - 10} more explicit fields")
    
    print("\n" + "=" * 80)
    print("✅ Analysis Complete")
    print("=" * 80)

if __name__ == "__main__":
    main()

