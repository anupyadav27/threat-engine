#!/usr/bin/env python3
"""
Comprehensive audit and fix script for ALL services.
Finds and fixes missing customer-managed filters and MaxResults.
"""
import os
import glob
import yaml
import re

services_dir = 'services'
yaml_files = glob.glob(f'{services_dir}/*/rules/*.yaml')

print("="*80)
print("COMPREHENSIVE SERVICE AUDIT & FIX")
print("="*80)
print()

# Track what needs fixing
fixes_needed = []

for yaml_file in sorted(yaml_files):
    service = yaml_file.split('/')[-3]
    
    try:
        with open(yaml_file, 'r') as f:
            content = f.read()
            data = yaml.safe_load(content) if content else {}
    except Exception as e:
        print(f"⚠️  Error reading {service}: {e}")
        continue
    
    discoveries = data.get('discovery', [])
    
    for disc_idx, disc in enumerate(discoveries):
        disc_id = disc.get('discovery_id', '')
        calls = disc.get('calls', [])
        
        for call_idx, call in enumerate(calls):
            action = call.get('action', '')
            params = call.get('params', {})
            
            # Check snapshot/image operations for customer filters
            if 'snapshot' in action.lower() or 'image' in action.lower():
                if 'describe_snapshots' in action or 'describe_images' in action or 'describe_db_cluster_snapshots' in action:
                    has_filter = any(key in str(params) for key in ['OwnerIds', 'Owners', 'IncludeShared', 'IncludePublic'])
                    if not has_filter:
                        # Determine appropriate filter
                        if 'ec2' in action or 'ebs' in service:
                            filter_type = 'OwnerIds'
                            filter_value = "['self']"
                        elif 'db_cluster_snapshots' in action:
                            filter_type = 'IncludeShared/IncludePublic'
                            filter_value = 'false'
                        else:
                            filter_type = 'Unknown'
                            filter_value = None
                        
                        fixes_needed.append({
                            'file': yaml_file,
                            'service': service,
                            'disc_idx': disc_idx,
                            'call_idx': call_idx,
                            'action': action,
                            'type': 'customer_filter',
                            'filter_type': filter_type,
                            'filter_value': filter_value
                        })
            
            # Check list operations for MaxResults
            if 'list_' in action.lower():
                has_max = any(key in str(params) for key in ['MaxResults', 'MaxRecords', 'Limit', 'MaxItems'])
                if not has_max:
                    # Determine appropriate MaxResults parameter name
                    if 'rds' in service or 'docdb' in service or 'neptune' in service:
                        max_param = 'MaxRecords'
                        max_value = 100
                    elif 'dynamodb' in service or 'kinesis' in service or 'kms' in service:
                        max_param = 'Limit'
                        max_value = 1000
                    elif 'route53' in service or 'cloudfront' in service:
                        max_param = 'MaxItems'
                        max_value = 1000 if 'route53' in service else 100
                    else:
                        max_param = 'MaxResults'
                        max_value = 1000
                    
                    fixes_needed.append({
                        'file': yaml_file,
                        'service': service,
                        'disc_idx': disc_idx,
                        'call_idx': call_idx,
                        'action': action,
                        'type': 'maxresults',
                        'max_param': max_param,
                        'max_value': max_value
                    })

print(f"📊 FOUND {len(fixes_needed)} OPTIMIZATIONS NEEDED")
print()

# Group by type
customer_filter_fixes = [f for f in fixes_needed if f['type'] == 'customer_filter']
maxresults_fixes = [f for f in fixes_needed if f['type'] == 'maxresults']

print(f"1. Customer Filters: {len(customer_filter_fixes)}")
for fix in customer_filter_fixes[:10]:
    print(f"   - {fix['service']}.{fix['action']}")
if len(customer_filter_fixes) > 10:
    print(f"   ... and {len(customer_filter_fixes) - 10} more")

print()
print(f"2. MaxResults: {len(maxresults_fixes)}")
for fix in maxresults_fixes[:20]:
    print(f"   - {fix['service']}.{fix['action']}")
if len(maxresults_fixes) > 20:
    print(f"   ... and {len(maxresults_fixes) - 20} more")

print()
print("="*80)
print("READY TO APPLY FIXES")
print("="*80)

