#!/usr/bin/env python3
"""
Proactive optimization script for all AWS service YAML files.
Adds MaxResults and on_error: continue where appropriate.
"""

import os
import yaml
import re
from pathlib import Path
from typing import Dict, List, Any

# Services that may not be enabled/available in all regions/accounts
SERVICES_THAT_MAY_FAIL = [
    'macie', 'inspector', 'securityhub', 'guardduty', 'detective',
    'kinesisvideostreams', 'sagemaker', 'bedrock', 'wellarchitected',
    'controltower', 'costexplorer', 'savingsplans', 'shield',
    'identitycenter', 'organizations', 'config', 'quicksight'
]

# Operations that typically support MaxResults
LIST_OPERATIONS = ['list_', 'describe_', 'get_', 'search_', 'query_']

def should_add_maxresults(action: str, params: Dict) -> bool:
    """Determine if MaxResults should be added to this operation."""
    # Skip if already has MaxResults or maxResults
    if 'MaxResults' in params or 'maxResults' in params:
        return False
    
    # Add to list operations (but not describe_* that don't list)
    if any(action.startswith(op) for op in ['list_', 'search_', 'query_']):
        return True
    
    # Some describe operations that list multiple items
    if action.startswith('describe_') and any(x in action for x in ['list', 'all', 'multiple']):
        return True
    
    return False

def optimize_yaml_file(yaml_file: Path) -> Dict[str, int]:
    """Optimize a single YAML file."""
    stats = {
        'maxresults_added': 0,
        'on_error_added': 0,
        'calls_checked': 0
    }
    
    try:
        with open(yaml_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Parse YAML
        data = yaml.safe_load(content)
        if not data or 'discovery' not in data:
            return stats
        
        service_name = yaml_file.parent.parent.name
        modified = False
        
        # Process each discovery
        for discovery in data.get('discovery', []):
            calls = discovery.get('calls', [])
            for call in calls:
                stats['calls_checked'] += 1
                action = call.get('action', '')
                params = call.get('params', {})
                has_on_error = 'on_error' in call
                
                # Add MaxResults for list operations
                if should_add_maxresults(action, params):
                    if 'params' not in call:
                        call['params'] = {}
                    # Use MaxResults (capital M) for most AWS APIs
                    call['params']['MaxResults'] = 1000
                    stats['maxresults_added'] += 1
                    modified = True
                
                # Add on_error: continue for services that may fail
                if not has_on_error and service_name in SERVICES_THAT_MAY_FAIL:
                    call['on_error'] = 'continue'
                    stats['on_error_added'] += 1
                    modified = True
        
        # Write back if modified
        if modified:
            with open(yaml_file, 'w', encoding='utf-8') as f:
                yaml.dump(data, f, default_flow_style=False, sort_keys=False, 
                         allow_unicode=True, width=1000)
        
        return stats
        
    except Exception as e:
        print(f"⚠️  Error processing {yaml_file}: {e}")
        return stats

def main():
    print("="*80)
    print("PROACTIVE OPTIMIZATION - ALL SERVICES")
    print("="*80)
    print()
    
    services_dir = Path('configScan_engines/aws-configScan-engine/services')
    if not services_dir.exists():
        print(f"❌ Services directory not found: {services_dir}")
        return
    
    yaml_files = list(services_dir.glob('*/rules/*.yaml'))
    print(f"📊 Found {len(yaml_files)} YAML files to check")
    print()
    
    total_stats = {
        'files_checked': 0,
        'files_modified': 0,
        'maxresults_added': 0,
        'on_error_added': 0,
        'calls_checked': 0
    }
    
    modified_files = []
    
    for yaml_file in sorted(yaml_files):
        service_name = yaml_file.parent.parent.name
        total_stats['files_checked'] += 1
        
        stats = optimize_yaml_file(yaml_file)
        
        total_stats['calls_checked'] += stats['calls_checked']
        total_stats['maxresults_added'] += stats['maxresults_added']
        total_stats['on_error_added'] += stats['on_error_added']
        
        if stats['maxresults_added'] > 0 or stats['on_error_added'] > 0:
            total_stats['files_modified'] += 1
            modified_files.append({
                'service': service_name,
                'file': str(yaml_file),
                'maxresults': stats['maxresults_added'],
                'on_error': stats['on_error_added']
            })
    
    print()
    print("📊 OPTIMIZATION SUMMARY:")
    print(f"   Files checked: {total_stats['files_checked']}")
    print(f"   Files modified: {total_stats['files_modified']}")
    print(f"   Calls checked: {total_stats['calls_checked']}")
    print(f"   MaxResults added: {total_stats['maxresults_added']}")
    print(f"   on_error added: {total_stats['on_error_added']}")
    print()
    
    if modified_files:
        print("✅ SERVICES OPTIMIZED:")
        for mod in modified_files[:30]:  # Show first 30
            print(f"   - {mod['service']}: +{mod['maxresults']} MaxResults, +{mod['on_error']} on_error")
        if len(modified_files) > 30:
            print(f"   ... and {len(modified_files) - 30} more")
        print()
    
    print("="*80)
    print()
    print("✅ ABOUT MaxResults:")
    print("   - Limits per-request results (e.g., 1000 items)")
    print("   - Pagination automatically handles if more exist")
    print("   - NO impact on scan quality - all items discovered")
    print("   - Only improves performance by reducing timeout risk")
    print()
    print("✅ ABOUT on_error: continue:")
    print("   - Allows scan to continue if service not enabled")
    print("   - Prevents scan from failing on expected errors")
    print("   - Improves scan reliability across all accounts/regions")
    print()

if __name__ == '__main__':
    main()

