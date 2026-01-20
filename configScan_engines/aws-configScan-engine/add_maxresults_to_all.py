#!/usr/bin/env python3
"""
Add MaxResults to all list_* operations that don't have it.
"""

import yaml
import re
from pathlib import Path

# Default MaxResults value
DEFAULT_MAX_RESULTS = 1000

# Services that may need on_error: continue
SERVICES_THAT_MAY_FAIL = [
    'macie', 'inspector', 'securityhub', 'guardduty', 'detective',
    'kinesisvideostreams', 'sagemaker', 'bedrock', 'wellarchitected',
    'controltower', 'costexplorer', 'savingsplans', 'shield',
    'identitycenter', 'organizations', 'config', 'quicksight'
]

def add_maxresults_to_file(yaml_file: Path) -> dict:
    """Add MaxResults to list operations in a YAML file."""
    stats = {
        'maxresults_added': 0,
        'on_error_added': 0,
        'modified': False
    }
    
    try:
        with open(yaml_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Parse YAML
        data = yaml.safe_load(content)
        if not data or 'discovery' not in data:
            return stats
        
        service_name = yaml_file.parent.parent.name
        
        # Process each discovery
        for discovery in data.get('discovery', []):
            calls = discovery.get('calls', [])
            for call in calls:
                action = call.get('action', '')
                
                # Only process list_ operations
                if not action.startswith('list_'):
                    continue
                
                # Check if already has MaxResults
                params = call.get('params', {})
                has_maxresults = 'MaxResults' in params or 'maxResults' in params
                
                # Add MaxResults if missing
                if not has_maxresults:
                    if 'params' not in call:
                        call['params'] = {}
                    call['params']['MaxResults'] = DEFAULT_MAX_RESULTS
                    stats['maxresults_added'] += 1
                    stats['modified'] = True
                
                # Add on_error if service may fail
                has_on_error = 'on_error' in call
                if not has_on_error and service_name in SERVICES_THAT_MAY_FAIL:
                    call['on_error'] = 'continue'
                    stats['on_error_added'] += 1
                    stats['modified'] = True
        
        # Write back if modified
        if stats['modified']:
            with open(yaml_file, 'w', encoding='utf-8') as f:
                yaml.dump(data, f, default_flow_style=False, sort_keys=False,
                         allow_unicode=True, width=1000)
        
        return stats
        
    except Exception as e:
        print(f"Error processing {yaml_file}: {e}")
        return stats

def main():
    print("="*80)
    print("ADDING MaxResults TO ALL list_* OPERATIONS")
    print("="*80)
    print()
    
    services_dir = Path('configScan_engines/aws-configScan-engine/services')
    if not services_dir.exists():
        print(f"❌ Services directory not found: {services_dir}")
        return
    
    yaml_files = list(services_dir.glob('*/rules/*.yaml'))
    
    total_stats = {
        'files_processed': 0,
        'files_modified': 0,
        'maxresults_added': 0,
        'on_error_added': 0
    }
    
    modified_files = []
    
    for yaml_file in sorted(yaml_files):
        service_name = yaml_file.parent.parent.name
        total_stats['files_processed'] += 1
        
        stats = add_maxresults_to_file(yaml_file)
        
        total_stats['maxresults_added'] += stats['maxresults_added']
        total_stats['on_error_added'] += stats['on_error_added']
        
        if stats['modified']:
            total_stats['files_modified'] += 1
            modified_files.append({
                'service': service_name,
                'maxresults': stats['maxresults_added'],
                'on_error': stats['on_error_added']
            })
    
    print("📊 RESULTS:")
    print(f"   Files processed: {total_stats['files_processed']}")
    print(f"   Files modified: {total_stats['files_modified']}")
    print(f"   MaxResults added: {total_stats['maxresults_added']}")
    print(f"   on_error added: {total_stats['on_error_added']}")
    print()
    
    if modified_files:
        print("✅ SERVICES OPTIMIZED:")
        for mod in modified_files:
            print(f"   - {mod['service']}: +{mod['maxresults']} MaxResults, +{mod['on_error']} on_error")
        print()
    
    print("="*80)

if __name__ == '__main__':
    main()

