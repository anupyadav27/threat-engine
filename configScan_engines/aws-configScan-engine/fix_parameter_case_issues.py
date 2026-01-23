#!/usr/bin/env python3
"""
Fix parameter case sensitivity issues in discovery YAML files.
Uses parameter_name_mapping.json to correct MaxResults vs maxResults.
"""

import json
import yaml
from pathlib import Path
from typing import Dict, List, Optional

# Load parameter mapping
CONFIG_DIR = Path(__file__).parent / "config"
MAPPING_FILE = CONFIG_DIR / "parameter_name_mapping.json"

def load_parameter_mapping() -> Dict:
    """Load parameter name mapping from config file."""
    with open(MAPPING_FILE, 'r') as f:
        return json.load(f)

def get_correct_parameter_name(service: str, action: str, mapping: Dict) -> Optional[str]:
    """
    Get the correct parameter name for a service/action.
    Returns None if operation doesn't support pagination.
    """
    # Check if operation doesn't support MaxResults
    no_maxresults = mapping.get("no_maxresults_operations", {})
    if service in no_maxresults and action in no_maxresults[service]:
        return None
    
    # Get parameter name mapping
    param_mapping = mapping.get("maxresults_parameter", {})
    
    # Check each parameter name type
    for param_name, services in param_mapping.items():
        if service in services:
            # Check for service-specific limits
            service_limits = mapping.get("service_specific_limits", {}).get(service, {})
            if param_name in service_limits:
                action_limits = service_limits[param_name]
                if action in action_limits:
                    return param_name
                elif "default" in action_limits:
                    return param_name
            return param_name
    
    # Default to MaxResults if not found
    return "MaxResults"

def fix_yaml_file(yaml_file: Path, mapping: Dict) -> Dict:
    """Fix parameter names in a YAML file."""
    stats = {
        'fixed': 0,
        'skipped': 0,
        'errors': 0,
        'modified': False
    }
    
    try:
        with open(yaml_file, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        if not data or 'discovery' not in data:
            return stats
        
        service_name = yaml_file.parent.parent.name
        
        # Process each discovery
        for discovery in data.get('discovery', []):
            calls = discovery.get('calls', [])
            for call in calls:
                action = call.get('action', '')
                params = call.get('params', {})
                
                # Check for incorrect parameter names
                incorrect_params = ['MaxResults', 'maxResults', 'MaxRecords', 'Limit', 'MaxItems']
                found_incorrect = None
                for param in incorrect_params:
                    if param in params:
                        found_incorrect = param
                        break
                
                if found_incorrect:
                    # Get correct parameter name
                    correct_param = get_correct_parameter_name(service_name, action, mapping)
                    
                    if correct_param is None:
                        # Operation doesn't support pagination - remove parameter
                        del params[found_incorrect]
                        stats['fixed'] += 1
                        stats['modified'] = True
                        print(f"  ✅ Removed {found_incorrect} from {service_name}.{action} (not supported)")
                    elif correct_param != found_incorrect:
                        # Wrong parameter name - fix it
                        value = params.pop(found_incorrect)
                        params[correct_param] = value
                        stats['fixed'] += 1
                        stats['modified'] = True
                        print(f"  ✅ Fixed {service_name}.{action}: {found_incorrect} → {correct_param}")
                    else:
                        stats['skipped'] += 1
        
        # Write back if modified
        if stats['modified']:
            with open(yaml_file, 'w', encoding='utf-8') as f:
                yaml.dump(data, f, default_flow_style=False, sort_keys=False,
                         allow_unicode=True, width=1000)
        
        return stats
        
    except Exception as e:
        print(f"  ❌ Error processing {yaml_file}: {e}")
        stats['errors'] += 1
        return stats

def main():
    print("="*80)
    print("FIXING PARAMETER CASE SENSITIVITY ISSUES")
    print("="*80)
    print()
    
    # Load mapping
    if not MAPPING_FILE.exists():
        print(f"❌ Mapping file not found: {MAPPING_FILE}")
        print("   Creating default mapping file...")
        # Create default mapping (already created above)
        return
    
    mapping = load_parameter_mapping()
    print(f"✅ Loaded parameter mapping from {MAPPING_FILE}")
    print()
    
    # Find all discovery YAML files
    # Try multiple possible locations
    possible_dirs = [
        Path('services'),
        Path('engines-input/aws-configScan-engine/input/rule_db/default/services'),
        Path(__file__).parent / 'services'
    ]
    
    services_dir = None
    for dir_path in possible_dirs:
        if dir_path.exists():
            services_dir = dir_path
            break
    
    if not services_dir:
        print(f"❌ Services directory not found. Tried: {[str(d) for d in possible_dirs]}")
        return
    
    print(f"✅ Using services directory: {services_dir}")
    
    # Look for discovery files in both discoveries/ and rules/ subdirectories
    yaml_files = list(services_dir.glob('*/discoveries/*.yaml'))
    yaml_files.extend(list(services_dir.glob('*/rules/*.discoveries.yaml')))
    yaml_files = [f for f in yaml_files if f.name != '*.checks.yaml']  # Skip check files
    
    print(f"📁 Found {len(yaml_files)} discovery YAML files")
    print()
    
    total_stats = {
        'files_processed': 0,
        'files_modified': 0,
        'total_fixed': 0,
        'total_skipped': 0,
        'total_errors': 0
    }
    
    modified_files = []
    
    for yaml_file in sorted(yaml_files):
        service_name = yaml_file.parent.parent.name
        total_stats['files_processed'] += 1
        
        print(f"Processing {service_name}...")
        stats = fix_yaml_file(yaml_file, mapping)
        
        total_stats['total_fixed'] += stats['fixed']
        total_stats['total_skipped'] += stats['skipped']
        total_stats['total_errors'] += stats['errors']
        
        if stats['modified']:
            total_stats['files_modified'] += 1
            modified_files.append({
                'service': service_name,
                'fixed': stats['fixed']
            })
        else:
            print(f"  ⏭️  No changes needed")
        print()
    
    print("="*80)
    print("📊 RESULTS:")
    print(f"   Files processed: {total_stats['files_processed']}")
    print(f"   Files modified: {total_stats['files_modified']}")
    print(f"   Parameters fixed: {total_stats['total_fixed']}")
    print(f"   Parameters skipped: {total_stats['total_skipped']}")
    print(f"   Errors: {total_stats['total_errors']}")
    print()
    
    if modified_files:
        print("✅ SERVICES FIXED:")
        for mod in modified_files:
            print(f"   - {mod['service']}: {mod['fixed']} fixes")
        print()
    
    print("="*80)

if __name__ == '__main__':
    main()

