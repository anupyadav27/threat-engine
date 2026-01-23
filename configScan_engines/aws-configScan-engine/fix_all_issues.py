#!/usr/bin/env python3
"""
Fix all parameter issues in configScan_engines YAML files.
- Route53 MaxItems type (string)
- EC2 limits
- EDR maxResults (camelCase)
- CodeBuild list_projects (remove MaxResults)
- CloudWatch MaxRecords
"""

import json
import yaml
from pathlib import Path
from typing import Dict, Optional

CONFIG_DIR = Path(__file__).parent / "config"
MAPPING_FILE = CONFIG_DIR / "parameter_name_mapping.json"

def load_parameter_mapping() -> Dict:
    """Load parameter name mapping from config file."""
    with open(MAPPING_FILE, 'r') as f:
        return json.load(f)

def get_correct_parameter_info(service: str, action: str, mapping: Dict) -> Optional[tuple]:
    """
    Get the correct parameter name, value, and type for a service/action.
    Returns (param_name, param_value, param_type) or None if operation doesn't support pagination.
    """
    # Check if operation doesn't support MaxResults
    no_maxresults = mapping.get("no_maxresults_operations", {})
    if service in no_maxresults and action in no_maxresults[service]:
        return None
    
    # Get parameter name mapping
    param_mapping = mapping.get("maxresults_parameter", {})
    
    # Determine parameter name
    param_name = None
    for param_type, services in param_mapping.items():
        if service in services:
            param_name = param_type
            break
    
    if not param_name:
        param_name = "MaxResults"
    
    # Special case: Route53 list_* operations use MaxItems
    if service == "route53" and action.startswith("list_"):
        param_name = "MaxItems"
    
    # Special case: CloudWatch uses MaxRecords
    if service == "cloudwatch" and "describe_alarm" in action:
        param_name = "MaxRecords"
    
    # Get service-specific limits
    service_limits = mapping.get("service_specific_limits", {}).get(service, {})
    param_limits = service_limits.get(param_name, {})
    
    # Get limit for this action or use default
    if action in param_limits:
        param_value = param_limits[action]
    elif "default" in param_limits:
        param_value = param_limits["default"]
    else:
        param_value = 1000
    
    # Determine parameter type
    if service == "route53" and param_name == "MaxItems":
        param_type = "string"
    else:
        param_type = "int"
    
    return (param_name, param_value, param_type)

def fix_yaml_file(yaml_file: Path, mapping: Dict) -> Dict:
    """Fix parameter types and values in a YAML file."""
    stats = {
        'modified': False,
        'params_fixed': 0,
        'params_added': 0,
        'params_removed': 0,
        'errors': 0
    }
    
    try:
        with open(yaml_file, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        if not data:
            return stats
        
        # Handle both discovery and discovery sections
        discovery_section = data.get('discovery', [])
        if not discovery_section:
            return stats
        
        service_name = yaml_file.parent.parent.name
        
        # Process each discovery
        for discovery in discovery_section:
            calls = discovery.get('calls', [])
            for call in calls:
                action = call.get('action', '')
                
                # Skip if not a list/describe operation
                if not (action.startswith('list_') or action.startswith('describe_')):
                    continue
                
                # Get correct parameter info
                param_info = get_correct_parameter_info(service_name, action, mapping)
                
                if param_info is None:
                    # Operation doesn't support pagination - remove if present
                    params = call.get('params', {})
                    pagination_params = ['MaxResults', 'maxResults', 'MaxRecords', 'Limit', 'MaxItems']
                    removed = False
                    for param in pagination_params:
                        if param in params:
                            del params[param]
                            removed = True
                    if removed:
                        stats['params_removed'] += 1
                        stats['modified'] = True
                    continue
                
                param_name, param_value, param_type = param_info
                
                # Ensure params dict exists
                if 'params' not in call:
                    call['params'] = {}
                
                params = call['params']
                
                # Remove incorrect parameter names
                pagination_params = ['MaxResults', 'maxResults', 'MaxRecords', 'Limit', 'MaxItems']
                for old_param in pagination_params:
                    if old_param != param_name and old_param in params:
                        # If we're replacing with a different param name, preserve value
                        if param_name not in params:
                            value = params[old_param]
                            del params[old_param]
                            # Convert value based on type
                            if param_type == "string":
                                params[param_name] = str(value)
                            else:
                                params[param_name] = value
                        else:
                            del params[old_param]
                        stats['params_fixed'] += 1
                        stats['modified'] = True
                
                # Add or fix parameter
                if param_name not in params:
                    # Add parameter with correct type
                    if param_type == "string":
                        params[param_name] = str(param_value)
                    else:
                        params[param_name] = param_value
                    stats['params_added'] += 1
                    stats['modified'] = True
                else:
                    # Fix existing parameter
                    current_value = params[param_name]
                    current_type = type(current_value).__name__
                    
                    # Fix type if wrong
                    if param_type == "string" and current_type != "str":
                        params[param_name] = str(current_value)
                        stats['params_fixed'] += 1
                        stats['modified'] = True
                    elif param_type == "int" and current_type == "str":
                        try:
                            params[param_name] = int(current_value)
                            stats['params_fixed'] += 1
                            stats['modified'] = True
                        except ValueError:
                            pass
                    
                    # Fix value if wrong (check limits)
                    if isinstance(current_value, (int, str)):
                        try:
                            current_int = int(current_value)
                            if current_int != param_value:
                                # Update to correct limit
                                if param_type == "string":
                                    params[param_name] = str(param_value)
                                else:
                                    params[param_name] = param_value
                                stats['params_fixed'] += 1
                                stats['modified'] = True
                        except ValueError:
                            pass
        
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
    print("=" * 80)
    print("FIXING ALL PARAMETER ISSUES IN CONFIGSCAN_ENGINES YAML FILES")
    print("=" * 80)
    print()
    
    # Load mapping
    if not MAPPING_FILE.exists():
        print(f"❌ Mapping file not found: {MAPPING_FILE}")
        return
    
    mapping = load_parameter_mapping()
    print(f"✅ Loaded parameter mapping from {MAPPING_FILE}")
    print()
    
    # Find all discovery YAML files
    services_dir = Path(__file__).parent / "services"
    yaml_files = list(services_dir.glob('*/discoveries/*.yaml'))
    yaml_files.extend(list(services_dir.glob('*/rules/*.discoveries.yaml')))
    yaml_files.extend(list(services_dir.glob('*/rules/*.nested.yaml')))
    
    if not yaml_files:
        print(f"❌ No YAML files found in {services_dir}")
        return
    
    print(f"✅ Found {len(yaml_files)} YAML files to process")
    print()
    
    total_stats = {
        'files_processed': 0,
        'files_modified': 0,
        'params_fixed': 0,
        'params_added': 0,
        'params_removed': 0,
        'errors': 0
    }
    
    modified_services = {}
    
    for yaml_file in sorted(yaml_files):
        service_name = yaml_file.parent.parent.name if yaml_file.parent.name != 'discoveries' else yaml_file.parent.parent.name
        total_stats['files_processed'] += 1
        
        stats = fix_yaml_file(yaml_file, mapping)
        
        total_stats['params_fixed'] += stats['params_fixed']
        total_stats['params_added'] += stats['params_added']
        total_stats['params_removed'] += stats['params_removed']
        total_stats['errors'] += stats['errors']
        
        if stats['modified']:
            total_stats['files_modified'] += 1
            if service_name not in modified_services:
                modified_services[service_name] = {
                    'fixed': 0,
                    'added': 0,
                    'removed': 0
                }
            modified_services[service_name]['fixed'] += stats['params_fixed']
            modified_services[service_name]['added'] += stats['params_added']
            modified_services[service_name]['removed'] += stats['params_removed']
    
    print("=" * 80)
    print("📊 RESULTS:")
    print(f"   Files processed: {total_stats['files_processed']}")
    print(f"   Files modified: {total_stats['files_modified']}")
    print(f"   Parameters fixed: {total_stats['params_fixed']}")
    print(f"   Parameters added: {total_stats['params_added']}")
    print(f"   Parameters removed: {total_stats['params_removed']}")
    print(f"   Errors: {total_stats['errors']}")
    print()
    
    if modified_services:
        print("✅ SERVICES FIXED:")
        for service, svc_stats in sorted(modified_services.items()):
            print(f"   - {service}: {svc_stats['fixed']} fixed, {svc_stats['added']} added, {svc_stats['removed']} removed")
        print()
    
    print("=" * 80)

if __name__ == '__main__':
    main()

