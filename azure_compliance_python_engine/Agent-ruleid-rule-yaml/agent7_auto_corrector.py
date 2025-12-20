"""
Agent 7: Auto-Corrector (Azure)

Applies fixes from Agent 6 to YAML files.

Input: output/error_analysis_and_fixes.json
Output: Updated YAML files in services/*/rules/

Then triggers Agent 5 again for re-testing (recursive loop).
"""

import json
import yaml
import re
import os
from typing import Dict
from agent_logger import get_logger

logger = get_logger('agent7')


def fix_template_variables(discovery: dict, parent_emit: dict = None) -> bool:
    """
    Fix template variable resolution issues in a discovery.
    
    Common issues:
    - {{ item.id }} should be {{ item.name }} or similar
    - Missing fields in parent emit
    - Wrong field names in params
    
    Returns True if fixed
    """
    fixed = False
    
    # Check if this discovery has for_each
    if 'for_each' not in discovery:
        return False
    
    # Check params for unresolved templates
    if 'calls' in discovery:
        for call in discovery['calls']:
            if 'params' in call:
                for param_name, param_value in call['params'].items():
                    if isinstance(param_value, str) and '{{ item.' in param_value:
                        # Extract field name
                        match = re.search(r'\{\{\s*item\.(\w+)\s*\}\}', param_value)
                        if match:
                            field = match.group(1)
                            
                            # Common fixes for Azure field names
                            field_fixes = {
                                'id': ['name', 'id', 'resource_id'],
                                'name': ['name', 'id', 'resource_name'],
                                'resource_group': ['resource_group_name', 'resourceGroup'],
                            }
                            
                            if field in field_fixes:
                                # Try first alternative
                                new_field = field_fixes[field][0]
                                new_value = param_value.replace(f'{{{{ item.{field} }}}}', f'{{{{ item.{new_field} }}}}')
                                call['params'][param_name] = new_value
                                fixed = True
                                logger.info(f"Fixed template: {{ item.{field} }} → {{ item.{new_field} }}")
    
    return fixed


def apply_fixes(fixes: dict) -> int:
    """
    Apply fixes to YAML files.
    
    Returns:
        Number of fixes applied
    """
    fixes_applied = 0
    
    for service, service_fixes in fixes.items():
        yaml_file = f'../services/{service}/rules/{service}.yaml'
        
        print(f"\n📦 {service}")
        
        # Check if file exists
        if not os.path.exists(yaml_file):
            print(f"   ⚠️  YAML file not found: {yaml_file}")
            logger.warning(f"YAML file not found: {yaml_file}")
            continue
        
        # Load YAML
        try:
            with open(yaml_file) as f:
                data = yaml.safe_load(f)
        except Exception as e:
            print(f"   ❌ Failed to load YAML: {e}")
            logger.error(f"Failed to load YAML {yaml_file}: {e}")
            continue
        
        service_fixed = False
        
        # Apply fixes based on error type
        for fix in service_fixes:
            error_type = fix['error_type']
            
            if error_type == 'template_not_resolved':
                # Fix template variable issues in discoveries
                if 'discovery' in data:
                    for discovery in data['discovery']:
                        if fix_template_variables(discovery):
                            service_fixed = True
                            fixes_applied += 1
                            print(f"   ✅ Fixed template variables")
            
            elif error_type == 'missing_parameter':
                print(f"   ⏭️  Skipping missing_parameter (needs manual fix)")
            
            elif error_type == 'invalid_parameter':
                print(f"   ⏭️  Skipping invalid_parameter (needs manual fix)")
            
            elif error_type == 'field_access_error':
                print(f"   ⏭️  Skipping field_access_error (needs manual fix)")
            
            elif error_type == 'authentication_error':
                print(f"   ⏭️  Skipping authentication_error (check credentials)")
            
            else:
                print(f"   ⏭️  Skipping {error_type} (needs manual review)")
        
        # Save updated YAML if fixes were applied
        if service_fixed:
            try:
                with open(yaml_file, 'w') as f:
                    yaml.dump(data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
                print(f"   ✅ Updated YAML saved")
                logger.info(f"Updated YAML: {yaml_file}")
            except Exception as e:
                print(f"   ❌ Failed to save: {e}")
                logger.error(f"Failed to save {yaml_file}: {e}")
        else:
            print(f"   ⏭️  No automated fixes available")
    
    return fixes_applied


def main():
    logger.info("Agent 7 starting - Auto-Corrector")
    print("=" * 80)
    print("AGENT 7: Auto-Corrector (Azure)")
    print("=" * 80)
    
    # Check if fixes file exists
    fixes_file = 'output/error_analysis_and_fixes.json'
    if not os.path.exists(fixes_file):
        print("❌ error_analysis_and_fixes.json not found")
        print("Run Agent 6 first: python3 agent6_error_analyzer.py")
        return
    
    # Load fixes
    with open(fixes_file) as f:
        fixes = json.load(f)
    
    if not fixes:
        print("\n✅ No fixes needed - no errors found")
        return
    
    # Apply
    count = apply_fixes(fixes)
    
    print("\n" + "=" * 80)
    print(f"✅ Applied {count} fixes")
    print("=" * 80)
    print(f"\nNext: Re-run Agent 5 to test again")
    logger.info(f"Agent 7 complete: {count} fixes applied")


if __name__ == '__main__':
    main()
