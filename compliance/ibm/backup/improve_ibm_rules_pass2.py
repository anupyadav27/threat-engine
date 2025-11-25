#!/usr/bin/env python3
"""
IBM Cloud CSPM - Second Pass Assertion Improvements

This script handles the remaining assertion improvements that need
more sophisticated pattern matching and context awareness.
"""

import yaml
from datetime import datetime
from collections import defaultdict

# Enhanced assertion improvements - more comprehensive patterns
ENHANCED_ASSERTION_IMPROVEMENTS = {
    # Remaining _check patterns
    'workgroup_encryption_check': 'workgroup_encryption_enabled',
    'dataset_cmk_encryption_check': 'dataset_cmk_encryption_enabled',
    'dataset_public_access_check': 'dataset_public_access_blocked',
    'table_cmk_encryption_check': 'table_cmk_encryption_enabled',
    'project_artifact_encryption_check': 'project_artifact_encryption_enabled',
    'project_older_90_days_check': 'project_age_90_days_maximum',
    
    # Access control patterns
    'public_access': 'public_access_blocked',
    'access_policies_least_privilege': 'access_policies_least_privilege_enforced',
    'identity_access_rbac_no_inline_policies': 'rbac_inline_policies_prohibited',
    'roles_least_privilege': 'roles_least_privilege_enforced',
    'role_allow_assume_from_anything': 'role_assume_from_any_blocked',
    
    # Configuration patterns
    'definition_version_pinned': 'definition_version_pinned_required',
    'source_trusted': 'source_trust_verified',
    'multi_az': 'multi_az_deployment_enabled',
    'copy_tags_to_snapshots': 'copy_tags_to_snapshots_enabled',
    'defined': 'policy_defined',
    'retention_days_minimum': 'retention_days_minimum_configured',
    
    # Versioning and lifecycle
    'version_pinned': 'version_pinned_required',
    'lifecycle_policy': 'lifecycle_policy_configured',
    'versioning': 'versioning_enabled',
    
    # Monitoring and alerting
    'alerts_configured': 'alerts_configured',
    'notification_configured': 'notifications_configured',
    
    # Compliance
    'compliant': 'compliance_validated',
    'compliance': 'compliance_validated',
}

# Pattern-based improvements for common suffixes
PATTERN_IMPROVEMENTS = {
    # Any assertion ending with these should be improved
    '_in_use': '_in_use_blocked',  # e.g., rsasha1_in_use
    '_older_90_days': '_age_90_days_maximum',
    '_allow_': '_allow_blocked',  # Permissions that shouldn't exist
    '_no_': '_prohibited',  # Negative policies
    '_without_': '_required',  # Missing features
}

def apply_pattern_improvements(assertion: str) -> str:
    """Apply pattern-based improvements"""
    
    # Check for pattern matches
    for pattern, replacement in PATTERN_IMPROVEMENTS.items():
        if pattern in assertion:
            if pattern == '_in_use' and 'deprecated' in assertion or 'insecure' in assertion:
                return assertion.replace('_in_use', '_in_use_blocked')
            elif pattern == '_allow_' and 'anything' in assertion or 'all' in assertion:
                return assertion.replace(pattern, '_allow_blocked')
            elif pattern == '_no_' and 'policies' in assertion:
                return assertion.replace(pattern, '_prohibited')
            elif pattern == '_without_':
                return assertion.replace(pattern, '_required')
    
    # Handle specific patterns
    if assertion.endswith('_minimum') and 'days' in assertion:
        return assertion.replace('_minimum', '_minimum_configured')
    
    if assertion.endswith('_maximum') and not assertion.endswith('_configured'):
        return assertion + '_configured'
    
    # Handle 'least_privilege' patterns
    if 'least_privilege' in assertion and not assertion.endswith('_enforced'):
        return assertion + '_enforced'
    
    # Handle 'pinned' patterns
    if 'pinned' in assertion and not assertion.endswith('_required') and not assertion.endswith('_enabled'):
        return assertion + '_required'
    
    # Handle 'trusted' patterns
    if assertion.endswith('_trusted') or assertion == 'source_trusted':
        return assertion.replace('_trusted', '_trust_verified')
    
    return assertion

def improve_assertion_pass2(assertion: str) -> tuple:
    """
    Second pass assertion improvements with enhanced logic
    Returns: (improved_assertion, was_changed)
    """
    original = assertion
    
    # First check direct mappings
    if assertion in ENHANCED_ASSERTION_IMPROVEMENTS:
        return ENHANCED_ASSERTION_IMPROVEMENTS[assertion], True
    
    # Apply pattern improvements
    improved = apply_pattern_improvements(assertion)
    if improved != assertion:
        return improved, True
    
    # Handle remaining _check suffixes
    if assertion.endswith('_check'):
        base = assertion.replace('_check', '')
        if 'encryption' in base or 'encrypted' in base:
            return base + '_enabled', True
        elif 'public' in base or 'access' in base:
            if 'block' in base or 'restrict' in base:
                return base + '_enforced', True
            else:
                return base + '_blocked', True
        elif 'compliance' in base or 'compliant' in base:
            return base + '_validated', True
        else:
            return base + '_enabled', True
    
    # Handle vague assertions
    if assertion in ['public_access', 'unrestricted_access', 'open_access']:
        return 'public_access_blocked', True
    
    if assertion == 'multi_az' or assertion == 'multiple_az':
        return 'multi_az_deployment_enabled', True
    
    # No improvement needed
    return assertion, False

def process_rules_pass2(rules: list) -> dict:
    """Process rules with second pass improvements"""
    improved_rules = []
    changes = []
    
    for rule in rules:
        parts = rule.split('.')
        if len(parts) < 4:
            improved_rules.append(rule)
            continue
        
        csp = parts[0]
        service = parts[1]
        resource = parts[2]
        assertion = '.'.join(parts[3:])
        
        new_assertion, was_changed = improve_assertion_pass2(assertion)
        
        if was_changed:
            new_rule = f"{csp}.{service}.{resource}.{new_assertion}"
            improved_rules.append(new_rule)
            changes.append((rule, new_rule, f"{assertion} → {new_assertion}"))
        else:
            improved_rules.append(rule)
    
    # Remove duplicates
    original_count = len(improved_rules)
    improved_rules = list(dict.fromkeys(improved_rules))
    duplicates_removed = original_count - len(improved_rules)
    
    return {
        'rules': improved_rules,
        'changes': changes,
        'duplicates_removed': duplicates_removed
    }

def main():
    print("=" * 80)
    print("IBM CLOUD CSPM - SECOND PASS ASSERTION IMPROVEMENTS")
    print("=" * 80)
    print()
    
    # Read current rules
    print("📖 Reading rule_ids.yaml...")
    with open('rule_ids.yaml', 'r') as f:
        data = yaml.safe_load(f)
    
    rules = data['rule_ids']
    print(f"   Current: {len(rules)} rules")
    print()
    
    # Backup
    backup_file = f"rule_ids_BACKUP_PASS2_{datetime.now().strftime('%Y%m%d_%H%M%S')}.yaml"
    print(f"💾 Creating backup: {backup_file}")
    with open(backup_file, 'w') as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)
    print()
    
    # Process
    print("🔧 Applying second pass improvements...")
    result = process_rules_pass2(rules)
    print()
    
    # Statistics
    print("=" * 80)
    print("📊 SECOND PASS STATISTICS")
    print("=" * 80)
    print(f"Rules Processed:         {len(rules)}")
    print(f"Assertions Improved:     {len(result['changes'])}")
    print(f"Duplicates Removed:      {result['duplicates_removed']}")
    print(f"Final Rule Count:        {len(result['rules'])}")
    print()
    
    if len(result['changes']) > 0:
        print("Sample Improvements:")
        for old, new, change in result['changes'][:10]:
            print(f"  {change}")
        if len(result['changes']) > 10:
            print(f"  ... and {len(result['changes']) - 10} more")
        print()
    
    # Update and save
    data['metadata']['total_rules'] = len(result['rules'])
    data['metadata']['last_improved_pass2'] = datetime.now().isoformat()
    data['rule_ids'] = result['rules']
    
    print("💾 Writing improved rules...")
    with open('rule_ids.yaml', 'w') as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)
    
    # Generate report
    if len(result['changes']) > 0:
        with open('IBM_PASS2_IMPROVEMENTS.txt', 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("IBM CLOUD CSPM - SECOND PASS IMPROVEMENTS\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"Total Improvements: {len(result['changes'])}\n\n")
            
            f.write("DETAILED CHANGES:\n")
            f.write("-" * 80 + "\n\n")
            for old, new, change in result['changes']:
                f.write(f"OLD: {old}\n")
                f.write(f"NEW: {new}\n")
                f.write(f"     {change}\n\n")
    
    print()
    print("=" * 80)
    print("✅ SECOND PASS COMPLETE!")
    print("=" * 80)
    print(f"Improved: {len(result['changes'])} assertions")
    print(f"Output: rule_ids.yaml")
    if len(result['changes']) > 0:
        print(f"Report: IBM_PASS2_IMPROVEMENTS.txt")
    print("=" * 80)

if __name__ == "__main__":
    main()

