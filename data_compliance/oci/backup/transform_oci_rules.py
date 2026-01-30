#!/usr/bin/env python3
"""
OCI Cloud CSPM Rule ID Transformation Script

Transforms OCI rules to enterprise-grade format:
- Aligns services with OCI Python SDK naming
- Aligns resources with OCI Python SDK naming
- Improves assertions to have clear desired states

Format: oci.service.resource.security_check_assertion

OCI Scale: 370 services, 2,497 rules
Current Quality: 34% good assertions (Grade: C)
Target: 90%+ good assertions (Grade: A)
"""

import yaml
import re
from datetime import datetime
from collections import defaultdict
from oci_python_sdk_mappings import (
    get_official_service_name,
    get_official_resource_name,
    OCI_SERVICE_MAPPINGS,
    OCI_RESOURCE_MAPPINGS
)

# =============================================================================
# ASSERTION IMPROVEMENT MAPPINGS
# =============================================================================

# Comprehensive _check suffix removal
CHECK_SUFFIX_PATTERNS = {
    # Encryption
    'encryption': '_enabled',
    'encrypted': '_enabled',
    'cmek': '_enabled',
    'kms': '_enabled',
    
    # Access Control
    'public': '_blocked',
    'access': '_restricted',
    'anonymous': '_blocked',
    'rbac': '_enforced',
    'least_privilege': '_enforced',
    'iam': '_enforced',
    
    # Network
    'private': '_enforced',
    'tls': '_required',
    'ssl': '_required',
    
    # Monitoring
    'logging': '_enabled',
    'monitoring': '_enabled',
    'audit': '_enabled',
    'alert': '_enabled',
    
    # Configuration
    'configured': '',  # Keep as is
    'defined': '_required',
    'verified': '_validated',
    'version': '_required',
    'expiration': '_monitored',
    
    # Backup/DR
    'backup': '_enabled',
    'replication': '_enabled',
    'retention': '_configured',
    'immutable': '_enabled',
    
    # Default
    'default': '_enabled',
}

# Direct mappings for common patterns
DIRECT_ASSERTION_IMPROVEMENTS = {
    # Access Control
    'no_public_access': 'public_access_blocked',
    'not_publicly_accessible': 'public_access_blocked',
    'not_publicly_shared': 'public_sharing_blocked',
    'not_public': 'public_access_blocked',
    'no_anonymous_access': 'anonymous_access_blocked',
    'no_wildcards_on_actions_or_principals': 'wildcards_on_actions_principals_prohibited',
    'deny_insecure_transport': 'insecure_transport_blocked',
    'deny_unencrypted_puts': 'unencrypted_puts_blocked',
    'no_public_principals': 'public_principals_prohibited',
    
    # RBAC & Permissions
    'rbac_least_privilege': 'rbac_least_privilege_enforced',
    'iam_role_least_privileged': 'iam_role_least_privilege_enforced',
    'admin_access_least_privilege': 'admin_access_least_privilege_enforced',
    'access_policies_least_privilege': 'access_policies_least_privilege_enforced',
    'policy_least_privilege': 'policy_least_privilege_enforced',
    'roles_least_privilege': 'roles_least_privilege_enforced',
    'execution_roles_least_privilege': 'execution_roles_least_privilege_enforced',
    'role_least_privilege': 'role_least_privilege_enforced',
    
    # Encryption
    'encryption_at_rest_cmek': 'encryption_at_rest_cmek_enabled',
    'encrypted_at_rest_cmek': 'encryption_at_rest_cmek_enabled',
    'kms_encryption': 'kms_encryption_enabled',
    'cmk_encryption': 'cmk_encryption_enabled',
    'encrypted': 'encryption_at_rest_enabled',
    'encryption': 'encryption_enabled',
    
    # Network & Access
    'private_only': 'private_networking_enforced',
    'private_networking': 'private_networking_enforced',
    'private_access': 'private_access_enforced',
    'network_private_only': 'private_networking_enforced',
    'tls_required': 'tls_enforced',
    'tls_min_1_2': 'tls_version_1_2_minimum_required',
    'tls_min_1_2_enforced': 'tls_version_1_2_minimum_enforced',
    'require_ssl': 'ssl_tls_required',
    
    # Configuration
    'version_pinned': 'version_pinned_required',
    'definition_version_pinned': 'definition_version_pinned_required',
    'source_trusted': 'source_trust_verified',
    'cache_ttl_reasonable': 'cache_ttl_configured',
    'quota_limits_configured': 'quota_limits_configured',
    'rate_limits_configured': 'rate_limits_configured',
    
    # Sharing & Isolation
    'cross_account_sharing_restricted': 'cross_account_sharing_restricted',
    'public_sharing_disabled': 'public_sharing_disabled',
    'row_level_security': 'row_level_security_enabled',
    'column_level_access_controls': 'column_level_access_controls_enabled',
    
    # Compliance & Governance
    'compliance_framework_mappings_defined': 'compliance_framework_mappings_defined',
    'policy_admin_rbac_least_privilege': 'policy_admin_rbac_least_privilege_enforced',
    'compliance_access_rbac_least_privilege': 'compliance_access_rbac_least_privilege_enforced',
    
    # Certificates & Expiration
    'certificates_expiration': 'certificates_expiration_monitored',
    'expiration_required': 'expiration_monitoring_required',
    
    # Token & Auth
    'token_audience_restricted': 'token_audience_restriction_enforced',
    'require_usage_plan_for_api_keys': 'usage_plan_for_api_keys_required',
    
    # Backup & DR
    'destination_private_only': 'destination_private_only_enforced',
    'schedule_defined_min_frequency': 'schedule_minimum_frequency_configured',
    'immutable_or_worm_enabled_where_supported': 'immutability_enabled_where_supported',
    
    # Other
    'oncall_contacts_verified': 'oncall_contacts_verification_enabled',
    'policy_exists_for_critical_severity': 'critical_severity_policy_configured',
    'allowed_cidrs_minimized': 'allowed_cidrs_minimized',
}

def improve_assertion(service: str, resource: str, assertion: str) -> tuple:
    """
    Improve assertion quality
    Returns: (improved_assertion, was_changed, change_type)
    """
    original = assertion
    
    # Direct mapping first
    if assertion in DIRECT_ASSERTION_IMPROVEMENTS:
        return DIRECT_ASSERTION_IMPROVEMENTS[assertion], True, "direct_mapping"
    
    # Remove _check suffix intelligently
    if assertion.endswith('_check'):
        base = assertion.replace('_check', '')
        
        # Try direct mapping of base
        if base in DIRECT_ASSERTION_IMPROVEMENTS:
            return DIRECT_ASSERTION_IMPROVEMENTS[base], True, "check_removal_direct"
        
        # Pattern-based improvement
        for pattern, suffix in CHECK_SUFFIX_PATTERNS.items():
            if pattern in base:
                return base + suffix, True, "check_removal_pattern"
        
        # Default: keep base (it's likely already clear)
        return base, True, "check_removal_default"
    
    # Pattern improvements for assertions without _check
    if assertion in ['encrypted', 'encryption'] and not assertion.endswith('_enabled'):
        return 'encryption_at_rest_enabled', True, "encryption_pattern"
    
    if assertion.startswith('no_') and not assertion.endswith('_blocked'):
        # no_public_access → public_access_blocked
        cleaned = assertion.replace('no_', '')
        return cleaned + '_blocked', True, "negative_pattern"
    
    if assertion.endswith('_least_privilege') and not assertion.endswith('_enforced'):
        return assertion + '_enforced', True, "least_privilege_pattern"
    
    if assertion.endswith('_private_only') and not assertion.endswith('_enforced'):
        return assertion.replace('_private_only', '_private_networking_enforced'), True, "private_only_pattern"
    
    # Already good
    return assertion, False, "no_change"

def improve_rule_id(rule: str) -> tuple:
    """
    Improve a single rule ID
    Returns: (improved_rule, was_changed, changes_description)
    """
    original_rule = rule
    changes = []
    
    parts = rule.split('.')
    if len(parts) < 4:
        return rule, False, "malformed"
    
    csp = parts[0]
    service = parts[1]
    resource = parts[2]
    assertion = '.'.join(parts[3:])
    
    # Fix service name
    new_service = get_official_service_name(service)
    if new_service != service:
        changes.append(f"service:{service}→{new_service}")
        service = new_service
    
    # Fix resource name
    new_resource = get_official_resource_name(service, resource)
    if new_resource != resource:
        changes.append(f"resource:{resource}→{new_resource}")
        resource = new_resource
    
    # Fix assertion
    new_assertion, assertion_changed, change_type = improve_assertion(service, resource, assertion)
    if assertion_changed:
        changes.append(f"assertion:{assertion}→{new_assertion}")
        assertion = new_assertion
    
    # Reconstruct rule
    new_rule = f"{csp}.{service}.{resource}.{assertion}"
    
    if new_rule != original_rule:
        return new_rule, True, " | ".join(changes)
    
    return rule, False, "no_change"

def process_rules(rules: list) -> dict:
    """Process all rules and return statistics"""
    improved_rules = []
    changes_log = defaultdict(list)
    stats = {
        'total': len(rules),
        'changed': 0,
        'unchanged': 0,
        'service_fixes': 0,
        'resource_fixes': 0,
        'assertion_fixes': 0,
    }
    
    print(f"Processing {len(rules)} rules...")
    
    for i, rule in enumerate(rules):
        if (i + 1) % 500 == 0:
            print(f"  Progress: {i+1}/{len(rules)} ({(i+1)/len(rules)*100:.1f}%)")
        
        new_rule, was_changed, change_desc = improve_rule_id(rule)
        improved_rules.append(new_rule)
        
        if was_changed:
            stats['changed'] += 1
            changes_log[change_desc].append((rule, new_rule))
            
            if 'service:' in change_desc:
                stats['service_fixes'] += 1
            if 'resource:' in change_desc:
                stats['resource_fixes'] += 1
            if 'assertion:' in change_desc:
                stats['assertion_fixes'] += 1
        else:
            stats['unchanged'] += 1
    
    # Remove duplicates
    original_count = len(improved_rules)
    improved_rules = list(dict.fromkeys(improved_rules))
    stats['duplicates_removed'] = original_count - len(improved_rules)
    
    return {
        'rules': improved_rules,
        'changes_log': dict(changes_log),
        'stats': stats
    }

def main():
    print("=" * 80)
    print("OCI CLOUD CSPM RULE ID TRANSFORMATION")
    print("=" * 80)
    print()
    
    # Read rules
    print("📖 Reading rule_ids.yaml...")
    with open('rule_ids.yaml', 'r') as f:
        data = yaml.safe_load(f)
    
    rules = data['rule_ids']
    print(f"   Loaded: {len(rules)} rules")
    print()
    
    # Backup
    backup_file = f"rule_ids_BACKUP_{datetime.now().strftime('%Y%m%d_%H%M%S')}.yaml"
    print(f"💾 Creating backup: {backup_file}")
    with open(backup_file, 'w') as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)
    print()
    
    # Process rules
    print("🔧 Processing rules...")
    print()
    result = process_rules(rules)
    print()
    
    # Print statistics
    stats = result['stats']
    print("=" * 80)
    print("📊 TRANSFORMATION STATISTICS")
    print("=" * 80)
    print(f"Total Rules:             {stats['total']}")
    print(f"  ✅ Improved:           {stats['changed']} rules ({stats['changed']/stats['total']*100:.1f}%)")
    print(f"  ➡️  Unchanged:          {stats['unchanged']} rules ({stats['unchanged']/stats['total']*100:.1f}%)")
    if stats['duplicates_removed'] > 0:
        print(f"  🔍 Duplicates Removed: {stats['duplicates_removed']} rules")
    print()
    print(f"Fix Breakdown:")
    print(f"  🏢 Service names:      {stats['service_fixes']} fixes")
    print(f"  📦 Resource names:     {stats['resource_fixes']} fixes")
    print(f"  ✨ Assertions:         {stats['assertion_fixes']} fixes")
    print()
    
    # Update metadata
    data['metadata']['total_rules'] = len(result['rules'])
    data['metadata']['last_improved'] = datetime.now().isoformat()
    data['metadata']['improvement_version'] = 'enterprise_cspm_v2'
    data['rule_ids'] = result['rules']
    
    # Write improved rules
    print("💾 Writing improved rules to rule_ids.yaml...")
    with open('rule_ids.yaml', 'w') as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)
    print()
    
    # Generate report
    print("📝 Generating improvement report...")
    with open('OCI_TRANSFORMATION_REPORT.txt', 'w') as f:
        f.write("=" * 80 + "\n")
        f.write("OCI CLOUD CSPM RULE ID TRANSFORMATION REPORT\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        f.write(f"STATISTICS:\n")
        f.write(f"  Total Rules:           {stats['total']}\n")
        f.write(f"  Improved:              {stats['changed']} rules ({stats['changed']/stats['total']*100:.1f}%)\n")
        f.write(f"  Unchanged:             {stats['unchanged']} rules ({stats['unchanged']/stats['total']*100:.1f}%)\n")
        if stats['duplicates_removed'] > 0:
            f.write(f"  Duplicates Removed:    {stats['duplicates_removed']} rules\n")
        f.write(f"\n")
        f.write(f"  Service Fixes:         {stats['service_fixes']}\n")
        f.write(f"  Resource Fixes:        {stats['resource_fixes']}\n")
        f.write(f"  Assertion Fixes:       {stats['assertion_fixes']}\n")
        f.write(f"\n")
        
        f.write("=" * 80 + "\n")
        f.write("TOP CHANGES (by frequency)\n")
        f.write("=" * 80 + "\n\n")
        
        for change_desc, rules in sorted(result['changes_log'].items(), key=lambda x: -len(x[1]))[:20]:
            f.write(f"\n{change_desc} ({len(rules)} rules)\n")
            f.write("-" * 80 + "\n")
            for old, new in rules[:5]:
                f.write(f"  OLD: {old}\n")
                f.write(f"  NEW: {new}\n\n")
            if len(rules) > 5:
                f.write(f"  ... and {len(rules) - 5} more\n\n")
    
    print("=" * 80)
    print("✅ TRANSFORMATION COMPLETE!")
    print("=" * 80)
    print(f"Improved rules written to: rule_ids.yaml")
    print(f"Backup saved to: {backup_file}")
    print(f"Detailed report: OCI_TRANSFORMATION_REPORT.txt")
    print()
    print(f"Summary: {stats['changed']} rules improved, {stats['unchanged']} unchanged")
    if stats['duplicates_removed'] > 0:
        print(f"         {stats['duplicates_removed']} duplicates removed")
    print("=" * 80)

if __name__ == "__main__":
    main()

