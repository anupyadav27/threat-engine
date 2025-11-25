#!/usr/bin/env python3
"""
CSPM Assertion Standardization - Enterprise Grade Format
Format: [parameter/config]_[desired_status/value] in snake_case

Examples:
- encryption_enabled
- mfa_required  
- tls_version_1_2_minimum
- public_access_blocked
- logging_enabled
- backup_retention_90_days
"""

import yaml
from datetime import datetime
from collections import Counter
import re

# Standard desired states (suffix)
STANDARD_STATES = {
    'enabled': 'enabled',
    'disabled': 'disabled',
    'required': 'required',
    'blocked': 'blocked',
    'restricted': 'restricted',
    'enforced': 'enforced',
    'configured': 'configured',
    'protected': 'protected',
    'encrypted': 'encrypted',
    'logged': 'logged',
    'monitored': 'monitored',
    'validated': 'validated',
    'compliant': 'compliant',
    'present': 'present',
    'absent': 'absent',
}

# Common assertion improvements
ASSERTION_IMPROVEMENTS = {
    # Verbose → Concise
    'encryption_at_rest_enabled': 'encryption_enabled',
    'encryption_in_transit_enabled': 'tls_enabled',
    'multi_factor_authentication_enabled': 'mfa_enabled',
    'multi_factor_authentication_required': 'mfa_required',
    'public_access_blocked': 'public_access_blocked',  # Good as is
    'logging_enabled': 'logging_enabled',  # Good as is
    
    # Remove redundant prefixes
    'data_protection_storage_security_bucket': 'bucket',
    'identity_access_security_user': 'user',
    'network_security_subnet': 'subnet',
    
    # Standardize status verbs
    '_is_enabled': '_enabled',
    '_is_disabled': '_disabled',
    '_is_required': '_required',
    '_is_configured': '_configured',
    '_should_be_enabled': '_enabled',
    '_must_be_enabled': '_required',
}

def clean_assertion(assertion: str) -> str:
    """
    Clean and standardize assertion to enterprise format
    Format: [parameter/config]_[desired_status/value]
    """
    # Remove redundant parts that repeat full context
    cleaned = assertion
    
    # Pattern 1: Remove duplicate assertion (common pattern)
    # Example: "something.something" → "something"
    parts = cleaned.split('.')
    if len(parts) > 1:
        # Often the last part is the clean assertion
        last_part = parts[-1]
        first_part = parts[0]
        
        # If last part is more specific or has a clear state, use it
        if any(state in last_part for state in STANDARD_STATES.keys()):
            cleaned = last_part
        elif len(last_part) < len(first_part):
            cleaned = last_part
        else:
            # Use first part but try to improve it
            cleaned = first_part
    
    # Pattern 2: Remove redundant security domain prefixes from assertion itself
    # (These should be in service/resource, not assertion)
    prefixes_to_remove = [
        'data_protection_storage_security_',
        'identity_access_security_',
        'network_security_',
        'data_governance_security_',
        'data_warehouse_security_',
        'data_analytics_security_',
        'compute_security_',
        'database_security_',
        'db_security_',
        'serverless_security_',
        'containers_kubernetes_security_',
        'ai_services_security_',
        'platform_security_',
        'logging_security_',
        'monitoring_security_',
        'backup_security_',
        'dr_security_',
        'vuln_security_',
        'threat_security_',
        'privacy_security_',
        'governance_security_',
        'compliance_security_',
        'supply_chain_security_',
        'configuration_management_security_',
        'paas_security_',
        'incident_security_',
        'resilience_security_',
        'cost_security_',
        'lineage_security_',
        'datalake_security_',
        'data_catalog_security_',
        'machine_learning_security_',
        'ml_ops_security_',
        'edge_security_',
    ]
    
    for prefix in prefixes_to_remove:
        if cleaned.startswith(prefix):
            cleaned = cleaned[len(prefix):]
            break
    
    # Pattern 3: Simplify verbose status words
    replacements = {
        '_enforced_required': '_required',
        '_restricted_enforced': '_enforced',
        '_enabled_required': '_required',
        '_configured_enabled': '_enabled',
        '_present_enabled': '_enabled',
        '_blocked_restricted': '_blocked',
        '_disabled_blocked': '_blocked',
        
        # Simplify "where supported/applicable"
        '_enabled_where_supported': '_enabled',
        '_required_where_applicable': '_required',
        '_configured_where_supported': '_configured',
        
        # Simplify verbose endings
        '_least_privilege_enforced': '_least_privilege_required',
        '_least_privilege_restricted_enforced': '_least_privilege_required',
        '_least_privilege_restricted': '_least_privilege_required',
    }
    
    for old, new in replacements.items():
        if cleaned.endswith(old):
            cleaned = cleaned[:-len(old)] + new
    
    # Pattern 4: Standardize common parameters
    param_standards = {
        'cmk_cmek': 'cmk',
        'customer_managed_key': 'cmk',
        'kms_key': 'cmk',
        'multi_factor_authentication': 'mfa',
        'two_factor_authentication': 'mfa',
        '2fa': 'mfa',
        'encryption_at_rest': 'encryption',
        'encryption_in_transit': 'tls',
        'transport_layer_security': 'tls',
        'secure_sockets_layer': 'tls',
        'role_based_access_control': 'rbac',
        'access_control_list': 'acl',
    }
    
    for old, new in param_standards.items():
        cleaned = cleaned.replace(old, new)
    
    # Pattern 5: Ensure it ends with a clear state
    has_state = any(cleaned.endswith('_' + state) or cleaned.endswith(state) 
                   for state in STANDARD_STATES.keys())
    
    if not has_state:
        # Try to infer state from context
        if 'no_' in cleaned or 'not_' in cleaned or 'disable' in cleaned:
            if not cleaned.endswith('_disabled'):
                cleaned = cleaned + '_disabled'
        elif 'require' in cleaned or 'must' in cleaned or 'mandatory' in cleaned:
            if not cleaned.endswith('_required'):
                cleaned = cleaned + '_required'
        elif 'block' in cleaned or 'deny' in cleaned or 'prevent' in cleaned:
            if not cleaned.endswith('_blocked'):
                cleaned = cleaned + '_blocked'
        else:
            # Default to enabled for positive checks
            if not cleaned.endswith('_enabled'):
                cleaned = cleaned + '_enabled'
    
    # Pattern 6: Remove duplicate words
    parts = cleaned.split('_')
    seen = set()
    deduplicated = []
    for part in parts:
        if part not in seen or part in STANDARD_STATES.keys():
            deduplicated.append(part)
            seen.add(part)
    cleaned = '_'.join(deduplicated)
    
    # Pattern 7: Limit length (max 8 words)
    parts = cleaned.split('_')
    if len(parts) > 8:
        # Keep first 6 parts + state (last part)
        cleaned = '_'.join(parts[:6] + [parts[-1]])
    
    return cleaned

print("=" * 100)
print("CSPM ASSERTION STANDARDIZATION - ENTERPRISE GRADE")
print("=" * 100)

# Load rules
with open('rule_ids.yaml', 'r') as f:
    data = yaml.safe_load(f)

rules = data['rule_ids']
print(f"\nTotal Rules: {len(rules)}")

# Analyze and standardize
improved_rules = []
changes = []
stats = {
    'shortened': 0,
    'prefix_removed': 0,
    'state_added': 0,
    'duplicates_removed': 0,
    'unchanged': 0,
}

for rule in rules:
    parts = rule.split('.')
    if len(parts) >= 4:
        csp = parts[0]
        service = parts[1]
        resource = parts[2]
        assertion = '.'.join(parts[3:])
        
        # Clean assertion
        new_assertion = clean_assertion(assertion)
        
        # Track changes
        if new_assertion != assertion:
            new_rule = f"{csp}.{service}.{resource}.{new_assertion}"
            improved_rules.append(new_rule)
            
            changes.append({
                'old_rule': rule,
                'new_rule': new_rule,
                'old_assertion': assertion,
                'new_assertion': new_assertion,
                'service': service,
                'old_length': len(assertion.split('_')),
                'new_length': len(new_assertion.split('_'))
            })
            
            # Track improvement types
            if len(new_assertion) < len(assertion):
                stats['shortened'] += 1
            if assertion.count('.') > new_assertion.count('.'):
                stats['duplicates_removed'] += 1
            if any(prefix in assertion for prefix in ['security_', '_security']):
                stats['prefix_removed'] += 1
        else:
            improved_rules.append(rule)
            stats['unchanged'] += 1
    else:
        improved_rules.append(rule)

print(f"\n{'=' * 100}")
print("STANDARDIZATION RESULTS")
print(f"{'=' * 100}")
print(f"Rules Improved: {len(changes)} ({len(changes)/len(rules)*100:.1f}%)")
print(f"Rules Unchanged: {stats['unchanged']} ({stats['unchanged']/len(rules)*100:.1f}%)")
print(f"\nImprovement Types:")
print(f"  - Shortened: {stats['shortened']}")
print(f"  - Security Prefix Removed: {stats['prefix_removed']}")
print(f"  - Duplicates Removed: {stats['duplicates_removed']}")

print(f"\n{'=' * 100}")
print("SAMPLE IMPROVEMENTS (First 40)")
print(f"{'=' * 100}")

for change in changes[:40]:
    old_words = change['old_length']
    new_words = change['new_length']
    reduction = old_words - new_words
    
    print(f"\nService: {change['service']:25s} | Reduced: {old_words} → {new_words} words ({reduction} words shorter)")
    print(f"  OLD: {change['old_assertion']}")
    print(f"  NEW: {change['new_assertion']}")

print(f"\n{'=' * 100}")
print("BEFORE vs AFTER EXAMPLES")
print(f"{'=' * 100}")

# Show some good examples
examples = [
    change for change in changes 
    if change['old_length'] - change['new_length'] >= 5
][:15]

print("\nSignificantly Improved (5+ words shorter):")
for example in examples:
    print(f"\n  Service: {example['service']}")
    print(f"  BEFORE ({example['old_length']} words): {example['old_assertion']}")
    print(f"  AFTER  ({example['new_length']} words): {example['new_assertion']}")

# Save preview (don't update yet)
print(f"\n{'=' * 100}")
print("PREVIEW MODE")
print(f"{'=' * 100}")
print("""
This is a PREVIEW of assertion standardization.

Review the changes above. If approved, we can:
1. Apply these improvements to rule_ids.yaml
2. Create detailed before/after report
3. Backup current version

Would you like to proceed with applying these improvements?
""")

print(f"{'=' * 100}")

