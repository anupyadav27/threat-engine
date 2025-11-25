#!/usr/bin/env python3
"""
Apply CSPM Assertion Standardization
Enterprise-grade format: [parameter/config]_[desired_status/value]
"""

import yaml
from datetime import datetime
from collections import Counter
import re

# Copy all the cleaning logic from preview
def clean_assertion(assertion: str) -> str:
    """Clean and standardize assertion to enterprise format"""
    cleaned = assertion
    
    # Pattern 1: Remove duplicate assertion
    parts = cleaned.split('.')
    if len(parts) > 1:
        last_part = parts[-1]
        first_part = parts[0]
        
        STANDARD_STATES = ['enabled', 'disabled', 'required', 'blocked', 'restricted', 
                          'enforced', 'configured', 'protected', 'encrypted', 'logged',
                          'monitored', 'validated', 'compliant', 'present', 'absent']
        
        if any(state in last_part for state in STANDARD_STATES):
            cleaned = last_part
        elif len(last_part) < len(first_part):
            cleaned = last_part
        else:
            cleaned = first_part
    
    # Pattern 2: Remove redundant security domain prefixes
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
        'data_privacy_ai_security_',
        'data_governance_ai_security_',
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
        '_enabled_where_supported': '_enabled',
        '_required_where_applicable': '_required',
        '_configured_where_supported': '_configured',
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
    
    # Pattern 5: Remove duplicate words
    parts = cleaned.split('_')
    seen = set()
    deduplicated = []
    STANDARD_STATES = ['enabled', 'disabled', 'required', 'blocked', 'restricted', 
                       'enforced', 'configured', 'protected', 'encrypted', 'logged',
                       'monitored', 'validated', 'compliant', 'present', 'absent']
    
    for part in parts:
        if part not in seen or part in STANDARD_STATES:
            deduplicated.append(part)
            seen.add(part)
    cleaned = '_'.join(deduplicated)
    
    # Pattern 6: Limit length (max 8 words)
    parts = cleaned.split('_')
    if len(parts) > 8:
        cleaned = '_'.join(parts[:6] + [parts[-1]])
    
    return cleaned

print("=" * 100)
print("APPLYING CSPM ASSERTION STANDARDIZATION")
print("=" * 100)

# Load rules
with open('rule_ids.yaml', 'r') as f:
    data = yaml.safe_load(f)

rules = data['rule_ids']
print(f"\nTotal Rules: {len(rules)}")

# Backup
backup_file = f"rule_ids_BACKUP_ASSERTION_STD_{datetime.now().strftime('%Y%m%d_%H%M%S')}.yaml"
print(f"Creating backup: {backup_file}")
with open(backup_file, 'w') as f:
    yaml.dump(data, f, default_flow_style=False, sort_keys=False)

# Apply standardization
standardized_rules = []
changes = []
stats = Counter()

for rule in rules:
    parts = rule.split('.')
    if len(parts) >= 4:
        csp = parts[0]
        service = parts[1]
        resource = parts[2]
        assertion = '.'.join(parts[3:])
        
        new_assertion = clean_assertion(assertion)
        
        if new_assertion != assertion:
            new_rule = f"{csp}.{service}.{resource}.{new_assertion}"
            standardized_rules.append(new_rule)
            
            old_len = len(assertion.split('_'))
            new_len = len(new_assertion.split('_'))
            
            changes.append({
                'old': rule,
                'new': new_rule,
                'service': service,
                'reduction': old_len - new_len
            })
            
            stats['improved'] += 1
            if old_len - new_len >= 5:
                stats['significantly_improved'] += 1
        else:
            standardized_rules.append(rule)
            stats['unchanged'] += 1
    else:
        standardized_rules.append(rule)

print(f"\n{'=' * 100}")
print("STANDARDIZATION RESULTS")
print(f"{'=' * 100}")
print(f"Rules Improved: {stats['improved']} ({stats['improved']/len(rules)*100:.1f}%)")
print(f"Significantly Improved (5+ words): {stats['significantly_improved']}")
print(f"Rules Unchanged: {stats['unchanged']} ({stats['unchanged']/len(rules)*100:.1f}%)")

# Update rules
data['rule_ids'] = standardized_rules
data['metadata']['total_rules'] = len(standardized_rules)
data['metadata']['last_assertion_standardization'] = datetime.now().isoformat()
data['metadata']['assertion_standardization'] = 'enterprise_grade_complete'
data['metadata']['assertions_improved'] = stats['improved']

# Save
print(f"\n{'=' * 100}")
print("SAVING STANDARDIZED RULES")
print(f"{'=' * 100}")

with open('rule_ids.yaml', 'w') as f:
    yaml.dump(data, f, default_flow_style=False, sort_keys=False)

# Generate report
report_lines = []
report_lines.append("=" * 100)
report_lines.append("CSPM ASSERTION STANDARDIZATION REPORT")
report_lines.append("=" * 100)
report_lines.append(f"\nGenerated: {datetime.now().isoformat()}")
report_lines.append(f"\nTotal Rules: {len(rules)}")
report_lines.append(f"Rules Improved: {stats['improved']} ({stats['improved']/len(rules)*100:.1f}%)")
report_lines.append(f"Significantly Improved: {stats['significantly_improved']}")
report_lines.append(f"\n{'=' * 100}")
report_lines.append("TOP 50 IMPROVEMENTS")
report_lines.append("=" * 100)

for change in sorted(changes, key=lambda x: x['reduction'], reverse=True)[:50]:
    old_parts = change['old'].split('.')
    new_parts = change['new'].split('.')
    report_lines.append(f"\nService: {change['service']}")
    report_lines.append(f"  OLD: {'.'.join(old_parts[3:])}")
    report_lines.append(f"  NEW: {'.'.join(new_parts[3:])}")
    report_lines.append(f"  Reduction: {change['reduction']} words")

with open('ASSERTION_STANDARDIZATION_REPORT.txt', 'w') as f:
    f.write('\n'.join(report_lines))

print(f"\n✅ Assertion Standardization Complete!")
print(f"✅ Rules Improved: {stats['improved']}")
print(f"✅ Backup: {backup_file}")
print(f"✅ Report: ASSERTION_STANDARDIZATION_REPORT.txt")
print(f"\n{'=' * 100}")

