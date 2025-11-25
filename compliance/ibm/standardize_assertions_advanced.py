#!/usr/bin/env python3
"""
Advanced IBM Cloud Assertion Standardization
Convert verbose assertions to enterprise-grade concise format
"""

import yaml
import re
from datetime import datetime
from collections import Counter

print("=" * 100)
print("IBM CLOUD - ADVANCED ASSERTION STANDARDIZATION")
print("=" * 100)

# Load rules
with open('rule_ids.yaml', 'r') as f:
    data = yaml.safe_load(f)

rules = data['rule_ids']
print(f"\nTotal Rules: {len(rules)}")

# Backup
backup_file = f"rule_ids_BACKUP_ADVANCED_ASSERTION_{datetime.now().strftime('%Y%m%d_%H%M%S')}.yaml"
print(f"Creating backup: {backup_file}")
with open(backup_file, 'w') as f:
    yaml.dump(data, f, default_flow_style=False, sort_keys=False)

def standardize_assertion_advanced(assertion):
    """
    Advanced assertion standardization
    Remove category prefixes and create concise enterprise-grade format
    """
    if not assertion:
        return assertion
    
    original = assertion
    
    # Remove category prefixes (these are redundant as they're clear from service/resource)
    category_prefixes = [
        'data_protection_',
        'data_privacy_',
        'data_governance_',
        'identity_access_',
        'network_security_',
        'network_encryption_',
        'configuration_management_',
        'resilience_recovery_',
        'resilience_dr_',
        'supply_chain_',
        'logging_monitoring_',
        'logging_metric_filter_',
        'governance_',
        'compliance_',
        'machine_learning_',
        'security_',
        'policy_',
        'check_',
        'ensure_',
        'verify_',
        'validate_',
    ]
    
    # Apply category prefix removal
    for prefix in category_prefixes:
        if assertion.startswith(prefix):
            assertion = assertion[len(prefix):]
            break  # Only remove first matching prefix
    
    # Remove redundant service/resource name prefixes in assertions
    service_resource_prefixes = [
        'storage_bucket_',
        'storage_fileshare_',
        'storage_global_table_',
        'ai_endpoint_',
        'ai_human_review_',
        'config_delivery_',
        'config_drift_',
        'config_remediation_',
        'config_compliance_',
        'config_recorder_',
        'service_account_',
        'instance_profile_',
        'registry_replication_',
        'backup_coverage_',
        'delivery_channel_',
        'metric_filter_',
    ]
    
    for prefix in service_resource_prefixes:
        if assertion.startswith(prefix):
            assertion = assertion[len(prefix):]
            break
    
    # Common replacements for conciseness
    replacements = [
        # Long patterns first
        ('workload_identity_federation_used_where_supported', 'workload_identity_federation_enabled'),
        ('requires_external_id_or_audience_condition_where_supported', 'external_id_required'),
        ('least_privilege_enforced', 'least_privilege'),
        ('keys_not_used_or_rotated_90_days_or_less', 'keys_rotated_90d'),
        ('scopes_or_roles_least_privilege_enforced', 'scopes_least_privilege'),
        ('no_instance_profile_with_admin_star', 'no_admin_wildcard'),
        ('destination_access_least_privilege_enforced', 'destination_least_privilege'),
        ('cross_account_destinations_restricted', 'cross_account_restricted'),
        ('notification_cross_account_destinations_restricted', 'notification_restricted'),
        ('notification_destination_least_privilege_enforced', 'notification_least_privilege'),
        ('critical_resources_drift_detection_enabled', 'drift_detection_enabled'),
        ('auto_remediation_enabled_for_high', 'auto_remediation_high'),
        ('workteam_access_rbac_least_privilege_enforced', 'workteam_rbac_enforced'),
        ('no_wildcards_on_actions_or_principals', 'no_wildcards'),
        ('kms_key_deletion_or_disable_detected_filter_present', 'kms_deletion_alert'),
        ('kms_key_policy_least_privilege_enforced', 'kms_key_least_privilege'),
        ('network_acl_or_sg_change_detected_filter_present', 'network_change_alert'),
        ('global_resource_types_tracked', 'global_resources_tracked'),
        ('secure_destination_configured', 'secure_destination'),
        ('evidence_export_configured', 'evidence_export_enabled'),
        ('destinations_least_privilege_enforced', 'destinations_least_privilege'),
        ('unprotected_assets_alerting_enabled', 'unprotected_assets_alert'),
        ('cross_region_replication_encrypted', 'cross_region_encrypted'),
        ('reporting_dashboards_enabled', 'dashboards_enabled'),
        ('mtls_required_for_internal_services_where_supported', 'mtls_required'),
        ('data_capture_bucket_encrypted_private', 'data_capture_encrypted'),
        ('endpoint_config_data_capture_bucket_encrypted_private', 'endpoint_data_encrypted'),
    ]
    
    # Apply replacements
    for old, new in replacements:
        if old in assertion:
            assertion = assertion.replace(old, new)
    
    # Remove duplicate consecutive words
    words = assertion.split('_')
    unique_words = []
    prev = None
    for word in words:
        if word != prev or word in ['ibm', 'enabled', 'disabled', 'configured']:
            unique_words.append(word)
        prev = word
    assertion = '_'.join(unique_words)
    
    # If still too long (> 60 chars), abbreviate further
    if len(assertion) > 60:
        # Common abbreviations
        assertion = assertion.replace('_enabled', '_en')
        assertion = assertion.replace('_configured', '_cfg')
        assertion = assertion.replace('_required', '_req')
        assertion = assertion.replace('_detected', '_det')
        assertion = assertion.replace('_enforced', '_enf')
        assertion = assertion.replace('_present', '_set')
        
        # If STILL too long, keep first + last parts
        if len(assertion) > 60:
            parts = assertion.split('_')
            if len(parts) > 8:
                assertion = '_'.join(parts[:3] + ['...'] + parts[-2:])
    
    return assertion

# Apply advanced standardization
updated_rules = []
changes = Counter()
improved_count = 0
significant_improvements = []

for rule in rules:
    parts = rule.split('.')
    
    if len(parts) >= 4:
        csp = parts[0]
        service = parts[1]
        resource = parts[2]
        assertion = '.'.join(parts[3:])
        
        # Standardize assertion
        new_assertion = standardize_assertion_advanced(assertion)
        
        # Build new rule
        new_rule = f"{csp}.{service}.{resource}.{new_assertion}"
        updated_rules.append(new_rule)
        
        if assertion != new_assertion:
            improved_count += 1
            reduction = len(assertion) - len(new_assertion)
            changes[f"Reduced {reduction} chars"] += 1
            
            if reduction > 20:  # Significant improvement
                significant_improvements.append({
                    'before': assertion,
                    'after': new_assertion,
                    'reduction': reduction,
                    'full_rule': rule
                })
    else:
        updated_rules.append(rule)

# Display results
print(f"\n{'=' * 100}")
print("TRANSFORMATION RESULTS")
print(f"{'=' * 100}")

print(f"\nRules with Assertions: {sum(1 for r in rules if len(r.split('.')) >= 4)}")
print(f"Assertions Improved: {improved_count} ({improved_count/len(rules)*100:.1f}%)")
print(f"Significant Improvements (>20 chars): {len(significant_improvements)}")

# Calculate average assertion length before and after
before_lengths = []
after_lengths = []
for rule in rules:
    parts = rule.split('.')
    if len(parts) >= 4:
        before_lengths.append(len('.'.join(parts[3:])))

for rule in updated_rules:
    parts = rule.split('.')
    if len(parts) >= 4:
        after_lengths.append(len('.'.join(parts[3:])))

if before_lengths and after_lengths:
    avg_before = sum(before_lengths) / len(before_lengths)
    avg_after = sum(after_lengths) / len(after_lengths)
    total_chars_saved = sum(before_lengths) - sum(after_lengths)
    
    print(f"\nAverage Assertion Length:")
    print(f"  Before: {avg_before:.1f} chars")
    print(f"  After:  {avg_after:.1f} chars")
    print(f"  Reduction: {avg_before - avg_after:.1f} chars ({(avg_before - avg_after)/avg_before*100:.1f}%)")
    print(f"  Total characters saved: {total_chars_saved:,}")

# Show significant improvements
print(f"\n{'=' * 100}")
print("TOP 30 SIGNIFICANT IMPROVEMENTS (>20 character reduction)")
print(f"{'=' * 100}")

significant_improvements.sort(key=lambda x: x['reduction'], reverse=True)
for i, imp in enumerate(significant_improvements[:30], 1):
    print(f"\n{i}. Reduction: {imp['reduction']} chars")
    print(f"   BEFORE ({len(imp['before']):2d}): {imp['before']}")
    print(f"   AFTER  ({len(imp['after']):2d}): {imp['after']}")

# Update metadata
data['rule_ids'] = updated_rules
data['metadata']['total_rules'] = len(updated_rules)
data['metadata']['last_advanced_assertion_std'] = datetime.now().isoformat()
data['metadata']['assertion_advanced_phase'] = 'enterprise_concise_complete'
data['metadata']['assertions_advanced_improved'] = improved_count
data['metadata']['avg_assertion_reduction'] = round(avg_before - avg_after, 1) if before_lengths else 0

# Save
print(f"\n{'=' * 100}")
print("SAVING UPDATED RULES")
print(f"{'=' * 100}")

with open('rule_ids.yaml', 'w') as f:
    yaml.dump(data, f, default_flow_style=False, sort_keys=False)

print(f"\n✅ Advanced Assertion Standardization Complete!")
print(f"✅ Assertions Improved: {improved_count}")
print(f"✅ Average Reduction: {avg_before - avg_after:.1f} chars")
print(f"✅ Backup: {backup_file}")
print(f"\n{'=' * 100}")

