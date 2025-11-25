#!/usr/bin/env python3
"""
IBM Cloud CSPM Rule ID Improvement Script

This script transforms IBM Cloud rule IDs to enterprise-grade format:
- Aligns services with IBM Python SDK naming
- Aligns resources with IBM Python SDK naming  
- Improves assertions to have clear desired states

Format: ibm.service.resource.security_check_assertion
"""

import yaml
import re
from datetime import datetime
from collections import defaultdict
from ibm_python_sdk_validation import (
    IBM_SERVICE_MAPPINGS,
    IBM_RESOURCE_MAPPINGS,
    get_official_service_name,
    get_official_resource_name,
    is_ibm_native_service,
    is_multi_cloud_service
)

# =============================================================================
# ASSERTION IMPROVEMENT MAPPINGS
# =============================================================================

# Remove '_check' suffix and add clear state
CHECK_SUFFIX_IMPROVEMENTS = {
    'certificates_expiration_check': 'certificates_expiration_monitored',
    'tracker_alert_configuration_verification_check': 'tracker_alerts_configured',
    'tracker_data_encryption_at_rest_check': 'data_encryption_at_rest_enabled',
    'tracker_login_ip_restriction_check': 'login_ip_restriction_enabled',
    'tracker_threat_detection_enumeration_check': 'threat_detection_enumeration_enabled',
    'tracker_threat_detection_llm_jacking_check': 'threat_detection_llm_jacking_enabled',
    'tracker_threat_detection_privilege_escalation_check': 'threat_detection_privilege_escalation_enabled',
    'api_restrictions_configured_check': 'api_restrictions_configured',
    'connect_restapi_waf_acl_attached_check': 'waf_acl_attached',
    'minimum_tls_version_12_check': 'tls_version_1_2_minimum_required',
    'workgroup_encryption_check': 'workgroup_encryption_enabled',
    'dataset_cmk_encryption_check': 'dataset_cmk_encryption_enabled',
    'dataset_public_access_check': 'dataset_public_access_blocked',
    'table_cmk_encryption_check': 'table_cmk_encryption_enabled',
    'maintain_current_contact_details_check': 'current_contact_details_maintained',
    'maintain_different_contact_details_to_security_billing_and_operations_check': 'separate_security_billing_ops_contacts_configured',
    'insecure_ssl_ciphers_check': 'insecure_ssl_ciphers_blocked',
    'internet_facing_check': 'internet_facing_enabled',
    'is_in_multiple_az_check': 'multi_az_deployment_enabled',
    'securitygroup_default_restrict_traffic_check': 'default_security_group_traffic_restricted',
    'high_availability_check': 'high_availability_enabled',
    'admission_control_check': 'admission_control_enabled',
}

# Encryption assertions
ENCRYPTION_IMPROVEMENTS = {
    'encrypted': 'encryption_at_rest_enabled',
    'encrypted_at_rest': 'encryption_at_rest_enabled',
    'encryption': 'encryption_enabled',
    'cmk_encryption': 'cmk_encryption_enabled',
    'cmek_configured': 'cmek_encryption_configured',
    'kms_encryption': 'kms_encryption_enabled',
    'data_encrypted': 'data_encryption_enabled',
    'disk_encryption': 'disk_encryption_enabled',
    'volume_encryption': 'volume_encryption_enabled',
    'bucket_encryption': 'bucket_encryption_enabled',
    'snapshot_encryption': 'snapshot_encryption_enabled',
}

# Access control assertions
ACCESS_CONTROL_IMPROVEMENTS = {
    'not_publicly_accessible': 'public_access_blocked',
    'public_access': 'public_access_blocked',
    'is_not_publicly_accessible': 'public_access_blocked',
    'not_public': 'public_access_blocked',
    'private': 'private_access_enforced',
    'rbac_least_privilege': 'rbac_least_privilege_enforced',
    'role_least_privilege': 'role_least_privilege_enforced',
    'least_privilege': 'least_privilege_enforced',
    'access_rbac_least_privilege': 'rbac_least_privilege_enforced',
    'unrestricted_inbound_access': 'unrestricted_inbound_access_blocked',
    'restricted': 'access_restricted',
    'authorization': 'authorization_enforced',
    'authentication': 'authentication_required',
    'authn_required': 'authentication_required',
    'authz_policies_enforced': 'authorization_policies_enforced',
}

# Network assertions
NETWORK_IMPROVEMENTS = {
    'network_private_only': 'private_networking_enforced',
    'private_networking': 'private_networking_enabled',
    'private_networking_enforced': 'private_networking_enforced',
    'inside_vpc': 'vpc_deployment_required',
    'vpc_multi_az': 'vpc_multi_az_configured',
    'multi_az': 'multi_az_deployment_enabled',
    'multiple_az': 'multi_az_deployment_enabled',
}

# Logging/Monitoring assertions
LOGGING_MONITORING_IMPROVEMENTS = {
    'logging': 'logging_enabled',
    'monitoring': 'monitoring_enabled',
    'audit_logging': 'audit_logging_enabled',
    'access_logging': 'access_logging_enabled',
    'flow_logging': 'flow_logging_enabled',
    'log_retention': 'log_retention_configured',
    'logs_encrypted': 'log_encryption_enabled',
    'alert_configured': 'alerts_configured',
    'notification': 'notifications_configured',
}

# TLS/SSL assertions
TLS_SSL_IMPROVEMENTS = {
    'tls_version_12': 'tls_version_1_2_required',
    'tls_min_1_2': 'tls_version_1_2_minimum_required',
    'tls_min_1_2_enforced': 'tls_version_1_2_minimum_enforced',
    'ssl_enforced': 'ssl_tls_enforced',
    'https_required': 'https_enforced',
    'https_only': 'https_enforced',
}

# Backup/DR assertions
BACKUP_DR_IMPROVEMENTS = {
    'backup': 'backup_enabled',
    'automated_backups': 'automated_backups_enabled',
    'backup_retention': 'backup_retention_configured',
    'cross_region_backup': 'cross_region_backup_enabled',
    'cross_region_copy': 'cross_region_copy_enabled',
    'point_in_time_recovery': 'point_in_time_recovery_enabled',
    'deletion_protection': 'deletion_protection_enabled',
}

# Vague assertions that need context
VAGUE_IMPROVEMENTS = {
    'enabled': 'feature_enabled',  # Context-dependent
    'configured': 'feature_configured',  # Context-dependent
    'disabled': 'feature_disabled',  # Context-dependent
}

# Combine all improvements
ALL_ASSERTION_IMPROVEMENTS = {
    **CHECK_SUFFIX_IMPROVEMENTS,
    **ENCRYPTION_IMPROVEMENTS,
    **ACCESS_CONTROL_IMPROVEMENTS,
    **NETWORK_IMPROVEMENTS,
    **LOGGING_MONITORING_IMPROVEMENTS,
    **TLS_SSL_IMPROVEMENTS,
    **BACKUP_DR_IMPROVEMENTS,
}

# =============================================================================
# UNMAPPED SCOPE FIXES (48 rules with wrong service)
# =============================================================================

UNMAPPED_SCOPE_FIXES = {
    # Kubernetes API Server
    'ibm.unmapped.scope.k8s_apiserver': 'ibm.kubernetes_service.cluster.apiserver_',
    # Kubernetes Kubelet
    'ibm.unmapped.scope.k8s_kubelet': 'ibm.kubernetes_service.worker.kubelet_',
    # Kubernetes RBAC
    'ibm.unmapped.scope.k8s_rbac': 'ibm.kubernetes_service.cluster.rbac_',
    # Kubernetes etcd
    'ibm.unmapped.scope.k8s_etcd': 'ibm.kubernetes_service.cluster.etcd_',
    # Kubernetes Scheduler
    'ibm.unmapped.scope.k8s_scheduler': 'ibm.kubernetes_service.cluster.scheduler_',
    # Kubernetes Controller Manager
    'ibm.unmapped.scope.k8s_controllermanager': 'ibm.kubernetes_service.cluster.controller_manager_',
    # KMS Keys
    'ibm.unmapped.scope.crypto_kms': 'ibm.key_protect.instance.kms_',
    'ibm.unmapped.scope.crypto_kms_key': 'ibm.key_protect.key.kms_key_',
}

# =============================================================================
# FIX FUNCTIONS
# =============================================================================

def fix_check_suffix(assertion: str) -> str:
    """Fix assertions ending with '_check'"""
    if assertion in CHECK_SUFFIX_IMPROVEMENTS:
        return CHECK_SUFFIX_IMPROVEMENTS[assertion]
    
    if not assertion.endswith('_check'):
        return assertion
    
    base = assertion.replace('_check', '')
    
    # Context-based improvements
    if 'encryption' in base or 'encrypted' in base:
        return base + '_enabled'
    elif 'public' in base or 'unrestricted' in base:
        return base + '_blocked'
    elif 'least_privilege' in base or 'rbac' in base:
        return base + '_enforced'
    elif 'tls' in base or 'ssl' in base or 'version' in base:
        return base + '_required'
    elif 'backup' in base or 'logging' in base or 'monitoring' in base:
        return base + '_enabled'
    elif 'configured' in base or 'attached' in base:
        return base
    else:
        return base + '_enabled'

def improve_assertion(service: str, resource: str, assertion: str) -> str:
    """Improve assertion quality with context awareness"""
    
    # First, check if it's in our comprehensive mapping
    if assertion in ALL_ASSERTION_IMPROVEMENTS:
        return ALL_ASSERTION_IMPROVEMENTS[assertion]
    
    # Fix _check suffix
    if assertion.endswith('_check'):
        return fix_check_suffix(assertion)
    
    # Fix vague assertions with service context
    if assertion == 'enabled':
        if 'analyzer' in service:
            return 'access_analyzer_enabled'
        elif 'scaling' in resource:
            return 'auto_scaling_enabled'
        return 'feature_enabled'
    
    if assertion == 'configured':
        if 'scaling' in resource:
            return 'auto_scaling_configured'
        return 'feature_configured'
    
    # Apply pattern-based improvements
    # Encryption patterns
    if assertion in ['encrypted', 'encryption'] and not assertion.endswith('_enabled'):
        return 'encryption_at_rest_enabled'
    
    # Access control patterns
    if 'not_publicly_accessible' in assertion:
        return 'public_access_blocked'
    if assertion == 'public_access' and not assertion.endswith('_blocked'):
        return 'public_access_blocked'
    
    # Network patterns
    if assertion == 'network_private_only':
        return 'private_networking_enforced'
    if assertion == 'inside_vpc':
        return 'vpc_deployment_required'
    
    # Already good - has clear desired state
    return assertion

def fix_unmapped_scope(rule: str) -> str:
    """Fix rules with ibm.unmapped.scope prefix"""
    for old_prefix, new_prefix in UNMAPPED_SCOPE_FIXES.items():
        if rule.startswith(old_prefix):
            # Extract the specific check part after the scope
            # e.g., ibm.unmapped.scope.k8s_apiserver → extract what comes after
            return rule.replace('ibm.unmapped.scope.', new_prefix)
    
    return rule

def improve_rule_id(rule: str) -> tuple:
    """
    Improve a single rule ID
    Returns: (improved_rule, was_changed, change_description)
    """
    original_rule = rule
    changes = []
    
    # Handle unmapped scope first
    if rule.startswith('ibm.unmapped.scope.'):
        # These need manual review - keep but log
        changes.append("unmapped_scope")
        # We'll keep them as-is for now, pending manual review
        return rule, False, "unmapped_scope_needs_manual_review"
    
    parts = rule.split('.')
    if len(parts) < 4:
        return rule, False, "malformed"
    
    csp = parts[0]
    service = parts[1]
    resource = parts[2]
    assertion = '.'.join(parts[3:])
    
    # Skip non-IBM native services for now (AWS, Azure, GCP)
    if is_multi_cloud_service(service):
        return rule, False, "multi_cloud_service"
    
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
    new_assertion = improve_assertion(service, resource, assertion)
    if new_assertion != assertion:
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
        'multi_cloud_skipped': 0,
        'unmapped_scope': 0,
    }
    
    for rule in rules:
        new_rule, was_changed, change_desc = improve_rule_id(rule)
        improved_rules.append(new_rule)
        
        if was_changed:
            stats['changed'] += 1
            changes_log[change_desc].append((rule, new_rule))
            
            # Count specific fix types
            if 'service:' in change_desc:
                stats['service_fixes'] += 1
            if 'resource:' in change_desc:
                stats['resource_fixes'] += 1
            if 'assertion:' in change_desc:
                stats['assertion_fixes'] += 1
        else:
            stats['unchanged'] += 1
            
            if change_desc == 'multi_cloud_service':
                stats['multi_cloud_skipped'] += 1
            elif change_desc == 'unmapped_scope_needs_manual_review':
                stats['unmapped_scope'] += 1
    
    return {
        'rules': improved_rules,
        'changes_log': dict(changes_log),
        'stats': stats
    }

def main():
    """Main execution"""
    print("=" * 80)
    print("IBM CLOUD CSPM RULE ID IMPROVEMENT")
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
    backup_file = f"rule_ids_BACKUP_IMPROVEMENT_{datetime.now().strftime('%Y%m%d_%H%M%S')}.yaml"
    print(f"💾 Creating backup: {backup_file}")
    with open(backup_file, 'w') as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)
    print()
    
    # Process rules
    print("🔧 Processing rules...")
    result = process_rules(rules)
    print()
    
    # Remove duplicates
    original_count = len(result['rules'])
    result['rules'] = list(dict.fromkeys(result['rules']))  # Remove duplicates while preserving order
    duplicates_removed = original_count - len(result['rules'])
    
    if duplicates_removed > 0:
        print(f"🔍 Removed {duplicates_removed} duplicate rules")
        result['stats']['duplicates_removed'] = duplicates_removed
    print()
    
    # Print statistics
    stats = result['stats']
    print("=" * 80)
    print("📊 IMPROVEMENT STATISTICS")
    print("=" * 80)
    print(f"Total Rules:             {stats['total']}")
    print(f"  ✅ Improved:           {stats['changed']} rules ({stats['changed']/stats['total']*100:.1f}%)")
    print(f"  ➡️  Unchanged:          {stats['unchanged']} rules ({stats['unchanged']/stats['total']*100:.1f}%)")
    if duplicates_removed > 0:
        print(f"  🔍 Duplicates Removed: {duplicates_removed} rules")
    print()
    print(f"Fix Breakdown:")
    print(f"  🏢 Service names:      {stats['service_fixes']} fixes")
    print(f"  📦 Resource names:     {stats['resource_fixes']} fixes")
    print(f"  ✨ Assertions:         {stats['assertion_fixes']} fixes")
    print()
    print(f"Skipped:")
    print(f"  ☁️  Multi-cloud:        {stats['multi_cloud_skipped']} rules (AWS/Azure/GCP)")
    print(f"  ⚠️  Unmapped scope:     {stats['unmapped_scope']} rules (needs manual review)")
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
    
    # Generate detailed change report
    print("📝 Generating improvement report...")
    with open('IBM_IMPROVEMENT_REPORT.txt', 'w') as f:
        f.write("=" * 80 + "\n")
        f.write("IBM CLOUD CSPM RULE ID IMPROVEMENT REPORT\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        f.write(f"STATISTICS:\n")
        f.write(f"  Total Rules:           {stats['total']}\n")
        f.write(f"  Improved:              {stats['changed']} rules ({stats['changed']/stats['total']*100:.1f}%)\n")
        f.write(f"  Unchanged:             {stats['unchanged']} rules ({stats['unchanged']/stats['total']*100:.1f}%)\n")
        if duplicates_removed > 0:
            f.write(f"  Duplicates Removed:    {duplicates_removed} rules\n")
        f.write(f"\n")
        f.write(f"  Service Fixes:         {stats['service_fixes']}\n")
        f.write(f"  Resource Fixes:        {stats['resource_fixes']}\n")
        f.write(f"  Assertion Fixes:       {stats['assertion_fixes']}\n")
        f.write(f"\n")
        f.write(f"  Multi-Cloud Skipped:   {stats['multi_cloud_skipped']}\n")
        f.write(f"  Unmapped Scope:        {stats['unmapped_scope']}\n")
        f.write(f"\n")
        
        f.write("=" * 80 + "\n")
        f.write("DETAILED CHANGES\n")
        f.write("=" * 80 + "\n\n")
        
        for change_desc, rules in sorted(result['changes_log'].items(), key=lambda x: -len(x[1])):
            f.write(f"\n{change_desc} ({len(rules)} rules)\n")
            f.write("-" * 80 + "\n")
            for old, new in rules[:10]:
                f.write(f"  OLD: {old}\n")
                f.write(f"  NEW: {new}\n\n")
            if len(rules) > 10:
                f.write(f"  ... and {len(rules) - 10} more\n\n")
    
    print("=" * 80)
    print("✅ IMPROVEMENT COMPLETE!")
    print("=" * 80)
    print(f"Improved rules written to: rule_ids.yaml")
    print(f"Backup saved to: {backup_file}")
    print(f"Detailed report: IBM_IMPROVEMENT_REPORT.txt")
    print()
    print(f"Summary: {stats['changed']} rules improved, {stats['unchanged']} unchanged")
    print("=" * 80)

if __name__ == "__main__":
    main()

