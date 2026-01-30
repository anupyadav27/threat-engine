#!/usr/bin/env python3
"""
OCI CSPM Rules - Second Pass Complete Standardization

Fixes ALL remaining issues:
1. Wrong CSP names (oracle.* → oci.*)
2. Long/unstandardized service names
3. Generic "resource" → specific resource types
4. Unclear assertions → clear desired states

Target: 90%+ good assertions (Grade: A-)
"""

import yaml
import re
from datetime import datetime
from collections import defaultdict
from oci_python_sdk_mappings import (
    get_official_service_name,
    get_official_resource_name
)

# =============================================================================
# SERVICE NAME STANDARDIZATION (Long Names → Short Standard Names)
# =============================================================================

LONG_SERVICE_NAME_FIXES = {
    # Very long service names need consolidation
    "bucket_policy_pre_auth_requests_iam": "object_storage",
    "cloud_guard_incidents_triage_respond": "cloud_guard",
    "adw_external_tables_hive_metastore_entries": "database",
    "autonomous_data_lakehouse_adw_schemas": "database",
    "adw_adb_partitions_metadata": "database",
    "adw_adb_partitions": "database",
    "adw_adb_schemas": "database",
    "autonomous_db_db_system_entries": "database",
    "adw_backup_snapshot": "database",
    "adw_hdfs_os_objects": "database",
    "adw_network_acl_iam": "database",
    "adw_parameter_sets_init_params": "database",
    "adw_parameters_profile": "database",
    "adw_private_endpoint_vpn": "database",
    "adb_adw_projects": "database",
    
    # API Gateway consolidation
    "api_gateway_api_keys_usage_plans": "apigateway",
    "api_gateway_jwt_custom_auth": "apigateway",
    "api_gateway_stage_deployment": "apigateway",
    "api_gateway_usage_plans_quotas": "apigateway",
    
    # Monitoring/Alarms
    "alarms_escalation": "monitoring",
    "anomaly_detection_net_metrics": "ai_anomaly_detection",
    
    # Audit & Logging
    "audit_object_storage_logging": "audit",
    
    # Functions & Automation
    "automation_via_functions": "functions",
    
    # Block Storage
    "block_volume_backups": "block_storage",
    "block_volume_replication": "block_storage",
    "block_volume_boot_volume_snapshot": "block_storage",
    
    # Backup & DR
    "backup_jobs": "database",  # Database backup jobs
}

# =============================================================================
# RESOURCE NAME FIXES (Generic "resource" → Specific Types)
# =============================================================================

def get_specific_resource_name(service: str, current_resource: str) -> str:
    """
    Convert generic 'resource' to specific resource type based on service context
    """
    if current_resource != "resource":
        return current_resource
    
    # Map generic "resource" to service-appropriate resource type
    resource_mappings = {
        "ai_anomaly_detection": "detector",
        "apis": "api",
        "apigateway": "gateway",
        "audit": "configuration",
        "database": "autonomous_database",
        "block_storage": "volume",
        "object_storage": "bucket",
        "compute": "instance",
        "container_engine": "cluster",
        "virtual_network": "vcn",
        "identity": "user",
        "key_management": "vault",
        "functions": "application",
        "monitoring": "alarm",
        "logging": "log_group",
        "data_catalog": "catalog",
        "data_science": "project",
        "analytics": "instance",
        "bds": "instance",
        "cloud_guard": "target",
        "devops": "project",
        "file_storage": "file_system",
        "load_balancer": "load_balancer",
        "mysql": "db_system",
        "nosql": "table",
    }
    
    return resource_mappings.get(service, "resource")

# =============================================================================
# ASSERTION IMPROVEMENTS (Remaining Unclear → Clear Desired States)
# =============================================================================

ASSERTION_IMPROVEMENTS_PASS2 = {
    # Unclear patterns → Clear states
    "kubelet_client_ca_file": "kubelet_client_ca_file_configured",
    "ec2_kubelet_config_ownership": "kubelet_config_ownership_restricted",
    "kubernetes_kubelet_config_permission": "kubelet_config_permissions_restricted",
    "incident_security_escalation_policy_exists_for_critical_severity": "critical_severity_escalation_policy_configured",
    "platform_security_authorizer_cache_ttl_reasonable": "authorizer_cache_ttl_configured",
    "function_not_publicly_accessible": "function_public_access_blocked",
    
    # Naming pattern fixes
    "lineage_security_database_cross_account_sharing_restricted": "cross_account_sharing_restricted",
    "lineage_security_database_encrypted": "database_encryption_enabled",
    "lineage_security_database_policy_least_privilege": "database_policy_least_privilege_enforced",
    "lineage_security_partition_access_policies_least_privilege": "partition_access_policies_least_privilege_enforced",
    "lineage_security_partition_catalog_encrypted": "partition_catalog_encryption_enabled",
    
    "data_catalog_security_partition_access_policies_least_privilege": "partition_access_policies_least_privilege_enforced",
    "data_catalog_security_partition_catalog_encrypted": "partition_catalog_encryption_enabled",
    "data_catalog_security_database_cross_account_sharing_restricted": "database_cross_account_sharing_restricted",
    "data_catalog_security_database_encrypted": "database_encryption_enabled",
    "data_catalog_security_database_policy_least_privilege": "database_policy_least_privilege_enforced",
    
    # Datalake patterns
    "datalake_security_schema_encrypted": "schema_encryption_enabled",
    "datalake_security_schema_rbac_least_privilege": "schema_rbac_least_privilege_enforced",
    "datalake_security_schema_version_immutability_enforced": "schema_version_immutability_enforced",
    "datalake_security_database_cross_account_sharing_restricted": "database_cross_account_sharing_restricted",
    "datalake_security_database_encrypted": "database_encryption_enabled",
    "datalake_security_database_policy_least_privilege": "database_policy_least_privilege_enforced",
    
    # Data warehouse patterns
    "data_warehouse_security_snapshot_not_publicly_shared": "snapshot_public_sharing_blocked",
    "data_warehouse_security_endpoint_authz_no_anonymous_access": "endpoint_anonymous_access_blocked",
    "data_warehouse_security_endpoint_authz_rbac_least_privilege": "endpoint_rbac_least_privilege_enforced",
    "data_warehouse_security_parameter_group_require_ssl": "parameter_group_ssl_required",
    "data_warehouse_security_endpoint_access_allowed_cidrs_minimized": "endpoint_allowed_cidrs_minimized",
    "data_warehouse_security_endpoint_access_private_only": "endpoint_private_access_enforced",
    
    # Platform/API patterns
    "platform_security_api_key_rotation_policy_defined": "api_key_rotation_policy_configured",
    "platform_security_api_key_scopes_least_privilege": "api_key_scopes_least_privilege_enforced",
    "platform_security_authorizer_token_audience_restricted": "authorizer_token_audience_restriction_enforced",
    "platform_security_stage_require_usage_plan_for_api_keys": "stage_usage_plan_for_api_keys_required",
    "platform_security_usage_plan_quota_limits_configured": "usage_plan_quota_limits_configured",
    "platform_security_usage_plan_rate_limits_configured": "usage_plan_rate_limits_configured",
}

def improve_assertion_pass2(assertion: str) -> tuple:
    """
    Second pass assertion improvements
    Returns: (improved_assertion, was_changed)
    """
    original = assertion
    
    # Direct mapping
    if assertion in ASSERTION_IMPROVEMENTS_PASS2:
        return ASSERTION_IMPROVEMENTS_PASS2[assertion], True
    
    # Remove redundant prefixes
    prefixes_to_remove = [
        'lineage_security_',
        'data_catalog_security_',
        'datalake_security_',
        'data_warehouse_security_',
        'data_analytics_security_',
        'platform_security_',
        'incident_security_',
        'governance_security_',
        'resilience_security_',
        'network_security_',
        'vuln_security_',
        'threat_security_',
    ]
    
    for prefix in prefixes_to_remove:
        if assertion.startswith(prefix):
            cleaned = assertion.replace(prefix, '', 1)
            # Check if it now has a clear state
            if any(s in cleaned for s in ['_enabled', '_enforced', '_configured', '_blocked', '_required', '_restricted']):
                return cleaned, True
    
    # Pattern improvements
    if assertion.endswith('_not_publicly_accessible') or assertion.endswith('_not_public'):
        base = assertion.replace('_not_publicly_accessible', '').replace('_not_public', '')
        return base + '_public_access_blocked' if base else 'public_access_blocked', True
    
    if '_least_privilege' in assertion and not assertion.endswith('_enforced'):
        return assertion + '_enforced', True
    
    if assertion.endswith('_exists') or assertion.endswith('_defined'):
        return assertion.replace('_exists', '_configured').replace('_defined', '_configured'), True
    
    return assertion, False

def fix_rule_comprehensive(rule: str) -> tuple:
    """
    Comprehensive rule fix - CSP, Service, Resource, Assertion
    Returns: (fixed_rule, was_changed, changes_list)
    """
    original = rule
    changes = []
    
    # Handle malformed rules (comma-separated or with oracle prefix)
    if ',' in rule or rule.startswith('oracle.'):
        # Extract the first valid-looking rule
        if ',' in rule:
            rule = rule.split(',')[0]
        
        # Fix CSP
        if rule.startswith('oracle.'):
            rule = rule.replace('oracle.', 'oci.', 1)
            changes.append("csp:oracle→oci")
    
    parts = rule.split('.')
    if len(parts) < 4:
        return rule, False, "malformed"
    
    csp = parts[0]
    service = parts[1]
    resource = parts[2]
    assertion = '.'.join(parts[3:])
    
    # Fix CSP
    if csp != 'oci':
        changes.append(f"csp:{csp}→oci")
        csp = 'oci'
    
    # Fix long service names
    if service in LONG_SERVICE_NAME_FIXES:
        new_service = LONG_SERVICE_NAME_FIXES[service]
        changes.append(f"service:{service}→{new_service}")
        service = new_service
    else:
        # Try official mapping
        new_service = get_official_service_name(service)
        if new_service != service:
            changes.append(f"service:{service}→{new_service}")
            service = new_service
    
    # Fix generic resource
    if resource == "resource":
        new_resource = get_specific_resource_name(service, resource)
        if new_resource != resource:
            changes.append(f"resource:generic→{new_resource}")
            resource = new_resource
    else:
        # Try official mapping
        new_resource = get_official_resource_name(service, resource)
        if new_resource != resource:
            changes.append(f"resource:{resource}→{new_resource}")
            resource = new_resource
    
    # Fix assertion
    new_assertion, assertion_changed = improve_assertion_pass2(assertion)
    if assertion_changed:
        changes.append(f"assertion")
        assertion = new_assertion
    
    # Reconstruct
    new_rule = f"{csp}.{service}.{resource}.{assertion}"
    
    if new_rule != original:
        return new_rule, True, " | ".join(changes)
    
    return rule, False, "no_change"

def main():
    print("=" * 80)
    print("OCI CSPM - SECOND PASS COMPLETE STANDARDIZATION")
    print("=" * 80)
    print()
    
    # Read rules
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
    print("🔧 Applying comprehensive fixes...")
    improved_rules = []
    changes_log = defaultdict(list)
    stats = {
        'total': len(rules),
        'changed': 0,
        'csp_fixes': 0,
        'service_fixes': 0,
        'resource_fixes': 0,
        'assertion_fixes': 0,
    }
    
    for i, rule in enumerate(rules):
        if (i + 1) % 500 == 0:
            print(f"  Progress: {i+1}/{len(rules)}")
        
        new_rule, was_changed, change_desc = fix_rule_comprehensive(rule)
        improved_rules.append(new_rule)
        
        if was_changed:
            stats['changed'] += 1
            changes_log[change_desc].append((rule, new_rule))
            
            if 'csp:' in change_desc:
                stats['csp_fixes'] += 1
            if 'service:' in change_desc:
                stats['service_fixes'] += 1
            if 'resource:' in change_desc:
                stats['resource_fixes'] += 1
            if 'assertion' in change_desc:
                stats['assertion_fixes'] += 1
    
    # Remove duplicates
    original_count = len(improved_rules)
    improved_rules = list(dict.fromkeys(improved_rules))
    stats['duplicates_removed'] = original_count - len(improved_rules)
    
    print()
    print("=" * 80)
    print("📊 SECOND PASS STATISTICS")
    print("=" * 80)
    print(f"Total Rules:             {stats['total']}")
    print(f"  ✅ Improved:           {stats['changed']} rules")
    if stats['duplicates_removed'] > 0:
        print(f"  🔍 Duplicates Removed: {stats['duplicates_removed']} rules")
    print()
    print(f"Fix Breakdown:")
    print(f"  🏷️  CSP fixes:          {stats['csp_fixes']} (oracle → oci)")
    print(f"  🏢 Service fixes:      {stats['service_fixes']}")
    print(f"  📦 Resource fixes:     {stats['resource_fixes']}")
    print(f"  ✨ Assertion fixes:    {stats['assertion_fixes']}")
    print()
    
    # Update and save
    data['metadata']['total_rules'] = len(improved_rules)
    data['metadata']['last_improved_pass2'] = datetime.now().isoformat()
    data['rule_ids'] = improved_rules
    
    print("💾 Writing improved rules...")
    with open('rule_ids.yaml', 'w') as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)
    
    print()
    print("=" * 80)
    print("✅ SECOND PASS COMPLETE!")
    print("=" * 80)
    print(f"Final rule count: {len(improved_rules)}")
    print(f"Improvements: {stats['changed']} rules")
    if stats['duplicates_removed'] > 0:
        print(f"Duplicates removed: {stats['duplicates_removed']}")
    print("=" * 80)

if __name__ == "__main__":
    main()

