#!/usr/bin/env python3
"""
Azure Complete Normalization Pipeline
Phases 2-5: Resources, Assertions, and Deduplication
"""

import yaml
import re
from datetime import datetime
from collections import Counter, defaultdict

print("=" * 100)
print("AZURE COMPLETE NORMALIZATION PIPELINE")
print("=" * 100)

# Load rules
with open('rule_ids.yaml', 'r') as f:
    data = yaml.safe_load(f)

original_rules = data['rule_ids']
print(f"\nStarting Rules: {len(original_rules)}")

# Create comprehensive backup
backup_file = f"rule_ids_BACKUP_COMPLETE_NORM_{datetime.now().strftime('%Y%m%d_%H%M%S')}.yaml"
print(f"Creating backup: {backup_file}")
with open(backup_file, 'w') as f:
    yaml.dump(data, f, default_flow_style=False, sort_keys=False)

# ==================== PHASE 3: RESOURCE NORMALIZATION ====================
print(f"\n{'=' * 100}")
print("PHASE 3: RESOURCE NORMALIZATION")
print(f"{'=' * 100}")

# Azure SDK Resource Mappings
RESOURCE_MAPPINGS = {
    # Identity & Access
    'directory_tenant': 'tenant',
    'directory_group': 'group',
    'directory_user': 'user',
    'directory_app_registration': 'application',
    'directory_enterprise_application': 'enterprise_app',
    
    # App Service
    'paas_app': 'app',
    'azure_paas_app': 'app',
    
    # Managed resources
    'managed_compliant_patching': 'patch_configuration',
    'ensure_using_managed_disks': 'disk',
    
    # Storage
    'bucket': 'container',  # S3 terminology → Azure
    'sas': 'shared_access_signature',
    
    # Defender/Security
    'additional_email_configured_with_a_security_contact': 'security_contact',
    'for': 'defender_plan',  # defender.for.* → defender_plan
    
    # SQL
    'server_configuration': 'configuration',
    
    # Network
    'nsg': 'network_security_group',
    
    # Compute
    'virtual_machine_template': 'vm_template',
    'ebs': 'disk',  # AWS EBS → Azure Disk
    
    # Monitoring
    'action_group': 'action_group',
    'metric_alert': 'alert',
    'alert_rule': 'alert',
    'activity': 'activity_log',
    
    # Synapse
    'workgroup_encryption': 'workspace',
    'sql_pool': 'dedicated_sql_pool',
    'integration_runtime': 'integration_runtime',
    
    # Machine Learning
    'learning_pipeline': 'pipeline',
    'learning_job': 'job',
    'learning_endpoint': 'endpoint',
    'learning_auto_ml_job': 'automl_job',
    
    # Data
    'factory_dataset': 'dataset',
    'factory_pipeline': 'pipeline',
    'factory_pipeline_parameter': 'pipeline_parameter',
    'lake_analytics_job': 'analytics_job',
    
    # Purview
    'data_quality': 'data_quality_rule',
    'data_quality_rule': 'data_quality_rule',
    
    # AKS/Kubernetes
    'api_server': 'api_server',
    'managed_cluster': 'cluster',
    
    # Key Vault
    'rbac': 'access_policy',
    
    # CDN
    'custom_domain': 'domain',
    
    # Notification
    'hub_topic_subscription_configured': 'subscription',
    
    # Logic Apps
    'apps_workflow': 'workflow',
}

# Service-specific default resources
SERVICE_DEFAULT_RESOURCES = {
    'active_directory': 'user',
    'compute': 'virtual_machine',
    'storage': 'account',
    'network': 'virtual_network',
    'sql': 'server',
    'postgresql': 'server',
    'mysql': 'server',
    'cosmosdb': 'account',
    'synapse': 'workspace',
    'aks': 'cluster',
    'keyvault': 'vault',
    'security': 'policy',
    'monitor': 'alert',
    'app': 'service',
    'api': 'management',
    'machinelearning': 'workspace',
    'automation': 'account',
    'backup': 'vault',
    'recovery': 'vault',
    'datafactory': 'factory',
    'purview': 'account',
    'policy': 'assignment',
    'resource_manager': 'resource_group',
    'redis': 'cache',
    'eventgrid': 'topic',
    'servicebus': 'namespace',
    'eventhub': 'namespace',
    'iothub': 'hub',
    'search': 'service',
    'cdn': 'profile',
    'frontdoor': 'frontdoor',
    'logicapps': 'workflow',
    'containerregistry': 'registry',
    'notificationhubs': 'namespace',
}

def normalize_resource(service, resource):
    """Normalize resource name"""
    # Check if it's generic 'resource'
    if resource == 'resource' and service in SERVICE_DEFAULT_RESOURCES:
        return SERVICE_DEFAULT_RESOURCES[service]
    
    # Check if there's a specific mapping
    if resource in RESOURCE_MAPPINGS:
        return RESOURCE_MAPPINGS[resource]
    
    return resource

# ==================== PHASE 4: ASSERTION STANDARDIZATION ====================

def standardize_assertion(assertion):
    """Standardize assertion to enterprise-grade format"""
    if not assertion:
        return assertion
    
    original = assertion
    
    # Remove category prefixes
    category_prefixes = [
        'data_protection_', 'data_privacy_', 'data_governance_',
        'identity_access_', 'network_security_', 'network_encryption_',
        'configuration_management_', 'resilience_recovery_',
        'supply_chain_', 'logging_monitoring_', 'logging_metric_filter_',
        'governance_', 'compliance_', 'machine_learning_',
        'security_', 'policy_', 'check_', 'ensure_', 'verify_',
        'validate_', 'api_security_', 'paas_security_',
    ]
    
    for prefix in category_prefixes:
        if assertion.startswith(prefix):
            assertion = assertion[len(prefix):]
            break
    
    # Remove service/resource prefixes
    service_prefixes = [
        'storage_bucket_', 'storage_account_', 'ai_', 'app_',
        'api_', 'management_', 'config_', 'monitoring_',
    ]
    
    for prefix in service_prefixes:
        if assertion.startswith(prefix):
            assertion = assertion[len(prefix):]
            break
    
    # Remove duplicate consecutive words
    words = assertion.split('_')
    unique_words = []
    prev = None
    for word in words:
        if word != prev:
            unique_words.append(word)
        prev = word
    assertion = '_'.join(unique_words)
    
    # If too long, abbreviate
    if len(assertion) > 60:
        assertion = assertion.replace('_enabled', '_en')
        assertion = assertion.replace('_configured', '_cfg')
        assertion = assertion.replace('_required', '_req')
        assertion = assertion.replace('_disabled', '_dis')
        
        if len(assertion) > 60:
            parts = assertion.split('_')
            if len(parts) > 8:
                assertion = '_'.join(parts[:3] + ['...'] + parts[-2:])
    
    return assertion

# ==================== APPLY ALL TRANSFORMATIONS ====================

print("\nApplying comprehensive normalization...")

updated_rules = []
resource_changes = Counter()
assertion_changes = Counter()

for rule in original_rules:
    parts = rule.split('.')
    
    if len(parts) >= 3:
        csp = parts[0]
        service = parts[1]
        resource = parts[2]
        assertion = '.'.join(parts[3:]) if len(parts) > 3 else ''
        
        # Normalize resource
        new_resource = normalize_resource(service, resource)
        if resource != new_resource:
            resource_changes[f"{resource} → {new_resource}"] += 1
        
        # Standardize assertion
        new_assertion = standardize_assertion(assertion) if assertion else ''
        if assertion != new_assertion:
            assertion_changes[f"assertion_improved"] += 1
        
        # Build new rule
        if new_assertion:
            new_rule = f"{csp}.{service}.{new_resource}.{new_assertion}"
        else:
            new_rule = f"{csp}.{service}.{new_resource}"
        
        updated_rules.append(new_rule)
    else:
        updated_rules.append(rule)

print(f"  Resources normalized: {len(resource_changes)}")
print(f"  Assertions improved: {assertion_changes.get('assertion_improved', 0)}")

# ==================== PHASE 5: DEDUPLICATION ====================
print(f"\n{'=' * 100}")
print("PHASE 5: DEDUPLICATION")
print(f"{'=' * 100}")

rule_counts = Counter(updated_rules)
duplicates = {rule: count for rule, count in rule_counts.items() if count > 1}

print(f"Duplicate rules found: {len(duplicates)}")
print(f"Total duplicate instances: {sum(count - 1 for count in duplicates.values())}")

# Remove duplicates
final_rules = []
seen = set()
for rule in updated_rules:
    if rule not in seen:
        final_rules.append(rule)
        seen.add(rule)

# ==================== FINAL RESULTS ====================
print(f"\n{'=' * 100}")
print("FINAL RESULTS")
print(f"{'=' * 100}")

print(f"\nOriginal Rules:        {len(original_rules)}")
print(f"After Normalization:   {len(updated_rules)}")
print(f"After Deduplication:   {len(final_rules)}")
print(f"Duplicates Removed:    {len(updated_rules) - len(final_rules)} ({(len(updated_rules) - len(final_rules))/len(original_rules)*100:.1f}%)")

# Update metadata
data['rule_ids'] = final_rules
data['metadata']['total_rules'] = len(final_rules)
data['metadata']['last_complete_normalization'] = datetime.now().isoformat()
data['metadata']['normalization_phases'] = 'service+resource+assertion+dedup'
data['metadata']['resources_normalized'] = len(resource_changes)
data['metadata']['assertions_improved'] = assertion_changes.get('assertion_improved', 0)
data['metadata']['duplicates_removed'] = len(updated_rules) - len(final_rules)

# Save
with open('rule_ids.yaml', 'w') as f:
    yaml.dump(data, f, default_flow_style=False, sort_keys=False)

print(f"\n✅ Complete Normalization Finished!")
print(f"✅ Final Rules: {len(final_rules)}")
print(f"✅ Backup: {backup_file}")
print(f"\n{'=' * 100}")

