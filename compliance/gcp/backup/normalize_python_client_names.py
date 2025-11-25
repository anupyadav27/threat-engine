#!/usr/bin/env python3
"""
Map GCP services and resources to official Python client library names
Based on google-cloud-* Python packages
"""

import yaml
import re
from datetime import datetime
from collections import defaultdict
import shutil

# Official GCP Python Client Service Names
# Based on https://cloud.google.com/python/docs/reference
OFFICIAL_SERVICE_NAMES = {
    'accessapproval': 'accessapproval',
    'aiplatform': 'aiplatform',
    'apigateway': 'apigateway',
    'apigee': 'apigee',
    'apikeys': 'apikeys',
    'appengine': 'appengine',
    'artifactregistry': 'artifactregistry',
    'backupdr': 'backupdr',
    'batch': 'batch',
    'bigquery': 'bigquery',
    'bigtable': 'bigtable',
    'billing': 'billing',
    'certificatemanager': 'certificatemanager',
    'cloud': None,  # Too generic, needs mapping
    'cloudasset': 'asset',  # google-cloud-asset
    'cloudaudit': 'logging',  # Cloud Audit is part of logging
    'cloudfunctions': 'functions',  # google-cloud-functions
    'cloudidentity': 'cloudidentity',
    'cloudkms': 'kms',  # google-cloud-kms
    'compute': 'compute',
    'container': 'container',  # GKE
    'datacatalog': 'datacatalog',
    'dataflow': 'dataflow',
    'dataproc': 'dataproc',
    'datastudio': 'datastudio',
    'dlp': 'dlp',
    'dns': 'dns',
    'elasticsearch': 'elasticsearch',
    'endpoints': 'endpoints',
    'essential': 'essentialcontacts',
    'external': 'compute',  # External IPs are part of compute
    'filestore': 'filestore',
    'firestore': 'firestore',
    'functions': 'functions',
    'healthcare': 'healthcare',
    'iam': 'iam',
    'kms': 'kms',
    'kubernetes': 'container',  # GKE
    'loadbalancing': 'compute',  # Load balancing is part of compute
    'logging': 'logging',
    'monitoring': 'monitoring',
    'multi': None,  # Too generic
    'notebooks': 'notebooks',
    'organizations': 'resourcemanager',
    'os': 'osconfig',  # google-cloud-os-config
    'osconfig': 'osconfig',
    'persistent': 'compute',  # Persistent disks are part of compute
    'pubsub': 'pubsub',
    'resourcemanager': 'resourcemanager',
    'secretmanager': 'secretmanager',
    'securitycenter': 'securitycenter',
    'services': None,  # Too generic
    'spanner': 'spanner',
    'sql': 'sql',
    'ssm': 'secretmanager',  # SSM maps to Secret Manager in GCP
    'storage': 'storage',
    'trace': 'trace',
    'workflows': 'workflows',
    'workspace': 'workspace',
}

# Official GCP Python Client Resource Names
# Based on actual API resource types in google-cloud-* packages
OFFICIAL_RESOURCE_NAMES = {
    # Access Approval
    'accessapproval': {
        'approval': 'approval_request',
    },
    # AI Platform (Vertex AI)
    'aiplatform': {
        'ai_auto_ml_job': 'automl_training_job',
        'ai_batch_prediction_job': 'batch_prediction_job',
        'ai_custom_job': 'custom_job',
        'ai_dataset': 'dataset',
        'ai_deployment': 'deployment',
        'ai_endpoint': 'endpoint',
        'ai_experiment': 'experiment',
        'ai_featurestore': 'featurestore',
        'ai_hyperparameter_tuning_job': 'hyperparameter_tuning_job',
        'ai_index': 'index',
        'ai_model': 'model',
        'ai_model_deployment_monitoring_job': 'model_deployment_monitoring_job',
        'ai_notebook': 'notebook_runtime',
        'ai_pipeline': 'pipeline_job',
        'ai_pipeline_job': 'pipeline_job',
        'ai_training_pipeline': 'training_pipeline',
    },
    # API Gateway
    'apigateway': {
        'api': 'api',
        'api_config': 'api_config',
        'gateway': 'gateway',
    },
    # Apigee
    'apigee': {
        'rate_limit': 'environment',
        'validation': 'api_proxy',
    },
    # API Keys
    'apikeys': {
        'key': 'key',
    },
    # App Engine
    'appengine': {
        'application': 'application',
        'service': 'service',
        'version': 'version',
    },
    # Artifact Registry
    'artifactregistry': {
        'lifecycle_policy': 'repository',
        'policy': 'repository',
        'replication_config': 'repository',
        'repo': 'repository',
        'repository': 'repository',
    },
    # Asset (Cloud Asset Inventory)
    'asset': {
        'asset': 'asset',
        'feed': 'feed',
    },
    # Backup and DR
    'backupdr': {
        'backup_job': 'backup_plan',
        'backup_plan': 'backup_plan',
        'backup_vault': 'backup_vault',
    },
    # BigQuery
    'bigquery': {
        'dataset': 'dataset',
        'table': 'table',
    },
    # Bigtable
    'bigtable': {
        'cluster': 'cluster',
        'instance': 'instance',
    },
    # Billing
    'billing': {
        'account': 'account',
        'budget': 'budget',
    },
    # Certificate Manager
    'certificatemanager': {
        'certificate': 'certificate',
    },
    # Cloud Identity
    'cloudidentity': {
        'group': 'group',
    },
    # Compute Engine
    'compute': {
        'address': 'address',
        'disk': 'disk',
        'external_ip': 'address',
        'firewall': 'firewall',
        'firewall_policy': 'firewall_policy',
        'firewall_rule': 'firewall',
        'forwarding_rule': 'forwarding_rule',
        'image': 'image',
        'instance': 'instance',
        'instance_group': 'instance_group',
        'instance_template': 'instance_template',
        'load_balancer': 'backend_service',
        'network': 'network',
        'persistent_disk': 'disk',
        'project': 'project',
        'router': 'router',
        'snapshot': 'snapshot',
        'ssl_certificate': 'ssl_certificate',
        'ssl_policy': 'ssl_policy',
        'subnetwork': 'subnetwork',
        'target_https_proxy': 'target_https_proxy',
        'target_pool': 'target_pool',
        'url_map': 'url_map',
        'vpc': 'network',
    },
    # Container (GKE)
    'container': {
        'cluster': 'cluster',
        'node_pool': 'node_pool',
    },
    # Data Catalog
    'datacatalog': {
        'data_policy': 'policy',
        'entry': 'entry',
        'entry_group': 'entry_group',
        'policy': 'policy',
        'tag': 'tag',
        'tag_template': 'tag_template',
        'taxonomy': 'taxonomy',
    },
    # Dataflow
    'dataflow': {
        'job': 'job',
    },
    # Dataproc
    'dataproc': {
        'autoscaling_policy': 'autoscaling_policy',
        'cluster': 'cluster',
    },
    # Data Studio
    'datastudio': {
        'report': 'report',
    },
    # DLP (Data Loss Prevention)
    'dlp': {
        'inspect_template': 'inspect_template',
        'job': 'job',
        'stored_info_type': 'stored_info_type',
    },
    # DNS
    'dns': {
        'managed_zone': 'managed_zone',
        'policy': 'policy',
    },
    # Elasticsearch (Elastic Cloud on GCP)
    'elasticsearch': {
        'domain': 'cluster',
    },
    # Endpoints
    'endpoints': {
        'service': 'service',
    },
    # Essential Contacts
    'essentialcontacts': {
        'contact': 'contact',
    },
    # Filestore
    'filestore': {
        'instance': 'instance',
    },
    # Firestore
    'firestore': {
        'database': 'database',
        'document': 'document',
    },
    # Cloud Functions
    'functions': {
        'function': 'function',
    },
    # Healthcare
    'healthcare': {
        'consent_store': 'consent_store',
        'dataset': 'dataset',
        'dicom_store': 'dicom_store',
        'fhir_store': 'fhir_store',
        'hl7_v2_store': 'hl7_v2_store',
    },
    # IAM
    'iam': {
        'deny_policy': 'deny_policy',
        'policy': 'policy',
        'role': 'role',
        'service_account': 'service_account',
        'service_account_key': 'key',
        'workload_identity_pool': 'workload_identity_pool',
    },
    # KMS
    'kms': {
        'crypto_key': 'crypto_key',
        'crypto_key_version': 'crypto_key_version',
        'key': 'crypto_key',
        'key_ring': 'key_ring',
    },
    # Logging
    'logging': {
        'audit_log': 'log',
        'exclusion': 'exclusion',
        'log': 'log',
        'log_bucket': 'bucket',
        'log_metric': 'metric',
        'log_sink': 'sink',
        'metric': 'metric',
        'sink': 'sink',
    },
    # Monitoring
    'monitoring': {
        'alert_policy': 'alert_policy',
        'dashboard': 'dashboard',
        'notification_channel': 'notification_channel',
        'uptime_check': 'uptime_check_config',
    },
    # Notebooks
    'notebooks': {
        'instance': 'instance',
        'runtime': 'runtime',
    },
    # OS Config
    'osconfig': {
        'os_policy_assignment': 'os_policy_assignment',
        'patch_deployment': 'patch_deployment',
    },
    # Pub/Sub
    'pubsub': {
        'schema': 'schema',
        'snapshot': 'snapshot',
        'subscription': 'subscription',
        'topic': 'topic',
    },
    # Resource Manager
    'resourcemanager': {
        'configuration': 'project',
        'connector': 'project',
        'connector_delivery': 'project',
        'connector_drift': 'project',
        'connector_policy': 'project',
        'connector_recorder': 'project',
        'connector_remediation': 'project',
        'connector_rule': 'project',
        'folder': 'folder',
        'organization': 'organization',
        'project': 'project',
    },
    # Secret Manager
    'secretmanager': {
        'manager': 'secret',
        'secret': 'secret',
        'secret_version': 'secret_version',
    },
    # Security Center (Security Command Center)
    'securitycenter': {
        'command': 'finding',
        'command_center_automation': 'automation',
        'command_center_finding': 'finding',
        'command_center_no_high_severity_findings': 'finding',
        'command_center_source': 'source',
        'finding': 'finding',
        'source': 'source',
    },
    # Spanner
    'spanner': {
        'database': 'database',
        'instance': 'instance',
    },
    # Cloud SQL
    'sql': {
        'database': 'database',
        'database_instance': 'instance',
        'instance': 'instance',
        'user': 'user',
    },
    # Cloud Storage
    'storage': {
        'bucket': 'bucket',
        'object': 'object',
    },
    # Cloud Trace
    'trace': {
        'trace': 'trace',
    },
    # Workflows
    'workflows': {
        'workflow': 'workflow',
    },
    # Workspace
    'workspace': {
        'domain': 'domain',
    },
}

def normalize_to_python_client_names(rule_id: str) -> tuple:
    """Normalize service and resource names to Python client library names."""
    parts = rule_id.split('.')
    
    if len(parts) != 4:
        return rule_id, []
    
    csp, service, resource, assertion = parts
    changes = []
    original_service = service
    original_resource = resource
    
    # Normalize service name
    if service in OFFICIAL_SERVICE_NAMES:
        new_service = OFFICIAL_SERVICE_NAMES[service]
        if new_service is None:
            # Handle special cases
            if service == 'cloud':
                # Try to infer from resource
                if 'kms' in resource or 'kms' in assertion:
                    new_service = 'kms'
                elif 'log' in resource:
                    new_service = 'logging'
                elif 'storage' in resource or 'bucket' in resource:
                    new_service = 'storage'
                else:
                    new_service = 'compute'
        
        if new_service and new_service != service:
            service = new_service
            changes.append(f"Service: {original_service} → {service}")
    
    # Normalize resource name
    if service in OFFICIAL_RESOURCE_NAMES:
        if resource in OFFICIAL_RESOURCE_NAMES[service]:
            new_resource = OFFICIAL_RESOURCE_NAMES[service][resource]
            if new_resource != resource:
                resource = new_resource
                changes.append(f"Resource: {original_resource} → {resource}")
    
    normalized_rule = f"{csp}.{service}.{resource}.{assertion}"
    return normalized_rule, changes

def process_all_rules(rule_ids: list) -> tuple:
    """Process all rules and normalize to Python client names."""
    normalized_rules = []
    stats = {
        'total': len(rule_ids),
        'changed': 0,
        'unchanged': 0,
    }
    
    changes_log = []
    
    for rule_id in rule_ids:
        normalized_rule, changes = normalize_to_python_client_names(rule_id)
        normalized_rules.append(normalized_rule)
        
        if changes:
            stats['changed'] += 1
            changes_log.append({
                'original': rule_id,
                'normalized': normalized_rule,
                'changes': changes
            })
        else:
            stats['unchanged'] += 1
    
    return normalized_rules, stats, changes_log

def main():
    """Main function."""
    print("=" * 80)
    print("GCP Python Client Library Name Normalization")
    print("=" * 80)
    print()
    
    # Paths
    rule_file = '/Users/apple/Desktop/threat-engine/compliance/gcp/rule_ids.yaml'
    backup_file = f'/Users/apple/Desktop/threat-engine/compliance/gcp/rule_ids_BACKUP_PYTHON_CLIENT_{datetime.now().strftime("%Y%m%d_%H%M%S")}.yaml'
    
    # Backup
    print(f"Creating backup: {backup_file}")
    shutil.copy(rule_file, backup_file)
    print("✓ Backup created")
    print()
    
    # Read
    print(f"Reading rules from: {rule_file}")
    with open(rule_file, 'r') as f:
        data = yaml.safe_load(f)
    
    original_rules = data.get('rule_ids', [])
    print(f"Total rules: {len(original_rules)}")
    print()
    
    # Process
    print("Normalizing to Python client library names...")
    print()
    normalized_rules, stats, changes_log = process_all_rules(original_rules)
    
    # Show sample changes
    if changes_log:
        print("Sample changes (first 30):")
        print()
        for i, change in enumerate(changes_log[:30]):
            print(f"{i+1}. {change['original']}")
            print(f"   → {change['normalized']}")
            print(f"   Changes: {', '.join(change['changes'])}")
            print()
    
    # Update metadata
    data['rule_ids'] = normalized_rules
    data['metadata']['formatted_date'] = datetime.now().isoformat()
    data['metadata']['last_normalized'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    data['metadata']['format_version'] = 'enterprise_cspm_v3_python_client'
    
    # Write
    print(f"Writing normalized rules to: {rule_file}")
    with open(rule_file, 'w') as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
    print("✓ File written")
    print()
    
    print("=" * 80)
    print("NORMALIZATION COMPLETE")
    print("=" * 80)
    print(f"Total rules:     {stats['total']}")
    print(f"Changed:         {stats['changed']} ({stats['changed']/stats['total']*100:.1f}%)")
    print(f"Unchanged:       {stats['unchanged']} ({stats['unchanged']/stats['total']*100:.1f}%)")
    print(f"Backup saved:    {backup_file}")
    print()
    
    # Save changes log
    if changes_log:
        log_file = '/Users/apple/Desktop/threat-engine/compliance/gcp/python_client_normalization_log.txt'
        with open(log_file, 'w') as f:
            f.write("GCP Python Client Library Name Normalization Log\n")
            f.write("=" * 80 + "\n\n")
            for i, change in enumerate(changes_log):
                f.write(f"{i+1}. {change['original']}\n")
                f.write(f"   → {change['normalized']}\n")
                f.write(f"   Changes: {', '.join(change['changes'])}\n\n")
        print(f"Full changes log saved: {log_file}")
        print()

if __name__ == "__main__":
    main()

