#!/usr/bin/env python3
"""
GCP Python Client Resource Alignment Script
Updates all resources to match official GCP Python client library naming
Processes 472 resources across 34 services
"""

import yaml
import re
from datetime import datetime
from collections import defaultdict

# Complete resource mapping for all services
RESOURCE_MAPPINGS = {
    'aiplatform': {
        'ai_model_version': 'model',
        'ai_workbench': 'notebook_runtime',
        'auto_ml_job': 'automl_training_job',
        'instance': 'endpoint',
    },
    'apigateway': {
        'certificate': 'api',
        'gateway_restapi_waf_acl_attached': 'api',
        'service': 'api',
    },
    'apikeys': {
        'api_restrictions_configured': 'key',
    },
    'artifactregistry': {
        'registry': 'repository',
    },
    'backupdr': {
        'dr_configured': 'backup_plan',
        'plan_min_retention': 'backup_plan',
        'recovery_point_retention': 'backup_plan',
    },
    'bigquery': {
        'capacity_monitoring': 'reservation',
        'cluster': 'table',
        'dataset_cmk_encryption': 'dataset',
        'dataset_public_access': 'dataset',
        'dlp': 'dataset',
        'parameter': 'routine',
        'schema': 'table',
        'snapshot': 'table',
        'table_cmk_encryption': 'table',
        'user': 'dataset_access_entry',
    },
    'billing': {
        'allocation': 'budget',
        'category': 'billing_account',
        'commitment': 'billing_account',
    },
    'certificatemanager': {
        'certificates': 'certificate',
        'manager': 'certificate',
    },
    'cloudidentity': {
        'user': 'membership',
    },
    'compute': {
        'access_control': 'firewall',
        'alb_https_redirect': 'url_map',
        'anomaly_detection': 'security_policy',
        'application': 'instance',
        'asset': 'instance',
        'automation': 'instance_template',
        'autoscaler_configured': 'autoscaler',
        'backend': 'backend_service',
        'balancing': 'backend_service',
        'balancing_deletion_protection': 'backend_service',
        'balancing_desync_mitigation_mode': 'backend_service',
        'balancing_insecure_ssl_ciphers': 'ssl_policy',
        'balancing_ssl_listeners': 'target_https_proxy',
        'balancing_waf_acl_attached': 'security_policy',
        'build': 'instance',
        'dedicated_host': 'instance',
        'deletion': 'instance',
        'distributions_using_deprecated_ssl_protocols': 'ssl_policy',
        'elastic': 'address',
        'encryption': 'disk',
        'flow': 'subnetwork',
        'function': 'instance',
        'functions': 'instance',
        'global_address': 'address',
        'ip_attached': 'address',
        'isolation': 'network',
        'job': 'instance',
        'load': 'backend_service',
        'micro_segmentation': 'firewall',
        'monitoring': 'instance',
        'network_interface': 'instance',
        'networkacl': 'firewall',
        'networkacl_allow_ingress_any_port': 'firewall',
        'networkacl_unrestricted_ingress': 'firewall',
        'os_config_compliance': 'instance',
        'patch_compliance': 'instance',
        'plan': 'instance',
        'preemptible_instance': 'instance',
        'public_address_shodan': 'address',
        'recovery_instance': 'instance',
        'securitygroup': 'firewall',
        'securitygroup_common_ports_restricted': 'firewall',
        'securitygroup_default_restrict_traffic': 'firewall',
        'securitygroup_default_restricted': 'firewall',
        'securitygroup_rdp_restricted': 'firewall',
        'securitygroup_ssh_restricted': 'firewall',
        'segmentation': 'firewall',
        'snapshot_schedule': 'resource_policy',
        'source_server': 'instance',
        'sql': 'instance',
        'ssh_key': 'instance',
        'stopped_instance': 'instance',
        'traffic_analysis': 'packet_mirroring',
        'v2': 'backend_service',
        'volume': 'disk',
    },
    'container': {
        'admission_controller': 'cluster',
        'autopilot': 'cluster',
        'binary': 'node_pool',
        'control_plane_apiserver': 'cluster',
        'control_plane_controller_manager': 'cluster',
        'control_plane_etcd': 'cluster',
        'control_plane_scheduler': 'cluster',
        'ingress': 'cluster',
        'kubernetes': 'cluster',
        'network_policy': 'cluster',
        'node_kubelet': 'node_pool',
        'persistent': 'node_pool',
        'shielded': 'node_pool',
    },
    'datacatalog': {
        'catalog': 'entry_group',
        'connection': 'entry',
        'lineage': 'entry',
        'schema': 'entry',
    },
    'dataflow': {
        'parameter': 'job',
    },
    'dataproc': {
        'workflow': 'workflow_template',
    },
    'datastudio': {
        'dashboard': 'report',
    },
    'dns': {
        'key': 'managed_zone',
        'managed': 'managed_zone',
        'rsasha1_in_use_to_zone_sign_in_dnssec': 'managed_zone',
        'vpc': 'policy',
    },
    'elasticsearch': {
        'service': 'cluster',
    },
    'endpoints': {
        'service': 'endpoint',
    },
    'essentialcontacts': {
        'contacts': 'contact',
    },
    'functions': {
        'concurrency_limit': 'function',
        'event_source': 'function',
        'layer': 'function',
        'provisioned_concurrency': 'function',
        'version': 'function',
    },
    'iam': {
        'account': 'service_account',
        'gke': 'service_account',
        'kms': 'service_account',
        'no': 'service_account',
        'no_guest_accounts_with_permissions': 'service_account',
        'organization_essential_contacts_configured': 'service_account',
        'password': 'user',
        'project': 'service_account',
        'rotate': 'key',
        'sa_no_administrative_privileges': 'service_account',
        'service': 'service_account',
    },
    'kms': {
        'build': 'crypto_key',
        'crypto': 'crypto_key',
        'kms': 'crypto_key',
    },
    'logging': {
        'alert': 'metric',
        'audit': 'log',
        'export': 'sink',
        'firewall': 'sink',
        'instance': 'sink',
        'log_metric_filter_alarm_configured': 'metric',
        'log_stream': 'sink',
        'logging': 'sink',
        'network': 'sink',
        'query_definition': 'log',
        'role': 'sink',
        'sink_created': 'sink',
        'sinks': 'sink',
        'sql': 'sink',
        'storage': 'bucket',
        'store': 'bucket',
        'vpc': 'sink',
    },
    'monitoring': {
        'alarm_configured': 'alert_policy',
        'capacity_alerts': 'alert_policy',
        'changes_to_vpcs_alarm_configured': 'alert_policy',
        'cpu_utilization_alert': 'alert_policy',
        'log': 'alert_policy',
        'memory_utilization_alert': 'alert_policy',
        'network': 'alert_policy',
    },
    'osconfig': {
        'config': 'patch_deployment',
        'config_managed_compliant_patching': 'patch_deployment',
        'config_patch_deployment': 'patch_deployment',
        'patch_deployment_exists': 'patch_deployment',
        'vm': 'guest_policy',
    },
    'pubsub': {
        'analytics_application': 'topic',
        'firehose': 'subscription',
        'stream': 'subscription',
        'stream_consumer': 'subscription',
        'topic_subscription_configured': 'subscription',
        'video_stream': 'subscription',
    },
    'resourcemanager': {
        'account': 'project',
        'policy': 'project',
    },
    'secretmanager': {
        'alias': 'secret',
        'certificate': 'secret',
        'compliant': 'secret',
        'grant': 'secret',
        'managed': 'secret',
        'parameter': 'secret',
        'patch': 'secret',
        'private_ca': 'secret',
        'store': 'secret',
    },
    'services': {
        'api': 'service',
    },
    'sql': {
        'auto_minor_version_upgrade': 'instance',
        'backup_retention': 'instance',
        'cluster': 'instance',
        'config': 'instance',
        'mysql': 'instance',
        'option_group': 'instance',
        'postgresql': 'instance',
        'server': 'instance',
        'snapshots_public_access': 'backup',
        'sqlserver': 'instance',
        'storage': 'instance',
    },
    'storage': {
        'account': 'bucket',
        'lifecycle': 'bucket',
        'multi_region': 'bucket',
        'object_retention': 'bucket',
        'policy': 'bucket',
        'retention': 'bucket',
        'snapshot': 'bucket',
        'storage': 'bucket',
        'website_https_only': 'bucket',
    },
}

def update_rules():
    """Update all rules with correct Python client resource names"""
    
    # Read current rules
    with open('rule_ids.yaml', 'r') as f:
        data = yaml.safe_load(f)
    
    original_rules = data['rule_ids']
    updated_rules = []
    changes_by_service = defaultdict(int)
    total_changes = 0
    
    print("=" * 80)
    print("PYTHON CLIENT ALIGNMENT - PROCESSING")
    print("=" * 80)
    print()
    
    for rule in original_rules:
        parts = rule.split('.')
        
        if len(parts) == 4:
            csp, service, resource, assertion = parts
            
            # Check if this resource needs updating
            if service in RESOURCE_MAPPINGS:
                if resource in RESOURCE_MAPPINGS[service]:
                    new_resource = RESOURCE_MAPPINGS[service][resource]
                    new_rule = f"{csp}.{service}.{new_resource}.{assertion}"
                    updated_rules.append(new_rule)
                    changes_by_service[service] += 1
                    total_changes += 1
                    continue
            
            # No mapping needed, keep as is
            updated_rules.append(rule)
        else:
            # Malformed rule, keep as is
            updated_rules.append(rule)
    
    # Update metadata
    data['rule_ids'] = updated_rules
    data['metadata']['formatted_date'] = datetime.now().isoformat()
    data['metadata']['format_version'] = 'enterprise_cspm_v5_python_client_aligned'
    data['metadata']['last_python_client_alignment'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    data['metadata']['python_client_aligned'] = True
    
    # Write updated rules
    with open('rule_ids.yaml', 'w') as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
    
    # Report
    print(f"✅ Updated {total_changes} rules across {len(changes_by_service)} services")
    print()
    print("Services updated:")
    for service in sorted(changes_by_service.keys(), key=lambda x: changes_by_service[x], reverse=True):
        print(f"  {service}: {changes_by_service[service]} rules")
    
    return total_changes, changes_by_service

if __name__ == "__main__":
    print("Starting Python client alignment...")
    print()
    
    total, by_service = update_rules()
    
    print()
    print("=" * 80)
    print("✅ PYTHON CLIENT ALIGNMENT COMPLETE")
    print("=" * 80)
    print(f"Total rules updated: {total}")
    print(f"Services affected: {len(by_service)}")
    print()

