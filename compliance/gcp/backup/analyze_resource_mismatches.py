#!/usr/bin/env python3
"""
Complete GCP Python Client Validation
Identifies all service/resource mismatches and creates update plan
"""

import yaml
from collections import defaultdict

# Official GCP Python Client mappings for ALL resources
# Based on actual google-cloud-* package APIs

CORRECT_RESOURCE_MAPPINGS = {
    # Services with resources that need fixing
    'aiplatform': {
        'ai_model_version': 'model',
        'ai_workbench': 'notebook_runtime',
        'auto_ml_job': 'automl_training_job',
        'instance': 'endpoint',  # Generic 'instance' should be 'endpoint'
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
        # Many compute resources need consolidation
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
        'resource_record_set': 'resource_record_set',
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
        'group': 'group',
        'log': 'alert_policy',
        'memory_utilization_alert': 'alert_policy',
        'network': 'alert_policy',
    },
    'multi': {
        'region': 'storage',  # Invalid service, should map to storage
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
    'securitycenter': {
        # Resources are correct
    },
    'services': {
        'api': 'service',  # Should use proper service name
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
        'ssl_cert': 'ssl_cert',
        'storage': 'instance',
    },
    'storage': {
        'account': 'bucket',
        'lifecycle': 'bucket',
        'multi_region': 'bucket',
        'notification': 'notification',
        'object_retention': 'bucket',
        'policy': 'bucket',
        'retention': 'bucket',
        'snapshot': 'bucket',
        'storage': 'bucket',
        'website_https_only': 'bucket',
    },
    'trace': {
        'trace': 'trace',  # Correct
    },
    'workspace': {
        'user': 'user',  # Correct
    },
}

def analyze_mismatches():
    """Analyze all mismatches and generate report"""
    with open('rule_ids.yaml', 'r') as f:
        data = yaml.safe_load(f)
    
    rules = data['rule_ids']
    
    # Count mismatches by service
    mismatch_count = defaultdict(int)
    total_mismatches = 0
    mismatch_details = defaultdict(list)
    
    for rule in rules:
        parts = rule.split('.')
        if len(parts) == 4:
            service = parts[1]
            resource = parts[2]
            
            if service in CORRECT_RESOURCE_MAPPINGS:
                if resource in CORRECT_RESOURCE_MAPPINGS[service]:
                    correct_resource = CORRECT_RESOURCE_MAPPINGS[service][resource]
                    mismatch_count[service] += 1
                    total_mismatches += 1
                    mismatch_details[service].append({
                        'current': resource,
                        'correct': correct_resource,
                        'rule': rule
                    })
    
    # Generate report
    print("=" * 80)
    print("GCP PYTHON CLIENT VALIDATION REPORT")
    print("=" * 80)
    print(f"\nTotal Resources Needing Update: {total_mismatches}")
    print(f"Services Affected: {len(mismatch_count)}")
    print()
    
    print("=" * 80)
    print("MISMATCHES BY SERVICE")
    print("=" * 80)
    
    for service in sorted(mismatch_count.keys(), key=lambda x: mismatch_count[x], reverse=True):
        count = mismatch_count[service]
        print(f"\n{service}: {count} resources need updating")
        
        # Group by resource type
        resource_map = defaultdict(list)
        for detail in mismatch_details[service]:
            key = f"{detail['current']} → {detail['correct']}"
            resource_map[key].append(detail['rule'])
        
        for mapping, rules_list in sorted(resource_map.items()):
            print(f"  {mapping} ({len(rules_list)} rules)")
    
    # Save detailed mapping
    with open('resource_mismatch_report.txt', 'w') as f:
        f.write("GCP Python Client Resource Mismatch Report\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"Total Mismatches: {total_mismatches}\n")
        f.write(f"Services Affected: {len(mismatch_count)}\n\n")
        
        for service in sorted(mismatch_count.keys()):
            f.write(f"\n{service.upper()}\n")
            f.write("-" * 80 + "\n")
            
            resource_map = defaultdict(list)
            for detail in mismatch_details[service]:
                key = f"{detail['current']} → {detail['correct']}"
                resource_map[key].append(detail['rule'])
            
            for mapping, rules_list in sorted(resource_map.items()):
                f.write(f"\n{mapping}:\n")
                for rule in rules_list[:5]:  # Show first 5 examples
                    f.write(f"  - {rule}\n")
                if len(rules_list) > 5:
                    f.write(f"  ... and {len(rules_list) - 5} more\n")
    
    print("\n" + "=" * 80)
    print("✅ Detailed report saved to: resource_mismatch_report.txt")
    print("=" * 80)
    
    return total_mismatches, mismatch_details

if __name__ == "__main__":
    total, details = analyze_mismatches()
    print(f"\nSummary: {total} resources identified for update")

